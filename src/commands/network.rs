//! Network management commands

use crate::cli::NetworkAction;
use crate::error::Result;
use crate::network::netgraph::NgBridge;
use crate::{error, manifest, network};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct NetworkStatus {
    pub name: String,
    pub bridge: String,
    pub backend: String,
    pub subnet: String,
    pub gateway: String,
    pub host_iface: Option<String>,
    pub status: &'static str,
}

/// List persisted networks with their current runtime status.
pub fn list(config: Option<&manifest::BlackshipConfig>) -> Result<Vec<NetworkStatus>> {
    use network::NetworkStore;
    use network::bridge::Bridge;

    NetworkStore::from_config(config)
        .list()?
        .into_iter()
        .map(|record| {
            // NgBridge::open needs root; the host eiface's ifnet is visible to all.
            let alive = match record.backend.as_str() {
                "netgraph" => {
                    record
                        .host_iface
                        .as_deref()
                        .map(network::ioctl::interface_exists)
                        .transpose()?
                        .unwrap_or(false)
                        || NgBridge::open(&record.bridge).is_ok()
                }
                _ => Bridge::exists(&record.bridge)?,
            };

            Ok(NetworkStatus {
                name: record.name,
                bridge: record.bridge,
                backend: record.backend,
                subnet: record.subnet,
                gateway: record.gateway,
                host_iface: record.host_iface,
                status: if alive { "active" } else { "missing-bridge" },
            })
        })
        .collect()
}

pub fn handle(config: Option<&manifest::BlackshipConfig>, action: NetworkAction) -> Result<()> {
    use ipnet::IpNet;
    use network::bridge::destroy_bridge;
    use network::{IpPool, NetworkRecord, NetworkStore};

    let store = NetworkStore::from_config(config);

    match action {
        NetworkAction::Create {
            name,
            subnet,
            gateway,
            bridge,
            backend,
        } => {
            let subnet: IpNet = subnet
                .parse()
                .map_err(|e| error::Error::Network(format!("Invalid subnet: {e}")))?;

            if store.get(&name)?.is_some() {
                return Err(error::Error::NetworkAlreadyExists(name));
            }

            let gateway_ip = if let Some(gw) = gateway {
                let gateway_ip = gw
                    .parse()
                    .map_err(|e| error::Error::Network(format!("Invalid gateway: {e}")))?;
                IpPool::with_gateway(subnet, gateway_ip)?;
                gateway_ip
            } else {
                IpPool::new(subnet)?.gateway()
            };

            let mut record = NetworkRecord {
                name: name.clone(),
                bridge: bridge.clone(),
                subnet: subnet.to_string(),
                gateway: gateway_ip.to_string(),
                backend,
                host_iface: None,
            };

            ensure_matches_manifest(config, &record)?;

            network::ensure::ensure_network(&mut record)?;

            if let Err(err) = store.create(&record) {
                // Rollback; keep the original error.
                let _ = network::bridge::destroy_bridge(&bridge, true);
                return Err(err);
            }

            println!(
                "Created network '{}' on bridge '{}' ({})",
                name, bridge, record.backend
            );
            println!("  Subnet: {subnet}");
            println!("  Gateway: {gateway_ip}");
            if let Some(host_iface) = &record.host_iface {
                println!("  Host gateway interface: {host_iface}");
            }
        }
        NetworkAction::Destroy { name, force } => {
            let record = store
                .get(&name)?
                .ok_or_else(|| error::Error::NetworkNotFound(name.clone()))?;

            // destroy_bridge handles both if_bridge and ng_bridge backends.
            match destroy_bridge(&record.bridge, force) {
                Ok(()) => {}
                Err(error::Error::InterfaceNotFound(_)) if force => {
                    // Bridge already gone - force flag allows removing stale metadata.
                }
                Err(e) => return Err(e),
            }

            store.delete(&name)?;
            println!("Destroyed network '{}' on bridge '{}'", name, record.bridge);
        }
        NetworkAction::List => list_networks(config)?,
    }

    Ok(())
}

/// Reject a network that blackship.toml declares with a different subnet or gateway.
fn ensure_matches_manifest(
    config: Option<&manifest::BlackshipConfig>,
    record: &network::NetworkRecord,
) -> Result<()> {
    use ipnet::IpNet;
    use network::IpPool;

    let Some(existing) = config.and_then(|c| {
        c.networks
            .iter()
            .find(|existing| existing.name == record.name)
    }) else {
        return Ok(());
    };

    let configured_gateway = if let Some(gateway) = existing.gateway {
        gateway.to_string()
    } else {
        let configured_subnet: IpNet = existing.subnet.parse().map_err(|e| {
            error::Error::Network(format!(
                "Invalid subnet '{}' for network '{}': {}",
                existing.subnet, existing.name, e
            ))
        })?;
        IpPool::new(configured_subnet)?.gateway().to_string()
    };
    if existing.subnet != record.subnet || configured_gateway != record.gateway {
        return Err(error::Error::Network(format!(
            "Network '{}' is already defined differently in blackship.toml",
            record.name
        )));
    }
    Ok(())
}

fn list_networks(config: Option<&manifest::BlackshipConfig>) -> Result<()> {
    let networks = list(config)?;
    if networks.is_empty() {
        println!("No networks found.");
        return Ok(());
    }
    println!("Networks:");
    for network in networks {
        let host_iface = network
            .host_iface
            .as_deref()
            .map(|i| format!(" host_iface={i}"))
            .unwrap_or_default();
        println!(
            "  {}: bridge={} backend={} subnet={} gateway={}{} status={}",
            network.name,
            network.bridge,
            network.backend,
            network.subnet,
            network.gateway,
            host_iface,
            network.status
        );
    }
    Ok(())
}
