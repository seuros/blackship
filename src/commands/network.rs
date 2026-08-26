//! Network management commands

use crate::cli::NetworkAction;
use crate::error::Result;
use crate::network::netgraph::NgBridge;
use crate::{error, manifest, network};

pub fn handle(config: Option<&manifest::BlackshipConfig>, action: NetworkAction) -> Result<()> {
    use ipnet::IpNet;
    use network::bridge::{Bridge, destroy_bridge};
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
                .map_err(|e| error::Error::Network(format!("Invalid subnet: {}", e)))?;

            if store.get(&name)?.is_some() {
                return Err(error::Error::NetworkAlreadyExists(name));
            }

            let gateway_ip = if let Some(gw) = gateway {
                let gateway_ip = gw
                    .parse()
                    .map_err(|e| error::Error::Network(format!("Invalid gateway: {}", e)))?;
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

            if let Some(config) = config
                && let Some(existing) = config
                    .networks
                    .iter()
                    .find(|existing| existing.name == name)
            {
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
                        name
                    )));
                }
            }

            network::ensure::ensure_network(&mut record)?;

            if let Err(err) = store.create(&record) {
                let _ = network::bridge::destroy_bridge(&bridge, true);
                return Err(err);
            }

            println!(
                "Created network '{}' on bridge '{}' ({})",
                name, bridge, record.backend
            );
            println!("  Subnet: {}", subnet);
            println!("  Gateway: {}", gateway_ip);
            if let Some(host_iface) = &record.host_iface {
                println!("  Host gateway interface: {}", host_iface);
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
        NetworkAction::List => {
            let networks = store.list()?;
            if networks.is_empty() {
                println!("No networks found.");
            } else {
                println!("Networks:");
                for network in networks {
                    // NgBridge::open needs a control socket (root); the host
                    // eiface's ifnet is visible to everyone, so check that.
                    let alive = match network.backend.as_str() {
                        "netgraph" => {
                            network
                                .host_iface
                                .as_deref()
                                .map(network::ioctl::interface_exists)
                                .transpose()?
                                .unwrap_or(false)
                                || NgBridge::open(&network.bridge).is_ok()
                        }
                        _ => Bridge::exists(&network.bridge)?,
                    };
                    let status = if alive { "active" } else { "missing-bridge" };
                    let host_iface = network
                        .host_iface
                        .as_deref()
                        .map(|i| format!(" host_iface={}", i))
                        .unwrap_or_default();
                    println!(
                        "  {}: bridge={} backend={} subnet={} gateway={}{} status={}",
                        network.name,
                        network.bridge,
                        network.backend,
                        network.subnet,
                        network.gateway,
                        host_iface,
                        status
                    );
                }
            }
        }
    }

    Ok(())
}
