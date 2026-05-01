//! Network management commands

use crate::cli::NetworkAction;
use crate::error::Result;
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

            let record = NetworkRecord {
                name: name.clone(),
                bridge: bridge.clone(),
                subnet: subnet.to_string(),
                gateway: gateway_ip.to_string(),
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

            let br = Bridge::create(&bridge)?;

            let gateway_with_prefix = format!("{}/{}", gateway_ip, subnet.prefix_len());
            if let Err(err) = br.set_address(&gateway_with_prefix) {
                return Err(rollback_bridge(&bridge, err));
            }

            if let Err(err) = store.create(&record) {
                return Err(rollback_bridge(&bridge, err));
            }

            println!("Created network '{}' on bridge '{}'", name, bridge);
            println!("  Subnet: {}", subnet);
            println!("  Gateway: {}", gateway_ip);
        }
        NetworkAction::Destroy { name, force } => {
            let record = store
                .get(&name)?
                .ok_or_else(|| error::Error::NetworkNotFound(name.clone()))?;

            if Bridge::exists(&record.bridge)? {
                destroy_bridge(&record.bridge, force)?;
            } else if !force {
                return Err(error::Error::Network(format!(
                    "Network '{}' points to missing bridge '{}'. Use --force to remove stale metadata.",
                    record.name, record.bridge
                )));
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
                    let status = if Bridge::exists(&network.bridge)? {
                        "active"
                    } else {
                        "missing-bridge"
                    };
                    println!(
                        "  {}: bridge={} subnet={} gateway={} status={}",
                        network.name, network.bridge, network.subnet, network.gateway, status
                    );
                }
            }
        }
    }

    Ok(())
}

fn rollback_bridge(bridge: &str, err: error::Error) -> error::Error {
    match network::bridge::Bridge::open(bridge).and_then(|br| br.destroy()) {
        Ok(()) => err,
        Err(cleanup_err) => error::Error::Network(format!(
            "{} (cleanup of bridge '{}' also failed: {})",
            err, bridge, cleanup_err
        )),
    }
}
