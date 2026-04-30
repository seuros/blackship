//! Network management commands

use crate::cli::NetworkAction;
use crate::error::Result;
use crate::{error, network};

pub fn handle(action: NetworkAction) -> Result<()> {
    use ipnet::IpNet;
    use network::bridge::{Bridge, destroy_bridge, list_bridges};

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

            let gateway_ip: Option<std::net::IpAddr> = if let Some(gw) = gateway {
                Some(
                    gw.parse()
                        .map_err(|e| error::Error::Network(format!("Invalid gateway: {}", e)))?,
                )
            } else {
                None
            };

            let br = Bridge::create_or_open(&bridge)?;

            if let Some(gw) = &gateway_ip {
                let prefix = subnet.prefix_len();
                br.set_address(&format!("{}/{}", gw, prefix))?;
            }

            println!("Created network '{}' on bridge '{}'", name, bridge);
            println!("  Subnet: {}", subnet);
            if let Some(gw) = gateway_ip {
                println!("  Gateway: {}", gw);
            }
        }
        NetworkAction::Destroy { name, force } => {
            destroy_bridge(&name, force)?;
            println!("Destroyed bridge '{}'", name);
        }
        NetworkAction::List => {
            let bridges = list_bridges()?;
            if bridges.is_empty() {
                println!("No bridge interfaces found.");
            } else {
                println!("Bridge interfaces:");
                for bridge in bridges {
                    let br = Bridge::open(&bridge)?;
                    let members = br.members()?;
                    if members.is_empty() {
                        println!("  {} (no members)", bridge);
                    } else {
                        println!("  {} (members: {})", bridge, members.join(", "));
                    }
                }
            }
        }
        NetworkAction::Attach { jail, network, ip } => {
            println!(
                "Attaching jail '{}' to network '{}' (ip: {:?})",
                jail, network, ip
            );
            println!("Note: Attach is done automatically during 'up' with network config.");
        }
        NetworkAction::Detach { jail, network } => {
            println!("Detaching jail '{}' from network '{}'", jail, network);
            println!("Note: Detach is done automatically during 'down'.");
        }
    }

    Ok(())
}
