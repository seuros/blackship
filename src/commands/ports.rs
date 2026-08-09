//! Port forwarding commands: expose, ports, unexpose

use std::path::Path;

use crate::error::Result;
use crate::{bridge, error, manifest};

pub fn handle_expose(
    config_path: &Path,
    verbose: bool,
    jail: String,
    port: u16,
    internal: Option<u16>,
    proto: String,
    bind_ip: Option<String>,
) -> Result<()> {
    use std::net::IpAddr;

    let config = manifest::load(config_path)?;
    let mut bridge = bridge::Bridge::open(config, verbose)?;

    let bind_addr: Option<IpAddr> =
        if let Some(ip_str) = bind_ip {
            Some(ip_str.parse().map_err(|e| {
                error::Error::Network(format!("Invalid bind IP '{}': {}", ip_str, e))
            })?)
        } else {
            None
        };

    let forward = bridge.expose_port(&jail, port, internal, &proto, bind_addr)?;

    println!("Port forwarding configured:");
    println!(
        "  {}:{}/{} -> {}:{}",
        bind_addr
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "*".to_string()),
        port,
        proto,
        forward.jail_ip,
        internal.unwrap_or(port)
    );
    println!("\nPF rule applied: {}", forward.to_pf_rule()?);
    println!("\nNote: Ensure these lines are in /etc/pf.conf:");
    println!("  rdr-anchor \"blackship\"");
    println!("  anchor \"blackship\"");

    Ok(())
}

pub fn handle_ports(config_path: &Path, jail: Option<String>) -> Result<()> {
    let config = manifest::load(config_path)?;
    let bridge = bridge::Bridge::new(config)?;

    println!("Port forwarding status:");
    println!(
        "{:<20} {:<12} {:<18} {:<18}",
        "JAIL", "PROTO", "EXTERNAL", "INTERNAL"
    );
    println!("{}", "-".repeat(70));

    let forwards = if let Some(jail_name) = &jail {
        bridge.get_jail_port_forwards(jail_name)
    } else {
        bridge.list_port_forwards().iter().collect()
    };

    if forwards.is_empty() {
        println!("No port forwards configured.");
    } else {
        for forward in forwards {
            let bind_str = forward
                .bind_ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "*".to_string());
            println!(
                "{:<20} {:<12} {:<18} {:<18}",
                forward.jail_name,
                forward.protocol,
                format!("{}:{}", bind_str, forward.external_port),
                format!("{}:{}", forward.jail_ip, forward.internal_port)
            );
        }
    }

    println!("\nTo expose a port:");
    println!("  blackship expose <jail> -p <port> [--bind-ip <ip>]");

    Ok(())
}

pub fn handle_unexpose(config_path: &Path, verbose: bool, jail: String) -> Result<()> {
    let config = manifest::load(config_path)?;
    let (_service_name, full_name) = config
        .resolve_jail_names(&jail)
        .ok_or_else(|| error::Error::JailNotFound(jail.clone()))?;
    let mut bridge = bridge::Bridge::open(config, verbose)?;
    bridge.remove_port_forwards(&full_name)?;
    println!("Removed all port forwards for jail '{}'", full_name);

    Ok(())
}
