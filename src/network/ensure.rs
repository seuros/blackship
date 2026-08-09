//! Idempotent realization of network records.
//!
//! `ensure_network` makes the host match a NetworkRecord: bridge present,
//! gateway addressed, forwarding on. Used by `network create` and re-applied
//! by `setup` after a reboot, when bridges and eifaces no longer exist.

use crate::error::{Error, Result};
use crate::network::netgraph::NgBridge;
use crate::network::store::NetworkRecord;
use crate::network::{Bridge, ioctl};
use ipnet::IpNet;

/// Ensure the record's backing interfaces exist and are configured.
///
/// Returns true when the record was changed (netgraph host_iface renamed)
/// and needs to be persisted again.
pub fn ensure_network(record: &mut NetworkRecord) -> Result<bool> {
    let subnet: IpNet = record
        .subnet
        .parse()
        .map_err(|e| Error::Network(format!("Invalid subnet '{}': {}", record.subnet, e)))?;
    let gateway_with_prefix = format!("{}/{}", record.gateway, subnet.prefix_len());

    match record.backend.as_str() {
        "netgraph" => ensure_netgraph(record, &gateway_with_prefix),
        "epair" => ensure_epair(record, &gateway_with_prefix),
        other => Err(Error::Network(format!(
            "Unknown network backend '{}' (expected epair or netgraph)",
            other
        ))),
    }
}

fn ensure_epair(record: &NetworkRecord, gateway_with_prefix: &str) -> Result<bool> {
    if Bridge::exists(&record.bridge)? {
        return Ok(false);
    }
    let bridge = Bridge::create(&record.bridge)?;
    if let Err(e) = bridge.set_address(gateway_with_prefix) {
        let _ = bridge.destroy();
        return Err(e);
    }
    let _ = crate::sys::tag_interface(&record.bridge);
    crate::sys::set_sysctl_int("net.inet.ip.forwarding", 1)?;
    Ok(false)
}

fn ensure_netgraph(record: &mut NetworkRecord, gateway_with_prefix: &str) -> Result<bool> {
    let host_iface_alive = record
        .host_iface
        .as_deref()
        .map(ioctl::interface_exists)
        .transpose()?
        .unwrap_or(false);

    if NgBridge::open(&record.bridge).is_ok() && host_iface_alive {
        return Ok(false);
    }

    let mut bridge = NgBridge::create_or_open(&record.bridge)?;

    // The gateway lives on a host-side eiface hanging off the ng_bridge.
    let eiface = bridge.add_eiface()?;
    let ifname = eiface.ifname().to_string();
    if let Err(e) = ioctl::set_ipv4_address(&ifname, gateway_with_prefix) {
        let _ = eiface.destroy();
        return Err(e);
    }
    let _ = crate::sys::tag_interface(&ifname);
    crate::sys::set_sysctl_int("net.inet.ip.forwarding", 1)?;

    let changed = record.host_iface.as_deref() != Some(ifname.as_str());
    record.host_iface = Some(ifname);
    Ok(changed)
}
