//! VNET jail network configuration
//!
//! Provides:
//! - VNET jail parameter configuration
//! - Full network setup for VNET jails
//! - Integration with bridges and epairs (default) or netgraph

use crate::error::Result;
use crate::network::Bridge;
use crate::network::epair::EpairInterface;
use crate::network::netgraph::{NgBridge, NgEiface};
use crate::network::store::VnetStateRecord;
use std::net::IpAddr;

/// Which dataplane backend to use for VNET networking.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkBackend {
    /// if_bridge + if_epair (the default)
    #[default]
    Epair,
    /// ng_bridge + ng_eiface (netgraph)
    Netgraph,
}

/// VNET network configuration for a jail
#[derive(Debug, Clone)]
pub struct VnetConfig {
    /// Bridge to connect to
    pub bridge: String,
    /// IP address with prefix (e.g., "10.0.1.10/24")
    pub ip: String,
    /// Gateway address
    pub gateway: IpAddr,
    /// Static MAC address for the jail-side interface
    pub mac_address: Option<String>,
    /// VLAN ID for this jail's interface (untagged/PVID)
    pub vlan_id: Option<u16>,
    pub backend: NetworkBackend,
}

impl VnetConfig {
    /// Create a new VNET configuration
    pub fn new(bridge: String, ip: String, gateway: IpAddr) -> Self {
        Self {
            bridge,
            ip,
            gateway,
            mac_address: None,
            vlan_id: None,
            backend: NetworkBackend::default(),
        }
    }

    /// Set static MAC address for the jail-side interface
    pub fn with_mac_address(mut self, mac: String) -> Self {
        self.mac_address = Some(mac);
        self
    }

    /// Set VLAN ID for the jail's interface
    pub fn with_vlan_id(mut self, vlan_id: u16) -> Self {
        self.vlan_id = Some(vlan_id);
        self
    }

    pub fn with_backend(mut self, backend: NetworkBackend) -> Self {
        self.backend = backend;
        self
    }
}

/// Wait for a dying jail's interface to be swept back to the host vnet.
///
/// vnet_if_return moves a dead jail's ifnets home asynchronously. Destroying
/// an interface while that sweep is in flight races the kernel's bpf list
/// (bpf_vmove panics on dead_bpf_if; observed on 16.0-CURRENT). Once the
/// ifnet is host-visible again the sweep is done and teardown is safe.
fn wait_for_host_return(ifname: &str) {
    for _ in 0..50 {
        if crate::network::ioctl::interface_exists(ifname).unwrap_or(true) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Deterministic MAC for a jail interface: 58:9c:fc (FreeBSD OUI) plus
/// three hash bytes of the jail name and bridge. Stable across restarts,
/// clones keep distinct addresses because the name participates.
fn deterministic_mac(jail_name: &str, bridge: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"blackship-mac");
    hasher.update(jail_name.as_bytes());
    hasher.update(bridge.as_bytes());
    let digest = hasher.finalize();
    format!(
        "58:9c:fc:{:02x}:{:02x}:{:02x}",
        digest[0], digest[1], digest[2]
    )
}

#[derive(Debug, Clone)]
enum VnetInterface {
    Epair(EpairInterface),
    Netgraph(NgEiface),
}

/// Network setup for a VNET jail
#[derive(Debug, Clone)]
pub struct VnetSetup {
    interface: VnetInterface,
    pub bridge_name: String,
    /// IP configuration
    pub config: VnetConfig,
}

impl VnetSetup {
    /// Create a VNET network setup for a jail
    ///
    /// Creates the interface pair and adds it to the bridge; the move into the
    /// jail happens later, during jail creation.
    pub fn create(jail_name: &str, mut config: VnetConfig) -> Result<Self> {
        // Deterministic MAC by default: stable across restarts and hosts,
        // derived from the jail identity (FreeBSD Foundation OUI).
        if config.mac_address.is_none() {
            config.mac_address = Some(deterministic_mac(jail_name, &config.bridge));
        }
        match config.backend {
            NetworkBackend::Epair => Self::create_epair(jail_name, config),
            NetworkBackend::Netgraph => Self::create_netgraph(config),
        }
    }

    fn create_epair(jail_name: &str, config: VnetConfig) -> Result<Self> {
        let bridge = Bridge::create_or_open(&config.bridge)?;
        let epair = EpairInterface::create_for_jail(jail_name)?;

        if let Some(ref mac) = config.mac_address
            && let Err(e) = epair.set_mac_address(mac)
        {
            let _ = epair.destroy();
            return Err(e);
        }

        let add_result = if let Some(vlan_id) = config.vlan_id {
            bridge.add_member_untagged(epair.host_side(), vlan_id)
        } else {
            bridge.add_member(epair.host_side())
        };
        if let Err(e) = add_result {
            let _ = epair.destroy();
            return Err(e);
        }

        Ok(Self {
            interface: VnetInterface::Epair(epair),
            bridge_name: config.bridge.clone(),
            config,
        })
    }

    fn create_netgraph(config: VnetConfig) -> Result<Self> {
        if config.vlan_id.is_some() {
            return Err(crate::error::Error::Network(
                "VLAN tagging is not supported with the netgraph backend".to_string(),
            ));
        }

        let mut bridge = NgBridge::create_or_open(&config.bridge)?;
        let eiface = bridge.add_eiface()?;

        if let Some(ref mac) = config.mac_address
            && let Err(e) = eiface.set_mac_address(mac)
        {
            let _ = eiface.destroy();
            return Err(e);
        }

        Ok(Self {
            interface: VnetInterface::Netgraph(eiface),
            bridge_name: config.bridge.clone(),
            config,
        })
    }

    /// Get the interface name that will be used inside the jail
    pub fn jail_interface(&self) -> &str {
        match &self.interface {
            VnetInterface::Epair(epair) => epair.jail_side(),
            VnetInterface::Netgraph(eiface) => eiface.ifname(),
        }
    }

    pub fn host_interface(&self) -> &str {
        match &self.interface {
            VnetInterface::Epair(epair) => epair.host_side(),
            // Netgraph eiface has no separate host side.
            VnetInterface::Netgraph(eiface) => eiface.ifname(),
        }
    }

    /// Move the jail-side interface into the jail and configure it
    pub fn attach_to_jail(&self, jid: i32) -> Result<()> {
        match &self.interface {
            VnetInterface::Epair(epair) => {
                epair.move_to_jail(jid)?;
                EpairInterface::configure_in_jail(
                    jid,
                    epair.jail_side(),
                    &self.config.ip,
                    Some(&self.config.gateway.to_string()),
                )?;
            }
            VnetInterface::Netgraph(eiface) => {
                eiface.move_to_jail(jid)?;
                EpairInterface::configure_in_jail(
                    jid,
                    eiface.ifname(),
                    &self.config.ip,
                    Some(&self.config.gateway.to_string()),
                )?;
            }
        }
        Ok(())
    }

    /// Clean up the network setup
    pub fn cleanup(&self) -> Result<()> {
        wait_for_host_return(self.jail_interface());
        match &self.interface {
            VnetInterface::Epair(epair) => {
                if let Ok(bridge) = Bridge::open(&self.bridge_name) {
                    let _ = bridge.remove_member(epair.host_side());
                }
                epair.destroy()
            }
            VnetInterface::Netgraph(eiface) => eiface.destroy(),
        }
    }

    pub fn state_record(&self, owner: &str, network: Option<&str>) -> VnetStateRecord {
        let backend = match &self.interface {
            VnetInterface::Epair(_) => "epair",
            VnetInterface::Netgraph(_) => "netgraph",
        };
        VnetStateRecord {
            owner: owner.to_string(),
            network: network.map(str::to_string),
            bridge: self.bridge_name.clone(),
            host_interface: self.host_interface().to_string(),
            jail_interface: self.jail_interface().to_string(),
            backend: backend.to_string(),
        }
    }

    pub fn cleanup_state(record: &VnetStateRecord) -> Result<()> {
        wait_for_host_return(&record.jail_interface);
        match record.backend.as_str() {
            "netgraph" => {
                let eiface = NgEiface::from_state(
                    &record.bridge,
                    &record.host_interface,
                    &record.jail_interface,
                );
                eiface.destroy()
            }
            "epair" => {
                // A state record can outlive its interfaces; if the name has
                // been recycled by an interface we do not own, leave it alone.
                if crate::network::ioctl::interface_exists(&record.host_interface)?
                    && !crate::sys::interface_is_tagged(&record.host_interface)
                {
                    return Err(crate::error::Error::Network(format!(
                        "Interface '{}' is not tagged with group '{}'; refusing to destroy it",
                        record.host_interface,
                        crate::sys::IFACE_GROUP
                    )));
                }
                if let Ok(bridge) = Bridge::open(&record.bridge) {
                    let _ = bridge.remove_member(&record.host_interface);
                }
                EpairInterface::from_existing(
                    record.host_interface.clone(),
                    record.jail_interface.clone(),
                )
                .destroy()
            }
            other => Err(crate::error::Error::Network(format!(
                "Unknown network backend '{}' in state record for '{}'",
                other, record.owner
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vnet_config() {
        let config = VnetConfig::new(
            "blackship0".to_string(),
            "10.0.1.10/24".to_string(),
            "10.0.1.1".parse().unwrap(),
        );

        assert_eq!(config.bridge, "blackship0");
        assert_eq!(config.ip, "10.0.1.10/24");
        assert_eq!(config.backend, NetworkBackend::Epair);
    }

    #[test]
    fn test_vnet_config_netgraph() {
        let config = VnetConfig::new(
            "ngbridge0".to_string(),
            "10.0.1.10/24".to_string(),
            "10.0.1.1".parse().unwrap(),
        )
        .with_backend(NetworkBackend::Netgraph);

        assert_eq!(config.backend, NetworkBackend::Netgraph);
    }
}
