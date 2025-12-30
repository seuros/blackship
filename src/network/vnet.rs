//! VNET jail network configuration
//!
//! Provides:
//! - VNET jail parameter configuration
//! - Full network setup for VNET jails
//! - Integration with bridges and epairs

use crate::error::Result;
use crate::network::{Bridge, EpairInterface};
use std::net::IpAddr;

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
}

/// Network setup for a VNET jail
#[derive(Debug, Clone)]
pub struct VnetSetup {
    /// Epair interface pair
    pub epair: EpairInterface,
    /// Bridge the epair is connected to
    pub bridge_name: String,
    /// IP configuration
    pub config: VnetConfig,
}

impl VnetSetup {
    /// Create a VNET network setup for a jail
    ///
    /// This creates the epair, adds it to the bridge, but does NOT
    /// move the interface into the jail (that happens during jail creation).
    pub fn create(jail_name: &str, config: VnetConfig) -> Result<Self> {
        // Open or create the bridge
        let bridge = Bridge::create_or_open(&config.bridge)?;

        // Create epair for this jail
        let epair = EpairInterface::create_for_jail(jail_name)?;

        // Set static MAC address if configured (before adding to bridge)
        if let Some(ref mac) = config.mac_address {
            epair.set_mac_address(mac)?;
        }

        // Add host side of epair to bridge
        // Use VLAN filtering if vlan_id is configured (FreeBSD 15.0+)
        if let Some(vlan_id) = config.vlan_id {
            bridge.add_member_untagged(epair.host_side(), vlan_id)?;
        } else {
            bridge.add_member(epair.host_side())?;
        }

        Ok(Self {
            epair,
            bridge_name: config.bridge.clone(),
            config,
        })
    }

    /// Get the interface name that will be used inside the jail
    pub fn jail_interface(&self) -> &str {
        self.epair.jail_side()
    }

    /// Move the jail-side interface into the jail and configure it
    pub fn attach_to_jail(&self, jid: i32) -> Result<()> {
        // Move interface into jail
        self.epair.move_to_jail(jid)?;

        // Configure interface inside jail
        EpairInterface::configure_in_jail(
            jid,
            self.jail_interface(),
            &self.config.ip,
            Some(&self.config.gateway.to_string()),
        )?;

        Ok(())
    }

    /// Clean up the network setup
    pub fn cleanup(&self) -> Result<()> {
        // Remove from bridge (if still connected)
        if let Ok(bridge) = Bridge::open(&self.bridge_name) {
            let _ = bridge.remove_member(self.epair.host_side());
        }

        // Destroy the epair
        self.epair.destroy()
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
    }
}
