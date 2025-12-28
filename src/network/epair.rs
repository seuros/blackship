//! Epair interface management for VNET jails
//!
//! Epairs are virtual Ethernet pairs used to connect VNET jails to bridges.
//! One end stays on the host (and is added to a bridge), the other is moved
//! into the jail.

use crate::error::{Error, Result};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

/// Counter for generating unique epair names
static EPAIR_COUNTER: AtomicU32 = AtomicU32::new(0);

/// An epair interface pair for connecting VNET jails to bridges
#[derive(Debug, Clone)]
pub struct EpairInterface {
    /// Host-side interface name (e.g., "epair0a")
    host_side: String,
    /// Jail-side interface name (e.g., "epair0b")
    jail_side: String,
}

impl EpairInterface {
    /// Create a new epair interface pair
    ///
    /// The epair is created with system-assigned names (epairNa, epairNb).
    pub fn create() -> Result<Self> {
        let output = Command::new("ifconfig")
            .args(["epair", "create"])
            .output()
            .map_err(|e| Error::Network(format!("Failed to create epair: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Network(format!(
                "Failed to create epair: {}",
                stderr
            )));
        }

        // Output is something like "epair0a\n"
        let host_side = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // The jail side is the same but with 'b' instead of 'a'
        let jail_side = host_side
            .strip_suffix('a')
            .map(|s| format!("{}b", s))
            .ok_or_else(|| {
                Error::Network(format!("Unexpected epair name format: {}", host_side))
            })?;

        // Bring host side up
        let output = Command::new("ifconfig")
            .args([&host_side, "up"])
            .output()
            .map_err(|e| Error::Network(format!("Failed to bring up epair: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Network(format!(
                "Failed to bring up {}: {}",
                host_side, stderr
            )));
        }

        Ok(Self {
            host_side,
            jail_side,
        })
    }

    /// Create an epair with a specific naming pattern for a jail
    ///
    /// Creates interfaces named like "e0a_jailname" and "e0b_jailname"
    pub fn create_for_jail(jail_name: &str) -> Result<Self> {
        // First create a regular epair
        let epair = Self::create()?;

        // Generate a unique counter
        let counter = EPAIR_COUNTER.fetch_add(1, Ordering::SeqCst);

        // Create the custom names
        let new_host_name = format!("e{}a_{}", counter, Self::sanitize_name(jail_name));
        let new_jail_name = format!("e{}b_{}", counter, Self::sanitize_name(jail_name));

        // Rename host side
        let output = Command::new("ifconfig")
            .args([&epair.host_side, "name", &new_host_name])
            .output()
            .map_err(|e| Error::Network(format!("Failed to rename epair: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Clean up the original epair
            let _ = Command::new("ifconfig")
                .args([&epair.host_side, "destroy"])
                .output();
            return Err(Error::Network(format!(
                "Failed to rename {}: {}",
                epair.host_side, stderr
            )));
        }

        // Rename jail side
        let output = Command::new("ifconfig")
            .args([&epair.jail_side, "name", &new_jail_name])
            .output()
            .map_err(|e| Error::Network(format!("Failed to rename epair: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Clean up
            let _ = Command::new("ifconfig")
                .args([&new_host_name, "destroy"])
                .output();
            return Err(Error::Network(format!(
                "Failed to rename {}: {}",
                epair.jail_side, stderr
            )));
        }

        Ok(Self {
            host_side: new_host_name,
            jail_side: new_jail_name,
        })
    }

    /// Get the host-side interface name
    pub fn host_side(&self) -> &str {
        &self.host_side
    }

    /// Get the jail-side interface name
    pub fn jail_side(&self) -> &str {
        &self.jail_side
    }

    /// Set MAC address on the jail-side interface
    ///
    /// Must be called before moving the interface into the jail.
    /// MAC format: "02:00:00:00:00:01" (locally administered addresses start with 02)
    pub fn set_mac_address(&self, mac: &str) -> Result<()> {
        let output = Command::new("ifconfig")
            .args([&self.jail_side, "ether", mac])
            .output()
            .map_err(|e| Error::Network(format!("Failed to set MAC address: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Network(format!(
                "Failed to set MAC {} on {}: {}",
                mac, self.jail_side, stderr
            )));
        }

        Ok(())
    }

    /// Move the jail-side interface into a VNET jail
    ///
    /// This is done by setting the vnet parameter when creating the jail,
    /// or using `ifconfig <iface> vnet <jid>` after jail creation.
    pub fn move_to_jail(&self, jid: i32) -> Result<()> {
        let output = Command::new("ifconfig")
            .args([&self.jail_side, "vnet", &jid.to_string()])
            .output()
            .map_err(|e| Error::Network(format!("Failed to move interface to jail: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Network(format!(
                "Failed to move {} to jail {}: {}",
                self.jail_side, jid, stderr
            )));
        }

        Ok(())
    }

    /// Configure the jail-side interface with an IP address (inside the jail)
    pub fn configure_in_jail(
        jid: i32,
        interface: &str,
        addr: &str,
        gateway: Option<&str>,
    ) -> Result<()> {
        // Configure IP address inside jail
        let output = Command::new("jexec")
            .args([&jid.to_string(), "ifconfig", interface, addr])
            .output()
            .map_err(|e| Error::Network(format!("Failed to configure interface: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Network(format!(
                "Failed to configure {} in jail {}: {}",
                interface, jid, stderr
            )));
        }

        // Bring interface up
        let output = Command::new("jexec")
            .args([&jid.to_string(), "ifconfig", interface, "up"])
            .output()
            .map_err(|e| Error::Network(format!("Failed to bring up interface: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Network(format!(
                "Failed to bring up {} in jail {}: {}",
                interface, jid, stderr
            )));
        }

        // Set default route if gateway provided
        if let Some(gw) = gateway {
            let output = Command::new("jexec")
                .args([&jid.to_string(), "route", "add", "default", gw])
                .output()
                .map_err(|e| Error::Network(format!("Failed to add route: {}", e)))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                // Don't fail if route already exists
                if !stderr.contains("File exists") {
                    return Err(Error::Network(format!(
                        "Failed to add default route in jail {}: {}",
                        jid, stderr
                    )));
                }
            }
        }

        Ok(())
    }

    /// Destroy the epair (destroys both ends)
    pub fn destroy(&self) -> Result<()> {
        // Destroying either end destroys both
        let output = Command::new("ifconfig")
            .args([&self.host_side, "destroy"])
            .output()
            .map_err(|e| Error::Network(format!("Failed to destroy epair: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Don't fail if already destroyed
            if !stderr.contains("does not exist") {
                return Err(Error::Network(format!(
                    "Failed to destroy {}: {}",
                    self.host_side, stderr
                )));
            }
        }

        Ok(())
    }

    /// Sanitize a jail name for use in interface names
    ///
    /// Interface names have a max length of 15 characters on FreeBSD.
    fn sanitize_name(name: &str) -> String {
        // Keep only alphanumeric and underscore, truncate to fit
        let sanitized: String = name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .take(10) // Leave room for e0a_ prefix
            .collect();

        if sanitized.is_empty() {
            "jail".to_string()
        } else {
            sanitized
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_name() {
        assert_eq!(EpairInterface::sanitize_name("myjail"), "myjail");
        assert_eq!(EpairInterface::sanitize_name("my-jail"), "myjail");
        assert_eq!(
            EpairInterface::sanitize_name("verylongjailname"),
            "verylongja"
        );
        assert_eq!(EpairInterface::sanitize_name(""), "jail");
    }
}
