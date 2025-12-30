//! Epair interface management for VNET jails
//!
//! Epairs are virtual Ethernet pairs used to connect VNET jails to bridges.
//! One end stays on the host (and is added to a bridge), the other is moved
//! into the jail.

use crate::error::{Error, Result};
use crate::jail::jexec_with_output;
use crate::network::ioctl;
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
    /// Create a new epair interface pair using native ioctl syscalls
    ///
    /// The epair is created with system-assigned names (epairNa, epairNb).
    pub fn create() -> Result<Self> {
        // Use native SIOCIFCREATE ioctl instead of spawning ifconfig process
        let host_side = ioctl::create_interface("epair", None)?;

        // The jail side is the same but with 'b' instead of 'a'
        let jail_side = host_side
            .strip_suffix('a')
            .map(|s| format!("{}b", s))
            .ok_or_else(|| {
                Error::Network(format!("Unexpected epair name format: {}", host_side))
            })?;

        // Bring host side up using native ioctl
        ioctl::set_interface_up(&host_side, true)?;

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

        // Rename host side using ioctl
        if let Err(e) = ioctl::rename_interface(&epair.host_side, &new_host_name) {
            // Clean up the original epair
            let _ = ioctl::destroy_interface(&epair.host_side);
            return Err(e);
        }

        // Rename jail side using ioctl
        if let Err(e) = ioctl::rename_interface(&epair.jail_side, &new_jail_name) {
            // Clean up
            let _ = ioctl::destroy_interface(&new_host_name);
            return Err(e);
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

    /// Set MAC address on the jail-side interface using ioctl
    ///
    /// Must be called before moving the interface into the jail.
    /// MAC format: "02:00:00:00:00:01" (locally administered addresses start with 02)
    pub fn set_mac_address(&self, mac: &str) -> Result<()> {
        ioctl::set_mac_address(&self.jail_side, mac)
    }

    /// Move the jail-side interface into a VNET jail using ioctl
    ///
    /// This is done via SIOCSIFVNET ioctl syscall.
    pub fn move_to_jail(&self, jid: i32) -> Result<()> {
        ioctl::move_to_vnet(&self.jail_side, jid)
    }

    /// Configure the jail-side interface with an IP address (inside the jail)
    pub fn configure_in_jail(
        jid: i32,
        interface: &str,
        addr: &str,
        gateway: Option<&str>,
    ) -> Result<()> {
        // Configure IP address inside jail using native jexec syscall
        let (exit_code, _stdout, stderr) = jexec_with_output(jid, &["ifconfig", interface, addr])
            .map_err(|e| Error::Network(format!("Failed to configure interface: {}", e)))?;

        if exit_code != 0 {
            let stderr_str = String::from_utf8_lossy(&stderr);
            return Err(Error::Network(format!(
                "Failed to configure {} in jail {}: {}",
                interface, jid, stderr_str
            )));
        }

        // Bring interface up using native jexec syscall
        let (exit_code, _stdout, stderr) = jexec_with_output(jid, &["ifconfig", interface, "up"])
            .map_err(|e| Error::Network(format!("Failed to bring up interface: {}", e)))?;

        if exit_code != 0 {
            let stderr_str = String::from_utf8_lossy(&stderr);
            return Err(Error::Network(format!(
                "Failed to bring up {} in jail {}: {}",
                interface, jid, stderr_str
            )));
        }

        // Set default route if gateway provided using native jexec syscall
        if let Some(gw) = gateway {
            let (exit_code, _stdout, stderr) = jexec_with_output(jid, &["route", "add", "default", gw])
                .map_err(|e| Error::Network(format!("Failed to add route: {}", e)))?;

            if exit_code != 0 {
                let stderr_str = String::from_utf8_lossy(&stderr);
                // Don't fail if route already exists
                if !stderr_str.contains("File exists") {
                    return Err(Error::Network(format!(
                        "Failed to add default route in jail {}: {}",
                        jid, stderr_str
                    )));
                }
            }
        }

        Ok(())
    }

    /// Destroy the epair using ioctl (destroys both ends)
    pub fn destroy(&self) -> Result<()> {
        // Destroying either end destroys both
        // Ignore error if already destroyed
        ioctl::destroy_interface(&self.host_side).or_else(|e| {
            if e.to_string().contains("does not exist") {
                Ok(())
            } else {
                Err(e)
            }
        })
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
