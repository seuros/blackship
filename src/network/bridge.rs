//! Bridge interface management
//!
//! Provides:
//! - Creation and destruction of bridge interfaces
//! - Adding/removing member interfaces
//! - Bridge configuration

use crate::error::{Error, Result};
use crate::network::ioctl;
use std::ffi::CString;

// FreeBSD kldload syscall - not in libc crate
unsafe extern "C" {
    fn kldload(file: *const libc::c_char) -> libc::c_int;
}

/// A bridge interface
#[derive(Debug, Clone)]
pub struct Bridge {
    /// Bridge interface name (e.g., "blackship0")
    name: String,
}

impl Bridge {
    /// Create a new bridge interface
    pub fn create(name: &str) -> Result<Self> {
        // Check if bridge already exists
        if Self::exists(name)? {
            return Err(Error::BridgeAlreadyExists(name.to_string()));
        }

        // Load required kernel modules
        Self::load_modules()?;

        // Create bridge using native ioctl
        ioctl::create_interface("bridge", Some(name))?;

        // Bring interface up using native ioctl
        ioctl::set_interface_up(name, true)?;

        Ok(Self {
            name: name.to_string(),
        })
    }

    /// Open an existing bridge interface
    pub fn open(name: &str) -> Result<Self> {
        if !Self::exists(name)? {
            return Err(Error::InterfaceNotFound(name.to_string()));
        }

        Ok(Self {
            name: name.to_string(),
        })
    }

    /// Create or open an existing bridge
    pub fn create_or_open(name: &str) -> Result<Self> {
        if Self::exists(name)? {
            Self::open(name)
        } else {
            Self::create(name)
        }
    }

    /// Get bridge name (_unused: future feature)
    #[allow(dead_code)]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Check if a bridge exists
    pub fn exists(name: &str) -> Result<bool> {
        // Use native ioctl to check if interface exists
        ioctl::interface_exists(name)
    }

    /// Destroy the bridge interface
    pub fn destroy(&self) -> Result<()> {
        // Use native ioctl to destroy interface
        ioctl::destroy_interface(&self.name)
    }

    /// Add a member interface to the bridge (_unused: future feature)
    #[allow(dead_code)]
    pub fn add_member(&self, interface: &str) -> Result<()> {
        // Use native ioctl to add member to bridge
        ioctl::bridge_add_member(&self.name, interface)
    }

    /// Remove a member interface from the bridge (_unused: future feature)
    #[allow(dead_code)]
    pub fn remove_member(&self, interface: &str) -> Result<()> {
        // Use native ioctl to remove member from bridge
        ioctl::bridge_delete_member(&self.name, interface)
    }

    /// Set an IP address on the bridge
    ///
    /// Uses native SIOCSIFADDR ioctl syscall.
    pub fn set_address(&self, addr: &str) -> Result<()> {
        ioctl::set_ipv4_address(&self.name, addr)
    }

    /// Enable VLAN filtering on the bridge (FreeBSD 15.0+)
    ///
    /// Uses native SIOCSDRVSPEC ioctl with BRDGSFLAGS command.
    pub fn enable_vlan_filtering(&self) -> Result<()> {
        ioctl::bridge_enable_vlan_filtering(&self.name)
    }

    /// Add a trunk member with tagged VLANs (FreeBSD 15.0+)
    ///
    /// The interface is added to the bridge with specified tagged VLAN IDs.
    /// Uses native SIOCSDRVSPEC ioctls for bridge member add and VLAN set.
    pub fn add_trunk_member(&self, interface: &str, tagged_vlans: &[u16]) -> Result<()> {
        if tagged_vlans.is_empty() {
            return Err(Error::Network(
                "At least one tagged VLAN required for trunk".to_string(),
            ));
        }

        // First add the member to the bridge
        ioctl::bridge_add_member(&self.name, interface)?;

        // Then set the tagged VLANs
        ioctl::bridge_set_tagged_vlans(&self.name, interface, tagged_vlans)
    }

    /// Add a member interface with untagged VLAN (PVID) (FreeBSD 15.0+)
    ///
    /// The interface is added as an access port with the specified VLAN ID.
    /// Uses native SIOCSDRVSPEC ioctls for bridge member add and PVID set.
    pub fn add_member_untagged(&self, interface: &str, vlan_id: u16) -> Result<()> {
        // First add the member to the bridge
        ioctl::bridge_add_member(&self.name, interface)?;

        // Then set the PVID
        ioctl::bridge_set_pvid(&self.name, interface, vlan_id)
    }

    /// Disable hardware VLAN filtering on an interface
    ///
    /// Some NICs (especially Broadcom) have buggy VLAN hardware filtering.
    /// Uses native SIOCGIFCAP/SIOCSIFCAP ioctls to clear IFCAP_VLAN_HWFILTER.
    pub fn disable_hwfilter(interface: &str) -> Result<()> {
        ioctl::disable_hwfilter(interface)
    }

    /// List member interfaces
    ///
    /// Uses native SIOCGDRVSPEC ioctl with BRDGGIFS command.
    pub fn members(&self) -> Result<Vec<String>> {
        ioctl::bridge_list_members(&self.name)
    }

    /// Load required kernel modules for bridging using native syscall
    fn load_modules() -> Result<()> {
        let modules = ["if_bridge", "bridgestp", "if_epair"];

        for module in modules {
            let module_cstr = CString::new(module).map_err(|e| {
                Error::Network(format!("Invalid module name {}: {}", module, e))
            })?;

            // Use native kldload(2) syscall instead of spawning process
            let result = unsafe { kldload(module_cstr.as_ptr()) };

            if result < 0 {
                let err = std::io::Error::last_os_error();
                let errno = err.raw_os_error().unwrap_or(0);

                // Ignore if module is already loaded (EEXIST) or built-in (ENOENT)
                if errno != libc::EEXIST && errno != libc::ENOENT {
                    return Err(Error::Network(format!(
                        "Failed to load module {}: {}",
                        module, err
                    )));
                }
            }
        }

        Ok(())
    }
}

/// Destroy a bridge interface
///
/// If `force` is false and the bridge has members attached, returns an error.
/// If `force` is true, destroys the bridge even if it has members.
pub fn destroy_bridge(name: &str, force: bool) -> Result<()> {
    // Check if bridge exists
    if !Bridge::exists(name)? {
        return Err(Error::InterfaceNotFound(name.to_string()));
    }

    let bridge = Bridge::open(name)?;

    // Check for members if not forcing
    let members = bridge.members()?;
    if !members.is_empty() && !force {
        return Err(Error::Network(format!(
            "Bridge '{}' has {} member(s) attached: {}. Use --force to destroy anyway.",
            name,
            members.len(),
            members.join(", ")
        )));
    }

    // Destroy the bridge
    bridge.destroy()
}

/// List all bridge interfaces on the system
///
/// Uses native if_nameindex(3) to enumerate interfaces.
pub fn list_bridges() -> Result<Vec<String>> {
    ioctl::list_bridges()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_exists_check() {
        // lo0 should always exist
        assert!(Bridge::exists("lo0").unwrap());
        // random name should not exist
        assert!(!Bridge::exists("nonexistent12345").unwrap());
    }
}
