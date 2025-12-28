//! Bridge interface management
//!
//! Provides:
//! - Creation and destruction of bridge interfaces
//! - Adding/removing member interfaces
//! - Bridge configuration

use crate::error::{Error, Result};
use std::process::Command;

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

        // Create bridge
        let output = Command::new("ifconfig")
            .args(["bridge", "create", "name", name])
            .output()
            .map_err(|e| Error::Network(format!("Failed to create bridge: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Network(format!(
                "Failed to create bridge {}: {}",
                name, stderr
            )));
        }

        // Bring interface up
        let output = Command::new("ifconfig")
            .args([name, "up"])
            .output()
            .map_err(|e| Error::Network(format!("Failed to bring up bridge: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Network(format!(
                "Failed to bring up bridge {}: {}",
                name, stderr
            )));
        }

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
        let output = Command::new("ifconfig")
            .arg(name)
            .output()
            .map_err(|e| Error::Network(format!("Failed to check interface: {}", e)))?;

        Ok(output.status.success())
    }

    /// Destroy the bridge interface
    pub fn destroy(&self) -> Result<()> {
        let output = Command::new("ifconfig")
            .args([&self.name, "destroy"])
            .output()
            .map_err(|e| Error::Network(format!("Failed to destroy bridge: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Network(format!(
                "Failed to destroy bridge {}: {}",
                self.name, stderr
            )));
        }

        Ok(())
    }

    /// Add a member interface to the bridge (_unused: future feature)
    #[allow(dead_code)]
    pub fn add_member(&self, interface: &str) -> Result<()> {
        let output = Command::new("ifconfig")
            .args([&self.name, "addm", interface])
            .output()
            .map_err(|e| Error::Network(format!("Failed to add member: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Network(format!(
                "Failed to add {} to bridge {}: {}",
                interface, self.name, stderr
            )));
        }

        Ok(())
    }

    /// Remove a member interface from the bridge (_unused: future feature)
    #[allow(dead_code)]
    pub fn remove_member(&self, interface: &str) -> Result<()> {
        let output = Command::new("ifconfig")
            .args([&self.name, "deletem", interface])
            .output()
            .map_err(|e| Error::Network(format!("Failed to remove member: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Network(format!(
                "Failed to remove {} from bridge {}: {}",
                interface, self.name, stderr
            )));
        }

        Ok(())
    }

    /// Set an IP address on the bridge
    pub fn set_address(&self, addr: &str) -> Result<()> {
        let output = Command::new("ifconfig")
            .args([&self.name, addr])
            .output()
            .map_err(|e| Error::Network(format!("Failed to set address: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Network(format!(
                "Failed to set address on {}: {}",
                self.name, stderr
            )));
        }

        Ok(())
    }

    /// List member interfaces
    pub fn members(&self) -> Result<Vec<String>> {
        let output = Command::new("ifconfig")
            .arg(&self.name)
            .output()
            .map_err(|e| Error::Network(format!("Failed to get bridge info: {}", e)))?;

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut members = Vec::new();

        for line in stdout.lines() {
            let line = line.trim();
            if line.starts_with("member:")
                && let Some(iface) = line.split_whitespace().nth(1) {
                    members.push(iface.to_string());
                }
        }

        Ok(members)
    }

    /// Load required kernel modules for bridging
    fn load_modules() -> Result<()> {
        let modules = ["if_bridge", "bridgestp", "if_epair"];

        for module in modules {
            let output = Command::new("kldload").arg(module).output().map_err(|e| {
                Error::Network(format!("Failed to load module {}: {}", module, e))
            })?;

            // Ignore "already loaded" errors (exit code 1 with specific message)
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("already loaded") && !stderr.contains("module already loaded") {
                    // Not an error if module is built-in or already loaded
                    if stderr.contains("No such file") {
                        // Module might be built into kernel, that's fine
                        continue;
                    }
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
pub fn list_bridges() -> Result<Vec<String>> {
    let output = Command::new("ifconfig")
        .args(["-l", "-g", "bridge"])
        .output()
        .map_err(|e| Error::Network(format!("Failed to list bridges: {}", e)))?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.split_whitespace().map(String::from).collect())
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
