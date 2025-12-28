//! Firewall management for jail port forwarding
//!
//! Uses PF (Packet Filter) anchors to manage RDR rules without
//! modifying the host's pf.conf.

use crate::error::{Error, Result};
use std::net::IpAddr;
use std::process::Command;

/// PF anchor name for blackship rules

const PF_ANCHOR: &str = "blackship";

/// Port forwarding rule
#[derive(Debug, Clone)]
pub struct PortForward {
    /// External port to listen on
    pub external_port: u16,
    /// Internal (jail) port to forward to
    pub internal_port: u16,
    /// Protocol (tcp, udp)
    pub protocol: String,
    /// Jail IP address
    pub jail_ip: IpAddr,
    /// Bind to specific external IP (None = all interfaces)
    pub bind_ip: Option<IpAddr>,
    /// Jail name (for identification)
    pub jail_name: String,
}

impl PortForward {
    /// Create a new port forward rule
    pub fn new(
        external_port: u16,
        internal_port: u16,
        protocol: &str,
        jail_ip: IpAddr,
        jail_name: &str,
    ) -> Self {
        Self {
            external_port,
            internal_port,
            protocol: protocol.to_string(),
            jail_ip,
            bind_ip: None,
            jail_name: jail_name.to_string(),
        }
    }

    /// Bind to a specific external IP
    pub fn with_bind_ip(mut self, ip: IpAddr) -> Self {
        self.bind_ip = Some(ip);
        self
    }

    /// Generate PF RDR rule
    pub fn to_pf_rule(&self) -> String {
        let bind = match &self.bind_ip {
            Some(ip) => format!("on {} ", ip),
            None => String::new(),
        };

        format!(
            "rdr {}proto {} from any to any port {} -> {} port {} # jail:{}",
            bind,
            self.protocol,
            self.external_port,
            self.jail_ip,
            self.internal_port,
            self.jail_name
        )
    }
}

/// Bulkhead manager for PF
#[derive(Debug, Default)]
pub struct BulkheadManager {
    /// Active port forwards 
    
    forwards: Vec<PortForward>,
}

impl BulkheadManager {
    /// Create a new bulkhead manager 
    
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialize the PF anchor
    ///
    /// This should be called once at startup. The host's pf.conf must include:
    /// ```text
    /// rdr-anchor "blackship"
    /// anchor "blackship"
    /// ```
    
    pub fn init() -> Result<()> {
        // Check if PF is enabled
        let output = Command::new("pfctl")
            .args(["-s", "info"])
            .output()
            .map_err(|e| Error::Network(format!("Failed to check PF status: {}", e)))?;

        if !output.status.success() {
            return Err(Error::Network(
                "PF is not running. Enable it with: service pf start".to_string(),
            ));
        }

        // Check if our anchor exists (it's ok if it doesn't have rules yet)
        let output = Command::new("pfctl")
            .args(["-a", PF_ANCHOR, "-s", "rules"])
            .output()
            .map_err(|e| Error::Network(format!("Failed to check anchor: {}", e)))?;

        // If the anchor doesn't exist in pf.conf, warn the user
        if !output.status.success() {
            eprintln!("Warning: PF anchor '{}' may not be configured.", PF_ANCHOR);
            eprintln!("Add these lines to /etc/pf.conf:");
            eprintln!("  rdr-anchor \"{}\"", PF_ANCHOR);
            eprintln!("  anchor \"{}\"", PF_ANCHOR);
        }

        Ok(())
    }

    /// Add a port forward rule 
    
    pub fn add_forward(&mut self, forward: PortForward) -> Result<()> {
        // Add to our list
        self.forwards.push(forward);

        // Apply all rules
        self.apply_rules()
    }

    /// Remove port forwards for a jail 
    
    pub fn remove_jail_forwards(&mut self, jail_name: &str) -> Result<()> {
        self.forwards.retain(|f| f.jail_name != jail_name);
        self.apply_rules()
    }

    /// Apply all rules to the PF anchor 
    
    fn apply_rules(&self) -> Result<()> {
        // Generate rules
        let rules: Vec<String> = self.forwards.iter().map(|f| f.to_pf_rule()).collect();
        let rules_text = rules.join("\n");

        // Apply to anchor using pfctl
        let mut child = Command::new("pfctl")
            .args(["-a", PF_ANCHOR, "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| Error::Network(format!("Failed to run pfctl: {}", e)))?;

        if let Some(stdin) = child.stdin.as_mut() {
            use std::io::Write;
            stdin
                .write_all(rules_text.as_bytes())
                .map_err(|e| Error::Network(format!("Failed to write rules: {}", e)))?;
        }

        let output = child
            .wait_with_output()
            .map_err(|e| Error::Network(format!("Failed to wait for pfctl: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Network(format!("pfctl failed: {}", stderr)));
        }

        Ok(())
    }

    /// List current port forwards 
    
    pub fn list_forwards(&self) -> &[PortForward] {
        &self.forwards
    }

    /// Get forwards for a specific jail 
    
    pub fn get_jail_forwards(&self, jail_name: &str) -> Vec<&PortForward> {
        self.forwards
            .iter()
            .filter(|f| f.jail_name == jail_name)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_forward_rule() {
        let forward = PortForward::new(8080, 80, "tcp", "10.0.1.10".parse().unwrap(), "webserver");

        let rule = forward.to_pf_rule();
        assert!(rule.contains("rdr"));
        assert!(rule.contains("proto tcp"));
        assert!(rule.contains("port 8080"));
        assert!(rule.contains("-> 10.0.1.10"));
        assert!(rule.contains("port 80"));
        assert!(rule.contains("# jail:webserver"));
    }

    #[test]
    fn test_port_forward_with_bind_ip() {
        let forward = PortForward::new(443, 443, "tcp", "10.0.1.10".parse().unwrap(), "webserver")
            .with_bind_ip("192.168.1.100".parse().unwrap());

        let rule = forward.to_pf_rule();
        assert!(rule.contains("on 192.168.1.100"));
    }

    #[test]
    fn test_port_forward_creation() {
        let forward = PortForward::new(
            3000,
            3000,
            "tcp",
            "10.0.1.5".parse().unwrap(),
            "myjail",
        );

        assert_eq!(forward.external_port, 3000);
        assert_eq!(forward.internal_port, 3000);
        assert_eq!(forward.jail_name, "myjail");
        assert_eq!(forward.protocol, "tcp");
    }

    #[test]
    fn test_bulkhead_manager() {
        let manager = BulkheadManager::new();
        assert_eq!(manager.list_forwards().len(), 0);
    }
}
