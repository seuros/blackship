//! Port forwarding via PF firewall

use std::net::IpAddr;

use crate::bulkhead::{BulkheadManager, PortForward};
use crate::error::{Error, Result};

use super::Bridge;

impl Bridge {
    /// Initialize the PF firewall anchor for port forwarding
    pub fn init_bulkhead(&self) -> Result<()> {
        BulkheadManager::init()
    }

    /// Re-apply persisted PF rules to the anchor.
    pub fn sync_bulkhead(&self) -> Result<()> {
        self.bulkhead.sync_rules()
    }

    /// Expose a port from a jail to the host
    pub fn expose_port(
        &mut self,
        jail_name: &str,
        external_port: u16,
        internal_port: Option<u16>,
        protocol: &str,
        bind_ip: Option<IpAddr>,
    ) -> Result<PortForward> {
        let (service_name, full_name) = self.resolve_jail_names(jail_name)?;
        let jail_def = self
            .config
            .get_jail(&service_name)
            .ok_or_else(|| Error::JailNotFound(jail_name.to_string()))?;

        let jail_ip = if let Some(ip) = jail_def.network.as_ref().and_then(|network| network.ip) {
            ip
        } else if let Some((_, ip)) = self.allocated_ips.get(&full_name) {
            *ip
        } else if let Some(network_cfg) = jail_def.network.as_ref() {
            let mut leased_ip = None;
            for network_name in &network_cfg.networks {
                for lease in self.lease_store.list(network_name)? {
                    if lease.owner == full_name {
                        leased_ip = Some(lease.ip.parse().map_err(|e| {
                            Error::Network(format!(
                                "Invalid leased IP '{}' for jail '{}': {}",
                                lease.ip, full_name, e
                            ))
                        })?);
                        break;
                    }
                }

                if leased_ip.is_some() {
                    break;
                }
            }

            leased_ip.ok_or_else(|| {
                Error::Network(format!("Jail '{}' has no IP address configured", full_name))
            })?
        } else {
            return Err(Error::Network(format!(
                "Jail '{}' has no IP address configured",
                full_name
            )));
        };

        let internal = internal_port.unwrap_or(external_port);
        let mut forward = PortForward::new(external_port, internal, protocol, jail_ip, &full_name);

        if let Some(ip) = bind_ip {
            forward = forward.with_bind_ip(ip);
        }

        self.bulkhead.add_forward(forward.clone())?;

        if self.verbose {
            println!(
                "Exposed port {}:{}/{} -> {}:{}",
                bind_ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "*".to_string()),
                external_port,
                protocol,
                jail_ip,
                internal
            );
        }

        Ok(forward)
    }

    /// Remove all port forwards for a jail
    pub fn remove_port_forwards(&mut self, jail_name: &str) -> Result<()> {
        let (_service_name, full_name) = self.resolve_jail_names(jail_name)?;
        self.bulkhead.remove_jail_forwards(&full_name)?;

        if self.verbose {
            println!("Removed port forwards for jail '{}'", full_name);
        }

        Ok(())
    }

    /// List all active port forwards
    pub fn list_port_forwards(&self) -> &[PortForward] {
        self.bulkhead.list_forwards()
    }

    /// Get port forwards for a specific jail
    pub fn get_jail_port_forwards(&self, jail_name: &str) -> Vec<&PortForward> {
        if let Some((_service_name, full_name)) = self.config.resolve_jail_names(jail_name) {
            self.bulkhead.get_jail_forwards(&full_name)
        } else {
            Vec::new()
        }
    }
}
