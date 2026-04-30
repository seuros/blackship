//! DNS configuration for jails

use std::path::Path;

use crate::error::{Error, Result};
use crate::manifest::DnsConfig;

use super::Bridge;

impl Bridge {
    /// Configure DNS in a jail
    pub(super) fn configure_dns(&self, jail_path: &Path, dns_config: &DnsConfig) -> Result<()> {
        let resolv_path = jail_path.join("etc/resolv.conf");

        if dns_config.is_inherit() {
            std::fs::copy("/etc/resolv.conf", &resolv_path)
                .map_err(|e| Error::JailOperation(format!("Failed to copy resolv.conf: {}", e)))?;
        } else if let Some(content) = dns_config.to_resolv_conf() {
            std::fs::write(&resolv_path, content)
                .map_err(|e| Error::JailOperation(format!("Failed to write resolv.conf: {}", e)))?;
        }

        Ok(())
    }
}
