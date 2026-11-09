//! DNS configuration for jails

use std::path::Path;

use crate::error::{Error, Result};
use crate::manifest::DnsConfig;

/// Configure DNS in a jail
pub(super) fn configure_dns(jail_path: &Path, dns_config: &DnsConfig) -> Result<()> {
    let resolv_path = jail_path.join("etc/resolv.conf");

    // Reject symlinked intermediate dirs that could escape the jail root.
    let relative = std::path::Path::new("etc/resolv.conf");
    let mut current = jail_path.to_path_buf();
    for component in relative.components() {
        current.push(component);
        if !current.exists() {
            break;
        }
        if let Ok(meta) = std::fs::symlink_metadata(&current)
            && meta.file_type().is_symlink()
        {
            eprintln!(
                "Warning: {} is a symlink, skipping DNS configuration",
                current.display()
            );
            return Ok(());
        }
    }

    if dns_config.is_inherit() {
        let content = std::fs::read("/etc/resolv.conf")
            .map_err(|e| Error::JailOperation(format!("Failed to read /etc/resolv.conf: {e}")))?;
        crate::sys::write_nofollow(&resolv_path, &content)?;
    } else if let Some(content) = dns_config.to_resolv_conf() {
        crate::sys::write_nofollow(&resolv_path, content.as_bytes())?;
    }

    Ok(())
}
