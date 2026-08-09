//! DNS configuration for jails

use std::path::Path;

use crate::error::{Error, Result};
use crate::manifest::DnsConfig;

use super::Bridge;

/// Write a path without following symlinks: unlink first, then O_CREAT|O_EXCL (TOCTOU).
fn write_nofollow(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let _ = std::fs::remove_file(path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::JailOperation(format!(
                "Failed to create directory {}: {}",
                parent.display(),
                e
            ))
        })?;
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| Error::JailOperation(format!("Failed to create {}: {}", path.display(), e)))?;
    f.write_all(data)
        .map_err(|e| Error::JailOperation(format!("Failed to write {}: {}", path.display(), e)))
}

impl Bridge {
    /// Configure DNS in a jail
    pub(super) fn configure_dns(&self, jail_path: &Path, dns_config: &DnsConfig) -> Result<()> {
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
            let content = std::fs::read("/etc/resolv.conf").map_err(|e| {
                Error::JailOperation(format!("Failed to read /etc/resolv.conf: {}", e))
            })?;
            write_nofollow(&resolv_path, &content)?;
        } else if let Some(content) = dns_config.to_resolv_conf() {
            write_nofollow(&resolv_path, content.as_bytes())?;
        }

        Ok(())
    }
}
