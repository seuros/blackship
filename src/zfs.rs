//! ZFS dataset management for jail roots
//!
//! Provides basic ZFS operations:
//! - Create datasets for jails
//! - Set compression and other properties
//! - Destroy datasets on jail removal

use crate::error::{Error, Result};
use std::path::PathBuf;
use std::process::Command;

/// ZFS dataset manager
pub struct ZfsManager {
    /// ZFS pool name (_unused: future feature)
    #[allow(dead_code)]
    pool: String,
    /// Base dataset name (e.g., "blackship")
    base_dataset: String,
}

impl ZfsManager {
    /// Create a new ZFS manager
    pub fn new(pool: impl Into<String>, base: impl Into<String>) -> Self {
        let pool = pool.into();
        let base = base.into();
        Self {
            base_dataset: format!("{}/{}", pool, base),
            pool,
        }
    }

    /// Get the full dataset path for jails
    fn jails_dataset(&self) -> String {
        format!("{}/jails", self.base_dataset)
    }

    /// Get the dataset name for a specific jail
    fn jail_dataset(&self, name: &str) -> String {
        format!("{}/{}", self.jails_dataset(), name)
    }

    /// Get the mountpoint path for a jail
    pub fn jail_path(&self, name: &str) -> PathBuf {
        PathBuf::from(format!("/{}/{}", self.jails_dataset(), name))
    }

    /// Initialize the base dataset structure
    ///
    /// Creates: pool/blackship and pool/blackship/jails
    pub fn init(&self) -> Result<()> {
        // Create base dataset if it doesn't exist
        if !self.dataset_exists(&self.base_dataset)? {
            self.create_dataset(&self.base_dataset)?;
        }

        // Create jails dataset if it doesn't exist
        let jails = self.jails_dataset();
        if !self.dataset_exists(&jails)? {
            self.create_dataset(&jails)?;
        }

        Ok(())
    }

    /// Check if a dataset exists
    pub fn dataset_exists(&self, dataset: &str) -> Result<bool> {
        let output = Command::new("zfs")
            .args(["list", "-H", "-o", "name", dataset])
            .output()
            .map_err(|e| Error::Zfs(format!("Failed to run zfs list: {}", e)))?;

        Ok(output.status.success())
    }

    /// Create a dataset with default properties
    fn create_dataset(&self, dataset: &str) -> Result<()> {
        let status = Command::new("zfs")
            .args(["create", "-p", "-o", "compression=lz4", dataset])
            .status()
            .map_err(|e| Error::Zfs(format!("Failed to run zfs create: {}", e)))?;

        if status.success() {
            Ok(())
        } else {
            Err(Error::Zfs(format!(
                "Failed to create dataset '{}'",
                dataset
            )))
        }
    }

    /// Create a dataset for a jail
    ///
    /// Creates: pool/blackship/jails/<name>
    pub fn create_jail_dataset(&self, name: &str) -> Result<PathBuf> {
        let dataset = self.jail_dataset(name);

        if self.dataset_exists(&dataset)? {
            return Err(Error::Zfs(format!(
                "Dataset '{}' already exists",
                dataset
            )));
        }

        self.create_dataset(&dataset)?;
        Ok(self.jail_path(name))
    }

    /// Destroy a jail's dataset
    ///
    /// Warning: This recursively destroys all child datasets
    pub fn destroy_jail_dataset(&self, name: &str) -> Result<()> {
        let dataset = self.jail_dataset(name);

        if !self.dataset_exists(&dataset)? {
            // Already gone, nothing to do
            return Ok(());
        }

        let status = Command::new("zfs")
            .args(["destroy", "-r", &dataset])
            .status()
            .map_err(|e| Error::Zfs(format!("Failed to run zfs destroy: {}", e)))?;

        if status.success() {
            Ok(())
        } else {
            Err(Error::Zfs(format!(
                "Failed to destroy dataset '{}'",
                dataset
            )))
        }
    }

    /// Get dataset properties
    /// Get a ZFS property value (_unused: future feature)
    #[allow(dead_code)]
    pub fn get_property(&self, dataset: &str, property: &str) -> Result<String> {
        let output = Command::new("zfs")
            .args(["get", "-H", "-o", "value", property, dataset])
            .output()
            .map_err(|e| Error::Zfs(format!("Failed to run zfs get: {}", e)))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err(Error::Zfs(format!(
                "Failed to get property '{}' for dataset '{}'",
                property, dataset
            )))
        }
    }

    /// Set a dataset property (_unused: future feature)
    #[allow(dead_code)]
    pub fn set_property(&self, dataset: &str, property: &str, value: &str) -> Result<()> {
        let status = Command::new("zfs")
            .args(["set", &format!("{}={}", property, value), dataset])
            .status()
            .map_err(|e| Error::Zfs(format!("Failed to run zfs set: {}", e)))?;

        if status.success() {
            Ok(())
        } else {
            Err(Error::Zfs(format!(
                "Failed to set property '{}={}' for dataset '{}'",
                property, value, dataset
            )))
        }
    }

    /// Create a snapshot of a jail
    ///
    /// If no name is provided, generates one with timestamp
    pub fn create_snapshot(&self, jail: &str, name: Option<&str>) -> Result<String> {
        let dataset = self.jail_dataset(jail);

        if !self.dataset_exists(&dataset)? {
            return Err(Error::Zfs(format!(
                "Jail dataset '{}' does not exist",
                jail
            )));
        }

        let snap_name = match name {
            Some(n) => n.to_string(),
            None => {
                use std::time::{SystemTime, UNIX_EPOCH};
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                format!("snap-{}", ts)
            }
        };

        let snapshot = format!("{}@{}", dataset, snap_name);

        let status = Command::new("zfs")
            .args(["snapshot", "-r", &snapshot])
            .status()
            .map_err(|e| Error::Zfs(format!("Failed to run zfs snapshot: {}", e)))?;

        if status.success() {
            Ok(snap_name)
        } else {
            Err(Error::Zfs(format!(
                "Failed to create snapshot '{}'",
                snapshot
            )))
        }
    }

    /// List snapshots for a jail
    pub fn list_snapshots(&self, jail: &str) -> Result<Vec<SnapshotInfo>> {
        let dataset = self.jail_dataset(jail);

        if !self.dataset_exists(&dataset)? {
            return Err(Error::Zfs(format!(
                "Jail dataset '{}' does not exist",
                jail
            )));
        }

        let output = Command::new("zfs")
            .args([
                "list",
                "-H",
                "-t",
                "snapshot",
                "-o",
                "name,creation,used,refer",
                "-r",
                &dataset,
            ])
            .output()
            .map_err(|e| Error::Zfs(format!("Failed to run zfs list: {}", e)))?;

        if !output.status.success() {
            return Err(Error::Zfs("Failed to list snapshots".into()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut snapshots = Vec::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 4 {
                // Extract snapshot name from full path (pool/blackship/jails/foo@snap -> snap)
                let full_name = parts[0];
                if let Some(at_pos) = full_name.find('@') {
                    let name = &full_name[at_pos + 1..];
                    snapshots.push(SnapshotInfo {
                        name: name.to_string(),
                        creation: parts[1].to_string(),
                        used: parts[2].to_string(),
                        refer: parts[3].to_string(),
                    });
                }
            }
        }

        Ok(snapshots)
    }

    /// Rollback a jail to a snapshot
    ///
    /// Warning: This destroys all data newer than the snapshot
    pub fn rollback_snapshot(&self, jail: &str, snapshot: &str, force: bool) -> Result<()> {
        let dataset = self.jail_dataset(jail);
        let snapshot_full = format!("{}@{}", dataset, snapshot);

        // Check if snapshot exists
        let output = Command::new("zfs")
            .args(["list", "-H", "-t", "snapshot", &snapshot_full])
            .output()
            .map_err(|e| Error::Zfs(format!("Failed to check snapshot: {}", e)))?;

        if !output.status.success() {
            return Err(Error::Zfs(format!(
                "Snapshot '{}' does not exist",
                snapshot
            )));
        }

        let mut args = vec!["rollback"];
        if force {
            args.push("-r"); // Destroy later snapshots
        }
        args.push(&snapshot_full);

        let status = Command::new("zfs")
            .args(&args)
            .status()
            .map_err(|e| Error::Zfs(format!("Failed to run zfs rollback: {}", e)))?;

        if status.success() {
            Ok(())
        } else {
            Err(Error::Zfs(format!(
                "Failed to rollback to snapshot '{}'. Use --force to destroy newer snapshots.",
                snapshot
            )))
        }
    }

    /// Delete a snapshot
    pub fn delete_snapshot(&self, jail: &str, snapshot: &str) -> Result<()> {
        let dataset = self.jail_dataset(jail);
        let snapshot_full = format!("{}@{}", dataset, snapshot);

        let status = Command::new("zfs")
            .args(["destroy", &snapshot_full])
            .status()
            .map_err(|e| Error::Zfs(format!("Failed to run zfs destroy: {}", e)))?;

        if status.success() {
            Ok(())
        } else {
            Err(Error::Zfs(format!(
                "Failed to delete snapshot '{}'",
                snapshot
            )))
        }
    }

    /// Clone a jail from a snapshot
    ///
    /// Creates a new jail from an existing jail's snapshot
    pub fn clone_from_snapshot(
        &self,
        source_jail: &str,
        snapshot: &str,
        new_jail: &str,
    ) -> Result<PathBuf> {
        let source_dataset = self.jail_dataset(source_jail);
        let snapshot_full = format!("{}@{}", source_dataset, snapshot);
        let target_dataset = self.jail_dataset(new_jail);

        // Check if snapshot exists
        let output = Command::new("zfs")
            .args(["list", "-H", "-t", "snapshot", &snapshot_full])
            .output()
            .map_err(|e| Error::Zfs(format!("Failed to check snapshot: {}", e)))?;

        if !output.status.success() {
            return Err(Error::Zfs(format!(
                "Snapshot '{}@{}' does not exist",
                source_jail, snapshot
            )));
        }

        // Check if target already exists
        if self.dataset_exists(&target_dataset)? {
            return Err(Error::Zfs(format!(
                "Jail '{}' already exists",
                new_jail
            )));
        }

        let status = Command::new("zfs")
            .args(["clone", &snapshot_full, &target_dataset])
            .status()
            .map_err(|e| Error::Zfs(format!("Failed to run zfs clone: {}", e)))?;

        if status.success() {
            Ok(self.jail_path(new_jail))
        } else {
            Err(Error::Zfs(format!(
                "Failed to clone snapshot '{}' to '{}'",
                snapshot_full, new_jail
            )))
        }
    }

    /// Get the dataset name for a jail (public accessor) (_unused: future feature)
    #[allow(dead_code)]
    pub fn get_jail_dataset(&self, name: &str) -> String {
        self.jail_dataset(name)
    }
}

/// Information about a ZFS snapshot
#[derive(Debug, Clone)]
pub struct SnapshotInfo {
    /// Snapshot name (without dataset prefix)
    pub name: String,
    /// Creation timestamp
    pub creation: String,
    /// Space used by snapshot
    pub used: String,
    /// Referenced space
    pub refer: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dataset_paths() {
        let zfs = ZfsManager::new("zroot", "blackship");
        assert_eq!(zfs.jails_dataset(), "zroot/blackship/jails");
        assert_eq!(zfs.jail_dataset("test"), "zroot/blackship/jails/test");
        assert_eq!(
            zfs.jail_path("test"),
            PathBuf::from("/zroot/blackship/jails/test")
        );
    }
}
