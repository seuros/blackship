//! ZFS dataset management for jail roots
//!
//! Provides basic ZFS operations:
//! - Create datasets for jails
//! - Set compression and other properties
//! - Destroy datasets on jail removal

use crate::error::{Error, Result};
use jiff::Zoned;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Spawn /sbin/zfs and wait for its exit status.
fn zfs_status(args: &[&str]) -> Result<std::process::ExitStatus> {
    Command::new("/sbin/zfs").args(args).status().map_err(|e| {
        Error::Zfs(format!(
            "Failed to run zfs {}: {}",
            args.first().unwrap_or(&"?"),
            e
        ))
    })
}

/// Spawn /sbin/zfs and capture its output.
fn zfs_output(args: &[&str]) -> Result<std::process::Output> {
    Command::new("/sbin/zfs").args(args).output().map_err(|e| {
        Error::Zfs(format!(
            "Failed to run zfs {}: {}",
            args.first().unwrap_or(&"?"),
            e
        ))
    })
}

/// Run a zfs command, mapping a non-zero exit to the given error message.
fn zfs_run(args: &[&str], fail_msg: impl FnOnce() -> String) -> Result<()> {
    if zfs_status(args)?.success() {
        Ok(())
    } else {
        Err(Error::Zfs(fail_msg()))
    }
}

/// ZFS dataset manager
pub struct ZfsManager {
    /// ZFS pool name (_unused: future feature)
    #[allow(dead_code)]
    pool: String,
    /// Base dataset name (e.g., "blackship")
    base_dataset: String,
    /// Where the jails dataset is mounted (data_dir/jails), so ZFS and
    /// plain-directory jail roots resolve to the same paths.
    jails_mountpoint: PathBuf,
}

impl ZfsManager {
    /// Create a new ZFS manager
    pub fn new(
        pool: impl Into<String>,
        base: impl Into<String>,
        jails_mountpoint: impl Into<PathBuf>,
    ) -> Self {
        let pool = pool.into();
        let base = base.into();
        Self {
            base_dataset: format!("{}/{}", pool, base),
            pool,
            jails_mountpoint: jails_mountpoint.into(),
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

    /// Public dataset name for a jail (pool/base/jails/<name>)
    pub fn jail_dataset_name(&self, name: &str) -> String {
        self.jail_dataset(name)
    }

    /// Get the mountpoint path for a jail
    pub fn jail_path(&self, name: &str) -> PathBuf {
        self.jails_mountpoint.join(name)
    }

    /// Initialize the base dataset structure
    ///
    /// Creates: pool/blackship and pool/blackship/jails, with the jails
    /// dataset mounted at data_dir/jails so every jail root lives at the
    /// same path whether or not it is a dataset.
    pub fn init(&self) -> Result<()> {
        // Create base dataset if it doesn't exist
        if !self.dataset_exists(&self.base_dataset)? {
            self.create_dataset(&self.base_dataset)?;
        }

        let jails = self.jails_dataset();
        let mountpoint = self.jails_mountpoint.display().to_string();
        if !self.dataset_exists(&jails)? {
            self.create_dataset(&jails)?;
        }
        self.set_property(&jails, "mountpoint", &mountpoint)?;

        Ok(())
    }

    /// Check if a dataset exists
    pub fn dataset_exists(&self, dataset: &str) -> Result<bool> {
        Ok(zfs_output(&["list", "-H", "-o", "name", dataset])?
            .status
            .success())
    }

    /// Create a dataset with default properties
    fn create_dataset(&self, dataset: &str) -> Result<()> {
        zfs_run(&["create", "-p", "-o", "compression=lz4", dataset], || {
            format!("Failed to create dataset '{}'", dataset)
        })
    }

    /// Check whether a jail's dataset exists
    pub fn jail_dataset_exists(&self, name: &str) -> Result<bool> {
        self.dataset_exists(&self.jail_dataset(name))
    }

    /// Dataset name for a bootstrapped/committed release
    fn release_dataset(&self, release: &str) -> String {
        format!("{}/releases/{}", self.base_dataset, release)
    }

    /// The snapshot releases are cloned from
    const PRISTINE: &'static str = "pristine";

    /// Check whether a release is dataset-backed
    pub fn release_dataset_exists(&self, release: &str) -> Result<bool> {
        self.dataset_exists(&self.release_dataset(release))
    }

    /// Create a release dataset mounted at the given path (idempotent)
    pub fn create_release_dataset(&self, release: &str, mountpoint: &Path) -> Result<()> {
        let dataset = self.release_dataset(release);
        if !self.dataset_exists(&dataset)? {
            self.create_dataset(&dataset)?;
        }
        self.set_property(&dataset, "mountpoint", &mountpoint.display().to_string())
    }

    /// Snapshot a release as @pristine so jails can be cloned from it
    pub fn snapshot_release_pristine(&self, release: &str) -> Result<()> {
        let dataset = self.release_dataset(release);
        let snapshot = format!("{}@{}", dataset, Self::PRISTINE);
        if self.snapshot_exists(&snapshot)? {
            return Ok(());
        }
        self.take_snapshot(&snapshot)
    }

    /// Whether a release can be clone-provisioned (dataset with @pristine)
    pub fn release_is_cloneable(&self, release: &str) -> bool {
        let snapshot = format!("{}@{}", self.release_dataset(release), Self::PRISTINE);
        self.snapshot_exists(&snapshot).unwrap_or(false)
    }

    /// Provision a jail root instantly by cloning the release's @pristine
    pub fn clone_jail_from_release(&self, release: &str, jail: &str) -> Result<PathBuf> {
        let snapshot = format!("{}@{}", self.release_dataset(release), Self::PRISTINE);
        let target = self.jail_dataset(jail);
        if self.dataset_exists(&target)? {
            return Err(Error::Zfs(format!("Dataset '{}' already exists", target)));
        }
        zfs_run(&["clone", &snapshot, &target], || {
            format!("Failed to clone '{}' to '{}'", snapshot, target)
        })?;
        self.set_property(
            &target,
            "mountpoint",
            &self.jail_path(jail).display().to_string(),
        )?;
        Ok(self.jail_path(jail))
    }

    /// Freeze a jail into a reusable release: snapshot, clone, promote.
    ///
    /// Zero-copy "docker commit". After promotion the release owns the
    /// block chain and the source jail becomes a clone of it.
    pub fn commit_jail_to_release(
        &self,
        jail: &str,
        release: &str,
        release_mountpoint: &Path,
    ) -> Result<()> {
        let source = self.require_jail_dataset(jail)?;
        let target = self.release_dataset(release);
        if self.dataset_exists(&target)? {
            return Err(Error::Zfs(format!("Release '{}' already exists", release)));
        }

        let snapshot = format!("{}@{}", source, Self::PRISTINE);
        if !self.snapshot_exists(&snapshot)? {
            self.take_snapshot(&snapshot)?;
        }

        zfs_run(&["clone", &snapshot, &target], || {
            format!("Failed to clone '{}' to '{}'", snapshot, target)
        })?;

        if !zfs_status(&["promote", &target])?.success() {
            let _ = zfs_status(&["destroy", &target]);
            return Err(Error::Zfs(format!("Failed to promote '{}'", target)));
        }

        self.set_property(
            &target,
            "mountpoint",
            &release_mountpoint.display().to_string(),
        )
    }

    /// Name of a build layer snapshot: bs-layer-<index>-<hash>
    pub fn layer_snapshot_name(index: usize, hash: &str) -> String {
        format!("bs-layer-{}-{}", index, hash)
    }

    /// Check whether a jail has a given build layer snapshot
    pub fn has_layer(&self, jail: &str, layer: &str) -> bool {
        let snapshot = format!("{}@{}", self.jail_dataset(jail), layer);
        self.snapshot_exists(&snapshot).unwrap_or(false)
    }

    /// Snapshot the jail dataset as a build layer
    pub fn create_layer(&self, jail: &str, layer: &str) -> Result<()> {
        self.take_snapshot(&format!("{}@{}", self.jail_dataset(jail), layer))
    }

    /// Roll the jail dataset back to a build layer, discarding newer layers
    pub fn rollback_to_layer(&self, jail: &str, layer: &str) -> Result<()> {
        let snapshot = format!("{}@{}", self.jail_dataset(jail), layer);
        zfs_run(&["rollback", "-r", &snapshot], || {
            format!("Failed to rollback to '{}'", snapshot)
        })
    }

    /// List a jail's build layer snapshot names
    pub fn list_layers(&self, jail: &str) -> Result<Vec<String>> {
        Ok(self
            .list_snapshots(jail)?
            .into_iter()
            .filter_map(|s| {
                s.name
                    .split('@')
                    .nth(1)
                    .filter(|n| n.starts_with("bs-layer-"))
                    .map(String::from)
            })
            .collect())
    }

    /// Take a snapshot by full name (dataset@snap)
    fn take_snapshot(&self, snapshot_full: &str) -> Result<()> {
        zfs_run(&["snapshot", snapshot_full], || {
            format!("Failed to snapshot '{}'", snapshot_full)
        })
    }

    /// Check if a snapshot exists by full name (dataset@snap)
    fn snapshot_exists(&self, snapshot_full: &str) -> Result<bool> {
        Ok(
            zfs_output(&["list", "-H", "-t", "snapshot", "-o", "name", snapshot_full])?
                .status
                .success(),
        )
    }

    /// Create a dataset for a jail
    ///
    /// Creates: pool/blackship/jails/<name>
    pub fn create_jail_dataset(&self, name: &str) -> Result<PathBuf> {
        let dataset = self.jail_dataset(name);

        if self.dataset_exists(&dataset)? {
            return Err(Error::Zfs(format!("Dataset '{}' already exists", dataset)));
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

        zfs_run(&["destroy", "-r", &dataset], || {
            format!("Failed to destroy dataset '{}'", dataset)
        })
    }

    /// Get dataset properties
    /// Get a ZFS property value (_unused: future feature)
    #[allow(dead_code)]
    pub fn get_property(&self, dataset: &str, property: &str) -> Result<String> {
        let output = zfs_output(&["get", "-H", "-o", "value", property, dataset])?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err(Error::Zfs(format!(
                "Failed to get property '{}' for dataset '{}'",
                property, dataset
            )))
        }
    }

    /// Set a dataset property (no-op when it already holds the value)
    pub fn set_property(&self, dataset: &str, property: &str, value: &str) -> Result<()> {
        let current = zfs_output(&["get", "-H", "-o", "value", property, dataset])?;
        if current.status.success() && String::from_utf8_lossy(&current.stdout).trim() == value {
            return Ok(());
        }

        zfs_run(
            &["set", &format!("{}={}", property, value), dataset],
            || {
                format!(
                    "Failed to set property '{}={}' for dataset '{}'",
                    property, value, dataset
                )
            },
        )
    }

    /// Check that a jail dataset exists, returning its name or an error
    fn require_jail_dataset(&self, jail: &str) -> Result<String> {
        let dataset = self.jail_dataset(jail);
        if !self.dataset_exists(&dataset)? {
            return Err(Error::Zfs(format!(
                "Jail dataset '{}' does not exist",
                jail
            )));
        }
        Ok(dataset)
    }

    /// Check that a snapshot exists via `zfs list`
    fn require_snapshot_exists(&self, snapshot_full: &str, snapshot: &str) -> Result<()> {
        let output = zfs_output(&["list", "-H", "-t", "snapshot", snapshot_full])?;
        if !output.status.success() {
            return Err(Error::Zfs(format!(
                "Snapshot '{}' does not exist",
                snapshot
            )));
        }
        Ok(())
    }

    /// Create a snapshot of a jail
    ///
    /// If no name is provided, generates one with timestamp
    pub fn create_snapshot(&self, jail: &str, name: Option<&str>) -> Result<String> {
        let dataset = self.require_jail_dataset(jail)?;

        let snap_name = match name {
            Some(n) => n.to_string(),
            None => default_snapshot_name(),
        };

        let snapshot = format!("{}@{}", dataset, snap_name);

        zfs_run(&["snapshot", "-r", &snapshot], || {
            format!("Failed to create snapshot '{}'", snapshot)
        })?;
        Ok(snap_name)
    }

    /// List snapshots for a jail
    pub fn list_snapshots(&self, jail: &str) -> Result<Vec<SnapshotInfo>> {
        let dataset = self.require_jail_dataset(jail)?;

        let output = zfs_output(&[
            "list",
            "-H",
            "-t",
            "snapshot",
            "-o",
            "name,creation,used,refer",
            "-r",
            &dataset,
        ])?;

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
        self.require_snapshot_exists(&snapshot_full, snapshot)?;

        let mut args = vec!["rollback"];
        if force {
            args.push("-r"); // Destroy later snapshots
        }
        args.push(&snapshot_full);

        zfs_run(&args, || {
            format!(
                "Failed to rollback to snapshot '{}'. Use --force to destroy newer snapshots.",
                snapshot
            )
        })
    }

    /// Delete a snapshot
    pub fn delete_snapshot(&self, jail: &str, snapshot: &str) -> Result<()> {
        let dataset = self.jail_dataset(jail);
        let snapshot_full = format!("{}@{}", dataset, snapshot);

        zfs_run(&["destroy", &snapshot_full], || {
            format!("Failed to delete snapshot '{}'", snapshot)
        })
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
        self.require_snapshot_exists(&snapshot_full, &format!("{}@{}", source_jail, snapshot))?;

        // Check if target already exists
        if self.dataset_exists(&target_dataset)? {
            return Err(Error::Zfs(format!("Jail '{}' already exists", new_jail)));
        }

        zfs_run(&["clone", &snapshot_full, &target_dataset], || {
            format!(
                "Failed to clone snapshot '{}' to '{}'",
                snapshot_full, new_jail
            )
        })?;
        Ok(self.jail_path(new_jail))
    }

    /// Get the dataset name for a jail (public accessor) (_unused: future feature)
    #[allow(dead_code)]
    pub fn get_jail_dataset(&self, name: &str) -> String {
        self.jail_dataset(name)
    }
}

fn default_snapshot_name() -> String {
    format!("snap-{}", Zoned::now().strftime("%Y%m%d-%H%M%S"))
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
        let zfs = ZfsManager::new("zroot", "blackship", "/var/blackship/jails");
        assert_eq!(zfs.jails_dataset(), "zroot/blackship/jails");
        assert_eq!(zfs.jail_dataset("test"), "zroot/blackship/jails/test");
        assert_eq!(
            zfs.jail_path("test"),
            PathBuf::from("/var/blackship/jails/test")
        );
    }
}
