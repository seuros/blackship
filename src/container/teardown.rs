//! Destroying a container by name, from any state. Each step treats "already
//! gone" as done; the ownership record goes last.

use super::{registry, validate_container_name};
use crate::error::{Error, Result};
use crate::host::Layout;
use crate::manifest::BlackshipConfig;
use crate::network;
use deadline_machines::{Clock, Deadline, SystemClock};
use std::path::Path;
use std::time::Duration;

/// How long to wait for a removed jail to stop showing up by name.
const JAIL_GONE_TIMEOUT: Duration = Duration::from_secs(10);

pub fn destroy(layout: &Layout, name: &str) -> Result<()> {
    Error::require_root("destroying a container")?;
    validate_container_name(name)?;

    let record = registry::load(layout, name);
    let root = record
        .as_ref()
        .map_or_else(|| layout.container_root(name), |r| r.root.clone());
    let mut failures: Vec<String> = Vec::new();

    if let Err(e) = remove_jail(name) {
        failures.push(e.to_string());
    }

    if crate::rctl::is_enabled() {
        crate::rctl::remove_limits(name);
    }

    if let Err(e) = network_cleanup(layout.state_config(), name) {
        failures.push(format!("network: {e}"));
    }

    if root.exists()
        && let Err(e) = unmount_jail_filesystems(&root)
    {
        failures.push(e.to_string());
    }

    // A live nullfs mount would let removal reach into the host.
    let still_mounted = crate::sys::mount_table()
        .map(|table| crate::sys::mounted_paths_under(&root, &table))
        .unwrap_or_default();
    if !still_mounted.is_empty() {
        failures.push(format!(
            "still mounted under {}: {}; leaving the root in place",
            root.display(),
            still_mounted
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    } else if let Err(e) = remove_root(layout, name, record.as_ref(), &root) {
        failures.push(e.to_string());
    }

    if failures.is_empty() {
        registry::remove(layout, name)
    } else {
        Err(Error::JailOperation(format!(
            "container '{name}' was not fully destroyed: {}",
            failures.join("; ")
        )))
    }
}

/// `jail_remove(2)` the jail if it exists, then wait for the name to vanish.
fn remove_jail(name: &str) -> Result<()> {
    let Ok(jid) = crate::jail::jail_getid(name) else {
        return Ok(());
    };
    if crate::jail::jail_remove(jid).is_err() && crate::jail::jail_getid(name).is_ok() {
        return Err(Error::JailOperation(format!(
            "failed to remove jail '{name}' (jid {jid})"
        )));
    }
    let clock = SystemClock::new();
    let deadline = Deadline::after(clock.now(), crate::sys::nanos(JAIL_GONE_TIMEOUT));
    while crate::jail::jail_getid(name).is_ok() {
        if deadline.is_expired(clock.now()) {
            return Err(Error::JailOperation(format!(
                "jail '{name}' still present {}s after removal",
                JAIL_GONE_TIMEOUT.as_secs()
            )));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

/// Destroy the dataset when there is one, else remove the copied tree.
fn remove_root(
    layout: &Layout,
    name: &str,
    record: Option<&registry::Record>,
    root: &Path,
) -> Result<()> {
    let dataset = record.and_then(|r| r.dataset.clone()).or_else(|| {
        layout
            .zfs()
            .map(|zfs| zfs.container_dataset(name))
            .filter(|ds| dataset_exists(layout, ds))
    });

    match (dataset, layout.zfs()) {
        (Some(dataset), Some(zfs)) => {
            zfs.destroy_dataset(&dataset)?;
            // zfs destroy leaves the empty mountpoint directory behind.
            let _ = std::fs::remove_dir(root);
            Ok(())
        }
        (Some(dataset), None) => Err(Error::Zfs(format!(
            "container '{name}' lives on dataset '{dataset}' but this host has ZFS disabled"
        ))),
        (None, _) => {
            if root.exists() {
                crate::blueprint::context::reject_symlink_ancestors(layout.data_dir(), root)?;
                crate::sys::remove_tree_with_flags(root)?;
            }
            Ok(())
        }
    }
}

fn dataset_exists(layout: &Layout, dataset: &str) -> bool {
    layout
        .zfs()
        .is_some_and(|zfs| zfs.dataset_exists(dataset).unwrap_or(false))
}

/// Tear down a jail's VNET interfaces and release its address leases.
pub fn network_cleanup(config: Option<&BlackshipConfig>, owner: &str) -> Result<()> {
    let vnet_state_store = network::VnetStateStore::from_config(config);
    if let Some(record) = vnet_state_store.get(owner)? {
        network::VnetSetup::cleanup_state(&record)?;
        let _ = vnet_state_store.delete(owner)?;
    }

    let lease_store = network::NetworkLeaseStore::from_config(config);
    let _ = lease_store.release_owner(owner)?;
    Ok(())
}

/// Unmount everything at or below `jail_root`, deepest first.
pub fn unmount_jail_filesystems(jail_root: &Path) -> Result<()> {
    let table = crate::sys::mount_table()?;

    for mountpoint in crate::sys::mounted_paths_under(jail_root, &table) {
        unmount_path(&mountpoint)?;
    }

    Ok(())
}

fn unmount_path(path: &Path) -> Result<()> {
    use nix::errno::Errno;
    use nix::mount::{MntFlags, unmount};

    match unmount(path, MntFlags::empty()) {
        // Not a mount point, or already gone: nothing to undo.
        Ok(()) | Err(Errno::EINVAL | Errno::ENOENT) => return Ok(()),
        Err(_) => {}
    }
    unmount(path, MntFlags::MNT_FORCE)
        .map_err(|e| Error::JailOperation(format!("Failed to unmount '{}': {e}", path.display())))
}
