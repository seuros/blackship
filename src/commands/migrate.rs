//! Jail migration between hosts over zfs send | ssh zfs receive.
//!
//! The snapshot carries the staged .blackship/ config, so the receiving
//! host gets the jail definition along with the data. A successful transfer
//! fences the source: its dataset goes read-only and starts refuse, so the
//! jail cannot silently run on two hosts. A failed transfer fences nothing and
//! removes the partial destination dataset it created.

use std::path::Path;
use std::process::{Command, Stdio};

use crate::error::{Error, Result};
use crate::manifest;

pub fn handle_migrate(
    config_path: &Path,
    jail: &str,
    target: &str,
    remote_dataset: Option<String>,
    keep: bool,
) -> Result<()> {
    let config = manifest::load(config_path)?;
    let zfs = super::snapshot::require_zfs(&config)?;
    let (service_name, full_name) = config.require_jail_names(jail)?;

    if crate::jail::jail_getid(&full_name).is_ok() {
        return Err(Error::JailOperation(format!(
            "Jail '{full_name}' is running; stop it before migrating"
        )));
    }

    let local_dataset = zfs.jail_dataset_name(&full_name);
    let remote_dataset =
        remote_dataset.unwrap_or_else(|| format!("zroot/blackship/jails/{full_name}"));

    // Preflight: target reachable, remote dataset absent.
    let probe = Command::new("/usr/bin/ssh")
        .args(["-o", "BatchMode=yes", target])
        .args(["zfs", "list", "-H", "-o", "name", &remote_dataset])
        .output()
        .map_err(|e| Error::JailOperation(format!("Failed to run ssh: {e}")))?;
    if probe.status.success() {
        return Err(Error::JailOperation(format!(
            "Dataset '{remote_dataset}' already exists on {target}"
        )));
    }
    let reachable = Command::new("/usr/bin/ssh")
        .args(["-o", "BatchMode=yes", target, "true"])
        .status()
        .map_err(|e| Error::JailOperation(format!("Failed to run ssh: {e}")))?;
    if !reachable.success() {
        return Err(Error::JailOperation(format!(
            "Cannot reach '{target}' over ssh (BatchMode)"
        )));
    }

    // Snapshot with the jail definition staged inside the dataset.
    super::snapshot::stage_config_in_dataset(&config, &service_name, &full_name);
    let snap_name = zfs.create_snapshot(&full_name, None)?;
    let snapshot = format!("{local_dataset}@{snap_name}");

    println!("Sending {snapshot} to {target}:{remote_dataset} ...");
    let mut send = Command::new("/sbin/zfs")
        .args(send_args(
            &snapshot,
            zfs.dataset_origin(&local_dataset).is_some(),
        ))
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| Error::JailOperation(format!("Failed to run zfs send: {e}")))?;
    let send_out = send
        .stdout
        .take()
        .ok_or_else(|| Error::JailOperation("Failed to capture zfs send output".to_string()))?;
    let receive = Command::new("/usr/bin/ssh")
        .args(["-o", "BatchMode=yes", target])
        .args(["zfs", "receive", "-u", &remote_dataset])
        .stdin(Stdio::from(send_out))
        .status()
        .map_err(|e| Error::JailOperation(format!("Failed to run remote receive: {e}")))?;
    let send_status = send
        .wait()
        .map_err(|e| Error::JailOperation(format!("zfs send failed: {e}")))?;

    if !send_status.success() || !receive.success() {
        let cleaned = discard_partial_destination(target, &remote_dataset);
        if let Err(e) = zfs.delete_snapshot(&full_name, &snap_name) {
            eprintln!("Warning: could not remove the migration snapshot '{snap_name}': {e}");
        }
        return Err(Error::JailOperation(format!(
            "Migration transfer failed; the source is untouched and {}",
            if cleaned {
                "the partial remote dataset was removed"
            } else {
                "the remote dataset may be partial"
            }
        )));
    }

    println!("Transfer complete.");
    let destination = fence_value(target, &remote_dataset, crate::scope::now_unix());
    zfs.fence_jail_dataset(&full_name, &destination)?;
    println!("Source fenced: read-only, and 'up {service_name}' refuses here.");
    for line in destination_steps(
        target,
        &remote_dataset,
        &full_name,
        &service_name,
        &zfs.jail_path(&full_name),
    ) {
        println!("{line}");
    }

    if !keep {
        println!("Remove the source for good with: blackship rm {service_name} --volumes");
        println!("Undo the migration here with: blackship unfence {service_name}");
    }

    Ok(())
}

/// Destroy the remote dataset a failed transfer may have left; true when none remains.
fn discard_partial_destination(target: &str, remote_dataset: &str) -> bool {
    let ssh = |args: &[&str]| {
        Command::new("/usr/bin/ssh")
            .args(["-o", "BatchMode=yes", target])
            .args(args)
            .output()
    };
    // The preflight proved the dataset absent, so whatever exists now is this run's.
    if let Err(e) = ssh(&["zfs", "destroy", "-r", remote_dataset]) {
        eprintln!("Warning: could not ask {target} to remove the partial dataset: {e}");
    }
    ssh(&["zfs", "list", "-H", "-o", "name", remote_dataset])
        .is_ok_and(|probe| !probe.status.success())
}

/// `zfs send` arguments for the snapshot. A jail cloned from a release is sent as a full
/// stream: `-R` would make the target look for the clone's origin snapshot, which it
/// does not have, and the receive would fail. The cost is that its older snapshots stay behind.
const fn send_args(snapshot: &str, cloned: bool) -> [&str; 3] {
    ["send", if cloned { "-p" } else { "-R" }, snapshot]
}

/// What to do on the target. The dataset keeps the mountpoint it had here; only a target
/// with a different data directory needs to move it, and only the target knows its layout.
fn destination_steps(
    target: &str,
    remote_dataset: &str,
    full_name: &str,
    service_name: &str,
    source_path: &Path,
) -> Vec<String> {
    vec![
        format!("On {target}, finish with:"),
        format!(
            "  # the dataset arrives with mountpoint {}; if the target's data_dir differs:",
            source_path.display()
        ),
        format!("  zfs set mountpoint=<data_dir>/jails/{full_name} {remote_dataset}"),
        "  # the jail definition travels at .blackship/jail.toml inside the dataset".to_string(),
        format!("  blackship up {service_name}"),
    ]
}

/// `<host>/<dataset>@<unix time>`: where a migrated jail went, and when.
fn fence_value(target: &str, remote_dataset: &str, at: i64) -> String {
    let host = target.rsplit('@').next().unwrap_or(target);
    format!("{host}/{remote_dataset}@{at}")
}

/// Lift a migration fence.
pub fn handle_unfence(config_path: &Path, jail: &str) -> Result<()> {
    let config = manifest::load(config_path)?;
    let zfs = super::snapshot::require_zfs(&config)?;
    let (_, full_name) = config.require_jail_names(jail)?;

    let Some(fence) = zfs.jail_migration_fence(&full_name) else {
        return Err(Error::JailOperation(format!(
            "Jail '{full_name}' is not fenced"
        )));
    };
    zfs.clear_jail_migration_fence(&full_name)?;
    println!("Cleared the fence on '{full_name}' (it had been migrated to {fence}).");
    println!("It can start here again; make sure it does not also run there.");
    Ok(())
}

#[cfg(test)]
mod tests;
