//! Jail migration between hosts over zfs send | ssh zfs receive.
//!
//! The snapshot carries the staged .blackship/ config, so the receiving
//! host gets the jail definition along with the data.

use std::path::Path;
use std::process::{Command, Stdio};

use crate::error::{Error, Result};
use crate::manifest;

pub fn handle_migrate(
    config_path: &Path,
    jail: String,
    target: String,
    remote_dataset: Option<String>,
    keep: bool,
) -> Result<()> {
    let config = manifest::load(config_path)?;
    let zfs = super::snapshot::require_zfs(&config)?;
    let (service_name, full_name) = config
        .resolve_jail_names(&jail)
        .ok_or_else(|| Error::JailNotFound(jail.clone()))?;

    if crate::jail::jail_getid(&full_name).is_ok() {
        return Err(Error::JailOperation(format!(
            "Jail '{}' is running; stop it before migrating",
            full_name
        )));
    }

    let local_dataset = zfs.jail_dataset_name(&full_name);
    let remote_dataset =
        remote_dataset.unwrap_or_else(|| format!("zroot/blackship/jails/{}", full_name));

    // Preflight: target reachable, remote dataset absent.
    let probe = Command::new("/usr/bin/ssh")
        .args(["-o", "BatchMode=yes", &target])
        .args(["zfs", "list", "-H", "-o", "name", &remote_dataset])
        .output()
        .map_err(|e| Error::JailOperation(format!("Failed to run ssh: {}", e)))?;
    if probe.status.success() {
        return Err(Error::JailOperation(format!(
            "Dataset '{}' already exists on {}",
            remote_dataset, target
        )));
    }
    let reachable = Command::new("/usr/bin/ssh")
        .args(["-o", "BatchMode=yes", &target, "true"])
        .status()
        .map_err(|e| Error::JailOperation(format!("Failed to run ssh: {}", e)))?;
    if !reachable.success() {
        return Err(Error::JailOperation(format!(
            "Cannot reach '{}' over ssh (BatchMode)",
            target
        )));
    }

    // Snapshot with the jail definition staged inside the dataset.
    super::snapshot::stage_config_in_dataset(&config, &service_name, &full_name);
    let snap_name = zfs.create_snapshot(&full_name, None)?;
    let snapshot = format!("{}@{}", local_dataset, snap_name);

    println!("Sending {} to {}:{} ...", snapshot, target, remote_dataset);
    let mut send = Command::new("/sbin/zfs")
        .args(["send", "-R", &snapshot])
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| Error::JailOperation(format!("Failed to run zfs send: {}", e)))?;
    let send_out = send
        .stdout
        .take()
        .ok_or_else(|| Error::JailOperation("Failed to capture zfs send output".to_string()))?;
    let receive = Command::new("/usr/bin/ssh")
        .args(["-o", "BatchMode=yes", &target])
        .args(["zfs", "receive", "-u", &remote_dataset])
        .stdin(Stdio::from(send_out))
        .status()
        .map_err(|e| Error::JailOperation(format!("Failed to run remote receive: {}", e)))?;
    let send_status = send
        .wait()
        .map_err(|e| Error::JailOperation(format!("zfs send failed: {}", e)))?;

    if !send_status.success() || !receive.success() {
        return Err(Error::JailOperation(
            "Migration transfer failed; the remote dataset may be partial".to_string(),
        ));
    }

    println!("Transfer complete.");
    println!("On {target}, finish with:");
    println!(
        "  zfs set mountpoint=/var/blackship/jails/{} {}",
        full_name, remote_dataset
    );
    println!("  # jail definition travels at .blackship/jail.toml inside the dataset");
    println!("  blackship up {}", service_name);

    if !keep {
        println!(
            "Source dataset kept; remove it with: blackship rm {} --volumes",
            service_name
        );
    }

    Ok(())
}
