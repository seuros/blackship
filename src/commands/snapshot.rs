//! Snapshot, clone, export, and import commands

use std::path::Path;

use crate::cli::SnapshotAction;
use crate::error::Result;
use crate::manifest::BlackshipConfig;
use crate::{error, export, jail, manifest, zfs};

/// Require ZFS to be enabled and return a ready ZfsManager.
pub(crate) fn require_zfs(config: &BlackshipConfig) -> Result<zfs::ZfsManager> {
    if !config.config.zfs_enabled {
        return Err(error::Error::ZfsNotEnabled);
    }
    let pool = config
        .config
        .zpool
        .as_ref()
        .ok_or(error::Error::ZfsNotEnabled)?;
    Ok(zfs::ZfsManager::new(
        pool,
        &config.config.dataset,
        config.config.data_dir.join("jails"),
    ))
}

/// Resolve a jail name and verify it exists in the config
fn resolve_jail(config: &BlackshipConfig, jail: &str) -> Result<(String, String)> {
    let (service_name, full_name) = config
        .resolve_jail_names(jail)
        .ok_or_else(|| error::Error::JailNotFound(jail.to_string()))?;
    if config.get_jail(&service_name).is_none() {
        return Err(error::Error::JailNotFound(jail.to_string()));
    }
    Ok((service_name, full_name))
}

/// Stage the jail's definition (and Jailfile, when known) inside the dataset
/// at .blackship/ so snapshots, exports, and zfs send carry everything needed
/// to reconstruct the jail elsewhere.
pub(crate) fn stage_config_in_dataset(config: &BlackshipConfig, service_name: &str, full_name: &str) {
    let Some(jail_def) = config.get_jail(service_name) else {
        return;
    };
    let root = config.config.data_dir.join("jails").join(full_name);
    if !root.join("bin").exists() {
        return;
    }
    let stage = root.join(".blackship");
    if let Err(e) = std::fs::create_dir_all(&stage) {
        eprintln!("Warning: failed to stage config in dataset: {}", e);
        return;
    }
    match toml::to_string_pretty(jail_def) {
        Ok(serialized) => {
            if let Err(e) = std::fs::write(stage.join("jail.toml"), serialized) {
                eprintln!("Warning: failed to write staged jail.toml: {}", e);
            }
        }
        Err(e) => eprintln!("Warning: failed to serialize jail definition: {}", e),
    }
    let jailfile = jail_def
        .jailfile
        .clone()
        .or_else(|| jail_def.build.as_ref().map(|dir| dir.join("Jailfile")));
    if let Some(jailfile) = jailfile
        && jailfile.exists()
    {
        let _ = std::fs::copy(&jailfile, stage.join("Jailfile"));
    }
}

/// Freeze a jail into a reusable release via snapshot + clone + promote.
pub fn handle_commit(config_path: &Path, jail: String, release: String) -> Result<()> {
    let config = manifest::load(config_path)?;
    let zfs = require_zfs(&config)?;
    let (service_name, full_name) = resolve_jail(&config, &jail)?;
    manifest::validate_name("release", &release)?;
    stage_config_in_dataset(&config, &service_name, &full_name);

    let release_path = config.config.releases_dir.join(&release);
    if release_path.exists() {
        return Err(error::Error::Zfs(format!(
            "Release path '{}' already exists",
            release_path.display()
        )));
    }

    zfs.commit_jail_to_release(&full_name, &release, &release_path)?;
    println!(
        "Committed jail '{}' as release '{}' ({})",
        full_name,
        release,
        release_path.display()
    );
    println!("Use it with: FROM {}  (Jailfile) or release = \"{}\"", release, release);
    Ok(())
}

pub fn handle_snapshot(config_path: &Path, action: SnapshotAction) -> Result<()> {
    let config = manifest::load(config_path)?;
    let zfs = require_zfs(&config)?;

    match action {
        SnapshotAction::Create { jail, name } => {
            let (service_name, full_name) = resolve_jail(&config, &jail)?;

            stage_config_in_dataset(&config, &service_name, &full_name);
            let snap_name = zfs.create_snapshot(&full_name, name.as_deref())?;
            println!("Created snapshot: {}@{}", full_name, snap_name);
        }
        SnapshotAction::List { jail, json } => {
            let (_service_name, full_name) = resolve_jail(&config, &jail)?;

            let snapshots = zfs.list_snapshots(&full_name)?;

            if json {
                let json_data: Vec<_> = snapshots
                    .iter()
                    .map(|s| {
                        serde_json::json!({
                            "name": s.name,
                            "creation": s.creation,
                            "used": s.used,
                            "refer": s.refer
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&json_data).unwrap());
            } else if snapshots.is_empty() {
                println!("No snapshots for jail '{}'.", full_name);
            } else {
                println!("Snapshots for jail '{}':", full_name);
                println!(
                    "{:<30} {:<24} {:<10} {:<10}",
                    "NAME", "CREATED", "USED", "REFER"
                );
                println!("{}", "-".repeat(76));
                for snap in snapshots {
                    println!(
                        "{:<30} {:<24} {:<10} {:<10}",
                        snap.name, snap.creation, snap.used, snap.refer
                    );
                }
            }
        }
        SnapshotAction::Rollback {
            jail,
            snapshot,
            force,
        } => {
            let (_service_name, full_name) = resolve_jail(&config, &jail)?;

            if jail::jail_getid(&full_name).is_ok() {
                return Err(error::Error::JailOperation(format!(
                    "Jail '{}' is running. Stop it first with 'blackship down {}'",
                    full_name, full_name
                )));
            }

            zfs.rollback_snapshot(&full_name, &snapshot, force)?;
            println!(
                "Rolled back jail '{}' to snapshot '{}'",
                full_name, snapshot
            );
        }
        SnapshotAction::Delete { jail, snapshot } => {
            let (_service_name, full_name) = resolve_jail(&config, &jail)?;

            zfs.delete_snapshot(&full_name, &snapshot)?;
            println!("Deleted snapshot '{}@{}'", full_name, snapshot);
        }
    }

    Ok(())
}

pub fn handle_clone(config_path: &Path, source: String, name: String) -> Result<()> {
    let config = manifest::load(config_path)?;
    let zfs = require_zfs(&config)?;

    let parts: Vec<&str> = source.split('@').collect();
    if parts.len() != 2 {
        return Err(error::Error::JailOperation(
            "Source must be in format 'jail@snapshot'".into(),
        ));
    }
    let (source_jail, snapshot) = (parts[0], parts[1]);

    let (_source_service, source_full) = resolve_jail(&config, source_jail)?;

    if config.resolve_jail_names(&name).is_some() {
        return Err(error::Error::JailOperation(format!(
            "Jail '{}' already exists in config",
            name
        )));
    }

    manifest::validate_name("jail", &name)?;

    let new_full_name = config.jail_name(&name);
    let new_path = zfs.clone_from_snapshot(&source_full, snapshot, &new_full_name)?;

    println!(
        "Cloned '{}@{}' to new jail '{}'",
        source_full, snapshot, new_full_name
    );
    println!("Path: {}", new_path.display());
    println!("\nTo use this jail, add it to blackship.toml:");
    println!("  [[jails]]");
    println!("  name = \"{}\"", name);
    println!("  path = \"{}\"", new_path.display());

    Ok(())
}

pub fn handle_export(
    config_path: &Path,
    jail: String,
    output: Option<std::path::PathBuf>,
    zfs_send: bool,
) -> Result<()> {
    let config = manifest::load(config_path)?;

    let (service_name, full_name) = resolve_jail(&config, &jail)?;
    let jail_def = config
        .get_jail(&service_name)
        .ok_or_else(|| error::Error::JailNotFound(jail.clone()))?;

    let jail_path = jail_def.effective_path(&config.config, &full_name);

    let output_path =
        output.unwrap_or_else(|| std::path::PathBuf::from(format!("{}.tar.zst", full_name)));

    let hostname = jail_def.hostname.as_deref();
    let ip = jail_def
        .network
        .as_ref()
        .and_then(|n| n.ip)
        .map(|ip| ip.to_string());

    if zfs_send {
        require_zfs(&config)?; // validates zfs_enabled + zpool present
        let pool = config.config.zpool.as_ref().unwrap();
        let dataset = format!("{}/{}/jails/{}", pool, config.config.dataset, full_name);
        export::export_jail_zfs(&full_name, &dataset, &output_path, hostname, ip.as_deref())?;
    } else {
        export::export_jail(
            &full_name,
            &jail_path,
            &output_path,
            hostname,
            ip.as_deref(),
        )?;
    }

    Ok(())
}

pub fn handle_import(
    config_path: &Path,
    file: std::path::PathBuf,
    name: Option<String>,
    force: bool,
) -> Result<()> {
    let config = manifest::load(config_path)?;

    let metadata = export::read_metadata(&file)?;
    let target_name = name.as_deref().unwrap_or(metadata.name.as_str());
    manifest::validate_name("jail", target_name)?;
    let full_name = config.jail_name(target_name);
    let target_path = config.config.data_dir.join("jails").join(&full_name);

    if target_path.exists() && !force {
        return Err(error::Error::JailOperation(format!(
            "Jail path {} already exists. Use --force to overwrite.",
            target_path.display()
        )));
    }

    // Build proper ZFS dataset path from config instead of deriving from filesystem path.
    let zfs_dataset = config
        .config
        .zpool
        .as_ref()
        .map(|zpool| format!("{}/{}/jails/{}", zpool, config.config.dataset, full_name));

    let imported_name = export::import_jail(
        &file,
        &target_path,
        Some(target_name),
        zfs_dataset.as_deref(),
    )?;

    println!("\nTo add the imported jail to your config:");
    println!("  [[jails]]");
    println!("  name = \"{}\"", imported_name);
    println!("  path = \"{}\"", target_path.display());

    Ok(())
}
