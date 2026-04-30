//! Snapshot, clone, export, and import commands

use std::path::Path;

use crate::cli::SnapshotAction;
use crate::error::Result;
use crate::{error, export, jail, manifest, zfs};

pub fn handle_snapshot(config_path: &Path, action: SnapshotAction) -> Result<()> {
    let config = manifest::load(config_path)?;

    if !config.config.zfs_enabled {
        return Err(error::Error::ZfsNotEnabled);
    }

    let pool = config
        .config
        .zpool
        .as_ref()
        .ok_or(error::Error::ZfsNotEnabled)?;
    let zfs = zfs::ZfsManager::new(pool, &config.config.dataset);

    match action {
        SnapshotAction::Create { jail, name } => {
            let (service_name, full_name) = config
                .resolve_jail_names(&jail)
                .ok_or_else(|| error::Error::JailNotFound(jail.clone()))?;
            if config.get_jail(&service_name).is_none() {
                return Err(error::Error::JailNotFound(jail.clone()));
            }

            let snap_name = zfs.create_snapshot(&full_name, name.as_deref())?;
            println!("Created snapshot: {}@{}", full_name, snap_name);
        }
        SnapshotAction::List { jail, json } => {
            let (service_name, full_name) = config
                .resolve_jail_names(&jail)
                .ok_or_else(|| error::Error::JailNotFound(jail.clone()))?;
            if config.get_jail(&service_name).is_none() {
                return Err(error::Error::JailNotFound(jail.clone()));
            }

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
            let (service_name, full_name) = config
                .resolve_jail_names(&jail)
                .ok_or_else(|| error::Error::JailNotFound(jail.clone()))?;
            if config.get_jail(&service_name).is_none() {
                return Err(error::Error::JailNotFound(jail.clone()));
            }

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
            let (service_name, full_name) = config
                .resolve_jail_names(&jail)
                .ok_or_else(|| error::Error::JailNotFound(jail.clone()))?;
            if config.get_jail(&service_name).is_none() {
                return Err(error::Error::JailNotFound(jail.clone()));
            }

            zfs.delete_snapshot(&full_name, &snapshot)?;
            println!("Deleted snapshot '{}@{}'", full_name, snapshot);
        }
    }

    Ok(())
}

pub fn handle_clone(config_path: &Path, source: String, name: String) -> Result<()> {
    let config = manifest::load(config_path)?;

    if !config.config.zfs_enabled {
        return Err(error::Error::ZfsNotEnabled);
    }

    let parts: Vec<&str> = source.split('@').collect();
    if parts.len() != 2 {
        return Err(error::Error::JailOperation(
            "Source must be in format 'jail@snapshot'".into(),
        ));
    }
    let (source_jail, snapshot) = (parts[0], parts[1]);

    let (source_service, source_full) = config
        .resolve_jail_names(source_jail)
        .ok_or_else(|| error::Error::JailNotFound(source_jail.to_string()))?;
    if config.get_jail(&source_service).is_none() {
        return Err(error::Error::JailNotFound(source_jail.to_string()));
    }

    if config.resolve_jail_names(&name).is_some() {
        return Err(error::Error::JailOperation(format!(
            "Jail '{}' already exists in config",
            name
        )));
    }

    let pool = config
        .config
        .zpool
        .as_ref()
        .ok_or(error::Error::ZfsNotEnabled)?;
    let zfs = zfs::ZfsManager::new(pool, &config.config.dataset);

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

    let (service_name, full_name) = config
        .resolve_jail_names(&jail)
        .ok_or_else(|| error::Error::JailNotFound(jail.clone()))?;
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
        if !config.config.zfs_enabled {
            return Err(error::Error::ZfsNotEnabled);
        }
        let pool = config
            .config
            .zpool
            .as_ref()
            .ok_or(error::Error::ZfsNotEnabled)?;
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
    let full_name = config.jail_name(target_name);
    let target_path = config.config.data_dir.join("jails").join(&full_name);

    if target_path.exists() && !force {
        return Err(error::Error::JailOperation(format!(
            "Jail path {} already exists. Use --force to overwrite.",
            target_path.display()
        )));
    }

    let imported_name = export::import_jail(&file, &target_path, Some(target_name))?;

    println!("\nTo add the imported jail to your config:");
    println!("  [[jails]]");
    println!("  name = \"{}\"", imported_name);
    println!("  path = \"{}\"", target_path.display());

    Ok(())
}
