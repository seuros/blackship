//! Bootstrap and release management commands

use std::path::Path;

use crate::cli::ReleasesAction;
use crate::error::Result;
use crate::{manifest, provision};

pub fn handle_bootstrap(
    config_path: &Path,
    release: String,
    force: bool,
    archives: Option<Vec<String>>,
    pkgbase: bool,
) -> Result<()> {
    // FreeBSD 16 dropped distribution sets: pkgbase is the only path.
    let pkgbase = pkgbase
        || crate::sys::OsVersion::parse(&release)
            .map(|v| v.requires_pkgbase())
            .unwrap_or(false);
    let config = manifest::load_or_default(config_path)?;
    let mut bs = provision::Provisioner::from_config(&config.config)?;

    if let Some(archives) = archives {
        bs = provision::Provisioner::new(
            config.config.mirror_url.clone(),
            config.config.releases_dir.clone(),
            config.config.cache_dir.clone(),
            archives,
            config.config.retry.clone(),
        )?;
    }

    // With ZFS the release extracts into its own dataset so jails can be
    // clone-provisioned from a @pristine snapshot afterwards.
    let zfs = release_zfs(&config);
    let release_path = config.config.releases_dir.join(&release);
    let mut dataset_backed = false;
    if let Some(zfs) = &zfs {
        if zfs.release_dataset_exists(&release)? {
            dataset_backed = true;
        } else if !release_path.exists() {
            zfs.create_release_dataset(&release, &release_path)?;
            dataset_backed = true;
        } else if force {
            // Legacy plain-dir release: replace it with a dataset so it
            // becomes clone-ready. --force re-extracts anyway.
            // Base userlands carry schg-flagged files; strip them first.
            let _ = std::process::Command::new("/bin/chflags")
                .args(["-R", "noschg"])
                .arg(&release_path)
                .status();
            std::fs::remove_dir_all(&release_path).map_err(|e| {
                crate::error::Error::Zfs(format!(
                    "Failed to remove legacy release dir '{}': {}",
                    release_path.display(),
                    e
                ))
            })?;
            zfs.create_release_dataset(&release, &release_path)?;
            dataset_backed = true;
        } else {
            println!(
                "Release '{}' is a plain directory; re-run with --force to make it clone-ready.",
                release
            );
        }
    }

    if pkgbase {
        bs.bootstrap_pkgbase(&release, force)?;
    } else {
        bs.bootstrap(&release, force)?;
    }

    if dataset_backed && let Some(zfs) = &zfs {
        zfs.snapshot_release_pristine(&release)?;
        println!("Release '{}' is clone-ready (@pristine).", release);
    }
    Ok(())
}

/// ZFS manager for release datasets, when ZFS is enabled and usable
pub(crate) fn release_zfs(config: &manifest::BlackshipConfig) -> Option<crate::zfs::ZfsManager> {
    if !config.config.zfs_enabled {
        return None;
    }
    config.config.zpool.as_ref().map(|pool| {
        crate::zfs::ZfsManager::new(
            pool,
            &config.config.dataset,
            config.config.data_dir.join("jails"),
        )
    })
}

pub fn handle_releases(
    config_path: &Path,
    action: Option<ReleasesAction>,
    json: bool,
) -> Result<()> {
    let config = manifest::load_or_default(config_path)?;
    let bs = provision::Provisioner::from_config(&config.config)?;

    match action.unwrap_or(ReleasesAction::List) {
        ReleasesAction::List => {
            let releases = bs.list_releases()?;
            if json {
                let json_data: Vec<_> = releases
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "name": r.name,
                            "arch": r.arch.freebsd_name(),
                            "path": r.path.display().to_string()
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&json_data).unwrap());
            } else if releases.is_empty() {
                println!("No releases bootstrapped.");
                println!("Use 'blackship bootstrap <release>' to bootstrap a release.");
            } else {
                println!("Bootstrapped releases:");
                for release in releases {
                    println!(
                        "  {} ({}) - {}",
                        release.name,
                        release.arch.freebsd_name(),
                        release.path.display()
                    );
                }
            }
        }
        ReleasesAction::Delete { release } => {
            bs.delete(&release)?;
        }
        ReleasesAction::Verify { release } => {
            if bs.verify(&release)? {
                println!("Release '{}' is valid.", release);
            } else {
                println!("Release '{}' is corrupted or incomplete.", release);
                std::process::exit(1);
            }
        }
    }

    Ok(())
}
