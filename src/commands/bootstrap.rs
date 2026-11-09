//! Bootstrap and release management commands

use std::path::Path;

use crate::cli::ReleasesAction;
use crate::error::Result;
use crate::host::Host;
use crate::release::Bootstrap;
use crate::{manifest, provision};

pub fn handle_bootstrap(
    config_path: &Path,
    release: &str,
    force: bool,
    archives: Option<Vec<String>>,
    pkgbase: bool,
) -> Result<()> {
    let host = Host::from_manifest(config_path)?;

    let mut plan = Bootstrap::release(release);
    if force {
        plan = plan.force();
    }
    if let Some(archives) = archives {
        plan = plan.archives(archives);
    }
    if pkgbase {
        plan = plan.pkgbase();
    }

    if host.uses_zfs() && !force && host.release(release)?.is_some_and(|r| r.dataset.is_none()) {
        println!(
            "Release '{release}' is a plain directory; re-run with --force to make it clone-ready."
        );
    }

    let bootstrapped = host.bootstrap(&plan)?;
    if bootstrapped.cloneable {
        println!("Release '{release}' is clone-ready (@pristine).");
    }
    Ok(())
}

/// ZFS manager for release datasets, when ZFS is enabled and usable
pub fn release_zfs(config: &manifest::BlackshipConfig) -> Option<crate::zfs::ZfsManager> {
    if !config.config.zfs_enabled {
        return None;
    }
    config.config.zpool.as_ref().map(|pool| {
        crate::zfs::ZfsManager::new(pool, &config.config.dataset, config.config.jails_dir())
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
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json_data)
                        .expect("serde_json::Value always serializes")
                );
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
                println!("Release '{release}' is valid.");
            } else {
                println!("Release '{release}' is corrupted or incomplete.");
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

/// Return bootstrapped releases without writing terminal output.
pub fn releases_data(config_path: &Path) -> Result<Vec<serde_json::Value>> {
    let config = manifest::load_or_default(config_path)?;
    let bs = provision::Provisioner::from_config(&config.config)?;
    Ok(bs
        .list_releases()?
        .iter()
        .map(|release| {
            serde_json::json!({
                "name": release.name,
                "arch": release.arch.freebsd_name(),
                "path": release.path.display().to_string()
            })
        })
        .collect())
}
