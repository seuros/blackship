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
) -> Result<()> {
    let config = manifest::load(config_path)?;
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

    bs.bootstrap(&release, force)?;
    Ok(())
}

pub fn handle_releases(
    config_path: &Path,
    action: Option<ReleasesAction>,
    json: bool,
) -> Result<()> {
    let config = manifest::load(config_path)?;
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
