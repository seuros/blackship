//! Armada (docker-compose style) orchestration commands

use std::path::Path;

use crate::cli::ArmadaAction;
use crate::commands::build::copy_release_to;
use crate::error::Result;
use crate::{blueprint, bridge, error, manifest, provision};

pub fn handle(
    _config_path: &Path,
    verbose: bool,
    files: Vec<std::path::PathBuf>,
    action: ArmadaAction,
) -> Result<()> {
    match action {
        ArmadaAction::Init { file, force } => {
            use std::fs;

            if file.exists() && !force {
                eprintln!(
                    "Error: {} already exists. Use -y/--force to overwrite.",
                    file.display()
                );
                std::process::exit(1);
            }

            let content = r#"# Blackship Armada Configuration
# https://github.com/seuros/blackship

[config]
# data_dir defaults to ~/.local/share/blackship (XDG_DATA_HOME)
# Uncomment to override:
# data_dir = "/var/blackship"
# zfs_enabled = true
# zpool = "zroot"

# Example jail referencing a Jailfile:
# [[jails]]
# name = "web"
# build = "./web"              # Directory containing Jailfile
# depends_on = ["db"]
#
# [jails.network]
# ip_cidr = "10.0.1.10/24"
#
# [[jails.hooks]]
# phase = "post_start"
# command = "echo 'Web started'"

# Example jail without Jailfile (using release directly):
# [[jails]]
# name = "db"
# release = "15.1-RELEASE"
# path = "/jails/db"
"#;

            fs::write(&file, content)?;
            println!("Created {}", file.display());
            println!("\nNext steps:");
            println!("  1. Edit {} to define your jails", file.display());
            println!("  2. Run 'blackship armada up' to start all jails");
            Ok(())
        }

        ArmadaAction::Up {
            detach,
            jails,
            build: _,
            no_build: _,
            dry_run,
        } => {
            let config = manifest::load_merged(&files)?;
            let mut bridge = bridge::Bridge::open(config, verbose)?;

            if jails.is_empty() {
                if dry_run {
                    bridge.up_dry_run(None)?;
                } else {
                    bridge.up(None)?;
                }
            } else {
                for jail in &jails {
                    if dry_run {
                        bridge.up_dry_run(Some(jail))?;
                    } else {
                        bridge.up(Some(jail))?;
                    }
                }
            }

            if detach {
                println!("Jails started in background.");
                println!("Use 'blackship supervise' for warden mode with auto-restart.");
            }
            Ok(())
        }

        ArmadaAction::Down { jails, dry_run } => {
            let config = manifest::load_merged(&files)?;
            let mut bridge = bridge::Bridge::open(config, verbose)?;

            if jails.is_empty() {
                if dry_run {
                    bridge.down_dry_run(None)?;
                } else {
                    bridge.down(None)?;
                }
            } else {
                for jail in &jails {
                    if dry_run {
                        bridge.down_dry_run(Some(jail))?;
                    } else {
                        bridge.down(Some(jail))?;
                    }
                }
            }
            Ok(())
        }

        ArmadaAction::Build { jails, dry_run } => {
            let config = manifest::load_merged(&files)?;

            let jails_to_build: Vec<_> = if jails.is_empty() {
                config.jails.iter().collect()
            } else {
                let mut service_names = Vec::new();
                for name in &jails {
                    let (service_name, _full_name) = config
                        .resolve_jail_names(name)
                        .ok_or_else(|| error::Error::JailNotFound(name.clone()))?;
                    service_names.push(service_name);
                }
                config
                    .jails
                    .iter()
                    .filter(|j| service_names.contains(&j.name))
                    .collect()
            };

            if dry_run {
                println!("=== DRY RUN - No changes will be made ===\n");
            }

            for jail_def in jails_to_build {
                if let Some(build_path) = &jail_def.build {
                    let jailfile_path = build_path.join("Jailfile");
                    if jailfile_path.exists() {
                        build_jail_from_file(
                            &config,
                            &jailfile_path,
                            &jail_def.name,
                            Some(build_path),
                            dry_run,
                            verbose,
                        )?;
                    } else if let Some(jailfile_explicit) = &jail_def.jailfile {
                        if jailfile_explicit.exists() {
                            let context_dir = jailfile_explicit
                                .parent()
                                .unwrap_or(std::path::Path::new("."));
                            build_jail_from_file(
                                &config,
                                jailfile_explicit,
                                &jail_def.name,
                                Some(&context_dir.to_path_buf()),
                                dry_run,
                                verbose,
                            )?;
                        } else {
                            eprintln!(
                                "Warning: Jailfile not found at {}",
                                jailfile_explicit.display()
                            );
                        }
                    } else {
                        eprintln!("Warning: No Jailfile found at {}", jailfile_path.display());
                    }
                }
            }
            Ok(())
        }

        ArmadaAction::Ps { json } => {
            let config = manifest::load_merged(&files)?;
            let bridge = bridge::Bridge::open(config, verbose)?;
            bridge.ps(json)?;
            Ok(())
        }

        ArmadaAction::Config { show } => {
            let config = manifest::load_merged(&files)?;

            if show {
                println!("# Merged configuration from: {:?}\n", files);
                println!("[config]");
                println!("data_dir = \"{}\"", config.config.data_dir.display());
                if config.config.zfs_enabled {
                    println!("zfs_enabled = true");
                    if let Some(pool) = &config.config.zpool {
                        println!("zpool = \"{}\"", pool);
                    }
                }
                println!();
                for jail in &config.jails {
                    println!("[[jails]]");
                    println!("name = \"{}\"", jail.name);
                    if let Some(path) = &jail.path {
                        println!("path = \"{}\"", path.display());
                    }
                    if let Some(release) = &jail.release {
                        println!("release = \"{}\"", release);
                    }
                    if let Some(build) = &jail.build {
                        println!("build = \"{}\"", build.display());
                    }
                    if !jail.depends_on.is_empty() {
                        println!("depends_on = {:?}", jail.depends_on);
                    }
                    println!();
                }
            } else {
                println!("Configuration valid.");
                println!("  Files: {:?}", files);
                println!("  Jails: {}", config.jails.len());
            }
            Ok(())
        }
    }
}

/// Build a jail from a Jailfile, bootstrapping the base release if needed
fn build_jail_from_file(
    config: &manifest::BlackshipConfig,
    jailfile_path: &std::path::Path,
    service_name: &str,
    context_dir: Option<&std::path::PathBuf>,
    dry_run: bool,
    verbose: bool,
) -> Result<()> {
    use blueprint::{BuildContext, TemplateExecutor, parse_jailfile};

    let full_name = config.jail_name(service_name);
    println!(
        "Building jail '{}' from {}",
        full_name,
        jailfile_path.display()
    );

    let content = std::fs::read_to_string(jailfile_path).map_err(|e| {
        error::Error::TemplateParseFailed(format!(
            "Failed to read {}: {}",
            jailfile_path.display(),
            e
        ))
    })?;
    let jailfile = parse_jailfile(&content)?;

    let target_path = config.config.data_dir.join("jails").join(&full_name);

    crate::blueprint::context::reject_symlink_ancestors(&config.config.data_dir, &target_path)?;
    crate::blueprint::context::reject_symlink_target(&target_path)?;

    if let Some(release) = &jailfile.from {
        crate::manifest::validate_name("release", release)?;
        let bs = provision::Provisioner::from_config(&config.config)?;
        let release_path = config.config.releases_dir.join(release);

        if !release_path.exists() {
            println!("  Base release '{}' not found. Bootstrapping...", release);
            if !dry_run {
                bs.bootstrap(release, false)?;
            }
        }

        if !dry_run && !target_path.exists() {
            println!("  Creating jail root from {}...", release);
            std::fs::create_dir_all(&target_path)?;
            copy_release_to(&release_path, &target_path)?;
        }
    }

    let ctx_dir = context_dir
        .map(|p| p.as_path())
        .unwrap_or_else(|| jailfile_path.parent().unwrap_or(std::path::Path::new(".")));

    let ctx = BuildContext::new(ctx_dir, &target_path, &full_name).verbose(verbose);
    let mut executor = TemplateExecutor::new(ctx).dry_run(dry_run);
    executor.execute(&jailfile)?;

    if !dry_run {
        println!("  Build complete: {}\n", target_path.display());
    }

    Ok(())
}
