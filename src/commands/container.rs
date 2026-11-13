//! Docker-style container commands (run, cp, rm) over the library API.

use crate::container::{self, CopyJailSide as JailSide};
use crate::error::Result;
use crate::host::Host;
use crate::manifest::validate_name;
use crate::{ContainerSpec, Exec, Exit, Network, error, manifest};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Run a command in an ephemeral jail
///
/// Creates a jail from a release, runs the command, and cleans up.
/// In detached mode, the jail persists until removed with `blackship rm`.
pub fn run_ephemeral_jail(
    name: &str,
    release: &str,
    detach: bool,
    network: Option<&str>,
    dns: &[String],
    command: &[String],
    config: Option<manifest::BlackshipConfig>,
) -> Result<()> {
    // Validate arguments before creating any resources
    if detach && !command.is_empty() {
        return Err(error::Error::InvalidArgument(
            "Cannot use --detach with a command. Use 'blackship exec' after jail starts."
                .to_string(),
        ));
    }

    let nameservers = dns
        .iter()
        .map(|server| {
            server.parse::<IpAddr>().map_err(|_| {
                error::Error::InvalidArgument(format!("--dns '{server}' is not an IP address"))
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let host = Host::from_config(config);
    if host.release(release)?.is_some_and(|r| !r.cloneable) {
        println!("ZFS clone not available, copying release (this may take a while)...");
    }

    let network = match network {
        Some(name) => Network::vnet(name),
        None => Network::Inherit,
    };
    // The library hands the jail a resolver that fits its network.
    let spec = nameservers.into_iter().fold(
        ContainerSpec::new(name, release).network(network).boot(),
        ContainerSpec::nameserver,
    );
    let mut container = host.create(&spec)?;
    println!("Jail '{name}' started from release '{release}'");

    if detach {
        container.keep()?;
        println!("Running in detached mode. Use 'blackship exec {name}' to run commands.");
        println!("Use 'blackship rm {name}' to stop and remove.");
        return Ok(());
    }

    let argv = if command.is_empty() {
        vec!["/bin/sh".to_string()]
    } else {
        command.to_vec()
    };
    let outcome = container.exec(Exec::argv(argv).inherit_stdio());

    println!("Cleaning up ephemeral jail '{name}'...");
    if let Err(err) = container.destroy() {
        eprintln!("Warning: Failed to clean up jail '{name}': {err}");
    }

    match outcome?.exit {
        Exit::Code(code) => std::process::exit(code),
        _ => std::process::exit(1),
    }
}

/// Copy files between host and jail
///
/// Supports paths in format:
/// - `jail:path` - path inside a jail
/// - `path` - path on the host
pub fn copy_files(
    source: &str,
    dest: &str,
    preserve: bool,
    config: Option<&manifest::BlackshipConfig>,
) -> Result<()> {
    let from = side_of(source, config)?;
    let to = side_of(dest, config)?;
    container::transfer_between(&from.as_side(), &to.as_side(), preserve)?;
    println!("Copied {source} -> {dest}");
    Ok(())
}

/// A parsed `jail:path` or host path, with the jail's root resolved.
enum Endpoint {
    Host(PathBuf),
    Jail(JailSide),
}

impl Endpoint {
    fn as_side(&self) -> container::CopySide<'_> {
        match self {
            Self::Host(path) => container::CopySide::Host(path),
            Self::Jail(jail) => container::CopySide::Jail(jail.clone()),
        }
    }
}

fn side_of(arg: &str, config: Option<&manifest::BlackshipConfig>) -> Result<Endpoint> {
    let (jail, path) = parse_jail_path(arg);
    let Some(jail) = jail else {
        return Ok(Endpoint::Host(PathBuf::from(path)));
    };
    // Short names and prefixes resolve through the config, as for exec and rm.
    let jail = config
        .and_then(|c| c.resolve_jail_names(&jail))
        .map_or(jail, |(_, full)| full);
    let root = get_jail_root(&jail, config)?;
    crate::blueprint::context::reject_symlink_ancestors(&data_dir_of(config), &root)?;
    Ok(Endpoint::Jail(JailSide {
        jid: crate::jail::jail_getid(&jail).ok(),
        root,
        path: path.to_string(),
    }))
}

/// Remove/destroy jails
pub fn remove_jails(
    jails: &[String],
    force: bool,
    volumes: bool,
    config: Option<manifest::BlackshipConfig>,
) -> Result<()> {
    use std::process::Command;

    let host = Host::from_config(config);
    let layout = host.layout();
    let config = layout.state_config();
    let (zpool, dataset) = zfs_pool_dataset(config);

    let mut warnings: Vec<String> = Vec::new();
    let mut retained: Vec<String> = Vec::new();
    let mut failures: Vec<error::Error> = Vec::new();
    let rm_data_dir = data_dir_of(config);

    for jail in jails {
        // Resolve short names and prefixes through the config.
        let resolved = config
            .and_then(|c| c.resolve_jail_names(jail))
            .map_or_else(|| jail.clone(), |(_, full)| full);
        let jail = &resolved;
        validate_name("jail", jail)?;

        if host
            .containers()?
            .iter()
            .any(|c| &c.name == jail && c.release.is_some())
        {
            if crate::jail::jail_getid(jail).is_ok() && !force {
                failures.push(running_without_force(jail));
                continue;
            }
            println!("Removing container '{jail}'...");
            match host.destroy_container(jail) {
                Ok(()) => println!("Jail '{jail}' removed."),
                Err(e) => warnings.push(e.to_string()),
            }
            continue;
        }

        let is_running = crate::jail::jail_getid(jail).is_ok();
        let jail_root = get_jail_root(jail, config);
        if !is_running && jail_root.is_err() {
            failures.push(error::Error::JailNotFound(jail.clone()));
            continue;
        }

        if is_running && !force {
            failures.push(running_without_force(jail));
            continue;
        }

        println!("Removing jail '{jail}'...");
        crate::sickbay::HealthStateStore::from_config(config).forget(jail);

        if is_running {
            println!("  Stopping jail...");
            let stop_status = Command::new("/usr/sbin/jail").args(["-r", jail]).status()?;
            if !stop_status.success() {
                eprintln!("  Warning: Failed to stop jail cleanly");
            }
        }

        if let Err(e) = container::network_cleanup(config, jail) {
            if force {
                eprintln!("  Warning: Failed to clean up network state: {e}");
            } else {
                return Err(e);
            }
        }

        if let Ok(root) = &jail_root
            && let Err(e) = container::unmount_jail_filesystems(root)
        {
            if force {
                eprintln!("  Warning: Failed to unmount jail filesystems: {e}");
            } else {
                return Err(e);
            }
        }

        // Try to remove ZFS dataset if volumes flag is set
        if volumes && destroy_jail_datasets(&zpool, &dataset, jail, &mut warnings, &mut retained) {
            println!("Jail '{jail}' removed.");
            continue;
        }

        // Fall back to removing directory
        if let Ok(root) = jail_root
            && root.exists()
        {
            crate::blueprint::context::reject_symlink_ancestors(&rm_data_dir, &root)?;
            if let Err(e) = crate::sys::remove_tree_with_flags(&root) {
                failures.push(error::Error::JailOperation(format!(
                    "Failed to remove {}: {e}",
                    root.display()
                )));
                continue;
            }
            println!("  Removed jail root: {}", root.display());
        }

        println!("Jail '{jail}' removed.");
    }

    // Partial failures are reported, not silently swallowed.
    if !warnings.is_empty() {
        eprintln!("Completed with {} warning(s):", warnings.len());
        for warning in &warnings {
            eprintln!("  - {warning}");
        }
    }
    if !retained.is_empty() {
        eprintln!("Retained datasets (remove manually when ready):");
        for dataset in &retained {
            eprintln!("  - {dataset}");
        }
    }

    removal_result(failures, jails.len())
}

/// A jail that was not removed is a failure, not a line on stderr.
fn removal_result(mut failures: Vec<error::Error>, total: usize) -> Result<()> {
    if failures.len() > 1 {
        for failure in &failures {
            eprintln!("Error: {failure}");
        }
        return Err(error::Error::JailOperation(format!(
            "{} of {total} jail(s) not removed",
            failures.len()
        )));
    }
    failures.pop().map_or(Ok(()), Err)
}

fn running_without_force(jail: &str) -> error::Error {
    error::Error::JailOperation(format!(
        "Jail '{jail}' is running. Use --force to stop and remove."
    ))
}

/// `rm --volumes`: stop the jail and destroy its dataset; returns whether one went.
fn destroy_jail_datasets(
    zpool: &str,
    dataset: &str,
    jail: &str,
    warnings: &mut Vec<String>,
    retained: &mut Vec<String>,
) -> bool {
    use std::process::Command;

    // Best-effort; may already be gone.
    let _ = Command::new("/usr/sbin/jail").args(["-r", jail]).status();

    let mut destroyed = false;
    for parent in ["jails", "containers"] {
        let zfs_dataset = format!("{zpool}/{dataset}/{parent}/{jail}");
        let exists = Command::new("/sbin/zfs")
            .args(["list", "-H", "-o", "name", &zfs_dataset])
            .output()
            .is_ok_and(|o| o.status.success());
        if !exists {
            continue;
        }
        let zfs_result = Command::new("/sbin/zfs")
            .args(["destroy", "-r", &zfs_dataset])
            .status();
        if zfs_result.is_ok_and(|s| s.success()) {
            println!("  Removed ZFS dataset: {zfs_dataset}");
            destroyed = true;
        } else {
            warnings.push(format!("dataset '{zfs_dataset}' could not be destroyed"));
            retained.push(zfs_dataset);
        }
    }
    destroyed
}

/// The effective data dir: config's when present, default otherwise.
fn data_dir_of(config: Option<&manifest::BlackshipConfig>) -> PathBuf {
    config.map_or_else(manifest::default_data_dir, |c| c.config.data_dir.clone())
}

fn zfs_pool_dataset(config: Option<&manifest::BlackshipConfig>) -> (String, String) {
    config.map_or_else(
        || ("zroot".to_string(), "blackship".to_string()),
        |c| {
            (
                c.config
                    .zpool
                    .clone()
                    .unwrap_or_else(|| "zroot".to_string()),
                c.config.dataset.clone(),
            )
        },
    )
}

/// Parse a jail:path format string
///
/// Returns (`Some(jail_name)`, path) for "jail:path" format,
/// or (None, path) for local paths.
pub fn parse_jail_path(s: &str) -> (Option<String>, &str) {
    // FreeBSD-only: no need to handle Windows paths
    if let Some(colon_pos) = s.find(':') {
        let jail = &s[..colon_pos];
        let path = &s[colon_pos + 1..];
        (Some(jail.to_string()), path)
    } else {
        (None, s)
    }
}

/// Get the root path of a jail
fn get_jail_root(jail: &str, config: Option<&manifest::BlackshipConfig>) -> Result<PathBuf> {
    use std::process::Command;

    validate_name("jail", jail)?;

    // Try to get jail path from jls (running jail)
    let output = Command::new("/usr/sbin/jls")
        .args(["-j", jail, "-h", "path"])
        .output()?;

    if output.status.success() {
        let path = String::from_utf8_lossy(&output.stdout)
            .lines()
            .nth(1) // Skip header
            .unwrap_or("")
            .trim()
            .to_string();
        if !path.is_empty() {
            return Ok(PathBuf::from(path));
        }
    }

    let data_dir = data_dir_of(config);

    // Fall back to checking common locations
    for parent in ["containers", "jails"] {
        let candidate: PathBuf = Path::new(&data_dir).join(parent).join(jail);
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    Err(error::Error::JailNotFound(jail.to_string()))
}

#[cfg(test)]
mod tests;
