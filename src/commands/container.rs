//! Docker-style container commands: run, cp, rm

use crate::error::Result;
use crate::{console, error, manifest, network};
use std::ffi::CString;
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
    command: &[String],
    config: Option<&manifest::BlackshipConfig>,
) -> Result<()> {
    use std::process::Command;

    // Get paths from config or use XDG defaults
    let releases_dir = config
        .map(|c| c.config.releases_dir.clone())
        .unwrap_or_else(|| manifest::get_xdg_data_dir().join("releases"));

    let data_dir = config
        .map(|c| c.config.data_dir.clone())
        .unwrap_or_else(manifest::default_data_dir);

    let (zpool, dataset) = config
        .map(|c| {
            (
                c.config
                    .zpool
                    .clone()
                    .unwrap_or_else(|| "zroot".to_string()),
                c.config.dataset.clone(),
            )
        })
        .unwrap_or_else(|| ("zroot".to_string(), "blackship".to_string()));

    // Validate arguments before creating any resources
    if detach && !command.is_empty() {
        return Err(error::Error::InvalidArgument(
            "Cannot use --detach with a command. Use 'blackship exec' after jail starts."
                .to_string(),
        ));
    }

    let release_path = releases_dir.join(release);
    if !release_path.exists() {
        return Err(error::Error::ReleaseNotFound(release.to_string()));
    }

    let lease_store = network::NetworkLeaseStore::from_config(config);
    let vnet_state_store = network::VnetStateStore::from_config(config);

    // Create jail root using ZFS clone if available, otherwise copy
    let jail_root = data_dir.join("containers").join(name);

    if jail_root.exists() {
        return Err(error::Error::JailExists(name.to_string()));
    }

    // Try ZFS clone first
    let zfs_dataset = format!("{}/{}/releases/{}", zpool, dataset, release);
    let new_dataset = format!("{}/{}/containers/{}", zpool, dataset, name);

    let clone_result = Command::new("zfs")
        .args([
            "clone",
            "-p",
            &format!("{}@base", zfs_dataset),
            &new_dataset,
        ])
        .status();

    let using_zfs = match clone_result {
        Ok(status) if status.success() => true,
        _ => {
            // Fall back to copying
            println!("ZFS clone not available, copying release (this may take a while)...");
            std::fs::create_dir_all(&jail_root)?;

            let release_path_str = release_path.to_str().ok_or_else(|| {
                error::Error::JailCreationFailed("Invalid UTF-8 in release path".into())
            })?;
            let jail_root_str = jail_root.to_str().ok_or_else(|| {
                error::Error::JailCreationFailed("Invalid UTF-8 in jail root path".into())
            })?;

            // Use "/." suffix to copy contents of release into jail_root, not the directory itself
            let release_cp_src = format!("{}/.", release_path_str);
            let status = Command::new("cp")
                .args(["-a", &release_cp_src, jail_root_str])
                .status()?;
            if !status.success() {
                return Err(error::Error::JailCreationFailed(
                    "Failed to copy release".to_string(),
                ));
            }
            false
        }
    };

    let mut allocated_ip: Option<(String, std::net::IpAddr)> = None;
    let mut vnet_setup: Option<network::VnetSetup> = None;

    if let Some(network_name) = network {
        let (runtime_networks, mut allocator, _) = network::build_runtime_allocator(config)?;
        let runtime_network = runtime_networks
            .get(network_name)
            .cloned()
            .ok_or_else(|| error::Error::NetworkNotFound(network_name.to_string()))?;
        let bridge_name = runtime_network.bridge.clone().ok_or_else(|| {
            error::Error::Network(format!(
                "Network '{}' exists but has no host bridge. Create it with 'blackship network create {} ...'",
                network_name, network_name
            ))
        })?;

        let ip = allocator.allocate(network_name)?;
        if let Err(err) = lease_store.record(network_name, name, ip) {
            if using_zfs {
                let _ = Command::new("zfs")
                    .args(["destroy", "-r", &new_dataset])
                    .status();
            } else {
                let _ = std::fs::remove_dir_all(&jail_root);
            }
            return Err(err);
        }
        allocated_ip = Some((network_name.to_string(), ip));

        let vnet_config = network::VnetConfig::new(
            bridge_name,
            format!("{}/{}", ip, runtime_network.subnet.prefix_len()),
            runtime_network.gateway,
        );
        match network::VnetSetup::create(name, vnet_config) {
            Ok(setup) => {
                let state_record = setup.state_record(name, Some(network_name));
                if let Err(err) = vnet_state_store.save(&state_record) {
                    let _ = setup.cleanup();
                    let _ = lease_store.release(network_name, name);
                    if using_zfs {
                        let _ = Command::new("zfs")
                            .args(["destroy", "-r", &new_dataset])
                            .status();
                    } else {
                        let _ = std::fs::remove_dir_all(&jail_root);
                    }
                    return Err(err);
                }
                vnet_setup = Some(setup);
            }
            Err(err) => {
                let _ = lease_store.release(network_name, name);
                if using_zfs {
                    let _ = Command::new("zfs")
                        .args(["destroy", "-r", &new_dataset])
                        .status();
                } else {
                    let _ = std::fs::remove_dir_all(&jail_root);
                }
                return Err(err);
            }
        }
    }

    // Determine the command to run
    let jail_command = if command.is_empty() {
        vec!["/bin/sh".to_string()]
    } else {
        command.to_vec()
    };

    // Build jail.conf parameters
    let mut jail_params = vec![
        format!("name={}", name),
        format!("path={}", jail_root.display()),
        "exec.start=/bin/sh /etc/rc".to_string(),
        "exec.stop=/bin/sh /etc/rc.shutdown jail".to_string(),
        "mount.devfs".to_string(),
        "allow.raw_sockets".to_string(),
        "allow.socket_af".to_string(),
        "allow.chflags".to_string(),
    ];

    // Add network configuration
    if network.is_some() {
        // vnet is a boolean flag, not a key=value parameter
        jail_params.push("vnet".to_string());
    } else {
        // Use shared IP mode with loopback
        jail_params.push("ip4=inherit".to_string());
    }

    // Start the jail
    let mut jail_cmd = Command::new("jail");
    jail_cmd.arg("-c");
    for param in &jail_params {
        jail_cmd.arg(param);
    }

    let status = jail_cmd.status()?;
    if !status.success() {
        if let Some(setup) = vnet_setup.take() {
            let _ = setup.cleanup();
            let _ = vnet_state_store.delete(name);
        }
        if let Some((network_name, _ip)) = &allocated_ip {
            let _ = lease_store.release(network_name, name);
        }
        let _ = cleanup_jail_root(&jail_root, Some(&new_dataset), using_zfs);
        return Err(error::Error::JailCreationFailed(
            "Failed to start jail".to_string(),
        ));
    }

    if let Some(setup) = vnet_setup.as_ref() {
        let jid = crate::jail::jail_getid(name)?;
        if let Err(err) = setup.attach_to_jail(jid) {
            let _ = Command::new("jail").args(["-r", name]).status();
            let _ = network_cleanup(config, name);
            let _ = cleanup_jail_root(&jail_root, Some(&new_dataset), using_zfs);
            return Err(err);
        }
    }

    println!("Jail '{}' started from release '{}'", name, release);

    if detach {
        // In detach mode, just return - jail keeps running
        println!(
            "Running in detached mode. Use 'blackship exec {}' to run commands.",
            name
        );
        println!("Use 'blackship rm {}' to stop and remove.", name);
        return Ok(());
    }

    // Execute the command
    let opts = console::ExecOptions::default();
    let exec_status = console::exec_in_jail(name, &jail_command, &opts);

    // Always cleanup ephemeral jails in non-detached mode
    println!("Cleaning up ephemeral jail '{}'...", name);
    // Stop the jail
    let _ = Command::new("jail").args(["-r", name]).status();
    let _ = network_cleanup(config, name);
    if let Err(err) = cleanup_jail_root(&jail_root, Some(&new_dataset), using_zfs) {
        eprintln!("Warning: Failed to clean up jail root '{}': {}", name, err);
    }

    match exec_status {
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(e) => Err(e),
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
    use std::process::Command;

    let (src_jail, src_path) = parse_jail_path(source);
    let (dst_jail, dst_path) = parse_jail_path(dest);

    // Can't copy from jail to jail directly
    if src_jail.is_some() && dst_jail.is_some() {
        return Err(error::Error::InvalidArgument(
            "Cannot copy directly between two jails. Copy to host first.".to_string(),
        ));
    }

    // Get jail root paths
    let src_full = if let Some(jail) = src_jail {
        let jail_root = get_jail_root(&jail, config)?;
        jail_root.join(src_path.trim_start_matches('/'))
    } else {
        std::path::PathBuf::from(src_path)
    };

    let dst_full = if let Some(jail) = dst_jail {
        let jail_root = get_jail_root(&jail, config)?;
        jail_root.join(dst_path.trim_start_matches('/'))
    } else {
        std::path::PathBuf::from(dst_path)
    };

    // Verify source exists
    if !src_full.exists() {
        return Err(error::Error::CopyFailed(format!(
            "Source '{}' not found",
            source
        )));
    }

    // Verify destination parent exists
    if let Some(parent) = dst_full.parent()
        && !parent.exists()
    {
        return Err(error::Error::CopyFailed(format!(
            "Destination directory '{}' does not exist",
            parent.display()
        )));
    }

    // Build cp command
    // Use -r for recursive, -p for preserve (not -a which is GNU-specific)
    let mut cmd = Command::new("cp");
    cmd.arg("-r");
    if preserve {
        cmd.arg("-p");
    }
    cmd.arg(&src_full);
    cmd.arg(&dst_full);

    let status = cmd.status()?;
    if !status.success() {
        return Err(error::Error::CopyFailed(format!(
            "Failed to copy {} to {}",
            src_full.display(),
            dst_full.display()
        )));
    }

    println!("Copied {} -> {}", source, dest);
    Ok(())
}

/// Remove/destroy jails
pub fn remove_jails(
    jails: &[String],
    force: bool,
    volumes: bool,
    config: Option<&manifest::BlackshipConfig>,
) -> Result<()> {
    use std::process::Command;

    // Get ZFS config from config or use defaults
    let (zpool, dataset) = config
        .map(|c| {
            (
                c.config
                    .zpool
                    .clone()
                    .unwrap_or_else(|| "zroot".to_string()),
                c.config.dataset.clone(),
            )
        })
        .unwrap_or_else(|| ("zroot".to_string(), "blackship".to_string()));

    for jail in jails {
        println!("Removing jail '{}'...", jail);

        // Check if jail is running
        let jls_output = Command::new("jls").args(["-j", jail]).output();

        let is_running = jls_output.map(|o| o.status.success()).unwrap_or(false);

        if is_running {
            if !force {
                eprintln!(
                    "Error: Jail '{}' is running. Use --force to stop and remove.",
                    jail
                );
                continue;
            }
            // Stop the jail
            println!("  Stopping jail...");
            let stop_status = Command::new("jail").args(["-r", jail]).status()?;
            if !stop_status.success() {
                eprintln!("  Warning: Failed to stop jail cleanly");
            }
        }

        // Get jail path before removing
        let jail_root = get_jail_root(jail, config);
        if let Err(e) = network_cleanup(config, jail) {
            if force {
                eprintln!("  Warning: Failed to clean up network state: {}", e);
            } else {
                return Err(e);
            }
        }

        if let Ok(root) = &jail_root
            && let Err(e) = unmount_jail_filesystems(root)
        {
            if force {
                eprintln!("  Warning: Failed to unmount jail filesystems: {}", e);
            } else {
                return Err(e);
            }
        }

        // Try to remove ZFS dataset if volumes flag is set
        if volumes {
            // Stop the jail first if running (ensures clean ZFS removal)
            let _ = Command::new("jail").args(["-r", jail]).status();

            let zfs_dataset = format!("{}/{}/containers/{}", zpool, dataset, jail);
            let zfs_result = Command::new("zfs")
                .args(["destroy", "-r", &zfs_dataset])
                .status();

            if zfs_result.map(|s| s.success()).unwrap_or(false) {
                println!("  Removed ZFS dataset: {}", zfs_dataset);
                continue;
            }
        }

        // Fall back to removing directory
        if let Ok(root) = jail_root
            && root.exists()
        {
            if let Err(e) = std::fs::remove_dir_all(&root) {
                eprintln!("Error removing {}: {}", root.display(), e);
                continue;
            }
            println!("  Removed jail root: {}", root.display());
        }

        println!("Jail '{}' removed.", jail);
    }

    Ok(())
}

/// Parse a jail:path format string
///
/// Returns (Some(jail_name), path) for "jail:path" format,
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

    // Try to get jail path from jls (running jail)
    let output = Command::new("jls")
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

    // Get data_dir from config or use XDG default
    let data_dir = config
        .map(|c| c.config.data_dir.clone())
        .unwrap_or_else(manifest::default_data_dir);

    // Fall back to checking common locations
    let containers_path = data_dir.join("containers").join(jail);
    if containers_path.exists() {
        return Ok(containers_path);
    }

    let jails_path = data_dir.join("jails").join(jail);
    if jails_path.exists() {
        return Ok(jails_path);
    }

    Err(error::Error::JailNotFound(jail.to_string()))
}

fn network_cleanup(config: Option<&manifest::BlackshipConfig>, owner: &str) -> Result<()> {
    let vnet_state_store = network::VnetStateStore::from_config(config);
    if let Some(record) = vnet_state_store.get(owner)? {
        network::VnetSetup::cleanup_state(&record)?;
        let _ = vnet_state_store.delete(owner)?;
    }

    let lease_store = network::NetworkLeaseStore::from_config(config);
    let _ = lease_store.release_owner(owner)?;
    Ok(())
}

fn cleanup_jail_root(jail_root: &Path, zfs_dataset: Option<&str>, using_zfs: bool) -> Result<()> {
    if jail_root.exists() {
        unmount_jail_filesystems(jail_root)?;
    }

    if using_zfs {
        let Some(dataset) = zfs_dataset else {
            return Err(error::Error::JailOperation(
                "Missing ZFS dataset for jail cleanup".to_string(),
            ));
        };

        let status = std::process::Command::new("zfs")
            .args(["destroy", "-r", dataset])
            .status()?;
        if !status.success() {
            return Err(error::Error::JailOperation(format!(
                "Failed to destroy ZFS dataset '{}'",
                dataset
            )));
        }
    } else if jail_root.exists() {
        std::fs::remove_dir_all(jail_root)?;
    }

    Ok(())
}

fn unmount_jail_filesystems(jail_root: &Path) -> Result<()> {
    let output = std::process::Command::new("mount").arg("-p").output()?;
    if !output.status.success() {
        return Err(error::Error::JailOperation(
            "Failed to inspect mounted filesystems".to_string(),
        ));
    }

    let mounts = mounted_paths_under(jail_root, String::from_utf8_lossy(&output.stdout).as_ref());

    for mountpoint in mounts {
        unmount_path(&mountpoint)?;
    }

    Ok(())
}

fn mounted_paths_under(jail_root: &Path, mount_output: &str) -> Vec<PathBuf> {
    let root = jail_root.to_string_lossy();
    let prefix = format!("{}/", root);
    let mut mountpoints: Vec<PathBuf> = mount_output
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let _source = fields.next()?;
            let mountpoint = fields.next()?;
            if mountpoint == root || mountpoint.starts_with(&prefix) {
                Some(PathBuf::from(mountpoint))
            } else {
                None
            }
        })
        .collect();

    mountpoints.sort_by_key(|path| std::cmp::Reverse(path.to_string_lossy().len()));
    mountpoints
}

fn unmount_path(path: &Path) -> Result<()> {
    let path_str = path.to_string_lossy().into_owned();
    let c_path = CString::new(path_str.clone())?;

    let result = unsafe { libc::unmount(c_path.as_ptr(), 0) };
    if result == 0 {
        return Ok(());
    }

    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(code) if code == libc::EINVAL || code == libc::ENOENT => return Ok(()),
        _ => {}
    }

    let force_result = unsafe { libc::unmount(c_path.as_ptr(), libc::MNT_FORCE) };
    if force_result == 0 {
        return Ok(());
    }

    Err(error::Error::JailOperation(format!(
        "Failed to unmount '{}': {}",
        path.display(),
        std::io::Error::last_os_error()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_jail_path_with_jail() {
        let (jail, path) = parse_jail_path("myjail:/etc/hosts");
        assert_eq!(jail, Some("myjail".to_string()));
        assert_eq!(path, "/etc/hosts");
    }

    #[test]
    fn test_parse_jail_path_host_only() {
        let (jail, path) = parse_jail_path("/etc/hosts");
        assert_eq!(jail, None);
        assert_eq!(path, "/etc/hosts");
    }

    #[test]
    fn test_parse_jail_path_multiple_colons() {
        // Path with multiple colons - first colon determines split
        let (jail, path) = parse_jail_path("myjail:/path/with:colon");
        assert_eq!(jail, Some("myjail".to_string()));
        assert_eq!(path, "/path/with:colon");
    }

    #[test]
    fn test_parse_jail_path_empty_path() {
        let (jail, path) = parse_jail_path("myjail:");
        assert_eq!(jail, Some("myjail".to_string()));
        assert_eq!(path, "");
    }

    #[test]
    fn test_parse_jail_path_relative() {
        let (jail, path) = parse_jail_path("./local/file");
        assert_eq!(jail, None);
        assert_eq!(path, "./local/file");
    }

    #[test]
    fn test_mounted_paths_under_sorts_deepest_first() {
        let mounts = mounted_paths_under(
            Path::new("/var/blackship/jails/demo"),
            "\
devfs /var/blackship/jails/demo/dev devfs rw 0 0\n\
procfs /var/blackship/jails/demo/proc procfs rw 0 0\n\
fdescfs /var/blackship/jails/demo/dev/fd fdescfs rw 0 0\n\
tmpfs /tmp tmpfs rw 0 0\n",
        );

        assert_eq!(
            mounts,
            vec![
                PathBuf::from("/var/blackship/jails/demo/dev/fd"),
                PathBuf::from("/var/blackship/jails/demo/proc"),
                PathBuf::from("/var/blackship/jails/demo/dev"),
            ]
        );
    }
}
