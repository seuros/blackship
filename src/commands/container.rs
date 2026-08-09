//! Docker-style container commands: run, cp, rm

use crate::error::Result;
use crate::manifest::validate_name;
use crate::{console, error, manifest, network};
use std::ffi::CString;
use std::path::{Path, PathBuf};

/// Run a command in an ephemeral jail
///
/// Creates a jail from a release, runs the command, and cleans up.
/// In detached mode, the jail persists until removed with `blackship rm`.
/// Total bytes used by a directory tree (best effort)
fn dir_size(path: &Path) -> Option<u64> {
    let output = std::process::Command::new("/usr/bin/du")
        .args(["-sk"])
        .arg(path)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let kib: u64 = text.split_whitespace().next()?.parse().ok()?;
    Some(kib * 1024)
}

/// Free bytes on the filesystem holding `path`
fn free_space(path: &Path) -> Option<u64> {
    use std::ffi::CString;
    let c_path = CString::new(path.to_str()?).ok()?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c_path.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    Some(stat.f_bavail as u64 * stat.f_bsize as u64)
}

/// The effective data dir: config's when present, default otherwise.
fn data_dir_of(config: Option<&manifest::BlackshipConfig>) -> std::path::PathBuf {
    config
        .map(|c| c.config.data_dir.clone())
        .unwrap_or_else(manifest::default_data_dir)
}

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

    let data_dir = data_dir_of(config);

    let (zpool, dataset) = zfs_pool_dataset(config);

    // Name lands in filesystem paths, ZFS datasets, and state records.
    validate_name("container", name)?;

    validate_name("release", release)?;

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
    let mut jail_root = data_dir.join("containers").join(name);

    crate::blueprint::context::reject_symlink_ancestors(&data_dir, &jail_root)?;

    // A destroyed dataset leaves its empty mountpoint dir behind; only a
    // root with content means the name is genuinely taken.
    if jail_root.exists() {
        let occupied = std::fs::read_dir(&jail_root)
            .map(|mut entries| entries.next().is_some())
            .unwrap_or(true);
        if occupied {
            return Err(error::Error::JailExists(name.to_string()));
        }
        let _ = std::fs::remove_dir(&jail_root);
    }

    // Try ZFS clone first
    let zfs_dataset = format!("{}/{}/releases/{}", zpool, dataset, release);
    let new_dataset = format!("{}/{}/containers/{}", zpool, dataset, name);

    let clone_result = Command::new("/sbin/zfs")
        .args([
            "clone",
            "-p",
            &format!("{}@pristine", zfs_dataset),
            &new_dataset,
        ])
        .status();

    let using_zfs = match clone_result {
        Ok(status) if status.success() => {
            // Keep the root under data_dir/containers like the copy path.
            let mount_ok = Command::new("/sbin/zfs")
                .args([
                    "set",
                    &format!("mountpoint={}", jail_root.display()),
                    &new_dataset,
                ])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !mount_ok {
                if let Ok(output) = Command::new("/sbin/zfs")
                    .args(["get", "-H", "-o", "value", "mountpoint", &new_dataset])
                    .output()
                    && output.status.success()
                {
                    let mp = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if !mp.is_empty() && mp != "-" {
                        jail_root = PathBuf::from(mp);
                    }
                }
            }
            true
        }
        _ => {
            // Fall back to copying: a full userland per jail, so check the
            // filesystem can take it before starting (chaos runs on a
            // ZFS-less host filled a 39G disk in two rounds).
            if let Some(needed) = dir_size(&release_path) {
                let free = free_space(&data_dir).unwrap_or(u64::MAX);
                if free < needed + needed / 10 {
                    return Err(error::Error::JailCreationFailed(format!(
                        "Not enough space to copy release: need ~{} MiB, {} MiB free on {}. \
                         Enable ZFS for copy-on-write clones.",
                        needed / 1_048_576,
                        free / 1_048_576,
                        data_dir.display()
                    )));
                }
            }
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
            let status = Command::new("/bin/cp")
                .args(["-a", &release_cp_src, jail_root_str])
                .status()?;
            if !status.success() {
                let _ = crate::sys::remove_tree_with_flags(&jail_root);
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
        // Any failure from here on owns a freshly created root: clean it up.
        let net_setup = (|| -> Result<_> {
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
            let ip =
                network::allocate_and_record(&mut allocator, &lease_store, network_name, name)?;
            Ok((runtime_network, bridge_name, ip))
        })();
        let (runtime_network, bridge_name, ip) = match net_setup {
            Ok(v) => v,
            Err(err) => {
                let _ = cleanup_jail_root(&jail_root, Some(&new_dataset), using_zfs);
                return Err(err);
            }
        };
        allocated_ip = Some((network_name.to_string(), ip));

        // Inherit the network's backend so netgraph networks work here too.
        let backend = match runtime_network.backend.as_str() {
            "netgraph" => network::vnet::NetworkBackend::Netgraph,
            _ => network::vnet::NetworkBackend::Epair,
        };
        let vnet_config = network::VnetConfig::new(
            bridge_name,
            format!("{}/{}", ip, runtime_network.subnet.prefix_len()),
            runtime_network.gateway,
        )
        .with_backend(backend);
        match network::VnetSetup::create(name, vnet_config) {
            Ok(setup) => {
                let state_record = setup.state_record(name, Some(network_name));
                if let Err(err) = vnet_state_store.save(&state_record) {
                    let _ = setup.cleanup();
                    let _ = lease_store.release(network_name, name);
                    let _ = cleanup_jail_root(&jail_root, Some(&new_dataset), using_zfs);
                    return Err(err);
                }
                vnet_setup = Some(setup);
            }
            Err(err) => {
                let _ = lease_store.release(network_name, name);
                let _ = cleanup_jail_root(&jail_root, Some(&new_dataset), using_zfs);
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

    // Minimal caps: no raw sockets or chflags -- use `bridge start` for jails needing them.
    let mut jail_params = vec![
        format!("name={}", name),
        format!("path={}", jail_root.display()),
        "exec.start=/bin/sh /etc/rc".to_string(),
        "exec.stop=/bin/sh /etc/rc.shutdown jail".to_string(),
        "mount.devfs".to_string(),
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
    let mut jail_cmd = Command::new("/usr/sbin/jail");
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
            // If `jail -r` fails the jail may still be live: never tear down under it.
            match Command::new("/usr/sbin/jail").args(["-r", name]).status() {
                Ok(status) if status.success() => {
                    let _ = network_cleanup(config, name);
                    let _ = cleanup_jail_root(&jail_root, Some(&new_dataset), using_zfs);
                }
                _ => {
                    eprintln!(
                        "Warning: 'jail -r {}' failed; skipping cleanup (jail may still be running)",
                        name
                    );
                }
            }
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
    let _ = Command::new("/usr/sbin/jail").args(["-r", name]).status();
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

    let src_jail_name = src_jail.clone();

    let src_full = if let Some(jail) = src_jail {
        let jail_root = get_jail_root(&jail, config)?;
        let cp_data_dir = data_dir_of(config);
        crate::blueprint::context::reject_symlink_ancestors(&cp_data_dir, &jail_root)?;
        let joined = jail_root.join(src_path.trim_start_matches('/'));
        let resolved = joined.canonicalize().map_err(|_| {
            error::Error::CopyFailed(format!("Source path '{}' not found in jail", src_path))
        })?;
        if !resolved.starts_with(&jail_root) {
            return Err(error::Error::InvalidArgument(format!(
                "Source path '{}' escapes jail root",
                src_path
            )));
        }
        resolved
    } else {
        std::path::PathBuf::from(src_path)
    };

    let dst_is_jail = dst_jail.is_some();
    let dst_jail_name = dst_jail.clone();

    // Freeze before validating: a live jail process could swap paths for symlinks.
    let src_jail_jid = src_jail_name
        .as_ref()
        .and_then(|name| crate::jail::jail_getid(name).ok());
    if let Some(jid) = src_jail_jid {
        let _ = Command::new("/bin/pkill")
            .args(["-STOP", "-j", &jid.to_string()])
            .status();
    }

    let dst_jail_jid = dst_jail_name
        .as_ref()
        .and_then(|name| crate::jail::jail_getid(name).ok());
    if let Some(jid) = dst_jail_jid {
        let _ = Command::new("/bin/pkill")
            .args(["-STOP", "-j", &jid.to_string()])
            .status();
    }

    // Closure so jail processes get SIGCONT on every error path.
    let copy_result = (|| -> Result<()> {
        let dst_full = if let Some(jail) = dst_jail {
            let jail_root = get_jail_root(&jail, config)?;
            let dst_data_dir = data_dir_of(config);
            crate::blueprint::context::reject_symlink_ancestors(&dst_data_dir, &jail_root)?;
            let joined = jail_root.join(dst_path.trim_start_matches('/'));
            let parent = joined.parent().ok_or_else(|| {
                error::Error::CopyFailed(format!(
                    "Destination path '{}' has no parent directory",
                    dst_path
                ))
            })?;
            let resolved_parent = parent.canonicalize().map_err(|_| {
                error::Error::CopyFailed(format!(
                    "Destination directory for '{}' not found in jail",
                    dst_path
                ))
            })?;
            if !resolved_parent.starts_with(&jail_root) {
                return Err(error::Error::InvalidArgument(format!(
                    "Destination path '{}' escapes jail root",
                    dst_path
                )));
            }
            let final_path = if let Some(file_name) = joined.file_name() {
                resolved_parent.join(file_name)
            } else {
                resolved_parent.clone()
            };
            if let Ok(meta) = std::fs::symlink_metadata(&final_path) {
                if meta.file_type().is_symlink() {
                    return Err(error::Error::InvalidArgument(format!(
                        "Destination '{}' is a symlink, which is not allowed as a copy destination",
                        dst_path
                    )));
                }
                let resolved_final = final_path.canonicalize().map_err(|_| {
                    error::Error::CopyFailed(format!(
                        "Cannot resolve destination '{}' in jail",
                        dst_path
                    ))
                })?;
                let canonical_root = jail_root.canonicalize().unwrap_or(jail_root);
                if !resolved_final.starts_with(&canonical_root) {
                    return Err(error::Error::InvalidArgument(format!(
                        "Destination '{}' resolves outside jail root (symlink escape)",
                        dst_path
                    )));
                }
            }
            final_path
        } else {
            std::path::PathBuf::from(dst_path)
        };

        if !src_full.exists() {
            return Err(error::Error::CopyFailed(format!(
                "Source '{}' not found",
                source
            )));
        }

        if let Some(parent) = dst_full.parent()
            && !parent.exists()
        {
            return Err(error::Error::CopyFailed(format!(
                "Destination directory '{}' does not exist",
                parent.display()
            )));
        }

        if dst_is_jail
            && dst_full.is_dir()
            && let Some(basename) = src_full.file_name()
        {
            let effective_target = dst_full.join(basename);
            if let Ok(meta) = std::fs::symlink_metadata(&effective_target)
                && meta.file_type().is_symlink()
            {
                return Err(error::Error::InvalidArgument(format!(
                    "Effective copy target '{}' is a symlink",
                    effective_target.display()
                )));
            }
            if effective_target.is_dir() {
                reject_dest_symlinks(&effective_target)?;
            }
        }

        // FreeBSD cp: -R does not follow symlinks, -r does.
        let mut cmd = Command::new("/bin/cp");
        cmd.arg("-R");
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
    })();

    if let Some(jid) = src_jail_jid {
        let _ = Command::new("/bin/pkill")
            .args(["-CONT", "-j", &jid.to_string()])
            .status();
    }
    if let Some(jid) = dst_jail_jid {
        let _ = Command::new("/bin/pkill")
            .args(["-CONT", "-j", &jid.to_string()])
            .status();
    }

    copy_result
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
    let (zpool, dataset) = zfs_pool_dataset(config);

    let mut warnings: Vec<String> = Vec::new();
    let mut retained: Vec<String> = Vec::new();

    for jail in jails {
        // Resolve short names and prefixes through the config.
        let resolved = config
            .and_then(|c| c.resolve_jail_names(jail))
            .map(|(_, full)| full)
            .unwrap_or_else(|| jail.clone());
        let jail = &resolved;
        validate_name("jail", jail)?;

        println!("Removing jail '{}'...", jail);

        // Check if jail is running
        let jls_output = Command::new("/usr/sbin/jls").args(["-j", jail]).output();

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
            let stop_status = Command::new("/usr/sbin/jail").args(["-r", jail]).status()?;
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
            let _ = Command::new("/usr/sbin/jail").args(["-r", jail]).status();

            // Managed jails live under jails/, ephemeral ones under containers/.
            let mut destroyed = false;
            for parent in ["jails", "containers"] {
                let zfs_dataset = format!("{}/{}/{}/{}", zpool, dataset, parent, jail);
                let exists = Command::new("/sbin/zfs")
                    .args(["list", "-H", "-o", "name", &zfs_dataset])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                if !exists {
                    continue;
                }
                let zfs_result = Command::new("/sbin/zfs")
                    .args(["destroy", "-r", &zfs_dataset])
                    .status();
                if zfs_result.map(|s| s.success()).unwrap_or(false) {
                    println!("  Removed ZFS dataset: {}", zfs_dataset);
                    destroyed = true;
                } else {
                    warnings.push(format!("dataset '{}' could not be destroyed", zfs_dataset));
                    retained.push(zfs_dataset);
                }
            }
            if destroyed {
                println!("Jail '{}' removed.", jail);
                continue;
            }
        }

        // Fall back to removing directory
        if let Ok(root) = jail_root
            && root.exists()
        {
            let rm_data_dir = data_dir_of(config);
            crate::blueprint::context::reject_symlink_ancestors(&rm_data_dir, &root)?;
            if let Err(e) = crate::sys::remove_tree_with_flags(&root) {
                eprintln!("Error removing {}: {}", root.display(), e);
                continue;
            }
            println!("  Removed jail root: {}", root.display());
        }

        println!("Jail '{}' removed.", jail);
    }

    // Partial failures are reported, not silently swallowed.
    if !warnings.is_empty() {
        eprintln!("Completed with {} warning(s):", warnings.len());
        for warning in &warnings {
            eprintln!("  - {}", warning);
        }
    }
    if !retained.is_empty() {
        eprintln!("Retained datasets (remove manually when ready):");
        for dataset in &retained {
            eprintln!("  - {}", dataset);
        }
    }

    Ok(())
}

fn zfs_pool_dataset(config: Option<&manifest::BlackshipConfig>) -> (String, String) {
    config
        .map(|c| {
            (
                c.config
                    .zpool
                    .clone()
                    .unwrap_or_else(|| "zroot".to_string()),
                c.config.dataset.clone(),
            )
        })
        .unwrap_or_else(|| ("zroot".to_string(), "blackship".to_string()))
}

/// Reject any symlink in a directory tree; pre-validates recursive copy destinations.
fn reject_dest_symlinks(dir: &Path) -> Result<()> {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Ok(meta) = std::fs::symlink_metadata(entry.path()) {
                if meta.file_type().is_symlink() {
                    return Err(error::Error::InvalidArgument(format!(
                        "Destination subtree contains symlink '{}', which could redirect writes outside the jail",
                        entry.path().display()
                    )));
                }
                if meta.file_type().is_dir() {
                    reject_dest_symlinks(&entry.path())?;
                }
            }
        }
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

    // Get data_dir from config or use XDG default
    let data_dir = data_dir_of(config);

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

        let status = std::process::Command::new("/sbin/zfs")
            .args(["destroy", "-r", dataset])
            .status()?;
        if !status.success() {
            return Err(error::Error::JailOperation(format!(
                "Failed to destroy ZFS dataset '{}'",
                dataset
            )));
        }
        // zfs destroy unmounts but leaves the mountpoint dir stub behind
        let _ = std::fs::remove_dir(jail_root);
    } else if jail_root.exists() {
        crate::sys::remove_tree_with_flags(jail_root)?;
    }

    Ok(())
}

fn unmount_jail_filesystems(jail_root: &Path) -> Result<()> {
    let output = std::process::Command::new("/sbin/mount")
        .arg("-p")
        .output()?;
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
