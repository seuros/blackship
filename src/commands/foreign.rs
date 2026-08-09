//! Import jails from other jail managers (iocage, ezjail, plain rootfs).
//!
//! Best-effort conversion: the filesystem comes over intact and blackship
//! prints the [[jails]] definition it derived from the foreign metadata.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{Error, Result};
use crate::manifest;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForeignFormat {
    Iocage,
    Ezjail,
    Rootfs,
}

impl ForeignFormat {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "iocage" => Ok(Self::Iocage),
            "ezjail" => Ok(Self::Ezjail),
            "rootfs" | "qjail" => Ok(Self::Rootfs),
            other => Err(Error::InvalidArgument(format!(
                "Unknown import format '{}' (expected iocage, ezjail, or rootfs)",
                other
            ))),
        }
    }
}

/// Detect the source manager from the archive itself.
fn detect_format(file: &Path) -> ForeignFormat {
    if file.extension().and_then(|e| e.to_str()) == Some("zip") {
        return ForeignFormat::Iocage;
    }
    if let Ok(output) = Command::new("/usr/bin/tar").arg("-tf").arg(file).output() {
        let listing = String::from_utf8_lossy(&output.stdout);
        if listing.lines().any(|l| l.contains("prop.ezjail")) {
            return ForeignFormat::Ezjail;
        }
    }
    ForeignFormat::Rootfs
}

pub fn handle_foreign_import(
    config_path: &Path,
    file: PathBuf,
    name: Option<String>,
    from: Option<String>,
) -> Result<()> {
    let config = manifest::load_or_default(config_path)?;
    let format = match from.as_deref() {
        Some("auto") | None => detect_format(&file),
        Some(explicit) => ForeignFormat::parse(explicit)?,
    };

    if !file.exists() {
        return Err(Error::InvalidArgument(format!(
            "Archive '{}' not found",
            file.display()
        )));
    }

    let staging = config.config.cache_dir.join("foreign-import");
    let _ = crate::sys::remove_tree_with_flags(&staging);
    std::fs::create_dir_all(&staging)?;

    // bsdtar reads zip, tar, and every compression in use here.
    let status = Command::new("/usr/bin/tar")
        .arg("-xf")
        .arg(&file)
        .arg("-C")
        .arg(&staging)
        .status()
        .map_err(|e| Error::JailOperation(format!("Failed to run tar: {}", e)))?;
    if !status.success() {
        return Err(Error::JailOperation(format!(
            "Failed to extract '{}'",
            file.display()
        )));
    }

    let (jail_name, root_source, ip_hint, release_hint) = match format {
        ForeignFormat::Iocage => import_iocage(&staging, name)?,
        ForeignFormat::Ezjail => import_ezjail(&staging, &file, name)?,
        ForeignFormat::Rootfs => import_rootfs(&staging, &file, name)?,
    };

    manifest::validate_name("jail", &jail_name)?;
    let target = config.config.data_dir.join("jails").join(&jail_name);
    if target.join("bin").exists() {
        return Err(Error::JailOperation(format!(
            "Jail root '{}' already exists",
            target.display()
        )));
    }

    // Put the root on a dataset when ZFS is on, same as native jails.
    if let Some(zfs) = super::bootstrap::release_zfs(&config)
        && !zfs.jail_dataset_exists(&jail_name)?
    {
        zfs.init()?;
        zfs.create_jail_dataset(&jail_name)?;
    }
    std::fs::create_dir_all(&target)?;

    let status = Command::new("/bin/cp")
        .arg("-a")
        .arg(format!("{}/.", root_source.display()))
        .arg(&target)
        .status()
        .map_err(|e| Error::JailOperation(format!("Failed to copy root: {}", e)))?;
    if !status.success() {
        return Err(Error::JailOperation(
            "Failed to copy imported root into place".to_string(),
        ));
    }
    let _ = crate::sys::remove_tree_with_flags(&staging);

    println!(
        "Imported '{}' -> {}",
        file.display(),
        target.display()
    );
    println!("\nAdd it to blackship.toml:");
    println!("[[jails]]");
    println!("name = \"{}\"", jail_name);
    if let Some(release) = release_hint {
        println!("# origin release: {}", release);
    }
    println!("\n[jails.network]");
    println!("vnet = true");
    println!("networks = [\"default\"]");
    match ip_hint {
        Some(ip) => println!("ip = \"{}\"", ip),
        None => println!("# ip = \"10.0.1.x\""),
    }
    if format == ForeignFormat::Ezjail {
        println!(
            "\nNote: ezjail thin jails carry only etc/var; overlay them on a\nbootstrapped release (the basejail is not in the archive)."
        );
    }
    Ok(())
}

/// iocage export: a zip holding config.json plus one or two zfs streams.
fn import_iocage(
    staging: &Path,
    name: Option<String>,
) -> Result<(String, PathBuf, Option<String>, Option<String>)> {
    let config_json = find_file(staging, "config.json").ok_or_else(|| {
        Error::JailOperation("No config.json in archive; not an iocage export?".to_string())
    })?;
    let parsed: serde_json::Value = serde_json::from_slice(&std::fs::read(&config_json)?)
        .map_err(|e| Error::JailOperation(format!("Invalid iocage config.json: {}", e)))?;

    let jail_name = name
        .or_else(|| {
            parsed
                .get("host_hostname")
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .ok_or_else(|| {
            Error::InvalidArgument("Cannot derive a jail name; pass --name".to_string())
        })?;

    // iocage ip4_addr looks like "vnet0|10.0.0.5/24" or "none"
    let ip_hint = parsed
        .get("ip4_addr")
        .and_then(|v| v.as_str())
        .filter(|s| *s != "none")
        .and_then(|s| s.rsplit('|').next())
        .and_then(|s| s.split('/').next())
        .map(String::from);
    let release_hint = parsed
        .get("release")
        .and_then(|v| v.as_str())
        .map(String::from);

    // Prefer an extracted root/ directory; iocage zips of zfs streams need
    // a manual `zfs receive` and are called out explicitly.
    for candidate in ["root", "_root"] {
        let dir = config_json.parent().unwrap_or(staging).join(candidate);
        if dir.join("bin").exists() {
            return Ok((jail_name, dir, ip_hint, release_hint));
        }
    }
    if let Some(dir) = find_root_dir(staging) {
        return Ok((jail_name, dir, ip_hint, release_hint));
    }
    Err(Error::JailOperation(
        "Archive holds zfs send streams, not files. Receive them manually:\n  \
         zfs receive zroot/blackship/jails/<name> < <stream>_root"
            .to_string(),
    ))
}

/// ezjail archive: jail tree plus prop.ezjail-* metadata file.
fn import_ezjail(
    staging: &Path,
    file: &Path,
    name: Option<String>,
) -> Result<(String, PathBuf, Option<String>, Option<String>)> {
    let jail_name = name
        .or_else(|| {
            file.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.split('-').next().unwrap_or(n).to_string())
        })
        .ok_or_else(|| {
            Error::InvalidArgument("Cannot derive a jail name; pass --name".to_string())
        })?;

    // prop.ezjail-<name>-<date>: filename encodes the ip in some versions;
    // the tree itself is what matters.
    let root = find_root_dir(staging).unwrap_or_else(|| staging.to_path_buf());
    Ok((jail_name, root, None, None))
}

/// Plain rootfs tar (qjail or hand-rolled): find the directory with bin/sh.
fn import_rootfs(
    staging: &Path,
    file: &Path,
    name: Option<String>,
) -> Result<(String, PathBuf, Option<String>, Option<String>)> {
    let jail_name = name
        .or_else(|| {
            file.file_stem()
                .and_then(|n| n.to_str())
                .map(|n| n.split('.').next().unwrap_or(n).to_string())
        })
        .ok_or_else(|| {
            Error::InvalidArgument("Cannot derive a jail name; pass --name".to_string())
        })?;
    let root = find_root_dir(staging).ok_or_else(|| {
        Error::JailOperation("No FreeBSD root (bin/sh) found in archive".to_string())
    })?;
    Ok((jail_name, root, None, None))
}

/// Breadth-first search (3 levels) for an entry matching the predicate.
fn find_entry(base: &Path, matches: impl Fn(&Path) -> bool) -> Option<PathBuf> {
    let mut queue = vec![(base.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = queue.pop() {
        if matches(&dir) {
            return Some(dir);
        }
        if depth < 3
            && let Ok(entries) = std::fs::read_dir(&dir)
        {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    queue.push((path, depth + 1));
                }
            }
        }
    }
    None
}

/// Find a directory containing a FreeBSD userland (bin/sh).
fn find_root_dir(base: &Path) -> Option<PathBuf> {
    find_entry(base, |dir| dir.join("bin/sh").exists())
}

/// Find a file by name, returning its full path.
fn find_file(base: &Path, target: &str) -> Option<PathBuf> {
    find_entry(base, |dir| dir.join(target).is_file()).map(|dir| dir.join(target))
}
