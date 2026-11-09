//! Copying between the host and a jail root, without letting anything
//! inside the jail redirect the copy through a symlink.

use crate::error::{Error, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// A path inside a jail, with the jail's root on the host.
#[derive(Debug, Clone)]
pub struct JailSide {
    /// Running jail to freeze for the duration of the copy.
    pub(crate) jid: Option<i32>,
    pub(crate) root: PathBuf,
    /// Path inside the jail, absolute or relative to its root.
    pub(crate) path: String,
}

/// One end of a copy.
#[derive(Debug)]
pub enum Side<'a> {
    Host(&'a Path),
    Jail(JailSide),
}

impl Side<'_> {
    const fn jail(&self) -> Option<&JailSide> {
        match self {
            Side::Jail(side) => Some(side),
            Side::Host(_) => None,
        }
    }
}

/// Copy `src` to `dst` with `cp -R`; exactly one side may be a jail. Running
/// jails are frozen (SIGSTOP) so nothing can swap in a symlink mid-copy.
pub fn transfer(src: &Side<'_>, dst: &Side<'_>, preserve: bool) -> Result<()> {
    if src.jail().is_some() && dst.jail().is_some() {
        return Err(Error::InvalidArgument(
            "Cannot copy directly between two jails. Copy to host first.".to_string(),
        ));
    }

    let src_full = match &src {
        Side::Jail(jail) => resolve_jail_source(jail)?,
        Side::Host(path) => path.to_path_buf(),
    };

    let frozen: Vec<i32> = [src.jail(), dst.jail()]
        .into_iter()
        .flatten()
        .filter_map(|j| j.jid)
        .collect();
    for jid in &frozen {
        signal_jail(*jid, "-STOP");
    }

    let result = (|| -> Result<()> {
        let dst_full = match &dst {
            Side::Jail(jail) => resolve_jail_destination(jail)?,
            Side::Host(path) => path.to_path_buf(),
        };

        if !src_full.exists() {
            return Err(Error::CopyFailed(format!(
                "Source '{}' not found",
                src_full.display()
            )));
        }

        if let Some(parent) = dst_full.parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            return Err(Error::CopyFailed(format!(
                "Destination directory '{}' does not exist",
                parent.display()
            )));
        }

        if dst.jail().is_some()
            && dst_full.is_dir()
            && let Some(basename) = src_full.file_name()
        {
            let effective_target = dst_full.join(basename);
            if let Ok(meta) = std::fs::symlink_metadata(&effective_target)
                && meta.file_type().is_symlink()
            {
                return Err(Error::InvalidArgument(format!(
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
        let output = cmd.arg(&src_full).arg(&dst_full).output()?;
        if !output.status.success() {
            return Err(Error::CopyFailed(format!(
                "Failed to copy {} to {}: {}",
                src_full.display(),
                dst_full.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    })();

    for jid in &frozen {
        signal_jail(*jid, "-CONT");
    }
    result
}

fn signal_jail(jid: i32, signal: &str) {
    // pkill exits non-zero when the jail has no processes; nothing to report.
    let _ = Command::new("/bin/pkill")
        .args([signal, "-j", &jid.to_string()])
        .status();
}

/// The real path of a jail-side source, refusing anything outside the root.
fn resolve_jail_source(jail: &JailSide) -> Result<PathBuf> {
    let joined = jail.root.join(jail.path.trim_start_matches('/'));
    let resolved = joined
        .canonicalize()
        .map_err(|_| Error::CopyFailed(format!("Source path '{}' not found in jail", jail.path)))?;
    let root = jail
        .root
        .canonicalize()
        .unwrap_or_else(|_| jail.root.clone());
    if !resolved.starts_with(&root) {
        return Err(Error::InvalidArgument(format!(
            "Source path '{}' escapes jail root",
            jail.path
        )));
    }
    Ok(resolved)
}

/// The host path a jail-side destination lands on, confined to the root.
fn resolve_jail_destination(jail: &JailSide) -> Result<PathBuf> {
    let dst_path = &jail.path;
    let root = jail
        .root
        .canonicalize()
        .unwrap_or_else(|_| jail.root.clone());
    let joined = jail.root.join(dst_path.trim_start_matches('/'));
    let parent = joined.parent().ok_or_else(|| {
        Error::CopyFailed(format!(
            "Destination path '{dst_path}' has no parent directory"
        ))
    })?;
    let resolved_parent = parent.canonicalize().map_err(|_| {
        Error::CopyFailed(format!(
            "Destination directory for '{dst_path}' not found in jail"
        ))
    })?;
    if !resolved_parent.starts_with(&root) {
        return Err(Error::InvalidArgument(format!(
            "Destination path '{dst_path}' escapes jail root"
        )));
    }
    let final_path = match joined.file_name() {
        Some(file_name) => resolved_parent.join(file_name),
        None => resolved_parent,
    };
    if let Ok(meta) = std::fs::symlink_metadata(&final_path) {
        if meta.file_type().is_symlink() {
            return Err(Error::InvalidArgument(format!(
                "Destination '{dst_path}' is a symlink, which is not allowed as a copy destination"
            )));
        }
        let resolved_final = final_path.canonicalize().map_err(|_| {
            Error::CopyFailed(format!("Cannot resolve destination '{dst_path}' in jail"))
        })?;
        if !resolved_final.starts_with(&root) {
            return Err(Error::InvalidArgument(format!(
                "Destination '{dst_path}' resolves outside jail root (symlink escape)"
            )));
        }
    }
    Ok(final_path)
}

/// Reject any symlink in a directory tree; pre-validates recursive copy destinations.
fn reject_dest_symlinks(dir: &Path) -> Result<()> {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Ok(meta) = std::fs::symlink_metadata(entry.path()) {
                if meta.file_type().is_symlink() {
                    return Err(Error::InvalidArgument(format!(
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

#[cfg(test)]
mod tests;
