//! Atomic TOML state files
//!
//! Write to a uniquely-named temp file, then rename over the target.

use crate::error::{Error, Result};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Read and parse a TOML state file. `label` names it in errors.
pub fn read_toml<T: DeserializeOwned>(path: &Path, label: &str) -> Result<T> {
    let content = fs::read_to_string(path)
        .map_err(|e| Error::State(format!("Failed to read {label}: {e}")))?;
    toml::from_str(&content).map_err(|e| Error::State(format!("Failed to parse {label}: {e}")))
}

/// Serialize `value` and replace `path` with it atomically.
pub fn write_toml_atomic<T: Serialize>(path: &Path, value: &T, label: &str) -> Result<()> {
    let content = toml::to_string(value)
        .map_err(|e| Error::State(format!("Failed to serialize {label}: {e}")))?;

    write_atomic(path, &content, label)
}

/// Replace `path` with `content` atomically.
///
/// The temp file is created beside the target, so the final rename stays
/// within one filesystem.
pub fn write_atomic(path: &Path, content: &str, label: &str) -> Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::Builder::new()
        .prefix(".blackship-")
        .suffix(".tmp")
        // Unprivileged commands read state root writes; tempfile defaults to 0600.
        .permissions(fs::Permissions::from_mode(0o644))
        .tempfile_in(dir)
        .map_err(|e| Error::State(format!("Failed to create {label} temp file: {e}")))?;
    tmp.write_all(content.as_bytes())
        .map_err(|e| Error::State(format!("Failed to write {label}: {e}")))?;
    tmp.persist(path)
        .map_err(|e| Error::State(format!("Failed to finalize {label}: {}", e.error)))?;
    Ok(())
}

#[cfg(test)]
mod tests;
