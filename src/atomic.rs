//! Atomic TOML state files
//!
//! Write to a uniquely-named temp file, then rename over the target.

use crate::error::{Error, Result};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::Path;

/// Read and parse a TOML state file. `label` names it in errors.
pub fn read_toml<T: DeserializeOwned>(path: &Path, label: &str) -> Result<T> {
    let content = fs::read_to_string(path)
        .map_err(|e| Error::Network(format!("Failed to read {}: {}", label, e)))?;
    toml::from_str(&content)
        .map_err(|e| Error::Network(format!("Failed to parse {}: {}", label, e)))
}

/// Serialize `value` and replace `path` with it atomically.
pub fn write_toml_atomic<T: Serialize>(path: &Path, value: &T, label: &str) -> Result<()> {
    let content = toml::to_string(value)
        .map_err(|e| Error::Network(format!("Failed to serialize {}: {}", label, e)))?;

    let nonce = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        std::process::id() ^ nanos
    };

    // create_new fails on an existing path (symlink attack), so walk the
    // suffix until we win a name: concurrent writers otherwise collide.
    let mut tmp_path = path.with_extension(format!("{}.tmp", nonce));
    let mut file = None;
    for attempt in 0..64u32 {
        if attempt > 0 {
            tmp_path = path.with_extension(format!("{}-{}.tmp", nonce, attempt));
        }
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
        {
            Ok(f) => {
                file = Some(f);
                break;
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(Error::Network(format!(
                    "Failed to create {} temp file: {}",
                    label, e
                )));
            }
        }
    }

    {
        let mut f = file.ok_or_else(|| {
            Error::Network(format!(
                "Failed to create {} temp file: no free name",
                label
            ))
        })?;
        f.write_all(content.as_bytes())
            .map_err(|e| Error::Network(format!("Failed to write {}: {}", label, e)))?;
    }

    fs::rename(&tmp_path, path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        Error::Network(format!("Failed to finalize {}: {}", label, e))
    })
}
