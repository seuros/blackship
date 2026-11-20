//! The on-disk record of a migration in flight: `<data_root>/migrations/<jail>.json`.
//!
//! It exists from before the first effect until the migration settles, so a killed
//! process always leaves a trace of the half-done transfer.

use std::fs::{self, File};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use saga_machines::Snapshot;
use serde::{Deserialize, Serialize};

use crate::atomic::write_atomic;
use crate::error::{Error, Result};
use crate::manifest::{self, BlackshipConfig};

pub const VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub version: u32,
    /// Full jail name; also the record's file name.
    pub jail: String,
    pub service: String,
    pub target: String,
    pub remote_dataset: String,
    pub source_dataset: String,
    /// Snapshot name, without the dataset.
    pub snapshot: String,
    pub keep: bool,
    pub started_at: i64,
    /// The value the source fence carries, fixed before the fence is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fence: Option<String>,
    /// Why a compensation parked the migration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parked: Option<String>,
    /// Compensation attempts that failed since the last success or retry.
    #[serde(default)]
    pub compensation_failures: u32,
    pub saga: Snapshot,
}

pub struct RecordStore {
    root: PathBuf,
}

impl RecordStore {
    pub fn from_config(config: &BlackshipConfig) -> Self {
        Self::new(manifest::data_root(Some(config)).join("migrations"))
    }

    pub const fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn path(&self, jail: &str) -> Result<PathBuf> {
        manifest::validate_name("jail", jail)?;
        Ok(self.root.join(format!("{jail}.json")))
    }

    pub fn exists(&self, jail: &str) -> Result<bool> {
        Ok(self.path(jail)?.exists())
    }

    /// The record, or `None`. A file that does not read back as a sound record is
    /// refused by name and left alone: it may be the only trace of a transfer.
    pub fn load(&self, jail: &str) -> Result<Option<Record>> {
        let path = self.path(jail)?;
        let content = match fs::read_to_string(&path) {
            Ok(content) => content,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(unsound(&path, &e.to_string())),
        };
        let record: Record =
            serde_json::from_str(&content).map_err(|e| unsound(&path, &e.to_string()))?;
        if record.version != VERSION {
            return Err(unsound(
                &path,
                &format!("record version {} is not {VERSION}", record.version),
            ));
        }
        if record.jail != jail {
            return Err(unsound(
                &path,
                &format!("it describes jail '{}'", record.jail),
            ));
        }
        Ok(Some(record))
    }

    pub fn save(&self, record: &Record) -> Result<()> {
        let path = self.path(&record.jail)?;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.root)
            .map_err(|e| Error::State(format!("Failed to create migrations dir: {e}")))?;
        let json = serde_json::to_string_pretty(record)
            .map_err(|e| Error::State(format!("Failed to serialize migration record: {e}")))?;
        write_atomic(&path, &json, "migration record")
    }

    pub fn delete(&self, jail: &str) -> Result<()> {
        match fs::remove_file(self.path(jail)?) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::State(format!(
                "Failed to remove the migration record for '{jail}': {e}"
            ))),
        }
    }

    /// Exclusive hold on one jail's migration for the life of the guard. The kernel
    /// drops it when the process dies, which is what lets a resume follow a kill.
    pub fn lock(&self, jail: &str) -> Result<Lock> {
        manifest::validate_name("jail", jail)?;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.root)
            .map_err(|e| Error::State(format!("Failed to create migrations dir: {e}")))?;
        let path = self.root.join(format!("{jail}.lock"));
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| Error::State(format!("Failed to open {}: {e}", path.display())))?;
        match file.try_lock() {
            Ok(()) => Ok(Lock { file, path }),
            Err(fs::TryLockError::WouldBlock) => Err(Error::JailOperation(format!(
                "A migration of '{jail}' is running right now; wait for it, or stop it before resuming or aborting"
            ))),
            Err(fs::TryLockError::Error(e)) => Err(Error::State(format!(
                "Failed to lock {}: {e}",
                path.display()
            ))),
        }
    }
}

pub struct Lock {
    file: File,
    path: PathBuf,
}

impl Lock {
    /// Drop the lock file with the settled record, and the directory once it is empty,
    /// so nothing is left behind.
    pub fn discard(self) {
        let _ = fs::remove_file(&self.path);
        if let Some(dir) = self.path.parent() {
            let _ = fs::remove_dir(dir);
        }
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn unsound(path: &Path, why: &str) -> Error {
    Error::State(format!(
        "Migration record {} is not usable ({why}); it was left untouched. Check both hosts by hand, then remove the file",
        path.display()
    ))
}

/// The refusal for a second migration of a jail that has a record.
pub fn refuse_second(jail: &str, path: &Path) -> Error {
    Error::JailOperation(format!(
        "A migration of '{jail}' is already recorded at {}; finish it with 'blackship migrate --resume {jail}' or roll it back with 'blackship migrate --abort {jail}'",
        path.display()
    ))
}
