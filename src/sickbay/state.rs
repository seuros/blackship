//! Durable last-known health summaries.

use crate::atomic::{read_toml, write_toml_atomic};
use crate::error::{Error, Result};
use crate::{manifest, scope};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use super::{HealthChecker, HealthStatus};

/// The result of the most recent completed health pass for one jail.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct HealthStateRecord {
    pub jail: String,
    pub status: HealthStatus,
    pub checked_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jid: Option<i32>,
    pub checks_total: usize,
    pub checks_passing: usize,
    pub checks_failing: usize,
}

impl HealthStateRecord {
    /// Capture the compact, durable part of a completed check pass.
    pub fn from_checker(checker: &HealthChecker, status: HealthStatus) -> Self {
        let results = checker.get_check_results();
        let checks_passing = results
            .iter()
            .filter(|(_, result, _)| result.is_some_and(|result| result.passed))
            .count();
        let checks_failing = results
            .iter()
            .filter(|(_, result, _)| result.is_some_and(|result| !result.passed))
            .count();

        Self {
            jail: checker.jail_name().to_string(),
            status,
            checked_at: scope::now_unix(),
            jid: checker.jid(),
            checks_total: results.len(),
            checks_passing,
            checks_failing,
        }
    }
}

/// Atomic store under `<data_dir>/health`.
#[derive(Debug, Clone)]
pub struct HealthStateStore {
    root: PathBuf,
}

impl HealthStateStore {
    pub fn from_config(config: Option<&manifest::BlackshipConfig>) -> Self {
        Self::new(manifest::data_root(config).join("health"))
    }

    pub const fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn save(&self, record: &HealthStateRecord) -> Result<()> {
        validate_name(&record.jail)?;
        fs::create_dir_all(&self.root)
            .map_err(|e| Error::State(format!("Failed to create health state dir: {e}")))?;
        write_toml_atomic(&self.record_path(&record.jail), record, "health state")
    }

    pub fn get(&self, jail: &str) -> Result<Option<HealthStateRecord>> {
        validate_name(jail)?;
        let path = self.record_path(jail);
        if !path.exists() {
            return Ok(None);
        }
        let record = read_toml::<HealthStateRecord>(&path, "health state")?;
        if record.jail != jail {
            return Err(Error::State(format!(
                "Health state '{}' contains record for '{}'",
                path.display(),
                record.jail
            )));
        }
        Ok(Some(record))
    }

    /// Drop a jail's snapshot; a missing one is fine.
    pub fn delete(&self, jail: &str) -> Result<()> {
        validate_name(jail)?;
        match fs::remove_file(self.record_path(jail)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::State(format!("Failed to remove health state: {e}"))),
        }
    }

    /// `delete`, reporting a failure instead of returning it: a stale snapshot is harmless.
    pub fn forget(&self, jail: &str) {
        if let Err(e) = self.delete(jail) {
            eprintln!("Warning: could not clear health state for '{jail}': {e}");
        }
    }

    fn record_path(&self, jail: &str) -> PathBuf {
        self.root.join(format!("{jail}.toml"))
    }
}

fn validate_name(name: &str) -> Result<()> {
    manifest::validate_record_name("health state", name)
}

#[cfg(test)]
mod tests;
