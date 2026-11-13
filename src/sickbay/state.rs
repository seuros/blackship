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

    fn record_path(&self, jail: &str) -> PathBuf {
        self.root.join(format!("{jail}.toml"))
    }
}

fn validate_name(name: &str) -> Result<()> {
    manifest::validate_record_name("health state", name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = HealthStateStore::new(dir.path().join("health"));
        let record = HealthStateRecord {
            jail: "project-web".to_string(),
            status: HealthStatus::Healthy,
            checked_at: 123,
            jid: Some(7),
            checks_total: 2,
            checks_passing: 2,
            checks_failing: 0,
        };

        store.save(&record).unwrap();

        assert_eq!(store.get("project-web").unwrap(), Some(record));
    }

    #[test]
    fn store_rejects_path_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let store = HealthStateStore::new(dir.path().join("health"));
        let record = HealthStateRecord {
            jail: "../other".to_string(),
            status: HealthStatus::Unknown,
            checked_at: 123,
            jid: None,
            checks_total: 0,
            checks_passing: 0,
            checks_failing: 0,
        };

        assert!(store.save(&record).is_err());
        assert!(store.get("../other").is_err());
    }

    #[test]
    fn store_rejects_mismatched_record_name() {
        let dir = tempfile::tempdir().unwrap();
        let store = HealthStateStore::new(dir.path().join("health"));
        let record = HealthStateRecord {
            jail: "project-api".to_string(),
            status: HealthStatus::Healthy,
            checked_at: 123,
            jid: Some(7),
            checks_total: 1,
            checks_passing: 1,
            checks_failing: 0,
        };
        store.save(&record).unwrap();
        std::fs::rename(
            dir.path().join("health/project-api.toml"),
            dir.path().join("health/project-web.toml"),
        )
        .unwrap();

        assert!(store.get("project-web").is_err());
    }
}
