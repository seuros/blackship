//! Durable per-jail lifecycle audit log.

use crate::error::{Error, Result};
use crate::manifest;
use crate::scope::now_unix;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const MAX_LOG_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEvent {
    Created,
    Provisioned,
    Running,
    RollbackStep,
    QosShift,
    HealthChanged,
    DrainStart,
    DrainEnd,
    Terminating,
    Destroyed,
    Reaped,
    Failed,
}

impl AuditEvent {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Provisioned => "provisioned",
            Self::Running => "running",
            Self::RollbackStep => "rollback_step",
            Self::QosShift => "qos_shift",
            Self::HealthChanged => "health_changed",
            Self::DrainStart => "drain_start",
            Self::DrainEnd => "drain_end",
            Self::Terminating => "terminating",
            Self::Destroyed => "destroyed",
            Self::Reaped => "reaped",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuditRecord {
    pub ts: i64,
    pub jail: String,
    pub event: AuditEvent,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub detail: BTreeMap<String, String>,
}

impl AuditRecord {
    pub fn new(jail: impl Into<String>, event: AuditEvent) -> Self {
        Self {
            ts: now_unix(),
            jail: jail.into(),
            event,
            detail: BTreeMap::new(),
        }
    }

    pub fn with(mut self, key: &str, value: impl std::fmt::Display) -> Self {
        self.detail.insert(key.to_string(), value.to_string());
        self
    }
}

pub struct AuditLog {
    root: PathBuf,
}

impl AuditLog {
    pub fn from_config(config: Option<&manifest::BlackshipConfig>) -> Self {
        Self::new(manifest::data_root(config).join("audit"))
    }

    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Append a record to the jail's log and export it.
    pub fn record(&self, record: &AuditRecord) {
        if let Err(e) = self.append(record) {
            eprintln!("Warning: failed to write audit record: {e}");
        }
        crate::telemetry::emit(record);
    }

    pub fn event(&self, jail: &str, event: AuditEvent) {
        self.record(&AuditRecord::new(jail, event));
    }

    pub fn append(&self, record: &AuditRecord) -> Result<()> {
        validate_name(&record.jail)?;
        fs::create_dir_all(&self.root)
            .map_err(|e| Error::State(format!("Failed to create audit dir: {e}")))?;

        let path = self.log_path(&record.jail);
        self.rotate_if_needed(&path)?;

        let line = serde_json::to_string(record)
            .map_err(|e| Error::State(format!("Failed to serialize audit record: {e}")))?;

        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| Error::State(format!("Failed to open audit log: {e}")))?;
        writeln!(file, "{line}")
            .map_err(|e| Error::State(format!("Failed to append audit record: {e}")))
    }

    /// Read a jail's history, oldest first, including the rotated generation.
    pub fn read(&self, jail: &str) -> Result<Vec<AuditRecord>> {
        validate_name(jail)?;
        let mut records = Vec::new();
        for path in [self.rotated_path(jail), self.log_path(jail)] {
            let content = match fs::read_to_string(&path) {
                Ok(content) => content,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(Error::State(format!("Failed to read audit log: {e}"))),
            };
            for line in content.lines().filter(|l| !l.trim().is_empty()) {
                match serde_json::from_str::<AuditRecord>(line) {
                    Ok(record) => records.push(record),
                    Err(e) => eprintln!("Warning: skipping malformed audit line: {e}"),
                }
            }
        }
        Ok(records)
    }

    /// Remove a jail's audit log, including a rotated one.
    pub fn delete(&self, jail: &str) -> Result<()> {
        validate_name(jail)?;
        for path in [self.log_path(jail), self.rotated_path(jail)] {
            if let Err(e) = fs::remove_file(&path)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                return Err(Error::State(format!("Failed to remove audit log: {e}")));
            }
        }
        Ok(())
    }

    fn rotate_if_needed(&self, path: &Path) -> Result<()> {
        let too_big = fs::metadata(path).map(|m| m.len() >= MAX_LOG_BYTES);
        match too_big {
            Ok(true) => {}
            _ => return Ok(()),
        }

        let rotated = path.with_extension("jsonl.1");
        fs::rename(path, &rotated)
            .map_err(|e| Error::State(format!("Failed to rotate audit log: {e}")))
    }

    fn log_path(&self, jail: &str) -> PathBuf {
        self.root.join(format!("{jail}.jsonl"))
    }

    fn rotated_path(&self, jail: &str) -> PathBuf {
        self.root.join(format!("{jail}.jsonl.1"))
    }
}

fn validate_name(jail: &str) -> Result<()> {
    manifest::validate_record_name("audit jail", jail)
}

#[cfg(test)]
mod tests;
