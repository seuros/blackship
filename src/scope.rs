//! Durable jail scope records.

use crate::atomic::{read_toml, write_toml_atomic};
use crate::error::{Error, Result};
use crate::manifest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;

/// The scope machine carries no data; the record around it holds everything.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct ScopeCtx {}

mod machine {
    use super::ScopeCtx;
    use state_machines::state_machine;

    state_machine! {
        name: ScopeMachine,
        dynamic: true,
        snapshot: true,
        context: ScopeCtx,
        initial: Provisioning,
        states: [Provisioning, Running, Draining, Terminating, Failed],
        events {
            provisioned { transition: { from: Provisioning, to: Running } }
            drain { transition: { from: Running, to: Draining } }
            terminate { transition: { from: [Provisioning, Running, Draining, Failed], to: Terminating } }
            fail { transition: { from: [Provisioning, Running, Draining, Terminating, Failed], to: Failed } }
        }
    }
}

pub use machine::{
    DynamicScopeMachine, ScopeMachineEvent, ScopeMachineSnapshot, ScopeMachineState,
};

/// Persist the phase as the machine's own versioned snapshot envelope, so a
/// record written by a future state graph is rejected instead of misread.
mod phase_snapshot {
    use super::{DynamicScopeMachine, ScopeCtx, ScopeMachineSnapshot, ScopeMachineState};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(phase: &ScopeMachineState, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        DynamicScopeMachine::new_init_state(ScopeCtx::default(), *phase)
            .into_snapshot()
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ScopeMachineState, D::Error>
    where
        D: Deserializer<'de>,
    {
        let snapshot = ScopeMachineSnapshot::deserialize(deserializer)?;
        DynamicScopeMachine::from_snapshot(snapshot)
            .map(|machine| machine.current_state())
            .map_err(|(_, e)| serde::de::Error::custom(format!("invalid scope phase: {:?}", e)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum QosPhase {
    #[default]
    None,
    Startup,
    Steady,
}

impl QosPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Startup => "startup",
            Self::Steady => "steady",
        }
    }
}

/// What to do with jails that depend on one being stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CascadePolicy {
    /// Stop dependents too.
    #[default]
    Strict,
    /// Stop only the target, leave dependents alone.
    Detach,
    /// Leave dependents running but fence them off at the firewall.
    Isolate,
}

/// Highest resource usage seen across the sampling window. Accuracy is bounded
/// by the sample interval; these are not exact kernel peaks.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct PeakMetrics {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub resources: BTreeMap<String, u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub samples: Option<u64>,
}

impl PeakMetrics {
    /// Fold a racct sample in, keeping the per-resource maximum.
    pub fn observe(&mut self, sample: &std::collections::HashMap<String, u64>) {
        for (key, value) in sample {
            let slot = self.resources.entry(key.clone()).or_insert(0);
            if *value > *slot {
                *slot = *value;
            }
        }
        self.samples = Some(self.samples.unwrap_or(0) + 1);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ScopeRecord {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jid: Option<i32>,
    #[serde(default, with = "phase_snapshot")]
    pub phase: ScopeMachineState,
    pub created_at: i64,
    pub updated_at: i64,

    /// Whether teardown may destroy the dataset without `--force`.
    #[serde(default)]
    pub ephemeral: bool,
    /// Set only when blackship created the dataset itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zfs_dataset: Option<String>,
    /// `Some` means the dataset is a clone of this snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zfs_origin: Option<String>,
    /// A `VnetStateRecord` exists under `<data_dir>/vnet/<name>.toml`.
    #[serde(default)]
    pub has_vnet_record: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rctl_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpuset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drain_anchor: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allocated_ips: Vec<IpAddr>,

    #[serde(default)]
    pub qos_phase: QosPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(default)]
    pub cascade: CascadePolicy,
    #[serde(default)]
    pub peak: PeakMetrics,
}

impl ScopeRecord {
    pub fn new(name: impl Into<String>) -> Self {
        let now = now_unix();
        Self {
            name: name.into(),
            jid: None,
            phase: ScopeMachineState::Provisioning,
            created_at: now,
            updated_at: now,
            ephemeral: false,
            zfs_dataset: None,
            zfs_origin: None,
            has_vnet_record: false,
            rctl_subject: None,
            cpuset: None,
            drain_anchor: None,
            mounts: Vec::new(),
            allocated_ips: Vec::new(),
            qos_phase: QosPhase::None,
            parent: None,
            cascade: CascadePolicy::default(),
            peak: PeakMetrics::default(),
        }
    }

    pub fn touch(&mut self) {
        self.updated_at = now_unix();
    }

    /// Drive the phase through `ScopeMachine`, rejecting illegal transitions.
    pub fn advance(&mut self, event: ScopeMachineEvent) -> Result<()> {
        let mut machine = DynamicScopeMachine::new_init_state(ScopeCtx::default(), self.phase);
        machine.handle(event).map_err(|e| {
            Error::State(format!(
                "Invalid scope transition for '{}' in phase {}: {:?}",
                self.name,
                self.phase.name(),
                e
            ))
        })?;
        self.phase = machine.current_state();
        self.touch();
        Ok(())
    }

    pub fn advance_or_warn(&mut self, event: ScopeMachineEvent) {
        if let Err(e) = self.advance(event) {
            eprintln!("Warning: {}", e);
        }
    }

    /// True when the record claims something that must be released on teardown.
    pub fn holds_resources(&self) -> bool {
        self.zfs_dataset.is_some()
            || self.has_vnet_record
            || self.rctl_subject.is_some()
            || self.drain_anchor.is_some()
            || !self.mounts.is_empty()
            || !self.allocated_ips.is_empty()
    }
}

pub struct ScopeStore {
    root: PathBuf,
}

impl ScopeStore {
    pub fn from_config(config: Option<&manifest::BlackshipConfig>) -> Self {
        Self::new(manifest::data_root(config).join("scope"))
    }

    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn save(&self, record: &ScopeRecord) -> Result<()> {
        validate_name(&record.name)?;
        fs::create_dir_all(&self.root)
            .map_err(|e| Error::State(format!("Failed to create scope dir: {}", e)))?;
        write_toml_atomic(&self.record_path(&record.name), record, "scope record")
    }

    pub fn get(&self, name: &str) -> Result<Option<ScopeRecord>> {
        validate_name(name)?;
        let path = self.record_path(name);
        if !path.exists() {
            return Ok(None);
        }
        read_toml::<ScopeRecord>(&path, "scope record").map(Some)
    }

    pub fn delete(&self, name: &str) -> Result<bool> {
        validate_name(name)?;
        let path = self.record_path(name);
        if !path.exists() {
            return Ok(false);
        }
        fs::remove_file(&path)
            .map_err(|e| Error::State(format!("Failed to remove scope record: {}", e)))?;
        Ok(true)
    }

    pub fn list(&self) -> Result<Vec<ScopeRecord>> {
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(Error::State(format!("Failed to read scope dir: {}", e))),
        };

        let mut records = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension() != Some(OsStr::new("toml")) {
                continue;
            }
            match read_toml::<ScopeRecord>(&path, "scope record") {
                Ok(record) => records.push(record),
                Err(e) => eprintln!("Warning: skipping scope record {:?}: {}", path, e),
            }
        }
        records.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(records)
    }

    /// Read-modify-write a record, creating it when absent.
    pub fn update<F>(&self, name: &str, mutate: F) -> Result<ScopeRecord>
    where
        F: FnOnce(&mut ScopeRecord),
    {
        let mut record = self
            .get(name)?
            .unwrap_or_else(|| ScopeRecord::new(name.to_string()));
        mutate(&mut record);
        record.touch();
        self.save(&record)?;
        Ok(record)
    }

    fn record_path(&self, name: &str) -> PathBuf {
        self.root.join(format!("{}.toml", name))
    }
}

fn validate_name(name: &str) -> Result<()> {
    manifest::validate_record_name("scope record", name)
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
