//! Container ownership records, one TOML file each under `data_dir/container-state/`.
//! The exclusive-create claim is both the name lock and the orphan trail.

use super::validate_container_name;
use crate::atomic::write_toml_atomic;
use crate::error::{Error, Result};
use crate::host::Layout;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

/// What the registry remembers about one container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub(crate) release: String,
    pub(crate) root: PathBuf,
    pub(crate) dataset: Option<String>,
    /// The creating process; `None` once the container is kept.
    pub(crate) owner_pid: Option<u32>,
    #[serde(default)]
    pub(crate) labels: BTreeMap<String, String>,
}

fn record_path(layout: &Layout, name: &str) -> PathBuf {
    layout.registry_dir().join(format!("{name}.toml"))
}

/// Claim `name` for a new container, or fail with [`Error::JailExists`].
pub fn claim(layout: &Layout, name: &str, record: &Record) -> Result<()> {
    let dir = layout.registry_dir();
    fs::create_dir_all(&dir)
        .map_err(|e| Error::State(format!("Failed to create {}: {e}", dir.display())))?;
    let content = toml::to_string(record)
        .map_err(|e| Error::State(format!("Failed to serialize container record: {e}")))?;

    // link(2) refuses an existing target: an atomic, never half-written claim.
    let target = record_path(layout, name);
    let tmp = dir.join(format!(".{name}.{}.claim", std::process::id()));
    let written = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .and_then(|mut f| f.write_all(content.as_bytes()));
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp); // best-effort; the write error is reported
        return Err(Error::State(format!(
            "Failed to write container record: {e}"
        )));
    }
    let linked = fs::hard_link(&tmp, &target);
    let _ = fs::remove_file(&tmp); // the temp name is pid-scoped; a leftover is harmless
    match linked {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => Err(Error::JailExists(name.into())),
        Err(e) => Err(Error::State(format!(
            "Failed to claim container '{name}': {e}"
        ))),
    }
}

/// The record for `name`, if any. An unreadable record reads as absent.
pub fn load(layout: &Layout, name: &str) -> Option<Record> {
    let path = record_path(layout, name);
    path.exists()
        .then(|| crate::atomic::read_toml(&path, "container record").ok())
        .flatten()
}

/// Forget the owner so the container is never reaped as an orphan.
pub fn disown(layout: &Layout, name: &str) -> Result<()> {
    match load(layout, name) {
        Some(mut record) => {
            record.owner_pid = None;
            write_toml_atomic(&record_path(layout, name), &record, "container record")
        }
        None => Ok(()),
    }
}

/// Drop the record once the container is fully gone.
pub fn remove(layout: &Layout, name: &str) -> Result<()> {
    match fs::remove_file(record_path(layout, name)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::State(format!(
            "Failed to remove record for container '{name}': {e}"
        ))),
    }
}

/// A container as found on the host, by [`Host::containers`](crate::Host::containers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerInfo {
    /// Container (and jail) name.
    pub name: String,
    /// Root directory on the host.
    pub root: PathBuf,
    /// Backing dataset, on ZFS hosts.
    pub dataset: Option<String>,
    /// Jail id, when the jail is running.
    pub jid: Option<i32>,
    /// Release it was cloned from, when recorded.
    pub release: Option<String>,
    /// Labels given at creation.
    pub labels: BTreeMap<String, String>,
    /// The process that created it; `None` when kept or unrecorded.
    pub owner_pid: Option<u32>,
}

impl ContainerInfo {
    /// Whether the jail is running.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        self.jid.is_some()
    }

    /// Whether the creating process is gone, leaving nobody to destroy it.
    #[must_use]
    pub fn is_orphan(&self) -> bool {
        self.owner_pid.is_some_and(|pid| !process_alive(pid))
    }
}

/// Picks containers by name prefix and labels; every criterion must match.
///
/// ```
/// use blackship::Selector;
///
/// let kim_jobs = Selector::prefix("kim-").and_label("runner", "bastion");
/// # let _ = kim_jobs;
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Selector {
    prefix: Option<String>,
    labels: BTreeMap<String, String>,
}

impl Selector {
    /// Every container.
    #[must_use]
    pub fn all() -> Self {
        Self::default()
    }

    /// Containers whose name starts with `prefix`.
    pub fn prefix(prefix: impl Into<String>) -> Self {
        Self {
            prefix: Some(prefix.into()),
            ..Self::default()
        }
    }

    /// Containers carrying `key = value`.
    pub fn label(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self::default().and_label(key, value)
    }

    /// Also require `key = value`.
    #[must_use]
    pub fn and_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    /// Whether `info` satisfies every criterion.
    #[must_use]
    pub fn matches(&self, info: &ContainerInfo) -> bool {
        self.prefix
            .as_deref()
            .is_none_or(|prefix| info.name.starts_with(prefix))
            && self
                .labels
                .iter()
                .all(|(k, v)| info.labels.get(k) == Some(v))
    }
}

/// Union of every trace a container leaves: records, datasets, roots.
pub fn list(layout: &Layout) -> Vec<ContainerInfo> {
    let mut names = BTreeSet::new();
    names.extend(dir_entries(&layout.registry_dir(), |name| {
        name.strip_suffix(".toml")
            .filter(|n| !n.starts_with('.'))
            .map(str::to_string)
    }));
    names.extend(dir_entries(&layout.containers_dir(), |name| {
        Some(name.to_string())
    }));
    let zfs = layout.zfs();
    if let Some(zfs) = &zfs {
        names.extend(zfs.list_container_datasets());
    }

    names
        .into_iter()
        .filter(|name| validate_container_name(name).is_ok())
        .map(|name| {
            let record = load(layout, &name);
            let jid = crate::jail::jail_getid(&name).ok();
            let dataset = record.as_ref().and_then(|r| r.dataset.clone()).or_else(|| {
                let zfs = zfs.as_ref()?;
                let dataset = zfs.container_dataset(&name);
                zfs.dataset_exists(&dataset)
                    .unwrap_or(false)
                    .then_some(dataset)
            });
            ContainerInfo {
                root: record
                    .as_ref()
                    .map_or_else(|| layout.container_root(&name), |r| r.root.clone()),
                dataset,
                jid,
                release: record.as_ref().map(|r| r.release.clone()),
                labels: record
                    .as_ref()
                    .map(|r| r.labels.clone())
                    .unwrap_or_default(),
                owner_pid: record.and_then(|r| r.owner_pid),
                name,
            }
        })
        .collect()
}

fn dir_entries(dir: &Path, keep: impl Fn(&str) -> Option<String>) -> Vec<String> {
    fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|e| e.file_name().to_str().and_then(&keep))
                .collect()
        })
        .unwrap_or_default()
}

/// kill(pid, 0): ESRCH means gone; EPERM means alive but not ours.
fn process_alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    matches!(
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None),
        Ok(()) | Err(nix::errno::Errno::EPERM)
    )
}

#[cfg(test)]
mod tests;
