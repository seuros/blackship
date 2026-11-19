//! Jail migration between hosts over zfs send | ssh zfs receive.
//!
//! The snapshot carries the staged .blackship/ config, so the receiving
//! host gets the jail definition along with the data. A successful transfer
//! fences the source: its dataset goes read-only and starts refuse, so the
//! jail cannot silently run on two hosts. A failed transfer fences nothing and
//! removes the partial destination dataset it created.
//!
//! The sequence is a saga (`saga.rs`) recorded under `<data_root>/migrations`, so a
//! killed migrate can be resumed or aborted instead of leaving the jail runnable on
//! both hosts with no trace of the transfer.

use std::path::Path;
use std::process::Command;

use saga_machines::Saga;
use serde::Serialize;

use self::host::Host;
use self::record::{Lock, Record, RecordStore, refuse_second};
use self::saga::{Driver, STEPS, Settled, Step, saga_id};
use crate::error::{Error, Result};
use crate::manifest;

mod host;
mod record;
mod saga;

/// What one invocation of `blackship migrate` asks for.
#[derive(Debug, PartialEq, Eq)]
pub enum Mode {
    Start {
        jail: String,
        target: String,
        remote_dataset: Option<String>,
        keep: bool,
    },
    Resume(String),
    Abort(String),
}

/// Sort the arguments into one mode: `--resume` and `--abort` stand alone.
pub fn mode(
    jail: Option<String>,
    target: Option<String>,
    remote_dataset: Option<String>,
    keep: bool,
    resume: Option<String>,
    abort: Option<String>,
) -> Result<Mode> {
    let lone = |flag: &str| {
        if jail.is_some() || target.is_some() || remote_dataset.is_some() || keep {
            return Err(Error::InvalidArgument(format!(
                "{flag} takes only the jail name"
            )));
        }
        Ok(())
    };
    match (resume, abort) {
        (Some(_), Some(_)) => Err(Error::InvalidArgument(
            "--resume and --abort are exclusive".to_string(),
        )),
        (Some(jail), None) => lone("--resume").map(|()| Mode::Resume(jail)),
        (None, Some(jail)) => lone("--abort").map(|()| Mode::Abort(jail)),
        (None, None) => match (jail, target) {
            (Some(jail), Some(target)) => Ok(Mode::Start {
                jail,
                target,
                remote_dataset,
                keep,
            }),
            _ => Err(Error::InvalidArgument(
                "migrate needs <jail> <target>, or --resume <jail>, or --abort <jail>".to_string(),
            )),
        },
    }
}

pub fn handle_migrate(
    config_path: &(impl manifest::ConfigSource + ?Sized),
    mode: Mode,
) -> Result<()> {
    match mode {
        Mode::Start {
            jail,
            target,
            remote_dataset,
            keep,
        } => start(config_path, &jail, &target, remote_dataset, keep),
        Mode::Resume(jail) => resume(config_path, &jail),
        Mode::Abort(jail) => abort(config_path, &jail),
    }
}

/// The `--format json` result of `migrate --resume` and `migrate --abort`.
#[derive(Debug, Serialize)]
pub struct MigrateReport {
    pub jail: String,
    pub action: &'static str,
    pub outcome: &'static str,
    /// Where the jail went, for a completed migration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    pub messages: Vec<String>,
}

pub fn resume_data(
    config_path: &(impl manifest::ConfigSource + ?Sized),
    jail: &str,
) -> Result<MigrateReport> {
    let (destination, messages) =
        crate::output::capture_stdout(|| resume_inner(config_path, jail))?;
    Ok(MigrateReport {
        jail: jail.to_string(),
        action: "resume",
        outcome: "completed",
        destination,
        messages,
    })
}

pub fn abort_data(
    config_path: &(impl manifest::ConfigSource + ?Sized),
    jail: &str,
) -> Result<MigrateReport> {
    let ((), messages) = crate::output::capture_stdout(|| abort(config_path, jail))?;
    Ok(MigrateReport {
        jail: jail.to_string(),
        action: "abort",
        outcome: "aborted",
        destination: None,
        messages,
    })
}

fn preflight(target: &str, remote_dataset: &str) -> Result<()> {
    let probe = Command::new("/usr/bin/ssh")
        .args(["-o", "BatchMode=yes", target])
        .args(["zfs", "list", "-H", "-o", "name", remote_dataset])
        .output()
        .map_err(|e| Error::JailOperation(format!("Failed to run ssh: {e}")))?;
    if probe.status.success() {
        return Err(Error::JailOperation(format!(
            "Dataset '{remote_dataset}' already exists on {target}"
        )));
    }
    let reachable = Command::new("/usr/bin/ssh")
        .args(["-o", "BatchMode=yes", target, "true"])
        .status()
        .map_err(|e| Error::JailOperation(format!("Failed to run ssh: {e}")))?;
    if !reachable.success() {
        return Err(Error::JailOperation(format!(
            "Cannot reach '{target}' over ssh (BatchMode)"
        )));
    }
    Ok(())
}

fn require_stopped(full_name: &str) -> Result<()> {
    if crate::jail::jail_getid(full_name).is_ok() {
        return Err(Error::JailOperation(format!(
            "Jail '{full_name}' is running; stop it before migrating"
        )));
    }
    Ok(())
}

fn start(
    config_path: &(impl manifest::ConfigSource + ?Sized),
    jail: &str,
    target: &str,
    remote_dataset: Option<String>,
    keep: bool,
) -> Result<()> {
    let config = manifest::load(config_path)?;
    let zfs = super::snapshot::require_zfs(&config)?;
    let (service_name, full_name) = config.require_jail_names(jail)?;
    require_stopped(&full_name)?;

    let store = RecordStore::from_config(&config);
    if store.exists(&full_name)? {
        return Err(refuse_second(&full_name, &store.path(&full_name)?));
    }
    let local_dataset = zfs.jail_dataset_name(&full_name);
    let remote_dataset =
        remote_dataset.unwrap_or_else(|| format!("zroot/blackship/jails/{full_name}"));
    preflight(target, &remote_dataset)?;

    let lock = store.lock(&full_name)?;
    if store.exists(&full_name)? {
        return Err(refuse_second(&full_name, &store.path(&full_name)?));
    }
    let record = Record {
        version: record::VERSION,
        jail: full_name.clone(),
        service: service_name,
        target: target.to_string(),
        remote_dataset,
        source_dataset: local_dataset,
        snapshot: crate::zfs::default_snapshot_name(),
        keep,
        started_at: crate::scope::now_unix(),
        fence: None,
        parked: None,
        saga: Saga::<STEPS>::new(saga_id(&full_name)).snapshot(),
    };
    let source_path = zfs.jail_path(&full_name);
    let host = Host::new(&config, zfs, &record);
    let mut driver = Driver::restore(host, record, &store)?;
    let settled = driver.drive();
    release(lock, &store, &full_name);
    conclude(settled?, driver.record(), &source_path)
}

/// Let go of the migration lock, and remove its file when no record is left.
fn release(lock: Lock, store: &RecordStore, jail: &str) {
    if store.exists(jail).is_ok_and(|recorded| !recorded) {
        lock.discard();
    }
}

/// Report how a start or resume ended: the destination steps, or why it did not.
fn conclude(settled: Settled, record: &Record, source_path: &Path) -> Result<()> {
    match settled {
        Settled::Completed => {
            for line in destination_steps(
                &record.target,
                &record.remote_dataset,
                &record.jail,
                &record.service,
                source_path,
            ) {
                println!("{line}");
            }
            if !record.keep {
                println!(
                    "Remove the source for good with: blackship rm {} --volumes",
                    record.service
                );
                println!(
                    "Undo the migration here with: blackship unfence {}",
                    record.service
                );
            }
            Ok(())
        }
        Settled::RolledBack {
            failed: Some((Step::Transfer, _)),
        } => Err(Error::JailOperation(
            "Migration transfer failed; the source is untouched and the partial remote dataset was removed"
                .to_string(),
        )),
        Settled::RolledBack {
            failed: Some((_, e)),
        } => Err(e),
        Settled::RolledBack { failed: None } => Err(Error::JailOperation(format!(
            "Migration of '{}' was rolled back; the source is untouched and nothing is left on {}",
            record.jail, record.target
        ))),
    }
}

/// A record to act on: the jail's name resolved, the record read and locked.
struct Recorded {
    config: manifest::BlackshipConfig,
    store: RecordStore,
    record: Record,
}

fn recorded(config_path: &(impl manifest::ConfigSource + ?Sized), jail: &str) -> Result<Recorded> {
    let config = manifest::load(config_path)?;
    let full_name = config
        .resolve_jail_names(jail)
        .map_or_else(|| jail.to_string(), |(_, full)| full);
    let store = RecordStore::from_config(&config);
    let Some(record) = store.load(&full_name)? else {
        return Err(Error::JailOperation(format!(
            "No migration is recorded for '{full_name}'"
        )));
    };
    Ok(Recorded {
        config,
        store,
        record,
    })
}

fn resume(config_path: &(impl manifest::ConfigSource + ?Sized), jail: &str) -> Result<()> {
    resume_inner(config_path, jail).map(drop)
}

/// The destination a resumed migration ended at.
fn resume_inner(
    config_path: &(impl manifest::ConfigSource + ?Sized),
    jail: &str,
) -> Result<Option<String>> {
    let Recorded {
        config,
        store,
        record,
    } = recorded(config_path, jail)?;
    let lock = store.lock(&record.jail)?;
    let zfs = super::snapshot::require_zfs(&config)?;
    require_stopped(&record.jail)?;
    println!(
        "Resuming the migration of '{}' to {}:{} ...",
        record.jail, record.target, record.remote_dataset
    );
    let source_path = zfs.jail_path(&record.jail);
    let jail = record.jail.clone();
    let host = Host::new(&config, zfs, &record);
    let mut driver = Driver::restore(host, record, &store)?;
    let settled = driver.drive();
    release(lock, &store, &jail);
    conclude(settled?, driver.record(), &source_path)?;
    Ok(driver.record().fence.clone())
}

fn abort(config_path: &(impl manifest::ConfigSource + ?Sized), jail: &str) -> Result<()> {
    let Recorded {
        config,
        store,
        record,
    } = recorded(config_path, jail)?;
    let lock = store.lock(&record.jail)?;
    let zfs = super::snapshot::require_zfs(&config)?;
    let jail = record.jail.clone();
    let target = record.target.clone();
    let host = Host::new(&config, zfs, &record);
    let mut driver = Driver::restore(host, record, &store)?;
    let aborted = driver.abort();
    release(lock, &store, &jail);
    aborted?;
    println!(
        "Aborted the migration of '{jail}': nothing is left on {target}, and '{jail}' here is as it was."
    );
    Ok(())
}

/// `zfs send` arguments for the snapshot. A jail cloned from a release is sent as a full
/// stream: `-R` would make the target look for the clone's origin snapshot, which it
/// does not have, and the receive would fail. The cost is that its older snapshots stay behind.
const fn send_args(snapshot: &str, cloned: bool) -> [&str; 3] {
    ["send", if cloned { "-p" } else { "-R" }, snapshot]
}

/// What to do on the target. The dataset keeps the mountpoint it had here; only a target
/// with a different data directory needs to move it, and only the target knows its layout.
fn destination_steps(
    target: &str,
    remote_dataset: &str,
    full_name: &str,
    service_name: &str,
    source_path: &Path,
) -> Vec<String> {
    vec![
        format!("On {target}, finish with:"),
        format!(
            "  # the dataset arrives with mountpoint {}; if the target's data_dir differs:",
            source_path.display()
        ),
        format!("  zfs set mountpoint=<data_dir>/jails/{full_name} {remote_dataset}"),
        "  # the jail definition travels at .blackship/jail.toml inside the dataset".to_string(),
        format!("  blackship up {service_name}"),
    ]
}

/// `<host>/<dataset>@<unix time>`: where a migrated jail went, and when.
fn fence_value(target: &str, remote_dataset: &str, at: i64) -> String {
    let host = target.rsplit('@').next().unwrap_or(target);
    format!("{host}/{remote_dataset}@{at}")
}

/// Lift a migration fence.
pub fn handle_unfence(
    config_path: &(impl manifest::ConfigSource + ?Sized),
    jail: &str,
) -> Result<()> {
    let config = manifest::load(config_path)?;
    let zfs = super::snapshot::require_zfs(&config)?;
    let (_, full_name) = config.require_jail_names(jail)?;

    let Some(fence) = zfs.jail_migration_fence(&full_name) else {
        return Err(Error::JailOperation(format!(
            "Jail '{full_name}' is not fenced"
        )));
    };
    zfs.clear_jail_migration_fence(&full_name)?;
    println!("Cleared the fence on '{full_name}' (it had been migrated to {fence}).");
    println!("It can start here again; make sure it does not also run there.");
    Ok(())
}

#[cfg(test)]
mod tests;
