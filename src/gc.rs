//! Orphan reclamation: scope records that outlived their jail.

use crate::audit::{AuditEvent, AuditLog, AuditRecord};
use crate::bulkhead::BulkheadManager;
use crate::error::{Error, Result};
use crate::jail::{RunningJails, jail_getname};
use crate::manifest::BlackshipConfig;
use crate::network::store::{FileLock, NetworkLeaseStore, VnetStateRecord, VnetStateStore};
use crate::network::vnet::VnetSetup;
use crate::scope::{ScopeRecord, ScopeStore};
use crate::zfs::ZfsManager;
use std::collections::HashSet;
use std::path::PathBuf;

/// What was found stranded, and what it takes to release it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrphanKind {
    /// A scope record whose jail is no longer running.
    DeadScope(Box<ScopeRecord>),
    /// A VNET record with no scope record and no live jail.
    StrayVnet(Box<VnetStateRecord>),
    /// A blackship-tagged interface no VNET record claims.
    StrayInterface(String),
    /// A dataset under `jails/` with no scope record and no live jail.
    StrayDataset(String),
    /// A drain sub-anchor left loaded after its jail is gone.
    StrayDrainAnchor(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Orphan {
    pub jail: String,
    pub kind: OrphanKind,
    pub reason: String,
    /// Resources this orphan claims, as human-readable labels.
    pub resources: Vec<String>,
    /// True when reaping needs `--force`: blackship cannot prove it owns this.
    pub requires_force: bool,
}

impl Orphan {
    pub fn kind_label(&self) -> &'static str {
        match self.kind {
            OrphanKind::DeadScope(_) => "scope",
            OrphanKind::StrayVnet(_) => "vnet",
            OrphanKind::StrayInterface(_) => "interface",
            OrphanKind::StrayDataset(_) => "dataset",
            OrphanKind::StrayDrainAnchor(_) => "drain-anchor",
        }
    }
}

/// Facts a classification is made from, gathered by [`survey`].
pub struct Survey {
    pub live: HashSet<String>,
    pub scopes: Vec<ScopeRecord>,
    pub vnet: Vec<VnetStateRecord>,
    pub tagged_ifaces: Vec<String>,
    pub datasets: Vec<String>,
    pub drain_anchors: Vec<String>,
}

/// Decide what is stranded. Pure: no syscalls, no filesystem.
pub fn classify(survey: &Survey) -> Vec<Orphan> {
    let scoped: HashSet<&str> = survey.scopes.iter().map(|s| s.name.as_str()).collect();
    let claimed_ifaces: HashSet<&str> = survey
        .vnet
        .iter()
        .flat_map(|r| [r.host_interface.as_str(), r.jail_interface.as_str()])
        .collect();

    let mut orphans = Vec::new();

    for scope in &survey.scopes {
        if survey.live.contains(&scope.name) {
            continue;
        }
        if !scope.holds_resources() && scope.jid.is_none() {
            orphans.push(Orphan {
                jail: scope.name.clone(),
                kind: OrphanKind::DeadScope(Box::new(scope.clone())),
                reason: "scope record holds no resources".to_string(),
                resources: Vec::new(),
                requires_force: false,
            });
            continue;
        }

        let mut resources = Vec::new();
        if let Some(subject) = &scope.rctl_subject {
            resources.push(format!("rctl {}", subject));
        }
        if scope.has_vnet_record {
            resources.push("vnet".to_string());
        }
        if let Some(anchor) = &scope.drain_anchor {
            resources.push(format!("pf anchor {}", anchor));
        }
        for mount in &scope.mounts {
            resources.push(format!("mount {}", mount.display()));
        }
        for ip in &scope.allocated_ips {
            resources.push(format!("lease {}", ip));
        }
        if let Some(dataset) = &scope.zfs_dataset {
            resources.push(if scope.ephemeral {
                format!("dataset {} (ephemeral)", dataset)
            } else {
                format!("dataset {} (retained)", dataset)
            });
        }

        orphans.push(Orphan {
            jail: scope.name.clone(),
            kind: OrphanKind::DeadScope(Box::new(scope.clone())),
            reason: format!("jail is not running, scope phase {}", scope.phase.as_str()),
            resources,
            requires_force: false,
        });
    }

    for record in &survey.vnet {
        if survey.live.contains(&record.owner) || scoped.contains(record.owner.as_str()) {
            continue;
        }
        orphans.push(Orphan {
            jail: record.owner.clone(),
            kind: OrphanKind::StrayVnet(Box::new(record.clone())),
            reason: "VNET record with no scope record and no live jail".to_string(),
            resources: vec![format!(
                "{} {}/{}",
                record.backend, record.host_interface, record.jail_interface
            )],
            requires_force: false,
        });
    }

    for iface in &survey.tagged_ifaces {
        if claimed_ifaces.contains(iface.as_str()) {
            continue;
        }
        orphans.push(Orphan {
            jail: String::new(),
            kind: OrphanKind::StrayInterface(iface.clone()),
            reason: "interface carries the blackship group but no record claims it".to_string(),
            resources: vec![format!("interface {}", iface)],
            requires_force: true,
        });
    }

    for dataset in &survey.datasets {
        if survey.live.contains(dataset) || scoped.contains(dataset.as_str()) {
            continue;
        }
        orphans.push(Orphan {
            jail: dataset.clone(),
            kind: OrphanKind::StrayDataset(dataset.clone()),
            reason: "dataset has no scope record and no live jail".to_string(),
            resources: vec![format!("dataset {}", dataset)],
            requires_force: true,
        });
    }

    let claimed_anchors: HashSet<String> = survey
        .live
        .iter()
        .map(String::as_str)
        .chain(scoped.iter().copied())
        .map(crate::bulkhead::drain_anchor_path)
        .collect();

    for anchor in &survey.drain_anchors {
        if claimed_anchors.contains(anchor) {
            continue;
        }
        orphans.push(Orphan {
            jail: anchor.rsplit('/').next().unwrap_or_default().to_string(),
            kind: OrphanKind::StrayDrainAnchor(anchor.clone()),
            reason: "drain anchor outlived its jail and is still blocking traffic".to_string(),
            resources: vec![format!("pf anchor {}", anchor)],
            requires_force: false,
        });
    }

    orphans
}

/// Owns the stores a reap needs, plus the lock that serializes it.
pub struct Reaper {
    scope_store: ScopeStore,
    vnet_state_store: VnetStateStore,
    lease_store: NetworkLeaseStore,
    audit: AuditLog,
    zfs: Option<ZfsManager>,
    data_dir: PathBuf,
    verbose: bool,
    _lock: FileLock,
}

impl Reaper {
    pub fn new(config: &BlackshipConfig, verbose: bool) -> Result<Self> {
        let data_dir = config.config.data_dir.clone();
        let lock = FileLock::acquire(&data_dir.join("gc.lock"))?;

        let zfs = match (config.config.zfs_enabled, config.config.zpool.as_ref()) {
            (true, Some(pool)) => Some(ZfsManager::new(
                pool,
                &config.config.dataset,
                data_dir.join("jails"),
            )),
            _ => None,
        };

        Ok(Self {
            scope_store: ScopeStore::from_config(Some(config)),
            vnet_state_store: VnetStateStore::from_config(Some(config)),
            lease_store: NetworkLeaseStore::from_config(Some(config)),
            audit: AuditLog::from_config(Some(config)),
            zfs,
            data_dir,
            verbose,
            _lock: lock,
        })
    }

    /// Gather the live-vs-recorded picture of the host.
    pub fn survey(&self) -> Result<Survey> {
        let mut live = HashSet::new();
        for jid in RunningJails::new() {
            match jail_getname(jid) {
                Ok(name) => {
                    live.insert(name);
                }
                Err(e) if self.verbose => {
                    eprintln!("Warning: could not read name of JID {}: {}", jid, e)
                }
                Err(_) => {}
            }
        }

        Ok(Survey {
            live,
            scopes: self.scope_store.list()?,
            vnet: self.vnet_state_store.list()?,
            tagged_ifaces: crate::sys::list_tagged_interfaces(),
            datasets: self
                .zfs
                .as_ref()
                .map(|zfs| zfs.list_jail_datasets())
                .unwrap_or_default(),
            drain_anchors: crate::bulkhead::list_drain_anchors(),
        })
    }

    /// Release everything an orphan claims. `dry_run` reports without mutating.
    pub fn reap(&self, orphan: &Orphan, force: bool, dry_run: bool) -> Result<()> {
        if orphan.requires_force && !force {
            return Err(Error::InvalidArgument(format!(
                "refusing to reap {} '{}' without --force",
                orphan.kind_label(),
                orphan.jail
            )));
        }
        if dry_run {
            return Ok(());
        }

        match &orphan.kind {
            OrphanKind::DeadScope(scope) => self.reap_scope(scope, force),
            OrphanKind::StrayVnet(record) => {
                VnetSetup::cleanup_state(record)?;
                self.vnet_state_store.delete(&record.owner)?;
                Ok(())
            }
            OrphanKind::StrayInterface(iface) => crate::network::ioctl::destroy_interface(iface),
            OrphanKind::StrayDataset(name) => match &self.zfs {
                Some(zfs) => zfs.destroy_jail_dataset(name),
                None => Err(Error::Zfs("ZFS is not enabled".to_string())),
            },
            OrphanKind::StrayDrainAnchor(anchor) => {
                crate::bulkhead::flush_drain_anchor(anchor);
                Ok(())
            }
        }
    }

    /// Mirrors `stop_jail`'s teardown order: fence, then unbind, then destroy.
    fn reap_scope(&self, scope: &ScopeRecord, force: bool) -> Result<()> {
        let mut residual = Vec::new();

        if let Some(anchor) = &scope.drain_anchor {
            crate::bulkhead::flush_drain_anchor(anchor);
        }

        if scope.rctl_subject.is_some() {
            crate::rctl::remove_limits(&scope.name);
        }

        if scope.has_vnet_record
            && let Some(record) = self.vnet_state_store.get(&scope.name)?
        {
            match VnetSetup::cleanup_state(&record) {
                Ok(()) => {
                    self.vnet_state_store.delete(&scope.name)?;
                }
                Err(e) => {
                    eprintln!("Warning: VNET cleanup for '{}' failed: {}", scope.name, e);
                    residual.push("vnet".to_string());
                }
            }
        }

        let jail_root = self.data_dir.join("jails").join(&scope.name);
        if let Ok(table) = crate::sys::mount_table() {
            for mountpoint in crate::sys::mounted_paths_under(&jail_root, &table) {
                crate::sys::unmount_quiet(&mountpoint);
            }
            if let Ok(table) = crate::sys::mount_table() {
                for mountpoint in crate::sys::mounted_paths_under(&jail_root, &table) {
                    residual.push(format!("mount {}", mountpoint.display()));
                }
            }
        }

        if let Some(dataset) = &scope.zfs_dataset {
            if scope.ephemeral || force {
                match &self.zfs {
                    Some(zfs) => {
                        if let Err(e) = zfs.destroy_jail_dataset(&scope.name) {
                            eprintln!("Warning: failed to destroy '{}': {}", dataset, e);
                            residual.push(format!("dataset {}", dataset));
                        }
                    }
                    None => residual.push(format!("dataset {}", dataset)),
                }
            } else {
                println!(
                    "  Keeping non-ephemeral dataset '{}' (use --force to destroy)",
                    dataset
                );
            }
        }

        let released = self.lease_store.release_owner(&scope.name)?;
        if self.verbose {
            for (network, ip) in &released {
                println!("  Released {} from network '{}'", ip, network);
            }
        }

        if let Ok(mut bulkhead) = BulkheadManager::from_data_dir(&self.data_dir)
            && let Err(e) = bulkhead.remove_jail_forwards(&scope.name)
        {
            eprintln!(
                "Warning: failed to remove port forwards for '{}': {}",
                scope.name, e
            );
            residual.push("port-forwards".to_string());
        }

        let mut record = AuditRecord::new(&scope.name, AuditEvent::Reaped);
        if residual.is_empty() {
            self.audit.record(&record);
            self.scope_store.delete(&scope.name)?;
            if force && let Err(e) = self.audit.delete(&scope.name) {
                eprintln!(
                    "Warning: failed to remove audit log for '{}': {}",
                    scope.name, e
                );
            }
            Ok(())
        } else {
            record = record.with("residual", residual.join(","));
            self.audit.record(&record);
            Err(Error::State(format!(
                "reaped '{}' but {} remain; scope record kept",
                scope.name,
                residual.join(", ")
            )))
        }
    }
}

/// Reap only what blackship can prove it owns. Never fails the caller.
pub fn auto_reconcile(config: &BlackshipConfig, verbose: bool) {
    let reaper = match Reaper::new(config, verbose) {
        Ok(reaper) => reaper,
        Err(e) => {
            if verbose {
                eprintln!("Warning: skipping reconcile: {}", e);
            }
            return;
        }
    };

    let survey = match reaper.survey() {
        Ok(survey) => survey,
        Err(e) => {
            eprintln!("Warning: reconcile survey failed: {}", e);
            return;
        }
    };

    for orphan in classify(&survey) {
        if orphan.requires_force {
            continue;
        }
        println!(
            "Reconciling orphaned {} '{}'",
            orphan.kind_label(),
            orphan.jail
        );
        if let Err(e) = reaper.reap(&orphan, false, false) {
            eprintln!("Warning: {}", e);
        }
    }
}

#[cfg(test)]
mod tests;
