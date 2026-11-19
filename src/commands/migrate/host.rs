//! The real effects of a migration: zfs here, ssh to the destination.

use std::process::{Command, Output, Stdio};

use super::record::Record;
use super::saga::{Effects, Remote};
use crate::error::{Error, Result};
use crate::manifest::BlackshipConfig;
use crate::zfs::ZfsManager;

pub struct Host<'a> {
    config: &'a BlackshipConfig,
    zfs: ZfsManager,
    service: String,
    jail: String,
    source_dataset: String,
    snapshot: String,
    target: String,
    remote_dataset: String,
}

impl<'a> Host<'a> {
    pub fn new(config: &'a BlackshipConfig, zfs: ZfsManager, record: &Record) -> Self {
        Self {
            config,
            zfs,
            service: record.service.clone(),
            jail: record.jail.clone(),
            source_dataset: record.source_dataset.clone(),
            snapshot: record.snapshot.clone(),
            target: record.target.clone(),
            remote_dataset: record.remote_dataset.clone(),
        }
    }

    fn snapshot_ref(&self) -> String {
        format!("{}@{}", self.source_dataset, self.snapshot)
    }

    fn ssh(&self, args: &[&str]) -> Result<Output> {
        Command::new("/usr/bin/ssh")
            .args(["-o", "BatchMode=yes", &self.target])
            .args(args)
            .output()
            .map_err(|e| Error::JailOperation(format!("Failed to run ssh: {e}")))
    }

    /// Whether the destination has `name`. ssh's own failure (255) is not an answer.
    fn remote_has(&self, name: &str) -> Result<bool> {
        let probe = self.ssh(&["zfs", "list", "-H", "-o", "name", name])?;
        match probe.status.code() {
            Some(0) => Ok(true),
            Some(255) | None => Err(Error::JailOperation(format!(
                "Cannot ask {} about '{name}' over ssh",
                self.target
            ))),
            Some(_) => Ok(false),
        }
    }
}

impl Effects for Host<'_> {
    fn stage(&mut self) -> bool {
        super::super::snapshot::stage_config_in_dataset(self.config, &self.service, &self.jail)
    }

    fn snapshot_exists(&mut self) -> Result<bool> {
        self.zfs.dataset_exists(&self.snapshot_ref())
    }

    fn create_snapshot(&mut self) -> Result<()> {
        self.zfs
            .create_snapshot(&self.jail, Some(&self.snapshot))
            .map(drop)
    }

    fn delete_snapshot(&mut self) -> Result<()> {
        self.zfs.delete_snapshot(&self.jail, &self.snapshot)
    }

    fn remote(&mut self) -> Result<Remote> {
        if !self.remote_has(&self.remote_dataset)? {
            return Ok(Remote::Absent);
        }
        let snapshot = format!("{}@{}", self.remote_dataset, self.snapshot);
        Ok(if self.remote_has(&snapshot)? {
            Remote::Complete
        } else {
            Remote::Partial
        })
    }

    fn transfer(&mut self) -> Result<()> {
        let snapshot = self.snapshot_ref();
        println!(
            "Sending {snapshot} to {}:{} ...",
            self.target, self.remote_dataset
        );
        let mut send = Command::new("/sbin/zfs")
            .args(super::send_args(
                &snapshot,
                self.zfs.dataset_origin(&self.source_dataset).is_some(),
            ))
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| Error::JailOperation(format!("Failed to run zfs send: {e}")))?;
        let Some(send_out) = send.stdout.take() else {
            let _ = send.kill();
            let _ = send.wait();
            return Err(Error::JailOperation(
                "Failed to capture zfs send output".to_string(),
            ));
        };
        let receive = Command::new("/usr/bin/ssh")
            .args(["-o", "BatchMode=yes", &self.target])
            .args(["zfs", "receive", "-u", &self.remote_dataset])
            .stdin(Stdio::from(send_out))
            .status();
        let send_status = send.wait();
        let receive = receive
            .map_err(|e| Error::JailOperation(format!("Failed to run remote receive: {e}")))?;
        let send_status =
            send_status.map_err(|e| Error::JailOperation(format!("zfs send failed: {e}")))?;
        if !send_status.success() || !receive.success() {
            return Err(Error::JailOperation(
                "zfs send or the remote receive failed".to_string(),
            ));
        }
        println!("Transfer complete.");
        Ok(())
    }

    fn discard_destination(&mut self) -> Result<()> {
        // A record exists only after the preflight proved the dataset absent, so
        // whatever carries the name now is this migration's.
        self.ssh(&["zfs", "destroy", "-r", &self.remote_dataset])?;
        if self.remote_has(&self.remote_dataset)? {
            return Err(Error::JailOperation(format!(
                "'{}' is still on {}",
                self.remote_dataset, self.target
            )));
        }
        Ok(())
    }

    fn source_changed(&mut self) -> Result<bool> {
        let written =
            ZfsManager::get_property(&self.source_dataset, &format!("written@{}", self.snapshot))?;
        Ok(!is_unwritten(&written))
    }

    fn fence_state(&mut self) -> Result<Option<String>> {
        Ok(self.zfs.jail_migration_fence(&self.jail))
    }

    fn fence(&mut self, destination: &str) -> Result<()> {
        if let Err(e) = self.zfs.fence_jail_dataset(&self.jail, destination) {
            let _ = self.zfs.clear_jail_migration_fence(&self.jail);
            return Err(e);
        }
        println!(
            "Source fenced: read-only, and 'up {}' refuses here.",
            self.service
        );
        Ok(())
    }

    fn clear_fence(&mut self) -> Result<()> {
        self.zfs.clear_jail_migration_fence(&self.jail)
    }
}

/// `zfs get written@snap` prints a human size: zero is "0B", and "-" is no answer.
pub fn is_unwritten(written: &str) -> bool {
    matches!(written.trim(), "0" | "0B")
}
