//! Status and dry-run operations

use crate::error::Result;
use crate::jail::jail_getid;
use crate::sickbay::HealthStatus;
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::Path;

use super::Bridge;

/// Stable jail status representation used by JSON consumers.
#[derive(Debug, Serialize)]
pub struct JailStatus {
    pub name: String,
    pub state: String,
    pub jid: Option<i32>,
    pub running: bool,
    pub hostname: Option<String>,
    pub ip: Option<String>,
    pub ips: Vec<String>,
    pub path: String,
    pub tags: Vec<String>,
    pub autostart: bool,
}

/// Host inventory for one manifest plus running jails it does not manage.
#[derive(Debug, Serialize)]
pub struct InventoryReport {
    pub project: String,
    pub config_path: String,
    pub jails: Vec<InventoryJail>,
}

/// One jail in the host inventory.
#[derive(Debug, Serialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "stable JSON uses explicit ownership and lifecycle flags"
)]
pub struct InventoryJail {
    pub service_name: Option<String>,
    pub full_name: String,
    pub manager: &'static str,
    pub managed: bool,
    pub configured: bool,
    pub running: bool,
    pub state: String,
    pub jid: Option<i32>,
    pub release: Option<String>,
    pub hostname: Option<String>,
    pub ip: Option<String>,
    pub ips: Vec<String>,
    pub path: Option<String>,
    pub networks: Vec<String>,
    pub depends_on: Vec<String>,
    pub tags: Vec<String>,
    pub autostart: bool,
}

/// Result of validating the manifest and resolving its jail paths.
#[derive(Debug, Serialize)]
pub struct CheckReport {
    pub valid: bool,
    pub start_order: Vec<String>,
    pub zfs_enabled: bool,
    pub jail_paths: Vec<JailPathStatus>,
    /// Host state that will stop a start but not the manifest itself.
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct JailPathStatus {
    pub name: String,
    pub path: String,
    pub exists: bool,
}

impl Bridge {
    /// The owning jail descriptor fd held for a jail, when there is one.
    pub fn jail_descriptor_fd(&self, full_name: &str) -> Option<i32> {
        self.instances
            .get(full_name)
            .and_then(|instance| instance.handle.as_ref())
            .and_then(crate::jail::JailHandle::descriptor_fd)
    }

    /// A handle on this bridge's audit log, for readers that outlive a borrow of it.
    pub fn audit_log(&self) -> crate::audit::AuditLog {
        self.audit.clone()
    }

    /// Report a health verdict into the jail's chart; ignored unless it is running.
    pub fn record_health(&mut self, full_name: &str, status: HealthStatus) {
        if let Some(instance) = self.instances.get_mut(full_name)
            && instance.is_running()
        {
            match instance.set_health(status) {
                Ok(()) if self.verbose => {
                    println!("  Health chart '{full_name}': {:?}", instance.health());
                }
                Ok(()) => {}
                Err(e) => {
                    eprintln!("Warning: health chart rejected '{status}' for '{full_name}': {e}");
                }
            }
        }
    }

    /// Print jail status
    pub fn ps(&self, json: bool) {
        let jails = self.ps_data();
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&jails).expect("JailStatus always serializes")
            );
            return;
        }
        println!("{:<20} {:<10} {:<10}", "NAME", "STATE", "JID");
        println!("{}", "-".repeat(42));
        for jail in jails {
            let jid = jail.jid.map(|j| j.to_string()).unwrap_or_default();
            println!("{:<20} {:<10} {jid:<10}", jail.name, jail.state);
        }
    }

    /// Print configured Blackship jails and every other running host jail.
    pub fn ps_host(&self, config_path: &Path, json: bool) {
        let report = self.inventory_data(config_path);
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).expect("InventoryReport always serializes")
            );
            return;
        }

        println!(
            "{:<24} {:<12} {:<10} {:<10}",
            "NAME", "MANAGER", "STATE", "JID"
        );
        println!("{}", "-".repeat(60));
        for jail in report.jails {
            let jid = jail.jid.map(|j| j.to_string()).unwrap_or_default();
            println!(
                "{:<24} {:<12} {:<10} {jid:<10}",
                jail.full_name, jail.manager, jail.state
            );
        }
    }

    /// Return jail status without writing terminal output.
    pub fn ps_data(&self) -> Vec<JailStatus> {
        let autostart = self
            .autostart_order()
            .unwrap_or_default()
            .into_iter()
            .collect::<BTreeSet<_>>();
        self.config
            .jails
            .iter()
            .map(|jail_def| {
                let full_name = self.config.jail_name(&jail_def.name);
                let instance = self.instances.get(&full_name);

                let (state, jid, running) = match instance {
                    Some(instance) => (
                        format!("{:?}", instance.state()),
                        instance.jid,
                        instance.is_running(),
                    ),
                    None => match jail_getid(&full_name) {
                        Ok(jid) => ("Running".to_string(), Some(jid), true),
                        Err(_) => ("Stopped".to_string(), None, false),
                    },
                };

                let (name, path, hostname, ips) = match instance {
                    Some(instance) => (
                        instance.config.name.clone(),
                        instance.config.path.clone(),
                        instance.config.hostname.clone(),
                        instance
                            .config
                            .ips
                            .iter()
                            .map(std::string::ToString::to_string)
                            .collect::<Vec<_>>(),
                    ),
                    None => (
                        full_name,
                        jail_def.effective_path(
                            &self.config.config,
                            &self.config.jail_name(&jail_def.name),
                        ),
                        jail_def.hostname.clone(),
                        jail_def
                            .network
                            .as_ref()
                            .and_then(crate::manifest::JailNetworkConfig::static_ip)
                            .map(|ip| vec![ip.to_string()])
                            .unwrap_or_default(),
                    ),
                };
                let ip = ips.first().cloned();

                JailStatus {
                    name,
                    state,
                    jid,
                    running,
                    hostname,
                    ip,
                    ips,
                    path: path.to_string_lossy().into_owned(),
                    tags: jail_def.tags.clone(),
                    autostart: autostart.contains(&jail_def.name),
                }
            })
            .collect()
    }

    /// Return manifest-owned jails and running jails outside that manifest.
    ///
    /// Stopped unmanaged jails are intentionally absent: without a known
    /// manifest there is no authoritative host-wide registry for them.
    pub fn inventory_data(&self, config_path: &Path) -> InventoryReport {
        let statuses = self.ps_data();
        let managed_names: BTreeSet<String> = self
            .config
            .jails
            .iter()
            .map(|jail| self.config.jail_name(&jail.name))
            .collect();

        let mut jails = self
            .config
            .jails
            .iter()
            .zip(statuses)
            .map(|(definition, status)| InventoryJail {
                service_name: Some(definition.name.clone()),
                full_name: status.name,
                manager: "blackship",
                managed: true,
                configured: true,
                running: status.running,
                state: status.state,
                jid: status.jid,
                release: definition.release.clone(),
                hostname: status.hostname,
                ip: status.ip,
                ips: status.ips,
                path: Some(status.path),
                networks: definition
                    .network
                    .as_ref()
                    .map_or_else(Vec::new, |network| network.networks.clone()),
                depends_on: definition.depends_on.clone(),
                tags: status.tags,
                autostart: status.autostart,
            })
            .collect::<Vec<_>>();

        jails.extend(crate::jail::RunningJails::new().filter_map(|jid| {
            let name = crate::jail::jail_getname(jid).ok()?;
            if managed_names.contains(&name) {
                return None;
            }
            Some(InventoryJail {
                service_name: None,
                full_name: name,
                manager: "native",
                managed: false,
                configured: false,
                running: true,
                state: "Running".to_string(),
                jid: Some(jid),
                release: None,
                hostname: None,
                ip: None,
                ips: Vec::new(),
                path: None,
                networks: Vec::new(),
                depends_on: Vec::new(),
                tags: Vec::new(),
                autostart: false,
            })
        }));

        InventoryReport {
            project: self.config.config.project_name().to_string(),
            config_path: config_path.display().to_string(),
            jails,
        }
    }

    /// Validate configuration
    pub fn check(&self) -> Result<()> {
        let report = self.check_data()?;
        println!("Configuration is valid.");
        println!("\nStart order:");
        for (i, name) in report.start_order.iter().enumerate() {
            println!("  {}. {}", i + 1, name);
        }

        if report.zfs_enabled {
            println!("\nZFS: enabled");
        } else {
            println!("\nZFS: disabled");
        }

        println!("\nJail paths:");
        for jail in report.jail_paths {
            let status = if jail.exists { "exists" } else { "missing" };
            println!("  {}: {} ({})", jail.name, jail.path, status);
        }

        if !report.warnings.is_empty() {
            println!("\nWarnings:");
            for warning in &report.warnings {
                println!("  {warning}");
            }
        }

        Ok(())
    }

    /// Validate configuration and return a structured report.
    pub fn check_data(&self) -> Result<CheckReport> {
        let start_order = self
            .start_order()?
            .into_iter()
            .map(|name| self.config.jail_name(name))
            .collect();
        let jail_paths = self
            .config
            .jails
            .iter()
            .map(|jail| {
                let name = self.config.jail_name(&jail.name);
                let path = jail.effective_path(&self.config.config, &name);
                JailPathStatus {
                    name,
                    exists: path.exists(),
                    path: path.to_string_lossy().into_owned(),
                }
            })
            .collect();

        Ok(CheckReport {
            valid: true,
            start_order,
            zfs_enabled: self.zfs.is_some(),
            jail_paths,
            warnings: crate::provision::unbootstrapped_releases(&self.config),
        })
    }
}
