//! Status and dry-run operations

use crate::error::Result;
use crate::jail::jail_getid;
use crate::sickbay::{HealthStateRecord, HealthStateStore, HealthStatus};
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
    pub health: HealthSummary,
}

/// Passive, last-known health information for a host inventory row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HealthSummary {
    pub configured: bool,
    pub status: String,
    pub reason: Option<&'static str>,
    pub checked_at: Option<i64>,
    pub checks_total: usize,
    pub checks_passing: Option<usize>,
    pub checks_failing: Option<usize>,
    pub checks_pending: Option<usize>,
}

fn managed_health_summary(
    definition: &crate::manifest::JailDef,
    running: bool,
    jid: Option<i32>,
    state: Result<Option<HealthStateRecord>>,
) -> HealthSummary {
    let checks_total = definition.healthcheck.checks.len();
    if !definition.healthcheck.enabled || checks_total == 0 {
        return HealthSummary {
            configured: false,
            status: "not_configured".to_string(),
            reason: None,
            checked_at: None,
            checks_total: 0,
            checks_passing: None,
            checks_failing: None,
            checks_pending: None,
        };
    }

    let unknown = |reason| HealthSummary {
        configured: true,
        status: "unknown".to_string(),
        reason: Some(reason),
        checked_at: None,
        checks_total,
        checks_passing: None,
        checks_failing: None,
        checks_pending: None,
    };

    if !running {
        return unknown("stopped");
    }

    match state {
        Ok(Some(record)) if record.jid == jid => HealthSummary {
            configured: true,
            status: record.status.to_string(),
            reason: None,
            checked_at: Some(record.checked_at),
            checks_total: record.checks_total,
            checks_passing: Some(record.checks_passing),
            checks_failing: Some(record.checks_failing),
            checks_pending: Some(
                record
                    .checks_total
                    .saturating_sub(record.checks_passing.saturating_add(record.checks_failing)),
            ),
        },
        Ok(Some(_)) => unknown("stale_jid"),
        Ok(None) => unknown("not_checked"),
        Err(_) => unknown("state_unavailable"),
    }
}

fn unmanaged_health_summary() -> HealthSummary {
    HealthSummary {
        configured: false,
        status: "unknown".to_string(),
        reason: Some("unmanaged"),
        checked_at: None,
        checks_total: 0,
        checks_passing: None,
        checks_failing: None,
        checks_pending: None,
    }
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
            "{:<24} {:<12} {:<10} {:<14} {:<10}",
            "NAME", "MANAGER", "STATE", "HEALTH", "JID"
        );
        println!("{}", "-".repeat(75));
        for jail in report.jails {
            let jid = jail.jid.map(|j| j.to_string()).unwrap_or_default();
            println!(
                "{:<24} {:<12} {:<10} {:<14} {jid:<10}",
                jail.full_name, jail.manager, jail.state, jail.health.status
            );
        }
    }

    /// The effective autostart set, plus why it is empty when the graph cannot be ordered.
    pub(super) fn autostart_set(&self) -> (BTreeSet<String>, Option<crate::error::Error>) {
        match self.autostart_order() {
            Ok(order) => (order.into_iter().collect(), None),
            Err(e) => (BTreeSet::new(), Some(e)),
        }
    }

    /// Return jail status without writing terminal output.
    pub fn ps_data(&self) -> Vec<JailStatus> {
        let (autostart, problem) = self.autostart_set();
        if let Some(problem) = problem {
            eprintln!("Warning: autostart cannot be resolved, reporting none: {problem}");
        }
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
        let health_store = HealthStateStore::from_config(Some(&self.config));
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
            .map(|(definition, status)| {
                let health = managed_health_summary(
                    definition,
                    status.running,
                    status.jid,
                    health_store.get(&status.name),
                );
                InventoryJail {
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
                    health,
                }
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
                health: unmanaged_health_summary(),
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

#[cfg(test)]
mod health_summary_tests {
    use super::*;
    use crate::error::Error;
    use crate::manifest::BlackshipConfig;
    use crate::sickbay::HealthStatus;

    fn health_definition() -> crate::manifest::JailDef {
        let mut config: BlackshipConfig = toml::from_str(
            r#"
[config]

[[jails]]
name = "web"

[jails.healthcheck]
enabled = true

[[jails.healthcheck.checks]]
name = "http"
command = "fetch -qo /dev/null http://127.0.0.1/"
"#,
        )
        .unwrap();
        config.jails.remove(0)
    }

    #[test]
    fn summary_reports_health_not_configured() {
        let mut definition = health_definition();
        definition.healthcheck.enabled = false;

        let summary = managed_health_summary(&definition, true, Some(7), Ok(None));

        assert_eq!(summary.status, "not_configured");
        assert!(!summary.configured);
        assert_eq!(summary.reason, None);
    }

    #[test]
    fn summary_explains_unknown_states() {
        let definition = health_definition();

        let stopped = managed_health_summary(&definition, false, None, Ok(None));
        let unchecked = managed_health_summary(&definition, true, Some(7), Ok(None));
        let unavailable = managed_health_summary(
            &definition,
            true,
            Some(7),
            Err(Error::State("broken record".to_string())),
        );

        assert_eq!(stopped.reason, Some("stopped"));
        assert_eq!(unchecked.reason, Some("not_checked"));
        assert_eq!(unavailable.reason, Some("state_unavailable"));
    }

    #[test]
    fn summary_uses_only_health_from_current_jail_instance() {
        let definition = health_definition();
        let record = HealthStateRecord {
            jail: "blackship-web".to_string(),
            status: HealthStatus::Healthy,
            checked_at: 123,
            jid: Some(7),
            checks_total: 1,
            checks_passing: 1,
            checks_failing: 0,
        };

        let current = managed_health_summary(&definition, true, Some(7), Ok(Some(record.clone())));
        let restarted = managed_health_summary(&definition, true, Some(8), Ok(Some(record)));

        assert_eq!(current.status, "healthy");
        assert_eq!(current.checked_at, Some(123));
        assert_eq!(current.checks_passing, Some(1));
        assert_eq!(current.checks_pending, Some(0));
        assert_eq!(restarted.status, "unknown");
        assert_eq!(restarted.reason, Some("stale_jid"));
        assert_eq!(restarted.checked_at, None);
    }

    #[test]
    fn unmanaged_summary_is_explicit() {
        let summary = unmanaged_health_summary();

        assert_eq!(summary.status, "unknown");
        assert_eq!(summary.reason, Some("unmanaged"));
        assert!(!summary.configured);
    }
}
