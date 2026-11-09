//! Status and dry-run operations

use crate::error::Result;
use crate::hooks::HookPhase;
use crate::jail::jail_getid;
use serde::Serialize;

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
}

/// Result of validating the manifest and resolving its jail paths.
#[derive(Debug, Serialize)]
pub struct CheckReport {
    pub valid: bool,
    pub start_order: Vec<String>,
    pub zfs_enabled: bool,
    pub jail_paths: Vec<JailPathStatus>,
}

#[derive(Debug, Serialize)]
pub struct JailPathStatus {
    pub name: String,
    pub path: String,
    pub exists: bool,
}

impl Bridge {
    /// Build the machine-readable plan behind an `up --dry-run` invocation.
    pub(crate) fn up_plan_data(&self, jail: Option<&str>) -> Result<Vec<serde_json::Value>> {
        self.jails_for_up(jail)?
            .iter()
            .map(|name| {
                let (service_name, full_name) = self.resolve_jail_names(name)?;
                let jail_def = self
                    .config
                    .get_jail(&service_name)
                    .ok_or_else(|| crate::error::Error::JailNotFound(service_name.clone()))?;
                let path = jail_def.effective_path(&self.config.config, &full_name);
                let ip = jail_def
                    .network
                    .as_ref()
                    .and_then(|network| network.ip)
                    .map(|ip| ip.to_string());
                Ok(serde_json::json!({
                    "action": "start",
                    "jail": full_name,
                    "path": path.display().to_string(),
                    "ip": ip,
                    "currently_running": jail_getid(&full_name).is_ok(),
                    "create_zfs_dataset": self.zfs.is_some() && jail_def.path.is_none(),
                    "hooks": {
                        "pre_start": hook_count(jail_def, HookPhase::PreStart),
                        "post_start": hook_count(jail_def, HookPhase::PostStart),
                    }
                }))
            })
            .collect()
    }

    /// Build the machine-readable plan behind a `down --dry-run` invocation.
    pub(crate) fn down_plan_data(&self, jail: Option<&str>) -> Result<Vec<serde_json::Value>> {
        self.jails_for_down(jail)?
            .iter()
            .map(|name| {
                let (service_name, full_name) = self.resolve_jail_names(name)?;
                let jail_def = self.config.get_jail(&service_name);
                Ok(serde_json::json!({
                    "action": "stop",
                    "jail": full_name,
                    "currently_running": jail_getid(&full_name).is_ok(),
                    "hooks": {
                        "pre_stop": jail_def.map_or(0, |jail| hook_count(jail, HookPhase::PreStop)),
                        "post_stop": jail_def.map_or(0, |jail| hook_count(jail, HookPhase::PostStop)),
                    }
                }))
            })
            .collect()
    }

    /// Dry run: show what 'up' would do without making changes
    pub fn up_dry_run(&self, jail: Option<&str>) -> Result<()> {
        println!("=== DRY RUN - No changes will be made ===\n");

        let jails_to_start = self.jails_for_up(jail)?;

        println!("Would start {} jail(s):\n", jails_to_start.len());

        for name in &jails_to_start {
            let (service_name, full_name) = self.resolve_jail_names(name)?;
            let jail_def = self.config.get_jail(&service_name);
            if let Some(jail_def) = jail_def {
                let path = jail_def.effective_path(&self.config.config, &full_name);
                let ip = jail_def
                    .network
                    .as_ref()
                    .and_then(|n| n.ip)
                    .map_or_else(|| "none".to_string(), |ip| ip.to_string());

                println!("  [START] {full_name}");
                println!("          Path: {}", path.display());
                println!("          IP: {ip}");

                if self.zfs.is_some() && jail_def.path.is_none() {
                    println!("          ZFS: would create dataset");
                }

                print_hook_counts(
                    jail_def,
                    "          ",
                    [
                        (HookPhase::PreStart, "pre_start"),
                        (HookPhase::PostStart, "post_start"),
                    ],
                );
                println!();
            }
        }

        Ok(())
    }

    /// Dry run: show what 'down' would do without making changes
    pub fn down_dry_run(&self, jail: Option<&str>) -> Result<()> {
        println!("=== DRY RUN - No changes will be made ===\n");

        let jails_to_stop = self.jails_for_down(jail)?;

        println!("Would stop {} jail(s):\n", jails_to_stop.len());

        for name in &jails_to_stop {
            let (service_name, full_name) = self.resolve_jail_names(name)?;
            let is_running = jail_getid(&full_name).is_ok();
            let status = if is_running { "running" } else { "stopped" };

            println!("  [STOP] {full_name} (currently {status})");

            if let Some(jail_def) = self.config.get_jail(&service_name) {
                print_hook_counts(
                    jail_def,
                    "         ",
                    [
                        (HookPhase::PreStop, "pre_stop"),
                        (HookPhase::PostStop, "post_stop"),
                    ],
                );
            }
        }

        println!();
        Ok(())
    }

    /// The owning jail descriptor fd held for a jail, when there is one.
    pub fn jail_descriptor_fd(&self, full_name: &str) -> Option<i32> {
        self.instances
            .get(full_name)
            .and_then(|instance| instance.handle.as_ref())
            .and_then(crate::jail::JailHandle::descriptor_fd)
    }

    /// Print jail status
    pub fn ps(&self, json: bool) {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&self.ps_data())
                    .expect("JailStatus always serializes")
            );
        } else {
            println!("{:<20} {:<10} {:<10}", "NAME", "STATE", "JID");
            println!("{}", "-".repeat(42));

            for jail_def in &self.config.jails {
                let full_name = self.config.jail_name(&jail_def.name);
                let (state, jid) = if let Some(instance) = self.instances.get(&full_name) {
                    let state = format!("{:?}", instance.state());
                    let jid = instance.jid.map(|j| j.to_string()).unwrap_or_default();
                    (state, jid)
                } else {
                    match jail_getid(&full_name) {
                        Ok(jid) => ("Running".to_string(), jid.to_string()),
                        Err(_) => ("Stopped".to_string(), String::new()),
                    }
                };

                println!("{full_name:<20} {state:<10} {jid:<10}");
            }
        }
    }

    /// Return jail status without writing terminal output.
    pub fn ps_data(&self) -> Vec<JailStatus> {
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
                            .and_then(|network| network.ip)
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
                }
            })
            .collect()
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
        })
    }
}

fn hook_count(jail: &crate::manifest::JailDef, phase: HookPhase) -> usize {
    jail.hooks.iter().filter(|hook| hook.phase == phase).count()
}

/// Dry-run line per phase that has hooks: `Hooks: 2 pre_start`.
fn print_hook_counts(
    jail_def: &crate::manifest::JailDef,
    indent: &str,
    phases: [(HookPhase, &str); 2],
) {
    for (phase, label) in phases {
        let count = jail_def.hooks.iter().filter(|h| h.phase == phase).count();
        if count > 0 {
            println!("{indent}Hooks: {count} {label}");
        }
    }
}
