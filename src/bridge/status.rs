//! Status and dry-run operations

use crate::error::Result;
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
    /// The owning jail descriptor fd held for a jail, when there is one.
    pub fn jail_descriptor_fd(&self, full_name: &str) -> Option<i32> {
        self.instances
            .get(full_name)
            .and_then(|instance| instance.handle.as_ref())
            .and_then(crate::jail::JailHandle::descriptor_fd)
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
