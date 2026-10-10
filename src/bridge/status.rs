//! Status and dry-run operations

use crate::error::Result;
use crate::jail::jail_getid;

use super::Bridge;

impl Bridge {
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
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "none".to_string());

                println!("  [START] {full_name}");
                println!("          Path: {}", path.display());
                println!("          IP: {ip}");

                if self.zfs.is_some() && jail_def.path.is_none() {
                    println!("          ZFS: would create dataset");
                }

                if !jail_def.hooks.is_empty() {
                    let pre_start: Vec<_> = jail_def
                        .hooks
                        .iter()
                        .filter(|h| h.phase == crate::hooks::HookPhase::PreStart)
                        .collect();
                    let post_start: Vec<_> = jail_def
                        .hooks
                        .iter()
                        .filter(|h| h.phase == crate::hooks::HookPhase::PostStart)
                        .collect();

                    if !pre_start.is_empty() {
                        println!("          Hooks: {} pre_start", pre_start.len());
                    }
                    if !post_start.is_empty() {
                        println!("          Hooks: {} post_start", post_start.len());
                    }
                }
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

            if let Some(jail_def) = self.config.get_jail(&service_name)
                && !jail_def.hooks.is_empty()
            {
                let pre_stop: Vec<_> = jail_def
                    .hooks
                    .iter()
                    .filter(|h| h.phase == crate::hooks::HookPhase::PreStop)
                    .collect();
                let post_stop: Vec<_> = jail_def
                    .hooks
                    .iter()
                    .filter(|h| h.phase == crate::hooks::HookPhase::PostStop)
                    .collect();

                if !pre_stop.is_empty() {
                    println!("         Hooks: {} pre_stop", pre_stop.len());
                }
                if !post_stop.is_empty() {
                    println!("         Hooks: {} post_stop", post_stop.len());
                }
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
    pub fn ps(&self, json: bool) -> Result<()> {
        if json {
            let mut jails_data: Vec<serde_json::Value> = Vec::new();

            for jail_def in &self.config.jails {
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
                        full_name.clone(),
                        jail_def.effective_path(&self.config.config, &full_name),
                        jail_def.hostname.clone(),
                        jail_def
                            .network
                            .as_ref()
                            .and_then(|n| n.ip)
                            .map(|ip| vec![ip.to_string()])
                            .unwrap_or_default(),
                    ),
                };

                jails_data.push(serde_json::json!({
                    "name": name,
                    "state": state,
                    "jid": jid,
                    "running": running,
                    "hostname": hostname,
                    "ip": ips.first(),
                    "ips": ips,
                    "path": path.to_string_lossy()
                }));
            }

            println!("{}", serde_json::to_string_pretty(&jails_data).unwrap());
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

        Ok(())
    }

    /// Validate configuration
    pub fn check(&self) -> Result<()> {
        println!("Configuration is valid.");

        let order = self.start_order()?;
        println!("\nStart order:");
        for (i, name) in order.iter().enumerate() {
            let full_name = self.config.jail_name(name);
            println!("  {}. {}", i + 1, full_name);
        }

        if self.zfs.is_some() {
            println!("\nZFS: enabled");
        } else {
            println!("\nZFS: disabled");
        }

        println!("\nJail paths:");
        for jail in &self.config.jails {
            let full_name = self.config.jail_name(&jail.name);
            let path = jail.effective_path(&self.config.config, &full_name);
            let exists = path.exists();
            let status = if exists { "exists" } else { "missing" };
            println!("  {}: {} ({})", full_name, path.display(), status);
        }

        Ok(())
    }
}
