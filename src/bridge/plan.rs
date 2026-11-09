//! Dry-run plans: computed once, rendered as JSON or as text.

use serde::Serialize;

use crate::error::{Error, Result};
use crate::hooks::HookPhase;
use crate::jail::jail_getid;
use crate::manifest::JailDef;

use super::Bridge;

/// One step of a lifecycle plan.
#[derive(Debug, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum PlanStep {
    Start {
        jail: String,
        path: String,
        ip: Option<String>,
        currently_running: bool,
        create_zfs_dataset: bool,
        hooks: StartHooks,
    },
    Stop {
        jail: String,
        currently_running: bool,
        hooks: StopHooks,
    },
    Update {
        jail: String,
        jid: i32,
        parameter_changes: Vec<String>,
        restart_required: Vec<String>,
        unreadable_parameters: Vec<String>,
        rctl_rules: Vec<String>,
        cpu_list: Option<String>,
        no_changes: bool,
    },
    Skip {
        jail: String,
        reason: &'static str,
    },
}

#[derive(Debug, Default, Serialize)]
pub struct StartHooks {
    pre_start: usize,
    post_start: usize,
}

#[derive(Debug, Default, Serialize)]
pub struct StopHooks {
    pre_stop: usize,
    post_stop: usize,
}

fn hook_count(jail: &JailDef, phase: HookPhase) -> usize {
    jail.hooks.iter().filter(|hook| hook.phase == phase).count()
}

fn print_hooks(indent: &str, counts: [(usize, &str); 2]) {
    for (count, label) in counts {
        if count > 0 {
            println!("{indent}Hooks: {count} {label}");
        }
    }
}

impl PlanStep {
    /// The dry-run text for this step.
    pub fn print(&self) {
        match self {
            Self::Start {
                jail,
                path,
                ip,
                create_zfs_dataset,
                hooks,
                ..
            } => {
                const IND: &str = "          ";
                println!("  [START] {jail}");
                println!("{IND}Path: {path}");
                println!("{IND}IP: {}", ip.as_deref().unwrap_or("none"));
                if *create_zfs_dataset {
                    println!("{IND}ZFS: would create dataset");
                }
                print_hooks(
                    IND,
                    [
                        (hooks.pre_start, "pre_start"),
                        (hooks.post_start, "post_start"),
                    ],
                );
                println!();
            }
            Self::Stop {
                jail,
                currently_running,
                hooks,
            } => {
                let status = if *currently_running {
                    "running"
                } else {
                    "stopped"
                };
                println!("  [STOP] {jail} (currently {status})");
                print_hooks(
                    "         ",
                    [(hooks.pre_stop, "pre_stop"), (hooks.post_stop, "post_stop")],
                );
            }
            Self::Update {
                jail,
                jid,
                parameter_changes,
                restart_required,
                unreadable_parameters,
                rctl_rules,
                cpu_list,
                no_changes,
            } => {
                println!("  [EVA] {jail} (JID {jid})");
                for line in parameter_changes {
                    println!("          {line}");
                }
                for line in restart_required {
                    println!("        ! {line} (requires restart)");
                }
                for key in unreadable_parameters {
                    println!("          {key}: not reported by jls, would apply blind");
                }
                if !rctl_rules.is_empty() {
                    println!("          rctl: replace with {} rule(s):", rctl_rules.len());
                    for rule in rctl_rules {
                        println!("            {rule}");
                    }
                }
                if let Some(list) = cpu_list {
                    println!("          cpuset: pin to CPUs {list}");
                }
                if *no_changes {
                    println!("          (no changes)");
                }
                println!();
            }
            Self::Skip { jail, reason } => {
                println!("  [SKIP] {jail} ({})", reason.replace('_', " "));
            }
        }
    }
}

impl Bridge {
    /// What `up` would do, in start order.
    pub(crate) fn start_steps(&self, jail: Option<&str>) -> Result<Vec<PlanStep>> {
        self.jails_for_up(jail)?
            .iter()
            .map(|name| {
                let (service_name, full_name) = self.resolve_jail_names(name)?;
                let jail_def = self
                    .config
                    .get_jail(&service_name)
                    .ok_or_else(|| Error::JailNotFound(service_name.clone()))?;
                Ok(PlanStep::Start {
                    path: jail_def
                        .effective_path(&self.config.config, &full_name)
                        .display()
                        .to_string(),
                    ip: jail_def
                        .network
                        .as_ref()
                        .and_then(|network| network.ip)
                        .map(|ip| ip.to_string()),
                    currently_running: jail_getid(&full_name).is_ok(),
                    create_zfs_dataset: self.zfs.is_some() && jail_def.path.is_none(),
                    hooks: StartHooks {
                        pre_start: hook_count(jail_def, HookPhase::PreStart),
                        post_start: hook_count(jail_def, HookPhase::PostStart),
                    },
                    jail: full_name,
                })
            })
            .collect()
    }

    /// What `down` would do, in stop order.
    pub(crate) fn stop_steps(&self, jail: Option<&str>) -> Result<Vec<PlanStep>> {
        self.jails_for_down(jail)?
            .iter()
            .map(|name| {
                let (service_name, full_name) = self.resolve_jail_names(name)?;
                let hooks = self
                    .config
                    .get_jail(&service_name)
                    .map(|def| StopHooks {
                        pre_stop: hook_count(def, HookPhase::PreStop),
                        post_stop: hook_count(def, HookPhase::PostStop),
                    })
                    .unwrap_or_default();
                Ok(PlanStep::Stop {
                    currently_running: jail_getid(&full_name).is_ok(),
                    jail: full_name,
                    hooks,
                })
            })
            .collect()
    }

    /// Dry run: show what `up` would do without making changes.
    pub fn up_dry_run(&self, jail: Option<&str>) -> Result<()> {
        let steps = self.start_steps(jail)?;
        println!("=== DRY RUN - No changes will be made ===\n");
        println!("Would start {} jail(s):\n", steps.len());
        steps.iter().for_each(PlanStep::print);
        Ok(())
    }

    /// Dry run: show what `down` would do without making changes.
    pub fn down_dry_run(&self, jail: Option<&str>) -> Result<()> {
        let steps = self.stop_steps(jail)?;
        println!("=== DRY RUN - No changes will be made ===\n");
        println!("Would stop {} jail(s):\n", steps.len());
        steps.iter().for_each(PlanStep::print);
        println!();
        Ok(())
    }
}
