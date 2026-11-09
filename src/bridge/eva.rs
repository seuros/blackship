//! EVA: hot update of running jails via `jail_set(JAIL_UPDATE)`, no restart.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::hooks::{HookContext, HookPhase, HookRunner};
use crate::jail::{ParamValue, jail_getid, jail_update};
use crate::manifest::JailDef;
use crate::rctl::ResourceConfig;

use super::Bridge;
use super::lifecycle::build_jail_params;
use super::plan::PlanStep;

/// How a parameter behaves once the jail is running. `ip4.addr`/`ip6.addr`
/// are kernel-updatable on non-vnet jails but stay immutable here: blackship
/// couples them to the lease store and pf anchors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParamClass {
    Selector,
    Immutable,
    Updatable,
}

fn classify_param(key: &str) -> ParamClass {
    use crate::sys::consts::{
        JAIL_PARAM_DEVFS_RULESET, JAIL_PARAM_IP4_ADDR, JAIL_PARAM_IP6_ADDR, JAIL_PARAM_JID,
        JAIL_PARAM_NAME, JAIL_PARAM_PATH, JAIL_PARAM_VNET,
    };
    match key {
        JAIL_PARAM_NAME | JAIL_PARAM_JID => ParamClass::Selector,
        JAIL_PARAM_PATH
        | JAIL_PARAM_VNET
        | JAIL_PARAM_IP4_ADDR
        | JAIL_PARAM_IP6_ADDR
        | JAIL_PARAM_DEVFS_RULESET => ParamClass::Immutable,
        _ => ParamClass::Updatable,
    }
}

fn param_display(value: &ParamValue) -> String {
    match value {
        ParamValue::Int(v) => v.to_string(),
        ParamValue::String(s) => s.clone(),
        ParamValue::Bool(b) => b.to_string(),
        ParamValue::Ipv4(addrs) => addrs
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
        ParamValue::Ipv6(addrs) => addrs
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
    }
}

fn param_value_matches(desired: &ParamValue, live: &str) -> bool {
    let live = live.trim();
    match desired {
        ParamValue::Int(v) => {
            live.parse::<i32>() == Ok(*v)
                || matches!(
                    (live, *v),
                    ("disable", libc::JAIL_SYS_DISABLE)
                        | ("new", libc::JAIL_SYS_NEW)
                        | ("inherit", libc::JAIL_SYS_INHERIT)
                )
        }
        ParamValue::String(s) => s == live,
        ParamValue::Bool(b) => match live {
            "true" | "1" => *b,
            "false" | "0" => !*b,
            _ => false,
        },
        ParamValue::Ipv4(addrs) => addr_list_matches(live, addrs),
        ParamValue::Ipv6(addrs) => addr_list_matches(live, addrs),
    }
}

fn addr_list_matches<T: std::str::FromStr + PartialEq>(live: &str, desired: &[T]) -> bool {
    let parsed: Vec<T> = live
        .split([',', ' '])
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect();
    parsed.len() == desired.len() && parsed.iter().zip(desired).all(|(a, b)| a == b)
}

#[derive(Debug, Default)]
struct EvaDiff {
    changes: HashMap<String, ParamValue>,
    display: Vec<String>,
    immutable_diffs: Vec<String>,
}

fn diff_params(
    desired: &HashMap<String, ParamValue>,
    live: &HashMap<String, String>,
    unreadable: &[String],
) -> EvaDiff {
    let mut diff = EvaDiff::default();

    let mut keys: Vec<&String> = desired.keys().collect();
    keys.sort();

    for key in keys {
        let value = &desired[key];
        let class = classify_param(key);
        if class == ParamClass::Selector {
            continue;
        }

        let (differs, live_str) = match live.get(key) {
            Some(live_value) => (!param_value_matches(value, live_value), live_value.clone()),
            None if unreadable.contains(key) => (true, "(unverified)".to_string()),
            None => (true, "(unset)".to_string()),
        };

        if !differs {
            continue;
        }

        let change = format!("{}: {} -> {}", key, live_str, param_display(value));
        match class {
            ParamClass::Immutable => diff.immutable_diffs.push(change),
            ParamClass::Updatable => {
                diff.display.push(change);
                diff.changes.insert(key.clone(), value.clone());
            }
            ParamClass::Selector => unreachable!(),
        }
    }

    diff
}

/// jls fails the whole invocation on any key it does not know, so fall
/// back to per-key reads and report the losers as unreadable.
fn read_live_params(full_name: &str, keys: &[&str]) -> (HashMap<String, String>, Vec<String>) {
    if let Ok(map) = jls_json(full_name, keys) {
        (map, Vec::new())
    } else {
        let mut live = HashMap::new();
        let mut unreadable = Vec::new();
        for &key in keys {
            match jls_json(full_name, &[key]) {
                Ok(map) => live.extend(map),
                Err(_) => unreadable.push(key.to_string()),
            }
        }
        (live, unreadable)
    }
}

fn jls_json(full_name: &str, keys: &[&str]) -> Result<HashMap<String, String>> {
    let mut args = vec!["--libxo", "json", "-j", full_name];
    args.extend_from_slice(keys);
    let json = crate::sys::run_json("/usr/sbin/jls", &args)?;

    let entry = json
        .get("jail-information")
        .and_then(|i| i.get("jail"))
        .and_then(|j| j.as_array())
        .and_then(|a| a.first())
        .ok_or_else(|| Error::JailOperation(format!("jls returned no data for '{full_name}'")))?;

    let mut map = HashMap::new();
    for key in keys {
        if let Some(value) = entry.get(*key) {
            let s = match value {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            map.insert(key.to_string(), s);
        }
    }
    Ok(map)
}

/// Addresses of `desired`'s family on `iface` inside the jail's vnet, or
/// `None` when they cannot be read (not root, interface gone).
fn vnet_addresses(full_name: &str, iface: &str, desired: IpAddr) -> Option<Vec<IpAddr>> {
    let family = if desired.is_ipv4() { "inet" } else { "inet6" };
    let output = std::process::Command::new("/sbin/ifconfig")
        .args(["-j", full_name, iface, family])
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    Some(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| {
                let mut words = line.split_whitespace();
                (words.next() == Some(family)).then(|| words.next())?
            })
            .filter_map(|addr| addr.split('%').next()?.parse().ok())
            .collect(),
    )
}

/// Everything EVA needs to know about one running jail.
struct EvaPlan<'a> {
    jail_def: &'a JailDef,
    full_name: String,
    jid: i32,
    path: PathBuf,
    static_ip: Option<IpAddr>,
    diff: EvaDiff,
    unreadable: Vec<String>,
    resources: &'a ResourceConfig,
    rctl_rules: Vec<String>,
    /// The kernel already holds exactly these rules; `None` when unreadable.
    rctl_current: Option<bool>,
    cpu_list: Option<String>,
}

impl EvaPlan<'_> {
    fn is_noop(&self) -> bool {
        self.diff.changes.is_empty() && self.rctl_current == Some(true) && self.cpu_list.is_none()
    }

    fn step(&self) -> PlanStep {
        PlanStep::Update {
            jail: self.full_name.clone(),
            jid: self.jid,
            parameter_changes: self.diff.display.clone(),
            restart_required: self.diff.immutable_diffs.clone(),
            unreadable_parameters: {
                let mut unreadable = self.unreadable.clone();
                if self.rctl_current.is_none() {
                    unreadable.push("rctl".to_string());
                }
                unreadable
            },
            rctl_rules: if self.rctl_current == Some(false) {
                self.rctl_rules.clone()
            } else {
                Vec::new()
            },
            rctl_clear: self.rctl_current == Some(false) && self.rctl_rules.is_empty(),
            cpu_list: self.cpu_list.clone(),
            no_changes: self.is_noop(),
        }
    }
}

enum EvaTarget<'a> {
    Skip(PlanStep),
    Ready(Box<EvaPlan<'a>>),
}

impl Bridge {
    fn eva_target(&self, name: &str) -> Result<EvaTarget<'_>> {
        let (service_name, full_name) = self.resolve_jail_names(name)?;
        let skip = |reason| {
            EvaTarget::Skip(PlanStep::Skip {
                jail: full_name.clone(),
                reason,
            })
        };
        let Some(jail_def) = self.config.get_jail(&service_name) else {
            return Ok(skip("not_configured"));
        };
        let Ok(jid) = jail_getid(&full_name) else {
            return Ok(skip("not_running"));
        };

        let is_vnet = jail_def.network.as_ref().is_some_and(|n| n.vnet);
        let static_ip = jail_def
            .network
            .as_ref()
            .and_then(crate::manifest::JailNetworkConfig::static_ip);
        let path = jail_def.effective_path(&self.config.config, &full_name);
        let mut desired = build_jail_params(jail_def, &full_name, is_vnet, static_ip)?;
        desired.insert(
            crate::sys::consts::JAIL_PARAM_PATH.to_string(),
            ParamValue::String(path.display().to_string()),
        );
        let keys: Vec<&str> = desired.keys().map(String::as_str).collect();
        let (live, unreadable) = read_live_params(&full_name, &keys);
        let mut unreadable = unreadable;
        let mut diff = diff_params(&desired, &live, &unreadable);
        if is_vnet && let Some(ip) = static_ip {
            self.diff_vnet_address(&full_name, ip, &mut diff, &mut unreadable);
        }

        let resources = self.effective_resources(&full_name, jail_def);
        let cpu_list =
            crate::rctl::resolve_cpu_list(resources, self.other_cpuset_pins(&service_name));
        Ok(EvaTarget::Ready(Box::new(EvaPlan {
            jail_def,
            rctl_rules: resources.to_rules(&full_name),
            rctl_current: crate::rctl::rules_current(&full_name, resources),
            full_name,
            jid,
            path,
            static_ip,
            diff,
            unreadable,
            resources,
            cpu_list,
        })))
    }

    /// A VNET jail's address lives in its own stack, where jls cannot see it:
    /// read it from the jail's interface and report drift as restart-required.
    fn diff_vnet_address(
        &self,
        full_name: &str,
        desired: IpAddr,
        diff: &mut EvaDiff,
        unreadable: &mut Vec<String>,
    ) {
        let key = match desired {
            IpAddr::V4(_) => crate::sys::consts::JAIL_PARAM_IP4_ADDR,
            IpAddr::V6(_) => crate::sys::consts::JAIL_PARAM_IP6_ADDR,
        };
        let live = self
            .vnet_state_store
            .get(full_name)
            .ok()
            .flatten()
            .and_then(|record| vnet_addresses(full_name, &record.jail_interface, desired));
        match live {
            Some(addrs) if addrs.contains(&desired) => {}
            Some(addrs) => {
                let live = addrs
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                let live = if live.is_empty() {
                    "(unset)".into()
                } else {
                    live
                };
                diff.immutable_diffs
                    .push(format!("{key}: {live} -> {desired}"));
            }
            None => unreadable.push(key.to_string()),
        }
    }

    /// What `eva` would do, per target jail.
    pub(crate) fn eva_steps(&self, jail: Option<&str>) -> Result<Vec<PlanStep>> {
        self.jails_for_up(jail)?
            .iter()
            .map(|name| {
                Ok(match self.eva_target(name)? {
                    EvaTarget::Skip(step) => step,
                    EvaTarget::Ready(plan) => plan.step(),
                })
            })
            .collect()
    }

    /// Hot-update running jails to match the manifest (EVA).
    pub fn eva(&self, jail: Option<&str>) -> Result<()> {
        self.eva_inner(jail, false)
    }

    /// Dry run: show what `eva` would change without applying anything.
    pub fn eva_dry_run(&self, jail: Option<&str>) -> Result<()> {
        println!("=== DRY RUN - No changes will be made ===\n");
        self.eva_inner(jail, true)
    }

    fn eva_inner(&self, jail: Option<&str>, dry_run: bool) -> Result<()> {
        let mut failures = Vec::new();
        for name in self.jails_for_up(jail)? {
            let outcome = self.eva_target(&name).and_then(|target| match target {
                EvaTarget::Skip(step) => {
                    step.print();
                    Ok(())
                }
                EvaTarget::Ready(plan) if dry_run => {
                    plan.step().print();
                    Ok(())
                }
                EvaTarget::Ready(plan) => self.apply_eva(&plan),
            });
            if let Err(e) = outcome {
                eprintln!("EVA failed for '{name}': {e}");
                failures.push(name);
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(Error::JailOperation(format!(
                "EVA failed for {} jail(s): {}",
                failures.len(),
                failures.join(", ")
            )))
        }
    }

    fn apply_eva(&self, plan: &EvaPlan<'_>) -> Result<()> {
        let EvaPlan {
            full_name,
            jid,
            diff,
            resources,
            cpu_list,
            ..
        } = plan;
        let hook_runner = HookRunner::new(plan.jail_def.hooks.clone()).verbose(self.verbose);
        let mut hook_context = HookContext::new(full_name, &plan.path).with_jid(*jid);
        if let Some(ip) = plan.static_ip {
            hook_context = hook_context.with_ip(ip.to_string());
        }

        hook_runner.execute_phase(HookPhase::PreEva, &hook_context)?;

        for line in &diff.immutable_diffs {
            eprintln!("Warning: '{full_name}': {line} -- requires restart, not applied");
        }

        if !diff.changes.is_empty() {
            jail_update(*jid, &diff.changes)?;
            for line in &diff.display {
                println!("  {full_name}: {line}");
            }
        }

        let rctl_stale = plan.rctl_current != Some(true);
        if rctl_stale {
            crate::rctl::remove_limits(full_name);
        }
        if rctl_stale
            && resources.has_rctl_rules()
            && let Err(e) = crate::rctl::apply_limits(full_name, resources)
        {
            eprintln!(
                "Warning: rctl limits partially applied for '{full_name}': {e} -- re-run eva or restart"
            );
        }

        if let Some(list) = cpu_list {
            match crate::rctl::apply_cpuset(*jid, list) {
                Ok(()) => println!("  {full_name}: pinned to CPUs {list}"),
                Err(e) => eprintln!(
                    "Warning: cpuset re-pin failed for '{full_name}': {e} -- re-run eva or restart"
                ),
            }
        }

        hook_runner.execute_phase(HookPhase::PostEva, &hook_context)?;

        if plan.is_noop() {
            println!("  [OK] {full_name} (no changes)");
        } else {
            println!(
                "  [OK] {full_name} ({} param(s) updated)",
                diff.changes.len()
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
