//! EVA: hot update of running jails via jail_set(JAIL_UPDATE), no restart.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::error::{Error, Result};
use crate::hooks::{HookContext, HookPhase, HookRunner};
use crate::jail::{ParamValue, jail_getid, jail_update};

use super::Bridge;
use super::lifecycle::build_jail_params;

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
    use crate::sys::consts::*;
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
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(","),
        ParamValue::Ipv6(addrs) => addrs
            .iter()
            .map(|a| a.to_string())
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
            Some(live_value) => (
                !param_value_matches(value, live_value),
                live_value.clone(),
            ),
            None if unreadable.contains(key) => (true, "(unverified)".to_string()),
            None => (true, "(unset)".to_string()),
        };

        if !differs {
            continue;
        }

        let line = format!("{}: {} -> {}", key, live_str, param_display(value));
        match class {
            ParamClass::Immutable => diff.immutable_diffs.push(line),
            ParamClass::Updatable => {
                diff.display.push(line);
                diff.changes.insert(key.clone(), value.clone());
            }
            ParamClass::Selector => unreachable!(),
        }
    }

    diff
}

/// jls fails the whole invocation on any key it does not know, so fall
/// back to per-key reads and report the losers as unreadable.
fn read_live_params(
    full_name: &str,
    keys: &[&str],
) -> (HashMap<String, String>, Vec<String>) {
    match jls_json(full_name, keys) {
        Ok(map) => (map, Vec::new()),
        Err(_) => {
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
}

fn jls_json(full_name: &str, keys: &[&str]) -> Result<HashMap<String, String>> {
    let mut args = vec!["--libxo", "json", "-j", full_name];
    args.extend_from_slice(keys);
    let json = crate::commands::stats::run_json("/usr/sbin/jls", &args)?;

    let entry = json
        .get("jail-information")
        .and_then(|i| i.get("jail"))
        .and_then(|j| j.as_array())
        .and_then(|a| a.first())
        .ok_or_else(|| Error::JailOperation(format!("jls returned no data for '{}'", full_name)))?;

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

impl Bridge {
    /// Hot-update running jails to match the manifest (EVA).
    pub fn eva(&mut self, jail: Option<&str>) -> Result<()> {
        self.eva_inner(jail, false)
    }

    /// Dry run: show what `eva` would change without applying anything.
    pub fn eva_dry_run(&mut self, jail: Option<&str>) -> Result<()> {
        println!("=== DRY RUN - No changes will be made ===\n");
        self.eva_inner(jail, true)
    }

    fn eva_inner(&mut self, jail: Option<&str>, dry_run: bool) -> Result<()> {
        let targets = self.jails_for_up(jail)?;
        let mut failures: Vec<(String, Error)> = Vec::new();

        for name in &targets {
            match self.eva_jail(name, dry_run) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("EVA failed for '{}': {}", name, e);
                    failures.push((name.clone(), e));
                }
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(Error::JailOperation(format!(
                "EVA failed for {} jail(s): {}",
                failures.len(),
                failures
                    .iter()
                    .map(|(n, _)| n.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )))
        }
    }

    fn eva_jail(&mut self, name: &str, dry_run: bool) -> Result<()> {
        let (service_name, full_name) = self.resolve_jail_names(name)?;
        let Some(jail_def) = self.config.get_jail(&service_name) else {
            return Ok(());
        };

        let jid = match jail_getid(&full_name) {
            Ok(jid) => jid,
            Err(_) => {
                println!("  [SKIP] {} (not running)", full_name);
                return Ok(());
            }
        };

        let is_vnet = jail_def.network.as_ref().is_some_and(|n| n.vnet);
        let static_ip: Option<IpAddr> = jail_def.network.as_ref().and_then(|n| n.ip);

        let path = jail_def.effective_path(&self.config.config, &full_name);
        let mut desired = build_jail_params(jail_def, &full_name, is_vnet, static_ip)?;
        desired.insert(
            crate::sys::consts::JAIL_PARAM_PATH.to_string(),
            ParamValue::String(path.display().to_string()),
        );

        let keys: Vec<&str> = desired.keys().map(String::as_str).collect();
        let (live, unreadable) = read_live_params(&full_name, &keys);
        let diff = diff_params(&desired, &live, &unreadable);

        let resources = &jail_def.resources;
        let rctl_rules = resources.to_rules(&full_name);
        let other_pins: Vec<String> = self
            .config
            .jails
            .iter()
            .filter(|other| other.name != service_name)
            .filter_map(|other| other.resources.cpuset.clone())
            .collect();
        let cpu_list = crate::rctl::resolve_cpu_list(resources, other_pins.into_iter());

        if dry_run {
            println!("  [EVA] {} (JID {})", full_name, jid);
            for line in &diff.display {
                println!("          {}", line);
            }
            for line in &diff.immutable_diffs {
                println!("        ! {} (requires restart)", line);
            }
            for key in &unreadable {
                println!("          {}: not reported by jls, would apply blind", key);
            }
            if resources.has_rctl_rules() {
                println!("          rctl: replace with {} rule(s):", rctl_rules.len());
                for rule in &rctl_rules {
                    println!("            {}", rule);
                }
            }
            if let Some(ref list) = cpu_list {
                println!("          cpuset: pin to CPUs {}", list);
            }
            if diff.changes.is_empty() && !resources.has_rctl_rules() && cpu_list.is_none() {
                println!("          (no changes)");
            }
            println!();
            return Ok(());
        }

        let hook_runner = HookRunner::new(jail_def.hooks.clone()).verbose(self.verbose);
        let mut hook_context = HookContext::new(&full_name, &path).with_jid(jid);
        if let Some(ip) = static_ip {
            hook_context = hook_context.with_ip(ip.to_string());
        }

        hook_runner.execute_phase(HookPhase::PreEva, &hook_context)?;

        for line in &diff.immutable_diffs {
            eprintln!(
                "Warning: '{}': {} -- requires restart, not applied",
                full_name, line
            );
        }

        if !diff.changes.is_empty() {
            jail_update(jid, &diff.changes)?;
            for line in &diff.display {
                println!("  {}: {}", full_name, line);
            }
        }

        crate::rctl::remove_limits(&full_name);
        if resources.has_rctl_rules()
            && let Err(e) = crate::rctl::apply_limits(&full_name, resources)
        {
            eprintln!(
                "Warning: rctl limits partially applied for '{}': {} -- re-run eva or restart",
                full_name, e
            );
        }

        if let Some(ref list) = cpu_list {
            match crate::rctl::apply_cpuset(jid, list) {
                Ok(()) => println!("  {}: pinned to CPUs {}", full_name, list),
                Err(e) => eprintln!(
                    "Warning: cpuset re-pin failed for '{}': {} -- re-run eva or restart",
                    full_name, e
                ),
            }
        }

        hook_runner.execute_phase(HookPhase::PostEva, &hook_context)?;

        if diff.changes.is_empty() && !resources.has_rctl_rules() && cpu_list.is_none() {
            println!("  [OK] {} (no changes)", full_name);
        } else {
            println!(
                "  [OK] {} ({} param(s) updated)",
                full_name,
                diff.changes.len()
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_param_value_matches_int() {
        assert!(param_value_matches(&ParamValue::Int(5), "5"));
        assert!(param_value_matches(&ParamValue::Int(5), " 5 "));
        assert!(!param_value_matches(&ParamValue::Int(5), "6"));
        assert!(!param_value_matches(&ParamValue::Int(5), "new"));
    }

    #[test]
    fn test_param_value_matches_bool() {
        assert!(param_value_matches(&ParamValue::Bool(true), "true"));
        assert!(param_value_matches(&ParamValue::Bool(true), "1"));
        assert!(param_value_matches(&ParamValue::Bool(false), "false"));
        assert!(param_value_matches(&ParamValue::Bool(false), "0"));
        assert!(!param_value_matches(&ParamValue::Bool(true), "false"));
        assert!(!param_value_matches(&ParamValue::Bool(true), "yes"));
    }

    #[test]
    fn test_param_value_matches_ipv4() {
        let v = ParamValue::Ipv4(vec![Ipv4Addr::new(10, 0, 0, 5)]);
        assert!(param_value_matches(&v, "10.0.0.5"));
        assert!(!param_value_matches(&v, "10.0.0.6"));
        assert!(!param_value_matches(&v, "10.0.0.5,10.0.0.6"));
    }

    #[test]
    fn test_diff_params_change_and_skip() {
        let mut desired = HashMap::new();
        desired.insert("name".to_string(), ParamValue::String("web".into()));
        desired.insert(
            "host.hostname".to_string(),
            ParamValue::String("new.example".into()),
        );
        desired.insert("children.max".to_string(), ParamValue::Int(4));

        let mut live = HashMap::new();
        live.insert("host.hostname".to_string(), "old.example".to_string());
        live.insert("children.max".to_string(), "4".to_string());

        let diff = diff_params(&desired, &live, &[]);
        assert_eq!(diff.changes.len(), 1);
        assert!(diff.changes.contains_key("host.hostname"));
        assert_eq!(diff.display, vec!["host.hostname: old.example -> new.example"]);
        assert!(diff.immutable_diffs.is_empty());
    }

    #[test]
    fn test_diff_params_immutable_drift() {
        let mut desired = HashMap::new();
        desired.insert("vnet".to_string(), ParamValue::Int(1));

        let mut live = HashMap::new();
        live.insert("vnet".to_string(), "0".to_string());

        let diff = diff_params(&desired, &live, &[]);
        assert!(diff.changes.is_empty());
        assert_eq!(diff.immutable_diffs, vec!["vnet: 0 -> 1"]);
    }

    #[test]
    fn test_diff_params_unreadable_applied_blind() {
        let mut desired = HashMap::new();
        desired.insert("sysvmsg".to_string(), ParamValue::Int(1));

        let diff = diff_params(&desired, &HashMap::new(), &["sysvmsg".to_string()]);
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.display, vec!["sysvmsg: (unverified) -> 1"]);
    }

    #[test]
    fn test_diff_params_idempotent() {
        let mut desired = HashMap::new();
        desired.insert(
            "host.hostname".to_string(),
            ParamValue::String("same".into()),
        );
        let mut live = HashMap::new();
        live.insert("host.hostname".to_string(), "same".to_string());

        let diff = diff_params(&desired, &live, &[]);
        assert!(diff.changes.is_empty());
        assert!(diff.display.is_empty());
        assert!(diff.immutable_diffs.is_empty());
    }
}
