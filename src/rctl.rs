//! RCTL (Resource Control) for per-jail resource limits
//!
//! Wraps FreeBSD's rctl(4) syscalls to apply resource limits to jails.
//! Rule format: "jail:<name>:<resource>:<action>=<amount>"

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

// Syscall numbers from sys/syscall.h
const SYS_RCTL_ADD_RULE: libc::c_int = 528;
const SYS_RCTL_REMOVE_RULE: libc::c_int = 529;
const SYS_RCTL_GET_RACCT: libc::c_int = 525;

/// Resource limit configuration for a jail
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ResourceConfig {
    /// Memory limit (e.g., "1g", "512m")
    pub memory: Option<String>,
    /// Virtual memory limit
    pub vmemory: Option<String>,
    /// CPU percentage limit (e.g., "100" = one core)
    pub cpu: Option<String>,
    /// Maximum processes
    pub maxproc: Option<u32>,
    /// Maximum threads
    pub maxthreads: Option<u32>,
    /// Maximum open files
    pub openfiles: Option<u32>,
    /// Maximum swap usage
    pub swap: Option<String>,
    /// Pin the jail to this many cores, chosen least-loaded across the
    /// other jails' pins
    pub cores: Option<u16>,
    /// Pin the jail to an explicit CPU list (e.g., "0,1,2"); wins over cores
    pub cpuset: Option<String>,
    /// Custom RCTL rules (advanced, raw format)
    #[serde(default)]
    pub rules: Vec<String>,
}

impl ResourceConfig {
    pub fn is_empty(&self) -> bool {
        self.memory.is_none()
            && self.vmemory.is_none()
            && self.cpu.is_none()
            && self.maxproc.is_none()
            && self.maxthreads.is_none()
            && self.openfiles.is_none()
            && self.swap.is_none()
            && self.cores.is_none()
            && self.cpuset.is_none()
            && self.rules.is_empty()
    }

    /// True when only cpuset pinning is configured (no rctl rules needed)
    pub fn has_rctl_rules(&self) -> bool {
        self.memory.is_some()
            || self.vmemory.is_some()
            || self.cpu.is_some()
            || self.maxproc.is_some()
            || self.maxthreads.is_some()
            || self.openfiles.is_some()
            || self.swap.is_some()
            || !self.rules.is_empty()
    }

    /// Convert to a list of RCTL rule strings for a given jail name
    fn to_rules(&self, jail_name: &str) -> Vec<String> {
        let mut rules = Vec::new();

        if let Some(ref mem) = self.memory {
            rules.push(format!("jail:{}:memoryuse:deny={}", jail_name, mem));
        }
        if let Some(ref vmem) = self.vmemory {
            rules.push(format!("jail:{}:vmemoryuse:deny={}", jail_name, vmem));
        }
        if let Some(ref cpu) = self.cpu {
            rules.push(format!("jail:{}:pcpu:deny={}", jail_name, cpu));
        }
        if let Some(maxproc) = self.maxproc {
            rules.push(format!("jail:{}:maxproc:deny={}", jail_name, maxproc));
        }
        if let Some(maxthreads) = self.maxthreads {
            rules.push(format!("jail:{}:nthr:deny={}", jail_name, maxthreads));
        }
        if let Some(openfiles) = self.openfiles {
            rules.push(format!("jail:{}:openfiles:deny={}", jail_name, openfiles));
        }
        if let Some(ref swap) = self.swap {
            rules.push(format!("jail:{}:swapuse:deny={}", jail_name, swap));
        }

        let own_prefix = format!("jail:{}:", jail_name);
        for rule in &self.rules {
            if rule.starts_with("jail:") {
                if !rule.starts_with(&own_prefix) {
                    eprintln!(
                        "Warning: rejecting RCTL rule '{}' -- targets a different jail",
                        rule
                    );
                    continue;
                }
                rules.push(rule.clone());
            } else {
                // Prefix with jail subject if not already
                rules.push(format!("jail:{}:{}", jail_name, rule));
            }
        }

        rules
    }
}

/// Resolve the CPU list a jail should be pinned to.
///
/// Explicit `cpuset` wins. `cores = N` picks the N logical CPUs with the
/// fewest explicit claims across the other jails' configs (least-loaded
/// spreading), so co-hosted jails end up on different cores by default.
pub fn resolve_cpu_list(
    config: &ResourceConfig,
    other_pins: impl Iterator<Item = String>,
) -> Option<String> {
    if let Some(list) = &config.cpuset {
        return Some(list.clone());
    }
    let want = config.cores? as usize;
    let ncpu = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    let ncpu = if ncpu > 0 { ncpu as usize } else { 1 };

    let mut load = vec![0usize; ncpu];
    for pin in other_pins {
        for part in pin.split(',') {
            if let Ok(core) = part.trim().parse::<usize>()
                && core < ncpu
            {
                load[core] += 1;
            }
        }
    }

    let mut cores: Vec<usize> = (0..ncpu).collect();
    cores.sort_by_key(|&c| (load[c], c));
    cores.truncate(want.min(ncpu));
    cores.sort();
    Some(
        cores
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(","),
    )
}

/// Pin a running jail to a CPU list via cpuset(1)
pub fn apply_cpuset(jid: i32, cpu_list: &str) -> Result<()> {
    let status = std::process::Command::new("/usr/bin/cpuset")
        .args(["-l", cpu_list, "-j", &jid.to_string()])
        .status()
        .map_err(|e| Error::Rctl(format!("Failed to run cpuset: {}", e)))?;
    if !status.success() {
        return Err(Error::Rctl(format!(
            "cpuset -l {} -j {} failed",
            cpu_list, jid
        )));
    }
    Ok(())
}

/// Check if RCTL is enabled in the kernel
pub fn is_enabled() -> bool {
    // Check kern.racct.enable sysctl
    let output = std::process::Command::new("/sbin/sysctl")
        .args(["-n", "kern.racct.enable"])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let val = String::from_utf8_lossy(&out.stdout).trim().to_string();
            val == "1"
        }
        _ => false,
    }
}

/// Apply resource limits to a jail
pub fn apply_limits(jail_name: &str, config: &ResourceConfig) -> Result<()> {
    if !config.has_rctl_rules() {
        // Pure cpuset pinning needs no rctl (and no RACCT).
        return Ok(());
    }

    if !is_enabled() {
        return Err(Error::Rctl(
            "RCTL not enabled. Set kern.racct.enable=1 in /boot/loader.conf and reboot.".into(),
        ));
    }

    let rules = config.to_rules(jail_name);

    for rule in &rules {
        rctl_add_rule(rule)?;
    }

    if !rules.is_empty() {
        println!("  Applied {} resource limit(s)", rules.len());
    }

    Ok(())
}

/// Remove all resource limits for a jail
pub fn remove_limits(jail_name: &str) {
    // Remove all rules matching this jail
    let filter = format!("jail:{}", jail_name);
    let _ = rctl_remove_rule(&filter);
}

/// Get current resource usage for a jail
#[allow(dead_code)]
pub fn get_usage(jail_name: &str) -> Result<std::collections::HashMap<String, u64>> {
    let filter = format!("jail:{}", jail_name);
    rctl_get_racct(&filter)
}

/// Invoke an RCTL syscall that takes a rule/filter string and no output buffer
fn rctl_string_syscall(
    syscall_num: libc::c_int,
    arg: &str,
    fail_msg: impl FnOnce(std::io::Error) -> String,
) -> Result<()> {
    let arg_bytes = arg.as_bytes();

    let ret = unsafe {
        libc::syscall(
            syscall_num,
            arg_bytes.as_ptr() as *const libc::c_void,
            arg_bytes.len(),
            std::ptr::null_mut::<libc::c_void>(),
            0usize,
        )
    };

    if ret != 0 {
        return Err(Error::Rctl(fail_msg(std::io::Error::last_os_error())));
    }

    Ok(())
}

/// Add an RCTL rule via syscall
fn rctl_add_rule(rule: &str) -> Result<()> {
    rctl_string_syscall(SYS_RCTL_ADD_RULE, rule, |e| {
        format!("Failed to add rule '{}': {}", rule, e)
    })
}

/// Remove RCTL rules matching a filter
fn rctl_remove_rule(filter: &str) -> Result<()> {
    rctl_string_syscall(SYS_RCTL_REMOVE_RULE, filter, |e| {
        format!("Failed to remove rules for '{}': {}", filter, e)
    })
}

/// Get resource accounting data for a subject
fn rctl_get_racct(filter: &str) -> Result<std::collections::HashMap<String, u64>> {
    let filter_bytes = filter.as_bytes();
    let mut outbuf = vec![0u8; 4096];

    let ret = unsafe {
        libc::syscall(
            SYS_RCTL_GET_RACCT,
            filter_bytes.as_ptr() as *const libc::c_void,
            filter_bytes.len(),
            outbuf.as_mut_ptr() as *mut libc::c_void,
            outbuf.len(),
        )
    };

    if ret != 0 {
        return Err(Error::Rctl(format!(
            "Failed to get resource usage for '{}': {}",
            filter,
            std::io::Error::last_os_error()
        )));
    }

    // Parse output: "resource=value,resource=value,..."
    let output = String::from_utf8_lossy(&outbuf);
    let output = output.trim_end_matches('\0');

    let mut usage = std::collections::HashMap::new();
    for pair in output.split(',') {
        if let Some((key, val)) = pair.split_once('=')
            && let Ok(v) = val.parse::<u64>()
        {
            usage.insert(key.to_string(), v);
        }
    }

    Ok(usage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_config_empty() {
        let config = ResourceConfig::default();
        assert!(config.is_empty());
    }

    #[test]
    fn test_resource_config_to_rules() {
        let config = ResourceConfig {
            memory: Some("1g".into()),
            maxproc: Some(100),
            openfiles: Some(1024),
            ..Default::default()
        };

        let rules = config.to_rules("myjail");
        assert_eq!(rules.len(), 3);
        assert!(rules.contains(&"jail:myjail:memoryuse:deny=1g".to_string()));
        assert!(rules.contains(&"jail:myjail:maxproc:deny=100".to_string()));
        assert!(rules.contains(&"jail:myjail:openfiles:deny=1024".to_string()));
    }

    #[test]
    fn test_resource_config_custom_rules() {
        let config = ResourceConfig {
            rules: vec!["cputime:log=3600".into()],
            ..Default::default()
        };

        let rules = config.to_rules("test");
        assert_eq!(rules, vec!["jail:test:cputime:log=3600"]);
    }
}
