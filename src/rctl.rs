//! RCTL (Resource Control) for per-jail resource limits
//!
//! Wraps FreeBSD's rctl(4) syscalls to apply resource limits to jails.
//! Rule format: `jail:<name>:<resource>:<action>=<amount>`

// FFI module: rctl(2) syscalls.
#![allow(unsafe_code)]

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

// Syscall numbers from sys/syscall.h
const SYS_RCTL_ADD_RULE: libc::c_int = 528;
const SYS_RCTL_REMOVE_RULE: libc::c_int = 529;
const SYS_RCTL_GET_RACCT: libc::c_int = 525;
const SYS_RCTL_GET_RULES: libc::c_int = 526;

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
    pub const fn is_empty(&self) -> bool {
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
    pub const fn has_rctl_rules(&self) -> bool {
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
    pub(crate) fn to_rules(&self, jail_name: &str) -> Vec<String> {
        let mut rules = Vec::new();

        if let Some(ref mem) = self.memory {
            rules.push(format!("jail:{jail_name}:memoryuse:deny={mem}"));
        }
        if let Some(ref vmem) = self.vmemory {
            rules.push(format!("jail:{jail_name}:vmemoryuse:deny={vmem}"));
        }
        if let Some(ref cpu) = self.cpu {
            rules.push(format!("jail:{jail_name}:pcpu:deny={cpu}"));
        }
        if let Some(maxproc) = self.maxproc {
            rules.push(format!("jail:{jail_name}:maxproc:deny={maxproc}"));
        }
        if let Some(maxthreads) = self.maxthreads {
            rules.push(format!("jail:{jail_name}:nthr:deny={maxthreads}"));
        }
        if let Some(openfiles) = self.openfiles {
            rules.push(format!("jail:{jail_name}:openfiles:deny={openfiles}"));
        }
        if let Some(ref swap) = self.swap {
            rules.push(format!("jail:{jail_name}:swapuse:deny={swap}"));
        }

        let own_prefix = format!("jail:{jail_name}:");
        for rule in &self.rules {
            if rule.starts_with("jail:") {
                if !rule.starts_with(&own_prefix) {
                    eprintln!("Warning: rejecting RCTL rule '{rule}' -- targets a different jail");
                    continue;
                }
                rules.push(rule.clone());
            } else {
                // Prefix with jail subject if not already
                rules.push(format!("jail:{jail_name}:{rule}"));
            }
        }

        rules
    }
}

/// What moves a jail from its startup profile to its steady profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum QosTransition {
    /// First passing health check. Needs `blackship supervise`.
    #[default]
    Healthy,
    /// `max_startup_secs` elapsing.
    Timer,
    /// Only `blackship qos <jail> --steady`.
    Manual,
}

/// Two resource profiles and the rule that switches between them.
///
/// A jail needs headroom while it builds caches and forks workers, and a
/// tighter cap once it settles. One static profile has to be the looser of the
/// two, which leaves the steady state unprotected.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct QosConfig {
    /// Applied at start, in place of `resources`.
    pub startup: ResourceConfig,
    /// Applied on transition. Absent means the startup profile is permanent.
    #[serde(default)]
    pub steady: Option<ResourceConfig>,
    #[serde(default)]
    pub transition: QosTransition,
    /// Fallback deadline for the `healthy` transition, in seconds.
    #[serde(default)]
    pub max_startup_secs: Option<u64>,
}

impl QosConfig {
    pub fn profile(&self, phase: crate::scope::QosPhase) -> &ResourceConfig {
        match phase {
            crate::scope::QosPhase::Steady => self.steady.as_ref().unwrap_or(&self.startup),
            _ => &self.startup,
        }
    }
}

/// Resources a profile owns. Anything else in `rules` belongs to the user.
const MANAGED_RESOURCES: [&str; 7] = [
    "memoryuse",
    "vmemoryuse",
    "pcpu",
    "maxproc",
    "nthr",
    "openfiles",
    "swapuse",
];

/// The resources a profile owns, for callers outside this module.
#[cfg_attr(
    not(feature = "mcp"),
    expect(
        dead_code,
        reason = "the MCP host_facts tool is this accessor's only caller"
    )
)]
pub const fn managed_resources() -> &'static [&'static str] {
    &MANAGED_RESOURCES
}

/// Split a profile's rules into the managed `(resource, rule)` pairs and the
/// user's own rules, in one pass over `to_rules`.
fn split_rules(config: &ResourceConfig, jail_name: &str) -> (Vec<(String, String)>, Vec<String>) {
    let prefix = format!("jail:{jail_name}:");
    let mut managed = Vec::new();
    let mut custom = Vec::new();

    for rule in config.to_rules(jail_name) {
        let resource = rule
            .strip_prefix(&prefix)
            .and_then(|rest| rest.split(':').next())
            .filter(|resource| MANAGED_RESOURCES.contains(resource))
            .map(str::to_string);
        match resource {
            Some(resource) => managed.push((resource, rule)),
            None => custom.push(rule),
        }
    }

    (managed, custom)
}

/// Rules to remove and rules to add for a phase switch.
///
/// `remove_limits` uses the blanket `jail:<name>` filter, which would drop the
/// user's custom `rules` along with the profile's. A switch therefore removes
/// per-resource, and only for resources the profiles actually manage.
pub fn phase_diff(
    jail_name: &str,
    from: &ResourceConfig,
    to: &ResourceConfig,
) -> (Vec<String>, Vec<String>) {
    let (from_managed, from_custom) = split_rules(from, jail_name);
    let (to_managed, to_custom) = split_rules(to, jail_name);

    let mut removals = Vec::new();
    let mut additions = Vec::new();

    for (resource, rule) in &from_managed {
        match to_managed.iter().find(|(r, _)| r == resource) {
            Some((_, new_rule)) if new_rule == rule => {}
            _ => removals.push(format!("jail:{jail_name}:{resource}")),
        }
    }

    for (resource, rule) in &to_managed {
        match from_managed.iter().find(|(r, _)| r == resource) {
            Some((_, old_rule)) if old_rule == rule => {}
            _ => additions.push(rule.clone()),
        }
    }

    for rule in &from_custom {
        if !to_custom.contains(rule) {
            removals.push(rule.clone());
        }
    }
    for rule in &to_custom {
        if !from_custom.contains(rule) {
            additions.push(rule.clone());
        }
    }

    (removals, additions)
}

/// Switch a live jail from one profile to another.
pub fn apply_phase(jail_name: &str, from: &ResourceConfig, to: &ResourceConfig) -> Result<()> {
    let (removals, additions) = phase_diff(jail_name, from, to);
    if removals.is_empty() && additions.is_empty() {
        return Ok(());
    }

    if !is_enabled() {
        return Err(Error::Rctl(
            "RCTL not enabled. Set kern.racct.enable=1 in /boot/loader.conf and reboot.".into(),
        ));
    }

    for filter in &removals {
        if let Err(e) = rctl_remove_rule(filter) {
            eprintln!("Warning: {e}");
        }
    }
    for rule in &additions {
        rctl_add_rule(rule)?;
    }

    Ok(())
}

/// Resolve the CPU list a jail should be pinned to.
///
/// Explicit `cpuset` wins. `cores = N` picks the N logical CPUs with the
/// fewest explicit claims across the other jails' configs (least-loaded
/// spreading), so co-hosted jails end up on different cores by default.
pub fn resolve_cpu_list<'a>(
    config: &ResourceConfig,
    other_pins: impl Iterator<Item = &'a str>,
) -> Option<String> {
    if let Some(list) = &config.cpuset {
        return Some(list.clone());
    }
    let want = config.cores? as usize;
    // SAFETY: plain integer arg.
    let ncpu = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    let ncpu = usize::try_from(ncpu).ok().filter(|&n| n > 0).unwrap_or(1);

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
    cores.sort_unstable();
    let mut list = String::with_capacity(cores.len() * 3);
    for core in cores {
        if !list.is_empty() {
            list.push(',');
        }
        // Writing to a String cannot fail.
        let _ = write!(list, "{core}");
    }
    Some(list)
}

/// Pin a running jail to a CPU list via cpuset(1)
pub fn apply_cpuset(jid: i32, cpu_list: &str) -> Result<()> {
    let status = std::process::Command::new("/usr/bin/cpuset")
        .args(["-l", cpu_list, "-j", &jid.to_string()])
        .status()
        .map_err(|e| Error::Rctl(format!("Failed to run cpuset: {e}")))?;
    if !status.success() {
        return Err(Error::Rctl(format!("cpuset -l {cpu_list} -j {jid} failed")));
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
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim() == "1",
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

/// Whether the kernel holds exactly the rules `config` asks for, compared
/// after expanding size suffixes (`1g` is stored as `1073741824`). `None`
/// when the kernel's rules cannot be read (not root, no RACCT).
pub fn rules_current(jail_name: &str, config: &ResourceConfig) -> Option<bool> {
    let live = rctl_get_rules(&format!("jail:{jail_name}")).ok()?;
    let Ok(mut desired) = config
        .to_rules(jail_name)
        .iter()
        .map(|rule| expand_rule(rule).map(|r| canonical_rule(&r)))
        .collect::<Result<Vec<_>>>()
    else {
        return Some(false);
    };
    let mut live: Vec<String> = live.iter().map(|r| canonical_rule(r)).collect();
    desired.sort();
    live.sort();
    Some(desired == live)
}

/// `subject:id:resource:action=amount[/per]` with `per` spelled out: the
/// kernel reports the default (the subject type) explicitly.
fn canonical_rule(rule: &str) -> String {
    match rule.split_once('=') {
        Some((head, tail)) if !tail.contains('/') => {
            let subject = head.split(':').next().unwrap_or_default();
            format!("{head}={tail}/{subject}")
        }
        _ => rule.to_string(),
    }
}

/// Remove all resource limits for a jail
pub fn remove_limits(jail_name: &str) {
    // Remove all rules matching this jail
    let filter = format!("jail:{jail_name}");
    // ESRCH (no rules) and ENOSYS (no RACCT) are expected.
    let _ = rctl_remove_rule(&filter);
}

/// Get current resource usage for a jail
pub fn get_usage(jail_name: &str) -> Result<std::collections::HashMap<String, u64>> {
    let filter = format!("jail:{jail_name}");
    rctl_get_racct(&filter)
}

/// Invoke an RCTL syscall that takes a rule/filter string and no output buffer
fn rctl_string_syscall(
    syscall_num: libc::c_int,
    arg: &str,
    fail_msg: impl FnOnce(std::io::Error) -> String,
) -> Result<()> {
    // The kernel copyinstr()s the argument: the length must cover the NUL.
    let arg = std::ffi::CString::new(arg)?;
    let arg_bytes = arg.as_bytes_with_nul();

    // SAFETY: live input with its length; NULL output with length 0.
    let ret = unsafe {
        libc::syscall(
            syscall_num,
            arg_bytes.as_ptr().cast::<libc::c_void>(),
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
    let expanded = expand_rule(rule)?;
    rctl_string_syscall(SYS_RCTL_ADD_RULE, &expanded, |e| {
        format!("Failed to add rule '{rule}': {e}")
    })
}

/// Expand the amount's size suffix as rctl(8) does; the kernel only takes integers.
fn expand_rule(rule: &str) -> Result<String> {
    let Some((head, tail)) = rule.split_once('=') else {
        return Ok(rule.to_string());
    };
    let (amount, per) = tail
        .split_once('/')
        .map_or((tail, None), |(a, p)| (a, Some(p)));
    let num = expand_number(amount).ok_or_else(|| {
        Error::Rctl(format!(
            "malformed rule '{rule}': invalid amount '{amount}'"
        ))
    })?;
    Ok(per.map_or_else(|| format!("{head}={num}"), |p| format!("{head}={num}/{p}")))
}

/// `expand_number(3)`: an integer with an optional k/m/g/t/p/e suffix (powers of 1024).
fn expand_number(s: &str) -> Option<u64> {
    let s = s.trim();
    let s = s
        .strip_suffix(['b', 'B'])
        .filter(|r| r.ends_with(|c: char| c.is_ascii_alphabetic()))
        .unwrap_or(s);
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (digits, suffix) = s.split_at(split);
    let base: u64 = digits.parse().ok()?;
    let shift = match suffix.to_ascii_lowercase().as_str() {
        "" => 0,
        "k" => 10,
        "m" => 20,
        "g" => 30,
        "t" => 40,
        "p" => 50,
        "e" => 60,
        _ => return None,
    };
    base.checked_mul(1u64.checked_shl(shift)?)
}

/// Remove RCTL rules matching a filter
fn rctl_remove_rule(filter: &str) -> Result<()> {
    rctl_string_syscall(SYS_RCTL_REMOVE_RULE, filter, |e| {
        format!("Failed to remove rules for '{filter}': {e}")
    })
}

/// The rules the kernel holds for a filter, comma-separated in its reply.
fn rctl_get_rules(filter: &str) -> Result<Vec<String>> {
    let filter_c = std::ffi::CString::new(filter)?;
    let filter_bytes = filter_c.as_bytes_with_nul();
    let mut outbuf = vec![0u8; 4096];

    loop {
        // SAFETY: live buffers, each passed with its own length.
        let ret = unsafe {
            libc::syscall(
                SYS_RCTL_GET_RULES,
                filter_bytes.as_ptr().cast::<libc::c_void>(),
                filter_bytes.len(),
                outbuf.as_mut_ptr().cast::<libc::c_void>(),
                outbuf.len(),
            )
        };
        if ret == 0 {
            break;
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ERANGE) && outbuf.len() < 1 << 20 {
            outbuf.resize(outbuf.len() * 4, 0);
            continue;
        }
        return Err(Error::Rctl(format!(
            "Failed to get rules for '{filter}': {err}"
        )));
    }

    let end = outbuf.iter().position(|&b| b == 0).unwrap_or(outbuf.len());
    Ok(String::from_utf8_lossy(&outbuf[..end])
        .split(',')
        .filter(|rule| !rule.is_empty())
        .map(str::to_string)
        .collect())
}

/// Get resource accounting data for a subject
fn rctl_get_racct(filter: &str) -> Result<std::collections::HashMap<String, u64>> {
    let filter_c = std::ffi::CString::new(filter)?;
    let filter_bytes = filter_c.as_bytes_with_nul();
    let mut outbuf = [0u8; 4096];

    // SAFETY: live buffers, each passed with its own length.
    let ret = unsafe {
        libc::syscall(
            SYS_RCTL_GET_RACCT,
            filter_bytes.as_ptr().cast::<libc::c_void>(),
            filter_bytes.len(),
            outbuf.as_mut_ptr().cast::<libc::c_void>(),
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
mod tests;
