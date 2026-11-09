//! Everything a model needs to know about this host before it plans jails:
//! what the kernel and blackship can do, how much memory, CPU and disk there
//! is and how much existing jails already claim, which networks and
//! addresses exist, and what is already running. Served as the
//! `blackship:///host` resource.
//!
//! Every section is best effort and unprivileged: a probe that fails reports
//! an error object in place, never fails the whole profile.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::Path;

use ipnet::IpNet;
use serde_json::{Value, json};

use crate::manifest::BlackshipConfig;

/// The full host profile, as JSON.
pub(super) fn collect(config_path: &Path) -> Value {
    let config = crate::manifest::load_or_default(config_path);
    let config_error = config.as_ref().err().map(ToString::to_string);
    let config = config.ok();
    let global = config.as_ref().map(|config| &config.config);

    json!({
        "config": {
            "path": config_path.display().to_string(),
            "source": if config_path.exists() { "file" } else { "defaults" },
            "error": config_error,
        },
        "system": system_facts(),
        "kernel": kernel_facts(),
        "cpu": cpu_facts(config.as_ref()),
        "memory": memory_facts(config.as_ref()),
        "rctl": rctl_facts(),
        "network": network_facts(config.as_ref()),
        "releases": release_facts(global),
        "zfs": zfs_facts(global),
        "jails": jail_facts(config.as_ref()),
        "facilities": facility_facts(),
    })
}

fn system_facts() -> Value {
    json!({
        "hostname": crate::sys::sysctl_string("kern.hostname"),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "blackship_version": env!("CARGO_PKG_VERSION"),
    })
}

/// CPUs, and how much of them manifest jails already claim through `cpu`
/// (rctl pcpu, 100 = one core) and pinning.
fn cpu_facts(config: Option<&BlackshipConfig>) -> Value {
    let jails = config.map_or(&[][..], |c| c.jails.as_slice());
    let pcpu_claimed: u64 = jails
        .iter()
        .filter_map(|j| j.resources.cpu.as_deref()?.trim().parse::<u64>().ok())
        .sum();
    json!({
        "online": online_cpus(),
        "model": crate::sys::sysctl_string("hw.model"),
        "manifest_pcpu_limits_total": pcpu_claimed,
        "note": "pcpu: 100 = one core",
    })
}

/// Physical memory, what is free right now, and what manifest jails claim.
fn memory_facts(config: Option<&BlackshipConfig>) -> Value {
    let page = crate::sys::sysctl_u64("hw.pagesize").unwrap_or(4096);
    let pages = |name| crate::sys::sysctl_u64(name).map(|n| n * page);
    let jails = config.map_or(&[][..], |c| c.jails.as_slice());
    let limits: Vec<u64> = jails
        .iter()
        .filter_map(|j| crate::rctl::expand_number(j.resources.memory.as_deref()?))
        .collect();
    let unlimited = jails.len() - limits.len();
    let physical = crate::sys::sysctl_u64("hw.physmem");
    let committed: u64 = limits.iter().sum();

    json!({
        "physical_bytes": physical,
        "free_bytes": pages("vm.stats.vm.v_free_count"),
        "inactive_bytes": pages("vm.stats.vm.v_inactive_count"),
        "laundry_bytes": pages("vm.stats.vm.v_laundry_count"),
        "zfs_arc_bytes": crate::sys::sysctl_u64("kstat.zfs.misc.arcstats.size"),
        "swap_total_bytes": crate::sys::sysctl_u64("vm.swap_total"),
        "manifest_memory_limits_total_bytes": committed,
        "manifest_jails_without_memory_limit": unlimited,
        "uncommitted_bytes": physical.map(|p| p.saturating_sub(committed)),
        "note": "reclaimable ≈ free + inactive + laundry + most of ARC; limits are \
                 caps, not reservations",
    })
}

/// Blackship networks with their address usage, PF state, and the egress
/// interface a NAT rule would use.
fn network_facts(config: Option<&BlackshipConfig>) -> Value {
    let egress = command_lines("/sbin/route", &["-n", "get", "default"])
        .ok()
        .and_then(|lines| {
            lines.iter().find_map(|l| {
                l.trim()
                    .strip_prefix("interface:")
                    .map(|i| i.trim().to_string())
            })
        });

    let networks = match crate::network::NetworkStore::from_config(config).list() {
        Ok(records) => {
            let leases = crate::network::NetworkLeaseStore::from_config(config);
            json!(
                records
                    .iter()
                    .map(|record| network_usage(record, &leases, config))
                    .collect::<Vec<_>>()
            )
        }
        Err(e) => json!({ "error": e.to_string() }),
    };

    json!({
        "default_route_interface": egress,
        "pf_enabled": pf_state(),
        "networks": networks,
        "note": "no NAT installed: egress needs `nat on <default_route_interface>` per subnet",
    })
}

fn network_usage(
    record: &crate::network::NetworkRecord,
    leases: &crate::network::NetworkLeaseStore,
    config: Option<&BlackshipConfig>,
) -> Value {
    let subnet: Option<IpNet> = record.subnet.parse().ok();
    let mut used: BTreeSet<IpAddr> = leases
        .list(&record.name)
        .unwrap_or_default()
        .iter()
        .filter_map(|lease| lease.ip.parse().ok())
        .collect();
    // Static addresses in the manifest hold their place whether or not the
    // jail is running.
    if let (Some(subnet), Some(config)) = (subnet, config) {
        used.extend(
            config
                .jails
                .iter()
                .filter_map(|j| j.network.as_ref()?.static_ip())
                .filter(|ip| subnet.contains(ip)),
        );
    }
    if let Ok(gateway) = record.gateway.parse::<IpAddr>() {
        used.remove(&gateway);
    }
    let usable = subnet.and_then(usable_hosts);

    json!({
        "name": record.name,
        "subnet": record.subnet,
        "gateway": record.gateway,
        "bridge": record.bridge,
        "backend": record.backend,
        "addresses_in_use": used.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "addresses_free": usable.map(|n| n.saturating_sub(used.len() as u64)),
    })
}

/// Assignable IPv4 hosts in a subnet, minus the gateway. IPv6 subnets are
/// effectively unbounded and report `None`.
fn usable_hosts(subnet: IpNet) -> Option<u64> {
    match subnet {
        IpNet::V4(net) => {
            let bits = 32 - u32::from(net.prefix_len());
            let total = 1u64 << bits;
            Some(total.saturating_sub(3)) // network, broadcast, gateway
        }
        IpNet::V6(_) => None,
    }
}

/// Jails the manifest defines, and running jails it does not.
fn jail_facts(config: Option<&BlackshipConfig>) -> Value {
    let mut managed = BTreeSet::new();
    let manifest: Vec<Value> = config.map_or_else(Vec::new, |config| {
        config
            .jails
            .iter()
            .map(|jail| {
                let full_name = config.jail_name(&jail.name);
                let entry = json!({
                    "name": jail.name,
                    "full_name": full_name,
                    "release": jail.release,
                    "running": crate::jail::jail_getid(&full_name).is_ok(),
                    "ip": jail.network.as_ref().and_then(crate::manifest::JailNetworkConfig::static_ip).map(|ip| ip.to_string()),
                    "networks": jail.network.as_ref().map(|n| n.networks.clone()),
                    "depends_on": jail.depends_on,
                    "memory_limit": jail.resources.memory,
                    "cpu_limit": jail.resources.cpu,
                });
                managed.insert(full_name);
                entry
            })
            .collect()
    });

    json!({
        "project": config.map(|c| c.config.project_name().to_string()),
        "manifest": manifest,
        "unmanaged_running": unmanaged_jails(&managed),
    })
}

/// Host tools blackship drives, and whether each is installed.
fn facility_facts() -> Value {
    match crate::commands::capabilities::data() {
        Ok(report) => json!(report.facilities),
        Err(e) => json!({ "error": e.to_string() }),
    }
}

/// ZFS: pool capacity, and blackship's base dataset when configured.
fn zfs_facts(config: Option<&crate::manifest::GlobalConfig>) -> Value {
    let pools = match command_lines(
        "/sbin/zpool",
        &["list", "-Hp", "-o", "name,size,alloc,free,health"],
    ) {
        Ok(lines) => json!(
            lines
                .iter()
                .filter_map(|line| {
                    let f: Vec<&str> = line.split('\t').collect();
                    let num = |i: usize| f.get(i)?.parse::<u64>().ok();
                    Some(json!({
                        "name": f.first()?,
                        "size_bytes": num(1),
                        "allocated_bytes": num(2),
                        "free_bytes": num(3),
                        "health": f.get(4),
                    }))
                })
                .collect::<Vec<_>>()
        ),
        Err(e) => json!({ "error": e }),
    };

    let Some(config) = config else {
        return json!({ "pools": pools, "enabled": Value::Null });
    };
    let base = config
        .zpool
        .as_deref()
        .filter(|_| config.zfs_enabled)
        .map(|pool| format!("{pool}/{}", config.dataset));
    let available = base.as_deref().and_then(|dataset| {
        command_lines(
            "/sbin/zfs",
            &["get", "-Hp", "-o", "value", "available", dataset],
        )
        .ok()?
        .first()?
        .parse::<u64>()
        .ok()
    });

    json!({
        "pools": pools,
        "enabled": config.zfs_enabled,
        "zpool": config.zpool,
        "base_dataset": base,
        "base_dataset_exists": available.is_some(),
        "base_dataset_available_bytes": available,
        "jails_dir": config.jails_dir().display().to_string(),
        "note": match (config.zfs_enabled, config.zpool.is_some()) {
            (true, true) => "jail roots are clones of the release: near-zero cost until written",
            (true, false) => "zfs_enabled without zpool: misconfigured",
            (false, _) => "ZFS off: each jail root is a full copy of its release",
        },
    })
}

/// RACCT/RCTL: whether manifest limits can be enforced.
fn rctl_facts() -> Value {
    let enabled = crate::rctl::is_enabled();
    let mut facts = json!({
        "enabled": enabled,
        "managed_resources": crate::rctl::managed_resources(),
    });
    if !enabled {
        facts["note"] =
            json!("kern.racct.enable=0: limits unenforceable (loader.conf + reboot); cpuset works");
    }
    facts
}

/// PF state: `null` when it cannot be read (pfctl needs root), never a guess.
fn pf_state() -> Value {
    match command_lines("/sbin/pfctl", &["-s", "info"]) {
        Ok(lines) => json!(lines.iter().any(|l| l.contains("Status: Enabled"))),
        Err(_) => Value::Null,
    }
}

/// Running jails the manifest does not define, including ones blackship
/// did not create.
fn unmanaged_jails(managed: &BTreeSet<String>) -> Vec<Value> {
    crate::jail::RunningJails::new()
        .filter_map(|jid| {
            let name = crate::jail::jail_getname(jid).ok();
            if name.as_ref().is_some_and(|n| managed.contains(n)) {
                return None;
            }
            Some(json!({ "jid": jid, "name": name }))
        })
        .collect()
}

/// A command's stdout lines, or its failure as text.
fn command_lines(program: &str, args: &[&str]) -> std::result::Result<Vec<String>, String> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("cannot run {program}: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "{program} exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_string)
        .collect())
}

/// Bootstrapped releases under the configured (or default) releases dir.
fn release_facts(config: Option<&crate::manifest::GlobalConfig>) -> Value {
    let Some(config) = config else {
        return json!({ "status": "error", "error": "configuration is unavailable" });
    };

    let provisioner = match crate::provision::Provisioner::from_config(config) {
        Ok(provisioner) => provisioner,
        Err(e) => return json!({ "status": "error", "error": e.to_string() }),
    };

    let dir = config.releases_dir.display().to_string();
    if !config.releases_dir.exists() {
        return json!({
            "status": "absent",
            "releases_dir": dir,
            "note": "releases directory does not exist; nothing is bootstrapped yet",
        });
    }

    match provisioner.list_releases() {
        Ok(releases) => json!({
            "status": "present",
            "releases_dir": dir,
            "bootstrapped": releases
                .iter()
                .map(|release| json!({
                    "name": release.name,
                    "path": release.path.display().to_string(),
                    "arch": release.arch.freebsd_name(),
                }))
                .collect::<Vec<_>>(),
        }),
        Err(e) => json!({
            "status": "error",
            "releases_dir": dir,
            "error": e.to_string(),
        }),
    }
}

/// Kernel version and the feature gates blackship keys off it.
fn kernel_facts() -> Value {
    match crate::sys::OsVersion::detect_kernel() {
        Ok(version) => json!({
            "status": "present",
            "version": version.to_string(),
            "major": version.major,
            "minor": version.minor,
            "patch": version.patch,
            "release_type": version.release_type.to_string(),
            "features": {
                "vlan_filtering": version.supports_vlan_filtering(),
                "requires_pkgbase": version.requires_pkgbase(),
                "jail_descriptors": version.supports_jail_descriptors(),
                "jail_kqueue": version.supports_jail_kqueue(),
            },
        }),
        Err(e) => json!({ "status": "error", "error": e.to_string() }),
    }
}

/// Online logical CPUs, never less than one.
///
/// The `unsafe` call is sound unconditionally: `sysconf(3)` takes an integer
/// name and returns a `long`, no pointers are involved, and
/// `_SC_NPROCESSORS_ONLN` is always a valid name. A negative or zero return
/// means "indeterminate", which is clamped to one rather than propagated.
#[allow(unsafe_code)] // sysconf(3): nix only binds _NPROCESSORS_ONLN on Linux.
fn online_cpus() -> i64 {
    // SAFETY: integer in, `long` out; see above.
    let count = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if count > 0 { count } else { 1 }
}

#[cfg(test)]
mod tests;
