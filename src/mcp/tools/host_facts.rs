//! What this host can actually do, so a model stops guessing.

use mcp_host::prelude::*;
use mcp_host::registry::router::McpToolRouter;
use serde_json::{Value, json};

use super::super::McpState;

impl McpState {
    /// Report the real capabilities of the host this server runs on.
    #[mcp_tool(
        name = "host_facts",
        description = "Kernel version and feature gates, CPU count, rctl availability, \
                       running jails (including ones blackship did not create), \
                       bootstrapped releases, and ZFS state for this host. Call this \
                       before drafting configuration.",
        read_only = true,
        idempotent = true
    )]
    async fn host_facts(&self, _ctx: Ctx<'_>, _params: Parameters<()>) -> ToolResult {
        let config = crate::manifest::load_or_default(&self.config_path);
        let config_error = config.as_ref().err().map(ToString::to_string);
        let global = config.as_ref().ok().map(|config| &config.config);

        let facts = json!({
            "config_source": self.config_source(),
            "config_path": self.config_path.display().to_string(),
            "config_error": config_error,
            "kernel": kernel_facts(),
            "cpu": json!({ "online": online_cpus() }),
            "rctl": rctl_facts(),
            "running_jails": running_jails(),
            "releases": release_facts(global),
            "zfs": zfs_facts(global),
        });

        let text = serde_json::to_string_pretty(&facts)
            .map_err(|e| ToolError::Execution(format!("Failed to serialize host facts: {e}")))?;

        Ok(ToolOutput::text(text))
    }
}

impl McpState {
    /// Where the manifest-dependent sections got their configuration.
    fn config_source(&self) -> Value {
        if self.config_path.exists() {
            json!(self.config_path.display().to_string())
        } else {
            json!("defaults")
        }
    }

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

/// ZFS configuration, the pools the host really has, and the base dataset.
///
/// The pool list is probed regardless of configuration: a model proposing
/// `zfs_enabled = true` needs to know whether a pool exists, and answering
/// only "config says no" would hide that.
fn zfs_facts(config: Option<&crate::manifest::GlobalConfig>) -> Value {
    let pools = available_pools();

    let Some(config) = config else {
        return json!({
            "status": "error",
            "error": "configuration is unavailable",
            "host_pools": pools,
        });
    };

    if !config.zfs_enabled {
        return json!({
            "status": "absent",
            "enabled": false,
            "note": "zfs_enabled is false; jail roots are plain directories under \
                     data_dir/jails. Set zfs_enabled and zpool to use datasets.",
            "jails_dir": config.jails_dir().display().to_string(),
            "host_pools": pools,
        });
    }

    let Some(pool) = config.zpool.as_deref() else {
        return json!({
            "status": "error",
            "enabled": true,
            "error": "zfs_enabled is true but no zpool is configured",
            "host_pools": pools,
        });
    };

    let base_dataset = format!("{pool}/{}", config.dataset);
    let manager = crate::zfs::ZfsManager::new(pool, config.dataset.clone(), config.jails_dir());

    match manager.dataset_exists(&base_dataset) {
        Ok(exists) => json!({
            "status": "present",
            "enabled": true,
            "zpool": pool,
            "base_dataset": base_dataset,
            "base_dataset_exists": exists,
            "jails_mountpoint": config.jails_dir().display().to_string(),
            "host_pools": pools,
        }),
        Err(e) => json!({
            "status": "error",
            "enabled": true,
            "zpool": pool,
            "base_dataset": base_dataset,
            "error": e.to_string(),
            "host_pools": pools,
        }),
    }
}

/// Imported ZFS pools, via `zpool list`.
///
/// A missing or failing `zpool(8)` means no usable ZFS, which is reported as
/// an error object rather than an empty list, so "none imported" and "cannot
/// tell" stay distinguishable.
fn available_pools() -> Value {
    let output = std::process::Command::new("/sbin/zpool")
        .args(["list", "-H", "-o", "name"])
        .output();

    match output {
        Ok(out) if out.status.success() => json!({
            "status": "present",
            "pools": String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .collect::<Vec<_>>(),
        }),
        Ok(out) => json!({
            "status": "error",
            "error": format!(
                "zpool list exited {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        }),
        Err(e) => json!({ "status": "absent", "error": format!("cannot run /sbin/zpool: {e}") }),
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
fn online_cpus() -> i64 {
    let count = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if count > 0 { count } else { 1 }
}

/// Whether RACCT/RCTL is usable, and the resources blackship manages through it.
fn rctl_facts() -> Value {
    let enabled = crate::rctl::is_enabled();
    json!({
        "enabled": enabled,
        "managed_resources": crate::rctl::managed_resources(),
        "note": if enabled {
            "resource limits in a manifest will be applied"
        } else {
            "kern.racct.enable is not 1; rctl limits cannot be applied (cpuset pinning \
             still works). Enable it in /boot/loader.conf and reboot."
        },
    })
}

/// Every jail running on the host, whether or not blackship created it.
///
/// `RunningJails` yields bare JIDs; a JID whose name lookup fails is still
/// reported with a null name rather than dropped.
fn running_jails() -> Value {
    let jails: Vec<Value> = crate::jail::RunningJails::new()
        .map(|jid| match crate::jail::jail_getname(jid) {
            Ok(name) => json!({ "jid": jid, "name": name }),
            Err(e) => json!({ "jid": jid, "name": Value::Null, "name_error": e.to_string() }),
        })
        .collect();

    json!({
        "count": jails.len(),
        "jails": jails,
        "note": "enumerated via the jail_get(2) syscall, so this includes jails blackship \
                 does not manage",
    })
}

pub fn mount(router: McpToolRouter<McpState>) -> McpToolRouter<McpState> {
    router.with_tool(
        McpState::host_facts_tool_info(),
        McpState::host_facts_handler,
        None,
    )
}
