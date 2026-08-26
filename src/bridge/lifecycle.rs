//! Jail lifecycle: start, stop, restart

use crate::error::{Error, Result};
use crate::hooks::{HookContext, HookPhase, HookRunner};
use crate::jail::state::State as JailState;
use crate::jail::{
    JailConfig, JailHandle, JailInstance, ParamValue, jail_create, jail_create_with_descriptor,
    jail_getid, jail_remove,
};
use crate::network::{VnetConfig, VnetSetup};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;
use throttle_machines::gate::Gate;
use throttle_machines::token_bucket::{TokenBucket, TokenBucketParams, TokenBucketState};

use super::Bridge;

impl Bridge {
    /// Roll back resources allocated during a failed `start_jail`.
    fn rollback_start(
        &mut self,
        full_name: &str,
        vnet_setup: Option<VnetSetup>,
        allocated_ip: &Option<(String, IpAddr)>,
        created_zfs_dataset: bool,
    ) {
        if let Some(setup) = vnet_setup {
            match setup.cleanup() {
                Ok(()) => {
                    let _ = self.vnet_state_store.delete(full_name);
                }
                Err(e) => {
                    eprintln!(
                        "Warning: VNET cleanup failed for '{}': {} -- keeping state record for manual cleanup",
                        full_name, e
                    );
                }
            }
        }
        if let Some((network_name, ip)) = allocated_ip {
            self.ip_allocator.release(network_name, ip);
            let _ = self.lease_store.release(network_name, full_name);
        }
        if created_zfs_dataset {
            eprintln!("Cleaning up ZFS dataset...");
            if let Some(zfs) = &self.zfs {
                let _ = zfs.destroy_jail_dataset(full_name);
            }
        }
    }

    /// Mark a jail as failed and notify the Warden.
    fn mark_jail_failed(&mut self, full_name: &str, path: &std::path::Path) {
        let jail_config = JailConfig::new(full_name, path);
        let mut instance = JailInstance::new(jail_config);
        instance.start().ok();
        instance.fail().ok();
        self.instances.insert(full_name.to_string(), instance);
        if let Some(handle) = &self.warden_handle {
            let _ = handle.notify_failure_blocking(full_name);
        }
    }

    /// Start all jails (or a specific one with its dependencies)
    pub fn up(&mut self, jail: Option<&str>) -> Result<()> {
        let jails_to_start = self.jails_for_up(jail)?;

        for name in &jails_to_start {
            self.start_jail(name)?;
        }

        Ok(())
    }

    /// Stop all jails (or a specific one with its dependents)
    pub fn down(&mut self, jail: Option<&str>) -> Result<()> {
        let jails_to_stop = self.jails_for_down(jail)?;

        for name in &jails_to_stop {
            self.stop_jail(name)?;
        }

        Ok(())
    }

    /// Restart jails
    pub fn restart(&mut self, jail: Option<&str>) -> Result<()> {
        self.down(jail)?;
        self.up(jail)?;
        Ok(())
    }

    /// Restart a jail (stop then start)
    ///
    /// Used by the Warden for automatic restart on failure
    pub fn restart_jail(&mut self, name: &str) -> Result<()> {
        let (service_name, full_name) = self.resolve_jail_names(name)?;
        println!("Restarting jail '{}'...", full_name);

        if let Some(instance) = self.instances.get_mut(&full_name)
            && instance.state() == JailState::Failed
        {
            instance.recover().ok();
        }

        if jail_getid(&full_name).is_ok() {
            self.stop_jail(&service_name)?;
        }

        self.start_jail(&service_name)?;

        println!("Jail '{}' restarted successfully", full_name);
        Ok(())
    }

    /// Start a single jail with cleanup on failure
    pub(super) fn start_jail(&mut self, name: &str) -> Result<()> {
        self.prepare_runtime()?;

        // Rate limiting to prevent thundering herd on `up --all`
        let capacity = self.jail_start_capacity;
        const REFILL_RATE: f64 = 1.0;

        loop {
            let mut state = self.rate_limiter.lock().unwrap();
            let (tokens, last_refill) = *state;
            let now = Instant::now();
            let now_secs = now.duration_since(self.rate_limiter_epoch).as_secs_f64();
            let last_refill_secs = last_refill
                .duration_since(self.rate_limiter_epoch)
                .as_secs_f64();

            let tb_state = TokenBucketState {
                tokens,
                last_refill: last_refill_secs,
            };
            let tb_params = TokenBucketParams {
                capacity,
                refill_rate: REFILL_RATE,
            };
            let result = TokenBucket::check(tb_state, now_secs, tb_params);

            if result.allowed {
                *state = (result.state.tokens, now);
                break;
            }

            let retry_after = result.retry_after;
            drop(state);
            std::thread::sleep(std::time::Duration::from_secs_f64(retry_after));
        }

        let (service_name, full_name) = self.resolve_jail_names(name)?;
        let jail_def = self
            .config
            .get_jail(&service_name)
            .ok_or_else(|| Error::JailNotFound(name.to_string()))?;

        // Check if already running
        if jail_getid(&full_name).is_ok() {
            return Err(Error::JailAlreadyRunning(full_name));
        }

        // Track resources for cleanup on failure
        let mut created_zfs_dataset = false;

        // Create ZFS dataset if needed (a prior `build` may already own it).
        // A clone-ready release provisions the whole root in one zfs clone.
        let path = if let Some(zfs) = &self.zfs {
            if jail_def.path.is_none() {
                if zfs.jail_dataset_exists(&full_name)? {
                    zfs.jail_path(&full_name)
                } else if let Some(release) = jail_def
                    .release
                    .as_ref()
                    .filter(|release| zfs.release_is_cloneable(release))
                {
                    created_zfs_dataset = true;
                    println!(
                        "Provisioning jail '{}' by cloning release '{}'...",
                        full_name, release
                    );
                    zfs.clone_jail_from_release(release, &full_name)?
                } else {
                    created_zfs_dataset = true;
                    zfs.create_jail_dataset(&full_name)?
                }
            } else {
                jail_def.effective_path(&self.config.config, &full_name)
            }
        } else {
            jail_def.effective_path(&self.config.config, &full_name)
        };

        // Validate no ancestor of the jail path is a symlink
        if let Some(parent) = path.parent()
            && parent.exists()
        {
            crate::blueprint::context::reject_symlink_ancestors(
                &self.config.config.data_dir,
                &path,
            )?;
        }

        // A pre-existing symlink here would redirect jail ops to arbitrary host paths.
        if let Ok(meta) = std::fs::symlink_metadata(&path)
            && meta.file_type().is_symlink()
        {
            self.rollback_start(&full_name, None, &None, created_zfs_dataset);
            return Err(Error::JailOperation(format!(
                "Jail path '{}' is a symlink, refusing to use it",
                path.display()
            )));
        }

        // Auto-provision from release when the root is missing or empty.
        // A freshly created ZFS dataset exists but holds no userland, so
        // checking for ./bin instead of bare existence catches both cases.
        if !path.join("bin").exists() {
            if let Some(release) = &jail_def.release {
                crate::manifest::validate_name("release", release)?;
                let release_path = self.config.config.releases_dir.join(release);
                if release_path.exists() {
                    println!(
                        "Provisioning jail '{}' from release '{}'...",
                        full_name, release
                    );

                    if let Err(e) = std::fs::create_dir_all(&path) {
                        self.rollback_start(&full_name, None, &None, created_zfs_dataset);
                        return Err(Error::JailOperation(format!(
                            "Failed to create jail directory: {}",
                            e
                        )));
                    }

                    let status = std::process::Command::new("/bin/cp")
                        .arg("-a")
                        .arg(format!("{}/.", release_path.display()))
                        .arg(&path)
                        .status();

                    match status {
                        Ok(s) if s.success() => {
                            // cp -a may have followed a symlink out of the parent.
                            let data_parent = path.parent().unwrap_or(std::path::Path::new("/"));
                            if let (Ok(canonical_path), Ok(canonical_parent)) =
                                (path.canonicalize(), data_parent.canonicalize())
                                && !canonical_path.starts_with(&canonical_parent)
                            {
                                let _ = std::fs::remove_dir_all(&path);
                                self.rollback_start(&full_name, None, &None, created_zfs_dataset);
                                return Err(Error::JailOperation(format!(
                                    "Jail path '{}' resolves to '{}' which is outside '{}'",
                                    path.display(),
                                    canonical_path.display(),
                                    canonical_parent.display()
                                )));
                            }
                            println!(
                                "Jail '{}' provisioned from release '{}'",
                                full_name, release
                            );
                        }
                        Ok(s) => {
                            let _ = std::fs::remove_dir_all(&path);
                            self.rollback_start(&full_name, None, &None, created_zfs_dataset);
                            return Err(Error::JailOperation(format!(
                                "Failed to copy release: cp exited with status {}",
                                s
                            )));
                        }
                        Err(e) => {
                            let _ = std::fs::remove_dir_all(&path);
                            self.rollback_start(&full_name, None, &None, created_zfs_dataset);
                            return Err(Error::JailOperation(format!(
                                "Failed to execute cp command: {}",
                                e
                            )));
                        }
                    }
                } else {
                    let msg = format!(
                        "Release '{}' not found at {}. Run 'blackship bootstrap {}' first.",
                        release,
                        release_path.display(),
                        release
                    );
                    self.rollback_start(&full_name, None, &None, created_zfs_dataset);
                    return Err(Error::JailOperation(msg));
                }
            } else {
                if created_zfs_dataset && let Some(zfs) = &self.zfs {
                    let _ = zfs.destroy_jail_dataset(&full_name);
                }
                return Err(Error::JailPathNotFound(path));
            }
        }

        // Configure DNS before starting the jail
        if let Some(network) = &jail_def.network
            && let Err(e) = self.configure_dns(&path, &network.dns)
        {
            self.rollback_start(&full_name, None, &None, created_zfs_dataset);
            return Err(e);
        }

        // Determine IP address for this jail
        let mut allocated_ip: Option<(String, IpAddr)> = None;
        let effective_ip: Option<IpAddr> = if let Some(network) = &jail_def.network {
            if let Some(static_ip) = network.ip {
                for net_name in &network.networks {
                    if !self.runtime_networks.contains_key(net_name) {
                        let msg = format!(
                            "Jail '{}' references unknown network '{}'",
                            full_name, net_name
                        );
                        self.rollback_start(&full_name, None, &None, created_zfs_dataset);
                        return Err(Error::Network(msg));
                    }
                }
                Some(static_ip)
            } else if let Some(first_network) = network.networks.first() {
                match crate::network::allocate_and_record(
                    &mut self.ip_allocator,
                    &self.lease_store,
                    first_network,
                    &full_name,
                ) {
                    Ok(ip) => {
                        allocated_ip = Some((first_network.clone(), ip));
                        if self.verbose {
                            println!(
                                "  Auto-allocated IP {} from network '{}'",
                                ip, first_network
                            );
                        }
                        Some(ip)
                    }
                    Err(e) => {
                        self.rollback_start(&full_name, None, &None, created_zfs_dataset);
                        return Err(e);
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        // Setup hook runner and context
        let hook_runner = HookRunner::new(jail_def.hooks.clone()).verbose(self.verbose);
        let mut hook_context = HookContext::new(&full_name, &path);

        if let Some(ip) = effective_ip {
            hook_context = hook_context.with_ip(ip.to_string());
        }

        // Execute pre_start hooks
        if let Err(e) = hook_runner.execute_phase(HookPhase::PreStart, &hook_context) {
            self.rollback_start(&full_name, None, &allocated_ip, created_zfs_dataset);
            return Err(e);
        }

        // Check if this is a VNET jail
        let is_vnet = jail_def.network.as_ref().is_some_and(|n| n.vnet);

        // Create VNET setup for VNET jails before creating the jail
        let mut vnet_setup: Option<VnetSetup> = None;
        if is_vnet && let Some(network) = &jail_def.network {
            let primary_runtime_network = network
                .networks
                .first()
                .map(|network_name| {
                    self.runtime_networks
                        .get(network_name)
                        .cloned()
                        .ok_or_else(|| {
                            Error::Network(format!(
                                "Jail '{}' references unknown network '{}'",
                                full_name, network_name
                            ))
                        })
                })
                .transpose()?;

            let bridge_name = network
                .bridge
                .clone()
                .or_else(|| {
                    primary_runtime_network
                        .as_ref()
                        .and_then(|runtime| runtime.bridge.clone())
                })
                .ok_or_else(|| {
                    Error::Network(format!(
                        "VNET jail '{}' requires a bridge configuration",
                        full_name
                    ))
                })?;

            let ip_config = if let Some(ip_cidr) = network.ip_cidr.clone() {
                ip_cidr
            } else {
                let ip = network.ip.or(effective_ip).ok_or_else(|| {
                    Error::Network(format!(
                        "VNET jail '{}' requires an IP address or attached network",
                        full_name
                    ))
                })?;
                let prefix_len = primary_runtime_network
                    .as_ref()
                    .map(|runtime| runtime.subnet.prefix_len())
                    .unwrap_or(24);
                format!("{}/{}", ip, prefix_len)
            };

            let gateway = network
                .gateway
                .or_else(|| {
                    primary_runtime_network
                        .as_ref()
                        .map(|runtime| runtime.gateway)
                })
                .ok_or_else(|| {
                    Error::Network(format!(
                        "VNET jail '{}' requires a gateway or attached network",
                        full_name
                    ))
                })?;

            let mut vnet_config = VnetConfig::new(bridge_name.clone(), ip_config, gateway);

            if let Some(ref mac) = network.mac_address {
                vnet_config = vnet_config.with_mac_address(mac.clone());
            }

            if let Some(vlan_id) = network.vlan_id {
                vnet_config = vnet_config.with_vlan_id(vlan_id);
            }

            // Explicit jail backend wins; otherwise inherit from the
            // attached named network so netgraph networks just work.
            let backend = network.backend.unwrap_or_else(|| {
                match primary_runtime_network
                    .as_ref()
                    .map(|runtime| runtime.backend.as_str())
                {
                    Some("netgraph") => crate::network::vnet::NetworkBackend::Netgraph,
                    _ => crate::network::vnet::NetworkBackend::Epair,
                }
            });
            vnet_config = vnet_config.with_backend(backend);

            let setup = match VnetSetup::create(&full_name, vnet_config) {
                Ok(s) => s,
                Err(e) => {
                    self.rollback_start(&full_name, None, &allocated_ip, created_zfs_dataset);
                    return Err(e);
                }
            };

            if self.verbose {
                println!(
                    "  Created {} <-> {} for VNET jail",
                    setup.host_interface(),
                    setup.jail_interface()
                );
                println!(
                    "  Added {} to bridge {}",
                    setup.host_interface(),
                    bridge_name
                );
            }

            let state_record =
                setup.state_record(&full_name, network.networks.first().map(String::as_str));
            if let Err(e) = self.vnet_state_store.save(&state_record) {
                self.rollback_start(&full_name, Some(setup), &allocated_ip, created_zfs_dataset);
                return Err(e);
            }

            vnet_setup = Some(setup);
        }

        // Reserved params are rejected so manifests cannot bypass jail isolation.
        const RESERVED_PARAMS: &[&str] = &[
            "name",
            "jid",
            "path",
            "errmsg",
            "persist",
            "nopersist",
            "vnet",
            "ip4.addr",
            "ip6.addr",
            "host.hostname",
            "securelevel",
            "devfs_ruleset",
            "allow.mount",
            "allow.mount.devfs",
            "allow.mount.fdescfs",
            "allow.mount.fusefs",
            "allow.mount.nullfs",
            "allow.mount.procfs",
            "allow.mount.tmpfs",
            "allow.mount.zfs",
            "allow.mount.linprocfs",
            "allow.raw_sockets",
            "allow.chflags",
            "allow.sysvipc",
            "allow.quotas",
            "allow.socket_af",
            "allow.mlock",
            "children.max",
            "enforce_statfs",
        ];

        let mut params = HashMap::new();

        for (key, value) in &jail_def.params {
            if RESERVED_PARAMS.contains(&key.as_str()) {
                eprintln!(
                    "Warning: ignoring reserved jail parameter '{}' in manifest",
                    key
                );
                continue;
            }
            let param_value = ParamValue::try_from(value)?;
            params.insert(key.clone(), param_value);
        }

        params.insert("name".to_string(), ParamValue::String(full_name.clone()));

        if let Some(hostname) = &jail_def.hostname {
            params.insert(
                "host.hostname".to_string(),
                ParamValue::String(hostname.clone()),
            );
        }

        if is_vnet {
            // `vnet` is a jailsys CTLTYPE_INT param in the kernel, even though
            // jail.conf exposes it as the strings "inherit"/"new".
            params.insert("vnet".to_string(), ParamValue::Int(libc::JAIL_SYS_NEW));
        } else if let Some(ip) = effective_ip {
            match ip {
                IpAddr::V4(addr) => {
                    params.insert("ip4.addr".to_string(), ParamValue::Ipv4(vec![addr]));
                }
                IpAddr::V6(addr) => {
                    params.insert("ip6.addr".to_string(), ParamValue::Ipv6(vec![addr]));
                }
            }
        }

        // Mount devfs into the jail root. The jail(2) syscall does not honor
        // mount.devfs (that is jail(8) machinery), so this is our job.
        let devfs_ruleset = jail_def
            .devfs_ruleset
            .unwrap_or(crate::sys::DEVFS_RULESET_JAIL);
        if devfs_ruleset != 0 {
            let dev_path = path.join("dev");
            if !dev_path.join("null").exists() {
                std::fs::create_dir_all(&dev_path).ok();
                if let Err(e) = crate::sys::mount_devfs(&dev_path)
                    .and_then(|_| crate::sys::apply_devfs_ruleset(&dev_path, devfs_ruleset))
                {
                    crate::sys::unmount_quiet(&dev_path);
                    self.rollback_start(&full_name, vnet_setup, &allocated_ip, created_zfs_dataset);
                    return Err(e);
                }
            }
        }

        println!("Starting jail '{}'...", full_name);
        // Owning descriptors are only useful while a long-lived supervisor
        // process keeps them open. For one-shot CLI commands like `up`, using
        // an owning descriptor would remove the jail as soon as blackship exits.
        let use_descriptors =
            self.os_version.supports_jail_descriptors() && self.warden_handle.is_some();
        let (jid, jail_handle) = if use_descriptors {
            match jail_create_with_descriptor(&path, params) {
                Ok((jid, desc)) => (jid, Some(JailHandle::Descriptor { fd: desc, jid })),
                Err(e) => {
                    eprintln!("Failed to create jail '{}': {}", full_name, e);
                    crate::sys::unmount_jail_devfs(&path);
                    self.rollback_start(&full_name, vnet_setup, &allocated_ip, created_zfs_dataset);
                    self.mark_jail_failed(&full_name, &path);
                    return Err(e);
                }
            }
        } else {
            match jail_create(&path, params) {
                Ok(jid) => (jid, Some(JailHandle::Jid(jid))),
                Err(e) => {
                    eprintln!("Failed to create jail '{}': {}", full_name, e);
                    crate::sys::unmount_jail_devfs(&path);
                    self.rollback_start(&full_name, vnet_setup, &allocated_ip, created_zfs_dataset);
                    self.mark_jail_failed(&full_name, &path);
                    return Err(e);
                }
            }
        };
        println!(
            "Jail '{}' started with JID {}{}",
            full_name,
            jid,
            if use_descriptors {
                " (owning descriptor)"
            } else {
                ""
            }
        );

        // Fail closed: never run without the configured resource limits.
        if !jail_def.resources.is_empty()
            && let Err(e) = crate::rctl::apply_limits(&full_name, &jail_def.resources)
        {
            eprintln!(
                "Failed to apply resource limits for '{}': {}, stopping jail",
                full_name, e
            );
            // Remove the jail before releasing ZFS/IP -- never while it is alive.
            if let Err(remove_err) = jail_remove(jid) {
                eprintln!(
                    "Warning: Failed to remove jail '{}' (JID {}) during RCTL rollback: {}",
                    full_name, jid, remove_err
                );
                self.mark_jail_failed(&full_name, &path);
                return Err(e);
            }
            crate::sys::unmount_jail_devfs(&path);
            self.rollback_start(&full_name, None, &allocated_ip, created_zfs_dataset);
            self.mark_jail_failed(&full_name, &path);
            return Err(e);
        }

        // Pin the jail to its CPU set, spreading across other jails' pins.
        let other_pins: Vec<String> = self
            .config
            .jails
            .iter()
            .filter(|other| other.name != service_name)
            .filter_map(|other| other.resources.cpuset.clone())
            .collect();
        if let Some(cpu_list) =
            crate::rctl::resolve_cpu_list(&jail_def.resources, other_pins.into_iter())
        {
            if let Err(e) = crate::rctl::apply_cpuset(jid, &cpu_list) {
                eprintln!(
                    "Failed to pin jail '{}' to CPUs: {}, stopping jail",
                    full_name, e
                );
                if let Err(remove_err) = jail_remove(jid) {
                    eprintln!(
                        "Warning: Failed to remove jail '{}' (JID {}) during cpuset rollback: {}",
                        full_name, jid, remove_err
                    );
                    self.mark_jail_failed(&full_name, &path);
                    return Err(e);
                }
                crate::sys::unmount_jail_devfs(&path);
                self.rollback_start(&full_name, None, &allocated_ip, created_zfs_dataset);
                self.mark_jail_failed(&full_name, &path);
                return Err(e);
            }
            println!("  Pinned to CPUs: {}", cpu_list);
        }

        // For VNET jails: attach the VnetSetup to the jail
        if let Some(setup) = vnet_setup {
            if let Err(e) = setup.attach_to_jail(jid) {
                eprintln!(
                    "Error: Failed to attach VNET to jail '{}': {}",
                    full_name, e
                );
                // If jail_remove fails the jail is still alive: do not release IP/ZFS.
                if let Err(remove_err) = jail_remove(jid) {
                    eprintln!(
                        "Warning: Failed to remove jail '{}' (JID {}) during VNET rollback: {}",
                        full_name, jid, remove_err
                    );
                    self.mark_jail_failed(&full_name, &path);
                    return Err(e);
                }
                crate::sys::unmount_jail_devfs(&path);
                self.rollback_start(&full_name, Some(setup), &allocated_ip, created_zfs_dataset);
                self.mark_jail_failed(&full_name, &path);
                return Err(e);
            } else if self.verbose {
                println!(
                    "  Moved {} into jail {} (JID {})",
                    setup.jail_interface(),
                    full_name,
                    jid
                );
                println!(
                    "  Configured {} with {} in jail",
                    setup.jail_interface(),
                    setup.config.ip
                );
                println!("  Set default gateway to {}", setup.config.gateway);
            }

            self.vnet_setups.insert(full_name.clone(), setup);
        }

        // Boot the jail's userland after networking is attached so services
        // can bind their addresses. jail(2) has no exec.start; running rc is
        // our job, exactly like devfs.
        if jail_def.init.unwrap_or(true) {
            match crate::jail::jexec::jexec_run(jid, &["/bin/sh", "/etc/rc"]) {
                Ok(exit_code) if exit_code != 0 => {
                    eprintln!(
                        "Warning: /etc/rc in jail '{}' exited with {}",
                        full_name, exit_code
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    eprintln!(
                        "Warning: failed to run /etc/rc in jail '{}': {}",
                        full_name, e
                    );
                }
            }
        }

        // Update context with JID for post_start hooks
        let hook_context = hook_context.with_jid(jid);

        if let Err(e) = hook_runner.execute_phase(HookPhase::PostStart, &hook_context) {
            eprintln!(
                "Warning: post_start hook failed for jail '{}': {}",
                full_name, e
            );
            eprintln!("Jail is running but may not be fully configured.");
        }

        // Track the instance
        let mut jail_config = JailConfig::new(&full_name, &path);
        if let Some(hostname) = &jail_def.hostname {
            jail_config = jail_config.hostname(hostname);
        }
        if let Some(ip) = effective_ip {
            jail_config = jail_config.ip(ip);
        }
        let mut instance = JailInstance::new(jail_config);
        instance.jid = Some(jid);
        instance.handle = jail_handle;
        instance.start().ok();
        instance.started().ok();
        self.instances.insert(full_name.clone(), instance);

        if let Some(alloc) = allocated_ip {
            self.allocated_ips.insert(full_name.clone(), alloc);
        }

        if let Some(handle) = &self.warden_handle
            && let Err(e) = handle.notify_started_blocking(&full_name)
        {
            eprintln!("Warning: Failed to notify Warden of jail start: {}", e);
        }

        Ok(())
    }

    /// Stop a single jail
    pub(super) fn stop_jail(&mut self, name: &str) -> Result<()> {
        let (service_name, full_name) = self.resolve_jail_names(name)?;

        let jid = match jail_getid(&full_name) {
            Ok(jid) => jid,
            Err(_) => {
                return Err(Error::JailNotRunning(full_name));
            }
        };

        // Remove RCTL limits before stopping
        crate::rctl::remove_limits(&full_name);

        let jail_def = self.config.get_jail(&service_name);
        let mut post_stop_hook: Option<(HookRunner, std::path::PathBuf)> = None;

        if let Some(jail_def) = jail_def {
            let path = jail_def.effective_path(&self.config.config, &full_name);
            let hook_runner = HookRunner::new(jail_def.hooks.clone()).verbose(self.verbose);
            let mut hook_context = HookContext::new(&full_name, &path).with_jid(jid);

            if let Some(network) = &jail_def.network
                && let Some(ip) = &network.ip
            {
                hook_context = hook_context.with_ip(ip.to_string());
            }

            hook_runner.execute_phase(HookPhase::PreStop, &hook_context)?;

            // Give rc-managed services an orderly shutdown before removal.
            if jail_def.init.unwrap_or(true)
                && let Ok(exit_code) =
                    crate::jail::jexec::jexec_run(jid, &["/bin/sh", "/etc/rc.shutdown"])
                && exit_code != 0
            {
                eprintln!(
                    "Warning: /etc/rc.shutdown in jail '{}' exited with {}",
                    full_name, exit_code
                );
            }

            post_stop_hook = Some((hook_runner, path));
        }

        if let Some(handle) = &self.warden_handle {
            handle.mark_stop_requested(jid);
        }

        println!("Stopping jail '{}'...", full_name);
        if let Err(e) = jail_remove(jid) {
            if let Some(handle) = &self.warden_handle {
                handle.clear_stop_requested(jid);
            }
            return Err(e);
        }
        println!("Jail '{}' stopped", full_name);

        if let Some(handle) = &self.warden_handle
            && let Err(e) = handle.notify_stopped_blocking(&full_name, jid)
        {
            handle.clear_stop_requested(jid);
            eprintln!("Warning: Failed to notify Warden of jail stop: {}", e);
        }

        let mut stop_result = Ok(());
        if let Some((hook_runner, path)) = post_stop_hook {
            let hook_context = HookContext::new(&full_name, &path);
            if let Err(e) = hook_runner.execute_phase(HookPhase::PostStop, &hook_context) {
                stop_result = Err(e);
            }
            crate::sys::unmount_jail_devfs(&path);
        }

        if let Some(instance) = self.instances.get_mut(&full_name) {
            instance.stop().ok();
            instance.stopped().ok();
            instance.jid = None;
            instance.handle = None;
        }

        let mut cleaned_persisted_vnet = false;
        if let Some(vnet_setup) = self.vnet_setups.remove(&full_name) {
            match vnet_setup.cleanup() {
                Ok(()) => {
                    let _ = self.vnet_state_store.delete(&full_name);
                    if self.verbose {
                        println!("  Cleaned up VNET for bridge {}", vnet_setup.bridge_name);
                    }
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Failed to cleanup VNET setup for jail '{}': {} -- keeping state record for manual cleanup",
                        full_name, e
                    );
                }
            }
            cleaned_persisted_vnet = true;
        }
        if !cleaned_persisted_vnet && let Ok(Some(record)) = self.vnet_state_store.get(&full_name) {
            match VnetSetup::cleanup_state(&record) {
                Ok(()) => {
                    let _ = self.vnet_state_store.delete(&full_name);
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Failed to cleanup persisted VNET setup for jail '{}': {} -- keeping state record for manual cleanup",
                        full_name, e
                    );
                }
            }
        }

        if let Some((network_name, ip)) = self.allocated_ips.remove(&full_name) {
            self.ip_allocator.release(&network_name, &ip);
            let _ = self.lease_store.release(&network_name, &full_name);
            if self.verbose {
                println!("  Released IP {} back to network '{}'", ip, network_name);
            }
        } else {
            let _ = self.lease_store.release_owner(&full_name);
        }

        stop_result
    }

    /// Force cleanup of a failed jail
    pub fn cleanup(&mut self, name: &str, force: bool) -> Result<()> {
        let (service_name, full_name) = self.resolve_jail_names(name)?;
        println!("Cleaning up jail '{}'...", full_name);

        let jail_def = self.config.get_jail(&service_name);

        if let Ok(jid) = jail_getid(&full_name) {
            println!("  Removing jail (JID {})...", jid);
            if let Err(e) = jail_remove(jid) {
                if force {
                    eprintln!("  Warning: Failed to remove jail: {}", e);
                } else {
                    return Err(e);
                }
            }
        }

        if let Some(zfs) = &self.zfs
            && let Some(jail_def) = jail_def
            && jail_def.path.is_none()
        {
            println!("  Destroying ZFS dataset...");
            if let Err(e) = zfs.destroy_jail_dataset(&full_name) {
                if force {
                    eprintln!("  Warning: Failed to destroy dataset: {}", e);
                } else {
                    return Err(e);
                }
            }
        }

        self.instances.remove(&full_name);

        let mut cleaned_persisted_vnet = false;
        if let Some(vnet_setup) = self.vnet_setups.remove(&full_name) {
            println!("  Cleaning up VNET setup...");
            if let Err(e) = vnet_setup.cleanup() {
                if force {
                    eprintln!("  Warning: Failed to cleanup VNET setup: {}", e);
                } else {
                    return Err(e);
                }
            }
            let _ = self.vnet_state_store.delete(&full_name);
            cleaned_persisted_vnet = true;
        }
        if !cleaned_persisted_vnet && let Ok(Some(record)) = self.vnet_state_store.get(&full_name) {
            println!("  Cleaning up persisted VNET state...");
            if let Err(e) = VnetSetup::cleanup_state(&record) {
                if force {
                    eprintln!("  Warning: Failed to cleanup persisted VNET state: {}", e);
                } else {
                    return Err(e);
                }
            }
            let _ = self.vnet_state_store.delete(&full_name);
        }

        if let Some((network_name, ip)) = self.allocated_ips.remove(&full_name) {
            self.ip_allocator.release(&network_name, &ip);
            let _ = self.lease_store.release(&network_name, &full_name);
            println!("  Released IP {} back to network '{}'", ip, network_name);
        } else {
            let released = self.lease_store.release_owner(&full_name)?;
            for (network_name, ip) in released {
                println!("  Released IP {} back to network '{}'", ip, network_name);
            }
        }

        println!("Cleanup complete for jail '{}'", full_name);
        Ok(())
    }
}
