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
use throttle_machines::token_bucket;

use super::Bridge;

impl Bridge {
    /// Start all jails (or a specific one with its dependencies)
    pub fn up(&mut self, jail: Option<&str>) -> Result<()> {
        let jails_to_start: Vec<String> = if let Some(name) = jail {
            self.get_dependencies(name)?
                .into_iter()
                .map(String::from)
                .collect()
        } else {
            self.start_order()?.into_iter().map(String::from).collect()
        };

        for name in &jails_to_start {
            self.start_jail(name)?;
        }

        Ok(())
    }

    /// Stop all jails (or a specific one with its dependents)
    pub fn down(&mut self, jail: Option<&str>) -> Result<()> {
        let jails_to_stop: Vec<String> = if let Some(name) = jail {
            self.get_dependents(name)?
                .into_iter()
                .map(String::from)
                .collect()
        } else {
            self.stop_order()?.into_iter().map(String::from).collect()
        };

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

            let result =
                token_bucket::check(tokens, last_refill_secs, now_secs, capacity, REFILL_RATE);

            if result.allowed {
                *state = (result.new_tokens, now);
                break;
            } else {
                let retry_after = result.retry_after;
                drop(state);
                std::thread::sleep(std::time::Duration::from_secs_f64(retry_after));
            }
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

        // Create ZFS dataset if needed
        let path = if let Some(zfs) = &self.zfs {
            if jail_def.path.is_none() {
                created_zfs_dataset = true;
                zfs.create_jail_dataset(&full_name)?
            } else {
                jail_def.effective_path(&self.config.config, &full_name)
            }
        } else {
            jail_def.effective_path(&self.config.config, &full_name)
        };

        // Check path exists - auto-provision from release if available
        if !path.exists() {
            if let Some(release) = &jail_def.release {
                let release_path = self.config.config.releases_dir.join(release);
                if release_path.exists() {
                    println!(
                        "Provisioning jail '{}' from release '{}'...",
                        full_name, release
                    );

                    if let Err(e) = std::fs::create_dir_all(&path) {
                        if created_zfs_dataset && let Some(zfs) = &self.zfs {
                            let _ = zfs.destroy_jail_dataset(&full_name);
                        }
                        return Err(Error::JailOperation(format!(
                            "Failed to create jail directory: {}",
                            e
                        )));
                    }

                    let status = std::process::Command::new("cp")
                        .arg("-a")
                        .arg(format!("{}/.", release_path.display()))
                        .arg(&path)
                        .status();

                    match status {
                        Ok(s) if s.success() => {
                            println!(
                                "Jail '{}' provisioned from release '{}'",
                                full_name, release
                            );
                        }
                        Ok(s) => {
                            let _ = std::fs::remove_dir_all(&path);
                            if created_zfs_dataset && let Some(zfs) = &self.zfs {
                                let _ = zfs.destroy_jail_dataset(&full_name);
                            }
                            return Err(Error::JailOperation(format!(
                                "Failed to copy release: cp exited with status {}",
                                s
                            )));
                        }
                        Err(e) => {
                            let _ = std::fs::remove_dir_all(&path);
                            if created_zfs_dataset && let Some(zfs) = &self.zfs {
                                let _ = zfs.destroy_jail_dataset(&full_name);
                            }
                            return Err(Error::JailOperation(format!(
                                "Failed to execute cp command: {}",
                                e
                            )));
                        }
                    }
                } else {
                    if created_zfs_dataset && let Some(zfs) = &self.zfs {
                        let _ = zfs.destroy_jail_dataset(&full_name);
                    }
                    return Err(Error::JailOperation(format!(
                        "Release '{}' not found at {}. Run 'blackship bootstrap {}' first.",
                        release,
                        release_path.display(),
                        release
                    )));
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
            if created_zfs_dataset && let Some(zfs) = &self.zfs {
                let _ = zfs.destroy_jail_dataset(&full_name);
            }
            return Err(e);
        }

        // Determine IP address for this jail
        let mut allocated_ip: Option<(String, IpAddr)> = None;
        let effective_ip: Option<IpAddr> = if let Some(network) = &jail_def.network {
            if let Some(static_ip) = network.ip {
                for net_name in &network.networks {
                    if !self.runtime_networks.contains_key(net_name) {
                        if created_zfs_dataset && let Some(zfs) = &self.zfs {
                            let _ = zfs.destroy_jail_dataset(&full_name);
                        }
                        return Err(Error::Network(format!(
                            "Jail '{}' references unknown network '{}'",
                            full_name, net_name
                        )));
                    }
                }
                Some(static_ip)
            } else if let Some(first_network) = network.networks.first() {
                match self.ip_allocator.allocate(first_network) {
                    Ok(ip) => {
                        if let Err(e) = self.lease_store.record(first_network, &full_name, ip) {
                            if created_zfs_dataset && let Some(zfs) = &self.zfs {
                                let _ = zfs.destroy_jail_dataset(&full_name);
                            }
                            return Err(e);
                        }
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
                        if created_zfs_dataset && let Some(zfs) = &self.zfs {
                            let _ = zfs.destroy_jail_dataset(&full_name);
                        }
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
            if let Some((network_name, ip)) = &allocated_ip {
                self.ip_allocator.release(network_name, ip);
                let _ = self.lease_store.release(network_name, &full_name);
            }
            if created_zfs_dataset && let Some(zfs) = &self.zfs {
                let _ = zfs.destroy_jail_dataset(&full_name);
            }
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

            let setup = match VnetSetup::create(&full_name, vnet_config) {
                Ok(s) => s,
                Err(e) => {
                    if let Some((network_name, ip)) = &allocated_ip {
                        self.ip_allocator.release(network_name, ip);
                        let _ = self.lease_store.release(network_name, &full_name);
                    }
                    if created_zfs_dataset && let Some(zfs) = &self.zfs {
                        let _ = zfs.destroy_jail_dataset(&full_name);
                    }
                    return Err(e);
                }
            };

            if self.verbose {
                println!(
                    "  Created epair {} <-> {} for VNET jail",
                    setup.epair.host_side(),
                    setup.epair.jail_side()
                );
                println!(
                    "  Added {} to bridge {}",
                    setup.epair.host_side(),
                    bridge_name
                );
            }

            let state_record =
                setup.state_record(&full_name, network.networks.first().map(String::as_str));
            if let Err(e) = self.vnet_state_store.save(&state_record) {
                let _ = setup.cleanup();
                if let Some((network_name, ip)) = &allocated_ip {
                    self.ip_allocator.release(network_name, ip);
                    let _ = self.lease_store.release(network_name, &full_name);
                }
                if created_zfs_dataset && let Some(zfs) = &self.zfs {
                    let _ = zfs.destroy_jail_dataset(&full_name);
                }
                return Err(e);
            }

            vnet_setup = Some(setup);
        }

        // Build jail parameters
        let mut params = HashMap::new();
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

        for (key, value) in &jail_def.params {
            let param_value = ParamValue::try_from(value)?;
            params.insert(key.clone(), param_value);
        }

        // Create the jail — use owning descriptors on FreeBSD 16+
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
                    if let Some(setup) = vnet_setup {
                        let _ = setup.cleanup();
                        let _ = self.vnet_state_store.delete(&full_name);
                    }
                    if let Some((network_name, ip)) = &allocated_ip {
                        self.ip_allocator.release(network_name, ip);
                        let _ = self.lease_store.release(network_name, &full_name);
                    }
                    if created_zfs_dataset {
                        eprintln!("Cleaning up ZFS dataset...");
                        if let Some(zfs) = &self.zfs {
                            let _ = zfs.destroy_jail_dataset(&full_name);
                        }
                    }
                    let jail_config = JailConfig::new(&full_name, &path);
                    let mut instance = JailInstance::new(jail_config);
                    instance.start().ok();
                    instance.fail().ok();
                    self.instances.insert(full_name.clone(), instance);
                    if let Some(handle) = &self.warden_handle {
                        let _ = handle.notify_failure_blocking(&full_name);
                    }
                    return Err(e);
                }
            }
        } else {
            match jail_create(&path, params) {
                Ok(jid) => (jid, Some(JailHandle::Jid(jid))),
                Err(e) => {
                    eprintln!("Failed to create jail '{}': {}", full_name, e);
                    if let Some(setup) = vnet_setup {
                        let _ = setup.cleanup();
                        let _ = self.vnet_state_store.delete(&full_name);
                    }
                    if let Some((network_name, ip)) = &allocated_ip {
                        self.ip_allocator.release(network_name, ip);
                        let _ = self.lease_store.release(network_name, &full_name);
                    }
                    if created_zfs_dataset {
                        eprintln!("Cleaning up ZFS dataset...");
                        if let Some(zfs) = &self.zfs {
                            let _ = zfs.destroy_jail_dataset(&full_name);
                        }
                    }
                    let jail_config = JailConfig::new(&full_name, &path);
                    let mut instance = JailInstance::new(jail_config);
                    instance.start().ok();
                    instance.fail().ok();
                    self.instances.insert(full_name.clone(), instance);
                    if let Some(handle) = &self.warden_handle {
                        let _ = handle.notify_failure_blocking(&full_name);
                    }
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

        // Apply RCTL resource limits
        if !jail_def.resources.is_empty()
            && let Err(e) = crate::rctl::apply_limits(&full_name, &jail_def.resources)
        {
            eprintln!(
                "Warning: Failed to apply resource limits for '{}': {}",
                full_name, e
            );
        }

        // For VNET jails: attach the VnetSetup to the jail
        if let Some(setup) = vnet_setup {
            if let Err(e) = setup.attach_to_jail(jid) {
                eprintln!(
                    "Warning: Failed to attach VNET to jail '{}': {}",
                    full_name, e
                );
                eprintln!("VNET networking may not work correctly.");
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
        }

        if let Some(instance) = self.instances.get_mut(&full_name) {
            instance.stop().ok();
            instance.stopped().ok();
            instance.jid = None;
            instance.handle = None;
        }

        let mut cleaned_persisted_vnet = false;
        if let Some(vnet_setup) = self.vnet_setups.remove(&full_name) {
            if let Err(e) = vnet_setup.cleanup() {
                eprintln!(
                    "Warning: Failed to cleanup VNET setup for jail '{}': {}",
                    full_name, e
                );
            } else if self.verbose {
                println!("  Cleaned up VNET for bridge {}", vnet_setup.bridge_name);
            }
            let _ = self.vnet_state_store.delete(&full_name);
            cleaned_persisted_vnet = true;
        }
        if !cleaned_persisted_vnet && let Ok(Some(record)) = self.vnet_state_store.get(&full_name) {
            if let Err(e) = VnetSetup::cleanup_state(&record) {
                eprintln!(
                    "Warning: Failed to cleanup persisted VNET setup for jail '{}': {}",
                    full_name, e
                );
            }
            let _ = self.vnet_state_store.delete(&full_name);
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
