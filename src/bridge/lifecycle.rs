//! Jail lifecycle: start, stop, restart

use crate::audit::{AuditEvent, AuditRecord};
use crate::error::{Error, Result};
use crate::hooks::{HookContext, HookPhase, HookRunner};
use crate::jail::state::State as JailState;
use crate::jail::{
    JailConfig, JailHandle, JailInstance, ParamValue, jail_create, jail_create_with_descriptor,
    jail_getid, jail_remove,
};
use crate::network::{VnetConfig, VnetSetup};
use crate::scope::{ScopeMachineEvent, ScopeRecord};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Instant;
use throttle_machines::gate::Gate;
use throttle_machines::token_bucket::{TokenBucket, TokenBucketParams, TokenBucketState};

use super::Bridge;

/// Reserved params are rejected so manifests cannot bypass jail isolation.
/// `allow.` is matched by prefix: module-registered params are runtime
/// sysctl entries no header can enumerate.
pub fn is_reserved_param(key: &str) -> bool {
    use crate::sys::consts::{
        JAIL_PARAM_CHILDREN_MAX, JAIL_PARAM_DEVFS_RULESET, JAIL_PARAM_ENFORCE_STATFS,
        JAIL_PARAM_ERRMSG, JAIL_PARAM_HOST_HOSTNAME, JAIL_PARAM_IP4_ADDR, JAIL_PARAM_IP6_ADDR,
        JAIL_PARAM_JID, JAIL_PARAM_NAME, JAIL_PARAM_NOPERSIST, JAIL_PARAM_PATH, JAIL_PARAM_PERSIST,
        JAIL_PARAM_SECURELEVEL, JAIL_PARAM_VNET,
    };
    key.starts_with("allow.")
        || matches!(
            key,
            JAIL_PARAM_NAME
                | JAIL_PARAM_JID
                | JAIL_PARAM_PATH
                | JAIL_PARAM_ERRMSG
                | JAIL_PARAM_PERSIST
                | JAIL_PARAM_NOPERSIST
                | JAIL_PARAM_VNET
                | JAIL_PARAM_IP4_ADDR
                | JAIL_PARAM_IP6_ADDR
                | JAIL_PARAM_HOST_HOSTNAME
                | JAIL_PARAM_SECURELEVEL
                | JAIL_PARAM_DEVFS_RULESET
                | JAIL_PARAM_CHILDREN_MAX
                | JAIL_PARAM_ENFORCE_STATFS
        )
}

/// Build the `jail_set` parameter map shared by creation and eva.
pub(super) fn build_jail_params(
    jail_def: &crate::manifest::JailDef,
    full_name: &str,
    is_vnet: bool,
    effective_ip: Option<IpAddr>,
) -> Result<HashMap<String, ParamValue>> {
    let mut params = HashMap::new();

    for (key, value) in &jail_def.params {
        if is_reserved_param(key) {
            eprintln!("Warning: ignoring reserved jail parameter '{key}' in manifest");
            continue;
        }
        let param_value = ParamValue::try_from(value)?;
        params.insert(key.clone(), param_value);
    }

    params.insert(
        "name".to_string(),
        ParamValue::String(full_name.to_string()),
    );

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
    } else if jail_def.network.as_ref().is_some_and(|n| n.shared) {
        // Same jailsys param as `vnet` above.
        params.insert("ip4".to_string(), ParamValue::Int(libc::JAIL_SYS_INHERIT));
    }

    Ok(params)
}

/// Copies the host's resolv.conf into a shared-network jail, if it has none.
fn copy_resolv_conf_if_absent(jail_root: &std::path::Path) {
    let resolv_path = jail_root.join("etc/resolv.conf");

    if crate::blueprint::context::reject_symlink_ancestors(jail_root, &resolv_path).is_err() {
        return;
    }

    if !resolv_path.exists()
        && let Ok(content) = std::fs::read("/etc/resolv.conf")
    {
        if let Some(parent) = resolv_path.parent() {
            let _ = std::fs::create_dir_all(parent); // best-effort
        }
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&resolv_path)
        {
            use std::io::Write;
            let _ = f.write_all(&content); // best-effort
        }
    }
}
/// Mount devfs into the jail root; jail(2) ignores `mount.devfs`.
fn mount_jail_devfs(jail_def: &crate::manifest::JailDef, path: &Path) -> Result<()> {
    let devfs_ruleset = jail_def
        .devfs_ruleset
        .unwrap_or(crate::sys::DEVFS_RULESET_JAIL);
    if devfs_ruleset != 0 {
        let dev_path = path.join("dev");
        if !dev_path.join("null").exists() {
            // A missing dir surfaces as a mount_devfs error just below.
            std::fs::create_dir_all(&dev_path).ok();
            if let Err(e) = crate::sys::mount_devfs(&dev_path)
                .and_then(|()| crate::sys::apply_devfs_ruleset(&dev_path, devfs_ruleset))
            {
                crate::sys::unmount_quiet(&dev_path);
                return Err(e);
            }
        }
    }
    Ok(())
}

/// Move the jail side of a VNET pair into the live jail.
fn attach_vnet(setup: &VnetSetup, full_name: &str, jid: i32, verbose: bool) -> Result<()> {
    setup.attach_to_jail(jid).inspect_err(|e| {
        eprintln!("Error: Failed to attach VNET to jail '{full_name}': {e}");
    })?;
    if verbose {
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
    Ok(())
}

/// Run /etc/rc inside the jail (jail(2) has no exec.start). Failures only warn.
fn run_jail_rc(full_name: &str, jid: i32) {
    match crate::jail::jexec::jexec_run(jid, &["/bin/sh", "/etc/rc"]) {
        Ok(exit_code) if exit_code != 0 => {
            eprintln!("Warning: /etc/rc in jail '{full_name}' exited with {exit_code}");
        }
        Ok(_) => {}
        Err(e) => {
            eprintln!("Warning: failed to run /etc/rc in jail '{full_name}': {e}");
        }
    }
}

/// Copies a release userland into a jail root with `cp -a`.
fn copy_release(release_path: &Path, path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .map_err(|e| Error::JailOperation(format!("Failed to create jail directory: {e}")))?;

    let status = std::process::Command::new("/bin/cp")
        .arg("-a")
        .arg(format!("{}/.", release_path.display()))
        .arg(path)
        .status()
        .map_err(|e| Error::JailOperation(format!("Failed to execute cp command: {e}")))?;
    if !status.success() {
        return Err(Error::JailOperation(format!(
            "Failed to copy release: cp exited with status {status}"
        )));
    }

    // cp -a may have followed a symlink out of the parent.
    let data_parent = path.parent().unwrap_or_else(|| Path::new("/"));
    if let (Ok(canonical_path), Ok(canonical_parent)) =
        (path.canonicalize(), data_parent.canonicalize())
        && !canonical_path.starts_with(&canonical_parent)
    {
        return Err(Error::JailOperation(format!(
            "Jail path '{}' resolves to '{}' which is outside '{}'",
            path.display(),
            canonical_path.display(),
            canonical_parent.display()
        )));
    }
    Ok(())
}

/// What a `start_jail` attempt holds so far; `unwind_start` gives it back.
#[derive(Default)]
struct StartClaims {
    /// The jail's ZFS dataset was created by this attempt (not inherited from a build).
    zfs_dataset: bool,
    /// IP leased from a network pool.
    allocated_ip: Option<(String, IpAddr)>,
    /// Epair or netgraph pair, with its state record on disk.
    vnet_setup: Option<VnetSetup>,
    /// Set once jail(2) is attempted: devfs may be mounted and the jail is reported failed.
    jail_root: Option<PathBuf>,
    /// The live jail, once jail(2) succeeded.
    jid: Option<i32>,
}

/// The `post_stop` hook runner and the jail root it runs against.
type PostStopHook = (HookRunner, PathBuf);

impl Bridge {
    /// Persist the in-flight scope record. Never fails the jail operation.
    pub(super) fn persist_scope(&self, scope: &mut ScopeRecord) {
        scope.touch();
        if let Err(e) = self.scope_store.save(scope) {
            eprintln!(
                "Warning: failed to persist scope record for '{}': {}",
                scope.name, e
            );
        }
    }

    /// Apply `mutate` to the stored record. Absent records are left absent.
    fn amend_scope<F>(&self, full_name: &str, mutate: F)
    where
        F: FnOnce(&mut ScopeRecord),
    {
        match self.scope_store.get(full_name) {
            Ok(Some(mut scope)) => {
                mutate(&mut scope);
                self.persist_scope(&mut scope);
            }
            Ok(None) => {}
            Err(e) => eprintln!("Warning: failed to read scope record for '{full_name}': {e}"),
        }
    }

    /// Roll back resources allocated during a failed `start_jail`.
    fn rollback_start(
        &mut self,
        full_name: &str,
        vnet_setup: Option<VnetSetup>,
        allocated_ip: Option<&(String, IpAddr)>,
        created_zfs_dataset: bool,
    ) {
        if let Some(setup) = vnet_setup {
            match setup.cleanup() {
                Ok(()) => {
                    if let Err(e) = self.vnet_state_store.delete(full_name) {
                        eprintln!(
                            "Warning: failed to remove VNET state record for '{full_name}': {e}"
                        );
                    }
                    self.audit.record(
                        &AuditRecord::new(full_name, AuditEvent::RollbackStep)
                            .with("step", "vnet")
                            .with("outcome", "released"),
                    );
                    self.amend_scope(full_name, |scope| scope.has_vnet_record = false);
                }
                Err(e) => {
                    eprintln!(
                        "Warning: VNET cleanup failed for '{full_name}': {e} -- keeping state record for manual cleanup"
                    );
                    self.audit.record(
                        &AuditRecord::new(full_name, AuditEvent::RollbackStep)
                            .with("step", "vnet")
                            .with("outcome", "leaked")
                            .with("error", e),
                    );
                }
            }
        }
        if let Some((network_name, ip)) = allocated_ip {
            self.ip_allocator.release(network_name, ip);
            if let Err(e) = self.lease_store.release(network_name, full_name) {
                eprintln!("Warning: failed to release lease for '{full_name}': {e}");
            }
            self.audit.record(
                &AuditRecord::new(full_name, AuditEvent::RollbackStep)
                    .with("step", "lease")
                    .with("outcome", "released")
                    .with("ip", ip),
            );
            self.amend_scope(full_name, |scope| scope.allocated_ips.clear());
        }
        if created_zfs_dataset {
            eprintln!("Cleaning up ZFS dataset...");
            let outcome = match &self.zfs {
                Some(zfs) => match zfs.destroy_jail_dataset(full_name) {
                    Ok(()) => "released",
                    Err(e) => {
                        eprintln!("Warning: failed to destroy dataset for '{full_name}': {e}");
                        "leaked"
                    }
                },
                None => "skipped",
            };
            self.audit.record(
                &AuditRecord::new(full_name, AuditEvent::RollbackStep)
                    .with("step", "zfs")
                    .with("outcome", outcome),
            );
            if outcome == "released" {
                self.amend_scope(full_name, |scope| {
                    scope.zfs_dataset = None;
                    scope.zfs_origin = None;
                });
            }
        }

        self.finish_rollback(full_name);
    }

    /// Park an existing scope record in `Failed` with no live jid.
    fn mark_scope_failed(&self, full_name: &str) {
        self.amend_scope(full_name, |scope| {
            scope.jid = None;
            scope.advance_or_warn(ScopeMachineEvent::Fail);
        });
    }

    /// Drop the scope record when the rollback released everything it claimed.
    fn finish_rollback(&self, full_name: &str) {
        match self.scope_store.get(full_name) {
            Ok(Some(scope)) if !scope.holds_resources() => {
                if let Err(e) = self.scope_store.delete(full_name) {
                    eprintln!("Warning: failed to remove scope record for '{full_name}': {e}");
                }
            }
            Ok(Some(_)) => self.mark_scope_failed(full_name),
            Ok(None) => {}
            Err(e) => eprintln!("Warning: failed to read scope record for '{full_name}': {e}"),
        }
    }

    /// Mark a jail as failed and notify the Warden.
    fn mark_jail_failed(&mut self, full_name: &str, path: &std::path::Path) {
        let jail_config = JailConfig::new(full_name, path);
        let mut instance = JailInstance::new(jail_config);
        // Fresh instance: Stopped -> Starting -> Failed cannot be rejected.
        instance.start().ok();
        instance.fail().ok(); // see above
        self.instances.insert(full_name.to_string(), instance);

        match self.scope_store.get(full_name) {
            Ok(Some(_)) => self.mark_scope_failed(full_name),
            Ok(None) => {
                let mut scope = ScopeRecord::new(full_name);
                scope.advance_or_warn(ScopeMachineEvent::Fail);
                self.persist_scope(&mut scope);
            }
            Err(e) => eprintln!("Warning: failed to read scope record for '{full_name}': {e}"),
        }
        self.audit.event(full_name, AuditEvent::Failed);

        if let Some(handle) = &self.warden_handle
            && let Err(e) = handle.notify_failure(full_name)
        {
            eprintln!("Warning: failed to notify Warden about '{full_name}': {e}");
        }
    }

    /// Start all jails (or a specific one with its dependencies)
    ///
    /// Jails already running are skipped, so bringing up a jail whose
    /// dependencies are up only starts what is missing.
    pub fn up(&mut self, jail: Option<&str>) -> Result<()> {
        for name in &self.jails_for_up(jail)? {
            if self.is_running(name)? {
                println!("Jail '{name}' is already running");
                continue;
            }
            self.start_jail(name)?;
        }

        Ok(())
    }

    /// Stop all jails (or a specific one with its dependents)
    ///
    /// Jails already stopped are skipped.
    pub fn down(&mut self, jail: Option<&str>) -> Result<()> {
        self.down_and_report(jail).map(|_| ())
    }

    /// Stop what `down` would stop, returning the jails actually stopped in
    /// stop order.
    fn down_and_report(&mut self, jail: Option<&str>) -> Result<Vec<String>> {
        let plan = self.down_plan(jail)?;

        for name in &plan.isolate {
            self.isolate_jail(name);
        }

        let mut stopped = Vec::new();
        for name in &plan.stop {
            if !self.is_running(name)? {
                println!("Jail '{name}' is not running");
                continue;
            }
            self.stop_jail(name)?;
            stopped.push(name.clone());
        }

        Ok(stopped)
    }

    fn is_running(&self, name: &str) -> Result<bool> {
        let (_, full_name) = self.resolve_jail_names(name)?;
        Ok(jail_getid(&full_name).is_ok())
    }

    /// Fence a dependent off at the firewall without stopping it. The anchor is
    /// left loaded until the jail exits and `gc` reports it.
    fn isolate_jail(&self, name: &str) {
        let Ok((service_name, full_name)) = self.resolve_jail_names(name) else {
            return;
        };

        if !crate::bulkhead::pf_enabled() {
            eprintln!("Warning: cannot isolate jail '{full_name}': PF is not enabled");
            return;
        }

        let Some(jail_def) = self.config.get_jail(&service_name) else {
            return;
        };
        let ips = self.drainable_ips(&full_name, jail_def);
        match crate::bulkhead::load_drain_anchor(&self.config.config.data_dir, &full_name, &ips) {
            Ok(anchor) => {
                println!("Isolated jail '{full_name}': new connections blocked via {anchor}");
                if let Ok(Some(mut scope)) = self.scope_store.get(&full_name) {
                    scope.drain_anchor = Some(anchor.clone());
                    self.persist_scope(&mut scope);
                }
                self.audit.record(
                    &AuditRecord::new(&full_name, AuditEvent::DrainStart)
                        .with("anchor", &anchor)
                        .with("cascade", "isolate"),
                );
            }
            Err(e) => eprintln!("Warning: failed to isolate jail '{full_name}': {e}"),
        }
    }

    /// Restart jails
    ///
    /// Dependents that `down` cascaded through come back up too, in start
    /// order (the reverse of stop order).
    pub fn restart(&mut self, jail: Option<&str>) -> Result<()> {
        let stopped = self.down_and_report(jail)?;
        self.up(jail)?;
        for name in stopped.iter().rev() {
            if !self.is_running(name)? {
                self.start_jail(name)?;
            }
        }
        Ok(())
    }

    /// Restart a jail (stop then start)
    ///
    /// Used by the Warden for automatic restart on failure
    pub fn restart_jail(&mut self, name: &str) -> Result<()> {
        let (service_name, full_name) = self.resolve_jail_names(name)?;
        println!("Restarting jail '{full_name}'...");

        if let Some(instance) = self.instances.get_mut(&full_name)
            && instance.state() == JailState::Failed
        {
            instance.recover().ok(); // guarded by the Failed check, cannot be rejected
        }

        if jail_getid(&full_name).is_ok() {
            self.stop_jail(&service_name)?;
        }

        self.start_jail(&service_name)?;

        println!("Jail '{full_name}' restarted successfully");
        Ok(())
    }

    /// Start a single jail with cleanup on failure
    pub(super) fn start_jail(&mut self, name: &str) -> Result<()> {
        const REFILL_RATE: f64 = 1.0;

        self.prepare_runtime()?;

        // Rate limiting to prevent thundering herd on `up --all`
        let capacity = self.jail_start_capacity;

        loop {
            let mut state = self
                .rate_limiter
                .lock()
                .expect("rate limiter mutex poisoned");
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

        let mut scope = ScopeRecord::new(&full_name);
        scope.cascade = jail_def.cascade;
        scope.ephemeral = jail_def.ephemeral.unwrap_or(false);
        self.persist_scope(&mut scope);
        self.audit.event(&full_name, AuditEvent::Created);

        let mut claims = StartClaims::default();
        if let Err(e) = self.provision_and_start(&service_name, &full_name, &mut scope, &mut claims)
        {
            self.unwind_start(&full_name, claims);
            return Err(e);
        }
        Ok(())
    }

    /// Everything `start_jail` does once the scope record exists. Each resource
    /// lands in `claims` as soon as it is held, so `start_jail` can unwind it.
    fn provision_and_start(
        &mut self,
        service_name: &str,
        full_name: &str,
        scope: &mut ScopeRecord,
        claims: &mut StartClaims,
    ) -> Result<()> {
        let jail_def = self
            .config
            .get_jail(service_name)
            .ok_or_else(|| Error::JailNotFound(service_name.to_string()))?;

        let path = self.claim_jail_root(jail_def, full_name, scope, claims)?;
        self.prepare_jail_root(jail_def, full_name, &path)?;

        // Phase 3: the IP. Inline because `jail_def` borrows `self.config`.
        let effective_ip: Option<IpAddr> = if let Some(network) = &jail_def.network {
            if let Some(static_ip) = network.ip {
                if let Some(net_name) = network
                    .networks
                    .iter()
                    .find(|net_name| !self.runtime_networks.contains_key(*net_name))
                {
                    return Err(Error::Network(format!(
                        "Jail '{full_name}' references unknown network '{net_name}'"
                    )));
                }
                Some(static_ip)
            } else if let Some(first_network) = network.networks.first() {
                let ip = crate::network::allocate_and_record(
                    &mut self.ip_allocator,
                    &self.lease_store,
                    first_network,
                    full_name,
                )?;
                claims.allocated_ip = Some((first_network.clone(), ip));
                scope.allocated_ips.push(ip);
                self.persist_scope(scope);
                self.audit.record(
                    &AuditRecord::new(full_name, AuditEvent::Provisioned)
                        .with("step", "lease")
                        .with("ip", ip)
                        .with("network", first_network),
                );
                if self.verbose {
                    println!("  Auto-allocated IP {ip} from network '{first_network}'");
                }
                Some(ip)
            } else {
                None
            }
        } else {
            None
        };

        let hook_runner = HookRunner::new(jail_def.hooks.clone()).verbose(self.verbose);
        let mut hook_context = HookContext::new(full_name, &path);

        if let Some(ip) = effective_ip {
            hook_context = hook_context.with_ip(ip.to_string());
        }

        hook_runner.execute_phase(HookPhase::PreStart, &hook_context)?;

        let is_vnet = jail_def.network.as_ref().is_some_and(|n| n.vnet);

        if is_vnet && let Some(network) = &jail_def.network {
            self.claim_vnet(network, full_name, effective_ip, scope, claims)?;
        }

        let params = build_jail_params(jail_def, full_name, is_vnet, effective_ip)?;

        mount_jail_devfs(jail_def, &path)?;

        if jail_def.network.as_ref().is_some_and(|n| n.shared) {
            copy_resolv_conf_if_absent(&path);
        }

        let (jid, jail_handle) = self.create_jail(full_name, &path, &params, scope, claims)?;
        self.apply_startup_limits(jail_def, service_name, full_name, jid, scope)?;

        if let Some(setup) = &claims.vnet_setup {
            attach_vnet(setup, full_name, jid, self.verbose)?;
        }

        // Nothing past this point fails: hand the claims over to the bridge.
        if let Some(setup) = claims.vnet_setup.take() {
            self.vnet_setups.insert(full_name.to_string(), setup);
        }
        if let Some(alloc) = claims.allocated_ip.take() {
            self.allocated_ips.insert(full_name.to_string(), alloc);
        }

        // After networking, so services can bind their addresses.
        if jail_def.init.unwrap_or(true) {
            run_jail_rc(full_name, jid);
        }

        let hook_context = hook_context.with_jid(jid);

        if let Err(e) = hook_runner.execute_phase(HookPhase::PostStart, &hook_context) {
            eprintln!("Warning: post_start hook failed for jail '{full_name}': {e}");
            eprintln!("Jail is running but may not be fully configured.");
        }

        let mut jail_config = JailConfig::new(full_name, &path);
        if let Some(hostname) = &jail_def.hostname {
            jail_config = jail_config.hostname(hostname);
        }
        if let Some(ip) = effective_ip {
            jail_config = jail_config.ip(ip);
        }
        self.record_running(full_name, jail_config, jid, jail_handle, scope);

        Ok(())
    }

    /// Phase 1: the jail root; a dataset created here is claimed first.
    fn claim_jail_root(
        &self,
        jail_def: &crate::manifest::JailDef,
        full_name: &str,
        scope: &mut ScopeRecord,
        claims: &mut StartClaims,
    ) -> Result<PathBuf> {
        // Create ZFS dataset if needed (a prior `build` may already own it).
        // A clone-ready release provisions the whole root in one zfs clone.
        let path = if let Some(zfs) = &self.zfs {
            if jail_def.path.is_none() {
                if zfs.jail_dataset_exists(full_name)? {
                    zfs.jail_path(full_name)
                } else if let Some(release) = jail_def
                    .release
                    .as_ref()
                    .filter(|release| zfs.release_is_cloneable(release))
                {
                    println!("Provisioning jail '{full_name}' by cloning release '{release}'...");
                    let path = zfs.clone_jail_from_release(release, full_name)?;
                    claims.zfs_dataset = true;
                    path
                } else {
                    let path = zfs.create_jail_dataset(full_name)?;
                    claims.zfs_dataset = true;
                    path
                }
            } else {
                jail_def.effective_path(&self.config.config, full_name)
            }
        } else {
            jail_def.effective_path(&self.config.config, full_name)
        };

        if claims.zfs_dataset
            && let Some(zfs) = &self.zfs
        {
            let dataset = zfs.jail_dataset_name(full_name);
            scope.zfs_origin = zfs.dataset_origin(&dataset);
            scope.zfs_dataset = Some(dataset.clone());
            scope.ephemeral = jail_def.ephemeral.unwrap_or(true);
            self.persist_scope(scope);
            self.audit.record(
                &AuditRecord::new(full_name, AuditEvent::Provisioned)
                    .with("step", "zfs")
                    .with("dataset", dataset),
            );
        }

        Ok(path)
    }

    /// Phase 2: symlink checks, userland, DNS. Claims nothing.
    fn prepare_jail_root(
        &self,
        jail_def: &crate::manifest::JailDef,
        full_name: &str,
        path: &Path,
    ) -> Result<()> {
        // Validate no ancestor of the jail path is a symlink
        if let Some(parent) = path.parent()
            && parent.exists()
        {
            crate::blueprint::context::reject_symlink_ancestors(
                &self.config.config.data_dir,
                path,
            )?;
        }

        // A pre-existing symlink here would redirect jail ops to arbitrary host paths.
        if let Ok(meta) = std::fs::symlink_metadata(path)
            && meta.file_type().is_symlink()
        {
            return Err(Error::JailOperation(format!(
                "Jail path '{}' is a symlink, refusing to use it",
                path.display()
            )));
        }

        // Auto-provision from release when the root is missing or empty.
        // A freshly created ZFS dataset exists but holds no userland, so
        // checking for ./bin instead of bare existence catches both cases.
        if !path.join("bin").exists() {
            let Some(release) = &jail_def.release else {
                return Err(Error::JailPathNotFound(path.to_path_buf()));
            };
            crate::manifest::validate_name("release", release)?;
            let release_path = self.config.config.releases_dir.join(release);
            if !release_path.exists() {
                return Err(Error::JailOperation(format!(
                    "Release '{}' not found at {}. Run 'blackship bootstrap {}' first.",
                    release,
                    release_path.display(),
                    release
                )));
            }
            println!("Provisioning jail '{full_name}' from release '{release}'...");
            if let Err(e) = copy_release(&release_path, path) {
                // Rollback; keep the original error.
                let _ = std::fs::remove_dir_all(path);
                return Err(e);
            }
            println!("Jail '{full_name}' provisioned from release '{release}'");
        }

        // Configure DNS before starting the jail
        if let Some(network) = &jail_def.network {
            super::dns::configure_dns(path, &network.dns)?;
        }

        Ok(())
    }

    /// The bridge name and VNET config a jail asks for. Claims nothing.
    fn vnet_config_for(
        &self,
        network: &crate::manifest::JailNetworkConfig,
        full_name: &str,
        effective_ip: Option<IpAddr>,
    ) -> Result<(String, VnetConfig)> {
        let primary_runtime_network = network
            .networks
            .first()
            .map(|network_name| {
                self.runtime_networks
                    .get(network_name)
                    .cloned()
                    .ok_or_else(|| {
                        Error::Network(format!(
                            "Jail '{full_name}' references unknown network '{network_name}'"
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
                    "VNET jail '{full_name}' requires a bridge configuration"
                ))
            })?;

        let ip_config = if let Some(ip_cidr) = network.ip_cidr.clone() {
            ip_cidr
        } else {
            let ip = network.ip.or(effective_ip).ok_or_else(|| {
                Error::Network(format!(
                    "VNET jail '{full_name}' requires an IP address or attached network"
                ))
            })?;
            let prefix_len = primary_runtime_network
                .as_ref()
                .map_or(24, |runtime| runtime.subnet.prefix_len());
            format!("{ip}/{prefix_len}")
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
                    "VNET jail '{full_name}' requires a gateway or attached network"
                ))
            })?;

        let mut vnet_config = VnetConfig::new(bridge_name.clone(), ip_config, gateway);

        if let Some(ref mac) = network.mac_address {
            vnet_config = vnet_config.with_mac_address(mac.clone());
        }

        if let Some(vlan_id) = network.vlan_id {
            vnet_config = vnet_config.with_vlan_id(vlan_id);
        }

        // Explicit backend wins, else inherit the attached network's.
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

        Ok((bridge_name, vnet_config))
    }

    /// Phase 4: create the VNET pair, claimed before its state record is written.
    fn claim_vnet(
        &self,
        network: &crate::manifest::JailNetworkConfig,
        full_name: &str,
        effective_ip: Option<IpAddr>,
        scope: &mut ScopeRecord,
        claims: &mut StartClaims,
    ) -> Result<()> {
        let (bridge_name, vnet_config) = self.vnet_config_for(network, full_name, effective_ip)?;

        let setup = claims
            .vnet_setup
            .insert(VnetSetup::create(full_name, vnet_config)?);

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
            setup.state_record(full_name, network.networks.first().map(String::as_str));
        self.vnet_state_store.save(&state_record)?;

        scope.has_vnet_record = true;
        self.persist_scope(scope);
        self.audit.record(
            &AuditRecord::new(full_name, AuditEvent::Provisioned)
                .with("step", "vnet")
                .with("host_interface", setup.host_interface())
                .with("bridge", &bridge_name),
        );

        Ok(())
    }

    /// Phase 5: jail(2). Claims the root before the attempt, the jid after.
    fn create_jail(
        &self,
        full_name: &str,
        path: &Path,
        params: &HashMap<String, ParamValue>,
        scope: &mut ScopeRecord,
        claims: &mut StartClaims,
    ) -> Result<(i32, JailHandle)> {
        println!("Starting jail '{full_name}'...");
        // Owning descriptors are only useful while a long-lived supervisor
        // process keeps them open. For one-shot CLI commands like `up`, using
        // an owning descriptor would remove the jail as soon as blackship exits.
        let use_descriptors =
            self.os_version.supports_jail_descriptors() && self.warden_handle.is_some();
        claims.jail_root = Some(path.to_path_buf());
        let created = if use_descriptors {
            jail_create_with_descriptor(path, params)
                .map(|(jid, fd)| (jid, JailHandle::Descriptor { fd, jid }))
        } else {
            jail_create(path, params).map(|jid| (jid, JailHandle::Jid(jid)))
        };
        let (jid, jail_handle) =
            created.inspect_err(|e| eprintln!("Failed to create jail '{full_name}': {e}"))?;
        claims.jid = Some(jid);
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

        scope.jid = Some(jid);
        self.persist_scope(scope);
        self.audit.record(
            &AuditRecord::new(full_name, AuditEvent::Provisioned)
                .with("step", "jail_create")
                .with("jid", jid),
        );

        Ok((jid, jail_handle))
    }

    /// Phase 6: rctl limits and CPU pinning. Fails closed.
    fn apply_startup_limits(
        &self,
        jail_def: &crate::manifest::JailDef,
        service_name: &str,
        full_name: &str,
        jid: i32,
        scope: &mut ScopeRecord,
    ) -> Result<()> {
        // Fail closed: never run without the configured resource limits.
        let startup_profile = jail_def.startup_resources();
        if !startup_profile.is_empty() {
            crate::rctl::apply_limits(full_name, startup_profile).inspect_err(|e| {
                eprintln!("Failed to apply resource limits for '{full_name}': {e}, stopping jail");
            })?;

            scope.rctl_subject = Some(format!("jail:{full_name}"));
            if jail_def.qos.is_some() {
                scope.qos_phase = crate::scope::QosPhase::Startup;
            }
            self.persist_scope(scope);
            self.audit.record(
                &AuditRecord::new(full_name, AuditEvent::Provisioned)
                    .with("step", "rctl")
                    .with(
                        "qos_phase",
                        if jail_def.qos.is_some() {
                            "startup"
                        } else {
                            "none"
                        },
                    ),
            );
        }

        // Pin the jail to its CPU set, spreading across other jails' pins.
        let other_pins = self.other_cpuset_pins(service_name);
        if let Some(cpu_list) = crate::rctl::resolve_cpu_list(startup_profile, other_pins) {
            crate::rctl::apply_cpuset(jid, &cpu_list).inspect_err(|e| {
                eprintln!("Failed to pin jail '{full_name}' to CPUs: {e}, stopping jail");
            })?;
            println!("  Pinned to CPUs: {cpu_list}");
            scope.cpuset = Some(cpu_list.clone());
            self.persist_scope(scope);
            self.audit.record(
                &AuditRecord::new(full_name, AuditEvent::Provisioned)
                    .with("step", "cpuset")
                    .with("cpus", &cpu_list),
            );
        }

        Ok(())
    }

    /// Last phase: track the instance, finish the scope record, tell the Warden.
    fn record_running(
        &mut self,
        full_name: &str,
        jail_config: JailConfig,
        jid: i32,
        jail_handle: JailHandle,
        scope: &mut ScopeRecord,
    ) {
        let mut instance = JailInstance::new(jail_config);
        instance.jid = Some(jid);
        instance.handle = Some(jail_handle);
        // Fresh instance: Stopped -> Starting -> Running cannot be rejected.
        instance.start().ok();
        instance.started().ok(); // see above
        self.instances.insert(full_name.to_string(), instance);

        scope.advance_or_warn(ScopeMachineEvent::Provisioned);
        self.persist_scope(scope);
        self.audit
            .record(&AuditRecord::new(full_name, AuditEvent::Running).with("jid", jid));

        if let Some(handle) = &self.warden_handle
            && let Err(e) = handle.notify_started(full_name)
        {
            eprintln!("Warning: Failed to notify Warden of jail start: {e}");
        }
    }

    /// Release what a failed `provision_and_start` claimed, newest first.
    /// A jail that refuses to die keeps everything.
    fn unwind_start(&mut self, full_name: &str, claims: StartClaims) {
        if let (Some(jid), Some(root)) = (claims.jid, &claims.jail_root)
            && let Err(e) = jail_remove(jid)
        {
            eprintln!(
                "Warning: Failed to remove jail '{full_name}' (JID {jid}) during rollback: {e}"
            );
            self.mark_jail_failed(full_name, root);
            return;
        }
        if let Some(root) = &claims.jail_root {
            crate::sys::unmount_jail_devfs(root);
        }
        self.rollback_start(
            full_name,
            claims.vnet_setup,
            claims.allocated_ip.as_ref(),
            claims.zfs_dataset,
        );
        if let Some(root) = &claims.jail_root {
            self.mark_jail_failed(full_name, root);
        }
    }

    /// CPU pins already claimed by every jail other than `service_name`.
    pub(super) fn other_cpuset_pins<'a>(
        &'a self,
        service_name: &'a str,
    ) -> impl Iterator<Item = &'a str> {
        self.config
            .jails
            .iter()
            .filter(move |other| other.name != service_name)
            .filter_map(|other| other.startup_resources().cpuset.as_deref())
    }

    /// Addresses a draining jail can still be reached on.
    fn drainable_ips(&self, full_name: &str, jail_def: &crate::manifest::JailDef) -> Vec<IpAddr> {
        let mut ips: Vec<IpAddr> = Vec::new();

        if let Some(network) = &jail_def.network
            && let Some(ip) = network.ip
        {
            ips.push(ip);
        }

        if let Some((_, ip)) = self.allocated_ips.get(full_name) {
            ips.push(*ip);
        }

        if let Ok(Some(scope)) = self.scope_store.get(full_name) {
            ips.extend(scope.allocated_ips);
        }

        ips.sort();
        ips.dedup();
        ips
    }

    /// Refuse new connections and wait for in-flight ones. Returns the anchor.
    fn drain_connections(
        &self,
        full_name: &str,
        jail_def: &crate::manifest::JailDef,
    ) -> Option<String> {
        let drain = jail_def.drain.as_ref()?;
        if !drain.enabled {
            return None;
        }

        if !crate::bulkhead::pf_enabled() {
            eprintln!("Warning: PF is not enabled; skipping connection drain for '{full_name}'");
            return None;
        }

        let ips = self.drainable_ips(full_name, jail_def);
        if ips.is_empty() {
            eprintln!("Warning: no recorded address for '{full_name}'; skipping connection drain");
            return None;
        }

        let anchor = match crate::bulkhead::load_drain_anchor(
            &self.config.config.data_dir,
            full_name,
            &ips,
        ) {
            Ok(anchor) => anchor,
            Err(e) => {
                eprintln!(
                    "Warning: failed to load drain rules for '{full_name}': {e} -- stopping without drain"
                );
                return None;
            }
        };

        self.amend_scope(full_name, |scope| {
            scope.advance_or_warn(ScopeMachineEvent::Drain);
            scope.drain_anchor = Some(anchor.clone());
        });
        self.audit.record(
            &AuditRecord::new(full_name, AuditEvent::DrainStart)
                .with("anchor", &anchor)
                .with("timeout_secs", drain.timeout_secs),
        );

        println!(
            "Draining connections to '{}' (timeout {}s)...",
            full_name, drain.timeout_secs
        );

        let deadline = Instant::now() + std::time::Duration::from_secs(drain.timeout_secs);
        let mut remaining = usize::MAX;
        while Instant::now() < deadline {
            remaining = ips
                .iter()
                .map(|ip| crate::bulkhead::tcp_state_count(*ip))
                .sum();
            if remaining == 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }

        let timed_out = remaining != 0;
        if timed_out {
            eprintln!(
                "Warning: '{}' still had {} TCP state(s) after {}s; proceeding with stop",
                full_name, remaining, drain.timeout_secs
            );
        } else if self.verbose {
            println!("  All TCP states for '{full_name}' closed");
        }

        self.audit.record(
            &AuditRecord::new(full_name, AuditEvent::DrainEnd)
                .with("anchor", &anchor)
                .with("residual_states", remaining)
                .with("timed_out", timed_out),
        );

        Some(anchor)
    }

    /// Drop the drain anchor. Required on every path out of `stop_jail`.
    fn end_drain(&self, full_name: &str, anchor: Option<&str>) {
        let Some(anchor) = anchor else {
            return;
        };
        crate::bulkhead::flush_drain_anchor(anchor);
        self.amend_scope(full_name, |scope| scope.drain_anchor = None);
    }

    pub(super) fn stop_jail(&mut self, name: &str) -> Result<()> {
        let (service_name, full_name) = self.resolve_jail_names(name)?;

        // A held handle is authoritative: resolving the name again would race
        // against jid reuse.
        let handle_jid = self
            .instances
            .get(&full_name)
            .and_then(|instance| instance.handle.as_ref())
            .map(JailHandle::jid);

        let jid = match handle_jid {
            Some(jid) => jid,
            None => match jail_getid(&full_name) {
                Ok(jid) => jid,
                Err(_) => {
                    return Err(Error::JailNotRunning(full_name));
                }
            },
        };

        self.amend_scope(&full_name, |scope| {
            scope.advance_or_warn(ScopeMachineEvent::Terminate);
        });
        self.audit
            .record(&AuditRecord::new(&full_name, AuditEvent::Terminating).with("jid", jid));

        // Remove RCTL limits before stopping
        crate::rctl::remove_limits(&full_name);
        self.amend_scope(&full_name, |scope| scope.rctl_subject = None);

        if self
            .config
            .get_jail(&service_name)
            .and_then(|def| def.drain.as_ref())
            .is_some_and(|drain| drain.enabled)
            && let Some(instance) = self.instances.get_mut(&full_name)
        {
            instance.drain().ok(); // only valid from Running; otherwise nothing to drain
        }

        let (post_stop_hook, drain_anchor) = self.quiesce_jail(&service_name, &full_name, jid)?;

        if let Some(handle) = &self.warden_handle {
            handle.mark_stop_requested(jid);
        }

        println!("Stopping jail '{full_name}'...");
        let owned_handle = self
            .instances
            .get_mut(&full_name)
            .and_then(|instance| instance.handle.take());
        let remove_result = match owned_handle {
            Some(JailHandle::Descriptor { fd, .. }) => fd.remove(),
            _ => jail_remove(jid),
        };
        if let Err(e) = remove_result {
            if let Some(handle) = &self.warden_handle {
                handle.clear_stop_requested(jid);
            }
            self.end_drain(&full_name, drain_anchor.as_deref());
            return Err(e);
        }
        println!("Jail '{full_name}' stopped");

        self.end_drain(&full_name, drain_anchor.as_deref());

        if let Some(handle) = &self.warden_handle
            && let Err(e) = handle.notify_stopped(&full_name, jid)
        {
            handle.clear_stop_requested(jid);
            eprintln!("Warning: Failed to notify Warden of jail stop: {e}");
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
            // The jail is gone either way; a rejected transition is harmless.
            instance.stop().ok();
            instance.stopped().ok(); // see above
            instance.jid = None;
            instance.handle = None;
        }

        let leaked_resources = self.release_vnet_on_stop(&full_name);

        self.release_ip_on_stop(&full_name);

        // The scope record is the GC work-list: a leak keeps it alive in `Failed`.
        let peaks = self.peak_details(&full_name);
        let destroyed = |mut record: AuditRecord| -> AuditRecord {
            record.detail.extend(peaks.iter().cloned());
            record
        };

        if leaked_resources {
            self.mark_scope_failed(&full_name);
            self.audit.record(&destroyed(
                AuditRecord::new(&full_name, AuditEvent::Destroyed).with("residual", "true"),
            ));
        } else {
            self.audit.record(&destroyed(
                AuditRecord::new(&full_name, AuditEvent::Destroyed).with("jid", jid),
            ));
            if let Err(e) = self.scope_store.delete(&full_name) {
                eprintln!("Warning: failed to remove scope record for '{full_name}': {e}");
            }
        }

        stop_result
    }

    /// `pre_stop` hooks, drain, stop command and `rc.shutdown`; returns the
    /// `post_stop` hook and the drain anchor.
    fn quiesce_jail(
        &self,
        service_name: &str,
        full_name: &str,
        jid: i32,
    ) -> Result<(Option<PostStopHook>, Option<String>)> {
        let Some(jail_def) = self.config.get_jail(service_name) else {
            return Ok((None, None));
        };

        let path = jail_def.effective_path(&self.config.config, full_name);
        let hook_runner = HookRunner::new(jail_def.hooks.clone()).verbose(self.verbose);
        let mut hook_context = HookContext::new(full_name, &path).with_jid(jid);

        if let Some(network) = &jail_def.network
            && let Some(ip) = &network.ip
        {
            hook_context = hook_context.with_ip(ip.to_string());
        }

        hook_runner.execute_phase(HookPhase::PreStop, &hook_context)?;

        let drain_anchor = self.drain_connections(full_name, jail_def);

        if let Some(stop_cmd) = jail_def.resolve_stop()
            && let Ok(exit_code) = crate::jail::jexec::jexec_run(jid, &["/bin/sh", "-c", &stop_cmd])
            && exit_code != 0
        {
            eprintln!("Warning: stop command in jail '{full_name}' exited with {exit_code}");
        }

        if jail_def.init.unwrap_or(true)
            && let Ok(exit_code) =
                crate::jail::jexec::jexec_run(jid, &["/bin/sh", "/etc/rc.shutdown"])
            && exit_code != 0
        {
            eprintln!("Warning: /etc/rc.shutdown in jail '{full_name}' exited with {exit_code}");
        }

        Ok((Some((hook_runner, path)), drain_anchor))
    }

    /// Tear down the jail's VNET pair; returns whether anything leaked.
    fn release_vnet_on_stop(&mut self, full_name: &str) -> bool {
        let mut leaked_resources = false;
        if let Some(vnet_setup) = self.vnet_setups.remove(full_name) {
            match vnet_setup.cleanup() {
                Ok(()) => {
                    if let Err(e) = self.vnet_state_store.delete(full_name) {
                        eprintln!(
                            "Warning: failed to remove VNET state record for '{full_name}': {e}"
                        );
                    }
                    if self.verbose {
                        println!("  Cleaned up VNET for bridge {}", vnet_setup.bridge_name);
                    }
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Failed to cleanup VNET setup for jail '{full_name}': {e} -- keeping state record for manual cleanup"
                    );
                    leaked_resources = true;
                }
            }
        } else if let Ok(Some(record)) = self.vnet_state_store.get(full_name) {
            match VnetSetup::cleanup_state(&record) {
                Ok(()) => {
                    if let Err(e) = self.vnet_state_store.delete(full_name) {
                        eprintln!(
                            "Warning: failed to remove VNET state record for '{full_name}': {e}"
                        );
                    }
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Failed to cleanup persisted VNET setup for jail '{full_name}': {e} -- keeping state record for manual cleanup"
                    );
                    leaked_resources = true;
                }
            }
        }

        leaked_resources
    }

    /// Return the jail's IP lease(s) to the pool.
    fn release_ip_on_stop(&mut self, full_name: &str) {
        if let Some((network_name, ip)) = self.allocated_ips.remove(full_name) {
            self.ip_allocator.release(&network_name, &ip);
            if let Err(e) = self.lease_store.release(&network_name, full_name) {
                eprintln!("Warning: failed to release lease for '{full_name}': {e}");
            }
            if self.verbose {
                println!("  Released IP {ip} back to network '{network_name}'");
            }
        } else if let Err(e) = self.lease_store.release_owner(full_name) {
            eprintln!("Warning: failed to release leases for '{full_name}': {e}");
        }
    }

    /// Force cleanup of a failed jail
    pub fn cleanup(&mut self, name: &str, force: bool) -> Result<()> {
        let (service_name, full_name) = self.resolve_jail_names(name)?;
        println!("Cleaning up jail '{full_name}'...");

        let jail_def = self.config.get_jail(&service_name);

        if let Ok(jid) = jail_getid(&full_name) {
            println!("  Removing jail (JID {jid})...");
            if let Err(e) = jail_remove(jid) {
                if force {
                    eprintln!("  Warning: Failed to remove jail: {e}");
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
                    eprintln!("  Warning: Failed to destroy dataset: {e}");
                } else {
                    return Err(e);
                }
            }
        }

        self.instances.remove(&full_name);

        if let Some(vnet_setup) = self.vnet_setups.remove(&full_name) {
            println!("  Cleaning up VNET setup...");
            if let Err(e) = vnet_setup.cleanup() {
                if force {
                    eprintln!("  Warning: Failed to cleanup VNET setup: {e}");
                } else {
                    return Err(e);
                }
            }
            if let Err(e) = self.vnet_state_store.delete(&full_name) {
                eprintln!("  Warning: Failed to remove VNET state record: {e}");
            }
        } else if let Ok(Some(record)) = self.vnet_state_store.get(&full_name) {
            println!("  Cleaning up persisted VNET state...");
            if let Err(e) = VnetSetup::cleanup_state(&record) {
                if force {
                    eprintln!("  Warning: Failed to cleanup persisted VNET state: {e}");
                } else {
                    return Err(e);
                }
            }
            if let Err(e) = self.vnet_state_store.delete(&full_name) {
                eprintln!("  Warning: Failed to remove VNET state record: {e}");
            }
        }

        if let Some((network_name, ip)) = self.allocated_ips.remove(&full_name) {
            self.ip_allocator.release(&network_name, &ip);
            if let Err(e) = self.lease_store.release(&network_name, &full_name) {
                eprintln!("  Warning: Failed to release lease: {e}");
            }
            println!("  Released IP {ip} back to network '{network_name}'");
        } else {
            let released = self.lease_store.release_owner(&full_name)?;
            for (network_name, ip) in released {
                println!("  Released IP {ip} back to network '{network_name}'");
            }
        }

        self.audit
            .record(&AuditRecord::new(&full_name, AuditEvent::Destroyed).with("via", "cleanup"));
        if let Err(e) = self.scope_store.delete(&full_name) {
            eprintln!("Warning: failed to remove scope record for '{full_name}': {e}");
        }

        println!("Cleanup complete for jail '{full_name}'");
        Ok(())
    }
}
