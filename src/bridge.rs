//! Bridge for managing jail lifecycle and dependencies
//!
//! Handles:
//! - Building dependency graphs from configuration
//! - Starting jails in correct order (topological sort)
//! - Stopping jails in reverse order
//! - Managing ZFS datasets if enabled

use crate::bulkhead::{BulkheadManager, PortForward};
use crate::error::{Error, Result};
use crate::hooks::{HookContext, HookPhase, HookRunner};
use crate::jail::{
    jail_create, jail_getid, jail_remove, JailConfig, JailInstance, ParamValue,
};
use crate::jail::state::State as JailState;
use crate::manifest::{BlackshipConfig, DnsConfig};
use crate::network::{IpAllocator, IpPool, VnetConfig, VnetSetup};
use crate::warden::WardenHandle;
use crate::zfs::ZfsManager;
use ipnet::IpNet;
use std::net::IpAddr;

use petgraph::algo::toposort;
use petgraph::graph::DiGraph;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;
use throttle_machines::token_bucket;

/// Bridge for managing jails
pub struct Bridge {
    /// Loaded configuration
    config: BlackshipConfig,

    /// Dependency graph (jail name -> node index)
    graph: DiGraph<String, ()>,

    /// ZFS manager (if enabled)
    zfs: Option<ZfsManager>,

    /// Bulkhead manager for PF firewall rules
    bulkhead: BulkheadManager,

    /// IP allocator for automatic IP assignment from network pools
    ip_allocator: IpAllocator,

    /// Map of jail name to allocated IP (for cleanup on stop)
    allocated_ips: HashMap<String, (String, IpAddr)>,

    /// Running jail instances
    instances: HashMap<String, JailInstance>,

    /// Verbose output mode
    verbose: bool,

    /// Rate limiter state for jail starts (tokens, last_refill)
    rate_limiter: Mutex<(f64, Instant)>,

    /// Rate limiter start time for consistent timing
    rate_limiter_epoch: Instant,

    /// Rate limiter capacity for jail starts
    jail_start_capacity: f64,

    /// Optional handle to notify the Warden of jail events
    warden_handle: Option<WardenHandle>,

    /// VNET setups for VNET jails (jail name -> VnetSetup)
    vnet_setups: HashMap<String, VnetSetup>,
}

impl Bridge {
    /// Create a new bridge from configuration
    pub fn new(config: BlackshipConfig) -> Result<Self> {
        let mut graph = DiGraph::new();
        let mut node_map = HashMap::new();

        // Add nodes for each jail
        for jail in &config.jails {
            let idx = graph.add_node(jail.name.clone());
            node_map.insert(jail.name.clone(), idx);
        }

        // Add edges for dependencies (dep -> jail)
        for jail in &config.jails {
            let to = node_map[&jail.name];
            for dep in &jail.depends_on {
                let from = node_map
                    .get(dep)
                    .ok_or_else(|| Error::UnknownDependency(dep.clone()))?;
                graph.add_edge(*from, to, ());
            }
        }

        // Initialize ZFS manager if enabled
        let zfs = if config.config.zfs_enabled {
            let pool = config.config.zpool.as_ref().ok_or(Error::ZfsNotEnabled)?;
            let zfs = ZfsManager::new(pool, &config.config.dataset);
            zfs.init()?;
            Some(zfs)
        } else {
            None
        };

        // Initialize bulkhead manager for PF firewall rules
        let bulkhead = BulkheadManager::new();

        // Initialize IP allocator from network configurations
        let mut ip_allocator = IpAllocator::new();
        for network in &config.networks {
            let subnet: IpNet = network.subnet.parse().map_err(|e| {
                Error::Network(format!(
                    "Invalid subnet '{}' for network '{}': {}",
                    network.subnet, network.name, e
                ))
            })?;

            let pool = if let Some(gateway) = network.gateway {
                IpPool::with_gateway(subnet, gateway)?
            } else {
                IpPool::new(subnet)?
            };

            ip_allocator.add_pool(network.name.clone(), pool);
        }

        let jail_start_capacity = config.config.rate_limit.jail_start_capacity;
        let now = Instant::now();
        Ok(Self {
            config,
            graph,
            zfs,
            bulkhead,
            ip_allocator,
            allocated_ips: HashMap::new(),
            instances: HashMap::new(),
            verbose: false,
            rate_limiter: Mutex::new((jail_start_capacity, now)), // Start with full capacity
            rate_limiter_epoch: now,
            jail_start_capacity,
            warden_handle: None,
            vnet_setups: HashMap::new(),
        })
    }

    /// Enable verbose output
    pub fn verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Set a Warden handle for jail event notifications
    pub fn set_warden_handle(&mut self, handle: WardenHandle) {
        self.warden_handle = Some(handle);
    }

    /// Get the start order (topological sort)
    pub fn start_order(&self) -> Result<Vec<&str>> {
        toposort(&self.graph, None)
            .map(|nodes| nodes.iter().map(|n| self.graph[*n].as_str()).collect())
            .map_err(|cycle| {
                // Get the node involved in the cycle
                let cycle_node = &self.graph[cycle.node_id()];
                Error::ConfigValidation(format!(
                    "Cyclic dependency detected involving jail '{}'",
                    cycle_node
                ))
            })
    }

    /// Get the stop order (reverse of start order)
    pub fn stop_order(&self) -> Result<Vec<&str>> {
        let mut order = self.start_order()?;
        order.reverse();
        Ok(order)
    }

    /// Start all jails (or a specific one with its dependencies)
    pub fn up(&mut self, jail: Option<&str>) -> Result<()> {
        // Collect to owned strings to avoid borrow conflict
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
        // Collect to owned strings to avoid borrow conflict
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

    /// Dry run: show what 'up' would do without making changes
    pub fn up_dry_run(&self, jail: Option<&str>) -> Result<()> {
        println!("=== DRY RUN - No changes will be made ===\n");

        let jails_to_start: Vec<String> = if let Some(name) = jail {
            self.get_dependencies(name)?
                .into_iter()
                .map(String::from)
                .collect()
        } else {
            self.start_order()?.into_iter().map(String::from).collect()
        };

        println!("Would start {} jail(s):\n", jails_to_start.len());

        for name in &jails_to_start {
            let jail_def = self.config.get_jail(name);
            if let Some(jail_def) = jail_def {
                let path = jail_def.effective_path(&self.config.config);
                let ip = jail_def
                    .network
                    .as_ref()
                    .and_then(|n| n.ip)
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "none".to_string());

                println!("  [START] {}", name);
                println!("          Path: {}", path.display());
                println!("          IP: {}", ip);

                // Show if ZFS dataset would be created
                if self.zfs.is_some() && jail_def.path.is_none() {
                    println!("          ZFS: would create dataset");
                }

                // Show hooks that would run
                if !jail_def.hooks.is_empty() {
                    let pre_start: Vec<_> = jail_def
                        .hooks
                        .iter()
                        .filter(|h| h.phase == crate::hooks::HookPhase::PreStart)
                        .collect();
                    let post_start: Vec<_> = jail_def
                        .hooks
                        .iter()
                        .filter(|h| h.phase == crate::hooks::HookPhase::PostStart)
                        .collect();

                    if !pre_start.is_empty() {
                        println!("          Hooks: {} pre_start", pre_start.len());
                    }
                    if !post_start.is_empty() {
                        println!("          Hooks: {} post_start", post_start.len());
                    }
                }
                println!();
            }
        }

        Ok(())
    }

    /// Dry run: show what 'down' would do without making changes
    pub fn down_dry_run(&self, jail: Option<&str>) -> Result<()> {
        println!("=== DRY RUN - No changes will be made ===\n");

        let jails_to_stop: Vec<String> = if let Some(name) = jail {
            self.get_dependents(name)?
                .into_iter()
                .map(String::from)
                .collect()
        } else {
            self.stop_order()?.into_iter().map(String::from).collect()
        };

        println!("Would stop {} jail(s):\n", jails_to_stop.len());

        for name in &jails_to_stop {
            let is_running = jail_getid(name).is_ok();
            let status = if is_running { "running" } else { "stopped" };

            println!("  [STOP] {} (currently {})", name, status);

            // Show hooks that would run
            if let Some(jail_def) = self.config.get_jail(name)
                && !jail_def.hooks.is_empty() {
                    let pre_stop: Vec<_> = jail_def
                        .hooks
                        .iter()
                        .filter(|h| h.phase == crate::hooks::HookPhase::PreStop)
                        .collect();
                    let post_stop: Vec<_> = jail_def
                        .hooks
                        .iter()
                        .filter(|h| h.phase == crate::hooks::HookPhase::PostStop)
                        .collect();

                    if !pre_stop.is_empty() {
                        println!("         Hooks: {} pre_stop", pre_stop.len());
                    }
                    if !post_stop.is_empty() {
                        println!("         Hooks: {} post_stop", post_stop.len());
                    }
                }
        }

        println!();
        Ok(())
    }

    /// Print jail status
    pub fn ps(&self, json: bool) -> Result<()> {
        if json {
            let mut jails_data: Vec<serde_json::Value> = Vec::new();

            for jail_def in &self.config.jails {
                let (state, jid) = if let Some(instance) = self.instances.get(&jail_def.name) {
                    let state = format!("{:?}", instance.state());
                    let jid = instance.jid;
                    (state, jid)
                } else {
                    match jail_getid(&jail_def.name) {
                        Ok(jid) => ("Running".to_string(), Some(jid)),
                        Err(_) => ("Stopped".to_string(), None),
                    }
                };

                let ip = jail_def
                    .network
                    .as_ref()
                    .and_then(|n| n.ip)
                    .map(|ip| ip.to_string());

                jails_data.push(serde_json::json!({
                    "name": jail_def.name,
                    "state": state,
                    "jid": jid,
                    "ip": ip,
                    "path": jail_def.effective_path(&self.config.config).to_string_lossy()
                }));
            }

            println!("{}", serde_json::to_string_pretty(&jails_data).unwrap());
        } else {
            println!("{:<20} {:<10} {:<10}", "NAME", "STATE", "JID");
            println!("{}", "-".repeat(42));

            for jail_def in &self.config.jails {
                let (state, jid) = if let Some(instance) = self.instances.get(&jail_def.name) {
                    let state = format!("{:?}", instance.state());
                    let jid = instance.jid.map(|j| j.to_string()).unwrap_or_default();
                    (state, jid)
                } else {
                    match jail_getid(&jail_def.name) {
                        Ok(jid) => ("Running".to_string(), jid.to_string()),
                        Err(_) => ("Stopped".to_string(), String::new()),
                    }
                };

                println!("{:<20} {:<10} {:<10}", jail_def.name, state, jid);
            }
        }

        Ok(())
    }

    /// Validate configuration
    pub fn check(&self) -> Result<()> {
        // Configuration was already validated on load
        println!("Configuration is valid.");

        // Check start order
        let order = self.start_order()?;
        println!("\nStart order:");
        for (i, name) in order.iter().enumerate() {
            println!("  {}. {}", i + 1, name);
        }

        // Check ZFS status
        if self.zfs.is_some() {
            println!("\nZFS: enabled");
        } else {
            println!("\nZFS: disabled");
        }

        // Check jail paths
        println!("\nJail paths:");
        for jail in &self.config.jails {
            let path = jail.effective_path(&self.config.config);
            let exists = path.exists();
            let status = if exists { "exists" } else { "missing" };
            println!("  {}: {} ({})", jail.name, path.display(), status);
        }

        Ok(())
    }

    /// Start a single jail with cleanup on failure
    fn start_jail(&mut self, name: &str) -> Result<()> {
        // Rate limiting to prevent thundering herd on `up --all`
        let capacity = self.jail_start_capacity;
        const REFILL_RATE: f64 = 1.0; // 1 jail/sec

        loop {
            let mut state = self.rate_limiter.lock().unwrap();
            let (tokens, last_refill) = *state;
            let now = Instant::now();
            let now_secs = now.duration_since(self.rate_limiter_epoch).as_secs_f64();
            let last_refill_secs = last_refill.duration_since(self.rate_limiter_epoch).as_secs_f64();

            let result = token_bucket::check(tokens, last_refill_secs, now_secs, capacity, REFILL_RATE);

            if result.allowed {
                // Update state and proceed
                *state = (result.new_tokens, now);
                break;
            } else {
                // Release lock before sleeping
                let retry_after = result.retry_after;
                drop(state);
                std::thread::sleep(std::time::Duration::from_secs_f64(retry_after));
            }
        }

        let jail_def = self
            .config
            .get_jail(name)
            .ok_or_else(|| Error::JailNotFound(name.to_string()))?;

        // Check if already running
        if jail_getid(name).is_ok() {
            return Err(Error::JailAlreadyRunning(name.to_string()));
        }

        // Track resources for cleanup on failure
        let mut created_zfs_dataset = false;

        // Create ZFS dataset if needed
        let path = if let Some(zfs) = &self.zfs {
            if jail_def.path.is_none() {
                created_zfs_dataset = true;
                zfs.create_jail_dataset(name)?
            } else {
                jail_def.effective_path(&self.config.config)
            }
        } else {
            jail_def.effective_path(&self.config.config)
        };

        // Check path exists - auto-provision from release if available
        if !path.exists() {
            // Check if we can auto-provision from a release
            if let Some(release) = &jail_def.release {
                let release_path = self.config.config.releases_dir.join(release);
                if release_path.exists() {
                    println!(
                        "Provisioning jail '{}' from release '{}'...",
                        name, release
                    );

                    // Create the jail directory
                    if let Err(e) = std::fs::create_dir_all(&path) {
                        // Cleanup ZFS dataset if we created it
                        if created_zfs_dataset {
                            if let Some(zfs) = &self.zfs {
                                let _ = zfs.destroy_jail_dataset(name);
                            }
                        }
                        return Err(Error::JailOperation(format!(
                            "Failed to create jail directory: {}",
                            e
                        )));
                    }

                    // Copy release to jail path using cp -a for full recursive copy
                    let status = std::process::Command::new("cp")
                        .arg("-a")
                        .arg(format!("{}/.", release_path.display()))
                        .arg(&path)
                        .status();

                    match status {
                        Ok(s) if s.success() => {
                            println!("Jail '{}' provisioned from release '{}'", name, release);
                        }
                        Ok(s) => {
                            // Cleanup on failure
                            let _ = std::fs::remove_dir_all(&path);
                            if created_zfs_dataset {
                                if let Some(zfs) = &self.zfs {
                                    let _ = zfs.destroy_jail_dataset(name);
                                }
                            }
                            return Err(Error::JailOperation(format!(
                                "Failed to copy release: cp exited with status {}",
                                s
                            )));
                        }
                        Err(e) => {
                            // Cleanup on failure
                            let _ = std::fs::remove_dir_all(&path);
                            if created_zfs_dataset {
                                if let Some(zfs) = &self.zfs {
                                    let _ = zfs.destroy_jail_dataset(name);
                                }
                            }
                            return Err(Error::JailOperation(format!(
                                "Failed to execute cp command: {}",
                                e
                            )));
                        }
                    }
                } else {
                    // Release not found
                    if created_zfs_dataset {
                        if let Some(zfs) = &self.zfs {
                            let _ = zfs.destroy_jail_dataset(name);
                        }
                    }
                    return Err(Error::JailOperation(format!(
                        "Release '{}' not found at {}. Run 'blackship bootstrap {}' first.",
                        release,
                        release_path.display(),
                        release
                    )));
                }
            } else {
                // No release specified, return original error
                // Cleanup ZFS dataset if we created it
                if created_zfs_dataset {
                    if let Some(zfs) = &self.zfs {
                        let _ = zfs.destroy_jail_dataset(name);
                    }
                }
                return Err(Error::JailPathNotFound(path));
            }
        }

        // Configure DNS before starting the jail
        if let Some(network) = &jail_def.network
            && let Err(e) = self.configure_dns(&path, &network.dns) {
                // Cleanup on DNS config failure
                if created_zfs_dataset
                    && let Some(zfs) = &self.zfs {
                        let _ = zfs.destroy_jail_dataset(name);
                    }
                return Err(e);
            }

        // Determine IP address for this jail
        // Priority: static IP > auto-allocate from network pool > none
        let mut allocated_ip: Option<(String, IpAddr)> = None;
        let effective_ip: Option<IpAddr> = if let Some(network) = &jail_def.network {
            if let Some(static_ip) = network.ip {
                // Static IP configured - reserve it in pools if attached to a network
                for net_name in &network.networks {
                    if let Some(pool) = self.ip_allocator.get_pool_mut(net_name) {
                        // Try to reserve the static IP in the pool (ignore errors if not in subnet)
                        let _ = pool.allocate_specific(static_ip);
                    }
                }
                Some(static_ip)
            } else if let Some(first_network) = network.networks.first() {
                // No static IP but attached to a network - auto-allocate
                match self.ip_allocator.allocate(first_network) {
                    Ok(ip) => {
                        allocated_ip = Some((first_network.clone(), ip));
                        if self.verbose {
                            println!("  Auto-allocated IP {} from network '{}'", ip, first_network);
                        }
                        Some(ip)
                    }
                    Err(e) => {
                        // Cleanup on allocation failure
                        if created_zfs_dataset {
                            if let Some(zfs) = &self.zfs {
                                let _ = zfs.destroy_jail_dataset(name);
                            }
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
        let mut hook_context = HookContext::new(name, &path);

        // Add IP to context if available
        if let Some(ip) = effective_ip {
            hook_context = hook_context.with_ip(ip.to_string());
        }

        // Execute pre_start hooks
        if let Err(e) = hook_runner.execute_phase(HookPhase::PreStart, &hook_context) {
            // Cleanup on pre_start hook failure
            if let Some((network_name, ip)) = &allocated_ip {
                self.ip_allocator.release(network_name, ip);
            }
            if created_zfs_dataset
                && let Some(zfs) = &self.zfs {
                    let _ = zfs.destroy_jail_dataset(name);
                }
            return Err(e);
        }

        // Check if this is a VNET jail
        let is_vnet = jail_def.network.as_ref().is_some_and(|n| n.vnet);

        // Create VNET setup for VNET jails before creating the jail
        let mut vnet_setup: Option<VnetSetup> = None;
        if is_vnet {
            if let Some(network) = &jail_def.network {
                // Validate VNET configuration
                let bridge_name = network.bridge.as_ref().ok_or_else(|| {
                    Error::Network(format!(
                        "VNET jail '{}' requires a bridge configuration",
                        name
                    ))
                })?;

                // Build IP configuration string for VnetConfig
                let ip_config = network
                    .ip_cidr
                    .as_ref()
                    .cloned()
                    .or_else(|| network.ip.map(|ip| format!("{}/24", ip)))
                    .or_else(|| effective_ip.map(|ip| format!("{}/24", ip)))
                    .unwrap_or_else(|| "0.0.0.0/0".to_string());

                // Get gateway (required for VnetConfig)
                let gateway = network.gateway.unwrap_or_else(|| {
                    // Default gateway - first IP in subnet if not specified
                    "10.0.0.1".parse().unwrap()
                });

                // Build VnetConfig
                let mut vnet_config = VnetConfig::new(bridge_name.clone(), ip_config, gateway);

                // Set static MAC address if configured
                if let Some(ref mac) = network.mac_address {
                    vnet_config = vnet_config.with_mac_address(mac.clone());
                }

                // Create VnetSetup - this handles epair creation, MAC setting, and bridge addition
                let setup = match VnetSetup::create(name, vnet_config) {
                    Ok(s) => s,
                    Err(e) => {
                        // Cleanup on VnetSetup creation failure
                        if let Some((network_name, ip)) = &allocated_ip {
                            self.ip_allocator.release(network_name, ip);
                        }
                        if created_zfs_dataset {
                            if let Some(zfs) = &self.zfs {
                                let _ = zfs.destroy_jail_dataset(name);
                            }
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

                vnet_setup = Some(setup);
            }
        }

        // Build jail parameters
        let mut params = HashMap::new();
        params.insert("name".to_string(), ParamValue::String(name.to_string()));

        if let Some(hostname) = &jail_def.hostname {
            params.insert(
                "host.hostname".to_string(),
                ParamValue::String(hostname.clone()),
            );
        }

        // For VNET jails, enable vnet and don't set IP (configured inside jail)
        // For non-VNET jails, use traditional IP assignment
        if is_vnet {
            // Enable VNET for this jail
            params.insert("vnet".to_string(), ParamValue::String("new".to_string()));
        } else if let Some(ip) = effective_ip {
            // Traditional jail: assign IP directly
            match ip {
                IpAddr::V4(addr) => {
                    params.insert("ip4.addr".to_string(), ParamValue::Ipv4(vec![addr]));
                }
                IpAddr::V6(addr) => {
                    params.insert("ip6.addr".to_string(), ParamValue::Ipv6(vec![addr]));
                }
            }
        }

        // Add custom parameters
        for (key, value) in &jail_def.params {
            let param_value = ParamValue::try_from(value)?;
            params.insert(key.clone(), param_value);
        }

        // Create the jail
        println!("Starting jail '{}'...", name);
        let jid = match jail_create(&path, params) {
            Ok(jid) => jid,
            Err(e) => {
                // Cleanup on jail creation failure
                eprintln!("Failed to create jail '{}': {}", name, e);
                // Cleanup VnetSetup if created
                if let Some(setup) = vnet_setup {
                    let _ = setup.cleanup();
                }
                // Release allocated IP
                if let Some((network_name, ip)) = &allocated_ip {
                    self.ip_allocator.release(network_name, ip);
                }
                if created_zfs_dataset {
                    eprintln!("Cleaning up ZFS dataset...");
                    if let Some(zfs) = &self.zfs {
                        let _ = zfs.destroy_jail_dataset(name);
                    }
                }
                // Track the failed instance
                let jail_config = JailConfig::new(name, &path);
                let mut instance = JailInstance::new(jail_config);
                instance.start().ok(); // Transition to Starting
                instance.fail().ok();  // Transition to Failed
                self.instances.insert(name.to_string(), instance);
                // Notify Warden of failure
                if let Some(handle) = &self.warden_handle {
                    let _ = handle.notify_failure_blocking(name);
                }
                return Err(e);
            }
        };
        println!("Jail '{}' started with JID {}", name, jid);


        // For VNET jails: attach the VnetSetup to the jail (moves interface and configures networking)
        if let Some(setup) = vnet_setup {
            // Use VnetSetup::attach_to_jail which handles both moving interface and configuring
            if let Err(e) = setup.attach_to_jail(jid) {
                eprintln!(
                    "Warning: Failed to attach VNET to jail '{}': {}",
                    name, e
                );
                eprintln!("VNET networking may not work correctly.");
            } else if self.verbose {
                println!(
                    "  Moved {} into jail {} (JID {})",
                    setup.jail_interface(),
                    name,
                    jid
                );
                println!(
                    "  Configured {} with {} in jail",
                    setup.jail_interface(),
                    setup.config.ip
                );
                println!("  Set default gateway to {}", setup.config.gateway);
            }

            // Store the VnetSetup for cleanup on stop
            self.vnet_setups.insert(name.to_string(), setup);
        }

        // Update context with JID for post_start hooks
        let hook_context = hook_context.with_jid(jid);

        // Execute post_start hooks (failure here doesn't cleanup the jail)
        if let Err(e) = hook_runner.execute_phase(HookPhase::PostStart, &hook_context) {
            eprintln!("Warning: post_start hook failed for jail '{}': {}", name, e);
            eprintln!("Jail is running but may not be fully configured.");
        }

        // Track the instance with full configuration
        let mut jail_config = JailConfig::new(name, &path);
        if let Some(hostname) = &jail_def.hostname {
            jail_config = jail_config.hostname(hostname);
        }
        if let Some(ip) = effective_ip {
            jail_config = jail_config.ip(ip);
        }
        let mut instance = JailInstance::new(jail_config);
        instance.jid = Some(jid);
        instance.start().ok();
        instance.started().ok();
        self.instances.insert(name.to_string(), instance);

        // Track allocated IP for cleanup on stop
        if let Some(alloc) = allocated_ip {
            self.allocated_ips.insert(name.to_string(), alloc);
        }

        // Notify Warden that jail started successfully
        if let Some(handle) = &self.warden_handle {
            if let Err(e) = handle.notify_started_blocking(name) {
                eprintln!("Warning: Failed to notify Warden of jail start: {}", e);
            }
        }

        Ok(())
    }

    /// Force cleanup of a failed jail
    ///
    /// Removes any leftover resources from a failed jail start:
    /// - Kills any processes
    /// - Removes jail if partially created
    /// - Destroys ZFS dataset if created by blackship
    pub fn cleanup(&mut self, name: &str, force: bool) -> Result<()> {
        println!("Cleaning up jail '{}'...", name);

        // Try to get jail definition
        let jail_def = self.config.get_jail(name);

        // Try to remove jail if it exists (even partially)
        if let Ok(jid) = jail_getid(name) {
            println!("  Removing jail (JID {})...", jid);
            if let Err(e) = jail_remove(jid) {
                if force {
                    eprintln!("  Warning: Failed to remove jail: {}", e);
                } else {
                    return Err(e);
                }
            }
        }

        // Clean up ZFS dataset if we manage it
        if let Some(zfs) = &self.zfs
            && let Some(jail_def) = jail_def {
                // Only destroy if path is managed by blackship (not custom path)
                if jail_def.path.is_none() {
                    println!("  Destroying ZFS dataset...");
                    if let Err(e) = zfs.destroy_jail_dataset(name) {
                        if force {
                            eprintln!("  Warning: Failed to destroy dataset: {}", e);
                        } else {
                            return Err(e);
                        }
                    }
                }
            }

        // Remove from instances
        self.instances.remove(name);

        // Cleanup VNET epair interface if present
        if let Some(vnet_setup) = self.vnet_setups.remove(name) {
            println!("  Cleaning up VNET setup...");
            if let Err(e) = vnet_setup.cleanup() {
                if force {
                    eprintln!("  Warning: Failed to cleanup VNET setup: {}", e);
                } else {
                    return Err(e);
                }
            }
        }

        // Release allocated IP back to the pool
        if let Some((network_name, ip)) = self.allocated_ips.remove(name) {
            self.ip_allocator.release(&network_name, &ip);
            println!("  Released IP {} back to network '{}'", ip, network_name);
        }

        println!("Cleanup complete for jail '{}'", name);
        Ok(())
    }

    /// Stop a single jail
    fn stop_jail(&mut self, name: &str) -> Result<()> {
        // Get JID
        let jid = match jail_getid(name) {
            Ok(jid) => jid,
            Err(_) => {
                return Err(Error::JailNotRunning(name.to_string()));
            }
        };

        // Get jail definition for hooks
        let jail_def = self.config.get_jail(name);

        // Setup hooks if jail has hook configuration
        if let Some(jail_def) = jail_def {
            let path = jail_def.effective_path(&self.config.config);
            let hook_runner = HookRunner::new(jail_def.hooks.clone()).verbose(self.verbose);
            let mut hook_context = HookContext::new(name, &path).with_jid(jid);

            // Add IP to context if available
            if let Some(network) = &jail_def.network
                && let Some(ip) = &network.ip {
                    hook_context = hook_context.with_ip(ip.to_string());
                }

            // Execute pre_stop hooks (inside jail, while still running)
            hook_runner.execute_phase(HookPhase::PreStop, &hook_context)?;

            // Remove the jail
            println!("Stopping jail '{}'...", name);
            jail_remove(jid)?;
            println!("Jail '{}' stopped", name);

            // Execute post_stop hooks (on host, after jail stopped)
            // Note: JID is no longer valid, but path and name are
            let hook_context = HookContext::new(name, &path);
            hook_runner.execute_phase(HookPhase::PostStop, &hook_context)?;
        } else {
            // No jail definition found, just stop directly
            println!("Stopping jail '{}'...", name);
            jail_remove(jid)?;
            println!("Jail '{}' stopped", name);
        }

        // Update instance state
        if let Some(instance) = self.instances.get_mut(name) {
            instance.stop().ok();
            instance.stopped().ok();
            instance.jid = None;
        }

        // Cleanup VNET setup if present
        if let Some(vnet_setup) = self.vnet_setups.remove(name) {
            if let Err(e) = vnet_setup.cleanup() {
                eprintln!("Warning: Failed to cleanup VNET setup for jail '{}': {}", name, e);
            } else if self.verbose {
                println!("  Cleaned up VNET for bridge {}", vnet_setup.bridge_name);
            }
        }

        // Release allocated IP back to the pool
        if let Some((network_name, ip)) = self.allocated_ips.remove(name) {
            self.ip_allocator.release(&network_name, &ip);
            if self.verbose {
                println!("  Released IP {} back to network '{}'", ip, network_name);
            }
        }

        // Notify Warden that jail stopped
        if let Some(handle) = &self.warden_handle {
            if let Err(e) = handle.notify_stopped_blocking(name) {
                eprintln!("Warning: Failed to notify Warden of jail stop: {}", e);
            }
        }

        Ok(())
    }

    /// Restart a jail (stop then start)
    ///
    /// Used by the Warden for automatic restart on failure
    pub fn restart_jail(&mut self, name: &str) -> Result<()> {
        println!("Restarting jail '{}'...", name);

        // If the jail is in Failed state, recover it first
        if let Some(instance) = self.instances.get_mut(name) {
            if instance.state() == JailState::Failed {
                instance.recover().ok(); // Transition from Failed to Stopped
            }
        }

        // Stop if running
        if jail_getid(name).is_ok() {
            self.stop_jail(name)?;
        }

        // Start the jail
        self.start_jail(name)?;

        println!("Jail '{}' restarted successfully", name);
        Ok(())
    }

    /// Get all dependencies of a jail (including the jail itself)
    fn get_dependencies(&self, name: &str) -> Result<Vec<&str>> {
        let order = self.start_order()?;
        let idx = order
            .iter()
            .position(|n| *n == name)
            .ok_or_else(|| Error::JailNotFound(name.to_string()))?;

        // Return all jails up to and including this one
        Ok(order[..=idx].to_vec())
    }

    /// Get all dependents of a jail (including the jail itself)
    fn get_dependents(&self, name: &str) -> Result<Vec<&str>> {
        let order = self.stop_order()?;
        let idx = order
            .iter()
            .position(|n| *n == name)
            .ok_or_else(|| Error::JailNotFound(name.to_string()))?;

        // Return all jails from the start up to and including this one
        Ok(order[..=idx].to_vec())
    }

    /// Configure DNS in a jail
    fn configure_dns(&self, jail_path: &Path, dns_config: &DnsConfig) -> Result<()> {
        let resolv_path = jail_path.join("etc/resolv.conf");

        if dns_config.is_inherit() {
            // Copy from host
            std::fs::copy("/etc/resolv.conf", &resolv_path)
                .map_err(|e| Error::JailOperation(format!("Failed to copy resolv.conf: {}", e)))?;
        } else if let Some(content) = dns_config.to_resolv_conf() {
            // Write custom resolv.conf
            std::fs::write(&resolv_path, content)
                .map_err(|e| Error::JailOperation(format!("Failed to write resolv.conf: {}", e)))?;
        }

        Ok(())
    }

    /// Initialize the PF firewall anchor for port forwarding
    ///
    /// This should be called once at startup to ensure PF is properly configured.
    pub fn init_bulkhead(&self) -> Result<()> {
        BulkheadManager::init()
    }

    /// Expose a port from a jail to the host
    ///
    /// Creates a PF RDR rule to forward traffic from the external port to the jail.
    pub fn expose_port(
        &mut self,
        jail_name: &str,
        external_port: u16,
        internal_port: Option<u16>,
        protocol: &str,
        bind_ip: Option<IpAddr>,
    ) -> Result<PortForward> {
        // Verify jail exists and get its IP
        let jail_def = self
            .config
            .get_jail(jail_name)
            .ok_or_else(|| Error::JailNotFound(jail_name.to_string()))?;

        let jail_ip = jail_def
            .network
            .as_ref()
            .and_then(|n| n.ip)
            .ok_or_else(|| {
                Error::Network(format!(
                    "Jail '{}' has no IP address configured",
                    jail_name
                ))
            })?;

        // Create port forward rule
        let internal = internal_port.unwrap_or(external_port);
        let mut forward = PortForward::new(external_port, internal, protocol, jail_ip, jail_name);

        if let Some(ip) = bind_ip {
            forward = forward.with_bind_ip(ip);
        }

        // Add to bulkhead manager and apply
        self.bulkhead.add_forward(forward.clone())?;

        if self.verbose {
            println!(
                "Exposed port {}:{}/{} -> {}:{}",
                bind_ip.map(|ip| ip.to_string()).unwrap_or_else(|| "*".to_string()),
                external_port,
                protocol,
                jail_ip,
                internal
            );
        }

        Ok(forward)
    }

    /// Remove all port forwards for a jail
    pub fn remove_port_forwards(&mut self, jail_name: &str) -> Result<()> {
        self.bulkhead.remove_jail_forwards(jail_name)?;

        if self.verbose {
            println!("Removed port forwards for jail '{}'", jail_name);
        }

        Ok(())
    }

    /// List all active port forwards
    pub fn list_port_forwards(&self) -> &[PortForward] {
        self.bulkhead.list_forwards()
    }

    /// Get port forwards for a specific jail
    pub fn get_jail_port_forwards(&self, jail_name: &str) -> Vec<&PortForward> {
        self.bulkhead.get_jail_forwards(jail_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> BlackshipConfig {
        toml::from_str(
            r#"
[config]
data_dir = "/var/blackship"

[[jails]]
name = "database"
path = "/jails/database"

[[jails]]
name = "backend"
path = "/jails/backend"
depends_on = ["database"]

[[jails]]
name = "frontend"
path = "/jails/frontend"
depends_on = ["backend"]
"#,
        )
        .unwrap()
    }

    #[test]
    fn test_start_order() {
        let config = test_config();
        let bridge = Bridge::new(config).unwrap();
        let order = bridge.start_order().unwrap();
        assert_eq!(order, vec!["database", "backend", "frontend"]);
    }

    #[test]
    fn test_stop_order() {
        let config = test_config();
        let bridge = Bridge::new(config).unwrap();
        let order = bridge.stop_order().unwrap();
        assert_eq!(order, vec!["frontend", "backend", "database"]);
    }
}
