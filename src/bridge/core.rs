//! Bridge struct definition and constructor

use crate::bulkhead::BulkheadManager;
use crate::error::{Error, Result};
use crate::jail::JailInstance;
use crate::manifest::BlackshipConfig;
use crate::network::{
    Bridge as NetworkBridge, IpAllocator, NetworkLeaseStore, ResolvedNetwork, VnetSetup,
    VnetStateStore, build_runtime_allocator,
};
use crate::sys::OsVersion;
use crate::warden::WardenHandle;
use crate::zfs::ZfsManager;

use petgraph::graph::DiGraph;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

/// Bridge for managing jails
pub struct Bridge {
    /// Loaded configuration
    pub(super) config: BlackshipConfig,

    /// Dependency graph (jail name -> node index)
    pub(super) graph: DiGraph<String, ()>,

    /// ZFS manager (if enabled)
    pub(super) zfs: Option<ZfsManager>,

    /// Bulkhead manager for PF firewall rules
    pub(super) bulkhead: BulkheadManager,

    /// Resolved runtime networks available to this bridge.
    pub(super) runtime_networks: HashMap<String, ResolvedNetwork>,

    /// IP allocator for automatic IP assignment from network pools
    pub(super) ip_allocator: IpAllocator,

    /// Persistent lease state for auto-assigned addresses.
    pub(super) lease_store: NetworkLeaseStore,

    /// Persistent VNET attachment state for cleanup across CLI invocations.
    pub(super) vnet_state_store: VnetStateStore,

    /// Map of jail name to allocated IP (for cleanup on stop)
    pub(super) allocated_ips: HashMap<String, (String, IpAddr)>,

    /// Running jail instances
    pub(super) instances: HashMap<String, JailInstance>,

    /// Verbose output mode
    pub(super) verbose: bool,

    /// Rate limiter state for jail starts (tokens, last_refill)
    pub(super) rate_limiter: Mutex<(f64, Instant)>,

    /// Rate limiter start time for consistent timing
    pub(super) rate_limiter_epoch: Instant,

    /// Rate limiter capacity for jail starts
    pub(super) jail_start_capacity: f64,

    /// Optional handle to notify the Warden of jail events
    pub(super) warden_handle: Option<WardenHandle>,

    /// VNET setups for VNET jails (jail name -> VnetSetup)
    pub(super) vnet_setups: HashMap<String, VnetSetup>,

    /// Detected OS version for feature gating
    pub(super) os_version: OsVersion,

    /// Whether runtime prerequisites have been initialized on the host
    pub(super) runtime_prepared: bool,
}

impl Bridge {
    /// Create a new bridge from configuration.
    ///
    /// Construction is intentionally side-effect free. Host mutations such as
    /// bridge preparation and ZFS dataset initialization are deferred until a
    /// mutating lifecycle command explicitly needs them.
    pub fn new(config: BlackshipConfig) -> Result<Self> {
        // Detect OS version for feature compatibility checks
        let os_version = OsVersion::detect_kernel()?;

        // Check if VLAN filtering is being used and verify OS version
        if let Some(ref bridge_config) = config.config.bridge
            && bridge_config.vlan_filtering
            && !os_version.supports_vlan_filtering()
        {
            return Err(Error::UnsupportedOsVersion {
                feature: "VLAN filtering".to_string(),
                minimum: "15.0".to_string(),
                current: os_version.to_string(),
            });
        }

        let mut graph = DiGraph::new();
        let mut node_map = HashMap::new();

        for jail in &config.jails {
            let idx = graph.add_node(jail.name.clone());
            node_map.insert(jail.name.clone(), idx);
        }

        for jail in &config.jails {
            let to = node_map[&jail.name];
            for dep in &jail.depends_on {
                let from = node_map
                    .get(dep)
                    .ok_or_else(|| Error::UnknownDependency(dep.clone()))?;
                graph.add_edge(*from, to, ());
            }
        }

        let zfs = if config.config.zfs_enabled {
            let pool = config.config.zpool.as_ref().ok_or(Error::ZfsNotEnabled)?;
            Some(ZfsManager::new(pool, &config.config.dataset))
        } else {
            None
        };

        let bulkhead = BulkheadManager::from_data_dir(&config.config.data_dir)?;
        let (runtime_networks, ip_allocator, lease_store) = build_runtime_allocator(Some(&config))?;
        let vnet_state_store = VnetStateStore::from_config(Some(&config));

        let jail_start_capacity = config.config.rate_limit.jail_start_capacity;
        let now = Instant::now();
        Ok(Self {
            config,
            graph,
            zfs,
            bulkhead,
            runtime_networks,
            ip_allocator,
            lease_store,
            vnet_state_store,
            allocated_ips: HashMap::new(),
            instances: HashMap::new(),
            verbose: false,
            rate_limiter: Mutex::new((jail_start_capacity, now)),
            rate_limiter_epoch: now,
            jail_start_capacity,
            warden_handle: None,
            vnet_setups: HashMap::new(),
            os_version,
            runtime_prepared: false,
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

    /// Explicitly prepare host-side runtime prerequisites.
    pub fn prepare_host(&mut self) -> Result<()> {
        self.prepare_runtime()
    }

    /// Resolve a jail identifier to (service_name, full_name)
    pub(super) fn resolve_jail_names(&self, name: &str) -> Result<(String, String)> {
        self.config
            .resolve_jail_names(name)
            .ok_or_else(|| Error::JailNotFound(name.to_string()))
    }

    pub(super) fn prepare_runtime(&mut self) -> Result<()> {
        if self.runtime_prepared {
            return Ok(());
        }

        self.prepare_networking()?;
        self.prepare_storage()?;
        self.runtime_prepared = true;
        Ok(())
    }

    fn prepare_networking(&self) -> Result<()> {
        let Some(bridge_config) = self.config.config.bridge.as_ref() else {
            return Ok(());
        };

        if !bridge_config.vlan_filtering {
            return Ok(());
        }

        let bridge = NetworkBridge::create_or_open(&bridge_config.name)?;
        bridge.enable_vlan_filtering()?;

        if let Some(trunk) = bridge_config.trunk.as_ref() {
            if trunk.disable_hwfilter {
                NetworkBridge::disable_hwfilter(&trunk.interface)?;
            }

            if !trunk.tagged.is_empty() {
                bridge.add_trunk_member(&trunk.interface, &trunk.tagged)?;
            }
        }

        Ok(())
    }

    fn prepare_storage(&self) -> Result<()> {
        if let Some(zfs) = &self.zfs {
            zfs.init()?;
        }

        Ok(())
    }
}
