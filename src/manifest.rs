//! Configuration file parsing for Blackship
//!
//! Parses `blackship.toml` configuration files using serde

use crate::error::{Error, Result};
use crate::hooks::Hook;
use crate::sickbay::checker::HealthCheckConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Validate a jail/project/network name: these reach paths, ZFS datasets and netgraph nodes.
pub fn validate_name(kind: &str, name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::ConfigValidation(format!(
            "{kind} name cannot be empty"
        )));
    }
    if name.contains('/') || name.contains('\0') || name == "." || name == ".." {
        return Err(Error::ConfigValidation(format!(
            "{kind} name '{}' contains invalid characters",
            name
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(Error::ConfigValidation(format!(
            "{kind} name '{}' contains invalid characters (only alphanumeric, dash, underscore, dot allowed)",
            name
        )));
    }
    Ok(())
}

/// Validate a ZFS pool/dataset/snapshot name; leading dashes would parse as zfs(8) options.
fn validate_zfs_component(kind: &str, name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::ConfigValidation(format!(
            "{kind} name cannot be empty"
        )));
    }
    if name.starts_with('-') {
        return Err(Error::ConfigValidation(format!(
            "{kind} name '{}' must not start with '-'",
            name
        )));
    }
    if name == "." || name == ".." || name.contains("..") {
        return Err(Error::ConfigValidation(format!(
            "{kind} name '{}' contains invalid component",
            name
        )));
    }
    if name.contains('@') || name.contains('\0') {
        return Err(Error::ConfigValidation(format!(
            "{kind} name '{}' contains invalid characters",
            name
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '/'))
    {
        return Err(Error::ConfigValidation(format!(
            "{kind} name '{}' contains invalid characters",
            name
        )));
    }
    Ok(())
}

/// Read a config file, mapping IO errors to ConfigRead
fn read_config_file(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(|e| Error::ConfigRead {
        path: path.to_path_buf(),
        source: e,
    })
}

/// Derive a project name from a config file path (falls back to cwd, then random name)
fn project_name_from_path(path: &Path) -> String {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty() && p.as_os_str() != ".")
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .map(|s| s.to_string())
        .or_else(|| {
            // Config in current directory - use cwd name
            std::env::current_dir()
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        })
        .unwrap_or_else(|| black_ship_name_from_path(path))
}

/// Load configuration from a file
pub fn load(path: &Path) -> Result<BlackshipConfig> {
    let content = read_config_file(path)?;

    let mut config: BlackshipConfig = toml::from_str(&content)?;

    if config.config.project.is_none() {
        config.config.project = Some(project_name_from_path(path));
    }

    config.validate()?;

    Ok(config)
}

/// Load a config, falling back to defaults when the file does not exist.
///
/// System-level commands (bootstrap, releases, setup) work against the
/// default paths and should not demand a blackship.toml.
pub fn load_or_default(path: &Path) -> Result<BlackshipConfig> {
    if path.exists() {
        load(path)
    } else {
        let mut config: BlackshipConfig = toml::from_str("[config]\n")?;
        config.config.project = Some(project_name_from_path(path));
        Ok(config)
    }
}

/// Load and merge multiple configuration files
///
/// Files are merged in order, with later files overriding earlier ones.
/// Uses Docker Compose-style deep merge: later files only override fields they specify.
pub fn load_merged(paths: &[PathBuf]) -> Result<BlackshipConfig> {
    if paths.is_empty() {
        return Err(Error::ConfigValidation(
            "No configuration files provided".into(),
        ));
    }

    let mut base: Option<BlackshipConfig> = None;
    let first_path = &paths[0];

    for path in paths {
        let content = read_config_file(path)?;

        let config: BlackshipConfig = toml::from_str(&content)?;

        base = Some(match base {
            None => config,
            Some(b) => b.merge(config),
        });
    }

    let mut config = base.unwrap();

    if config.config.project.is_none() {
        config.config.project = Some(project_name_from_path(first_path));
    }

    config.validate()?;
    Ok(config)
}

/// Root configuration structure
#[derive(Debug, Deserialize, Serialize)]
pub struct BlackshipConfig {
    /// Global configuration settings
    pub config: GlobalConfig,

    /// Network definitions (_unused: future feature)
    #[serde(default)]
    #[allow(dead_code)]
    pub networks: Vec<NetworkConfig>,

    /// Jail definitions
    #[serde(default)]
    pub jails: Vec<JailDef>,
}

impl BlackshipConfig {
    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        validate_name("project", &self.config.project_name())?;

        let mut names = std::collections::HashSet::new();
        let mut full_names = std::collections::HashSet::new();
        for jail in &self.jails {
            validate_name("jail", &jail.name)?;
            if !names.insert(&jail.name) {
                return Err(Error::ConfigValidation(format!(
                    "Duplicate jail name: {}",
                    jail.name
                )));
            }
            // project="demo" + jails "web"/"demo-web" both resolve to "demo-web".
            let full = self.jail_name(&jail.name);
            if !full_names.insert(full.clone()) {
                return Err(Error::ConfigValidation(format!(
                    "Jail '{}' resolves to full name '{}' which collides with another jail",
                    jail.name, full
                )));
            }
        }

        // Check that all dependencies exist
        for jail in &self.jails {
            for dep in &jail.depends_on {
                if !names.contains(dep) {
                    return Err(Error::UnknownDependency(dep.clone()));
                }
            }
        }

        // Check for self-dependencies
        for jail in &self.jails {
            if jail.depends_on.contains(&jail.name) {
                return Err(Error::ConfigValidation(format!(
                    "Jail '{}' depends on itself",
                    jail.name
                )));
            }
        }

        for net in &self.networks {
            validate_name("network", &net.name)?;
        }

        for jail in &self.jails {
            if let Some(release) = &jail.release {
                validate_name("release", release)?;
            }
            if let Some(net) = &jail.network {
                if let Some(bridge) = &net.bridge {
                    validate_name("bridge", bridge)?;
                }
                for net_ref in &net.networks {
                    validate_name("network reference", net_ref)?;
                }
            }
        }

        // Check ZFS configuration
        if self.config.zfs_enabled {
            if self.config.zpool.is_none() {
                return Err(Error::ConfigValidation(
                    "ZFS is enabled but no zpool specified".into(),
                ));
            }
            if let Some(pool) = &self.config.zpool {
                validate_zfs_component("zpool", pool)?;
            }
            validate_zfs_component("dataset", &self.config.dataset)?;
        }

        Ok(())
    }

    /// Get a jail definition by name (can match either service name or full name)
    pub fn get_jail(&self, name: &str) -> Option<&JailDef> {
        // First try exact match on service name
        if let Some(jail) = self.jails.iter().find(|j| j.name == name) {
            return Some(jail);
        }
        // Then try matching the full prefixed name
        self.jails.iter().find(|j| self.jail_name(&j.name) == name)
    }

    /// Resolve a jail identifier to (service_name, full_name)
    pub fn resolve_jail_names(&self, name: &str) -> Option<(String, String)> {
        let names_of = |jail: &JailDef| (jail.name.clone(), self.jail_name(&jail.name));

        if let Some(jail) = self.jails.iter().find(|j| j.name == name) {
            return Some(names_of(jail));
        }
        if let Some(jail) = self.jails.iter().find(|j| self.jail_name(&j.name) == name) {
            return Some(names_of(jail));
        }

        // Unambiguous prefix of a service or full name
        let matches: Vec<&JailDef> = self
            .jails
            .iter()
            .filter(|j| j.name.starts_with(name) || self.jail_name(&j.name).starts_with(name))
            .collect();
        if let [jail] = matches.as_slice() {
            return Some(names_of(jail));
        }

        None
    }

    /// Get the full jail name with project prefix
    /// Format: {project}-{service_name}
    pub fn jail_name(&self, service_name: &str) -> String {
        let project = self.config.project_name();
        let prefix = format!("{}-", project);
        if service_name.starts_with(&prefix) {
            service_name.to_string()
        } else {
            format!("{}-{}", project, service_name)
        }
    }

    /// Get the project name (explicit or random Black Ship name)
    #[allow(dead_code)]
    pub fn project_name(&self) -> String {
        self.config.project_name()
    }

    /// Merge another config into this one (Docker Compose-style deep merge)
    ///
    /// Later values override earlier ones at the field level.
    /// Jails with the same name are deep-merged.
    pub fn merge(mut self, other: BlackshipConfig) -> BlackshipConfig {
        // Merge global config (other overrides self)
        self.config = self.config.merge(other.config);

        // Merge networks by name
        for net in other.networks {
            if let Some(existing) = self.networks.iter_mut().find(|n| n.name == net.name) {
                *existing = net;
            } else {
                self.networks.push(net);
            }
        }

        // Merge jails by name (deep merge)
        for jail in other.jails {
            if let Some(existing) = self.jails.iter_mut().find(|j| j.name == jail.name) {
                *existing = existing.clone().merge(jail);
            } else {
                self.jails.push(jail);
            }
        }

        self
    }
}

/// Known Black Ship names from Warhammer 40K lore
/// Used for random project name generation
const BLACK_SHIP_NAMES: &[&str] = &[
    "aegis_of_truth",
    "aeria_gloris",
    "enduring_abundance",
    "honour_haltis",
    "lamentation",
    "norns_ghost",
    "psythanatos",
    "validus",
    "white_sun",
];

/// Generate a Black Ship name based on a seed (deterministic)
pub fn black_ship_name(seed: usize) -> String {
    BLACK_SHIP_NAMES[seed % BLACK_SHIP_NAMES.len()].to_string()
}

/// Generate a Black Ship name from a path (uses path hash for determinism)
pub fn black_ship_name_from_path(path: &Path) -> String {
    let hash = path.to_string_lossy().bytes().fold(0usize, |acc, b| {
        acc.wrapping_add(b as usize).wrapping_mul(31)
    });
    black_ship_name(hash)
}

/// Global configuration settings
#[derive(Debug, Deserialize, Serialize)]
pub struct GlobalConfig {
    /// Project name (used as prefix for jail names)
    /// If not set, a random Black Ship name will be used
    pub project: Option<String>,

    /// Base data directory for Blackship (defaults to ~/.local/share/blackship)
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,

    /// Enable ZFS dataset management
    #[serde(default)]
    pub zfs_enabled: bool,

    /// ZFS pool name (required if zfs_enabled is true)
    pub zpool: Option<String>,

    /// Base dataset name under the pool
    #[serde(default = "default_dataset")]
    pub dataset: String,

    /// Directory for FreeBSD releases
    #[serde(default = "default_releases_dir")]
    pub releases_dir: PathBuf,

    /// Cache directory for downloads
    #[serde(default = "default_cache_dir")]
    pub cache_dir: PathBuf,

    /// FreeBSD mirror URL
    #[serde(default = "default_mirror_url")]
    pub mirror_url: String,

    /// Dead-man switch: URL fetched periodically by the supervisor
    /// (healthchecks.io / Uptime Kuma style). Silence means trouble.
    pub monitor_ping_url: Option<String>,

    /// Archives to bootstrap (base, lib32, ports, src)
    #[serde(default = "default_bootstrap_archives")]
    pub bootstrap_archives: Vec<String>,

    /// Rate limiting configuration
    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    /// Global health check defaults
    #[serde(default)]
    #[allow(dead_code)] // Config field - parsed from TOML for future use
    pub health: HealthDefaults,

    /// Retry/backoff configuration for HTTP operations
    #[serde(default)]
    pub retry: RetryConfig,

    /// Bridge VLAN configuration (FreeBSD 15.0+)
    pub bridge: Option<BridgeVlanConfig>,
}

impl GlobalConfig {
    /// Get the effective project name
    /// Should always be set by load/load_merged, but falls back to "blackship" if not
    pub fn project_name(&self) -> String {
        self.project
            .clone()
            .unwrap_or_else(|| "blackship".to_string())
    }

    /// Merge another GlobalConfig into this one
    /// Other's values override self's where specified
    fn merge(self, other: GlobalConfig) -> GlobalConfig {
        GlobalConfig {
            project: other.project.or(self.project),
            data_dir: if other.data_dir != default_data_dir() {
                other.data_dir
            } else {
                self.data_dir
            },
            zfs_enabled: other.zfs_enabled,
            monitor_ping_url: other.monitor_ping_url.or(self.monitor_ping_url),
            zpool: other.zpool.or(self.zpool),
            dataset: if other.dataset != default_dataset() {
                other.dataset
            } else {
                self.dataset
            },
            releases_dir: if other.releases_dir != default_releases_dir() {
                other.releases_dir
            } else {
                self.releases_dir
            },
            cache_dir: if other.cache_dir != default_cache_dir() {
                other.cache_dir
            } else {
                self.cache_dir
            },
            mirror_url: if other.mirror_url != default_mirror_url() {
                other.mirror_url
            } else {
                self.mirror_url
            },
            bootstrap_archives: if other.bootstrap_archives != default_bootstrap_archives() {
                other.bootstrap_archives
            } else {
                self.bootstrap_archives
            },
            rate_limit: other.rate_limit, // Take other's rate limit config
            health: other.health,         // Take other's health defaults
            retry: other.retry,           // Take other's retry config
            bridge: other.bridge.or(self.bridge), // Merge bridge VLAN config
        }
    }
}

fn default_dataset() -> String {
    "blackship".into()
}

/// Get user's home directory, falling back to /root
fn get_home_dir() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/root"))
}

/// Get XDG data directory for blackship (~/.local/share/blackship)
pub fn get_xdg_data_dir() -> PathBuf {
    std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| get_home_dir().join(".local/share"))
        .join("blackship")
}

/// Get XDG cache directory for blackship (~/.cache/blackship)
pub fn get_xdg_cache_dir() -> PathBuf {
    std::env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| get_home_dir().join(".cache"))
        .join("blackship")
}

/// Default data directory (XDG compliant)
pub fn default_data_dir() -> PathBuf {
    get_xdg_data_dir()
}

fn default_releases_dir() -> PathBuf {
    get_xdg_data_dir().join("releases")
}

fn default_cache_dir() -> PathBuf {
    get_xdg_cache_dir()
}

fn default_mirror_url() -> String {
    "https://download.freebsd.org/releases".into()
}

fn default_bootstrap_archives() -> Vec<String> {
    vec!["base".into()]
}

fn default_jail_start_capacity() -> f64 {
    3.0
}

fn default_health_capacity() -> f64 {
    5.0
}

fn default_health_refill_rate() -> f64 {
    0.5
}

/// Rate limiting configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitConfig {
    /// Max jails to start concurrently
    #[serde(default = "default_jail_start_capacity")]
    pub jail_start_capacity: f64,

    /// Health check rate limit capacity
    #[serde(default = "default_health_capacity")]
    pub health_capacity: f64,

    /// Health check rate limit refill rate (tokens per second)
    #[serde(default = "default_health_refill_rate")]
    pub health_refill_rate: f64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            jail_start_capacity: default_jail_start_capacity(),
            health_capacity: default_health_capacity(),
            health_refill_rate: default_health_refill_rate(),
        }
    }
}

fn default_health_interval() -> u64 {
    30
}

fn default_health_timeout() -> u64 {
    10
}

fn default_health_start_period() -> u64 {
    60
}

fn default_health_retries() -> u32 {
    3
}

/// Global health check default settings
///
/// These values are used as defaults for health checks when not specified
/// at the individual check level.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(dead_code)] // Config struct - fields are parsed from TOML
pub struct HealthDefaults {
    /// Default interval between health checks in seconds
    #[serde(default = "default_health_interval")]
    pub interval: u64,

    /// Default timeout for health check commands in seconds
    #[serde(default = "default_health_timeout")]
    pub timeout: u64,

    /// Default start period before health checks begin in seconds
    #[serde(default = "default_health_start_period")]
    pub start_period: u64,

    /// Default number of retries before marking unhealthy
    #[serde(default = "default_health_retries")]
    pub retries: u32,
}

impl Default for HealthDefaults {
    fn default() -> Self {
        Self {
            interval: default_health_interval(),
            timeout: default_health_timeout(),
            start_period: default_health_start_period(),
            retries: default_health_retries(),
        }
    }
}

// Retry configuration defaults
fn default_base_delay_ms() -> u64 {
    1000
}

fn default_max_delay_ms() -> u64 {
    30000
}

fn default_multiplier() -> f64 {
    2.0
}

fn default_max_attempts() -> u8 {
    5
}

fn default_jitter_factor() -> f64 {
    0.25
}

/// Retry/backoff configuration for HTTP operations
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RetryConfig {
    /// Base delay in milliseconds before first retry
    #[serde(default = "default_base_delay_ms")]
    pub base_delay_ms: u64,

    /// Maximum delay in milliseconds between retries
    #[serde(default = "default_max_delay_ms")]
    pub max_delay_ms: u64,

    /// Multiplier for exponential backoff
    #[serde(default = "default_multiplier")]
    pub multiplier: f64,

    /// Maximum number of retry attempts
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u8,

    /// Jitter factor (0.0-1.0) to randomize delays
    #[serde(default = "default_jitter_factor")]
    pub jitter_factor: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            base_delay_ms: default_base_delay_ms(),
            max_delay_ms: default_max_delay_ms(),
            multiplier: default_multiplier(),
            max_attempts: default_max_attempts(),
            jitter_factor: default_jitter_factor(),
        }
    }
}

/// Network configuration
///
/// Used for defining virtual networks that jails can be attached to.
#[derive(Debug, Deserialize, Serialize)]
#[allow(dead_code)] // Config struct - fields are parsed from TOML
pub struct NetworkConfig {
    /// Network name
    pub name: String,

    /// Subnet in CIDR notation (e.g., "10.0.1.0/24")
    pub subnet: String,

    /// Gateway address (first usable address if not specified)
    pub gateway: Option<IpAddr>,
}

/// Bridge with VLAN filtering configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(dead_code)] // Config struct - fields are parsed from TOML
pub struct BridgeVlanConfig {
    /// Bridge interface name (e.g., "vswitch1")
    pub name: String,

    /// Enable VLAN filtering on bridge (requires FreeBSD 15.0+)
    #[serde(default)]
    pub vlan_filtering: bool,

    /// Trunk interface configuration
    pub trunk: Option<TrunkConfig>,
}

/// Physical trunk interface configuration for VLAN filtering
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TrunkConfig {
    /// Physical interface (e.g., "igb1", "em0")
    pub interface: String,

    /// Tagged VLANs allowed on trunk (e.g., [10, 20, 21, 30, 99])
    #[serde(default)]
    pub tagged: Vec<u16>,

    /// Disable hardware VLAN filter (for Broadcom NICs that cause issues)
    #[serde(default)]
    pub disable_hwfilter: bool,
}

/// Jail definition from config file
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JailDef {
    /// Unique jail name
    pub name: String,

    /// Path to jail root (can be auto-generated with ZFS)
    pub path: Option<PathBuf>,

    /// FreeBSD release to use for auto-provisioning (e.g., "15.1-RELEASE")
    /// If specified and jail path doesn't exist, it will be created from this release
    pub release: Option<String>,

    /// Build context directory containing a Jailfile
    /// Used by `armada build` to build the jail from a Jailfile
    pub build: Option<PathBuf>,

    /// Explicit path to a Jailfile (alternative to `build`)
    /// If not specified and `build` is set, looks for Jailfile in the build directory
    pub jailfile: Option<PathBuf>,

    /// Hostname for the jail
    pub hostname: Option<String>,

    /// Jails that must be started before this one
    #[serde(default)]
    pub depends_on: Vec<String>,

    /// Jail parameters (exec.start, allow.raw_sockets, etc.)
    #[serde(default)]
    pub params: HashMap<String, toml::Value>,

    /// Network configuration
    pub network: Option<JailNetworkConfig>,

    /// Mount configuration (_unused: future feature)
    #[allow(dead_code)]
    pub mount: Option<JailMountConfig>,

    /// Lifecycle hooks
    #[serde(default)]
    pub hooks: Vec<Hook>,

    /// Health check configuration
    #[serde(default)]
    pub healthcheck: HealthCheckConfig,

    /// Resource limits (RCTL)
    #[serde(default)]
    pub resources: crate::rctl::ResourceConfig,

    /// devfs ruleset applied to the jail's /dev mount.
    /// Defaults to ruleset 4 (devfsrules_jail); set to 0 to skip mounting devfs.
    pub devfs_ruleset: Option<u32>,

    /// Run /etc/rc at start and /etc/rc.shutdown at stop (default: true).
    /// Disable for process-style jails that exec a single command.
    pub init: Option<bool>,

    /// Tags for group targeting (e.g., `blackship down web`)
    #[serde(default)]
    pub tags: Vec<String>,
}

impl JailDef {
    /// Get the effective path for this jail
    ///
    /// If ZFS is enabled and no path is specified, returns the ZFS mountpoint.
    /// The provided name should be the full jail name (project-prefixed).
    pub fn effective_path(&self, global: &GlobalConfig, full_name: &str) -> PathBuf {
        if let Some(path) = &self.path {
            path.clone()
        } else {
            // With ZFS enabled the jails dataset is mounted at data_dir/jails,
            // so this is the jail root either way.
            global.data_dir.join("jails").join(full_name)
        }
    }

    /// Merge another JailDef into this one (Docker Compose-style deep merge)
    ///
    /// Other's values override self's where specified (Option::Some or non-empty Vec)
    pub fn merge(self, other: JailDef) -> JailDef {
        JailDef {
            name: other.name, // Name should match
            path: other.path.or(self.path),
            release: other.release.or(self.release),
            build: other.build.or(self.build),
            jailfile: other.jailfile.or(self.jailfile),
            hostname: other.hostname.or(self.hostname),
            depends_on: if other.depends_on.is_empty() {
                self.depends_on
            } else {
                other.depends_on
            },
            params: {
                let mut merged = self.params;
                merged.extend(other.params);
                merged
            },
            network: other.network.or(self.network),
            mount: other.mount.or(self.mount),
            hooks: if other.hooks.is_empty() {
                self.hooks
            } else {
                other.hooks
            },
            healthcheck: if other.healthcheck.enabled || !other.healthcheck.checks.is_empty() {
                other.healthcheck
            } else {
                self.healthcheck
            },
            resources: if other.resources.is_empty() {
                self.resources
            } else {
                other.resources
            },
            devfs_ruleset: other.devfs_ruleset.or(self.devfs_ruleset),
            init: other.init.or(self.init),
            tags: if other.tags.is_empty() {
                self.tags
            } else {
                other.tags
            },
        }
    }
}

/// Jail network configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JailNetworkConfig {
    /// Enable VNET (virtual network stack) for this jail
    /// When true, the jail gets its own network stack with epair interface
    #[serde(default)]
    pub vnet: bool,

    /// Bridge interface to attach the epair to (required for VNET)
    /// e.g., "blackship0"
    pub bridge: Option<String>,

    /// Networks to attach to
    #[serde(default)]
    pub networks: Vec<String>,

    /// IP address assignment (with optional CIDR prefix for VNET, e.g., "10.0.1.10/24")
    pub ip: Option<IpAddr>,

    /// IP address with prefix length for VNET jails (e.g., "10.0.1.10/24")
    pub ip_cidr: Option<String>,

    /// Gateway address for VNET jails
    pub gateway: Option<IpAddr>,

    /// Static MAC address
    /// If not specified, the system assigns a random MAC
    pub mac_address: Option<String>,

    /// VLAN ID for this jail's interface (untagged/PVID) (FreeBSD 15.0+)
    /// When using VLAN filtering, this sets the port VLAN ID for the jail's epair
    pub vlan_id: Option<u16>,

    /// Network backend: "epair" or "netgraph".
    /// When omitted, inherited from the attached named network (default: epair).
    pub backend: Option<crate::network::vnet::NetworkBackend>,

    /// DNS configuration for this jail
    #[serde(default)]
    pub dns: DnsConfig,
}

/// DNS configuration for a jail
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct DnsConfig {
    /// DNS servers (e.g., ["8.8.8.8", "8.8.4.4"])
    /// If empty, uses "inherit" mode (copies from host)
    #[serde(default)]
    pub nameservers: Vec<String>,

    /// Search domains (e.g., ["example.com", "local"])
    #[serde(default)]
    pub search: Vec<String>,

    /// Domain name
    pub domain: Option<String>,

    /// Mode: "inherit" to copy from host, "custom" to use nameservers above
    /// Defaults to "inherit" if nameservers is empty
    #[serde(default = "default_dns_mode")]
    pub mode: String,
}

fn default_dns_mode() -> String {
    "inherit".to_string()
}

impl DnsConfig {
    /// Check if this config inherits from host
    pub fn is_inherit(&self) -> bool {
        self.mode == "inherit" || (self.mode != "custom" && self.nameservers.is_empty())
    }

    /// Generate resolv.conf content
    pub fn to_resolv_conf(&self) -> Option<String> {
        if self.is_inherit() {
            return None; // Will copy from host
        }

        let mut content = String::new();

        if let Some(domain) = &self.domain {
            content.push_str(&format!("domain {}\n", domain));
        }

        if !self.search.is_empty() {
            content.push_str(&format!("search {}\n", self.search.join(" ")));
        }

        for ns in &self.nameservers {
            content.push_str(&format!("nameserver {}\n", ns));
        }

        Some(content)
    }
}

/// Jail mount configuration (_unused: future feature)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JailMountConfig {
    /// Volume mounts in "host:jail" format (_unused: future feature)
    #[serde(default)]
    #[allow(dead_code)]
    pub volumes: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_config() {
        let toml = r#"
[config]
data_dir = "/var/blackship"

[[jails]]
name = "test"
path = "/jails/test"
"#;

        let config: BlackshipConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.jails.len(), 1);
        assert_eq!(config.jails[0].name, "test");
    }

    #[test]
    fn test_parse_full_config() {
        let toml = r#"
[config]
data_dir = "/var/blackship"
zfs_enabled = true
zpool = "zroot"

[[networks]]
name = "backend"
subnet = "10.0.1.0/24"
gateway = "10.0.1.1"

[[jails]]
name = "postgres"
path = "/jails/postgres"
hostname = "db.local"

[jails.params]
"allow.raw_sockets" = true
"exec.start" = "/bin/sh /etc/rc"

[jails.network]
networks = ["backend"]
ip = "10.0.1.10"

[[jails]]
name = "webapp"
path = "/jails/webapp"
depends_on = ["postgres"]
"#;

        let config: BlackshipConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.jails.len(), 2);
        assert_eq!(config.jails[1].depends_on, vec!["postgres"]);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_duplicate_name_error() {
        let toml = r#"
[config]
data_dir = "/var/blackship"

[[jails]]
name = "test"
path = "/jails/test"

[[jails]]
name = "test"
path = "/jails/test2"
"#;

        let config: BlackshipConfig = toml::from_str(toml).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_unknown_dependency_error() {
        let toml = r#"
[config]
data_dir = "/var/blackship"

[[jails]]
name = "webapp"
path = "/jails/webapp"
depends_on = ["nonexistent"]
"#;

        let config: BlackshipConfig = toml::from_str(toml).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_parse_config_without_data_dir() {
        // data_dir should default to XDG path when not specified
        let toml = r#"
[config]

[[jails]]
name = "test"
path = "/jails/test"
"#;

        let config: BlackshipConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.jails.len(), 1);
        // data_dir should be set to XDG default
        assert!(
            config
                .config
                .data_dir
                .to_string_lossy()
                .contains("blackship")
        );
    }

    #[test]
    fn test_xdg_paths() {
        // Test that XDG functions return expected structure
        let data_dir = get_xdg_data_dir();
        let cache_dir = get_xdg_cache_dir();

        assert!(data_dir.to_string_lossy().ends_with("blackship"));
        assert!(cache_dir.to_string_lossy().ends_with("blackship"));
    }
}
