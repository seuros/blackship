//! Configuration file parsing for Blackship
//!
//! Parses `blackship.toml` configuration files using serde

use crate::error::{Error, Result};
use crate::sickbay::checker::HealthCheckConfig;
use crate::hooks::Hook;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Load configuration from a file
pub fn load(path: &Path) -> Result<BlackshipConfig> {
    let content = fs::read_to_string(path).map_err(|e| Error::ConfigRead {
        path: path.to_path_buf(),
        source: e,
    })?;

    let config: BlackshipConfig = toml::from_str(&content)?;
    config.validate()?;

    Ok(config)
}

/// Root configuration structure
#[derive(Debug, Deserialize)]
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
        // Check for duplicate jail names
        let mut names = std::collections::HashSet::new();
        for jail in &self.jails {
            if !names.insert(&jail.name) {
                return Err(Error::ConfigValidation(format!(
                    "Duplicate jail name: {}",
                    jail.name
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

        // Check ZFS configuration
        if self.config.zfs_enabled && self.config.zpool.is_none() {
            return Err(Error::ConfigValidation(
                "ZFS is enabled but no zpool specified".into(),
            ));
        }

        Ok(())
    }

    /// Get a jail definition by name
    pub fn get_jail(&self, name: &str) -> Option<&JailDef> {
        self.jails.iter().find(|j| j.name == name)
    }
}

/// Global configuration settings
#[derive(Debug, Deserialize)]
pub struct GlobalConfig {
    /// Base data directory for Blackship
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
}

fn default_dataset() -> String {
    "blackship".into()
}

fn default_releases_dir() -> PathBuf {
    PathBuf::from("/var/blackship/releases")
}

fn default_cache_dir() -> PathBuf {
    PathBuf::from("/var/blackship/cache")
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
#[derive(Debug, Clone, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
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
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Config struct - fields are parsed from TOML
pub struct NetworkConfig {
    /// Network name
    pub name: String,

    /// Subnet in CIDR notation (e.g., "10.0.1.0/24")
    pub subnet: String,

    /// Gateway address (first usable address if not specified)
    pub gateway: Option<IpAddr>,
}

/// Jail definition from config file
#[derive(Debug, Clone, Deserialize)]
pub struct JailDef {
    /// Unique jail name
    pub name: String,

    /// Path to jail root (can be auto-generated with ZFS)
    pub path: Option<PathBuf>,

    /// FreeBSD release to use for auto-provisioning (e.g., "15.0-RELEASE")
    /// If specified and jail path doesn't exist, it will be created from this release
    pub release: Option<String>,

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
}

impl JailDef {
    /// Get the effective path for this jail
    ///
    /// If ZFS is enabled and no path is specified, returns the ZFS mountpoint
    pub fn effective_path(&self, global: &GlobalConfig) -> PathBuf {
        if let Some(path) = &self.path {
            path.clone()
        } else if global.zfs_enabled {
            // ZFS mountpoint: /<pool>/<dataset>/jails/<name>
            PathBuf::from(format!(
                "/{}/{}/jails/{}",
                global.zpool.as_deref().unwrap_or("zroot"),
                global.dataset,
                self.name
            ))
        } else {
            // Fallback to data_dir
            global.data_dir.join("jails").join(&self.name)
        }
    }
}

/// Jail network configuration
#[derive(Debug, Clone, Deserialize)]
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

    /// DNS configuration for this jail
    #[serde(default)]
    pub dns: DnsConfig,
}

/// DNS configuration for a jail
#[derive(Debug, Clone, Default, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
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
}
