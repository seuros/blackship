//! Persistent network metadata and runtime state.
//!
//! This module backs:
//! - named network definitions created by `blackship network create`
//! - resolved runtime networks merged from config and CLI-created state
//! - persistent IP leases for auto-assigned addresses
//! - persistent VNET attachment state for cleanup across CLI invocations

use super::ip::{IpAllocator, IpPool};
use crate::error::{Error, Result};
use crate::manifest;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsStr;
use std::fs;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkRecord {
    pub name: String,
    pub bridge: String,
    pub subnet: String,
    pub gateway: String,
    /// "epair" (if_bridge) or "netgraph" (ng_bridge)
    #[serde(default = "default_backend_epair")]
    pub backend: String,
    /// Host-side gateway interface for netgraph networks (e.g., ngeth1)
    #[serde(default)]
    pub host_iface: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedNetwork {
    pub name: String,
    pub bridge: Option<String>,
    pub subnet: IpNet,
    pub gateway: IpAddr,
    /// "epair" or "netgraph", inherited by jails that omit a backend
    pub backend: String,
}

#[derive(Debug, Clone)]
pub struct NetworkStore {
    root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkLeaseRecord {
    pub owner: String,
    pub ip: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NetworkLeaseFile {
    leases: Vec<NetworkLeaseRecord>,
}

#[derive(Debug, Clone)]
pub struct NetworkLeaseStore {
    root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VnetStateRecord {
    pub owner: String,
    pub network: Option<String>,
    pub bridge: String,
    pub host_interface: String,
    pub jail_interface: String,
    /// "epair" or "netgraph" -persisted so cleanup knows which backend to use.
    #[serde(default = "default_backend_epair")]
    pub backend: String,
}

fn default_backend_epair() -> String {
    "epair".to_string()
}

#[derive(Debug, Clone)]
pub struct VnetStateStore {
    root: PathBuf,
}

impl NetworkStore {
    pub fn from_config(config: Option<&manifest::BlackshipConfig>) -> Self {
        Self {
            root: data_root_from_config(config).join("networks"),
        }
    }

    pub fn create(&self, record: &NetworkRecord) -> Result<()> {
        validate_network_name(&record.name)?;
        fs::create_dir_all(&self.root)
            .map_err(|e| Error::Network(format!("Failed to create network state dir: {}", e)))?;

        let path = self.record_path(&record.name)?;
        let content = toml::to_string(record)
            .map_err(|e| Error::Network(format!("Failed to serialize network metadata: {}", e)))?;
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                use std::io::Write;
                file.write_all(content.as_bytes())
                    .map_err(|e| Error::Network(format!("Failed to write network metadata: {}", e)))
            }
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                Err(Error::NetworkAlreadyExists(record.name.clone()))
            }
            Err(err) => Err(Error::Network(format!(
                "Failed to create network metadata file: {}",
                err
            ))),
        }
    }

    /// Write a record, replacing any existing one (used to refresh
    /// runtime-assigned fields like host_iface).
    pub fn save(&self, record: &NetworkRecord) -> Result<()> {
        validate_network_name(&record.name)?;
        fs::create_dir_all(&self.root)
            .map_err(|e| Error::Network(format!("Failed to create network state dir: {}", e)))?;
        let path = self.record_path(&record.name)?;
        let content = toml::to_string(record)
            .map_err(|e| Error::Network(format!("Failed to serialize network metadata: {}", e)))?;
        fs::write(&path, content)
            .map_err(|e| Error::Network(format!("Failed to write network metadata: {}", e)))
    }

    pub fn get(&self, name: &str) -> Result<Option<NetworkRecord>> {
        let path = self.record_path(name)?;
        if !path.exists() {
            return Ok(None);
        }

        read_network_record(&path)
    }

    pub fn delete(&self, name: &str) -> Result<bool> {
        let path = self.record_path(name)?;
        if !path.exists() {
            return Ok(false);
        }

        fs::remove_file(&path)
            .map_err(|e| Error::Network(format!("Failed to remove network metadata: {}", e)))?;
        Ok(true)
    }

    pub fn list(&self) -> Result<Vec<NetworkRecord>> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }

        let mut records = Vec::new();
        let entries = fs::read_dir(&self.root)
            .map_err(|e| Error::Network(format!("Failed to read network state dir: {}", e)))?;

        for entry in entries {
            let entry = entry
                .map_err(|e| Error::Network(format!("Failed to read network entry: {}", e)))?;
            let path = entry.path();

            if path.extension() != Some(OsStr::new("toml")) {
                continue;
            }

            if let Some(record) = read_network_record(&path)? {
                records.push(record);
            }
        }

        records.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(records)
    }

    fn record_path(&self, name: &str) -> Result<PathBuf> {
        validate_network_name(name)?;
        Ok(self.root.join(format!("{}.toml", name)))
    }
}

impl NetworkLeaseStore {
    pub fn from_config(config: Option<&manifest::BlackshipConfig>) -> Self {
        Self {
            root: data_root_from_config(config).join("network-leases"),
        }
    }

    pub fn list(&self, network: &str) -> Result<Vec<NetworkLeaseRecord>> {
        validate_network_name(network)?;
        let path = self.record_path(network);
        if !path.exists() {
            return Ok(Vec::new());
        }

        Ok(read_toml::<NetworkLeaseFile>(&path, "network lease metadata")?.leases)
    }

    /// Lock file guarding read-modify-write of one network's lease list
    fn lock_path(&self, network: &str) -> PathBuf {
        self.root.join(format!("{}.lock", network))
    }

    pub fn record(&self, network: &str, owner: &str, ip: IpAddr) -> Result<()> {
        validate_network_name(network)?;
        let _guard = FileLock::acquire(&self.lock_path(network))?;
        if owner.is_empty() {
            return Err(Error::InvalidArgument(
                "Network lease owner cannot be empty".into(),
            ));
        }

        fs::create_dir_all(&self.root)
            .map_err(|e| Error::Network(format!("Failed to create network lease dir: {}", e)))?;

        let mut leases = self.list(network)?;
        let ip_str = ip.to_string();

        if let Some(existing) = leases
            .iter()
            .find(|lease| lease.owner != owner && lease.ip == ip_str)
        {
            return Err(Error::Network(format!(
                "Address {} is already leased to '{}'",
                existing.ip, existing.owner
            )));
        }

        if let Some(existing) = leases.iter_mut().find(|lease| lease.owner == owner) {
            existing.ip = ip_str;
        } else {
            leases.push(NetworkLeaseRecord {
                owner: owner.to_string(),
                ip: ip_str,
            });
        }

        leases.sort_by(|a, b| a.owner.cmp(&b.owner));
        write_toml_atomic(
            &self.record_path(network),
            &NetworkLeaseFile { leases },
            "network lease metadata",
        )
    }

    pub fn release(&self, network: &str, owner: &str) -> Result<bool> {
        validate_network_name(network)?;
        let _guard = FileLock::acquire(&self.lock_path(network))?;
        let path = self.record_path(network);
        if !path.exists() {
            return Ok(false);
        }

        let mut leases = self.list(network)?;
        let original_len = leases.len();
        leases.retain(|lease| lease.owner != owner);

        if leases.len() == original_len {
            return Ok(false);
        }

        if leases.is_empty() {
            fs::remove_file(&path).map_err(|e| {
                Error::Network(format!(
                    "Failed to remove empty network lease metadata: {}",
                    e
                ))
            })?;
        } else {
            write_toml_atomic(
                &path,
                &NetworkLeaseFile { leases },
                "network lease metadata",
            )?;
        }

        Ok(true)
    }

    pub fn release_owner(&self, owner: &str) -> Result<Vec<(String, IpAddr)>> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }

        let mut released = Vec::new();
        let entries = fs::read_dir(&self.root)
            .map_err(|e| Error::Network(format!("Failed to read network lease dir: {}", e)))?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                Error::Network(format!("Failed to read network lease entry: {}", e))
            })?;
            let path = entry.path();
            if path.extension() != Some(OsStr::new("toml")) {
                continue;
            }

            let Some(network_name) = path.file_stem().and_then(|stem| stem.to_str()) else {
                continue;
            };

            let leases = self.list(network_name)?;
            for lease in leases.iter().filter(|lease| lease.owner == owner) {
                let ip = lease.ip.parse().map_err(|e| {
                    Error::Network(format!(
                        "Failed to parse leased IP '{}' for owner '{}': {}",
                        lease.ip, owner, e
                    ))
                })?;
                released.push((network_name.to_string(), ip));
            }

            let _ = self.release(network_name, owner)?;
        }

        Ok(released)
    }

    fn record_path(&self, network: &str) -> PathBuf {
        self.root.join(format!("{}.toml", network))
    }
}

impl VnetStateStore {
    pub fn from_config(config: Option<&manifest::BlackshipConfig>) -> Self {
        Self {
            root: data_root_from_config(config).join("vnet"),
        }
    }

    pub fn save(&self, record: &VnetStateRecord) -> Result<()> {
        Self::validate_owner(&record.owner)?;

        fs::create_dir_all(&self.root)
            .map_err(|e| Error::Network(format!("Failed to create VNET state dir: {}", e)))?;
        write_toml_atomic(
            &self.record_path(&record.owner),
            record,
            "VNET state metadata",
        )
    }

    pub fn get(&self, owner: &str) -> Result<Option<VnetStateRecord>> {
        Self::validate_owner(owner)?;
        let path = self.record_path(owner);
        if !path.exists() {
            return Ok(None);
        }

        read_toml::<VnetStateRecord>(&path, "VNET state metadata").map(Some)
    }

    pub fn delete(&self, owner: &str) -> Result<bool> {
        Self::validate_owner(owner)?;
        let path = self.record_path(owner);
        if !path.exists() {
            return Ok(false);
        }

        fs::remove_file(&path)
            .map_err(|e| Error::Network(format!("Failed to remove VNET state metadata: {}", e)))?;
        Ok(true)
    }

    fn record_path(&self, owner: &str) -> PathBuf {
        self.root.join(format!("{}.toml", owner))
    }

    /// Validate owner string to prevent path traversal
    fn validate_owner(owner: &str) -> Result<()> {
        if owner.is_empty() {
            return Err(Error::InvalidArgument(
                "VNET state owner cannot be empty".into(),
            ));
        }
        if owner.contains('/') || owner.contains('\\') || owner.contains("..") {
            return Err(Error::InvalidArgument(format!(
                "VNET state owner '{}' contains invalid characters",
                owner
            )));
        }
        Ok(())
    }
}

pub fn load_runtime_networks(
    config: Option<&manifest::BlackshipConfig>,
) -> Result<Vec<ResolvedNetwork>> {
    let mut networks = BTreeMap::new();

    if let Some(config) = config {
        for network in &config.networks {
            let subnet: IpNet = network.subnet.parse().map_err(|e| {
                Error::Network(format!(
                    "Invalid subnet '{}' for network '{}': {}",
                    network.subnet, network.name, e
                ))
            })?;
            let gateway = if let Some(gateway) = network.gateway {
                IpPool::with_gateway(subnet, gateway)?.gateway()
            } else {
                IpPool::new(subnet)?.gateway()
            };

            networks.insert(
                network.name.clone(),
                ResolvedNetwork {
                    name: network.name.clone(),
                    bridge: None,
                    subnet,
                    gateway,
                    backend: default_backend_epair(),
                },
            );
        }
    }

    for record in NetworkStore::from_config(config).list()? {
        let subnet: IpNet = record.subnet.parse().map_err(|e| {
            Error::Network(format!(
                "Invalid subnet '{}' for network '{}': {}",
                record.subnet, record.name, e
            ))
        })?;
        let gateway: IpAddr = record.gateway.parse().map_err(|e| {
            Error::Network(format!(
                "Invalid gateway '{}' for network '{}': {}",
                record.gateway, record.name, e
            ))
        })?;
        let bridge = Some(record.bridge.clone());

        if let Some(existing) = networks.get_mut(&record.name) {
            if existing.subnet != subnet || existing.gateway != gateway {
                return Err(Error::Network(format!(
                    "Network '{}' is defined differently in config and runtime state",
                    record.name
                )));
            }
            existing.bridge = bridge;
            existing.backend = record.backend.clone();
        } else {
            networks.insert(
                record.name.clone(),
                ResolvedNetwork {
                    name: record.name.clone(),
                    bridge,
                    subnet,
                    gateway,
                    backend: record.backend.clone(),
                },
            );
        }
    }

    Ok(networks.into_values().collect())
}

pub fn load_runtime_network_map(
    config: Option<&manifest::BlackshipConfig>,
) -> Result<HashMap<String, ResolvedNetwork>> {
    let mut map = HashMap::new();
    for network in load_runtime_networks(config)? {
        map.insert(network.name.clone(), network);
    }
    Ok(map)
}

pub fn build_runtime_allocator(
    config: Option<&manifest::BlackshipConfig>,
) -> Result<(
    HashMap<String, ResolvedNetwork>,
    IpAllocator,
    NetworkLeaseStore,
)> {
    let runtime_networks = load_runtime_network_map(config)?;
    let lease_store = NetworkLeaseStore::from_config(config);
    let mut allocator = IpAllocator::new();

    for network in runtime_networks.values() {
        let mut pool = IpPool::with_gateway(network.subnet, network.gateway)?;

        for lease in lease_store.list(&network.name)? {
            let ip: IpAddr = lease.ip.parse().map_err(|e| {
                Error::Network(format!(
                    "Failed to parse leased IP '{}' for owner '{}': {}",
                    lease.ip, lease.owner, e
                ))
            })?;
            pool.allocate_specific(ip)?;
        }

        allocator.add_pool(network.name.clone(), pool);
    }

    if let Some(config) = config {
        for jail in &config.jails {
            let Some(network) = jail.network.as_ref() else {
                continue;
            };
            let Some(static_ip) = network.ip else {
                continue;
            };

            for network_name in &network.networks {
                let Some(pool) = allocator.get_pool_mut(network_name) else {
                    continue;
                };
                pool.allocate_specific(static_ip)?;
            }
        }
    }

    Ok((runtime_networks, allocator, lease_store))
}

fn read_network_record(path: &Path) -> Result<Option<NetworkRecord>> {
    read_toml::<NetworkRecord>(path, "network metadata").map(Some)
}

fn read_toml<T>(path: &Path, label: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let content = fs::read_to_string(path)
        .map_err(|e| Error::Network(format!("Failed to read {}: {}", label, e)))?;
    toml::from_str(&content)
        .map_err(|e| Error::Network(format!("Failed to parse {}: {}", label, e)))
}

fn write_toml_atomic<T>(path: &Path, value: &T, label: &str) -> Result<()>
where
    T: Serialize,
{
    let content = toml::to_string(value)
        .map_err(|e| Error::Network(format!("Failed to serialize {}: {}", label, e)))?;
    let nonce = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        std::process::id() ^ nanos
    };
    // create_new fails on an existing path (symlink attack), so walk the
    // suffix until we win a name: concurrent writers otherwise collide.
    let mut tmp_path = path.with_extension(format!("{}.tmp", nonce));
    let mut file = None;
    for attempt in 0..64u32 {
        if attempt > 0 {
            tmp_path = path.with_extension(format!("{}-{}.tmp", nonce, attempt));
        }
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
        {
            Ok(f) => {
                file = Some(f);
                break;
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(Error::Network(format!(
                    "Failed to create {} temp file: {}",
                    label, e
                )));
            }
        }
    }
    {
        use std::io::Write;
        let mut f = file.ok_or_else(|| {
            Error::Network(format!("Failed to create {} temp file: no free name", label))
        })?;
        f.write_all(content.as_bytes())
            .map_err(|e| Error::Network(format!("Failed to write {}: {}", label, e)))?;
    }
    fs::rename(&tmp_path, path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        Error::Network(format!("Failed to finalize {}: {}", label, e))
    })
}

/// Allocate an address and durably claim it, retrying when another process
/// wins the same address first.
///
/// Each process allocates from its own snapshot of the pool, so concurrent
/// creators pick the same free address; the lease store is the arbiter.
pub fn allocate_and_record(
    allocator: &mut IpAllocator,
    lease_store: &NetworkLeaseStore,
    network: &str,
    owner: &str,
) -> Result<IpAddr> {
    for _ in 0..256 {
        let ip = allocator.allocate(network)?;
        match lease_store.record(network, owner, ip) {
            Ok(()) => return Ok(ip),
            // Address taken between our read and our write: the allocator
            // has already marked it used, so the next round picks another.
            Err(Error::Network(msg)) if msg.contains("already leased") => continue,
            Err(e) => return Err(e),
        }
    }
    Err(Error::Network(format!(
        "Could not claim a free address on network '{}' after 256 attempts",
        network
    )))
}

/// Exclusive advisory lock held for a read-modify-write of a state file.
///
/// Separate blackship processes racing on the same lease file would
/// otherwise lose updates: both read, both write, one wins.
struct FileLock {
    file: fs::File,
}

impl FileLock {
    fn acquire(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| Error::Network(format!("Failed to create lock dir: {}", e)))?;
        }
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|e| Error::Network(format!("Failed to open lock file: {}", e)))?;
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(&file);
        if unsafe { libc::flock(fd, libc::LOCK_EX) } != 0 {
            return Err(Error::Network(format!(
                "Failed to lock {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            )));
        }
        Ok(Self { file })
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(&self.file);
        unsafe {
            libc::flock(fd, libc::LOCK_UN);
        }
    }
}

fn validate_network_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidArgument(
            "Network name cannot be empty".into(),
        ));
    }

    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(Error::InvalidArgument(format!(
            "Invalid network name '{}': use only letters, numbers, '.', '-' and '_'",
            name
        )));
    }

    Ok(())
}

fn data_root_from_config(config: Option<&manifest::BlackshipConfig>) -> PathBuf {
    config
        .map(|cfg| cfg.config.data_dir.clone())
        .unwrap_or_else(default_unconfigured_data_dir)
}

fn default_unconfigured_data_dir() -> PathBuf {
    PathBuf::from("/var/blackship")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_store_root() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("blackship-network-store-{}", unique))
    }

    #[test]
    fn test_network_name_validation() {
        validate_network_name("default").unwrap();
        validate_network_name("prod-net_1").unwrap();
        assert!(validate_network_name("../bad").is_err());
        assert!(validate_network_name("bad/name").is_err());
        assert!(validate_network_name("").is_err());
    }

    #[test]
    fn test_store_round_trip() {
        let root = temp_store_root();
        let store = NetworkStore {
            root: root.join("networks"),
        };
        let record = NetworkRecord {
            name: "default".into(),
            bridge: "blackship0".into(),
            subnet: "10.0.1.0/24".into(),
            gateway: "10.0.1.1".into(),
            backend: "epair".into(),
            host_iface: None,
        };

        store.create(&record).unwrap();
        assert_eq!(store.get("default").unwrap(), Some(record.clone()));

        let list = store.list().unwrap();
        assert_eq!(list, vec![record]);

        assert!(store.delete("default").unwrap());
        assert_eq!(store.get("default").unwrap(), None);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_duplicate_create_fails() {
        let root = temp_store_root();
        let store = NetworkStore {
            root: root.join("networks"),
        };
        let record = NetworkRecord {
            name: "default".into(),
            bridge: "blackship0".into(),
            subnet: "10.0.1.0/24".into(),
            gateway: "10.0.1.1".into(),
            backend: "epair".into(),
            host_iface: None,
        };

        store.create(&record).unwrap();
        let err = store.create(&record).unwrap_err();
        assert!(matches!(err, Error::NetworkAlreadyExists(ref name) if name == "default"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_network_leases_round_trip() {
        let root = temp_store_root();
        let store = NetworkLeaseStore {
            root: root.join("network-leases"),
        };

        store
            .record("default", "demo-web", "10.0.1.10".parse().unwrap())
            .unwrap();
        assert_eq!(
            store.list("default").unwrap(),
            vec![NetworkLeaseRecord {
                owner: "demo-web".into(),
                ip: "10.0.1.10".into(),
            }]
        );

        assert!(store.release("default", "demo-web").unwrap());
        assert!(store.list("default").unwrap().is_empty());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_vnet_state_round_trip() {
        let root = temp_store_root();
        let store = VnetStateStore {
            root: root.join("vnet"),
        };
        let record = VnetStateRecord {
            owner: "demo-web".into(),
            network: Some("default".into()),
            bridge: "blackship0".into(),
            host_interface: "e0a_demoweb".into(),
            jail_interface: "e0b_demoweb".into(),
            backend: "epair".into(),
        };

        store.save(&record).unwrap();
        assert_eq!(store.get("demo-web").unwrap(), Some(record));
        assert!(store.delete("demo-web").unwrap());
        assert_eq!(store.get("demo-web").unwrap(), None);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_allocator_ignores_static_ip_for_missing_runtime_network() {
        let root = temp_store_root();
        fs::create_dir_all(&root).unwrap();
        let config: manifest::BlackshipConfig = toml::from_str(&format!(
            r#"
[config]
project = "demo"
data_dir = "{}"

[[jails]]
name = "web"
release = "15.0-RELEASE"

[jails.network]
networks = ["missing"]
ip = "10.0.1.10"
"#,
            root.display()
        ))
        .unwrap();

        let result = build_runtime_allocator(Some(&config));
        assert!(result.is_ok());

        fs::remove_dir_all(root).unwrap();
    }
}
