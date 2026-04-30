//! Persistent network metadata storage.
//!
//! The `blackship network` CLI manages named networks. Those names need
//! durable metadata so `create`, `list`, and `destroy` operate on the same
//! logical object instead of guessing from bridge names.

use crate::error::{Error, Result};
use crate::manifest;
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkRecord {
    pub name: String,
    pub bridge: String,
    pub subnet: String,
    pub gateway: String,
}

#[derive(Debug, Clone)]
pub struct NetworkStore {
    root: PathBuf,
}

impl NetworkStore {
    pub fn from_config(config: Option<&manifest::BlackshipConfig>) -> Self {
        let data_dir = config
            .map(|cfg| cfg.config.data_dir.clone())
            .unwrap_or_else(default_unconfigured_data_dir);

        Self {
            root: data_dir.join("networks"),
        }
    }

    pub fn create(&self, record: &NetworkRecord) -> Result<()> {
        validate_network_name(&record.name)?;
        fs::create_dir_all(&self.root)
            .map_err(|e| Error::Network(format!("Failed to create network state dir: {}", e)))?;

        let path = self.record_path(&record.name)?;
        if path.exists() {
            return Err(Error::NetworkAlreadyExists(record.name.clone()));
        }

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

        read_record(&path)
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

            if let Some(record) = read_record(&path)? {
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

fn read_record(path: &Path) -> Result<Option<NetworkRecord>> {
    let content = fs::read_to_string(path)
        .map_err(|e| Error::Network(format!("Failed to read network metadata: {}", e)))?;
    let record: NetworkRecord = toml::from_str(&content)
        .map_err(|e| Error::Network(format!("Failed to parse network metadata: {}", e)))?;
    Ok(Some(record))
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
        let store = NetworkStore { root: root.clone() };
        let record = NetworkRecord {
            name: "default".into(),
            bridge: "blackship0".into(),
            subnet: "10.0.1.0/24".into(),
            gateway: "10.0.1.1".into(),
        };

        store.create(&record).unwrap();
        assert_eq!(store.get("default").unwrap(), Some(record.clone()));

        let list = store.list().unwrap();
        assert_eq!(list, vec![record]);

        assert!(store.delete("default").unwrap());
        assert_eq!(store.get("default").unwrap(), None);

        fs::remove_dir_all(root).unwrap();
    }
}
