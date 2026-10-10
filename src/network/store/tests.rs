use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_store_root() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("blackship-network-store-{unique}"))
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
