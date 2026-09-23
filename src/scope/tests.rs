use super::*;

fn temp_root() -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("blackship-scope-{}", unique))
}

#[test]
fn round_trips_through_toml() {
    let root = temp_root();
    let store = ScopeStore::new(root.clone());

    let mut record = ScopeRecord::new("demo-web");
    record.jid = Some(42);
    record.phase = ScopePhase::Running;
    record.ephemeral = true;
    record.zfs_dataset = Some("zroot/blackship/jails/demo-web".into());
    record.zfs_origin = Some("zroot/blackship/releases/15.0@pristine".into());
    record.has_vnet_record = true;
    record.rctl_subject = Some("jail:demo-web".into());
    record.mounts = vec![PathBuf::from("/jails/demo-web/dev")];
    record.allocated_ips = vec!["10.0.0.5".parse().unwrap()];
    record.qos_phase = QosPhase::Startup;
    record.cascade = CascadePolicy::Isolate;

    store.save(&record).unwrap();
    let loaded = store.get("demo-web").unwrap().expect("record present");

    assert_eq!(loaded.name, "demo-web");
    assert_eq!(loaded.jid, Some(42));
    assert_eq!(loaded.phase, ScopePhase::Running);
    assert_eq!(loaded.qos_phase, QosPhase::Startup);
    assert_eq!(loaded.cascade, CascadePolicy::Isolate);
    assert_eq!(
        loaded.zfs_origin.as_deref(),
        Some("zroot/blackship/releases/15.0@pristine")
    );
    assert_eq!(loaded.allocated_ips, record.allocated_ips);

    assert!(store.delete("demo-web").unwrap());
    assert!(store.get("demo-web").unwrap().is_none());
    assert!(!store.delete("demo-web").unwrap());

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn list_skips_non_toml_and_sorts() {
    let root = temp_root();
    let store = ScopeStore::new(root.clone());
    store.save(&ScopeRecord::new("zeta")).unwrap();
    store.save(&ScopeRecord::new("alpha")).unwrap();
    fs::write(root.join("notes.txt"), b"ignored").unwrap();

    let names: Vec<String> = store.list().unwrap().into_iter().map(|r| r.name).collect();
    assert_eq!(names, vec!["alpha", "zeta"]);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn update_creates_then_mutates() {
    let root = temp_root();
    let store = ScopeStore::new(root.clone());

    let created = store.update("demo", |_| {}).unwrap();
    assert_eq!(created.phase, ScopePhase::Provisioning);

    store
        .update("demo", |r| {
            r.advance_or_warn(ScopeMachineEvent::Provisioned);
            r.jid = Some(7);
        })
        .unwrap();

    let loaded = store.get("demo").unwrap().unwrap();
    assert_eq!(loaded.phase, ScopePhase::Running);
    assert_eq!(loaded.jid, Some(7));
    assert_eq!(loaded.created_at, created.created_at);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn rejects_path_traversal() {
    let store = ScopeStore::new(temp_root());
    assert!(store.get("../escape").is_err());
    assert!(store.get("sub/jail").is_err());
    assert!(store.get("").is_err());
}

#[test]
fn peak_metrics_keep_maximum() {
    let mut peak = PeakMetrics::default();
    peak.observe(&[("memoryuse".to_string(), 100)].into_iter().collect());
    peak.observe(&[("memoryuse".to_string(), 40)].into_iter().collect());
    peak.observe(
        &[("memoryuse".to_string(), 250), ("nthr".to_string(), 12)]
            .into_iter()
            .collect(),
    );

    assert_eq!(peak.resources.get("memoryuse"), Some(&250));
    assert_eq!(peak.resources.get("nthr"), Some(&12));
    assert_eq!(peak.samples, Some(3));
}

#[test]
fn advance_follows_the_lifecycle() {
    let mut record = ScopeRecord::new("demo");
    record.advance(ScopeMachineEvent::Provisioned).unwrap();
    assert_eq!(record.phase, ScopePhase::Running);
    record.advance(ScopeMachineEvent::Drain).unwrap();
    assert_eq!(record.phase, ScopePhase::Draining);
    record.advance(ScopeMachineEvent::Terminate).unwrap();
    assert_eq!(record.phase, ScopePhase::Terminating);
    record.advance(ScopeMachineEvent::Fail).unwrap();
    assert_eq!(record.phase, ScopePhase::Failed);
}

#[test]
fn advance_rejects_illegal_transitions() {
    let mut record = ScopeRecord::new("demo");
    assert!(record.advance(ScopeMachineEvent::Drain).is_err());
    assert_eq!(record.phase, ScopePhase::Provisioning);

    record.advance(ScopeMachineEvent::Terminate).unwrap();
    assert!(record.advance(ScopeMachineEvent::Provisioned).is_err());
    assert_eq!(record.phase, ScopePhase::Terminating);
}

#[test]
fn advance_restores_the_machine_from_disk() {
    let root = temp_root();
    let store = ScopeStore::new(root.clone());

    let mut record = ScopeRecord::new("demo");
    record.advance(ScopeMachineEvent::Provisioned).unwrap();
    store.save(&record).unwrap();

    let mut loaded = store.get("demo").unwrap().unwrap();
    assert!(loaded.advance(ScopeMachineEvent::Provisioned).is_err());
    loaded.advance(ScopeMachineEvent::Drain).unwrap();
    assert_eq!(loaded.phase, ScopePhase::Draining);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn holds_resources_tracks_claims() {
    let mut record = ScopeRecord::new("demo");
    assert!(!record.holds_resources());
    record.has_vnet_record = true;
    assert!(record.holds_resources());
}
