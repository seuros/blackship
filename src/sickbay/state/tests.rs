use super::*;

#[test]
fn store_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let store = HealthStateStore::new(dir.path().join("health"));
    let record = HealthStateRecord {
        jail: "project-web".to_string(),
        status: HealthStatus::Healthy,
        checked_at: 123,
        jid: Some(7),
        checks_total: 2,
        checks_passing: 2,
        checks_failing: 0,
    };

    store.save(&record).unwrap();

    assert_eq!(store.get("project-web").unwrap(), Some(record));
}

#[test]
fn store_rejects_path_traversal() {
    let dir = tempfile::tempdir().unwrap();
    let store = HealthStateStore::new(dir.path().join("health"));
    let record = HealthStateRecord {
        jail: "../other".to_string(),
        status: HealthStatus::Unknown,
        checked_at: 123,
        jid: None,
        checks_total: 0,
        checks_passing: 0,
        checks_failing: 0,
    };

    assert!(store.save(&record).is_err());
    assert!(store.get("../other").is_err());
}

#[test]
fn store_rejects_mismatched_record_name() {
    let dir = tempfile::tempdir().unwrap();
    let store = HealthStateStore::new(dir.path().join("health"));
    let record = HealthStateRecord {
        jail: "project-api".to_string(),
        status: HealthStatus::Healthy,
        checked_at: 123,
        jid: Some(7),
        checks_total: 1,
        checks_passing: 1,
        checks_failing: 0,
    };
    store.save(&record).unwrap();
    std::fs::rename(
        dir.path().join("health/project-api.toml"),
        dir.path().join("health/project-web.toml"),
    )
    .unwrap();

    assert!(store.get("project-web").is_err());
}

#[test]
fn delete_removes_the_record_and_tolerates_absence() {
    let dir = tempfile::tempdir().unwrap();
    let store = HealthStateStore::new(dir.path().join("health"));
    let record = HealthStateRecord {
        jail: "project-web".to_string(),
        status: HealthStatus::Healthy,
        checked_at: 1,
        jid: Some(3),
        checks_total: 1,
        checks_passing: 1,
        checks_failing: 0,
    };
    store.save(&record).unwrap();

    store.delete("project-web").unwrap();
    assert_eq!(store.get("project-web").unwrap(), None);
    store.delete("project-web").unwrap();
    assert!(store.delete("../other").is_err());
}
