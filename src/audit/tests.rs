use super::*;

fn temp_root() -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("blackship-audit-{unique}"))
}

#[test]
fn appends_and_reads_back_in_order() {
    let root = temp_root();
    let log = AuditLog::new(root.clone());

    log.append(&AuditRecord::new("demo", AuditEvent::Created))
        .unwrap();
    log.append(&AuditRecord::new("demo", AuditEvent::Provisioned).with("step", "zfs"))
        .unwrap();
    log.append(&AuditRecord::new("demo", AuditEvent::Running).with("jid", 42))
        .unwrap();

    let records = log.read("demo").unwrap();
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].event, AuditEvent::Created);
    assert_eq!(
        records[1].detail.get("step").map(String::as_str),
        Some("zfs")
    );
    assert_eq!(records[2].detail.get("jid").map(String::as_str), Some("42"));

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn rotation_preserves_history_across_generations() {
    let root = temp_root();
    let log = AuditLog::new(root.clone());

    log.append(&AuditRecord::new("demo", AuditEvent::Created))
        .unwrap();

    let path = root.join("demo.jsonl");
    let padding = vec![b'\n'; MAX_LOG_BYTES as usize];
    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(&padding)
        .unwrap();

    log.append(&AuditRecord::new("demo", AuditEvent::Destroyed))
        .unwrap();

    assert!(root.join("demo.jsonl.1").exists());
    let records = log.read("demo").unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].event, AuditEvent::Created);
    assert_eq!(records[1].event, AuditEvent::Destroyed);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn read_tolerates_missing_and_malformed_lines() {
    let root = temp_root();
    let log = AuditLog::new(root.clone());
    assert!(log.read("absent").unwrap().is_empty());

    log.append(&AuditRecord::new("demo", AuditEvent::Created))
        .unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(root.join("demo.jsonl"))
        .unwrap()
        .write_all(b"{ not json\n\n")
        .unwrap();

    assert_eq!(log.read("demo").unwrap().len(), 1);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn rejects_path_traversal() {
    let log = AuditLog::new(temp_root());
    assert!(log.read("../escape").is_err());
    assert!(
        log.append(&AuditRecord::new("a/b", AuditEvent::Created))
            .is_err()
    );
}
