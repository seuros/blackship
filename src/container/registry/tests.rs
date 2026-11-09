use super::*;
use crate::host::Host;

fn scratch_host(tag: &str) -> (Host, tempfile::TempDir) {
    let dir = tempfile::Builder::new()
        .prefix(&format!("blackship-registry-{tag}-"))
        .tempdir()
        .expect("scratch dir");
    (Host::new(dir.path()), dir)
}

fn record(owner_pid: Option<u32>) -> Record {
    Record {
        release: "16.0-CURRENT".into(),
        root: PathBuf::from("/nonexistent/root"),
        dataset: None,
        owner_pid,
        labels: BTreeMap::from([("job".to_string(), "42".to_string())]),
    }
}

#[test]
fn a_name_can_only_be_claimed_once() {
    let (host, _dir) = scratch_host("claim");
    let layout = host.layout();
    claim(layout, "kim-1", &record(Some(std::process::id()))).unwrap();
    match claim(layout, "kim-1", &record(None)) {
        Err(Error::JailExists(name)) => assert_eq!(name, "kim-1"),
        other => panic!("expected JailExists, got {other:?}"),
    }
    remove(layout, "kim-1").unwrap();
    claim(layout, "kim-1", &record(None)).unwrap();
}

#[test]
fn removing_a_missing_record_is_fine() {
    let (host, _dir) = scratch_host("remove");
    remove(host.layout(), "never-was").unwrap();
}

#[test]
fn a_dead_owner_makes_an_orphan_and_keep_clears_it() {
    let (host, _dir) = scratch_host("orphan");
    let layout = host.layout();
    // pid_t max on FreeBSD is 99999; this one cannot be running.
    claim(layout, "kim-dead", &record(Some(999_999))).unwrap();
    claim(layout, "kim-live", &record(Some(std::process::id()))).unwrap();

    let infos = list(layout);
    let dead = infos.iter().find(|i| i.name == "kim-dead").unwrap();
    let live = infos.iter().find(|i| i.name == "kim-live").unwrap();
    assert!(dead.is_orphan());
    assert!(!live.is_orphan());
    assert_eq!(dead.labels.get("job").map(String::as_str), Some("42"));
    assert_eq!(dead.release.as_deref(), Some("16.0-CURRENT"));

    disown(layout, "kim-dead").unwrap();
    let infos = list(layout);
    assert!(!infos.iter().any(ContainerInfo::is_orphan));
}

#[test]
fn selector_needs_every_criterion() {
    let info = ContainerInfo {
        name: "kim-7".into(),
        root: PathBuf::new(),
        dataset: None,
        jid: None,
        release: None,
        labels: BTreeMap::from([("runner".to_string(), "bastion".to_string())]),
        owner_pid: None,
    };
    assert!(Selector::all().matches(&info));
    assert!(Selector::prefix("kim-").matches(&info));
    assert!(!Selector::prefix("ci-").matches(&info));
    assert!(Selector::label("runner", "bastion").matches(&info));
    assert!(
        !Selector::prefix("kim-")
            .and_label("runner", "forge")
            .matches(&info)
    );
}
