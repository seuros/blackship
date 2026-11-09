use super::*;

#[test]
fn new_host_keeps_everything_under_data_dir() {
    let host = Host::new("/var/db/kim");
    assert_eq!(host.data_dir(), Path::new("/var/db/kim"));
    assert_eq!(host.releases_dir(), Path::new("/var/db/kim/releases"));
    assert_eq!(
        host.layout().container_root("kim-1"),
        Path::new("/var/db/kim/containers/kim-1")
    );
    assert!(!host.uses_zfs());
    assert!(host.layout().state_config().is_some());
}

#[test]
fn with_zfs_enables_dataset_backing() {
    let host = Host::new("/var/db/kim").with_zfs("zroot", "kim/blackship");
    assert!(host.uses_zfs());
    let zfs = host.layout().zfs().unwrap();
    assert_eq!(
        zfs.container_dataset("kim-1"),
        "zroot/kim/blackship/containers/kim-1"
    );
}

#[test]
fn builders_do_not_leak_into_existing_clones() {
    let base = Host::new("/a");
    let moved = base.clone().with_releases_dir("/b");
    assert_eq!(base.releases_dir(), Path::new("/a/releases"));
    assert_eq!(moved.releases_dir(), Path::new("/b"));
}

#[test]
fn manifestless_cli_host_keeps_the_legacy_state_root() {
    let host = Host::from_config(None);
    assert!(host.layout().state_config().is_none());
}

#[test]
fn host_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Host>();
}
