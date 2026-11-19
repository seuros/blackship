use super::*;

#[test]
fn container_names_refuse_dots() {
    validate_container_name("kim-42").unwrap();
    assert!(validate_container_name("kim.42").is_err());
    assert!(validate_container_name("").is_err());
}

#[test]
fn library_calls_refuse_to_run_unprivileged() {
    if nix::unistd::geteuid().is_root() {
        return;
    }
    let host = Host::new(std::env::temp_dir().join("blackship-unprivileged"));
    match host.create(&ContainerSpec::new("kim-1", "16.0-CURRENT")) {
        Err(Error::NeedsRoot { operation, .. }) => assert_eq!(operation, "creating a container"),
        other => panic!("expected NeedsRoot, got {other:?}"),
    }
    match host.destroy_container("kim-1") {
        Err(Error::NeedsRoot { .. }) => {}
        other => panic!("expected NeedsRoot, got {other:?}"),
    }
}

#[test]
fn handles_can_cross_threads() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Container>();
    assert_send_sync::<ContainerSpec>();
}

#[test]
fn read_write_mounts_are_nosuid_unless_told_otherwise() {
    let rw = Mount::read_write("/var/db/kim/jobs/1", "/work");
    assert!(rw.is_nosuid());
    assert_eq!(rw.options(), ["rw", "nosuid"]);
    assert_eq!(rw.clone().allow_setuid().options(), ["rw"]);
    assert_eq!(rw.noexec().options(), ["rw", "nosuid", "noexec"]);

    let ro = Mount::read_only("/usr/local/share/distfiles", "/distfiles");
    assert!(!ro.is_nosuid());
    assert_eq!(ro.options(), ["ro"]);
    assert_eq!(ro.nosuid().noexec().options(), ["ro", "nosuid", "noexec"]);
}

#[test]
fn a_source_holding_the_container_root_is_refused_before_any_mount() {
    let host = tempfile::tempdir().unwrap();
    let root = host.path().join("jails/web");
    std::fs::create_dir_all(&root).unwrap();

    let error = mount_nullfs(&root, &Mount::read_only(host.path(), "/workspace")).unwrap_err();

    assert!(error.to_string().contains("contains the container root"));
    assert!(!root.join("workspace").exists());
}

#[test]
fn mount_shape_does_not_need_the_source_to_exist() {
    assert!(
        Mount::read_only("/no/such/source", "/workspace")
            .validate_shape()
            .is_ok()
    );
    assert!(
        Mount::read_only("/no/such/source", "/workspace")
            .validate()
            .is_err()
    );
    assert!(
        Mount::read_only("relative", "/workspace")
            .validate_shape()
            .is_err()
    );
}
