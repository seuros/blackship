use super::*;

#[test]
fn test_dataset_paths() {
    let zfs = ZfsManager::new("zroot", "blackship", "/var/blackship/jails");
    assert_eq!(zfs.jails_dataset(), "zroot/blackship/jails");
    assert_eq!(zfs.jail_dataset("test"), "zroot/blackship/jails/test");
    assert_eq!(
        zfs.jail_path("test"),
        PathBuf::from("/var/blackship/jails/test")
    );
}
