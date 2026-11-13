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

#[test]
#[ignore = "needs root and ZFS"]
fn init_leaves_a_shared_parent_mountpoint_alone() {
    let (Some(data_dir), Some(zfs_base)) = (
        std::env::var("BLACKSHIP_E2E_DATA_DIR").ok(),
        std::env::var("BLACKSHIP_E2E_ZFS").ok(),
    ) else {
        return;
    };
    let Some((pool, dataset)) = zfs_base.split_once('/') else {
        return;
    };
    if !nix::unistd::geteuid().is_root() {
        return;
    }
    let dataset = format!("{dataset}/mp{}", std::process::id());
    let first = PathBuf::from(&data_dir).join(format!("mp{}-a", std::process::id()));
    let second = PathBuf::from(&data_dir).join(format!("mp{}-b", std::process::id()));
    let a = ZfsManager::new(pool, &dataset, &first);
    let b = ZfsManager::new(pool, &dataset, &second);

    let outcome = (|| -> Result<()> {
        a.init()?;
        b.init()?;
        let parent = ZfsManager::get_property(&b.jails_dataset(), "mountpoint")?;
        assert_eq!(parent, first.display().to_string());
        let path = b.create_jail_dataset("web")?;
        let child = ZfsManager::get_property(&b.jail_dataset("web"), "mountpoint")?;
        assert_eq!(child, path.display().to_string());
        assert_eq!(path, second.join("web"));
        Ok(())
    })();
    let base = format!("{pool}/{dataset}");
    let _ = a.destroy_dataset(&base);
    let _ = std::fs::remove_dir_all(&first);
    let _ = std::fs::remove_dir_all(&second);
    outcome.unwrap();
}

#[test]
#[ignore = "needs root and ZFS"]
fn a_fence_makes_the_dataset_read_only_and_names_the_destination() {
    let (Some(data_dir), Some(zfs_base)) = (
        std::env::var("BLACKSHIP_E2E_DATA_DIR").ok(),
        std::env::var("BLACKSHIP_E2E_ZFS").ok(),
    ) else {
        return;
    };
    let Some((pool, dataset)) = zfs_base.split_once('/') else {
        return;
    };
    if !nix::unistd::geteuid().is_root() {
        return;
    }
    let dataset = format!("{dataset}/fence{}", std::process::id());
    let root = PathBuf::from(&data_dir).join(format!("fence{}", std::process::id()));
    let zfs = ZfsManager::new(pool, &dataset, &root);

    let outcome = (|| -> Result<()> {
        zfs.init()?;
        zfs.create_jail_dataset("web")?;
        assert_eq!(zfs.jail_migration_fence("web"), None);

        zfs.fence_jail_dataset("web", "bastion/zroot/web@42")?;
        assert_eq!(
            zfs.jail_migration_fence("web").as_deref(),
            Some("bastion/zroot/web@42")
        );
        let readonly = ZfsManager::get_property(&zfs.jail_dataset("web"), "readonly")?;
        assert_eq!(readonly, "on");

        zfs.clear_jail_migration_fence("web")?;
        assert_eq!(zfs.jail_migration_fence("web"), None);
        let readonly = ZfsManager::get_property(&zfs.jail_dataset("web"), "readonly")?;
        assert_eq!(readonly, "off");
        Ok(())
    })();
    let _ = zfs.destroy_dataset(&format!("{pool}/{dataset}"));
    let _ = std::fs::remove_dir_all(&root);
    outcome.unwrap();
}
