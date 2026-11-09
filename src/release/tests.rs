use super::*;
use std::fs;

#[test]
fn freebsd_16_always_bootstraps_from_pkgbase() {
    assert!(Bootstrap::release("16.0-CURRENT").uses_pkgbase());
    assert!(!Bootstrap::release("15.1-RELEASE").uses_pkgbase());
    assert!(Bootstrap::release("15.1-RELEASE").pkgbase().uses_pkgbase());
}

#[test]
fn listing_sees_only_complete_userlands() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    fs::create_dir_all(dir.join("releases/16.0-CURRENT/bin")).unwrap();
    fs::create_dir_all(dir.join("releases/16.0-CURRENT/usr")).unwrap();
    fs::create_dir_all(dir.join("releases/half-baked/bin")).unwrap();

    let host = Host::new(&dir);
    let names: Vec<String> = host
        .releases()
        .unwrap()
        .into_iter()
        .map(|r| r.name)
        .collect();
    assert_eq!(names, ["16.0-CURRENT"]);
    assert!(host.has_release("16.0-CURRENT").unwrap());
    assert!(!host.has_release("half-baked").unwrap());
    let release = host.release("16.0-CURRENT").unwrap().unwrap();
    assert!(!release.cloneable);
    assert_eq!(release.dataset, None);
}
