use super::*;

#[test]
fn test_mounted_paths_under_sorts_deepest_first() {
    let mounts = mounted_paths_under(
        std::path::Path::new("/var/blackship/jails/demo"),
        "\
devfs /var/blackship/jails/demo/dev devfs rw 0 0\n\
procfs /var/blackship/jails/demo/proc procfs rw 0 0\n\
fdescfs /var/blackship/jails/demo/dev/fd fdescfs rw 0 0\n\
tmpfs /tmp tmpfs rw 0 0\n",
    );

    assert_eq!(
        mounts,
        vec![
            std::path::PathBuf::from("/var/blackship/jails/demo/dev/fd"),
            std::path::PathBuf::from("/var/blackship/jails/demo/proc"),
            std::path::PathBuf::from("/var/blackship/jails/demo/dev"),
        ]
    );
}

#[test]
fn test_parse_current() {
    let ver = OsVersion::parse("16.0-CURRENT").unwrap();
    assert_eq!(ver.major, 16);
    assert_eq!(ver.minor, 0);
    assert_eq!(ver.patch, None);
    assert_eq!(ver.release_type, ReleaseType::Current);
}

#[test]
fn test_parse_release() {
    let ver = OsVersion::parse("15.0-RELEASE").unwrap();
    assert_eq!(ver.major, 15);
    assert_eq!(ver.minor, 0);
    assert_eq!(ver.patch, None);
    assert_eq!(ver.release_type, ReleaseType::Release);
}

#[test]
fn test_parse_release_with_patch() {
    let ver = OsVersion::parse("15.0-RELEASE-p1").unwrap();
    assert_eq!(ver.major, 15);
    assert_eq!(ver.minor, 0);
    assert_eq!(ver.patch, Some(1));
    assert_eq!(ver.release_type, ReleaseType::Release);
}

#[test]
fn test_parse_stable() {
    let ver = OsVersion::parse("14.2-STABLE").unwrap();
    assert_eq!(ver.major, 14);
    assert_eq!(ver.minor, 2);
    assert_eq!(ver.release_type, ReleaseType::Stable);
}

#[test]
fn test_parse_rc() {
    let ver = OsVersion::parse("15.0-RC2").unwrap();
    assert_eq!(ver.major, 15);
    assert_eq!(ver.minor, 0);
    assert_eq!(ver.release_type, ReleaseType::Rc(2));
}

#[test]
fn test_vlan_filtering_support() {
    assert!(
        OsVersion::parse("15.0-RELEASE")
            .unwrap()
            .supports_vlan_filtering()
    );
    assert!(
        OsVersion::parse("16.0-CURRENT")
            .unwrap()
            .supports_vlan_filtering()
    );
    assert!(
        !OsVersion::parse("14.2-STABLE")
            .unwrap()
            .supports_vlan_filtering()
    );
    assert!(
        !OsVersion::parse("13.3-RELEASE")
            .unwrap()
            .supports_vlan_filtering()
    );
}

#[test]
fn test_display() {
    assert_eq!(
        OsVersion::parse("16.0-CURRENT").unwrap().to_string(),
        "16.0-CURRENT"
    );
    assert_eq!(
        OsVersion::parse("15.0-RELEASE-p1").unwrap().to_string(),
        "15.0-RELEASE-p1"
    );
}
