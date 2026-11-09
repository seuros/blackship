use super::*;

#[test]
fn test_arch_detection() {
    let arch = Arch::current();
    assert!(arch.is_ok());
}

#[test]
fn test_manifest_parsing() {
    let manifest = "base.txz\tabc123\t100\t1000\nkernel.txz\tdef456\t50\t500";
    let checksums = Provisioner::parse_manifest(manifest);

    assert_eq!(checksums.get("base"), Some(&"abc123".to_string()));
    assert_eq!(checksums.get("kernel"), Some(&"def456".to_string()));
}

#[test]
fn test_archive_url() {
    let provisioner = Provisioner {
        mirror_url: "https://download.freebsd.org/releases".to_string(),
        releases_dir: PathBuf::new(),
        cache_dir: PathBuf::new(),
        archives: vec![],
        arch: Arch::Amd64,
        retry_config: RetryConfig::default(),
    };

    let url = provisioner.archive_url("15.1-RELEASE", "base");
    assert_eq!(
        url,
        "https://download.freebsd.org/releases/amd64/15.1-RELEASE/base.txz"
    );
}

#[test]
fn test_unbootstrapped_releases_warns_per_jail() {
    let tmp = tempfile::tempdir().unwrap();
    let releases = tmp.path().join("releases");
    std::fs::create_dir_all(releases.join("15.1-RELEASE/bin")).unwrap();
    std::fs::create_dir_all(releases.join("15.1-RELEASE/usr")).unwrap();
    let config: crate::manifest::BlackshipConfig = toml::from_str(&format!(
        "[config]\nreleases_dir = \"{}\"\n\n[[jails]]\nname = \"ok\"\nrelease = \"15.1-RELEASE\"\n\n\
         [[jails]]\nname = \"missing\"\nrelease = \"14.3-RELEASE\"\n\n[[jails]]\nname = \"built\"\n",
        releases.display()
    ))
    .unwrap();

    let warnings = unbootstrapped_releases(&config);
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains("`missing`") && warnings[0].contains("14.3-RELEASE"));
}
