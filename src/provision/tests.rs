use super::*;

#[test]
fn test_arch_detection() {
    let arch = Arch::current();
    assert!(arch.is_ok());
}

#[test]
fn test_manifest_parsing() {
    let provisioner = Provisioner {
        mirror_url: String::new(),
        releases_dir: PathBuf::new(),
        cache_dir: PathBuf::new(),
        archives: vec![],
        arch: Arch::Amd64,
        retry_config: RetryConfig::default(),
    };

    let manifest = "base.txz\tabc123\t100\t1000\nkernel.txz\tdef456\t50\t500";
    let checksums = provisioner.parse_manifest(manifest);

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

    let url = provisioner.archive_url("14.2-RELEASE", "base");
    assert_eq!(
        url,
        "https://download.freebsd.org/releases/amd64/14.2-RELEASE/base.txz"
    );
}
