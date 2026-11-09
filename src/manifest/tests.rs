use super::*;

#[test]
fn test_resolve_stop_prefers_manifest_over_jailfile() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let jailfile = dir.join("Jailfile");
    std::fs::write(&jailfile, "FROM 15.1-RELEASE\nSTOP from-jailfile\n").unwrap();

    let from_jailfile: JailDef = toml::from_str(&format!(
        r#"
name = "web"
jailfile = "{}"
"#,
        jailfile.display()
    ))
    .unwrap();
    assert_eq!(
        from_jailfile.resolve_stop(),
        Some("from-jailfile".to_string())
    );

    let overridden: JailDef = toml::from_str(&format!(
        r#"
name = "web"
jailfile = "{}"
stop = "from-manifest"
"#,
        jailfile.display()
    ))
    .unwrap();
    assert_eq!(overridden.resolve_stop(), Some("from-manifest".to_string()));

    let neither: JailDef = toml::from_str("name = \"web\"\n").unwrap();
    assert_eq!(neither.resolve_stop(), None);
}

#[test]
fn test_parse_minimal_config() {
    let toml = r#"
[config]
data_dir = "/var/blackship"

[[jails]]
name = "test"
path = "/jails/test"
"#;

    let config: BlackshipConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.jails.len(), 1);
    assert_eq!(config.jails[0].name, "test");
}

#[test]
fn test_parse_full_config() {
    let toml = r#"
[config]
data_dir = "/var/blackship"
zfs_enabled = true
zpool = "zroot"

[[networks]]
name = "backend"
subnet = "10.0.1.0/24"
gateway = "10.0.1.1"

[[jails]]
name = "postgres"
path = "/jails/postgres"
hostname = "db.local"

[jails.params]
"allow.raw_sockets" = true
"exec.start" = "/bin/sh /etc/rc"

[jails.network]
networks = ["backend"]
ip = "10.0.1.10"

[[jails]]
name = "webapp"
path = "/jails/webapp"
depends_on = ["postgres"]
"#;

    let config: BlackshipConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.jails.len(), 2);
    assert_eq!(config.jails[1].depends_on, vec!["postgres"]);
    assert!(config.validate().is_ok());
}

#[test]
fn test_duplicate_name_error() {
    let toml = r#"
[config]
data_dir = "/var/blackship"

[[jails]]
name = "test"
path = "/jails/test"

[[jails]]
name = "test"
path = "/jails/test2"
"#;

    let config: BlackshipConfig = toml::from_str(toml).unwrap();
    assert!(config.validate().is_err());
}

#[test]
fn test_unknown_dependency_error() {
    let toml = r#"
[config]
data_dir = "/var/blackship"

[[jails]]
name = "webapp"
path = "/jails/webapp"
depends_on = ["nonexistent"]
"#;

    let config: BlackshipConfig = toml::from_str(toml).unwrap();
    assert!(config.validate().is_err());
}

#[test]
fn test_parse_config_without_data_dir() {
    // data_dir should default to XDG path when not specified
    let toml = r#"
[config]

[[jails]]
name = "test"
path = "/jails/test"
"#;

    let config: BlackshipConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.jails.len(), 1);
    // data_dir should be set to XDG default
    assert!(
        config
            .config
            .data_dir
            .to_string_lossy()
            .contains("blackship")
    );
}

#[test]
fn test_xdg_paths() {
    // Test that XDG functions return expected structure
    let data_dir = get_xdg_data_dir();
    let cache_dir = get_xdg_cache_dir();

    assert!(data_dir.to_string_lossy().ends_with("blackship"));
    assert!(cache_dir.to_string_lossy().ends_with("blackship"));
}

#[test]
fn test_jail_lookup_matches_prefixed_and_unprefixed_names() {
    let toml = r#"
[config]
project = "demo"

[[jails]]
name = "web"

[[jails]]
name = "demo-api"
"#;
    let config: BlackshipConfig = toml::from_str(toml).unwrap();

    assert_eq!(config.jail_name("web"), "demo-web");
    assert_eq!(config.jail_name("demo-api"), "demo-api");

    assert_eq!(config.get_jail("web").map(|j| j.name.as_str()), Some("web"));
    assert_eq!(
        config.get_jail("demo-web").map(|j| j.name.as_str()),
        Some("web")
    );
    assert_eq!(
        config.get_jail("demo-api").map(|j| j.name.as_str()),
        Some("demo-api")
    );
    assert!(config.get_jail("demo-nope").is_none());
    assert!(config.get_jail("other-web").is_none());

    assert_eq!(
        config.resolve_jail_names("we"),
        Some(("web".to_string(), "demo-web".to_string()))
    );
    assert_eq!(
        config.resolve_jail_names("demo-a"),
        Some(("demo-api".to_string(), "demo-api".to_string()))
    );
    // "demo" and "demo-" prefix both jails' full names: ambiguous.
    assert!(config.resolve_jail_names("demo").is_none());
    assert!(config.resolve_jail_names("demo-").is_none());
    assert!(config.resolve_jail_names("zzz").is_none());
}

#[test]
fn default_global_config_matches_an_empty_config_table() {
    let parsed: BlackshipConfig = toml::from_str("[config]\n").unwrap();
    let built = BlackshipConfig::default();
    assert_eq!(
        toml::to_string(&parsed).unwrap(),
        toml::to_string(&built).unwrap()
    );
}

#[test]
fn test_project_name_ignores_path_spelling() {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("orbital");
    std::fs::create_dir_all(project.join("sub")).unwrap();
    std::fs::write(project.join("blackship.toml"), "").unwrap();

    assert_eq!(
        project_name_from_path(&project.join("blackship.toml")),
        "orbital"
    );
    assert_eq!(
        project_name_from_path(&project.join("sub/../blackship.toml")),
        "orbital"
    );
    assert_eq!(
        project_name_from_path(&project.join("./blackship.toml")),
        "orbital"
    );
}

fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).unwrap();
    path
}

#[test]
fn test_merge_override_keeps_what_it_does_not_write() {
    let tmp = tempfile::tempdir().unwrap();
    let base = write(
        tmp.path(),
        "base.toml",
        r#"
[config]
zfs_enabled = true
zpool = "tank"
dataset = "fleet"

[[jails]]
name = "cache"
release = "15.1-RELEASE"
hostname = "cache.local"
depends_on = ["db"]

[[jails]]
name = "db"
release = "15.1-RELEASE"
"#,
    );
    // No [config] at all: an override file only says what changes.
    let prod = write(
        tmp.path(),
        "prod.toml",
        r#"
[[jails]]
name = "cache"
hostname = "cache-prod.local"

[[jails]]
name = "worker"
release = "15.1-RELEASE"
"#,
    );

    let config = load_merged(&[base, prod]).unwrap();

    assert!(
        config.config.zfs_enabled,
        "zfs_enabled must survive an override that omits it"
    );
    assert_eq!(config.config.zpool.as_deref(), Some("tank"));
    assert_eq!(config.config.dataset, "fleet");

    let cache = config.get_jail("cache").unwrap();
    assert_eq!(cache.hostname.as_deref(), Some("cache-prod.local"));
    assert_eq!(cache.release.as_deref(), Some("15.1-RELEASE"));
    assert_eq!(cache.depends_on, ["db"]);

    let names: Vec<_> = config.jails.iter().map(|j| j.name.as_str()).collect();
    assert_eq!(names, ["cache", "db", "worker"]);
}

#[test]
fn test_merge_later_file_can_switch_settings_off() {
    let tmp = tempfile::tempdir().unwrap();
    let base = write(tmp.path(), "base.toml", "[config]\nzfs_enabled = true\n");
    let local = write(tmp.path(), "local.toml", "[config]\nzfs_enabled = false\n");

    assert!(!load_merged(&[base, local]).unwrap().config.zfs_enabled);
}

#[test]
fn test_static_ip_reads_ip_cidr_and_ip() {
    let cidr: JailNetworkConfig = toml::from_str("ip_cidr = \"10.77.0.30/24\"").unwrap();
    assert_eq!(cidr.static_ip(), Some("10.77.0.30".parse().unwrap()));

    let bare: JailNetworkConfig = toml::from_str("ip = \"10.77.0.31\"").unwrap();
    assert_eq!(bare.static_ip(), Some("10.77.0.31".parse().unwrap()));

    let none: JailNetworkConfig = toml::from_str("vnet = true").unwrap();
    assert_eq!(none.static_ip(), None);
}
