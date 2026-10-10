use super::*;

#[test]
fn test_resolve_stop_prefers_manifest_over_jailfile() {
    let dir = std::env::temp_dir().join(format!("blackship-stop-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
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

    std::fs::remove_dir_all(&dir).ok();
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
