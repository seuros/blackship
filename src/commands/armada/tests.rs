use super::*;

#[test]
fn the_resolved_view_never_carries_a_telemetry_secret() {
    let config: manifest::BlackshipConfig = toml::from_str(
        r#"
[config]
project = "demo"
data_dir = "/var/demo"

[telemetry]
endpoint = "http://collector:4318"
[telemetry.headers]
authorization = "Bearer super-secret-token"

[[jails]]
name = "db"
release = "16.0-CURRENT"

[[jails]]
name = "web"
path = "/jails/web"
depends_on = ["db"]
"#,
    )
    .unwrap();

    let value = serde_json::to_value(ResolvedConfig::from(&config)).unwrap();
    let rendered = value.to_string();

    assert!(!rendered.contains("super-secret-token"), "{rendered}");
    assert!(!rendered.contains("authorization"), "{rendered}");
    assert_eq!(value["config"]["project"], "demo");
    assert_eq!(value["jails"][1]["name"], "web");
    assert_eq!(value["jails"][1]["depends_on"][0], "db");
}

#[test]
fn build_flags_map_to_one_mode_and_one_json_name() {
    assert!(matches!(build_mode(false, true), (None, "none")));
    assert!(matches!(
        build_mode(true, false),
        (Some(BuildMode::Force), "force")
    ));
    assert!(matches!(
        build_mode(false, false),
        (Some(BuildMode::IfMissing), "if_missing")
    ));
}
