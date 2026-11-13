use super::Bridge;
use crate::manifest::BlackshipConfig;
use std::path::Path;

fn test_config() -> BlackshipConfig {
    toml::from_str(
        r#"
[config]
data_dir = "/var/blackship"

[[jails]]
name = "database"
path = "/jails/database"

[[jails]]
name = "backend"
path = "/jails/backend"
depends_on = ["database"]

[[jails]]
name = "frontend"
path = "/jails/frontend"
depends_on = ["backend"]
"#,
    )
    .unwrap()
}

#[test]
fn test_start_order() {
    let config = test_config();
    let bridge = Bridge::new(config).unwrap();
    let order = bridge.start_order().unwrap();
    assert_eq!(order, vec!["database", "backend", "frontend"]);
}

#[test]
fn test_stop_order() {
    let config = test_config();
    let bridge = Bridge::new(config).unwrap();
    let order = bridge.stop_order().unwrap();
    assert_eq!(order, vec!["frontend", "backend", "database"]);
}

#[test]
fn test_machine_up_plan_preserves_dependency_order() {
    let bridge = Bridge::new(test_config()).unwrap();
    let plan = serde_json::to_value(bridge.start_steps(Some("frontend")).unwrap()).unwrap();
    let plan = plan.as_array().unwrap();
    let names: Vec<_> = plan
        .iter()
        .map(|step| step["jail"].as_str().unwrap())
        .collect();

    assert_eq!(
        names,
        vec![
            "blackship-database",
            "blackship-backend",
            "blackship-frontend"
        ]
    );
    assert!(plan.iter().all(|step| step["action"] == "start"));
}

#[test]
fn test_machine_down_plan_preserves_reverse_dependency_order() {
    let bridge = Bridge::new(test_config()).unwrap();
    let plan = serde_json::to_value(bridge.stop_steps(Some("database")).unwrap()).unwrap();
    let plan = plan.as_array().unwrap();
    let names: Vec<_> = plan
        .iter()
        .map(|step| step["jail"].as_str().unwrap())
        .collect();

    assert_eq!(
        names,
        vec![
            "blackship-frontend",
            "blackship-backend",
            "blackship-database"
        ]
    );
    assert!(plan.iter().all(|step| step["action"] == "stop"));
}

#[test]
fn test_constructor_defers_zfs_initialization() {
    let config: BlackshipConfig = toml::from_str(
        r#"
[config]
data_dir = "/var/blackship"
zfs_enabled = true
zpool = "pool-that-should-not-be-touched-during-construction"

[[jails]]
name = "app"
"#,
    )
    .unwrap();

    assert!(Bridge::new(config).is_ok());
}

#[test]
fn test_inventory_identifies_manifest_owned_jails() {
    let bridge = Bridge::new(test_config()).unwrap();
    let inventory = serde_json::to_value(
        bridge.inventory_data(Path::new("/usr/local/etc/blackship/blackship.toml")),
    )
    .unwrap();
    let database = inventory["jails"]
        .as_array()
        .unwrap()
        .iter()
        .find(|jail| jail["service_name"] == "database")
        .unwrap();

    assert_eq!(inventory["project"], "blackship");
    assert_eq!(
        inventory["config_path"],
        "/usr/local/etc/blackship/blackship.toml"
    );
    assert_eq!(database["full_name"], "blackship-database");
    assert_eq!(database["manager"], "blackship");
    assert_eq!(database["managed"], true);
    assert_eq!(database["configured"], true);
    assert_eq!(database["depends_on"], serde_json::json!([]));
    assert_eq!(database["health"]["configured"], false);
    assert_eq!(database["health"]["status"], "not_configured");
}

fn cascade_config(policy: &str) -> BlackshipConfig {
    toml::from_str(&format!(
        r#"
[config]
data_dir = "/var/blackship"

[[jails]]
name = "database"
path = "/jails/database"
cascade = "{policy}"

[[jails]]
name = "backend"
path = "/jails/backend"
depends_on = ["database"]

[[jails]]
name = "frontend"
path = "/jails/frontend"
depends_on = ["backend"]
"#
    ))
    .unwrap()
}

#[test]
fn test_cascade_strict_stops_dependents() {
    let bridge = Bridge::new(cascade_config("strict")).unwrap();
    let plan = bridge.down_plan(Some("database")).unwrap();
    assert_eq!(plan.stop, vec!["frontend", "backend", "database"]);
    assert_eq!(plan.isolate, Vec::<String>::new());
}

#[test]
fn test_cascade_detach_stops_only_the_target() {
    let bridge = Bridge::new(cascade_config("detach")).unwrap();
    let plan = bridge.down_plan(Some("database")).unwrap();
    assert_eq!(plan.stop, vec!["database"]);
    assert_eq!(plan.isolate, Vec::<String>::new());
}

#[test]
fn test_cascade_isolate_fences_dependents_in_stop_order() {
    let bridge = Bridge::new(cascade_config("isolate")).unwrap();
    let plan = bridge.down_plan(Some("database")).unwrap();
    assert_eq!(plan.stop, vec!["database"]);
    assert_eq!(plan.isolate, vec!["frontend", "backend"]);
}

#[test]
fn test_stopping_wins_over_isolating_a_shared_dependent() {
    let config: BlackshipConfig = toml::from_str(
        r#"
[config]
data_dir = "/var/blackship"

[[jails]]
name = "database"
path = "/jails/database"
cascade = "isolate"

[[jails]]
name = "cache"
path = "/jails/cache"
cascade = "strict"

[[jails]]
name = "backend"
path = "/jails/backend"
depends_on = ["database", "cache"]
"#,
    )
    .unwrap();

    let bridge = Bridge::new(config).unwrap();
    let plan = bridge.down_plan(Some("all")).unwrap();
    assert_eq!(plan.isolate, Vec::<String>::new());
    assert!(plan.stop.contains(&"backend".to_string()));
}
