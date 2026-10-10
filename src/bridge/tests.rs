use super::Bridge;
use crate::manifest::BlackshipConfig;

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
    assert!(plan.isolate.is_empty());
}

#[test]
fn test_cascade_detach_stops_only_the_target() {
    let bridge = Bridge::new(cascade_config("detach")).unwrap();
    let plan = bridge.down_plan(Some("database")).unwrap();
    assert_eq!(plan.stop, vec!["database"]);
    assert!(plan.isolate.is_empty());
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
    assert!(plan.isolate.is_empty());
    assert!(plan.stop.contains(&"backend".to_string()));
}
