#[cfg(test)]
mod tests {
    use super::super::Bridge;
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
}
