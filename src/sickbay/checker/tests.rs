use super::*;

#[test]
fn test_health_status_display() {
    assert_eq!(HealthStatus::Healthy.to_string(), "healthy");
    assert_eq!(HealthStatus::Failing.to_string(), "failing");
    assert_eq!(HealthStatus::Starting.to_string(), "starting");
    assert_eq!(HealthStatus::Suspended.to_string(), "suspended");
}

#[test]
fn test_health_check_builder() {
    let check = HealthCheck::new("http", "curl -sf http://localhost:8080/health")
        .with_target(CheckTarget::Jail)
        .with_interval(15)
        .with_timeout(5)
        .with_retries(5);

    assert_eq!(check.name, "http");
    assert_eq!(check.interval, 15);
    assert_eq!(check.timeout, 5);
    assert_eq!(check.retries, 5);
}

#[test]
fn test_health_config_builder() {
    let config = HealthCheckConfig::enabled()
        .with_check(HealthCheck::new("test", "true"))
        .with_check(HealthCheck::new("test2", "true"));

    assert!(config.enabled);
    assert_eq!(config.checks.len(), 2);
}

#[test]
fn test_health_checker_creation() {
    let config = HealthCheckConfig::enabled().with_check(HealthCheck::new("test", "true"));

    let checker = HealthChecker::new("testjail", config);
    assert_eq!(checker.jail_name(), "testjail");
    assert!(checker.is_enabled());
}

#[test]
fn test_health_check_deserialize() {
    let toml = r#"
name = "http"
command = "curl -sf http://localhost/health"
target = "jail"
interval = 30
timeout = 10
start_period = 60
retries = 3
"#;

    let check: HealthCheck = toml::from_str(toml).unwrap();
    assert_eq!(check.name, "http");
    assert_eq!(check.target, CheckTarget::Jail);
    assert_eq!(check.interval, 30);
}
