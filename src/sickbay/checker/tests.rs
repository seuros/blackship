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

fn host_check(command: &str) -> HealthCheck {
    let mut check = HealthCheck::new("flag", command).with_target(CheckTarget::Host);
    check.start_period = 0;
    check.retries = 2;
    check
}

fn statuses(check: HealthCheck, runs: usize) -> Vec<HealthStatus> {
    let config = HealthCheckConfig::enabled().with_check(check);
    let mut checker = HealthChecker::new("testjail", config);
    (0..runs).map(|_| checker.run_checks().unwrap()).collect()
}

#[test]
fn suspicion_is_off_unless_configured() {
    let check: HealthCheck = toml::from_str("name = \"a\"\ncommand = \"true\"").unwrap();
    assert!(check.suspicion.is_none());

    let check: HealthCheck =
        toml::from_str("name = \"a\"\ncommand = \"true\"\n[suspicion]\nfailing_phi = 9.0").unwrap();
    assert_eq!(
        check.suspicion.unwrap().failing_phi.to_bits(),
        9.0_f64.to_bits()
    );
}

#[test]
fn retry_counting_without_suspicion() {
    assert_eq!(
        statuses(host_check("false"), 3),
        [
            HealthStatus::Unhealthy,
            HealthStatus::Failing,
            HealthStatus::Failing
        ]
    );
    assert_eq!(statuses(host_check("true"), 2), [HealthStatus::Healthy; 2]);
}

#[test]
fn warming_suspicion_falls_back_to_retry_counting() {
    let suspicion = crate::sickbay::suspicion::SuspicionConfig {
        min_samples: 8,
        unhealthy_phi: 3.0,
        failing_phi: 8.0,
        min_std_dev_ms: None,
    };
    assert_eq!(
        statuses(host_check("false").with_suspicion(suspicion), 3),
        [
            HealthStatus::Unhealthy,
            HealthStatus::Failing,
            HealthStatus::Failing
        ]
    );
}
