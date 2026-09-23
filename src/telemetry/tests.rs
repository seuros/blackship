use super::*;
use crate::audit::{AuditEvent, AuditRecord};

#[test]
fn parses_full_config() {
    let cfg: TelemetryConfig = toml::from_str(
        r#"
        endpoint = "http://collector.internal:4318"
        service_name = "fleet-jails"
        timeout_secs = 5
        metrics_interval_secs = 10

        [headers]
        authorization = "Bearer redacted"
        "#,
    )
    .unwrap();

    assert_eq!(
        cfg.endpoint.as_deref(),
        Some("http://collector.internal:4318")
    );
    assert_eq!(cfg.service_name, "fleet-jails");
    assert_eq!(cfg.timeout_secs, Some(5));
    assert_eq!(cfg.metrics_interval_secs, Some(10));
    assert_eq!(
        cfg.headers.get("authorization").map(String::as_str),
        Some("Bearer redacted")
    );
}

#[test]
fn empty_config_defaults_to_local_collector() {
    let cfg: TelemetryConfig = toml::from_str("").unwrap();
    assert_eq!(cfg.endpoint, None);
    assert_eq!(cfg.service_name, DEFAULT_SERVICE_NAME);
    assert!(cfg.headers.is_empty());
}

#[test]
fn rejects_invalid_headers() {
    let mut headers = BTreeMap::new();
    headers.insert("bad header".to_string(), "value".to_string());
    assert!(build_headers(&headers).is_err());

    let mut headers = BTreeMap::new();
    headers.insert("x-token".to_string(), "value".to_string());
    assert!(build_headers(&headers).is_ok());
}

#[test]
fn emit_and_shutdown_are_noops_when_uninitialized() {
    init(None);
    assert!(meter().is_none());
    emit(&AuditRecord::new("demo", AuditEvent::Created));
    shutdown();
}
