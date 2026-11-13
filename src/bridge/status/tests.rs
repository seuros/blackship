use super::*;
use crate::error::Error;
use crate::manifest::BlackshipConfig;
use crate::sickbay::HealthStatus;

fn health_definition() -> crate::manifest::JailDef {
    let mut config: BlackshipConfig = toml::from_str(
        r#"
[config]

[[jails]]
name = "web"

[jails.healthcheck]
enabled = true

[[jails.healthcheck.checks]]
name = "http"
command = "fetch -qo /dev/null http://127.0.0.1/"
"#,
    )
    .unwrap();
    config.jails.remove(0)
}

#[test]
fn summary_reports_health_not_configured() {
    let mut definition = health_definition();
    definition.healthcheck.enabled = false;

    let summary = managed_health_summary(&definition, true, Some(7), Ok(None));

    assert_eq!(summary.status, SummaryStatus::NotConfigured);
    assert!(!summary.configured);
    assert_eq!(summary.reason, None);
}

#[test]
fn summary_explains_unknown_states() {
    let definition = health_definition();

    let stopped = managed_health_summary(&definition, false, None, Ok(None));
    let unchecked = managed_health_summary(&definition, true, Some(7), Ok(None));
    let unavailable = managed_health_summary(
        &definition,
        true,
        Some(7),
        Err(Error::State("broken record".to_string())),
    );

    assert_eq!(stopped.reason, Some(UnknownReason::Stopped));
    assert_eq!(unchecked.reason, Some(UnknownReason::NotChecked));
    assert_eq!(unavailable.reason, Some(UnknownReason::StateUnavailable));
}

#[test]
fn summary_uses_only_health_from_current_jail_instance() {
    let definition = health_definition();
    let record = HealthStateRecord {
        jail: "blackship-web".to_string(),
        status: HealthStatus::Healthy,
        checked_at: 123,
        jid: Some(7),
        checks_total: 1,
        checks_passing: 1,
        checks_failing: 0,
    };

    let current = managed_health_summary(&definition, true, Some(7), Ok(Some(record.clone())));
    let restarted = managed_health_summary(&definition, true, Some(8), Ok(Some(record)));

    assert_eq!(current.status, SummaryStatus::Healthy);
    assert_eq!(current.checked_at, Some(123));
    assert_eq!(current.checks_passing, Some(1));
    assert_eq!(current.checks_pending, Some(0));
    assert_eq!(restarted.status, SummaryStatus::Unknown);
    assert_eq!(restarted.reason, Some(UnknownReason::StaleJid));
    assert_eq!(restarted.checked_at, None);
}

#[test]
fn unmanaged_summary_is_explicit() {
    let summary = unmanaged_health_summary();

    assert_eq!(summary.status, SummaryStatus::Unknown);
    assert_eq!(summary.reason, Some(UnknownReason::Unmanaged));
    assert!(!summary.configured);
}

#[test]
fn json_strings_stay_stable() {
    let summary = unmanaged_health_summary();
    let value = serde_json::to_value(&summary).unwrap();
    assert_eq!(value["status"], "unknown");
    assert_eq!(value["reason"], "unmanaged");

    let value = serde_json::to_value(SummaryStatus::NotConfigured).unwrap();
    assert_eq!(value, "not_configured");
    assert_eq!(
        serde_json::to_value(UnknownReason::StateUnavailable).unwrap(),
        "state_unavailable"
    );
}
