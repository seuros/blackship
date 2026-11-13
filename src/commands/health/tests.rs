use super::*;

fn record(status: HealthStatus, jid: Option<i32>) -> HealthStateRecord {
    HealthStateRecord {
        jail: "p-web".to_string(),
        status,
        checked_at: 1,
        jid,
        checks_total: 1,
        checks_passing: 1,
        checks_failing: 0,
    }
}

#[test]
fn a_starting_one_shot_does_not_demote_a_settled_record() {
    let old = record(HealthStatus::Healthy, Some(7));
    assert!(!should_overwrite(
        Some(&old),
        &record(HealthStatus::Starting, Some(7))
    ));
}

#[test]
fn a_real_verdict_replaces_the_record() {
    let old = record(HealthStatus::Healthy, Some(7));
    assert!(should_overwrite(
        Some(&old),
        &record(HealthStatus::Failing, Some(7))
    ));
    assert!(should_overwrite(
        None,
        &record(HealthStatus::Starting, Some(7))
    ));
}

#[test]
fn another_jail_instance_always_replaces() {
    let old = record(HealthStatus::Healthy, Some(7));
    assert!(should_overwrite(
        Some(&old),
        &record(HealthStatus::Starting, Some(8))
    ));
}
