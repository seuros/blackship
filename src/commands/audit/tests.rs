use super::*;

fn record(event: AuditEvent, ts: i64) -> AuditRecord {
    let mut rec = AuditRecord::new("demo", event);
    rec.ts = ts;
    rec
}

#[test]
fn summarize_reports_span_counts_and_clean_termination() {
    let records = vec![
        record(AuditEvent::Created, 1_000),
        record(AuditEvent::Provisioned, 1_002),
        record(AuditEvent::Provisioned, 1_003),
        record(AuditEvent::Running, 1_005),
        record(AuditEvent::Destroyed, 1_100).with("jid", 7),
    ];

    let summary = summarize(&records);
    assert_eq!(summary.lifetime_secs, Some(100));
    assert_eq!(summary.event_counts.get("provisioned"), Some(&2));
    assert_eq!(summary.termination.as_deref(), Some("destroyed cleanly"));
    assert!(summary.peaks.is_empty());
}

#[test]
fn summarize_lifts_peaks_out_of_the_destroy_record() {
    let records = vec![
        record(AuditEvent::Running, 10),
        record(AuditEvent::Destroyed, 20)
            .with("peak.memoryuse", 1_048_576)
            .with("peak.samples", 12)
            .with("residual", "true"),
    ];

    let summary = summarize(&records);
    assert_eq!(
        summary.peaks.get("memoryuse").map(String::as_str),
        Some("1048576")
    );
    assert_eq!(summary.peak_samples.as_deref(), Some("12"));
    assert_eq!(
        summary.termination.as_deref(),
        Some("destroyed with residual resources")
    );
}

#[test]
fn summarize_prefers_the_last_terminal_event_and_keeps_rollback_steps() {
    let records = vec![
        record(AuditEvent::Failed, 5).with("reason", "rctl denied"),
        record(AuditEvent::RollbackStep, 6).with("step", "zfs"),
        record(AuditEvent::RollbackStep, 7).with("step", "vnet"),
        record(AuditEvent::Reaped, 8),
    ];

    let summary = summarize(&records);
    assert_eq!(summary.termination.as_deref(), Some("reaped by gc"));
    assert_eq!(summary.rollback_steps, vec!["zfs", "vnet"]);
}

#[test]
fn summarize_of_an_empty_history_is_empty() {
    let summary = summarize(&[]);
    assert_eq!(summary, Summary::default());
}

#[test]
fn format_ts_renders_utc_calendar_time() {
    assert_eq!(format_ts(0), "1970-01-01 00:00:00Z");
    assert_eq!(format_ts(1_759_190_400), "2025-09-30 00:00:00Z");
}
