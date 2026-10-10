//! Lifecycle post-mortem over the durable audit log.

use std::path::Path;

use crate::audit::{AuditEvent, AuditLog, AuditRecord};
use crate::error::{Error, Result};
use crate::manifest;
use crate::scope::ScopeStore;
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Everything derivable from a jail's event history.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    pub first_seen: Option<i64>,
    pub last_seen: Option<i64>,
    pub lifetime_secs: Option<i64>,
    pub event_counts: BTreeMap<&'static str, usize>,
    pub peaks: BTreeMap<String, String>,
    pub peak_samples: Option<String>,
    pub termination: Option<String>,
    pub rollback_steps: Vec<String>,
}

pub fn summarize(records: &[AuditRecord]) -> Summary {
    let mut summary = Summary::default();
    if records.is_empty() {
        return summary;
    }

    summary.first_seen = records.first().map(|r| r.ts);
    summary.last_seen = records.last().map(|r| r.ts);
    if let (Some(first), Some(last)) = (summary.first_seen, summary.last_seen) {
        summary.lifetime_secs = Some(last - first);
    }

    for record in records {
        *summary
            .event_counts
            .entry(record.event.as_str())
            .or_insert(0) += 1;

        for (key, value) in &record.detail {
            match key.strip_prefix("peak.") {
                Some("samples") => summary.peak_samples = Some(value.clone()),
                Some(resource) => {
                    summary.peaks.insert(resource.to_string(), value.clone());
                }
                None => {}
            }
        }

        match record.event {
            AuditEvent::RollbackStep => {
                if let Some(step) = record.detail.get("step") {
                    summary.rollback_steps.push(step.clone());
                }
            }
            AuditEvent::Failed => {
                summary.termination = Some(format!(
                    "failed: {}",
                    record
                        .detail
                        .get("reason")
                        .or_else(|| record.detail.get("error"))
                        .map(String::as_str)
                        .unwrap_or("unknown")
                ));
            }
            AuditEvent::Destroyed => {
                summary.termination = Some(if record.detail.contains_key("residual") {
                    "destroyed with residual resources".to_string()
                } else if record.detail.contains_key("via") {
                    "destroyed via cleanup".to_string()
                } else {
                    "destroyed cleanly".to_string()
                });
            }
            AuditEvent::Reaped => {
                summary.termination = Some("reaped by gc".to_string());
            }
            _ => {}
        }
    }

    summary
}

pub fn handle_audit(config_path: &Path, jail: String, json: bool) -> Result<()> {
    let config = manifest::load(config_path)?;
    let project = config.config.project_name();
    let log = AuditLog::from_config(Some(&config));
    let scopes = ScopeStore::from_config(Some(&config));

    let prefixed = jail
        .strip_prefix(project)
        .is_some_and(|rest| rest.starts_with('-'));
    let candidates = if prefixed {
        vec![jail.clone()]
    } else {
        vec![format!("{project}-{jail}"), jail.clone()]
    };

    let mut resolved = None;
    for candidate in &candidates {
        let records = log.read(candidate)?;
        if !records.is_empty() {
            resolved = Some((candidate.clone(), records));
            break;
        }
    }

    let Some((full_name, records)) = resolved else {
        return Err(Error::State(format!(
            "No audit history for '{}' (looked for {})",
            jail,
            candidates.join(", ")
        )));
    };

    let mut summary = summarize(&records);

    if summary.peaks.is_empty()
        && let Ok(Some(scope)) = scopes.get(&full_name)
    {
        for (resource, value) in &scope.peak.resources {
            summary.peaks.insert(resource.clone(), value.to_string());
        }
    }

    if json {
        print_json(&full_name, &records, &summary)?;
    } else {
        print_timeline(&full_name, &records, &summary);
    }

    Ok(())
}

fn print_json(full_name: &str, records: &[AuditRecord], summary: &Summary) -> Result<()> {
    let value = serde_json::json!({
        "jail": full_name,
        "events": records,
        "summary": {
            "first_seen": summary.first_seen,
            "last_seen": summary.last_seen,
            "lifetime_secs": summary.lifetime_secs,
            "event_counts": summary.event_counts,
            "peaks": summary.peaks,
            "peak_samples": summary.peak_samples,
            "termination": summary.termination,
            "rollback_steps": summary.rollback_steps,
        }
    });

    let rendered = serde_json::to_string_pretty(&value)
        .map_err(|e| Error::State(format!("Failed to render audit JSON: {e}")))?;
    println!("{rendered}");
    Ok(())
}

fn print_timeline(full_name: &str, records: &[AuditRecord], summary: &Summary) {
    println!("Audit history for '{full_name}'");
    println!();

    let mut detail = String::new();
    for record in records {
        detail.clear();
        for (key, value) in &record.detail {
            if !detail.is_empty() {
                detail.push(' ');
            }
            let _ = write!(detail, "{key}={value}");
        }
        println!(
            "  {}  {:<14} {}",
            format_ts(record.ts),
            record.event.as_str(),
            detail
        );
    }

    println!();
    if let Some(lifetime) = summary.lifetime_secs {
        println!("Span: {}s across {} events", lifetime, records.len());
    }

    if !summary.peaks.is_empty() {
        match &summary.peak_samples {
            Some(samples) => println!("Peak usage (max over {samples} samples, not exact):"),
            None => println!("Peak usage (sampled, not exact):"),
        }
        for (resource, value) in &summary.peaks {
            println!("  {resource:<14} {value}");
        }
    }

    if !summary.rollback_steps.is_empty() {
        println!("Rollback steps: {}", summary.rollback_steps.join(", "));
    }

    match &summary.termination {
        Some(reason) => println!("Termination: {reason}"),
        None => println!("Termination: none recorded (jail may still be running)"),
    }
}

fn format_ts(ts: i64) -> String {
    let secs = ts.max(0) as u64;
    let days = secs / 86_400;
    let time = secs % 86_400;
    let (year, month, day) = civil_from_days(days as i64);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}Z",
        year,
        month,
        day,
        time / 3600,
        (time % 3600) / 60,
        time % 60
    )
}

/// Howard's `civil_from_days`: days since the Unix epoch to a calendar date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests;
