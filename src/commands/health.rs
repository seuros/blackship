//! Health check command

use std::fmt::Write as _;
use std::path::Path;

use crate::error::Result;
use crate::{error, jail, manifest, sickbay};
use sickbay::{HealthChecker, HealthStatus};

pub fn handle(
    config_path: &Path,
    jail: Option<String>,
    watch: bool,
    interval: u64,
    json: bool,
) -> Result<()> {
    let config = manifest::load(config_path)?;

    let jails: Vec<_> = if let Some(jail_name) = &jail {
        let (service_name, _full_name) = config
            .resolve_jail_names(jail_name)
            .ok_or_else(|| error::Error::JailNotFound(jail_name.clone()))?;
        config
            .jails
            .iter()
            .filter(|j| j.name == service_name)
            .collect()
    } else {
        config.jails.iter().collect()
    };

    if jails.is_empty() {
        if json {
            println!("[]");
        } else if let Some(name) = jail {
            println!("Jail '{name}' not found in configuration.");
        } else {
            println!("No jails defined in configuration.");
        }
        return Ok(());
    }

    let rate_limit = &config.config.rate_limit;
    let mut checkers: Vec<HealthChecker> = jails
        .iter()
        .filter(|j| j.healthcheck.enabled)
        .map(|j| {
            let full_name = config.jail_name(&j.name);
            let mut checker = HealthChecker::with_rate_limit(
                &full_name,
                j.healthcheck.clone(),
                rate_limit.health_capacity,
                rate_limit.health_refill_rate,
            );
            if let Ok(jid) = jail::jail_getid(&full_name) {
                checker = checker.with_jid(jid);
            }
            checker
        })
        .collect();

    if checkers.is_empty() {
        if json {
            println!("[]");
        } else {
            println!("No jails have health checks enabled.");
        }
        return Ok(());
    }

    if !json {
        println!("{:<20} {:<12} {:<20}", "JAIL", "STATUS", "CHECKS");
        println!("{}", "-".repeat(54));
    }

    loop {
        let mut json_results: Vec<serde_json::Value> = Vec::new();

        for checker in &mut checkers {
            let status = checker.run_checks()?;
            if json {
                json_results.push(checker_json(checker, status));
            } else {
                print_checker_row(checker, status);
            }
        }

        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json_results)
                    .expect("serde_json::Value always serializes")
            );
        }

        if !watch {
            break;
        }

        std::thread::sleep(std::time::Duration::from_secs(interval));
        print!("\x1b[{}A", checkers.len() + 2);
        println!("{:<20} {:<12} {:<20}", "JAIL", "STATUS", "CHECKS");
        println!("{}", "-".repeat(54));
    }

    Ok(())
}

/// One jail's health as a JSON object for `health --json`.
fn checker_json(checker: &HealthChecker, status: HealthStatus) -> serde_json::Value {
    let checks: Vec<_> = checker
        .get_check_results()
        .iter()
        .map(|(check, result, failures)| {
            serde_json::json!({
                "name": check.name,
                "passed": result.as_ref().map(|r| r.passed),
                "output": result.as_ref().map(|r| r.output.clone()),
                "duration_ms": result.as_ref().map(|r| r.duration.as_millis()),
                "age_ms": result.as_ref().map(|r| r.age().as_millis()),
                "failures": failures
            })
        })
        .collect();

    serde_json::json!({
        "jail": checker.jail_name(),
        "status": status,
        "checks": checks
    })
}

/// One jail's row in the human health table.
fn print_checker_row(checker: &HealthChecker, status: HealthStatus) {
    let mut checks_summary = String::new();
    for (_check, result, failures) in &checker.get_check_results() {
        if !checks_summary.is_empty() {
            checks_summary.push_str(", ");
        }
        match result {
            Some(r) => {
                checks_summary.push_str(&r.summary());
                if *failures > 0 {
                    let _ = write!(checks_summary, " ({failures}x)"); // fmt::Write into a String is infallible
                }
            }
            None => checks_summary.push('?'),
        }
    }

    let status_str = match ansi_color(status) {
        Some(color) => format!("\x1b[{color}m{status}\x1b[0m"),
        None => status.to_string(),
    };

    println!(
        "{:<20} {:<12} {:<20}",
        checker.jail_name(),
        status_str,
        checks_summary
    );
}

/// ANSI color for a status in the human table; `Unknown` stays plain.
const fn ansi_color(status: HealthStatus) -> Option<u8> {
    match status {
        HealthStatus::Healthy => Some(32),
        HealthStatus::Unhealthy => Some(33),
        HealthStatus::Failing => Some(31),
        HealthStatus::Starting => Some(34),
        HealthStatus::Suspended => Some(35),
        HealthStatus::Unknown => None,
    }
}
