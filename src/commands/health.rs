//! Health check command

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
            println!("Jail '{}' not found in configuration.", name);
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
            let check_results = checker.get_check_results();

            if json {
                let status_str = match status {
                    HealthStatus::Healthy => "healthy",
                    HealthStatus::Unhealthy => "unhealthy",
                    HealthStatus::Failing => "failing",
                    HealthStatus::Starting => "starting",
                    HealthStatus::Suspended => "suspended",
                    HealthStatus::Unknown => "unknown",
                };

                let checks: Vec<_> = check_results
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

                json_results.push(serde_json::json!({
                    "jail": checker.jail_name(),
                    "status": status_str,
                    "checks": checks
                }));
            } else {
                let checks_summary: String = check_results
                    .iter()
                    .map(|(_check, result, failures)| match result {
                        Some(r) => {
                            let summary = r.summary();
                            if *failures > 0 {
                                format!("{} ({}x)", summary, failures)
                            } else {
                                summary
                            }
                        }
                        None => "?".to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join(", ");

                let status_str = match status {
                    HealthStatus::Healthy => "\x1b[32mhealthy\x1b[0m",
                    HealthStatus::Unhealthy => "\x1b[33munhealthy\x1b[0m",
                    HealthStatus::Failing => "\x1b[31mfailing\x1b[0m",
                    HealthStatus::Starting => "\x1b[34mstarting\x1b[0m",
                    HealthStatus::Suspended => "\x1b[35msuspended\x1b[0m",
                    HealthStatus::Unknown => "unknown",
                };

                println!(
                    "{:<20} {:<12} {:<20}",
                    checker.jail_name(),
                    status_str,
                    checks_summary
                );
            }
        }

        if json {
            println!("{}", serde_json::to_string_pretty(&json_results).unwrap());
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
