//! Per-jail resource statistics from jls/ps libxo JSON output.
//!
//! Structured output instead of text scraping: `jls --libxo json` maps
//! JIDs to names, `ps --libxo json` provides per-process CPU and RSS,
//! aggregated here per jail.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use crate::error::{Error, Result};
use crate::manifest;

#[derive(Debug, Default)]
struct JailStats {
    processes: u64,
    cpu_percent: f64,
    rss_kib: u64,
}

fn run_json(program: &str, args: &[&str]) -> Result<serde_json::Value> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| Error::CommandFailed {
            command: program.to_string(),
            message: e.to_string(),
        })?;
    if !output.status.success() {
        return Err(Error::CommandFailed {
            command: format!("{} {}", program, args.join(" ")),
            message: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }
    serde_json::from_slice(&output.stdout).map_err(|e| Error::CommandFailed {
        command: program.to_string(),
        message: format!("invalid libxo JSON: {}", e),
    })
}

pub fn handle(config_path: &Path, jail: Option<String>, json: bool) -> Result<()> {
    let config = manifest::load_or_default(config_path)?;

    // JID -> jail name
    let jls = run_json("/usr/sbin/jls", &["--libxo", "json", "jid", "name"])?;
    let mut names: HashMap<String, String> = HashMap::new();
    if let Some(jails) = jls
        .get("jail-information")
        .and_then(|i| i.get("jail"))
        .and_then(|j| j.as_array())
    {
        for entry in jails {
            if let (Some(jid), Some(name)) = (
                entry.get("jid").and_then(|v| v.as_str()),
                entry.get("name").and_then(|v| v.as_str()),
            ) {
                names.insert(jid.to_string(), name.to_string());
            }
        }
    }

    // Aggregate per-process CPU and RSS by jail id
    let ps = run_json(
        "/bin/ps",
        &["ax", "-o", "jid,pcpu,rss", "--libxo", "json"],
    )?;
    let mut stats: HashMap<String, JailStats> = HashMap::new();
    if let Some(processes) = ps
        .get("process-information")
        .and_then(|i| i.get("process"))
        .and_then(|p| p.as_array())
    {
        for process in processes {
            let jid = process
                .get("jail-id")
                .and_then(|v| v.as_str())
                .unwrap_or("0");
            if jid == "0" {
                continue;
            }
            let entry = stats.entry(jid.to_string()).or_default();
            entry.processes += 1;
            entry.cpu_percent += process
                .get("percent-cpu")
                .and_then(|v| v.as_str())
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(0.0);
            entry.rss_kib += process
                .get("rss")
                .and_then(|v| v.as_str())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
        }
    }

    // Restrict to one jail when asked, resolving through the config
    let filter: Option<String> = jail.map(|j| {
        config
            .resolve_jail_names(&j)
            .map(|(_, full)| full)
            .unwrap_or(j)
    });

    let mut rows: Vec<(String, String, JailStats)> = names
        .into_iter()
        .filter(|(_, name)| filter.as_deref().is_none_or(|f| f == name))
        .map(|(jid, name)| {
            let stat = stats.remove(&jid).unwrap_or_default();
            (jid, name, stat)
        })
        .collect();
    rows.sort_by(|a, b| a.1.cmp(&b.1));

    if json {
        let out: Vec<_> = rows
            .iter()
            .map(|(jid, name, s)| {
                serde_json::json!({
                    "jid": jid,
                    "name": name,
                    "processes": s.processes,
                    "cpu_percent": (s.cpu_percent * 10.0).round() / 10.0,
                    "rss_mib": s.rss_kib / 1024,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else if rows.is_empty() {
        println!("No running jails.");
    } else {
        println!(
            "{:<6} {:<24} {:>6} {:>8} {:>10}",
            "JID", "NAME", "PROCS", "CPU%", "RSS(MiB)"
        );
        for (jid, name, s) in rows {
            println!(
                "{:<6} {:<24} {:>6} {:>8.1} {:>10}",
                jid,
                name,
                s.processes,
                s.cpu_percent,
                s.rss_kib / 1024
            );
        }
    }

    Ok(())
}
