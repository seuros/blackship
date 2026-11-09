//! Orphan reclamation command

use std::path::Path;

use crate::error::Result;
use crate::gc::{self, Orphan, Reaper};
use crate::manifest;

/// Flags for `blackship gc`.
#[allow(clippy::struct_excessive_bools)] // independent CLI switches, not a state machine
pub struct GcOptions {
    /// Report what would be reclaimed without touching anything.
    pub dry_run: bool,
    /// Reap even resources that look in use.
    pub force: bool,
    /// Include orphans only reachable with `--force` (unreferenced datasets etc.).
    pub prune_unreferenced: bool,
    /// Machine-readable output.
    pub json: bool,
}

pub fn handle_gc(
    config_path: &Path,
    verbose: bool,
    jail: Option<&str>,
    opts: &GcOptions,
) -> Result<()> {
    let GcOptions {
        dry_run,
        force,
        prune_unreferenced,
        json,
    } = *opts;
    let config = manifest::load(config_path)?;
    let reaper = Reaper::new(&config, verbose)?;
    let survey = reaper.survey()?;

    let mut orphans = gc::classify(&survey);
    if let Some(jail) = jail {
        orphans.retain(|orphan| orphan.jail == jail);
    }
    if !prune_unreferenced {
        orphans.retain(|orphan| !orphan.requires_force);
    }

    if json {
        println!("{}", render_json(&orphans, dry_run));
        if dry_run {
            return Ok(());
        }
    } else if orphans.is_empty() {
        println!("Nothing to reclaim.");
        return Ok(());
    } else {
        report(&orphans, dry_run);
    }

    if dry_run {
        return Ok(());
    }

    let mut failed = 0usize;
    for orphan in &orphans {
        if let Err(e) = reaper.reap(orphan, force, false) {
            eprintln!("  {} '{}': {}", orphan.kind_label(), orphan.jail, e);
            failed += 1;
        }
    }

    if !json {
        let reclaimed = orphans.len() - failed;
        println!("Reclaimed {} of {} orphans.", reclaimed, orphans.len());
    }

    Ok(())
}

fn report(orphans: &[Orphan], dry_run: bool) {
    println!(
        "{} {} orphan(s):",
        if dry_run {
            "Would reclaim"
        } else {
            "Reclaiming"
        },
        orphans.len()
    );
    for orphan in orphans {
        let label = if orphan.jail.is_empty() {
            orphan.kind_label().to_string()
        } else {
            format!("{} {}", orphan.kind_label(), orphan.jail)
        };
        println!("  {} -- {}", label, orphan.reason);
        for resource in &orphan.resources {
            println!("      {resource}");
        }
        if orphan.requires_force {
            println!("      requires --force");
        }
    }
}

fn render_json(orphans: &[Orphan], dry_run: bool) -> String {
    let entries: Vec<serde_json::Value> = orphans
        .iter()
        .map(|orphan| {
            serde_json::json!({
                "jail": orphan.jail,
                "kind": orphan.kind_label(),
                "reason": orphan.reason,
                "resources": orphan.resources,
                "requires_force": orphan.requires_force,
            })
        })
        .collect();

    serde_json::json!({ "dry_run": dry_run, "orphans": entries }).to_string()
}
