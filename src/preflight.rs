//! Host storage preflight: is the configured zpool fit to take new data?
//!
//! `vitals-machines` observes the pool; the policy (what counts as unfit, how
//! low is too low) lives here. Only ZFS-enabled configs are checked, and a pool
//! that cannot be observed (`Unavailable`, `NotFound`) warns but never blocks.

use crate::error::{Error, Result};
use crate::manifest::GlobalConfig;
use serde::Serialize;
use vitals_machines::probe::{PoolHealth, PoolObservation, ZfsPool, inspect_pool};

/// Refuse new data when the pool has less than this percent free, unless
/// `[config] zpool_min_free_percent` says otherwise.
pub const REFUSE_BELOW_FREE_PERCENT: u8 = 5;

/// Warn when the pool has less than this percent free (never below the refuse line).
pub const WARN_BELOW_FREE_PERCENT: u8 = 15;

/// What an unfit pool does to the operation asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stance {
    /// Space-consuming work: an unfit pool stops it.
    Refuse,
    /// Reclaiming work: an unfit pool is reported, the work goes on.
    WarnOnly,
}

/// The free-space lines, in whole percent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Thresholds {
    pub refuse_below: u8,
    pub warn_below: u8,
}

impl Thresholds {
    pub fn of(config: &GlobalConfig) -> Self {
        let refuse_below = config
            .zpool_min_free_percent
            .unwrap_or(REFUSE_BELOW_FREE_PERCENT);
        Self {
            refuse_below,
            warn_below: WARN_BELOW_FREE_PERCENT.max(refuse_below),
        }
    }
}

/// What the observation means for new writes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", content = "detail", rename_all = "snake_case")]
pub enum Verdict {
    Clear,
    Warn(String),
    Refuse(String),
}

/// One look at the configured pool and what it means.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Assessment {
    pub pool: String,
    pub observation: PoolObservation,
    #[serde(flatten)]
    pub verdict: Verdict,
    pub thresholds: Thresholds,
}

/// The pool blackship puts datasets on, when ZFS is enabled.
fn configured_pool(config: &GlobalConfig) -> Option<&str> {
    config
        .zfs_enabled
        .then_some(config.zpool.as_deref())
        .flatten()
}

/// Observe the configured pool; `None` when the config does not use ZFS.
pub fn assess(config: &GlobalConfig) -> Option<Assessment> {
    let pool = configured_pool(config)?;
    let observation = inspect_pool(pool);
    let thresholds = Thresholds::of(config);
    Some(Assessment {
        pool: pool.to_string(),
        verdict: judge(pool, &observation, thresholds),
        observation,
        thresholds,
    })
}

/// Gate an operation on the configured pool; a no-op for a config without ZFS.
///
/// # Errors
///
/// [`Error::StoragePreflight`] when the pool is unfit and `stance` is [`Stance::Refuse`].
pub fn check(config: &GlobalConfig, stance: Stance) -> Result<()> {
    assess(config).map_or(Ok(()), |assessment| settle(assessment.verdict, stance))
}

fn settle(verdict: Verdict, stance: Stance) -> Result<()> {
    match (verdict, stance) {
        (Verdict::Clear, _) => Ok(()),
        (Verdict::Warn(message) | Verdict::Refuse(message), Stance::WarnOnly)
        | (Verdict::Warn(message), Stance::Refuse) => {
            eprintln!("Warning: {message}");
            Ok(())
        }
        (Verdict::Refuse(message), Stance::Refuse) => Err(Error::StoragePreflight(message)),
    }
}

fn judge(pool: &str, observation: &PoolObservation, thresholds: Thresholds) -> Verdict {
    match observation {
        PoolObservation::Found(found) => judge_pool(found, thresholds),
        PoolObservation::NotFound => Verdict::Warn(format!(
            "zpool '{pool}' is not imported; storage preflight skipped"
        )),
        PoolObservation::Unavailable(reason) => Verdict::Warn(format!(
            "cannot inspect zpool '{pool}': {reason}; storage preflight skipped"
        )),
    }
}

fn judge_pool(pool: &ZfsPool, thresholds: Thresholds) -> Verdict {
    let free = pool.available_percent();
    let health = health_label(&pool.health);
    let mut reasons = Vec::new();
    if !pool.is_online() {
        reasons.push("it is not ONLINE".to_string());
    }
    if pool.read_only {
        reasons.push("it is read-only".to_string());
    }
    if free.is_some_and(|free| free < f64::from(thresholds.refuse_below)) {
        reasons.push("free space is below the threshold".to_string());
    }
    let free_text = free.map_or_else(|| "unknown".to_string(), |free| format!("{free:.1}%"));
    if !reasons.is_empty() {
        return Verdict::Refuse(format!(
            "zpool '{}' is unfit for new data: {} (health {health}, {}, {free_text} free, refuse below {}% free)",
            pool.name,
            reasons.join(" and "),
            if pool.read_only {
                "read-only"
            } else {
                "read-write"
            },
            thresholds.refuse_below,
        ));
    }
    if free.is_some_and(|free| free < f64::from(thresholds.warn_below)) {
        return Verdict::Warn(format!(
            "zpool '{}' is down to {free_text} free (warning below {}%, refusing below {}%)",
            pool.name, thresholds.warn_below, thresholds.refuse_below,
        ));
    }
    Verdict::Clear
}

fn health_label(health: &PoolHealth) -> String {
    match health {
        PoolHealth::Online => "ONLINE".into(),
        PoolHealth::Degraded => "DEGRADED".into(),
        PoolHealth::Faulted => "FAULTED".into(),
        PoolHealth::Offline => "OFFLINE".into(),
        PoolHealth::Unavail => "UNAVAIL".into(),
        PoolHealth::Removed => "REMOVED".into(),
        PoolHealth::Suspended => "SUSPENDED".into(),
        PoolHealth::Unrecognized(other) => other.clone(),
    }
}

#[cfg(test)]
mod tests;
