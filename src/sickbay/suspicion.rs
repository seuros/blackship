//! Phi-accrual suspicion for health checks; reports levels, never decides recovery.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use suspect_machines::{
    Config, ConfigError, Detector, Distribution, Refusal, Suspicion, Threshold,
};

use crate::error::{Error, Result};

const WINDOW: usize = 64;

const fn default_min_samples() -> usize {
    8
}

const fn default_unhealthy_phi() -> f64 {
    3.0
}

const fn default_failing_phi() -> f64 {
    8.0
}

/// Optional per-check suspicion thresholds; absent keeps retry counting.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct SuspicionConfig {
    /// Passing checks needed before phi is reported
    #[serde(default = "default_min_samples")]
    pub min_samples: usize,
    /// Phi at which a failed check reports unhealthy
    #[serde(default = "default_unhealthy_phi")]
    pub unhealthy_phi: f64,
    /// Phi at which a failed check reports failing and may trigger recovery
    #[serde(default = "default_failing_phi")]
    pub failing_phi: f64,
    /// Deviation floor in milliseconds; defaults to a quarter of the check interval
    pub min_std_dev_ms: Option<u64>,
}

/// What suspicion says about one check at one instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Not enough history; the caller falls back to retry counting
    Warming,
    Steady,
    Unhealthy,
    Failing,
}

/// Per-check detector with its thresholds.
#[derive(Debug, Clone)]
pub struct Accrual {
    detector: Detector<WINDOW>,
    unhealthy: Threshold,
    failing: Threshold,
}

fn invalid(what: &str) -> Error {
    Error::ConfigValidation(format!("suspicion: {what}"))
}

impl SuspicionConfig {
    /// Build the detector for a check running every `interval_secs`.
    pub fn build(&self, interval_secs: u64) -> Result<Accrual> {
        let unhealthy = Threshold::new(self.unhealthy_phi)
            .ok_or_else(|| invalid("unhealthy_phi must be finite and positive"))?;
        let failing = Threshold::new(self.failing_phi)
            .ok_or_else(|| invalid("failing_phi must be finite and positive"))?;
        if self.unhealthy_phi > self.failing_phi {
            return Err(invalid("unhealthy_phi must not exceed failing_phi"));
        }
        let floor_ms = self
            .min_std_dev_ms
            .unwrap_or_else(|| interval_secs.saturating_mul(250));
        let config = Config::new(
            Distribution::Normal {
                min_std_dev: Duration::from_millis(floor_ms),
            },
            self.min_samples,
        )
        .map_err(config_error)?;
        let detector = Detector::new(config).map_err(config_error)?;
        Ok(Accrual {
            detector,
            unhealthy,
            failing,
        })
    }
}

fn config_error(error: ConfigError) -> Error {
    invalid(&format!("{error:?}"))
}

impl Accrual {
    /// Record a passing check at `now`, measured from the checker's start.
    pub fn beat(&mut self, now: Duration) -> std::result::Result<(), Refusal> {
        self.detector.heartbeat(now).map(drop)
    }

    /// Suspicion at `now`; a refused read counts as warming.
    pub fn verdict(&self, now: Duration) -> Verdict {
        match self.detector.suspicion(now) {
            Ok(Suspicion::Measured(phi)) if phi.reaches(self.failing) => Verdict::Failing,
            Ok(Suspicion::Measured(phi)) if phi.reaches(self.unhealthy) => Verdict::Unhealthy,
            Ok(Suspicion::Measured(_)) => Verdict::Steady,
            _ => Verdict::Warming,
        }
    }
}

#[cfg(test)]
mod tests;
