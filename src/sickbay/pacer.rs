//! Adaptive bound on concurrent health-check runs (shed-machines AIMD).

use std::time::Duration;

use serde::{Deserialize, Serialize};
use shed_machines::{Aimd, Backoff, Bounds, Controller, DEFAULT_CEILING, Outcome, Sample};

use crate::error::{Error, Result};

const fn default_initial() -> u32 {
    4
}

const fn default_min() -> u32 {
    1
}

const fn default_max() -> u32 {
    DEFAULT_CEILING
}

/// Optional bounds for concurrent check runs; absent leaves them unbounded.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PacerConfig {
    /// Runs allowed in flight at the start
    #[serde(default = "default_initial")]
    pub initial: u32,
    /// The limit never drops below this
    #[serde(default = "default_min")]
    pub min: u32,
    /// The limit never grows above this
    #[serde(default = "default_max")]
    pub max: u32,
}

/// A run that got in; hand it back to [`Pacer::leave`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admission {
    in_flight: u32,
}

/// Concurrency limit moved by completed runs; the caller owns the threads.
#[derive(Debug, Clone, Copy)]
pub struct Pacer {
    control: Aimd,
    in_flight: u32,
}

impl PacerConfig {
    pub fn build(&self) -> Result<Pacer> {
        let invalid =
            || Error::ConfigValidation("health_concurrency: need 1 <= min <= max".to_string());
        let bounds = Bounds::new(self.min, self.max).ok_or_else(invalid)?;
        let control = Aimd::new(bounds, bounds.clamp(self.initial), Backoff::default())
            .ok_or_else(invalid)?;
        Ok(Pacer {
            control,
            in_flight: 0,
        })
    }
}

impl Pacer {
    pub fn limit(&self) -> u32 {
        self.control.limit()
    }

    pub const fn in_flight(&self) -> u32 {
        self.in_flight
    }

    /// Take a slot, or `None` when the limit is reached and the run should be shed.
    pub fn enter(&mut self) -> Option<Admission> {
        if self.in_flight >= self.control.limit() {
            return None;
        }
        self.in_flight += 1;
        Some(Admission {
            in_flight: self.in_flight,
        })
    }

    /// Release a slot. A run taking at least half its `timeout`, or failing outright, reads as overload.
    /// Returns `(before, after)` when the limit moved.
    pub fn leave(
        &mut self,
        admission: Admission,
        rtt: Duration,
        timeout: Duration,
        failed: bool,
    ) -> Option<(u32, u32)> {
        self.in_flight = self.in_flight.saturating_sub(1);
        let before = self.control.limit();
        let outcome = if failed || rtt.saturating_mul(2) >= timeout {
            Outcome::Overload
        } else {
            Outcome::Ok
        };
        // An admission always counts itself, so `in_flight` is never zero.
        if let Some(sample) = Sample::new(rtt, admission.in_flight, outcome) {
            self.control.observe(sample);
        }
        let after = self.control.limit();
        (before != after).then_some((before, after))
    }
}

#[cfg(test)]
mod tests;
