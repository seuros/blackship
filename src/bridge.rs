//! Bridge for managing jail lifecycle and dependencies
//!
//! Handles:
//! - Building dependency graphs from configuration
//! - Starting jails in correct order (topological sort)
//! - Stopping jails in reverse order
//! - Managing ZFS datasets if enabled

mod core;
mod dns;
mod eva;
mod graph;
pub mod lifecycle;
mod plan;
mod ports;
mod qos;
mod status;
#[cfg(test)]
mod tests;
mod usage;

pub use self::core::Bridge;
pub use self::plan::PlanStep;
pub use self::qos::{ShiftOutcome, startup_deadline_secs};
