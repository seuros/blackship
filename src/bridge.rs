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
mod lifecycle;
mod ports;
mod qos;
mod status;
#[cfg(test)]
mod tests;
mod usage;

pub use self::core::Bridge;
pub use self::qos::{ShiftOutcome, startup_deadline_secs};
