//! Bridge for managing jail lifecycle and dependencies
//!
//! Handles:
//! - Building dependency graphs from configuration
//! - Starting jails in correct order (topological sort)
//! - Stopping jails in reverse order
//! - Managing ZFS datasets if enabled

mod core;
mod dns;
mod graph;
mod lifecycle;
mod ports;
mod status;
mod tests;

pub use self::core::Bridge;
