//! Health monitoring and recovery for jails
//!
//! Provides:
//! - Health check definitions and status tracking
//! - Background monitoring threads per jail
//! - Auto-recovery actions (restart, stop, custom commands)
//! - CLI status display

pub mod checker;
pub mod recovery;

pub use checker::{HealthChecker, HealthStatus};
