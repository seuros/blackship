//! Jail management module
//!
//! This module provides:
//! - FFI bindings to FreeBSD jail syscalls
//! - Type-safe parameter handling
//! - State machine for jail lifecycle management

pub mod ffi;
pub mod state;
pub mod types;

// Re-exports
pub use ffi::{jail_attach, jail_create, jail_getid, jail_remove};
pub use state::{JailConfig, JailInstance};
pub use types::ParamValue;
