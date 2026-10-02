//! Jail management module
//!
//! This module provides:
//! - FFI bindings to FreeBSD jail syscalls
//! - Type-safe parameter handling
//! - State machine for jail lifecycle management

pub mod ffi;
pub mod jexec;
pub mod kqueue;
pub mod state;
pub mod types;

// Re-exports
pub use ffi::{
    RunningJails, jail_create, jail_create_with_descriptor, jail_getid, jail_getname, jail_remove,
    jail_update,
};
pub use jexec::jexec_with_output;
pub use state::{JailConfig, JailHandle, JailInstance};
pub use types::ParamValue;
