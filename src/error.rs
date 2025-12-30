//! Unified error types for Blackship

use std::io;
use std::path::PathBuf;
use thiserror::Error;

/// Main error type for Blackship operations
#[derive(Error, Debug)]
pub enum Error {
    // IO errors
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    // Config errors
    #[error("Failed to read config file '{path}': {source}")]
    ConfigRead { path: PathBuf, source: io::Error },

    #[error("Failed to parse config: {0}")]
    ConfigParse(#[from] toml::de::Error),

    #[error("Config validation failed: {0}")]
    ConfigValidation(String),

    // Dependency errors
    #[error("Unknown dependency '{0}' - jail not defined")]
    UnknownDependency(String),

    // Jail errors
    #[error("Jail '{0}' not found")]
    JailNotFound(String),

    #[error("Jail '{0}' is already running")]
    JailAlreadyRunning(String),

    #[error("Jail '{0}' is not running")]
    JailNotRunning(String),

    #[error("Jail path does not exist: {0}")]
    JailPathNotFound(PathBuf),

    #[error("Jail operation failed: {0}")]
    JailOperation(String),

    // FFI errors
    #[error("jail_get syscall failed: {0}")]
    JailGet(String),

    #[error("jail_set syscall failed: {0}")]
    JailSet(String),

    #[error("jail_remove syscall failed")]
    JailRemoveFailed,

    #[error("Failed to attach to jail with JID {0}")]
    JailAttachFailed(i32),

    #[error("Command execution failed in jail: {0}")]
    JailExecFailed(String),

    #[error("Failed to create C string: {0}")]
    CString(#[from] std::ffi::NulError),

    // ZFS errors
    #[error("ZFS operation failed: {0}")]
    Zfs(String),

    #[error("ZFS not enabled but required for operation")]
    ZfsNotEnabled,

    // Bootstrap errors
    #[error("Failed to download: {0}")]
    DownloadFailed(String),

    #[error("Checksum mismatch for {file}: expected {expected}, got {actual}")]
    ChecksumMismatch {
        file: String,
        expected: String,
        actual: String,
    },

    #[error("Release '{0}' not found")]
    ReleaseNotFound(String),

    #[error("Release '{0}' already exists")]
    ReleaseAlreadyExists(String),

    #[error("Failed to extract archive: {0}")]
    ExtractionFailed(String),

    #[error("Unsupported architecture: {0}")]
    UnsupportedArch(String),

    // System errors
    #[error("Feature '{feature}' requires FreeBSD {minimum}+, but running {current}")]
    UnsupportedOsVersion {
        feature: String,
        minimum: String,
        current: String,
    },

    #[error("Invalid version format: {0}")]
    InvalidVersion(String),

    #[error("Command '{command}' failed: {message}")]
    CommandFailed { command: String, message: String },

    // Network errors
    #[error("Network error: {0}")]
    Network(String),

    #[error("Interface '{0}' not found")]
    InterfaceNotFound(String),

    #[error("Bridge '{0}' already exists")]
    BridgeAlreadyExists(String),

    // Hook errors
    #[error("Hook failed at phase '{phase}': {command} - {message}")]
    HookFailed {
        phase: String,
        command: String,
        message: String,
    },

    #[error("Hook timeout after {0} seconds")]
    HookTimeout(u64),

    // Jail execution timeout
    #[error("Jail command timeout after {0} seconds")]
    JailTimeout(u64),

    // Health check errors
    #[error("Health check failed for jail '{jail}' ({check}): {message}")]
    HealthCheckFailed {
        jail: String,
        check: String,
        message: String,
    },

    // Template errors
    #[error("Template parse failed: {0}")]
    TemplateParseFailed(String),

    #[error("Build failed at step '{step}': {message}")]
    BuildFailed { step: String, message: String },
}

/// Result type alias for Blackship operations
pub type Result<T> = std::result::Result<T, Error>;
