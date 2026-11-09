//! Unified error types for Blackship

use std::io;
use std::path::PathBuf;
use thiserror::Error;

/// Everything a Blackship operation can fail with. New variants may be
/// added in minor releases.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// A privileged library call ran without root; the library never escalates.
    #[error("{operation} requires root privileges (effective uid is {euid})")]
    NeedsRoot {
        /// What was attempted, e.g. "creating a container"
        operation: &'static str,
        /// The effective uid the call ran with
        euid: u32,
    },

    /// The CLI was asked not to obtain the root privileges a command needs.
    #[error(
        "This command requires root privileges, but automatic escalation was disabled by --no-escalate (effective uid is {euid})"
    )]
    EscalationDisabled {
        /// The effective uid the CLI is running with.
        euid: u32,
    },

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

    #[error("Jail '{0}' already exists")]
    JailExists(String),

    #[error("Jail creation failed: {0}")]
    JailCreationFailed(String),

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

    // State file errors
    #[error("State error: {0}")]
    State(String),

    // Network errors
    #[error("Network error: {0}")]
    Network(String),

    #[error("Network '{0}' already exists")]
    NetworkAlreadyExists(String),

    #[error("Network '{0}' not found")]
    NetworkNotFound(String),

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

    // Copy errors
    #[error("Copy failed: {0}")]
    CopyFailed(String),

    // Resource control errors
    #[error("RCTL error: {0}")]
    Rctl(String),

    // Argument errors
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("{0}")]
    CliParse(String),

    #[error("The requested output format is not supported for this command")]
    UnsupportedOutputFormat,

    #[error("Failed to serialize JSON output: {0}")]
    JsonOutput(String),

    #[error("{0}")]
    User(String),
}

impl Error {
    /// Stable identifier for machine-readable error handling.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Io(_) => "io_error",
            Self::ConfigRead { .. } => "config_read_failed",
            Self::ConfigParse(_) => "config_parse_failed",
            Self::ConfigValidation(_) => "config_validation_failed",
            Self::UnknownDependency(_) => "unknown_dependency",
            Self::JailNotFound(_) => "jail_not_found",
            Self::JailAlreadyRunning(_) => "jail_already_running",
            Self::JailNotRunning(_) => "jail_not_running",
            Self::JailExists(_) => "jail_already_exists",
            Self::JailCreationFailed(_) => "jail_creation_failed",
            Self::JailPathNotFound(_) => "jail_path_not_found",
            Self::JailOperation(_) => "jail_operation_failed",
            Self::JailGet(_) => "jail_get_failed",
            Self::JailSet(_) => "jail_set_failed",
            Self::JailRemoveFailed => "jail_remove_failed",
            Self::JailAttachFailed(_) => "jail_attach_failed",
            Self::JailExecFailed(_) => "jail_exec_failed",
            Self::CString(_) => "invalid_c_string",
            Self::Zfs(_) => "zfs_operation_failed",
            Self::ZfsNotEnabled => "zfs_not_enabled",
            Self::DownloadFailed(_) => "download_failed",
            Self::ChecksumMismatch { .. } => "checksum_mismatch",
            Self::ReleaseNotFound(_) => "release_not_found",
            Self::ReleaseAlreadyExists(_) => "release_already_exists",
            Self::ExtractionFailed(_) => "extraction_failed",
            Self::UnsupportedArch(_) => "unsupported_architecture",
            Self::UnsupportedOsVersion { .. } => "unsupported_os_version",
            Self::InvalidVersion(_) => "invalid_version",
            Self::CommandFailed { .. } => "command_failed",
            Self::State(_) => "state_error",
            Self::Network(_) => "network_error",
            Self::NetworkAlreadyExists(_) => "network_already_exists",
            Self::NetworkNotFound(_) => "network_not_found",
            Self::InterfaceNotFound(_) => "interface_not_found",
            Self::BridgeAlreadyExists(_) => "bridge_already_exists",
            Self::HookFailed { .. } => "hook_failed",
            Self::HookTimeout(_) => "hook_timeout",
            Self::JailTimeout(_) => "jail_timeout",
            Self::HealthCheckFailed { .. } => "health_check_failed",
            Self::TemplateParseFailed(_) => "template_parse_failed",
            Self::BuildFailed { .. } => "build_failed",
            Self::CopyFailed(_) => "copy_failed",
            Self::Rctl(_) => "rctl_error",
            Self::InvalidArgument(_) => "invalid_argument",
            Self::CliParse(_) => "cli_parse_failed",
            Self::UnsupportedOutputFormat => "unsupported_output_format",
            Self::JsonOutput(_) => "json_output_failed",
            Self::NeedsRoot { .. } => "needs_root",
            Self::EscalationDisabled { .. } => "escalation_disabled",
            Self::User(_) => "user_error",
        }
    }

    /// Fail with [`Error::NeedsRoot`] unless the process runs as root.
    pub(crate) fn require_root(operation: &'static str) -> Result<()> {
        let euid = nix::unistd::geteuid().as_raw();
        if euid == 0 {
            Ok(())
        } else {
            Err(Self::NeedsRoot { operation, euid })
        }
    }
}

/// Result type alias for Blackship operations
pub type Result<T> = std::result::Result<T, Error>;
