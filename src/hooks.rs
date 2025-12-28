//! Lifecycle hooks for jail management
//!
//! Provides:
//! - Hook definitions for various lifecycle phases
//! - Variable substitution in hook commands
//! - Execution on host or inside jail
//! - Configurable failure handling

use crate::error::{Error, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Lifecycle phases when hooks can be executed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookPhase {
    /// Before jail filesystem is created
    PreCreate,
    /// After jail filesystem is created
    PostCreate,
    /// Before jail is started
    PreStart,
    /// After jail is started and running
    PostStart,
    /// Before jail is stopped
    PreStop,
    /// After jail is stopped
    PostStop,
}

impl HookPhase {
    /// Get all phases in lifecycle order (_unused: future feature)
    #[allow(dead_code)]
    pub fn all() -> &'static [HookPhase] {
        &[
            HookPhase::PreCreate,
            HookPhase::PostCreate,
            HookPhase::PreStart,
            HookPhase::PostStart,
            HookPhase::PreStop,
            HookPhase::PostStop,
        ]
    }

    /// Check if this phase requires a running jail
    #[allow(dead_code)]
    pub fn requires_running_jail(&self) -> bool {
        matches!(self, HookPhase::PostStart | HookPhase::PreStop)
    }
}

impl std::fmt::Display for HookPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            HookPhase::PreCreate => "pre_create",
            HookPhase::PostCreate => "post_create",
            HookPhase::PreStart => "pre_start",
            HookPhase::PostStart => "post_start",
            HookPhase::PreStop => "pre_stop",
            HookPhase::PostStop => "post_stop",
        };
        write!(f, "{}", s)
    }
}

/// Where to execute the hook
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum HookTarget {
    /// Execute on the host system
    #[default]
    Host,
    /// Execute inside the jail (requires running jail)
    Jail,
}

/// What to do when a hook fails
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OnFailure {
    /// Abort the operation (default)
    #[default]
    Abort,
    /// Continue with the next hook/operation
    Continue,
}

/// A lifecycle hook definition
#[derive(Debug, Clone, Deserialize)]
pub struct Hook {
    /// Lifecycle phase to execute at
    pub phase: HookPhase,

    /// Where to execute (host or jail)
    #[serde(default)]
    pub target: HookTarget,

    /// Command to execute
    pub command: String,

    /// Arguments (supports variable substitution)
    #[serde(default)]
    pub args: Vec<String>,

    /// Timeout in seconds (default: 30)
    #[serde(default = "default_timeout")]
    pub timeout: u64,

    /// What to do on failure
    #[serde(default)]
    pub on_failure: OnFailure,

    /// Optional description for logging
    pub description: Option<String>,
}

fn default_timeout() -> u64 {
    30
}

impl Hook {
    /// Create a new hook (_unused: future feature)
    #[allow(dead_code)]
    pub fn new(phase: HookPhase, command: String) -> Self {
        Self {
            phase,
            target: HookTarget::Host,
            command,
            args: Vec::new(),
            timeout: default_timeout(),
            on_failure: OnFailure::Abort,
            description: None,
        }
    }

    /// Set hook target (_unused: future feature)
    #[allow(dead_code)]
    pub fn with_target(mut self, target: HookTarget) -> Self {
        self.target = target;
        self
    }

    /// Set hook arguments (_unused: future feature)
    #[allow(dead_code)]
    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    /// Set timeout (_unused: future feature)
    #[allow(dead_code)]
    pub fn with_timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set failure behavior (_unused: future feature)
    #[allow(dead_code)]
    pub fn with_on_failure(mut self, on_failure: OnFailure) -> Self {
        self.on_failure = on_failure;
        self
    }

    /// Set description (_unused: future feature)
    #[allow(dead_code)]
    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }
}

/// Context for variable substitution in hooks
#[derive(Debug, Clone, Default)]
pub struct HookContext {
    /// Jail name
    pub jail_name: String,
    /// Jail filesystem path
    pub jail_path: String,
    /// Jail IP address (if assigned)
    pub jail_ip: Option<String>,
    /// Jail ID (if running)
    pub jid: Option<i32>,
    /// Additional custom variables
    pub extra: HashMap<String, String>,
}

impl HookContext {
    /// Create a new hook context
    pub fn new(jail_name: &str, jail_path: &Path) -> Self {
        Self {
            jail_name: jail_name.to_string(),
            jail_path: jail_path.display().to_string(),
            jail_ip: None,
            jid: None,
            extra: HashMap::new(),
        }
    }

    /// Set jail IP
    pub fn with_ip(mut self, ip: String) -> Self {
        self.jail_ip = Some(ip);
        self
    }

    /// Set jail ID
    pub fn with_jid(mut self, jid: i32) -> Self {
        self.jid = Some(jid);
        self
    }

    /// Add custom variable (_unused: future feature)
    #[allow(dead_code)]
    pub fn with_var(mut self, name: &str, value: &str) -> Self {
        self.extra.insert(name.to_string(), value.to_string());
        self
    }

    /// Substitute variables in a string
    ///
    /// Supported variables:
    /// - ${jail_name} - Jail name
    /// - ${jail_path} - Jail filesystem path
    /// - ${jail_ip} - Jail IP address
    /// - ${jid} - Jail ID
    /// - ${custom_var} - Custom variables from extra
    pub fn substitute(&self, input: &str) -> String {
        let mut result = input.to_string();

        // Built-in variables
        result = result.replace("${jail_name}", &self.jail_name);
        result = result.replace("${jail_path}", &self.jail_path);

        if let Some(ip) = &self.jail_ip {
            result = result.replace("${jail_ip}", ip);
        } else {
            result = result.replace("${jail_ip}", "");
        }

        if let Some(jid) = self.jid {
            result = result.replace("${jid}", &jid.to_string());
        } else {
            result = result.replace("${jid}", "");
        }

        // Custom variables
        for (name, value) in &self.extra {
            result = result.replace(&format!("${{{}}}", name), value);
        }

        result
    }
}

/// Hook execution result
#[derive(Debug)]
#[allow(dead_code)] // Fields used via summary() and output() methods
pub struct HookResult {
    /// Whether the hook succeeded
    pub success: bool,
    /// Exit code (if available)
    pub exit_code: Option<i32>,
    /// Standard output
    pub stdout: String,
    /// Standard error
    pub stderr: String,
}

#[allow(dead_code)] // Public API for hook result inspection
impl HookResult {
    /// Get a formatted summary of the hook result
    pub fn summary(&self) -> String {
        let status = if self.success { "success" } else { "failed" };
        let code = self
            .exit_code
            .map(|c| format!(" (exit {})", c))
            .unwrap_or_default();
        format!("{}{}", status, code)
    }

    /// Get combined output (stdout + stderr)
    pub fn output(&self) -> String {
        if self.stdout.is_empty() {
            self.stderr.clone()
        } else if self.stderr.is_empty() {
            self.stdout.clone()
        } else {
            format!("{}\n{}", self.stdout, self.stderr)
        }
    }
}

/// Runner for executing hooks
pub struct HookRunner {
    /// Hooks to execute
    hooks: Vec<Hook>,
    /// Verbose output
    verbose: bool,
}

impl HookRunner {
    /// Create a new hook runner
    pub fn new(hooks: Vec<Hook>) -> Self {
        Self {
            hooks,
            verbose: false,
        }
    }

    /// Enable verbose output
    pub fn verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Execute all hooks for a given phase
    pub fn execute_phase(&self, phase: HookPhase, context: &HookContext) -> Result<()> {
        let phase_hooks: Vec<&Hook> = self.hooks.iter().filter(|h| h.phase == phase).collect();

        if phase_hooks.is_empty() {
            return Ok(());
        }

        if self.verbose {
            println!("Executing {} hooks for phase {}", phase_hooks.len(), phase);
        }

        for hook in phase_hooks {
            let result = self.execute_hook(hook, context)?;

            if !result.success {
                let desc = hook.description.as_deref().unwrap_or(&hook.command);
                let msg = format!(
                    "Hook '{}' failed at phase {}: {}",
                    desc, phase, result.stderr
                );

                match hook.on_failure {
                    OnFailure::Abort => {
                        return Err(Error::HookFailed {
                            phase: phase.to_string(),
                            command: hook.command.clone(),
                            message: result.stderr,
                        });
                    }
                    OnFailure::Continue => {
                        eprintln!("Warning: {}", msg);
                    }
                }
            }
        }

        Ok(())
    }

    /// Execute a single hook
    fn execute_hook(&self, hook: &Hook, context: &HookContext) -> Result<HookResult> {
        // Substitute variables in command and args
        let command = context.substitute(&hook.command);
        let args: Vec<String> = hook.args.iter().map(|a| context.substitute(a)).collect();

        if self.verbose {
            let desc = hook.description.as_deref().unwrap_or(&command);
            println!("  Running: {} ({:?})", desc, hook.target);
        }

        match hook.target {
            HookTarget::Host => self.execute_on_host(&command, &args, hook.timeout),
            HookTarget::Jail => {
                let jid = context.jid.ok_or_else(|| Error::HookFailed {
                    phase: hook.phase.to_string(),
                    command: command.clone(),
                    message: "Cannot execute jail hook: jail is not running".to_string(),
                })?;
                self.execute_in_jail(jid, &command, &args, hook.timeout)
            }
        }
    }

    /// Execute a command on the host with timeout enforcement
    fn execute_on_host(
        &self,
        command: &str,
        args: &[String],
        timeout_secs: u64,
    ) -> Result<HookResult> {
        let timeout = Duration::from_secs(timeout_secs);

        let mut child = Command::new(command)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::HookFailed {
                phase: String::new(),
                command: command.to_string(),
                message: e.to_string(),
            })?;

        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    // Process completed, read output
                    let mut stdout = String::new();
                    let mut stderr = String::new();

                    if let Some(mut stdout_handle) = child.stdout.take() {
                        let _ = stdout_handle.read_to_string(&mut stdout);
                    }
                    if let Some(mut stderr_handle) = child.stderr.take() {
                        let _ = stderr_handle.read_to_string(&mut stderr);
                    }

                    return Ok(HookResult {
                        success: status.success(),
                        exit_code: status.code(),
                        stdout,
                        stderr,
                    });
                }
                Ok(None) => {
                    // Process still running, check timeout
                    if start.elapsed() > timeout {
                        let _ = child.kill();
                        // Wait for process to be reaped after kill
                        let _ = child.wait();
                        return Err(Error::HookTimeout(timeout_secs));
                    }
                    thread::sleep(Duration::from_millis(100));
                }
                Err(e) => {
                    return Err(Error::HookFailed {
                        phase: String::new(),
                        command: command.to_string(),
                        message: format!("Failed to wait on process: {}", e),
                    });
                }
            }
        }
    }

    /// Execute a command inside a jail with timeout enforcement
    fn execute_in_jail(
        &self,
        jid: i32,
        command: &str,
        args: &[String],
        timeout_secs: u64,
    ) -> Result<HookResult> {
        let timeout = Duration::from_secs(timeout_secs);

        // Build jexec command with piped output for capturing
        let mut cmd = Command::new("/usr/sbin/jexec");
        cmd.arg("-u")
            .arg("root")
            .arg(jid.to_string())
            .arg(command)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| Error::HookFailed {
            phase: String::new(),
            command: command.to_string(),
            message: format!("Failed to execute jexec: {}", e),
        })?;

        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    // Process completed, read output
                    let mut stdout = String::new();
                    let mut stderr = String::new();

                    if let Some(mut stdout_handle) = child.stdout.take() {
                        let _ = stdout_handle.read_to_string(&mut stdout);
                    }
                    if let Some(mut stderr_handle) = child.stderr.take() {
                        let _ = stderr_handle.read_to_string(&mut stderr);
                    }

                    return Ok(HookResult {
                        success: status.success(),
                        exit_code: status.code(),
                        stdout,
                        stderr,
                    });
                }
                Ok(None) => {
                    // Process still running, check timeout
                    if start.elapsed() > timeout {
                        let _ = child.kill();
                        // Wait for process to be reaped after kill
                        let _ = child.wait();
                        return Err(Error::HookTimeout(timeout_secs));
                    }
                    thread::sleep(Duration::from_millis(100));
                }
                Err(e) => {
                    return Err(Error::HookFailed {
                        phase: String::new(),
                        command: command.to_string(),
                        message: format!("Failed to wait on process: {}", e),
                    });
                }
            }
        }
    }
}

/// Filter hooks by phase
/// 
/// Utility function for filtering hooks when you need to process
/// hooks for a specific phase outside of HookRunner.
/// 
/// # Example
/// ```ignore
/// let pre_start_hooks = filter_by_phase(&jail.hooks, HookPhase::PreStart);
/// println!("Found {} pre_start hooks", pre_start_hooks.len());
/// ```
#[allow(dead_code)] // Public API utility function
pub fn filter_by_phase(hooks: &[Hook], phase: HookPhase) -> Vec<&Hook> {
    hooks.iter().filter(|h| h.phase == phase).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_phase_display() {
        assert_eq!(HookPhase::PreStart.to_string(), "pre_start");
        assert_eq!(HookPhase::PostStop.to_string(), "post_stop");
    }

    #[test]
    fn test_hook_context_substitution() {
        let ctx = HookContext::new("myjail", Path::new("/jails/myjail"))
            .with_ip("10.0.1.10".to_string())
            .with_jid(42)
            .with_var("custom", "value");

        assert_eq!(ctx.substitute("jail: ${jail_name}"), "jail: myjail");
        assert_eq!(ctx.substitute("path: ${jail_path}"), "path: /jails/myjail");
        assert_eq!(ctx.substitute("ip: ${jail_ip}"), "ip: 10.0.1.10");
        assert_eq!(ctx.substitute("jid: ${jid}"), "jid: 42");
        assert_eq!(ctx.substitute("var: ${custom}"), "var: value");
    }

    #[test]
    fn test_hook_builder() {
        let hook = Hook::new(HookPhase::PreStart, "/bin/echo".to_string())
            .with_target(HookTarget::Host)
            .with_args(vec!["hello".to_string()])
            .with_timeout(60)
            .with_on_failure(OnFailure::Continue);

        assert_eq!(hook.phase, HookPhase::PreStart);
        assert_eq!(hook.target, HookTarget::Host);
        assert_eq!(hook.timeout, 60);
        assert_eq!(hook.on_failure, OnFailure::Continue);
    }

    #[test]
    fn test_phase_requires_running_jail() {
        assert!(!HookPhase::PreCreate.requires_running_jail());
        assert!(!HookPhase::PostCreate.requires_running_jail());
        assert!(!HookPhase::PreStart.requires_running_jail());
        assert!(HookPhase::PostStart.requires_running_jail());
        assert!(HookPhase::PreStop.requires_running_jail());
        assert!(!HookPhase::PostStop.requires_running_jail());
    }

    #[test]
    fn test_hook_deserialize() {
        let toml = r#"
phase = "pre_start"
target = "host"
command = "/usr/local/bin/setup.sh"
args = ["${jail_name}", "${jail_ip}"]
timeout = 60
on_failure = "continue"
description = "Run setup script"
"#;

        let hook: Hook = toml::from_str(toml).unwrap();
        assert_eq!(hook.phase, HookPhase::PreStart);
        assert_eq!(hook.target, HookTarget::Host);
        assert_eq!(hook.command, "/usr/local/bin/setup.sh");
        assert_eq!(hook.args.len(), 2);
        assert_eq!(hook.timeout, 60);
        assert_eq!(hook.on_failure, OnFailure::Continue);
    }
}
