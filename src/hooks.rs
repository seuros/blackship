//! Lifecycle hooks for jail management
//!
//! Provides:
//! - Hook definitions for various lifecycle phases
//! - Variable substitution in hook commands
//! - Execution on host or inside jail
//! - Configurable failure handling

use crate::error::{Error, Result};
use crate::jail::jexec::jexec_with_timeout;
use crate::proc::{Outcome, run_supervised};
use crate::strings::replace_in_place;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// Lifecycle phases when hooks can be executed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
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
    /// Before a hot update (eva) is applied to a running jail
    PreEva,
    /// After a hot update (eva) is applied to a running jail
    PostEva,
}

impl HookPhase {
    /// Check if this phase requires a running jail
    pub fn requires_running_jail(&self) -> bool {
        matches!(
            self,
            HookPhase::PostStart | HookPhase::PreStop | HookPhase::PreEva | HookPhase::PostEva
        )
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
            HookPhase::PreEva => "pre_eva",
            HookPhase::PostEva => "post_eva",
        };
        write!(f, "{s}")
    }
}

/// Where to execute the hook
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum HookTarget {
    /// Execute on the host system
    #[default]
    Host,
    /// Execute inside the jail (requires running jail)
    Jail,
}

/// What to do when a hook fails
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OnFailure {
    /// Abort the operation (default)
    #[default]
    Abort,
    /// Continue with the next hook/operation
    Continue,
}

/// A lifecycle hook definition
#[derive(Debug, Clone, Deserialize, Serialize)]
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

#[cfg(test)]
impl Hook {
    /// Create a new hook
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

    /// Set hook target
    pub fn with_target(mut self, target: HookTarget) -> Self {
        self.target = target;
        self
    }

    /// Set hook arguments
    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    /// Set timeout
    pub fn with_timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set failure behavior
    pub fn with_on_failure(mut self, on_failure: OnFailure) -> Self {
        self.on_failure = on_failure;
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

    /// Add custom variable
    #[cfg(test)]
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
        if !input.contains('$') {
            return input.to_string();
        }

        let mut result = input.to_string();

        replace_in_place(&mut result, "${jail_name}", &self.jail_name);
        replace_in_place(&mut result, "${jail_path}", &self.jail_path);
        replace_in_place(
            &mut result,
            "${jail_ip}",
            self.jail_ip.as_deref().unwrap_or(""),
        );

        if result.contains("${jid}") {
            match self.jid {
                Some(jid) => result = result.replace("${jid}", &jid.to_string()),
                None => result = result.replace("${jid}", ""),
            }
        }

        let mut needle = String::new();
        for (name, value) in &self.extra {
            needle.clear();
            needle.push_str("${");
            needle.push_str(name);
            needle.push('}');
            replace_in_place(&mut result, &needle, value);
        }

        result
    }
}

/// Hook execution result
#[derive(Debug)]
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

impl HookResult {
    /// Get a formatted summary of the hook result
    pub fn summary(&self) -> String {
        let status = if self.success { "success" } else { "failed" };
        let code = self
            .exit_code
            .map(|c| format!(" (exit {c})"))
            .unwrap_or_default();
        format!("{status}{code}")
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
        let phase_hooks = filter_by_phase(&self.hooks, phase);

        if phase_hooks.is_empty() {
            return Ok(());
        }

        if phase.requires_running_jail() && context.jid.is_none() {
            return Err(Error::HookFailed {
                phase: phase.to_string(),
                command: phase_hooks[0].command.clone(),
                message: format!(
                    "Phase {} needs a running jail but no JID was supplied for '{}'",
                    phase, context.jail_name
                ),
            });
        }

        if self.verbose {
            println!("Executing {} hooks for phase {}", phase_hooks.len(), phase);
        }

        for hook in phase_hooks {
            let result = self.execute_hook(hook, context)?;

            let desc = hook.description.as_deref().unwrap_or(&hook.command);
            if self.verbose {
                println!("  {} -> {}", desc, result.summary());
                let output = result.output();
                if !output.trim().is_empty() {
                    println!("{}", output.trim_end());
                }
            }

            if !result.success {
                let msg = format!(
                    "Hook '{}' {} at phase {}: {}",
                    desc,
                    result.summary(),
                    phase,
                    result.output().trim_end()
                );

                match hook.on_failure {
                    OnFailure::Abort => {
                        return Err(Error::HookFailed {
                            phase: phase.to_string(),
                            command: hook.command.clone(),
                            message: format!(
                                "{}: {}",
                                result.summary(),
                                result.output().trim_end()
                            ),
                        });
                    }
                    OnFailure::Continue => {
                        eprintln!("Warning: {msg}");
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
        let mut cmd = Command::new(command);
        cmd.args(args);

        let failed = |message: String| Error::HookFailed {
            phase: String::new(),
            command: command.to_string(),
            message,
        };

        match run_supervised(&mut cmd, Duration::from_secs(timeout_secs))
            .map_err(|e| failed(e.to_string()))?
        {
            Outcome::Exited(out) => Ok(HookResult {
                success: out.success,
                exit_code: out.exit_code,
                stdout: out.stdout,
                stderr: out.stderr,
            }),
            Outcome::TimedOut => Err(Error::HookTimeout(timeout_secs)),
        }
    }

    /// Execute a command inside a jail with timeout enforcement
    ///
    /// Uses native jail_attach(2) syscall instead of spawning jexec process
    fn execute_in_jail(
        &self,
        jid: i32,
        command: &str,
        args: &[String],
        timeout_secs: u64,
    ) -> Result<HookResult> {
        // Build full command array for jexec
        let mut cmd_parts: Vec<&str> = vec![command];
        for arg in args {
            cmd_parts.push(arg);
        }

        match jexec_with_timeout(jid, &cmd_parts, timeout_secs) {
            Ok((exit_code, stdout, stderr)) => Ok(HookResult {
                success: exit_code == 0,
                exit_code: Some(exit_code),
                stdout,
                stderr,
            }),
            Err(Error::JailTimeout(secs)) => Err(Error::HookTimeout(secs)),
            Err(e) => Err(Error::HookFailed {
                phase: String::new(),
                command: command.to_string(),
                message: e.to_string(),
            }),
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
pub fn filter_by_phase(hooks: &[Hook], phase: HookPhase) -> Vec<&Hook> {
    hooks.iter().filter(|h| h.phase == phase).collect()
}

#[cfg(test)]
mod tests;
