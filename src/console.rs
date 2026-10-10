//! Console and exec functionality for jails
//!
//! Provides the ability to:
//! - Execute commands inside a running jail
//! - Open an interactive console session

use crate::error::{Error, Result};

/// Validate that an environment variable key is safe for shell use.
/// Keys must start with a letter or underscore, followed by alphanumerics or underscores.
fn is_valid_env_key(key: &str) -> bool {
    if key.is_empty() {
        return false;
    }
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Escape a string for safe use in single quotes
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
use crate::jail::jail_getid;
use std::fmt::Write as _;
use std::process::{Command, ExitStatus, Stdio};

/// Options for executing commands in a jail
#[derive(Debug, Clone)]
pub struct ExecOptions {
    /// User to run as inside the jail
    pub user: String,
    /// Working directory inside the jail
    pub workdir: Option<String>,
    /// Environment variables to set
    pub env: Vec<(String, String)>,
    /// Clear environment before setting new vars (`env -i` semantics)
    pub clear_env: bool,
}

impl Default for ExecOptions {
    fn default() -> Self {
        Self {
            user: "root".to_string(),
            workdir: None,
            env: Vec::new(),
            clear_env: false,
        }
    }
}

/// Execute a command inside a jail using jexec
///
/// This is the simpler approach that wraps the jexec(8) utility.
pub fn exec_in_jail(jail: &str, command: &[String], opts: &ExecOptions) -> Result<ExitStatus> {
    let jid = jail_getid(jail)?;

    let mut cmd = Command::new("/usr/sbin/jexec");

    // Add user flag
    cmd.arg("-u").arg(&opts.user);

    // Add jail ID
    cmd.arg(jid.to_string());

    // Build the actual command to run
    // If we have a workdir or env, wrap in shell
    if opts.workdir.is_some() || !opts.env.is_empty() || opts.clear_env {
        cmd.arg("/bin/sh");
        cmd.arg("-c");

        let mut script = String::new();
        let mut assignments = String::new();

        // Validate every key, whether it is exported or handed to env -i
        for (key, value) in &opts.env {
            if !is_valid_env_key(key) {
                return Err(Error::JailExecFailed(format!(
                    "Invalid environment variable key: '{key}'. Keys must start with a letter or underscore, followed by alphanumerics or underscores."
                )));
            }
            let escaped = shell_quote(value);
            if opts.clear_env {
                if !assignments.is_empty() {
                    assignments.push(' ');
                }
                let _ = write!(assignments, "{key}={escaped}");
            } else {
                let _ = write!(script, "export {key}={escaped}; ");
            }
        }

        // Add working directory change (properly escaped)
        if let Some(ref workdir) = opts.workdir {
            let escaped_workdir = shell_quote(workdir);
            let _ = write!(script, "cd {escaped_workdir} || exit 1; ");
        }

        script.push_str("exec ");
        if opts.clear_env {
            script.push_str("/usr/bin/env -i ");
            if !assignments.is_empty() {
                script.push_str(&assignments);
                script.push(' ');
            }
        }

        // Add the actual command
        if command.is_empty() {
            script.push_str("/bin/sh");
        } else {
            // Always quote each argument for safety
            for (i, arg) in command.iter().enumerate() {
                if i > 0 {
                    script.push(' ');
                }
                script.push_str(&shell_quote(arg));
            }
        }

        cmd.arg(script);
    } else {
        // No workdir or env, just run the command directly
        if command.is_empty() {
            cmd.arg("/bin/sh");
        } else {
            cmd.args(command);
        }
    }

    // Note: We pass environment through the shell script above, not here
    // This ensures the env is set inside the jail, not on the host side

    // Inherit stdio for interactive use
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let status = cmd
        .status()
        .map_err(|e| Error::JailExecFailed(format!("Failed to execute jexec: {e}")))?;

    Ok(status)
}

/// Open an interactive console in a jail
///
/// This opens a login shell inside the jail.
pub fn console(jail: &str, user: &str) -> Result<ExitStatus> {
    let opts = ExecOptions {
        user: user.to_string(),
        ..Default::default()
    };

    // Use login shell
    exec_in_jail(jail, &["-".to_string()], &opts)
}

#[cfg(test)]
mod tests;
