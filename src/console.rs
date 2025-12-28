//! Console and exec functionality for jails
//!
//! Provides the ability to:
//! - Execute commands inside a running jail
//! - Open an interactive console session

use crate::error::{Error, Result};
use crate::jail::{jail_attach, jail_getid};
use std::ffi::CString;
use std::os::unix::process::ExitStatusExt;
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
    /// Clear environment before setting new vars
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

    // Add command and arguments
    if command.is_empty() {
        // Default to shell
        cmd.arg("/bin/sh");
    } else {
        cmd.args(command);
    }

    // Set working directory if specified
    if let Some(ref workdir) = opts.workdir {
        cmd.current_dir(workdir);
    }

    // Handle environment
    if opts.clear_env {
        cmd.env_clear();
    }
    for (key, value) in &opts.env {
        cmd.env(key, value);
    }

    // Inherit stdio for interactive use
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let status = cmd
        .status()
        .map_err(|e| Error::JailExecFailed(format!("Failed to execute jexec: {}", e)))?;

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

/// Execute a command inside a jail using fork + jail_attach
///
/// This is the lower-level approach that directly uses the jail_attach syscall.
/// It provides more control but is more complex.
#[allow(dead_code)]
pub fn exec_in_jail_direct(
    jail: &str,
    command: &[String],
    opts: &ExecOptions,
) -> Result<ExitStatus> {
    let jid = jail_getid(jail)?;

    if command.is_empty() {
        return Err(Error::JailExecFailed("No command specified".to_string()));
    }

    // Fork and exec in child
    match unsafe { libc::fork() } {
        -1 => Err(Error::JailExecFailed("Fork failed".to_string())),
        0 => {
            // Child process
            // Attach to jail
            if let Err(e) = jail_attach(jid) {
                eprintln!("Failed to attach to jail: {}", e);
                std::process::exit(1);
            }

            // Change user if not root
            if opts.user != "root"
                && let Err(e) = set_user(&opts.user) {
                    eprintln!("Failed to set user: {}", e);
                    std::process::exit(1);
                }

            // Change working directory
            if let Some(ref workdir) = opts.workdir
                && let Err(e) = std::env::set_current_dir(workdir) {
                    eprintln!("Failed to change directory: {}", e);
                    std::process::exit(1);
                }

            // Build command
            let program = CString::new(command[0].as_str()).unwrap();
            let args: Vec<CString> = command
                .iter()
                .map(|s| CString::new(s.as_str()).unwrap())
                .collect();
            let args_ptr: Vec<*const libc::c_char> = args
                .iter()
                .map(|s| s.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect();

            // Exec - this doesn't return on success
            unsafe {
                libc::execvp(program.as_ptr(), args_ptr.as_ptr());
            }

            // If we get here, exec failed
            eprintln!("Failed to exec: {}", std::io::Error::last_os_error());
            std::process::exit(1);
        }
        pid => {
            // Parent process - wait for child
            let mut status: libc::c_int = 0;
            unsafe {
                libc::waitpid(pid, &mut status, 0);
            }

            // Convert to ExitStatus
            let _exit_code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                1
            };

            Ok(std::process::ExitStatus::from_raw(status))
        }
    }
}

/// Set the current user (drop privileges)
fn set_user(username: &str) -> Result<()> {
    let username_c = CString::new(username)
        .map_err(|_| Error::JailExecFailed("Invalid username".to_string()))?;

    unsafe {
        let pwd = libc::getpwnam(username_c.as_ptr());
        if pwd.is_null() {
            return Err(Error::JailExecFailed(format!(
                "User '{}' not found",
                username
            )));
        }

        let uid = (*pwd).pw_uid;
        let gid = (*pwd).pw_gid;

        // Set groups, then gid, then uid (order matters for dropping privileges)
        if libc::initgroups(username_c.as_ptr(), gid as libc::gid_t) != 0 {
            return Err(Error::JailExecFailed("Failed to set groups".to_string()));
        }

        if libc::setgid(gid) != 0 {
            return Err(Error::JailExecFailed("Failed to set GID".to_string()));
        }

        if libc::setuid(uid) != 0 {
            return Err(Error::JailExecFailed("Failed to set UID".to_string()));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exec_options_default() {
        let opts = ExecOptions::default();
        assert_eq!(opts.user, "root");
        assert!(opts.workdir.is_none());
        assert!(opts.env.is_empty());
    }
}
