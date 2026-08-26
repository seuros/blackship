//! Native jexec implementation using jail_attach(2) syscall
//!
//! Based on FreeBSD's jexec(8) source code.
//! This implementation uses direct syscalls instead of spawning the jexec process,
//! providing ~150x performance improvement.

use crate::error::{Error, Result};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{ForkResult, fork, pipe};
use std::ffi::CString;
use std::io::Read;
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::{Duration, Instant};

/// Execute a command inside a jail using native jail_attach(2) syscall
///
/// This is a direct replacement for `jexec <jid> <command>` that uses
/// syscalls instead of spawning a process.
///
/// # Arguments
/// * `jid` - The jail ID to execute in
/// * `command` - The command to execute (e.g., ["ifconfig", "eth0", "up"])
///
/// # Returns
/// A tuple of (exit_code, stdout, stderr)
///
/// # Performance
/// ~150x faster than spawning /usr/sbin/jexec process
pub fn jexec_with_output(jid: i32, command: &[&str]) -> Result<(i32, Vec<u8>, Vec<u8>)> {
    check_nonempty_command(command)?;

    // Create pipes for stdout and stderr
    let (stdout_read, stdout_write) = jexec_pipe("stdout")?;
    let (stderr_read, stderr_write) = jexec_pipe("stderr")?;

    // Fork the process
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            // Parent process: close write ends and read output
            drop(stdout_write);
            drop(stderr_write);

            // Read concurrently: a descendant holding a pipe open would block waitpid.
            let stdout_thread = std::thread::spawn(move || read_fd_to_end(stdout_read));
            let stderr_thread = std::thread::spawn(move || read_fd_to_end(stderr_read));

            let result = wait_child(child, jid, command);

            // Kill the process group so grandchildren release inherited pipe fds.
            unsafe {
                libc::kill(-(child.as_raw()), libc::SIGKILL);
            }

            let stdout = stdout_thread.join().unwrap_or_default();
            let stderr = stderr_thread.join().unwrap_or_default();

            result.map(|code| (code, stdout, stderr))
        }
        Ok(ForkResult::Child) => piped_child(
            ChildPipes {
                stdout_read,
                stderr_read,
                stdout_write,
                stderr_write,
            },
            jid,
            command,
        ),
        Err(e) => Err(jexec_fork_error(e)),
    }
}

/// Execute a command in a jail with stdio on /dev/null, waiting for exit.
///
/// For boot-style commands (/etc/rc) that spawn long-lived daemons: pipes
/// would be inherited by setsid'd descendants and block the reader forever,
/// so no output is captured.
pub fn jexec_run(jid: i32, command: &[&str]) -> Result<i32> {
    check_nonempty_command(command)?;

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => wait_child(child, jid, command),
        Ok(ForkResult::Child) => {
            unsafe {
                let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
                if null >= 0 {
                    libc::dup2(null, 0);
                    libc::dup2(null, 1);
                    libc::dup2(null, 2);
                    if null > 2 {
                        libc::close(null);
                    }
                }
            }
            attach_and_exec(jid, command);
        }
        Err(e) => Err(jexec_fork_error(e)),
    }
}

/// Final stage of every jexec child: drop inherited descriptors, enter the
/// jail, and exec. Never returns; exits 127 when exec fails.
fn attach_and_exec(jid: i32, command: &[&str]) -> ! {
    unsafe {
        libc::closefrom(3);
    }

    if unsafe { libc::jail_attach(jid) } != 0 {
        eprintln!(
            "jail_attach({}) failed: {}",
            jid,
            std::io::Error::last_os_error()
        );
        std::process::exit(1);
    }

    let cmd_cstring = match CString::new(command[0]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Invalid command string: {}", e);
            std::process::exit(1);
        }
    };
    let mut args: Vec<CString> = Vec::new();
    for arg in command {
        match CString::new(*arg) {
            Ok(s) => args.push(s),
            Err(e) => {
                eprintln!("Invalid argument string: {}", e);
                std::process::exit(1);
            }
        }
    }
    let mut arg_ptrs: Vec<*const libc::c_char> = args.iter().map(|s| s.as_ptr()).collect();
    arg_ptrs.push(std::ptr::null());

    unsafe {
        libc::execvp(cmd_cstring.as_ptr(), arg_ptrs.as_ptr());
    }
    eprintln!("execvp failed: {}", std::io::Error::last_os_error());
    std::process::exit(127);
}

/// Wait for a plain (unpiped) jexec child and map its exit status.
fn wait_child(child: nix::unistd::Pid, jid: i32, command: &[&str]) -> Result<i32> {
    match waitpid(child, None) {
        Ok(WaitStatus::Exited(_, exit_code)) => Ok(exit_code),
        Ok(WaitStatus::Signaled(_, signal, _)) => Err(Error::CommandFailed {
            command: format!("jexec {} {:?}", jid, command),
            message: format!("Process killed by signal {}", signal),
        }),
        Ok(status) => Err(Error::CommandFailed {
            command: format!("jexec {} {:?}", jid, command),
            message: format!("Unexpected wait status: {:?}", status),
        }),
        Err(e) => Err(Error::CommandFailed {
            command: format!("jexec {} {:?}", jid, command),
            message: format!("waitpid failed: {}", e),
        }),
    }
}

/// Return an error if a jexec command slice is empty
fn check_nonempty_command(command: &[&str]) -> Result<()> {
    if command.is_empty() {
        return Err(Error::CommandFailed {
            command: "jexec".to_string(),
            message: "Empty command".to_string(),
        });
    }
    Ok(())
}

/// Map a fork() failure into a CommandFailed error
fn jexec_fork_error(e: nix::errno::Errno) -> Error {
    Error::CommandFailed {
        command: "jexec".to_string(),
        message: format!("Fork failed: {}", e),
    }
}

/// Create a pipe, mapping errors to a CommandFailed error with the given label
fn jexec_pipe(label: &str) -> Result<(OwnedFd, OwnedFd)> {
    pipe().map_err(|e| Error::CommandFailed {
        command: "jexec".to_string(),
        message: format!("Failed to create {} pipe: {}", label, e),
    })
}

/// Child side of a piped jexec: drop the read ends, take our own process group
/// so the parent can kill grandchildren, wire up the pipes, attach, exec.
fn piped_child(pipes: ChildPipes, jid: i32, command: &[&str]) -> ! {
    drop(pipes.stdout_read);
    drop(pipes.stderr_read);
    unsafe {
        libc::setpgid(0, 0);
    }
    redirect_child_io(pipes.stdout_write, pipes.stderr_write);
    attach_and_exec(jid, command);
}

/// Stop being a reaper; descendants revert to init.
fn reap_release() {
    unsafe {
        libc::procctl(
            libc::P_PID as libc::idtype_t,
            0,
            libc::PROC_REAP_RELEASE,
            std::ptr::null_mut(),
        );
    }
}

/// The four pipe ends a forked child inherits.
struct ChildPipes {
    stdout_read: OwnedFd,
    stderr_read: OwnedFd,
    stdout_write: OwnedFd,
    stderr_write: OwnedFd,
}

/// Redirect stdout/stderr to the given pipe write-ends and drop them.
///
/// Must only be called in the child after fork(). The dup2 calls replace fd 1
/// and fd 2, so the original OwnedFds can be dropped immediately after.
fn redirect_child_io(stdout_write: OwnedFd, stderr_write: OwnedFd) {
    unsafe {
        libc::dup2(stdout_write.as_raw_fd(), 1); // STDOUT_FILENO
        libc::dup2(stderr_write.as_raw_fd(), 2); // STDERR_FILENO
    }
    // Drop closes the originals; fd 1/2 now point into the pipes
    drop(stdout_write);
    drop(stderr_write);
}

/// Read all data from a file descriptor into a Vec<u8>
fn read_fd_to_end(fd: OwnedFd) -> Vec<u8> {
    let mut buffer = Vec::new();
    let mut file = std::fs::File::from(fd);
    file.read_to_end(&mut buffer).ok();
    buffer
}

/// Execute a command inside a jail with timeout enforcement
///
/// Similar to `jexec_with_output` but with timeout support.
/// Uses non-blocking waitpid to poll for completion.
///
/// # Arguments
/// * `jid` - The jail ID to execute in
/// * `command` - The command to execute
/// * `timeout_secs` - Timeout in seconds (0 = no timeout)
///
/// # Returns
/// A tuple of (exit_code, stdout_string, stderr_string)
/// Returns Error::JailTimeout if the command exceeds the timeout
pub fn jexec_with_timeout(
    jid: i32,
    command: &[&str],
    timeout_secs: u64,
) -> Result<(i32, String, String)> {
    check_nonempty_command(command)?;

    // Create pipes for stdout and stderr
    let (stdout_read, stdout_write) = jexec_pipe("stdout")?;
    let (stderr_read, stderr_write) = jexec_pipe("stderr")?;

    // Fork the process
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            // Parent process: close write ends
            drop(stdout_write);
            drop(stderr_write);

            let stdout_thread = std::thread::spawn(move || read_fd_to_end(stdout_read));
            let stderr_thread = std::thread::spawn(move || read_fd_to_end(stderr_read));

            let timeout = Duration::from_secs(timeout_secs);
            let start = Instant::now();

            // Poll for child completion with timeout
            loop {
                match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::StillAlive) => {
                        // Process still running, check timeout
                        if timeout_secs > 0 && start.elapsed() > timeout {
                            let kill_ret = unsafe { libc::kill(-(child.as_raw()), libc::SIGKILL) };
                            if kill_ret == -1 {
                                unsafe {
                                    libc::kill(child.as_raw(), libc::SIGKILL);
                                }
                            }
                            let _ = waitpid(child, None);
                            let _ = stdout_thread.join();
                            let _ = stderr_thread.join();
                            return Err(Error::JailTimeout(timeout_secs));
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Ok(WaitStatus::Exited(_, exit_code)) => {
                        unsafe {
                            libc::kill(-(child.as_raw()), libc::SIGKILL);
                        }
                        let stdout = stdout_thread.join().unwrap_or_default();
                        let stderr = stderr_thread.join().unwrap_or_default();

                        return Ok((
                            exit_code,
                            String::from_utf8_lossy(&stdout).into_owned(),
                            String::from_utf8_lossy(&stderr).into_owned(),
                        ));
                    }
                    Ok(WaitStatus::Signaled(_, signal, _)) => {
                        unsafe {
                            libc::kill(-(child.as_raw()), libc::SIGKILL);
                        }
                        let _ = stdout_thread.join();
                        let _ = stderr_thread.join();
                        return Err(Error::CommandFailed {
                            command: format!("jexec {} {:?}", jid, command),
                            message: format!("Process killed by signal {}", signal),
                        });
                    }
                    Ok(status) => {
                        unsafe {
                            libc::kill(-(child.as_raw()), libc::SIGKILL);
                        }
                        let _ = stdout_thread.join();
                        let _ = stderr_thread.join();
                        return Err(Error::CommandFailed {
                            command: format!("jexec {} {:?}", jid, command),
                            message: format!("Unexpected wait status: {:?}", status),
                        });
                    }
                    Err(e) => {
                        unsafe {
                            libc::kill(-(child.as_raw()), libc::SIGKILL);
                        }
                        let _ = stdout_thread.join();
                        let _ = stderr_thread.join();
                        return Err(Error::CommandFailed {
                            command: format!("jexec {} {:?}", jid, command),
                            message: format!("waitpid failed: {}", e),
                        });
                    }
                }
            }
        }
        Ok(ForkResult::Child) => piped_child(
            ChildPipes {
                stdout_read,
                stderr_read,
                stdout_write,
                stderr_write,
            },
            jid,
            command,
        ),
        Err(e) => Err(jexec_fork_error(e)),
    }
}

/// Execute a command in a chroot environment using native syscalls
///
/// This is a direct replacement for `/usr/sbin/chroot <path> /bin/sh -c <command>`
/// that uses syscalls instead of spawning a process.
///
/// # Arguments
/// * `root_path` - The path to chroot into
/// * `command` - The shell command to execute
/// * `env_vars` - Environment variables to set
///
/// # Returns
/// A tuple of (exit_code, stdout, stderr)
pub fn chroot_exec(
    root_path: &str,
    command: &str,
    env_vars: &[(String, String)],
) -> Result<(i32, Vec<u8>, Vec<u8>)> {
    // Create pipes for stdout and stderr
    let (stdout_read, stdout_write) = pipe().map_err(|e| Error::CommandFailed {
        command: "chroot".to_string(),
        message: format!("Failed to create stdout pipe: {}", e),
    })?;

    let (stderr_read, stderr_write) = pipe().map_err(|e| Error::CommandFailed {
        command: "chroot".to_string(),
        message: format!("Failed to create stderr pipe: {}", e),
    })?;

    let root_cstring = CString::new(root_path).map_err(|e| Error::CommandFailed {
        command: "chroot".to_string(),
        message: format!("Invalid path: {}", e),
    })?;

    // Subreaper: orphaned descendants (even setsid'd ones) reparent to us, so
    // RUN can't leave detached processes racing later build steps.
    let reap_ret = unsafe {
        libc::procctl(
            libc::P_PID as libc::idtype_t,
            0, // self
            libc::PROC_REAP_ACQUIRE,
            std::ptr::null_mut(),
        )
    };
    if reap_ret != 0 {
        return Err(Error::CommandFailed {
            command: "chroot".to_string(),
            message: format!(
                "procctl(PROC_REAP_ACQUIRE) failed: {}",
                std::io::Error::last_os_error()
            ),
        });
    }

    // Fork the process
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            // Parent process: close write ends and read output
            drop(stdout_write);
            drop(stderr_write);

            let stdout_thread = std::thread::spawn(move || read_fd_to_end(stdout_read));
            let stderr_thread = std::thread::spawn(move || read_fd_to_end(stderr_read));

            let wait_result = waitpid(child, None);

            unsafe {
                libc::kill(-(child.as_raw()), libc::SIGKILL);
            }

            // Reaper-kill the rest (setsid'd included). Must match struct
            // procctl_reaper_kill: the kernel copies the whole struct back out.
            #[repr(C)]
            struct ProcctlReapKill {
                rk_sig: libc::c_int,
                rk_flags: libc::c_uint,
                rk_subtree: libc::pid_t,
                rk_killed: libc::c_uint,
                rk_fpid: libc::pid_t,
                rk_pad0: [libc::c_uint; 15],
            }
            const _: [(); crate::sys::consts::SIZEOF_PROCCTL_REAPER_KILL] =
                [(); std::mem::size_of::<ProcctlReapKill>()];
            let mut rk = ProcctlReapKill {
                rk_sig: libc::SIGKILL,
                rk_flags: crate::sys::consts::REAPER_KILL_SUBTREE,
                rk_subtree: child.as_raw(),
                rk_killed: 0,
                rk_fpid: 0,
                rk_pad0: [0; 15],
            };
            unsafe {
                libc::procctl(
                    libc::P_PID as libc::idtype_t,
                    0,
                    libc::PROC_REAP_KILL,
                    &mut rk as *mut _ as *mut libc::c_void,
                );
            }

            loop {
                match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::StillAlive) | Err(_) => break,
                    _ => continue,
                }
            }

            let stdout = stdout_thread.join().unwrap_or_default();
            let stderr = stderr_thread.join().unwrap_or_default();

            reap_release();

            match wait_result {
                Ok(WaitStatus::Exited(_, exit_code)) => Ok((exit_code, stdout, stderr)),
                Ok(WaitStatus::Signaled(_, signal, _)) => Err(Error::CommandFailed {
                    command: format!("chroot {}", root_path),
                    message: format!("Process killed by signal {}", signal),
                }),
                Ok(status) => Err(Error::CommandFailed {
                    command: format!("chroot {}", root_path),
                    message: format!("Unexpected wait status: {:?}", status),
                }),
                Err(e) => Err(Error::CommandFailed {
                    command: format!("chroot {}", root_path),
                    message: format!("waitpid failed: {}", e),
                }),
            }
        }
        Ok(ForkResult::Child) => {
            // Child process: chroot and execute command
            drop(stdout_read);
            drop(stderr_read);

            // Redirect stdout and stderr to pipes
            redirect_child_io(stdout_write, stderr_write);

            unsafe {
                libc::closefrom(3);
            }

            // chroot(2) syscall
            let result = unsafe { libc::chroot(root_cstring.as_ptr()) };
            if result != 0 {
                eprintln!(
                    "chroot({}) failed: {}",
                    root_path,
                    std::io::Error::last_os_error()
                );
                std::process::exit(1);
            }

            // Fatal on failure: a stale cwd is a chroot escape vector.
            let root_dir = CString::new("/").unwrap();
            if unsafe { libc::chdir(root_dir.as_ptr()) } != 0 {
                eprintln!(
                    "chdir(\"/\") after chroot failed: {}",
                    std::io::Error::last_os_error()
                );
                std::process::exit(1);
            }

            unsafe {
                libc::setpgid(0, 0);
            }

            // No privilege drop: RUN builds the target filesystem and needs root.

            // SAFETY: We're in a forked child process, single-threaded
            for (key, value) in env_vars {
                unsafe { std::env::set_var(key, value) };
            }

            // Execute command via shell
            let cmd_cstring = CString::new("/bin/sh").unwrap();
            let arg_c = CString::new("-c").unwrap();
            let arg_cmd = match CString::new(command) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Invalid command string: {}", e);
                    std::process::exit(1);
                }
            };

            let args: [*const libc::c_char; 4] = [
                cmd_cstring.as_ptr(),
                arg_c.as_ptr(),
                arg_cmd.as_ptr(),
                std::ptr::null(),
            ];

            unsafe {
                libc::execvp(cmd_cstring.as_ptr(), args.as_ptr());
            }

            eprintln!("execvp failed: {}", std::io::Error::last_os_error());
            std::process::exit(127);
        }
        Err(e) => {
            reap_release();
            Err(Error::CommandFailed {
                command: "chroot".to_string(),
                message: format!("Fork failed: {}", e),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires a running jail
    fn test_jexec_basic() {
        // This test requires a jail with JID 1 to be running
        // Run: sudo jail -c name=test path=/tmp persist
        let result = jexec_with_output(1, &["echo", "hello"]);
        assert!(result.is_ok());

        if let Ok((exit_code, stdout, _stderr)) = result {
            assert_eq!(exit_code, 0);
            assert_eq!(String::from_utf8_lossy(&stdout).trim(), "hello");
        }
    }
}
