//! Supervised host command execution
//!
//! Run a command, capture both pipes, kill it if it outlives its timeout.
//! Shared by hooks and health checks.

use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// How often the supervisor polls a running child.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// A child that ran to completion.
#[derive(Debug)]
pub struct Output {
    /// Whether the child exited zero.
    pub success: bool,
    /// Exit code, or `None` if the child died to a signal.
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// Why a supervised command stopped.
#[derive(Debug)]
pub enum Outcome {
    /// The child exited on its own.
    Exited(Output),
    /// The child outlived its timeout and was killed.
    TimedOut,
}

/// Run `cmd` to completion under `timeout`, capturing stdout and stderr.
///
/// Child gets its own process group; the group is killed on exit or timeout so
/// grandchildren drop the pipes and the drain threads finish.
///
/// `Err` is spawn/wait failure. A non-zero exit is `Ok(Exited)`.
pub fn run_supervised(cmd: &mut Command, timeout: Duration) -> io::Result<Outcome> {
    let mut child = unsafe {
        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                harden_fds();
                Ok(())
            })
            .spawn()?
    };

    // Drain the pipes in threads: >64KB of output would block the child before try_wait().
    let mut stdout_thread = child.stdout.take().map(|mut s| {
        thread::spawn(move || {
            let mut buf = String::new();
            let _ = io::Read::read_to_string(&mut s, &mut buf);
            buf
        })
    });
    let mut stderr_thread = child.stderr.take().map(|mut s| {
        thread::spawn(move || {
            let mut buf = String::new();
            let _ = io::Read::read_to_string(&mut s, &mut buf);
            buf
        })
    });

    let pid = child.id() as libc::pid_t;
    let start = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Kill the group so grandchildren drop the pipe fds and readers finish.
                unsafe { libc::kill(-pid, libc::SIGKILL) };
                let (stdout, stderr) = join_pipes(&mut stdout_thread, &mut stderr_thread);
                return Ok(Outcome::Exited(Output {
                    success: status.success(),
                    exit_code: status.code(),
                    stdout,
                    stderr,
                }));
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    reap_group(&mut child, pid);
                    join_pipes(&mut stdout_thread, &mut stderr_thread);
                    return Ok(Outcome::TimedOut);
                }
                thread::sleep(POLL_INTERVAL);
            }
            Err(e) => {
                reap_group(&mut child, pid);
                join_pipes(&mut stdout_thread, &mut stderr_thread);
                return Err(e);
            }
        }
    }
}

/// Mark every inherited fd above stderr close-on-exec. Runs pre-exec, so
/// syscalls only.
///
/// Not `closefrom(3)`: that also closes std's CLOEXEC exec-failure pipe, which
/// turns a missing binary into a SIGABRT child instead of `NotFound`.
fn harden_fds() {
    let marked = unsafe {
        libc::close_range(
            3,
            libc::c_uint::MAX,
            libc::CLOSE_RANGE_CLOEXEC as libc::c_int,
        )
    };
    if marked == -1 {
        // close_range(2) is FreeBSD 13+; blunt fallback beats inheritable fds.
        unsafe { libc::closefrom(3) };
    }
}

/// Kill the child's process group, falling back to the child alone, then reap it.
fn reap_group(child: &mut std::process::Child, pid: libc::pid_t) {
    let killed_group = unsafe { libc::kill(-pid, libc::SIGKILL) };
    if killed_group == -1 {
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    let _ = child.wait();
}

/// Join both drain threads, yielding whatever they managed to read.
fn join_pipes(
    stdout_thread: &mut Option<thread::JoinHandle<String>>,
    stderr_thread: &mut Option<thread::JoinHandle<String>>,
) -> (String, String) {
    let stdout = stdout_thread
        .take()
        .map(|t| t.join().unwrap_or_default())
        .unwrap_or_default();
    let stderr = stderr_thread
        .take()
        .map(|t| t.join().unwrap_or_default())
        .unwrap_or_default();
    (stdout, stderr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_captures_stdout_and_exit_code() {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "echo hello; exit 3"]);

        match run_supervised(&mut cmd, Duration::from_secs(10)).unwrap() {
            Outcome::Exited(out) => {
                assert!(!out.success);
                assert_eq!(out.exit_code, Some(3));
                assert_eq!(out.stdout.trim(), "hello");
            }
            Outcome::TimedOut => panic!("should not time out"),
        }
    }

    #[test]
    fn test_captures_stderr() {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "echo oops >&2"]);

        match run_supervised(&mut cmd, Duration::from_secs(10)).unwrap() {
            Outcome::Exited(out) => {
                assert!(out.success);
                assert_eq!(out.stderr.trim(), "oops");
            }
            Outcome::TimedOut => panic!("should not time out"),
        }
    }

    #[test]
    fn test_timeout_kills_child() {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "sleep 30"]);

        let started = Instant::now();
        match run_supervised(&mut cmd, Duration::from_millis(200)).unwrap() {
            Outcome::TimedOut => {}
            Outcome::Exited(_) => panic!("should have timed out"),
        }
        assert!(started.elapsed() < Duration::from_secs(5), "kill was slow");
    }

    #[test]
    fn test_backgrounded_grandchild_does_not_wedge_the_drain() {
        // Child exits at once but leaves a grandchild holding the pipe.
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "sh -c 'sleep 30' & echo done"]);

        let started = Instant::now();
        match run_supervised(&mut cmd, Duration::from_secs(10)).unwrap() {
            Outcome::Exited(out) => assert_eq!(out.stdout.trim(), "done"),
            Outcome::TimedOut => panic!("should not time out"),
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "drain waited on the grandchild"
        );
    }

    /// Regression: `closefrom(3)` made this a SIGABRT child, not NotFound.
    #[test]
    fn test_missing_command_reports_not_found() {
        let mut cmd = Command::new("/nonexistent/blackship-does-not-exist");
        let err = run_supervised(&mut cmd, Duration::from_secs(5))
            .expect_err("spawning a missing binary must fail");
        assert_eq!(err.kind(), io::ErrorKind::NotFound, "got: {err}");
    }

    #[test]
    fn test_hardening_does_not_break_successful_exec() {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "echo ok"]);

        match run_supervised(&mut cmd, Duration::from_secs(10)).unwrap() {
            Outcome::Exited(out) => {
                assert!(out.success);
                assert_eq!(out.stdout.trim(), "ok");
            }
            Outcome::TimedOut => panic!("should not time out"),
        }
    }
}
