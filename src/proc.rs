//! Supervised host command execution
//!
//! Run a command, capture both pipes, kill it if it outlives its timeout.
//! Shared by hooks and health checks.

// FFI module: pre_exec hooks and process-group signals.
#![allow(unsafe_code)]

use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use deadline_machines::{Clock, Deadline, SystemClock};

/// Whether `pid` has exited, without reaping it, so its group id stays
/// reserved for a following `kill(-pid)`. `block` waits instead of polling.
pub fn wait_exited(pid: nix::unistd::Pid, block: bool) -> nix::Result<bool> {
    use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid};

    let mut flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT;
    if !block {
        flags |= WaitPidFlag::WNOHANG;
    }
    Ok(!matches!(
        waitid(Id::Pid(pid), flags)?,
        WaitStatus::StillAlive
    ))
}

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
    // SAFETY: the pre_exec hook makes only async-signal-safe syscalls.
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
    let mut stdout_thread = child.stdout.take().map(spawn_reader);
    let mut stderr_thread = child.stderr.take().map(spawn_reader);

    let pid = child.id() as libc::pid_t;
    let clock = SystemClock::new();
    let deadline = Deadline::after(clock.now(), crate::sys::nanos(timeout));

    loop {
        match wait_exited(nix::unistd::Pid::from_raw(pid), false) {
            Ok(true) => {
                // Unreaped child still pins the group id.
                // SAFETY: plain integer args.
                unsafe { libc::kill(-pid, libc::SIGKILL) };
                let status = child.wait();
                let (stdout, stderr) = join_pipes(&mut stdout_thread, &mut stderr_thread);
                let status = status?;
                return Ok(Outcome::Exited(Output {
                    success: status.success(),
                    exit_code: status.code(),
                    stdout,
                    stderr,
                }));
            }
            Ok(false) => {
                if deadline.is_expired(clock.now()) {
                    reap_group(&mut child, pid);
                    join_pipes(&mut stdout_thread, &mut stderr_thread);
                    return Ok(Outcome::TimedOut);
                }
                thread::sleep(POLL_INTERVAL);
            }
            Err(e) => {
                reap_group(&mut child, pid);
                join_pipes(&mut stdout_thread, &mut stderr_thread);
                return Err(io::Error::from(e));
            }
        }
    }
}

/// Consecutive closed descriptors after which [`close_dir_fds`] stops looking.
const FD_GAP: libc::c_int = 1024;

/// Close every directory fd above stderr; pre-exec safe.
///
/// `jail_attach(2)` refuses with EPERM while the process holds a directory fd, and a
/// fork taken while another thread has one open inherits it, close-on-exec or not.
/// FreeBSD has no cheap "highest open fd", so the scan ends after [`FD_GAP`]
/// consecutive closed descriptors; descriptors are allocated lowest-first, so a
/// wider gap does not occur in practice.
pub fn close_dir_fds() {
    let mut fd = 3;
    let mut closed_run = 0;
    while closed_run < FD_GAP {
        // SAFETY: zeroed `stat` is a valid out-parameter; fstat and close take integers.
        unsafe {
            let mut st: libc::stat = std::mem::zeroed();
            if libc::fstat(fd, &raw mut st) == 0 {
                closed_run = 0;
                if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
                    libc::close(fd);
                }
            } else {
                closed_run += 1;
            }
        }
        fd += 1;
    }
}

/// Mark every fd above stderr close-on-exec; pre-exec safe.
///
/// Not `closefrom(3)`: that closes std's exec-failure pipe, turning `NotFound` into SIGABRT.
pub fn harden_fds() {
    // SAFETY: plain integer args.
    let marked = unsafe {
        libc::close_range(
            3,
            libc::c_uint::MAX,
            libc::CLOSE_RANGE_CLOEXEC.cast_signed(),
        )
    };
    if marked == -1 {
        // close_range(2) is FreeBSD 13+; blunt fallback beats inheritable fds.
        // SAFETY: integer arg; we exec right after.
        unsafe { libc::closefrom(3) };
    }
}

/// Kill the child's process group, falling back to the child alone, then reap it.
fn reap_group(child: &mut std::process::Child, pid: libc::pid_t) {
    // SAFETY: plain integer args.
    let killed_group = unsafe { libc::kill(-pid, libc::SIGKILL) };
    if killed_group == -1 {
        // SAFETY: plain integer args.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    // Status is moot after SIGKILL.
    let _ = child.wait();
}

fn spawn_reader(mut pipe: impl io::Read + Send + 'static) -> thread::JoinHandle<String> {
    thread::spawn(move || {
        let mut buf = String::new();
        // Partial output beats none.
        let _ = pipe.read_to_string(&mut buf);
        buf
    })
}

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
mod tests;
