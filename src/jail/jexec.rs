//! Native jexec via `jail_attach(2)`, modeled on FreeBSD's jexec(8).

// FFI module: fork/exec, jail_attach(2), chroot(2), procctl(2) reaper.
#![allow(unsafe_code)]

use crate::error::{Error, Result};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, fork, pipe};
use std::ffi::CString;
use std::io::Read;
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::{Duration, Instant};

/// Run `command` in jail `jid`; returns (`exit_code`, stdout, stderr).
pub fn jexec_with_output(jid: i32, command: &[&str]) -> Result<(i32, Vec<u8>, Vec<u8>)> {
    check_nonempty_command(command)?;
    let argv = ExecArgv::new(command)?;

    let (stdout_read, stdout_write) = jexec_pipe("stdout")?;
    let (stderr_read, stderr_write) = jexec_pipe("stderr")?;

    // SAFETY: child runs only async-signal-safe syscalls until exec/_exit.
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            drop(stdout_write);
            drop(stderr_write);

            let readers = OutputReaders::spawn(stdout_read, stderr_read);

            // Kill the group before reaping, while the zombie pins its pid.
            let _ = crate::proc::wait_exited(child, true);
            kill_process_group(child);
            let result = wait_child(child, jid, command);
            let (stdout, stderr) = readers.join();

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
            &argv,
        ),
        Err(e) => Err(jexec_fork_error(e)),
    }
}

/// Run `command` in jail `jid` with stdio on /dev/null and wait for it.
///
/// For /etc/rc and friends: daemons would inherit pipes and block the reader forever.
pub fn jexec_run(jid: i32, command: &[&str]) -> Result<i32> {
    check_nonempty_command(command)?;
    let argv = ExecArgv::new(command)?;

    // SAFETY: child runs only async-signal-safe syscalls until exec/_exit.
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => wait_child(child, jid, command),
        Ok(ForkResult::Child) => {
            // SAFETY: static C string and plain fds.
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
            attach_and_exec(jid, &argv);
        }
        Err(e) => Err(jexec_fork_error(e)),
    }
}

/// Argv built before `fork()`; the child must not allocate.
struct ExecArgv {
    args: Vec<CString>,
    /// NULL-terminated pointers into `args`.
    ptrs: Vec<*const libc::c_char>,
}

impl ExecArgv {
    fn new(command: &[&str]) -> Result<Self> {
        let args = command
            .iter()
            .map(|arg| CString::new(*arg))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::CommandFailed {
                command: "jexec".to_string(),
                message: format!("Invalid argument string: {e}"),
            })?;
        let mut ptrs: Vec<*const libc::c_char> = args.iter().map(|s| s.as_ptr()).collect();
        ptrs.push(std::ptr::null());
        Ok(Self { args, ptrs })
    }
}

/// Close inherited fds, enter the jail, exec; exits 127 if exec fails.
fn attach_and_exec(jid: i32, argv: &ExecArgv) -> ! {
    // SAFETY: integer arg; the child never returns, so no OwnedFd drop follows.
    unsafe {
        libc::closefrom(3);
    }

    // SAFETY: integer arg.
    if unsafe { libc::jail_attach(jid) } != 0 {
        child_fail(b"jail_attach failed", 1);
    }

    // SAFETY: NULL-terminated argv, non-empty; FreeBSD execvp does not allocate.
    unsafe {
        libc::execvp(argv.args[0].as_ptr(), argv.ptrs.as_ptr());
    }
    child_fail(b"execvp failed", 127);
}

/// Write `what: errno N` to fd 2 and `_exit`, without allocating or locking.
fn child_fail(what: &[u8], code: libc::c_int) -> ! {
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    let mut digits = [0u8; 10];
    let mut n = errno.unsigned_abs();
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let sep = b": errno ";
    // SAFETY: writes stay within each slice; both calls are async-signal-safe.
    unsafe {
        libc::write(2, what.as_ptr().cast(), what.len());
        libc::write(2, sep.as_ptr().cast(), sep.len());
        libc::write(2, digits[start..].as_ptr().cast(), digits.len() - start);
        libc::write(2, b"\n".as_ptr().cast(), 1);
        libc::_exit(code)
    }
}

fn wait_child(child: Pid, jid: i32, command: &[&str]) -> Result<i32> {
    exit_code_of(waitpid(child, None), || format!("jexec {jid} {command:?}"))
}

fn exit_code_of(status: nix::Result<WaitStatus>, label: impl FnOnce() -> String) -> Result<i32> {
    let message = match status {
        Ok(WaitStatus::Exited(_, exit_code)) => return Ok(exit_code),
        Ok(WaitStatus::Signaled(_, signal, _)) => format!("Process killed by signal {signal}"),
        Ok(status) => format!("Unexpected wait status: {status:?}"),
        Err(e) => format!("waitpid failed: {e}"),
    };
    Err(Error::CommandFailed {
        command: label(),
        message,
    })
}

/// SIGKILL the child's process group; false when no such group exists.
fn kill_process_group(child: Pid) -> bool {
    // SAFETY: plain integer args.
    unsafe { libc::kill(-child.as_raw(), libc::SIGKILL) == 0 }
}

/// Drains stdout and stderr concurrently so a full pipe never blocks the child.
struct OutputReaders {
    stdout: std::thread::JoinHandle<Vec<u8>>,
    stderr: std::thread::JoinHandle<Vec<u8>>,
}

impl OutputReaders {
    fn spawn(stdout: OwnedFd, stderr: OwnedFd) -> Self {
        Self {
            stdout: std::thread::spawn(move || read_fd_to_end(stdout)),
            stderr: std::thread::spawn(move || read_fd_to_end(stderr)),
        }
    }

    /// Blocks until EOF; kill the writers first.
    fn join(self) -> (Vec<u8>, Vec<u8>) {
        (
            self.stdout.join().unwrap_or_default(),
            self.stderr.join().unwrap_or_default(),
        )
    }
}

fn check_nonempty_command(command: &[&str]) -> Result<()> {
    if command.is_empty() {
        return Err(Error::CommandFailed {
            command: "jexec".to_string(),
            message: "Empty command".to_string(),
        });
    }
    Ok(())
}

fn jexec_fork_error(e: nix::errno::Errno) -> Error {
    Error::CommandFailed {
        command: "jexec".to_string(),
        message: format!("Fork failed: {e}"),
    }
}

fn jexec_pipe(label: &str) -> Result<(OwnedFd, OwnedFd)> {
    pipe().map_err(|e| Error::CommandFailed {
        command: "jexec".to_string(),
        message: format!("Failed to create {label} pipe: {e}"),
    })
}

/// Child side of a piped jexec; own process group so the parent can kill grandchildren.
fn piped_child(pipes: ChildPipes, jid: i32, argv: &ExecArgv) -> ! {
    drop(pipes.stdout_read);
    drop(pipes.stderr_read);
    // SAFETY: plain integer args.
    unsafe {
        libc::setpgid(0, 0);
    }
    redirect_child_io(pipes.stdout_write, pipes.stderr_write);
    attach_and_exec(jid, argv);
}

/// Reaper status is process-wide, so overlapping `chroot_exec` calls share it.
static REAPER_USERS: std::sync::Mutex<usize> = std::sync::Mutex::new(0);

/// Subreaper guard; the last holder releases.
struct Reaper;

impl Reaper {
    // Guard held across procctl so a concurrent Drop cannot release mid-acquire.
    #[allow(clippy::significant_drop_tightening)]
    fn acquire() -> Result<Self> {
        let mut users = REAPER_USERS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *users == 0 {
            // SAFETY: PROC_REAP_ACQUIRE takes no data; NULL is valid.
            let ret = unsafe {
                libc::procctl(
                    libc::P_PID as libc::idtype_t,
                    0, // self
                    libc::PROC_REAP_ACQUIRE,
                    std::ptr::null_mut(),
                )
            };
            if ret != 0 {
                return Err(Error::CommandFailed {
                    command: "chroot".to_string(),
                    message: format!(
                        "procctl(PROC_REAP_ACQUIRE) failed: {}",
                        std::io::Error::last_os_error()
                    ),
                });
            }
        }
        *users += 1;
        Ok(Self)
    }
}

impl Drop for Reaper {
    fn drop(&mut self) {
        let mut users = REAPER_USERS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *users -= 1;
        if *users == 0 {
            // Failure is harmless: we just keep reaping.
            // SAFETY: PROC_REAP_RELEASE takes no data; NULL is valid.
            unsafe {
                libc::procctl(
                    libc::P_PID as libc::idtype_t,
                    0,
                    libc::PROC_REAP_RELEASE,
                    std::ptr::null_mut(),
                );
            }
        }
    }
}

/// struct `procctl_reaper_pidinfo`
#[repr(C)]
#[allow(clippy::struct_field_names)] // mirrors struct procctl_reaper_pidinfo in <sys/procctl.h>
#[derive(Clone, Copy)]
struct ReaperPidInfo {
    pi_pid: libc::pid_t,
    pi_subtree: libc::pid_t,
    pi_flags: libc::c_uint,
    pi_pad0: [libc::c_uint; 15],
}

/// struct `procctl_reaper_pids`
#[repr(C)]
#[allow(clippy::struct_field_names)] // mirrors struct procctl_reaper_pids in <sys/procctl.h>
struct ReaperPids {
    rp_count: libc::c_uint,
    rp_pad0: [libc::c_uint; 15],
    rp_pids: *mut ReaperPidInfo,
}

const _: [(); crate::sys::consts::SIZEOF_PROCCTL_REAPER_PIDINFO] =
    [(); std::mem::size_of::<ReaperPidInfo>()];
const _: [(); crate::sys::consts::SIZEOF_PROCCTL_REAPER_PIDS] =
    [(); std::mem::size_of::<ReaperPids>()];
const _: [(); crate::sys::consts::OFFSETOF_PROCCTL_REAPER_PIDS_RP_PIDS] =
    [(); std::mem::offset_of!(ReaperPids, rp_pids)];

/// SIGKILL everything left in `subtree`, setsid'd included.
fn kill_subtree(subtree: nix::unistd::Pid) {
    #[repr(C)]
    #[allow(clippy::struct_field_names)] // mirrors struct procctl_reaper_kill in <sys/procctl.h>
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
        rk_subtree: subtree.as_raw(),
        rk_killed: 0,
        rk_fpid: 0,
        rk_pad0: [0; 15],
    };
    // ESRCH (nothing left) is expected; the reap loop confirms.
    // SAFETY: rk matches procctl_reaper_kill (size asserted) and outlives the call.
    unsafe {
        libc::procctl(
            libc::P_PID as libc::idtype_t,
            0,
            libc::PROC_REAP_KILL,
            (&raw mut rk).cast::<libc::c_void>(),
        );
    }
}

/// Kill and reap only `subtree`'s orphans; waitpid(-1) would steal unrelated children.
fn reap_subtree(subtree: nix::unistd::Pid) {
    const SLOTS: libc::c_uint = 256;
    const EMPTY: ReaperPidInfo = ReaperPidInfo {
        pi_pid: 0,
        pi_subtree: 0,
        pi_flags: 0,
        pi_pad0: [0; 15],
    };
    let mut infos = vec![EMPTY; SLOTS as usize];
    loop {
        // Every pass: a process may have forked before it died.
        kill_subtree(subtree);
        infos.fill(EMPTY);
        let mut req = ReaperPids {
            rp_count: SLOTS,
            rp_pad0: [0; 15],
            rp_pids: infos.as_mut_ptr(),
        };
        // SAFETY: req matches procctl_reaper_pids (layout asserted); rp_count slots writable.
        let ret = unsafe {
            libc::procctl(
                libc::P_PID as libc::idtype_t,
                0,
                libc::PROC_REAP_GETPIDS,
                (&raw mut req).cast(),
            )
        };
        if ret != 0 {
            return;
        }

        let ours = infos.iter().filter(|info| {
            let flags = info.pi_flags;
            flags & crate::sys::consts::REAPER_PIDINFO_VALID != 0
                && flags & crate::sys::consts::REAPER_PIDINFO_CHILD != 0
                && info.pi_subtree == subtree.as_raw()
        });
        let mut reaped = 0;
        for info in ours {
            // Blocking is fine: everything got SIGKILL.
            let _ = waitpid(nix::unistd::Pid::from_raw(info.pi_pid), None);
            reaped += 1;
        }
        if reaped == 0 {
            return;
        }
    }
}

struct ChildPipes {
    stdout_read: OwnedFd,
    stderr_read: OwnedFd,
    stdout_write: OwnedFd,
    stderr_write: OwnedFd,
}

/// Child-only: dup the write ends onto fd 1/2.
fn redirect_child_io(stdout_write: OwnedFd, stderr_write: OwnedFd) {
    // SAFETY: plain fds from open OwnedFds.
    unsafe {
        libc::dup2(stdout_write.as_raw_fd(), 1);
        libc::dup2(stderr_write.as_raw_fd(), 2);
    }
    drop(stdout_write);
    drop(stderr_write);
}

fn read_fd_to_end(fd: OwnedFd) -> Vec<u8> {
    let mut buffer = Vec::new();
    let mut file = std::fs::File::from(fd);
    // Partial output beats none.
    file.read_to_end(&mut buffer).ok();
    buffer
}

/// Like `jexec_with_output`, but fails with `Error::JailTimeout` after
/// `timeout_secs` (0 = no timeout).
pub fn jexec_with_timeout(
    jid: i32,
    command: &[&str],
    timeout_secs: u64,
) -> Result<(i32, String, String)> {
    check_nonempty_command(command)?;
    let argv = ExecArgv::new(command)?;

    let (stdout_read, stdout_write) = jexec_pipe("stdout")?;
    let (stderr_read, stderr_write) = jexec_pipe("stderr")?;

    // SAFETY: child runs only async-signal-safe syscalls until exec/_exit.
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            drop(stdout_write);
            drop(stderr_write);

            let readers = OutputReaders::spawn(stdout_read, stderr_read);

            let deadline =
                (timeout_secs > 0).then(|| Instant::now() + Duration::from_secs(timeout_secs));

            while crate::proc::wait_exited(child, false) == Ok(false) {
                if deadline.is_some_and(|deadline| Instant::now() > deadline) {
                    if !kill_process_group(child) {
                        // No group yet (child not past setpgid).
                        let _ = nix::sys::signal::kill(child, nix::sys::signal::SIGKILL);
                    }
                    // Status is moot; we report the timeout.
                    let _ = waitpid(child, None);
                    readers.join();
                    return Err(Error::JailTimeout(timeout_secs));
                }
                std::thread::sleep(Duration::from_millis(10));
            }

            kill_process_group(child);
            let status = waitpid(child, None);
            let (stdout, stderr) = readers.join();
            let exit_code = exit_code_of(status, || format!("jexec {jid} {command:?}"))?;
            Ok((
                exit_code,
                crate::sys::string_from_utf8_lossy(stdout),
                crate::sys::string_from_utf8_lossy(stderr),
            ))
        }
        Ok(ForkResult::Child) => piped_child(
            ChildPipes {
                stdout_read,
                stderr_read,
                stdout_write,
                stderr_write,
            },
            jid,
            &argv,
        ),
        Err(e) => Err(jexec_fork_error(e)),
    }
}

/// Run `/bin/sh -c command` chrooted into `root_path`; returns (`exit_code`, stdout, stderr).
pub fn chroot_exec(
    root_path: &str,
    command: &str,
    env_vars: &[(String, String)],
) -> Result<(i32, Vec<u8>, Vec<u8>)> {
    let (stdout_read, stdout_write) = pipe().map_err(|e| Error::CommandFailed {
        command: "chroot".to_string(),
        message: format!("Failed to create stdout pipe: {e}"),
    })?;

    let (stderr_read, stderr_write) = pipe().map_err(|e| Error::CommandFailed {
        command: "chroot".to_string(),
        message: format!("Failed to create stderr pipe: {e}"),
    })?;

    let root_cstring = CString::new(root_path).map_err(|e| Error::CommandFailed {
        command: "chroot".to_string(),
        message: format!("Invalid path: {e}"),
    })?;

    // Built before fork: the child must not allocate.
    let arg_cmd = CString::new(command).map_err(|e| Error::CommandFailed {
        command: "chroot".to_string(),
        message: format!("Invalid command string: {e}"),
    })?;
    let sh_argv: [*const libc::c_char; 4] = [
        c"/bin/sh".as_ptr(),
        c"-c".as_ptr(),
        arg_cmd.as_ptr(),
        std::ptr::null(),
    ];
    let envp = ChildEnv::new(env_vars)?;

    // Subreaper, so RUN can't leave detached processes racing later steps.
    let _reaper = Reaper::acquire()?;

    // SAFETY: child runs only async-signal-safe syscalls until exec/_exit.
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            drop(stdout_write);
            drop(stderr_write);

            let readers = OutputReaders::spawn(stdout_read, stderr_read);

            // Kill the group before reaping, while the zombie pins its pid.
            let _ = crate::proc::wait_exited(child, true);
            kill_process_group(child);
            let wait_result = waitpid(child, None);

            reap_subtree(child);

            let (stdout, stderr) = readers.join();

            exit_code_of(wait_result, || format!("chroot {root_path}"))
                .map(|code| (code, stdout, stderr))
        }
        Ok(ForkResult::Child) => {
            drop(stdout_read);
            drop(stderr_read);

            redirect_child_io(stdout_write, stderr_write);

            // SAFETY: integer arg; the child never returns, so no OwnedFd drop follows.
            unsafe {
                libc::closefrom(3);
            }

            // SAFETY: live NUL-terminated path.
            if unsafe { libc::chroot(root_cstring.as_ptr()) } != 0 {
                child_fail(b"chroot failed", 1);
            }

            // Fatal: a stale cwd is a chroot escape.
            // SAFETY: static NUL-terminated path.
            if unsafe { libc::chdir(c"/".as_ptr()) } != 0 {
                child_fail(b"chdir(\"/\") after chroot failed", 1);
            }

            // SAFETY: plain integer args.
            unsafe {
                libc::setpgid(0, 0);
            }

            // No privilege drop: RUN needs root.
            // SAFETY: NULL-terminated pointer arrays into live CStrings.
            unsafe {
                libc::execve(c"/bin/sh".as_ptr(), sh_argv.as_ptr(), envp.ptrs.as_ptr());
            }

            child_fail(b"execve /bin/sh failed", 127);
        }
        Err(e) => Err(Error::CommandFailed {
            command: "chroot".to_string(),
            message: format!("Fork failed: {e}"),
        }),
    }
}

/// Inherited env with `env_vars` on top (later wins), built before `fork()`.
struct ChildEnv {
    _vars: Vec<CString>,
    /// NULL-terminated pointers into `_vars`.
    ptrs: Vec<*const libc::c_char>,
}

impl ChildEnv {
    fn new(env_vars: &[(String, String)]) -> Result<Self> {
        use std::os::unix::ffi::OsStrExt;

        let invalid = |message: String| Error::CommandFailed {
            command: "chroot".to_string(),
            message,
        };
        let overridden = |key: &[u8]| env_vars.iter().any(|(k, _)| k.as_bytes() == key);

        let mut vars = Vec::new();
        for (key, value) in std::env::vars_os() {
            if overridden(key.as_bytes()) {
                continue;
            }
            let mut entry = key.as_bytes().to_vec();
            entry.push(b'=');
            entry.extend_from_slice(value.as_bytes());
            vars.push(CString::new(entry)?);
        }
        for (i, (key, value)) in env_vars.iter().enumerate() {
            if key.is_empty() || key.contains('=') {
                return Err(invalid(format!(
                    "Invalid environment variable name: {key:?}"
                )));
            }
            if env_vars[i + 1..].iter().any(|(k, _)| k == key) {
                continue;
            }
            let entry = CString::new(format!("{key}={value}"))
                .map_err(|e| invalid(format!("Invalid environment variable {key}: {e}")))?;
            vars.push(entry);
        }

        let mut ptrs: Vec<*const libc::c_char> = vars.iter().map(|v| v.as_ptr()).collect();
        ptrs.push(std::ptr::null());
        Ok(Self { _vars: vars, ptrs })
    }
}

#[cfg(test)]
mod tests;
