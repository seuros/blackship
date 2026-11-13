//! Running commands inside a container: `jail_attach(2)` between fork and
//! exec, output multiplexed with poll(2) on the calling thread.

// FFI module: jail_attach(2) in pre_exec, process groups, poll(2).
#![allow(unsafe_code)]

use crate::error::{Error, Result};
use deadline_machines::{Clock, Deadline, SystemClock};
use std::ffi::CString;
use std::fmt;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, ChildStderr, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

/// `PATH` inside the container unless the caller sets one.
const DEFAULT_PATH: &str = "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin";

/// Longest single wait in the supervision loop, so exits are noticed promptly.
const TICK: Duration = Duration::from_millis(50);

/// How long output is still drained after exit, for background holders of the pipes.
const DRAIN_GRACE: Duration = Duration::from_millis(500);

/// Which pipe a chunk of output came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// A streaming output callback.
type Sink<'a> = Box<dyn FnMut(Stream, &[u8]) + 'a>;

enum Output<'a> {
    Capture,
    Stream(Sink<'a>),
    Inherit,
}

enum Limit {
    Timeout(Duration),
    Deadline(Instant),
}

/// A command to run in a container.
///
/// ```
/// use blackship::{Exec, Stream};
/// use std::time::Duration;
///
/// let mut log = Vec::new();
/// let step = Exec::shell("cargo test")
///     .cwd("/work")
///     .env("CARGO_TERM_COLOR", "never")
///     .timeout(Duration::from_secs(600))
///     .on_output(|stream, bytes| {
///         if stream == Stream::Stdout {
///             log.extend_from_slice(bytes);
///         }
///     });
/// # drop(step);
/// ```
///
/// Runs as root with a clean environment and stdin on `/dev/null`.
pub struct Exec<'a> {
    argv: Vec<String>,
    env: Vec<(String, String)>,
    cwd: Option<String>,
    limit: Option<Limit>,
    output: Output<'a>,
}

impl<'a> Exec<'a> {
    /// Run `argv` directly; `argv[0]` is looked up on the container's `PATH`.
    pub fn argv<I, S>(argv: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            argv: argv.into_iter().map(Into::into).collect(),
            env: Vec::new(),
            cwd: None,
            limit: None,
            output: Output::Capture,
        }
    }

    /// Run `script` with `/bin/sh -c`.
    pub fn shell(script: impl Into<String>) -> Self {
        Self::argv(["/bin/sh".to_string(), "-c".to_string(), script.into()])
    }

    /// Set an environment variable.
    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Set several environment variables.
    #[must_use]
    pub fn envs<I, K, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.env
            .extend(vars.into_iter().map(|(k, v)| (k.into(), v.into())));
        self
    }

    /// Working directory inside the container; `/` by default.
    #[must_use]
    pub fn cwd(mut self, dir: impl Into<String>) -> Self {
        self.cwd = Some(dir.into());
        self
    }

    /// Give up after `timeout`, counted from when the command starts.
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.limit = Some(Limit::Timeout(timeout));
        self
    }

    /// Give up at `deadline`, for a budget shared across several commands.
    #[must_use]
    pub const fn deadline(mut self, deadline: Instant) -> Self {
        self.limit = Some(Limit::Deadline(deadline));
        self
    }

    /// Hand output to `sink` as it arrives instead of capturing it.
    #[must_use]
    pub fn on_output(mut self, sink: impl FnMut(Stream, &[u8]) + 'a) -> Self {
        self.output = Output::Stream(Box::new(sink));
        self
    }

    /// Share this process's stdin, stdout and stderr, for interactive use.
    #[must_use]
    pub fn inherit_stdio(mut self) -> Self {
        self.output = Output::Inherit;
        self
    }
}

impl fmt::Debug for Exec<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let output = match self.output {
            Output::Capture => "capture",
            Output::Stream(_) => "stream",
            Output::Inherit => "inherit",
        };
        f.debug_struct("Exec")
            .field("argv", &self.argv)
            .field("env", &self.env)
            .field("cwd", &self.cwd)
            .field("output", &output)
            .finish_non_exhaustive()
    }
}

/// How a command ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// Exited with this status code.
    Code(i32),
    /// Killed by this signal.
    Signal(i32),
    /// Ran past its timeout or deadline; everything in the container was killed.
    TimedOut,
}

impl Exit {
    /// Whether the command exited zero.
    #[must_use]
    pub fn success(self) -> bool {
        self == Self::Code(0)
    }

    /// The exit code, when the command exited on its own.
    #[must_use]
    pub const fn code(self) -> Option<i32> {
        match self {
            Self::Code(code) => Some(code),
            _ => None,
        }
    }
}

/// What a finished command left behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    /// How it ended.
    pub exit: Exit,
    /// Captured stdout; empty when streamed or inherited.
    pub stdout: Vec<u8>,
    /// Captured stderr; empty when streamed or inherited.
    pub stderr: Vec<u8>,
    /// Wall-clock time from start to exit.
    pub duration: Duration,
}

/// Run `exec` inside jail `jid`.
pub fn run(jid: i32, exec: Exec<'_>) -> Result<ExecOutput> {
    let Exec {
        argv,
        env,
        cwd,
        limit,
        mut output,
    } = exec;
    let Some(program) = argv.first() else {
        return Err(Error::InvalidArgument("exec needs a command".into()));
    };
    let cwd = CString::new(cwd.as_deref().unwrap_or("/"))?;
    let inherit = matches!(output, Output::Inherit);

    let mut cmd = Command::new(program);
    cmd.args(&argv[1..])
        .env_clear()
        .env("PATH", DEFAULT_PATH)
        .env("HOME", "/root")
        .env("USER", "root")
        .env("SHELL", "/bin/sh");
    if inherit {
        if let Some(term) = std::env::var_os("TERM") {
            cmd.env("TERM", term);
        }
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
    } else {
        // Own process group so a timeout can kill the whole tree at once.
        cmd.process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
    }
    cmd.envs(env);

    // SAFETY: only async-signal-safe syscalls on memory allocated before fork.
    unsafe {
        cmd.pre_exec(move || {
            crate::proc::close_dir_fds();
            if libc::jail_attach(jid) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::chdir(cwd.as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            crate::proc::harden_fds();
            Ok(())
        });
    }

    let clock = SystemClock::new();
    let started = Instant::now();
    let deadline = match limit {
        None => Deadline::never(),
        Some(Limit::Timeout(timeout)) => Deadline::after(clock.now(), crate::sys::nanos(timeout)),
        Some(Limit::Deadline(at)) => Deadline::after(
            clock.now(),
            crate::sys::nanos(at.saturating_duration_since(started)),
        ),
    };
    let mut child = cmd
        .spawn()
        .map_err(|e| Error::JailExecFailed(format!("cannot run '{program}' in jail {jid}: {e}")))?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let status = if inherit {
        wait(&mut child, jid, &clock, deadline)?
    } else {
        let mut sink = |stream: Stream, bytes: &[u8]| match &mut output {
            Output::Stream(callback) => callback(stream, bytes),
            _ => match stream {
                Stream::Stdout => stdout.extend_from_slice(bytes),
                Stream::Stderr => stderr.extend_from_slice(bytes),
            },
        };
        supervise(&mut child, jid, &clock, deadline, &mut sink)?
    };

    let exit = match status {
        Waited::TimedOut => Exit::TimedOut,
        Waited::Exited(status) => match (status.code(), status.signal()) {
            (Some(code), _) => Exit::Code(code),
            (None, Some(signal)) => Exit::Signal(signal),
            (None, None) => Exit::Code(-1),
        },
    };
    Ok(ExecOutput {
        exit,
        stdout,
        stderr,
        duration: started.elapsed(),
    })
}

enum Waited {
    Exited(std::process::ExitStatus),
    TimedOut,
}

/// Pump both pipes into `sink` until they close, the command exits, or the deadline.
fn supervise(
    child: &mut Child,
    jid: i32,
    clock: &SystemClock,
    deadline: Deadline,
    sink: &mut dyn FnMut(Stream, &[u8]),
) -> Result<Waited> {
    let mut pipes = Pipes {
        stdout: child.stdout.take(),
        stderr: child.stderr.take(),
    };
    let mut exited = None;
    let mut drain = Deadline::never();

    while pipes.any_open() {
        let now = clock.now();
        if exited.is_none() {
            if let Some(status) = child.try_wait()? {
                exited = Some(status);
                drain = Deadline::after(now, crate::sys::nanos(DRAIN_GRACE));
            } else if deadline.is_expired(now) {
                kill_everything(child, || kill_jail_processes(jid));
                return Ok(Waited::TimedOut);
            }
        }
        if drain.is_expired(now) {
            break;
        }

        let budget = if exited.is_none() { deadline } else { drain };
        let wake = budget.clamp_sleep_ns(now, crate::sys::nanos(TICK));
        pipes.pump(Duration::from_nanos(wake), sink)?;
    }
    drop(pipes);

    match exited {
        Some(status) => Ok(Waited::Exited(status)),
        None => wait(child, jid, clock, deadline),
    }
}

/// Wait for the command alone, honouring the deadline.
fn wait(child: &mut Child, jid: i32, clock: &SystemClock, deadline: Deadline) -> Result<Waited> {
    if deadline.expires_at().is_none() {
        return Ok(Waited::Exited(child.wait()?));
    }
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Waited::Exited(status));
        }
        let now = clock.now();
        if deadline.is_expired(now) {
            kill_everything(child, || kill_jail_processes(jid));
            return Ok(Waited::TimedOut);
        }
        let nap = deadline.clamp_sleep_ns(now, crate::sys::nanos(TICK));
        std::thread::sleep(Duration::from_nanos(nap));
    }
}

/// Kill the command's process group and reap the command, then `sweep`
/// the rest of the jail.
///
/// The reap comes first: an unreaped zombie still belongs to the jail, so
/// `pgrep -j` kept finding our own child and the sweep spent its whole
/// retry budget (~1.4 s) on a process only `wait` can remove.
fn kill_everything(child: &mut Child, sweep: impl FnOnce()) {
    // The group goes before the reap, while the zombie pins the pgid.
    if let Ok(pgid) = libc::pid_t::try_from(child.id()) {
        // SAFETY: negative pid signals the command's own process group.
        unsafe { libc::kill(-pgid, libc::SIGKILL) };
    }
    let _ = child.kill(); // usually already dead from the group SIGKILL
    let _ = child.wait(); // reap only; the exit status of a killed child is moot
    sweep();
}

/// SIGKILL everything inside jail `jid`, sweeping until it is empty.
pub fn kill_jail_processes(jid: i32) {
    let jid = jid.to_string();
    for _ in 0..50 {
        // Best-effort; nothing may be left.
        let _ = Command::new("/bin/pkill")
            .args(["-KILL", "-j", &jid])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let survivors = Command::new("/bin/pgrep")
            .args(["-j", &jid])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        // pgrep exits 1 when nothing matched; anything else means look again.
        if survivors.map_or(true, |s| s.code() == Some(1)) {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

struct Pipes {
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
}

impl Pipes {
    const fn any_open(&self) -> bool {
        self.stdout.is_some() || self.stderr.is_some()
    }

    /// Wait up to `wait`, then read one chunk from each ready pipe.
    fn pump(&mut self, wait: Duration, sink: &mut dyn FnMut(Stream, &[u8])) -> Result<()> {
        let mut fds = Vec::with_capacity(2);
        if let Some(out) = &self.stdout {
            fds.push(pollfd(out.as_raw_fd()));
        }
        if let Some(err) = &self.stderr {
            fds.push(pollfd(err.as_raw_fd()));
        }
        let timeout = libc::c_int::try_from(wait.as_millis()).unwrap_or(libc::c_int::MAX);
        let nfds = libc::nfds_t::try_from(fds.len()).unwrap_or(0);
        // SAFETY: `fds` is a live, correctly sized array of pollfd.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), nfds, timeout) };
        if ready < 0 {
            let err = io::Error::last_os_error();
            return if err.kind() == io::ErrorKind::Interrupted {
                Ok(())
            } else {
                Err(err.into())
            };
        }

        let mut buf = [0u8; 16 * 1024];
        for pfd in fds {
            if pfd.revents == 0 {
                continue;
            }
            if self
                .stdout
                .as_ref()
                .is_some_and(|p| p.as_raw_fd() == pfd.fd)
            {
                read_chunk(&mut self.stdout, Stream::Stdout, &mut buf, sink);
            } else {
                read_chunk(&mut self.stderr, Stream::Stderr, &mut buf, sink);
            }
        }
        Ok(())
    }
}

const fn pollfd(fd: libc::c_int) -> libc::pollfd {
    libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }
}

/// One read from a pipe poll(2) marked ready; EOF or an error closes it.
fn read_chunk<R: Read>(
    pipe: &mut Option<R>,
    stream: Stream,
    buf: &mut [u8],
    sink: &mut dyn FnMut(Stream, &[u8]),
) {
    let Some(reader) = pipe else {
        return;
    };
    match reader.read(buf) {
        Ok(0) => *pipe = None,
        Ok(n) => sink(stream, &buf[..n]),
        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
        Err(_) => *pipe = None,
    }
}

#[cfg(test)]
mod tests;
