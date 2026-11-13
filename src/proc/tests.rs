use super::*;
use std::time::Instant;

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

/// Regression: `closefrom(3)` made this a SIGABRT child, not `NotFound`.
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

#[test]
fn test_close_dir_fds_drops_directories_and_keeps_files() {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;

    let dir = std::fs::File::open("/").unwrap();
    let file = std::fs::File::open("/dev/null").unwrap();
    let (dir_fd, file_fd) = (dir.as_raw_fd(), file.as_raw_fd());
    // Inheritable: fork copies them whether or not they are close-on-exec.
    for fd in [dir_fd, file_fd] {
        // SAFETY: plain integer args on fds we own.
        unsafe { libc::fcntl(fd, libc::F_SETFD, 0) };
    }

    let mut cmd = Command::new("/usr/bin/true");
    // SAFETY: only async-signal-safe syscalls between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            close_dir_fds();
            let dir_open = libc::fcntl(dir_fd, libc::F_GETFD) != -1;
            let file_open = libc::fcntl(file_fd, libc::F_GETFD) != -1;
            if dir_open || !file_open {
                return Err(io::Error::from_raw_os_error(libc::EBADF));
            }
            Ok(())
        });
    }
    assert!(cmd.status().unwrap().success());
}
