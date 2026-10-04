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
