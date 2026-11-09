use super::*;

/// A host child shaped like the ones `run` spawns, minus `jail_attach`.
fn spawn(script: &str) -> Child {
    Command::new("/bin/sh")
        .args(["-c", script])
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// No jail has this id, so the jail-wide sweep is a no-op.
const NO_JAIL: i32 = 999_999;

#[test]
fn shell_wraps_the_script_in_sh_c() {
    let exec = Exec::shell("echo hi");
    assert_eq!(exec.argv, ["/bin/sh", "-c", "echo hi"]);
}

#[test]
fn exit_reports_success_only_for_zero() {
    assert!(Exit::Code(0).success());
    assert!(!Exit::Code(1).success());
    assert!(!Exit::Signal(9).success());
    assert!(!Exit::TimedOut.success());
    assert_eq!(Exit::Code(3).code(), Some(3));
    assert_eq!(Exit::TimedOut.code(), None);
}

#[test]
fn empty_argv_is_rejected_before_spawning() {
    let empty: [&str; 0] = [];
    match run(NO_JAIL, Exec::argv(empty)) {
        Err(Error::InvalidArgument(_)) => {}
        other => panic!("expected InvalidArgument, got {other:?}"),
    }
}

#[test]
fn supervise_streams_both_pipes_in_order() {
    let mut child = spawn("echo out; echo err >&2; echo out2; exit 3");
    let mut seen: Vec<(Stream, Vec<u8>)> = Vec::new();
    let waited = supervise(&mut child, NO_JAIL, None, &mut |s, b| {
        seen.push((s, b.to_vec()));
    })
    .unwrap();
    let Waited::Exited(status) = waited else {
        panic!("expected an exit");
    };
    assert_eq!(status.code(), Some(3));
    let stdout: Vec<u8> = seen
        .iter()
        .filter(|(s, _)| *s == Stream::Stdout)
        .flat_map(|(_, b)| b.clone())
        .collect();
    let stderr: Vec<u8> = seen
        .iter()
        .filter(|(s, _)| *s == Stream::Stderr)
        .flat_map(|(_, b)| b.clone())
        .collect();
    assert_eq!(stdout, b"out\nout2\n");
    assert_eq!(stderr, b"err\n");
}

#[test]
fn supervise_times_out_and_kills_the_group() {
    let mut child = spawn("echo started; sleep 30 & sleep 30");
    let started = Instant::now();
    let mut out = Vec::new();
    let waited = supervise(
        &mut child,
        NO_JAIL,
        Some(Instant::now() + Duration::from_millis(300)),
        &mut |_, b| out.extend_from_slice(b),
    )
    .unwrap();
    let Waited::TimedOut = waited else {
        panic!("expected a timeout");
    };
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(out, b"started\n");
}

#[test]
fn a_background_process_holding_the_pipe_does_not_hang_supervise() {
    // The shell exits at once; its child keeps stdout open for 30s.
    let mut child = spawn("sleep 30 & echo done");
    let started = Instant::now();
    let waited = supervise(&mut child, NO_JAIL, None, &mut |_, _| {}).unwrap();
    let Waited::Exited(status) = waited else {
        panic!("expected an exit");
    };
    assert!(status.success());
    assert!(started.elapsed() < Duration::from_secs(5));
    let _ = nix::sys::signal::killpg(
        nix::unistd::Pid::from_raw(child.id() as libc::pid_t),
        nix::sys::signal::SIGKILL,
    );
}

#[test]
fn the_command_is_reaped_before_the_jail_sweep() {
    let mut child = spawn("sleep 30");
    let pid = nix::unistd::Pid::from_raw(libc::pid_t::try_from(child.id()).unwrap());
    let mut still_there = None;
    kill_everything(&mut child, || {
        // A zombie still answers kill(pid, 0); a reaped child is ESRCH.
        still_there = Some(nix::sys::signal::kill(pid, None).is_ok());
    });
    assert_eq!(
        still_there,
        Some(false),
        "the sweep ran while our own child was unreaped"
    );
}
