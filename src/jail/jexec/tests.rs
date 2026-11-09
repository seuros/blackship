use super::*;

#[test]
#[ignore = "requires root"]
fn test_jexec_basic() {
    let name = format!("bs-jexec-{}", std::process::id());
    let out = std::process::Command::new("/usr/sbin/jail")
        .args(["-i", "-c", &format!("name={name}"), "path=/", "persist"])
        .output()
        .unwrap();
    assert!(out.status.success(), "jail -c failed: {out:?}");
    let jid: i32 = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap();

    let result = jexec_with_output(jid, &["echo", "hello"]);
    let removed = std::process::Command::new("/usr/sbin/jail")
        .args(["-r", &name])
        .status()
        .unwrap();

    let (exit_code, stdout, _stderr) = result.unwrap();
    assert_eq!(exit_code, 0);
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "hello");
    assert!(removed.success());
}

/// Count of processes whose command line contains `needle`.
fn running(needle: &str) -> usize {
    let out = std::process::Command::new("/bin/pgrep")
        .args(["-f", needle])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).lines().count()
}

#[test]
#[ignore = "needs root (chroot and procctl reaper)"]
fn chroot_exec_reaps_only_its_own_orphans() {
    // Unrelated zombie that chroot_exec must not reap.
    let bystander = std::process::Command::new("/bin/sh")
        .args(["-c", "exit 7"])
        .spawn()
        .unwrap();

    // daemon(8) detaches: only the reaper can find it.
    let marker = format!("sleep 31{}", std::process::id() % 1000);
    let (code, _, _) = chroot_exec(
        "/",
        &format!("/usr/sbin/daemon -f /bin/{marker}; sleep 0.3; exit 3"),
        &[],
    )
    .unwrap();
    assert_eq!(code, 3);
    assert_eq!(running(&marker), 0, "detached orphan survived the RUN step");

    let status = { bystander }.wait().expect("bystander's status was stolen");
    assert_eq!(status.code(), Some(7));
}

#[test]
#[ignore = "needs root (chroot and procctl reaper)"]
fn overlapping_chroot_execs_keep_reaping() {
    // The short call's release must not strip reaper status from the long one.
    let marker = format!("sleep 32{}", std::process::id() % 1000);
    let long = {
        let marker = marker.clone();
        std::thread::spawn(move || {
            chroot_exec(
                "/",
                &format!("sleep 0.5; /usr/sbin/daemon -f /bin/{marker}; sleep 0.3; exit 0"),
                &[],
            )
        })
    };
    std::thread::sleep(std::time::Duration::from_millis(100));
    let (short_code, _, _) = chroot_exec("/", "exit 0", &[]).unwrap();
    assert_eq!(short_code, 0);

    let (long_code, _, _) = long.join().unwrap().unwrap();
    assert_eq!(long_code, 0);
    assert_eq!(
        running(&marker),
        0,
        "orphan escaped after the reaper was dropped"
    );
}
