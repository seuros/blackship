//! End-to-end checks against a real host; run as root with a bootstrapped release:
//!
//! ```sh
//! sudo env BLACKSHIP_E2E_DATA_DIR=/var/tmp/bw \
//!     BLACKSHIP_E2E_ZFS=zroot/blackship-e2e \
//!     BLACKSHIP_E2E_RELEASE=16.0-CURRENT \
//!     cargo test --test containers_as_root -- --ignored --test-threads=1
//! ```

use blackship::{
    Build, ContainerSpec, Error, Exec, Exit, Host, Limits, Mount, Network, Selector, Stream,
};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

struct Setup {
    host: Host,
    release: String,
    data_dir: PathBuf,
}

fn setup() -> Option<Setup> {
    if !nix::unistd::geteuid().is_root() {
        eprintln!("skipping: needs root");
        return None;
    }
    let data_dir = PathBuf::from(std::env::var("BLACKSHIP_E2E_DATA_DIR").ok()?);
    let release = std::env::var("BLACKSHIP_E2E_RELEASE").ok()?;
    let mut host = Host::new(&data_dir);
    if let Some((pool, dataset)) = std::env::var("BLACKSHIP_E2E_ZFS").ok().and_then(|v| {
        v.split_once('/')
            .map(|(p, d)| (p.to_string(), d.to_string()))
    }) {
        host = host.with_zfs(pool, dataset);
    }
    host.release(&release).ok()??;
    Some(Setup {
        host,
        release,
        data_dir,
    })
}

fn name(tag: &str) -> String {
    format!("e2e-{tag}-{}", std::process::id())
}

fn jail_processes(jid: i32) -> usize {
    let out = Command::new("/bin/pgrep")
        .args(["-j", &jid.to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).lines().count()
}

#[test]
#[ignore = "needs root and a bootstrapped release"]
fn exec_streams_sets_env_and_cwd() {
    let Some(s) = setup() else { return };
    let c = s
        .host
        .create(&ContainerSpec::new(name("exec"), &s.release))
        .unwrap();

    let captured = c
        .exec(
            Exec::shell("pwd; echo \"$GREETING\"; echo oops >&2; exit 7")
                .cwd("/tmp")
                .env("GREETING", "ahoy"),
        )
        .unwrap();
    assert_eq!(captured.exit, Exit::Code(7));
    assert_eq!(captured.stdout, b"/tmp\nahoy\n");
    assert_eq!(captured.stderr, b"oops\n");

    let mut chunks = Vec::new();
    let streamed = c
        .exec(Exec::argv(["echo", "streamed"]).on_output(|s, b| chunks.push((s, b.to_vec()))))
        .unwrap();
    assert!(streamed.exit.success());
    assert_eq!(streamed.stdout, b"");
    assert_eq!(chunks, [(Stream::Stdout, b"streamed\n".to_vec())]);

    match c.exec(Exec::argv(["/no/such/binary"])) {
        Err(Error::JailExecFailed(_)) => {}
        other => panic!("expected JailExecFailed, got {other:?}"),
    }
    c.destroy().unwrap();
}

#[test]
#[ignore = "needs root and a bootstrapped release"]
fn timeout_kills_everything_in_the_jail() {
    let Some(s) = setup() else { return };
    let c = s
        .host
        .create(&ContainerSpec::new(name("timeout"), &s.release))
        .unwrap();

    // A daemonized straggler outside the command's process group.
    let daemon = c
        .exec(Exec::shell("daemon -f sleep 600; echo spawned"))
        .unwrap();
    assert!(daemon.exit.success());
    assert!(jail_processes(c.jid()) >= 1);

    let started = Instant::now();
    let out = c
        .exec(Exec::shell("echo before; sleep 600 & sleep 600").timeout(Duration::from_secs(1)))
        .unwrap();
    assert_eq!(out.exit, Exit::TimedOut);
    assert_eq!(out.stdout, b"before\n");
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(jail_processes(c.jid()), 0, "processes survived the timeout");

    // The container itself is still usable.
    let after = c
        .exec(Exec::argv(["echo", "still here"]).deadline(Instant::now() + Duration::from_secs(5)))
        .unwrap();
    assert_eq!(after.stdout, b"still here\n");
    c.destroy().unwrap();
}

#[test]
#[ignore = "needs root and a bootstrapped release"]
fn deadlines_are_kept_to_the_tick() {
    let Some(s) = setup() else { return };
    let c = s
        .host
        .create(&ContainerSpec::new(name("deadline"), &s.release))
        .unwrap();
    let budget = Duration::from_millis(1500);
    for exec in [
        Exec::argv(["sleep", "600"]).timeout(budget),
        Exec::argv(["sleep", "600"]).timeout(budget).inherit_stdio(),
    ] {
        let out = c.exec(exec).unwrap();
        assert_eq!(out.exit, Exit::TimedOut);
        // The kill and reap take a few ticks; a sweep that waits on our own
        // zombie used to add ~1.4 s on top.
        assert!(
            out.duration < budget + Duration::from_millis(500),
            "a {budget:?} deadline ended after {:?}",
            out.duration
        );
    }
    c.destroy().unwrap();
}

#[test]
#[ignore = "needs root and a bootstrapped release"]
fn nullfs_mounts_respect_modes_and_survive_teardown() {
    let Some(s) = setup() else { return };
    let src = s.data_dir.join(format!("mount-src-{}", std::process::id()));
    let out = s.data_dir.join(format!("mount-out-{}", std::process::id()));
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(src.join("input"), "from host\n").unwrap();

    let c = s
        .host
        .create(
            &ContainerSpec::new(name("mounts"), &s.release)
                .mount(Mount::read_only(&src, "/src"))
                .mount(Mount::read_write(&out, "/work/out")),
        )
        .unwrap();
    let read = c.exec(Exec::argv(["cat", "/src/input"])).unwrap();
    assert_eq!(read.stdout, b"from host\n");
    let denied = c.exec(Exec::shell("touch /src/nope")).unwrap();
    assert!(!denied.exit.success(), "read-only mount was writable");
    let wrote = c
        .exec(Exec::shell("echo from jail > /work/out/result"))
        .unwrap();
    assert!(wrote.exit.success());

    c.destroy().unwrap();
    // Teardown unmounted before destroying: host data is untouched.
    assert_eq!(
        std::fs::read_to_string(src.join("input")).unwrap(),
        "from host\n"
    );
    assert_eq!(
        std::fs::read_to_string(out.join("result")).unwrap(),
        "from jail\n"
    );
    std::fs::remove_dir_all(&src).unwrap();
    std::fs::remove_dir_all(&out).unwrap();
}

/// The options mount(8) lists for the filesystem mounted at `path`:
/// `nullfs`, `local`, `read-only`, `nosuid`, `noexec`, ...
fn mount_options(path: &std::path::Path) -> Vec<String> {
    let path = path.canonicalize().unwrap();
    let suffix = format!(" on {} (", path.display());
    let out = Command::new("/sbin/mount").output().unwrap();
    let table = String::from_utf8(out.stdout).unwrap();
    let line = table
        .lines()
        .find(|l| l.contains(&suffix))
        .unwrap_or_else(|| panic!("{} is not mounted", path.display()));
    let (_, options) = line.split_once(&suffix).unwrap();
    options
        .trim_end_matches(')')
        .split(", ")
        .map(str::to_string)
        .collect()
}

#[test]
#[ignore = "needs root and a bootstrapped release"]
fn mounts_carry_nosuid_and_noexec() {
    let Some(s) = setup() else { return };
    let pid = std::process::id();
    let dirs: Vec<PathBuf> = ["plain", "exec", "suid"]
        .iter()
        .map(|tag| s.data_dir.join(format!("mount-{tag}-{pid}")))
        .collect();
    for dir in &dirs {
        std::fs::create_dir_all(dir).unwrap();
    }

    let c = s
        .host
        .create(
            &ContainerSpec::new(name("mountopts"), &s.release)
                .mount(Mount::read_write(&dirs[0], "/work"))
                .mount(Mount::read_write(&dirs[1], "/noexec").noexec())
                .mount(Mount::read_write(&dirs[2], "/suid").allow_setuid())
                .mount(Mount::read_only(&dirs[0], "/ro").nosuid().noexec()),
        )
        .unwrap();
    let has = |dir: &str, option: &str| {
        mount_options(&c.root().join(dir))
            .iter()
            .any(|o| o == option)
    };
    assert!(has("work", "nosuid"), "rw mount is not nosuid");
    assert!(!has("work", "read-only") && !has("work", "noexec"));
    assert!(has("noexec", "noexec") && has("noexec", "nosuid"));
    assert!(!has("suid", "nosuid"));
    // mount_nullfs(8) drops a comma-joined option list, read-only included.
    assert!(has("ro", "read-only") && has("ro", "nosuid") && has("ro", "noexec"));

    // noexec is enforced inside the container, not just recorded.
    let ran = c
        .exec(Exec::shell(
            "cp /bin/echo /noexec/echo && /noexec/echo nope; \
             cp /bin/echo /work/echo && /work/echo yes",
        ))
        .unwrap();
    assert_eq!(ran.stdout, b"yes\n");
    assert!(
        String::from_utf8_lossy(&ran.stderr).contains("Permission denied"),
        "noexec mount ran a binary: {:?}",
        String::from_utf8_lossy(&ran.stderr)
    );

    // A setuid program written through the nosuid mount does not elevate;
    // the same program through the opted-out mount does.
    let euid = |dir: &str| {
        let out = c
            .exec(Exec::shell(format!(
                "cp /usr/bin/id {dir}/id && chmod 4755 {dir}/id && \
                 su -m nobody -c '{dir}/id -u'"
            )))
            .unwrap();
        assert!(
            out.exit.success(),
            "{:?}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };
    assert_eq!(euid("/work"), "65534\n");
    assert_eq!(euid("/suid"), "0\n");

    c.destroy().unwrap();
    for dir in dirs {
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
#[ignore = "needs root and a bootstrapped release"]
fn copy_in_and_out_round_trip() {
    let Some(s) = setup() else { return };
    let c = s
        .host
        .create(&ContainerSpec::new(name("copy"), &s.release))
        .unwrap();
    let host_file = s.data_dir.join(format!("copy-{}", std::process::id()));
    std::fs::write(&host_file, "payload\n").unwrap();
    c.copy_in(&host_file, "/tmp/payload").unwrap();
    let seen = c.exec(Exec::argv(["cat", "/tmp/payload"])).unwrap();
    assert_eq!(seen.stdout, b"payload\n");
    let back = host_file.with_extension("back");
    c.copy_out("/tmp/payload", &back).unwrap();
    assert_eq!(std::fs::read_to_string(&back).unwrap(), "payload\n");
    std::fs::remove_file(host_file).unwrap();
    std::fs::remove_file(back).unwrap();
    c.destroy().unwrap();
}

#[test]
#[ignore = "needs root and a bootstrapped release"]
fn destroy_is_idempotent_and_orphans_get_reaped() {
    let Some(s) = setup() else { return };
    s.host.destroy_container(&name("never-existed")).unwrap();

    let orphan_name = name("orphan");
    let c = s
        .host
        .create(
            &ContainerSpec::new(&orphan_name, &s.release)
                .label("suite", "e2e")
                .boot(),
        )
        .unwrap();
    let jid = c.jid();
    // Simulate a crash: no destructor, and the recorded owner is gone.
    std::mem::forget(c);
    let record = s
        .data_dir
        .join("container-state")
        .join(format!("{orphan_name}.toml"));
    let text = std::fs::read_to_string(&record).unwrap();
    let rewritten: String = text
        .lines()
        .map(|l| {
            if l.starts_with("owner_pid") {
                "owner_pid = 99999".to_string()
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&record, rewritten).unwrap();

    let kept_name = name("kept");
    let mut kept = s
        .host
        .create(&ContainerSpec::new(&kept_name, &s.release).label("suite", "e2e"))
        .unwrap();
    kept.keep().unwrap();
    drop(kept);

    let selector = Selector::prefix("e2e-").and_label("suite", "e2e");
    let orphans: Vec<String> = s
        .host
        .orphans(&selector)
        .unwrap()
        .into_iter()
        .map(|o| o.name)
        .collect();
    assert_eq!(orphans, std::slice::from_ref(&orphan_name));
    assert_eq!(
        s.host.reap_orphans(&selector).unwrap(),
        std::slice::from_ref(&orphan_name)
    );
    assert_eq!(jail_processes(jid), 0);
    assert!(
        !s.host
            .containers()
            .unwrap()
            .iter()
            .any(|c| c.name == orphan_name)
    );

    // The kept one survived its handle and the reap, and can be reopened.
    let reopened = s.host.open(&kept_name).unwrap();
    assert!(reopened.exec(Exec::argv(["true"])).unwrap().exit.success());
    drop(reopened);
    s.host.destroy_container(&kept_name).unwrap();
    s.host.destroy_container(&kept_name).unwrap();
}

#[test]
#[ignore = "needs root and a bootstrapped release"]
fn containers_run_concurrently() {
    let Some(s) = setup() else { return };
    // Collecting spawns all four before joining any; lazy would serialize them.
    #[allow(clippy::needless_collect)]
    let handles: Vec<_> = (0..4)
        .map(|i| {
            let host = s.host.clone();
            let release = s.release.clone();
            std::thread::spawn(move || {
                let c = host
                    .create(
                        &ContainerSpec::new(name(&format!("par{i}")), release)
                            .network(Network::Inherit),
                    )
                    .unwrap();
                let out = c.exec(Exec::shell("hostname")).unwrap();
                let hostname = String::from_utf8(out.stdout).unwrap();
                c.destroy().unwrap();
                hostname
            })
        })
        .collect();
    let mut hostnames: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    hostnames.sort();
    hostnames.dedup();
    assert_eq!(hostnames.len(), 4);
}

#[test]
#[ignore = "needs root and a bootstrapped release"]
fn same_name_twice_is_refused_without_harming_the_first() {
    let Some(s) = setup() else { return };
    let n = name("dup");
    let first = s.host.create(&ContainerSpec::new(&n, &s.release)).unwrap();
    match s.host.create(&ContainerSpec::new(&n, &s.release)) {
        Err(Error::JailExists(_)) => {}
        other => panic!("expected JailExists, got {other:?}"),
    }
    assert!(first.exec(Exec::argv(["true"])).unwrap().exit.success());
    first.destroy().unwrap();
}

#[test]
#[ignore = "needs root and a bootstrapped release"]
fn limits_apply_or_fail_cleanly() {
    let Some(s) = setup() else { return };
    let racct = Command::new("/sbin/sysctl")
        .args(["-n", "kern.racct.enable"])
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "1");
    let n = name("limits");
    let made = s.host.create(
        &ContainerSpec::new(&n, &s.release).limits(Limits::new().memory("256m").max_processes(64)),
    );
    if racct {
        let c = made.unwrap();
        let rules = Command::new("/usr/bin/rctl")
            .arg(format!("jail:{n}"))
            .output()
            .unwrap();
        let rules = String::from_utf8_lossy(&rules.stdout);
        assert!(rules.contains("memoryuse:deny=268435456"), "{rules}");
        assert!(rules.contains("maxproc:deny=64"), "{rules}");
        c.destroy().unwrap();
    } else {
        match made {
            Err(Error::Rctl(_)) => {}
            other => panic!("expected Rctl, got {other:?}"),
        }
        assert!(!s.host.containers().unwrap().iter().any(|c| c.name == n));
    }
}

#[test]
#[ignore = "needs root, ZFS and a bootstrapped release"]
fn build_commit_and_clone_an_image() {
    let Some(s) = setup() else { return };
    if !s.host.uses_zfs() {
        return;
    }
    let pid = std::process::id();
    let dir = s.data_dir.join(format!("image-ctx-{pid}"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("Jailfile"),
        format!(
            "FROM {}\nARG FLAVOUR=plain\nRUN echo $FLAVOUR > /etc/e2e-flavour\n",
            s.release
        ),
    )
    .unwrap();

    let image = s
        .host
        .build(
            &Build::jailfile(dir.join("Jailfile"))
                .name(format!("e2e-img-{pid}"))
                .arg("FLAVOUR", "salty"),
        )
        .unwrap();
    let release = s
        .host
        .commit_image(&image, &format!("e2e-rel-{pid}"))
        .unwrap();
    assert!(release.cloneable);

    let c = s
        .host
        .create(&ContainerSpec::new(name("from-image"), &release.name))
        .unwrap();
    let flavour = c.exec(Exec::argv(["cat", "/etc/e2e-flavour"])).unwrap();
    assert_eq!(flavour.stdout, b"salty\n");

    // Commit a container too, and clone that.
    c.exec(Exec::shell("echo committed > /etc/e2e-commit"))
        .unwrap();
    let committed = c.commit(&format!("e2e-commit-{pid}")).unwrap();
    c.destroy().unwrap();
    let c2 = s
        .host
        .create(&ContainerSpec::new(name("from-commit"), &committed.name))
        .unwrap();
    let marker = c2.exec(Exec::argv(["cat", "/etc/e2e-commit"])).unwrap();
    assert_eq!(marker.stdout, b"committed\n");
    c2.destroy().unwrap();

    // A release still cloned by something refuses to go.
    match s.host.remove_release(&release.name) {
        Err(Error::Zfs(_)) => {}
        other => panic!("expected Zfs refusal, got {other:?}"),
    }
    s.host.remove_release(&committed.name).unwrap();
    s.host.remove_image(&image.name).unwrap();
    s.host.remove_release(&release.name).unwrap();
    s.host.remove_release(&release.name).unwrap();
    assert!(!s.host.has_release(&release.name).unwrap());
    std::fs::remove_dir_all(dir).unwrap();
}
