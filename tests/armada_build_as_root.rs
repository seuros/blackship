//! Armada auto-builds must survive into the running jail on ZFS; run as root:
//!
//! ```sh
//! sudo env BLACKSHIP_E2E_DATA_DIR=/var/tmp/bw \
//!     BLACKSHIP_E2E_ZFS=zroot/blackship-e2e \
//!     BLACKSHIP_E2E_RELEASE=16.0-CURRENT \
//!     cargo test --test armada_build_as_root -- --ignored --test-threads=1
//! ```

use std::path::PathBuf;
use std::process::{Command, Output};

struct Fixture {
    manifest: PathBuf,
    data_dir: PathBuf,
    dataset: String,
    jail: String,
    _scratch: tempfile::TempDir,
}

impl Fixture {
    fn new(tag: &str) -> Option<Self> {
        if !nix::unistd::geteuid().is_root() {
            eprintln!("skipping: needs root");
            return None;
        }
        let data_dir = PathBuf::from(std::env::var("BLACKSHIP_E2E_DATA_DIR").ok()?);
        let release = std::env::var("BLACKSHIP_E2E_RELEASE").ok()?;
        let zfs = std::env::var("BLACKSHIP_E2E_ZFS").ok()?;
        let (pool, dataset) = zfs.split_once('/')?;
        if !data_dir.join("releases").join(&release).exists() {
            eprintln!("skipping: release {release} is not bootstrapped");
            return None;
        }

        let project = format!("e2e40{tag}{}", std::process::id());
        let scratch = tempfile::tempdir().expect("scratch directory");
        let context = scratch.path().join("ctx");
        std::fs::create_dir(&context).expect("context directory");
        std::fs::write(
            context.join("Jailfile"),
            format!("FROM {release}\nRUN touch /armada-built\n"),
        )
        .expect("write Jailfile");

        let manifest = scratch.path().join("blackship.toml");
        std::fs::write(
            &manifest,
            format!(
                r#"[config]
project = "{project}"
data_dir = "{data}"
releases_dir = "{data}/releases"
cache_dir = "{data}/cache"
zfs_enabled = true
zpool = "{pool}"
dataset = "{dataset}"

[[jails]]
name = "web"
release = "{release}"
build = "{context}"
"#,
                data = data_dir.display(),
                context = context.display(),
            ),
        )
        .expect("write manifest");

        Some(Self {
            manifest,
            data_dir,
            dataset: format!("{pool}/{dataset}/jails/{project}-web"),
            jail: format!("{project}-web"),
            _scratch: scratch,
        })
    }

    fn armada(&self, args: &[&str]) -> Output {
        let output = Command::new(env!("CARGO_BIN_EXE_blackship"))
            .args(["--no-escalate", "--non-interactive", "armada", "-f"])
            .arg(&self.manifest)
            .args(args)
            .output()
            .expect("run blackship");
        assert!(
            output.status.success(),
            "armada {args:?} failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn assert_built_in_running_jail(&self) {
        let root = self.data_dir.join("jails").join(&self.jail);
        assert!(
            root.join("armada-built").exists(),
            "{} is missing from the jail root",
            root.join("armada-built").display()
        );
        let probe = Command::new("/usr/sbin/jexec")
            .args([&self.jail, "/bin/test", "-e", "/armada-built"])
            .status()
            .expect("run jexec");
        assert!(probe.success(), "/armada-built is missing inside the jail");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = Command::new(env!("CARGO_BIN_EXE_blackship"))
            .args(["--no-escalate", "--non-interactive", "armada", "-f"])
            .arg(&self.manifest)
            .arg("down")
            .output();
        let _ = Command::new("/sbin/zfs")
            .args(["destroy", "-r", &self.dataset])
            .output();
        let root = self.data_dir.join("jails").join(&self.jail);
        let _ = Command::new("/bin/chflags")
            .args(["-R", "noschg"])
            .arg(&root)
            .output();
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_file(
            self.data_dir
                .join("audit")
                .join(format!("{}.jsonl", self.jail)),
        );
        for leftover in ["audit", "scope"] {
            let _ = std::fs::remove_dir(self.data_dir.join(leftover));
        }
    }
}

#[test]
#[ignore = "needs root, ZFS and a bootstrapped release"]
fn armada_up_keeps_the_jailfile_output() {
    let Some(f) = Fixture::new("up") else { return };
    f.armada(&["up", "web"]);
    f.assert_built_in_running_jail();
}

#[test]
#[ignore = "needs root, ZFS and a bootstrapped release"]
fn armada_build_then_up_without_build_keeps_the_jailfile_output() {
    let Some(f) = Fixture::new("build") else {
        return;
    };
    f.armada(&["build", "web"]);
    f.armada(&["up", "--no-build", "web"]);
    f.assert_built_in_running_jail();
}
