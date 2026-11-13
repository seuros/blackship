use serde_json::Value;
use std::path::Path;
use std::process::{Command, Output};

fn blackship(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_blackship"))
        .args(["--format", "json", "--no-escalate", "--non-interactive"])
        .args(args)
        .output()
        .expect("run blackship")
}

fn success_json(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "command failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout was not one JSON document: {error}\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn write_manifest(root: &Path) -> std::path::PathBuf {
    let manifest = root.join("blackship.toml");
    let data_dir = root.join("data");
    let jail_path = data_dir.join("jails/json-test-web");
    std::fs::write(
        &manifest,
        format!(
            r#"[config]
project = "json-test"
data_dir = "{}"
zfs_enabled = false

[[jails]]
name = "web"
release = "15.1-RELEASE"
path = "{}"
"#,
            data_dir.display(),
            jail_path.display()
        ),
    )
    .expect("write manifest");
    manifest
}

#[test]
fn armada_init_emits_json_without_progress_on_stdout() {
    let root = tempfile::tempdir().expect("temporary directory");
    let manifest = root.path().join("generated.toml");
    let value = success_json(&blackship(&[
        "armada",
        "init",
        "--file",
        manifest.to_str().expect("UTF-8 path"),
    ]));

    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["action"], "init");
    assert_eq!(value["data"]["created"], true);
    assert!(
        value["data"]["messages"]
            .as_array()
            .is_some_and(|v| !v.is_empty())
    );
    assert!(manifest.exists());
}

#[test]
fn armada_config_emits_resolved_config_as_json() {
    let root = tempfile::tempdir().expect("temporary directory");
    let manifest = write_manifest(root.path());
    let value = success_json(&blackship(&[
        "armada",
        "--file",
        manifest.to_str().expect("UTF-8 path"),
        "config",
        "--show",
    ]));

    assert_eq!(value["data"]["action"], "config");
    assert_eq!(value["data"]["valid"], true);
    assert_eq!(value["data"]["check"]["start_order"][0], "json-test-web");
    assert_eq!(value["data"]["resolved"]["jails"][0]["name"], "web");
}

#[test]
fn armada_dry_runs_keep_progress_inside_json() {
    let root = tempfile::tempdir().expect("temporary directory");
    let manifest = write_manifest(root.path());
    let file = manifest.to_str().expect("UTF-8 path");
    let cases: [(&str, &[&str]); 3] = [
        ("up", &["up", "--no-build", "--dry-run"]),
        ("down", &["down", "--dry-run"]),
        ("build", &["build", "--dry-run"]),
    ];

    for (action, action_args) in cases {
        let mut args = vec!["armada", "--file", file];
        args.extend_from_slice(action_args);
        let value = success_json(&blackship(&args));

        assert_eq!(value["data"]["action"], action);
        assert_eq!(value["data"]["dry_run"], true);
        assert_eq!(value["data"]["jails"][0], "json-test-web");
        let messages = value["data"]["messages"]
            .as_array()
            .expect("messages array");
        assert!(
            messages
                .iter()
                .filter_map(Value::as_str)
                .any(|line| line.contains("DRY RUN")),
            "missing dry-run progress in {value}"
        );
    }
}
