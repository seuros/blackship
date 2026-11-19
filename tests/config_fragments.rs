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

fn write_fragments(root: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let project = root.join("project.toml");
    let database = root.join("database.toml");
    let data_dir = root.join("data");
    std::fs::write(
        &project,
        format!(
            r#"[config]
project = "fragment-test"
data_dir = "{}"
zfs_enabled = false

[[jails]]
name = "web"
release = "15.1-RELEASE"
depends_on = ["database"]
"#,
            data_dir.display()
        ),
    )
    .expect("write project manifest");
    std::fs::write(
        &database,
        r#"[[jails]]
name = "database"
release = "15.1-RELEASE"

[jails.params]
sysvmsg = "new"
sysvsem = "new"
sysvshm = "new"
"#,
    )
    .expect("write database manifest");
    (project, database)
}

#[test]
fn repeated_global_configs_drive_top_level_commands() {
    let root = tempfile::tempdir().expect("temporary directory");
    let (project, database) = write_fragments(root.path());
    let project = project.to_str().expect("UTF-8 project path");
    let database = database.to_str().expect("UTF-8 database path");
    let value = success_json(&blackship(&[
        "--config", project, "--config", database, "check",
    ]));

    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["ok"], true);
    assert_eq!(
        value["data"]["start_order"],
        serde_json::json!(["fragment-test-database", "fragment-test-web"])
    );

    let value = success_json(&blackship(&[
        "--config",
        project,
        "--config",
        database,
        "eva",
        "database",
        "--dry-run",
    ]));
    assert_eq!(value["data"]["operation"], "eva");
    assert_eq!(value["data"]["dry_run"], true);
}
