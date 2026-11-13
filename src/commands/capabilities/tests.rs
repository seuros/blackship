use super::*;
use std::collections::HashSet;

#[test]
fn report_is_manifestless_and_machine_serializable() {
    let report = data().unwrap();
    let value = serde_json::to_value(report).unwrap();

    assert_eq!(value["output_schema_version"], SCHEMA_VERSION);
    assert_eq!(value["platform"]["os"], "freebsd");
    assert_eq!(
        value["cli"]["output_formats"],
        serde_json::json!(["text", "json"])
    );
    assert!(value["cli"]["machine_output"].is_array());
    assert!(value["facilities"].is_array());
    assert!(value["privilege_escalators"].is_array());
}

#[test]
fn command_capabilities_have_unique_stable_ids() {
    let report = cli_capabilities().unwrap();
    let mut operations = HashSet::new();

    for capability in &report.machine_output {
        assert!(operations.insert(capability.operation));
        assert_ne!(capability.invocation, "");
    }

    for expected in [
        "capabilities",
        "host",
        "ps.host",
        "network.list",
        "armada.ps",
        "armada.config",
        "autostart.dry_run",
        "up.dry_run",
    ] {
        assert!(operations.contains(expected), "missing {expected}");
    }
}

#[test]
fn command_capabilities_report_privilege_and_effect_for_exact_mode() {
    let report = cli_capabilities().unwrap();
    let capability = |operation| {
        report
            .machine_output
            .iter()
            .find(|candidate| candidate.operation == operation)
            .unwrap()
    };

    assert!(!capability("up.dry_run").requires_root);
    assert!(!capability("up.dry_run").mutates);
    assert!(capability("health").requires_root);
    assert!(!capability("health").mutates);
}

/// Every invocation the CLI could plausibly offer a JSON mode for. A new mode with a
/// JSON contract must appear here and in `OPERATION_SPECS`, or the next test fails.
const CANDIDATES: &[&[&str]] = &[
    &["capabilities"],
    &["host"],
    &["ps"],
    &["ps", "--host"],
    &["check"],
    &["ports"],
    &["network", "list"],
    &["releases", "list"],
    &["stats"],
    &["health"],
    &["health", "--watch"],
    &["audit", "jail"],
    &["snapshot", "list", "jail"],
    &["up", "--all"],
    &["up", "--all", "--dry-run"],
    &["down", "--all"],
    &["down", "--all", "--dry-run"],
    &["restart", "--all"],
    &["restart", "--all", "--dry-run"],
    &["eva", "--all"],
    &["eva", "--all", "--dry-run"],
    &["autostart"],
    &["autostart", "--dry-run"],
    &["armada", "init"],
    &["armada", "config"],
    &["armada", "ps"],
    &["armada", "up"],
    &["armada", "up", "--dry-run"],
    &["armada", "down"],
    &["armada", "down", "--dry-run"],
    &["armada", "build"],
    &["armada", "build", "--dry-run"],
    &["gc", "--dry-run"],
    &["supervise"],
    &["migrate", "jail", "root@host"],
];

#[test]
fn every_json_capable_mode_has_a_row_and_every_row_is_json_capable() {
    let rows: HashSet<Vec<&str>> = OPERATION_SPECS
        .iter()
        .map(|spec| spec.args.to_vec())
        .collect();

    for args in CANDIDATES {
        let owned: Vec<std::ffi::OsString> = args.iter().map(Into::into).collect();
        let refs: Vec<&OsStr> = owned.iter().map(std::ffi::OsString::as_os_str).collect();
        let cli = Cli::parse_from(&refs).unwrap_or_else(|e| panic!("{args:?} must parse: {e:?}"));
        assert_eq!(
            cli.command.supports_machine_output(),
            rows.contains(&args.to_vec()),
            "{args:?}: machine output and capability row disagree"
        );
    }
    for row in OPERATION_SPECS {
        assert!(
            CANDIDATES.contains(&row.args),
            "{}: add its arguments to CANDIDATES",
            row.operation
        );
    }
}

#[test]
fn the_table_builds_without_depending_on_the_kernel() {
    let report = cli_capabilities().unwrap();
    assert_eq!(report.machine_output.len(), OPERATION_SPECS.len());
}

#[test]
fn effect_comes_from_the_command_itself() {
    let report = cli_capabilities().unwrap();
    let effect = |operation: &str| {
        report
            .machine_output
            .iter()
            .find(|c| c.operation == operation)
            .unwrap()
            .mutates
    };
    assert!(effect("armada.init"));
    assert!(effect("armada.up"));
    assert!(!effect("armada.up.dry_run"));
    assert!(!effect("autostart.dry_run"));
    assert!(!effect("ps.host"));
}
