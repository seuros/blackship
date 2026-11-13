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
    let report = data().unwrap();
    let mut operations = HashSet::new();

    for capability in &report.cli.machine_output {
        assert!(operations.insert(capability.operation));
        assert_ne!(capability.invocation, "");
    }

    for expected in [
        "capabilities",
        "host",
        "ps.host",
        "network.list",
        "armada.ps",
        "up.dry_run",
    ] {
        assert!(operations.contains(expected), "missing {expected}");
    }
}

#[test]
fn command_capabilities_report_privilege_and_effect_for_exact_mode() {
    let report = data().unwrap();
    let capability = |operation| {
        report
            .cli
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
