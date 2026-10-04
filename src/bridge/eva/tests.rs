use super::*;
use std::net::Ipv4Addr;

#[test]
fn test_param_value_matches_int() {
    assert!(param_value_matches(&ParamValue::Int(5), "5"));
    assert!(param_value_matches(&ParamValue::Int(5), " 5 "));
    assert!(!param_value_matches(&ParamValue::Int(5), "6"));
    assert!(!param_value_matches(&ParamValue::Int(5), "new"));
}

#[test]
fn test_param_value_matches_bool() {
    assert!(param_value_matches(&ParamValue::Bool(true), "true"));
    assert!(param_value_matches(&ParamValue::Bool(true), "1"));
    assert!(param_value_matches(&ParamValue::Bool(false), "false"));
    assert!(param_value_matches(&ParamValue::Bool(false), "0"));
    assert!(!param_value_matches(&ParamValue::Bool(true), "false"));
    assert!(!param_value_matches(&ParamValue::Bool(true), "yes"));
}

#[test]
fn test_param_value_matches_ipv4() {
    let v = ParamValue::Ipv4(vec![Ipv4Addr::new(10, 0, 0, 5)]);
    assert!(param_value_matches(&v, "10.0.0.5"));
    assert!(!param_value_matches(&v, "10.0.0.6"));
    assert!(!param_value_matches(&v, "10.0.0.5,10.0.0.6"));
}

#[test]
fn test_diff_params_change_and_skip() {
    let mut desired = HashMap::new();
    desired.insert("name".to_string(), ParamValue::String("web".into()));
    desired.insert(
        "host.hostname".to_string(),
        ParamValue::String("new.example".into()),
    );
    desired.insert("children.max".to_string(), ParamValue::Int(4));

    let mut live = HashMap::new();
    live.insert("host.hostname".to_string(), "old.example".to_string());
    live.insert("children.max".to_string(), "4".to_string());

    let diff = diff_params(&desired, &live, &[]);
    assert_eq!(diff.changes.len(), 1);
    assert!(diff.changes.contains_key("host.hostname"));
    assert_eq!(
        diff.display,
        vec!["host.hostname: old.example -> new.example"]
    );
    assert!(diff.immutable_diffs.is_empty());
}

#[test]
fn test_diff_params_immutable_drift() {
    let mut desired = HashMap::new();
    desired.insert("vnet".to_string(), ParamValue::Int(1));

    let mut live = HashMap::new();
    live.insert("vnet".to_string(), "0".to_string());

    let diff = diff_params(&desired, &live, &[]);
    assert!(diff.changes.is_empty());
    assert_eq!(diff.immutable_diffs, vec!["vnet: 0 -> 1"]);
}

#[test]
fn test_diff_params_unreadable_applied_blind() {
    let mut desired = HashMap::new();
    desired.insert("sysvmsg".to_string(), ParamValue::Int(1));

    let diff = diff_params(&desired, &HashMap::new(), &["sysvmsg".to_string()]);
    assert_eq!(diff.changes.len(), 1);
    assert_eq!(diff.display, vec!["sysvmsg: (unverified) -> 1"]);
}

#[test]
fn test_diff_params_idempotent() {
    let mut desired = HashMap::new();
    desired.insert(
        "host.hostname".to_string(),
        ParamValue::String("same".into()),
    );
    let mut live = HashMap::new();
    live.insert("host.hostname".to_string(), "same".to_string());

    let diff = diff_params(&desired, &live, &[]);
    assert!(diff.changes.is_empty());
    assert!(diff.display.is_empty());
    assert!(diff.immutable_diffs.is_empty());
}
