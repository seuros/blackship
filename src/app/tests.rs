use super::{find_escalator_with, requested_json};
use std::ffi::OsString;

#[test]
fn mdo_is_the_preferred_escalator() {
    let available = ["/usr/bin/mdo", "/usr/local/bin/doas", "/usr/bin/sudo"];

    assert_eq!(
        find_escalator_with(|path| available.contains(&path)),
        Some("/usr/bin/mdo")
    );
}

#[test]
fn doas_is_used_when_mdo_cannot_elevate() {
    let available = ["/usr/local/bin/doas", "/usr/bin/sudo"];

    assert_eq!(
        find_escalator_with(|path| available.contains(&path)),
        Some("/usr/local/bin/doas")
    );
}

#[test]
fn sudo_is_used_when_mdo_and_doas_are_unavailable() {
    assert_eq!(
        find_escalator_with(|path| path == "/usr/bin/sudo"),
        Some("/usr/bin/sudo")
    );
}

#[test]
fn no_escalator_is_reported_when_none_are_usable() {
    assert_eq!(find_escalator_with(|_| false), None);
}

fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

#[test]
fn detects_both_json_option_forms() {
    assert!(requested_json(&args(&["--format", "json", "ps"])));
    assert!(requested_json(&args(&["--format=json", "check"])));
    assert!(requested_json(&args(&[
        "--format", "text", "--format", "json", "ps"
    ])));
}

#[test]
fn ignores_format_words_after_double_dash() {
    assert!(!requested_json(&args(&[
        "exec", "web", "--", "echo", "--format", "json"
    ])));
}
