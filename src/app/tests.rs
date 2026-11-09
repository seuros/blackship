use super::{MDO, escalation_command, find_escalator_with, requested_json, should_escalate};
use crate::error::Error;
use std::ffi::{OsStr, OsString};
use std::path::Path;

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

#[test]
fn no_escalate_fails_before_selecting_an_escalator() {
    let error = should_escalate(true, 1000, true).unwrap_err();

    assert!(matches!(error, Error::EscalationDisabled { euid: 1000 }));
    assert_eq!(error.code(), "escalation_disabled");
}

#[test]
fn escalation_is_skipped_when_unneeded_or_already_root() {
    assert!(!should_escalate(false, 1000, true).unwrap());
    assert!(!should_escalate(true, 0, true).unwrap());
    assert!(should_escalate(true, 1000, false).unwrap());
}

fn command_args(command: &std::process::Command) -> Vec<&OsStr> {
    command.get_args().collect()
}

#[test]
fn non_interactive_adds_n_for_doas_and_sudo() {
    let args = [OsString::from("up"), OsString::from("--all")];

    for escalator in [
        "/usr/local/bin/doas",
        "/usr/local/bin/sudo",
        "/usr/bin/sudo",
    ] {
        let command = escalation_command(escalator, Path::new("/bin/blackship"), &args, true);
        assert_eq!(
            command_args(&command),
            ["-n", "/bin/blackship", "up", "--all"]
        );
    }
}

#[test]
fn mdo_is_inherently_non_interactive_and_does_not_receive_n() {
    let args = [OsString::from("up"), OsString::from("--all")];
    let command = escalation_command(MDO, Path::new("/bin/blackship"), &args, true);

    assert_eq!(command_args(&command), ["/bin/blackship", "up", "--all"]);
}

#[test]
fn interactive_mode_does_not_add_escalator_flags() {
    let args = [OsString::from("up"), OsString::from("--all")];
    let command = escalation_command(
        "/usr/local/bin/doas",
        Path::new("/bin/blackship"),
        &args,
        false,
    );

    assert_eq!(command_args(&command), ["/bin/blackship", "up", "--all"]);
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
