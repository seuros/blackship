use super::*;

#[test]
fn test_hook_phase_display() {
    assert_eq!(HookPhase::PreStart.to_string(), "pre_start");
    assert_eq!(HookPhase::PostStop.to_string(), "post_stop");
}

#[test]
fn test_hook_context_substitution() {
    let ctx = HookContext::new("myjail", Path::new("/jails/myjail"))
        .with_ip("10.0.1.10".to_string())
        .with_jid(42)
        .with_var("custom", "value");

    assert_eq!(ctx.substitute("jail: ${jail_name}"), "jail: myjail");
    assert_eq!(ctx.substitute("path: ${jail_path}"), "path: /jails/myjail");
    assert_eq!(ctx.substitute("ip: ${jail_ip}"), "ip: 10.0.1.10");
    assert_eq!(ctx.substitute("jid: ${jid}"), "jid: 42");
    assert_eq!(ctx.substitute("var: ${custom}"), "var: value");
}

#[test]
fn test_hook_builder() {
    let hook = Hook::new(HookPhase::PreStart, "/bin/echo".to_string())
        .with_target(HookTarget::Host)
        .with_args(vec!["hello".to_string()])
        .with_timeout(60)
        .with_on_failure(OnFailure::Continue);

    assert_eq!(hook.phase, HookPhase::PreStart);
    assert_eq!(hook.target, HookTarget::Host);
    assert_eq!(hook.timeout, 60);
    assert_eq!(hook.on_failure, OnFailure::Continue);
}

#[test]
fn test_filter_by_phase_selects_only_that_phase() {
    let hooks = vec![
        Hook::new(HookPhase::PreStart, "/bin/a".to_string()),
        Hook::new(HookPhase::PostStart, "/bin/b".to_string()),
        Hook::new(HookPhase::PreStart, "/bin/c".to_string()),
    ];

    let pre: Vec<&str> = filter_by_phase(&hooks, HookPhase::PreStart)
        .iter()
        .map(|h| h.command.as_str())
        .collect();
    assert_eq!(pre, ["/bin/a", "/bin/c"]);
    assert_eq!(filter_by_phase(&hooks, HookPhase::PreStop).len(), 0);
}

#[test]
fn test_execute_phase_rejects_missing_jid() {
    let runner = HookRunner::new(vec![Hook::new(
        HookPhase::PostStart,
        "/bin/false".to_string(),
    )]);
    let ctx = HookContext::new("myjail", Path::new("/jails/myjail"));

    let err = runner
        .execute_phase(HookPhase::PostStart, &ctx)
        .expect_err("post_start without a JID must fail fast");
    assert!(matches!(err, Error::HookFailed { .. }));

    // A phase that does not need a jail still runs with the same context.
    let runner = HookRunner::new(vec![Hook::new(
        HookPhase::PostStop,
        "/usr/bin/true".to_string(),
    )]);
    assert!(runner.execute_phase(HookPhase::PostStop, &ctx).is_ok());
}

#[test]
fn test_phase_requires_running_jail() {
    assert!(!HookPhase::PreCreate.requires_running_jail());
    assert!(!HookPhase::PostCreate.requires_running_jail());
    assert!(!HookPhase::PreStart.requires_running_jail());
    assert!(HookPhase::PostStart.requires_running_jail());
    assert!(HookPhase::PreStop.requires_running_jail());
    assert!(!HookPhase::PostStop.requires_running_jail());
    assert!(HookPhase::PreEva.requires_running_jail());
    assert!(HookPhase::PostEva.requires_running_jail());
}

#[test]
fn test_hook_deserialize() {
    let toml = r#"
phase = "pre_start"
target = "host"
command = "/usr/local/bin/setup.sh"
args = ["${jail_name}", "${jail_ip}"]
timeout = 60
on_failure = "continue"
description = "Run setup script"
"#;

    let hook: Hook = toml::from_str(toml).unwrap();
    assert_eq!(hook.phase, HookPhase::PreStart);
    assert_eq!(hook.target, HookTarget::Host);
    assert_eq!(hook.command, "/usr/local/bin/setup.sh");
    assert_eq!(hook.args.len(), 2);
    assert_eq!(hook.timeout, 60);
    assert_eq!(hook.on_failure, OnFailure::Continue);
}
