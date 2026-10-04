use super::*;

#[test]
fn test_recovery_action_default() {
    let action = RecoveryAction::default();
    assert_eq!(action, RecoveryAction::None);
}

#[test]
fn test_recovery_config_builders() {
    let restart = RecoveryConfig::restart().with_max_attempts(5);
    assert_eq!(restart.action, RecoveryAction::Restart);
    assert_eq!(restart.max_attempts, 5);

    let stop = RecoveryConfig::stop().with_cooldown(120);
    assert_eq!(stop.action, RecoveryAction::Stop);
    assert_eq!(stop.cooldown, 120);

    let cmd = RecoveryConfig::command("/usr/local/bin/fix.sh");
    assert_eq!(
        cmd.action,
        RecoveryAction::Command("/usr/local/bin/fix.sh".to_string())
    );
}

#[test]
fn test_should_attempt_across_cooldown_boundary() {
    let config = RecoveryConfig::restart().with_cooldown(60);

    assert!(config.should_attempt(None));

    let now = std::time::Instant::now();
    assert!(!config.should_attempt(Some(now)));
    assert!(!config.should_attempt(Some(now - std::time::Duration::from_secs(59))));
    assert!(config.should_attempt(Some(now - std::time::Duration::from_secs(60))));

    let immediate = RecoveryConfig::restart().with_cooldown(0);
    assert!(immediate.should_attempt(Some(now)));
}

#[test]
fn test_recovery_config_deserialize() {
    let toml = r#"
action = "restart"
max_attempts = 5
cooldown = 120
"#;

    let config: RecoveryConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.action, RecoveryAction::Restart);
    assert_eq!(config.max_attempts, 5);
    assert_eq!(config.cooldown, 120);
}

#[test]
fn test_recovery_command_deserialize() {
    let toml = r#"
action = { command = "/usr/local/bin/restart-service.sh" }
max_attempts = 2
"#;

    let config: RecoveryConfig = toml::from_str(toml).unwrap();
    assert_eq!(
        config.action,
        RecoveryAction::Command("/usr/local/bin/restart-service.sh".to_string())
    );
}
