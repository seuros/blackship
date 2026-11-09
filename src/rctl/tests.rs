use super::*;

#[test]
fn test_resource_config_empty() {
    let config = ResourceConfig::default();
    assert!(config.is_empty());
}

#[test]
fn test_resource_config_to_rules() {
    let config = ResourceConfig {
        memory: Some("1g".into()),
        maxproc: Some(100),
        openfiles: Some(1024),
        ..Default::default()
    };

    let rules = config.to_rules("myjail");
    assert_eq!(rules.len(), 3);
    assert!(rules.contains(&"jail:myjail:memoryuse:deny=1g".to_string()));
    assert!(rules.contains(&"jail:myjail:maxproc:deny=100".to_string()));
    assert!(rules.contains(&"jail:myjail:openfiles:deny=1024".to_string()));
}

#[test]
fn test_resource_config_custom_rules() {
    let config = ResourceConfig {
        rules: vec!["cputime:log=3600".into()],
        ..Default::default()
    };

    let rules = config.to_rules("test");
    assert_eq!(rules, vec!["jail:test:cputime:log=3600"]);
}

#[test]
fn test_phase_diff_replaces_changed_resources_only() {
    let startup = ResourceConfig {
        memory: Some("2g".into()),
        cpu: Some("400".into()),
        maxproc: Some(100),
        ..Default::default()
    };
    let steady = ResourceConfig {
        memory: Some("2g".into()),
        cpu: Some("100".into()),
        maxproc: Some(100),
        ..Default::default()
    };

    let (removals, additions) = phase_diff("web", &startup, &steady);

    assert_eq!(removals, vec!["jail:web:pcpu"]);
    assert_eq!(additions, vec!["jail:web:pcpu:deny=100"]);
}

#[test]
fn test_phase_diff_removes_resources_dropped_by_target() {
    let startup = ResourceConfig {
        memory: Some("2g".into()),
        openfiles: Some(4096),
        ..Default::default()
    };
    let steady = ResourceConfig {
        memory: Some("2g".into()),
        ..Default::default()
    };

    let (removals, additions) = phase_diff("web", &startup, &steady);

    assert_eq!(removals, vec!["jail:web:openfiles"]);
    assert_eq!(additions, Vec::<String>::new());
}

#[test]
fn test_phase_diff_preserves_custom_rules() {
    let startup = ResourceConfig {
        cpu: Some("400".into()),
        rules: vec!["cputime:log=3600".into()],
        ..Default::default()
    };
    let steady = ResourceConfig {
        cpu: Some("100".into()),
        rules: vec!["cputime:log=3600".into()],
        ..Default::default()
    };

    let (removals, additions) = phase_diff("web", &startup, &steady);

    assert!(!removals.iter().any(|rule| rule.contains("cputime")));
    assert!(!additions.iter().any(|rule| rule.contains("cputime")));
    assert!(!removals.contains(&"jail:web".to_string()));
}

#[test]
fn test_phase_diff_swaps_custom_rules_that_changed() {
    let startup = ResourceConfig {
        rules: vec!["cputime:log=3600".into()],
        ..Default::default()
    };
    let steady = ResourceConfig {
        rules: vec!["cputime:deny=7200".into()],
        ..Default::default()
    };

    let (removals, additions) = phase_diff("web", &startup, &steady);

    assert_eq!(removals, vec!["jail:web:cputime:log=3600"]);
    assert_eq!(additions, vec!["jail:web:cputime:deny=7200"]);
}

#[test]
fn test_phase_diff_identical_profiles_are_noop() {
    let profile = ResourceConfig {
        memory: Some("1g".into()),
        cpu: Some("200".into()),
        rules: vec!["cputime:log=3600".into()],
        ..Default::default()
    };

    let (removals, additions) = phase_diff("web", &profile, &profile);

    assert_eq!(removals, Vec::<String>::new());
    assert_eq!(additions, Vec::<String>::new());
}

#[test]
fn test_qos_config_profile_falls_back_to_startup() {
    let qos = QosConfig {
        startup: ResourceConfig {
            memory: Some("4g".into()),
            ..Default::default()
        },
        steady: None,
        transition: QosTransition::Healthy,
        max_startup_secs: None,
    };

    assert_eq!(
        qos.profile(crate::scope::QosPhase::Steady)
            .memory
            .as_deref(),
        Some("4g")
    );
}

#[test]
fn rules_reach_the_kernel_as_plain_integers() {
    assert_eq!(
        expand_rule("jail:web:memoryuse:deny=256m").unwrap(),
        "jail:web:memoryuse:deny=268435456"
    );
    assert_eq!(
        expand_rule("jail:web:readbps:throttle=1G/process").unwrap(),
        "jail:web:readbps:throttle=1073741824/process"
    );
    assert_eq!(
        expand_rule("jail:web:maxproc:deny=64").unwrap(),
        "jail:web:maxproc:deny=64"
    );
    assert_eq!(expand_rule("jail:web").unwrap(), "jail:web");
    assert!(expand_rule("jail:web:memoryuse:deny=lots").is_err());
    assert!(expand_rule("jail:web:memoryuse:deny=99999999e").is_err());
}

#[test]
fn expand_number_matches_libutil() {
    assert_eq!(expand_number("0"), Some(0));
    assert_eq!(expand_number("1k"), Some(1024));
    assert_eq!(expand_number("4G"), Some(4 << 30));
    assert_eq!(expand_number("2mb"), Some(2 << 20));
    assert_eq!(expand_number("12b"), None);
    assert_eq!(expand_number(""), None);
    assert_eq!(expand_number("1x"), None);
}
