use super::*;

/// Params with a single named jail and nothing optional set.
fn minimal(project: &str, jail: &str) -> ManifestParams {
    ManifestParams {
        path: None,
        project: project.to_string(),
        data_dir: None,
        releases_dir: None,
        zpool: None,
        dataset: None,
        jails: vec![JailParams {
            name: jail.to_string(),
            release: Some("15.1-RELEASE".to_string()),
            path: None,
            build: None,
            jailfile: None,
            hostname: None,
            depends_on: Vec::new(),
            tags: Vec::new(),
            init: None,
            stop: None,
            network: None,
            resources: None,
            params: std::collections::BTreeMap::new(),
        }],
    }
}

/// The report `manifest_create` consults before asking the operator anything.
fn report(params: &ManifestParams) -> serde_json::Value {
    let rendered = render(params).expect("render");
    super::super::manifest_validate::validate_text(json!({}), &rendered)
}

#[test]
fn a_rendered_manifest_round_trips_through_the_real_config_type() {
    let rendered = render(&minimal("demo", "web")).expect("render");

    let config: crate::manifest::BlackshipConfig = toml::from_str(&rendered).expect("parse");
    config.validate().expect("validate");

    assert_eq!(config.config.project.as_deref(), Some("demo"));
    assert_eq!(config.jails[0].name, "web");
    assert_eq!(config.jails[0].release.as_deref(), Some("15.1-RELEASE"));
}

#[test]
fn omitted_options_do_not_appear_in_the_output() {
    let rendered = render(&minimal("demo", "web")).expect("render");

    assert!(!rendered.contains("zpool"), "{rendered}");
    assert!(!rendered.contains("hostname"), "{rendered}");
    assert!(!rendered.contains("depends_on"), "{rendered}");
}

#[test]
fn a_zpool_turns_zfs_on() {
    let mut params = minimal("demo", "web");
    params.zpool = Some("tank".to_string());
    params.dataset = Some("ships".to_string());

    let rendered = render(&params).expect("render");
    let config: crate::manifest::BlackshipConfig = toml::from_str(&rendered).expect("parse");

    assert!(config.config.zfs_enabled);
    assert_eq!(config.config.zpool.as_deref(), Some("tank"));
    assert_eq!(config.config.dataset, "ships");
}

#[test]
fn a_dataset_without_a_pool_is_dropped_rather_than_enabling_nothing() {
    let mut params = minimal("demo", "web");
    params.dataset = Some("ships".to_string());

    let rendered = render(&params).expect("render");

    assert!(!rendered.contains("ships"), "{rendered}");
}

#[test]
fn raw_jail_parameters_keep_their_toml_type() {
    let mut params = minimal("demo", "web");
    params.jails[0].params.insert(
        "allow.raw_sockets".to_string(),
        JailParamValue::Bool(true),
    );
    params.jails[0]
        .params
        .insert("children.max".to_string(), JailParamValue::Integer(4));
    params.jails[0].params.insert(
        "exec.start".to_string(),
        JailParamValue::Text("/bin/sh /etc/rc".to_string()),
    );

    let rendered = render(&params).expect("render");
    let config: crate::manifest::BlackshipConfig = toml::from_str(&rendered).expect("parse");
    let jail_params = &config.jails[0].params;

    assert_eq!(jail_params["allow.raw_sockets"].as_bool(), Some(true));
    assert_eq!(jail_params["children.max"].as_integer(), Some(4));
    assert_eq!(
        jail_params["exec.start"].as_str(),
        Some("/bin/sh /etc/rc"),
        "a string parameter must not be retyped"
    );
}

#[test]
fn network_and_resource_blocks_reach_the_parsed_config() {
    let mut params = minimal("demo", "web");
    params.jails[0].network = Some(NetworkParams {
        vnet: true,
        bridge: Some("blackship0".to_string()),
        ip_cidr: Some("10.0.1.10/24".to_string()),
        ip: None,
        gateway: Some("10.0.1.1".to_string()),
        nameservers: vec!["9.9.9.9".to_string()],
    });
    params.jails[0].resources = Some(ResourceParams {
        memory: Some("1g".to_string()),
        swap: None,
        cpu: Some("100".to_string()),
        maxproc: Some(64),
        openfiles: None,
        cores: Some(2),
        cpuset: None,
    });

    let rendered = render(&params).expect("render");
    let config: crate::manifest::BlackshipConfig = toml::from_str(&rendered).expect("parse");
    let network = config.jails[0].network.as_ref().expect("network");

    assert!(network.vnet);
    assert_eq!(network.ip_cidr.as_deref(), Some("10.0.1.10/24"));
    assert_eq!(network.dns.nameservers, vec!["9.9.9.9".to_string()]);
    assert_eq!(config.jails[0].resources.memory.as_deref(), Some("1g"));
    assert_eq!(config.jails[0].resources.cores, Some(2));
}

#[test]
fn an_empty_resource_block_is_not_emitted() {
    let mut params = minimal("demo", "web");
    params.jails[0].resources = Some(ResourceParams {
        memory: None,
        swap: None,
        cpu: None,
        maxproc: None,
        openfiles: None,
        cores: None,
        cpuset: None,
    });

    let rendered = render(&params).expect("render");

    assert!(!rendered.contains("resources"), "{rendered}");
}

#[test]
fn a_bad_project_name_is_caught_before_any_write() {
    let outcome = report(&minimal("demo/../etc", "web"));

    assert_eq!(outcome["valid"], false);
    assert_eq!(outcome["failed_stage"], "validate");
}

#[test]
fn an_unknown_dependency_is_caught_before_any_write() {
    let mut params = minimal("demo", "web");
    params.jails[0].depends_on = vec!["db".to_string()];

    let outcome = report(&params);

    assert_eq!(outcome["valid"], false);
    assert_eq!(outcome["failed_stage"], "validate");
}

#[test]
fn duplicate_jail_names_are_caught_before_any_write() {
    let mut params = minimal("demo", "web");
    params.jails.push(JailParams {
        name: "web".to_string(),
        release: Some("15.1-RELEASE".to_string()),
        path: None,
        build: None,
        jailfile: None,
        hostname: None,
        depends_on: Vec::new(),
        tags: Vec::new(),
        init: None,
        stop: None,
        network: None,
        resources: None,
        params: std::collections::BTreeMap::new(),
    });

    let outcome = report(&params);

    assert_eq!(outcome["valid"], false);
    assert_eq!(outcome["failed_stage"], "validate");
}

#[test]
fn a_jail_name_with_a_quote_does_not_escape_its_string() {
    let rendered = render(&minimal("demo", "we\"b")).expect("render");

    let parsed: toml::Table = toml::from_str(&rendered).expect("parse");
    let name = parsed["jails"][0]["name"].as_str().expect("name");

    assert_eq!(name, "we\"b");
}
