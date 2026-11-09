use super::*;
use crate::container::{Limits, Mount};

#[test]
fn default_spec_has_no_network_and_persists() {
    let spec = ContainerSpec::new("kim-1", "16.0-CURRENT");
    let params = jail_params(&spec, Path::new("/c/kim-1"));
    assert_eq!(
        params,
        [
            "name=kim-1",
            "path=/c/kim-1",
            "host.hostname=kim-1",
            "persist",
            "mount.devfs",
            "ip4=disable",
            "ip6=disable",
        ]
    );
}

#[test]
fn spec_knobs_map_to_jail_params() {
    let spec = ContainerSpec::new("kim-2", "16.0-CURRENT")
        .hostname("ci")
        .network(Network::Inherit)
        .allow_raw_sockets()
        .boot()
        .jail_param("allow.mlock");
    let params = jail_params(&spec, Path::new("/c/kim-2"));
    for expected in [
        "host.hostname=ci",
        "ip4=inherit",
        "ip6=inherit",
        "allow.raw_sockets",
        "exec.start=/bin/sh /etc/rc",
        "allow.mlock",
    ] {
        assert!(params.iter().any(|p| p == expected), "missing {expected}");
    }

    let vnet = ContainerSpec::new("kim-3", "r").network(Network::vnet("ci"));
    assert!(
        jail_params(&vnet, Path::new("/c"))
            .iter()
            .any(|p| p == "vnet")
    );
}

#[test]
fn validate_rejects_bad_names_hosts_and_mounts() {
    let ok = ContainerSpec::new("kim-1", "16.0-CURRENT");
    validate(&ok).unwrap();

    for bad in [
        ContainerSpec::new("kim.1", "16.0-CURRENT"),
        ContainerSpec::new("kim/1", "16.0-CURRENT"),
        ContainerSpec::new("kim-1", "../etc"),
        ok.clone().hostname("bad host"),
        ok.clone().mount(Mount::read_only("relative", "/x")),
        ok.clone().mount(Mount::read_only("/tmp", "relative")),
        ok.clone().mount(Mount::read_only("/tmp", "/a/../../etc")),
        ok.clone().mount(Mount::read_only("/tmp", "/")),
        ok.clone().jail_param("-r"),
    ] {
        assert!(validate(&bad).is_err(), "accepted {bad:?}");
    }

    validate(&ok.mount(Mount::read_write("/tmp", "/work"))).unwrap();
}

#[test]
fn limits_feed_the_rctl_config() {
    let limits = Limits::new()
        .memory("4g")
        .cpu_percent(200)
        .max_processes(512)
        .cpus("0-3");
    let resources = limits.resources();
    assert_eq!(resources.memory.as_deref(), Some("4g"));
    assert_eq!(resources.cpu.as_deref(), Some("200"));
    assert_eq!(resources.maxproc, Some(512));
    assert_eq!(resources.cpuset.as_deref(), Some("0-3"));
    assert!(resources.has_rctl_rules());
    assert!(Limits::new().is_empty());
}
