use super::*;
use crate::scope::ScopeMachineState;

fn vnet(owner: &str, host: &str, jail: &str) -> VnetStateRecord {
    VnetStateRecord {
        owner: owner.to_string(),
        network: None,
        bridge: "bridge0".to_string(),
        host_interface: host.to_string(),
        jail_interface: jail.to_string(),
        backend: "epair".to_string(),
    }
}

fn survey(
    live: &[&str],
    scopes: Vec<ScopeRecord>,
    vnet: Vec<VnetStateRecord>,
    ifaces: &[&str],
    datasets: &[&str],
) -> Survey {
    Survey {
        live: live.iter().map(std::string::ToString::to_string).collect(),
        scopes,
        vnet,
        tagged_ifaces: ifaces
            .iter()
            .map(std::string::ToString::to_string)
            .collect(),
        datasets: datasets
            .iter()
            .map(std::string::ToString::to_string)
            .collect(),
        drain_anchors: Vec::new(),
        bridges: Vec::new(),
        named_bridges: HashSet::new(),
        migrated: HashMap::new(),
    }
}

fn running_scope(name: &str) -> ScopeRecord {
    let mut scope = ScopeRecord::new(name);
    scope.jid = Some(11);
    scope.phase = ScopeMachineState::Running;
    scope.rctl_subject = Some(format!("jail:{name}"));
    scope.has_vnet_record = true;
    scope
}

#[test]
fn live_jail_is_left_alone() {
    let s = survey(
        &["web"],
        vec![running_scope("web")],
        vec![vnet("web", "epair0a", "epair0b")],
        &["epair0a"],
        &["web"],
    );
    assert_eq!(classify(&s), Vec::<Orphan>::new());
}

#[test]
fn dead_jail_scope_is_reapable_without_force() {
    let s = survey(&[], vec![running_scope("web")], vec![], &[], &[]);
    let orphans = classify(&s);

    assert_eq!(orphans.len(), 1);
    assert_eq!(orphans[0].jail, "web");
    assert!(!orphans[0].requires_force);
    assert!(orphans[0].resources.iter().any(|r| r == "rctl jail:web"));
    assert!(orphans[0].resources.iter().any(|r| r == "vnet"));
}

#[test]
fn non_ephemeral_dataset_is_reported_as_retained() {
    let mut scope = running_scope("db");
    scope.zfs_dataset = Some("zroot/blackship/jails/db".to_string());
    scope.ephemeral = false;

    let orphans = classify(&survey(&[], vec![scope], vec![], &[], &["db"]));
    assert_eq!(orphans.len(), 1);
    assert!(
        orphans[0]
            .resources
            .iter()
            .any(|r| r.contains("(retained)"))
    );
}

#[test]
fn dataset_covered_by_a_scope_is_not_reported_twice() {
    let orphans = classify(&survey(
        &[],
        vec![running_scope("web")],
        vec![],
        &[],
        &["web"],
    ));
    assert_eq!(orphans.len(), 1);
    assert_eq!(orphans[0].kind_label(), "scope");
}

#[test]
fn untracked_dataset_needs_force() {
    let orphans = classify(&survey(&[], vec![], vec![], &[], &["leftover"]));
    assert_eq!(orphans.len(), 1);
    assert_eq!(orphans[0].kind_label(), "dataset");
    assert!(orphans[0].requires_force);
}

#[test]
fn interface_claimed_by_a_vnet_record_is_not_stray() {
    let s = survey(
        &[],
        vec![],
        vec![vnet("web", "epair0a", "epair0b")],
        &["epair0a", "epair9a"],
        &[],
    );
    let orphans = classify(&s);

    let strays: Vec<&Orphan> = orphans
        .iter()
        .filter(|o| o.kind_label() == "interface")
        .collect();
    assert_eq!(strays.len(), 1);
    assert_eq!(strays[0].kind, OrphanKind::StrayInterface("epair9a".into()));
    assert!(strays[0].requires_force);
}

#[test]
fn drain_anchor_of_a_live_jail_is_left_loaded() {
    let mut s = survey(&["web"], vec![running_scope("web")], vec![], &[], &[]);
    s.drain_anchors = vec!["blackship/drain/web".to_string()];

    assert_eq!(classify(&s), Vec::<Orphan>::new());
}

#[test]
fn drain_anchor_without_a_jail_is_flushable() {
    let mut s = survey(&[], vec![], vec![], &[], &[]);
    s.drain_anchors = vec!["blackship/drain/gone".to_string()];

    let orphans = classify(&s);
    assert_eq!(orphans.len(), 1);
    assert_eq!(orphans[0].kind_label(), "drain-anchor");
    assert_eq!(orphans[0].jail, "gone");
    assert!(!orphans[0].requires_force);
}

#[test]
fn stray_vnet_record_without_scope_is_reapable() {
    let s = survey(
        &[],
        vec![],
        vec![vnet("gone", "epair3a", "epair3b")],
        &[],
        &[],
    );
    let orphans = classify(&s);

    assert_eq!(orphans.len(), 1);
    assert_eq!(orphans[0].kind_label(), "vnet");
    assert!(!orphans[0].requires_force);
}

fn with_bridge(name: &str, members: &[&str], named: &[&str]) -> Survey {
    let mut survey = survey(&[], vec![], vec![], &[name], &[]);
    survey.bridges = vec![BridgeFacts {
        name: name.to_string(),
        members: members.iter().map(ToString::to_string).collect(),
    }];
    survey.named_bridges = named.iter().map(ToString::to_string).collect();
    survey
}

#[test]
fn an_empty_unnamed_tagged_bridge_is_reclaimed_without_force() {
    let orphans = classify(&with_bridge("spkbr0", &[], &[]));
    assert_eq!(orphans.len(), 1);
    assert_eq!(orphans[0].kind, OrphanKind::StrayBridge("spkbr0".into()));
    assert!(!orphans[0].requires_force);
}

#[test]
fn a_bridge_with_members_or_a_name_is_left_alone() {
    assert_eq!(classify(&with_bridge("spkbr0", &["epair9a"], &[])), []);
    assert_eq!(classify(&with_bridge("spkbr0", &[], &["spkbr0"])), []);
}

#[test]
fn a_bridge_a_vnet_record_uses_is_left_alone() {
    let mut survey = with_bridge("bridge0", &[], &[]);
    survey.vnet = vec![vnet("web", "epair1a", "epair1b")];
    survey.live.insert("web".to_string());
    assert_eq!(classify(&survey), []);
}

#[test]
fn a_tagged_interface_that_is_no_bridge_stays_a_forced_stray() {
    let survey = survey(&[], vec![], vec![], &["ngeth3"], &[]);
    let strays = classify(&survey);
    assert_eq!(strays[0].kind, OrphanKind::StrayInterface("ngeth3".into()));
    assert!(strays[0].requires_force);
}

#[test]
fn a_bridge_only_a_gone_jails_epair_holds_is_reclaimed() {
    let mut survey = with_bridge("bridge0", &["epair1a"], &[]);
    survey.vnet = vec![vnet("web", "epair1a", "epair1b")];
    survey.tagged_ifaces.push("epair1a".to_string());
    let orphans = classify(&survey);
    assert!(
        orphans
            .iter()
            .any(|o| o.kind == OrphanKind::StrayBridge("bridge0".into()))
    );
}

#[test]
fn a_stray_dataset_says_when_it_was_migrated() {
    let mut survey = survey(&[], vec![], vec![], &[], &["mig-web", "plain"]);
    survey.migrated.insert(
        "mig-web".to_string(),
        "bastion/zroot/jails/mig-web@1794570755".to_string(),
    );

    let orphans = classify(&survey);
    let reason = |jail: &str| {
        orphans
            .iter()
            .find(|o| o.jail == jail)
            .map(|o| o.reason.clone())
            .unwrap()
    };

    assert!(reason("mig-web").contains("migrated to bastion/zroot/jails/mig-web"));
    assert!(reason("mig-web").contains("fenced"));
    assert_eq!(
        reason("plain"),
        "dataset has no scope record and no live jail"
    );
    assert!(orphans.iter().all(|o| o.requires_force));
}
