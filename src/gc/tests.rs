use super::*;
use crate::scope::ScopePhase;

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
        live: live.iter().map(|s| s.to_string()).collect(),
        scopes,
        vnet,
        tagged_ifaces: ifaces.iter().map(|s| s.to_string()).collect(),
        datasets: datasets.iter().map(|s| s.to_string()).collect(),
        drain_anchors: Vec::new(),
    }
}

fn running_scope(name: &str) -> ScopeRecord {
    let mut scope = ScopeRecord::new(name);
    scope.jid = Some(11);
    scope.phase = ScopePhase::Running;
    scope.rctl_subject = Some(format!("jail:{}", name));
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
    assert!(classify(&s).is_empty());
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

    assert!(classify(&s).is_empty());
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
