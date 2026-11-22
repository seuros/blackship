use super::*;
use std::assert_matches;

fn pool(health: PoolHealth, read_only: bool, free_percent: u64) -> ZfsPool {
    ZfsPool {
        name: "zroot".into(),
        size_bytes: 1000,
        allocated_bytes: 1000 - free_percent * 10,
        free_bytes: free_percent * 10,
        capacity_percent: u8::try_from(100 - free_percent).unwrap(),
        health,
        read_only,
    }
}

const DEFAULTS: Thresholds = Thresholds {
    refuse_below: REFUSE_BELOW_FREE_PERCENT,
    warn_below: WARN_BELOW_FREE_PERCENT,
};

fn verdict(pool: ZfsPool) -> Verdict {
    judge("zroot", &PoolObservation::Found(pool), DEFAULTS)
}

#[test]
fn a_roomy_online_pool_is_clear() {
    assert_eq!(verdict(pool(PoolHealth::Online, false, 34)), Verdict::Clear);
}

#[test]
fn low_free_space_warns_then_refuses() {
    assert_matches!(
        verdict(pool(PoolHealth::Online, false, 10)),
        Verdict::Warn(_)
    );
    assert_matches!(
        verdict(pool(PoolHealth::Online, false, 4)),
        Verdict::Refuse(_)
    );
    // The line itself is still fine: below means below.
    assert_matches!(
        verdict(pool(PoolHealth::Online, false, 5)),
        Verdict::Warn(_)
    );
}

#[test]
fn a_degraded_pool_is_refused_even_with_room() {
    assert_matches!(
        verdict(pool(PoolHealth::Degraded, false, 60)),
        Verdict::Refuse(_)
    );
}

#[test]
fn a_read_only_pool_is_refused() {
    assert_matches!(
        verdict(pool(PoolHealth::Online, true, 60)),
        Verdict::Refuse(_)
    );
}

#[test]
fn an_unrecognized_state_is_not_healthy() {
    let found = pool(PoolHealth::Unrecognized("WEIRD".into()), false, 60);
    let Verdict::Refuse(message) = verdict(found) else {
        panic!("expected a refusal");
    };
    assert!(message.contains("WEIRD"), "{message}");
}

#[test]
fn the_refusal_names_pool_health_free_and_threshold() {
    let Verdict::Refuse(message) = verdict(pool(PoolHealth::Degraded, false, 4)) else {
        panic!("expected a refusal");
    };
    for needle in ["zroot", "DEGRADED", "4.0% free", "5% free"] {
        assert!(message.contains(needle), "{needle} missing from: {message}");
    }
}

#[test]
fn an_unobservable_pool_warns_and_never_blocks() {
    let gone = judge("zroot", &PoolObservation::NotFound, DEFAULTS);
    assert_matches!(gone, Verdict::Warn(_));
    let blind = judge(
        "zroot",
        &PoolObservation::Unavailable("no zpool".into()),
        DEFAULTS,
    );
    assert_matches!(blind, Verdict::Warn(_));
    assert!(settle(gone, Stance::Refuse).is_ok());
    assert!(settle(blind, Stance::Refuse).is_ok());
}

#[test]
fn settle_refuses_only_when_the_stance_says_so() {
    let refusal = Verdict::Refuse("full".into());
    let err = settle(refusal.clone(), Stance::Refuse).unwrap_err();
    assert_matches!(err, Error::StoragePreflight(ref m) if m == "full");
    assert_eq!(err.code(), "storage_preflight_refused");
    assert!(settle(refusal, Stance::WarnOnly).is_ok());
}

#[test]
fn the_manifest_key_moves_the_refuse_line_and_drags_the_warn_line() {
    let mut config = GlobalConfig::default();
    assert_eq!(Thresholds::of(&config), DEFAULTS);
    config.zpool_min_free_percent = Some(20);
    let thresholds = Thresholds::of(&config);
    assert_eq!(thresholds.refuse_below, 20);
    assert_eq!(thresholds.warn_below, 20);
    let found = PoolObservation::Found(pool(PoolHealth::Online, false, 19));
    assert_matches!(judge("zroot", &found, thresholds), Verdict::Refuse(_));
}

#[test]
fn a_config_without_zfs_is_not_checked() {
    let mut config = GlobalConfig {
        zpool: Some("zroot".into()),
        ..GlobalConfig::default()
    };
    assert!(assess(&config).is_none());
    config.zfs_enabled = true;
    config.zpool = None;
    assert!(assess(&config).is_none());
    assert!(check(&config, Stance::Refuse).is_ok());
}

#[test]
fn an_assessment_serializes_flat_for_the_host_profile() {
    let assessment = Assessment {
        pool: "zroot".into(),
        observation: PoolObservation::Found(pool(PoolHealth::Online, false, 34)),
        verdict: Verdict::Clear,
        thresholds: DEFAULTS,
    };
    let json = serde_json::to_value(&assessment).unwrap();
    assert_eq!(json["pool"], "zroot");
    assert_eq!(json["verdict"], "clear");
    assert_eq!(json["thresholds"]["refuse_below"], 5);
    assert_eq!(json["observation"]["found"]["health"], "online");

    let warned = Assessment {
        verdict: Verdict::Warn("low".into()),
        ..assessment
    };
    let json = serde_json::to_value(&warned).unwrap();
    assert_eq!(json["verdict"], "warn");
    assert_eq!(json["detail"], "low");
}
