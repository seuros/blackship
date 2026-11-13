use super::*;

const fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn config() -> SuspicionConfig {
    SuspicionConfig {
        min_samples: 4,
        unhealthy_phi: default_unhealthy_phi(),
        failing_phi: default_failing_phi(),
        min_std_dev_ms: None,
    }
}

fn warmed() -> Accrual {
    let mut accrual = config().build(2).unwrap();
    for beat in 0..=4 {
        accrual.beat(secs(beat * 2)).unwrap();
    }
    accrual
}

#[test]
fn warming_until_enough_beats() {
    let mut accrual = config().build(2).unwrap();
    assert_eq!(accrual.verdict(secs(0)), Verdict::Warming);
    for beat in 0..3 {
        accrual.beat(secs(beat * 2)).unwrap();
    }
    assert_eq!(accrual.verdict(secs(10)), Verdict::Warming);
}

#[test]
fn steady_heartbeats_stay_steady() {
    let accrual = warmed();
    assert_eq!(accrual.verdict(secs(8)), Verdict::Steady);
    assert_eq!(accrual.verdict(secs(9)), Verdict::Steady);
}

#[test]
fn growing_gap_goes_unhealthy_then_failing() {
    let accrual = warmed();
    assert_eq!(accrual.verdict(secs(12)), Verdict::Unhealthy);
    assert_eq!(accrual.verdict(secs(14)), Verdict::Failing);
    assert_eq!(accrual.verdict(secs(60)), Verdict::Failing);
}

#[test]
fn one_good_beat_clears_suspicion() {
    let mut accrual = warmed();
    assert_eq!(accrual.verdict(secs(14)), Verdict::Failing);
    accrual.beat(secs(15)).unwrap();
    assert_eq!(accrual.verdict(secs(16)), Verdict::Steady);
}

#[test]
fn a_late_blip_stays_below_unhealthy() {
    let accrual = warmed();
    assert_eq!(accrual.verdict(secs(10)), Verdict::Steady);
}

#[test]
fn deviation_floor_defaults_to_a_quarter_interval() {
    let wide = SuspicionConfig {
        min_std_dev_ms: Some(2_000),
        ..config()
    };
    let mut accrual = wide.build(2).unwrap();
    for beat in 0..=4 {
        accrual.beat(secs(beat * 2)).unwrap();
    }
    assert_eq!(accrual.verdict(secs(12)), Verdict::Steady);
}

#[test]
fn unusable_thresholds_are_refused() {
    let bad = |cfg: SuspicionConfig| cfg.build(2).is_err();
    assert!(bad(SuspicionConfig {
        unhealthy_phi: 0.0,
        ..config()
    }));
    assert!(bad(SuspicionConfig {
        failing_phi: f64::NAN,
        ..config()
    }));
    assert!(bad(SuspicionConfig {
        unhealthy_phi: 9.0,
        failing_phi: 8.0,
        ..config()
    }));
    assert!(bad(SuspicionConfig {
        min_samples: 0,
        ..config()
    }));
    assert!(bad(SuspicionConfig {
        min_samples: WINDOW + 1,
        ..config()
    }));
}

#[test]
fn table_defaults_fill_in() {
    let parsed: SuspicionConfig = toml::from_str("").unwrap();
    assert_eq!(parsed.min_samples, 8);
    assert!((parsed.unhealthy_phi - 3.0).abs() < f64::EPSILON);
    assert!((parsed.failing_phi - 8.0).abs() < f64::EPSILON);
    assert_eq!(parsed.min_std_dev_ms, None);
}
