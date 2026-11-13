use super::*;

const SECOND: Duration = Duration::from_secs(1);
const TIMEOUT: Duration = Duration::from_secs(10);

fn pacer(initial: u32, min: u32, max: u32) -> Pacer {
    PacerConfig { initial, min, max }.build().unwrap()
}

#[test]
fn sheds_once_the_limit_is_in_flight() {
    let mut pacer = pacer(2, 1, 8);
    let first = pacer.enter().unwrap();
    let second = pacer.enter().unwrap();
    assert!(pacer.enter().is_none());
    assert_eq!(pacer.in_flight(), 2);
    pacer.leave(first, SECOND / 10, TIMEOUT, false);
    pacer.leave(second, SECOND / 10, TIMEOUT, false);
    assert_eq!(pacer.in_flight(), 0);
}

#[test]
fn saturated_fast_runs_grow_the_limit() {
    let mut pacer = pacer(2, 1, 8);
    let _held = pacer.enter().unwrap();
    let saturated = pacer.enter().unwrap();
    assert_eq!(
        pacer.leave(saturated, SECOND / 10, TIMEOUT, false),
        Some((2, 3))
    );
}

#[test]
fn idle_runs_hold_the_limit() {
    let mut pacer = pacer(4, 1, 8);
    let alone = pacer.enter().unwrap();
    assert_eq!(pacer.leave(alone, SECOND / 10, TIMEOUT, false), None);
    assert_eq!(pacer.limit(), 4);
}

#[test]
fn slow_runs_cut_the_limit_to_three_quarters() {
    let mut pacer = pacer(8, 1, 16);
    let run = pacer.enter().unwrap();
    assert_eq!(pacer.leave(run, 6 * SECOND, TIMEOUT, false), Some((8, 6)));
}

#[test]
fn a_failed_run_reads_as_overload() {
    let mut pacer = pacer(8, 1, 16);
    let run = pacer.enter().unwrap();
    assert_eq!(pacer.leave(run, SECOND / 10, TIMEOUT, true), Some((8, 6)));
}

#[test]
fn limit_stays_inside_the_bounds() {
    let mut pacer = pacer(2, 2, 3);
    for _ in 0..10 {
        let run = pacer.enter().unwrap();
        pacer.leave(run, 9 * SECOND, TIMEOUT, false);
    }
    assert_eq!(pacer.limit(), 2);

    let mut pacer = pacer_at_ceiling();
    let held = pacer.enter().unwrap();
    pacer.leave(held, SECOND / 10, TIMEOUT, false);
    assert_eq!(pacer.limit(), 1);
}

fn pacer_at_ceiling() -> Pacer {
    pacer(1, 1, 1)
}

#[test]
fn unusable_bounds_are_refused() {
    assert!(
        PacerConfig {
            initial: 1,
            min: 0,
            max: 4
        }
        .build()
        .is_err()
    );
    assert!(
        PacerConfig {
            initial: 1,
            min: 5,
            max: 4
        }
        .build()
        .is_err()
    );
}

#[test]
fn table_defaults_fill_in() {
    let parsed: PacerConfig = toml::from_str("").unwrap();
    assert_eq!(
        parsed,
        PacerConfig {
            initial: 4,
            min: 1,
            max: DEFAULT_CEILING
        }
    );
}
