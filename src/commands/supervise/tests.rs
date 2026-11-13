use super::*;
use crate::sickbay::checker::{CheckTarget, HealthCheck, HealthCheckConfig};
use crate::sickbay::pacer::PacerConfig;

fn checker(command: &str) -> sickbay::HealthChecker {
    let mut check = HealthCheck::new("probe", command).with_target(CheckTarget::Host);
    check.start_period = 0;
    sickbay::HealthChecker::new(
        "snapshot-jail",
        HealthCheckConfig::enabled().with_check(check),
    )
}

fn store() -> (tempfile::TempDir, sickbay::HealthStateStore) {
    let tmp = tempfile::Builder::new()
        .prefix("blackship-health-")
        .tempdir()
        .expect("scratch dir");
    let store = sickbay::HealthStateStore::new(tmp.path().to_path_buf());
    (tmp, store)
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
        .block_on(future)
}

fn one_slot_pacer() -> SharedPacer {
    let pacer = PacerConfig {
        initial: 1,
        min: 1,
        max: 1,
    }
    .build()
    .expect("bounds");
    Arc::new(std::sync::Mutex::new(pacer))
}

#[test]
fn a_shed_cycle_leaves_no_snapshot() {
    let (_tmp, store) = store();
    let pacer = one_slot_pacer();
    let _held = lock(&pacer).enter().expect("the only slot");

    let (checker, cycle) = block_on(run_cycle(checker("true"), Some(&pacer))).unwrap();
    assert!(matches!(cycle, Cycle::Shed));
    save_snapshot(&store, &checker, checker.status(), &cycle);

    assert_eq!(store.get("snapshot-jail").unwrap(), None);
}

#[test]
fn an_errored_cycle_leaves_no_snapshot() {
    let (_tmp, store) = store();
    let checker = checker("true");
    let cycle = Cycle::Ran(Err(crate::error::Error::State("boom".to_string())));

    save_snapshot(&store, &checker, checker.status(), &cycle);

    assert_eq!(store.get("snapshot-jail").unwrap(), None);
}

#[test]
fn a_completed_cycle_writes_one() {
    let (_tmp, store) = store();
    let pacer = one_slot_pacer();

    let (checker, cycle) = block_on(run_cycle(checker("true"), Some(&pacer))).unwrap();
    assert!(matches!(cycle, Cycle::Ran(Ok(_))));
    save_snapshot(&store, &checker, checker.status(), &cycle);

    let record = store.get("snapshot-jail").unwrap().expect("a snapshot");
    assert_eq!(record.status, sickbay::HealthStatus::Healthy);
}
