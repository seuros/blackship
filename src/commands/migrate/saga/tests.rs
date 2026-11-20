use std::cell::RefCell;
use std::rc::Rc;

use saga_machines::{Progress, Saga};

use super::*;
use crate::fault;

#[derive(Default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "one switch per injected failure"
)]
struct World {
    stageable: bool,
    snapshot: bool,
    remote: Remote,
    fence: Option<String>,
    log: Vec<&'static str>,
    sends: u32,
    fail_snapshot: bool,
    fail_transfer: bool,
    fail_fence: bool,
    fail_delete_snapshot: bool,
    fail_discard: bool,
    unreachable: bool,
    changed: bool,
}

#[derive(Clone, Default)]
struct Fake(Rc<RefCell<World>>);

impl Fake {
    fn with(setup: impl FnOnce(&mut World)) -> Self {
        let fake = Self::default();
        setup(&mut fake.0.borrow_mut());
        fake
    }

    fn log(&self) -> Vec<&'static str> {
        self.0.borrow().log.clone()
    }
}

fn failed(what: &str) -> Error {
    Error::JailOperation(format!("injected {what} failure"))
}

impl Effects for Fake {
    fn stage(&mut self) -> bool {
        let mut world = self.0.borrow_mut();
        world.log.push("stage");
        world.stageable
    }

    fn snapshot_exists(&mut self) -> Result<bool> {
        Ok(self.0.borrow().snapshot)
    }

    fn create_snapshot(&mut self) -> Result<()> {
        let mut world = self.0.borrow_mut();
        world.log.push("snapshot");
        if world.fail_snapshot {
            return Err(failed("snapshot"));
        }
        world.snapshot = true;
        Ok(())
    }

    fn delete_snapshot(&mut self) -> Result<()> {
        let mut world = self.0.borrow_mut();
        world.log.push("delete_snapshot");
        if world.fail_delete_snapshot {
            return Err(failed("delete_snapshot"));
        }
        world.snapshot = false;
        Ok(())
    }

    fn remote(&mut self) -> Result<Remote> {
        let world = self.0.borrow();
        if world.unreachable {
            return Err(failed("ssh"));
        }
        Ok(world.remote)
    }

    fn transfer(&mut self) -> Result<()> {
        let mut world = self.0.borrow_mut();
        world.log.push("send");
        world.sends += 1;
        if world.fail_transfer {
            world.remote = Remote::Partial;
            return Err(failed("transfer"));
        }
        world.remote = Remote::Complete;
        Ok(())
    }

    fn discard_destination(&mut self) -> Result<()> {
        let mut world = self.0.borrow_mut();
        world.log.push("discard");
        if world.fail_discard {
            return Err(failed("discard"));
        }
        world.remote = Remote::Absent;
        Ok(())
    }

    fn source_changed(&mut self) -> Result<bool> {
        Ok(self.0.borrow().changed)
    }

    fn fence_state(&mut self) -> Result<Option<String>> {
        Ok(self.0.borrow().fence.clone())
    }

    fn fence(&mut self, destination: &str) -> Result<()> {
        let mut world = self.0.borrow_mut();
        world.log.push("fence");
        if world.fail_fence {
            return Err(failed("fence"));
        }
        world.fence = Some(destination.to_string());
        Ok(())
    }

    fn clear_fence(&mut self) -> Result<()> {
        let mut world = self.0.borrow_mut();
        world.log.push("clear_fence");
        world.fence = None;
        Ok(())
    }
}

const JAIL: &str = "mgs-web";

fn fresh_record() -> Record {
    Record {
        version: super::super::record::VERSION,
        jail: JAIL.to_string(),
        service: "web".to_string(),
        target: "root@bastion".to_string(),
        remote_dataset: "zroot/mgs/web".to_string(),
        source_dataset: "zroot/jails/mgs-web".to_string(),
        snapshot: "snap-1".to_string(),
        keep: false,
        started_at: 1,
        fence: None,
        parked: None,
        compensation_failures: 0,
        saga: Saga::<STEPS>::new(saga_id(JAIL)).snapshot(),
    }
}

struct Bench {
    dir: tempfile::TempDir,
    store: RecordStore,
}

impl Bench {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = RecordStore::new(dir.path().join("migrations"));
        Self { dir, store }
    }

    fn fresh(&self, fake: &Fake) -> Driver<'_, Fake> {
        Driver::restore(fake.clone(), fresh_record(), &self.store).unwrap()
    }

    /// What a new process sees after the old one died.
    fn reopened(&self, fake: &Fake) -> Driver<'_, Fake> {
        let record = self.store.load(JAIL).unwrap().expect("a record on disk");
        Driver::restore(fake.clone(), record, &self.store).unwrap()
    }

    fn recorded(&self) -> bool {
        self.store.exists(JAIL).unwrap()
    }
}

fn crash_at(point: fault::Point, bench: &Bench, fake: &Fake) {
    fault::arm(point);
    let crashed = bench.fresh(fake).drive();
    fault::disarm();
    assert!(crashed.is_err(), "{point:?} must interrupt the migration");
}

const POINTS: [fault::Point; 3] = [
    fault::Point::AfterSnapshot,
    fault::Point::AfterSend,
    fault::Point::BeforeFence,
];

#[test]
fn a_clean_run_settles_and_leaves_no_record() {
    let bench = Bench::new();
    let fake = Fake::with(|w| w.stageable = true);
    let settled = bench.fresh(&fake).drive().unwrap();
    assert!(matches!(settled, Settled::Completed));
    assert_eq!(fake.log(), ["stage", "snapshot", "send", "fence"]);
    assert!(fake.0.borrow().fence.is_some());
    assert!(!bench.recorded());
}

#[test]
fn a_step_that_does_not_apply_is_skipped_and_never_compensated() {
    let bench = Bench::new();
    let fake = Fake::with(|w| w.fail_fence = true);
    let settled = bench.fresh(&fake).drive().unwrap();
    assert!(matches!(settled, Settled::RolledBack { .. }));
    assert_eq!(
        fake.log(),
        [
            "stage",
            "snapshot",
            "send",
            "fence",
            "discard",
            "delete_snapshot"
        ]
    );
}

#[test]
fn a_skip_is_recorded_before_the_next_step_runs() {
    let bench = Bench::new();
    let fake = Fake::default();
    crash_at(fault::Point::AfterSnapshot, &bench, &fake);
    let record = bench.store.load(JAIL).unwrap().unwrap();
    assert_eq!(record.saga.skipped(), 1);
    assert_eq!(record.saga.progress(), Progress::Forward(1));
}

#[test]
fn a_failed_send_unwinds_in_reverse_and_leaves_no_record() {
    let bench = Bench::new();
    let fake = Fake::with(|w| w.fail_transfer = true);
    let settled = bench.fresh(&fake).drive().unwrap();
    let Settled::RolledBack {
        failed: Some((step, _)),
    } = settled
    else {
        panic!("expected a rollback with a failed step");
    };
    assert_eq!(step, Step::Transfer);
    assert_eq!(
        fake.log(),
        ["stage", "snapshot", "send", "discard", "delete_snapshot"]
    );
    let world = fake.0.borrow();
    assert!(!world.snapshot);
    assert_eq!(world.remote, Remote::Absent);
    assert_eq!(world.fence, None);
    drop(world);
    assert!(!bench.recorded());
}

#[test]
fn a_failed_snapshot_has_nothing_to_undo_but_the_skipped_stage() {
    let bench = Bench::new();
    let fake = Fake::with(|w| w.fail_snapshot = true);
    let settled = bench.fresh(&fake).drive().unwrap();
    assert!(matches!(
        settled,
        Settled::RolledBack {
            failed: Some((Step::Snapshot, _))
        }
    ));
    assert_eq!(fake.log(), ["stage", "snapshot"]);
    assert!(!bench.recorded());
}

#[test]
fn a_failed_fence_unwinds_the_transfer_then_the_snapshot() {
    let bench = Bench::new();
    let fake = Fake::with(|w| w.fail_fence = true);
    let settled = bench.fresh(&fake).drive().unwrap();
    assert!(matches!(
        settled,
        Settled::RolledBack {
            failed: Some((Step::Fence, _))
        }
    ));
    let log = fake.log();
    assert_eq!(&log[log.len() - 2..], ["discard", "delete_snapshot"]);
    assert_eq!(fake.0.borrow().remote, Remote::Absent);
    assert!(!bench.recorded());
}

#[test]
fn a_send_that_cannot_be_cleaned_keeps_the_record_and_goes_no_further() {
    let bench = Bench::new();
    let fake = Fake::with(|w| {
        w.fail_transfer = true;
        w.fail_discard = true;
    });
    let Err(error) = bench.fresh(&fake).drive() else {
        panic!("a partial destination must stop the run");
    };
    assert!(error.to_string().contains("--abort mgs-web"), "{error}");
    assert!(bench.recorded());
    assert!(!fake.log().contains(&"fence"));
}

#[test]
fn a_compensation_that_cannot_finish_parks_the_migration() {
    let bench = Bench::new();
    let fake = Fake::with(|w| {
        w.fail_fence = true;
        w.fail_delete_snapshot = true;
    });
    let Err(error) = bench.fresh(&fake).drive() else {
        panic!("the migration must park");
    };
    let message = error.to_string();
    assert!(message.contains("PARKED"), "{message}");
    assert!(message.contains("snapshot"), "{message}");
    assert!(message.contains("--abort mgs-web"), "{message}");

    let record = bench.store.load(JAIL).unwrap().unwrap();
    assert_eq!(record.saga.progress(), Progress::Stuck(1));
    assert!(record.parked.is_some());
    assert_eq!(
        fake.log()
            .iter()
            .filter(|l| **l == "delete_snapshot")
            .count(),
        COMPENSATION_ATTEMPTS as usize
    );
    // the transfer was undone before the snapshot got stuck
    assert_eq!(fake.0.borrow().remote, Remote::Absent);
}

fn parked_on_a_held_snapshot(bench: &Bench) -> Fake {
    let fake = Fake::with(|w| {
        w.fail_fence = true;
        w.fail_delete_snapshot = true;
    });
    assert!(bench.fresh(&fake).drive().is_err());
    fake
}

#[test]
fn a_parked_migration_stays_parked_while_the_cause_remains() {
    let bench = Bench::new();
    let fake = parked_on_a_held_snapshot(&bench);
    assert_eq!(
        bench
            .store
            .load(JAIL)
            .unwrap()
            .unwrap()
            .compensation_failures,
        COMPENSATION_ATTEMPTS
    );

    for retry in [true, false] {
        let mut driver = bench.reopened(&fake);
        let Err(error) = (if retry {
            driver.abort()
        } else {
            driver.resume()
        }) else {
            panic!("the snapshot is still held");
        };
        assert!(error.to_string().contains("PARKED"), "{error}");
        let record = bench.store.load(JAIL).unwrap().unwrap();
        assert_eq!(record.saga.progress(), Progress::Stuck(1));
        assert_eq!(record.compensation_failures, COMPENSATION_ATTEMPTS);
    }
}

#[test]
fn fixing_the_cause_then_resume_completes_the_compensation_and_settles() {
    let bench = Bench::new();
    let fake = parked_on_a_held_snapshot(&bench);
    fake.0.borrow_mut().fail_delete_snapshot = false;

    let settled = bench.reopened(&fake).resume().unwrap();
    assert!(matches!(settled, Settled::RolledBack { failed: None }));
    let world = fake.0.borrow();
    assert!(!world.snapshot);
    assert_eq!(world.remote, Remote::Absent);
    assert_eq!(world.fence, None);
    drop(world);
    assert!(!bench.recorded());
}

#[test]
fn fixing_the_cause_then_abort_retries_the_compensation_too() {
    let bench = Bench::new();
    let fake = parked_on_a_held_snapshot(&bench);
    fake.0.borrow_mut().fail_delete_snapshot = false;

    let settled = bench.reopened(&fake).abort().unwrap();
    assert!(matches!(settled, Settled::RolledBack { failed: None }));
    assert!(!fake.0.borrow().snapshot);
    assert!(!bench.recorded());
}

#[test]
fn a_retry_gets_a_fresh_run_of_attempts_and_the_park_note_is_cleared() {
    let bench = Bench::new();
    let fake = parked_on_a_held_snapshot(&bench);
    let before = fake
        .log()
        .iter()
        .filter(|l| **l == "delete_snapshot")
        .count();

    assert!(bench.reopened(&fake).resume().is_err());
    let attempts = fake
        .log()
        .iter()
        .filter(|l| **l == "delete_snapshot")
        .count()
        - before;
    assert_eq!(attempts, COMPENSATION_ATTEMPTS as usize);
}

#[test]
fn the_attempt_count_survives_a_restart() {
    let bench = Bench::new();
    let mut saga = Saga::<STEPS>::new(saga_id(JAIL));
    for outcome in [
        saga_machines::Outcome::Skipped,
        saga_machines::Outcome::Success,
        saga_machines::Outcome::Failure,
    ] {
        let action = saga.next_action().unwrap().unwrap();
        saga.resolve(action, outcome).unwrap();
    }
    let mut record = fresh_record();
    record.saga = saga.snapshot();
    record.compensation_failures = COMPENSATION_ATTEMPTS - 1;
    bench.store.save(&record).unwrap();
    let fake = Fake::with(|w| {
        w.snapshot = true;
        w.fail_delete_snapshot = true;
    });

    assert!(bench.reopened(&fake).resume().is_err());
    assert_eq!(fake.log(), ["delete_snapshot"]);
    let record = bench.store.load(JAIL).unwrap().unwrap();
    assert_eq!(record.saga.progress(), Progress::Stuck(1));
}

#[test]
fn only_a_parked_migration_can_be_unstuck() {
    let bench = Bench::new();
    let mut driver = bench.fresh(&Fake::default());
    let error = driver.unstick().unwrap_err().to_string();
    assert!(error.contains("not parked"), "{error}");
}

#[test]
fn a_kill_mid_compensation_resumes_and_finishes_the_unwind() {
    let bench = Bench::new();
    let fake = Fake::default();
    crash_at(fault::Point::AfterSend, &bench, &fake);
    let mut driver = bench.reopened(&fake);
    driver.saga.cancel().unwrap();
    driver.persist().unwrap();
    drop(driver);
    fake.0.borrow_mut().remote = Remote::Absent;

    let settled = bench.reopened(&fake).resume().unwrap();
    assert!(matches!(settled, Settled::RolledBack { failed: None }));
    assert!(!fake.0.borrow().snapshot);
    assert!(!bench.recorded());
}

#[test]
fn a_kill_at_each_seam_leaves_a_record_and_an_unfenced_source() {
    for point in POINTS {
        let bench = Bench::new();
        let fake = Fake::default();
        crash_at(point, &bench, &fake);
        assert!(bench.recorded(), "{point:?}");
        assert_eq!(fake.0.borrow().fence, None, "{point:?}");
    }
}

#[test]
fn resume_after_each_seam_completes_without_repeating_effects() {
    for point in POINTS {
        let bench = Bench::new();
        let fake = Fake::default();
        crash_at(point, &bench, &fake);

        let settled = bench.reopened(&fake).drive().unwrap();
        assert!(matches!(settled, Settled::Completed), "{point:?}");
        let world = fake.0.borrow();
        assert!(world.fence.is_some(), "{point:?}");
        assert_eq!(world.remote, Remote::Complete, "{point:?}");
        assert!(world.snapshot, "{point:?}");
        assert_eq!(
            world.sends, 1,
            "{point:?}: the stream must not be sent twice"
        );
        assert_eq!(
            world.log.iter().filter(|l| **l == "snapshot").count(),
            1,
            "{point:?}"
        );
        drop(world);
        assert!(!bench.recorded(), "{point:?}");
    }
}

#[test]
fn the_fence_keeps_the_value_it_was_given_before_the_kill() {
    let bench = Bench::new();
    let fake = Fake::default();
    crash_at(fault::Point::BeforeFence, &bench, &fake);
    let before = bench.store.load(JAIL).unwrap().unwrap().fence;
    assert!(before.is_some());
    bench.reopened(&fake).drive().unwrap();
    assert_eq!(fake.0.borrow().fence, before);
}

#[test]
fn abort_after_each_seam_undoes_in_reverse_and_leaves_the_source_alone() {
    let expected: [&[&str]; 3] = [
        &["delete_snapshot"],
        &["discard", "delete_snapshot"],
        &["discard", "delete_snapshot"],
    ];
    for (point, tail) in POINTS.into_iter().zip(expected) {
        let bench = Bench::new();
        let fake = Fake::default();
        crash_at(point, &bench, &fake);
        let before = fake.log().len();

        let settled = bench.reopened(&fake).abort().unwrap();
        assert!(
            matches!(settled, Settled::RolledBack { failed: None }),
            "{point:?}"
        );
        assert_eq!(fake.log()[before..], *tail, "{point:?}");
        let world = fake.0.borrow();
        assert!(!world.snapshot, "{point:?}");
        assert_eq!(world.remote, Remote::Absent, "{point:?}");
        assert_eq!(world.fence, None, "{point:?}");
        drop(world);
        assert!(!bench.recorded(), "{point:?}");
    }
}

#[test]
fn abort_finds_a_receive_the_record_never_heard_about() {
    let bench = Bench::new();
    let fake = Fake::default();
    crash_at(fault::Point::AfterSend, &bench, &fake);
    let record = bench.store.load(JAIL).unwrap().unwrap();
    assert_eq!(record.saga.progress(), Progress::Forward(2));
    assert_eq!(fake.0.borrow().remote, Remote::Complete);

    bench.reopened(&fake).abort().unwrap();
    assert_eq!(fake.0.borrow().remote, Remote::Absent);
}

#[test]
fn abort_of_a_migration_that_got_fenced_refuses_and_points_at_unfence() {
    let bench = Bench::new();
    let fake = Fake::default();
    crash_at(fault::Point::BeforeFence, &bench, &fake);
    let value = bench.store.load(JAIL).unwrap().unwrap().fence;
    fake.0.borrow_mut().fence = value;

    let Err(error) = bench.reopened(&fake).abort() else {
        panic!("a fenced source is a finished migration");
    };
    assert!(error.to_string().contains("unfence web"), "{error}");
    assert_eq!(fake.0.borrow().remote, Remote::Complete);
    assert!(!bench.recorded());
}

#[test]
fn a_foreign_fence_fails_the_step_instead_of_being_overwritten() {
    let bench = Bench::new();
    let fake = Fake::with(|w| w.fence = Some("elsewhere/zroot/x@1".to_string()));
    let settled = bench.fresh(&fake).drive().unwrap();
    assert!(matches!(
        settled,
        Settled::RolledBack {
            failed: Some((Step::Fence, _))
        }
    ));
    assert_eq!(
        fake.0.borrow().fence.as_deref(),
        Some("elsewhere/zroot/x@1")
    );
}

#[test]
fn an_unreachable_destination_is_not_read_as_an_empty_one() {
    let bench = Bench::new();
    let fake = Fake::default();
    crash_at(fault::Point::AfterSnapshot, &bench, &fake);
    fake.0.borrow_mut().unreachable = true;

    assert!(bench.reopened(&fake).drive().is_err());
    assert!(bench.recorded());
    assert_eq!(fake.0.borrow().sends, 0);
    assert!(!fake.log().contains(&"discard"));
}

#[test]
fn a_partial_destination_is_cleared_before_a_resume_sends_again() {
    let bench = Bench::new();
    let fake = Fake::default();
    crash_at(fault::Point::AfterSnapshot, &bench, &fake);
    fake.0.borrow_mut().remote = Remote::Partial;

    bench.reopened(&fake).drive().unwrap();
    let log = fake.log();
    let discard = log.iter().position(|l| *l == "discard").unwrap();
    let send = log.iter().position(|l| *l == "send").unwrap();
    assert!(discard < send, "{log:?}");
}

#[test]
fn a_record_from_another_saga_is_refused_untouched() {
    let bench = Bench::new();
    let mut record = fresh_record();
    record.saga = Saga::<STEPS>::new(saga_id("someone-else")).snapshot();
    assert!(Driver::restore(Fake::default(), record, &bench.store).is_err());
}

#[test]
fn a_record_for_a_longer_saga_is_refused() {
    let bench = Bench::new();
    let mut record = fresh_record();
    record.saga = Saga::<9>::new(saga_id(JAIL)).snapshot();
    let mut long = Saga::<9>::new(saga_id(JAIL));
    for _ in 0..8 {
        let action = long.next_action().unwrap().unwrap();
        long.resolve(action, saga_machines::Outcome::Success)
            .unwrap();
    }
    record.saga = long.snapshot();
    assert!(Driver::restore(Fake::default(), record, &bench.store).is_err());
}

#[test]
fn unreadable_and_foreign_records_are_refused_and_left_on_disk() {
    let bench = Bench::new();
    let path = bench.store.path(JAIL).unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();

    std::fs::write(&path, "not json").unwrap();
    let message = bench.store.load(JAIL).unwrap_err().to_string();
    assert!(message.contains("mgs-web.json"), "{message}");
    assert!(path.exists());

    let mut other = fresh_record();
    other.jail = "other".to_string();
    std::fs::write(&path, serde_json::to_string(&other).unwrap()).unwrap();
    assert!(bench.store.load(JAIL).is_err());

    let mut old = fresh_record();
    old.version = 0;
    std::fs::write(&path, serde_json::to_string(&old).unwrap()).unwrap();
    assert!(bench.store.load(JAIL).is_err());
    assert!(path.exists());
}

#[test]
fn the_record_dir_is_private_and_a_second_holder_is_turned_away() {
    use std::os::unix::fs::PermissionsExt;

    let bench = Bench::new();
    bench.store.save(&fresh_record()).unwrap();
    let mode = std::fs::metadata(bench.dir.path().join("migrations"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700);

    let held = bench.store.lock(JAIL).unwrap();
    let message = bench.store.lock(JAIL).err().unwrap().to_string();
    assert!(message.contains("running right now"), "{message}");
    drop(held);
    bench.store.delete(JAIL).unwrap();
    bench.store.lock(JAIL).unwrap().discard();
    assert!(!bench.dir.path().join("migrations").exists());
}

#[test]
fn the_second_migration_is_refused_by_naming_the_record_and_both_ways_out() {
    let bench = Bench::new();
    let path = bench.store.path(JAIL).unwrap();
    let message = super::super::record::refuse_second(JAIL, &path).to_string();
    assert!(message.contains(path.to_str().unwrap()), "{message}");
    assert!(message.contains("--resume mgs-web"), "{message}");
    assert!(message.contains("--abort mgs-web"), "{message}");
}

#[test]
fn a_source_that_changed_since_the_snapshot_is_not_fenced_over_a_stale_copy() {
    let bench = Bench::new();
    let fake = Fake::default();
    crash_at(fault::Point::BeforeFence, &bench, &fake);
    fake.0.borrow_mut().changed = true;

    let settled = bench.reopened(&fake).drive().unwrap();
    let Settled::RolledBack {
        failed: Some((Step::Fence, error)),
    } = settled
    else {
        panic!("a stale copy must roll back");
    };
    assert!(error.to_string().contains("stale"), "{error}");
    let world = fake.0.borrow();
    assert_eq!(world.fence, None);
    assert_eq!(world.remote, Remote::Absent);
    assert!(!world.snapshot);
    drop(world);
    assert!(!bench.recorded());
}
