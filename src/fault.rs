//! Test-only fault gate over rogue-machines; compiles to a no-op outside tests.

/// Seams in the start path where a test can make the next step fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Point {
    AfterBridge,
    AfterZfs,
    AfterLease,
    AfterJailCreate,
    BeforeRctl,
}

#[cfg(not(test))]
#[allow(
    clippy::unnecessary_wraps,
    clippy::missing_const_for_fn,
    reason = "mirrors the fallible test build"
)]
pub fn trip(_point: Point) -> crate::error::Result<()> {
    Ok(())
}

#[cfg(test)]
pub use armed::{arm, disarm, trip};

#[cfg(test)]
mod armed {
    use std::cell::RefCell;

    use rogue_machines::{Decision, Experiment, Fault, Fraction, Rogue, Slot};

    use super::Point;
    use crate::error::{Error, Result};

    const HOUR_NS: u64 = 3_600_000_000_000;

    thread_local! {
        static ROGUE: RefCell<Rogue> = const { RefCell::new(Rogue::new()) };
    }

    fn slot(point: Point) -> Option<Slot> {
        Slot::new(point as usize)
    }

    /// Fail every call at `point` on this thread until disarmed.
    pub fn arm(point: Point) {
        if let Some(slot) = slot(point) {
            ROGUE.with_borrow_mut(|rogue| {
                rogue.arm(slot, Experiment::new(Fault::Raise, Fraction::ALL, HOUR_NS));
            });
        }
    }

    /// Clear every armed point on this thread.
    pub fn disarm() {
        ROGUE.with_borrow_mut(Rogue::disarm_all);
    }

    pub fn trip(point: Point) -> Result<()> {
        let injected = slot(point).is_some_and(|slot| {
            ROGUE.with_borrow(|rogue| rogue.decide(slot, 0, 0) == Decision::Inject(Fault::Raise))
        });
        if injected {
            return Err(Error::JailOperation(format!("injected fault at {point:?}")));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
