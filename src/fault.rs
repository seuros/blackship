//! Test-only fault gate over rogue-machines; compiles to a no-op outside tests.

/// Seams in the start path where a test can make the next step fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Point {
    AfterBridge,
    AfterZfs,
    AfterLease,
    AfterMount,
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
    use std::time::Duration;

    use rogue_machines::{Decision, Draw, Experiment, Fault, Fraction, Rogue, Slot};

    use super::Point;
    use crate::error::{Error, Result};

    const HOUR: Duration = Duration::from_secs(3600);

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
                rogue.arm(slot, Experiment::new(Fault::Raise, Fraction::ALL, HOUR));
            });
        }
    }

    /// Clear every armed point on this thread.
    pub fn disarm() {
        ROGUE.with_borrow_mut(Rogue::disarm_all);
    }

    pub fn trip(point: Point) -> Result<()> {
        let injected = slot(point).zip(Draw::new(0)).is_some_and(|(slot, draw)| {
            ROGUE.with_borrow(|rogue| {
                rogue.decide(slot, Duration::ZERO, draw) == Decision::Inject(Fault::Raise)
            })
        });
        if injected {
            return Err(Error::JailOperation(format!("injected fault at {point:?}")));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
