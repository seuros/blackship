//! The migration as a saga: stage, snapshot, transfer, fence.
//!
//! Every forward step looks at the real state before it acts, so the same code runs a
//! fresh migration and a resume after a kill. The fence is last: until it is set the
//! jail stays runnable here, and only the source side is ever fenced.

use std::fmt;

use saga_machines::{Action, Kind, Outcome, Progress, Refusal, Saga};

use super::record::{Record, RecordStore};
use crate::error::{Error, Result};
use crate::fault::{self, Point};

pub const STEPS: usize = 4;

/// Compensation attempts before the migration is parked.
const COMPENSATION_ATTEMPTS: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Stage,
    Snapshot,
    Transfer,
    Fence,
}

impl Step {
    pub const fn of(index: usize) -> Option<Self> {
        match index {
            0 => Some(Self::Stage),
            1 => Some(Self::Snapshot),
            2 => Some(Self::Transfer),
            3 => Some(Self::Fence),
            _ => None,
        }
    }
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Stage => "stage",
            Self::Snapshot => "snapshot",
            Self::Transfer => "transfer",
            Self::Fence => "fence",
        })
    }
}

/// What the destination holds under the migration's dataset name.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Remote {
    #[default]
    Absent,
    /// The dataset exists without the migration snapshot: an interrupted receive.
    Partial,
    Complete,
}

/// Every effect and every question about the real world. A failed probe is an `Err`,
/// never "absent": an unreachable host must not read as an empty one.
pub trait Effects {
    /// Stage the jail definition in the dataset; false when there was nothing to stage.
    fn stage(&mut self) -> bool;
    fn snapshot_exists(&mut self) -> Result<bool>;
    fn create_snapshot(&mut self) -> Result<()>;
    fn delete_snapshot(&mut self) -> Result<()>;
    fn remote(&mut self) -> Result<Remote>;
    fn transfer(&mut self) -> Result<()>;
    /// Destroy the destination dataset; `Err` unless it is verifiably gone.
    fn discard_destination(&mut self) -> Result<()>;
    fn fence_state(&mut self) -> Result<Option<String>>;
    fn fence(&mut self, destination: &str) -> Result<()>;
    fn clear_fence(&mut self) -> Result<()>;
}

pub enum Settled {
    Completed,
    /// Everything that ran was undone. `failed` is the forward failure of this run.
    RolledBack {
        failed: Option<(Step, Error)>,
    },
}

pub struct Driver<'a, E: Effects> {
    effects: E,
    record: Record,
    store: &'a RecordStore,
    saga: Saga<STEPS>,
    failure: Option<(Step, Error)>,
    refused: u32,
}

fn refused(r: Refusal) -> Error {
    Error::State(format!("The migration saga refused a step: {r:?}"))
}

pub const fn saga_id(jail: &str) -> saga_machines::SagaId {
    saga_machines::SagaId::from_bytes(jail.as_bytes())
}

impl<'a, E: Effects> Driver<'a, E> {
    /// Rebuild the driver from a record; a saga state no saga could have saved is refused.
    pub fn restore(effects: E, record: Record, store: &'a RecordStore) -> Result<Self> {
        let saga = Saga::<STEPS>::restored(record.saga, 0)
            .filter(|saga| saga.id() == saga_id(&record.jail))
            .ok_or_else(|| {
                Error::State(format!(
                    "Migration record for '{}' holds a saga state that cannot be restored; it was left untouched",
                    record.jail
                ))
            })?;
        Ok(Self {
            effects,
            record,
            store,
            saga,
            failure: None,
            refused: 0,
        })
    }

    pub const fn record(&self) -> &Record {
        &self.record
    }

    fn persist(&mut self) -> Result<()> {
        self.record.saga = self.saga.snapshot();
        self.store.save(&self.record)
    }

    /// Run the saga until it settles or parks.
    pub fn drive(&mut self) -> Result<Settled> {
        while let Some(action) = self.saga.next_action().map_err(refused)? {
            self.persist()?;
            let outcome = self.perform(action)?;
            if action.kind() == Kind::Forward {
                match Step::of(action.step()) {
                    Some(Step::Snapshot) => fault::trip(Point::AfterSnapshot)?,
                    Some(Step::Transfer) => fault::trip(Point::AfterSend)?,
                    _ => {}
                }
            }
            self.saga.resolve(action, outcome).map_err(refused)?;
            self.persist()?;
        }
        self.conclude()
    }

    fn conclude(&mut self) -> Result<Settled> {
        match self.saga.progress() {
            Progress::Complete => {
                self.settle();
                Ok(Settled::Completed)
            }
            Progress::Aborted => {
                self.settle();
                Ok(Settled::RolledBack {
                    failed: self.failure.take(),
                })
            }
            Progress::Stuck(step) => {
                self.persist()?;
                Err(self.parked_error(step))
            }
            Progress::Forward(_) | Progress::Compensating(_) => Err(Error::State(
                "The migration saga stopped before it settled".to_string(),
            )),
        }
    }

    fn settle(&self) {
        let _ = self.store.delete(&self.record.jail);
    }

    fn parked_error(&self, step: usize) -> Error {
        let what = Step::of(step).map_or_else(|| step.to_string(), |s| s.to_string());
        let path = self
            .store
            .path(&self.record.jail)
            .map_or_else(|_| String::new(), |p| p.display().to_string());
        Error::JailOperation(format!(
            "Migration of '{jail}' is PARKED: undoing the {what} step failed ({reason}). \
             Leftovers may remain on this host or on {target}; the record is kept at {path}. \
             Fix the cause, then run 'blackship migrate --abort {jail}'",
            jail = self.record.jail,
            reason = self
                .record
                .parked
                .as_deref()
                .unwrap_or("no reason recorded"),
            target = self.record.target,
        ))
    }

    fn perform(&mut self, action: Action) -> Result<Outcome> {
        let Some(step) = Step::of(action.step()) else {
            return Err(Error::State(format!(
                "Migration step {} does not exist",
                action.step()
            )));
        };
        match action.kind() {
            Kind::Forward => self.forward(step),
            Kind::Compensate => Ok(self.compensate(step)),
        }
    }

    fn forward(&mut self, step: Step) -> Result<Outcome> {
        match step {
            Step::Stage => Ok(if self.effects.stage() {
                Outcome::Success
            } else {
                Outcome::Skipped
            }),
            Step::Snapshot => {
                if self.effects.snapshot_exists()? {
                    return Ok(Outcome::Success);
                }
                Ok(self.settle_effect(step, Effects::create_snapshot))
            }
            Step::Transfer => self.transfer(),
            Step::Fence => self.fence(),
        }
    }

    fn settle_effect(&mut self, step: Step, effect: impl FnOnce(&mut E) -> Result<()>) -> Outcome {
        match effect(&mut self.effects) {
            Ok(()) => Outcome::Success,
            Err(e) => {
                self.failure = Some((step, e));
                Outcome::Failure
            }
        }
    }

    fn transfer(&mut self) -> Result<Outcome> {
        match self.effects.remote()? {
            Remote::Complete => return Ok(Outcome::Success),
            Remote::Partial => self.effects.discard_destination()?,
            Remote::Absent => {}
        }
        let Err(sent) = self.effects.transfer() else {
            return Ok(Outcome::Success);
        };
        if self.effects.discard_destination().is_err() {
            return Err(Error::JailOperation(format!(
                "Migration transfer failed ({sent}); the source is untouched and the remote dataset may be partial. \
                 The record is kept: run 'blackship migrate --abort {}' once {} is reachable",
                self.record.jail, self.record.target
            )));
        }
        self.failure = Some((Step::Transfer, sent));
        Ok(Outcome::Failure)
    }

    fn fence(&mut self) -> Result<Outcome> {
        let destination = if let Some(value) = &self.record.fence {
            value.clone()
        } else {
            let value = super::fence_value(
                &self.record.target,
                &self.record.remote_dataset,
                crate::scope::now_unix(),
            );
            self.record.fence = Some(value.clone());
            self.persist()?;
            value
        };
        fault::trip(Point::BeforeFence)?;
        if let Some(holder) = self.effects.fence_state()?
            && holder != destination
        {
            self.failure = Some((
                Step::Fence,
                Error::JailOperation(format!(
                    "'{}' is already fenced for a different migration ({holder})",
                    self.record.jail
                )),
            ));
            return Ok(Outcome::Failure);
        }
        Ok(self.settle_effect(Step::Fence, |effects| effects.fence(&destination)))
    }

    fn compensate(&mut self, step: Step) -> Outcome {
        let undone = match step {
            Step::Stage => Ok(()),
            Step::Snapshot => self.effects.snapshot_exists().and_then(|exists| {
                if exists {
                    self.effects.delete_snapshot()
                } else {
                    Ok(())
                }
            }),
            Step::Transfer => self.effects.discard_destination(),
            Step::Fence => self.effects.clear_fence(),
        };
        let Err(e) = undone else {
            self.refused = 0;
            return Outcome::Success;
        };
        eprintln!("Warning: could not undo the {step} step: {e}");
        self.refused += 1;
        if self.refused < COMPENSATION_ATTEMPTS {
            return Outcome::Failure;
        }
        self.refused = 0;
        self.record.parked = Some(e.to_string());
        Outcome::Stuck
    }

    /// Roll the migration back: settle what the real world shows the in-flight step
    /// already did, stop going forward, and compensate in reverse.
    pub fn abort(&mut self) -> Result<Settled> {
        match self.saga.progress() {
            Progress::Complete => {
                self.settle();
                Err(Error::JailOperation(format!(
                    "Migration of '{}' had already completed: the source is fenced and the copy lives on {}. \
                     To undo it, run 'blackship unfence {}' after making sure the copy is not running",
                    self.record.jail, self.record.target, self.record.service
                )))
            }
            Progress::Aborted => self.conclude(),
            Progress::Stuck(step) => self.abort_parked(step),
            Progress::Compensating(_) => self.drive(),
            Progress::Forward(step) => {
                self.reconcile_in_flight(step)?;
                if matches!(self.saga.progress(), Progress::Complete) {
                    return self.abort();
                }
                self.saga.cancel().map_err(refused)?;
                self.persist()?;
                self.drive()
            }
        }
    }

    /// The in-flight step may have taken effect before the kill: if the real state
    /// shows it did, record it as done so it is compensated rather than forgotten.
    fn reconcile_in_flight(&mut self, step: usize) -> Result<()> {
        let done = match Step::of(step) {
            Some(Step::Snapshot) => self.effects.snapshot_exists()?,
            Some(Step::Transfer) => self.effects.remote()? != Remote::Absent,
            Some(Step::Fence) => {
                let held = self.effects.fence_state()?;
                held.is_some() && held == self.record.fence
            }
            Some(Step::Stage) | None => false,
        };
        if !done {
            return Ok(());
        }
        let Some(action) = self.saga.next_action().map_err(refused)? else {
            return Ok(());
        };
        self.saga
            .resolve(action, Outcome::Success)
            .map_err(refused)?;
        self.persist()
    }

    /// A parked saga cannot issue another compensation. When the real world shows
    /// nothing is left to undo, the record has nothing left to say.
    fn abort_parked(&mut self, stuck: usize) -> Result<Settled> {
        let skipped = self.saga.skipped();
        let ran = |step: usize| stuck >= step && skipped & (1 << step) == 0;
        let mut left = Vec::new();
        if ran(1) && self.effects.snapshot_exists()? {
            left.push(format!("snapshot {}", self.record.snapshot_ref()));
        }
        if ran(2) && self.effects.remote()? != Remote::Absent {
            left.push(format!(
                "dataset {} on {}",
                self.record.remote_dataset, self.record.target
            ));
        }
        if !left.is_empty() {
            return Err(Error::JailOperation(format!(
                "Migration of '{}' is parked and still holds: {}. Remove them by hand, then run 'blackship migrate --abort {}' again",
                self.record.jail,
                left.join(", "),
                self.record.jail
            )));
        }
        self.settle();
        Ok(Settled::RolledBack { failed: None })
    }
}

#[cfg(test)]
mod tests;
