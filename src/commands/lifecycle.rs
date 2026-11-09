//! Lifecycle commands: up, down, restart, eva

use serde::Serialize;

use crate::bridge::{Bridge, PlanStep};
use crate::error::{Error, Result};

/// A lifecycle command over one jail (with its dependencies) or all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Up,
    Down,
    Restart,
    Eva,
}

impl Operation {
    const fn name(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Down => "down",
            Self::Restart => "restart",
            Self::Eva => "eva",
        }
    }

    const fn verb(self) -> &'static str {
        match self {
            Self::Up => "start",
            Self::Down => "stop",
            Self::Restart => "restart",
            Self::Eva => "update",
        }
    }

    fn check_selection(self, jail: Option<&str>, all: bool) -> Result<()> {
        if jail.is_none() && !all {
            return Err(Error::InvalidArgument(format!(
                "specify a jail name or use --all to {} all jails",
                self.verb()
            )));
        }
        Ok(())
    }
}

/// The machine-readable answer to a `--dry-run`.
#[derive(Debug, Serialize)]
pub struct Plan {
    operation: &'static str,
    dry_run: bool,
    steps: Vec<PlanStep>,
}

pub fn plan(bridge: &Bridge, op: Operation, jail: Option<&str>, all: bool) -> Result<Plan> {
    op.check_selection(jail, all)?;
    let steps = match op {
        Operation::Up => bridge.start_steps(jail)?,
        Operation::Down => bridge.stop_steps(jail)?,
        Operation::Restart => {
            let mut steps = bridge.stop_steps(jail)?;
            steps.extend(bridge.start_steps(jail)?);
            steps
        }
        Operation::Eva => bridge.eva_steps(jail)?,
    };
    Ok(Plan {
        operation: op.name(),
        dry_run: true,
        steps,
    })
}

pub fn handle(
    bridge: &mut Bridge,
    op: Operation,
    jail: Option<&str>,
    all: bool,
    dry_run: bool,
) -> Result<()> {
    op.check_selection(jail, all)?;
    match (op, dry_run) {
        (Operation::Up, true) => bridge.up_dry_run(jail),
        (Operation::Up, false) => bridge.up(jail),
        (Operation::Down, true) => bridge.down_dry_run(jail),
        (Operation::Down, false) => bridge.down(jail),
        (Operation::Restart, true) => {
            bridge.down_dry_run(jail)?;
            bridge.up_dry_run(jail)
        }
        (Operation::Restart, false) => bridge.restart(jail),
        (Operation::Eva, true) => bridge.eva_dry_run(jail),
        (Operation::Eva, false) => bridge.eva(jail),
    }
}
