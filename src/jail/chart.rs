//! Jail lifecycle and health as one statechart.

use harel_machines::{Chart, Configuration, State, StateId, Transition, TransitionKind};
use thiserror::Error;

use super::state::JailMachineState;
use crate::sickbay::checker::HealthStatus;

/// Every state of the jail chart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Node {
    Jail,
    Down,
    Stopped,
    Failed,
    Up,
    Starting,
    Running,
    Healthy,
    Unhealthy,
    Failing,
    Suspended,
    Draining,
    Stopping,
}

impl Node {
    const ALL: [Self; STATES] = [
        Self::Jail,
        Self::Down,
        Self::Stopped,
        Self::Failed,
        Self::Up,
        Self::Starting,
        Self::Running,
        Self::Healthy,
        Self::Unhealthy,
        Self::Failing,
        Self::Suspended,
        Self::Draining,
        Self::Stopping,
    ];

    const fn id(self) -> StateId {
        self as StateId
    }

    fn from_id(id: StateId) -> Option<Self> {
        Self::ALL.get(usize::from(id)).copied()
    }
}

/// Health leaves inside `Running`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Health {
    #[default]
    Healthy,
    Unhealthy,
    Failing,
    Suspended,
}

impl Health {
    const fn node(self) -> Node {
        match self {
            Self::Healthy => Node::Healthy,
            Self::Unhealthy => Node::Unhealthy,
            Self::Failing => Node::Failing,
            Self::Suspended => Node::Suspended,
        }
    }
}

/// `Starting` and `Unknown` carry no verdict yet, so they sit in the chart's initial `Healthy` leaf.
impl From<HealthStatus> for Health {
    fn from(status: HealthStatus) -> Self {
        match status {
            HealthStatus::Starting | HealthStatus::Unknown | HealthStatus::Healthy => Self::Healthy,
            HealthStatus::Unhealthy => Self::Unhealthy,
            HealthStatus::Failing => Self::Failing,
            HealthStatus::Suspended => Self::Suspended,
        }
    }
}

/// Why a step could not be resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Error {
    #[error("no move from {from:?} to {to:?}")]
    Illegal {
        from: JailMachineState,
        to: JailMachineState,
    },
    #[error("malformed jail chart: {0}")]
    Chart(harel_machines::Error),
}

impl From<harel_machines::Error> for Error {
    fn from(error: harel_machines::Error) -> Self {
        Self::Chart(error)
    }
}

const STATES: usize = 13;

/// The jail chart.
pub const CHART: Chart<STATES> = Chart::new([
    State::compound(None, Node::Down.id()),
    State::compound(Some(Node::Jail.id()), Node::Stopped.id()),
    State::atomic(Some(Node::Down.id())),
    State::atomic(Some(Node::Down.id())),
    State::compound(Some(Node::Jail.id()), Node::Starting.id()),
    State::atomic(Some(Node::Up.id())),
    State::compound(Some(Node::Up.id()), Node::Healthy.id()),
    State::atomic(Some(Node::Running.id())),
    State::atomic(Some(Node::Running.id())),
    State::atomic(Some(Node::Running.id())),
    State::atomic(Some(Node::Running.id())),
    State::atomic(Some(Node::Up.id())),
    State::atomic(Some(Node::Up.id())),
]);

/// Whether the lifecycle allows moving from one phase to the next.
#[must_use]
pub const fn allows(from: JailMachineState, to: JailMachineState) -> bool {
    use JailMachineState::{Draining, Failed, Running, Starting, Stopped, Stopping};
    matches!(
        (from, to),
        (Stopped, Starting)
            | (Starting, Running | Failed)
            | (Running, Draining | Stopping | Failed)
            | (Draining, Stopping | Failed)
            | (Stopping, Stopped | Failed)
            | (Failed, Stopped)
    )
}

const fn phase_node(state: JailMachineState) -> Node {
    match state {
        JailMachineState::Stopped => Node::Stopped,
        JailMachineState::Starting => Node::Starting,
        JailMachineState::Running => Node::Running,
        JailMachineState::Draining => Node::Draining,
        JailMachineState::Stopping => Node::Stopping,
        JailMachineState::Failed => Node::Failed,
    }
}

/// The states a move leaves and joins, as chart nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Step(Transition<STATES>);

impl Step {
    fn resolve(from: Node, to: Node) -> Result<Self, Error> {
        let mut active = Configuration::new();
        active.insert(from.id());
        let transition = CHART.resolve(&active, from.id(), to.id(), TransitionKind::External)?;
        Ok(Self(transition))
    }

    /// Resolve a lifecycle move; `health` is the leaf held while leaving `Running`.
    pub fn phase(
        from: JailMachineState,
        health: Health,
        to: JailMachineState,
    ) -> Result<Self, Error> {
        if !allows(from, to) {
            return Err(Error::Illegal { from, to });
        }
        let source = if from == JailMachineState::Running {
            health.node()
        } else {
            phase_node(from)
        };
        Self::resolve(source, phase_node(to))
    }

    /// Resolve a health change inside `Running`.
    pub fn health(from: Health, to: Health) -> Result<Self, Error> {
        Self::resolve(from.node(), to.node())
    }

    /// Nodes to leave, innermost first.
    pub fn exit(&self) -> impl Iterator<Item = Node> + '_ {
        self.0.exit().iter().copied().filter_map(Node::from_id)
    }

    #[cfg(test)]
    /// Nodes to join, outermost first, ending at a leaf.
    pub fn entry(&self) -> impl Iterator<Item = Node> + '_ {
        self.0.entry().iter().copied().filter_map(Node::from_id)
    }

    #[cfg(test)]
    /// The leaf the jail rests in afterwards.
    #[must_use]
    pub fn leaf(&self) -> Option<Node> {
        self.0
            .configuration()
            .as_slice()
            .first()
            .copied()
            .and_then(Node::from_id)
    }
}

#[cfg(test)]
mod tests;
