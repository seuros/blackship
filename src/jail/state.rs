//! Jail state machine
//!
//! Type-safe state machine for jail lifecycle management using state-machines crate.
//! Uses dynamic dispatch mode for runtime flexibility with external events.

use std::path::PathBuf;

use state_machines::state_machine;

state_machine! {
    name: JailMachine,
    dynamic: true,  // Enable runtime dispatch for event-driven jail management
    initial: Stopped,
    states: [Stopped, Starting, Running, Draining, Stopping, Failed],
    events {
        start {
            transition: { from: Stopped, to: Starting }
        }
        started {
            transition: { from: Starting, to: Running }
        }
        drain {
            transition: { from: Running, to: Draining }
        }
        stop {
            transition: { from: [Running, Draining], to: Stopping }
        }
        stopped {
            transition: { from: Stopping, to: Stopped }
        }
        fail {
            transition: { from: [Starting, Running, Draining, Stopping], to: Failed }
        }
        recover {
            transition: { from: Failed, to: Stopped }
        }
    }
}

/// Simple state enum for external use (backwards compatible)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Stopped,
    Starting,
    Running,
    Draining,
    Stopping,
    Failed,
}

/// Configuration for a jail instance
#[derive(Debug, Clone)]
pub struct JailConfig {
    /// Unique name for the jail
    pub name: String,
    /// Path to the jail root filesystem
    pub path: PathBuf,
    /// Hostname for the jail
    pub hostname: Option<String>,
    /// IP addresses assigned to the jail
    pub ips: Vec<std::net::IpAddr>,
}

impl JailConfig {
    pub fn new(name: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
            hostname: None,
            ips: Vec::new(),
        }
    }

    pub fn hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    pub fn ip(mut self, addr: std::net::IpAddr) -> Self {
        self.ips.push(addr);
        self
    }
}

/// Handle to a running jail - either a legacy JID or an owning descriptor
#[derive(Debug)]
pub enum JailHandle {
    /// Legacy JID-based reference (FreeBSD < 16)
    Jid(i32),
    /// Owning descriptor (FreeBSD 16+) - jail is removed when dropped
    Descriptor {
        fd: super::ffi::JailDescriptor,
        jid: i32,
    },
}

impl JailHandle {
    /// Get the JID regardless of handle type
    pub fn jid(&self) -> i32 {
        match self {
            JailHandle::Jid(jid) => *jid,
            JailHandle::Descriptor { jid, .. } => *jid,
        }
    }

    /// The descriptor fd, when this handle owns one.
    pub fn descriptor_fd(&self) -> Option<i32> {
        match self {
            JailHandle::Jid(_) => None,
            JailHandle::Descriptor { fd, .. } => Some(fd.as_raw_fd()),
        }
    }
}

/// Runtime data for a jail instance using dynamic dispatch
pub struct JailInstance {
    /// The state machine (dynamic mode with unit context)
    pub machine: DynamicJailMachine<()>,
    /// Configuration the jail was created with
    pub config: JailConfig,
    /// Jail ID (when running) - kept for backward compatibility
    pub jid: Option<i32>,
    /// Jail handle (descriptor or JID)
    pub handle: Option<JailHandle>,
}

impl JailInstance {
    pub fn new(config: JailConfig) -> Self {
        // Create typestate machine and convert to dynamic for runtime flexibility
        let machine = JailMachine::new(()).into_dynamic();
        Self {
            machine,
            config,
            jid: None,
            handle: None,
        }
    }

    /// Get current state as enum
    pub fn state(&self) -> State {
        match self.machine.current_state() {
            JailMachineState::Stopped => State::Stopped,
            JailMachineState::Starting => State::Starting,
            JailMachineState::Running => State::Running,
            JailMachineState::Draining => State::Draining,
            JailMachineState::Stopping => State::Stopping,
            JailMachineState::Failed => State::Failed,
        }
    }

    /// Check if the jail is currently in Running state
    pub fn is_running(&self) -> bool {
        self.machine.current_state() == JailMachineState::Running
    }

    /// Dispatch a jail machine event
    fn send(&mut self, event: JailMachineEvent) -> Result<(), state_machines::DynamicError> {
        self.machine.handle(event)
    }

    /// Trigger start event
    pub fn start(&mut self) -> Result<(), state_machines::DynamicError> {
        self.send(JailMachineEvent::Start)
    }

    /// Trigger started event (transition to Running)
    pub fn started(&mut self) -> Result<(), state_machines::DynamicError> {
        self.send(JailMachineEvent::Started)
    }

    /// Trigger drain event (Running -> Draining)
    pub fn drain(&mut self) -> Result<(), state_machines::DynamicError> {
        self.send(JailMachineEvent::Drain)
    }

    /// Trigger stop event
    pub fn stop(&mut self) -> Result<(), state_machines::DynamicError> {
        self.send(JailMachineEvent::Stop)
    }

    /// Trigger stopped event (transition to Stopped)
    pub fn stopped(&mut self) -> Result<(), state_machines::DynamicError> {
        self.send(JailMachineEvent::Stopped)
    }

    /// Trigger fail event
    pub fn fail(&mut self) -> Result<(), state_machines::DynamicError> {
        self.send(JailMachineEvent::Fail)
    }

    /// Trigger recover event
    pub fn recover(&mut self) -> Result<(), state_machines::DynamicError> {
        self.send(JailMachineEvent::Recover)
    }
}

#[cfg(test)]
mod tests;
