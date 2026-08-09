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
    states: [Stopped, Starting, Running, Stopping, Failed],
    events {
        start {
            transition: { from: Stopped, to: Starting }
        }
        started {
            transition: { from: Starting, to: Running }
        }
        stop {
            transition: { from: Running, to: Stopping }
        }
        stopped {
            transition: { from: Stopping, to: Stopped }
        }
        fail {
            transition: { from: [Starting, Running, Stopping], to: Failed }
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
    Stopping,
    Failed,
}

/// Configuration for a jail instance
///
/// Fields are populated during jail creation and stored for introspection.
/// While not all fields are currently read, they provide useful metadata
/// about the jail configuration that may be accessed via the public API.
#[derive(Debug, Clone)]
#[allow(dead_code)]
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
#[allow(dead_code)]
pub enum JailHandle {
    /// Legacy JID-based reference (FreeBSD < 16)
    Jid(i32),
    /// Owning descriptor (FreeBSD 16+) - jail is removed when dropped
    Descriptor {
        fd: super::ffi::JailDescriptor,
        jid: i32,
    },
}

#[allow(dead_code)]
impl JailHandle {
    /// Get the JID regardless of handle type
    pub fn jid(&self) -> i32 {
        match self {
            JailHandle::Jid(jid) => *jid,
            JailHandle::Descriptor { jid, .. } => *jid,
        }
    }
}

/// Runtime data for a jail instance using dynamic dispatch
pub struct JailInstance {
    /// The state machine (dynamic mode with unit context)
    pub machine: DynamicJailMachine<()>,
    /// Configuration (stored for introspection via public field access)
    #[allow(dead_code)]
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
            JailMachineState::Stopping => State::Stopping,
            JailMachineState::Failed => State::Failed,
        }
    }

    /// Check if the jail is currently in Running state
    #[allow(dead_code)]
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
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let machine = JailMachine::new(()).into_dynamic();
        assert_eq!(machine.current_state(), JailMachineState::Stopped);
    }

    #[test]
    fn test_start_transition() {
        let mut machine = JailMachine::new(()).into_dynamic();
        assert!(machine.handle(JailMachineEvent::Start).is_ok());
        assert_eq!(machine.current_state(), JailMachineState::Starting);
    }

    #[test]
    fn test_full_lifecycle() {
        let mut machine = JailMachine::new(()).into_dynamic();

        // Start
        machine.handle(JailMachineEvent::Start).unwrap();
        assert_eq!(machine.current_state(), JailMachineState::Starting);

        // Started
        machine.handle(JailMachineEvent::Started).unwrap();
        assert_eq!(machine.current_state(), JailMachineState::Running);

        // Stop
        machine.handle(JailMachineEvent::Stop).unwrap();
        assert_eq!(machine.current_state(), JailMachineState::Stopping);

        // Stopped
        machine.handle(JailMachineEvent::Stopped).unwrap();
        assert_eq!(machine.current_state(), JailMachineState::Stopped);
    }

    #[test]
    fn test_fail_and_recover() {
        let mut machine = JailMachine::new(()).into_dynamic();

        machine.handle(JailMachineEvent::Start).unwrap();
        machine.handle(JailMachineEvent::Fail).unwrap();
        assert_eq!(machine.current_state(), JailMachineState::Failed);

        machine.handle(JailMachineEvent::Recover).unwrap();
        assert_eq!(machine.current_state(), JailMachineState::Stopped);
    }

    #[test]
    fn test_invalid_transition() {
        let mut machine = JailMachine::new(()).into_dynamic();
        // Can't stop from Stopped state
        assert!(machine.handle(JailMachineEvent::Stop).is_err());
    }

    #[test]
    fn test_jail_instance() {
        let config = JailConfig::new("test", "/jails/test");
        let mut instance = JailInstance::new(config);

        assert_eq!(instance.state(), State::Stopped);

        instance.start().unwrap();
        assert_eq!(instance.state(), State::Starting);

        instance.started().unwrap();
        assert!(instance.is_running());
    }
}
