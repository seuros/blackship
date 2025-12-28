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

impl State {
    /// Parse state from string representation
    pub fn from_str(s: &str) -> Self {
        match s {
            "Stopped" => State::Stopped,
            "Starting" => State::Starting,
            "Running" => State::Running,
            "Stopping" => State::Stopping,
            "Failed" => State::Failed,
            _ => State::Stopped, // Fallback
        }
    }
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

/// Runtime data for a jail instance using dynamic dispatch
pub struct JailInstance {
    /// The state machine (dynamic mode with unit context)
    pub machine: DynamicJailMachine<()>,
    /// Configuration (stored for introspection via public field access)
    #[allow(dead_code)]
    pub config: JailConfig,
    /// Jail ID (when running)
    pub jid: Option<i32>,
}

impl JailInstance {
    pub fn new(config: JailConfig) -> Self {
        // Create typestate machine and convert to dynamic for runtime flexibility
        let machine = JailMachine::new(()).into_dynamic();
        Self {
            machine,
            config,
            jid: None,
        }
    }

    /// Get current state as enum
    pub fn state(&self) -> State {
        State::from_str(self.machine.current_state())
    }

    /// Check if the jail is currently in Running state
    #[allow(dead_code)]
    pub fn is_running(&self) -> bool {
        self.machine.current_state() == "Running"
    }

    /// Trigger start event
    pub fn start(&mut self) -> Result<(), state_machines::DynamicError> {
        self.machine.handle(JailMachineEvent::Start)
    }

    /// Trigger started event (transition to Running)
    pub fn started(&mut self) -> Result<(), state_machines::DynamicError> {
        self.machine.handle(JailMachineEvent::Started)
    }

    /// Trigger stop event
    pub fn stop(&mut self) -> Result<(), state_machines::DynamicError> {
        self.machine.handle(JailMachineEvent::Stop)
    }

    /// Trigger stopped event (transition to Stopped)
    pub fn stopped(&mut self) -> Result<(), state_machines::DynamicError> {
        self.machine.handle(JailMachineEvent::Stopped)
    }

    /// Trigger fail event
    pub fn fail(&mut self) -> Result<(), state_machines::DynamicError> {
        self.machine.handle(JailMachineEvent::Fail)
    }

    /// Trigger recover event
    pub fn recover(&mut self) -> Result<(), state_machines::DynamicError> {
        self.machine.handle(JailMachineEvent::Recover)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let machine = JailMachine::new(()).into_dynamic();
        assert_eq!(machine.current_state(), "Stopped");
    }

    #[test]
    fn test_start_transition() {
        let mut machine = JailMachine::new(()).into_dynamic();
        assert!(machine.handle(JailMachineEvent::Start).is_ok());
        assert_eq!(machine.current_state(), "Starting");
    }

    #[test]
    fn test_full_lifecycle() {
        let mut machine = JailMachine::new(()).into_dynamic();

        // Start
        machine.handle(JailMachineEvent::Start).unwrap();
        assert_eq!(machine.current_state(), "Starting");

        // Started
        machine.handle(JailMachineEvent::Started).unwrap();
        assert_eq!(machine.current_state(), "Running");

        // Stop
        machine.handle(JailMachineEvent::Stop).unwrap();
        assert_eq!(machine.current_state(), "Stopping");

        // Stopped
        machine.handle(JailMachineEvent::Stopped).unwrap();
        assert_eq!(machine.current_state(), "Stopped");
    }

    #[test]
    fn test_fail_and_recover() {
        let mut machine = JailMachine::new(()).into_dynamic();

        machine.handle(JailMachineEvent::Start).unwrap();
        machine.handle(JailMachineEvent::Fail).unwrap();
        assert_eq!(machine.current_state(), "Failed");

        machine.handle(JailMachineEvent::Recover).unwrap();
        assert_eq!(machine.current_state(), "Stopped");
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
