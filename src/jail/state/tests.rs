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
fn test_drain_before_stop() {
    let mut machine = JailMachine::new(()).into_dynamic();
    machine.handle(JailMachineEvent::Start).unwrap();
    machine.handle(JailMachineEvent::Started).unwrap();

    machine.handle(JailMachineEvent::Drain).unwrap();
    assert_eq!(machine.current_state(), JailMachineState::Draining);
    assert!(machine.handle(JailMachineEvent::Drain).is_err());

    machine.handle(JailMachineEvent::Stop).unwrap();
    assert_eq!(machine.current_state(), JailMachineState::Stopping);
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

#[test]
fn test_schema_validates_without_errors() {
    let diagnostics = JailMachine::<(), Stopped>::schema().validate();
    let errors: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.level == state_machines::DiagnosticLevel::Error)
        .collect();
    assert!(errors.is_empty(), "schema errors: {:?}", errors);
}
