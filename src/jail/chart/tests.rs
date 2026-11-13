use super::*;
use crate::jail::state::{DynamicJailMachine, JailInstance, JailMachine, JailMachineEvent};
use JailMachineState::{Draining, Failed, Running, Starting, Stopped, Stopping};

const PHASES: [JailMachineState; 6] = [Stopped, Starting, Running, Draining, Stopping, Failed];

fn events() -> [JailMachineEvent; 7] {
    [
        JailMachineEvent::Start,
        JailMachineEvent::Started,
        JailMachineEvent::Drain,
        JailMachineEvent::Stop,
        JailMachineEvent::Stopped,
        JailMachineEvent::Fail,
        JailMachineEvent::Recover,
    ]
}

const HEALTHS: [Health; 4] = [
    Health::Healthy,
    Health::Unhealthy,
    Health::Failing,
    Health::Suspended,
];

fn exits(step: &Step) -> Vec<Node> {
    step.exit().collect()
}

fn entries(step: &Step) -> Vec<Node> {
    step.entry().collect()
}

fn machine_in(state: JailMachineState) -> DynamicJailMachine<()> {
    let route: Vec<JailMachineEvent> = match state {
        Stopped => vec![],
        Starting => vec![JailMachineEvent::Start],
        Running => vec![JailMachineEvent::Start, JailMachineEvent::Started],
        Draining => vec![
            JailMachineEvent::Start,
            JailMachineEvent::Started,
            JailMachineEvent::Drain,
        ],
        Stopping => vec![
            JailMachineEvent::Start,
            JailMachineEvent::Started,
            JailMachineEvent::Stop,
        ],
        Failed => vec![JailMachineEvent::Start, JailMachineEvent::Fail],
    };
    let mut machine = JailMachine::new(()).into_dynamic();
    for event in route {
        machine.handle(event).unwrap();
    }
    assert_eq!(machine.current_state(), state);
    machine
}

#[test]
fn start_enters_up_at_starting() {
    let step = Step::phase(Stopped, Health::Healthy, Starting).unwrap();
    assert_eq!(exits(&step), [Node::Stopped, Node::Down]);
    assert_eq!(entries(&step), [Node::Up, Node::Starting]);
    assert_eq!(step.leaf(), Some(Node::Starting));
}

#[test]
fn started_descends_to_healthy() {
    let step = Step::phase(Starting, Health::Healthy, Running).unwrap();
    assert_eq!(exits(&step), [Node::Starting]);
    assert_eq!(entries(&step), [Node::Running, Node::Healthy]);
}

#[test]
fn drain_leaves_running_from_any_health() {
    for health in HEALTHS {
        let step = Step::phase(Running, health, Draining).unwrap();
        assert_eq!(exits(&step), [health.node(), Node::Running]);
        assert_eq!(entries(&step), [Node::Draining]);
    }
}

#[test]
fn stop_from_running_and_draining_stays_in_up() {
    let step = Step::phase(Running, Health::Failing, Stopping).unwrap();
    assert_eq!(exits(&step), [Node::Failing, Node::Running]);
    assert_eq!(entries(&step), [Node::Stopping]);

    let step = Step::phase(Draining, Health::Healthy, Stopping).unwrap();
    assert_eq!(exits(&step), [Node::Draining]);
    assert_eq!(entries(&step), [Node::Stopping]);
}

#[test]
fn stopped_crosses_into_down() {
    let step = Step::phase(Stopping, Health::Healthy, Stopped).unwrap();
    assert_eq!(exits(&step), [Node::Stopping, Node::Up]);
    assert_eq!(entries(&step), [Node::Down, Node::Stopped]);
}

#[test]
fn fail_from_running_healthy_unwinds_health_running_up() {
    let step = Step::phase(Running, Health::Healthy, Failed).unwrap();
    assert_eq!(exits(&step), [Node::Healthy, Node::Running, Node::Up]);
    assert_eq!(entries(&step), [Node::Down, Node::Failed]);
    assert_eq!(step.leaf(), Some(Node::Failed));
}

#[test]
fn fail_from_every_up_phase_exits_up() {
    for from in [Starting, Draining, Stopping] {
        let step = Step::phase(from, Health::Healthy, Failed).unwrap();
        assert_eq!(exits(&step), [phase_node(from), Node::Up]);
        assert_eq!(entries(&step), [Node::Down, Node::Failed]);
    }
}

#[test]
fn recover_stays_inside_down() {
    let step = Step::phase(Failed, Health::Healthy, Stopped).unwrap();
    assert_eq!(exits(&step), [Node::Failed]);
    assert_eq!(entries(&step), [Node::Stopped]);
}

#[test]
fn health_change_stays_inside_running() {
    let step = Step::health(Health::Healthy, Health::Suspended).unwrap();
    assert_eq!(exits(&step), [Node::Healthy]);
    assert_eq!(entries(&step), [Node::Suspended]);
}

#[test]
fn health_status_mapping_defaults_unjudged_to_healthy() {
    assert_eq!(Health::from(HealthStatus::Starting), Health::Healthy);
    assert_eq!(Health::from(HealthStatus::Unknown), Health::Healthy);
    assert_eq!(Health::from(HealthStatus::Failing), Health::Failing);
}

#[test]
fn chart_and_machine_agree_on_legal_moves() {
    for from in PHASES {
        for event in events() {
            let mut machine = machine_in(from);
            let label = format!("{event:?}");
            let outcome = machine.handle(event);
            let to = machine.current_state();
            for health in HEALTHS {
                let step = Step::phase(from, health, to);
                match outcome {
                    Ok(()) => assert!(step.is_ok(), "{from:?} -{label}-> {to:?}"),
                    Err(_) => assert_eq!(to, from),
                }
            }
        }
    }
    for from in PHASES {
        for to in PHASES {
            let reachable = events().into_iter().any(|event| {
                let mut machine = machine_in(from);
                machine.handle(event).is_ok() && machine.current_state() == to
            });
            assert_eq!(allows(from, to), reachable, "{from:?} -> {to:?}");
        }
    }
}

#[test]
fn every_resolved_step_lands_on_a_leaf_of_the_target_phase() {
    for from in PHASES {
        for to in PHASES {
            if let Ok(step) = Step::phase(from, Health::Healthy, to) {
                let leaf = step.leaf().unwrap();
                let expected = if to == Running {
                    Node::Healthy
                } else {
                    phase_node(to)
                };
                assert_eq!(leaf, expected);
            }
        }
    }
}

#[test]
fn instance_records_step_per_event() {
    let mut jail = JailInstance::new(crate::jail::state::JailConfig::new("j", "/tmp/j"));
    assert!(jail.last_step().is_none());
    jail.start().unwrap();
    jail.started().unwrap();
    jail.set_health(HealthStatus::Failing).unwrap();
    assert_eq!(exits(jail.last_step().unwrap()), [Node::Healthy]);
    jail.fail().unwrap();
    let step = jail.last_step().unwrap();
    assert_eq!(exits(step), [Node::Failing, Node::Running, Node::Up]);
    assert_eq!(entries(step), [Node::Down, Node::Failed]);
    assert_eq!(jail.health(), Health::Healthy);
}

#[test]
fn rejected_event_keeps_previous_step() {
    let mut jail = JailInstance::new(crate::jail::state::JailConfig::new("j", "/tmp/j"));
    jail.start().unwrap();
    let before = *jail.last_step().unwrap();
    assert!(jail.recover().is_err());
    assert_eq!(jail.last_step(), Some(&before));
}

#[test]
fn health_requires_running() {
    let mut jail = JailInstance::new(crate::jail::state::JailConfig::new("j", "/tmp/j"));
    assert!(jail.set_health(HealthStatus::Unhealthy).is_err());
}
