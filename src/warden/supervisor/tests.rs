use super::machine::{Healthy, Supervisor};

#[test]
fn supervisor_schema_validates_without_errors() {
    let diagnostics = Supervisor::<Healthy>::schema().validate();
    let errors: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.level == state_machines::DiagnosticLevel::Error)
        .collect();
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}
