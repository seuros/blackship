use super::*;
use crate::blueprint::instructions::Jailfile;

#[test]
fn test_executor_creation() {
    let ctx = BuildContext::new(
        Path::new("/build/context"),
        Path::new("/jails/test"),
        "test",
    );
    let executor = TemplateExecutor::new(ctx);
    assert_eq!(executor.context().jail_name(), "test");
}

#[test]
fn test_dry_run_mode() {
    let ctx = BuildContext::new(
        Path::new("/build/context"),
        Path::new("/jails/test"),
        "test",
    );
    let mut executor = TemplateExecutor::new(ctx).dry_run(true);

    // Create a simple jailfile with RUN
    let jailfile = Jailfile::from_release("14.2-RELEASE").run("echo test");

    // Dry run should not fail even with non-existent paths
    let result = executor.execute(&jailfile);
    assert!(result.is_ok());
}

#[test]
fn test_variable_substitution_in_instructions() {
    let ctx = BuildContext::new(
        Path::new("/build/context"),
        Path::new("/jails/test"),
        "myapp",
    );
    let mut executor = TemplateExecutor::new(ctx).dry_run(true);
    executor.context_mut().set_arg("VERSION", "1.0");

    let jailfile = Jailfile::from_release("14.2-RELEASE")
        .arg("VERSION", Some("1.0"))
        .env("APP_VERSION", "${VERSION}")
        .env("APP_NAME", "${JAIL_NAME}");

    executor.execute(&jailfile).unwrap();

    assert_eq!(
        executor.context().env().get("APP_VERSION"),
        Some(&"1.0".to_string())
    );
    assert_eq!(
        executor.context().env().get("APP_NAME"),
        Some(&"myapp".to_string())
    );
}
