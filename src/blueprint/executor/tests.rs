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
    let jailfile = Jailfile::from_release("15.1-RELEASE").run("echo test");

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

    let jailfile = Jailfile::from_release("15.1-RELEASE")
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

/// A real executor over a scratch root whose `jail/escape` points at `outside`.
fn escape_fixture() -> (tempfile::TempDir, TemplateExecutor) {
    let dir = tempfile::tempdir().expect("scratch dir");
    let context = dir.path().join("context");
    let jail = dir.path().join("jail");
    let outside = dir.path().join("outside");
    for d in [&context, &jail, &outside] {
        fs::create_dir(d).unwrap();
    }
    fs::write(context.join("file.txt"), "payload").unwrap();
    std::os::unix::fs::symlink(&outside, jail.join("escape")).unwrap();

    let executor = TemplateExecutor::new(BuildContext::new(&context, &jail, "test"));
    (dir, executor)
}

fn outside_is_empty(dir: &tempfile::TempDir) -> bool {
    fs::read_dir(dir.path().join("outside"))
        .unwrap()
        .next()
        .is_none()
}

#[test]
fn workdir_creates_inside_the_jail() {
    let (dir, mut executor) = escape_fixture();
    executor
        .execute_instruction(&Instruction::Workdir("/app/data".into()))
        .unwrap();
    assert!(dir.path().join("jail/app/data").is_dir());
}

/// Where the fixture's `escape` link (an absolute path on the host) lands when
/// followed the way the jail sees it: re-rooted under the jail root.
fn rerooted_outside(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let outside = dir.path().join("outside");
    dir.path()
        .join("jail")
        .join(outside.strip_prefix("/").unwrap())
}

#[test]
fn workdir_and_volume_keep_symlinks_inside_the_jail() {
    let (dir, mut executor) = escape_fixture();
    for instruction in [
        Instruction::Workdir("/escape/pwned".into()),
        Instruction::Volume("/escape/pwned".into()),
    ] {
        executor.execute_instruction(&instruction).unwrap();
    }
    assert!(outside_is_empty(&dir));
    assert!(rerooted_outside(&dir).join("pwned").is_dir());
}

#[test]
fn copy_keeps_symlinks_inside_the_jail() {
    let (dir, mut executor) = escape_fixture();
    let copy = Instruction::Copy(CopySpec::new("file.txt", "/escape/file.txt"));
    executor.execute_instruction(&copy).unwrap();
    assert!(outside_is_empty(&dir));
    assert_eq!(
        fs::read_to_string(rerooted_outside(&dir).join("file.txt")).unwrap(),
        "payload"
    );
}

#[test]
fn copy_lands_inside_the_jail() {
    let (dir, mut executor) = escape_fixture();
    let copy = Instruction::Copy(CopySpec::new("file.txt", "/etc/file.txt"));
    executor.execute_instruction(&copy).unwrap();
    assert_eq!(
        fs::read_to_string(dir.path().join("jail/etc/file.txt")).unwrap(),
        "payload"
    );
}

#[test]
fn writes_refuse_a_missing_jail_root() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = BuildContext::new(dir.path(), &dir.path().join("gone"), "test");
    let mut executor = TemplateExecutor::new(ctx);
    assert!(
        executor
            .execute_instruction(&Instruction::Workdir("/app".into()))
            .is_err()
    );
    assert!(!dir.path().join("gone").exists());
}

#[test]
fn owners_resolve_against_the_jail_not_the_host() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("etc")).unwrap();
    fs::write(
        dir.path().join("etc/passwd"),
        "# jail users\nroot:*:0:0::0:0:Charlie &:/root:/bin/sh\napp:*:1042:1042::0:0:App:/home/app:/bin/sh\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("etc/group"),
        "wheel:*:0:root\napp:*:1042:\nwww:*:80:\n",
    )
    .unwrap();

    let root = dir.path();
    assert_eq!(resolve_owner(root, "app").unwrap(), (Some(1042), None));
    assert_eq!(
        resolve_owner(root, "app:www").unwrap(),
        (Some(1042), Some(80))
    );
    assert_eq!(resolve_owner(root, ":wheel").unwrap(), (None, Some(0)));
    assert_eq!(
        resolve_owner(root, "2000:2001").unwrap(),
        (Some(2000), Some(2001))
    );
    // Exists on most hosts, not in this jail: must not borrow the host's id.
    assert!(resolve_owner(root, "nobody").is_err());
    assert!(resolve_owner(root, "app:nogroup").is_err());
}
