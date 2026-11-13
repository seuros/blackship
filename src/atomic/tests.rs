use super::*;
use std::os::unix::fs::PermissionsExt;

#[test]
fn state_files_stay_readable_by_unprivileged_commands() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("state.toml");
    write_atomic(&target, "a = 1\n", "state").unwrap();

    let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o644);
}

#[test]
fn parent_or_dot_keeps_temp_files_beside_the_target() {
    assert_eq!(
        parent_or_dot(Path::new("/var/state/a.toml")),
        Path::new("/var/state")
    );
    assert_eq!(parent_or_dot(Path::new("a.toml")), Path::new("."));
}
