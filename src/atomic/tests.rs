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
