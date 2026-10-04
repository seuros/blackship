use super::*;

#[test]
#[ignore] // Requires a running jail
fn test_jexec_basic() {
    // This test requires a jail with JID 1 to be running
    // Run: sudo jail -c name=test path=/tmp persist
    let result = jexec_with_output(1, &["echo", "hello"]);
    assert!(result.is_ok());

    if let Ok((exit_code, stdout, _stderr)) = result {
        assert_eq!(exit_code, 0);
        assert_eq!(String::from_utf8_lossy(&stdout).trim(), "hello");
    }
}
