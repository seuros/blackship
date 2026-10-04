use super::*;

#[test]
fn test_bridge_exists_check() {
    // lo0 should always exist
    assert!(Bridge::exists("lo0").unwrap());
    // random name should not exist
    assert!(!Bridge::exists("nonexistent12345").unwrap());
}
