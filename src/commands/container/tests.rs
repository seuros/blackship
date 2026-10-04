use super::*;

#[test]
fn test_parse_jail_path_with_jail() {
    let (jail, path) = parse_jail_path("myjail:/etc/hosts");
    assert_eq!(jail, Some("myjail".to_string()));
    assert_eq!(path, "/etc/hosts");
}

#[test]
fn test_parse_jail_path_host_only() {
    let (jail, path) = parse_jail_path("/etc/hosts");
    assert_eq!(jail, None);
    assert_eq!(path, "/etc/hosts");
}

#[test]
fn test_parse_jail_path_multiple_colons() {
    // Path with multiple colons - first colon determines split
    let (jail, path) = parse_jail_path("myjail:/path/with:colon");
    assert_eq!(jail, Some("myjail".to_string()));
    assert_eq!(path, "/path/with:colon");
}

#[test]
fn test_parse_jail_path_empty_path() {
    let (jail, path) = parse_jail_path("myjail:");
    assert_eq!(jail, Some("myjail".to_string()));
    assert_eq!(path, "");
}

#[test]
fn test_parse_jail_path_relative() {
    let (jail, path) = parse_jail_path("./local/file");
    assert_eq!(jail, None);
    assert_eq!(path, "./local/file");
}
