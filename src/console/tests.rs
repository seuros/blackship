use super::*;

#[test]
fn test_exec_options_default() {
    let opts = ExecOptions::default();
    assert_eq!(opts.user, "root");
    assert!(opts.workdir.is_none());
    assert!(opts.env.is_empty());
}

#[test]
fn test_is_valid_env_key() {
    // Valid keys
    assert!(is_valid_env_key("PATH"));
    assert!(is_valid_env_key("_PRIVATE"));
    assert!(is_valid_env_key("HOME"));
    assert!(is_valid_env_key("MY_VAR_123"));
    assert!(is_valid_env_key("a"));
    assert!(is_valid_env_key("_"));
    assert!(is_valid_env_key("_1"));

    // Invalid keys
    assert!(!is_valid_env_key(""));
    assert!(!is_valid_env_key("123ABC"));
    assert!(!is_valid_env_key("MY-VAR"));
    assert!(!is_valid_env_key("MY VAR"));
    assert!(!is_valid_env_key("MY.VAR"));
    assert!(!is_valid_env_key("$(whoami)"));
    assert!(!is_valid_env_key("VAR;rm -rf /"));
}

#[test]
fn test_shell_quote() {
    assert_eq!(shell_quote("hello"), "'hello'");
    assert_eq!(shell_quote("hello world"), "'hello world'");
    assert_eq!(shell_quote("it's"), "'it'\\''s'");
    assert_eq!(shell_quote(""), "''");
    assert_eq!(shell_quote("a'b'c"), "'a'\\''b'\\''c'");
}

#[test]
fn test_shell_quote_special_chars() {
    // These should be safely quoted
    assert_eq!(shell_quote("$(whoami)"), "'$(whoami)'");
    assert_eq!(shell_quote("`id`"), "'`id`'");
    assert_eq!(shell_quote("$HOME"), "'$HOME'");
    assert_eq!(shell_quote("foo;bar"), "'foo;bar'");
    assert_eq!(shell_quote("foo|bar"), "'foo|bar'");
    assert_eq!(shell_quote("foo&bar"), "'foo&bar'");
    assert_eq!(shell_quote("foo\nbar"), "'foo\nbar'");
}
