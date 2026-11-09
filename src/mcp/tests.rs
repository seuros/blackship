use super::*;

#[test]
fn loopback_http_needs_no_token() {
    assert!(Transport::http("127.0.0.1:7340", None).is_ok());
    assert!(Transport::http("[::1]:7340", None).is_ok());
}

#[test]
fn http_off_loopback_requires_a_token() {
    assert!(Transport::http("0.0.0.0:7340", None).is_err());
    assert!(Transport::http("192.168.3.73:7340", Some(String::new())).is_err());
    assert!(Transport::http("192.168.3.73:7340", Some("s3cret".into())).is_ok());
}

#[test]
fn http_rejects_an_address_without_a_port() {
    assert!(Transport::http("127.0.0.1", None).is_err());
}
