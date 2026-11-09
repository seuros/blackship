use super::*;

#[test]
fn test_sha256_computation() {
    let tmp = tempfile::tempdir().unwrap();
    let test_file = tmp.path().join("hello.txt");
    fs::write(&test_file, b"hello world\n").unwrap();

    assert_eq!(
        sha256_file(&test_file).unwrap(),
        "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447"
    );
}

#[test]
fn test_client_errors_are_not_retried() {
    for code in [400, 401, 403, 404, 410, 451] {
        assert!(
            !is_retryable(&ureq::Error::StatusCode(code)),
            "{code} should fail fast"
        );
    }
}

#[test]
fn test_transient_statuses_are_retried() {
    // 408/429 are 4xx but explicitly retryable; 5xx always is.
    for code in [408, 429, 500, 502, 503, 504] {
        assert!(
            is_retryable(&ureq::Error::StatusCode(code)),
            "{code} should be retried"
        );
    }
}

#[test]
fn test_non_status_errors_are_retried() {
    // Transport-level failures (DNS, connect, TLS) are transient.
    assert!(is_retryable(&ureq::Error::HostNotFound));
}
