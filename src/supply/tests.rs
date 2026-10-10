use super::*;

#[test]
fn test_sha256_computation() {
    use std::io::Write;
    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join("blackship_test_sha256.txt");

    // Create a test file with known content
    let mut file = File::create(&test_file).unwrap();
    file.write_all(b"hello world\n").unwrap();
    drop(file);

    let hash = sha256_file(&test_file).unwrap();

    // Verify hash is 64 hex characters (SHA256 output)
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));

    // Clean up
    let _ = fs::remove_file(&test_file);
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
