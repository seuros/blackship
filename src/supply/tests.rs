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

#[test]
fn default_retry_config_allows_four_retries_in_five_attempts() {
    let mut retry = backoff_from_config(&RetryConfig::default()).unwrap();
    for _ in 0..4 {
        assert!(retry.failed(0).is_ok());
    }
    assert!(retry.failed(0).is_err());
}

#[test]
fn zero_max_attempts_means_no_retries() {
    let config = RetryConfig {
        max_attempts: 0,
        ..RetryConfig::default()
    };
    assert!(backoff_from_config(&config).unwrap().failed(0).is_err());
}

#[test]
fn retry_delays_double_and_stop_at_the_cap() {
    let config = RetryConfig {
        base_delay_ms: 100,
        max_delay_ms: 250,
        multiplier: 2.0,
        max_attempts: 5,
        jitter_factor: 0.0,
    };
    let mut retry = backoff_from_config(&config).unwrap();
    let delays: Vec<_> = (0..4)
        .map(|_| retry.failed(0).unwrap().as_millis())
        .collect();
    assert_eq!(delays, [100, 200, 250, 250]);
}
