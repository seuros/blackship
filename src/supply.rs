//! HTTP fetching utilities for downloading FreeBSD releases
//!
//! Provides:
//! - Progress-tracked downloads
//! - SHA256 checksum verification
//! - Retry with exponential backoff

use crate::error::{Error, Result};
use crate::manifest::RetryConfig;
use chrono_machines::{BackoffStrategy, ExponentialBackoff};
use rand::rng;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;

/// Create backoff strategy from RetryConfig
pub(crate) fn backoff_from_config(config: &RetryConfig) -> ExponentialBackoff {
    ExponentialBackoff::new()
        .base_delay_ms(config.base_delay_ms)
        .max_delay_ms(config.max_delay_ms)
        .multiplier(config.multiplier)
        .max_attempts(config.max_attempts)
        .jitter_factor(config.jitter_factor)
}

/// Whether a failed request is worth retrying.
///
/// Transport failures and 5xx are transient. Most 4xx are not: a 404 will not
/// become a 200 after five backoff sleeps, so retrying one just stalls the
/// caller for the full budget before reporting what the first response already
/// said. 408 and 429 are the retryable exceptions.
fn is_retryable(err: &ureq::Error) -> bool {
    match err {
        ureq::Error::StatusCode(408 | 429) => true,
        ureq::Error::StatusCode(code) => !(400..500).contains(code),
        _ => true,
    }
}

/// Retry an HTTP call with exponential backoff; `what` labels log and error messages.
fn retry_call<T>(
    url: &str,
    retry_config: &RetryConfig,
    what: &str,
    mut call: impl FnMut() -> std::result::Result<T, ureq::Error>,
) -> Result<T> {
    let backoff = backoff_from_config(retry_config);
    let mut rng = rng();
    let mut attempt: u8 = 0;

    loop {
        attempt += 1;
        match call() {
            Ok(v) => return Ok(v),
            Err(e) if !is_retryable(&e) => {
                return Err(Error::DownloadFailed(format!(
                    "{} failed for {}: {}",
                    what, url, e
                )));
            }
            Err(e) => {
                if let Some(delay_ms) = backoff.delay(attempt, &mut rng) {
                    eprintln!(
                        "{} attempt {} failed, retrying in {}ms...",
                        what, attempt, delay_ms
                    );
                    thread::sleep(Duration::from_millis(delay_ms));
                } else {
                    return Err(Error::DownloadFailed(format!(
                        "{} failed for {} after {} attempts: {}",
                        what, url, attempt, e
                    )));
                }
            }
        }
    }
}

/// Download a file from URL to destination with optional checksum verification
pub fn download_file(
    url: &str,
    dest: &Path,
    expected_sha256: Option<&str>,
    retry_config: &RetryConfig,
) -> Result<()> {
    // Create parent directory if needed
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            Error::DownloadFailed(format!(
                "Failed to create directory {}: {}",
                parent.display(),
                e
            ))
        })?;
    }

    eprintln!("Downloading: {}", url);

    // Make HTTP request with retry
    let response = retry_call(url, retry_config, "Download", || ureq::get(url).call())?;

    // Get content length if available
    let content_length: Option<u64> = response
        .headers()
        .get("Content-Length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());

    if let Some(len) = content_length {
        eprintln!("Size: {} bytes ({:.2} MB)", len, len as f64 / 1_048_576.0);
    }

    // Unlink then O_EXCL: never write through a symlink planted at dest.
    let _ = std::fs::remove_file(dest);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dest)
        .map_err(|e| {
            Error::DownloadFailed(format!("Failed to create file {}: {}", dest.display(), e))
        })?;

    // Download with progress
    let mut reader = response.into_body().into_reader();
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536]; // 64KB buffer
    let mut downloaded: u64 = 0;
    let mut last_progress = 0;

    loop {
        let bytes_read = reader
            .read(&mut buffer)
            .map_err(|e| Error::DownloadFailed(format!("Read error during download: {}", e)))?;

        if bytes_read == 0 {
            break;
        }

        file.write_all(&buffer[..bytes_read])
            .map_err(|e| Error::DownloadFailed(format!("Write error during download: {}", e)))?;

        if expected_sha256.is_some() {
            hasher.update(&buffer[..bytes_read]);
        }

        downloaded += bytes_read as u64;

        // Print progress every 10%
        if let Some(total) = content_length {
            let progress = (downloaded * 100 / total) as usize;
            if progress >= last_progress + 10 {
                eprintln!("Progress: {}% ({} / {} bytes)", progress, downloaded, total);
                last_progress = progress;
            }
        }
    }

    eprintln!("Downloaded: {} bytes", downloaded);

    // Verify checksum if provided
    if let Some(expected) = expected_sha256 {
        let actual = hex::encode(hasher.finalize());
        if actual != expected {
            // Remove the corrupt file
            let _ = fs::remove_file(dest);
            return Err(Error::ChecksumMismatch {
                file: dest.display().to_string(),
                expected: expected.to_string(),
                actual,
            });
        }
        eprintln!("Checksum verified: OK");
    }

    Ok(())
}

/// Compute SHA256 hash of a file
pub fn sha256_file(path: &Path) -> Result<String> {
    let file = File::open(path)
        .map_err(|e| Error::DownloadFailed(format!("Failed to open file for checksum: {}", e)))?;

    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];

    loop {
        let bytes_read = reader
            .read(&mut buffer)
            .map_err(|e| Error::DownloadFailed(format!("Read error computing checksum: {}", e)))?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Fetch a text file (like MANIFEST) and return its contents
pub fn fetch_text(url: &str, retry_config: &RetryConfig) -> Result<String> {
    let response = retry_call(url, retry_config, "Fetch", || ureq::get(url).call())?;

    response
        .into_body()
        .read_to_string()
        .map_err(|e| Error::DownloadFailed(format!("Failed to read response body: {}", e)))
}

/// Check if a URL exists (HEAD request)
///
/// A failure that outlives the retry budget is reported as "missing": callers
/// use this to pick a mirror path, and an unreachable URL is indistinguishable
/// from an absent one for that purpose.
pub fn url_exists(url: &str, retry_config: &RetryConfig) -> bool {
    retry_call(url, retry_config, "Probe", || ureq::head(url).call()).is_ok()
}

#[cfg(test)]
mod tests {
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
                "{} should fail fast",
                code
            );
        }
    }

    #[test]
    fn test_transient_statuses_are_retried() {
        // 408/429 are 4xx but explicitly retryable; 5xx always is.
        for code in [408, 429, 500, 502, 503, 504] {
            assert!(
                is_retryable(&ureq::Error::StatusCode(code)),
                "{} should be retried",
                code
            );
        }
    }

    #[test]
    fn test_non_status_errors_are_retried() {
        // Transport-level failures (DNS, connect, TLS) are transient.
        assert!(is_retryable(&ureq::Error::HostNotFound));
    }
}
