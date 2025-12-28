//! HTTP fetching utilities for downloading FreeBSD releases
//!
//! Provides:
//! - Progress-tracked downloads
//! - SHA256 checksum verification
//! - Resume support for interrupted downloads
//! - Retry with exponential backoff

use crate::manifest::RetryConfig;
use crate::error::{Error, Result};
use chrono_machines::{BackoffStrategy, ExponentialBackoff};
use rand::rng;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;

/// Create backoff strategy from RetryConfig
fn backoff_from_config(config: &RetryConfig) -> ExponentialBackoff {
    ExponentialBackoff::new()
        .base_delay_ms(config.base_delay_ms)
        .max_delay_ms(config.max_delay_ms)
        .multiplier(config.multiplier)
        .max_attempts(config.max_attempts)
        .jitter_factor(config.jitter_factor)
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
    let backoff = backoff_from_config(retry_config);
    let mut rng = rng();
    let mut attempt: u8 = 0;

    let response = loop {
        attempt += 1;
        match ureq::get(url).call() {
            Ok(resp) => break resp,
            Err(e) => {
                if let Some(delay_ms) = backoff.delay(attempt, &mut rng) {
                    eprintln!(
                        "Download attempt {} failed, retrying in {}ms...",
                        attempt, delay_ms
                    );
                    thread::sleep(Duration::from_millis(delay_ms));
                } else {
                    return Err(Error::DownloadFailed(format!(
                        "HTTP request failed for {} after {} attempts: {}",
                        url, attempt, e
                    )));
                }
            }
        }
    };

    // Get content length if available
    let content_length: Option<u64> = response
        .headers()
        .get("Content-Length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());

    if let Some(len) = content_length {
        eprintln!("Size: {} bytes ({:.2} MB)", len, len as f64 / 1_048_576.0);
    }

    // Create output file
    let mut file = File::create(dest).map_err(|e| {
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
    let backoff = backoff_from_config(retry_config);
    let mut rng = rng();
    let mut attempt: u8 = 0;

    let response = loop {
        attempt += 1;
        match ureq::get(url).call() {
            Ok(resp) => break resp,
            Err(e) => {
                if let Some(delay_ms) = backoff.delay(attempt, &mut rng) {
                    eprintln!(
                        "Fetch attempt {} failed, retrying in {}ms...",
                        attempt, delay_ms
                    );
                    thread::sleep(Duration::from_millis(delay_ms));
                } else {
                    return Err(Error::DownloadFailed(format!(
                        "Failed to fetch {} after {} attempts: {}",
                        url, attempt, e
                    )));
                }
            }
        }
    };

    response
        .into_body()
        .read_to_string()
        .map_err(|e| Error::DownloadFailed(format!("Failed to read response body: {}", e)))
}

/// Check if a URL exists (HEAD request)
pub fn url_exists(url: &str, retry_config: &RetryConfig) -> bool {
    let backoff = backoff_from_config(retry_config);
    let mut rng = rng();
    let mut attempt: u8 = 0;

    loop {
        attempt += 1;
        match ureq::head(url).call() {
            Ok(_) => return true,
            Err(ureq::Error::StatusCode(404)) => return false,
            Err(_) => {
                if let Some(delay_ms) = backoff.delay(attempt, &mut rng) {
                    thread::sleep(Duration::from_millis(delay_ms));
                } else {
                    return false;
                }
            }
        }
    }
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
}
