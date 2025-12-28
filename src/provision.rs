//! Bootstrap functionality for fetching FreeBSD releases
//!
//! Provides:
//! - Downloading and extracting FreeBSD base system archives
//! - Release management (list, verify)
//! - Support for different architectures
//! - Retry with exponential backoff for network operations

use crate::manifest::RetryConfig;
use crate::error::{Error, Result};
use crate::supply::{download_file, fetch_text, url_exists};
use chrono_machines::{BackoffStrategy, ExponentialBackoff};
use rand::rng;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use tar::Archive;
use xz2::read::XzDecoder;

/// Create backoff strategy from RetryConfig
fn backoff_from_config(config: &RetryConfig) -> ExponentialBackoff {
    ExponentialBackoff::new()
        .base_delay_ms(config.base_delay_ms)
        .max_delay_ms(config.max_delay_ms)
        .multiplier(config.multiplier)
        .max_attempts(config.max_attempts)
        .jitter_factor(config.jitter_factor)
}

/// Supported FreeBSD architectures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    Amd64,
    Arm64,
    I386,
}

impl Arch {
    /// Get architecture from current system
    pub fn current() -> Result<Self> {
        let arch = std::env::consts::ARCH;
        match arch {
            "x86_64" => Ok(Arch::Amd64),
            "aarch64" => Ok(Arch::Arm64),
            "x86" => Ok(Arch::I386),
            _ => Err(Error::UnsupportedArch(arch.to_string())),
        }
    }

    /// Get FreeBSD architecture name
    pub fn freebsd_name(&self) -> &'static str {
        match self {
            Arch::Amd64 => "amd64",
            Arch::Arm64 => "arm64",
            Arch::I386 => "i386",
        }
    }
}

/// A bootstrapped release
#[derive(Debug)]
pub struct Release {
    /// Release name (e.g., "14.2-RELEASE")
    pub name: String,
    /// Path to the extracted release
    pub path: PathBuf,
    /// Architecture
    pub arch: Arch,
}

/// Provisioner for fetching and managing releases
pub struct Provisioner {
    /// Base URL for FreeBSD mirror
    mirror_url: String,
    /// Directory for storing releases
    releases_dir: PathBuf,
    /// Cache directory for downloads
    cache_dir: PathBuf,
    /// Archives to download
    archives: Vec<String>,
    /// Current architecture
    arch: Arch,
    /// Retry configuration for network operations
    retry_config: RetryConfig,
}

impl Provisioner {
    /// Create a new provisioner
    pub fn new(
        mirror_url: String,
        releases_dir: PathBuf,
        cache_dir: PathBuf,
        archives: Vec<String>,
        retry_config: RetryConfig,
    ) -> Result<Self> {
        Ok(Self {
            mirror_url,
            releases_dir,
            cache_dir,
            archives,
            arch: Arch::current()?,
            retry_config,
        })
    }

    /// Create provisioner from config
    pub fn from_config(config: &crate::manifest::GlobalConfig) -> Result<Self> {
        Self::new(
            config.mirror_url.clone(),
            config.releases_dir.clone(),
            config.cache_dir.clone(),
            config.bootstrap_archives.clone(),
            config.retry.clone(),
        )
    }

    /// Get URL for a release archive
    fn archive_url(&self, release: &str, archive: &str) -> String {
        format!(
            "{}/{}/{}/{}.txz",
            self.mirror_url,
            self.arch.freebsd_name(),
            release,
            archive
        )
    }

    /// Get URL for release MANIFEST
    fn manifest_url(&self, release: &str) -> String {
        format!(
            "{}/{}/{}/MANIFEST",
            self.mirror_url,
            self.arch.freebsd_name(),
            release
        )
    }

    /// Parse a MANIFEST file and return archive -> sha256 mapping
    fn parse_manifest(&self, content: &str) -> HashMap<String, String> {
        let mut checksums = HashMap::new();

        for line in content.lines() {
            // Format: archive.txz\tsha256\tsize\tpath_count
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 2 {
                let archive = parts[0].trim_end_matches(".txz");
                let sha256 = parts[1];
                checksums.insert(archive.to_string(), sha256.to_string());
            }
        }

        checksums
    }

    /// Get the path where a release would be extracted
    pub fn release_path(&self, release: &str) -> PathBuf {
        self.releases_dir.join(release)
    }

    /// Check if a release is already bootstrapped
    pub fn is_bootstrapped(&self, release: &str) -> bool {
        let path = self.release_path(release);
        path.exists() && path.join("bin").exists() && path.join("usr").exists()
    }

    /// List all bootstrapped releases
    pub fn list_releases(&self) -> Result<Vec<Release>> {
        let mut releases = Vec::new();

        if !self.releases_dir.exists() {
            return Ok(releases);
        }

        for entry in fs::read_dir(&self.releases_dir).map_err(Error::Io)? {
            let entry = entry.map_err(Error::Io)?;
            let path = entry.path();

            if path.is_dir() {
                // Check if it looks like a valid release
                if path.join("bin").exists() && path.join("usr").exists()
                    && let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        releases.push(Release {
                            name: name.to_string(),
                            path: path.clone(),
                            arch: self.arch,
                        });
                    }
            }
        }

        // Sort by name
        releases.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(releases)
    }

    /// Bootstrap a FreeBSD release
    ///
    /// Downloads and extracts the specified release archives.
    pub fn bootstrap(&self, release: &str, force: bool) -> Result<PathBuf> {
        let release_path = self.release_path(release);

        // Check if already exists
        if self.is_bootstrapped(release) && !force {
            return Err(Error::ReleaseAlreadyExists(release.to_string()));
        }

        // Verify release exists on mirror
        let manifest_url = self.manifest_url(release);
        if !url_exists(&manifest_url, &self.retry_config) {
            return Err(Error::ReleaseNotFound(release.to_string()));
        }

        eprintln!("Bootstrapping {} for {}", release, self.arch.freebsd_name());

        // Fetch MANIFEST for checksums
        eprintln!("Fetching MANIFEST...");
        let manifest_content = fetch_text(&manifest_url, &self.retry_config)?;
        let checksums = self.parse_manifest(&manifest_content);

        // Create directories
        fs::create_dir_all(&self.cache_dir).map_err(Error::Io)?;
        fs::create_dir_all(&release_path).map_err(Error::Io)?;

        // Download and extract each archive with retry
        for archive in &self.archives {
            let url = self.archive_url(release, archive);
            let cache_file = self.cache_dir.join(format!("{}-{}.txz", release, archive));

            // Get expected checksum
            let expected_sha256 = checksums.get(archive.as_str());

            // Retry loop for download and extract
            let backoff = backoff_from_config(&self.retry_config);
            let mut rng = rng();
            let mut attempt: u8 = 0;

            loop {
                attempt += 1;

                // Download if not cached or checksum doesn't match
                let needs_download = if cache_file.exists() {
                    if let Some(expected) = expected_sha256 {
                        match crate::supply::sha256_file(&cache_file) {
                            Ok(actual) => actual != *expected,
                            Err(_) => true,
                        }
                    } else {
                        false
                    }
                } else {
                    true
                };

                let result: Result<()> = (|| {
                    if needs_download {
                        eprintln!("Downloading {}.txz...", archive);
                        download_file(
                            &url,
                            &cache_file,
                            expected_sha256.map(|s| s.as_str()),
                            &self.retry_config,
                        )?;
                    } else {
                        eprintln!("Using cached {}.txz", archive);
                    }

                    // Extract archive
                    eprintln!("Extracting {}.txz...", archive);
                    self.extract_txz(&cache_file, &release_path)?;
                    Ok(())
                })();

                match result {
                    Ok(()) => break,
                    Err(e) => {
                        if let Some(delay_ms) = backoff.delay(attempt, &mut rng) {
                            eprintln!(
                                "Archive {} attempt {} failed, retrying in {}ms...",
                                archive, attempt, delay_ms
                            );
                            // Remove potentially corrupt cached file before retry
                            let _ = fs::remove_file(&cache_file);
                            thread::sleep(Duration::from_millis(delay_ms));
                        } else {
                            return Err(e);
                        }
                    }
                }
            }
        }

        eprintln!("Bootstrap complete: {}", release_path.display());
        Ok(release_path)
    }

    /// Extract a .txz (tar.xz) archive
    fn extract_txz(&self, archive_path: &Path, dest: &Path) -> Result<()> {
        let file = File::open(archive_path).map_err(|e| {
            Error::ExtractionFailed(format!(
                "Failed to open archive {}: {}",
                archive_path.display(),
                e
            ))
        })?;

        let reader = BufReader::new(file);
        let xz = XzDecoder::new(reader);
        let mut archive = Archive::new(xz);

        // Preserve permissions and ownership
        archive.set_preserve_permissions(true);
        archive.set_preserve_ownerships(true);

        archive.unpack(dest).map_err(|e| {
            Error::ExtractionFailed(format!(
                "Failed to extract {}: {}",
                archive_path.display(),
                e
            ))
        })?;

        Ok(())
    }

    /// Delete a bootstrapped release
    pub fn delete(&self, release: &str) -> Result<()> {
        let path = self.release_path(release);

        if !path.exists() {
            return Err(Error::ReleaseNotFound(release.to_string()));
        }

        fs::remove_dir_all(&path)
            .map_err(|e| Error::ExtractionFailed(format!("Failed to delete release: {}", e)))?;

        eprintln!("Deleted release: {}", release);
        Ok(())
    }

    /// Verify a bootstrapped release against MANIFEST
    pub fn verify(&self, release: &str) -> Result<bool> {
        if !self.is_bootstrapped(release) {
            return Err(Error::ReleaseNotFound(release.to_string()));
        }

        // For now, just check that essential directories exist
        let release_path = self.release_path(release);
        let essential_paths = ["bin/sh", "usr/bin/env", "lib/libc.so.7"];

        for path in essential_paths {
            if !release_path.join(path).exists() {
                eprintln!("Missing essential file: {}", path);
                return Ok(false);
            }
        }

        Ok(true)
    }
}

/// Clone a release to create a new jail filesystem (_unused: future feature)
#[allow(dead_code)]
pub fn clone_release(release_path: &Path, jail_path: &Path) -> Result<()> {
    if !release_path.exists() {
        return Err(Error::ReleaseNotFound(release_path.display().to_string()));
    }

    // Create jail directory
    fs::create_dir_all(jail_path).map_err(Error::Io)?;

    // Use cp -a for proper cloning with permissions
    let status = std::process::Command::new("cp")
        .args(["-a", "."])
        .current_dir(release_path)
        .arg(jail_path)
        .status()
        .map_err(|e| Error::ExtractionFailed(format!("Failed to clone release: {}", e)))?;

    if !status.success() {
        return Err(Error::ExtractionFailed(
            "cp command failed during clone".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arch_detection() {
        let arch = Arch::current();
        assert!(arch.is_ok());
    }

    #[test]
    fn test_manifest_parsing() {
        let provisioner = Provisioner {
            mirror_url: String::new(),
            releases_dir: PathBuf::new(),
            cache_dir: PathBuf::new(),
            archives: vec![],
            arch: Arch::Amd64,
            retry_config: RetryConfig::default(),
        };

        let manifest = "base.txz\tabc123\t100\t1000\nkernel.txz\tdef456\t50\t500";
        let checksums = provisioner.parse_manifest(manifest);

        assert_eq!(checksums.get("base"), Some(&"abc123".to_string()));
        assert_eq!(checksums.get("kernel"), Some(&"def456".to_string()));
    }

    #[test]
    fn test_archive_url() {
        let provisioner = Provisioner {
            mirror_url: "https://download.freebsd.org/releases".to_string(),
            releases_dir: PathBuf::new(),
            cache_dir: PathBuf::new(),
            archives: vec![],
            arch: Arch::Amd64,
            retry_config: RetryConfig::default(),
        };

        let url = provisioner.archive_url("14.2-RELEASE", "base");
        assert_eq!(
            url,
            "https://download.freebsd.org/releases/amd64/14.2-RELEASE/base.txz"
        );
    }
}
