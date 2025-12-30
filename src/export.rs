//! Export and import functionality for jails
//!
//! Provides:
//! - Export jails to tar.zst archives
//! - Import jails from archives
//! - ZFS send/receive for efficient transfers

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process::Command;
use tar::{Archive, Builder};

/// Metadata stored in the archive
#[derive(Debug, Serialize, Deserialize)]
pub struct ExportMetadata {
    /// Original jail name
    pub name: String,
    /// Blackship version that created the export
    pub version: String,
    /// Export timestamp
    pub timestamp: String,
    /// Original path
    pub original_path: String,
    /// IP address if configured
    pub ip: Option<String>,
    /// Hostname if configured
    pub hostname: Option<String>,
}

/// Read export metadata without importing the archive
pub fn read_metadata(archive_path: &Path) -> Result<ExportMetadata> {
    // Open archive
    let file = File::open(archive_path)
        .map_err(|e| Error::JailOperation(format!("Failed to open archive: {}", e)))?;

    // Check for ZFS format
    let mut magic = [0u8; 8];
    {
        let mut reader = std::io::BufReader::new(&file);
        if reader.read_exact(&mut magic).is_ok() && &magic == b"BSZFS001" {
            let mut len_bytes = [0u8; 4];
            reader
                .read_exact(&mut len_bytes)
                .map_err(|e| Error::JailOperation(format!("Failed to read metadata length: {}", e)))?;
            let len = u32::from_le_bytes(len_bytes) as usize;
            let mut buf = vec![0u8; len];
            reader
                .read_exact(&mut buf)
                .map_err(|e| Error::JailOperation(format!("Failed to read metadata: {}", e)))?;
            return serde_json::from_slice(&buf)
                .map_err(|e| Error::JailOperation(format!("Failed to parse metadata: {}", e)));
        }
    }

    // Reopen file for tar/zstd
    let file = File::open(archive_path)
        .map_err(|e| Error::JailOperation(format!("Failed to reopen archive: {}", e)))?;

    // Decompress
    let decoder = zstd::stream::Decoder::new(file)
        .map_err(|e| Error::JailOperation(format!("Failed to decompress: {}", e)))?;

    // Open tar archive
    let mut archive = Archive::new(decoder);

    for entry in archive
        .entries()
        .map_err(|e| Error::JailOperation(format!("Failed to read archive entries: {}", e)))?
    {
        let mut entry = entry
            .map_err(|e| Error::JailOperation(format!("Failed to read archive entry: {}", e)))?;
        let path = entry
            .path()
            .map_err(|e| Error::JailOperation(format!("Failed to read entry path: {}", e)))?
            .to_path_buf();

        if path.to_string_lossy() == ".blackship-metadata.json" {
            let mut content = String::new();
            entry
                .read_to_string(&mut content)
                .map_err(|e| Error::JailOperation(format!("Failed to read metadata: {}", e)))?;
            return serde_json::from_str(&content)
                .map_err(|e| Error::JailOperation(format!("Failed to parse metadata: {}", e)));
        }
    }

    Err(Error::JailOperation("Archive missing metadata".into()))
}

/// Export a jail to a tar.zst archive
pub fn export_jail(
    name: &str,
    jail_path: &Path,
    output_path: &Path,
    hostname: Option<&str>,
    ip: Option<&str>,
) -> Result<()> {
    println!("Exporting jail '{}' to {}", name, output_path.display());

    // Create output file
    let file = File::create(output_path)
        .map_err(|e| Error::JailOperation(format!("Failed to create output file: {}", e)))?;

    // Wrap in zstd compressor
    let encoder = zstd::stream::Encoder::new(file, 3)
        .map_err(|e| Error::JailOperation(format!("Failed to create compressor: {}", e)))?;

    // Create tar builder
    let mut builder = Builder::new(encoder);

    // Create and add metadata
    let metadata = ExportMetadata {
        name: name.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: chrono_lite_timestamp(),
        original_path: jail_path.to_string_lossy().to_string(),
        ip: ip.map(String::from),
        hostname: hostname.map(String::from),
    };

    let metadata_json = serde_json::to_string_pretty(&metadata)
        .map_err(|e| Error::JailOperation(format!("Failed to serialize metadata: {}", e)))?;

    // Add metadata as first file
    let metadata_bytes = metadata_json.as_bytes();
    let mut header = tar::Header::new_gnu();
    header.set_size(metadata_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();

    builder
        .append_data(&mut header, ".blackship-metadata.json", metadata_bytes)
        .map_err(|e| Error::JailOperation(format!("Failed to add metadata: {}", e)))?;

    // Add jail root filesystem
    println!("  Adding jail filesystem...");
    builder
        .append_dir_all("rootfs", jail_path)
        .map_err(|e| Error::JailOperation(format!("Failed to add jail files: {}", e)))?;

    // Finish archive
    let encoder = builder
        .into_inner()
        .map_err(|e| Error::JailOperation(format!("Failed to finalize archive: {}", e)))?;

    encoder
        .finish()
        .map_err(|e| Error::JailOperation(format!("Failed to finish compression: {}", e)))?;

    println!("Export complete: {}", output_path.display());
    Ok(())
}

/// Export using ZFS send (faster for large jails)
pub fn export_jail_zfs(
    name: &str,
    dataset: &str,
    output_path: &Path,
    hostname: Option<&str>,
    ip: Option<&str>,
) -> Result<()> {
    println!(
        "Exporting jail '{}' via ZFS send to {}",
        name,
        output_path.display()
    );

    // Create a snapshot for consistent export
    let snapshot_name = format!("{}@blackship-export", dataset);

    // Create snapshot
    let status = Command::new("zfs")
        .args(["snapshot", &snapshot_name])
        .status()
        .map_err(|e| Error::Zfs(format!("Failed to create snapshot: {}", e)))?;

    if !status.success() {
        return Err(Error::Zfs("Failed to create export snapshot".into()));
    }

    // Create output file
    let output_file = File::create(output_path)
        .map_err(|e| Error::JailOperation(format!("Failed to create output file: {}", e)))?;

    // Write metadata header first
    let metadata = ExportMetadata {
        name: name.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: chrono_lite_timestamp(),
        original_path: format!("zfs:{}", dataset),
        ip: ip.map(String::from),
        hostname: hostname.map(String::from),
    };

    let mut output = std::io::BufWriter::new(output_file);

    // Write magic header and metadata length
    let metadata_json = serde_json::to_vec(&metadata)
        .map_err(|e| Error::JailOperation(format!("Failed to serialize metadata: {}", e)))?;

    output
        .write_all(b"BSZFS001")
        .map_err(|e| Error::JailOperation(format!("Failed to write header: {}", e)))?;
    output
        .write_all(&(metadata_json.len() as u32).to_le_bytes())
        .map_err(|e| Error::JailOperation(format!("Failed to write length: {}", e)))?;
    output
        .write_all(&metadata_json)
        .map_err(|e| Error::JailOperation(format!("Failed to write metadata: {}", e)))?;

    output
        .flush()
        .map_err(|e| Error::JailOperation(format!("Failed to flush: {}", e)))?;

    // Run zfs send piped to output
    let output_path_str = output_path.to_string_lossy();
    let status = Command::new("sh")
        .args([
            "-c",
            &format!("zfs send {} >> \"{}\"", snapshot_name, output_path_str),
        ])
        .status()
        .map_err(|e| Error::Zfs(format!("Failed to run zfs send: {}", e)))?;

    // Clean up snapshot
    let _ = Command::new("zfs")
        .args(["destroy", &snapshot_name])
        .status();

    if !status.success() {
        return Err(Error::Zfs("ZFS send failed".into()));
    }

    println!("Export complete: {}", output_path.display());
    Ok(())
}

/// Import a jail from an archive
pub fn import_jail(
    archive_path: &Path,
    target_path: &Path,
    new_name: Option<&str>,
) -> Result<String> {
    println!("Importing jail from {}", archive_path.display());

    // Open archive
    let file = File::open(archive_path)
        .map_err(|e| Error::JailOperation(format!("Failed to open archive: {}", e)))?;

    // Check for ZFS format
    let mut magic = [0u8; 8];
    {
        let mut reader = std::io::BufReader::new(&file);
        if reader.read_exact(&mut magic).is_ok() && &magic == b"BSZFS001" {
            drop(reader);
            return import_jail_zfs(archive_path, target_path, new_name);
        }
    }

    // Reopen file for tar/zstd
    let file = File::open(archive_path)
        .map_err(|e| Error::JailOperation(format!("Failed to reopen archive: {}", e)))?;

    // Decompress
    let decoder = zstd::stream::Decoder::new(file)
        .map_err(|e| Error::JailOperation(format!("Failed to decompress: {}", e)))?;

    // Open tar archive
    let mut archive = Archive::new(decoder);

    // Extract metadata first
    let mut metadata: Option<ExportMetadata> = None;

    // Create temp dir for extraction
    let temp_dir = target_path.parent().unwrap_or(Path::new("/tmp"));
    let temp_extract = temp_dir.join(format!(".import-{}", std::process::id()));
    std::fs::create_dir_all(&temp_extract)
        .map_err(|e| Error::JailOperation(format!("Failed to create temp dir: {}", e)))?;

    // Extract archive
    for entry in archive
        .entries()
        .map_err(|e| Error::JailOperation(format!("Failed to read archive entries: {}", e)))?
    {
        let mut entry = entry
            .map_err(|e| Error::JailOperation(format!("Failed to read archive entry: {}", e)))?;

        let path = entry
            .path()
            .map_err(|e| Error::JailOperation(format!("Failed to read entry path: {}", e)))?
            .to_path_buf(); // Convert to owned PathBuf to avoid borrow conflict

        if path.to_string_lossy() == ".blackship-metadata.json" {
            let mut content = String::new();
            entry
                .read_to_string(&mut content)
                .map_err(|e| Error::JailOperation(format!("Failed to read metadata: {}", e)))?;
            metadata =
                Some(serde_json::from_str(&content).map_err(|e| {
                    Error::JailOperation(format!("Failed to parse metadata: {}", e))
                })?);
        } else {
            entry.unpack_in(&temp_extract).map_err(|e| {
                Error::JailOperation(format!("Failed to extract {}: {}", path.display(), e))
            })?;
        }
    }

    let metadata =
        metadata.ok_or_else(|| Error::JailOperation("Archive missing metadata".into()))?;

    let jail_name = new_name.unwrap_or(&metadata.name);

    // Move rootfs to target
    let rootfs_src = temp_extract.join("rootfs");
    if rootfs_src.exists() {
        if target_path.exists() {
            std::fs::remove_dir_all(target_path)
                .map_err(|e| Error::JailOperation(format!("Failed to remove existing: {}", e)))?;
        }
        std::fs::rename(&rootfs_src, target_path)
            .map_err(|e| Error::JailOperation(format!("Failed to move rootfs: {}", e)))?;
    }

    // Clean up temp
    let _ = std::fs::remove_dir_all(&temp_extract);

    println!("Imported jail '{}' to {}", jail_name, target_path.display());
    println!("  Original: {}", metadata.name);
    if let Some(ip) = metadata.ip {
        println!("  IP: {}", ip);
    }

    Ok(jail_name.to_string())
}

/// Import from ZFS stream
fn import_jail_zfs(
    archive_path: &Path,
    target_path: &Path,
    new_name: Option<&str>,
) -> Result<String> {
    println!("Importing ZFS stream from {}", archive_path.display());

    let file = File::open(archive_path)
        .map_err(|e| Error::JailOperation(format!("Failed to open archive: {}", e)))?;

    let mut reader = std::io::BufReader::new(file);

    // Skip magic
    let mut magic = [0u8; 8];
    reader
        .read_exact(&mut magic)
        .map_err(|e| Error::JailOperation(format!("Failed to read header: {}", e)))?;

    // Read metadata length
    let mut len_bytes = [0u8; 4];
    reader
        .read_exact(&mut len_bytes)
        .map_err(|e| Error::JailOperation(format!("Failed to read length: {}", e)))?;
    let meta_len = u32::from_le_bytes(len_bytes) as usize;

    // Read metadata
    let mut meta_bytes = vec![0u8; meta_len];
    reader
        .read_exact(&mut meta_bytes)
        .map_err(|e| Error::JailOperation(format!("Failed to read metadata: {}", e)))?;

    let metadata: ExportMetadata = serde_json::from_slice(&meta_bytes)
        .map_err(|e| Error::JailOperation(format!("Failed to parse metadata: {}", e)))?;

    let jail_name = new_name.unwrap_or(&metadata.name);

    // Derive dataset name from target path
    // This assumes target_path is like /pool/dataset/jails/name
    let dataset = target_path
        .strip_prefix("/")
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| target_path.to_string_lossy().to_string());

    // Pipe remaining file to zfs receive
    let archive_path_str = archive_path.to_string_lossy();
    let skip_bytes = 8 + 4 + meta_len;

    let status = Command::new("sh")
        .args([
            "-c",
            &format!(
                "tail -c +{} \"{}\" | zfs receive {}",
                skip_bytes + 1,
                archive_path_str,
                dataset
            ),
        ])
        .status()
        .map_err(|e| Error::Zfs(format!("Failed to run zfs receive: {}", e)))?;

    if !status.success() {
        return Err(Error::Zfs("ZFS receive failed".into()));
    }

    println!("Imported jail '{}' to {}", jail_name, target_path.display());
    Ok(jail_name.to_string())
}

/// Simple timestamp without external crate
fn chrono_lite_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_serialization() {
        let metadata = ExportMetadata {
            name: "test".to_string(),
            version: "0.1.0".to_string(),
            timestamp: "12345".to_string(),
            original_path: "/jails/test".to_string(),
            ip: Some("10.0.1.10".to_string()),
            hostname: Some("test.local".to_string()),
        };

        let json = serde_json::to_string(&metadata).unwrap();
        assert!(json.contains("test"));
        assert!(json.contains("10.0.1.10"));

        let parsed: ExportMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "test");
    }
}
