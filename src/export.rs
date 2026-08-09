//! Export and import functionality for jails
//!
//! Provides:
//! - Export jails to tar.zst archives
//! - Import jails from archives
//! - ZFS send/receive for efficient transfers

use crate::error::{Error, Result};
use jiff::{Unit, Zoned};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
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

/// Get the path of a tar entry, mapping errors to JailOperation
fn entry_path<R: std::io::Read>(entry: &tar::Entry<R>) -> Result<std::path::PathBuf> {
    entry
        .path()
        .map_err(|e| Error::JailOperation(format!("Failed to read entry path: {}", e)))
        .map(|p| p.to_path_buf())
}

/// Maximum size for metadata entries read from tar archives (10 MB).
const MAX_TAR_METADATA_SIZE: u64 = 10 * 1024 * 1024;

/// Read a tar entry to string, refusing entries over `MAX_TAR_METADATA_SIZE`.
fn entry_read_to_string<R: std::io::Read>(
    entry: &mut tar::Entry<R>,
    buf: &mut String,
) -> Result<()> {
    let size = entry.header().size().unwrap_or(0);
    if size > MAX_TAR_METADATA_SIZE {
        return Err(Error::JailOperation(format!(
            "Metadata entry size {} exceeds maximum allowed size of {} bytes",
            size, MAX_TAR_METADATA_SIZE
        )));
    }
    entry
        .read_to_string(buf)
        .map_err(|e| Error::JailOperation(format!("Failed to read metadata: {}", e)))
        .map(|_| ())
}

/// Open a jail archive file, mapping the IO error to JailOperation
fn open_archive(path: &Path) -> Result<File> {
    File::open(path).map_err(|e| Error::JailOperation(format!("Failed to open archive: {}", e)))
}

/// Create an output file, mapping the IO error to JailOperation
fn create_output_file(path: &Path) -> Result<File> {
    File::create(path)
        .map_err(|e| Error::JailOperation(format!("Failed to create output file: {}", e)))
}

/// Wrap a file in a zstd decoder
fn open_decoder(file: File) -> Result<zstd::stream::Decoder<'static, std::io::BufReader<File>>> {
    zstd::stream::Decoder::new(file)
        .map_err(|e| Error::JailOperation(format!("Failed to decompress: {}", e)))
}

/// Read export metadata without importing the archive
pub fn read_metadata(archive_path: &Path) -> Result<ExportMetadata> {
    // Open archive
    let file = open_archive(archive_path)?;

    // Check for ZFS format
    let mut magic = [0u8; 8];
    {
        let mut reader = std::io::BufReader::new(&file);
        if reader.read_exact(&mut magic).is_ok() && &magic == b"BSZFS001" {
            let mut len_bytes = [0u8; 4];
            reader.read_exact(&mut len_bytes).map_err(|e| {
                Error::JailOperation(format!("Failed to read metadata length: {}", e))
            })?;
            let len = u32::from_le_bytes(len_bytes) as usize;
            const MAX_METADATA_LEN: usize = 10 * 1024 * 1024; // 10 MB
            if len > MAX_METADATA_LEN {
                return Err(Error::JailOperation(format!(
                    "Metadata length {} exceeds maximum allowed size of {} bytes",
                    len, MAX_METADATA_LEN
                )));
            }
            let mut buf = vec![0u8; len];
            reader
                .read_exact(&mut buf)
                .map_err(|e| Error::JailOperation(format!("Failed to read metadata: {}", e)))?;
            return serde_json::from_slice(&buf)
                .map_err(|e| Error::JailOperation(format!("Failed to parse metadata: {}", e)));
        }
    }

    // Reopen file for tar/zstd
    let file = open_archive(archive_path)?;

    // Decompress
    let decoder = open_decoder(file)?;

    // Open tar archive
    let mut archive = Archive::new(decoder);

    for entry in archive
        .entries()
        .map_err(|e| Error::JailOperation(format!("Failed to read archive entries: {}", e)))?
    {
        let mut entry = entry
            .map_err(|e| Error::JailOperation(format!("Failed to read archive entry: {}", e)))?;
        let path = entry_path(&entry)?;

        if path.to_string_lossy() == ".blackship-metadata.json" {
            let mut content = String::new();
            entry_read_to_string(&mut entry, &mut content)?;
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
    let file = create_output_file(output_path)?;

    // Wrap in zstd compressor
    let encoder = zstd::stream::Encoder::new(file, 3)
        .map_err(|e| Error::JailOperation(format!("Failed to create compressor: {}", e)))?;

    // Create tar builder
    let mut builder = Builder::new(encoder);
    // Archive symlinks as symlinks: following them would leak host files.
    builder.follow_symlinks(false);

    // Create and add metadata
    let metadata = ExportMetadata {
        name: name.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: export_timestamp(),
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
    let status = Command::new("/sbin/zfs")
        .args(["snapshot", &snapshot_name])
        .status()
        .map_err(|e| Error::Zfs(format!("Failed to create snapshot: {}", e)))?;

    if !status.success() {
        return Err(Error::Zfs("Failed to create export snapshot".into()));
    }

    let result = export_jail_zfs_inner(&snapshot_name, output_path, name, hostname, ip);

    // Destroy the snapshot on success or failure.
    let _ = Command::new("/sbin/zfs")
        .args(["destroy", &snapshot_name])
        .status();

    result
}

/// Split out so the caller can guarantee snapshot cleanup.
fn export_jail_zfs_inner(
    snapshot_name: &str,
    output_path: &Path,
    name: &str,
    hostname: Option<&str>,
    ip: Option<&str>,
) -> Result<()> {
    // Create output file
    let output_file = create_output_file(output_path)?;

    let dataset = snapshot_name.split('@').next().unwrap_or(snapshot_name);

    // Write metadata header first
    let metadata = ExportMetadata {
        name: name.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: export_timestamp(),
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

    let mut zfs_send = Command::new("/sbin/zfs")
        .args(["send", snapshot_name])
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| Error::Zfs(format!("Failed to spawn zfs send: {}", e)))?;

    {
        let mut outfile = std::fs::OpenOptions::new()
            .append(true)
            .open(output_path)
            .map_err(|e| Error::Zfs(format!("Failed to open output for append: {}", e)))?;
        let zfs_stdout = zfs_send
            .stdout
            .take()
            .ok_or_else(|| Error::Zfs("Failed to capture zfs send stdout".into()))?;
        let mut reader = std::io::BufReader::new(zfs_stdout);
        std::io::copy(&mut reader, &mut outfile)
            .map_err(|e| Error::Zfs(format!("Failed to write zfs send output: {}", e)))?;
    }

    let status = zfs_send
        .wait()
        .map_err(|e| Error::Zfs(format!("Failed to wait for zfs send: {}", e)))?;

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
    zfs_dataset: Option<&str>,
) -> Result<String> {
    println!("Importing jail from {}", archive_path.display());

    // Open archive
    let file = open_archive(archive_path)?;

    // Check for ZFS format
    let mut magic = [0u8; 8];
    {
        let mut reader = std::io::BufReader::new(&file);
        if reader.read_exact(&mut magic).is_ok() && &magic == b"BSZFS001" {
            drop(reader);
            return import_jail_zfs(archive_path, target_path, new_name, zfs_dataset);
        }
    }

    // Reopen file for tar/zstd
    let file = open_archive(archive_path)?;

    // Decompress
    let decoder = open_decoder(file)?;

    // Open tar archive
    let mut archive = Archive::new(decoder);

    // Extract metadata first
    let mut metadata: Option<ExportMetadata> = None;

    let temp_dir = target_path.parent().unwrap_or(Path::new("/tmp"));
    let temp_extract = temp_dir.join(format!(".import-{:016x}", rand::random::<u64>()));

    // A pre-existing temp path may be a planted symlink.
    if let Ok(meta) = std::fs::symlink_metadata(&temp_extract) {
        let _ = meta; // path exists -- refuse to use it
        return Err(Error::JailOperation(format!(
            "Temp directory {} already exists, refusing to proceed",
            temp_extract.display()
        )));
    }

    std::fs::create_dir_all(&temp_extract)
        .map_err(|e| Error::JailOperation(format!("Failed to create temp dir: {}", e)))?;

    let extract_result = (|| -> Result<ExportMetadata> {
        for entry in archive
            .entries()
            .map_err(|e| Error::JailOperation(format!("Failed to read archive entries: {}", e)))?
        {
            let mut entry = entry.map_err(|e| {
                Error::JailOperation(format!("Failed to read archive entry: {}", e))
            })?;

            let path = entry_path(&entry)?;

            if path.to_string_lossy() == ".blackship-metadata.json" {
                let mut content = String::new();
                entry_read_to_string(&mut entry, &mut content)?;
                metadata = Some(serde_json::from_str(&content).map_err(|e| {
                    Error::JailOperation(format!("Failed to parse metadata: {}", e))
                })?);
            } else {
                entry.unpack_in(&temp_extract).map_err(|e| {
                    Error::JailOperation(format!("Failed to extract {}: {}", path.display(), e))
                })?;
            }
        }

        metadata.ok_or_else(|| Error::JailOperation("Archive missing metadata".into()))
    })();

    let metadata = match extract_result {
        Ok(m) => m,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&temp_extract);
            return Err(e);
        }
    };

    let jail_name = new_name.unwrap_or(&metadata.name);

    // Move rootfs to target
    let rootfs_src = temp_extract.join("rootfs");

    if !rootfs_src.exists() {
        let _ = std::fs::remove_dir_all(&temp_extract);
        return Err(Error::JailOperation(
            "Archive does not contain a rootfs directory".into(),
        ));
    }

    // A symlinked rootfs from a hostile archive would redirect the rename below.
    let rootfs_meta = std::fs::symlink_metadata(&rootfs_src)
        .map_err(|e| Error::JailOperation(format!("Failed to stat rootfs: {}", e)))?;
    if rootfs_meta.file_type().is_symlink() {
        let _ = std::fs::remove_dir_all(&temp_extract);
        return Err(Error::JailOperation(
            "Extracted rootfs is a symlink, refusing to proceed".into(),
        ));
    }
    if !rootfs_meta.is_dir() {
        let _ = std::fs::remove_dir_all(&temp_extract);
        return Err(Error::JailOperation(
            "Extracted rootfs is not a directory".into(),
        ));
    }

    // Validate no ancestor of the target path is a symlink
    if let Some(data_dir) = target_path.parent().and_then(|p| p.parent()) {
        crate::blueprint::context::reject_symlink_ancestors(data_dir, target_path)?;
    }

    if target_path.exists() {
        std::fs::remove_dir_all(target_path)
            .map_err(|e| Error::JailOperation(format!("Failed to remove existing: {}", e)))?;
    }
    std::fs::rename(&rootfs_src, target_path)
        .map_err(|e| Error::JailOperation(format!("Failed to move rootfs: {}", e)))?;

    let canonical = std::fs::canonicalize(target_path)
        .map_err(|e| Error::JailOperation(format!("Failed to canonicalize target: {}", e)))?;
    let parent = target_path.parent().unwrap_or(Path::new("/"));
    let canonical_parent = std::fs::canonicalize(parent)
        .map_err(|e| Error::JailOperation(format!("Failed to canonicalize parent: {}", e)))?;
    if !canonical.starts_with(&canonical_parent) {
        let _ = std::fs::remove_dir_all(target_path);
        return Err(Error::JailOperation(
            "Imported rootfs resolved outside target directory".into(),
        ));
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
    zfs_dataset: Option<&str>,
) -> Result<String> {
    println!("Importing ZFS stream from {}", archive_path.display());

    let file = open_archive(archive_path)?;

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
    const MAX_METADATA_LEN: usize = 10 * 1024 * 1024; // 10 MB
    if meta_len > MAX_METADATA_LEN {
        return Err(Error::JailOperation(format!(
            "Metadata length {} exceeds maximum allowed size of {} bytes",
            meta_len, MAX_METADATA_LEN
        )));
    }

    // Read metadata
    let mut meta_bytes = vec![0u8; meta_len];
    reader
        .read_exact(&mut meta_bytes)
        .map_err(|e| Error::JailOperation(format!("Failed to read metadata: {}", e)))?;

    let metadata: ExportMetadata = serde_json::from_slice(&meta_bytes)
        .map_err(|e| Error::JailOperation(format!("Failed to parse metadata: {}", e)))?;

    let jail_name = new_name.unwrap_or(&metadata.name);

    let dataset = if let Some(ds) = zfs_dataset {
        ds.to_string()
    } else {
        target_path
            .strip_prefix("/")
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| target_path.to_string_lossy().to_string())
    };

    let mut zfs_recv = Command::new("/sbin/zfs")
        .args([
            "receive",
            "-u",
            "-x",
            "mountpoint",
            "-x",
            "canmount",
            &dataset,
        ])
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| Error::Zfs(format!("Failed to spawn zfs receive: {}", e)))?;

    {
        let zfs_stdin = zfs_recv
            .stdin
            .take()
            .ok_or_else(|| Error::Zfs("Failed to capture zfs receive stdin".into()))?;
        let mut writer = std::io::BufWriter::new(zfs_stdin);
        std::io::copy(&mut reader, &mut writer)
            .map_err(|e| Error::Zfs(format!("Failed to pipe to zfs receive: {}", e)))?;
    }

    let status = zfs_recv
        .wait()
        .map_err(|e| Error::Zfs(format!("Failed to wait for zfs receive: {}", e)))?;

    if !status.success() {
        return Err(Error::Zfs("ZFS receive failed".into()));
    }

    println!("Imported jail '{}' to {}", jail_name, target_path.display());
    Ok(jail_name.to_string())
}

/// Human-readable export timestamp in the system's local time zone.
fn export_timestamp() -> String {
    Zoned::now()
        .round(Unit::Second)
        .map(|zdt| zdt.to_string())
        .unwrap_or_else(|_| Zoned::now().to_string())
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
