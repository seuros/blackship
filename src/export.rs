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
use tar::Archive;

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

/// Get the path of a tar entry, mapping errors to `JailOperation`
fn entry_path<R: std::io::Read>(entry: &tar::Entry<R>) -> Result<std::path::PathBuf> {
    entry
        .path()
        .map_err(|e| Error::JailOperation(format!("Failed to read entry path: {e}")))
        .map(|p| p.to_path_buf())
}

/// Archive member holding the export metadata.
const METADATA_ENTRY: &str = ".blackship-metadata.json";

/// Maximum size for metadata entries read from tar archives (10 MB).
const MAX_TAR_METADATA_SIZE: u64 = 10 * 1024 * 1024;

/// Largest metadata block a ZFS-format archive may declare.
const MAX_METADATA_LEN: usize = 10 * 1024 * 1024; // 10 MB

/// Read a tar entry to string, refusing entries over `MAX_TAR_METADATA_SIZE`.
fn entry_read_to_string<R: std::io::Read>(
    entry: &mut tar::Entry<R>,
    buf: &mut String,
) -> Result<()> {
    let size = entry.header().size().unwrap_or(0);
    if size > MAX_TAR_METADATA_SIZE {
        return Err(Error::JailOperation(format!(
            "Metadata entry size {size} exceeds maximum allowed size of {MAX_TAR_METADATA_SIZE} bytes"
        )));
    }
    entry
        .read_to_string(buf)
        .map_err(|e| Error::JailOperation(format!("Failed to read metadata: {e}")))
        .map(|_| ())
}

/// Open a jail archive file, mapping the IO error to `JailOperation`
fn open_archive(path: &Path) -> Result<File> {
    File::open(path).map_err(|e| Error::JailOperation(format!("Failed to open archive: {e}")))
}

/// Create an output file, mapping the IO error to `JailOperation`
fn create_output_file(path: &Path) -> Result<File> {
    File::create(path)
        .map_err(|e| Error::JailOperation(format!("Failed to create output file: {e}")))
}

/// Wrap a file in a zstd decoder
fn open_decoder(file: File) -> Result<zstd::stream::Decoder<'static, std::io::BufReader<File>>> {
    zstd::stream::Decoder::new(file)
        .map_err(|e| Error::JailOperation(format!("Failed to decompress: {e}")))
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
                Error::JailOperation(format!("Failed to read metadata length: {e}"))
            })?;
            let len = u32::from_le_bytes(len_bytes) as usize;
            if len > MAX_METADATA_LEN {
                return Err(Error::JailOperation(format!(
                    "Metadata length {len} exceeds maximum allowed size of {MAX_METADATA_LEN} bytes"
                )));
            }
            let mut buf = vec![0u8; len];
            reader
                .read_exact(&mut buf)
                .map_err(|e| Error::JailOperation(format!("Failed to read metadata: {e}")))?;
            return serde_json::from_slice(&buf)
                .map_err(|e| Error::JailOperation(format!("Failed to parse metadata: {e}")));
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
        .map_err(|e| Error::JailOperation(format!("Failed to read archive entries: {e}")))?
    {
        let mut entry = entry
            .map_err(|e| Error::JailOperation(format!("Failed to read archive entry: {e}")))?;
        let path = entry_path(&entry)?;

        if path.to_string_lossy() == METADATA_ENTRY {
            let mut content = String::new();
            entry_read_to_string(&mut entry, &mut content)?;
            return serde_json::from_str(&content)
                .map_err(|e| Error::JailOperation(format!("Failed to parse metadata: {e}")));
        }
    }

    Err(Error::JailOperation("Archive missing metadata".into()))
}

/// Export a jail to a tar.zst archive
///
/// bsdtar does the archiving: it keeps hardlinks as links (`/rescue` is one
/// binary under ~150 names), file flags, and skips sockets with a warning
/// instead of failing. `--one-file-system` leaves out devfs and anything else
/// mounted into the root. The archive is written next to `output_path` and
/// renamed into place only when complete.
pub fn export_jail(
    name: &str,
    jail_path: &Path,
    output_path: &Path,
    hostname: Option<&str>,
    ip: Option<&str>,
) -> Result<()> {
    println!("Exporting jail '{}' to {}", name, output_path.display());

    let metadata = ExportMetadata {
        name: name.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: export_timestamp(),
        original_path: jail_path.to_string_lossy().to_string(),
        ip: ip.map(String::from),
        hostname: hostname.map(String::from),
    };
    let metadata_json = serde_json::to_string_pretty(&metadata)
        .map_err(|e| Error::JailOperation(format!("Failed to serialize metadata: {e}")))?;

    let scratch = sibling(output_path, "export")?;
    let partial = scratch.join("archive.tar.zst");
    let result = write_archive(&scratch, &partial, jail_path, &metadata_json).and_then(|()| {
        std::fs::rename(&partial, output_path)
            .map_err(|e| Error::JailOperation(format!("Failed to move archive into place: {e}")))
    });
    let _ = std::fs::remove_dir_all(&scratch); // best-effort; `result` is reported
    result?;

    println!("Export complete: {}", output_path.display());
    Ok(())
}

fn write_archive(scratch: &Path, partial: &Path, jail_path: &Path, metadata: &str) -> Result<()> {
    std::fs::write(scratch.join(METADATA_ENTRY), metadata)
        .map_err(|e| Error::JailOperation(format!("Failed to write metadata: {e}")))?;

    println!("  Adding jail filesystem...");
    let status = Command::new("/usr/bin/bsdtar")
        .args(["--zstd", "--fflags", "--one-file-system"])
        // The root goes in as `rootfs/`; the metadata name matches neither.
        .args(["-s", ",^\\./,rootfs/,", "-s", ",^\\.$,rootfs,", "-cf"])
        .arg(partial)
        .arg("-C")
        .arg(scratch)
        .arg(METADATA_ENTRY)
        .arg("-C")
        .arg(jail_path)
        .arg(".")
        .status()
        .map_err(|e| Error::JailOperation(format!("Failed to run bsdtar: {e}")))?;
    if !status.success() {
        return Err(Error::JailOperation(format!("bsdtar failed: {status}")));
    }
    Ok(())
}

/// A fresh scratch directory beside `path`, on the same filesystem so the
/// final rename is atomic.
fn sibling(path: &Path, what: &str) -> Result<std::path::PathBuf> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let dir = parent.join(format!(".blackship-{what}-{:016x}", rand::random::<u64>()));
    // create_dir, not create_dir_all: an existing (possibly planted) path fails.
    std::fs::create_dir(&dir)
        .map_err(|e| Error::JailOperation(format!("Failed to create {}: {e}", dir.display())))?;
    Ok(dir)
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
    let snapshot_name = format!("{dataset}@blackship-export");

    // Create snapshot
    let status = Command::new("/sbin/zfs")
        .args(["snapshot", &snapshot_name])
        .status()
        .map_err(|e| Error::Zfs(format!("Failed to create snapshot: {e}")))?;

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
        original_path: format!("zfs:{dataset}"),
        ip: ip.map(String::from),
        hostname: hostname.map(String::from),
    };

    let mut output = std::io::BufWriter::new(output_file);

    // Write magic header and metadata length
    let metadata_json = serde_json::to_vec(&metadata)
        .map_err(|e| Error::JailOperation(format!("Failed to serialize metadata: {e}")))?;

    output
        .write_all(b"BSZFS001")
        .map_err(|e| Error::JailOperation(format!("Failed to write header: {e}")))?;
    let metadata_len = u32::try_from(metadata_json.len())
        .map_err(|_| Error::JailOperation("Metadata too large to export".into()))?;
    output
        .write_all(&metadata_len.to_le_bytes())
        .map_err(|e| Error::JailOperation(format!("Failed to write length: {e}")))?;
    output
        .write_all(&metadata_json)
        .map_err(|e| Error::JailOperation(format!("Failed to write metadata: {e}")))?;

    output
        .flush()
        .map_err(|e| Error::JailOperation(format!("Failed to flush: {e}")))?;

    let mut zfs_send = Command::new("/sbin/zfs")
        .args(["send", snapshot_name])
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| Error::Zfs(format!("Failed to spawn zfs send: {e}")))?;

    {
        let mut outfile = std::fs::OpenOptions::new()
            .append(true)
            .open(output_path)
            .map_err(|e| Error::Zfs(format!("Failed to open output for append: {e}")))?;
        let zfs_stdout = zfs_send
            .stdout
            .take()
            .ok_or_else(|| Error::Zfs("Failed to capture zfs send stdout".into()))?;
        let mut reader = std::io::BufReader::new(zfs_stdout);
        std::io::copy(&mut reader, &mut outfile)
            .map_err(|e| Error::Zfs(format!("Failed to write zfs send output: {e}")))?;
    }

    let status = zfs_send
        .wait()
        .map_err(|e| Error::Zfs(format!("Failed to wait for zfs send: {e}")))?;

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

    let metadata = read_metadata(archive_path)?;

    let temp_extract = sibling(target_path, "import")?;
    if let Err(e) = extract_rootfs(archive_path, &temp_extract) {
        let _ = crate::sys::remove_tree_with_flags(&temp_extract); // best-effort; `e` is reported
        return Err(e);
    }

    let jail_name = new_name.unwrap_or(&metadata.name);

    // Move rootfs to target
    let rootfs_src = temp_extract.join("rootfs");

    if !rootfs_src.exists() {
        // Cleanup; keep the original error.
        let _ = crate::sys::remove_tree_with_flags(&temp_extract);
        return Err(Error::JailOperation(
            "Archive does not contain a rootfs directory".into(),
        ));
    }

    // A symlinked rootfs from a hostile archive would redirect the rename below.
    let rootfs_meta = std::fs::symlink_metadata(&rootfs_src)
        .map_err(|e| Error::JailOperation(format!("Failed to stat rootfs: {e}")))?;
    if rootfs_meta.file_type().is_symlink() {
        // Cleanup; keep the original error.
        let _ = crate::sys::remove_tree_with_flags(&temp_extract);
        return Err(Error::JailOperation(
            "Extracted rootfs is a symlink, refusing to proceed".into(),
        ));
    }
    if !rootfs_meta.is_dir() {
        // Cleanup; keep the original error.
        let _ = crate::sys::remove_tree_with_flags(&temp_extract);
        return Err(Error::JailOperation(
            "Extracted rootfs is not a directory".into(),
        ));
    }

    // Validate no ancestor of the target path is a symlink
    if let Some(data_dir) = target_path.parent().and_then(|p| p.parent()) {
        crate::blueprint::context::reject_symlink_ancestors(data_dir, target_path)?;
    }

    if target_path.exists() {
        crate::sys::remove_tree_with_flags(target_path)?;
    }
    std::fs::rename(&rootfs_src, target_path)
        .map_err(|e| Error::JailOperation(format!("Failed to move rootfs: {e}")))?;

    let canonical = std::fs::canonicalize(target_path)
        .map_err(|e| Error::JailOperation(format!("Failed to canonicalize target: {e}")))?;
    let parent = target_path.parent().unwrap_or_else(|| Path::new("/"));
    let canonical_parent = std::fs::canonicalize(parent)
        .map_err(|e| Error::JailOperation(format!("Failed to canonicalize parent: {e}")))?;
    if !canonical.starts_with(&canonical_parent) {
        // Cleanup; keep the original error.
        let _ = crate::sys::remove_tree_with_flags(target_path);
        return Err(Error::JailOperation(
            "Imported rootfs resolved outside target directory".into(),
        ));
    }

    // Clean up temp
    let _ = crate::sys::remove_tree_with_flags(&temp_extract);

    println!("Imported jail '{}' to {}", jail_name, target_path.display());
    println!("  Original: {}", metadata.name);
    if let Some(ip) = metadata.ip {
        println!("  IP: {ip}");
    }

    Ok(jail_name.to_string())
}

/// Extract the archive's `rootfs/` under `dest` with bsdtar, restoring
/// hardlinks and file flags. bsdtar's defaults refuse absolute paths, `..`,
/// and extraction through symlinks, which is what a hostile archive needs.
fn extract_rootfs(archive_path: &Path, dest: &Path) -> Result<()> {
    let status = Command::new("/usr/bin/bsdtar")
        .args(["-x", "--fflags", "--numeric-owner", "-p", "-f"])
        .arg(archive_path)
        .arg("-C")
        .arg(dest)
        .arg("rootfs")
        .status()
        .map_err(|e| Error::JailOperation(format!("Failed to run bsdtar: {e}")))?;
    if !status.success() {
        return Err(Error::JailOperation(format!("bsdtar failed: {status}")));
    }
    Ok(())
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
        .map_err(|e| Error::JailOperation(format!("Failed to read header: {e}")))?;

    // Read metadata length
    let mut len_bytes = [0u8; 4];
    reader
        .read_exact(&mut len_bytes)
        .map_err(|e| Error::JailOperation(format!("Failed to read length: {e}")))?;
    let meta_len = u32::from_le_bytes(len_bytes) as usize;
    if meta_len > MAX_METADATA_LEN {
        return Err(Error::JailOperation(format!(
            "Metadata length {meta_len} exceeds maximum allowed size of {MAX_METADATA_LEN} bytes"
        )));
    }

    // Read metadata
    let mut meta_bytes = vec![0u8; meta_len];
    reader
        .read_exact(&mut meta_bytes)
        .map_err(|e| Error::JailOperation(format!("Failed to read metadata: {e}")))?;

    let metadata: ExportMetadata = serde_json::from_slice(&meta_bytes)
        .map_err(|e| Error::JailOperation(format!("Failed to parse metadata: {e}")))?;

    let jail_name = new_name.unwrap_or(&metadata.name);

    let dataset = if let Some(ds) = zfs_dataset {
        ds.to_string()
    } else {
        target_path.strip_prefix("/").map_or_else(
            |_| target_path.to_string_lossy().to_string(),
            |p| p.to_string_lossy().into_owned(),
        )
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
        .map_err(|e| Error::Zfs(format!("Failed to spawn zfs receive: {e}")))?;

    {
        let zfs_stdin = zfs_recv
            .stdin
            .take()
            .ok_or_else(|| Error::Zfs("Failed to capture zfs receive stdin".into()))?;
        let mut writer = std::io::BufWriter::new(zfs_stdin);
        std::io::copy(&mut reader, &mut writer)
            .map_err(|e| Error::Zfs(format!("Failed to pipe to zfs receive: {e}")))?;
    }

    let status = zfs_recv
        .wait()
        .map_err(|e| Error::Zfs(format!("Failed to wait for zfs receive: {e}")))?;

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
        .map_or_else(|_| Zoned::now().to_string(), |zdt| zdt.to_string())
}

#[cfg(test)]
mod tests;
