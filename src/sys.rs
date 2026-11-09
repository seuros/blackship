//! System detection and version information

// FFI module: kldload(2), sysctl(3), mount helpers.
#![allow(unsafe_code)]

/// Constants read from the FreeBSD headers at build time; see `build/sys_consts.c`.
pub mod consts {
    #![allow(clippy::unreadable_literal)]
    include!(concat!(env!("OUT_DIR"), "/sys_consts.rs"));
}

use crate::error::{Error, Result};
use std::ffi::{CStr, CString};
use std::fmt;

/// Decode owned bytes, reusing the buffer's allocation when it is valid UTF-8.
pub fn string_from_utf8_lossy(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

// kldload(2) is not exposed by the libc crate.
// SAFETY: matches <sys/linker.h>: int kldload(const char *file).
unsafe extern "C" {
    fn kldload(file: *const libc::c_char) -> libc::c_int;
}

/// Load kernel modules via kldload(2), ignoring ones already loaded (EEXIST)
/// or compiled into the kernel (ENOENT).
pub fn load_modules(modules: &[&str]) -> Result<()> {
    for module in modules {
        let name = CString::new(*module)
            .map_err(|e| Error::Network(format!("Invalid module name {module}: {e}")))?;

        // SAFETY: live NUL-terminated string.
        if unsafe { kldload(name.as_ptr()) } < 0 {
            let err = std::io::Error::last_os_error();
            let errno = err.raw_os_error().unwrap_or(0);
            if errno != libc::EEXIST && errno != libc::ENOENT {
                return Err(Error::Network(format!(
                    "Failed to load module {module}: {err}"
                )));
            }
        }
    }
    Ok(())
}

/// FreeBSD release type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseType {
    /// -CURRENT development branch
    Current,
    /// -STABLE maintenance branch
    Stable,
    /// -RELEASE official release
    Release,
    /// -RC release candidate
    Rc(u8),
}

impl fmt::Display for ReleaseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Current => write!(f, "CURRENT"),
            Self::Stable => write!(f, "STABLE"),
            Self::Release => write!(f, "RELEASE"),
            Self::Rc(n) => write!(f, "RC{n}"),
        }
    }
}

/// FreeBSD OS version information
#[derive(Debug, Clone)]
pub struct OsVersion {
    /// Major version number
    pub major: u8,
    /// Minor version number
    pub minor: u8,
    /// Patch level (from -pX suffix)
    pub patch: Option<u8>,
    /// Release type (CURRENT, STABLE, RELEASE, etc.)
    pub release_type: ReleaseType,
}

impl OsVersion {
    /// Detect the FreeBSD kernel version
    ///
    /// Uses native `uname(2)` syscall to get the kernel version string, which is what
    /// determines driver capabilities (e.g., VLAN filtering in `if_bridge`).
    ///
    /// # Examples
    ///
    /// Parses version strings like:
    /// - `16.0-CURRENT`
    /// - `15.1-RELEASE`
    /// - `15.1-RELEASE-p1`
    /// - `15.2-STABLE`
    /// - `15.1-BETA1`
    /// - `15.1-RC2`
    pub fn detect_kernel() -> Result<Self> {
        // SAFETY: all-zero is a valid utsname.
        let mut utsname: libc::utsname = unsafe { std::mem::zeroed() };

        // SAFETY: valid exclusive pointer.
        let result = unsafe { libc::uname(&raw mut utsname) };

        if result != 0 {
            return Err(Error::CommandFailed {
                command: "uname(2) syscall".to_string(),
                message: format!("uname syscall failed with code {result}"),
            });
        }

        // SAFETY: uname succeeded, so release is NUL-terminated.
        let release_cstr = unsafe { CStr::from_ptr(utsname.release.as_ptr()) };
        let version_str = release_cstr
            .to_str()
            .map_err(|e| Error::InvalidVersion(format!("Invalid UTF-8 in uname.release: {e}")))?
            .to_string();

        Self::parse(&version_str)
    }

    /// Parse a FreeBSD version string
    pub fn parse(s: &str) -> Result<Self> {
        // Example: "16.0-CURRENT" or "15.1-RELEASE-p1"
        let parts: Vec<&str> = s.split('-').collect();

        if parts.len() < 2 {
            return Err(Error::InvalidVersion(format!(
                "Invalid version format: {s}"
            )));
        }

        // Parse version number (e.g., "16.0")
        let version_nums: Vec<&str> = parts[0].split('.').collect();
        if version_nums.len() != 2 {
            return Err(Error::InvalidVersion(format!(
                "Invalid version number: {}",
                parts[0]
            )));
        }

        let major = version_nums[0].parse::<u8>().map_err(|_| {
            Error::InvalidVersion(format!("Invalid major version: {}", version_nums[0]))
        })?;

        let minor = version_nums[1].parse::<u8>().map_err(|_| {
            Error::InvalidVersion(format!("Invalid minor version: {}", version_nums[1]))
        })?;

        // Parse release type
        let release_type = match parts[1] {
            "CURRENT" => ReleaseType::Current,
            "STABLE" => ReleaseType::Stable,
            "RELEASE" => ReleaseType::Release,
            s if s.starts_with("RC") => {
                let num = s
                    .strip_prefix("RC")
                    .and_then(|n| n.parse::<u8>().ok())
                    .unwrap_or(1);
                ReleaseType::Rc(num)
            }
            // Treat unknown release types (e.g., custom kernels) as CURRENT
            _ => ReleaseType::Current,
        };

        // Parse patch level (e.g., "p1" from "15.1-RELEASE-p1")
        let patch = if parts.len() > 2 && parts[2].starts_with('p') {
            parts[2]
                .strip_prefix('p')
                .and_then(|n| n.parse::<u8>().ok())
        } else {
            None
        };

        Ok(Self {
            major,
            minor,
            patch,
            release_type,
        })
    }

    /// Check if the OS supports VLAN filtering in `if_bridge`
    ///
    /// VLAN filtering requires FreeBSD 15.0 or later.
    pub const fn supports_vlan_filtering(&self) -> bool {
        self.major >= 15
    }

    /// Check if pkgbase is mandatory
    ///
    /// FreeBSD 16.0+ requires pkgbase; distribution sets are removed.
    pub const fn requires_pkgbase(&self) -> bool {
        self.major >= 16
    }

    /// Check if jail descriptors are supported
    ///
    /// Jail descriptors (owning fds, `EVFILT_JAILDESC`) require FreeBSD 16.0+.
    pub const fn supports_jail_descriptors(&self) -> bool {
        self.major >= 16
    }

    /// Check if kqueue `EVFILT_JAIL` is supported
    ///
    /// Kqueue jail event monitoring requires FreeBSD 16.0+.
    pub const fn supports_jail_kqueue(&self) -> bool {
        self.major >= 16
    }
}

impl fmt::Display for OsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}-{}", self.major, self.minor, self.release_type)?;
        if let Some(patch) = self.patch {
            write!(f, "-p{patch}")?;
        }
        Ok(())
    }
}

/// The stock devfs ruleset for jails from /etc/defaults/devfs.rules.
pub const DEVFS_RULESET_JAIL: u32 = 4;

/// The interface group marking host-side interfaces blackship owns.
pub const IFACE_GROUP: &str = "blackship";

/// Write an integer sysctl via sysctlbyname(3).
pub fn set_sysctl_int(name: &str, value: i32) -> Result<()> {
    let c_name = CString::new(name)
        .map_err(|e| Error::Network(format!("Invalid sysctl name {name}: {e}")))?;
    // SAFETY: NUL-terminated name; newp/newlen describe a live `value`.
    let rc = unsafe {
        libc::sysctlbyname(
            c_name.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            (&raw const value).cast::<libc::c_void>(),
            std::mem::size_of::<i32>(),
        )
    };
    if rc != 0 {
        return Err(Error::Network(format!(
            "sysctl {}={} failed: {}",
            name,
            value,
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Add an interface to the blackship ownership group.
pub fn tag_interface(iface: &str) -> Result<()> {
    let status = std::process::Command::new("/sbin/ifconfig")
        .args([iface, "group", IFACE_GROUP])
        .status()
        .map_err(|e| Error::Network(format!("Failed to run ifconfig: {e}")))?;
    if !status.success() {
        return Err(Error::Network(format!(
            "Failed to add {iface} to group {IFACE_GROUP}"
        )));
    }
    Ok(())
}

/// Check whether an interface carries the blackship ownership group.
///
/// Used as a sentinel before destroying interfaces found by name, so cleanup
/// never takes down an interface it does not own.
pub fn interface_is_tagged(iface: &str) -> bool {
    std::process::Command::new("/sbin/ifconfig")
        .args(["-g", IFACE_GROUP])
        .output()
        .is_ok_and(|o| {
            o.status.success()
                && String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .any(|line| line.trim() == iface)
        })
}

/// Every interface carrying the blackship ownership group.
///
/// epairs are deliberately not named after their jail, so the group tag is the
/// only reliable oracle for "blackship created this".
pub fn list_tagged_interfaces() -> Vec<String> {
    std::process::Command::new("/sbin/ifconfig")
        .args(["-g", IFACE_GROUP])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// `d` in nanoseconds, saturating at `u64::MAX` (584 years).
pub fn nanos(d: std::time::Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

/// Run a libxo-capable base utility and parse its JSON output.
pub fn run_json(program: &str, args: &[&str]) -> Result<serde_json::Value> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| Error::CommandFailed {
            command: program.to_string(),
            message: e.to_string(),
        })?;
    if !output.status.success() {
        return Err(Error::CommandFailed {
            command: format!("{} {}", program, args.join(" ")),
            message: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }
    serde_json::from_slice(&output.stdout).map_err(|e| Error::CommandFailed {
        command: program.to_string(),
        message: format!("invalid libxo JSON: {e}"),
    })
}

/// Read the mount table in `mount -p` format.
pub fn mount_table() -> Result<String> {
    let output = std::process::Command::new("/sbin/mount")
        .arg("-p")
        .output()?;
    if !output.status.success() {
        return Err(Error::JailOperation(
            "Failed to inspect mounted filesystems".to_string(),
        ));
    }
    Ok(string_from_utf8_lossy(output.stdout))
}

/// Mountpoints at or below `jail_root`, deepest first so unmounting in order
/// never blocks on a child mount.
pub fn mounted_paths_under(
    jail_root: &std::path::Path,
    mount_output: &str,
) -> Vec<std::path::PathBuf> {
    let root = jail_root.to_string_lossy();
    let prefix = format!("{root}/");
    let mut mountpoints: Vec<std::path::PathBuf> = mount_output
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let _source = fields.next()?;
            let mountpoint = fields.next()?;
            if mountpoint == root || mountpoint.starts_with(&prefix) {
                Some(std::path::PathBuf::from(mountpoint))
            } else {
                None
            }
        })
        .collect();

    mountpoints.sort_by_key(|path| std::cmp::Reverse(path.to_string_lossy().len()));
    mountpoints
}

/// Mount devfs at `dev_path` via nmount(2).
///
/// devfs has no `vfs_cmount`, so the legacy mount(2) syscall returns
/// EOPNOTSUPP; it is only mountable through nmount(2).
pub fn mount_devfs(dev_path: &std::path::Path) -> Result<()> {
    let path_str = dev_path
        .to_str()
        .ok_or_else(|| Error::JailOperation(format!("Invalid path: {}", dev_path.display())))?;

    let fspath_val =
        CString::new(path_str).map_err(|e| Error::JailOperation(format!("Invalid path: {e}")))?;

    let mut iov = [c"fstype", c"devfs", c"fspath", fspath_val.as_c_str()].map(|s| libc::iovec {
        iov_base: s.as_ptr().cast_mut().cast(),
        iov_len: s.to_bytes_with_nul().len(),
    });

    let niov = libc::c_uint::try_from(iov.len())
        .map_err(|_| Error::JailOperation("too many nmount options".into()))?;
    // SAFETY: iov points at live NUL-terminated strings that nmount only reads.
    let rc = unsafe { libc::nmount(iov.as_mut_ptr(), niov, 0) };
    if rc != 0 {
        return Err(Error::JailOperation(format!(
            "Failed to mount devfs at {}: {}",
            dev_path.display(),
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Apply a devfs ruleset to a mounted devfs instance.
pub fn apply_devfs_ruleset(dev_path: &std::path::Path, ruleset: u32) -> Result<()> {
    let status = std::process::Command::new("/sbin/devfs")
        .args(["-m"])
        .arg(dev_path)
        .args(["rule", "-s", &ruleset.to_string(), "applyset"])
        .status()
        .map_err(|e| Error::JailOperation(format!("Failed to run devfs: {e}")))?;
    if !status.success() {
        return Err(Error::JailOperation(format!(
            "Failed to apply devfs ruleset {} at {}",
            ruleset,
            dev_path.display()
        )));
    }
    Ok(())
}

/// Write a path without following symlinks: unlink first, then `O_CREAT|O_EXCL` (TOCTOU).
pub fn write_nofollow(path: &std::path::Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    // Usually NotFound; anything worse makes the O_EXCL open below fail loudly.
    let _ = std::fs::remove_file(path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::JailOperation(format!(
                "Failed to create directory {}: {}",
                parent.display(),
                e
            ))
        })?;
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| Error::JailOperation(format!("Failed to create {}: {}", path.display(), e)))?;
    f.write_all(data)
        .map_err(|e| Error::JailOperation(format!("Failed to write {}: {}", path.display(), e)))
}

/// Remove a directory tree that may contain schg/uchg-flagged files
/// (FreeBSD userlands protect init, libc, and friends with system flags).
pub fn remove_tree_with_flags(path: &std::path::Path) -> std::io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    // Best effort; real failures surface from remove_dir_all.
    let _ = std::process::Command::new("/bin/chflags")
        .args(["-R", "noschg,nouchg"])
        .arg(path)
        .status();
    std::fs::remove_dir_all(path)
}

/// Unmount the devfs instance of a jail root, ignoring "not mounted" errors.
pub fn unmount_jail_devfs(jail_root: &std::path::Path) {
    unmount_quiet(&jail_root.join("dev"));
}

/// Unmount a filesystem, ignoring "not mounted" errors.
pub fn unmount_quiet(path: &std::path::Path) {
    if let Some(path_str) = path.to_str()
        && let Ok(c_path) = CString::new(path_str)
    {
        // SAFETY: live NUL-terminated path.
        unsafe {
            libc::unmount(c_path.as_ptr(), 0);
        }
    }
}

#[cfg(test)]
mod tests;

/// Bytes of a fixed `c_char` buffer up to the first NUL (or all of it), for i8 and u8 `c_char`.
pub fn c_buf_bytes(buf: &[libc::c_char]) -> Vec<u8> {
    buf.iter()
        .map(|c| u8::from_ne_bytes(c.to_ne_bytes()))
        .take_while(|&b| b != 0)
        .collect()
}
