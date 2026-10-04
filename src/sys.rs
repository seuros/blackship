//! System detection and version information

/// Constants read from the FreeBSD headers at build time; see build/sys_consts.c.
pub mod consts {
    include!(concat!(env!("OUT_DIR"), "/sys_consts.rs"));
}

use crate::error::{Error, Result};
use std::ffi::{CStr, CString};
use std::fmt;

// kldload(2) is not exposed by the libc crate.
unsafe extern "C" {
    fn kldload(file: *const libc::c_char) -> libc::c_int;
}

/// Load kernel modules via kldload(2), ignoring ones already loaded (EEXIST)
/// or compiled into the kernel (ENOENT).
pub fn load_modules(modules: &[&str]) -> Result<()> {
    for module in modules {
        let name = CString::new(*module)
            .map_err(|e| Error::Network(format!("Invalid module name {}: {}", module, e)))?;

        if unsafe { kldload(name.as_ptr()) } < 0 {
            let err = std::io::Error::last_os_error();
            let errno = err.raw_os_error().unwrap_or(0);
            if errno != libc::EEXIST && errno != libc::ENOENT {
                return Err(Error::Network(format!(
                    "Failed to load module {}: {}",
                    module, err
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
            ReleaseType::Current => write!(f, "CURRENT"),
            ReleaseType::Stable => write!(f, "STABLE"),
            ReleaseType::Release => write!(f, "RELEASE"),
            ReleaseType::Rc(n) => write!(f, "RC{}", n),
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
    /// determines driver capabilities (e.g., VLAN filtering in if_bridge).
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
        // Use native uname(2) syscall instead of spawning a process
        let mut utsname: libc::utsname = unsafe { std::mem::zeroed() };

        let result = unsafe { libc::uname(&mut utsname) };

        if result != 0 {
            return Err(Error::CommandFailed {
                command: "uname(2) syscall".to_string(),
                message: format!("uname syscall failed with code {}", result),
            });
        }

        // Extract release field (e.g., "16.0-CURRENT")
        let release_cstr = unsafe { CStr::from_ptr(utsname.release.as_ptr()) };
        let version_str = release_cstr
            .to_str()
            .map_err(|e| Error::InvalidVersion(format!("Invalid UTF-8 in uname.release: {}", e)))?
            .to_string();

        Self::parse(&version_str)
    }

    /// Parse a FreeBSD version string
    pub fn parse(s: &str) -> Result<Self> {
        // Example: "16.0-CURRENT" or "15.1-RELEASE-p1"
        let parts: Vec<&str> = s.split('-').collect();

        if parts.len() < 2 {
            return Err(Error::InvalidVersion(format!(
                "Invalid version format: {}",
                s
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

        Ok(OsVersion {
            major,
            minor,
            patch,
            release_type,
        })
    }

    /// Check if the OS supports VLAN filtering in if_bridge
    ///
    /// VLAN filtering requires FreeBSD 15.0 or later.
    pub fn supports_vlan_filtering(&self) -> bool {
        self.major >= 15
    }

    /// Check if pkgbase is mandatory
    ///
    /// FreeBSD 16.0+ requires pkgbase; distribution sets are removed.
    pub fn requires_pkgbase(&self) -> bool {
        self.major >= 16
    }

    /// Check if jail descriptors are supported
    ///
    /// Jail descriptors (owning fds, EVFILT_JAILDESC) require FreeBSD 16.0+.
    pub fn supports_jail_descriptors(&self) -> bool {
        self.major >= 16
    }

    /// Check if kqueue EVFILT_JAIL is supported
    ///
    /// Kqueue jail event monitoring requires FreeBSD 16.0+.
    pub fn supports_jail_kqueue(&self) -> bool {
        self.major >= 16
    }
}

impl fmt::Display for OsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}-{}", self.major, self.minor, self.release_type)?;
        if let Some(patch) = self.patch {
            write!(f, "-p{}", patch)?;
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
        .map_err(|e| Error::Network(format!("Invalid sysctl name {}: {}", name, e)))?;
    let rc = unsafe {
        libc::sysctlbyname(
            c_name.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &value as *const i32 as *const libc::c_void,
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
        .map_err(|e| Error::Network(format!("Failed to run ifconfig: {}", e)))?;
    if !status.success() {
        return Err(Error::Network(format!(
            "Failed to add {} to group {}",
            iface, IFACE_GROUP
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
        .map(|o| {
            o.status.success()
                && String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .any(|line| line.trim() == iface)
        })
        .unwrap_or(false)
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
                .map(|line| line.trim().to_string())
                .filter(|line| !line.is_empty())
                .collect()
        })
        .unwrap_or_default()
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
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Mountpoints at or below `jail_root`, deepest first so unmounting in order
/// never blocks on a child mount.
pub fn mounted_paths_under(
    jail_root: &std::path::Path,
    mount_output: &str,
) -> Vec<std::path::PathBuf> {
    let root = jail_root.to_string_lossy();
    let prefix = format!("{}/", root);
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
/// devfs has no vfs_cmount, so the legacy mount(2) syscall returns
/// EOPNOTSUPP; it is only mountable through nmount(2).
pub fn mount_devfs(dev_path: &std::path::Path) -> Result<()> {
    let path_str = dev_path
        .to_str()
        .ok_or_else(|| Error::JailOperation(format!("Invalid path: {}", dev_path.display())))?;

    let fstype_key = CString::new("fstype").unwrap();
    let fstype_val = CString::new("devfs").unwrap();
    let fspath_key = CString::new("fspath").unwrap();
    let fspath_val =
        CString::new(path_str).map_err(|e| Error::JailOperation(format!("Invalid path: {}", e)))?;

    let mut iov = [&fstype_key, &fstype_val, &fspath_key, &fspath_val].map(|s| libc::iovec {
        iov_base: s.as_ptr() as *mut libc::c_void,
        iov_len: s.as_bytes_with_nul().len(),
    });

    let rc = unsafe { libc::nmount(iov.as_mut_ptr(), iov.len() as libc::c_uint, 0) };
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
        .map_err(|e| Error::JailOperation(format!("Failed to run devfs: {}", e)))?;
    if !status.success() {
        return Err(Error::JailOperation(format!(
            "Failed to apply devfs ruleset {} at {}",
            ruleset,
            dev_path.display()
        )));
    }
    Ok(())
}

/// Remove a directory tree that may contain schg/uchg-flagged files
/// (FreeBSD userlands protect init, libc, and friends with system flags).
pub fn remove_tree_with_flags(path: &std::path::Path) -> std::io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
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
        unsafe {
            libc::unmount(c_path.as_ptr(), 0);
        }
    }
}

#[cfg(test)]
mod tests;
