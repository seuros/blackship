//! System detection and version information

use crate::error::{Error, Result};
use std::ffi::CStr;
use std::fmt;

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
    /// - `15.0-RELEASE`
    /// - `15.0-RELEASE-p1`
    /// - `14.2-STABLE`
    /// - `15.0-BETA1`
    /// - `15.0-RC2`
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
    fn parse(s: &str) -> Result<Self> {
        // Example: "16.0-CURRENT" or "15.0-RELEASE-p1"
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
            _ => {
                return Err(Error::InvalidVersion(format!(
                    "Unknown release type: {}",
                    parts[1]
                )))
            }
        };

        // Parse patch level (e.g., "p1" from "15.0-RELEASE-p1")
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

    /// Check if the OS supports service jails
    ///
    /// Service jails require FreeBSD 15.0 or later.
    #[allow(dead_code)]
    pub fn supports_service_jails(&self) -> bool {
        self.major >= 15
    }

    /// Check if the OS supports zfs.dataset parameter for jails
    ///
    /// ZFS dataset attachment requires FreeBSD 15.0 or later.
    #[allow(dead_code)]
    pub fn supports_zfs_dataset(&self) -> bool {
        self.major >= 15
    }

    /// Check if pkgbase is mandatory
    ///
    /// FreeBSD 16.0+ requires pkgbase; distribution sets are removed.
    #[allow(dead_code)]
    pub fn requires_pkgbase(&self) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_current() {
        let ver = OsVersion::parse("16.0-CURRENT").unwrap();
        assert_eq!(ver.major, 16);
        assert_eq!(ver.minor, 0);
        assert_eq!(ver.patch, None);
        assert_eq!(ver.release_type, ReleaseType::Current);
    }

    #[test]
    fn test_parse_release() {
        let ver = OsVersion::parse("15.0-RELEASE").unwrap();
        assert_eq!(ver.major, 15);
        assert_eq!(ver.minor, 0);
        assert_eq!(ver.patch, None);
        assert_eq!(ver.release_type, ReleaseType::Release);
    }

    #[test]
    fn test_parse_release_with_patch() {
        let ver = OsVersion::parse("15.0-RELEASE-p1").unwrap();
        assert_eq!(ver.major, 15);
        assert_eq!(ver.minor, 0);
        assert_eq!(ver.patch, Some(1));
        assert_eq!(ver.release_type, ReleaseType::Release);
    }

    #[test]
    fn test_parse_stable() {
        let ver = OsVersion::parse("14.2-STABLE").unwrap();
        assert_eq!(ver.major, 14);
        assert_eq!(ver.minor, 2);
        assert_eq!(ver.release_type, ReleaseType::Stable);
    }


    #[test]
    fn test_parse_rc() {
        let ver = OsVersion::parse("15.0-RC2").unwrap();
        assert_eq!(ver.major, 15);
        assert_eq!(ver.minor, 0);
        assert_eq!(ver.release_type, ReleaseType::Rc(2));
    }

    #[test]
    fn test_vlan_filtering_support() {
        assert!(OsVersion::parse("15.0-RELEASE").unwrap().supports_vlan_filtering());
        assert!(OsVersion::parse("16.0-CURRENT").unwrap().supports_vlan_filtering());
        assert!(!OsVersion::parse("14.2-STABLE").unwrap().supports_vlan_filtering());
        assert!(!OsVersion::parse("13.3-RELEASE").unwrap().supports_vlan_filtering());
    }

    #[test]
    fn test_display() {
        assert_eq!(OsVersion::parse("16.0-CURRENT").unwrap().to_string(), "16.0-CURRENT");
        assert_eq!(OsVersion::parse("15.0-RELEASE-p1").unwrap().to_string(), "15.0-RELEASE-p1");
    }
}
