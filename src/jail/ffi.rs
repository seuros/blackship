//! FFI bindings for FreeBSD jail syscalls
//!
//! This code is adapted from libjail-rs (https://github.com/fubarnetes/libjail-rs)
//! Original authors: Fabian Freyer <fabian.freyer@physik.tu-berlin.de>
//! License: BSD-3-Clause
//!
//! Copyright (c) 2018, Fabian Freyer <fabian.freyer@physik.tu-berlin.de>
//! All rights reserved.
//!
//! Redistribution and use in source and binary forms, with or without
//! modification, are permitted provided that the following conditions are met:
//!
//! 1. Redistributions of source code must retain the above copyright notice, this
//!    list of conditions and the following disclaimer.
//!
//! 2. Redistributions in binary form must reproduce the above copyright notice,
//!    this list of conditions and the following disclaimer in the documentation
//!    and/or other materials provided with the distribution.
//!
//! 3. Neither the name of the copyright holder nor the names of its
//!    contributors may be used to endorse or promote products derived from
//!    this software without specific prior written permission.

use crate::error::Error;
use bitflags::bitflags;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::mem;
use std::path::Path;
use std::ptr;

use super::types::ParamValue;

/// Macro to construct iovec structures for jail syscalls
macro_rules! iovec {
    ($key:expr => ($value:expr, $size:expr)) => {
        vec![iovec!($key), iovec!($value, $size)]
    };
    ($key:expr => ()) => {
        vec![iovec!($key), iovec!()]
    };
    ($key:expr => $value:expr) => {
        vec![iovec!($key), iovec!($value)]
    };
    ($key:expr => mut $value:expr) => {
        vec![iovec!($key), iovec!(mut $value)]
    };
    ($value:expr, $size:expr) => {
        libc::iovec {
            iov_base: $value as *mut libc::c_void,
            iov_len: $size,
        }
    };
    ($name:expr) => {
        iovec!($name.as_ptr(), $name.len())
    };
    (mut $name:expr) => {
        iovec!($name.as_mut_ptr(), $name.len())
    };
    () => {
        iovec!(ptr::null::<libc::c_void>(), 0)
    };
}

bitflags! {
    /// Flags for jail_set syscall
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct JailFlags: i32 {
        /// Create the jail if it doesn't exist
        const CREATE = 0x01;
        /// Update parameters of existing jail
        const UPDATE = 0x02;
        /// Attach to jail upon creation
        const ATTACH = 0x04;
        /// Allow getting a dying jail
        const DYING = 0x08;
        /// Get/set jail in descriptor (FreeBSD 16+)
        const USE_DESC = 0x10;
        /// Find/add jail under descriptor (FreeBSD 16+)
        const AT_DESC = 0x20;
        /// Return a new jail descriptor (FreeBSD 16+)
        const GET_DESC = 0x40;
        /// Return a new owning jail descriptor (FreeBSD 16+)
        const OWN_DESC = 0x80;
    }
}

// Syscall numbers for FreeBSD 16 jail descriptor operations
#[allow(dead_code)]
const SYS_JAIL_ATTACH_JD: libc::c_int = 597;
const SYS_JAIL_REMOVE_JD: libc::c_int = 598;

/// Create a jail with the given path and parameters
///
/// Returns the jail ID (jid) on success
pub fn jail_create(path: &Path, params: HashMap<String, ParamValue>) -> Result<i32, Error> {
    // Convert parameters to raw bytes
    let raw_params: Vec<(Vec<u8>, Vec<u8>)> = params
        .iter()
        .map(|(key, value)| {
            Ok((
                CString::new(key.clone())?.into_bytes_with_nul(),
                value.as_bytes()?,
            ))
        })
        .collect::<Result<_, Error>>()?;

    let mut jiov: Vec<libc::iovec> = raw_params
        .iter()
        .flat_map(|(key, value)| iovec!(key => value))
        .collect();

    let pathstr = path
        .to_str()
        .ok_or_else(|| Error::JailSet("Invalid path encoding".into()))?;
    let pathstr = CString::new(pathstr)?.into_bytes_with_nul();

    // Set persist and errmsg
    let mut errmsg: [u8; 256] = unsafe { mem::zeroed() };
    jiov.append(
        &mut vec![
            iovec!(b"path\0" => pathstr),
            iovec!(b"errmsg\0" => mut errmsg),
            iovec!(b"persist\0" => ()),
        ]
        .into_iter()
        .flatten()
        .collect(),
    );

    let jid = unsafe {
        libc::jail_set(
            jiov[..].as_mut_ptr(),
            jiov.len() as u32,
            JailFlags::CREATE.bits(),
        )
    };

    let err = unsafe { CStr::from_ptr(errmsg.as_ptr() as *mut libc::c_char) }
        .to_string_lossy()
        .to_string();

    match jid {
        e if e < 0 => match errmsg[0] {
            0 => Err(Error::Io(std::io::Error::last_os_error())),
            _ => Err(Error::JailSet(err)),
        },
        _ => Ok(jid),
    }
}

/// Get the jail ID from a jail name
///
/// If the name can be parsed as an i32, it's returned directly
pub fn jail_getid(name: &str) -> Result<i32, Error> {
    let mut errmsg: [u8; 256] = unsafe { mem::zeroed() };

    // Try parsing as number first
    if let Ok(jid) = name.parse::<i32>() {
        return Ok(jid);
    }

    let name = CString::new(name)?.into_bytes_with_nul();

    let mut jiov: Vec<libc::iovec> =
        vec![iovec!(b"name\0" => name), iovec!(b"errmsg\0" => mut errmsg)]
            .into_iter()
            .flatten()
            .collect();

    let jid = unsafe {
        libc::jail_get(
            jiov[..].as_mut_ptr(),
            jiov.len() as u32,
            JailFlags::empty().bits(),
        )
    };

    let err = unsafe { CStr::from_ptr(errmsg.as_ptr() as *mut libc::c_char) }
        .to_string_lossy()
        .to_string();

    match jid {
        e if e < 0 => match errmsg[0] {
            0 => Err(Error::Io(std::io::Error::last_os_error())),
            _ => Err(Error::JailGet(err)),
        },
        _ => Ok(jid),
    }
}

/// Get the next jail ID after the given one (_unused: future feature)
///
/// Used to iterate through all jails
#[allow(dead_code)]
pub fn jail_nextjid(lastjid: i32) -> Result<i32, Error> {
    let mut errmsg: [u8; 256] = unsafe { mem::zeroed() };

    let mut jiov: Vec<libc::iovec> = vec![
        iovec!(b"lastjid\0" => (&lastjid as *const _, mem::size_of::<i32>())),
        iovec!(b"errmsg\0" => mut errmsg),
    ]
    .into_iter()
    .flatten()
    .collect();

    let jid = unsafe {
        libc::jail_get(
            jiov[..].as_mut_ptr(),
            jiov.len() as u32,
            JailFlags::empty().bits(),
        )
    };

    let err = unsafe { CStr::from_ptr(errmsg.as_ptr() as *mut libc::c_char) }
        .to_string_lossy()
        .to_string();

    match jid {
        e if e < 0 => match errmsg[0] {
            0 => Err(Error::Io(std::io::Error::last_os_error())),
            _ => Err(Error::JailGet(err)),
        },
        _ => Ok(jid),
    }
}

/// Remove a jail by its ID
///
/// This will kill all processes in the jail and remove it
pub fn jail_remove(jid: i32) -> Result<(), Error> {
    let ret = unsafe { libc::jail_remove(jid) };
    match ret {
        0 => Ok(()),
        -1 => Err(Error::Io(std::io::Error::last_os_error())),
        _ => Err(Error::JailRemoveFailed),
    }
}

/// Attach the current process to a jail
///
/// After calling this, the process runs inside the jail context.
/// This is typically used after fork() to run a command inside a jail.
pub fn jail_attach(jid: i32) -> Result<(), Error> {
    let ret = unsafe { libc::jail_attach(jid) };
    match ret {
        0 => Ok(()),
        -1 => Err(Error::JailAttachFailed(jid)),
        _ => Err(Error::JailAttachFailed(jid)),
    }
}

/// Create a jail and return an owning descriptor (FreeBSD 16+)
///
/// The returned `JailDescriptor` holds an owning fd — if it is dropped or
/// blackship crashes, the kernel automatically removes the jail.
/// Returns (jid, descriptor) on success.
pub fn jail_create_with_descriptor(
    path: &Path,
    params: HashMap<String, ParamValue>,
) -> Result<(i32, JailDescriptor), Error> {
    let raw_params: Vec<(Vec<u8>, Vec<u8>)> = params
        .iter()
        .map(|(key, value)| {
            Ok((
                CString::new(key.clone())?.into_bytes_with_nul(),
                value.as_bytes()?,
            ))
        })
        .collect::<Result<_, Error>>()?;

    let mut jiov: Vec<libc::iovec> = raw_params
        .iter()
        .flat_map(|(key, value)| iovec!(key => value))
        .collect();

    let pathstr = path
        .to_str()
        .ok_or_else(|| Error::JailSet("Invalid path encoding".into()))?;
    let pathstr = CString::new(pathstr)?.into_bytes_with_nul();

    // desc parameter receives the file descriptor
    let mut desc_fd: i32 = -1;
    let mut errmsg: [u8; 256] = unsafe { mem::zeroed() };

    jiov.append(
        &mut vec![
            iovec!(b"path\0" => pathstr),
            iovec!(b"errmsg\0" => mut errmsg),
            iovec!(b"persist\0" => ()),
            iovec!(b"desc\0" => (&mut desc_fd as *mut i32 as *mut u8, mem::size_of::<i32>())),
        ]
        .into_iter()
        .flatten()
        .collect(),
    );

    let flags = JailFlags::CREATE | JailFlags::GET_DESC | JailFlags::OWN_DESC;
    let jid = unsafe { libc::jail_set(jiov[..].as_mut_ptr(), jiov.len() as u32, flags.bits()) };

    let err = unsafe { CStr::from_ptr(errmsg.as_ptr() as *mut libc::c_char) }
        .to_string_lossy()
        .to_string();

    match jid {
        e if e < 0 => match errmsg[0] {
            0 => Err(Error::Io(std::io::Error::last_os_error())),
            _ => Err(Error::JailSet(err)),
        },
        _ => {
            use std::os::unix::io::FromRawFd;
            let owned_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(desc_fd) };
            Ok((jid, JailDescriptor { fd: owned_fd }))
        }
    }
}

/// Remove a jail via its owning descriptor (FreeBSD 16+)
#[allow(dead_code)]
pub fn jail_remove_jd(fd: std::os::fd::BorrowedFd<'_>) -> Result<(), Error> {
    use std::os::unix::io::AsRawFd;
    let ret = unsafe { libc::syscall(SYS_JAIL_REMOVE_JD, fd.as_raw_fd()) };
    if ret != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Attach to a jail via its descriptor (FreeBSD 16+)
#[allow(dead_code)]
pub fn jail_attach_jd(fd: std::os::fd::BorrowedFd<'_>) -> Result<(), Error> {
    use std::os::unix::io::AsRawFd;
    let ret = unsafe { libc::syscall(SYS_JAIL_ATTACH_JD, fd.as_raw_fd()) };
    if ret != 0 {
        return Err(Error::JailAttachFailed(-1));
    }
    Ok(())
}

/// Owning jail descriptor (FreeBSD 16+)
///
/// Wraps an owning file descriptor. When dropped, the kernel
/// automatically removes the associated jail.
#[allow(dead_code)]
pub struct JailDescriptor {
    fd: std::os::fd::OwnedFd,
}

#[allow(dead_code)]
impl JailDescriptor {
    /// Get the raw fd for use with kqueue or other operations
    pub fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::unix::io::AsFd;
        self.fd.as_fd()
    }

    /// Get the raw fd number
    pub fn as_raw_fd(&self) -> i32 {
        use std::os::unix::io::AsRawFd;
        self.fd.as_raw_fd()
    }

    /// Explicitly remove the jail via descriptor syscall
    pub fn remove(self) -> Result<(), Error> {
        jail_remove_jd(self.as_fd())?;
        // fd is dropped after this, but jail is already removed
        Ok(())
    }
}

impl std::fmt::Debug for JailDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::os::unix::io::AsRawFd;
        f.debug_struct("JailDescriptor")
            .field("fd", &self.fd.as_raw_fd())
            .finish()
    }
}

/// Clear the persist flag on a jail (_unused: future feature)
///
/// This allows the kernel to clean up the jail when no processes remain
#[allow(dead_code)]
pub fn jail_clearpersist(jid: i32) -> Result<(), Error> {
    let mut errmsg: [u8; 256] = unsafe { mem::zeroed() };
    let mut jiov: Vec<libc::iovec> = vec![
        iovec!(b"jid\0" => (&jid as *const _, mem::size_of::<i32>())),
        iovec!(b"errmsg\0" => mut errmsg),
        iovec!(b"nopersist\0" => ()),
    ]
    .into_iter()
    .flatten()
    .collect();

    let jid = unsafe {
        libc::jail_set(
            jiov[..].as_mut_ptr(),
            jiov.len() as u32,
            JailFlags::UPDATE.bits(),
        )
    };

    let err = unsafe { CStr::from_ptr(errmsg.as_ptr() as *mut libc::c_char) }
        .to_string_lossy()
        .to_string();

    match jid {
        e if e < 0 => match errmsg[0] {
            0 => Err(Error::Io(std::io::Error::last_os_error())),
            _ => Err(Error::JailSet(err)),
        },
        _ => Ok(()),
    }
}

/// Iterator over all running jails (_unused: future feature)
pub struct RunningJails {
    lastjid: i32,
}

impl RunningJails {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self { lastjid: 0 }
    }
}

impl Default for RunningJails {
    fn default() -> Self {
        Self::new()
    }
}

impl Iterator for RunningJails {
    type Item = i32;

    fn next(&mut self) -> Option<Self::Item> {
        match jail_nextjid(self.lastjid) {
            Ok(jid) => {
                self.lastjid = jid;
                Some(jid)
            }
            Err(_) => None,
        }
    }
}
