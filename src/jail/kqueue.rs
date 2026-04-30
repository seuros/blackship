//! Kqueue-based jail event monitoring (FreeBSD 16+)
//!
//! Uses EVFILT_JAIL and EVFILT_JAILDESC to receive kernel notifications
//! when jails are created, modified, attached to, or removed.

use crate::error::{Error, Result};
use std::os::fd::OwnedFd;
use std::time::Duration;

// Filter constants from sys/event.h
const EVFILT_JAIL: i16 = -14;
#[allow(dead_code)]
const EVFILT_JAILDESC: i16 = -15;

// Note flags for jail events
/// Child jail was created
pub const NOTE_JAIL_CHILD: u32 = 0x80000000;
/// Jail was modified
pub const NOTE_JAIL_SET: u32 = 0x40000000;
/// Process attached to jail
pub const NOTE_JAIL_ATTACH: u32 = 0x20000000;
/// Jail was removed
pub const NOTE_JAIL_REMOVE: u32 = 0x10000000;
/// Multiple events coalesced
#[allow(dead_code)]
pub const NOTE_JAIL_MULTI: u32 = 0x08000000;

/// All jail events
pub const NOTE_JAIL_ALL: u32 =
    NOTE_JAIL_CHILD | NOTE_JAIL_SET | NOTE_JAIL_ATTACH | NOTE_JAIL_REMOVE;

/// A jail lifecycle event from kqueue
#[derive(Debug, Clone)]
pub enum JailEvent {
    /// A child jail was created
    Child { jid: i32 },
    /// A jail was modified
    Set { jid: i32 },
    /// A process attached to the jail
    Attach { jid: i32 },
    /// The jail was removed
    Remove { jid: i32 },
}

/// Event source using kqueue for jail monitoring
pub struct JailEventSource {
    kq: OwnedFd,
}

impl JailEventSource {
    /// Create a new kqueue-based jail event source
    pub fn new() -> Result<Self> {
        let kq = unsafe { libc::kqueue() };
        if kq < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        use std::os::unix::io::FromRawFd;
        let fd = unsafe { OwnedFd::from_raw_fd(kq) };
        Ok(Self { kq: fd })
    }

    /// Register a jail for monitoring by JID
    pub fn register_jail(&self, jid: i32) -> Result<()> {
        self.register(jid as usize, EVFILT_JAIL, NOTE_JAIL_ALL)
    }

    /// Get the raw kqueue fd for use with tokio AsyncFd
    pub fn as_raw_fd(&self) -> i32 {
        use std::os::unix::io::AsRawFd;
        self.kq.as_raw_fd()
    }

    fn register(&self, ident: usize, filter: i16, fflags: u32) -> Result<()> {
        use std::os::unix::io::AsRawFd;

        let changelist = [libc::kevent {
            ident,
            filter,
            flags: libc::EV_ADD | libc::EV_CLEAR,
            fflags,
            data: 0,
            udata: std::ptr::null_mut(),
            ext: [0; 4],
        }];

        let ret = unsafe {
            libc::kevent(
                self.kq.as_raw_fd(),
                changelist.as_ptr(),
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };

        if ret < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }

        Ok(())
    }

    /// Poll for jail events with an optional timeout
    pub fn poll(&self, timeout: Option<Duration>) -> Result<Vec<JailEvent>> {
        use std::os::unix::io::AsRawFd;

        let mut events = [unsafe { std::mem::zeroed::<libc::kevent>() }; 16];

        let timeout_spec = timeout.map(|d| libc::timespec {
            tv_sec: d.as_secs() as libc::time_t,
            tv_nsec: d.subsec_nanos() as libc::c_long,
        });

        let timeout_ptr = match &timeout_spec {
            Some(ts) => ts as *const libc::timespec,
            None => std::ptr::null(),
        };

        let n = unsafe {
            libc::kevent(
                self.kq.as_raw_fd(),
                std::ptr::null(),
                0,
                events.as_mut_ptr(),
                events.len() as i32,
                timeout_ptr,
            )
        };

        if n < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }

        let mut result = Vec::new();
        for ev in &events[..n as usize] {
            let jid = ev.ident as i32;

            if ev.fflags & NOTE_JAIL_REMOVE != 0 {
                result.push(JailEvent::Remove { jid });
            }
            if ev.fflags & NOTE_JAIL_CHILD != 0 {
                result.push(JailEvent::Child { jid });
            }
            if ev.fflags & NOTE_JAIL_SET != 0 {
                result.push(JailEvent::Set { jid });
            }
            if ev.fflags & NOTE_JAIL_ATTACH != 0 {
                result.push(JailEvent::Attach { jid });
            }
        }

        Ok(result)
    }

    /// Unregister a jail from monitoring
    #[allow(dead_code)]
    pub fn unregister_jail(&self, jid: i32) -> Result<()> {
        use std::os::unix::io::AsRawFd;

        let changelist = [libc::kevent {
            ident: jid as usize,
            filter: EVFILT_JAIL,
            flags: libc::EV_DELETE,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
            ext: [0; 4],
        }];

        let ret = unsafe {
            libc::kevent(
                self.kq.as_raw_fd(),
                changelist.as_ptr(),
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };

        if ret < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kqueue_creation() {
        // kqueue creation should work on any FreeBSD
        let source = JailEventSource::new();
        assert!(
            source.is_ok(),
            "Failed to create kqueue: {:?}",
            source.err()
        );
    }

    #[test]
    fn test_poll_no_events() {
        let source = JailEventSource::new().unwrap();
        // Poll with zero timeout — should return empty immediately
        let events = source.poll(Some(Duration::ZERO)).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn test_register_nonexistent_jail() {
        let source = JailEventSource::new().unwrap();
        // Registering a non-existent JID should fail
        let result = source.register_jail(999999);
        // On FreeBSD 16+ this returns ESRCH, on older it returns EINVAL
        assert!(result.is_err());
    }

    #[test]
    fn test_jail_event_debug() {
        let event = JailEvent::Remove { jid: 42 };
        let debug = format!("{:?}", event);
        assert!(debug.contains("42"));
    }
}
