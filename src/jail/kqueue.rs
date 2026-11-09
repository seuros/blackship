//! Kqueue-based jail event monitoring (FreeBSD 16+)
//!
//! Uses `EVFILT_JAIL` and `EVFILT_JAILDESC` to receive kernel notifications
//! when jails are created, modified, attached to, or removed.

// FFI module: kqueue(2)/kevent(2) jail notifications.
#![allow(unsafe_code)]

use crate::error::{Error, Result};

macro_rules! io_err {
    () => {
        Err(Error::Io(std::io::Error::last_os_error()))
    };
}
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::io::FromRawFd;
use std::time::Duration;

// Filter constants from sys/event.h
const EVFILT_JAIL: i16 = -14;
const EVFILT_JAILDESC: i16 = -15;

/// A jid or fd as a kevent ident; negative gets EINVAL, as the kernel would.
fn kevent_ident(id: i32) -> Result<usize> {
    usize::try_from(id).map_err(|_| Error::Io(std::io::Error::from_raw_os_error(libc::EINVAL)))
}

#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)] // ident is the non-negative i32 we registered
const fn ident_i32(ident: usize) -> i32 {
    ident as i32
}

// Note flags for jail events
/// Child jail was created
pub const NOTE_JAIL_CHILD: u32 = 0x8000_0000;
/// Jail was modified
pub const NOTE_JAIL_SET: u32 = 0x4000_0000;
/// Process attached to jail
pub const NOTE_JAIL_ATTACH: u32 = 0x2000_0000;
/// Jail was removed
pub const NOTE_JAIL_REMOVE: u32 = 0x1000_0000;
/// More than one child or attach event since the last read
pub const NOTE_JAIL_MULTI: u32 = 0x0800_0000;

/// All jail events
pub const NOTE_JAIL_ALL: u32 =
    NOTE_JAIL_CHILD | NOTE_JAIL_SET | NOTE_JAIL_ATTACH | NOTE_JAIL_REMOVE;

/// The kqueue identity a jail event arrived under.
///
/// `EVFILT_JAIL` reports a jid, `EVFILT_JAILDESC` reports the descriptor fd.
/// A descriptor identity survives jid reuse; a jid does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JailIdent {
    Jid(i32),
    Descriptor(i32),
}

impl std::fmt::Display for JailIdent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Jid(jid) => write!(f, "JID {jid}"),
            Self::Descriptor(fd) => write!(f, "jail descriptor {fd}"),
        }
    }
}

/// A jail lifecycle event from kqueue
#[derive(Debug, Clone)]
pub enum JailEvent {
    /// A child jail was created
    Child { ident: JailIdent, coalesced: bool },
    /// A jail was modified
    Set { ident: JailIdent },
    /// A process attached to the jail
    Attach { ident: JailIdent, coalesced: bool },
    /// The jail was removed
    Remove { ident: JailIdent },
}

impl JailEvent {
    pub const fn ident(&self) -> JailIdent {
        match self {
            Self::Child { ident, .. }
            | Self::Set { ident }
            | Self::Attach { ident, .. }
            | Self::Remove { ident } => *ident,
        }
    }
}

/// Event source using kqueue for jail monitoring
pub struct JailEventSource {
    kq: OwnedFd,
}

impl JailEventSource {
    /// Create a new kqueue-based jail event source
    pub fn new() -> Result<Self> {
        // SAFETY: no arguments.
        let kq = unsafe { libc::kqueue() };
        if kq < 0 {
            return io_err!();
        }
        // SAFETY: fresh descriptor nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(kq) };
        Ok(Self { kq: fd })
    }

    /// Register a jail for monitoring by JID
    pub fn register_jail(&self, jid: i32) -> Result<()> {
        self.register(kevent_ident(jid)?, EVFILT_JAIL, NOTE_JAIL_ALL)
    }

    /// Register a jail for monitoring by owning descriptor.
    ///
    /// The caller must keep the descriptor open for as long as it wants events.
    pub fn register_jaildesc(&self, fd: i32) -> Result<()> {
        self.register(kevent_ident(fd)?, EVFILT_JAILDESC, NOTE_JAIL_ALL)
    }

    fn kevent_change(&self, changelist: &[libc::kevent; 1]) -> Result<()> {
        // SAFETY: changelist holds exactly nchanges (1) entries; no eventlist.
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
            return io_err!();
        }
        Ok(())
    }

    fn register(&self, ident: usize, filter: i16, fflags: u32) -> Result<()> {
        self.kevent_change(&[libc::kevent {
            ident,
            filter,
            flags: libc::EV_ADD | libc::EV_CLEAR,
            fflags,
            data: 0,
            udata: std::ptr::null_mut(),
            ext: [0; 4],
        }])
    }

    /// Poll for jail events with an optional timeout
    pub fn poll(&self, timeout: Option<Duration>) -> Result<Vec<JailEvent>> {
        // SAFETY: all-zero is a valid kevent.
        let mut events = [unsafe { std::mem::zeroed::<libc::kevent>() }; 16];

        let timeout_spec = timeout.map(|d| libc::timespec {
            // Saturate: a wrapped (negative) tv_sec would be EINVAL.
            tv_sec: libc::time_t::try_from(d.as_secs()).unwrap_or(libc::time_t::MAX),
            tv_nsec: libc::c_long::from(d.subsec_nanos()),
        });

        let timeout_ptr = match &timeout_spec {
            Some(ts) => std::ptr::from_ref::<libc::timespec>(ts),
            None => std::ptr::null(),
        };

        let nevents = libc::c_int::try_from(events.len()).unwrap_or(libc::c_int::MAX);
        // SAFETY: events holds nevents entries; timeout_ptr is NULL or live.
        let n = unsafe {
            libc::kevent(
                self.kq.as_raw_fd(),
                std::ptr::null(),
                0,
                events.as_mut_ptr(),
                nevents,
                timeout_ptr,
            )
        };

        let Ok(n) = usize::try_from(n) else {
            return io_err!();
        };

        let mut result = Vec::new();
        for ev in &events[..n] {
            let ident = if ev.filter == EVFILT_JAILDESC {
                JailIdent::Descriptor(ident_i32(ev.ident))
            } else {
                JailIdent::Jid(ident_i32(ev.ident))
            };
            let coalesced = ev.fflags & NOTE_JAIL_MULTI != 0;

            if ev.fflags & NOTE_JAIL_REMOVE != 0 {
                result.push(JailEvent::Remove { ident });
            }
            if ev.fflags & NOTE_JAIL_CHILD != 0 {
                result.push(JailEvent::Child { ident, coalesced });
            }
            if ev.fflags & NOTE_JAIL_SET != 0 {
                result.push(JailEvent::Set { ident });
            }
            if ev.fflags & NOTE_JAIL_ATTACH != 0 {
                result.push(JailEvent::Attach { ident, coalesced });
            }
        }

        Ok(result)
    }

    /// Stop monitoring a jail. An identity the kernel has already dropped --
    /// a removed jail or a closed descriptor -- is treated as success, since
    /// the desired end state is the same.
    pub fn unregister(&self, ident: JailIdent) -> Result<()> {
        let (raw, filter) = match ident {
            JailIdent::Jid(jid) => (jid, EVFILT_JAIL),
            JailIdent::Descriptor(fd) => (fd, EVFILT_JAILDESC),
        };

        let result = kevent_ident(raw).and_then(|raw| {
            self.kevent_change(&[libc::kevent {
                ident: raw,
                filter,
                flags: libc::EV_DELETE,
                fflags: 0,
                data: 0,
                udata: std::ptr::null_mut(),
                ext: [0; 4],
            }])
        });

        match result {
            Err(Error::Io(e))
                if matches!(
                    e.raw_os_error(),
                    Some(libc::ENOENT | libc::EINVAL | libc::EBADF)
                ) =>
            {
                Ok(())
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests;
