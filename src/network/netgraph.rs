//! Netgraph-based networking for VNET jails, via libnetgraph(3).
//!
//! ```text
//! [host NIC] -- ng_ether:lower -- ng_bridge:linkN -- ng_eiface:ether -- [jail vnet ngethN]
//! ```
//!
//! No host uplink is attached: the bridge must be wired to a NIC externally
//! (e.g. `ngctl`) or jails sit on an isolated segment with no gateway.

use crate::error::{Error, Result};
use crate::network::ioctl;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

// Cookies, command numbers and buffer sizes read from the netgraph headers at
// build time; see build/sys_consts.c.
use crate::sys::consts::{
    NG_HOOKSIZ, NG_NODESIZ, NG_TYPESIZ, NGM_BRIDGE_COOKIE, NGM_BRIDGE_SET_PERSISTENT,
    NGM_EIFACE_COOKIE, NGM_EIFACE_GET_IFNAME, NGM_GENERIC_COOKIE, NGM_LISTHOOKS, NGM_MKPEER,
    NGM_RMHOOK, NGM_SHUTDOWN, SIZEOF_LINKINFO, SIZEOF_NG_MESG_HEADER, SIZEOF_NGM_MKPEER,
    SIZEOF_NGM_RMHOOK, SIZEOF_NODEINFO,
};

// --- FFI structures ---

#[repr(C)]
struct NgmMkpeer {
    type_: [c_char; NG_TYPESIZ],
    ourhook: [c_char; NG_HOOKSIZ],
    peerhook: [c_char; NG_HOOKSIZ],
}

#[repr(C)]
struct NgmRmhook {
    ourhook: [c_char; NG_HOOKSIZ],
}

#[repr(C)]
struct NgNodeInfo {
    name: [c_char; NG_NODESIZ],
    type_: [c_char; NG_TYPESIZ],
    id: u32,
    hooks: u32,
}

#[repr(C)]
struct NgLinkInfo {
    ourhook: [c_char; NG_HOOKSIZ],
    peerhook: [c_char; NG_HOOKSIZ],
    nodeinfo: NgNodeInfo,
}

#[repr(C)]
struct NgMesgHeader {
    version: u8,
    spare: u8,
    spare2: u16,
    arglen: u32,
    cmd: u32,
    flags: u32,
    token: u32,
    typecookie: u32,
    cmdstr: [c_char; 32],
}

// ng_mesg is variable-length; we allocate a buffer and cast.
const NG_MESG_HEADER_SIZE: usize = std::mem::size_of::<NgMesgHeader>();

// Layouts must match the C structs; the kernel copies whole structs in and out.
const _: [(); SIZEOF_NG_MESG_HEADER] = [(); NG_MESG_HEADER_SIZE];
const _: [(); SIZEOF_NGM_MKPEER] = [(); std::mem::size_of::<NgmMkpeer>()];
const _: [(); SIZEOF_NGM_RMHOOK] = [(); std::mem::size_of::<NgmRmhook>()];
const _: [(); SIZEOF_NODEINFO] = [(); std::mem::size_of::<NgNodeInfo>()];
const _: [(); SIZEOF_LINKINFO] = [(); std::mem::size_of::<NgLinkInfo>()];

// --- libnetgraph FFI ---

#[link(name = "netgraph")]
unsafe extern "C" {
    fn NgMkSockNode(name: *const c_char, csp: *mut c_int, dsp: *mut c_int) -> c_int;
    fn NgSendMsg(
        cs: c_int,
        path: *const c_char,
        cookie: c_int,
        cmd: c_int,
        arg: *const c_void,
        arglen: usize,
    ) -> c_int;
    fn NgRecvMsg(cs: c_int, msg: *mut u8, buflen: usize, path: *mut c_char) -> c_int;
    fn NgNameNode(cs: c_int, path: *const c_char, fmt: *const c_char, ...) -> c_int;
}

// --- Helpers ---

fn fill_fixed<const N: usize>(buf: &mut [c_char; N], s: &str) -> Result<()> {
    let cstr = CString::new(s).map_err(|e| Error::Network(format!("Invalid string: {e}")))?;
    let bytes = cstr.as_bytes_with_nul();
    if bytes.len() > N {
        return Err(Error::Network(format!("String too long for buffer: {s}")));
    }
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr() as *const c_char,
            buf.as_mut_ptr(),
            bytes.len(),
        );
    }
    Ok(())
}

fn ng_error(msg: &str) -> Error {
    let errno = std::io::Error::last_os_error();
    Error::Network(format!("{msg}: {errno}"))
}

/// Load required netgraph kernel modules.
fn load_ng_modules() -> Result<()> {
    crate::sys::load_modules(&["ng_ether", "ng_bridge", "ng_eiface"])
}

// --- Control socket ---

/// One hook on a node: our hook name ("link0") and the peer node's type.
struct HookRecord {
    hook_name: String,
    peer_type: String,
}

/// A netgraph control socket pair (control + data).
struct NgSocket {
    cs: c_int,
    _ds: c_int,
}

impl NgSocket {
    fn new() -> Result<Self> {
        let mut cs: c_int = -1;
        let mut ds: c_int = -1;
        let rc = unsafe { NgMkSockNode(std::ptr::null(), &mut cs, &mut ds) };
        if rc < 0 {
            return Err(ng_error("NgMkSockNode failed"));
        }
        Ok(Self { cs, _ds: ds })
    }

    fn send_msg(
        &self,
        path: &str,
        cookie: i32,
        cmd: i32,
        arg: *const c_void,
        arglen: usize,
    ) -> Result<()> {
        let cpath = CString::new(path).map_err(|e| Error::Network(format!("Invalid path: {e}")))?;
        let rc = unsafe { NgSendMsg(self.cs, cpath.as_ptr(), cookie, cmd, arg, arglen) };
        if rc < 0 {
            return Err(ng_error(&format!("NgSendMsg({path}, cmd={cmd}) failed")));
        }
        Ok(())
    }

    /// Receive a reply (header + data). 64 KiB buffer holds ~400+ hook lists.
    fn recv_msg(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; NG_MESG_HEADER_SIZE + 65536];
        let rc = unsafe { NgRecvMsg(self.cs, buf.as_mut_ptr(), buf.len(), std::ptr::null_mut()) };
        if rc < 0 {
            return Err(ng_error("NgRecvMsg failed"));
        }
        let received = rc as usize;
        if received < NG_MESG_HEADER_SIZE {
            return Err(Error::Network("NgRecvMsg: truncated response".into()));
        }
        let header = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const NgMesgHeader) };
        let arglen = header.arglen as usize;
        if NG_MESG_HEADER_SIZE + arglen > received {
            return Err(Error::Network(
                "NgRecvMsg: arglen exceeds received data".into(),
            ));
        }
        Ok(buf)
    }

    fn mkpeer(&self, path: &str, type_: &str, ourhook: &str, peerhook: &str) -> Result<()> {
        let mut arg: NgmMkpeer = unsafe { std::mem::zeroed() };
        fill_fixed(&mut arg.type_, type_)?;
        fill_fixed(&mut arg.ourhook, ourhook)?;
        fill_fixed(&mut arg.peerhook, peerhook)?;

        self.send_msg(
            path,
            NGM_GENERIC_COOKIE,
            NGM_MKPEER,
            &arg as *const _ as *const c_void,
            std::mem::size_of::<NgmMkpeer>(),
        )
    }

    /// Name a node. Passes "%s" as the format to avoid format-string injection.
    fn name_node(&self, path: &str, name: &str) -> Result<()> {
        let cpath = CString::new(path).map_err(|e| Error::Network(format!("Invalid path: {e}")))?;
        let cname = CString::new(name).map_err(|e| Error::Network(format!("Invalid name: {e}")))?;
        let fmt = c"%s";
        let rc = unsafe { NgNameNode(self.cs, cpath.as_ptr(), fmt.as_ptr(), cname.as_ptr()) };
        if rc < 0 {
            return Err(ng_error(&format!("NgNameNode({path}, {name}) failed")));
        }
        Ok(())
    }

    fn rmhook(&self, path: &str, hook: &str) -> Result<()> {
        let mut arg: NgmRmhook = unsafe { std::mem::zeroed() };
        fill_fixed(&mut arg.ourhook, hook)?;

        self.send_msg(
            path,
            NGM_GENERIC_COOKIE,
            NGM_RMHOOK,
            &arg as *const _ as *const c_void,
            std::mem::size_of::<NgmRmhook>(),
        )
    }

    /// Query all hooks on a node; returns (next free link index, hooks).
    fn query_hooks(
        &self,
        path: &str,
        expected_type: Option<&str>,
    ) -> Result<(u32, Vec<HookRecord>)> {
        self.send_msg(path, NGM_GENERIC_COOKIE, NGM_LISTHOOKS, std::ptr::null(), 0)?;

        let buf = self.recv_msg()?;
        let header = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const NgMesgHeader) };
        let arglen = header.arglen as usize;

        let data = &buf[NG_MESG_HEADER_SIZE..NG_MESG_HEADER_SIZE + arglen];

        // Hooklist starts with a nodeinfo struct carrying the hook count.
        if data.len() < std::mem::size_of::<NgNodeInfo>() {
            return Ok((0, Vec::new()));
        }
        let nodeinfo = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const NgNodeInfo) };

        if let Some(expected) = expected_type {
            let type_bytes = unsafe { &*(&nodeinfo.type_ as *const [c_char] as *const [u8]) };
            let type_cstr = CStr::from_bytes_until_nul(type_bytes).unwrap_or(c"");
            let actual = type_cstr.to_str().unwrap_or("");
            if actual != expected {
                return Err(Error::Network(format!(
                    "Node '{}' is type '{}', expected '{}'",
                    path, actual, expected
                )));
            }
        }

        let nhooks = nodeinfo.hooks as usize;

        let links_offset = std::mem::size_of::<NgNodeInfo>();
        let link_size = std::mem::size_of::<NgLinkInfo>();
        let data_remaining = data.len().saturating_sub(links_offset);
        let max_hooks = data_remaining / link_size;
        let nhooks = nhooks.min(max_hooks);
        let mut max_idx: u32 = 0;
        let mut found = false;
        let mut hooks = Vec::with_capacity(nhooks);

        for i in 0..nhooks {
            let off = links_offset + i * link_size;
            if off + link_size > data.len() {
                break;
            }
            let link =
                unsafe { std::ptr::read_unaligned(data[off..].as_ptr() as *const NgLinkInfo) };
            let ourhook_bytes = unsafe { &*(&link.ourhook as *const [c_char] as *const [u8]) };
            let hook_name = CStr::from_bytes_until_nul(ourhook_bytes).unwrap_or(c"");
            let peertype_bytes =
                unsafe { &*(&link.nodeinfo.type_ as *const [c_char] as *const [u8]) };
            let peer_type = CStr::from_bytes_until_nul(peertype_bytes).unwrap_or(c"");

            let hook_str = hook_name.to_str().unwrap_or("").to_string();
            let type_str = peer_type.to_str().unwrap_or("").to_string();

            if let Some(idx_str) = hook_str.strip_prefix("link")
                && let Ok(idx) = idx_str.parse::<u32>()
            {
                found = true;
                if idx >= max_idx {
                    max_idx = idx + 1;
                }
            }

            hooks.push(HookRecord {
                hook_name: hook_str,
                peer_type: type_str,
            });
        }

        Ok((if found { max_idx } else { 0 }, hooks))
    }

    /// Make the bridge persistent so it survives hook disconnects.
    fn set_persistent(&self, path: &str) -> Result<()> {
        self.send_msg(
            path,
            NGM_BRIDGE_COOKIE,
            NGM_BRIDGE_SET_PERSISTENT,
            std::ptr::null(),
            0,
        )
    }

    /// Shut down a netgraph node.
    fn shutdown_node(&self, path: &str) -> Result<()> {
        self.send_msg(path, NGM_GENERIC_COOKIE, NGM_SHUTDOWN, std::ptr::null(), 0)
    }

    /// Query an eiface node for its interface name (e.g. "ngeth0").
    fn eiface_get_ifname(&self, path: &str) -> Result<String> {
        self.send_msg(
            path,
            NGM_EIFACE_COOKIE,
            NGM_EIFACE_GET_IFNAME,
            std::ptr::null(),
            0,
        )?;

        let buf = self.recv_msg()?;
        let header = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const NgMesgHeader) };
        let arglen = header.arglen as usize;
        if arglen == 0 {
            return Err(Error::Network("eiface returned empty ifname".into()));
        }
        let data = &buf[NG_MESG_HEADER_SIZE..NG_MESG_HEADER_SIZE + arglen];
        if !data.contains(&0) {
            return Err(Error::Network("eiface ifname not NUL-terminated".into()));
        }
        let cstr = unsafe { CStr::from_ptr(data.as_ptr() as *const c_char) };
        cstr.to_str()
            .map(|s| s.to_string())
            .map_err(|e| Error::Network(format!("Invalid ifname: {e}")))
    }
}

impl Drop for NgSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.cs);
            libc::close(self._ds);
        }
    }
}

// --- Public API ---

/// An ng_bridge node and its connected ng_eiface peers.
#[derive(Debug, Clone)]
pub struct NgBridge {
    /// ng node name.
    name: String,
    /// Next available link index on the bridge.
    next_link: u32,
}

impl NgBridge {
    /// Create a new ng_bridge node, loading kernel modules if needed.
    pub fn create(name: &str) -> Result<Self> {
        load_ng_modules()?;

        let sock = NgSocket::new()?;

        sock.mkpeer(".", "bridge", "bridge_tmp", "link0")?;

        let peer_path = ".:bridge_tmp";
        sock.name_node(peer_path, name)?;

        // Must be persistent before RMHOOK: ng_bridge self-destructs when its
        // last hook disconnects otherwise.
        let bridge_path = format!("{name}:");
        sock.set_persistent(&bridge_path)?;

        sock.rmhook(".", "bridge_tmp")?;

        Ok(Self {
            name: name.to_string(),
            next_link: 0,
        })
    }

    /// Open an existing ng_bridge node by name.
    pub fn open(name: &str) -> Result<Self> {
        let sock = NgSocket::new()?;
        let path = format!("{name}:");

        // Verify type and pick a link index that won't collide with existing hooks.
        let (next_link, _) = sock.query_hooks(&path, Some("bridge"))?;

        Ok(Self {
            name: name.to_string(),
            next_link,
        })
    }

    /// Create or open an existing ng_bridge.
    pub fn create_or_open(name: &str) -> Result<Self> {
        match Self::open(name) {
            Ok(b) => Ok(b),
            Err(_) => Self::create(name),
        }
    }

    /// Create an ng_eiface peer on this bridge; cleans up on partial failure.
    pub fn add_eiface(&mut self) -> Result<NgEiface> {
        let sock = NgSocket::new()?;
        let bridge_path = format!("{}:", self.name);

        // Concurrent creators race for the same free hook: EEXIST just
        // means someone won, so walk to the next index and retry.
        let mut link_hook = String::new();
        let mut attached = false;
        for _ in 0..64 {
            let candidate = format!("link{}", self.next_link);
            self.next_link += 1;
            match sock.mkpeer(&bridge_path, "eiface", &candidate, "ether") {
                Ok(()) => {
                    link_hook = candidate;
                    attached = true;
                    break;
                }
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("File exists") || msg.contains("os error 17") {
                        continue;
                    }
                    return Err(e);
                }
            }
        }
        if !attached {
            return Err(Error::Network(format!(
                "No free link hook on ng_bridge '{}' after 64 attempts",
                self.name
            )));
        }

        let eiface_path = format!("{}:{}", self.name, link_hook);
        let ifname = match sock.eiface_get_ifname(&eiface_path) {
            Ok(name) => name,
            Err(e) => {
                let _ = sock.shutdown_node(&eiface_path);
                return Err(e);
            }
        };

        if let Err(e) = ioctl::set_interface_up(&ifname, true) {
            // Shutting down the eiface node destroys both it and its ifnet.
            let _ = sock.shutdown_node(&eiface_path);
            return Err(e);
        }

        Ok(NgEiface {
            bridge_name: self.name.clone(),
            link_hook,
            ifname,
        })
    }

    /// Shut down all attached eiface peers, then the bridge node itself.
    ///
    /// ng_eiface does NOT self-destruct on hook disconnect, so each peer needs an
    /// explicit shutdown while still addressable. Non-eiface peers (ng_ether
    /// uplinks) are left alone; bridge shutdown just disconnects their hooks.
    pub fn destroy(&self) -> Result<()> {
        let sock = NgSocket::new()?;
        let bridge_path = format!("{}:", self.name);

        let mut first_err: Option<Error> = None;
        match sock.query_hooks(&bridge_path, None) {
            Ok((_, hooks)) => {
                for hook in &hooks {
                    if hook.peer_type == "eiface" {
                        let peer_path = format!("{}:{}", self.name, hook.hook_name);
                        if let Err(e) = sock.shutdown_node(&peer_path)
                            && first_err.is_none()
                        {
                            first_err = Some(e);
                        }
                    }
                }
            }
            Err(_) => {
                // Bridge may already be partially gone; try shutdown anyway.
            }
        }

        // Bail rather than destroy the bridge and orphan a live eiface.
        if let Some(e) = first_err {
            return Err(e);
        }

        sock.shutdown_node(&bridge_path)
    }
}

/// An ng_eiface node: like one side of an epair, movable into a jail VNET.
#[derive(Debug, Clone)]
pub struct NgEiface {
    /// Name of the parent bridge node.
    bridge_name: String,
    /// Hook name on the bridge (e.g. "link0").
    link_hook: String,
    /// Kernel interface name (e.g. "ngeth0").
    ifname: String,
}

impl NgEiface {
    /// Reconstruct a handle from persisted state during cleanup.
    pub fn from_state(bridge_name: &str, _host_interface: &str, jail_interface: &str) -> Self {
        Self {
            bridge_name: bridge_name.to_string(),
            // link_hook isn't persisted; cleanup destroys by ifname instead.
            link_hook: String::new(),
            ifname: jail_interface.to_string(),
        }
    }

    /// The kernel interface name (e.g. "ngeth0").
    pub fn ifname(&self) -> &str {
        &self.ifname
    }

    /// Set MAC address on this interface.
    pub fn set_mac_address(&self, mac: &str) -> Result<()> {
        ioctl::set_mac_address(&self.ifname, mac)
    }

    /// Move this interface into a jail's VNET.
    pub fn move_to_jail(&self, jid: i32) -> Result<()> {
        ioctl::move_to_vnet(&self.ifname, jid)
    }

    /// Disconnect this eiface from the bridge and shut down the node and its ifnet.
    pub fn destroy(&self) -> Result<()> {
        let sock = NgSocket::new()?;

        // Best-effort: the bridge may already be gone.
        if !self.link_hook.is_empty() {
            let bridge_path = format!("{}:", self.bridge_name);
            let _ = sock.rmhook(&bridge_path, &self.link_hook);
        }

        // Address by ifname so this works whether or not the bridge hook survives.
        let eiface_path = format!("{}:", self.ifname);
        match sock.shutdown_node(&eiface_path) {
            Ok(()) => Ok(()),
            Err(_) => {
                // Node may have been moved into a jail, or already be gone.
                ioctl::destroy_interface(&self.ifname)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fill_fixed() {
        let mut buf = [0i8; NG_HOOKSIZ];
        fill_fixed(&mut buf, "link0").unwrap();
        let cstr = unsafe { CStr::from_ptr(buf.as_ptr()) };
        assert_eq!(cstr.to_str().unwrap(), "link0");
    }

    #[test]
    fn test_fill_fixed_too_long() {
        let mut buf = [0i8; 4];
        assert!(fill_fixed(&mut buf, "toolong").is_err());
    }

    #[test]
    fn test_fill_fixed_rejects_nul() {
        let mut buf = [0i8; NG_HOOKSIZ];
        assert!(fill_fixed(&mut buf, "has\0nul").is_err());
    }
}
