//! FreeBSD network ioctls: native replacements for ifconfig.

// FFI module: interface and if_bridge ioctls.
#![allow(unsafe_code)]

use crate::error::{Error, Result};
use std::ffi::CString;
use std::net::UdpSocket;
use std::os::unix::io::AsRawFd;

// Request codes come from the system headers via build/sys_consts.c.
use crate::sys::consts::{
    BRDGADD, BRDGDEL, BRDGGFLAGS, BRDGGIFS, BRDGSFLAGS, BRDGSIFPVID, BRDGSIFVLANSET,
    IFCAP_VLAN_HWFILTER, OFFSETOF_IFBIF_VLAN_REQ_BV_SET, SIOCAIFADDR, SIOCGDRVSPEC, SIOCGIFCAP,
    SIOCGIFFLAGS, SIOCIFCREATE2, SIOCIFDESTROY, SIOCSDRVSPEC, SIOCSIFCAP, SIOCSIFFLAGS,
    SIOCSIFLLADDR, SIOCSIFNAME, SIOCSIFVNET, SIZEOF_IFBIF_VLAN_REQ, SIZEOF_IFBIFCONF,
    SIZEOF_IFBREQ, SIZEOF_IFBRPARAM,
};

/// Copy `name` into an ifreq name buffer; errors past 15 chars.
fn copy_ifname(dest: &mut [libc::c_char; libc::IF_NAMESIZE], name: &str) -> Result<()> {
    let name_cstr =
        CString::new(name).map_err(|e| Error::Network(format!("Invalid interface name: {e}")))?;
    let name_bytes = name_cstr.as_bytes_with_nul();

    if name_bytes.len() > libc::IF_NAMESIZE {
        return Err(Error::Network(format!(
            "Interface name too long: {} (max {} chars)",
            name,
            libc::IF_NAMESIZE - 1
        )));
    }

    // SAFETY: live CString bytes; c_char has u8 layout.
    dest[..name_bytes.len()].copy_from_slice(unsafe {
        std::slice::from_raw_parts(name_bytes.as_ptr().cast::<libc::c_char>(), name_bytes.len())
    });

    Ok(())
}

fn create_socket() -> Result<UdpSocket> {
    UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| Error::Network(format!("Failed to create socket: {e}")))
}

fn extract_ifname(name: &[libc::c_char; libc::IF_NAMESIZE]) -> Result<String> {
    String::from_utf8(crate::sys::c_buf_bytes(name))
        .map_err(|e| Error::Network(format!("Invalid interface name: {e}")))
}

#[repr(C)]
struct IfReqNameData {
    ifr_name: [libc::c_char; libc::IF_NAMESIZE],
    ifr_data: *mut libc::c_void,
    _padding: [u8; 8],
}

#[repr(C)]
struct IfReqFlags {
    ifr_name: [libc::c_char; libc::IF_NAMESIZE],
    ifr_flags: libc::c_short,
    ifr_flagshigh: libc::c_short,
    _padding: [u8; 12],
}

#[repr(C)]
struct IfReqSockaddr {
    ifr_name: [libc::c_char; libc::IF_NAMESIZE],
    ifr_addr: libc::sockaddr,
}

#[repr(C)]
struct IfReqJid {
    ifr_name: [libc::c_char; libc::IF_NAMESIZE],
    ifr_jid: libc::c_int,
    _padding: [u8; 12],
}

#[repr(C)]
struct IfReqCap {
    ifr_name: [libc::c_char; libc::IF_NAMESIZE],
    ifr_reqcap: libc::c_int,
    ifr_curcap: libc::c_int,
    _padding: [u8; 8],
}

#[repr(C)]
#[allow(clippy::struct_field_names)] // mirrors struct ifaliasreq in <net/if.h>
struct IfAliasReq {
    ifra_name: [libc::c_char; libc::IF_NAMESIZE],
    ifra_addr: libc::sockaddr_in,
    ifra_broadaddr: libc::sockaddr_in,
    ifra_mask: libc::sockaddr_in,
    ifra_vhid: libc::c_int,
}

#[repr(C)]
#[allow(clippy::struct_field_names)] // mirrors struct ifdrv in <net/if.h>
struct IfDrv {
    ifd_name: [libc::c_char; libc::IF_NAMESIZE],
    ifd_cmd: libc::c_ulong,
    ifd_len: libc::size_t,
    ifd_data: *mut libc::c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(clippy::struct_field_names)] // mirrors struct ifbreq in <net/if_bridgevar.h>
struct BridgeIfReq {
    ifbr_ifsname: [libc::c_char; libc::IF_NAMESIZE],
    ifbr_ifsflags: u32,
    ifbr_stpflags: u32,
    ifbr_path_cost: u32,
    ifbr_portno: u8,
    ifbr_priority: u8,
    ifbr_proto: u8,
    ifbr_role: u8,
    ifbr_state: u8,
    ifbr_addrcnt: u32,
    ifbr_addrmax: u32,
    ifbr_addrexceeded: u32,
    ifbr_pvid: u16,
    ifbr_vlanproto: u16,
    ifbr_pad: [u8; 28],
}

#[repr(C)]
struct BridgeIfConf {
    ifbic_len: u32,
    _padding: u32,
    ifbic_req: *mut BridgeIfReq,
}

#[repr(C)]
struct BridgeParam {
    ifbrp_int32: u32,
}

#[repr(C)]
#[allow(clippy::struct_field_names)] // mirrors struct ifbif_vlan_req in <net/if_bridgevar.h>
struct BridgeIfVlanReq {
    bv_ifname: [libc::c_char; libc::IF_NAMESIZE],
    bv_op: u8,
    /// `ifbvlan_set_t`: __BITSET of `long` words, 4096 bits.
    bv_set: [libc::c_ulong; 4096 / libc::c_ulong::BITS as usize],
}

const _: [(); std::mem::size_of::<IfReqNameData>()] = [(); std::mem::size_of::<libc::ifreq>()];
const _: [(); std::mem::size_of::<IfReqFlags>()] = [(); std::mem::size_of::<libc::ifreq>()];
const _: [(); std::mem::size_of::<IfReqSockaddr>()] = [(); std::mem::size_of::<libc::ifreq>()];
const _: [(); std::mem::size_of::<IfReqJid>()] = [(); std::mem::size_of::<libc::ifreq>()];
const _: [(); std::mem::size_of::<IfReqCap>()] = [(); std::mem::size_of::<libc::ifreq>()];
const _: [(); std::mem::size_of::<IfAliasReq>()] = [(); std::mem::size_of::<libc::ifaliasreq>()];
const _: [(); std::mem::size_of::<IfDrv>()] = [(); std::mem::size_of::<libc::ifdrv>()];
const _: [(); SIZEOF_IFBREQ] = [(); std::mem::size_of::<BridgeIfReq>()];
const _: [(); SIZEOF_IFBIFCONF] = [(); std::mem::size_of::<BridgeIfConf>()];
const _: [(); SIZEOF_IFBRPARAM] = [(); std::mem::size_of::<BridgeParam>()];
const _: [(); SIZEOF_IFBIF_VLAN_REQ] = [(); std::mem::size_of::<BridgeIfVlanReq>()];
const _: [(); OFFSETOF_IFBIF_VLAN_REQ_BV_SET] = [(); std::mem::offset_of!(BridgeIfVlanReq, bv_set)];

#[allow(clippy::cast_possible_truncation)] // AF_LINK (18) fits sa_family_t
const AF_LINK_FAMILY: libc::sa_family_t = libc::AF_LINK as libc::sa_family_t;
#[allow(clippy::cast_possible_truncation)] // AF_INET (2) fits sa_family_t
const AF_INET_FAMILY: libc::sa_family_t = libc::AF_INET as libc::sa_family_t;
#[allow(clippy::cast_possible_truncation)] // 16 bytes, asserted below
const SOCKADDR_IN_LEN: u8 = std::mem::size_of::<libc::sockaddr_in>() as u8;
const _: () = assert!(std::mem::size_of::<libc::sockaddr_in>() <= u8::MAX as usize);

/// One SIOCGDRVSPEC/SIOCSDRVSPEC round trip to an `if_bridge` command.
///
/// # Safety
/// `data` must be `len` live writable bytes of `cmd`'s struct, including any buffer it points to.
unsafe fn bridge_drvspec_io(
    sock_fd: libc::c_int,
    bridge: &str,
    cmd: libc::c_ulong,
    len: libc::size_t,
    data: *mut libc::c_void,
    set: bool,
) -> std::io::Result<()> {
    // SAFETY: plain-data struct; all-zero is valid.
    let mut req: IfDrv = unsafe { std::mem::zeroed() };
    copy_ifname(&mut req.ifd_name, bridge).map_err(|e| std::io::Error::other(e.to_string()))?;
    req.ifd_cmd = cmd;
    req.ifd_len = len;
    req.ifd_data = data;

    // SAFETY: req is a full struct ifdrv; data/len valid per contract.
    let result = unsafe {
        libc::ioctl(
            sock_fd,
            if set { SIOCSDRVSPEC } else { SIOCGDRVSPEC },
            &mut req,
        )
    };

    if result < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// [`bridge_drvspec_io`] mapped into [`Error::Network`].
///
/// # Safety
/// Same contract as [`bridge_drvspec_io`].
unsafe fn bridge_drvspec(
    sock_fd: libc::c_int,
    bridge: &str,
    cmd: libc::c_ulong,
    len: libc::size_t,
    data: *mut libc::c_void,
    set: bool,
) -> Result<()> {
    // SAFETY: caller upholds bridge_drvspec_io's contract.
    unsafe { bridge_drvspec_io(sock_fd, bridge, cmd, len, data, set) }
        .map_err(|e| Error::Network(format!("Bridge ioctl {cmd} failed: {e}")))
}

/// One interface ioctl on `sock`; a failure reads `Failed to <what>: <errno>`.
///
/// # Safety
/// `arg` must point to a live struct whose size and layout `request` expects.
unsafe fn interface_ioctl<T>(
    sock: &UdpSocket,
    request: libc::c_ulong,
    arg: *mut T,
    what: &str,
) -> Result<()> {
    // SAFETY: the descriptor lives as long as `sock`; `arg` is valid per the contract.
    if unsafe { libc::ioctl(sock.as_raw_fd(), request, arg) } < 0 {
        return Err(Error::Network(format!(
            "Failed to {what}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Create an anonymous cloned interface and return the assigned name.
fn create_clone_interface(iftype: &str) -> Result<String> {
    let sock = create_socket()?;

    // SAFETY: plain-data struct; all-zero is valid (null ifr_data = no clone params).
    let mut req: IfReqNameData = unsafe { std::mem::zeroed() };

    copy_ifname(&mut req.ifr_name, iftype)?;

    // SAFETY: req is ifreq-sized; kernel writes the assigned name into ifr_name.
    unsafe { interface_ioctl(&sock, SIOCIFCREATE2, &raw mut req, "create interface") }?;

    extract_ifname(&req.ifr_name)
}

/// Create a network interface (epair, bridge, etc.)
pub fn create_interface(iftype: &str, name: Option<&str>) -> Result<String> {
    let created_name = create_clone_interface(iftype)?;

    if let Some(requested_name) = name {
        if created_name != requested_name {
            // Like ifconfig: clone then rename; non-cloner names give EINVAL on create.
            if let Err(err) = rename_interface(&created_name, requested_name) {
                // Rollback; keep the original error.
                let _ = destroy_interface(&created_name);
                return Err(err);
            }
        }

        Ok(requested_name.to_string())
    } else {
        Ok(created_name)
    }
}

/// Destroy a network interface
pub fn destroy_interface(name: &str) -> Result<()> {
    let sock = create_socket()?;

    // SAFETY: plain-data struct; all-zero is valid.
    let mut req: IfReqNameData = unsafe { std::mem::zeroed() };
    copy_ifname(&mut req.ifr_name, name)?;

    // SAFETY: req is ifreq-sized; SIOCIFDESTROY only reads ifr_name.
    unsafe {
        interface_ioctl(
            &sock,
            SIOCIFDESTROY,
            std::ptr::from_ref(&req).cast_mut(),
            "destroy interface",
        )
    }?;

    Ok(())
}

/// Bring an interface up or down
pub fn set_interface_up(name: &str, up: bool) -> Result<()> {
    const IFF_UP: libc::c_short = 0x1;
    let sock = create_socket()?;

    // SAFETY: plain-data struct; all-zero is valid.
    let mut req: IfReqFlags = unsafe { std::mem::zeroed() };
    copy_ifname(&mut req.ifr_name, name)?;

    // SAFETY: req is ifreq-sized; kernel fills ifr_flags.
    unsafe { interface_ioctl(&sock, SIOCGIFFLAGS, &raw mut req, "get interface flags") }?;

    if up {
        req.ifr_flags |= IFF_UP;
    } else {
        req.ifr_flags &= !IFF_UP;
    }

    // SAFETY: req is ifreq-sized; SIOCSIFFLAGS only reads it.
    unsafe {
        interface_ioctl(
            &sock,
            SIOCSIFFLAGS,
            std::ptr::from_ref(&req).cast_mut(),
            "set interface flags",
        )
    }?;

    Ok(())
}

/// Rename a network interface
pub fn rename_interface(old_name: &str, new_name: &str) -> Result<()> {
    let sock = create_socket()?;

    // SAFETY: plain-data struct; all-zero is valid.
    let mut req: IfReqNameData = unsafe { std::mem::zeroed() };
    copy_ifname(&mut req.ifr_name, old_name)?;

    let new_cstr = CString::new(new_name)
        .map_err(|e| Error::Network(format!("Invalid interface name: {e}")))?;

    req.ifr_data = new_cstr.as_ptr().cast_mut().cast();

    // SAFETY: ifr_data points at new_cstr, alive until return; kernel bounds the copyinstr.
    unsafe {
        interface_ioctl(
            &sock,
            SIOCSIFNAME,
            std::ptr::from_ref(&req).cast_mut(),
            "rename interface",
        )
    }?;

    Ok(())
}

/// Set MAC address on an interface
pub fn set_mac_address(name: &str, mac: &str) -> Result<()> {
    let sock = create_socket()?;

    let mac_parts: Vec<&str> = mac.split(':').collect();
    if mac_parts.len() != 6 {
        return Err(Error::Network(format!("Invalid MAC address format: {mac}")));
    }

    let mut mac_bytes = [0u8; 6];
    for (i, part) in mac_parts.iter().enumerate() {
        mac_bytes[i] = u8::from_str_radix(part, 16)
            .map_err(|e| Error::Network(format!("Invalid MAC address: {e}")))?;
    }

    // SAFETY: plain-data struct; all-zero is valid.
    let mut req: IfReqSockaddr = unsafe { std::mem::zeroed() };
    copy_ifname(&mut req.ifr_name, name)?;

    // SIOCSIFLLADDR reads sa_data[0..sa_len]; kernel checks sa_len == if_addrlen.
    req.ifr_addr.sa_family = AF_LINK_FAMILY;
    req.ifr_addr.sa_len = 6;
    // SAFETY: sa_data is 14 bytes; we write 6 from a separate array.
    unsafe {
        std::ptr::copy_nonoverlapping(
            mac_bytes.as_ptr(),
            req.ifr_addr.sa_data.as_mut_ptr().cast::<u8>(),
            6,
        );
    }

    // SAFETY: req is ifreq-sized; SIOCSIFLLADDR only reads it.
    unsafe {
        interface_ioctl(
            &sock,
            SIOCSIFLLADDR,
            std::ptr::from_ref(&req).cast_mut(),
            "set MAC address",
        )
    }?;

    Ok(())
}

/// Move interface to VNET jail
pub fn move_to_vnet(name: &str, jid: i32) -> Result<()> {
    let sock = create_socket()?;

    // SAFETY: plain-data struct; all-zero is valid.
    let mut req: IfReqJid = unsafe { std::mem::zeroed() };
    copy_ifname(&mut req.ifr_name, name)?;

    req.ifr_jid = jid;

    // SAFETY: req is ifreq-sized; SIOCSIFVNET only reads it.
    unsafe {
        interface_ioctl(
            &sock,
            SIOCSIFVNET,
            std::ptr::from_ref(&req).cast_mut(),
            "move interface to VNET",
        )
    }?;

    Ok(())
}

fn bridge_member_op(bridge: &str, member: &str, cmd: libc::c_ulong) -> Result<()> {
    let sock = create_socket()?;

    // SAFETY: plain-data struct; all-zero is valid.
    let mut req: BridgeIfReq = unsafe { std::mem::zeroed() };
    copy_ifname(&mut req.ifbr_ifsname, member)?;

    // SAFETY: req is a live BridgeIfReq, as BRDGADD/BRDGDEL expect.
    unsafe {
        bridge_drvspec(
            sock.as_raw_fd(),
            bridge,
            cmd,
            std::mem::size_of::<BridgeIfReq>(),
            (&raw mut req).cast::<libc::c_void>(),
            true,
        )
    }
}

/// Add a member interface to a bridge
pub fn bridge_add_member(bridge: &str, member: &str) -> Result<()> {
    bridge_member_op(bridge, member, BRDGADD)
}

/// Remove a member interface from a bridge
pub fn bridge_delete_member(bridge: &str, member: &str) -> Result<()> {
    bridge_member_op(bridge, member, BRDGDEL)
}

/// Check if an interface exists
pub fn interface_exists(name: &str) -> Result<bool> {
    let sock = create_socket()?;

    // SAFETY: plain-data struct; all-zero is valid.
    let mut req: IfReqFlags = unsafe { std::mem::zeroed() };

    if name.len() >= libc::IF_NAMESIZE {
        return Ok(false);
    }
    copy_ifname(&mut req.ifr_name, name)?;

    // SAFETY: req is ifreq-sized; kernel fills ifr_flags.
    let result = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCGIFFLAGS, &mut req) };

    Ok(result >= 0)
}

/// Set IPv4 address on an interface
///
/// Supports CIDR notation like "10.0.0.1/24" or plain IP like "10.0.0.1".
/// When no prefix is specified, /32 is used.
pub fn set_ipv4_address(name: &str, addr: &str) -> Result<()> {
    const fn fill_sockaddr_in(dest: &mut libc::sockaddr_in, ip: Ipv4Addr) {
        dest.sin_len = SOCKADDR_IN_LEN;
        dest.sin_family = AF_INET_FAMILY;
        dest.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
    }

    use std::net::Ipv4Addr;

    let sock = create_socket()?;

    let (ip_str, prefix_len) = if let Some(slash_pos) = addr.find('/') {
        let ip = &addr[..slash_pos];
        let prefix: u8 = addr[slash_pos + 1..]
            .parse()
            .map_err(|_| Error::Network(format!("Invalid prefix length in: {addr}")))?;
        (ip, prefix)
    } else {
        (addr, 32)
    };

    if prefix_len > 32 {
        return Err(Error::Network(format!("Invalid prefix length in: {addr}")));
    }

    let ip: Ipv4Addr = ip_str
        .parse()
        .map_err(|_| Error::Network(format!("Invalid IPv4 address: {ip_str}")))?;

    // SAFETY: plain-data struct; all-zero is valid.
    let mut req: IfAliasReq = unsafe { std::mem::zeroed() };
    copy_ifname(&mut req.ifra_name, name)?;
    fill_sockaddr_in(&mut req.ifra_addr, ip);

    let netmask = if prefix_len == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix_len)
    };
    let netmask_ip = Ipv4Addr::from(netmask.to_be_bytes());
    fill_sockaddr_in(&mut req.ifra_mask, netmask_ip);

    if prefix_len < 32 {
        let ip_u32 = u32::from_be_bytes(ip.octets());
        let broadcast_ip = Ipv4Addr::from((ip_u32 | !netmask).to_be_bytes());
        fill_sockaddr_in(&mut req.ifra_broadaddr, broadcast_ip);
    }

    // SAFETY: req matches struct ifaliasreq; SIOCAIFADDR only reads it.
    unsafe {
        interface_ioctl(
            &sock,
            SIOCAIFADDR,
            std::ptr::from_ref(&req).cast_mut(),
            "set IP address",
        )
    }?;

    Ok(())
}

/// Disable hardware VLAN filtering on an interface
///
/// Uses SIOCGIFCAP/SIOCSIFCAP ioctls to clear `IFCAP_VLAN_HWFILTER` flag.
/// Some NICs (especially Broadcom) have buggy VLAN hardware filtering.
pub fn disable_hwfilter(name: &str) -> Result<()> {
    let sock = create_socket()?;

    // SAFETY: plain-data struct; all-zero is valid.
    let mut req: IfReqCap = unsafe { std::mem::zeroed() };
    copy_ifname(&mut req.ifr_name, name)?;

    // SAFETY: req is ifreq-sized; kernel fills ifr_curcap.
    unsafe {
        interface_ioctl(
            &sock,
            SIOCGIFCAP,
            &raw mut req,
            "get interface capabilities",
        )
    }?;

    req.ifr_reqcap = req.ifr_curcap & !IFCAP_VLAN_HWFILTER;

    // SAFETY: req is ifreq-sized; SIOCSIFCAP only reads it.
    unsafe {
        interface_ioctl(
            &sock,
            SIOCSIFCAP,
            std::ptr::from_ref(&req).cast_mut(),
            "disable hw VLAN filter",
        )
    }?;

    set_interface_up(name, true)?;

    Ok(())
}

/// Enable VLAN filtering on a bridge
///
/// Uses SIOCSDRVSPEC ioctl with BRDGSFLAGS command.
pub fn bridge_enable_vlan_filtering(bridge: &str) -> Result<()> {
    const IFBRF_VLANFILTER: u32 = 1;
    let sock = create_socket()?;

    let mut get_param = BridgeParam { ifbrp_int32: 0 };
    // SAFETY: get_param is a live BridgeParam, as BRDGGFLAGS expects.
    let result = unsafe {
        bridge_drvspec_io(
            sock.as_raw_fd(),
            bridge,
            BRDGGFLAGS,
            std::mem::size_of::<BridgeParam>(),
            (&raw mut get_param).cast::<libc::c_void>(),
            false,
        )
    };

    let current_flags = if result.is_ok() {
        get_param.ifbrp_int32
    } else {
        0
    };

    let mut set_param = BridgeParam {
        ifbrp_int32: current_flags | IFBRF_VLANFILTER,
    };
    // SAFETY: set_param is a live BridgeParam, as BRDGSFLAGS expects.
    unsafe {
        bridge_drvspec(
            sock.as_raw_fd(),
            bridge,
            BRDGSFLAGS,
            std::mem::size_of::<BridgeParam>(),
            (&raw mut set_param).cast::<libc::c_void>(),
            true,
        )
    }
}

/// Set PVID (Port VLAN ID) on a bridge member interface
///
/// Uses SIOCSDRVSPEC ioctl with BRDGSIFPVID command.
pub fn bridge_set_pvid(bridge: &str, member: &str, pvid: u16) -> Result<()> {
    let sock = create_socket()?;

    // SAFETY: plain-data struct; all-zero is valid.
    let mut breq: BridgeIfReq = unsafe { std::mem::zeroed() };
    copy_ifname(&mut breq.ifbr_ifsname, member)?;
    breq.ifbr_pvid = pvid;

    // SAFETY: breq is a live BridgeIfReq, as BRDGSIFPVID expects.
    unsafe {
        bridge_drvspec_io(
            sock.as_raw_fd(),
            bridge,
            BRDGSIFPVID,
            std::mem::size_of::<BridgeIfReq>(),
            (&raw mut breq).cast::<libc::c_void>(),
            true,
        )
    }
    .map_err(|e| Error::Network(format!("Failed to set PVID on {member}: {e}")))
}

/// Set tagged VLANs on a bridge member (trunk port)
///
/// Uses SIOCSDRVSPEC ioctl with BRDGSIFVLANSET command.
/// The vlans slice contains VLAN IDs (1-4094) to tag.
pub fn bridge_set_tagged_vlans(bridge: &str, member: &str, vlans: &[u16]) -> Result<()> {
    const BRDG_VLAN_OP_SET: u8 = 1;
    let sock = create_socket()?;

    // SAFETY: plain-data struct; all-zero is an empty VLAN set.
    let mut vreq: BridgeIfVlanReq = unsafe { std::mem::zeroed() };
    copy_ifname(&mut vreq.bv_ifname, member)?;

    vreq.bv_op = BRDG_VLAN_OP_SET;

    // __BIT_SET layout: word n / BITS, bit n % BITS.
    let word_bits = libc::c_ulong::BITS as usize;
    for &vlan in vlans {
        if vlan > 0 && vlan < 4095 {
            let vlan = vlan as usize;
            vreq.bv_set[vlan / word_bits] |= 1 << (vlan % word_bits);
        }
    }

    // SAFETY: vreq is a live BridgeIfVlanReq, as BRDGSIFVLANSET expects.
    unsafe {
        bridge_drvspec_io(
            sock.as_raw_fd(),
            bridge,
            BRDGSIFVLANSET,
            std::mem::size_of::<BridgeIfVlanReq>(),
            (&raw mut vreq).cast::<libc::c_void>(),
            true,
        )
    }
    .map_err(|e| Error::Network(format!("Failed to set tagged VLANs on {member}: {e}")))
}

/// List member interfaces of a bridge
///
/// Uses SIOCGDRVSPEC ioctl with BRDGGIFS command.
pub fn bridge_list_members(bridge: &str) -> Result<Vec<String>> {
    let sock = create_socket()?;
    let entry_size = std::mem::size_of::<BridgeIfReq>();

    // BRDGGIFS never returns ENOMEM; a zero length queries the needed size.
    let mut size_query = BridgeIfConf {
        ifbic_len: 0,
        _padding: 0,
        ifbic_req: std::ptr::null_mut(),
    };
    // SAFETY: zero ifbic_len; kernel only writes the length.
    unsafe { bridge_list_io(sock.as_raw_fd(), bridge, &mut size_query) }?;
    let mut slots = size_query.ifbic_len as usize / entry_size + 1;

    loop {
        // SAFETY: plain-data struct; all-zero is valid.
        let mut buffer: Vec<BridgeIfReq> = vec![unsafe { std::mem::zeroed() }; slots];
        let ifbic_len = u32::try_from(slots * entry_size)
            .map_err(|_| Error::Network(format!("Bridge {bridge} member list too large")))?;
        let mut bifc = BridgeIfConf {
            ifbic_len,
            _padding: 0,
            ifbic_req: buffer.as_mut_ptr(),
        };
        // SAFETY: ifbic_req/ifbic_len describe `buffer`, alive across the call.
        unsafe { bridge_list_io(sock.as_raw_fd(), bridge, &mut bifc) }?;

        let count = bifc.ifbic_len as usize / entry_size;
        if count == slots {
            // Buffer full: members joined since the size query.
            slots *= 2;
            continue;
        }

        return Ok(buffer
            .iter()
            .take(count)
            .filter_map(|entry| {
                String::from_utf8(crate::sys::c_buf_bytes(&entry.ifbr_ifsname))
                    .ok()
                    .filter(|name| !name.is_empty())
            })
            .collect());
    }
}

/// One BRDGGIFS round trip.
///
/// # Safety
/// `bifc.ifbic_req` must point at `ifbic_len` writable bytes, or `ifbic_len` must be zero.
unsafe fn bridge_list_io(fd: libc::c_int, bridge: &str, bifc: &mut BridgeIfConf) -> Result<()> {
    // SAFETY: bifc's buffer is valid per this function's contract.
    unsafe {
        bridge_drvspec_io(
            fd,
            bridge,
            BRDGGIFS,
            std::mem::size_of::<BridgeIfConf>(),
            std::ptr::from_mut(bifc).cast::<libc::c_void>(),
            false,
        )
    }
    .map_err(|err| Error::Network(format!("Failed to list bridge members: {err}")))
}

#[cfg(test)]
#[path = "ioctl/tests.rs"]
mod tests;
