//! FreeBSD network ioctl syscalls
//!
//! Native ioctl operations for network interface management, replacing ifconfig commands.

use crate::error::{Error, Result};
use std::ffi::CString;
use std::net::UdpSocket;
use std::os::unix::io::AsRawFd;

// Request codes and driver subcommands read from the system headers at build
// time; see build/sys_consts.c.
use crate::sys::consts::*;

/// Safely copy interface name into fixed-size buffer
/// Returns error if name is too long (max 15 chars + null terminator)
fn copy_ifname(dest: &mut [libc::c_char; libc::IF_NAMESIZE], name: &str) -> Result<()> {
    let name_cstr =
        CString::new(name).map_err(|e| Error::Network(format!("Invalid interface name: {}", e)))?;
    let name_bytes = name_cstr.as_bytes_with_nul();

    if name_bytes.len() > libc::IF_NAMESIZE {
        return Err(Error::Network(format!(
            "Interface name too long: {} (max {} chars)",
            name,
            libc::IF_NAMESIZE - 1
        )));
    }

    dest[..name_bytes.len()].copy_from_slice(unsafe {
        std::slice::from_raw_parts(name_bytes.as_ptr() as *const i8, name_bytes.len())
    });

    Ok(())
}

fn create_socket() -> Result<UdpSocket> {
    UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| Error::Network(format!("Failed to create socket: {}", e)))
}

fn extract_ifname(name: &[libc::c_char; libc::IF_NAMESIZE]) -> Result<String> {
    let name_len = name
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(libc::IF_NAMESIZE);
    let name_bytes: Vec<u8> = name[..name_len].iter().map(|&c| c as u8).collect();

    String::from_utf8(name_bytes)
        .map_err(|e| Error::Network(format!("Invalid interface name: {}", e)))
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
struct IfAliasReq {
    ifra_name: [libc::c_char; libc::IF_NAMESIZE],
    ifra_addr: libc::sockaddr_in,
    ifra_broadaddr: libc::sockaddr_in,
    ifra_mask: libc::sockaddr_in,
    ifra_vhid: libc::c_int,
}

#[repr(C)]
struct IfDrv {
    ifd_name: [libc::c_char; libc::IF_NAMESIZE],
    ifd_cmd: libc::c_ulong,
    ifd_len: libc::size_t,
    ifd_data: *mut libc::c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
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
struct BridgeIfVlanReq {
    bv_ifname: [libc::c_char; libc::IF_NAMESIZE],
    bv_op: u8,
    _padding: [u8; 7],
    bv_set: [u8; 512],
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
const _: [(); 536] = [(); std::mem::size_of::<BridgeIfVlanReq>()];

fn bridge_drvspec_io(
    sock_fd: libc::c_int,
    bridge: &str,
    cmd: libc::c_ulong,
    len: libc::size_t,
    data: *mut libc::c_void,
    set: bool,
) -> std::io::Result<()> {
    let mut req: IfDrv = unsafe { std::mem::zeroed() };
    copy_ifname(&mut req.ifd_name, bridge).map_err(|e| std::io::Error::other(e.to_string()))?;
    req.ifd_cmd = cmd;
    req.ifd_len = len;
    req.ifd_data = data;

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

fn bridge_drvspec(
    sock_fd: libc::c_int,
    bridge: &str,
    cmd: libc::c_ulong,
    len: libc::size_t,
    data: *mut libc::c_void,
    set: bool,
) -> Result<()> {
    bridge_drvspec_io(sock_fd, bridge, cmd, len, data, set)
        .map_err(|e| Error::Network(format!("Bridge ioctl {} failed: {}", cmd, e)))
}

/// Create an anonymous cloned interface and return the assigned name.
fn create_clone_interface(iftype: &str) -> Result<String> {
    // Create a socket for ioctl operations
    let sock = create_socket()?;

    // SIOCIFCREATE structure for FreeBSD
    let mut req: IfReqNameData = unsafe { std::mem::zeroed() };

    copy_ifname(&mut req.ifr_name, iftype)?;

    // ifconfig(8) uses SIOCIFCREATE2 for clone creation on modern FreeBSD.
    let result = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCIFCREATE2, &mut req) };

    if result < 0 {
        return Err(Error::Network(format!(
            "Failed to create interface: {}",
            std::io::Error::last_os_error()
        )));
    }

    extract_ifname(&req.ifr_name)
}

/// Create a network interface (epair, bridge, etc.)
pub fn create_interface(iftype: &str, name: Option<&str>) -> Result<String> {
    let created_name = create_clone_interface(iftype)?;

    if let Some(requested_name) = name {
        if created_name != requested_name {
            // FreeBSD's ifconfig creates the clone first and then renames it when a
            // custom name is requested. Doing the same avoids EINVAL when passing a
            // non-cloner name like "blackship0" directly to clone creation.
            if let Err(err) = rename_interface(&created_name, requested_name) {
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

    let mut req: IfReqNameData = unsafe { std::mem::zeroed() };
    copy_ifname(&mut req.ifr_name, name)?;

    // SIOCIFDESTROY ioctl

    let result = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCIFDESTROY, &req) };

    if result < 0 {
        return Err(Error::Network(format!(
            "Failed to destroy interface: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Bring an interface up or down
pub fn set_interface_up(name: &str, up: bool) -> Result<()> {
    let sock = create_socket()?;

    let mut req: IfReqFlags = unsafe { std::mem::zeroed() };
    copy_ifname(&mut req.ifr_name, name)?;

    // Get current flags
    let result = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCGIFFLAGS, &mut req) };
    if result < 0 {
        return Err(Error::Network(format!(
            "Failed to get interface flags: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Modify flags
    const IFF_UP: libc::c_short = 0x1;
    if up {
        req.ifr_flags |= IFF_UP;
    } else {
        req.ifr_flags &= !IFF_UP;
    }

    // Set new flags
    let result = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCSIFFLAGS, &req) };
    if result < 0 {
        return Err(Error::Network(format!(
            "Failed to set interface flags: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Rename a network interface
pub fn rename_interface(old_name: &str, new_name: &str) -> Result<()> {
    let sock = create_socket()?;

    let mut req: IfReqNameData = unsafe { std::mem::zeroed() };
    copy_ifname(&mut req.ifr_name, old_name)?;

    let new_cstr = CString::new(new_name)
        .map_err(|e| Error::Network(format!("Invalid interface name: {}", e)))?;

    req.ifr_data = new_cstr.as_ptr() as *mut libc::c_void;

    // SIOCSIFNAME ioctl

    let result = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCSIFNAME, &req) };

    if result < 0 {
        return Err(Error::Network(format!(
            "Failed to rename interface: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Set MAC address on an interface
pub fn set_mac_address(name: &str, mac: &str) -> Result<()> {
    let sock = create_socket()?;

    // Parse MAC address
    let mac_parts: Vec<&str> = mac.split(':').collect();
    if mac_parts.len() != 6 {
        return Err(Error::Network(format!(
            "Invalid MAC address format: {}",
            mac
        )));
    }

    let mut mac_bytes = [0u8; 6];
    for (i, part) in mac_parts.iter().enumerate() {
        mac_bytes[i] = u8::from_str_radix(part, 16)
            .map_err(|e| Error::Network(format!("Invalid MAC address: {}", e)))?;
    }

    let mut req: IfReqSockaddr = unsafe { std::mem::zeroed() };
    copy_ifname(&mut req.ifr_name, name)?;

    // SIOCSIFLLADDR reads sa_data[0..sa_len]; kernel checks sa_len == if_addrlen.
    req.ifr_addr.sa_family = libc::AF_LINK as u8;
    req.ifr_addr.sa_len = 6;
    unsafe {
        std::ptr::copy_nonoverlapping(
            mac_bytes.as_ptr(),
            req.ifr_addr.sa_data.as_mut_ptr() as *mut u8,
            6,
        );
    }

    // SIOCSIFLLADDR ioctl

    let result = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCSIFLLADDR, &req) };

    if result < 0 {
        return Err(Error::Network(format!(
            "Failed to set MAC address: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Move interface to VNET jail
pub fn move_to_vnet(name: &str, jid: i32) -> Result<()> {
    let sock = create_socket()?;

    let mut req: IfReqJid = unsafe { std::mem::zeroed() };
    copy_ifname(&mut req.ifr_name, name)?;

    req.ifr_jid = jid;

    // SIOCSIFVNET ioctl (FreeBSD-specific)

    let result = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCSIFVNET, &req) };

    if result < 0 {
        return Err(Error::Network(format!(
            "Failed to move interface to VNET: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Add or remove a bridge member via a BRDGADD/BRDGDEL drvspec ioctl
fn bridge_member_op(bridge: &str, member: &str, cmd: libc::c_ulong) -> Result<()> {
    let sock = create_socket()?;

    let mut req: BridgeIfReq = unsafe { std::mem::zeroed() };
    copy_ifname(&mut req.ifbr_ifsname, member)?;

    bridge_drvspec(
        sock.as_raw_fd(),
        bridge,
        cmd,
        std::mem::size_of::<BridgeIfReq>(),
        &mut req as *mut _ as *mut libc::c_void,
        true,
    )
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

    let mut req: IfReqFlags = unsafe { std::mem::zeroed() };

    // Validate name length - if too long, interface definitely doesn't exist
    if name.len() >= libc::IF_NAMESIZE {
        return Ok(false);
    }
    copy_ifname(&mut req.ifr_name, name)?;

    // Try to get interface flags - if it succeeds, interface exists
    let result = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCGIFFLAGS, &mut req) };

    Ok(result >= 0)
}

/// Set IPv4 address on an interface
///
/// Supports CIDR notation like "10.0.0.1/24" or plain IP like "10.0.0.1".
/// When no prefix is specified, /32 is used.
pub fn set_ipv4_address(name: &str, addr: &str) -> Result<()> {
    use std::net::Ipv4Addr;

    let sock = create_socket()?;

    // Parse address with optional CIDR notation
    let (ip_str, prefix_len) = if let Some(slash_pos) = addr.find('/') {
        let ip = &addr[..slash_pos];
        let prefix: u8 = addr[slash_pos + 1..]
            .parse()
            .map_err(|_| Error::Network(format!("Invalid prefix length in: {}", addr)))?;
        (ip, prefix)
    } else {
        (addr, 32)
    };

    if prefix_len > 32 {
        return Err(Error::Network(format!(
            "Invalid prefix length in: {}",
            addr
        )));
    }

    let ip: Ipv4Addr = ip_str
        .parse()
        .map_err(|_| Error::Network(format!("Invalid IPv4 address: {}", ip_str)))?;

    fn fill_sockaddr_in(dest: &mut libc::sockaddr_in, ip: Ipv4Addr) {
        dest.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
        dest.sin_family = libc::AF_INET as u8;
        dest.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
    }

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

    // SIOCAIFADDR ioctl

    let result = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCAIFADDR, &req) };

    if result < 0 {
        return Err(Error::Network(format!(
            "Failed to set IP address: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Disable hardware VLAN filtering on an interface
///
/// Uses SIOCGIFCAP/SIOCSIFCAP ioctls to clear IFCAP_VLAN_HWFILTER flag.
/// Some NICs (especially Broadcom) have buggy VLAN hardware filtering.
pub fn disable_hwfilter(name: &str) -> Result<()> {
    let sock = create_socket()?;

    let mut req: IfReqCap = unsafe { std::mem::zeroed() };
    copy_ifname(&mut req.ifr_name, name)?;

    // Get current capabilities
    let result = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCGIFCAP, &mut req) };
    if result < 0 {
        return Err(Error::Network(format!(
            "Failed to get interface capabilities: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Clear VLAN hardware filter capability
    req.ifr_reqcap = req.ifr_curcap & !IFCAP_VLAN_HWFILTER;

    // Set new capabilities
    let result = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCSIFCAP, &req) };
    if result < 0 {
        return Err(Error::Network(format!(
            "Failed to disable hw VLAN filter: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Also bring the interface up
    set_interface_up(name, true)?;

    Ok(())
}

/// Enable VLAN filtering on a bridge
///
/// Uses SIOCSDRVSPEC ioctl with BRDGSFLAGS command.
pub fn bridge_enable_vlan_filtering(bridge: &str) -> Result<()> {
    let sock = create_socket()?;

    // First get current flags
    let mut get_param = BridgeParam { ifbrp_int32: 0 };
    let result = bridge_drvspec_io(
        sock.as_raw_fd(),
        bridge,
        BRDGGFLAGS,
        std::mem::size_of::<BridgeParam>(),
        &mut get_param as *mut _ as *mut libc::c_void,
        false,
    );

    // Start with current flags or 0 if get failed
    let current_flags = if result.is_ok() {
        get_param.ifbrp_int32
    } else {
        0
    };

    // Set VLAN filtering flag
    const IFBRF_VLANFILTER: u32 = 1;
    let mut set_param = BridgeParam {
        ifbrp_int32: current_flags | IFBRF_VLANFILTER,
    };
    bridge_drvspec(
        sock.as_raw_fd(),
        bridge,
        BRDGSFLAGS,
        std::mem::size_of::<BridgeParam>(),
        &mut set_param as *mut _ as *mut libc::c_void,
        true,
    )
}

/// Set PVID (Port VLAN ID) on a bridge member interface
///
/// Uses SIOCSDRVSPEC ioctl with BRDGSIFPVID command.
pub fn bridge_set_pvid(bridge: &str, member: &str, pvid: u16) -> Result<()> {
    let sock = create_socket()?;

    // Bridge request structure with PVID
    let mut breq: BridgeIfReq = unsafe { std::mem::zeroed() };
    copy_ifname(&mut breq.ifbr_ifsname, member)?;
    breq.ifbr_pvid = pvid;

    bridge_drvspec_io(
        sock.as_raw_fd(),
        bridge,
        BRDGSIFPVID,
        std::mem::size_of::<BridgeIfReq>(),
        &mut breq as *mut _ as *mut libc::c_void,
        true,
    )
    .map_err(|e| Error::Network(format!("Failed to set PVID on {}: {}", member, e)))
}

/// Set tagged VLANs on a bridge member (trunk port)
///
/// Uses SIOCSDRVSPEC ioctl with BRDGSIFVLANSET command.
/// The vlans slice contains VLAN IDs (1-4094) to tag.
pub fn bridge_set_tagged_vlans(bridge: &str, member: &str, vlans: &[u16]) -> Result<()> {
    let sock = create_socket()?;

    let mut vreq: BridgeIfVlanReq = unsafe { std::mem::zeroed() };
    copy_ifname(&mut vreq.bv_ifname, member)?;

    // Operation: SET (replace entire VLAN set)
    const BRDG_VLAN_OP_SET: u8 = 1;
    vreq.bv_op = BRDG_VLAN_OP_SET;

    // Build VLAN bitmap
    for &vlan in vlans {
        if vlan > 0 && vlan < 4095 {
            let byte_idx = vlan as usize / 8;
            let bit_idx = vlan as usize % 8;
            vreq.bv_set[byte_idx] |= 1 << bit_idx;
        }
    }

    bridge_drvspec_io(
        sock.as_raw_fd(),
        bridge,
        BRDGSIFVLANSET,
        std::mem::size_of::<BridgeIfVlanReq>(),
        &mut vreq as *mut _ as *mut libc::c_void,
        true,
    )
    .map_err(|e| Error::Network(format!("Failed to set tagged VLANs on {}: {}", member, e)))
}

/// List member interfaces of a bridge
///
/// Uses SIOCGDRVSPEC ioctl with BRDGGIFS command.
pub fn bridge_list_members(bridge: &str) -> Result<Vec<String>> {
    let sock = create_socket()?;

    // Bridge interface request
    // Start with space for 16 members, grow if needed
    let mut capacity: usize = 16;
    let mut members = Vec::new();

    loop {
        let mut buffer: Vec<BridgeIfReq> = vec![unsafe { std::mem::zeroed() }; capacity];

        let mut bifc = BridgeIfConf {
            ifbic_len: (capacity * std::mem::size_of::<BridgeIfReq>()) as u32,
            _padding: 0,
            ifbic_req: buffer.as_mut_ptr(),
        };

        if let Err(err) = bridge_drvspec_io(
            sock.as_raw_fd(),
            bridge,
            BRDGGIFS,
            std::mem::size_of::<BridgeIfConf>(),
            &mut bifc as *mut _ as *mut libc::c_void,
            false,
        ) {
            // ENOMEM means we need more space
            // ENOMEM means we need more space
            if err.raw_os_error() == Some(libc::ENOMEM) {
                capacity *= 2;
                continue;
            }
            return Err(Error::Network(format!(
                "Failed to list bridge members: {}",
                err
            )));
        }

        // Parse results
        let count = bifc.ifbic_len as usize / std::mem::size_of::<BridgeIfReq>();
        for entry in buffer.iter().take(count) {
            let name_len = entry
                .ifbr_ifsname
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(libc::IF_NAMESIZE);
            let name_bytes: Vec<u8> = entry.ifbr_ifsname[..name_len]
                .iter()
                .map(|&c| c as u8)
                .collect();
            if let Ok(name) = String::from_utf8(name_bytes)
                && !name.is_empty()
            {
                members.push(name);
            }
        }

        break;
    }

    Ok(members)
}
