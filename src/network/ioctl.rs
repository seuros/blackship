//! FreeBSD network ioctl syscalls
//!
//! Native ioctl operations for network interface management, replacing ifconfig commands.

use crate::error::{Error, Result};
use std::ffi::CString;
use std::os::unix::io::AsRawFd;

/// Safely copy interface name into fixed-size buffer
/// Returns error if name is too long (max 15 chars + null terminator)
fn copy_ifname(dest: &mut [libc::c_char; libc::IF_NAMESIZE], name: &str) -> Result<()> {
    let name_cstr = CString::new(name)
        .map_err(|e| Error::Network(format!("Invalid interface name: {}", e)))?;
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

/// Create a network interface (epair, bridge, etc.)
pub fn create_interface(iftype: &str, name: Option<&str>) -> Result<String> {
    use std::net::UdpSocket;

    // Create a socket for ioctl operations
    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| Error::Network(format!("Failed to create socket: {}", e)))?;

    // SIOCIFCREATE structure for FreeBSD
    #[repr(C)]
    struct IfReq {
        ifr_name: [libc::c_char; libc::IF_NAMESIZE],
        ifr_data: *mut libc::c_void,
    }

    let mut req: IfReq = unsafe { std::mem::zeroed() };

    // Set interface type
    let type_cstr = CString::new(iftype)
        .map_err(|e| Error::Network(format!("Invalid interface type: {}", e)))?;

    if let Some(n) = name {
        let name_cstr = CString::new(n)
            .map_err(|e| Error::Network(format!("Invalid interface name: {}", e)))?;
        let name_bytes = name_cstr.as_bytes_with_nul();
        req.ifr_name[..name_bytes.len()].copy_from_slice(unsafe {
            std::slice::from_raw_parts(name_bytes.as_ptr() as *const i8, name_bytes.len())
        });
    } else {
        let type_bytes = type_cstr.as_bytes_with_nul();
        req.ifr_name[..type_bytes.len()].copy_from_slice(unsafe {
            std::slice::from_raw_parts(type_bytes.as_ptr() as *const i8, type_bytes.len())
        });
    }

    // SIOCIFCREATE ioctl
    const SIOCIFCREATE: libc::c_ulong = 0xc020697a;

    let result = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCIFCREATE, &mut req) };

    if result < 0 {
        return Err(Error::Network(format!(
            "Failed to create interface: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Extract the created interface name
    let name_len = req
        .ifr_name
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(libc::IF_NAMESIZE);
    let name_bytes: Vec<u8> = req.ifr_name[..name_len]
        .iter()
        .map(|&c| c as u8)
        .collect();

    String::from_utf8(name_bytes)
        .map_err(|e| Error::Network(format!("Invalid interface name: {}", e)))
}

/// Destroy a network interface
pub fn destroy_interface(name: &str) -> Result<()> {
    use std::net::UdpSocket;

    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| Error::Network(format!("Failed to create socket: {}", e)))?;

    #[repr(C)]
    struct IfReq {
        ifr_name: [libc::c_char; libc::IF_NAMESIZE],
        ifr_data: *mut libc::c_void,
    }

    let mut req: IfReq = unsafe { std::mem::zeroed() };

    let name_cstr = CString::new(name)
        .map_err(|e| Error::Network(format!("Invalid interface name: {}", e)))?;
    let name_bytes = name_cstr.as_bytes_with_nul();
    req.ifr_name[..name_bytes.len()].copy_from_slice(unsafe {
        std::slice::from_raw_parts(name_bytes.as_ptr() as *const i8, name_bytes.len())
    });

    // SIOCIFDESTROY ioctl
    const SIOCIFDESTROY: libc::c_ulong = 0x80206979;

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
    use std::net::UdpSocket;

    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| Error::Network(format!("Failed to create socket: {}", e)))?;

    #[repr(C)]
    struct IfReq {
        ifr_name: [libc::c_char; libc::IF_NAMESIZE],
        ifr_flags: libc::c_short,
        _padding: [u8; 24],
    }

    let mut req: IfReq = unsafe { std::mem::zeroed() };

    let name_cstr = CString::new(name)
        .map_err(|e| Error::Network(format!("Invalid interface name: {}", e)))?;
    let name_bytes = name_cstr.as_bytes_with_nul();
    req.ifr_name[..name_bytes.len()].copy_from_slice(unsafe {
        std::slice::from_raw_parts(name_bytes.as_ptr() as *const i8, name_bytes.len())
    });

    // Get current flags
    const SIOCGIFFLAGS: libc::c_ulong = 0xc0206911;
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
    const SIOCSIFFLAGS: libc::c_ulong = 0x80206910;
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
    use std::net::UdpSocket;

    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| Error::Network(format!("Failed to create socket: {}", e)))?;

    #[repr(C)]
    struct IfReq {
        ifr_name: [libc::c_char; libc::IF_NAMESIZE],
        ifr_data: *mut libc::c_void,
    }

    let mut req: IfReq = unsafe { std::mem::zeroed() };

    let old_cstr = CString::new(old_name)
        .map_err(|e| Error::Network(format!("Invalid interface name: {}", e)))?;
    let old_bytes = old_cstr.as_bytes_with_nul();
    req.ifr_name[..old_bytes.len()].copy_from_slice(unsafe {
        std::slice::from_raw_parts(old_bytes.as_ptr() as *const i8, old_bytes.len())
    });

    let new_cstr = CString::new(new_name)
        .map_err(|e| Error::Network(format!("Invalid interface name: {}", e)))?;

    req.ifr_data = new_cstr.as_ptr() as *mut libc::c_void;

    // SIOCSIFNAME ioctl
    const SIOCSIFNAME: libc::c_ulong = 0x80206928;

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
    use std::net::UdpSocket;

    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| Error::Network(format!("Failed to create socket: {}", e)))?;

    // Parse MAC address
    let mac_parts: Vec<&str> = mac.split(':').collect();
    if mac_parts.len() != 6 {
        return Err(Error::Network(format!("Invalid MAC address format: {}", mac)));
    }

    let mut mac_bytes = [0u8; 6];
    for (i, part) in mac_parts.iter().enumerate() {
        mac_bytes[i] = u8::from_str_radix(part, 16)
            .map_err(|e| Error::Network(format!("Invalid MAC address: {}", e)))?;
    }

    #[repr(C)]
    struct IfReq {
        ifr_name: [libc::c_char; libc::IF_NAMESIZE],
        ifr_addr: libc::sockaddr,
    }

    let mut req: IfReq = unsafe { std::mem::zeroed() };

    let name_cstr = CString::new(name)
        .map_err(|e| Error::Network(format!("Invalid interface name: {}", e)))?;
    let name_bytes = name_cstr.as_bytes_with_nul();
    req.ifr_name[..name_bytes.len()].copy_from_slice(unsafe {
        std::slice::from_raw_parts(name_bytes.as_ptr() as *const i8, name_bytes.len())
    });

    // Set up sockaddr_dl for MAC address
    req.ifr_addr.sa_family = libc::AF_LINK as u8;
    req.ifr_addr.sa_len = 20;
    unsafe {
        std::ptr::copy_nonoverlapping(
            mac_bytes.as_ptr(),
            req.ifr_addr.sa_data.as_mut_ptr() as *mut u8,
            6,
        );
    }

    // SIOCSIFLLADDR ioctl
    const SIOCSIFLLADDR: libc::c_ulong = 0x8020693c;

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
    use std::net::UdpSocket;

    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| Error::Network(format!("Failed to create socket: {}", e)))?;

    #[repr(C)]
    struct IfReq {
        ifr_name: [libc::c_char; libc::IF_NAMESIZE],
        ifr_jid: libc::c_int,
        _padding: [u8; 20],
    }

    let mut req: IfReq = unsafe { std::mem::zeroed() };

    let name_cstr = CString::new(name)
        .map_err(|e| Error::Network(format!("Invalid interface name: {}", e)))?;
    let name_bytes = name_cstr.as_bytes_with_nul();
    req.ifr_name[..name_bytes.len()].copy_from_slice(unsafe {
        std::slice::from_raw_parts(name_bytes.as_ptr() as *const i8, name_bytes.len())
    });

    req.ifr_jid = jid;

    // SIOCSIFVNET ioctl (FreeBSD-specific)
    const SIOCSIFVNET: libc::c_ulong = 0xc020695a;

    let result = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCSIFVNET, &req) };

    if result < 0 {
        return Err(Error::Network(format!(
            "Failed to move interface to VNET: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Add a member interface to a bridge
pub fn bridge_add_member(bridge: &str, member: &str) -> Result<()> {
    use std::net::UdpSocket;

    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| Error::Network(format!("Failed to create socket: {}", e)))?;

    #[repr(C)]
    struct IfBReq {
        ifbr_ifsname: [libc::c_char; libc::IF_NAMESIZE],
    }

    #[repr(C)]
    struct IfReq {
        ifr_name: [libc::c_char; libc::IF_NAMESIZE],
        ifr_data: *mut libc::c_void,
    }

    let mut breq: IfBReq = unsafe { std::mem::zeroed() };
    let mut req: IfReq = unsafe { std::mem::zeroed() };

    // Set bridge name
    let bridge_cstr = CString::new(bridge)
        .map_err(|e| Error::Network(format!("Invalid bridge name: {}", e)))?;
    let bridge_bytes = bridge_cstr.as_bytes_with_nul();
    req.ifr_name[..bridge_bytes.len()].copy_from_slice(unsafe {
        std::slice::from_raw_parts(bridge_bytes.as_ptr() as *const i8, bridge_bytes.len())
    });

    // Set member interface name
    let member_cstr = CString::new(member)
        .map_err(|e| Error::Network(format!("Invalid member name: {}", e)))?;
    let member_bytes = member_cstr.as_bytes_with_nul();
    breq.ifbr_ifsname[..member_bytes.len()].copy_from_slice(unsafe {
        std::slice::from_raw_parts(member_bytes.as_ptr() as *const i8, member_bytes.len())
    });

    req.ifr_data = &mut breq as *mut _ as *mut libc::c_void;

    // SIOCBRDGADD ioctl
    const SIOCBRDGADD: libc::c_ulong = 0x8028695c;

    let result = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCBRDGADD, &req) };

    if result < 0 {
        return Err(Error::Network(format!(
            "Failed to add member to bridge: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Remove a member interface from a bridge
pub fn bridge_delete_member(bridge: &str, member: &str) -> Result<()> {
    use std::net::UdpSocket;

    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| Error::Network(format!("Failed to create socket: {}", e)))?;

    #[repr(C)]
    struct IfBReq {
        ifbr_ifsname: [libc::c_char; libc::IF_NAMESIZE],
    }

    #[repr(C)]
    struct IfReq {
        ifr_name: [libc::c_char; libc::IF_NAMESIZE],
        ifr_data: *mut libc::c_void,
    }

    let mut breq: IfBReq = unsafe { std::mem::zeroed() };
    let mut req: IfReq = unsafe { std::mem::zeroed() };

    // Set bridge name
    let bridge_cstr = CString::new(bridge)
        .map_err(|e| Error::Network(format!("Invalid bridge name: {}", e)))?;
    let bridge_bytes = bridge_cstr.as_bytes_with_nul();
    req.ifr_name[..bridge_bytes.len()].copy_from_slice(unsafe {
        std::slice::from_raw_parts(bridge_bytes.as_ptr() as *const i8, bridge_bytes.len())
    });

    // Set member interface name
    let member_cstr = CString::new(member)
        .map_err(|e| Error::Network(format!("Invalid member name: {}", e)))?;
    let member_bytes = member_cstr.as_bytes_with_nul();
    breq.ifbr_ifsname[..member_bytes.len()].copy_from_slice(unsafe {
        std::slice::from_raw_parts(member_bytes.as_ptr() as *const i8, member_bytes.len())
    });

    req.ifr_data = &mut breq as *mut _ as *mut libc::c_void;

    // SIOCBRDGDEL ioctl
    const SIOCBRDGDEL: libc::c_ulong = 0x8028695d;

    let result = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCBRDGDEL, &req) };

    if result < 0 {
        return Err(Error::Network(format!(
            "Failed to remove member from bridge: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Check if an interface exists
pub fn interface_exists(name: &str) -> Result<bool> {
    use std::net::UdpSocket;

    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| Error::Network(format!("Failed to create socket: {}", e)))?;

    #[repr(C)]
    struct IfReq {
        ifr_name: [libc::c_char; libc::IF_NAMESIZE],
        ifr_flags: libc::c_short,
        _padding: [u8; 24],
    }

    let mut req: IfReq = unsafe { std::mem::zeroed() };

    // Validate name length - if too long, interface definitely doesn't exist
    if name.len() >= libc::IF_NAMESIZE {
        return Ok(false);
    }
    copy_ifname(&mut req.ifr_name, name)?;

    // Try to get interface flags - if it succeeds, interface exists
    const SIOCGIFFLAGS: libc::c_ulong = 0xc0206911;
    let result = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCGIFFLAGS, &mut req) };

    Ok(result >= 0)
}

/// Set IPv4 address on an interface
///
/// Supports CIDR notation like "10.0.0.1/24" or plain IP like "10.0.0.1"
/// When prefix length is specified, also sets the netmask.
pub fn set_ipv4_address(name: &str, addr: &str) -> Result<()> {
    use std::net::{Ipv4Addr, UdpSocket};

    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| Error::Network(format!("Failed to create socket: {}", e)))?;

    // Parse address with optional CIDR notation
    let (ip_str, prefix_len) = if let Some(slash_pos) = addr.find('/') {
        let ip = &addr[..slash_pos];
        let prefix: u8 = addr[slash_pos + 1..]
            .parse()
            .map_err(|_| Error::Network(format!("Invalid prefix length in: {}", addr)))?;
        (ip, Some(prefix))
    } else {
        (addr, None)
    };

    let ip: Ipv4Addr = ip_str
        .parse()
        .map_err(|_| Error::Network(format!("Invalid IPv4 address: {}", ip_str)))?;

    #[repr(C)]
    struct IfReqAddr {
        ifr_name: [libc::c_char; libc::IF_NAMESIZE],
        ifr_addr: libc::sockaddr_in,
    }

    let mut req: IfReqAddr = unsafe { std::mem::zeroed() };

    let name_cstr = CString::new(name)
        .map_err(|e| Error::Network(format!("Invalid interface name: {}", e)))?;
    let name_bytes = name_cstr.as_bytes_with_nul();
    req.ifr_name[..name_bytes.len()].copy_from_slice(unsafe {
        std::slice::from_raw_parts(name_bytes.as_ptr() as *const i8, name_bytes.len())
    });

    // Set up sockaddr_in
    req.ifr_addr.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
    req.ifr_addr.sin_family = libc::AF_INET as u8;
    req.ifr_addr.sin_addr.s_addr = u32::from_be_bytes(ip.octets()).to_be();

    // SIOCSIFADDR ioctl
    const SIOCSIFADDR: libc::c_ulong = 0x8020690c;

    let result = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCSIFADDR, &req) };

    if result < 0 {
        return Err(Error::Network(format!(
            "Failed to set IP address: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Set netmask if prefix length was specified
    if let Some(prefix) = prefix_len {
        let netmask = if prefix == 0 {
            0u32
        } else {
            !0u32 << (32 - prefix)
        };

        let mut mask_req: IfReqAddr = unsafe { std::mem::zeroed() };
        mask_req.ifr_name[..name_bytes.len()].copy_from_slice(unsafe {
            std::slice::from_raw_parts(name_bytes.as_ptr() as *const i8, name_bytes.len())
        });
        mask_req.ifr_addr.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
        mask_req.ifr_addr.sin_family = libc::AF_INET as u8;
        mask_req.ifr_addr.sin_addr.s_addr = netmask.to_be();

        // SIOCSIFNETMASK ioctl
        const SIOCSIFNETMASK: libc::c_ulong = 0x80206916;

        let result = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCSIFNETMASK, &mask_req) };

        if result < 0 {
            return Err(Error::Network(format!(
                "Failed to set netmask: {}",
                std::io::Error::last_os_error()
            )));
        }
    }

    Ok(())
}

/// List all bridge interfaces on the system
///
/// Uses if_nameindex(3) and filters for interfaces matching "bridge*" pattern
pub fn list_bridges() -> Result<Vec<String>> {
    let mut bridges = Vec::new();

    // Get list of all network interfaces
    let if_list = unsafe { libc::if_nameindex() };
    if if_list.is_null() {
        return Err(Error::Network(format!(
            "Failed to get interface list: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Iterate through interfaces
    let mut i = 0;
    loop {
        let entry = unsafe { *if_list.add(i) };
        if entry.if_index == 0 || entry.if_name.is_null() {
            break;
        }

        let name = unsafe { std::ffi::CStr::from_ptr(entry.if_name) }
            .to_string_lossy()
            .into_owned();

        // Filter for bridge interfaces
        if name.starts_with("bridge") {
            bridges.push(name);
        }

        i += 1;
    }

    // Free the interface list
    unsafe { libc::if_freenameindex(if_list) };

    Ok(bridges)
}

/// Disable hardware VLAN filtering on an interface
///
/// Uses SIOCGIFCAP/SIOCSIFCAP ioctls to clear IFCAP_VLAN_HWFILTER flag.
/// Some NICs (especially Broadcom) have buggy VLAN hardware filtering.
pub fn disable_hwfilter(name: &str) -> Result<()> {
    use std::net::UdpSocket;

    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| Error::Network(format!("Failed to create socket: {}", e)))?;

    #[repr(C)]
    struct IfReq {
        ifr_name: [libc::c_char; libc::IF_NAMESIZE],
        ifr_curcap: libc::c_int,
        ifr_reqcap: libc::c_int,
        _padding: [u8; 16],
    }

    let mut req: IfReq = unsafe { std::mem::zeroed() };
    copy_ifname(&mut req.ifr_name, name)?;

    // Get current capabilities
    const SIOCGIFCAP: libc::c_ulong = 0xc020693f;
    let result = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCGIFCAP, &mut req) };
    if result < 0 {
        return Err(Error::Network(format!(
            "Failed to get interface capabilities: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Clear VLAN hardware filter capability
    const IFCAP_VLAN_HWFILTER: libc::c_int = 1 << 17;
    req.ifr_reqcap = req.ifr_curcap & !IFCAP_VLAN_HWFILTER;

    // Set new capabilities
    const SIOCSIFCAP: libc::c_ulong = 0x80206937;
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
    use std::net::UdpSocket;

    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| Error::Network(format!("Failed to create socket: {}", e)))?;

    // Bridge parameter structure
    #[repr(C)]
    struct IfBrParam {
        ifbrp_csize: u32,
    }

    // Driver-specific ioctl structure
    #[repr(C)]
    struct IfDrv {
        ifd_name: [libc::c_char; libc::IF_NAMESIZE],
        ifd_cmd: libc::c_ulong,
        ifd_len: libc::size_t,
        ifd_data: *mut libc::c_void,
    }

    // First get current flags
    let mut get_param = IfBrParam { ifbrp_csize: 0 };
    let mut get_req: IfDrv = unsafe { std::mem::zeroed() };
    copy_ifname(&mut get_req.ifd_name, bridge)?;

    const BRDGGFLT: libc::c_ulong = 36; // Get filtering flags
    get_req.ifd_cmd = BRDGGFLT;
    get_req.ifd_len = std::mem::size_of::<IfBrParam>();
    get_req.ifd_data = &mut get_param as *mut _ as *mut libc::c_void;

    const SIOCGDRVSPEC: libc::c_ulong = 0xc0286977;
    let result = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCGDRVSPEC, &mut get_req) };

    // Start with current flags or 0 if get failed
    let current_flags = if result >= 0 { get_param.ifbrp_csize } else { 0 };

    // Set VLAN filtering flag
    const IFBRF_VLANFILTER: u32 = 1;
    let mut set_param = IfBrParam {
        ifbrp_csize: current_flags | IFBRF_VLANFILTER,
    };

    let mut set_req: IfDrv = unsafe { std::mem::zeroed() };
    copy_ifname(&mut set_req.ifd_name, bridge)?;

    const BRDGSFLAGS: libc::c_ulong = 35; // Set filtering flags
    set_req.ifd_cmd = BRDGSFLAGS;
    set_req.ifd_len = std::mem::size_of::<IfBrParam>();
    set_req.ifd_data = &mut set_param as *mut _ as *mut libc::c_void;

    const SIOCSDRVSPEC: libc::c_ulong = 0x8028695e;
    let result = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCSDRVSPEC, &set_req) };
    if result < 0 {
        return Err(Error::Network(format!(
            "Failed to enable VLAN filtering: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Set PVID (Port VLAN ID) on a bridge member interface
///
/// Uses SIOCSDRVSPEC ioctl with BRDGSIFPVID command.
pub fn bridge_set_pvid(bridge: &str, member: &str, pvid: u16) -> Result<()> {
    use std::net::UdpSocket;

    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| Error::Network(format!("Failed to create socket: {}", e)))?;

    // Bridge request structure with PVID
    #[repr(C)]
    struct IfBReq {
        ifbr_ifsname: [libc::c_char; libc::IF_NAMESIZE],
        ifbr_ifsflags: u32,
        ifbr_stpflags: u32,
        ifbr_path_cost: u32,
        ifbr_portno: u8,
        ifbr_priority: u8,
        ifbr_pvid: u16,
    }

    #[repr(C)]
    struct IfDrv {
        ifd_name: [libc::c_char; libc::IF_NAMESIZE],
        ifd_cmd: libc::c_ulong,
        ifd_len: libc::size_t,
        ifd_data: *mut libc::c_void,
    }

    let mut breq: IfBReq = unsafe { std::mem::zeroed() };
    copy_ifname(&mut breq.ifbr_ifsname, member)?;
    breq.ifbr_pvid = pvid;

    let mut req: IfDrv = unsafe { std::mem::zeroed() };
    copy_ifname(&mut req.ifd_name, bridge)?;

    const BRDGSIFPVID: libc::c_ulong = 31;
    req.ifd_cmd = BRDGSIFPVID;
    req.ifd_len = std::mem::size_of::<IfBReq>();
    req.ifd_data = &mut breq as *mut _ as *mut libc::c_void;

    const SIOCSDRVSPEC: libc::c_ulong = 0x8028695e;
    let result = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCSDRVSPEC, &req) };
    if result < 0 {
        return Err(Error::Network(format!(
            "Failed to set PVID on {}: {}",
            member,
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Set tagged VLANs on a bridge member (trunk port)
///
/// Uses SIOCSDRVSPEC ioctl with BRDGSIFVLANSET command.
/// The vlans slice contains VLAN IDs (1-4094) to tag.
pub fn bridge_set_tagged_vlans(bridge: &str, member: &str, vlans: &[u16]) -> Result<()> {
    use std::net::UdpSocket;

    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| Error::Network(format!("Failed to create socket: {}", e)))?;

    // VLAN bitmap - 4096 bits = 512 bytes
    const BRVLAN_SETSIZE: usize = 4096;
    const BRVLAN_BYTES: usize = BRVLAN_SETSIZE / 8;

    #[repr(C)]
    struct IfBifVlanReq {
        bv_ifname: [libc::c_char; libc::IF_NAMESIZE],
        bv_op: u8,
        _padding: [u8; 3],
        bv_set: [u8; BRVLAN_BYTES],
    }

    #[repr(C)]
    struct IfDrv {
        ifd_name: [libc::c_char; libc::IF_NAMESIZE],
        ifd_cmd: libc::c_ulong,
        ifd_len: libc::size_t,
        ifd_data: *mut libc::c_void,
    }

    let mut vreq: IfBifVlanReq = unsafe { std::mem::zeroed() };
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

    let mut req: IfDrv = unsafe { std::mem::zeroed() };
    copy_ifname(&mut req.ifd_name, bridge)?;

    const BRDGSIFVLANSET: libc::c_ulong = 32;
    req.ifd_cmd = BRDGSIFVLANSET;
    req.ifd_len = std::mem::size_of::<IfBifVlanReq>();
    req.ifd_data = &mut vreq as *mut _ as *mut libc::c_void;

    const SIOCSDRVSPEC: libc::c_ulong = 0x8028695e;
    let result = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCSDRVSPEC, &req) };
    if result < 0 {
        return Err(Error::Network(format!(
            "Failed to set tagged VLANs on {}: {}",
            member,
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// List member interfaces of a bridge
///
/// Uses SIOCGDRVSPEC ioctl with BRDGGIFS command.
pub fn bridge_list_members(bridge: &str) -> Result<Vec<String>> {
    use std::net::UdpSocket;

    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| Error::Network(format!("Failed to create socket: {}", e)))?;

    // Bridge interface request
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct IfBReq {
        ifbr_ifsname: [libc::c_char; libc::IF_NAMESIZE],
        ifbr_ifsflags: u32,
        ifbr_stpflags: u32,
        ifbr_path_cost: u32,
        ifbr_portno: u8,
        ifbr_priority: u8,
        ifbr_pvid: u16,
    }

    // Bridge interface config
    #[repr(C)]
    struct IfBifConf {
        ifbic_len: u32,
        ifbic_req: *mut IfBReq,
    }

    #[repr(C)]
    struct IfDrv {
        ifd_name: [libc::c_char; libc::IF_NAMESIZE],
        ifd_cmd: libc::c_ulong,
        ifd_len: libc::size_t,
        ifd_data: *mut libc::c_void,
    }

    // Start with space for 16 members, grow if needed
    let mut capacity: usize = 16;
    let mut members = Vec::new();

    loop {
        let mut buffer: Vec<IfBReq> = vec![unsafe { std::mem::zeroed() }; capacity];

        let mut bifc = IfBifConf {
            ifbic_len: (capacity * std::mem::size_of::<IfBReq>()) as u32,
            ifbic_req: buffer.as_mut_ptr(),
        };

        let mut req: IfDrv = unsafe { std::mem::zeroed() };
        copy_ifname(&mut req.ifd_name, bridge)?;

        const BRDGGIFS: libc::c_ulong = 6;
        req.ifd_cmd = BRDGGIFS;
        req.ifd_len = std::mem::size_of::<IfBifConf>();
        req.ifd_data = &mut bifc as *mut _ as *mut libc::c_void;

        const SIOCGDRVSPEC: libc::c_ulong = 0xc0286977;
        let result = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCGDRVSPEC, &mut req) };
        if result < 0 {
            let err = std::io::Error::last_os_error();
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
        let count = bifc.ifbic_len as usize / std::mem::size_of::<IfBReq>();
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
