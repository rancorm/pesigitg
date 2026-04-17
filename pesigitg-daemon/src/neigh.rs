// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! Neighbour table (ARP/NDP) lookup via netlink RTM_GETNEIGH.
//!
//! Resolves MAC addresses for backend servers that do not have a static MAC
//! configured in route config. Queries the kernel neighbour cache directly using
//! a blocking netlink socket.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use log::{debug, info, warn};

use crate::config::route::Server;

// linux/netlink.h
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

// linux/rtnetlink.h
const RTM_NEWNEIGH: u16 = 28;
const RTM_GETNEIGH: u16 = 30;
const NLM_F_REQUEST: u16 = 0x001;
const NLM_F_DUMP: u16 = 0x300;

// linux/socket.h
const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

// linux/neighbour.h — ndm_state flags
const NUD_REACHABLE: u16 = 0x02;
const NUD_STALE: u16 = 0x04;
const NUD_DELAY: u16 = 0x08;
const NUD_PROBE: u16 = 0x10;
const NUD_PERMANENT: u16 = 0x80;

/// States that indicate the neighbour has a usable, resolved MAC.
const NUD_VALID: u16 = NUD_REACHABLE | NUD_STALE | NUD_DELAY | NUD_PROBE | NUD_PERMANENT;

// linux/neighbour.h — nda_type attribute types
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;

/// RAII wrapper for a raw netlink socket fd.
struct NetlinkSocket(libc::c_int);

#[repr(C)]
pub struct ndmsg {
    pub ndm_family: u8,
    pub ndm_pad1: u8,
    pub ndm_pad2: u16,
    pub ndm_ifindex: i32,
    pub ndm_state: u16,
    pub ndm_flags: u8,
    pub ndm_type: u8,
}

impl NetlinkSocket {
    fn open() -> io::Result<Self> {
        let fd = unsafe {
            libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE)
        };

        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;

        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        
        if ret < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }

        Ok(Self(fd))
    }
}

impl Drop for NetlinkSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

/// Fill in `mac` for any [`Server`] entries where it is `None`, by looking up
/// the kernel neighbour table (ARP for IPv4, NDP for IPv6).
///
/// Servers with a statically configured MAC are left unchanged.
/// A warning is logged for any server whose MAC cannot be resolved.
pub fn resolve_macs(servers: &mut [Server]) {
    let to_resolve = servers.iter().filter(|s| s.mac.is_none()).count();

    if to_resolve == 0 {
        return;
    }

    debug!("resolve_macs: {} server(s) need MAC resolution", to_resolve);

    let table = match query_neighbour_table() {
        Ok(t) => t,
        Err(e) => {
            warn!("failed to query neighbour table: {}", e);
            return;
        }
    };

    debug!("resolve_macs: neighbour table has {} entries", table.len());

    for server in servers.iter_mut() {
        if server.mac.is_some() {
            continue;
        }

        match table.get(&server.address) {
            Some(&mac) => {
                info!("resolved {} -> {}", server.address, crate::utils::format_mac(&mac));
                server.mac = Some(mac);
            }
            None => {
                warn!(
                    "no neighbour entry for {} — packets to this server cannot be forwarded",
                    server.address
                );
            }
        }
    }

    let remaining = servers.iter().filter(|s| s.mac.is_none()).count();
    debug!(
        "resolve_macs: {} resolved, {} still unresolved",
        to_resolve - remaining,
        remaining
    );
}

/// Send `RTM_GETNEIGH | NLM_F_DUMP` and collect all valid entries into a map.
fn query_neighbour_table() -> io::Result<HashMap<IpAddr, [u8; 6]>> {
    let sock = NetlinkSocket::open()?;
    
    send_dump_request(&sock)?;
    recv_neigh_entries(&sock)
}

fn send_dump_request(sock: &NetlinkSocket) -> io::Result<()> {
    #[repr(C)]
    struct Request {
        hdr: libc::nlmsghdr,
        ndm: ndmsg,
    }

    let mut req: Request = unsafe { std::mem::zeroed() };
    
    req.hdr.nlmsg_len = std::mem::size_of::<Request>() as u32;
    req.hdr.nlmsg_type = RTM_GETNEIGH;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_seq = 1;
    req.ndm.ndm_family = AF_UNSPEC;

    let ret = unsafe {
        libc::send(
            sock.0,
            &req as *const _ as *const libc::c_void,
            std::mem::size_of::<Request>(),
            0,
        )
    };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn recv_neigh_entries(sock: &NetlinkSocket) -> io::Result<HashMap<IpAddr, [u8; 6]>> {
    let mut table = HashMap::new();
    let mut buf = vec![0u8; 65536];

    'recv: loop {
        let n = unsafe {
            libc::recv(sock.0, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
        };

        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut offset = 0usize;
        let n = n as usize;

        while offset + std::mem::size_of::<libc::nlmsghdr>() <= n {
            let hdr = unsafe { &*(buf.as_ptr().add(offset) as *const libc::nlmsghdr) };
            let msg_len = hdr.nlmsg_len as usize;

            if msg_len < std::mem::size_of::<libc::nlmsghdr>() || offset + msg_len > n {
                break;
            }

            match hdr.nlmsg_type {
                NLMSG_DONE   => break 'recv,
                NLMSG_ERROR  => return Err(io::Error::from_raw_os_error(libc::EPROTO)),
                RTM_NEWNEIGH => parse_neigh_msg(&buf[offset..offset + msg_len], &mut table),
                _ => {}
            }

            offset += nlmsg_align(msg_len);
        }
    }

    Ok(table)
}

fn parse_neigh_msg(buf: &[u8], table: &mut HashMap<IpAddr, [u8; 6]>) {
    let hdr_len = nlmsg_align(std::mem::size_of::<libc::nlmsghdr>());
    let ndm_len = std::mem::size_of::<ndmsg>();

    if buf.len() < hdr_len + ndm_len {
        return;
    }

    let ndm = unsafe { &*(buf.as_ptr().add(hdr_len) as *const ndmsg) };

    if ndm.ndm_state & NUD_VALID == 0 {
        return;
    }

    let family = ndm.ndm_family;

    if family != AF_INET && family != AF_INET6 {
        return;
    }

    let mut attr_offset = hdr_len + nlmsg_align(ndm_len);
    let mut dst_ip: Option<IpAddr> = None;
    let mut lladdr: Option<[u8; 6]> = None;

    while attr_offset + std::mem::size_of::<libc::nlattr>() <= buf.len() {
        let nla = unsafe { &*(buf.as_ptr().add(attr_offset) as *const libc::nlattr) };
        let nla_len = nla.nla_len as usize;

        if nla_len < std::mem::size_of::<libc::nlattr>() || attr_offset + nla_len > buf.len() {
            break;
        }

        let data_start = attr_offset + std::mem::size_of::<libc::nlattr>();
        let data = &buf[data_start..attr_offset + nla_len];

        // Upper 2 bits of nla_type are NLA_F_* flags; mask them off.
        match nla.nla_type & 0x3fff {
            NDA_DST if family == AF_INET && data.len() == 4 => {
                dst_ip = Some(IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])));
            }

            NDA_DST if family == AF_INET6 && data.len() == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(data);
                dst_ip = Some(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            
            NDA_LLADDR if data.len() == 6 => {
                let mut mac = [0u8; 6];
                mac.copy_from_slice(data);
                lladdr = Some(mac);
            }
            _ => {}
        }

        attr_offset += nlmsg_align(nla_len);
    }

    if let (Some(ip), Some(mac)) = (dst_ip, lladdr) {
        table.insert(ip, mac);
    }
}

/// Align `len` to a 4-byte boundary, matching the NLMSG_ALIGN / NLA_ALIGN macros.
#[inline]
fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}
