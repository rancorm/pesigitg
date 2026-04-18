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
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
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
                info!(
                    "resolved {} -> {}",
                    server.address,
                    pesigitg_common::mac::format(&mac)
                );
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
    let bytes = build_dump_request_bytes();

    let ret = unsafe {
        libc::send(
            sock.0,
            bytes.as_ptr() as *const libc::c_void,
            bytes.len(),
            0,
        )
    };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn build_dump_request_bytes() -> Vec<u8> {
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

    let ptr = &req as *const Request as *const u8;
    unsafe { std::slice::from_raw_parts(ptr, std::mem::size_of::<Request>()) }.to_vec()
}

enum ChunkOutcome {
    Continue,
    Done,
    Error(io::Error),
}

fn process_chunk(buf: &[u8], table: &mut HashMap<IpAddr, [u8; 6]>) -> ChunkOutcome {
    let mut offset = 0usize;

    while offset + std::mem::size_of::<libc::nlmsghdr>() <= buf.len() {
        let hdr = unsafe { &*(buf.as_ptr().add(offset) as *const libc::nlmsghdr) };
        let msg_len = hdr.nlmsg_len as usize;

        if msg_len < std::mem::size_of::<libc::nlmsghdr>() || offset + msg_len > buf.len() {
            break;
        }

        match hdr.nlmsg_type {
            NLMSG_DONE => return ChunkOutcome::Done,
            NLMSG_ERROR => return ChunkOutcome::Error(io::Error::from_raw_os_error(libc::EPROTO)),
            RTM_NEWNEIGH => parse_neigh_msg(&buf[offset..offset + msg_len], table),
            _ => {}
        }

        offset += nlmsg_align(msg_len);
    }

    ChunkOutcome::Continue
}

fn recv_neigh_entries(sock: &NetlinkSocket) -> io::Result<HashMap<IpAddr, [u8; 6]>> {
    let mut table = HashMap::new();
    let mut buf = vec![0u8; 65536];

    loop {
        let n = unsafe { libc::recv(sock.0, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };

        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        match process_chunk(&buf[..n as usize], &mut table) {
            ChunkOutcome::Continue => continue,
            ChunkOutcome::Done => return Ok(table),
            ChunkOutcome::Error(e) => return Err(e),
        }
    }
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
                dst_ip = Some(IpAddr::V4(Ipv4Addr::new(
                    data[0], data[1], data[2], data[3],
                )));
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

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    // ---------- Fixture builders ----------

    /// Build an RTM_NEWNEIGH message carrying NDA_DST + NDA_LLADDR. `ip_bytes`
    /// must be 4 bytes for AF_INET or 16 bytes for AF_INET6.
    fn build_neigh_msg(family: u8, state: u16, ip_bytes: &[u8], mac: &[u8; 6]) -> Vec<u8> {
        let mut buf = Vec::new();

        // nlmsghdr placeholder (len filled in at end).
        buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_len
        buf.extend_from_slice(&RTM_NEWNEIGH.to_ne_bytes()); // nlmsg_type
        buf.extend_from_slice(&0u16.to_ne_bytes()); // nlmsg_flags
        buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_seq
        buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid

        // ndmsg (already 4-byte aligned).
        buf.push(family); // ndm_family
        buf.push(0); // ndm_pad1
        buf.extend_from_slice(&0u16.to_ne_bytes()); // ndm_pad2
        buf.extend_from_slice(&1i32.to_ne_bytes()); // ndm_ifindex
        buf.extend_from_slice(&state.to_ne_bytes()); // ndm_state
        buf.push(0); // ndm_flags
        buf.push(0); // ndm_type

        // NDA_DST attribute.
        let dst_hdr_len = 4 + ip_bytes.len();
        buf.extend_from_slice(&(dst_hdr_len as u16).to_ne_bytes());
        buf.extend_from_slice(&NDA_DST.to_ne_bytes());
        buf.extend_from_slice(ip_bytes);
        while buf.len() % 4 != 0 {
            buf.push(0);
        }

        // NDA_LLADDR attribute.
        buf.extend_from_slice(&10u16.to_ne_bytes());
        buf.extend_from_slice(&NDA_LLADDR.to_ne_bytes());
        buf.extend_from_slice(mac);
        while buf.len() % 4 != 0 {
            buf.push(0);
        }

        let total = buf.len() as u32;
        buf[0..4].copy_from_slice(&total.to_ne_bytes());
        buf
    }

    fn build_nlmsg_done() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&16u32.to_ne_bytes()); // nlmsg_len
        buf.extend_from_slice(&NLMSG_DONE.to_ne_bytes()); // nlmsg_type
        buf.extend_from_slice(&0u16.to_ne_bytes()); // nlmsg_flags
        buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_seq
        buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid
        buf
    }

    fn build_nlmsg_error() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&16u32.to_ne_bytes());
        buf.extend_from_slice(&NLMSG_ERROR.to_ne_bytes());
        buf.extend_from_slice(&0u16.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf
    }

    // ---------- nlmsg_align ----------

    #[test]
    fn nlmsg_align_rounds_up_to_4() {
        assert_eq!(nlmsg_align(0), 0);
        assert_eq!(nlmsg_align(1), 4);
        assert_eq!(nlmsg_align(3), 4);
        assert_eq!(nlmsg_align(4), 4);
        assert_eq!(nlmsg_align(5), 8);
        assert_eq!(nlmsg_align(10), 12);
    }

    // ---------- Request construction ----------

    #[test]
    fn dump_request_bytes_match_nlmsghdr_plus_ndmsg_layout() {
        let bytes = build_dump_request_bytes();
        let nlmsg_sz = std::mem::size_of::<libc::nlmsghdr>();
        let ndmsg_sz = std::mem::size_of::<ndmsg>();
        assert_eq!(bytes.len(), nlmsg_sz + ndmsg_sz);

        let len = u32::from_ne_bytes(bytes[0..4].try_into().unwrap());
        let typ = u16::from_ne_bytes(bytes[4..6].try_into().unwrap());
        let flags = u16::from_ne_bytes(bytes[6..8].try_into().unwrap());
        let seq = u32::from_ne_bytes(bytes[8..12].try_into().unwrap());
        let pid = u32::from_ne_bytes(bytes[12..16].try_into().unwrap());

        assert_eq!(len, bytes.len() as u32);
        assert_eq!(typ, RTM_GETNEIGH);
        assert_eq!(flags, NLM_F_REQUEST | NLM_F_DUMP);
        assert_eq!(seq, 1);
        assert_eq!(pid, 0, "kernel assigns pid; we send 0");
        assert_eq!(
            bytes[nlmsg_sz], AF_UNSPEC,
            "ndm_family must request both v4+v6"
        );
    }

    // ---------- parse_neigh_msg ----------

    #[test]
    fn parse_neigh_msg_inserts_ipv4_reachable() {
        let mut table = HashMap::new();
        let msg = build_neigh_msg(AF_INET, NUD_REACHABLE, &[10, 0, 0, 1], &MAC);
        parse_neigh_msg(&msg, &mut table);
        assert_eq!(
            table.get(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            Some(&MAC)
        );
    }

    #[test]
    fn parse_neigh_msg_inserts_ipv6_permanent() {
        let mut table = HashMap::new();
        let ip: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let msg = build_neigh_msg(AF_INET6, NUD_PERMANENT, &ip, &MAC);
        parse_neigh_msg(&msg, &mut table);
        assert_eq!(table.get(&IpAddr::V6(Ipv6Addr::from(ip))), Some(&MAC));
    }

    #[test]
    fn parse_neigh_msg_skips_unresolved_state() {
        // NUD_FAILED (0x20) is not in NUD_VALID — no MAC is usable.
        let mut table = HashMap::new();
        let msg = build_neigh_msg(AF_INET, 0x20, &[10, 0, 0, 1], &MAC);
        parse_neigh_msg(&msg, &mut table);
        assert!(table.is_empty());
    }

    #[test]
    fn parse_neigh_msg_skips_unknown_family() {
        // AF_BRIDGE (7) is neither AF_INET nor AF_INET6.
        let mut table = HashMap::new();
        let msg = build_neigh_msg(7, NUD_REACHABLE, &[10, 0, 0, 1], &MAC);
        parse_neigh_msg(&msg, &mut table);
        assert!(table.is_empty());
    }

    #[test]
    fn parse_neigh_msg_skips_when_lladdr_missing() {
        // Build an RTM_NEWNEIGH message with NDA_DST only.
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(&RTM_NEWNEIGH.to_ne_bytes());
        buf.extend_from_slice(&0u16.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.push(AF_INET);
        buf.push(0);
        buf.extend_from_slice(&0u16.to_ne_bytes());
        buf.extend_from_slice(&1i32.to_ne_bytes());
        buf.extend_from_slice(&NUD_REACHABLE.to_ne_bytes());
        buf.push(0);
        buf.push(0);
        buf.extend_from_slice(&8u16.to_ne_bytes());
        buf.extend_from_slice(&NDA_DST.to_ne_bytes());
        buf.extend_from_slice(&[10, 0, 0, 1]);
        let len = buf.len() as u32;
        buf[0..4].copy_from_slice(&len.to_ne_bytes());

        let mut table = HashMap::new();
        parse_neigh_msg(&buf, &mut table);
        assert!(table.is_empty());
    }

    #[test]
    fn parse_neigh_msg_masks_nla_flag_bits() {
        // Netlink sets the top 2 bits of nla_type for NLA_F_NESTED /
        // NLA_F_NET_BYTEORDER. The parser must mask these off via `& 0x3fff`
        // so real attribute types still match.
        let mut msg = build_neigh_msg(AF_INET, NUD_REACHABLE, &[10, 0, 0, 1], &MAC);
        let nlmsg_sz = std::mem::size_of::<libc::nlmsghdr>();
        let ndmsg_sz = std::mem::size_of::<ndmsg>();
        let first_attr_type_off = nlmsg_sz + ndmsg_sz + 2;
        // Set NLA_F_NESTED (0x8000) on the NDA_DST attribute's nla_type.
        let mut raw = u16::from_ne_bytes(
            msg[first_attr_type_off..first_attr_type_off + 2]
                .try_into()
                .unwrap(),
        );
        raw |= 0x8000;
        msg[first_attr_type_off..first_attr_type_off + 2].copy_from_slice(&raw.to_ne_bytes());

        let mut table = HashMap::new();
        parse_neigh_msg(&msg, &mut table);
        assert_eq!(
            table.get(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            Some(&MAC)
        );
    }

    #[test]
    fn parse_neigh_msg_ignores_truncated_buffer() {
        // Truncate mid-ndmsg. Parser must not panic and must not insert.
        let mut msg = build_neigh_msg(AF_INET, NUD_REACHABLE, &[10, 0, 0, 1], &MAC);
        msg.truncate(std::mem::size_of::<libc::nlmsghdr>() + 4);
        let mut table = HashMap::new();
        parse_neigh_msg(&msg, &mut table);
        assert!(table.is_empty());
    }

    // ---------- process_chunk ----------

    #[test]
    fn process_chunk_returns_done_on_nlmsg_done() {
        let buf = build_nlmsg_done();
        let mut table = HashMap::new();
        assert!(matches!(
            process_chunk(&buf, &mut table),
            ChunkOutcome::Done
        ));
        assert!(table.is_empty());
    }

    #[test]
    fn process_chunk_returns_error_on_nlmsg_error() {
        let buf = build_nlmsg_error();
        let mut table = HashMap::new();
        let outcome = process_chunk(&buf, &mut table);
        match outcome {
            ChunkOutcome::Error(e) => assert_eq!(e.raw_os_error(), Some(libc::EPROTO)),
            _ => panic!("expected Error outcome"),
        }
    }

    #[test]
    fn process_chunk_walks_multiple_messages_then_done() {
        // Two RTM_NEWNEIGH entries followed by NLMSG_DONE in one recv() chunk.
        let mut buf = Vec::new();
        buf.extend(build_neigh_msg(
            AF_INET,
            NUD_REACHABLE,
            &[10, 0, 0, 1],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
        ));
        buf.extend(build_neigh_msg(
            AF_INET,
            NUD_STALE,
            &[10, 0, 0, 2],
            &[0x11, 0x12, 0x13, 0x14, 0x15, 0x16],
        ));
        buf.extend(build_nlmsg_done());

        let mut table = HashMap::new();
        assert!(matches!(
            process_chunk(&buf, &mut table),
            ChunkOutcome::Done
        ));
        assert_eq!(table.len(), 2);
        assert_eq!(
            table.get(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            Some(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
        );
        assert_eq!(
            table.get(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            Some(&[0x11, 0x12, 0x13, 0x14, 0x15, 0x16])
        );
    }
}
