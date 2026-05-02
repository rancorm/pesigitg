// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! Packet processing pipeline for QUIC-LB load balancing.
//!
//! Given a raw Ethernet frame containing a QUIC/UDP packet (as filtered
//! by the XDP program), extracts the QUIC Connection ID, decrypts the
//! server identifier, looks up the backend server, and rewrites the
//! Ethernet destination MAC for L2 forwarding.
//!
//! For packets with unroutable CIDs (client-generated Initials, config
//! rotation mismatches), falls back to consistent hashing over the 4-tuple
//! with a per-worker connection table for stickiness.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use pesigitg_common::{
    ETH_HDR_LEN, ETH_P_IP, ETH_P_IPV6, ICMP_DEST_UNREACH, ICMP_HDR_LEN, ICMP_TIME_EXCEEDED,
    ICMPV6_DEST_UNREACH, ICMPV6_PACKET_TOO_BIG, ICMPV6_TIME_EXCEEDED, IPPROTO_DSTOPTS,
    IPPROTO_FRAGMENT, IPPROTO_HOPOPTS, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_ROUTING, IPPROTO_UDP,
    IPV4_MIN_HDR_LEN, IPV6_HDR_LEN, MAX_IPV6_EXT_HDRS, UDP_HDR_LEN,
};

use crate::cid;
use crate::config::route::{ConfigTable, Server};
use crate::conntable::{ConnectionTable, DcidKey, FlowKey};

/// Outcome of packet processing.
pub enum Verdict {
    /// CID-routed: DCID decrypted and mapped to a backend server.
    /// Carries the config_id (0-6) for per-config stats tracking.
    CidForward(u8),
    /// CID-routed to a server that is draining. The packet is still
    /// forwarded (existing connections must finish), but counted
    /// separately so the main loop can detect when draining completes.
    CidForwardDraining(u8),
    /// Fallback-routed: connection table hit or consistent hash.
    FallbackForward,
    /// ICMP error routed back to the originating backend server.
    IcmpForward,
    /// CID matched a config and decrypted to a known server slot, but
    /// the server is unhealthy / removed / has no MAC. Drain-completion
    /// signal: drops to zero once stale clients catch up after a
    /// backend removal. Frame is not modified.
    CidUnroutableNoServer,
    /// CID matched a config but decryption produced an unknown
    /// server_id. Forgery / probing signal under a live config — a
    /// sustained nonzero rate without a recent server removal means
    /// someone is feeding the LB junk CIDs. Frame is not modified.
    CidUnroutableBadServerId,
    /// Packet not modified; pass through to the kernel stack.
    Pass,
}

/// Parsed L2/L3/L4 layout shared between the retry classifier and the
/// CID/fallback pipeline. Built once per frame in the worker hot loop;
/// each consumer reads only the fields it needs.
pub(crate) struct ParsedFrame {
    pub family: IpFamily,
    /// Length of the outer IP header (including any IPv6 extension
    /// headers walked to find the L4 protocol). Equals
    /// `<l4-offset> - ETH_HDR_LEN`.
    pub ip_hdr_len: usize,
    pub src_mac: [u8; 6],
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub l4: L4,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum IpFamily {
    Ipv4,
    Ipv6,
}

pub(crate) enum L4 {
    /// Regular UDP/QUIC packet.
    Udp {
        udp_offset: usize,
        quic_offset: usize,
        src_port: u16,
        dst_port: u16,
    },
    /// ICMP error containing an echoed UDP/QUIC packet.
    Icmp {
        inner_quic_offset: usize,
        reversed_flow: FlowKey,
    },
}

/// Process a raw Ethernet frame containing a QUIC/UDP packet.
///
/// 1. **CID path** (fast): decrypt the QUIC CID to extract a server ID,
///    look up the backend, and rewrite the destination MAC.
/// 2. **Fallback path**: if the CID is unroutable (client-generated, wrong
///    config rotation), check the connection table (4-tuple then DCID),
///    then fall back to consistent hashing over the 4-tuple.
///
/// Test-only entry point: production callers parse once at the worker
/// loop and dispatch through [`process_packet_parsed`].
#[cfg(test)]
pub(crate) fn process_packet(
    frame: &mut [u8],
    table: &ConfigTable,
    conn: &mut ConnectionTable,
    local_mac: &[u8; 6],
    now: Instant,
) -> Verdict {
    match parse_frame(frame) {
        Some(parsed) => process_packet_parsed(frame, &parsed, table, conn, local_mac, now),
        None => Verdict::Pass,
    }
}

/// Variant of [`process_packet`] for callers that have already parsed
/// the frame layout (e.g. the worker hot loop, which shares one parse
/// between this pipeline and the Retry classifier).
pub(crate) fn process_packet_parsed(
    frame: &mut [u8],
    parsed: &ParsedFrame,
    table: &ConfigTable,
    conn: &mut ConnectionTable,
    local_mac: &[u8; 6],
    now: Instant,
) -> Verdict {
    match parsed.l4 {
        L4::Udp {
            quic_offset,
            src_port,
            dst_port,
            ..
        } => {
            let flow = FlowKey {
                src_addr: parsed.src_addr,
                dst_addr: parsed.dst_addr,
                src_port,
                dst_port,
            };
            process_udp(frame, table, conn, quic_offset, flow, local_mac, now)
        }
        L4::Icmp {
            inner_quic_offset,
            reversed_flow,
        } => process_icmp(
            frame,
            table,
            conn,
            inner_quic_offset,
            reversed_flow,
            local_mac,
            now,
        ),
    }
}

/// Process a regular UDP/QUIC packet.
fn process_udp(
    frame: &mut [u8],
    table: &ConfigTable,
    conn: &mut ConnectionTable,
    quic_offset: usize,
    flow: FlowKey,
    local_mac: &[u8; 6],
    now: Instant,
) -> Verdict {
    let quic = &frame[quic_offset..];

    // Fast path: CID-based routing via config table lookup.
    if let Some((dcid, config)) = cid::lookup_config(quic, table) {
        let server_idx = cid::resolve_server_idx(dcid, config);
        if let Some(idx) = server_idx {
            let server = &config.servers[idx];
            if server.healthy
                && let Some(mac) = server.mac
            {
                // Record DCID mapping for NAT rebinding resilience.
                conn.record_dcid(DcidKey::from_slice(dcid), mac, now);
                frame[..6].copy_from_slice(&mac);
                frame[6..12].copy_from_slice(local_mac);
                return if server.draining {
                    Verdict::CidForwardDraining(config.config_id)
                } else {
                    Verdict::CidForward(config.config_id)
                };
            }
        }
        // Only treat as a stale/removed server if the CID is the right
        // length for this config. A too-short CID means this is a
        // client-generated Initial whose random first byte happened to
        // match our config_id bits — fall through to fallback routing.
        //
        // Split by reason: a known server slot that's gone is a drain
        // signal (recovers as clients reconnect), while an unknown
        // server_id under a valid config is a forgery / probing signal.
        if dcid.len() > config.cid_payload_length() as usize {
            return if server_idx.is_some() {
                Verdict::CidUnroutableNoServer
            } else {
                Verdict::CidUnroutableBadServerId
            };
        }
    }

    // Fallback path: CID is unroutable (client-generated Initial, config
    // rotation mismatch, or reserved config_id 7).
    let raw_dcid = table
        .fallback_cid_length()
        .and_then(|len| cid::extract_raw_dcid(quic, len));
    let dcid_key = raw_dcid.map(DcidKey::from_slice);

    // Check connection table: 4-tuple index first, then DCID index.
    if let Some(mac) = conn.lookup(&flow, dcid_key.as_ref(), now) {
        frame[..6].copy_from_slice(&mac);
        frame[6..12].copy_from_slice(local_mac);
        return Verdict::FallbackForward;
    }

    // Consistent hash over 4-tuple to select a backend.
    if let Some(mac) = fallback_mac(&flow, &table.fallback_servers) {
        conn.insert(flow, dcid_key, mac, now);
        frame[..6].copy_from_slice(&mac);
        frame[6..12].copy_from_slice(local_mac);
        return Verdict::FallbackForward;
    }

    Verdict::Pass
}

/// Process an ICMP error packet containing an echoed QUIC packet.
///
/// Strategy 1: If the inner QUIC has a long header, extract the Source CID
/// (server-generated) and route via CID decryption — fully stateless.
///
/// Strategy 2: Fall back to reversed 4-tuple connection table lookup.
fn process_icmp(
    frame: &mut [u8],
    table: &ConfigTable,
    conn: &mut ConnectionTable,
    inner_quic_offset: usize,
    reversed_flow: FlowKey,
    local_mac: &[u8; 6],
    now: Instant,
) -> Verdict {
    let inner_quic = &frame[inner_quic_offset..];

    // Strategy 1: Extract SCID from inner long header and route via CID.
    if let Some(scid) = cid::extract_scid(inner_quic)
        && !scid.is_empty()
    {
        let config_id = scid[0] >> 5;
        if config_id != 7
            && let Some(config) = table.get(config_id)
            && let Some(server_idx) = cid::resolve_server_idx(scid, config)
            && let Some(mac) = config.servers[server_idx].mac
        {
            frame[..6].copy_from_slice(&mac);
            frame[6..12].copy_from_slice(local_mac);
            return Verdict::IcmpForward;
        }
    }

    // Strategy 2: Reversed 4-tuple connection table lookup.
    if let Some(mac) = conn.lookup(&reversed_flow, None, now) {
        frame[..6].copy_from_slice(&mac);
        frame[6..12].copy_from_slice(local_mac);
        return Verdict::IcmpForward;
    }

    Verdict::Pass
}

/// Select a backend server via consistent hashing of the 4-tuple.
///
/// `servers` must only contain entries with a resolved MAC (guaranteed
/// by [`ConfigTable::rebuild_fallback_servers`]).
fn fallback_mac(flow: &FlowKey, servers: &[Server]) -> Option<[u8; 6]> {
    if servers.is_empty() {
        return None;
    }

    let mut hasher = DefaultHasher::new();
    flow.hash(&mut hasher);
    let target = (hasher.finish() as usize) % servers.len();

    servers[target].mac
}

/// Parse a raw Ethernet frame to extract the L2/L3/L4 layout.
pub(crate) fn parse_frame(frame: &[u8]) -> Option<ParsedFrame> {
    if frame.len() < ETH_HDR_LEN {
        return None;
    }

    let mut src_mac = [0u8; 6];
    src_mac.copy_from_slice(&frame[6..12]);

    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);

    match ethertype {
        ETH_P_IP => parse_frame_ipv4(frame, src_mac),
        ETH_P_IPV6 => parse_frame_ipv6(frame, src_mac),
        _ => None,
    }
}

fn parse_frame_ipv4(frame: &[u8], src_mac: [u8; 6]) -> Option<ParsedFrame> {
    if frame.len() < ETH_HDR_LEN + IPV4_MIN_HDR_LEN {
        return None;
    }

    let ihl = ((frame[ETH_HDR_LEN] & 0x0F) as usize) * 4;
    if ihl < IPV4_MIN_HDR_LEN {
        return None;
    }

    let protocol = frame[ETH_HDR_LEN + 9];

    let src_addr = IpAddr::V4(Ipv4Addr::new(
        frame[ETH_HDR_LEN + 12],
        frame[ETH_HDR_LEN + 13],
        frame[ETH_HDR_LEN + 14],
        frame[ETH_HDR_LEN + 15],
    ));
    let dst_addr = IpAddr::V4(Ipv4Addr::new(
        frame[ETH_HDR_LEN + 16],
        frame[ETH_HDR_LEN + 17],
        frame[ETH_HDR_LEN + 18],
        frame[ETH_HDR_LEN + 19],
    ));

    match protocol {
        IPPROTO_UDP => {
            let udp_offset = ETH_HDR_LEN + ihl;
            let quic_offset = udp_offset + UDP_HDR_LEN;
            if quic_offset > frame.len() {
                return None;
            }

            let src_port = u16::from_be_bytes([frame[udp_offset], frame[udp_offset + 1]]);
            let dst_port = u16::from_be_bytes([frame[udp_offset + 2], frame[udp_offset + 3]]);

            Some(ParsedFrame {
                family: IpFamily::Ipv4,
                ip_hdr_len: ihl,
                src_mac,
                src_addr,
                dst_addr,
                l4: L4::Udp {
                    udp_offset,
                    quic_offset,
                    src_port,
                    dst_port,
                },
            })
        }
        IPPROTO_ICMP => parse_frame_icmp_ipv4(frame, src_mac, ihl, src_addr, dst_addr),
        _ => None,
    }
}

/// Parse an ICMP error packet with an echoed IPv4/UDP/QUIC inner packet.
fn parse_frame_icmp_ipv4(
    frame: &[u8],
    src_mac: [u8; 6],
    outer_ihl: usize,
    src_addr: IpAddr,
    dst_addr: IpAddr,
) -> Option<ParsedFrame> {
    let icmp_offset = ETH_HDR_LEN + outer_ihl;
    if frame.len() < icmp_offset + ICMP_HDR_LEN {
        return None;
    }

    let icmp_type = frame[icmp_offset];
    if icmp_type != ICMP_DEST_UNREACH && icmp_type != ICMP_TIME_EXCEEDED {
        return None;
    }

    // Inner IPv4 header starts after ICMP header.
    let inner_ip_offset = icmp_offset + ICMP_HDR_LEN;
    if frame.len() < inner_ip_offset + IPV4_MIN_HDR_LEN {
        return None;
    }

    let inner_ihl = ((frame[inner_ip_offset] & 0x0F) as usize) * 4;
    if inner_ihl < IPV4_MIN_HDR_LEN {
        return None;
    }

    if frame[inner_ip_offset + 9] != IPPROTO_UDP {
        return None;
    }

    let inner_udp_offset = inner_ip_offset + inner_ihl;
    let inner_quic_offset = inner_udp_offset + UDP_HDR_LEN;
    if inner_udp_offset + 4 > frame.len() {
        return None;
    }

    // Inner packet is server→client; reverse to get client→server flow
    // for connection table lookup.
    let inner_src = IpAddr::V4(Ipv4Addr::new(
        frame[inner_ip_offset + 12],
        frame[inner_ip_offset + 13],
        frame[inner_ip_offset + 14],
        frame[inner_ip_offset + 15],
    ));
    let inner_dst = IpAddr::V4(Ipv4Addr::new(
        frame[inner_ip_offset + 16],
        frame[inner_ip_offset + 17],
        frame[inner_ip_offset + 18],
        frame[inner_ip_offset + 19],
    ));
    let inner_src_port = u16::from_be_bytes([frame[inner_udp_offset], frame[inner_udp_offset + 1]]);
    let inner_dst_port =
        u16::from_be_bytes([frame[inner_udp_offset + 2], frame[inner_udp_offset + 3]]);

    Some(ParsedFrame {
        family: IpFamily::Ipv4,
        ip_hdr_len: outer_ihl,
        src_mac,
        src_addr,
        dst_addr,
        l4: L4::Icmp {
            inner_quic_offset,
            reversed_flow: FlowKey {
                src_addr: inner_dst,
                dst_addr: inner_src,
                src_port: inner_dst_port,
                dst_port: inner_src_port,
            },
        },
    })
}

fn parse_frame_ipv6(frame: &[u8], src_mac: [u8; 6]) -> Option<ParsedFrame> {
    if frame.len() < ETH_HDR_LEN + IPV6_HDR_LEN {
        return None;
    }

    let mut src_octets = [0u8; 16];
    let mut dst_octets = [0u8; 16];
    src_octets.copy_from_slice(&frame[ETH_HDR_LEN + 8..ETH_HDR_LEN + 24]);
    dst_octets.copy_from_slice(&frame[ETH_HDR_LEN + 24..ETH_HDR_LEN + 40]);

    let src_addr = IpAddr::V6(Ipv6Addr::from(src_octets));
    let dst_addr = IpAddr::V6(Ipv6Addr::from(dst_octets));

    let mut next_hdr = frame[ETH_HDR_LEN + 6];
    let mut offset = ETH_HDR_LEN + IPV6_HDR_LEN;

    for _ in 0..MAX_IPV6_EXT_HDRS {
        match next_hdr {
            IPPROTO_UDP | IPPROTO_ICMPV6 => break,
            IPPROTO_FRAGMENT => {
                if offset >= frame.len() {
                    return None;
                }
                next_hdr = frame[offset];
                offset += 8;
            }
            IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_DSTOPTS => {
                if offset + 1 >= frame.len() {
                    return None;
                }
                next_hdr = frame[offset];
                let ext_len = frame[offset + 1] as usize;
                offset += (ext_len + 1) * 8;
            }
            _ => return None,
        }
    }

    let ip_hdr_len = offset - ETH_HDR_LEN;

    match next_hdr {
        IPPROTO_UDP => {
            let udp_offset = offset;
            let quic_offset = udp_offset + UDP_HDR_LEN;
            if quic_offset > frame.len() {
                return None;
            }

            let src_port = u16::from_be_bytes([frame[udp_offset], frame[udp_offset + 1]]);
            let dst_port = u16::from_be_bytes([frame[udp_offset + 2], frame[udp_offset + 3]]);

            Some(ParsedFrame {
                family: IpFamily::Ipv6,
                ip_hdr_len,
                src_mac,
                src_addr,
                dst_addr,
                l4: L4::Udp {
                    udp_offset,
                    quic_offset,
                    src_port,
                    dst_port,
                },
            })
        }
        IPPROTO_ICMPV6 => {
            parse_frame_icmpv6(frame, src_mac, ip_hdr_len, src_addr, dst_addr, offset)
        }
        _ => None,
    }
}

/// Parse an ICMPv6 error packet with an echoed IPv6/UDP/QUIC inner packet.
fn parse_frame_icmpv6(
    frame: &[u8],
    src_mac: [u8; 6],
    ip_hdr_len: usize,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    icmp_offset: usize,
) -> Option<ParsedFrame> {
    if frame.len() < icmp_offset + ICMP_HDR_LEN {
        return None;
    }

    let icmp_type = frame[icmp_offset];
    if icmp_type != ICMPV6_DEST_UNREACH
        && icmp_type != ICMPV6_PACKET_TOO_BIG
        && icmp_type != ICMPV6_TIME_EXCEEDED
    {
        return None;
    }

    // Inner IPv6 header starts after ICMPv6 header.
    let inner_ip_offset = icmp_offset + ICMP_HDR_LEN;
    if frame.len() < inner_ip_offset + IPV6_HDR_LEN {
        return None;
    }

    let mut inner_src = [0u8; 16];
    let mut inner_dst = [0u8; 16];
    inner_src.copy_from_slice(&frame[inner_ip_offset + 8..inner_ip_offset + 24]);
    inner_dst.copy_from_slice(&frame[inner_ip_offset + 24..inner_ip_offset + 40]);

    let inner_src_addr = IpAddr::V6(Ipv6Addr::from(inner_src));
    let inner_dst_addr = IpAddr::V6(Ipv6Addr::from(inner_dst));

    // Walk inner IPv6 extension headers to find UDP.
    let mut inner_next_hdr = frame[inner_ip_offset + 6];
    let mut inner_offset = inner_ip_offset + IPV6_HDR_LEN;

    for _ in 0..MAX_IPV6_EXT_HDRS {
        match inner_next_hdr {
            IPPROTO_UDP => break,
            IPPROTO_FRAGMENT => {
                if inner_offset >= frame.len() {
                    return None;
                }
                inner_next_hdr = frame[inner_offset];
                inner_offset += 8;
            }
            IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_DSTOPTS => {
                if inner_offset + 1 >= frame.len() {
                    return None;
                }
                inner_next_hdr = frame[inner_offset];
                let ext_len = frame[inner_offset + 1] as usize;
                inner_offset += (ext_len + 1) * 8;
            }
            _ => return None,
        }
    }

    if inner_next_hdr != IPPROTO_UDP {
        return None;
    }

    if inner_offset + 4 > frame.len() {
        return None;
    }

    let inner_src_port = u16::from_be_bytes([frame[inner_offset], frame[inner_offset + 1]]);
    let inner_dst_port = u16::from_be_bytes([frame[inner_offset + 2], frame[inner_offset + 3]]);
    let inner_quic_offset = inner_offset + UDP_HDR_LEN;

    Some(ParsedFrame {
        family: IpFamily::Ipv6,
        ip_hdr_len,
        src_mac,
        src_addr,
        dst_addr,
        l4: L4::Icmp {
            inner_quic_offset,
            reversed_flow: FlowKey {
                src_addr: inner_dst_addr,
                dst_addr: inner_src_addr,
                src_port: inner_dst_port,
                dst_port: inner_src_port,
            },
        },
    })
}

#[cfg(test)]
#[path = "packet_tests.rs"]
mod tests;

// Fuzz-only entry point. Lets the libFuzzer harness in `fuzz/` exercise
// the frame parser without making `parse_frame` or `ParsedFrame` part
// of the crate's public API surface.
#[cfg(fuzzing)]
pub(crate) fn fuzz_parse_frame(frame: &[u8]) -> bool {
    parse_frame(frame).is_some()
}
