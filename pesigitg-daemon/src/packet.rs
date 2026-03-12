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

use pesigitg_common::{
    ETH_HDR_LEN, ETH_P_IP, ETH_P_IPV6, IPPROTO_DSTOPTS, IPPROTO_FRAGMENT, IPPROTO_HOPOPTS,
    IPPROTO_ROUTING, IPPROTO_UDP, IPV4_MIN_HDR_LEN, IPV6_HDR_LEN, MAX_IPV6_EXT_HDRS, UDP_HDR_LEN,
};

use crate::cid;
use crate::config::route::{RouteConfig, Server};
use crate::conntable::{ConnectionTable, DcidKey, FlowKey};

/// Outcome of packet processing.
pub enum Verdict {
    /// Destination MAC rewritten; the packet should be forwarded.
    Forward,
    /// Packet not modified; pass through to the kernel stack.
    Pass,
}

/// Parsed frame metadata: QUIC payload offset and 4-tuple flow key.
struct FrameMeta {
    quic_offset: usize,
    flow: FlowKey,
}

/// Process a raw Ethernet frame containing a QUIC/UDP packet.
///
/// 1. **CID path** (fast): decrypt the QUIC CID to extract a server ID,
///    look up the backend, and rewrite the destination MAC.
/// 2. **Fallback path**: if the CID is unroutable (client-generated, wrong
///    config rotation), check the connection table (4-tuple then DCID),
///    then fall back to consistent hashing over the 4-tuple.
pub fn process_packet(
    frame: &mut [u8],
    config: &RouteConfig,
    conn: &mut ConnectionTable,
) -> Verdict {
    let meta = match parse_frame(frame) {
        Some(m) => m,
        None => return Verdict::Pass,
    };

    let quic = &frame[meta.quic_offset..];

    // Fast path: CID-based routing.
    if let Some(dcid) = cid::extract_dcid(quic, config) {
        if let Some(server_idx) = cid::resolve_server_idx(dcid, config) {
            let server = &config.servers[server_idx];
            if let Some(mac) = server.mac {
                // Record DCID mapping for NAT rebinding resilience.
                conn.record_dcid(DcidKey::from_slice(dcid), server_idx);
                frame[..6].copy_from_slice(&mac);
                return Verdict::Forward;
            }
        }
        // CID was routable but server unknown or has no MAC — don't fallback
        // to a random server; this is a stale/removed server, not a new client.
        return Verdict::Pass;
    }

    // Fallback path: CID is unroutable (client-generated Initial, config
    // rotation mismatch, or reserved config_id 7).
    let raw_dcid = cid::extract_raw_dcid(quic, config.cid_length());
    let dcid_key = raw_dcid.map(DcidKey::from_slice);

    // Check connection table: 4-tuple index first, then DCID index.
    if let Some(server_idx) = conn.lookup(&meta.flow, dcid_key.as_ref()) {
        if let Some(server) = config.servers.get(server_idx) {
            if let Some(mac) = server.mac {
                frame[..6].copy_from_slice(&mac);
                return Verdict::Forward;
            }
        }
    }

    // Consistent hash over 4-tuple to select a backend.
    if let Some(server_idx) = fallback_server_idx(&meta.flow, &config.servers) {
        // Safe: fallback_server_idx only returns servers with mac.is_some().
        let mac = config.servers[server_idx].mac.unwrap();
        conn.insert(meta.flow, dcid_key, server_idx);
        frame[..6].copy_from_slice(&mac);
        return Verdict::Forward;
    }

    Verdict::Pass
}

/// Select a backend server via consistent hashing of the 4-tuple.
///
/// Only considers servers that have a resolved MAC address. Returns the
/// index into `servers`, or `None` if no server is routable.
fn fallback_server_idx(flow: &FlowKey, servers: &[Server]) -> Option<usize> {
    let routable_count = servers.iter().filter(|s| s.mac.is_some()).count();
    if routable_count == 0 {
        return None;
    }

    let mut hasher = DefaultHasher::new();
    flow.hash(&mut hasher);
    let target = (hasher.finish() as usize) % routable_count;

    servers
        .iter()
        .enumerate()
        .filter(|(_, s)| s.mac.is_some())
        .nth(target)
        .map(|(i, _)| i)
}

/// Parse a raw Ethernet frame to extract the QUIC payload offset and 4-tuple.
fn parse_frame(frame: &[u8]) -> Option<FrameMeta> {
    if frame.len() < ETH_HDR_LEN {
        return None;
    }

    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);

    match ethertype {
        ETH_P_IP => parse_frame_ipv4(frame),
        ETH_P_IPV6 => parse_frame_ipv6(frame),
        _ => None,
    }
}

fn parse_frame_ipv4(frame: &[u8]) -> Option<FrameMeta> {
    if frame.len() < ETH_HDR_LEN + IPV4_MIN_HDR_LEN {
        return None;
    }

    let ihl = ((frame[ETH_HDR_LEN] & 0x0F) as usize) * 4;
    if ihl < IPV4_MIN_HDR_LEN {
        return None;
    }

    if frame[ETH_HDR_LEN + 9] != IPPROTO_UDP {
        return None;
    }

    let udp_offset = ETH_HDR_LEN + ihl;
    let quic_offset = udp_offset + UDP_HDR_LEN;
    if quic_offset > frame.len() {
        return None;
    }

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
    let src_port = u16::from_be_bytes([frame[udp_offset], frame[udp_offset + 1]]);
    let dst_port = u16::from_be_bytes([frame[udp_offset + 2], frame[udp_offset + 3]]);

    Some(FrameMeta {
        quic_offset,
        flow: FlowKey {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
        },
    })
}

fn parse_frame_ipv6(frame: &[u8]) -> Option<FrameMeta> {
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
            IPPROTO_UDP => break,
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

    if next_hdr != IPPROTO_UDP {
        return None;
    }

    let udp_offset = offset;
    let quic_offset = udp_offset + UDP_HDR_LEN;
    if quic_offset > frame.len() {
        return None;
    }

    let src_port = u16::from_be_bytes([frame[udp_offset], frame[udp_offset + 1]]);
    let dst_port = u16::from_be_bytes([frame[udp_offset + 2], frame[udp_offset + 3]]);

    Some(FrameMeta {
        quic_offset,
        flow: FlowKey {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::route::Encryption;
    use std::path::PathBuf;

    fn make_config() -> RouteConfig {
        RouteConfig {
            path: PathBuf::new(),
            config_id: 0,
            first_octet_encodes_cid_length: true,
            server_id_length: 3,
            nonce_length: 13,
            encryption: Encryption::Plaintext,
            servers: vec![Server {
                id: vec![0x00, 0x00, 0x01],
                address: "10.0.1.10".parse().unwrap(),
                mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]),
            }],
        }
    }

    fn make_config_two_servers() -> RouteConfig {
        RouteConfig {
            path: PathBuf::new(),
            config_id: 0,
            first_octet_encodes_cid_length: true,
            server_id_length: 3,
            nonce_length: 13,
            encryption: Encryption::Plaintext,
            servers: vec![
                Server {
                    id: vec![0x00, 0x00, 0x01],
                    address: "10.0.1.10".parse().unwrap(),
                    mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]),
                },
                Server {
                    id: vec![0x00, 0x00, 0x02],
                    address: "10.0.1.11".parse().unwrap(),
                    mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02]),
                },
            ],
        }
    }

    /// Build a minimal IPv4/UDP Ethernet frame with the given QUIC payload.
    fn build_ipv4_frame(quic: &[u8]) -> Vec<u8> {
        build_ipv4_frame_ex(quic, [10, 0, 0, 1], 443)
    }

    fn build_ipv4_frame_ex(quic: &[u8], src_ip: [u8; 4], src_port: u16) -> Vec<u8> {
        let mut f = Vec::new();

        // Ethernet: dst(6) + src(6) + ethertype(2)
        f.extend_from_slice(&[0xff; 6]);
        f.extend_from_slice(&[0x00; 6]);
        f.extend_from_slice(&ETH_P_IP.to_be_bytes());

        // IPv4 header (20 bytes, IHL=5, protocol=UDP)
        f.push(0x45); // version + IHL
        f.push(0x00);
        let total = (20 + 8 + quic.len()) as u16;
        f.extend_from_slice(&total.to_be_bytes());
        f.extend_from_slice(&[0x00; 4]); // ident, flags, frag
        f.push(0x40); // TTL
        f.push(IPPROTO_UDP);
        f.extend_from_slice(&[0x00; 2]); // checksum
        f.extend_from_slice(&src_ip);
        f.extend_from_slice(&[10, 0, 1, 10]); // dst

        // UDP header (8 bytes)
        f.extend_from_slice(&src_port.to_be_bytes());
        f.extend_from_slice(&443u16.to_be_bytes());
        let udp_len = (8 + quic.len()) as u16;
        f.extend_from_slice(&udp_len.to_be_bytes());
        f.extend_from_slice(&[0x00; 2]); // checksum

        f.extend_from_slice(quic);
        f
    }

    /// Build a minimal IPv6/UDP Ethernet frame with the given QUIC payload.
    fn build_ipv6_frame(quic: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();

        // Ethernet
        f.extend_from_slice(&[0xff; 6]);
        f.extend_from_slice(&[0x00; 6]);
        f.extend_from_slice(&ETH_P_IPV6.to_be_bytes());

        // IPv6 header (40 bytes)
        f.push(0x60); // version
        f.extend_from_slice(&[0x00; 3]); // traffic class + flow label
        let payload_len = (8 + quic.len()) as u16;
        f.extend_from_slice(&payload_len.to_be_bytes());
        f.push(IPPROTO_UDP); // next header
        f.push(0x40); // hop limit
        f.extend_from_slice(&[0x00; 16]); // src addr
        f.extend_from_slice(&[0x00; 16]); // dst addr

        // UDP header
        f.extend_from_slice(&443u16.to_be_bytes());
        f.extend_from_slice(&443u16.to_be_bytes());
        let udp_len = (8 + quic.len()) as u16;
        f.extend_from_slice(&udp_len.to_be_bytes());
        f.extend_from_slice(&[0x00; 2]);

        f.extend_from_slice(quic);
        f
    }

    fn build_quic_long_header(config_id: u8, server_id: &[u8], nonce: &[u8]) -> Vec<u8> {
        let cid_len = 1 + server_id.len() + nonce.len();
        let mut q = Vec::new();
        q.push(0xc0); // Long Header Initial
        q.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // version
        q.push(cid_len as u8); // DCID length
        q.push(config_id << 5); // first CID octet
        q.extend_from_slice(server_id);
        q.extend_from_slice(nonce);
        q.push(0x00); // SCID length
        q
    }

    // -- CID path tests (existing behavior preserved) --

    #[test]
    fn process_ipv4_long_header_rewrites_mac() {
        let config = make_config();
        let quic = build_quic_long_header(0, &[0x00, 0x00, 0x01], &[0xaa; 13]);
        let mut frame = build_ipv4_frame(&quic);
        let mut conn = ConnectionTable::new();

        assert!(matches!(
            process_packet(&mut frame, &config, &mut conn),
            Verdict::Forward
        ));
        assert_eq!(&frame[..6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
    }

    #[test]
    fn process_ipv6_long_header_rewrites_mac() {
        let config = make_config();
        let quic = build_quic_long_header(0, &[0x00, 0x00, 0x01], &[0xbb; 13]);
        let mut frame = build_ipv6_frame(&quic);
        let mut conn = ConnectionTable::new();

        assert!(matches!(
            process_packet(&mut frame, &config, &mut conn),
            Verdict::Forward
        ));
        assert_eq!(&frame[..6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
    }

    #[test]
    fn process_unknown_server_passes() {
        let config = make_config();
        let quic = build_quic_long_header(0, &[0xff, 0xff, 0xff], &[0x00; 13]);
        let mut frame = build_ipv4_frame(&quic);
        let mut conn = ConnectionTable::new();

        // CID is routable (config_id matches) but server_id is unknown
        // after decryption — this is a stale/removed server, not a new
        // client, so we do NOT fall back to consistent hash.
        assert!(matches!(
            process_packet(&mut frame, &config, &mut conn),
            Verdict::Pass
        ));
        assert_eq!(&frame[..6], &[0xff; 6]);
    }

    #[test]
    fn process_non_ip_passes() {
        let config = make_config();
        let mut conn = ConnectionTable::new();
        // ARP ethertype
        let mut frame = vec![0xff; 6];
        frame.extend_from_slice(&[0x00; 6]);
        frame.extend_from_slice(&[0x08, 0x06]); // ARP
        frame.extend_from_slice(&[0x00; 28]);

        assert!(matches!(
            process_packet(&mut frame, &config, &mut conn),
            Verdict::Pass
        ));
    }

    #[test]
    fn process_short_header_rewrites_mac() {
        let config = make_config();
        let mut conn = ConnectionTable::new();

        // Short Header: [0x40][CID: 17 bytes]
        let mut quic = vec![0x40];
        quic.push(0x00); // first CID octet (config_id=0)
        quic.extend_from_slice(&[0x00, 0x00, 0x01]); // server_id
        quic.extend_from_slice(&[0xcc; 13]); // nonce
        // Pad some extra bytes (packet number, payload)
        quic.extend_from_slice(&[0x00; 20]);

        let mut frame = build_ipv4_frame(&quic);

        assert!(matches!(
            process_packet(&mut frame, &config, &mut conn),
            Verdict::Forward
        ));
        assert_eq!(&frame[..6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
    }

    // -- Fallback path tests --

    #[test]
    fn fallback_routes_unroutable_cid() {
        // Wrong config_id → CID unroutable → fallback consistent hash.
        let config = make_config();
        let quic = build_quic_long_header(3, &[0x00, 0x00, 0x01], &[0x00; 13]);
        let mut frame = build_ipv4_frame(&quic);
        let mut conn = ConnectionTable::new();

        assert!(matches!(
            process_packet(&mut frame, &config, &mut conn),
            Verdict::Forward
        ));
        // Only one server with a MAC, so it must be selected.
        assert_eq!(&frame[..6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
    }

    #[test]
    fn fallback_connection_table_stickiness() {
        // First packet goes through consistent hash; second packet should
        // hit the connection table and pick the same server.
        let config = make_config_two_servers();
        let quic = build_quic_long_header(3, &[0x00, 0x00, 0x01], &[0x00; 13]);
        let mut conn = ConnectionTable::new();

        let mut frame1 = build_ipv4_frame(&quic);
        assert!(matches!(
            process_packet(&mut frame1, &config, &mut conn),
            Verdict::Forward
        ));
        let mac1 = frame1[..6].to_vec();

        // Second packet, same 4-tuple — should get same server from table.
        let mut frame2 = build_ipv4_frame(&quic);
        assert!(matches!(
            process_packet(&mut frame2, &config, &mut conn),
            Verdict::Forward
        ));
        assert_eq!(&frame2[..6], &mac1[..]);
    }

    #[test]
    fn fallback_dcid_nat_rebinding() {
        // Client retransmits Initial from a different source IP (NAT rebinding).
        // Different 4-tuple but same DCID → should reach the same server.
        let config = make_config_two_servers();
        let quic = build_quic_long_header(3, &[0x00, 0x00, 0x01], &[0x00; 13]);
        let mut conn = ConnectionTable::new();

        // First packet from 10.0.0.1:12345
        let mut frame1 = build_ipv4_frame_ex(&quic, [10, 0, 0, 1], 12345);
        assert!(matches!(
            process_packet(&mut frame1, &config, &mut conn),
            Verdict::Forward
        ));
        let mac1 = frame1[..6].to_vec();

        // Retransmit from 10.0.0.99:54321 (NAT rebinding) — same DCID.
        let mut frame2 = build_ipv4_frame_ex(&quic, [10, 0, 0, 99], 54321);
        assert!(matches!(
            process_packet(&mut frame2, &config, &mut conn),
            Verdict::Forward
        ));
        // Same server via DCID index.
        assert_eq!(&frame2[..6], &mac1[..]);
    }

    #[test]
    fn cid_route_records_dcid_for_rebinding() {
        // A successfully CID-routed packet records the DCID in the
        // connection table. Verify it's retrievable for NAT rebinding.
        let config = make_config();
        let quic = build_quic_long_header(0, &[0x00, 0x00, 0x01], &[0xaa; 13]);
        let mut frame = build_ipv4_frame(&quic);
        let mut conn = ConnectionTable::new();

        assert!(matches!(
            process_packet(&mut frame, &config, &mut conn),
            Verdict::Forward
        ));

        // The DCID should now be in the connection table.
        // Build the expected DCID bytes: [first_octet][server_id][nonce]
        let mut dcid_bytes = vec![0x00]; // config_id=0 << 5
        dcid_bytes.extend_from_slice(&[0x00, 0x00, 0x01]);
        dcid_bytes.extend_from_slice(&[0xaa; 13]);
        let dcid_key = DcidKey::from_slice(&dcid_bytes);

        let unrelated_flow = FlowKey {
            src_addr: "192.168.1.1".parse().unwrap(),
            dst_addr: "192.168.1.2".parse().unwrap(),
            src_port: 9999,
            dst_port: 9999,
        };

        assert_eq!(conn.lookup(&unrelated_flow, Some(&dcid_key)), Some(0));
    }

    #[test]
    fn fallback_deterministic_across_tables() {
        // The consistent hash should produce the same result regardless
        // of which ConnectionTable instance is used.
        let config = make_config_two_servers();
        let quic = build_quic_long_header(3, &[0x00, 0x00, 0x01], &[0x00; 13]);

        let mut frame1 = build_ipv4_frame(&quic);
        let mut frame2 = build_ipv4_frame(&quic);
        let mut conn1 = ConnectionTable::new();
        let mut conn2 = ConnectionTable::new();

        process_packet(&mut frame1, &config, &mut conn1);
        process_packet(&mut frame2, &config, &mut conn2);

        // Same 4-tuple → same consistent hash → same server.
        assert_eq!(&frame1[..6], &frame2[..6]);
    }

    // -- Frame parsing tests --

    #[test]
    fn parse_frame_ipv6_with_fragment_ext() {
        // IPv6 with Fragment extension header before UDP
        let quic_payload = [0x42; 10];
        let mut f = Vec::new();

        // Ethernet
        f.extend_from_slice(&[0xff; 6]);
        f.extend_from_slice(&[0x00; 6]);
        f.extend_from_slice(&ETH_P_IPV6.to_be_bytes());

        // IPv6 header: next_hdr = Fragment (44)
        f.push(0x60);
        f.extend_from_slice(&[0x00; 3]);
        let payload_len = (8 + 8 + quic_payload.len()) as u16; // frag hdr + udp + quic
        f.extend_from_slice(&payload_len.to_be_bytes());
        f.push(IPPROTO_FRAGMENT);
        f.push(0x40);
        f.extend_from_slice(&[0x00; 16]); // src
        f.extend_from_slice(&[0x00; 16]); // dst

        // Fragment extension header (8 bytes): next_hdr = UDP
        f.push(IPPROTO_UDP); // next header
        f.push(0x00); // reserved
        f.extend_from_slice(&[0x00; 2]); // frag offset + flags
        f.extend_from_slice(&[0x00; 4]); // identification

        // UDP
        f.extend_from_slice(&443u16.to_be_bytes());
        f.extend_from_slice(&443u16.to_be_bytes());
        let udp_len = (8 + quic_payload.len()) as u16;
        f.extend_from_slice(&udp_len.to_be_bytes());
        f.extend_from_slice(&[0x00; 2]);

        f.extend_from_slice(&quic_payload);

        let meta = parse_frame(&f).unwrap();
        assert_eq!(&f[meta.quic_offset..], &quic_payload);
    }
}
