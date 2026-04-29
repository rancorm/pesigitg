// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

use super::*;
use crate::config::route::{Encryption, RouteConfig};

const LOCAL_MAC: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

fn now() -> Instant {
    Instant::now()
}

fn make_config() -> ConfigTable {
    ConfigTable::with_configs(vec![RouteConfig {
        config_id: 0,
        first_octet_encodes_cid_length: true,
        server_id_length: 3,
        nonce_length: 13,
        encryption: Encryption::Plaintext,
        servers: vec![Server {
            id: vec![0x00, 0x00, 0x01],
            address: "10.0.1.10".parse().unwrap(),
            mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]),
            draining: false,
            healthy: true,
            transitions: 0,
            state_since: None,
        }],
    }])
}

fn make_config_two_servers() -> ConfigTable {
    ConfigTable::with_configs(vec![RouteConfig {
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
                draining: false,
                healthy: true,
                transitions: 0,
                state_since: None,
            },
            Server {
                id: vec![0x00, 0x00, 0x02],
                address: "10.0.1.11".parse().unwrap(),
                mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02]),
                draining: false,
                healthy: true,
                transitions: 0,
                state_since: None,
            },
        ],
    }])
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
        process_packet(&mut frame, &config, &mut conn, &LOCAL_MAC, now()),
        Verdict::CidForward(_)
    ));
    assert_eq!(&frame[..6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
    assert_eq!(&frame[6..12], &LOCAL_MAC);
}

#[test]
fn process_ipv6_long_header_rewrites_mac() {
    let config = make_config();
    let quic = build_quic_long_header(0, &[0x00, 0x00, 0x01], &[0xbb; 13]);
    let mut frame = build_ipv6_frame(&quic);
    let mut conn = ConnectionTable::new();

    assert!(matches!(
        process_packet(&mut frame, &config, &mut conn, &LOCAL_MAC, now()),
        Verdict::CidForward(_)
    ));
    assert_eq!(&frame[..6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
    assert_eq!(&frame[6..12], &LOCAL_MAC);
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
        process_packet(&mut frame, &config, &mut conn, &LOCAL_MAC, now()),
        Verdict::CidUnroutable
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
        process_packet(&mut frame, &config, &mut conn, &LOCAL_MAC, now()),
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
        process_packet(&mut frame, &config, &mut conn, &LOCAL_MAC, now()),
        Verdict::CidForward(_)
    ));
    assert_eq!(&frame[..6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
    assert_eq!(&frame[6..12], &LOCAL_MAC);
}

#[test]
fn client_initial_with_matching_config_id_falls_through_to_fallback() {
    // A client-generated Initial has a random DCID. If the first byte's
    // top 3 bits happen to match config_id 0, the CID path enters
    // lookup_config but the CID is too short to decrypt. This must fall
    // through to fallback routing, not Verdict::Pass.
    let config = make_config();
    let mut conn = ConnectionTable::new();

    // Client-generated DCID: 8 random bytes, first byte 0x05 (top 3 bits = 0 → config_id 0)
    let client_dcid: &[u8] = &[0x05, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03];
    let mut quic = Vec::new();
    quic.push(0xc0); // Long Header Initial
    quic.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // version
    quic.push(client_dcid.len() as u8); // DCID length = 8
    quic.extend_from_slice(client_dcid);
    quic.push(0x00); // SCID length = 0

    let mut frame = build_ipv4_frame(&quic);

    assert!(matches!(
        process_packet(&mut frame, &config, &mut conn, &LOCAL_MAC, now()),
        Verdict::FallbackForward
    ));
    assert_eq!(&frame[..6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
    assert_eq!(&frame[6..12], &LOCAL_MAC);
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
        process_packet(&mut frame, &config, &mut conn, &LOCAL_MAC, now()),
        Verdict::FallbackForward
    ));
    // Only one server with a MAC, so it must be selected.
    assert_eq!(&frame[..6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
    assert_eq!(&frame[6..12], &LOCAL_MAC);
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
        process_packet(&mut frame1, &config, &mut conn, &LOCAL_MAC, now()),
        Verdict::FallbackForward
    ));
    let mac1 = frame1[..6].to_vec();

    // Second packet, same 4-tuple — should get same server from table.
    let mut frame2 = build_ipv4_frame(&quic);
    assert!(matches!(
        process_packet(&mut frame2, &config, &mut conn, &LOCAL_MAC, now()),
        Verdict::FallbackForward
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
        process_packet(&mut frame1, &config, &mut conn, &LOCAL_MAC, now()),
        Verdict::FallbackForward
    ));
    let mac1 = frame1[..6].to_vec();

    // Retransmit from 10.0.0.99:54321 (NAT rebinding) — same DCID.
    let mut frame2 = build_ipv4_frame_ex(&quic, [10, 0, 0, 99], 54321);
    assert!(matches!(
        process_packet(&mut frame2, &config, &mut conn, &LOCAL_MAC, now()),
        Verdict::FallbackForward
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
        process_packet(&mut frame, &config, &mut conn, &LOCAL_MAC, now()),
        Verdict::CidForward(_)
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

    assert_eq!(
        conn.lookup(&unrelated_flow, Some(&dcid_key), now()),
        Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01])
    );
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

    process_packet(&mut frame1, &config, &mut conn1, &LOCAL_MAC, now());
    process_packet(&mut frame2, &config, &mut conn2, &LOCAL_MAC, now());

    // Same 4-tuple → same consistent hash → same server.
    assert_eq!(&frame1[..6], &frame2[..6]);
}

// -- ICMP path tests --

/// Build an IPv4 ICMP Destination Unreachable frame wrapping an inner
/// IPv4/UDP/QUIC packet (server→client direction).
fn build_icmp_ipv4_frame(
    inner_quic: &[u8],
    inner_src_ip: [u8; 4],
    inner_dst_ip: [u8; 4],
    inner_src_port: u16,
    inner_dst_port: u16,
) -> Vec<u8> {
    let mut f = Vec::new();

    // Ethernet
    f.extend_from_slice(&[0xff; 6]); // dst
    f.extend_from_slice(&[0x00; 6]); // src
    f.extend_from_slice(&ETH_P_IP.to_be_bytes());

    // Outer IPv4 header (20 bytes, protocol=ICMP)
    f.push(0x45);
    f.push(0x00);
    // total length placeholder — fill after building
    let total_len_pos = f.len();
    f.extend_from_slice(&[0x00; 2]);
    f.extend_from_slice(&[0x00; 4]); // ident, flags, frag
    f.push(0x40); // TTL
    f.push(IPPROTO_ICMP);
    f.extend_from_slice(&[0x00; 2]); // checksum
    f.extend_from_slice(&[192, 168, 1, 1]); // src (router)
    f.extend_from_slice(&[10, 0, 1, 1]); // dst (VIP)

    // ICMP header: type=3 (Dest Unreach), code=4 (Frag Needed), checksum, MTU
    f.push(ICMP_DEST_UNREACH);
    f.push(0x04); // code: fragmentation needed
    f.extend_from_slice(&[0x00; 2]); // checksum
    f.extend_from_slice(&[0x00; 2]); // unused
    f.extend_from_slice(&0x05dcu16.to_be_bytes()); // next-hop MTU

    // Inner IPv4 header (server→client)
    f.push(0x45);
    f.push(0x00);
    let inner_total = (20 + 8 + inner_quic.len()) as u16;
    f.extend_from_slice(&inner_total.to_be_bytes());
    f.extend_from_slice(&[0x00; 4]);
    f.push(0x40);
    f.push(IPPROTO_UDP);
    f.extend_from_slice(&[0x00; 2]);
    f.extend_from_slice(&inner_src_ip); // server (VIP)
    f.extend_from_slice(&inner_dst_ip); // client

    // Inner UDP header
    f.extend_from_slice(&inner_src_port.to_be_bytes());
    f.extend_from_slice(&inner_dst_port.to_be_bytes());
    let inner_udp_len = (8 + inner_quic.len()) as u16;
    f.extend_from_slice(&inner_udp_len.to_be_bytes());
    f.extend_from_slice(&[0x00; 2]);

    // Inner QUIC payload
    f.extend_from_slice(inner_quic);

    // Patch outer IPv4 total length
    let outer_total = (f.len() - ETH_HDR_LEN) as u16;
    f[total_len_pos..total_len_pos + 2].copy_from_slice(&outer_total.to_be_bytes());

    f
}

/// Build a QUIC long header with both DCID and SCID (server's response).
fn build_quic_long_header_with_scid(
    dcid: &[u8],
    scid_config_id: u8,
    scid_server_id: &[u8],
    scid_nonce: &[u8],
) -> Vec<u8> {
    let scid_len = 1 + scid_server_id.len() + scid_nonce.len();
    let mut q = Vec::new();
    q.push(0xc0); // Long Header
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // version
    q.push(dcid.len() as u8); // DCID length
    q.extend_from_slice(dcid); // DCID (client-generated)
    q.push(scid_len as u8); // SCID length
    q.push(scid_config_id << 5); // SCID first octet
    q.extend_from_slice(scid_server_id);
    q.extend_from_slice(scid_nonce);
    q
}

#[test]
fn icmp_scid_routes_to_server() {
    // ICMP containing a server's long-header response: SCID is routable.
    let config = make_config();
    let inner_quic = build_quic_long_header_with_scid(
        &[0xde, 0xad],       // client DCID (irrelevant)
        0,                   // config_id=0
        &[0x00, 0x00, 0x01], // server_id
        &[0xaa; 13],         // nonce
    );
    let mut frame = build_icmp_ipv4_frame(
        &inner_quic,
        [10, 0, 1, 10], // server (VIP)
        [10, 0, 0, 1],  // client
        443,
        12345,
    );
    let mut conn = ConnectionTable::new();

    assert!(matches!(
        process_packet(&mut frame, &config, &mut conn, &LOCAL_MAC, now()),
        Verdict::IcmpForward
    ));
    assert_eq!(&frame[..6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
    assert_eq!(&frame[6..12], &LOCAL_MAC);
}

#[test]
fn icmp_fallback_to_connection_table() {
    // ICMP containing a short header (no SCID). The reversed 4-tuple
    // should match a connection table entry from a prior fallback-routed
    // packet (CID fast path only records DCID, not the 4-tuple flow).
    let config = make_config();
    let mut conn = ConnectionTable::new();

    // First, send a fallback-routed packet (wrong config_id=3, so CID
    // path fails and it goes through consistent hash). This records the
    // 4-tuple in the connection table.
    let quic = build_quic_long_header(3, &[0x00, 0x00, 0x01], &[0x00; 13]);
    let mut normal_frame = build_ipv4_frame_ex(&quic, [10, 0, 0, 1], 12345);
    assert!(matches!(
        process_packet(&mut normal_frame, &config, &mut conn, &LOCAL_MAC, now()),
        Verdict::FallbackForward
    ));

    // Now an ICMP arrives with an inner short-header packet (server→client).
    // Short header: no SCID, so we fall back to reversed 4-tuple lookup.
    let mut inner_quic = vec![0x40]; // short header
    inner_quic.extend_from_slice(&[0x00; 20]); // some payload
    let mut icmp_frame = build_icmp_ipv4_frame(
        &inner_quic,
        [10, 0, 1, 10], // server src = VIP (dst of original flow)
        [10, 0, 0, 1],  // client dst = client (src of original flow)
        443,            // server port (dst_port of original flow)
        12345,          // client port (src_port of original flow)
    );

    assert!(matches!(
        process_packet(&mut icmp_frame, &config, &mut conn, &LOCAL_MAC, now()),
        Verdict::IcmpForward
    ));
    assert_eq!(&icmp_frame[..6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
    assert_eq!(&icmp_frame[6..12], &LOCAL_MAC);
}

#[test]
fn icmp_no_match_passes() {
    // ICMP with a short header and no connection table entry → Pass.
    let config = make_config();
    let mut conn = ConnectionTable::new();

    let mut inner_quic = vec![0x40]; // short header
    inner_quic.extend_from_slice(&[0x00; 20]);
    let mut frame = build_icmp_ipv4_frame(&inner_quic, [10, 0, 1, 10], [10, 0, 0, 99], 443, 54321);

    assert!(matches!(
        process_packet(&mut frame, &config, &mut conn, &LOCAL_MAC, now()),
        Verdict::Pass
    ));
    // MAC not rewritten.
    assert_eq!(&frame[..6], &[0xff; 6]);
}

#[test]
fn icmp_truncated_inner_quic_falls_back() {
    // ICMP with truncated inner QUIC (not enough bytes for SCID).
    // Should fall through to connection table lookup, then Pass.
    let config = make_config();
    let mut conn = ConnectionTable::new();

    // Only 8 bytes of inner QUIC — long header but way too short for SCID.
    let inner_quic = vec![0xc0, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04];
    let mut frame = build_icmp_ipv4_frame(&inner_quic, [10, 0, 1, 10], [10, 0, 0, 1], 443, 12345);

    assert!(matches!(
        process_packet(&mut frame, &config, &mut conn, &LOCAL_MAC, now()),
        Verdict::Pass
    ));
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
    match meta {
        FrameMeta::Udp { quic_offset, .. } => {
            assert_eq!(&f[quic_offset..], &quic_payload);
        }
        _ => panic!("expected FrameMeta::Udp"),
    }
}
