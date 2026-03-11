//! Packet processing pipeline for QUIC-LB load balancing.
//!
//! Given a raw Ethernet frame containing a QUIC/UDP packet (as filtered
//! by the XDP program), extracts the QUIC Connection ID, decrypts the
//! server identifier, looks up the backend server, and rewrites the
//! Ethernet destination MAC for L2 forwarding.

use pesigitg_common::{
    ETH_HDR_LEN, ETH_P_IP, ETH_P_IPV6, IPPROTO_DSTOPTS, IPPROTO_FRAGMENT, IPPROTO_HOPOPTS,
    IPPROTO_ROUTING, IPPROTO_UDP, IPV4_MIN_HDR_LEN, IPV6_HDR_LEN, MAX_IPV6_EXT_HDRS, UDP_HDR_LEN,
};

use crate::cid;
use crate::config::route::RouteConfig;

/// Outcome of packet processing.
pub enum Verdict {
    /// Destination MAC rewritten; the packet should be forwarded.
    Forward,
    /// Packet not modified; pass through to the kernel stack.
    Pass,
}

/// Process a raw Ethernet frame containing a QUIC/UDP packet.
///
/// Extracts the QUIC Connection ID, decrypts it per the QUIC-LB
/// configuration, looks up the backend server, and rewrites the
/// Ethernet destination MAC for L2 forwarding.
pub fn process_packet(frame: &mut [u8], config: &RouteConfig) -> Verdict {
    let quic_offset = match find_quic_offset(frame) {
        Some(off) => off,
        None => return Verdict::Pass,
    };

    let dcid = match cid::extract_dcid(&frame[quic_offset..], config) {
        Some(d) => d,
        None => return Verdict::Pass,
    };

    let server = match cid::resolve_server(dcid, config) {
        Some(s) => s,
        None => return Verdict::Pass,
    };

    let mac = match server.mac {
        Some(m) => m,
        None => return Verdict::Pass,
    };

    // Rewrite destination MAC (first 6 bytes of Ethernet frame)
    frame[..6].copy_from_slice(&mac);

    Verdict::Forward
}

/// Locate the byte offset where the QUIC payload starts within a raw
/// Ethernet frame (after ETH + IP + UDP headers).
fn find_quic_offset(frame: &[u8]) -> Option<usize> {
    if frame.len() < ETH_HDR_LEN {
        return None;
    }

    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);

    match ethertype {
        ETH_P_IP => find_quic_offset_ipv4(frame),
        ETH_P_IPV6 => find_quic_offset_ipv6(frame),
        _ => None,
    }
}

fn find_quic_offset_ipv4(frame: &[u8]) -> Option<usize> {
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

    let offset = ETH_HDR_LEN + ihl + UDP_HDR_LEN;
    if offset > frame.len() {
        return None;
    }

    Some(offset)
}

fn find_quic_offset_ipv6(frame: &[u8]) -> Option<usize> {
    if frame.len() < ETH_HDR_LEN + IPV6_HDR_LEN {
        return None;
    }

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

    let offset = offset + UDP_HDR_LEN;
    if offset > frame.len() {
        return None;
    }

    Some(offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::route::{Encryption, Server};
    use std::path::PathBuf;

    fn make_config() -> RouteConfig {
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
            ],
        }
    }

    /// Build a minimal IPv4/UDP Ethernet frame with the given QUIC payload.
    fn build_ipv4_frame(quic: &[u8]) -> Vec<u8> {
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
        f.extend_from_slice(&[10, 0, 0, 1]); // src
        f.extend_from_slice(&[10, 0, 1, 10]); // dst

        // UDP header (8 bytes)
        f.extend_from_slice(&443u16.to_be_bytes());
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

    #[test]
    fn process_ipv4_long_header_rewrites_mac() {
        let config = make_config();
        let quic = build_quic_long_header(0, &[0x00, 0x00, 0x01], &[0xaa; 13]);
        let mut frame = build_ipv4_frame(&quic);

        assert!(matches!(process_packet(&mut frame, &config), Verdict::Forward));
        assert_eq!(&frame[..6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
    }

    #[test]
    fn process_ipv6_long_header_rewrites_mac() {
        let config = make_config();
        let quic = build_quic_long_header(0, &[0x00, 0x00, 0x01], &[0xbb; 13]);
        let mut frame = build_ipv6_frame(&quic);

        assert!(matches!(process_packet(&mut frame, &config), Verdict::Forward));
        assert_eq!(&frame[..6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
    }

    #[test]
    fn process_unknown_server_passes() {
        let config = make_config();
        let quic = build_quic_long_header(0, &[0xff, 0xff, 0xff], &[0x00; 13]);
        let mut frame = build_ipv4_frame(&quic);

        assert!(matches!(process_packet(&mut frame, &config), Verdict::Pass));
        // MAC unchanged
        assert_eq!(&frame[..6], &[0xff; 6]);
    }

    #[test]
    fn process_wrong_config_id_passes() {
        let config = make_config();
        let quic = build_quic_long_header(3, &[0x00, 0x00, 0x01], &[0x00; 13]);
        let mut frame = build_ipv4_frame(&quic);

        assert!(matches!(process_packet(&mut frame, &config), Verdict::Pass));
    }

    #[test]
    fn process_non_ip_passes() {
        let config = make_config();
        // ARP ethertype
        let mut frame = vec![0xff; 6];
        frame.extend_from_slice(&[0x00; 6]);
        frame.extend_from_slice(&[0x08, 0x06]); // ARP
        frame.extend_from_slice(&[0x00; 28]);

        assert!(matches!(process_packet(&mut frame, &config), Verdict::Pass));
    }

    #[test]
    fn process_short_header_rewrites_mac() {
        let config = make_config();

        // Short Header: [0x40][CID: 17 bytes]
        let mut quic = vec![0x40];
        quic.push(0x00); // first CID octet (config_id=0)
        quic.extend_from_slice(&[0x00, 0x00, 0x01]); // server_id
        quic.extend_from_slice(&[0xcc; 13]); // nonce
        // Pad some extra bytes (packet number, payload)
        quic.extend_from_slice(&[0x00; 20]);

        let mut frame = build_ipv4_frame(&quic);

        assert!(matches!(process_packet(&mut frame, &config), Verdict::Forward));
        assert_eq!(&frame[..6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
    }

    #[test]
    fn find_quic_offset_ipv6_with_fragment_ext() {
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

        let offset = find_quic_offset(&f).unwrap();
        assert_eq!(&f[offset..], &quic_payload);
    }
}
