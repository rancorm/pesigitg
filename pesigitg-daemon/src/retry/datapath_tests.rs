use super::*;
use crate::config::route::ConfigTable;
use crate::retry::packet::INTEGRITY_TAG_LEN;
use crate::retry::token::TOKEN_LEN;
use std::net::{Ipv4Addr, Ipv6Addr};

const LOCAL_MAC: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
const CLIENT_MAC: [u8; 6] = [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa];
const KEY_HEX: &str =
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

fn make_table(retry_toml: &str) -> ConfigTable {
    let toml = format!(
        r#"
[[configs]]
config_id = 0
server_id_length = 3
nonce_length = 13

{}
"#,
        retry_toml
    );
    ConfigTable::from_str(&toml).expect("valid toml")
}

fn build_quic_initial(
    first_byte: u8,
    version: u32,
    dcid: &[u8],
    scid: &[u8],
    token: &[u8],
) -> Vec<u8> {
    let mut q = Vec::new();
    q.push(first_byte);
    q.extend_from_slice(&version.to_be_bytes());
    q.push(dcid.len() as u8);
    q.extend_from_slice(dcid);
    q.push(scid.len() as u8);
    q.extend_from_slice(scid);
    // Token length varint (1-byte form, ≤63).
    assert!(token.len() < 64, "test helper only handles short tokens");
    q.push(token.len() as u8);
    q.extend_from_slice(token);
    // Length varint = 20, 2-byte form: 0x4014. Plus 20 dummy payload bytes.
    q.extend_from_slice(&[0x40, 0x14]);
    q.extend_from_slice(&[0u8; 20]);
    q
}

fn build_v1_initial(dcid: &[u8], scid: &[u8], token: &[u8]) -> Vec<u8> {
    build_quic_initial(0xc0, 0x0000_0001, dcid, scid, token)
}

fn build_v2_initial(dcid: &[u8], scid: &[u8], token: &[u8]) -> Vec<u8> {
    build_quic_initial(0xd0, 0x6b33_43cf, dcid, scid, token)
}

/// A UMEM-sized buffer: way larger than any real frame, mirrors the
/// 4 KiB frames the real socket hands us.
struct TestFrame {
    buf: Vec<u8>,
    len: usize,
}

impl TestFrame {
    fn new(initial_bytes: &[u8]) -> Self {
        let mut buf = vec![0u8; 4096];
        buf[..initial_bytes.len()].copy_from_slice(initial_bytes);
        Self {
            buf,
            len: initial_bytes.len(),
        }
    }

    /// Analogue of `try_handle` that operates on plain slices so
    /// tests don't need to stand up a real AF_XDP socket. The
    /// production path is a thin wrapper around the same logic.
    fn try_handle_slice(
        &mut self,
        table: &ConfigTable,
        local_mac: &[u8; 6],
        now_ms: u64,
    ) -> (Outcome, Detail) {
        let retry = match table.retry.as_ref() {
            Some(r) if r.enabled => r,
            _ => return (Outcome::Skip, Detail::None),
        };
        let layout = match parse_layout(&self.buf[..self.len]) {
            Some(l) => l,
            None => return (Outcome::Skip, Detail::None),
        };
        if !retry.ports.is_empty() && !retry.ports.contains(&layout.dst_port) {
            return (Outcome::Skip, Detail::None);
        }
        let mut dcid_buf = [0u8; 20];
        let mut scid_buf = [0u8; 20];
        let dcid_len;
        let scid_len;
        let version;
        let (decision, detail) = {
            let quic = &self.buf[layout.quic_offset..self.len];
            let initial = match initial::parse_strict(quic) {
                Ok(i) => i,
                Err(ParseError::NotLongHeader)
                | Err(ParseError::NotInitial)
                | Err(ParseError::FixedBitUnset)
                | Err(ParseError::UnsupportedVersion(_))
                | Err(ParseError::Truncated) => return (Outcome::Skip, Detail::None),
                Err(_) => return (Outcome::Skip, Detail::ParseError),
            };
            dcid_len = initial.dcid.len();
            scid_len = initial.scid.len();
            version = initial.version;
            dcid_buf[..dcid_len].copy_from_slice(initial.dcid);
            scid_buf[..scid_len].copy_from_slice(initial.scid);
            classify(&initial, layout.src_ip, retry, now_ms)
        };

        match decision {
            Decision::Forward => (Outcome::Forward, detail),
            Decision::Skip => (Outcome::Skip, detail),
            Decision::Emit => {
                let outcome = self.emit_slice(
                    &layout,
                    version,
                    &dcid_buf[..dcid_len],
                    &scid_buf[..scid_len],
                    retry,
                    local_mac,
                    now_ms,
                );
                (outcome, detail)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_slice(
        &mut self,
        layout: &FrameLayout,
        version: u32,
        odcid: &[u8],
        client_scid: &[u8],
        retry: &RetryConfig,
        local_mac: &[u8; 6],
        now_ms: u64,
    ) -> Outcome {
        let token = match retry.token_key.mint(layout.src_ip, odcid, now_ms) {
            Ok(t) => t,
            Err(_) => return Outcome::Skip,
        };
        let mut retry_buf = [0u8; 128];
        let n = match build_retry(
            &mut retry_buf,
            version,
            odcid,
            client_scid,
            odcid,
            &token,
        ) {
            Ok(n) => n,
            Err(_) => return Outcome::Skip,
        };
        let retry_bytes = &retry_buf[..n];

        let mut hdr_buf = [0u8; 64];
        let hdr_len = build_reflected_headers(&mut hdr_buf, layout, local_mac, retry_bytes.len());

        let total = hdr_len + retry_bytes.len();
        if total > self.buf.len() {
            return Outcome::Skip;
        }
        self.buf[..hdr_len].copy_from_slice(&hdr_buf[..hdr_len]);
        self.buf[hdr_len..total].copy_from_slice(retry_bytes);
        self.len = total;

        if layout.is_ipv4 {
            write_ipv4_checksum(&mut self.buf[..self.len], layout.ip_offset, layout.ip_hdr_len);
        } else {
            write_ipv6_udp_checksum(&mut self.buf[..self.len], layout);
        }

        Outcome::Emitted
    }
}

fn build_udp_v4(
    quic: &[u8],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&LOCAL_MAC);   // dst mac (us)
    f.extend_from_slice(&CLIENT_MAC);  // src mac (client/upstream)
    f.extend_from_slice(&ETH_P_IP.to_be_bytes());

    f.push(0x45);
    f.push(0x00);
    let total = (20 + 8 + quic.len()) as u16;
    f.extend_from_slice(&total.to_be_bytes());
    f.extend_from_slice(&[0x00; 4]);
    f.push(0x40);
    f.push(IPPROTO_UDP);
    f.extend_from_slice(&[0x00; 2]);
    f.extend_from_slice(&src_ip);
    f.extend_from_slice(&dst_ip);

    f.extend_from_slice(&src_port.to_be_bytes());
    f.extend_from_slice(&dst_port.to_be_bytes());
    let udp_len = (8 + quic.len()) as u16;
    f.extend_from_slice(&udp_len.to_be_bytes());
    f.extend_from_slice(&[0x00; 2]);
    f.extend_from_slice(quic);
    f
}

fn build_udp_v6(
    quic: &[u8],
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&LOCAL_MAC);
    f.extend_from_slice(&CLIENT_MAC);
    f.extend_from_slice(&ETH_P_IPV6.to_be_bytes());

    f.push(0x60);
    f.extend_from_slice(&[0x00; 3]);
    let payload_len = (8 + quic.len()) as u16;
    f.extend_from_slice(&payload_len.to_be_bytes());
    f.push(IPPROTO_UDP);
    f.push(0x40);
    f.extend_from_slice(&src_ip);
    f.extend_from_slice(&dst_ip);

    f.extend_from_slice(&src_port.to_be_bytes());
    f.extend_from_slice(&dst_port.to_be_bytes());
    let udp_len = (8 + quic.len()) as u16;
    f.extend_from_slice(&udp_len.to_be_bytes());
    f.extend_from_slice(&[0x00; 2]);
    f.extend_from_slice(quic);
    f
}

// -- classify() unit tests ---------------------------------------------

#[test]
fn classify_always_mode_no_token_emits() {
    let table = make_table(&format!(
        "[retry]\nenabled = true\nmode = \"always\"\ntoken_key = \"{KEY_HEX}\""
    ));
    let retry = table.retry.as_ref().unwrap();
    let quic = build_v1_initial(&[0xaa; 8], &[0xbb; 4], &[]);
    let initial = initial::parse_strict(&quic).unwrap();
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    assert_eq!(
        classify(&initial, src, retry, 1_000),
        (Decision::Emit, Detail::Issued),
    );
}

#[test]
fn classify_valid_token_forwards() {
    let table = make_table(&format!(
        "[retry]\nenabled = true\nmode = \"always\"\ntoken_key = \"{KEY_HEX}\""
    ));
    let retry = table.retry.as_ref().unwrap();
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    let dcid = [0xaa; 8];
    let tok = retry.token_key.mint(src, &dcid, 1_000).unwrap();
    let quic = build_v1_initial(&dcid, &[0xbb; 4], &tok);
    let initial = initial::parse_strict(&quic).unwrap();
    assert_eq!(
        classify(&initial, src, retry, 1_100),
        (Decision::Forward, Detail::TokenValid),
    );
}

#[test]
fn classify_expired_token_reissues() {
    let table = make_table(&format!(
        "[retry]\nenabled = true\nmode = \"always\"\ntoken_key = \"{KEY_HEX}\"\n\
         token_lifetime_secs = 1"
    ));
    let retry = table.retry.as_ref().unwrap();
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    let dcid = [0xaa; 8];
    let tok = retry.token_key.mint(src, &dcid, 1_000).unwrap();
    let quic = build_v1_initial(&dcid, &[0xbb; 4], &tok);
    let initial = initial::parse_strict(&quic).unwrap();
    // Lifetime = 1000 ms, verify at +5s → expired → re-Retry.
    assert_eq!(
        classify(&initial, src, retry, 6_000),
        (Decision::Emit, Detail::TokenExpired),
    );
}

#[test]
fn classify_wrong_client_reissues() {
    let table = make_table(&format!(
        "[retry]\nenabled = true\nmode = \"always\"\ntoken_key = \"{KEY_HEX}\""
    ));
    let retry = table.retry.as_ref().unwrap();
    let minted_for = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    let attacker = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99));
    let dcid = [0xaa; 8];
    let tok = retry.token_key.mint(minted_for, &dcid, 1_000).unwrap();
    let quic = build_v1_initial(&dcid, &[0xbb; 4], &tok);
    let initial = initial::parse_strict(&quic).unwrap();
    assert_eq!(
        classify(&initial, attacker, retry, 1_100),
        (Decision::Emit, Detail::TokenInvalid),
    );
}

#[test]
fn classify_observe_never_emits() {
    let table = make_table(&format!(
        "[retry]\nenabled = true\nmode = \"observe\"\ntoken_key = \"{KEY_HEX}\""
    ));
    let retry = table.retry.as_ref().unwrap();
    let quic = build_v1_initial(&[0xaa; 8], &[0xbb; 4], &[]);
    let initial = initial::parse_strict(&quic).unwrap();
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    assert_eq!(
        classify(&initial, src, retry, 1_000),
        (Decision::Skip, Detail::Observed),
    );
}

/// Seed the load tracker so `observe_and_rate` reports `rate` from
/// the last completed window. The shared-atomic tracker only
/// publishes once a window flips, so this walks two windows.
fn seed_load_rate(retry: &RetryConfig, rate: u64) {
    let tracker = retry.load_tracker.as_ref().expect("load tracker present");
    // Window 0 at t=0 accumulates `rate` ticks...
    for _ in 0..rate {
        tracker.observe_and_rate(0);
    }
    // ...then a single observation at t=1s flips us into window 1
    // and publishes the window-0 count as `last_rate`.
    tracker.observe_and_rate(1_000);
    assert_eq!(tracker.rate(), rate);
}

#[test]
fn classify_load_below_trigger_skips() {
    // trigger_rate = 10, seeded rate = 5 → Skip.
    let table = make_table(&format!(
        "[retry]\nenabled = true\nmode = \"load\"\ntoken_key = \"{KEY_HEX}\"\n\
         [retry.load]\ntrigger_rate = 10"
    ));
    let retry = table.retry.as_ref().unwrap();
    seed_load_rate(retry, 5);

    let quic = build_v1_initial(&[0xaa; 8], &[0xbb; 4], &[]);
    let initial = initial::parse_strict(&quic).unwrap();
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    assert_eq!(
        classify(&initial, src, retry, 1_500),
        (Decision::Skip, Detail::Observed),
    );
}

#[test]
fn classify_load_at_trigger_emits() {
    // trigger_rate = 10, seeded rate = 10 → Emit (>= threshold).
    let table = make_table(&format!(
        "[retry]\nenabled = true\nmode = \"load\"\ntoken_key = \"{KEY_HEX}\"\n\
         [retry.load]\ntrigger_rate = 10"
    ));
    let retry = table.retry.as_ref().unwrap();
    seed_load_rate(retry, 10);

    let quic = build_v1_initial(&[0xaa; 8], &[0xbb; 4], &[]);
    let initial = initial::parse_strict(&quic).unwrap();
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    assert_eq!(
        classify(&initial, src, retry, 1_500),
        (Decision::Emit, Detail::Issued),
    );
}

#[test]
fn classify_load_invalid_token_gated_by_rate() {
    // Invalid token under Load mode: below trigger → Skip, above → Emit.
    // Both cases must preserve the `TokenInvalid` detail so counters
    // distinguish token forgery from no-token-present.
    let table = make_table(&format!(
        "[retry]\nenabled = true\nmode = \"load\"\ntoken_key = \"{KEY_HEX}\"\n\
         [retry.load]\ntrigger_rate = 100"
    ));
    let retry = table.retry.as_ref().unwrap();
    let minted_for = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    let attacker = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99));
    let dcid = [0xaa; 8];
    let tok = retry.token_key.mint(minted_for, &dcid, 1_000).unwrap();
    let quic = build_v1_initial(&dcid, &[0xbb; 4], &tok);
    let initial = initial::parse_strict(&quic).unwrap();

    // Below trigger: Skip + TokenInvalid.
    assert_eq!(
        classify(&initial, attacker, retry, 1_100),
        (Decision::Skip, Detail::TokenInvalid),
    );

    // Now bump the rate above the trigger.
    seed_load_rate(retry, 200);
    assert_eq!(
        classify(&initial, attacker, retry, 1_500),
        (Decision::Emit, Detail::TokenInvalid),
    );
}

// -- try_handle_slice integration tests --------------------------------

#[test]
fn disabled_short_circuits() {
    let table = make_table("");
    let quic = build_v1_initial(&[0xaa; 8], &[0xbb; 4], &[]);
    let frame = build_udp_v4(&quic, [203, 0, 113, 1], [10, 0, 0, 1], 12345, 4433);
    let mut f = TestFrame::new(&frame);
    assert_eq!(f.try_handle_slice(&table, &LOCAL_MAC, 1_000).0, Outcome::Skip);
    // Frame bytes untouched.
    assert_eq!(&f.buf[..f.len], frame.as_slice());
}

#[test]
fn port_filter_scopes_handling() {
    let table = make_table(&format!(
        "[retry]\nenabled = true\nmode = \"always\"\ntoken_key = \"{KEY_HEX}\"\n\
         ports = [443]"
    ));
    let quic = build_v1_initial(&[0xaa; 8], &[0xbb; 4], &[]);
    // dst port 4433 is not in the [443] list → Skip.
    let frame_wrong = build_udp_v4(&quic, [203, 0, 113, 1], [10, 0, 0, 1], 12345, 4433);
    let mut fw = TestFrame::new(&frame_wrong);
    assert_eq!(fw.try_handle_slice(&table, &LOCAL_MAC, 1_000).0, Outcome::Skip);

    // dst port 443 is in the list → Emitted.
    let frame_ok = build_udp_v4(&quic, [203, 0, 113, 1], [10, 0, 0, 1], 12345, 443);
    let mut fo = TestFrame::new(&frame_ok);
    assert_eq!(fo.try_handle_slice(&table, &LOCAL_MAC, 1_000).0, Outcome::Emitted);
}

#[test]
fn ipv4_emits_reflected_frame() {
    let table = make_table(&format!(
        "[retry]\nenabled = true\nmode = \"always\"\ntoken_key = \"{KEY_HEX}\""
    ));
    let quic = build_v1_initial(&[0xaa; 8], &[0xbb; 4], &[]);
    let frame = build_udp_v4(&quic, [203, 0, 113, 1], [10, 0, 0, 1], 12345, 4433);
    let mut f = TestFrame::new(&frame);
    assert_eq!(
        f.try_handle_slice(&table, &LOCAL_MAC, 1_000),
        (Outcome::Emitted, Detail::Issued),
    );

    // Ethernet reflected.
    assert_eq!(&f.buf[..6], &CLIENT_MAC, "dst mac should be client");
    assert_eq!(&f.buf[6..12], &LOCAL_MAC, "src mac should be LB");
    assert_eq!(&f.buf[12..14], &ETH_P_IP.to_be_bytes());

    // IPv4 header swapped.
    assert_eq!(&f.buf[14 + 12..14 + 16], &[10, 0, 0, 1], "src ip = VIP");
    assert_eq!(&f.buf[14 + 16..14 + 20], &[203, 0, 113, 1], "dst ip = client");

    // UDP ports swapped.
    assert_eq!(&f.buf[14 + 20..14 + 22], &4433u16.to_be_bytes());
    assert_eq!(&f.buf[14 + 22..14 + 24], &12345u16.to_be_bytes());

    // Payload is a v1 Retry: first byte 0xf0, version 0x00000001.
    let payload_off = 14 + 20 + 8;
    assert_eq!(f.buf[payload_off], 0xf0);
    assert_eq!(&f.buf[payload_off + 1..payload_off + 5], &[0, 0, 0, 1]);

    // IP header checksum is non-zero and correct (ones_complement_sum of
    // the header yields 0 when verified).
    let ip_sum = ones_complement_sum(&f.buf[14..14 + 20]);
    assert_eq!(ip_sum, 0, "verifying IPv4 header checksum");
}

#[test]
fn ipv4_emitted_token_round_trips() {
    // The token we mint on emit must round-trip through verify() with
    // the client's (src_ip, ODCID) tuple — otherwise the client's
    // retransmitted Initial would loop forever.
    let table = make_table(&format!(
        "[retry]\nenabled = true\nmode = \"always\"\ntoken_key = \"{KEY_HEX}\""
    ));
    let dcid = [0xaa; 8];
    let quic = build_v1_initial(&dcid, &[0xbb; 4], &[]);
    let src_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    let frame = build_udp_v4(&quic, [203, 0, 113, 7], [10, 0, 0, 1], 12345, 4433);
    let mut f = TestFrame::new(&frame);
    assert_eq!(f.try_handle_slice(&table, &LOCAL_MAC, 2_000).0, Outcome::Emitted);

    // Parse the emitted Retry back out and verify its token.
    let payload_off = 14 + 20 + 8;
    let retry = &f.buf[payload_off..f.len];
    // Token sits at: 1 (first) + 4 (version) + 1 (dcid_len) + dcid + 1 (scid_len) + scid.
    // For the Retry packet we emit: DCID = client scid (4 bytes), SCID = original dcid (8 bytes).
    let token_start = 1 + 4 + 1 + 4 + 1 + 8;
    let token_end = retry.len() - INTEGRITY_TAG_LEN;
    assert_eq!(token_end - token_start, TOKEN_LEN);
    let token = &retry[token_start..token_end];

    let retry_cfg = table.retry.as_ref().unwrap();
    retry_cfg
        .token_key
        .verify(token, src_ip, &dcid, 2_050, 10_000)
        .expect("minted token must verify against the same (src, odcid)");
}

#[test]
fn ipv6_emits_reflected_frame() {
    let table = make_table(&format!(
        "[retry]\nenabled = true\nmode = \"always\"\ntoken_key = \"{KEY_HEX}\""
    ));
    let quic = build_v1_initial(&[0xaa; 8], &[0xbb; 4], &[]);
    let client = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets();
    let vip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).octets();
    let frame = build_udp_v6(&quic, client, vip, 12345, 4433);
    let mut f = TestFrame::new(&frame);
    assert_eq!(
        f.try_handle_slice(&table, &LOCAL_MAC, 1_000),
        (Outcome::Emitted, Detail::Issued),
    );

    // Ethernet + IPv6 reflection.
    assert_eq!(&f.buf[..6], &CLIENT_MAC);
    assert_eq!(&f.buf[6..12], &LOCAL_MAC);
    assert_eq!(&f.buf[12..14], &ETH_P_IPV6.to_be_bytes());
    assert_eq!(&f.buf[14 + 8..14 + 24], &vip);
    assert_eq!(&f.buf[14 + 24..14 + 40], &client);

    // UDP checksum must be non-zero on IPv6 (mandatory).
    let udp_off = 14 + 40;
    let cksum = u16::from_be_bytes([f.buf[udp_off + 6], f.buf[udp_off + 7]]);
    assert_ne!(cksum, 0, "IPv6 UDP checksum is mandatory");
}

#[test]
fn non_udp_is_skipped() {
    // Craft an Ethernet frame with a non-UDP protocol and confirm
    // the layout parser rejects it cleanly rather than panicking.
    let table = make_table(&format!(
        "[retry]\nenabled = true\nmode = \"always\"\ntoken_key = \"{KEY_HEX}\""
    ));
    let mut frame = Vec::new();
    frame.extend_from_slice(&LOCAL_MAC);
    frame.extend_from_slice(&CLIENT_MAC);
    frame.extend_from_slice(&ETH_P_IP.to_be_bytes());
    frame.push(0x45);
    frame.push(0);
    frame.extend_from_slice(&30u16.to_be_bytes());
    frame.extend_from_slice(&[0u8; 5]);
    frame.push(0x01); // ICMP
    frame.extend_from_slice(&[0u8; 10]);
    let mut f = TestFrame::new(&frame);
    assert_eq!(f.try_handle_slice(&table, &LOCAL_MAC, 1_000).0, Outcome::Skip);
}

#[test]
fn short_header_is_skipped() {
    let table = make_table(&format!(
        "[retry]\nenabled = true\nmode = \"always\"\ntoken_key = \"{KEY_HEX}\""
    ));
    // Short header byte 0x40 — not a long-header Initial, skip silently.
    let mut quic = vec![0x40u8];
    quic.extend_from_slice(&[0xcc; 30]);
    let frame = build_udp_v4(&quic, [203, 0, 113, 1], [10, 0, 0, 1], 12345, 4433);
    let mut f = TestFrame::new(&frame);
    assert_eq!(
        f.try_handle_slice(&table, &LOCAL_MAC, 1_000),
        (Outcome::Skip, Detail::None),
    );
}

// -- Detail / counter integration tests ---------------------------------

#[test]
fn observe_mode_reports_observed_detail() {
    let table = make_table(&format!(
        "[retry]\nenabled = true\nmode = \"observe\"\ntoken_key = \"{KEY_HEX}\""
    ));
    let quic = build_v1_initial(&[0xaa; 8], &[0xbb; 4], &[]);
    let frame = build_udp_v4(&quic, [203, 0, 113, 1], [10, 0, 0, 1], 12345, 4433);
    let mut f = TestFrame::new(&frame);
    let (outcome, detail) = f.try_handle_slice(&table, &LOCAL_MAC, 1_000);
    assert_eq!(outcome, Outcome::Skip);
    assert_eq!(detail, Detail::Observed);
}

#[test]
fn observe_mode_expired_token_reports_detail() {
    let table = make_table(&format!(
        "[retry]\nenabled = true\nmode = \"observe\"\ntoken_key = \"{KEY_HEX}\"\n\
         token_lifetime_secs = 1"
    ));
    let retry = table.retry.as_ref().unwrap();
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    let dcid = [0xaa; 8];
    let tok = retry.token_key.mint(src, &dcid, 1_000).unwrap();
    let quic = build_v1_initial(&dcid, &[0xbb; 4], &tok);
    let frame = build_udp_v4(&quic, [203, 0, 113, 1], [10, 0, 0, 1], 12345, 4433);
    let mut f = TestFrame::new(&frame);
    // Token minted at 1000, verified at 6000, lifetime 1s → expired.
    let (outcome, detail) = f.try_handle_slice(&table, &LOCAL_MAC, 6_000);
    assert_eq!(outcome, Outcome::Skip, "observe mode never emits");
    assert_eq!(detail, Detail::TokenExpired);
}

#[test]
fn observe_mode_valid_token_forwards() {
    let table = make_table(&format!(
        "[retry]\nenabled = true\nmode = \"observe\"\ntoken_key = \"{KEY_HEX}\""
    ));
    let retry = table.retry.as_ref().unwrap();
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    let dcid = [0xaa; 8];
    let tok = retry.token_key.mint(src, &dcid, 1_000).unwrap();
    let quic = build_v1_initial(&dcid, &[0xbb; 4], &tok);
    let frame = build_udp_v4(&quic, [203, 0, 113, 1], [10, 0, 0, 1], 12345, 4433);
    let mut f = TestFrame::new(&frame);
    let (outcome, detail) = f.try_handle_slice(&table, &LOCAL_MAC, 1_100);
    // Valid token forwards in every mode.
    assert_eq!(outcome, Outcome::Forward);
    assert_eq!(detail, Detail::TokenValid);
}

// -- QUIC v2 integration tests -------------------------------------------

#[test]
fn v2_initial_emits_v2_retry() {
    let table = make_table(&format!(
        "[retry]\nenabled = true\nmode = \"always\"\ntoken_key = \"{KEY_HEX}\""
    ));
    let quic = build_v2_initial(&[0xaa; 8], &[0xbb; 4], &[]);
    let frame = build_udp_v4(&quic, [203, 0, 113, 1], [10, 0, 0, 1], 12345, 4433);
    let mut f = TestFrame::new(&frame);
    assert_eq!(
        f.try_handle_slice(&table, &LOCAL_MAC, 1_000),
        (Outcome::Emitted, Detail::Issued),
    );

    // Payload should be a v2 Retry: first byte 0xc0 (type 0b00),
    // version 0x6b3343cf.
    let payload_off = 14 + 20 + 8;
    assert_eq!(f.buf[payload_off], 0xc0);
    assert_eq!(
        &f.buf[payload_off + 1..payload_off + 5],
        &0x6b33_43cfu32.to_be_bytes(),
    );
}

#[test]
fn v2_emitted_token_round_trips() {
    let table = make_table(&format!(
        "[retry]\nenabled = true\nmode = \"always\"\ntoken_key = \"{KEY_HEX}\""
    ));
    let dcid = [0xaa; 8];
    let quic = build_v2_initial(&dcid, &[0xbb; 4], &[]);
    let src_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    let frame = build_udp_v4(&quic, [203, 0, 113, 7], [10, 0, 0, 1], 12345, 4433);
    let mut f = TestFrame::new(&frame);
    assert_eq!(f.try_handle_slice(&table, &LOCAL_MAC, 2_000).0, Outcome::Emitted);

    // Extract token from the emitted v2 Retry and verify it.
    let payload_off = 14 + 20 + 8;
    let retry = &f.buf[payload_off..f.len];
    let token_start = 1 + 4 + 1 + 4 + 1 + 8;
    let token_end = retry.len() - INTEGRITY_TAG_LEN;
    assert_eq!(token_end - token_start, TOKEN_LEN);
    let token = &retry[token_start..token_end];

    let retry_cfg = table.retry.as_ref().unwrap();
    retry_cfg
        .token_key
        .verify(token, src_ip, &dcid, 2_050, 10_000)
        .expect("v2 minted token must verify");
}

#[test]
fn v2_ipv6_emits_reflected_frame() {
    let table = make_table(&format!(
        "[retry]\nenabled = true\nmode = \"always\"\ntoken_key = \"{KEY_HEX}\""
    ));
    let quic = build_v2_initial(&[0xaa; 8], &[0xbb; 4], &[]);
    let client = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets();
    let vip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).octets();
    let frame = build_udp_v6(&quic, client, vip, 12345, 4433);
    let mut f = TestFrame::new(&frame);
    assert_eq!(
        f.try_handle_slice(&table, &LOCAL_MAC, 1_000),
        (Outcome::Emitted, Detail::Issued),
    );

    // v2 Retry header check.
    let payload_off = 14 + 40 + 8;
    assert_eq!(f.buf[payload_off], 0xc0);
    assert_eq!(
        &f.buf[payload_off + 1..payload_off + 5],
        &0x6b33_43cfu32.to_be_bytes(),
    );

    // IPv6 UDP checksum is mandatory.
    let udp_off = 14 + 40;
    let cksum = u16::from_be_bytes([f.buf[udp_off + 6], f.buf[udp_off + 7]]);
    assert_ne!(cksum, 0, "IPv6 UDP checksum is mandatory");
}

#[test]
fn v2_valid_token_forwards() {
    let table = make_table(&format!(
        "[retry]\nenabled = true\nmode = \"always\"\ntoken_key = \"{KEY_HEX}\""
    ));
    let retry = table.retry.as_ref().unwrap();
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    let dcid = [0xaa; 8];
    let tok = retry.token_key.mint(src, &dcid, 1_000).unwrap();
    let quic = build_v2_initial(&dcid, &[0xbb; 4], &tok);
    let initial = initial::parse_strict(&quic).unwrap();
    assert_eq!(
        classify(&initial, src, retry, 1_100),
        (Decision::Forward, Detail::TokenValid),
    );
}
