// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! QUIC Retry datapath entry point.
//!
//! Glues the building blocks from [`super::packet`], [`super::token`]
//! and [`crate::quic::initial`] onto a UDP/QUIC frame that has already
//! been routed to the worker by XDP. The worker invokes [`try_handle`]
//! *before* the CID-routing fast path so spoofed-source Initials can be
//! absorbed at the LB without ever reaching a backend.
//!
//! The function's contract is:
//!
//! - Returns [`Outcome::Skip`] for anything that isn't a v1 Initial we
//!   want to touch (wrong family, short header, unsupported version,
//!   retry disabled by config, mode that doesn't emit, etc.).
//!   The worker then falls through to the existing CID/fallback path.
//! - Returns [`Outcome::Forward`] for an Initial whose token proves the
//!   client already owns its source address. Again, worker falls through.
//! - Returns [`Outcome::Emitted`] when the frame has been rewritten
//!   in-place into a Retry response; the worker should push the same
//!   descriptor straight onto the TX ring.
//!
//! Everything stays alloc-free and panic-free on malformed input: parse
//! failures degrade to `Skip`, not a worker crash.

use std::net::IpAddr;

use xsk_rs::umem::frame::DataMut;

use pesigitg_common::{
    ETH_HDR_LEN, ETH_P_IP, ETH_P_IPV6, IPPROTO_UDP, IPV4_MIN_HDR_LEN, IPV6_HDR_LEN, UDP_HDR_LEN,
};

use crate::config::route::{ConfigTable, RetryConfig, RetryMode};
use crate::quic::initial::{self, Initial};

use super::packet::{build_retry, INTEGRITY_TAG_LEN};
use super::token::{TOKEN_LEN, VerifyError};

/// Outcome of the Retry classifier for one received frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Not an Initial we handle — caller must run the normal pipeline.
    Skip,
    /// Client presented a valid token; caller should forward the Initial
    /// to a backend via the existing CID routing path.
    Forward,
    /// Frame was rewritten into a Retry response in place. Caller should
    /// push the descriptor to the TX ring as-is.
    Emitted,
}

/// Fine-grained classification detail for stats recording. Returned
/// alongside [`Outcome`] so the worker loop can advance the appropriate
/// `retry_*` counters without the retry module depending on stats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detail {
    /// Not a packet the retry path touches (disabled, wrong protocol,
    /// port filtered, short header). No retry counters to advance.
    None,
    /// `initial::parse` failed on what appeared to be a QUIC payload.
    ParseError,
    /// Token HMAC valid and fresh — forwarding to backend.
    TokenValid,
    /// Token HMAC mismatch (attack or bug). May have re-issued a Retry.
    TokenInvalid,
    /// Token HMAC valid but expired. May have re-issued a Retry.
    TokenExpired,
    /// No token present (or wrong length), Retry issued.
    Issued,
    /// No token present (or wrong length), mode doesn't emit (observe/load).
    Observed,
}

/// Entry point called from the worker loop.
///
/// `now_ms` is the current wall-clock time in milliseconds; threaded
/// through as a parameter so unit tests can pin it. `local_mac` is the
/// LB's own MAC address — it goes in the source slot of the reflected
/// response.
pub fn try_handle(
    data: &mut DataMut<'_>,
    table: &ConfigTable,
    local_mac: &[u8; 6],
    now_ms: u64,
) -> (Outcome, Detail) {
    let retry = match table.retry.as_ref() {
        Some(r) if r.enabled => r,
        _ => return (Outcome::Skip, Detail::None),
    };

    // Carve out a read-only view of the frame so we can parse and run
    // the policy check before we touch anything. Resize happens via
    // `data.cursor()` later, after we've committed to emitting.
    let layout = match parse_layout(data.contents()) {
        Some(l) => l,
        None => return (Outcome::Skip, Detail::None),
    };

    // Optional per-port scoping. Empty list = every port.
    if !retry.ports.is_empty() && !retry.ports.contains(&layout.dst_port) {
        return (Outcome::Skip, Detail::None);
    }

    // Scope the immutable borrow of `data`: parse the Initial and
    // classify inside the block, then snapshot the CID bytes we need
    // for `emit` so the mutable borrow below does not conflict.
    let mut dcid_buf = [0u8; 20];
    let mut scid_buf = [0u8; 20];
    let dcid_len;
    let scid_len;
    let (decision, detail) = {
        let initial = match initial::parse(&data.contents()[layout.quic_offset..]) {
            Some(i) => i,
            None => return (Outcome::Skip, Detail::ParseError),
        };
        dcid_len = initial.dcid.len();
        scid_len = initial.scid.len();
        dcid_buf[..dcid_len].copy_from_slice(initial.dcid);
        scid_buf[..scid_len].copy_from_slice(initial.scid);
        classify(&initial, layout.src_ip, retry, now_ms)
    };

    match decision {
        Decision::Forward => (Outcome::Forward, detail),
        Decision::Skip => (Outcome::Skip, detail),
        Decision::Emit => {
            let outcome = emit(
                data,
                &layout,
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

/// Frame offsets and 4-tuple extracted from the L2/L3/L4 headers.
///
/// Kept separate from `packet::FrameMeta` because the Retry path needs
/// more fields (IP header length for checksum rewrite, the Ethernet
/// source MAC for reflection) than the CID fast path does.
#[derive(Debug, Clone, Copy)]
struct FrameLayout {
    is_ipv4: bool,
    ip_offset: usize,
    ip_hdr_len: usize,
    udp_offset: usize,
    quic_offset: usize,
    src_mac: [u8; 6],
    #[allow(dead_code)] // populated for completeness; reflected headers use local_mac instead
    dst_mac: [u8; 6],
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
}

fn parse_layout(frame: &[u8]) -> Option<FrameLayout> {
    if frame.len() < ETH_HDR_LEN {
        return None;
    }

    let mut dst_mac = [0u8; 6];
    let mut src_mac = [0u8; 6];
    dst_mac.copy_from_slice(&frame[..6]);
    src_mac.copy_from_slice(&frame[6..12]);

    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);

    match ethertype {
        ETH_P_IP => parse_layout_ipv4(frame, src_mac, dst_mac),
        ETH_P_IPV6 => parse_layout_ipv6(frame, src_mac, dst_mac),
        _ => None,
    }
}

fn parse_layout_ipv4(
    frame: &[u8],
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
) -> Option<FrameLayout> {
    let ip_offset = ETH_HDR_LEN;
    if frame.len() < ip_offset + IPV4_MIN_HDR_LEN {
        return None;
    }
    let ihl = ((frame[ip_offset] & 0x0F) as usize) * 4;
    if ihl < IPV4_MIN_HDR_LEN {
        return None;
    }
    if frame[ip_offset + 9] != IPPROTO_UDP {
        return None;
    }

    let udp_offset = ip_offset + ihl;
    let quic_offset = udp_offset + UDP_HDR_LEN;
    if quic_offset > frame.len() {
        return None;
    }

    let src_ip = IpAddr::from([
        frame[ip_offset + 12],
        frame[ip_offset + 13],
        frame[ip_offset + 14],
        frame[ip_offset + 15],
    ]);
    let dst_ip = IpAddr::from([
        frame[ip_offset + 16],
        frame[ip_offset + 17],
        frame[ip_offset + 18],
        frame[ip_offset + 19],
    ]);
    let src_port = u16::from_be_bytes([frame[udp_offset], frame[udp_offset + 1]]);
    let dst_port = u16::from_be_bytes([frame[udp_offset + 2], frame[udp_offset + 3]]);

    Some(FrameLayout {
        is_ipv4: true,
        ip_offset,
        ip_hdr_len: ihl,
        udp_offset,
        quic_offset,
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
    })
}

fn parse_layout_ipv6(
    frame: &[u8],
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
) -> Option<FrameLayout> {
    // Retry only touches v1 Initials sent directly over IPv6 — extension
    // headers are rejected here to keep the rewrite path simple. The
    // existing CID fast path still walks extensions for forwarding.
    let ip_offset = ETH_HDR_LEN;
    if frame.len() < ip_offset + IPV6_HDR_LEN {
        return None;
    }
    if frame[ip_offset + 6] != IPPROTO_UDP {
        return None;
    }

    let udp_offset = ip_offset + IPV6_HDR_LEN;
    let quic_offset = udp_offset + UDP_HDR_LEN;
    if quic_offset > frame.len() {
        return None;
    }

    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&frame[ip_offset + 8..ip_offset + 24]);
    dst.copy_from_slice(&frame[ip_offset + 24..ip_offset + 40]);

    let src_port = u16::from_be_bytes([frame[udp_offset], frame[udp_offset + 1]]);
    let dst_port = u16::from_be_bytes([frame[udp_offset + 2], frame[udp_offset + 3]]);

    Some(FrameLayout {
        is_ipv4: false,
        ip_offset,
        ip_hdr_len: IPV6_HDR_LEN,
        udp_offset,
        quic_offset,
        src_mac,
        dst_mac,
        src_ip: IpAddr::from(src),
        dst_ip: IpAddr::from(dst),
        src_port,
        dst_port,
    })
}

/// Outcome of the policy decision, before any bytes are rewritten.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    /// Mode is one that doesn't emit (observe/load-without-trigger).
    /// Also covers "no token present but classifier policy says fall
    /// through to normal forwarding".
    Skip,
    /// Valid token already carried by the Initial — the client is known
    /// to own its source address and should be forwarded.
    Forward,
    /// No/invalid/expired token + a mode that emits — mint a fresh
    /// token and rewrite the frame into a Retry.
    Emit,
}

fn classify(
    initial: &Initial<'_>,
    src_ip: IpAddr,
    retry: &RetryConfig,
    now_ms: u64,
) -> (Decision, Detail) {
    // A client that already has a valid token skips Retry in every mode.
    // An invalid/expired token is treated as "no token" — re-Retry so
    // the honest case (stale token after rotation) recovers naturally.
    if initial.token.len() == TOKEN_LEN {
        match retry.token_key.verify(
            initial.token,
            src_ip,
            initial.dcid,
            now_ms,
            retry.token_lifetime_ms,
        ) {
            Ok(()) => return (Decision::Forward, Detail::TokenValid),
            Err(VerifyError::Invalid) => {
                return match retry.mode {
                    RetryMode::Always => (Decision::Emit, Detail::TokenInvalid),
                    RetryMode::Observe | RetryMode::Load => (Decision::Skip, Detail::TokenInvalid),
                };
            }
            Err(VerifyError::Expired) => {
                return match retry.mode {
                    RetryMode::Always => (Decision::Emit, Detail::TokenExpired),
                    RetryMode::Observe | RetryMode::Load => (Decision::Skip, Detail::TokenExpired),
                };
            }
        }
    }

    match retry.mode {
        RetryMode::Always => (Decision::Emit, Detail::Issued),
        // Observe mode walks the whole classify path so counters
        // reflect real decisions, but never emits. Load mode will be
        // wired to a rate tracker in a later phase — until then it
        // degrades to Skip.
        RetryMode::Observe | RetryMode::Load => (Decision::Skip, Detail::Observed),
    }
}

/// Write the Retry response into the frame's UMEM buffer and update the
/// descriptor length. Returns [`Outcome::Emitted`] on success or
/// [`Outcome::Skip`] if building the response failed — the caller then
/// runs the normal pipeline so the packet isn't silently dropped.
fn emit(
    data: &mut DataMut<'_>,
    layout: &FrameLayout,
    odcid: &[u8],
    client_scid: &[u8],
    retry: &RetryConfig,
    local_mac: &[u8; 6],
    now_ms: u64,
) -> Outcome {
    // Mint a fresh token bound to (src_ip, ODCID, now_ms). The ODCID is
    // the DCID the client chose for its unvalidated Initial — per RFC
    // 9000 §17.2.5.1 it also becomes the Retry packet's AAD.
    let token = match retry.token_key.mint(layout.src_ip, odcid, now_ms) {
        Ok(t) => t,
        Err(_) => return Outcome::Skip,
    };

    // Build the Retry packet body into a scratch buffer. The max we can
    // produce is ~(5 + 1 + 20 + 1 + 20 + TOKEN_LEN + 16) ≈ 87 bytes.
    let mut retry_buf = [0u8; 128];
    // RFC 9000 §17.2.5: DCID of the Retry packet echoes the client's
    // SCID; SCID is opaque to the client so we reuse the ODCID — this
    // keeps the rewrite alloc-free and matches other LB implementations.
    let n = match build_retry(
        &mut retry_buf,
        odcid,
        client_scid,
        odcid,
        &token,
    ) {
        Ok(n) => n,
        Err(_) => return Outcome::Skip,
    };
    let retry_bytes = &retry_buf[..n];
    debug_assert!(retry_bytes.len() >= INTEGRITY_TAG_LEN);

    // Lay out headers in a scratch buffer before committing. This keeps
    // the cursor write one contiguous span and avoids partially
    // rewriting the UMEM frame on a late error. Max header = 14 + 40
    // (IPv6) + 8 = 62 bytes.
    let mut hdr_buf = [0u8; 64];
    let hdr_len = build_reflected_headers(&mut hdr_buf, layout, local_mac, retry_bytes.len());

    let total_len = hdr_len + retry_bytes.len();
    if total_len > frame_capacity(data) {
        return Outcome::Skip;
    }

    // Commit: cursor writes the new header + payload and updates the
    // frame descriptor's length.
    {
        let mut cursor = data.cursor();
        cursor.set_pos(0);
        use std::io::Write;
        if cursor.write_all(&hdr_buf[..hdr_len]).is_err() {
            return Outcome::Skip;
        }
        if cursor.write_all(retry_bytes).is_err() {
            return Outcome::Skip;
        }
    }

    // Post-write: fill in the IPv4 header checksum (requires the IP
    // total length field already set above). For IPv6 the UDP checksum
    // is mandatory and covers the pseudo-header — do it after the
    // payload is in place.
    let frame = data.contents_mut();
    if layout.is_ipv4 {
        write_ipv4_checksum(frame, layout.ip_offset, layout.ip_hdr_len);
    } else {
        write_ipv6_udp_checksum(frame, layout);
    }

    Outcome::Emitted
}

/// Total bytes available in the underlying UMEM buffer for this frame.
///
/// `DataMut` only exposes `contents()` up to the *current* length; use
/// the cursor's `buf_len()` (which counts the whole segment) as the
/// capacity check so we reject oversize rewrites before we touch bytes.
fn frame_capacity(data: &mut DataMut<'_>) -> usize {
    data.cursor().buf_len()
}

fn build_reflected_headers(
    out: &mut [u8],
    layout: &FrameLayout,
    local_mac: &[u8; 6],
    payload_len: usize,
) -> usize {
    // Ethernet: the old source becomes the new destination (we reply to
    // whoever handed us the packet). We always use our own MAC as the
    // new source so ARP/ND on the return path behaves like every other
    // locally-originated packet.
    out[0..6].copy_from_slice(&layout.src_mac);
    out[6..12].copy_from_slice(local_mac);

    if layout.is_ipv4 {
        out[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());

        let ip_off = ETH_HDR_LEN;
        // Version(4)/IHL(5) = 0x45, DSCP/ECN = 0.
        out[ip_off] = 0x45;
        out[ip_off + 1] = 0x00;
        let total_len = (IPV4_MIN_HDR_LEN + UDP_HDR_LEN + payload_len) as u16;
        out[ip_off + 2..ip_off + 4].copy_from_slice(&total_len.to_be_bytes());
        // Identification = 0 (DF set), flags/frag = 0x4000.
        out[ip_off + 4..ip_off + 6].copy_from_slice(&[0x00, 0x00]);
        out[ip_off + 6..ip_off + 8].copy_from_slice(&0x4000u16.to_be_bytes());
        // TTL and protocol.
        out[ip_off + 8] = 64;
        out[ip_off + 9] = IPPROTO_UDP;
        // Header checksum placeholder — filled after the slice is
        // written into the frame in [`write_ipv4_checksum`].
        out[ip_off + 10..ip_off + 12].copy_from_slice(&[0, 0]);
        // Src = us (the packet's original dst), Dst = the client.
        let (src, dst) = reflected_v4_addrs(layout);
        out[ip_off + 12..ip_off + 16].copy_from_slice(&src);
        out[ip_off + 16..ip_off + 20].copy_from_slice(&dst);

        let udp_off = ip_off + IPV4_MIN_HDR_LEN;
        out[udp_off..udp_off + 2].copy_from_slice(&layout.dst_port.to_be_bytes());
        out[udp_off + 2..udp_off + 4].copy_from_slice(&layout.src_port.to_be_bytes());
        let udp_len = (UDP_HDR_LEN + payload_len) as u16;
        out[udp_off + 4..udp_off + 6].copy_from_slice(&udp_len.to_be_bytes());
        // UDP checksum: 0 is legal on IPv4 (RFC 768) and is what the
        // rest of the daemon emits, so stay consistent.
        out[udp_off + 6..udp_off + 8].copy_from_slice(&[0, 0]);

        ETH_HDR_LEN + IPV4_MIN_HDR_LEN + UDP_HDR_LEN
    } else {
        out[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());

        let ip_off = ETH_HDR_LEN;
        // Version(6)/TC/FlowLabel = 0x60 00 00 00.
        out[ip_off] = 0x60;
        out[ip_off + 1] = 0x00;
        out[ip_off + 2] = 0x00;
        out[ip_off + 3] = 0x00;
        let payload = (UDP_HDR_LEN + payload_len) as u16;
        out[ip_off + 4..ip_off + 6].copy_from_slice(&payload.to_be_bytes());
        out[ip_off + 6] = IPPROTO_UDP;
        out[ip_off + 7] = 64; // hop limit
        let (src, dst) = reflected_v6_addrs(layout);
        out[ip_off + 8..ip_off + 24].copy_from_slice(&src);
        out[ip_off + 24..ip_off + 40].copy_from_slice(&dst);

        let udp_off = ip_off + IPV6_HDR_LEN;
        out[udp_off..udp_off + 2].copy_from_slice(&layout.dst_port.to_be_bytes());
        out[udp_off + 2..udp_off + 4].copy_from_slice(&layout.src_port.to_be_bytes());
        let udp_len = (UDP_HDR_LEN + payload_len) as u16;
        out[udp_off + 4..udp_off + 6].copy_from_slice(&udp_len.to_be_bytes());
        // Checksum left zero; filled by [`write_ipv6_udp_checksum`].
        out[udp_off + 6..udp_off + 8].copy_from_slice(&[0, 0]);

        ETH_HDR_LEN + IPV6_HDR_LEN + UDP_HDR_LEN
    }
}

fn reflected_v4_addrs(layout: &FrameLayout) -> ([u8; 4], [u8; 4]) {
    // Precondition: caller verified this is an IPv4 layout.
    let IpAddr::V4(src_v4) = layout.src_ip else {
        unreachable!("v4 layout with non-v4 src");
    };
    let IpAddr::V4(dst_v4) = layout.dst_ip else {
        unreachable!("v4 layout with non-v4 dst");
    };
    // Reply source = original destination (our VIP).
    // Reply destination = original source (the client).
    (dst_v4.octets(), src_v4.octets())
}

fn reflected_v6_addrs(layout: &FrameLayout) -> ([u8; 16], [u8; 16]) {
    let IpAddr::V6(src_v6) = layout.src_ip else {
        unreachable!("v6 layout with non-v6 src");
    };
    let IpAddr::V6(dst_v6) = layout.dst_ip else {
        unreachable!("v6 layout with non-v6 dst");
    };
    (dst_v6.octets(), src_v6.octets())
}

fn write_ipv4_checksum(frame: &mut [u8], ip_offset: usize, ip_hdr_len: usize) {
    // Zero the field before summing so we don't fold in a stale value.
    frame[ip_offset + 10] = 0;
    frame[ip_offset + 11] = 0;
    let sum = ones_complement_sum(&frame[ip_offset..ip_offset + ip_hdr_len]);
    frame[ip_offset + 10..ip_offset + 12].copy_from_slice(&sum.to_be_bytes());
}

fn write_ipv6_udp_checksum(frame: &mut [u8], layout: &FrameLayout) {
    let udp_len =
        u16::from_be_bytes([frame[layout.udp_offset + 4], frame[layout.udp_offset + 5]]);
    // Zero before summing.
    frame[layout.udp_offset + 6] = 0;
    frame[layout.udp_offset + 7] = 0;

    // IPv6 pseudo-header (RFC 8200 §8.1):
    //   src (16) || dst (16) || upper-layer-length (4) || zero (3) || next_header (1)
    let mut acc: u32 = 0;
    acc = fold_slice(acc, &frame[layout.ip_offset + 8..layout.ip_offset + 40]);
    acc = acc.wrapping_add(0);
    acc = acc.wrapping_add(u32::from(udp_len));
    acc = acc.wrapping_add(u32::from(IPPROTO_UDP));

    let udp_end = layout.udp_offset + udp_len as usize;
    acc = fold_slice(acc, &frame[layout.udp_offset..udp_end]);

    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    let mut sum = !acc as u16;
    // RFC 768: 0 is reserved as "no checksum"; replace with all-ones.
    if sum == 0 {
        sum = 0xffff;
    }
    frame[layout.udp_offset + 6..layout.udp_offset + 8].copy_from_slice(&sum.to_be_bytes());
}

fn ones_complement_sum(bytes: &[u8]) -> u16 {
    let mut acc: u32 = 0;
    acc = fold_slice(acc, bytes);
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

fn fold_slice(mut acc: u32, bytes: &[u8]) -> u32 {
    let mut i = 0;
    while i + 1 < bytes.len() {
        acc = acc.wrapping_add(u32::from(u16::from_be_bytes([bytes[i], bytes[i + 1]])));
        i += 2;
    }
    if i < bytes.len() {
        acc = acc.wrapping_add(u32::from(bytes[i]) << 8);
    }
    acc
}

#[cfg(test)]
mod tests {
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

    fn build_v1_initial(dcid: &[u8], scid: &[u8], token: &[u8]) -> Vec<u8> {
        // Minimum viable v1 Initial: byte0 = 0xc0 (long header, fixed
        // bit, type=Initial, PN length 1), version 0x00000001, DCID,
        // SCID, token (varint length + bytes), length varint, PN+payload.
        let mut q = Vec::new();
        q.push(0xc0);
        q.extend_from_slice(&0x0000_0001u32.to_be_bytes());
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
            let (decision, detail) = {
                let initial = match initial::parse(&self.buf[layout.quic_offset..self.len]) {
                    Some(i) => i,
                    None => return (Outcome::Skip, Detail::ParseError),
                };
                dcid_len = initial.dcid.len();
                scid_len = initial.scid.len();
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

        fn emit_slice(
            &mut self,
            layout: &FrameLayout,
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
        let initial = initial::parse(&quic).unwrap();
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
        let initial = initial::parse(&quic).unwrap();
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
        let initial = initial::parse(&quic).unwrap();
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
        let initial = initial::parse(&quic).unwrap();
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
        let initial = initial::parse(&quic).unwrap();
        let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        assert_eq!(
            classify(&initial, src, retry, 1_000),
            (Decision::Skip, Detail::Observed),
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
        // Short header byte 0x40 — Initial parser rejects it.
        let mut quic = vec![0x40u8];
        quic.extend_from_slice(&[0xcc; 30]);
        let frame = build_udp_v4(&quic, [203, 0, 113, 1], [10, 0, 0, 1], 12345, 4433);
        let mut f = TestFrame::new(&frame);
        assert_eq!(
            f.try_handle_slice(&table, &LOCAL_MAC, 1_000),
            (Outcome::Skip, Detail::ParseError),
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
}
