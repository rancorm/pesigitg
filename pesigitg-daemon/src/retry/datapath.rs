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
//! - Returns [`Outcome::Skip`] for anything that isn't a v1/v2 Initial
//!   we want to touch (wrong family, short header, unsupported version,
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

use pesigitg_common::{
    ETH_HDR_LEN, ETH_P_IP, ETH_P_IPV6, IPPROTO_UDP, IPV4_MIN_HDR_LEN, IPV6_HDR_LEN, UDP_HDR_LEN,
};

use crate::config::retry::{RetryConfig, RetryMode};
use crate::config::route::ConfigTable;
use crate::frame::FrameView;
use crate::packet::{IpFamily, L4, ParsedFrame};
use crate::quic::initial::{self, Initial, ParseError};

use super::packet::{INTEGRITY_TAG_LEN, build_retry};
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
    /// `initial::parse_strict` failed on what appeared to be a QUIC payload.
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
pub fn try_handle<V: FrameView>(
    data: &mut V,
    parsed: &ParsedFrame,
    table: &ConfigTable,
    local_mac: &[u8; 6],
    now_ms: u64,
    pending_load_initials: &mut u64,
) -> (Outcome, Detail) {
    let retry = match table.retry.as_ref() {
        Some(r) if r.enabled => r,
        _ => return (Outcome::Skip, Detail::None),
    };

    // Promote the shared `ParsedFrame` into the retry-specific layout,
    // rejecting frames the rewrite path cannot handle (non-UDP, IPv6
    // with extension headers).
    let layout = match FrameLayout::from_parsed(parsed) {
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
    let version;
    let (decision, detail) = {
        let quic = &data.contents()[layout.quic_offset..];
        let initial = match initial::parse_strict(quic) {
            Ok(i) => i,
            // Short headers, non-Initial long headers, and
            // unsupported versions — skip silently, no counter.
            Err(ParseError::NotLongHeader)
            | Err(ParseError::NotInitial)
            | Err(ParseError::FixedBitUnset)
            | Err(ParseError::UnsupportedVersion(_))
            | Err(ParseError::Truncated) => return (Outcome::Skip, Detail::None),
            // Anything else looked like a v1/v2 Initial but was malformed.
            Err(_) => return (Outcome::Skip, Detail::ParseError),
        };
        dcid_len = initial.dcid.len();
        scid_len = initial.scid.len();
        version = initial.version;
        dcid_buf[..dcid_len].copy_from_slice(initial.dcid);
        scid_buf[..scid_len].copy_from_slice(initial.scid);
        classify(
            &initial,
            layout.src_ip,
            retry,
            now_ms,
            pending_load_initials,
        )
    };

    match decision {
        Decision::Forward => (Outcome::Forward, detail),
        Decision::Skip => (Outcome::Skip, detail),
        Decision::Emit => {
            let outcome = emit(
                data,
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

/// Frame offsets and 4-tuple extracted from the shared [`ParsedFrame`],
/// narrowed to the subset the Retry rewrite path knows how to handle
/// (UDP only, IPv6 without extension headers).
///
/// Kept separate from [`ParsedFrame`] so emit/checksum helpers can
/// pattern-match on `is_ipv4` without re-asserting "this is UDP" at
/// every call site.
#[derive(Debug, Clone, Copy)]
struct FrameLayout {
    is_ipv4: bool,
    ip_offset: usize,
    ip_hdr_len: usize,
    udp_offset: usize,
    quic_offset: usize,
    src_mac: [u8; 6],
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
}

impl FrameLayout {
    fn from_parsed(parsed: &ParsedFrame) -> Option<Self> {
        let (udp_offset, quic_offset, src_port, dst_port) = match parsed.l4 {
            L4::Udp {
                udp_offset,
                quic_offset,
                src_port,
                dst_port,
            } => (udp_offset, quic_offset, src_port, dst_port),
            L4::Icmp { .. } => return None,
        };
        let is_ipv4 = match parsed.family {
            IpFamily::Ipv4 => true,
            IpFamily::Ipv6 => {
                // Retry only touches Initials sent directly over IPv6
                // — extension headers are rejected here to keep the
                // rewrite path simple.
                if parsed.ip_hdr_len > IPV6_HDR_LEN {
                    return None;
                }
                false
            }
        };
        Some(FrameLayout {
            is_ipv4,
            ip_offset: ETH_HDR_LEN,
            ip_hdr_len: parsed.ip_hdr_len,
            udp_offset,
            quic_offset,
            src_mac: parsed.src_mac,
            src_ip: parsed.src_addr,
            dst_ip: parsed.dst_addr,
            src_port,
            dst_port,
        })
    }
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
    pending_load_initials: &mut u64,
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
                return (
                    load_gated_decision(retry, pending_load_initials),
                    Detail::TokenInvalid,
                );
            }
            Err(VerifyError::Expired) => {
                return (
                    load_gated_decision(retry, pending_load_initials),
                    Detail::TokenExpired,
                );
            }
        }
    }

    match retry.mode {
        RetryMode::Always => (Decision::Emit, Detail::Issued),
        // Observe mode walks the whole classify path so counters
        // reflect real decisions, but never emits.
        RetryMode::Observe => (Decision::Skip, Detail::Observed),
        RetryMode::Load => {
            if load_over_trigger(retry, pending_load_initials) {
                (Decision::Emit, Detail::Issued)
            } else {
                (Decision::Skip, Detail::Observed)
            }
        }
    }
}

/// Collapse `(mode, trigger)` into an Emit/Skip decision for the
/// invalid/expired-token branches. Always → Emit, Observe → Skip, Load
/// → Emit iff the Initial-rate is over the configured trigger.
fn load_gated_decision(retry: &RetryConfig, pending_load_initials: &mut u64) -> Decision {
    match retry.mode {
        RetryMode::Always => Decision::Emit,
        RetryMode::Observe => Decision::Skip,
        RetryMode::Load => {
            if load_over_trigger(retry, pending_load_initials) {
                Decision::Emit
            } else {
                Decision::Skip
            }
        }
    }
}

/// Bump the per-batch local Initial counter and compare the last
/// completed window's rate against the configured trigger. The shared
/// counter is **not** touched here — `record_batch` flushes the
/// per-batch tally at end-of-batch in the worker loop. Precondition:
/// `retry.mode == RetryMode::Load` — `expect`s are validated at config
/// load time.
fn load_over_trigger(retry: &RetryConfig, pending_load_initials: &mut u64) -> bool {
    let tracker = retry
        .load_tracker
        .as_ref()
        .expect("load_tracker is Some when mode is Load");
    let trigger = retry
        .load_trigger_rate
        .expect("load_trigger_rate is Some when mode is Load");
    *pending_load_initials += 1;
    tracker.rate() >= trigger
}

/// Write the Retry response into the frame's UMEM buffer and update the
/// descriptor length. Returns [`Outcome::Emitted`] on success or
/// [`Outcome::Skip`] if building the response failed — the caller then
/// runs the normal pipeline so the packet isn't silently dropped.
#[allow(clippy::too_many_arguments)]
fn emit<V: FrameView>(
    data: &mut V,
    layout: &FrameLayout,
    version: u32,
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
    let n = match build_retry(&mut retry_buf, version, odcid, client_scid, odcid, &token) {
        Ok(n) => n,
        Err(_) => return Outcome::Skip,
    };
    let retry_bytes = &retry_buf[..n];
    debug_assert!(retry_bytes.len() >= INTEGRITY_TAG_LEN);

    // Lay out headers in a scratch buffer before committing. Max
    // header = 14 + 40 (IPv6) + 8 = 62 bytes.
    let mut hdr_buf = [0u8; 64];
    let hdr_len = build_reflected_headers(&mut hdr_buf, layout, local_mac, retry_bytes.len());

    let total_len = hdr_len + retry_bytes.len();

    // Commit: resize the frame to the new total and copy header +
    // payload into place. `resize` returns `None` if `total_len`
    // exceeds the chunk capacity.
    let frame = match data.resize(total_len) {
        Some(buf) => buf,
        None => return Outcome::Skip,
    };
    frame[..hdr_len].copy_from_slice(&hdr_buf[..hdr_len]);
    frame[hdr_len..total_len].copy_from_slice(retry_bytes);

    // Post-write: fill in the IPv4 header checksum (requires the IP
    // total length field already set above). For IPv6 the UDP checksum
    // is mandatory and covers the pseudo-header — do it after the
    // payload is in place.
    if layout.is_ipv4 {
        write_ipv4_checksum(frame, layout.ip_offset, layout.ip_hdr_len);
    } else {
        write_ipv6_udp_checksum(frame, layout);
    }

    Outcome::Emitted
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
    let udp_len = u16::from_be_bytes([frame[layout.udp_offset + 4], frame[layout.udp_offset + 5]]);
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
#[path = "datapath_tests.rs"]
mod tests;
