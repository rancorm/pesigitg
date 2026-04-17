// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! QUIC v1/v2 Initial long-header packet parsing.
//!
//! Decodes the public, unprotected portion of an Initial packet per
//! RFC 9000 §17.2.2 (v1) and RFC 9369 §3.1 (v2): version, DCID, SCID,
//! token, and Length varint. The packet number and payload are header-
//! and AEAD-protected and remain opaque to this parser.
//!
//! This parser runs on untrusted Internet input on the hot path. It must
//! be zero-allocation and panic-free on any byte sequence — it is the
//! direct target of the Retry-service fuzz harness.
//!
//! QUIC v1 (`0x00000001`) and v2 (`0x6b3343cf`) are recognized. Other
//! versions, long-header types other than Initial, and short headers all
//! return `Err`. Callers that only care whether a packet *is* a
//! parseable Initial can use [`parse`], which flattens everything to
//! `Option`.
//!
//! v2 uses a different packet-type encoding from v1 (RFC 9369 §3.1):
//! the two type bits in the first byte are scrambled to resist
//! ossification. This parser reads the version field before checking
//! the type bits, branching on the version to select the correct
//! encoding.

/// QUIC v1 version number (RFC 9000 §15).
pub const QUIC_V1: u32 = 0x0000_0001;

/// QUIC v2 version number (RFC 9369 §1).
pub const QUIC_V2: u32 = 0x6b33_43cf;

/// RFC 9000 §17.2 caps v1 DCID/SCID at 20 bytes.
const MAX_CID_LEN: usize = 20;

/// Parsed view over a QUIC v1 or v2 Initial long-header packet.
///
/// All slices borrow from the original packet buffer — no allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Initial<'a> {
    /// First byte of the packet, including header-protected bits.
    pub first_byte: u8,
    /// QUIC version — either [`QUIC_V1`] or [`QUIC_V2`].
    pub version: u32,
    /// Destination Connection ID. At most [`MAX_CID_LEN`] bytes.
    pub dcid: &'a [u8],
    /// Source Connection ID. At most [`MAX_CID_LEN`] bytes.
    pub scid: &'a [u8],
    /// Retry or NEW_TOKEN token; empty if the client hasn't been validated.
    pub token: &'a [u8],
    /// Value of the Length varint — bytes of packet number + payload that
    /// follow. The payload itself is AEAD-protected and not exposed here.
    pub length: u64,
    /// Offset from the start of `packet` at which the packet number begins
    /// (i.e. the byte immediately after the Length varint).
    pub pn_offset: usize,
}

/// Reasons a candidate Initial can fail to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Packet is shorter than the minimum long-header header.
    Truncated,
    /// Header form bit (bit 7) is 0.
    NotLongHeader,
    /// Fixed bit (bit 6) is 0. QUIC v1 requires it set.
    FixedBitUnset,
    /// Long header, but the packet type is not Initial. The type-bit
    /// encoding depends on the version (v2 scrambles the mapping), so
    /// this error is only returned after the version has been identified.
    NotInitial,
    /// Version is not [`QUIC_V1`] or [`QUIC_V2`]. Carries the observed
    /// version so callers can log or count unsupported-version traffic.
    UnsupportedVersion(u32),
    /// DCID length byte is > 20 or its declared bytes overrun the buffer.
    DcidLengthInvalid,
    /// SCID length byte is > 20 or its declared bytes overrun the buffer.
    ScidLengthInvalid,
    /// Token length varint is malformed or its declared bytes overrun the buffer.
    TokenLengthInvalid,
    /// Length varint is malformed.
    LengthInvalid,
    /// Declared Length exceeds the bytes available after the Length varint.
    LengthOverrun,
}

/// Test-only convenience: flatten any parse error into `None`. Production
/// code calls [`parse_strict`] directly so observe-mode metrics can see the
/// specific failure.
#[cfg(test)]
pub(crate) fn parse(packet: &[u8]) -> Option<Initial<'_>> {
    parse_strict(packet).ok()
}

/// Parse a candidate Initial, returning the specific failure reason.
pub fn parse_strict(packet: &[u8]) -> Result<Initial<'_>, ParseError> {
    // Minimum long header: first(1) + version(4) + dcid_len(1) + scid_len(1)
    //                    + token_len_varint(1) + length_varint(1) = 9 bytes.
    if packet.len() < 9 {
        return Err(ParseError::Truncated);
    }

    let first_byte = packet[0];
    if first_byte & 0x80 == 0 {
        return Err(ParseError::NotLongHeader);
    }
    if first_byte & 0x40 == 0 {
        return Err(ParseError::FixedBitUnset);
    }

    let version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);

    // The packet-type encoding differs between v1 and v2 (RFC 9369 §3.1):
    //   v1 Initial = 0b00,  v2 Initial = 0b01
    let ptype = (first_byte >> 4) & 0b11;
    match version {
        QUIC_V1 if ptype != 0b00 => return Err(ParseError::NotInitial),
        QUIC_V2 if ptype != 0b01 => return Err(ParseError::NotInitial),
        QUIC_V1 | QUIC_V2 => {}
        other => return Err(ParseError::UnsupportedVersion(other)),
    }

    let dcid_len = packet[5] as usize;
    if dcid_len > MAX_CID_LEN {
        return Err(ParseError::DcidLengthInvalid);
    }
    let dcid_start = 6;
    let dcid_end = dcid_start + dcid_len;
    // Need at least one more byte for scid_len.
    if packet.len() < dcid_end + 1 {
        return Err(ParseError::DcidLengthInvalid);
    }
    let dcid = &packet[dcid_start..dcid_end];

    let scid_len = packet[dcid_end] as usize;
    if scid_len > MAX_CID_LEN {
        return Err(ParseError::ScidLengthInvalid);
    }
    let scid_start = dcid_end + 1;
    let scid_end = scid_start + scid_len;
    if packet.len() < scid_end {
        return Err(ParseError::ScidLengthInvalid);
    }
    let scid = &packet[scid_start..scid_end];

    // Token Length (varint) + Token.
    let (token_len, tl_size) =
        read_varint(&packet[scid_end..]).ok_or(ParseError::TokenLengthInvalid)?;
    let token_start = scid_end + tl_size;
    let token_end = token_start
        .checked_add(token_len as usize)
        .ok_or(ParseError::TokenLengthInvalid)?;
    if packet.len() < token_end {
        return Err(ParseError::TokenLengthInvalid);
    }
    let token = &packet[token_start..token_end];

    // Length (varint).
    let (length, len_size) =
        read_varint(&packet[token_end..]).ok_or(ParseError::LengthInvalid)?;
    let pn_offset = token_end + len_size;

    // Length covers PN + payload bytes after the Length varint.
    let declared_end = pn_offset
        .checked_add(length as usize)
        .ok_or(ParseError::LengthOverrun)?;
    if packet.len() < declared_end {
        return Err(ParseError::LengthOverrun);
    }

    Ok(Initial {
        first_byte,
        version,
        dcid,
        scid,
        token,
        length,
        pn_offset,
    })
}

/// Decode a QUIC variable-length integer (RFC 9000 §16).
///
/// Returns `(value, bytes_consumed)` on success, `None` if the buffer is
/// empty or too short for the declared size.
#[inline]
fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let size = 1usize << ((first >> 6) as usize);
    if buf.len() < size {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for &byte in &buf[1..size] {
        value = (value << 8) | u64::from(byte);
    }
    Some((value, size))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a varint using the smallest size that fits. Test-only.
    fn write_varint(out: &mut Vec<u8>, value: u64) {
        if value < 1 << 6 {
            out.push(value as u8);
        } else if value < 1 << 14 {
            let v = value as u16 | 0x4000;
            out.extend_from_slice(&v.to_be_bytes());
        } else if value < 1 << 30 {
            let v = value as u32 | 0x8000_0000;
            out.extend_from_slice(&v.to_be_bytes());
        } else if value < 1 << 62 {
            let v = value | 0xc000_0000_0000_0000;
            out.extend_from_slice(&v.to_be_bytes());
        } else {
            panic!("varint overflow in test encoder");
        }
    }

    /// Build a well-formed Initial with the given version, DCID, SCID,
    /// token, and payload. Returns the wire bytes.
    fn build_initial_versioned(
        version: u32,
        dcid: &[u8],
        scid: &[u8],
        token: &[u8],
        payload_len: u64,
    ) -> Vec<u8> {
        let first_byte = match version {
            QUIC_V1 => 0xc0, // long header + fixed bit + v1 Initial type (0b00)
            QUIC_V2 => 0xd0, // long header + fixed bit + v2 Initial type (0b01)
            _ => panic!("test helper only handles v1/v2"),
        };
        let mut out = Vec::new();
        out.push(first_byte);
        out.extend_from_slice(&version.to_be_bytes());
        out.push(dcid.len() as u8);
        out.extend_from_slice(dcid);
        out.push(scid.len() as u8);
        out.extend_from_slice(scid);
        write_varint(&mut out, token.len() as u64);
        out.extend_from_slice(token);
        write_varint(&mut out, payload_len);
        out.extend(std::iter::repeat_n(0xaa, payload_len as usize));
        out
    }

    /// V1 convenience wrapper — used by the majority of existing tests.
    fn build_initial(dcid: &[u8], scid: &[u8], token: &[u8], payload_len: u64) -> Vec<u8> {
        build_initial_versioned(QUIC_V1, dcid, scid, token, payload_len)
    }

    #[test]
    fn parses_minimal_initial_no_token() {
        let dcid = [0xde, 0xad, 0xbe, 0xef];
        let scid = [0x01, 0x02, 0x03, 0x04, 0x05];
        let pkt = build_initial(&dcid, &scid, &[], 20);

        let parsed = parse(&pkt).expect("should parse");
        assert_eq!(parsed.version, QUIC_V1);
        assert_eq!(parsed.dcid, &dcid);
        assert_eq!(parsed.scid, &scid);
        assert!(parsed.token.is_empty());
        assert_eq!(parsed.length, 20);
    }

    #[test]
    fn parses_initial_with_token() {
        let dcid = [0x11; 8];
        let scid = [0x22; 8];
        let token = [0x33; 40];
        let pkt = build_initial(&dcid, &scid, &token, 100);

        let parsed = parse(&pkt).expect("should parse");
        assert_eq!(parsed.token, &token);
        assert_eq!(parsed.length, 100);
        // pn_offset should land right after the Length varint.
        // Length 100 fits in a 2-byte varint, so pn_offset should point past it.
        assert!(parsed.pn_offset < pkt.len());
    }

    #[test]
    fn parses_initial_with_large_token() {
        // Token length requiring a 2-byte varint (>= 64).
        let dcid = [0xaa; 4];
        let scid = [0xbb; 4];
        let token = vec![0xcc; 200];
        let pkt = build_initial(&dcid, &scid, &token, 50);

        let parsed = parse(&pkt).expect("should parse");
        assert_eq!(parsed.token.len(), 200);
        assert_eq!(parsed.length, 50);
    }

    #[test]
    fn parses_initial_with_empty_cids() {
        // v1 allows zero-length DCID and SCID.
        let pkt = build_initial(&[], &[], &[], 10);
        let parsed = parse(&pkt).expect("should parse");
        assert_eq!(parsed.dcid.len(), 0);
        assert_eq!(parsed.scid.len(), 0);
    }

    #[test]
    fn rejects_short_header() {
        // Bit 7 clear → short header, not an Initial.
        let pkt = [0x40, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        assert_eq!(parse_strict(&pkt), Err(ParseError::NotLongHeader));
    }

    #[test]
    fn rejects_fixed_bit_unset() {
        let mut pkt = build_initial(&[0; 4], &[0; 4], &[], 10);
        pkt[0] = 0x80; // long header, but fixed bit clear
        assert_eq!(parse_strict(&pkt), Err(ParseError::FixedBitUnset));
    }

    #[test]
    fn rejects_handshake_packet() {
        // 0xe0 = long header + fixed bit + Handshake type (0b10).
        let mut pkt = build_initial(&[0; 4], &[0; 4], &[], 10);
        pkt[0] = 0xe0;
        assert_eq!(parse_strict(&pkt), Err(ParseError::NotInitial));
    }

    #[test]
    fn rejects_zero_rtt_packet() {
        // 0xd0 = long header + fixed bit + 0-RTT type (0b01).
        let mut pkt = build_initial(&[0; 4], &[0; 4], &[], 10);
        pkt[0] = 0xd0;
        assert_eq!(parse_strict(&pkt), Err(ParseError::NotInitial));
    }

    #[test]
    fn rejects_retry_packet() {
        // 0xf0 = long header + fixed bit + Retry type (0b11).
        let mut pkt = build_initial(&[0; 4], &[0; 4], &[], 10);
        pkt[0] = 0xf0;
        assert_eq!(parse_strict(&pkt), Err(ParseError::NotInitial));
    }

    #[test]
    fn rejects_unknown_version() {
        let mut pkt = build_initial(&[0; 4], &[0; 4], &[], 10);
        // Overwrite version with a hypothetical future version.
        pkt[1..5].copy_from_slice(&0xaaaa_aaaau32.to_be_bytes());
        assert_eq!(
            parse_strict(&pkt),
            Err(ParseError::UnsupportedVersion(0xaaaa_aaaa))
        );
    }

    #[test]
    fn rejects_version_negotiation() {
        // Version 0 indicates Version Negotiation; not an Initial.
        let mut pkt = build_initial(&[0; 4], &[0; 4], &[], 10);
        pkt[1..5].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(parse_strict(&pkt), Err(ParseError::UnsupportedVersion(0)));
    }

    #[test]
    fn rejects_oversized_dcid() {
        let mut pkt = build_initial(&[0; 4], &[0; 4], &[], 10);
        pkt[5] = 21; // dcid_len > MAX_CID_LEN
        assert_eq!(parse_strict(&pkt), Err(ParseError::DcidLengthInvalid));
    }

    #[test]
    fn rejects_oversized_scid() {
        let mut pkt = build_initial(&[0; 4], &[0; 4], &[], 10);
        // scid_len lives at offset 6 + 4 = 10.
        pkt[10] = 21;
        assert_eq!(parse_strict(&pkt), Err(ParseError::ScidLengthInvalid));
    }

    #[test]
    fn rejects_truncated_minimum() {
        // 8 bytes: one short of the absolute minimum.
        let pkt = [0xc0, 0, 0, 0, 1, 0, 0, 0];
        assert_eq!(parse_strict(&pkt), Err(ParseError::Truncated));
    }

    #[test]
    fn rejects_truncated_in_dcid() {
        // Claim dcid_len=10 but only give 2 bytes before scid_len field.
        let mut pkt = Vec::new();
        pkt.push(0xc0);
        pkt.extend_from_slice(&QUIC_V1.to_be_bytes());
        pkt.push(10);
        pkt.extend_from_slice(&[0xaa; 2]);
        // Pad so it passes the initial length>=9 check.
        while pkt.len() < 9 {
            pkt.push(0);
        }
        assert_eq!(parse_strict(&pkt), Err(ParseError::DcidLengthInvalid));
    }

    #[test]
    fn rejects_truncated_in_token() {
        // Well-formed header, token_len=100 varint, but no token bytes.
        let mut pkt = Vec::new();
        pkt.push(0xc0);
        pkt.extend_from_slice(&QUIC_V1.to_be_bytes());
        pkt.push(0); // dcid_len
        pkt.push(0); // scid_len
        write_varint(&mut pkt, 100); // token_len=100
        // No actual token bytes, no Length varint.
        assert_eq!(parse_strict(&pkt), Err(ParseError::TokenLengthInvalid));
    }

    #[test]
    fn rejects_length_overrun() {
        // Well-formed header, Length varint claims more bytes than follow.
        let mut pkt = Vec::new();
        pkt.push(0xc0);
        pkt.extend_from_slice(&QUIC_V1.to_be_bytes());
        pkt.push(0); // dcid_len
        pkt.push(0); // scid_len
        write_varint(&mut pkt, 0); // token_len=0
        write_varint(&mut pkt, 1000); // Length=1000
        // No payload bytes follow.
        assert_eq!(parse_strict(&pkt), Err(ParseError::LengthOverrun));
    }

    #[test]
    fn accepts_trailing_bytes() {
        // Coalesced packets: extra bytes after the declared Length are
        // another QUIC packet and must not cause a parse failure.
        let mut pkt = build_initial(&[0xde; 8], &[0xad; 8], &[], 20);
        pkt.extend_from_slice(&[0xff; 50]);
        assert!(parse(&pkt).is_some());
    }

    // -- varint unit tests --

    #[test]
    fn varint_one_byte() {
        assert_eq!(read_varint(&[0x25]), Some((0x25, 1)));
    }

    #[test]
    fn varint_two_byte() {
        // 0x4025 = 2-byte varint, value 0x25.
        assert_eq!(read_varint(&[0x40, 0x25]), Some((0x25, 2)));
    }

    #[test]
    fn varint_four_byte() {
        assert_eq!(
            read_varint(&[0x80, 0x00, 0x00, 0x25]),
            Some((0x25, 4))
        );
    }

    #[test]
    fn varint_eight_byte() {
        assert_eq!(
            read_varint(&[0xc0, 0, 0, 0, 0, 0, 0, 0x25]),
            Some((0x25, 8))
        );
    }

    #[test]
    fn varint_truncated() {
        // Declares 8 bytes but only 4 present.
        assert_eq!(read_varint(&[0xc0, 0, 0, 0]), None);
    }

    #[test]
    fn varint_empty() {
        assert_eq!(read_varint(&[]), None);
    }

    // -- panic-safety smoke tests (lightweight fuzz) --

    #[test]
    fn no_panic_on_empty() {
        let _ = parse(&[]);
    }

    #[test]
    fn no_panic_on_random_short_inputs() {
        // Every possible 1..=8 byte prefix should parse or error, never panic.
        for len in 0..=8 {
            for seed in 0..=255u8 {
                let buf: Vec<u8> = (0..len).map(|i| seed.wrapping_add(i as u8)).collect();
                let _ = parse(&buf);
            }
        }
    }

    #[test]
    fn no_panic_on_adversarial_lengths() {
        // Various adversarial length byte combinations.
        let cases: &[&[u8]] = &[
            &[0xc0, 0, 0, 0, 1, 0xff],                       // dcid_len=255 only
            &[0xc0, 0, 0, 0, 1, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff],
            &[0xc0, 0, 0, 0, 1, 0, 0xff],                    // scid_len=255
            &[0xc0, 0, 0, 0, 1, 0, 0, 0xff, 0xff, 0xff, 0xff], // varint-ish garbage
        ];
        for pkt in cases {
            let _ = parse(pkt);
        }
    }

    // -- QUIC v2 tests --

    #[test]
    fn parses_v2_initial() {
        let dcid = [0xde, 0xad, 0xbe, 0xef];
        let scid = [0x01, 0x02, 0x03, 0x04, 0x05];
        let pkt = build_initial_versioned(QUIC_V2, &dcid, &scid, &[], 20);

        let parsed = parse(&pkt).expect("v2 Initial should parse");
        assert_eq!(parsed.version, QUIC_V2);
        assert_eq!(parsed.first_byte, 0xd0);
        assert_eq!(parsed.dcid, &dcid);
        assert_eq!(parsed.scid, &scid);
        assert!(parsed.token.is_empty());
        assert_eq!(parsed.length, 20);
    }

    #[test]
    fn parses_v2_initial_with_token() {
        let dcid = [0x11; 8];
        let scid = [0x22; 8];
        let token = [0x33; 40];
        let pkt = build_initial_versioned(QUIC_V2, &dcid, &scid, &token, 100);

        let parsed = parse(&pkt).expect("v2 Initial with token should parse");
        assert_eq!(parsed.version, QUIC_V2);
        assert_eq!(parsed.token, &token);
        assert_eq!(parsed.length, 100);
    }

    #[test]
    fn v2_rejects_v1_type_bits() {
        // 0xc0 has type bits 0b00, which is Initial in v1 but Retry in v2.
        let mut pkt = build_initial_versioned(QUIC_V2, &[0; 4], &[0; 4], &[], 10);
        pkt[0] = 0xc0; // v1-style Initial type bits with v2 version
        assert_eq!(parse_strict(&pkt), Err(ParseError::NotInitial));
    }

    #[test]
    fn v1_rejects_v2_type_bits() {
        // 0xd0 has type bits 0b01, which is Initial in v2 but 0-RTT in v1.
        let mut pkt = build_initial(&[0; 4], &[0; 4], &[], 10);
        pkt[0] = 0xd0; // v2-style Initial type bits with v1 version
        assert_eq!(parse_strict(&pkt), Err(ParseError::NotInitial));
    }

    #[test]
    fn v2_rejects_handshake() {
        // v2 Handshake = type bits 0b11 → first byte 0xf0.
        let mut pkt = build_initial_versioned(QUIC_V2, &[0; 4], &[0; 4], &[], 10);
        pkt[0] = 0xf0;
        assert_eq!(parse_strict(&pkt), Err(ParseError::NotInitial));
    }

    #[test]
    fn v2_rejects_zero_rtt() {
        // v2 0-RTT = type bits 0b10 → first byte 0xe0.
        let mut pkt = build_initial_versioned(QUIC_V2, &[0; 4], &[0; 4], &[], 10);
        pkt[0] = 0xe0;
        assert_eq!(parse_strict(&pkt), Err(ParseError::NotInitial));
    }
}
