// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! QUIC v1/v2 Retry packet construction and integrity tag.
//!
//! Implements RFC 9001 §5.8 (v1) and RFC 9369 §3.2 (v2): a Retry
//! packet ends with a 128-bit AEAD_AES_128_GCM authentication tag
//! computed over a pseudo-packet (the client's Original Destination CID
//! followed by the Retry packet bytes minus the tag itself). The key
//! and nonce are version-specific public constants fixed by the spec —
//! they are not secret; they prove the sender understood the incoming
//! Initial and produced a well-formed Retry in response. The
//! unguessable part is the token payload, minted elsewhere (Phase 3 —
//! [`super::token`]).
//!
//! This file owns the wire format only: build the bytes, compute the
//! tag. Policy (when to Retry), token mint/verify, and datapath
//! integration live in sibling modules.

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes128Gcm, Nonce,
};

use crate::quic::initial::{QUIC_V1, QUIC_V2};

/// RFC 9001 §5.8 v1 Retry Integrity Tag key.
const RETRY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
    0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];

/// RFC 9001 §5.8 v1 Retry Integrity Tag nonce.
const RETRY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2,
    0x23, 0x98, 0x25, 0xbb,
];

/// RFC 9369 §3.2 v2 Retry Integrity Tag key.
const RETRY_KEY_V2: [u8; 16] = [
    0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2,
    0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92,
];

/// RFC 9369 §3.2 v2 Retry Integrity Tag nonce.
const RETRY_NONCE_V2: [u8; 12] = [
    0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99,
    0x90, 0xef, 0xb0, 0x4a,
];

/// Size of the trailing integrity tag.
pub const INTEGRITY_TAG_LEN: usize = 16;

/// RFC 9000 §17.2 caps v1 CID length at 20 bytes.
const MAX_CID_LEN: usize = 20;

/// Upper bound on the stack buffer used for the pseudo-packet AAD.
///
/// The pseudo-packet is `1 + odcid + retry_without_tag`. With max CIDs
/// that is `1 + 20 + (5 + 1 + 20 + 1 + 20 + token)` = `68 + token`. A
/// 1 KiB ceiling leaves ~960 bytes for the token, which is far above
/// what we actually mint (48-64 bytes).
const PSEUDO_MAX: usize = 1024;

/// Errors raised while building a Retry packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildError {
    /// Caller's output slice is shorter than the assembled Retry packet.
    OutputTooSmall,
    /// A CID argument exceeds the 20-byte v1/v2 limit.
    CidTooLong,
    /// The pseudo-packet would exceed [`PSEUDO_MAX`]. Cap the token length
    /// or bump the buffer.
    PseudoTooLong,
    /// Version is not v1 or v2.
    UnsupportedVersion,
}

/// Build a QUIC Retry packet into `out` for the given `version`.
///
/// - `version` selects the wire encoding: [`QUIC_V1`] or [`QUIC_V2`].
///   v2 uses a different first-byte type encoding and different
///   integrity-tag constants (RFC 9369 §3.2).
/// - `odcid` is the client's Original Destination CID, taken from the
///   Initial that triggered the Retry. It feeds the tag AAD only — it
///   is **not** written to the wire.
/// - `dcid` is the Retry packet's Destination CID. RFC 9000 §17.2.5
///   requires this to equal the client's Source CID, so the client
///   recognizes the response and binds it to its handshake state.
/// - `scid` is the Retry packet's Source CID. Opaque to the client; the
///   client echoes it as the DCID of the retransmitted Initial.
/// - `token` is the opaque byte string the client must return on the
///   retransmitted Initial to prove address ownership.
///
/// Returns the number of bytes written to `out` on success. The four
/// "unused" bits of the first byte are set to 0; RFC 9001 §5.8 calls
/// them "arbitrary" and clients ignore them.
pub fn build_retry(
    out: &mut [u8],
    version: u32,
    odcid: &[u8],
    dcid: &[u8],
    scid: &[u8],
    token: &[u8],
) -> Result<usize, BuildError> {
    if odcid.len() > MAX_CID_LEN
        || dcid.len() > MAX_CID_LEN
        || scid.len() > MAX_CID_LEN
    {
        return Err(BuildError::CidTooLong);
    }

    // Retry type bits differ between versions (RFC 9369 §3.1):
    //   v1 Retry = 0b11 → first byte 0xf0
    //   v2 Retry = 0b00 → first byte 0xc0
    let first_byte = match version {
        QUIC_V1 => 0xf0,
        QUIC_V2 => 0xc0,
        _ => return Err(BuildError::UnsupportedVersion),
    };

    // first(1) + version(4) + dcid_len(1) + dcid + scid_len(1) + scid + token
    let body_len = 1 + 4 + 1 + dcid.len() + 1 + scid.len() + token.len();
    let total = body_len + INTEGRITY_TAG_LEN;
    if out.len() < total {
        return Err(BuildError::OutputTooSmall);
    }

    out[0] = first_byte;
    out[1..5].copy_from_slice(&version.to_be_bytes());
    let mut off = 5;
    out[off] = dcid.len() as u8;
    off += 1;
    out[off..off + dcid.len()].copy_from_slice(dcid);
    off += dcid.len();
    out[off] = scid.len() as u8;
    off += 1;
    out[off..off + scid.len()].copy_from_slice(scid);
    off += scid.len();
    out[off..off + token.len()].copy_from_slice(token);
    off += token.len();
    debug_assert_eq!(off, body_len);

    let tag = compute_integrity_tag(version, odcid, &out[..body_len])?;
    out[body_len..total].copy_from_slice(&tag);
    Ok(total)
}

/// Compute the 16-byte Retry Integrity Tag over a pseudo-packet.
///
/// The pseudo-packet is:
///
/// ```text
/// ODCID_len (1) || ODCID || retry_without_tag
/// ```
///
/// where `retry_without_tag` is the full Retry packet minus its
/// trailing 16-byte tag. `version` selects the key/nonce pair:
/// v1 uses RFC 9001 §5.8 constants, v2 uses RFC 9369 §3.2 constants.
///
/// Exposed so the RFC 9001 Appendix A.4 test vector can be checked
/// directly, and so callers who assemble the Retry bytes by hand can
/// attach a tag without round-tripping through [`build_retry`].
pub fn compute_integrity_tag(
    version: u32,
    odcid: &[u8],
    retry_without_tag: &[u8],
) -> Result<[u8; INTEGRITY_TAG_LEN], BuildError> {
    if odcid.len() > MAX_CID_LEN {
        return Err(BuildError::CidTooLong);
    }

    let (key, iv) = match version {
        QUIC_V1 => (&RETRY_KEY_V1, &RETRY_NONCE_V1),
        QUIC_V2 => (&RETRY_KEY_V2, &RETRY_NONCE_V2),
        _ => return Err(BuildError::UnsupportedVersion),
    };

    let pseudo_len = 1 + odcid.len() + retry_without_tag.len();
    if pseudo_len > PSEUDO_MAX {
        return Err(BuildError::PseudoTooLong);
    }

    let mut pseudo = [0u8; PSEUDO_MAX];
    pseudo[0] = odcid.len() as u8;
    pseudo[1..1 + odcid.len()].copy_from_slice(odcid);
    pseudo[1 + odcid.len()..pseudo_len].copy_from_slice(retry_without_tag);

    let cipher = Aes128Gcm::new_from_slice(key)
        .expect("Retry key is exactly 16 bytes");
    let nonce = Nonce::from_slice(iv);

    // AAD-only authentication: empty plaintext → no ciphertext, the
    // returned tag is the GCM MAC over the AAD.
    let mut empty: [u8; 0] = [];
    let tag = cipher
        .encrypt_in_place_detached(nonce, &pseudo[..pseudo_len], &mut empty)
        .expect("AES-GCM over empty plaintext cannot fail");

    let mut out = [0u8; INTEGRITY_TAG_LEN];
    out.copy_from_slice(tag.as_slice());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 9001 Appendix A.4 worked example.
    //
    //   ODCID: 8394c8f03e515708
    //   Retry: ff000000010008f067a5502a4262b5746f6b656e
    //          04a265ba2eff4d829058fb3f0f2496ba
    //
    // Breakdown of the Retry:
    //   ff                         first byte (retry type, all unused bits set)
    //   00000001                   version
    //   00                         dcid_len
    //                              (empty dcid)
    //   08                         scid_len
    //   f067a5502a4262b5           scid
    //   746f6b656e                 token = b"token"
    //   04a265ba2eff4d82 9058fb3f 0f2496ba    integrity tag
    //
    // Note: the RFC vector uses 0xff for the first byte (all unused bits
    // set). Our builder writes 0xf0 (unused bits cleared). The low-level
    // `compute_integrity_tag` test below feeds the RFC bytes directly so
    // it still matches the published tag.
    const RFC_ODCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    const RFC_RETRY_NO_TAG: &[u8] = &[
        0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5,
        0x74, 0x6f, 0x6b, 0x65, 0x6e,
    ];
    const RFC_EXPECTED_TAG: [u8; 16] = [
        0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96,
        0xba,
    ];

    #[test]
    fn rfc9001_a4_integrity_tag() {
        let tag = compute_integrity_tag(QUIC_V1, &RFC_ODCID, RFC_RETRY_NO_TAG).unwrap();
        assert_eq!(tag, RFC_EXPECTED_TAG, "RFC 9001 A.4 vector mismatch");
    }

    #[test]
    fn build_retry_v1_layout_and_self_consistent_tag() {
        let odcid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let dcid = [0x11, 0x22, 0x33, 0x44];
        let scid = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let token = [0x42u8; 32];

        let mut out = [0u8; 256];
        let n = build_retry(&mut out, QUIC_V1, &odcid, &dcid, &scid, &token).unwrap();
        assert_eq!(n, 1 + 4 + 1 + 4 + 1 + 6 + 32 + INTEGRITY_TAG_LEN);

        // First byte: long header + fixed + v1 Retry type (0b11), unused bits cleared.
        assert_eq!(out[0], 0xf0);
        assert_eq!(&out[1..5], &QUIC_V1.to_be_bytes());

        assert_eq!(out[5], 4);
        assert_eq!(&out[6..10], &dcid);
        assert_eq!(out[10], 6);
        assert_eq!(&out[11..17], &scid);
        assert_eq!(&out[17..49], &token);

        // Recompute the tag from the body and verify self-consistency.
        let recomputed = compute_integrity_tag(QUIC_V1, &odcid, &out[..n - INTEGRITY_TAG_LEN]).unwrap();
        assert_eq!(&out[n - INTEGRITY_TAG_LEN..n], &recomputed);
    }

    #[test]
    fn build_retry_v1_minimal() {
        // Empty DCID, empty SCID, empty token — smallest legal Retry.
        let odcid = [0u8; 4];
        let mut out = [0u8; 32];
        let n = build_retry(&mut out, QUIC_V1, &odcid, &[], &[], &[]).unwrap();
        // 1 (first) + 4 (version) + 1 (dcid_len) + 1 (scid_len) + 16 (tag)
        assert_eq!(n, 23);
        assert_eq!(out[0], 0xf0);
        assert_eq!(out[5], 0);
        assert_eq!(out[6], 0);
    }

    #[test]
    fn build_retry_v1_differs_when_odcid_differs() {
        // Tag must bind the ODCID: changing only the ODCID must change
        // the tag, otherwise a replay from one connection could be
        // delivered to another.
        let dcid = [0u8; 4];
        let scid = [0u8; 4];
        let token = [0u8; 16];

        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        let n_a = build_retry(&mut a, QUIC_V1, &[0u8; 8], &dcid, &scid, &token).unwrap();
        let n_b = build_retry(&mut b, QUIC_V1, &[0xffu8; 8], &dcid, &scid, &token).unwrap();
        assert_eq!(n_a, n_b);
        // Body up to the tag is identical; tag must differ.
        assert_eq!(&a[..n_a - 16], &b[..n_b - 16]);
        assert_ne!(&a[n_a - 16..n_a], &b[n_b - 16..n_b]);
    }

    #[test]
    fn rejects_oversized_cids() {
        let long = [0u8; 21];
        let ok = [0u8; 4];
        let mut out = [0u8; 256];

        assert_eq!(
            build_retry(&mut out, QUIC_V1, &long, &ok, &ok, &[]),
            Err(BuildError::CidTooLong)
        );
        assert_eq!(
            build_retry(&mut out, QUIC_V1, &ok, &long, &ok, &[]),
            Err(BuildError::CidTooLong)
        );
        assert_eq!(
            build_retry(&mut out, QUIC_V1, &ok, &ok, &long, &[]),
            Err(BuildError::CidTooLong)
        );
    }

    #[test]
    fn rejects_output_too_small() {
        let odcid = [0u8; 8];
        let dcid = [0u8; 4];
        let scid = [0u8; 4];
        let token = [0u8; 32];

        // Need: 1 + 4 + 1 + 4 + 1 + 4 + 32 + 16 = 63. Give 62.
        let mut out = [0u8; 62];
        assert_eq!(
            build_retry(&mut out, QUIC_V1, &odcid, &dcid, &scid, &token),
            Err(BuildError::OutputTooSmall)
        );
    }

    #[test]
    fn rejects_pseudo_too_long() {
        let odcid = [0u8; 20];
        // Any retry body larger than PSEUDO_MAX - 1 - 20 triggers the cap.
        let retry_body = [0u8; PSEUDO_MAX];
        assert_eq!(
            compute_integrity_tag(QUIC_V1, &odcid, &retry_body),
            Err(BuildError::PseudoTooLong)
        );
    }

    #[test]
    fn compute_integrity_tag_rejects_oversized_odcid() {
        let long = [0u8; 21];
        assert_eq!(
            compute_integrity_tag(QUIC_V1, &long, &[]),
            Err(BuildError::CidTooLong)
        );
    }

    // -- QUIC v2 Retry tests --

    #[test]
    fn build_retry_v2_layout() {
        let odcid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let dcid = [0x11, 0x22, 0x33, 0x44];
        let scid = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let token = [0x42u8; 32];

        let mut out = [0u8; 256];
        let n = build_retry(&mut out, QUIC_V2, &odcid, &dcid, &scid, &token).unwrap();
        assert_eq!(n, 1 + 4 + 1 + 4 + 1 + 6 + 32 + INTEGRITY_TAG_LEN);

        // First byte: long header + fixed + v2 Retry type (0b00), unused bits cleared.
        assert_eq!(out[0], 0xc0);
        assert_eq!(&out[1..5], &QUIC_V2.to_be_bytes());

        // Recompute the tag and verify self-consistency.
        let recomputed = compute_integrity_tag(QUIC_V2, &odcid, &out[..n - INTEGRITY_TAG_LEN]).unwrap();
        assert_eq!(&out[n - INTEGRITY_TAG_LEN..n], &recomputed);
    }

    #[test]
    fn v1_and_v2_tags_differ_for_same_inputs() {
        // Same CIDs, same token — different versions must produce
        // different integrity tags because the key/nonce and version
        // field differ.
        let odcid = [0xaa; 8];
        let dcid = [0xbb; 4];
        let scid = [0xcc; 4];
        let token = [0xdd; 16];

        let mut v1 = [0u8; 128];
        let mut v2 = [0u8; 128];
        let n1 = build_retry(&mut v1, QUIC_V1, &odcid, &dcid, &scid, &token).unwrap();
        let n2 = build_retry(&mut v2, QUIC_V2, &odcid, &dcid, &scid, &token).unwrap();
        assert_eq!(n1, n2);
        // Tags occupy the last 16 bytes.
        assert_ne!(&v1[n1 - 16..n1], &v2[n2 - 16..n2]);
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut out = [0u8; 128];
        assert_eq!(
            build_retry(&mut out, 0xdeadbeef, &[0; 4], &[0; 4], &[0; 4], &[0; 16]),
            Err(BuildError::UnsupportedVersion)
        );
        assert_eq!(
            compute_integrity_tag(0xdeadbeef, &[0; 4], &[0; 16]),
            Err(BuildError::UnsupportedVersion)
        );
    }
}
