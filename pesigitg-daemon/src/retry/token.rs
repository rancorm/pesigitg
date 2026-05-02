// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! QUIC Retry token mint and verify.
//!
//! Tokens are HMAC-SHA256 signatures binding a client's IP, the
//! Original DCID of the Initial that triggered the Retry, and a
//! millisecond-resolution timestamp. The LB keeps the signing key in
//! RAM and rotates it via SIGHUP along with the rest of the route
//! config (Phase 4 — [`crate::config::route`]).
//!
//! Wire format (24 bytes):
//!
//! ```text
//! timestamp_ms_be (8) || truncated_mac (16)
//! ```
//!
//! The MAC is computed over `(family, ip_octets, timestamp_be, odcid_len,
//! odcid)`; `verify` reconstructs the same tuple from its arguments plus
//! the on-wire timestamp and compares in constant time.
//!
//! This is a **no-shared-state** Retry Service (RFC 9000 §8.1.2): the
//! LB is the only party that signs or checks tokens. Backends trust
//! any Initial that reaches them.

use std::fmt;
use std::net::IpAddr;

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Size of the timestamp prefix (big-endian `u64` milliseconds since
/// the UNIX epoch).
const TS_LEN: usize = 8;

/// Size of the truncated HMAC tag. 16 bytes keeps tokens compact and
/// matches the Retry Integrity Tag width; SHA-256 truncated to 128 bits
/// still provides 2^128 forgery resistance.
const MAC_LEN: usize = 16;

/// Total token length on the wire.
pub const TOKEN_LEN: usize = TS_LEN + MAC_LEN;

/// Maximum ODCID length accepted by the signer. Matches QUIC v1's
/// 20-byte CID cap (RFC 9000 §17.2).
const MAX_ODCID: usize = 20;

/// Errors returned by [`TokenKey::mint`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintError {
    /// ODCID is longer than [`MAX_ODCID`]. Caller bug — the parser
    /// should never admit such a packet to the Retry path.
    OdcidTooLong,
}

/// Reasons [`TokenKey::verify`] may reject a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// Malformed length, wrong MAC, tampered timestamp, or a
    /// future-dated token. Maps to the `retry_token_invalid` counter —
    /// any of these is an attack or a bug.
    Invalid,
    /// MAC is valid but the token is older than `lifetime_ms`. Maps to
    /// the `retry_token_expired` counter. Not an attack signal on its
    /// own — a slow client can trip it legitimately.
    Expired,
}

/// A Retry signing key. 32 bytes is fixed here so the config surface
/// is uniform and rotation is trivial; HMAC itself admits any length.
#[derive(Clone)]
pub struct TokenKey {
    key: [u8; 32],
}

impl fmt::Debug for TokenKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenKey")
            .field("key", &"<redacted>")
            .finish()
    }
}

impl TokenKey {
    /// Construct a signing key from 32 bytes of secret material.
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// True if this key was derived from the same bytes as `other`.
    /// Used by the daemon to detect "same key across reload" so key-age
    /// telemetry doesn't reset on unrelated SIGHUPs. Plain `==` is fine
    /// here — both keys are already in our process memory; this is a
    /// config-equality check, not a secret-vs-attacker comparison.
    pub fn same_key(&self, other: &Self) -> bool {
        self.key == other.key
    }

    /// Mint a token binding `(client, odcid)` to `now_ms`.
    ///
    /// `now_ms` is the millisecond UNIX timestamp at which the token
    /// is being issued. The caller samples the clock — this function
    /// stays pure so the verify path can be exhaustively tested with
    /// deterministic inputs.
    pub fn mint(
        &self,
        client: IpAddr,
        odcid: &[u8],
        now_ms: u64,
    ) -> Result<[u8; TOKEN_LEN], MintError> {
        if odcid.len() > MAX_ODCID {
            return Err(MintError::OdcidTooLong);
        }

        let mut out = [0u8; TOKEN_LEN];
        let ts = now_ms.to_be_bytes();
        out[..TS_LEN].copy_from_slice(&ts);

        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        feed(&mut mac, client, &ts, odcid);
        let full = mac.finalize().into_bytes();
        out[TS_LEN..].copy_from_slice(&full[..MAC_LEN]);
        Ok(out)
    }

    /// Verify a token against the address + ODCID it must be bound to.
    ///
    /// `now_ms` and `lifetime_ms` are supplied by the caller; this
    /// function does not read the clock. MAC validation runs before
    /// the expiry check so the attacker-visible error is the same
    /// regardless of the internal state of the token, and the expiry
    /// branch only runs for inputs that are cryptographically valid.
    pub fn verify(
        &self,
        token: &[u8],
        client: IpAddr,
        odcid: &[u8],
        now_ms: u64,
        lifetime_ms: u64,
    ) -> Result<(), VerifyError> {
        if token.len() != TOKEN_LEN || odcid.len() > MAX_ODCID {
            return Err(VerifyError::Invalid);
        }

        let mut ts_bytes = [0u8; TS_LEN];
        ts_bytes.copy_from_slice(&token[..TS_LEN]);
        let ts_ms = u64::from_be_bytes(ts_bytes);

        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        feed(&mut mac, client, &ts_bytes, odcid);

        // Constant-time truncated-MAC comparison via the hmac crate.
        mac.verify_truncated_left(&token[TS_LEN..])
            .map_err(|_| VerifyError::Invalid)?;

        // Future-dated tokens can't come from an honest mint — treat
        // them as invalid so the `retry_token_invalid` counter fires
        // instead of the benign-sounding `retry_token_expired`.
        if ts_ms > now_ms {
            return Err(VerifyError::Invalid);
        }
        if now_ms - ts_ms > lifetime_ms {
            return Err(VerifyError::Expired);
        }
        Ok(())
    }
}

/// Feed the common `(family, ip, timestamp, odcid)` tuple into an HMAC
/// context. Shared between `mint` and `verify` so the wire
/// representation can never drift between them.
fn feed(mac: &mut HmacSha256, client: IpAddr, ts: &[u8; TS_LEN], odcid: &[u8]) {
    match client {
        IpAddr::V4(v4) => {
            mac.update(&[4u8]);
            mac.update(&v4.octets());
        }
        IpAddr::V6(v6) => {
            mac.update(&[6u8]);
            mac.update(&v6.octets());
        }
    }
    mac.update(ts);
    mac.update(&[odcid.len() as u8]);
    mac.update(odcid);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    fn key() -> TokenKey {
        TokenKey::from_bytes(KEY)
    }

    #[test]
    fn round_trip_ipv4() {
        let client = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
        let odcid = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];
        let t = key().mint(client, &odcid, 1_700_000_000_000).unwrap();
        assert_eq!(t.len(), TOKEN_LEN);

        key()
            .verify(&t, client, &odcid, 1_700_000_000_500, 10_000)
            .expect("fresh token should verify");
    }

    #[test]
    fn round_trip_ipv6() {
        let client = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let odcid = [0x11; 20];
        let t = key().mint(client, &odcid, 42).unwrap();

        key()
            .verify(&t, client, &odcid, 43, 100)
            .expect("v6 round-trip should verify");
    }

    #[test]
    fn rejects_expired_token() {
        let client = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let odcid = [0u8; 4];
        let t = key().mint(client, &odcid, 1_000).unwrap();
        // Issued at 1000, verified at 12000, lifetime 10000 → 11s stale.
        assert_eq!(
            key().verify(&t, client, &odcid, 12_000, 10_000),
            Err(VerifyError::Expired)
        );
    }

    #[test]
    fn accepts_on_expiry_boundary() {
        let client = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let odcid = [0u8; 4];
        let t = key().mint(client, &odcid, 1_000).unwrap();
        // Age exactly == lifetime should still verify.
        key()
            .verify(&t, client, &odcid, 11_000, 10_000)
            .expect("boundary should pass");
    }

    #[test]
    fn rejects_future_dated_token() {
        // A valid MAC can still be built by a mint with a clock ahead
        // of the verify side. Any negative age is treated as Invalid.
        let client = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let odcid = [0u8; 4];
        let t = key().mint(client, &odcid, 5_000).unwrap();
        assert_eq!(
            key().verify(&t, client, &odcid, 4_000, 10_000),
            Err(VerifyError::Invalid)
        );
    }

    #[test]
    fn rejects_client_address_mismatch() {
        let mint_client = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
        let wrong_client = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 43));
        let odcid = [0u8; 4];
        let t = key().mint(mint_client, &odcid, 1_000).unwrap();
        assert_eq!(
            key().verify(&t, wrong_client, &odcid, 1_100, 10_000),
            Err(VerifyError::Invalid)
        );
    }

    #[test]
    fn rejects_v4_vs_v6_mapped_collision() {
        // An attacker-controlled IPv6 that happens to share the octet
        // pattern of a v4 address must not validate — the family byte
        // prefix in `feed` is what prevents the collision.
        let v4 = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1));
        let v6_collision = IpAddr::V6(Ipv6Addr::from([0u8; 16])); // ::0
        let odcid = [0u8; 4];
        let t = key().mint(v4, &odcid, 1_000).unwrap();
        assert_eq!(
            key().verify(&t, v6_collision, &odcid, 1_000, 10_000),
            Err(VerifyError::Invalid)
        );
    }

    #[test]
    fn rejects_odcid_mismatch() {
        let client = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let odcid_a = [0xaau8; 8];
        let odcid_b = [0xbbu8; 8];
        let t = key().mint(client, &odcid_a, 1_000).unwrap();
        assert_eq!(
            key().verify(&t, client, &odcid_b, 1_100, 10_000),
            Err(VerifyError::Invalid)
        );
    }

    #[test]
    fn rejects_odcid_length_ambiguity() {
        // Ensures length-prefixing protects against
        // `(odcid="AB") vs (odcid="")` style collisions.
        let client = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let t = key().mint(client, &[0xab, 0xcd], 1_000).unwrap();
        assert_eq!(
            key().verify(&t, client, &[], 1_000, 10_000),
            Err(VerifyError::Invalid)
        );
    }

    #[test]
    fn rejects_tampered_mac() {
        let client = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let odcid = [0u8; 4];
        let mut t = key().mint(client, &odcid, 1_000).unwrap();
        t[TS_LEN] ^= 0x01;
        assert_eq!(
            key().verify(&t, client, &odcid, 1_100, 10_000),
            Err(VerifyError::Invalid)
        );
    }

    #[test]
    fn rejects_tampered_timestamp() {
        let client = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let odcid = [0u8; 4];
        let mut t = key().mint(client, &odcid, 1_000).unwrap();
        // Shift the timestamp forward — the MAC no longer covers it.
        t[7] ^= 0x10;
        assert_eq!(
            key().verify(&t, client, &odcid, 1_100, 10_000),
            Err(VerifyError::Invalid)
        );
    }

    #[test]
    fn rejects_wrong_length_token() {
        let client = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let odcid = [0u8; 4];
        assert_eq!(
            key().verify(&[0u8; TOKEN_LEN - 1], client, &odcid, 1_000, 10_000),
            Err(VerifyError::Invalid)
        );
        assert_eq!(
            key().verify(&[0u8; TOKEN_LEN + 1], client, &odcid, 1_000, 10_000),
            Err(VerifyError::Invalid)
        );
        assert_eq!(
            key().verify(&[], client, &odcid, 1_000, 10_000),
            Err(VerifyError::Invalid)
        );
    }

    #[test]
    fn rejects_wrong_key() {
        let client = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let odcid = [0u8; 4];
        let t = key().mint(client, &odcid, 1_000).unwrap();

        let mut other_key = KEY;
        other_key[0] ^= 0xff;
        let other = TokenKey::from_bytes(other_key);

        assert_eq!(
            other.verify(&t, client, &odcid, 1_100, 10_000),
            Err(VerifyError::Invalid)
        );
    }

    #[test]
    fn mint_rejects_oversized_odcid() {
        let client = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let too_long = [0u8; MAX_ODCID + 1];
        assert_eq!(
            key().mint(client, &too_long, 1_000),
            Err(MintError::OdcidTooLong)
        );
    }

    #[test]
    fn distinct_tokens_for_distinct_timestamps() {
        // Same inputs, different mint times → different MAC bytes.
        let client = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let odcid = [0u8; 4];
        let a = key().mint(client, &odcid, 1_000).unwrap();
        let b = key().mint(client, &odcid, 1_001).unwrap();
        assert_ne!(a, b);
    }
}
