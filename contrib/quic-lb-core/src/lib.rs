// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! QUIC-LB Connection ID encoder, free of any QUIC stack dependency.
//!
//! Implements server-side CID generation per draft-ietf-quic-load-balancers-21
//! Section 5.4: write `config_id` and `server_id` into the CID, fill the nonce
//! with random bytes, then encrypt the payload block.
//!
//! Three modes, derived from `server_id_length + nonce_length`:
//! - Plaintext (no key)
//! - Single-pass AES-128-ECB (sum == 16)
//! - Four-pass Feistel (sum != 16, ≤ 19)
//!
//! Bindings: [`quic-lb-quinn`](https://docs.rs/quic-lb-quinn) wraps this in
//! Quinn's `ConnectionIdGenerator` trait. For other QUIC stacks (lsquic,
//! msquic, quiche) the encoder is `&self` after construction, so a
//! 30-line shim against any stack's CID hook is straightforward.

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use rand::RngCore;

/// CID encryption mode.
///
/// The pre-computed [`Aes128`] cipher avoids a key schedule per encode
/// (~1500 cycles), mirroring the daemon-side decoder in
/// `pesigitg-routing::route::Encryption`. Use [`Self::single_pass`] /
/// [`Self::four_pass`] to construct — both fields stay public so callers
/// can `match enc { Encryption::SinglePass { key, .. } => ... }`.
pub enum Encryption {
    Plaintext,
    SinglePass { key: [u8; 16], cipher: Aes128 },
    FourPass { key: [u8; 16], cipher: Aes128 },
}

impl Encryption {
    /// Build a single-pass AES-128-ECB encryption mode (used when
    /// `server_id_length + nonce_length == 16`).
    pub fn single_pass(key: [u8; 16]) -> Self {
        Self::SinglePass {
            cipher: Aes128::new(GenericArray::from_slice(&key)),
            key,
        }
    }

    /// Build a four-pass Feistel encryption mode (used when
    /// `server_id_length + nonce_length != 16` and ≤ 19).
    pub fn four_pass(key: [u8; 16]) -> Self {
        Self::FourPass {
            cipher: Aes128::new(GenericArray::from_slice(&key)),
            key,
        }
    }
}

impl Clone for Encryption {
    fn clone(&self) -> Self {
        // `Aes128` doesn't impl `Clone`; rebuild from the raw key.
        // Cold path — encoders aren't cloned per packet.
        match self {
            Self::Plaintext => Self::Plaintext,
            Self::SinglePass { key, .. } => Self::single_pass(*key),
            Self::FourPass { key, .. } => Self::four_pass(*key),
        }
    }
}

impl std::fmt::Debug for Encryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plaintext => write!(f, "Plaintext"),
            Self::SinglePass { .. } => write!(f, "SinglePass"),
            Self::FourPass { .. } => write!(f, "FourPass"),
        }
    }
}

/// QUIC-LB CID encoder for a single server identity.
///
/// Construction validates field ranges via `assert!`; the encoder itself
/// is `&self` thereafter — only the thread-local RNG mutates per encode,
/// so the type is `Send + Sync` and cheap to share across tasks.
pub struct QuicLbEncoder {
    config_id: u8,
    server_id: Vec<u8>,
    nonce_length: u8,
    encryption: Encryption,
    /// Whether to encode CID length in the lower 5 bits of the first octet.
    encode_cid_length: bool,
}

impl QuicLbEncoder {
    pub fn new(
        config_id: u8,
        server_id: Vec<u8>,
        nonce_length: u8,
        encryption: Encryption,
        encode_cid_length: bool,
    ) -> Self {
        assert!(config_id <= 6, "config_id must be 0-6");
        assert!(!server_id.is_empty() && server_id.len() <= 15);
        assert!((4..=18).contains(&nonce_length));
        assert!(server_id.len() + nonce_length as usize <= 19);

        Self {
            config_id,
            server_id,
            nonce_length,
            encryption,
            encode_cid_length,
        }
    }

    /// Total CID length: 1 (first octet) + server_id_length + nonce_length.
    pub fn cid_length(&self) -> usize {
        1 + self.server_id.len() + self.nonce_length as usize
    }

    /// Encode one CID into `buf[..cid_length()]`. Returns the number of
    /// bytes written. Panics if `buf.len() < cid_length()`.
    pub fn encode_into(&self, buf: &mut [u8]) -> usize {
        let cid_len = self.cid_length();
        assert!(
            buf.len() >= cid_len,
            "buf too small: have {}, need {}",
            buf.len(),
            cid_len,
        );

        let sid_len = self.server_id.len();
        let nonce_len = self.nonce_length as usize;
        let payload_len = sid_len + nonce_len;

        // Build plaintext payload: server_id || nonce.
        let mut payload = [0u8; 19];
        payload[..sid_len].copy_from_slice(&self.server_id);
        rand::rng().fill_bytes(&mut payload[sid_len..payload_len]);

        // Encrypt in place using the pre-computed cipher.
        match &self.encryption {
            Encryption::Plaintext => {}
            Encryption::SinglePass { cipher, .. } => {
                let mut block = [0u8; 16];
                block[..payload_len].copy_from_slice(&payload[..payload_len]);
                Self::encrypt_single_pass(&mut block, cipher);
                payload[..16].copy_from_slice(&block);
            }
            Encryption::FourPass { cipher, .. } => {
                Self::encrypt_four_pass(&mut payload[..payload_len], sid_len, nonce_len, cipher);
            }
        }

        buf[0] = self.first_octet();
        buf[1..cid_len].copy_from_slice(&payload[..payload_len]);
        cid_len
    }

    /// Convenience wrapper around [`Self::encode_into`] that allocates
    /// a fresh `Vec`. Quinn's API takes the bytes by reference anyway,
    /// so the owned form costs the same allocation either way.
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let mut buf = vec![0u8; self.cid_length()];
        self.encode_into(&mut buf);
        buf
    }

    /// Build the first octet per Section 3 of the spec.
    ///
    /// Bits 7-5: config_id (3 bits)
    /// Bits 4-0: CID length encoding (if enabled), otherwise random.
    fn first_octet(&self) -> u8 {
        let upper = self.config_id << 5;
        if self.encode_cid_length {
            // Lower 5 bits encode CID length minus 1 (max 20 -> value 19).
            let len_bits = (self.cid_length() as u8).saturating_sub(1) & 0x1f;
            upper | len_bits
        } else {
            // Lower 5 bits are random to reduce linkability.
            let low: u8 = rand::random::<u8>() & 0x1f;
            upper | low
        }
    }

    /// Encrypt the plaintext block (server_id || nonce) using AES-128-ECB.
    fn encrypt_single_pass(payload: &mut [u8; 16], cipher: &Aes128) {
        let mut block = *GenericArray::from_slice(&payload[..]);
        cipher.encrypt_block(&mut block);
        payload.copy_from_slice(&block);
    }

    /// Four-pass Feistel encryption per Section 5.6 of the spec.
    fn encrypt_four_pass(buf: &mut [u8], sid_len: usize, nonce_len: usize, cipher: &Aes128) {
        for i in 0..4u8 {
            let mut block = [0u8; 16];

            if i % 2 == 0 {
                // Even pass: encrypt Right (nonce), XOR into Left (server_id).
                block[..nonce_len].copy_from_slice(&buf[sid_len..sid_len + nonce_len]);
                block[0] ^= i;

                let mut ga = *GenericArray::from_slice(&block);
                cipher.encrypt_block(&mut ga);

                for j in 0..sid_len {
                    buf[j] ^= ga[j];
                }
            } else {
                // Odd pass: encrypt Left (server_id), XOR into Right (nonce).
                block[..sid_len].copy_from_slice(&buf[..sid_len]);
                block[0] ^= i;

                let mut ga = *GenericArray::from_slice(&block);
                cipher.encrypt_block(&mut ga);

                for j in 0..nonce_len {
                    buf[sid_len + j] ^= ga[j];
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    #[test]
    fn cid_has_correct_length() {
        let enc = QuicLbEncoder::new(
            0,
            vec![0x00, 0x00, 0x01],
            13,
            Encryption::single_pass(TEST_KEY),
            true,
        );
        let cid = enc.encode_to_vec();
        assert_eq!(cid.len(), 17); // 1 + 3 + 13
    }

    #[test]
    fn config_id_encoded_in_top_bits() {
        let enc = QuicLbEncoder::new(3, vec![0x00, 0x01], 5, Encryption::Plaintext, true);
        let cid = enc.encode_to_vec();
        assert_eq!(cid[0] >> 5, 3);
    }

    #[test]
    fn plaintext_server_id_readable() {
        let sid = vec![0xde, 0xad, 0xbe];
        let enc = QuicLbEncoder::new(0, sid.clone(), 4, Encryption::Plaintext, true);
        let cid = enc.encode_to_vec();
        // In plaintext mode, server_id is at bytes [1..4].
        assert_eq!(&cid[1..4], &sid[..]);
    }

    #[test]
    fn encrypted_cid_differs_from_plaintext() {
        let sid = vec![0x00, 0x00, 0x01];
        let plain_enc = QuicLbEncoder::new(0, sid.clone(), 13, Encryption::Plaintext, true);
        let aes_enc = QuicLbEncoder::new(0, sid, 13, Encryption::single_pass(TEST_KEY), true);

        let plain = plain_enc.encode_to_vec();
        let aes = aes_enc.encode_to_vec();

        // Encrypted payload should (almost certainly) differ from plaintext.
        // The first octet may match, but the payload won't.
        assert_ne!(plain[1..], aes[1..]);
    }

    #[test]
    fn four_pass_generates_valid_length() {
        let enc = QuicLbEncoder::new(
            1,
            vec![0x00, 0x00, 0x01],
            4,
            Encryption::four_pass(TEST_KEY),
            true,
        );
        let cid = enc.encode_to_vec();
        assert_eq!(cid.len(), 8); // 1 + 3 + 4
        assert_eq!(cid[0] >> 5, 1);
    }

    #[test]
    fn unique_cids_generated() {
        let enc = QuicLbEncoder::new(
            0,
            vec![0x00, 0x00, 0x01],
            13,
            Encryption::single_pass(TEST_KEY),
            true,
        );
        let a = enc.encode_to_vec();
        let b = enc.encode_to_vec();
        assert_ne!(a, b);
    }

    #[test]
    fn encode_into_writes_to_caller_buffer() {
        let enc = QuicLbEncoder::new(0, vec![0xab, 0xcd], 4, Encryption::Plaintext, true);
        let mut buf = [0u8; 7];
        let written = enc.encode_into(&mut buf);
        assert_eq!(written, 7);
        assert_eq!(&buf[1..3], &[0xab, 0xcd]);
    }

    #[test]
    #[should_panic(expected = "buf too small")]
    fn encode_into_panics_on_short_buffer() {
        let enc = QuicLbEncoder::new(0, vec![0xab, 0xcd], 4, Encryption::Plaintext, true);
        let mut buf = [0u8; 3];
        enc.encode_into(&mut buf);
    }
}
