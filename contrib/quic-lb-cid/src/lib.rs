// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! QUIC-LB compliant Connection ID generator for Quinn.
//!
//! Implements the server-side CID generation per draft-ietf-quic-load-balancers-21
//! Section 5.4: the server writes its config_id and server_id into the CID, fills
//! the nonce with random bytes, then encrypts the payload block.
//!
//! Supports all three modes:
//! - Plaintext (no key)
//! - Single-pass AES-128-ECB (server_id_length + nonce_length == 16)
//! - Four-pass Feistel (server_id_length + nonce_length != 16)

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use quinn::ConnectionIdGenerator;
use rand::RngCore;

/// CID encryption mode, mirroring pesigitgd's `Encryption` enum.
#[derive(Debug, Clone)]
pub enum Encryption {
    Plaintext,
    SinglePass { key: [u8; 16] },
    FourPass { key: [u8; 16] },
}

/// Generates QUIC-LB compliant Connection IDs for a single server identity.
///
/// Thread-safety: Quinn requires `Send + Sync`. The AES key and server config
/// are immutable after construction; only the RNG state mutates, which is
/// handled by interior mutability through `rand`.
pub struct QuicLbCidGenerator {
    config_id: u8,
    server_id: Vec<u8>,
    nonce_length: u8,
    encryption: Encryption,
    /// Whether to encode CID length in the lower 5 bits of the first octet.
    encode_cid_length: bool,
}

impl QuicLbCidGenerator {
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
    fn cid_length(&self) -> usize {
        1 + self.server_id.len() + self.nonce_length as usize
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
    fn encrypt_single_pass(payload: &mut [u8; 16], key: &[u8; 16]) {
        let cipher = Aes128::new(GenericArray::from_slice(key));
        let mut block = *GenericArray::from_slice(&payload[..]);
        cipher.encrypt_block(&mut block);
        payload.copy_from_slice(&block);
    }

    /// Four-pass Feistel encryption per Section 5.6 of the spec.
    fn encrypt_four_pass(buf: &mut [u8], sid_len: usize, nonce_len: usize, key: &[u8; 16]) {
        let cipher = Aes128::new(GenericArray::from_slice(key));

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

impl ConnectionIdGenerator for QuicLbCidGenerator {
    fn cid_len(&self) -> usize {
        self.cid_length()
    }

    fn cid_lifetime(&self) -> Option<std::time::Duration> {
        None
    }

    fn generate_cid(&mut self) -> quinn::ConnectionId {
        let sid_len = self.server_id.len();
        let nonce_len = self.nonce_length as usize;
        let payload_len = sid_len + nonce_len;

        // Build plaintext payload: server_id || nonce.
        let mut payload = [0u8; 19];
        payload[..sid_len].copy_from_slice(&self.server_id);
        rand::rng().fill_bytes(&mut payload[sid_len..payload_len]);

        // Encrypt in place.
        match &self.encryption {
            Encryption::Plaintext => {}
            Encryption::SinglePass { key } => {
                let mut block = [0u8; 16];
                block[..payload_len].copy_from_slice(&payload[..payload_len]);
                Self::encrypt_single_pass(&mut block, key);
                payload[..16].copy_from_slice(&block);
            }
            Encryption::FourPass { key } => {
                Self::encrypt_four_pass(&mut payload[..payload_len], sid_len, nonce_len, key);
            }
        }

        // Assemble CID: [first_octet][encrypted_payload].
        let cid_len = self.cid_length();
        let mut cid = vec![0u8; cid_len];
        cid[0] = self.first_octet();
        cid[1..].copy_from_slice(&payload[..payload_len]);

        quinn::ConnectionId::new(&cid)
    }

    fn validate(&self, id: &quinn::ConnectionId) -> Result<(), quinn_proto::InvalidCid> {
        // Accept any CID with the correct length — the LB will route by
        // decrypting the payload, so validation here is just a sanity check.
        if id.len() == self.cid_length() {
            Ok(())
        } else {
            Err(quinn_proto::InvalidCid)
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
        let mut cid_gen = QuicLbCidGenerator::new(
            0,
            vec![0x00, 0x00, 0x01],
            13,
            Encryption::SinglePass { key: TEST_KEY },
            true,
        );
        let cid = cid_gen.generate_cid();
        assert_eq!(cid.len(), 17); // 1 + 3 + 13
    }

    #[test]
    fn config_id_encoded_in_top_bits() {
        let mut cid_gen =
            QuicLbCidGenerator::new(3, vec![0x00, 0x01], 5, Encryption::Plaintext, true);
        let cid = cid_gen.generate_cid();
        let bytes: &[u8] = cid.as_ref();
        assert_eq!(bytes[0] >> 5, 3);
    }

    #[test]
    fn plaintext_server_id_readable() {
        let sid = vec![0xde, 0xad, 0xbe];
        let mut cid_gen = QuicLbCidGenerator::new(0, sid.clone(), 4, Encryption::Plaintext, true);
        let cid = cid_gen.generate_cid();
        // In plaintext mode, server_id is at bytes [1..4].
        let bytes: &[u8] = cid.as_ref();
        assert_eq!(&bytes[1..4], &sid[..]);
    }

    #[test]
    fn encrypted_cid_differs_from_plaintext() {
        let sid = vec![0x00, 0x00, 0x01];
        let mut cid_gen_plain =
            QuicLbCidGenerator::new(0, sid.clone(), 13, Encryption::Plaintext, true);
        let mut cid_gen_enc =
            QuicLbCidGenerator::new(0, sid, 13, Encryption::SinglePass { key: TEST_KEY }, true);

        let plain = cid_gen_plain.generate_cid();
        let enc = cid_gen_enc.generate_cid();

        // Encrypted payload should (almost certainly) differ from plaintext.
        // The first octet may match, but the payload won't.
        let plain_bytes: &[u8] = plain.as_ref();
        let enc_bytes: &[u8] = enc.as_ref();
        assert_ne!(plain_bytes[1..], enc_bytes[1..]);
    }

    #[test]
    fn four_pass_generates_valid_length() {
        let mut cid_gen = QuicLbCidGenerator::new(
            1,
            vec![0x00, 0x00, 0x01],
            4,
            Encryption::FourPass { key: TEST_KEY },
            true,
        );
        let cid = cid_gen.generate_cid();
        assert_eq!(cid.len(), 8); // 1 + 3 + 4
        let bytes: &[u8] = cid.as_ref();
        assert_eq!(bytes[0] >> 5, 1);
    }

    #[test]
    fn unique_cids_generated() {
        let mut cid_gen = QuicLbCidGenerator::new(
            0,
            vec![0x00, 0x00, 0x01],
            13,
            Encryption::SinglePass { key: TEST_KEY },
            true,
        );
        let a = cid_gen.generate_cid();
        let b = cid_gen.generate_cid();
        assert_ne!(a, b);
    }
}
