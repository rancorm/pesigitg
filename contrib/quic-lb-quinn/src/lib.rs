// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! Quinn `ConnectionIdGenerator` binding over [`quic_lb_core::QuicLbEncoder`].
//!
//! Re-exports [`Encryption`] from the core crate so callers can keep a
//! single `use quic_lb_quinn::{Encryption, QuicLbCidGenerator};` line.

pub use quic_lb_core::Encryption;
use quic_lb_core::QuicLbEncoder;
use quinn::ConnectionIdGenerator;

/// QUIC-LB CID generator wired into Quinn's `EndpointConfig`.
pub struct QuicLbCidGenerator {
    encoder: QuicLbEncoder,
}

impl QuicLbCidGenerator {
    /// Construct from the same parameters as
    /// [`QuicLbEncoder::new`]; same validation, same semantics.
    pub fn new(
        config_id: u8,
        server_id: Vec<u8>,
        nonce_length: u8,
        encryption: Encryption,
        encode_cid_length: bool,
    ) -> Self {
        Self {
            encoder: QuicLbEncoder::new(
                config_id,
                server_id,
                nonce_length,
                encryption,
                encode_cid_length,
            ),
        }
    }

    /// Build a generator from a pre-constructed encoder. Useful when
    /// a caller wants to share encoder state with non-Quinn paths.
    pub fn from_encoder(encoder: QuicLbEncoder) -> Self {
        Self { encoder }
    }
}

impl ConnectionIdGenerator for QuicLbCidGenerator {
    fn cid_len(&self) -> usize {
        self.encoder.cid_length()
    }

    fn cid_lifetime(&self) -> Option<std::time::Duration> {
        None
    }

    fn generate_cid(&mut self) -> quinn::ConnectionId {
        let bytes = self.encoder.encode_to_vec();
        quinn::ConnectionId::new(&bytes)
    }

    fn validate(&self, id: &quinn::ConnectionId) -> Result<(), quinn_proto::InvalidCid> {
        // Accept any CID with the correct length — the LB will route by
        // decrypting the payload, so validation here is just a sanity check.
        if id.len() == self.encoder.cid_length() {
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
    fn generate_cid_returns_quinn_connection_id_with_correct_length() {
        let mut cid_gen = QuicLbCidGenerator::new(
            0,
            vec![0x00, 0x00, 0x01],
            13,
            Encryption::single_pass(TEST_KEY),
            true,
        );
        let cid = cid_gen.generate_cid();
        assert_eq!(cid.len(), 17);
        assert_eq!(
            <QuicLbCidGenerator as ConnectionIdGenerator>::cid_len(&cid_gen),
            17
        );
    }

    #[test]
    fn validate_accepts_correct_length() {
        let cid_gen = QuicLbCidGenerator::new(0, vec![0x00, 0x01], 5, Encryption::Plaintext, true);
        let bytes = [0u8; 8]; // 1 + 2 + 5
        let id = quinn::ConnectionId::new(&bytes);
        assert!(cid_gen.validate(&id).is_ok());
    }

    #[test]
    fn validate_rejects_wrong_length() {
        let cid_gen = QuicLbCidGenerator::new(0, vec![0x00, 0x01], 5, Encryption::Plaintext, true);
        let bytes = [0u8; 9];
        let id = quinn::ConnectionId::new(&bytes);
        assert!(cid_gen.validate(&id).is_err());
    }
}
