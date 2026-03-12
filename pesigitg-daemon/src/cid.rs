//! QUIC-LB Connection ID extraction and decryption.
//!
//! Implements CID decryption per draft-ietf-quic-load-balancers-21:
//! - Plaintext (no encryption)
//! - Single-pass AES-128-ECB (server_id_length + nonce_length == 16)
//! - Four-pass block cipher (Feistel construction)

use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};

use crate::config::route::{Encryption, RouteConfig};

/// Extract raw DCID bytes from a QUIC packet without validating the config
/// rotation ID. Used for connection table lookups on unroutable packets.
pub fn extract_raw_dcid<'a>(quic: &'a [u8], cid_length: u8) -> Option<&'a [u8]> {
    extract_dcid_bytes(quic, cid_length)
}

/// Extract the DCID from a QUIC packet payload (starting after the UDP header).
///
/// Returns the DCID slice, or `None` if the packet is malformed or the
/// config_id in the CID first octet doesn't match the active configuration.
pub fn extract_dcid<'a>(quic: &'a [u8], config: &RouteConfig) -> Option<&'a [u8]> {
    let dcid = extract_dcid_bytes(quic, config.cid_length())?;

    // Top 3 bits of the first CID octet carry the config rotation id.
    // Value 7 (0b111) is reserved for fallback/unroutable.
    let cid_config_id = dcid[0] >> 5;
    if cid_config_id == 7 || cid_config_id != config.config_id {
        return None;
    }

    Some(dcid)
}

/// Common DCID byte extraction for both long and short headers.
fn extract_dcid_bytes<'a>(quic: &'a [u8], cid_length: u8) -> Option<&'a [u8]> {
    if quic.is_empty() {
        return None;
    }

    let is_long = quic[0] & 0x80 != 0;

    let dcid = if is_long {
        // Long Header: [header(1)][version(4)][dcid_len(1)][dcid(..)]
        if quic.len() < 6 {
            return None;
        }
        let dcid_len = quic[5] as usize;
        let end = 6 + dcid_len;
        if quic.len() < end {
            return None;
        }
        &quic[6..end]
    } else {
        // Short Header: [header(1)][dcid(cid_length bytes)]
        let cid_len = cid_length as usize;
        let end = 1 + cid_len;
        if quic.len() < end {
            return None;
        }
        &quic[1..end]
    };

    if dcid.is_empty() {
        return None;
    }

    Some(dcid)
}

/// Decrypt the CID payload and return the index of the matching backend server.
///
/// Performs zero heap allocations — decryption works on a stack buffer.
pub fn resolve_server_idx(dcid: &[u8], config: &RouteConfig) -> Option<usize> {
    let payload_len = config.cid_payload_length() as usize;
    let sid_len = config.server_id_length as usize;

    if dcid.len() < 1 + payload_len {
        return None;
    }

    // Copy payload to stack buffer for in-place decryption.
    // Max payload = server_id(15) + nonce(18) capped at 19.
    let mut buf = [0u8; 19];
    buf[..payload_len].copy_from_slice(&dcid[1..1 + payload_len]);

    match &config.encryption {
        Encryption::Plaintext => {}
        Encryption::SinglePass { key } => {
            decrypt_single_pass(&mut buf, key);
        }
        Encryption::FourPass { key } => {
            decrypt_four_pass(&mut buf, sid_len, payload_len - sid_len, key);
        }
    }

    config.find_server_idx(&buf[..sid_len])
}

/// AES-128-ECB decrypt a 16-byte block in place.
fn decrypt_single_pass(buf: &mut [u8; 19], key: &[u8; 16]) {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut block = *GenericArray::from_slice(&buf[..16]);
    cipher.decrypt_block(&mut block);
    buf[..16].copy_from_slice(&block);
}

/// Four-pass Feistel decryption.
///
/// Reverses the encryption by running passes 3, 2, 1, 0. Each pass
/// uses AES-ECB *encrypt* (Feistel round functions are always forward).
fn decrypt_four_pass(buf: &mut [u8; 19], sid_len: usize, nonce_len: usize, key: &[u8; 16]) {
    let cipher = Aes128::new(GenericArray::from_slice(key));

    for i in (0..4u8).rev() {
        let mut block = [0u8; 16];

        if i % 2 == 1 {
            // Odd pass: encrypt Left (server_id), XOR into Right (nonce)
            block[..sid_len].copy_from_slice(&buf[..sid_len]);
            block[0] ^= i;
            let mut ga = *GenericArray::from_slice(&block);
            cipher.encrypt_block(&mut ga);
            for j in 0..nonce_len {
                buf[sid_len + j] ^= ga[j];
            }
        } else {
            // Even pass: encrypt Right (nonce), XOR into Left (server_id)
            block[..nonce_len].copy_from_slice(&buf[sid_len..sid_len + nonce_len]);
            block[0] ^= i;
            let mut ga = *GenericArray::from_slice(&block);
            cipher.encrypt_block(&mut ga);
            for j in 0..sid_len {
                buf[j] ^= ga[j];
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::route::Server;
    use std::path::PathBuf;

    const TEST_KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];

    fn make_config(encryption: Encryption, config_id: u8, sid_len: u8, nonce_len: u8) -> RouteConfig {
        RouteConfig {
            path: PathBuf::new(),
            config_id,
            first_octet_encodes_cid_length: true,
            server_id_length: sid_len,
            nonce_length: nonce_len,
            encryption,
            servers: vec![
                Server {
                    id: vec![0x00, 0x00, 0x01],
                    address: "10.0.1.10".parse().unwrap(),
                    mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]),
                },
                Server {
                    id: vec![0x00, 0x00, 0x02],
                    address: "10.0.1.11".parse().unwrap(),
                    mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02]),
                },
            ],
        }
    }

    /// Encrypt using four-pass Feistel (forward direction, for test vectors).
    fn encrypt_four_pass(buf: &mut [u8], sid_len: usize, nonce_len: usize, key: &[u8; 16]) {
        let cipher = Aes128::new(GenericArray::from_slice(key));

        for i in 0..4u8 {
            let mut block = [0u8; 16];

            if i % 2 == 0 {
                block[..nonce_len].copy_from_slice(&buf[sid_len..sid_len + nonce_len]);
                block[0] ^= i;
                let mut ga = *GenericArray::from_slice(&block);
                cipher.encrypt_block(&mut ga);
                for j in 0..sid_len {
                    buf[j] ^= ga[j];
                }
            } else {
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

    // -- extract_dcid tests --

    #[test]
    fn extract_dcid_long_header() {
        let config = make_config(Encryption::Plaintext, 0, 3, 13);

        // Long Header: first byte 0xC0 (form=1, fixed=1, type=Initial)
        // Version: [0x00, 0x00, 0x00, 0x01]
        // DCID length: 17 (1 + 3 + 13)
        // DCID: [first_octet=0x00 (config_id=0)][server_id: 3B][nonce: 13B]
        let mut quic = vec![0xc0];
        quic.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // version
        quic.push(17); // dcid_len
        // CID: config_id=0 in top 3 bits -> first octet = 0x00
        quic.push(0x00); // first octet
        quic.extend_from_slice(&[0x00, 0x00, 0x01]); // server_id
        quic.extend_from_slice(&[0xaa; 13]); // nonce

        let dcid = extract_dcid(&quic, &config).unwrap();
        assert_eq!(dcid.len(), 17);
        assert_eq!(dcid[0] >> 5, 0); // config_id
        assert_eq!(&dcid[1..4], &[0x00, 0x00, 0x01]); // server_id
    }

    #[test]
    fn extract_dcid_short_header() {
        let config = make_config(Encryption::Plaintext, 0, 3, 13);

        // Short Header: first byte 0x40 (form=0, fixed=1)
        // DCID starts at byte 1, length = cid_length = 17
        let mut quic = vec![0x40];
        quic.push(0x00); // first CID octet (config_id=0)
        quic.extend_from_slice(&[0x00, 0x00, 0x02]); // server_id
        quic.extend_from_slice(&[0xbb; 13]); // nonce

        let dcid = extract_dcid(&quic, &config).unwrap();
        assert_eq!(dcid.len(), 17);
        assert_eq!(&dcid[1..4], &[0x00, 0x00, 0x02]);
    }

    #[test]
    fn extract_dcid_wrong_config_id() {
        let config = make_config(Encryption::Plaintext, 0, 3, 13);

        // config_id = 3 in top 3 bits -> first CID octet = 3 << 5 = 0x60
        let mut quic = vec![0xc0];
        quic.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        quic.push(17);
        quic.push(0x60); // config_id=3, doesn't match config.config_id=0
        quic.extend_from_slice(&[0x00; 16]);

        assert!(extract_dcid(&quic, &config).is_none());
    }

    #[test]
    fn extract_dcid_reserved_config_id_7() {
        let config = make_config(Encryption::Plaintext, 0, 3, 13);

        // config_id = 7 -> 0xe0
        let mut quic = vec![0xc0];
        quic.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        quic.push(17);
        quic.push(0xe0); // config_id=7 (reserved)
        quic.extend_from_slice(&[0x00; 16]);

        assert!(extract_dcid(&quic, &config).is_none());
    }

    #[test]
    fn extract_dcid_truncated() {
        let config = make_config(Encryption::Plaintext, 0, 3, 13);
        assert!(extract_dcid(&[], &config).is_none());
        assert!(extract_dcid(&[0xc0, 0x00], &config).is_none());
    }

    // -- resolve_server tests --

    #[test]
    fn resolve_plaintext() {
        let config = make_config(Encryption::Plaintext, 0, 3, 13);

        let mut dcid = vec![0x00]; // first octet, config_id=0
        dcid.extend_from_slice(&[0x00, 0x00, 0x01]); // server_id
        dcid.extend_from_slice(&[0x00; 13]); // nonce

        assert_eq!(resolve_server_idx(&dcid, &config), Some(0));
    }

    #[test]
    fn resolve_plaintext_unknown_server() {
        let config = make_config(Encryption::Plaintext, 0, 3, 13);

        let mut dcid = vec![0x00];
        dcid.extend_from_slice(&[0xff, 0xff, 0xff]); // unknown server_id
        dcid.extend_from_slice(&[0x00; 13]);

        assert!(resolve_server_idx(&dcid, &config).is_none());
    }

    #[test]
    fn resolve_single_pass_round_trip() {
        let config = make_config(
            Encryption::SinglePass { key: TEST_KEY },
            0, 3, 13,
        );

        // Build a plaintext CID payload: server_id || nonce
        let mut payload = [0u8; 16];
        payload[0..3].copy_from_slice(&[0x00, 0x00, 0x01]); // server_id
        payload[3..16].copy_from_slice(&[0x42; 13]); // nonce

        // Encrypt with AES-128-ECB
        let cipher = Aes128::new(GenericArray::from_slice(&TEST_KEY));
        let mut block = *GenericArray::from_slice(&payload);
        cipher.encrypt_block(&mut block);

        // Build the full CID: [first_octet][encrypted_payload]
        let mut dcid = vec![0x00]; // config_id=0
        dcid.extend_from_slice(&block);

        assert_eq!(resolve_server_idx(&dcid, &config), Some(0));
    }

    #[test]
    fn resolve_four_pass_round_trip() {
        let config = make_config(
            Encryption::FourPass { key: TEST_KEY },
            1, 3, 4,
        );

        // Plaintext payload: server_id(3) || nonce(4)
        let mut payload = [0u8; 7];
        payload[0..3].copy_from_slice(&[0x00, 0x00, 0x01]);
        payload[3..7].copy_from_slice(&[0x42; 4]);

        // Encrypt with four-pass Feistel
        encrypt_four_pass(&mut payload, 3, 4, &TEST_KEY);

        // Build CID: [first_octet (config_id=1 -> 0x20)][encrypted_payload]
        let mut dcid = vec![0x20]; // config_id=1
        dcid.extend_from_slice(&payload);

        assert_eq!(resolve_server_idx(&dcid, &config), Some(0));
    }

    #[test]
    fn four_pass_encrypt_decrypt_inverse() {
        let sid_len = 3;
        let nonce_len = 4;

        let original = [0xde, 0xad, 0xbe, 0x01, 0x02, 0x03, 0x04];
        let mut buf = [0u8; 19];
        buf[..7].copy_from_slice(&original);

        encrypt_four_pass(&mut buf[..7], sid_len, nonce_len, &TEST_KEY);
        // Encrypted should differ from original
        assert_ne!(&buf[..7], &original);

        // Decrypt
        let mut dbuf = [0u8; 19];
        dbuf[..7].copy_from_slice(&buf[..7]);
        decrypt_four_pass(&mut dbuf, sid_len, nonce_len, &TEST_KEY);

        assert_eq!(&dbuf[..7], &original);
    }
}
