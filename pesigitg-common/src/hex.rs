// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! Minimal hex encode/decode without pulling in an external crate.

/// Decode a hex string into bytes. Whitespace around the input is trimmed;
/// any interior non-hex character returns an error.
pub fn decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();

    if !s.len().is_multiple_of(2) {
        return Err("odd number of hex characters".into());
    }

    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| format!("invalid hex at position {i}"))
        })
        .collect()
}

/// Encode bytes as a lowercase hex string.
pub fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_roundtrip() {
        let bytes = [0x01, 0xab, 0xcd, 0xef, 0x00];
        assert_eq!(decode(&encode(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn decode_trims_whitespace() {
        assert_eq!(
            decode("  deadbeef\n").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn decode_rejects_odd_length() {
        assert!(decode("abc").is_err());
    }

    #[test]
    fn decode_rejects_non_hex() {
        let err = decode("ab0g").unwrap_err();
        assert!(err.contains("position 2"));
    }

    #[test]
    fn encode_is_lowercase() {
        assert_eq!(encode(&[0xAB, 0xCD]), "abcd");
    }
}
