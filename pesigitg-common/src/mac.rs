// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! 6-byte Ethernet MAC address formatting and parsing.

/// Format a 6-byte MAC as a lowercase colon-separated hex string
/// (`aa:bb:cc:dd:ee:ff`).
pub fn format(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
    )
}

/// Parse a colon-separated MAC address string. Accepts upper- or lowercase
/// hex; rejects anything that isn't exactly six colon-separated octets.
pub fn parse(s: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = s.split(':').collect();

    if parts.len() != 6 {
        return Err(format!(
            "expected 6 colon-separated octets, got {}",
            parts.len(),
        ));
    }

    let mut mac = [0u8; 6];

    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .map_err(|_| format!("invalid hex octet '{}' at position {i}", part))?;
    }

    Ok(mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_lowercase_and_padded() {
        assert_eq!(format(&[0x01, 0x02, 0xab, 0xcd, 0xef, 0x00]), "01:02:ab:cd:ef:00");
    }

    #[test]
    fn parse_accepts_mixed_case() {
        assert_eq!(
            parse("AA:bb:CC:dd:EE:ff").unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        );
    }

    #[test]
    fn parse_roundtrip() {
        let mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x11];
        assert_eq!(parse(&format(&mac)).unwrap(), mac);
    }

    #[test]
    fn parse_rejects_wrong_count() {
        assert!(parse("aa:bb:cc:dd:ee").is_err());
        assert!(parse("aa:bb:cc:dd:ee:ff:00").is_err());
    }

    #[test]
    fn parse_rejects_bad_octet() {
        let err = parse("aa:bb:cc:dd:ee:gg").unwrap_err();
        assert!(err.contains("position 5"));
    }
}
