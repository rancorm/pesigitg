// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! Validated QUIC-LB route entries (per draft-ietf-quic-load-balancers-21).
//!
//! Holds only the data and validation needed to decode a Connection ID:
//! the daemon stitches these into its own `ConfigTable` (which also
//! carries retry-service runtime state), and `pesigitg-ctl` walks the
//! `Vec<RouteConfig>` returned by [`parse_routes`] for offline `whoami`.

use std::fmt;
use std::net::IpAddr;
use std::path::Path;
use std::time::Instant;

use aes::Aes128;
use aes::cipher::{KeyInit, generic_array::GenericArray};
use pesigitg_common::{hex, mac};
use serde::Deserialize;

/// Per-config-id configuration, validated and ready for use.
#[derive(Debug, Clone)]
pub struct RouteConfig {
    pub config_id: u8,
    pub first_octet_encodes_cid_length: bool,
    pub server_id_length: u8,
    pub nonce_length: u8,
    pub encryption: Encryption,
    pub servers: Vec<Server>,
    /// Optional rotation policy: when `Some(secs)`, the daemon emits a
    /// one-shot warning log line once the QUIC-LB key has been live
    /// longer than `secs`. `None` disables the nag. Validated `> 0` at
    /// parse time.
    pub max_key_age_secs: Option<u64>,
}

/// Encryption mode derived from `server_id_length + nonce_length`.
///
/// The pre-computed [`Aes128`] cipher avoids key expansion on every packet.
pub enum Encryption {
    /// Plaintext - no key supplied. Not recommended for production.
    Plaintext,
    /// Single-pass AES-128-ECB (server_id_length + nonce_length == 16).
    SinglePass { key: [u8; 16], cipher: Aes128 },
    /// Four-pass block cipher (server_id_length + nonce_length != 16, <= 19).
    FourPass { key: [u8; 16], cipher: Aes128 },
}

impl Clone for Encryption {
    fn clone(&self) -> Self {
        match self {
            Self::Plaintext => Self::Plaintext,
            Self::SinglePass { key, .. } => Self::SinglePass {
                key: *key,
                cipher: Aes128::new(GenericArray::from_slice(key)),
            },
            Self::FourPass { key, .. } => Self::FourPass {
                key: *key,
                cipher: Aes128::new(GenericArray::from_slice(key)),
            },
        }
    }
}

impl Encryption {
    /// True if `self` and `other` would produce identical CID encryption.
    /// Used by the daemon to detect "same key across reload" so key-age
    /// telemetry doesn't reset on unrelated SIGHUPs.
    pub fn same_key(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Plaintext, Self::Plaintext) => true,
            (Self::SinglePass { key: a, .. }, Self::SinglePass { key: b, .. }) => a == b,
            (Self::FourPass { key: a, .. }, Self::FourPass { key: b, .. }) => a == b,
            _ => false,
        }
    }
}

impl fmt::Debug for Encryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plaintext => write!(f, "Plaintext"),
            Self::SinglePass { .. } => write!(f, "SinglePass"),
            Self::FourPass { .. } => write!(f, "FourPass"),
        }
    }
}

/// A backend QUIC server
#[derive(Debug, Clone)]
pub struct Server {
    /// Raw server ID bytes (length == `RouteConfig::server_id_length`).
    pub id: Vec<u8>,
    /// IP address to forward packets to.
    pub address: IpAddr,
    /// MAC address of the server (optional).
    pub mac: Option<[u8; 6]>,
    /// When true, the server is draining: existing CID-routed connections
    /// continue, but new fallback connections are not assigned to it.
    pub draining: bool,
    /// Health probe status. Servers start unhealthy and are marked healthy
    /// once a QUIC probe succeeds.
    pub healthy: bool,
    /// Number of healthy↔unhealthy transitions observed for this server
    /// since daemon startup, excluding the initial warm-up flip from the
    /// default-unhealthy state. Mirrored from the daemon's health state
    /// after each probe cycle. Stays 0 in offline contexts.
    pub transitions: u32,
    /// Instant at which the server entered its current `healthy` state.
    /// `None` until the first probe completes (or in offline contexts).
    pub state_since: Option<Instant>,
}

#[derive(Debug)]
pub enum RouteConfigError {
    Io(std::io::Error),
    Parse(toml::de::Error),
    Validation(String),
}

impl fmt::Display for RouteConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "config I/O error: {}", e),
            Self::Parse(e) => write!(f, "config parse error: {}", e),
            Self::Validation(msg) => write!(f, "config validation error: {}", msg),
        }
    }
}

impl std::error::Error for RouteConfigError {}

impl From<std::io::Error> for RouteConfigError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<toml::de::Error> for RouteConfigError {
    fn from(e: toml::de::Error) -> Self {
        Self::Parse(e)
    }
}

/// Subset of the route TOML this crate cares about. Extra fields like
/// `[retry]` deserialize into `_other` and are dropped — the daemon
/// re-parses the file separately to handle its own sections.
#[derive(Deserialize)]
struct RawRouteFile {
    #[serde(default)]
    configs: Vec<RawConfig>,
}

#[derive(Deserialize)]
struct RawConfig {
    config_id: u8,
    #[serde(default)]
    first_octet_encodes_cid_length: bool,
    server_id_length: u8,
    nonce_length: u8,
    key: Option<String>,
    #[serde(default)]
    servers: Vec<RawServer>,
    max_key_age_secs: Option<u64>,
}

#[derive(Deserialize)]
struct RawServer {
    id: String,
    address: String,
    mac: Option<String>,
    #[serde(default)]
    draining: bool,
}

impl RouteConfig {
    fn validate(raw: RawConfig) -> Result<Self, RouteConfigError> {
        // config_id: 0..=6 (0b111 is reserved for fallback/unroutable)
        if raw.config_id > 6 {
            return Err(RouteConfigError::Validation(format!(
                "config_id must be 0-6, got {}",
                raw.config_id,
            )));
        }

        // server_id_length: 1..=15
        if raw.server_id_length == 0 || raw.server_id_length > 15 {
            return Err(RouteConfigError::Validation(format!(
                "server_id_length must be 1-15, got {}",
                raw.server_id_length,
            )));
        }

        // nonce_length: 4..=18
        if raw.nonce_length < 4 || raw.nonce_length > 18 {
            return Err(RouteConfigError::Validation(format!(
                "nonce_length must be 4-18, got {}",
                raw.nonce_length,
            )));
        }

        // server_id_length + nonce_length <= 19
        let sum = raw.server_id_length as u16 + raw.nonce_length as u16;
        if sum > 19 {
            return Err(RouteConfigError::Validation(format!(
                "server_id_length ({}) + nonce_length ({}) = {sum}, exceeds max 19",
                raw.server_id_length, raw.nonce_length,
            )));
        }

        // Determine encryption mode
        let encryption = match raw.key {
            None => Encryption::Plaintext,
            Some(ref hex) => {
                let key = parse_hex_key(hex)?;
                let cipher = Aes128::new(GenericArray::from_slice(&key));
                if sum == 16 {
                    Encryption::SinglePass { key, cipher }
                } else {
                    Encryption::FourPass { key, cipher }
                }
            }
        };

        // Parse servers
        let servers = raw
            .servers
            .iter()
            .map(|s| parse_server(s, raw.server_id_length))
            .collect::<Result<Vec<_>, _>>()?;

        // 0 would warn immediately on every reload — reject so a typo
        // can't suppress the actual rotation policy.
        if let Some(0) = raw.max_key_age_secs {
            return Err(RouteConfigError::Validation(format!(
                "max_key_age_secs must be > 0 when set (config_id={})",
                raw.config_id,
            )));
        }

        Ok(RouteConfig {
            config_id: raw.config_id,
            first_octet_encodes_cid_length: raw.first_octet_encodes_cid_length,
            server_id_length: raw.server_id_length,
            nonce_length: raw.nonce_length,
            encryption,
            servers,
            max_key_age_secs: raw.max_key_age_secs,
        })
    }

    /// Total CID payload length (excluding the first octet).
    /// This is `server_id_length + nonce_length`.
    #[inline]
    pub fn cid_payload_length(&self) -> u8 {
        self.server_id_length + self.nonce_length
    }

    /// Full CID length including the first octet.
    #[inline]
    pub fn cid_length(&self) -> u8 {
        1 + self.cid_payload_length()
    }

    /// Look up a server's index by its raw ID bytes.
    pub fn find_server_idx(&self, id: &[u8]) -> Option<usize> {
        self.servers.iter().position(|s| s.id == id)
    }
}

/// Parse `[[configs]]` from a route TOML string into validated entries.
///
/// Other top-level sections (e.g. `[retry]`) are accepted by the
/// deserializer but ignored — daemon-only state lives in the daemon's
/// own wrapper. Returns the entries in declaration order; callers that
/// need indexed lookup should organize them into a slot table keyed by
/// `config_id`.
pub fn parse_routes(text: &str) -> Result<Vec<RouteConfig>, RouteConfigError> {
    let raw: RawRouteFile = toml::from_str(text)?;

    if raw.configs.is_empty() {
        return Err(RouteConfigError::Validation(
            "no [[configs]] entries found".into(),
        ));
    }

    let mut out = Vec::with_capacity(raw.configs.len());
    let mut seen = [false; 7];

    for raw_config in raw.configs {
        let config = RouteConfig::validate(raw_config)?;
        let id = config.config_id as usize;

        if seen[id] {
            return Err(RouteConfigError::Validation(format!(
                "duplicate config_id {}",
                config.config_id,
            )));
        }
        seen[id] = true;

        out.push(config);
    }

    Ok(out)
}

/// Convenience wrapper: read a TOML file and call [`parse_routes`].
pub fn parse_routes_file(path: impl AsRef<Path>) -> Result<Vec<RouteConfig>, RouteConfigError> {
    let text = std::fs::read_to_string(path)?;
    parse_routes(&text)
}

/// Parse a hex-encoded 16-byte (128-bit) AES key.
fn parse_hex_key(s: &str) -> Result<[u8; 16], RouteConfigError> {
    let bytes = hex::decode(s)
        .map_err(|e| RouteConfigError::Validation(format!("invalid hex key: {e}")))?;

    if bytes.len() != 16 {
        return Err(RouteConfigError::Validation(format!(
            "key must be exactly 16 bytes (128 bits), got {} bytes",
            bytes.len(),
        )));
    }

    let mut key = [0u8; 16];
    key.copy_from_slice(&bytes);

    Ok(key)
}

/// Parse a single `[[configs.servers]]` entry.
fn parse_server(raw: &RawServer, expected_id_len: u8) -> Result<Server, RouteConfigError> {
    let expected_hex_len = expected_id_len as usize * 2;

    if raw.id.trim().len() != expected_hex_len {
        return Err(RouteConfigError::Validation(format!(
            "server id '{}' has {} hex chars, expected {} (server_id_length * 2)",
            raw.id,
            raw.id.trim().len(),
            expected_hex_len,
        )));
    }

    let id = hex::decode(&raw.id).map_err(|e| {
        RouteConfigError::Validation(format!("invalid hex server id '{}': {e}", raw.id,))
    })?;

    if id.len() != expected_id_len as usize {
        return Err(RouteConfigError::Validation(format!(
            "server id '{}' is {} bytes, expected {expected_id_len}",
            raw.id,
            id.len(),
        )));
    }

    let address: IpAddr = raw.address.parse().map_err(|e| {
        RouteConfigError::Validation(format!("invalid server address '{}': {e}", raw.address,))
    })?;

    let mac = raw
        .mac
        .as_deref()
        .map(mac::parse)
        .transpose()
        .map_err(|e| {
            RouteConfigError::Validation(format!(
                "invalid server mac '{}': {e}",
                raw.mac.as_deref().unwrap_or("")
            ))
        })?;

    Ok(Server {
        id,
        address,
        mac,
        draining: raw.draining,
        healthy: false,
        transitions: 0,
        state_since: None,
    })
}

impl fmt::Display for Encryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plaintext => write!(f, "plaintext"),
            Self::SinglePass { .. } => write!(f, "single-pass AES-ECB"),
            Self::FourPass { .. } => write!(f, "four-pass block cipher"),
        }
    }
}

impl fmt::Display for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let id_hex: String = self.id.iter().map(|b| format!("{b:02x}")).collect();

        match self.mac {
            Some(mac) => {
                let mac_str = mac
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":");

                write!(f, "{} -> {} (mac: {})", id_hex, self.address, mac_str)
            }
            None => write!(f, "{} -> {}", id_hex, self.address),
        }
    }
}

impl fmt::Display for RouteConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "config_id:        {}", self.config_id)?;
        writeln!(
            f,
            "first_octet_len:  {}",
            self.first_octet_encodes_cid_length
        )?;
        writeln!(f, "server_id_length: {}", self.server_id_length)?;
        writeln!(f, "nonce_length:     {}", self.nonce_length)?;
        writeln!(
            f,
            "cid_length:       {} (1 + {})",
            self.cid_length(),
            self.cid_payload_length()
        )?;
        writeln!(f, "encryption:       {}", self.encryption)?;

        if self.servers.is_empty() {
            write!(f, "servers:          0")?;
        } else {
            writeln!(f, "servers:          {}", self.servers.len())?;

            for (i, s) in self.servers.iter().enumerate() {
                if i + 1 < self.servers.len() {
                    writeln!(f, "  {}", s)?;
                } else {
                    write!(f, "  {}", s)?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TOML: &str = r#"
[[configs]]
config_id = 0
first_octet_encodes_cid_length = true
server_id_length = 3
nonce_length = 13
key = "000102030405060708090a0b0c0d0e0f"

[[configs.servers]]
id = "000001"
address = "10.0.1.10"

[[configs.servers]]
id = "000002"
address = "2001:db8::1"
"#;

    #[test]
    fn parse_valid_single_pass() {
        let configs = parse_routes(SAMPLE_TOML).unwrap();
        let cfg = &configs[0];

        assert_eq!(cfg.config_id, 0);
        assert!(cfg.first_octet_encodes_cid_length);
        assert_eq!(cfg.server_id_length, 3);
        assert_eq!(cfg.nonce_length, 13);
        assert!(matches!(cfg.encryption, Encryption::SinglePass { .. }));
        assert_eq!(cfg.cid_length(), 17); // 1 + 3 + 13
        assert_eq!(cfg.servers.len(), 2);
        assert_eq!(cfg.servers[0].id, vec![0x00, 0x00, 0x01]);
        assert!(cfg.servers[1].address.is_ipv6());
    }

    #[test]
    fn parse_four_pass() {
        let toml = r#"
[[configs]]
config_id = 1
server_id_length = 3
nonce_length = 4
key = "000102030405060708090a0b0c0d0e0f"
"#;
        let configs = parse_routes(toml).unwrap();
        let cfg = &configs[0];

        assert!(matches!(cfg.encryption, Encryption::FourPass { .. }));
        assert_eq!(cfg.cid_payload_length(), 7);
    }

    #[test]
    fn parse_plaintext() {
        let toml = r#"
[[configs]]
config_id = 2
server_id_length = 2
nonce_length = 5
"#;
        let configs = parse_routes(toml).unwrap();
        assert!(matches!(configs[0].encryption, Encryption::Plaintext));
    }

    #[test]
    fn parse_multiple_configs() {
        let toml = r#"
[[configs]]
config_id = 0
server_id_length = 3
nonce_length = 13
key = "000102030405060708090a0b0c0d0e0f"

[[configs.servers]]
id = "000001"
address = "10.0.1.10"

[[configs]]
config_id = 1
server_id_length = 3
nonce_length = 13
key = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"

[[configs.servers]]
id = "000001"
address = "10.0.1.10"
"#;
        let configs = parse_routes(toml).unwrap();
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].config_id, 0);
        assert_eq!(configs[1].config_id, 1);
    }

    #[test]
    fn ignores_retry_section() {
        // The retry-service block is daemon-only; the shared parser must
        // accept it as a passthrough without trying to validate.
        let toml = r#"
[[configs]]
config_id = 0
server_id_length = 3
nonce_length = 13

[retry]
enabled = true
token_key = "0000000000000000000000000000000000000000000000000000000000000000"
mode = "always"
"#;
        let configs = parse_routes(toml).unwrap();
        assert_eq!(configs.len(), 1);
    }

    #[test]
    fn reject_duplicate_config_id() {
        let toml = r#"
[[configs]]
config_id = 0
server_id_length = 3
nonce_length = 13

[[configs]]
config_id = 0
server_id_length = 3
nonce_length = 4
"#;
        let err = parse_routes(toml).unwrap_err();
        assert!(err.to_string().contains("duplicate config_id"));
    }

    #[test]
    fn reject_empty_configs() {
        let toml = "";
        assert!(parse_routes(toml).is_err());
    }

    #[test]
    fn reject_config_id_7() {
        let toml = r#"
[[configs]]
config_id = 7
server_id_length = 3
nonce_length = 13
"#;
        assert!(parse_routes(toml).is_err());
    }

    #[test]
    fn reject_sum_exceeds_19() {
        let toml = r#"
[[configs]]
config_id = 0
server_id_length = 15
nonce_length = 5
"#;
        assert!(parse_routes(toml).is_err());
    }

    #[test]
    fn reject_nonce_below_4() {
        let toml = r#"
[[configs]]
config_id = 0
server_id_length = 3
nonce_length = 3
"#;
        assert!(parse_routes(toml).is_err());
    }

    #[test]
    fn reject_wrong_server_id_length() {
        let toml = r#"
[[configs]]
config_id = 0
server_id_length = 3
nonce_length = 13

[[configs.servers]]
id = "0001"
address = "10.0.1.10"
"#;
        let err = parse_routes(toml).unwrap_err();
        assert!(err.to_string().contains("server_id_length * 2"));
    }

    #[test]
    fn reject_bad_key_length() {
        let toml = r#"
[[configs]]
config_id = 0
server_id_length = 3
nonce_length = 13
key = "0102030405"
"#;
        let err = parse_routes(toml).unwrap_err();
        assert!(err.to_string().contains("16 bytes"));
    }

    #[test]
    fn reject_server_id_hex_length_mismatch() {
        let toml = r#"
[[configs]]
config_id = 0
server_id_length = 3
nonce_length = 4

[[configs.servers]]
id = "01020304"
address = "10.0.1.10"
"#;
        let err = parse_routes(toml).unwrap_err();
        assert!(err.to_string().contains("server_id_length * 2"));
    }
}
