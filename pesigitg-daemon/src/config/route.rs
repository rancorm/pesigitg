// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! Configuration for load balancer.
//!
//! Parses `lb.toml` into validated Rust types per the QUIC-LB specification
//! (draft-ietf-quic-load-balancers-21). Supports multiple simultaneous
//! configurations indexed by config_id (0-6) for config rotation.

use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use aes::Aes128;
use aes::cipher::{KeyInit, generic_array::GenericArray};
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
}

/// Config table holding up to 7 simultaneous configurations (config_id 0-6).
///
/// The config_id from a CID's first octet is a direct index into this table.
/// Codepoint 7 is reserved for fallback/unroutable.
#[derive(Debug)]
pub struct ConfigTable {
    pub path: PathBuf,
    slots: [Option<RouteConfig>; 7],
    /// Merged, deduplicated server list for fallback consistent hashing.
    pub fallback_servers: Vec<Server>,
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

#[derive(Deserialize)]
struct RawConfigFile {
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

        Ok(RouteConfig {
            config_id: raw.config_id,
            first_octet_encodes_cid_length: raw.first_octet_encodes_cid_length,
            server_id_length: raw.server_id_length,
            nonce_length: raw.nonce_length,
            encryption,
            servers,
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

impl ConfigTable {
    /// Load and validate configuration from a TOML file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, RouteConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)?;
        let mut table = Self::from_str(&text)?;
        
        table.path = path.to_path_buf();
        
        Ok(table)
    }

    /// Parse and validate configuration from a TOML string.
    pub fn from_str(text: &str) -> Result<Self, RouteConfigError> {
        let raw: RawConfigFile = toml::from_str(text)?;

        if raw.configs.is_empty() {
            return Err(RouteConfigError::Validation(
                "no [[configs]] entries found".into(),
            ));
        }

        let mut slots: [Option<RouteConfig>; 7] = Default::default();

        for raw_config in raw.configs {
            let config = RouteConfig::validate(raw_config)?;
            let id = config.config_id as usize;

            if slots[id].is_some() {
                return Err(RouteConfigError::Validation(format!(
                    "duplicate config_id {}",
                    config.config_id,
                )));
            }
            
            slots[id] = Some(config);
        }

        Ok(ConfigTable {
            path: PathBuf::new(),
            slots,
            fallback_servers: Vec::new(),
        })
    }

    /// Look up a config by config_id (0-6).
    #[inline]
    pub fn get(&self, config_id: u8) -> Option<&RouteConfig> {
        self.slots.get(config_id as usize)?.as_ref()
    }

    /// CID length for raw DCID extraction on the fallback path.
    /// Uses the first active config's cid_length.
    pub fn fallback_cid_length(&self) -> Option<u8> {
        self.slots.iter()
            .flatten()
            .next()
            .map(|c| c.cid_length())
    }

    /// Iterator over all active configs.
    pub fn configs(&self) -> impl Iterator<Item = &RouteConfig> {
        self.slots.iter().filter_map(|s| s.as_ref())
    }

    /// Mutable iterator over all active configs.
    pub fn configs_mut(&mut self) -> impl Iterator<Item = &mut RouteConfig> {
        self.slots.iter_mut().filter_map(|s| s.as_mut())
    }

    /// Returns `true` if any server in any active config is draining.
    pub fn has_draining_servers(&self) -> bool {
        self.slots.iter().flatten()
            .any(|c| c.servers.iter().any(|s| s.draining))
    }

    /// Returns `true` if any server in any active config has an unresolved MAC.
    pub fn has_unresolved_macs(&self) -> bool {
        self.slots.iter().flatten()
            .any(|c| c.servers.iter().any(|s| s.mac.is_none()))
    }

    /// Returns `usize` of unresolved MAC addresses
    pub fn unresolved_macs_count(&self) -> usize {
        self.slots.iter().flatten()
            .flat_map(|rc| rc.servers.iter())
            .filter(|s| s.mac.is_none())
            .count()
    }
    
    /// Rebuild the merged fallback server list from all active configs.
    /// Call after resolving MACs.
    pub fn rebuild_fallback_servers(&mut self) {
        self.fallback_servers.clear();

        for config in self.slots.iter().flatten() {
            for server in &config.servers {
                if server.healthy
                    && server.mac.is_some()
                    && !server.draining
                    && !self.fallback_servers.iter().any(|s| s.address == server.address)
                {
                    self.fallback_servers.push(server.clone());
                }
            }
        }
    }

    /// Construct a ConfigTable directly from configs (for tests).
    #[cfg(test)]
    pub(crate) fn with_configs(configs: Vec<RouteConfig>) -> Self {
        let mut slots: [Option<RouteConfig>; 7] = Default::default();
        
        for config in configs {
            let id = config.config_id as usize;
            slots[id] = Some(config);
        }
        
        let mut table = ConfigTable {
            path: PathBuf::new(),
            slots,
            fallback_servers: Vec::new(),
        };
        
        table.rebuild_fallback_servers();
        table
    }
}

/// Parse a hex-encoded 16-byte (128-bit) AES key.
fn parse_hex_key(hex: &str) -> Result<[u8; 16], RouteConfigError> {
    let bytes = hex_decode(hex).map_err(|e| {
        RouteConfigError::Validation(format!("invalid hex key: {e}"))
    })?;

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

/// Parse a colon-separated MAC address string (e.g. `"aa:bb:cc:dd:ee:01"`).
fn parse_mac(s: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = s.split(':').collect();

    if parts.len() != 6 {
        return Err(format!("expected 6 colon-separated octets, got {}", parts.len()));
    }

    let mut mac = [0u8; 6];

    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .map_err(|_| format!("invalid hex octet '{}' at position {i}", part))?;
    }

    Ok(mac)
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

    let id = hex_decode(&raw.id).map_err(|e| {
        RouteConfigError::Validation(format!(
            "invalid hex server id '{}': {e}",
            raw.id,
        ))
    })?;

    if id.len() != expected_id_len as usize {
        return Err(RouteConfigError::Validation(format!(
            "server id '{}' is {} bytes, expected {expected_id_len}",
            raw.id,
            id.len(),
        )));
    }

    let address: IpAddr = raw.address.parse().map_err(|e| {
        RouteConfigError::Validation(format!(
            "invalid server address '{}': {e}",
            raw.address,
        ))
    })?;

    let mac = raw.mac.as_deref().map(parse_mac).transpose().map_err(|e| {
        RouteConfigError::Validation(format!("invalid server mac '{}': {e}", raw.mac.as_deref().unwrap_or("")))
    })?;

    Ok(Server { id, address, mac, draining: raw.draining, healthy: false })
}

/// Minimal hex decoder (no external dependency).
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();

    if s.len() % 2 != 0 {
        return Err("odd number of hex characters".into());
    }

    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| format!("invalid hex at position {i}"))
        })
        .collect()
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
        let id_hex: String = self.id
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

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
        writeln!(f, "first_octet_len:  {}", self.first_octet_encodes_cid_length)?;
        writeln!(f, "server_id_length: {}", self.server_id_length)?;
        writeln!(f, "nonce_length:     {}", self.nonce_length)?;
        writeln!(f, "cid_length:       {} (1 + {})", self.cid_length(), self.cid_payload_length())?;
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

impl fmt::Display for ConfigTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let active: Vec<_> = self.slots.iter().flatten().collect();
        
        write!(f, "config table ({} active):", active.len())?;
        
        for config in active {
            write!(f, "\n{}", config)?;
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
        let table = ConfigTable::from_str(SAMPLE_TOML).unwrap();
        let cfg = table.get(0).unwrap();

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
        let table = ConfigTable::from_str(toml).unwrap();
        let cfg = table.get(1).unwrap();

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
        let table = ConfigTable::from_str(toml).unwrap();
        let cfg = table.get(2).unwrap();

        assert!(matches!(cfg.encryption, Encryption::Plaintext));
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
        let table = ConfigTable::from_str(toml).unwrap();

        assert!(table.get(0).is_some());
        assert!(table.get(1).is_some());
        assert!(table.get(2).is_none());
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
        let err = ConfigTable::from_str(toml).unwrap_err();
        assert!(err.to_string().contains("duplicate config_id"));
    }

    #[test]
    fn reject_empty_configs() {
        let toml = "";
        assert!(ConfigTable::from_str(toml).is_err());
    }

    #[test]
    fn reject_config_id_7() {
        let toml = r#"
[[configs]]
config_id = 7
server_id_length = 3
nonce_length = 13
"#;
        assert!(ConfigTable::from_str(toml).is_err());
    }

    #[test]
    fn reject_sum_exceeds_19() {
        let toml = r#"
[[configs]]
config_id = 0
server_id_length = 15
nonce_length = 5
"#;
        assert!(ConfigTable::from_str(toml).is_err());
    }

    #[test]
    fn reject_nonce_below_4() {
        let toml = r#"
[[configs]]
config_id = 0
server_id_length = 3
nonce_length = 3
"#;
        assert!(ConfigTable::from_str(toml).is_err());
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
        let err = ConfigTable::from_str(toml).unwrap_err();
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
        let err = ConfigTable::from_str(toml).unwrap_err();
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
        let err = ConfigTable::from_str(toml).unwrap_err();
        assert!(err.to_string().contains("server_id_length * 2"));
    }

    #[test]
    fn fallback_cid_length_from_first_active() {
        let table = ConfigTable::from_str(SAMPLE_TOML).unwrap();
        assert_eq!(table.fallback_cid_length(), Some(17));
    }
}
