//! Configuration for load balancer.
//!
//! Parses `lb.toml` into validated Rust types per the QUIC-LB specification
//! (draft-ietf-quic-load-balancers-21). Determines the encryption algorithm
//! (single-pass AES-ECB vs four-pass block cipher) from field lengths.

use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use serde::Deserialize;

/// Top-level configuration, validated and ready for use.
#[derive(Debug, Clone)]
pub struct RouteConfig {
    pub path: PathBuf,
    pub config_id: u8,
    pub first_octet_encodes_cid_length: bool,
    pub server_id_length: u8,
    pub nonce_length: u8,
    pub encryption: Encryption,
    pub servers: Vec<Server>,
}

/// Encryption mode derived from `server_id_length + nonce_length`.
#[derive(Debug, Clone)]
pub enum Encryption {
    /// Plaintext - no key supplied. Not recommended for production.
    Plaintext,
    /// Single-pass AES-128-ECB (server_id_length + nonce_length == 16).
    SinglePass { key: [u8; 16] },
    /// Four-pass block cipher (server_id_length + nonce_length != 16, <= 19).
    FourPass { key: [u8; 16] },
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
}

impl RouteConfig {
    /// Load and validate configuration from a TOML file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, RouteConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)?;
        let mut config = Self::from_str(&text)?;
        
        config.path = path.to_path_buf();
        
        Ok(config)
    }

    /// Parse and validate configuration from a TOML string.
    pub fn from_str(text: &str) -> Result<Self, RouteConfigError> {
        let raw: RawConfig = toml::from_str(text)?;
        Self::validate(raw)
    }

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
                if sum == 16 {
                    Encryption::SinglePass { key }
                } else {
                    Encryption::FourPass { key }
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
            path: PathBuf::new(),
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

    /// Whether encryption is configured (not plaintext).
    #[inline]
    pub fn is_encrypted(&self) -> bool {
        !matches!(self.encryption, Encryption::Plaintext)
    }

    /// Whether single-pass AES-ECB is in use.
    #[inline]
    pub fn is_single_pass(&self) -> bool {
        matches!(self.encryption, Encryption::SinglePass { .. })
    }

    /// Look up a server by its raw ID bytes.
    pub fn find_server(&self, id: &[u8]) -> Option<&Server> {
        self.servers.iter().find(|s| s.id == id)
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

/// Parse a single `[[servers]]` entry.
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

    Ok(Server { id, address, mac })
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

impl fmt::Display for RouteConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Route Configuration:")?;
        writeln!(f, "  config_id:        {}", self.config_id)?;
        writeln!(f, "  first_octet_len:  {}", self.first_octet_encodes_cid_length)?;
        writeln!(f, "  server_id_length: {}", self.server_id_length)?;
        writeln!(f, "  nonce_length:     {}", self.nonce_length)?;
        writeln!(f, "  cid_length:       {} (1 + {})", self.cid_length(), self.cid_payload_length())?;
        write!(f, "  encryption:       ")?;
        
        match &self.encryption {
            Encryption::Plaintext => writeln!(f, "plaintext")?,
            Encryption::SinglePass { .. } => writeln!(f, "single-pass AES-ECB")?,
            Encryption::FourPass { .. } => writeln!(f, "four-pass block cipher")?,
        }
        
        writeln!(f, "  servers:          {}", self.servers.len())?;
        
        for s in &self.servers {
            let id_hex: String = s.id.iter().map(|b| format!("{b:02x}")).collect();
            match s.mac {
                Some(mac) => {
                    let mac_str = mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":");
                    writeln!(f, "    {} -> {} (mac: {})", id_hex, s.address, mac_str)?;
                }
                None => writeln!(f, "    {} -> {}", id_hex, s.address)?,
            }
        }
 
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TOML: &str = r#"
config_id = 0
first_octet_encodes_cid_length = true
server_id_length = 3
nonce_length = 13
key = "000102030405060708090a0b0c0d0e0f"

[[servers]]
id = "000001"
address = "10.0.1.10"

[[servers]]
id = "000002"
address = "2001:db8::1"
"#;

    #[test]
    fn parse_valid_single_pass() {
        let cfg = RouteConfig::from_str(SAMPLE_TOML).unwrap();
        assert_eq!(cfg.config_id, 0);
        assert!(cfg.first_octet_encodes_cid_length);
        assert_eq!(cfg.server_id_length, 3);
        assert_eq!(cfg.nonce_length, 13);
        assert!(cfg.is_single_pass());
        assert_eq!(cfg.cid_length(), 17); // 1 + 3 + 13
        assert_eq!(cfg.servers.len(), 2);
        assert_eq!(cfg.servers[0].id, vec![0x00, 0x00, 0x01]);
        assert!(cfg.servers[1].address.is_ipv6());
    }

    #[test]
    fn parse_four_pass() {
        let toml = r#"
config_id = 1
server_id_length = 3
nonce_length = 4
key = "000102030405060708090a0b0c0d0e0f"
"#;
        let cfg = RouteConfig::from_str(toml).unwrap();
        assert!(matches!(cfg.encryption, Encryption::FourPass { .. }));
        assert_eq!(cfg.cid_payload_length(), 7);
    }

    #[test]
    fn parse_plaintext() {
        let toml = r#"
config_id = 2
server_id_length = 2
nonce_length = 5
"#;
        let cfg = RouteConfig::from_str(toml).unwrap();
        assert!(matches!(cfg.encryption, Encryption::Plaintext));
    }

    #[test]
    fn reject_config_id_7() {
        let toml = r#"
config_id = 7
server_id_length = 3
nonce_length = 13
"#;
        assert!(RouteConfig::from_str(toml).is_err());
    }

    #[test]
    fn reject_sum_exceeds_19() {
        let toml = r#"
config_id = 0
server_id_length = 15
nonce_length = 5
"#;
        assert!(RouteConfig::from_str(toml).is_err());
    }

    #[test]
    fn reject_nonce_below_4() {
        let toml = r#"
config_id = 0
server_id_length = 3
nonce_length = 3
"#;
        assert!(RouteConfig::from_str(toml).is_err());
    }

    #[test]
    fn reject_wrong_server_id_length() {
        let toml = r#"
config_id = 0
server_id_length = 3
nonce_length = 13

[[servers]]
id = "0001"
address = "10.0.1.10"
"#;
        let err = RouteConfig::from_str(toml).unwrap_err();
        assert!(err.to_string().contains("server_id_length * 2"));
    }

    #[test]
    fn reject_bad_key_length() {
        let toml = r#"
config_id = 0
server_id_length = 3
nonce_length = 13
key = "0102030405"
"#;
        let err = RouteConfig::from_str(toml).unwrap_err();
        assert!(err.to_string().contains("16 bytes"));
    }

    #[test]
    fn reject_server_id_hex_length_mismatch() {
        // server_id_length = 3 expects 6 hex chars; "01020304" is 8
        let toml = r#"
config_id = 0
server_id_length = 3
nonce_length = 4

[[servers]]
id = "01020304"
address = "10.0.1.10"
"#;
        let err = RouteConfig::from_str(toml).unwrap_err();
        assert!(err.to_string().contains("server_id_length * 2"));
    }

    #[test]
    fn find_server_by_id() {
        let cfg = RouteConfig::from_str(SAMPLE_TOML).unwrap();
        let s = cfg.find_server(&[0x00, 0x00, 0x01]).unwrap();
        assert_eq!(s.address, "10.0.1.10".parse::<IpAddr>().unwrap());
        assert!(cfg.find_server(&[0xff, 0xff, 0xff]).is_none());
    }
}
