// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! Daemon-side wrapper around shared QUIC-LB route data.
//!
//! Route entries themselves (`RouteConfig`, `Encryption`, `Server`,
//! `RouteConfigError`) live in [`pesigitg_routing::route`] so
//! `pesigitg-ctl` can decode CIDs against the same parser. This module
//! adds the daemon-only [`ConfigTable`] that organizes routes into a
//! seven-slot index keyed by `config_id` and carries the QUIC Retry
//! service runtime state alongside.

use std::fmt;
use std::path::{Path, PathBuf};

// `pub use` so existing `crate::config::route::*` callers keep working.
// Marked `allow(unused_imports)` because the fuzz crate `#[path]`-includes
// this file in a context that only consumes a subset of these re-exports.
#[allow(unused_imports)]
pub use pesigitg_routing::route::{Encryption, RouteConfig, RouteConfigError, Server};
use serde::Deserialize;

use super::retry::{RawRetry, RetryConfig};

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
    /// Optional QUIC Retry service settings. `None` = no `[retry]` section
    /// in the TOML; datapath should short-circuit the classifier branch.
    pub retry: Option<RetryConfig>,
}

/// Subset of the route TOML the daemon parses on its own to handle the
/// `[retry]` section. Routes themselves come from
/// [`pesigitg_routing::route::parse_routes`] — splitting the parse keeps
/// the shared crate free of retry-service runtime types.
#[derive(Deserialize)]
struct RawRetryWrapper {
    retry: Option<RawRetry>,
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
    ///
    /// Routes are validated by the shared parser; the daemon then layers
    /// its own `[retry]` parse on top so the runtime types
    /// (`LoadRateTracker`, `TokenKey`) stay daemon-side.
    pub fn from_str(text: &str) -> Result<Self, RouteConfigError> {
        let configs = pesigitg_routing::route::parse_routes(text)?;

        let mut slots: [Option<RouteConfig>; 7] = Default::default();
        for config in configs {
            let id = config.config_id as usize;
            slots[id] = Some(config);
        }

        let wrapper: RawRetryWrapper = toml::from_str(text).map_err(RouteConfigError::Parse)?;
        let retry = wrapper.retry.map(RetryConfig::validate).transpose()?;

        Ok(ConfigTable {
            path: PathBuf::new(),
            slots,
            fallback_servers: Vec::new(),
            retry,
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
        self.slots.iter().flatten().next().map(|c| c.cid_length())
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
        self.slots
            .iter()
            .flatten()
            .any(|c| c.servers.iter().any(|s| s.draining))
    }

    /// Returns `true` if any server in any active config has an unresolved MAC.
    pub fn has_unresolved_macs(&self) -> bool {
        self.slots
            .iter()
            .flatten()
            .any(|c| c.servers.iter().any(|s| s.mac.is_none()))
    }

    /// Returns `usize` of unresolved MAC addresses
    pub fn unresolved_macs_count(&self) -> usize {
        self.slots
            .iter()
            .flatten()
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
                    && !self
                        .fallback_servers
                        .iter()
                        .any(|s| s.address == server.address)
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
            retry: None,
        };

        table.rebuild_fallback_servers();
        table
    }
}

impl fmt::Display for ConfigTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "route config: {}", self.path.display())?;

        let active: Vec<_> = self.configs().collect();
        if active.is_empty() {
            writeln!(f, "  (no active configs)")?;
        }

        for rc in &active {
            writeln!(f, "  config_id {}:", rc.config_id)?;
            writeln!(f, "    encryption:     {:?}", rc.encryption)?;
            writeln!(f, "    server_id_len:  {}", rc.server_id_length)?;
            writeln!(f, "    nonce_len:      {}", rc.nonce_length)?;
            writeln!(f, "    cid_length:     {}", rc.cid_length())?;

            if rc.servers.is_empty() {
                writeln!(f, "    servers:        (none)")?;
            } else {
                writeln!(f, "    servers:")?;
                for s in &rc.servers {
                    let mac = match s.mac {
                        Some(m) => format!(
                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            m[0], m[1], m[2], m[3], m[4], m[5]
                        ),
                        None => "unresolved".to_string(),
                    };
                    let id_hex: String = s.id.iter().map(|b| format!("{b:02x}")).collect();
                    let mut flags = Vec::new();
                    if s.draining {
                        flags.push("draining");
                    }
                    if !s.healthy {
                        flags.push("unhealthy");
                    }
                    let flag_str = if flags.is_empty() {
                        "healthy".to_string()
                    } else {
                        flags.join(", ")
                    };
                    writeln!(
                        f,
                        "      {} -> {} mac={} [{}]",
                        id_hex, s.address, mac, flag_str,
                    )?;
                }
            }
        }

        writeln!(
            f,
            "  fallback pool: {} servers",
            self.fallback_servers.len()
        )?;
        for s in &self.fallback_servers {
            writeln!(f, "    {}", s.address)?;
        }

        match &self.retry {
            Some(rc) => {
                writeln!(f, "  retry:")?;
                for line in format!("{rc}").lines() {
                    writeln!(f, "    {line}")?;
                }
            }
            None => {
                writeln!(f, "  retry: disabled")?;
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
"#;

    #[test]
    fn from_str_indexes_by_config_id() {
        let table = ConfigTable::from_str(SAMPLE_TOML).unwrap();
        assert!(table.get(0).is_some());
        assert!(table.get(1).is_none());
        assert_eq!(table.fallback_cid_length(), Some(17));
    }

    #[test]
    fn retry_section_is_layered_on_top() {
        // `[retry]` lives outside the shared parser; the daemon wrapper
        // is what stitches it back into the table.
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
        let table = ConfigTable::from_str(toml).unwrap();
        assert!(table.retry.is_some());
        assert!(table.retry.unwrap().enabled);
    }

    #[test]
    fn missing_retry_section_leaves_none() {
        let table = ConfigTable::from_str(SAMPLE_TOML).unwrap();
        assert!(table.retry.is_none());
    }
}
