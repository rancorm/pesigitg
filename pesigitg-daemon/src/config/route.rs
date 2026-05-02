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
use std::time::Instant;

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
///
/// `Clone` so the periodic rebuild path (MAC resolution + health probes)
/// can copy-on-write a fresh table and `ArcSwap::store` it without
/// blocking workers on a write lock. `RetryConfig::load_tracker` is an
/// `Arc<LoadRateTracker>`, so its accumulated rate state survives the
/// clone untouched.
#[derive(Clone, Debug)]
pub struct ConfigTable {
    pub path: PathBuf,
    slots: [Option<RouteConfig>; 7],
    /// Wall-clock instant each populated slot's QUIC-LB key was loaded.
    /// `None` for empty slots. Stamped at parse time and preserved
    /// across SIGHUP reloads when the encryption key bytes don't change
    /// (see [`Self::inherit_ages_from`]). Drives the `key_age_secs`
    /// field surfaced at `/config` so operators can pace rotation
    /// against a calendar without recording deploys externally.
    loaded_at: [Option<Instant>; 7],
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

        let now = Instant::now();
        let mut slots: [Option<RouteConfig>; 7] = Default::default();
        let mut loaded_at: [Option<Instant>; 7] = [None; 7];
        for config in configs {
            let id = config.config_id as usize;
            slots[id] = Some(config);
            loaded_at[id] = Some(now);
        }

        let wrapper: RawRetryWrapper = toml::from_str(text).map_err(RouteConfigError::Parse)?;
        let retry = wrapper.retry.map(RetryConfig::validate).transpose()?;

        Ok(ConfigTable {
            path: PathBuf::new(),
            slots,
            loaded_at,
            fallback_servers: Vec::new(),
            retry,
        })
    }

    /// Carry per-slot `loaded_at` over from `prev` for any slot whose
    /// QUIC-LB encryption key bytes are unchanged. Also delegates retry
    /// inheritance via [`RetryConfig::inherit_age_from`].
    ///
    /// Called once per SIGHUP reload, after a fresh table has been
    /// parsed but before it's stored. A non-key reload (server
    /// add/remove, MAC change, draining flag flip) leaves the timestamps
    /// alone; only an actual key rotation moves them forward.
    pub fn inherit_ages_from(&mut self, prev: &ConfigTable) {
        for i in 0..7 {
            let (Some(new_cfg), Some(old_cfg)) = (self.slots[i].as_ref(), prev.slots[i].as_ref())
            else {
                continue;
            };
            if new_cfg.encryption.same_key(&old_cfg.encryption) {
                self.loaded_at[i] = prev.loaded_at[i];
            }
        }
        if let (Some(new_retry), Some(old_retry)) = (self.retry.as_mut(), prev.retry.as_ref()) {
            new_retry.inherit_age_from(old_retry);
        }
    }

    /// Wall-clock instant the QUIC-LB key in slot `config_id` was
    /// loaded, or `None` if the slot is empty.
    pub fn loaded_at(&self, config_id: u8) -> Option<Instant> {
        self.loaded_at.get(config_id as usize).copied().flatten()
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
        let now = Instant::now();
        let mut slots: [Option<RouteConfig>; 7] = Default::default();
        let mut loaded_at: [Option<Instant>; 7] = [None; 7];

        for config in configs {
            let id = config.config_id as usize;
            slots[id] = Some(config);
            loaded_at[id] = Some(now);
        }

        let mut table = ConfigTable {
            path: PathBuf::new(),
            slots,
            loaded_at,
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

    #[test]
    fn from_str_stamps_loaded_at_for_populated_slots_only() {
        let table = ConfigTable::from_str(SAMPLE_TOML).unwrap();
        assert!(table.loaded_at(0).is_some());
        assert!(table.loaded_at(1).is_none());
    }

    #[test]
    fn inherit_ages_from_preserves_unchanged_qlb_key() {
        // Two parses of the same TOML produce the same key bytes; the
        // second table inherits the first's timestamp.
        let prev = ConfigTable::from_str(SAMPLE_TOML).unwrap();
        let prev_t = prev.loaded_at(0).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let mut next = ConfigTable::from_str(SAMPLE_TOML).unwrap();
        assert!(
            next.loaded_at(0).unwrap() > prev_t,
            "fresh stamp before inherit"
        );

        next.inherit_ages_from(&prev);
        assert_eq!(next.loaded_at(0), Some(prev_t));
    }

    #[test]
    fn inherit_ages_from_resets_when_qlb_key_changes() {
        let toml_b = r#"
[[configs]]
config_id = 0
first_octet_encodes_cid_length = true
server_id_length = 3
nonce_length = 13
key = "ffeeddccbbaa99887766554433221100"

[[configs.servers]]
id = "000001"
address = "10.0.1.10"
"#;
        let prev = ConfigTable::from_str(SAMPLE_TOML).unwrap();
        let mut next = ConfigTable::from_str(toml_b).unwrap();
        let next_t = next.loaded_at(0).unwrap();

        next.inherit_ages_from(&prev);
        // Different key => keep the freshly-stamped time.
        assert_eq!(next.loaded_at(0), Some(next_t));
    }

    #[test]
    fn inherit_ages_from_carries_retry_key_age_when_unchanged() {
        let toml = r#"
[[configs]]
config_id = 0
server_id_length = 3
nonce_length = 13

[retry]
enabled = true
token_key = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
mode = "always"
"#;
        let prev = ConfigTable::from_str(toml).unwrap();
        let prev_t = prev.retry.as_ref().unwrap().loaded_at;
        std::thread::sleep(std::time::Duration::from_millis(5));
        let mut next = ConfigTable::from_str(toml).unwrap();

        next.inherit_ages_from(&prev);
        assert_eq!(next.retry.as_ref().unwrap().loaded_at, prev_t);
    }

    #[test]
    fn inherit_ages_from_resets_retry_when_key_changes() {
        let toml_a = r#"
[[configs]]
config_id = 0
server_id_length = 3
nonce_length = 13

[retry]
enabled = true
token_key = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
mode = "always"
"#;
        let toml_b = r#"
[[configs]]
config_id = 0
server_id_length = 3
nonce_length = 13

[retry]
enabled = true
token_key = "ffffffff0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
mode = "always"
"#;
        let prev = ConfigTable::from_str(toml_a).unwrap();
        let mut next = ConfigTable::from_str(toml_b).unwrap();
        let next_t = next.retry.as_ref().unwrap().loaded_at;

        next.inherit_ages_from(&prev);
        assert_eq!(next.retry.as_ref().unwrap().loaded_at, next_t);
    }
}
