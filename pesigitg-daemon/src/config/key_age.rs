// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! One-shot key-age policy enforcement.
//!
//! When a [`RouteConfig::max_key_age_secs`] (or
//! [`RetryConfig::max_key_age_secs`]) is configured and the running
//! key has been live longer than that, the daemon emits a single
//! warning log line per (slot, key) generation. Subsequent ticks stay
//! quiet until the operator rotates the key — at which point the
//! `loaded_at` instant moves forward and the next breach re-arms the
//! warning.

use std::time::Instant;

use log::warn;

use super::route::ConfigTable;

/// Tracks "we've already warned about this exact key" per slot so the
/// daemon doesn't re-log on every tick once the threshold is crossed.
///
/// Identity is the key's `loaded_at` — when the operator rotates a
/// key, [`RetryConfig::inherit_age_from`] / [`ConfigTable::inherit_ages_from`]
/// stamp a fresh `loaded_at` and the new generation rearms its slot.
pub struct KeyAgeWarner {
    qlb_warned_for: [Option<Instant>; 7],
    retry_warned_for: Option<Instant>,
}

impl KeyAgeWarner {
    pub fn new() -> Self {
        Self {
            qlb_warned_for: [None; 7],
            retry_warned_for: None,
        }
    }

    /// Check every configured key against its `max_key_age_secs`,
    /// emitting one warning per slot per key generation. Idempotent
    /// across ticks once the warning has fired.
    pub fn check(&mut self, table: &ConfigTable) {
        self.check_at(table, Instant::now());
    }

    /// Test-friendly variant that takes the wall-clock as a parameter.
    pub fn check_at(&mut self, table: &ConfigTable, now: Instant) {
        for cfg in table.configs() {
            let Some(max) = cfg.max_key_age_secs else {
                continue;
            };
            let Some(loaded) = table.loaded_at(cfg.config_id) else {
                continue;
            };
            let age = now.saturating_duration_since(loaded).as_secs();
            if age <= max {
                continue;
            }
            let slot = cfg.config_id as usize;
            if self.qlb_warned_for[slot] == Some(loaded) {
                continue;
            }
            warn!(
                "QUIC-LB key for config_id={} is {}s old, exceeds max_key_age_secs={}s; \
                 rotate the key",
                cfg.config_id, age, max,
            );
            self.qlb_warned_for[slot] = Some(loaded);
        }

        if let Some(retry) = &table.retry
            && let Some(max) = retry.max_key_age_secs
        {
            let age = now.saturating_duration_since(retry.loaded_at).as_secs();
            if age > max && self.retry_warned_for != Some(retry.loaded_at) {
                warn!(
                    "Retry token key is {}s old, exceeds retry.max_key_age_secs={}s; \
                     rotate retry.token_key",
                    age, max,
                );
                self.retry_warned_for = Some(retry.loaded_at);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const QLB_KEY_TOML: &str = r#"
[[configs]]
config_id = 0
first_octet_encodes_cid_length = true
server_id_length = 3
nonce_length = 13
key = "000102030405060708090a0b0c0d0e0f"
max_key_age_secs = 60

[[configs.servers]]
id = "000001"
address = "10.0.1.10"
"#;

    const RETRY_KEY_TOML: &str = r#"
[[configs]]
config_id = 0
server_id_length = 3
nonce_length = 13

[retry]
enabled = true
token_key = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
mode = "always"
max_key_age_secs = 30
"#;

    /// Compute a "now" instant offset from the slot's loaded_at so tests
    /// can sweep age thresholds without sleeping or mocking the clock.
    fn now_at(table: &ConfigTable, config_id: u8, age_secs: u64) -> Instant {
        table.loaded_at(config_id).unwrap() + Duration::from_secs(age_secs)
    }

    #[test]
    fn qlb_under_threshold_does_not_warn() {
        let table = ConfigTable::from_str(QLB_KEY_TOML).unwrap();
        let mut warner = KeyAgeWarner::new();
        warner.check_at(&table, now_at(&table, 0, 30));
        assert!(warner.qlb_warned_for[0].is_none());
    }

    #[test]
    fn qlb_over_threshold_warns_once_per_key_generation() {
        let table = ConfigTable::from_str(QLB_KEY_TOML).unwrap();
        let mut warner = KeyAgeWarner::new();
        let breached = now_at(&table, 0, 120);

        warner.check_at(&table, breached);
        let first = warner.qlb_warned_for[0];
        assert_eq!(first, table.loaded_at(0));

        // Second check at an even later instant shouldn't bump the
        // marker — already warned for this generation.
        warner.check_at(&table, breached + Duration::from_secs(60));
        assert_eq!(warner.qlb_warned_for[0], first);
    }

    #[test]
    fn qlb_rotation_rearms_warning() {
        let mut table = ConfigTable::from_str(QLB_KEY_TOML).unwrap();
        let mut warner = KeyAgeWarner::new();
        warner.check_at(&table, now_at(&table, 0, 120));
        assert!(warner.qlb_warned_for[0].is_some());

        // Reload with a different key — loaded_at advances, the
        // previously-stamped warning marker no longer matches.
        let toml_b = QLB_KEY_TOML.replace(
            "key = \"000102030405060708090a0b0c0d0e0f\"",
            "key = \"ffeeddccbbaa99887766554433221100\"",
        );
        let new_table = ConfigTable::from_str(&toml_b).unwrap();
        // Inherit ages would NOT carry the timestamp (key changed), so
        // new_table.loaded_at(0) is fresh. Mimic reload_config:
        table = new_table;

        // Threshold not yet exceeded for the new key — quiet.
        warner.check_at(&table, now_at(&table, 0, 30));
        assert_ne!(warner.qlb_warned_for[0], table.loaded_at(0));

        // Cross the threshold for the new key — warns again.
        warner.check_at(&table, now_at(&table, 0, 120));
        assert_eq!(warner.qlb_warned_for[0], table.loaded_at(0));
    }

    #[test]
    fn retry_over_threshold_warns_once() {
        let table = ConfigTable::from_str(RETRY_KEY_TOML).unwrap();
        let retry_loaded = table.retry.as_ref().unwrap().loaded_at;
        let mut warner = KeyAgeWarner::new();

        warner.check_at(&table, retry_loaded + Duration::from_secs(15));
        assert!(warner.retry_warned_for.is_none());

        warner.check_at(&table, retry_loaded + Duration::from_secs(45));
        assert_eq!(warner.retry_warned_for, Some(retry_loaded));

        // Re-check at a later time, same key — still quiet.
        warner.check_at(&table, retry_loaded + Duration::from_secs(120));
        assert_eq!(warner.retry_warned_for, Some(retry_loaded));
    }

    #[test]
    fn no_policy_means_no_warning() {
        // SAMPLE_TOML has no max_key_age_secs anywhere.
        let toml = r#"
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
        let table = ConfigTable::from_str(toml).unwrap();
        let mut warner = KeyAgeWarner::new();
        // Pretend the key is a year old — no policy means no warning.
        warner.check_at(&table, now_at(&table, 0, 31_536_000));
        assert!(warner.qlb_warned_for[0].is_none());
    }
}
