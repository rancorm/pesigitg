// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! Validated `[retry]` TOML section for the QUIC Retry service.
//!
//! Split from [`super::route`] so the retry-specific schema, validation,
//! and tests sit alongside the runtime module at [`crate::retry`].

use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use pesigitg_common::hex;
use serde::Deserialize;

use crate::retry::load::LoadRateTracker;
use crate::retry::token::TokenKey;

use super::route::RouteConfigError;

/// QUIC Retry service enablement mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryMode {
    /// Count what would have been retried but don't emit Retry packets.
    /// Used to shake out classifier false positives before going live.
    Observe,
    /// Every non-token-bearing Initial is Retried.
    Always,
    /// Retry only when the Initial-packet rate crosses
    /// [`RetryConfig::load_trigger_rate`] packets per second.
    Load,
}

impl fmt::Display for RetryMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Observe => write!(f, "observe"),
            Self::Always => write!(f, "always"),
            Self::Load => write!(f, "load"),
        }
    }
}

/// Validated `[retry]` settings. Held inside [`super::route::ConfigTable`]
/// so it rides the same RwLock swap as the rest of the route config on
/// SIGHUP.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Master switch. When `false` every other field is ignored and the
    /// datapath does not consult the Retry module at all.
    pub enabled: bool,
    /// HMAC-SHA256 signing key for mint/verify. Redacted in Debug.
    pub token_key: TokenKey,
    /// Token lifetime used by [`TokenKey::verify`]. Stored in ms so the
    /// verify path doesn't re-multiply every packet.
    pub token_lifetime_ms: u64,
    /// Policy for when to emit Retry packets.
    pub mode: RetryMode,
    /// Optional restriction to specific UDP destination ports. Empty =
    /// apply to every port the daemon is listening on.
    pub ports: Vec<u16>,
    /// For [`RetryMode::Load`]: packets/sec threshold above which Retry
    /// engages. `None` for other modes.
    pub load_trigger_rate: Option<u64>,
    /// For [`RetryMode::Load`]: shared rate counter ticked by every
    /// worker's classifier. `None` for other modes. Held as an `Arc` so
    /// the read-lock on [`super::route::ConfigTable`] hands out the same
    /// counter to every worker without an extra round of cloning.
    pub load_tracker: Option<Arc<LoadRateTracker>>,
    /// Wall-clock instant the current `token_key` was loaded. Set to
    /// `Instant::now()` at validate-time and preserved across SIGHUP
    /// reloads when the key bytes don't change (see
    /// [`Self::inherit_age_from`]). Surfaced as `key_age_secs` in the
    /// status API so operators can pace rotation against a calendar.
    pub loaded_at: Instant,
    /// Optional rotation policy: when `Some(secs)`, the daemon emits a
    /// one-shot warning log line once `loaded_at` is older than `secs`.
    /// `None` disables the nag. Validated `> 0` at parse time.
    pub max_key_age_secs: Option<u64>,
}

impl RetryConfig {
    /// Carry `loaded_at` over from `prev` if the signing key bytes
    /// match. A SIGHUP that touches an unrelated field (mode, ports,
    /// trigger rate) shouldn't look like a key rotation.
    pub fn inherit_age_from(&mut self, prev: &RetryConfig) {
        if self.token_key.same_key(&prev.token_key) {
            self.loaded_at = prev.loaded_at;
        }
    }
}

impl fmt::Display for RetryConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "enabled:          {}", self.enabled)?;
        writeln!(f, "mode:             {}", self.mode)?;
        writeln!(f, "token_lifetime:   {} ms", self.token_lifetime_ms)?;

        if self.ports.is_empty() {
            writeln!(f, "ports:            all")?;
        } else {
            writeln!(f, "ports:            {:?}", self.ports)?;
        }

        if let Some(rate) = self.load_trigger_rate {
            write!(f, "load_trigger:     {} pps", rate)?;
        } else {
            write!(f, "load_trigger:     n/a")?;
        }

        Ok(())
    }
}

#[derive(Deserialize)]
pub(super) struct RawRetry {
    #[serde(default)]
    enabled: bool,
    token_key: Option<String>,
    #[serde(default = "default_token_lifetime_secs")]
    token_lifetime_secs: u64,
    #[serde(default = "default_retry_mode")]
    mode: String,
    #[serde(default)]
    ports: Vec<u16>,
    load: Option<RawRetryLoad>,
    max_key_age_secs: Option<u64>,
}

#[derive(Deserialize)]
struct RawRetryLoad {
    trigger_rate: u64,
}

fn default_token_lifetime_secs() -> u64 {
    10
}

fn default_retry_mode() -> String {
    "observe".to_string()
}

impl RetryConfig {
    pub(super) fn validate(raw: RawRetry) -> Result<Self, RouteConfigError> {
        let mode = match raw.mode.as_str() {
            "observe" => RetryMode::Observe,
            "always" => RetryMode::Always,
            "load" => RetryMode::Load,
            other => {
                return Err(RouteConfigError::Validation(format!(
                    "retry.mode must be one of observe|always|load, got '{}'",
                    other,
                )));
            }
        };

        // token_lifetime_secs: 1..=86400 (1s to 24h). Zero would reject
        // every token immediately; more than a day outlives any sane
        // handshake and leaves replay windows open for no benefit.
        if raw.token_lifetime_secs == 0 || raw.token_lifetime_secs > 86_400 {
            return Err(RouteConfigError::Validation(format!(
                "retry.token_lifetime_secs must be 1..=86400, got {}",
                raw.token_lifetime_secs,
            )));
        }
        let token_lifetime_ms = raw.token_lifetime_secs * 1_000;

        // Token key is mandatory when the service is enabled. When
        // disabled we still require a parseable key if the user supplied
        // one, but accept all-zeros so an operator can pre-stage the
        // section before flipping `enabled = true`.
        let token_key = match raw.token_key.as_deref() {
            Some(hex) => TokenKey::from_bytes(parse_hex_retry_key(hex)?),
            None if raw.enabled => {
                return Err(RouteConfigError::Validation(
                    "retry.token_key is required when retry.enabled = true".into(),
                ));
            }
            None => TokenKey::from_bytes([0u8; 32]),
        };

        let load_trigger_rate = match mode {
            RetryMode::Load => {
                let load = raw.load.ok_or_else(|| {
                    RouteConfigError::Validation(
                        "retry.mode = 'load' requires a [retry.load] section".into(),
                    )
                })?;

                if load.trigger_rate == 0 {
                    return Err(RouteConfigError::Validation(
                        "retry.load.trigger_rate must be > 0".into(),
                    ));
                }

                Some(load.trigger_rate)
            }
            _ => {
                // A [retry.load] block under mode=observe/always is
                // almost certainly a misconfiguration — fail loud so
                // the operator fixes it rather than silently ignoring it.
                if raw.load.is_some() {
                    return Err(RouteConfigError::Validation(format!(
                        "[retry.load] is only valid when retry.mode = 'load' (got '{}')",
                        mode,
                    )));
                }
                None
            }
        };

        // Dedupe + sort port list so downstream membership checks can
        // use binary search and log output is stable across reloads.
        let mut ports = raw.ports;
        ports.sort_unstable();
        ports.dedup();

        let load_tracker = match mode {
            RetryMode::Load => Some(Arc::new(LoadRateTracker::new())),
            _ => None,
        };

        // 0 would mean "warn immediately on any reload", which is just
        // noise; reject so a typo can't suppress the actual policy.
        if let Some(0) = raw.max_key_age_secs {
            return Err(RouteConfigError::Validation(
                "retry.max_key_age_secs must be > 0 when set".into(),
            ));
        }

        Ok(RetryConfig {
            enabled: raw.enabled,
            token_key,
            token_lifetime_ms,
            mode,
            ports,
            load_trigger_rate,
            load_tracker,
            loaded_at: Instant::now(),
            max_key_age_secs: raw.max_key_age_secs,
        })
    }
}

/// Parse a hex-encoded 32-byte HMAC-SHA256 Retry signing key.
///
/// Distinct from [`super::route::parse_hex_key`] (16 bytes / AES-128) so
/// the two keys can never be mistakenly swapped: the lengths don't
/// collide and the error message names the service.
fn parse_hex_retry_key(s: &str) -> Result<[u8; 32], RouteConfigError> {
    let bytes = hex::decode(s)
        .map_err(|e| RouteConfigError::Validation(format!("invalid hex retry token key: {e}")))?;

    if bytes.len() != 32 {
        return Err(RouteConfigError::Validation(format!(
            "retry.token_key must be exactly 32 bytes (256 bits), got {} bytes",
            bytes.len(),
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);

    Ok(key)
}

#[cfg(test)]
#[path = "retry_tests.rs"]
mod tests;
