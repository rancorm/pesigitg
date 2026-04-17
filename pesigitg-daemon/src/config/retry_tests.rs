// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

use super::*;
use crate::config::route::ConfigTable;

// -- [retry] section ----------------------------------------------------

/// Base config appended to every retry test so `from_str` doesn't
/// trip on the "no [[configs]]" guard.
const BASE_CFG: &str = r#"
[[configs]]
config_id = 0
server_id_length = 3
nonce_length = 13
"#;

const RETRY_KEY_HEX: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

#[test]
fn retry_absent_is_none() {
    let table = ConfigTable::from_str(BASE_CFG).unwrap();
    assert!(table.retry.is_none());
}

#[test]
fn retry_disabled_defaults() {
    let toml = format!("{BASE_CFG}\n[retry]\n");
    let table = ConfigTable::from_str(&toml).unwrap();
    let r = table.retry.unwrap();
    assert!(!r.enabled);
    assert_eq!(r.mode, RetryMode::Observe);
    assert_eq!(r.token_lifetime_ms, 10_000);
    assert!(r.ports.is_empty());
    assert_eq!(r.load_trigger_rate, None);
}

#[test]
fn retry_enabled_always_mode() {
    let toml = format!(
        "{BASE_CFG}\n[retry]\nenabled = true\nmode = \"always\"\n\
         token_key = \"{RETRY_KEY_HEX}\"\ntoken_lifetime_secs = 30\n"
    );
    let table = ConfigTable::from_str(&toml).unwrap();
    let r = table.retry.unwrap();
    assert!(r.enabled);
    assert_eq!(r.mode, RetryMode::Always);
    assert_eq!(r.token_lifetime_ms, 30_000);
}

#[test]
fn retry_load_mode_requires_trigger_rate() {
    let toml = format!(
        "{BASE_CFG}\n[retry]\nenabled = true\nmode = \"load\"\n\
         token_key = \"{RETRY_KEY_HEX}\"\n\n[retry.load]\ntrigger_rate = 50000\n"
    );
    let table = ConfigTable::from_str(&toml).unwrap();
    let r = table.retry.unwrap();
    assert_eq!(r.mode, RetryMode::Load);
    assert_eq!(r.load_trigger_rate, Some(50_000));
}

#[test]
fn retry_load_mode_without_section_rejected() {
    let toml = format!(
        "{BASE_CFG}\n[retry]\nenabled = true\nmode = \"load\"\ntoken_key = \"{RETRY_KEY_HEX}\"\n"
    );
    let err = ConfigTable::from_str(&toml).unwrap_err();
    assert!(err.to_string().contains("[retry.load]"));
}

#[test]
fn retry_load_block_under_wrong_mode_rejected() {
    // A stray [retry.load] under observe/always is almost always a typo —
    // fail loud rather than silently ignore.
    let toml = format!(
        "{BASE_CFG}\n[retry]\nenabled = true\nmode = \"always\"\n\
         token_key = \"{RETRY_KEY_HEX}\"\n\n[retry.load]\ntrigger_rate = 1\n"
    );
    let err = ConfigTable::from_str(&toml).unwrap_err();
    assert!(
        err.to_string()
            .contains("only valid when retry.mode = 'load'")
    );
}

#[test]
fn retry_load_zero_trigger_rate_rejected() {
    let toml = format!(
        "{BASE_CFG}\n[retry]\nenabled = true\nmode = \"load\"\n\
         token_key = \"{RETRY_KEY_HEX}\"\n\n[retry.load]\ntrigger_rate = 0\n"
    );
    let err = ConfigTable::from_str(&toml).unwrap_err();
    assert!(err.to_string().contains("trigger_rate"));
}

#[test]
fn retry_enabled_without_token_key_rejected() {
    let toml = format!("{BASE_CFG}\n[retry]\nenabled = true\n");
    let err = ConfigTable::from_str(&toml).unwrap_err();
    assert!(err.to_string().contains("token_key is required"));
}

#[test]
fn retry_disabled_without_key_ok() {
    // Staging: operator writes an empty [retry] block first, flips
    // enabled to true after sharing the signing key out-of-band.
    let toml = format!("{BASE_CFG}\n[retry]\nenabled = false\n");
    let table = ConfigTable::from_str(&toml).unwrap();
    assert!(table.retry.is_some());
}

#[test]
fn retry_bad_mode_rejected() {
    let toml = format!("{BASE_CFG}\n[retry]\nmode = \"sometimes\"\n");
    let err = ConfigTable::from_str(&toml).unwrap_err();
    assert!(err.to_string().contains("observe|always|load"));
}

#[test]
fn retry_bad_key_length_rejected() {
    let toml = format!("{BASE_CFG}\n[retry]\nenabled = true\ntoken_key = \"deadbeef\"\n");
    let err = ConfigTable::from_str(&toml).unwrap_err();
    assert!(err.to_string().contains("32 bytes"));
}

#[test]
fn retry_zero_lifetime_rejected() {
    let toml = format!(
        "{BASE_CFG}\n[retry]\nenabled = true\ntoken_key = \"{RETRY_KEY_HEX}\"\n\
         token_lifetime_secs = 0\n"
    );
    let err = ConfigTable::from_str(&toml).unwrap_err();
    assert!(err.to_string().contains("token_lifetime_secs"));
}

#[test]
fn retry_excessive_lifetime_rejected() {
    let toml = format!(
        "{BASE_CFG}\n[retry]\nenabled = true\ntoken_key = \"{RETRY_KEY_HEX}\"\n\
         token_lifetime_secs = 86401\n"
    );
    let err = ConfigTable::from_str(&toml).unwrap_err();
    assert!(err.to_string().contains("token_lifetime_secs"));
}

#[test]
fn retry_ports_dedupe_and_sort() {
    let toml = format!(
        "{BASE_CFG}\n[retry]\nenabled = true\ntoken_key = \"{RETRY_KEY_HEX}\"\n\
         ports = [4433, 443, 4433, 443, 8443]\n"
    );
    let table = ConfigTable::from_str(&toml).unwrap();
    let r = table.retry.unwrap();
    assert_eq!(r.ports, vec![443, 4433, 8443]);
}

#[test]
fn retry_token_key_redacted_in_debug() {
    // A full RetryConfig Debug print must not leak key bytes.
    let toml = format!("{BASE_CFG}\n[retry]\nenabled = true\ntoken_key = \"{RETRY_KEY_HEX}\"\n");
    let table = ConfigTable::from_str(&toml).unwrap();
    let dbg = format!("{:?}", table.retry.unwrap());
    assert!(dbg.contains("<redacted>"));
    assert!(!dbg.contains("0102030405"));
}
