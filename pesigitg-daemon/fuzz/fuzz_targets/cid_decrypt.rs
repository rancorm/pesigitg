// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! libFuzzer harness for the CID-decryption path.
//!
//! Calls `cid::lookup_config` to extract the DCID + matching
//! `RouteConfig`, then `cid::resolve_server_idx` to drive the chosen
//! decryption pass (plaintext / single-pass AES / four-pass Feistel).
//!
//! A small fixture `ConfigTable` registers one config of each
//! encryption mode so the fuzzer can hit every decrypt branch by
//! varying the config_id bits in the first CID octet. The fixture is
//! built once via `OnceLock` — re-parsing TOML per iteration would
//! dominate the fuzz runtime.
//!
//! Run (from `pesigitg-daemon/fuzz`):
//!
//! ```sh
//! cargo xtask fuzz cid_decrypt --smoke
//! ```

#![no_main]
#![allow(dead_code)]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;

#[path = "../../src/retry"]
mod retry {
    pub mod load;
    pub mod token;
}

#[path = "../../src/config"]
mod config {
    pub mod retry;
    pub mod route;
}

#[path = "../../src/cid.rs"]
mod cid;

// One config per encryption mode. server_id_length + nonce_length
// stays within the 19-byte stack buffer `decrypt_*` operates on.
const FIXTURE_TOML: &str = r#"
# config_id 0: Plaintext (key omitted)
[[configs]]
config_id = 0
server_id_length = 2
nonce_length = 5

[[configs.servers]]
id = "0001"
address = "10.0.0.1"

[[configs.servers]]
id = "0002"
address = "10.0.0.2"

# config_id 1: Single-pass AES (sid + nonce == 16)
[[configs]]
config_id = 1
server_id_length = 3
nonce_length = 13
key = "000102030405060708090a0b0c0d0e0f"

[[configs.servers]]
id = "000001"
address = "10.0.1.10"

# config_id 2: Four-pass Feistel (sid + nonce != 16)
[[configs]]
config_id = 2
server_id_length = 3
nonce_length = 4
key = "0123456789abcdef0123456789abcdef"

[[configs.servers]]
id = "000005"
address = "10.0.2.5"
"#;

static TABLE: OnceLock<config::route::ConfigTable> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let table = TABLE.get_or_init(|| config::route::ConfigTable::from_str(FIXTURE_TOML).unwrap());

    if let Some((dcid, cfg)) = cid::lookup_config(data, table) {
        let _ = cid::resolve_server_idx(dcid, cfg);
    }
});
