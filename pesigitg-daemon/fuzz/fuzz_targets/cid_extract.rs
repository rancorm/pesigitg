// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! libFuzzer harness for `cid::extract_raw_dcid` and `cid::extract_scid`.
//!
//! These two helpers walk a QUIC long/short header and slice out a CID
//! without needing any decryption state. Invariant: arbitrary input
//! must never panic — out-of-bounds indexing on truncated headers,
//! `cid_length` overflow, or empty-CID edge cases would surface here.
//!
//! Run (from `pesigitg-daemon/fuzz`):
//!
//! ```sh
//! cargo xtask fuzz cid_extract --smoke
//! ```

#![no_main]
#![allow(dead_code)]

use libfuzzer_sys::fuzz_target;

// Same module-tree reconstruction as `config_parse`; cid.rs imports
// `crate::config::route::{ConfigTable, Encryption, RouteConfig}` at file
// scope so the full chain has to resolve even though the harness only
// calls the two pure CID extractors.
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

fuzz_target!(|data: &[u8]| {
    // Use the first byte as `cid_length` (which can legally be 0..=20
    // per QUIC); pass the remainder as the QUIC packet body. Empty
    // input degenerates to cid_length=0 + empty packet, which both
    // helpers must handle.
    let (cid_length, quic) = match data.split_first() {
        Some((b, rest)) => (*b, rest),
        None => (0u8, &[][..]),
    };
    let _ = cid::extract_raw_dcid(quic, cid_length);
    let _ = cid::extract_scid(quic);
});
