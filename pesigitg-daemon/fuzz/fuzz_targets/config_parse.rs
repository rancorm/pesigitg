// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! libFuzzer harness for `config::route::ConfigTable::from_str`.
//!
//! Invariant: arbitrary UTF-8 strings must never cause the TOML route
//! config parser to unwind. Every input either produces a validated
//! [`ConfigTable`] or a [`RouteConfigError`]. Panics on malformed input
//! (hex key length slips, server_id length arithmetic, bad cipher
//! construction, etc.) would surface here.
//!
//! Run (from `pesigitg-daemon/fuzz`):
//!
//! ```sh
//! cargo +nightly fuzz run config_parse
//! ```

#![no_main]
// The included modules expose far more surface than this target exercises
// (we only call `ConfigTable::from_str`), so the unused items would
// otherwise trip clippy's warn-as-error.
#![allow(dead_code)]

use libfuzzer_sys::fuzz_target;

// `pesigitg-daemon` is a bin-only crate, so there's no library to depend
// on from the fuzz package. Point each inline `mod` at the matching real
// source directory so child files resolve inside it, and so references
// like `crate::retry::{load,token}` and `super::retry` inside the
// included files resolve the same way they do in the daemon build.
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

fuzz_target!(|data: &[u8]| {
    // Skip non-UTF-8 input — the file parser takes a string, so fuzzing
    // non-UTF-8 would just exercise the utf8 decoder.
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let _ = config::route::ConfigTable::from_str(s);
});
