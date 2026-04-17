// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! libFuzzer harness for `quic::initial::parse_strict`.
//!
//! The single invariant this target enforces: arbitrary byte sequences
//! must never cause the parser to unwind. Every input either produces a
//! parsed view or a `ParseError`. Out-of-bounds indexing, arithmetic
//! overflow, and `unwrap` on malformed inputs would all surface here.
//!
//! Run (from `pesigitg-daemon/fuzz`):
//!
//! ```sh
//! cargo +nightly fuzz run initial_parse
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

// Include the parser source directly. `pesigitg-daemon` is a bin-only
// crate, so there's no library to depend on from the fuzz package; the
// module is self-contained (no `crate::` references) so a path include
// is sufficient and avoids reshaping the whole crate just to fuzz one
// file.
#[path = "../../src/quic/initial.rs"]
mod initial;

fuzz_target!(|data: &[u8]| {
    let _ = initial::parse_strict(data);
});
