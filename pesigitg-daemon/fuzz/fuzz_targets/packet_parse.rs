// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! libFuzzer harness for `packet::fuzz_parse_frame`, which wraps the
//! private Ethernet/IP/UDP/ICMP frame parser.
//!
//! Invariant: arbitrary byte sequences must never cause the parser to
//! unwind. Out-of-bounds slicing on truncated headers, IHL/length
//! arithmetic on hostile values, and IPv6 extension-header walks are
//! the natural sources of panics this target would catch.
//!
//! `parse_frame` is private (and returns a private `FrameMeta`), so we
//! call it via the `#[cfg(fuzzing)] pub(crate) fn fuzz_parse_frame`
//! shim added to packet.rs rather than widening the production API.
//!
//! Run (from `pesigitg-daemon/fuzz`):
//!
//! ```sh
//! cargo xtask fuzz packet_parse --smoke
//! ```

#![no_main]
#![allow(dead_code)]

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

#[path = "../../src/conntable.rs"]
mod conntable;

#[path = "../../src/packet.rs"]
mod packet;

// `fuzz_parse_frame` is `#[cfg(fuzzing)]` in packet.rs so it doesn't
// leak into release builds; mirror the gate here so plain
// `cargo clippy --workspace` (no `--cfg fuzzing`) compiles cleanly.
fuzz_target!(|data: &[u8]| {
    #[cfg(fuzzing)]
    let _ = packet::fuzz_parse_frame(data);
    #[cfg(not(fuzzing))]
    let _ = data;
});
