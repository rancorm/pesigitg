// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! Daemon-side CID lookup.
//!
//! Extraction and decryption primitives live in
//! [`pesigitg_routing::cid`] so `pesigitg-ctl` can run the same decode
//! offline. This module adds [`lookup_config`], which indexes the
//! daemon-owned [`ConfigTable`] by the CID's first octet.

// `pub use` so existing `crate::cid::*` callers keep working. Marked
// `allow(unused_imports)` because the fuzz crate `#[path]`-includes
// this file in a context that only consumes a subset of these
// re-exports.
#[allow(unused_imports)]
pub use pesigitg_routing::cid::{extract_raw_dcid, extract_scid, resolve_server_idx};

use crate::config::route::{ConfigTable, RouteConfig};

/// Look up the config for a QUIC packet by extracting the config_id from the
/// CID's first octet and indexing into the config table.
///
/// Returns the DCID slice and the matching config, or `None` if the packet is
/// malformed, config_id is reserved (7), or no config exists for that id.
pub fn lookup_config<'a, 'b>(
    quic: &'a [u8],
    table: &'b ConfigTable,
) -> Option<(&'a [u8], &'b RouteConfig)> {
    let first_octet = pesigitg_routing::cid::first_cid_octet(quic)?;
    let config_id = first_octet >> 5;
    if config_id == 7 {
        return None;
    }
    let config = table.get(config_id)?;
    let dcid = pesigitg_routing::cid::extract_raw_dcid(quic, config.cid_length())?;
    Some((dcid, config))
}
