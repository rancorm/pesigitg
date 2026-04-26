// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! QUIC-LB routing types and Connection ID decode, shared between the
//! daemon datapath and the `pesigitg-ctl` control utility.
//!
//! The daemon wraps these types in a `ConfigTable` that also carries
//! retry-service runtime state; ctl uses them directly to decode CIDs
//! offline against a route TOML file.

pub mod cid;
pub mod route;
