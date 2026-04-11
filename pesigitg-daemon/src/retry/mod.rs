// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! QUIC Retry service.
//!
//! The Retry service moves QUIC address validation from each backend up
//! to the load balancer: the LB inspects every Initial packet, and if
//! the client hasn't yet been validated, emits a Retry packet carrying
//! a signed token. A client that returns a valid token is allowed to
//! continue; everything else is shed before reaching a backend. Under a
//! spoofed-source Initial flood this lets the LB absorb the blast
//! instead of N backends each paying the validation cost.
//!
//! This module is organized around the pieces that can be tested in
//! isolation:
//!
//! - [`packet`]: Retry wire format, including the RFC 9001 §5.8
//!   integrity tag.
//! - `token` (Phase 3): HMAC-SHA256 mint/verify.
//! - Classifier + datapath branch (Phase 4b).

// Items are wired into `process_udp` in Phase 4b of the quic-retry-offload
// plan; until then they are only reachable from their own tests.
#[allow(dead_code)]
pub mod packet;
