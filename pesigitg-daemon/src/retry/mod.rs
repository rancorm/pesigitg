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
//! - [`packet`]: Retry wire format, including the RFC 9001 §5.8 (v1)
//!   and RFC 9369 §3.2 (v2) integrity tag.
//! - [`token`]: HMAC-SHA256 mint/verify.
//! - [`datapath`]: Classifier + in-place Retry rewrite, wired into the
//!   worker loop before CID routing.

pub mod datapath;
pub mod packet;
pub mod token;
