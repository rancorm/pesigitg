// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! QUIC wire-format helpers.
//!
//! This module collects parsers and encoders that touch the QUIC long
//! header beyond what [`crate::cid`] already does for CID extraction.
//! Everything here runs on untrusted Internet input on the hot path and
//! must be zero-allocation and panic-free on arbitrary bytes.

pub mod initial;
