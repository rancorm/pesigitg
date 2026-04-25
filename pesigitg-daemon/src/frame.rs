// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! Generic byte-view abstraction over an AF_XDP frame.
//!
//! Both the xsk-rs-backed [`crate::xsk::XskSocket`] and the
//! raw-syscall [`crate::xdp_adopt::AdoptedSocket`] hand out frame
//! buffers of different concrete types (xsk-rs `DataMut` vs. our own
//! raw slice). [`FrameView`] collapses them to a single surface so
//! the retry datapath and packet pipeline can be generic over both.

/// Mutable access to one AF_XDP frame: the current packet bytes, the
/// chunk capacity above them, and a [`resize`][Self::resize] hook
/// that re-sets the frame length and yields the full new slice.
pub trait FrameView {
    /// Current packet bytes (length bounded by the descriptor's
    /// `len` field).
    fn contents(&self) -> &[u8];

    /// Current packet bytes, mutable. Length is unchanged.
    fn contents_mut(&mut self) -> &mut [u8];

    /// Total writable capacity of the chunk this frame sits in. The
    /// retry path checks this before attempting a rewrite.
    ///
    /// Takes `&mut self` because xsk-rs's only path to the chunk
    /// length is through its `Cursor` (which mutably borrows). The
    /// capacity itself is a static property of the UMEM layout.
    fn capacity(&mut self) -> usize;

    /// Update the descriptor's length to `new_len` and return a
    /// mutable slice of exactly that length. Returns `None` if
    /// `new_len` exceeds [`capacity`][Self::capacity].
    ///
    /// Used by the retry path to replace a parsed Initial with a
    /// freshly-built Retry response in one shot. The returned slice
    /// includes any previous bytes at the resized positions — the
    /// caller is expected to overwrite them.
    fn resize(&mut self, new_len: usize) -> Option<&mut [u8]>;
}
