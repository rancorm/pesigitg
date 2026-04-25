// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! Generic AF_XDP socket trait. Lets the worker loop dispatch
//! statically between [`crate::xsk::XskSocket`] (cold-boot, xsk-rs)
//! and [`crate::xdp_adopt::AdoptedSocket`] (warm-restart, raw
//! syscalls inherited via FDSTORE) without runtime branching on
//! every ring op.
//!
//! The associated `Frame` type is the per-variant descriptor — xsk-rs
//! `FrameDesc` for the cold path, `xdp_desc` for the warm path. The
//! associated `FrameView<'_>` GAT names the byte-view type each
//! variant produces. Both implement [`crate::frame::FrameView`] so
//! the retry datapath can stay generic.

use std::os::fd::{OwnedFd, RawFd};

use libc::xdp_desc;
use xsk_rs::FrameDesc;

use crate::frame::FrameView;
use crate::xdp_adopt::{AdoptedFrame, AdoptedSocket};
use crate::xsk::{FreshFrame, XskSocket};

/// Common interface for the two AF_XDP socket flavours.
pub trait AfXdpSocket {
    /// Per-variant frame descriptor: held in the worker's batch
    /// buffers and round-tripped through the rings.
    type Frame: Copy;

    /// Per-variant byte view into a frame's chunk.
    type FrameView<'a>: FrameView
    where
        Self: 'a;

    /// Zero-valued frame, used to pre-fill batch buffers before
    /// `poll_recv` overwrites them. `xsk_rs::FrameDesc` has a
    /// `Default` impl; `xdp_desc` does not, so this is a trait
    /// method rather than a `Default` bound.
    fn zero_frame() -> Self::Frame;

    /// FD for `XSKS` map registration.
    fn raw_fd(&self) -> RawFd;

    /// Drain the RX ring into `descs`. Returns the count written.
    fn poll_recv(&mut self, descs: &mut [Self::Frame], timeout_ms: i32) -> usize;

    /// Mutable byte view of the chunk pointed at by `desc`.
    ///
    /// # Safety
    /// `desc` must belong to this socket's UMEM and must not be in
    /// flight on any ring while the returned view is live.
    unsafe fn frame_view<'a>(&'a self, desc: &'a mut Self::Frame) -> Self::FrameView<'a>;

    /// Submit TX frames to the kernel. Returns the count enqueued.
    fn transmit(&mut self, descs: &[Self::Frame]) -> usize;

    /// Hand frame addresses back via the fill ring. Returns the count
    /// enqueued.
    fn refill(&mut self, descs: &[Self::Frame]) -> usize;

    /// Drain the completion ring into `scratch` and immediately try
    /// to refill them via the fill ring. Returns `(consumed,
    /// refilled)`; orphans sit in `scratch[refilled..consumed]` and
    /// must be retried by the caller.
    fn complete(&mut self, scratch: &mut [Self::Frame]) -> (usize, usize);

    /// Optionally consume the socket and return its sockfd + UMEM
    /// memfd for FDSTORE export across a SIGUSR2 handoff.
    ///
    /// `None` for variants whose UMEM is not memfd-backed (e.g.
    /// xsk-rs's `MAP_ANONYMOUS` UMEM, which has no FD that can be
    /// passed to a successor process). The caller treats `None` as
    /// "this queue won't survive the handoff" — phase 1's bpffs
    /// pinning still applies.
    fn detach_for_fdstore(self) -> Option<(OwnedFd, OwnedFd)>;
}

impl AfXdpSocket for XskSocket {
    type Frame = FrameDesc;
    type FrameView<'a> = FreshFrame<'a>;

    fn zero_frame() -> Self::Frame {
        FrameDesc::default()
    }

    fn raw_fd(&self) -> RawFd {
        XskSocket::raw_fd(self)
    }

    fn poll_recv(&mut self, descs: &mut [Self::Frame], timeout_ms: i32) -> usize {
        XskSocket::poll_recv(self, descs, timeout_ms)
    }

    unsafe fn frame_view<'a>(&'a self, desc: &'a mut Self::Frame) -> FreshFrame<'a> {
        // SAFETY: caller upholds the AdoptedSocket-style invariant.
        unsafe { XskSocket::frame_mut(self, desc) }
    }

    fn transmit(&mut self, descs: &[Self::Frame]) -> usize {
        XskSocket::transmit(self, descs)
    }

    fn refill(&mut self, descs: &[Self::Frame]) -> usize {
        XskSocket::refill(self, descs)
    }

    fn complete(&mut self, scratch: &mut [Self::Frame]) -> (usize, usize) {
        XskSocket::complete(self, scratch)
    }

    fn detach_for_fdstore(self) -> Option<(OwnedFd, OwnedFd)> {
        // xsk-rs's UMEM is MAP_ANONYMOUS — there's no backing FD to
        // hand to systemd. Phase 1's bpffs pinning still survives
        // the restart; this queue just goes through cold-create on
        // the next start.
        None
    }
}

impl AfXdpSocket for AdoptedSocket {
    type Frame = xdp_desc;
    type FrameView<'a> = AdoptedFrame<'a>;

    fn zero_frame() -> Self::Frame {
        xdp_desc {
            addr: 0,
            len: 0,
            options: 0,
        }
    }

    fn raw_fd(&self) -> RawFd {
        AdoptedSocket::raw_fd(self)
    }

    fn poll_recv(&mut self, descs: &mut [Self::Frame], timeout_ms: i32) -> usize {
        AdoptedSocket::poll_recv(self, descs, timeout_ms)
    }

    unsafe fn frame_view<'a>(&'a self, desc: &'a mut Self::Frame) -> AdoptedFrame<'a> {
        // SAFETY: caller upholds the invariant.
        unsafe { AdoptedSocket::frame_mut(self, desc) }
    }

    fn transmit(&mut self, descs: &[Self::Frame]) -> usize {
        AdoptedSocket::transmit(self, descs)
    }

    fn refill(&mut self, descs: &[Self::Frame]) -> usize {
        // The fill ring takes raw UMEM addresses, not full descriptors.
        let addrs: Vec<u64> = descs.iter().map(|d| d.addr).collect();
        AdoptedSocket::refill(self, &addrs)
    }

    fn complete(&mut self, scratch: &mut [Self::Frame]) -> (usize, usize) {
        // Drain the completion ring (addresses) directly into a
        // scratch Vec, then mirror them into the descriptor scratch
        // and immediately refill via the fill ring. Mirrors the
        // xsk-rs `complete` shape so the worker loop is identical.
        let mut addrs = vec![0u64; scratch.len()];
        let consumed = AdoptedSocket::complete(self, &mut addrs);
        for (slot, addr) in scratch.iter_mut().zip(addrs.iter().take(consumed)) {
            *slot = xdp_desc {
                addr: *addr,
                len: 0,
                options: 0,
            };
        }
        let refilled = if consumed > 0 {
            AdoptedSocket::refill(self, &addrs[..consumed])
        } else {
            0
        };
        (consumed, refilled)
    }

    fn detach_for_fdstore(self) -> Option<(OwnedFd, OwnedFd)> {
        Some(AdoptedSocket::detach(self))
    }
}
