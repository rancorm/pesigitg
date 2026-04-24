// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! Unified worker-facing socket boundary that dispatches between a
//! fresh xsk-rs-backed [`XskSocket`] and a raw-syscall
//! [`AdoptedSocket`] (the restart-adopt path).
//!
//! This module is phase-2-a1 scaffolding: it defines the enum, the
//! common [`WorkerFrame`] descriptor, and delegating methods. It does
//! **not** yet replace [`XskSocket`] at the `threading.rs` call site —
//! that's phase-2-a2. The goal here is just to commit the boundary
//! shape and make sure both variants compile against it.

#![allow(dead_code)]

use anyhow::Result;
use libc::xdp_desc;
use std::os::fd::RawFd;

use xsk_rs::FrameDesc;

use crate::xdp_adopt::AdoptedSocket;
use crate::xsk::{XdpMode, XskSocket};

/// Descriptor type shared across both socket variants. A superset of
/// `xdp_desc` plus the `data_len` the caller intends to transmit
/// (for TX) or observed after receive (for RX).
///
/// `addr` is a byte offset from the start of the UMEM region.
#[derive(Debug, Clone, Copy, Default)]
pub struct WorkerFrame {
    pub addr: u64,
    pub len: u32,
    pub options: u32,
}

impl WorkerFrame {
    pub fn from_xdp_desc(d: &xdp_desc) -> Self {
        Self {
            addr: d.addr,
            len: d.len,
            options: d.options,
        }
    }

    pub fn to_xdp_desc(&self) -> xdp_desc {
        xdp_desc {
            addr: self.addr,
            len: self.len,
            options: self.options,
        }
    }

    /// Read back from an xsk-rs [`FrameDesc`]. Note that xsk-rs tracks
    /// segment lengths rather than a single `len`; we flatten to the
    /// packet-data length here, which is what both rings (RX from the
    /// kernel, TX to the kernel) actually carry.
    pub fn from_xsk_frame_desc(d: &FrameDesc) -> Self {
        Self {
            addr: d.addr() as u64,
            len: d.lengths().data() as u32,
            options: d.options(),
        }
    }
}

/// Either a freshly-created xsk-rs socket (cold boot) or a rehydrated
/// raw-syscall socket (warm adopt).
pub enum WorkerSocket {
    Fresh {
        xsk: XskSocket,
        /// Scratch buffer: xsk-rs operates in terms of
        /// [`FrameDesc`], but the worker-facing API uses
        /// [`WorkerFrame`]. We round-trip through this to avoid
        /// per-call allocation.
        scratch_fd: Vec<FrameDesc>,
    },
    Adopted {
        xsk: AdoptedSocket,
        /// Scratch buffer for the xdp_desc side of the boundary.
        scratch_desc: Vec<xdp_desc>,
    },
}

impl WorkerSocket {
    pub fn fresh(interface: &str, queue_id: u32) -> Result<(Self, XdpMode)> {
        let (xsk, mode) = XskSocket::new(interface, queue_id)?;
        Ok((
            Self::Fresh {
                xsk,
                scratch_fd: Vec::new(),
            },
            mode,
        ))
    }

    pub fn adopted(xsk: AdoptedSocket) -> Self {
        Self::Adopted {
            xsk,
            scratch_desc: Vec::new(),
        }
    }

    pub fn raw_fd(&self) -> RawFd {
        match self {
            Self::Fresh { xsk, .. } => xsk.raw_fd(),
            Self::Adopted { xsk, .. } => xsk.raw_fd(),
        }
    }

    /// Drain RX into `out`, returning the count written. `out`'s length
    /// caps the batch size.
    pub fn poll_recv(&mut self, out: &mut [WorkerFrame], timeout_ms: i32) -> usize {
        match self {
            Self::Fresh { xsk, scratch_fd } => {
                scratch_fd.resize(out.len(), FrameDesc::default());
                let n = xsk.poll_recv(&mut scratch_fd[..out.len()], timeout_ms);
                for (dst, src) in out.iter_mut().zip(scratch_fd.iter().take(n)) {
                    *dst = WorkerFrame::from_xsk_frame_desc(src);
                }
                n
            }
            Self::Adopted { xsk, scratch_desc } => {
                scratch_desc.resize(out.len(), xdp_desc_zero());
                let n = xsk.poll_recv(&mut scratch_desc[..out.len()], timeout_ms);
                for (dst, src) in out.iter_mut().zip(scratch_desc.iter().take(n)) {
                    *dst = WorkerFrame::from_xdp_desc(src);
                }
                n
            }
        }
    }

    /// Produce TX descriptors. The `Fresh` variant requires round-trip
    /// through xsk-rs `FrameDesc`, which can only be constructed via
    /// `Default` externally — so this path is lossy and only usable
    /// for frames that were *obtained* from a prior `poll_recv` on
    /// the same socket (xsk-rs mutates `FrameDesc` in place when
    /// `Umem::data_mut` is used to write the packet). For the enum we
    /// side-step this by keeping the original `FrameDesc`s live in
    /// `scratch_fd` between `poll_recv` and `transmit`; callers hand
    /// us indices instead. That refactor belongs with the threading.rs
    /// port in slice (a2) — for now the Fresh path panics if called
    /// directly with synthesized `WorkerFrame`s.
    pub fn transmit(&mut self, frames: &[WorkerFrame]) -> usize {
        match self {
            Self::Fresh { .. } => {
                // Placeholder until slice (a2) lands the threading.rs
                // port. Callers should keep using `XskSocket` directly
                // for now.
                unimplemented!("WorkerSocket::transmit Fresh variant — deferred to slice (a2)");
            }
            Self::Adopted { xsk, scratch_desc } => {
                scratch_desc.clear();
                scratch_desc.extend(frames.iter().map(WorkerFrame::to_xdp_desc));
                xsk.transmit(scratch_desc)
            }
        }
    }

    /// Return frame addresses to the fill ring.
    pub fn refill(&mut self, frames: &[WorkerFrame]) -> usize {
        match self {
            Self::Fresh { .. } => {
                unimplemented!("WorkerSocket::refill Fresh variant — deferred to slice (a2)");
            }
            Self::Adopted { xsk, .. } => {
                let addrs: Vec<u64> = frames.iter().map(|f| f.addr).collect();
                xsk.refill(&addrs)
            }
        }
    }

    /// Drain completed TX from the completion ring. Returns the count.
    pub fn complete(&mut self, out: &mut [WorkerFrame]) -> usize {
        match self {
            Self::Fresh { .. } => {
                unimplemented!("WorkerSocket::complete Fresh variant — deferred to slice (a2)");
            }
            Self::Adopted { xsk, .. } => {
                let mut scratch = vec![0u64; out.len()];
                let n = xsk.complete(&mut scratch);
                for (dst, addr) in out.iter_mut().zip(scratch.iter().take(n)) {
                    *dst = WorkerFrame {
                        addr: *addr,
                        len: 0,
                        options: 0,
                    };
                }
                n
            }
        }
    }
}

fn xdp_desc_zero() -> xdp_desc {
    xdp_desc {
        addr: 0,
        len: 0,
        options: 0,
    }
}
