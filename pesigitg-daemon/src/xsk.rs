// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! AF_XDP socket wrapper using xsk-rs.
//!
//! Each worker thread owns one `XskSocket` bound to a specific NIC RX queue.
//! The socket receives packets redirected by the XDP program and provides
//! access to frame data for processing and retransmission.

use std::num::NonZeroU32;
use std::ops::DerefMut;
use std::os::fd::{AsRawFd, RawFd};

use anyhow::{Context, Result};
use xsk_rs::config::{BindFlags, LibbpfFlags, QueueSize, SocketConfig, UmemConfig};
use xsk_rs::{CompQueue, FillQueue, FrameDesc, RxQueue, Socket, TxQueue, Umem};

const NUM_FRAMES: u32 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpMode {
    ZeroCopy,
    Copy,
}

impl std::fmt::Display for XdpMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XdpMode::ZeroCopy => write!(f, "zero-copy"),
            XdpMode::Copy => write!(f, "copy"),
        }
    }
}

pub struct XskSocket {
    umem: Umem,
    rx_q: RxQueue,
    tx_q: TxQueue,
    fill_q: FillQueue,
    comp_q: CompQueue,
}

impl XskSocket {
    /// Create a UMEM and AF_XDP socket bound to `queue_id` on `interface`.
    ///
    /// Attempts zero-copy mode first; falls back to copy mode if the
    /// driver or kernel does not support it.  Returns the socket and
    /// the mode that was actually used.
    pub fn new(interface: &str, queue_id: u32) -> Result<(Self, XdpMode)> {
        let iface = interface.parse().context("invalid interface name")?;

        // Try zero-copy first, then fall back to copy mode.
        let modes = [
            (BindFlags::XDP_ZEROCOPY | BindFlags::XDP_USE_NEED_WAKEUP, XdpMode::ZeroCopy),
            (BindFlags::XDP_USE_NEED_WAKEUP, XdpMode::Copy),
        ];

        for (bind_flags, mode) in modes {
            let umem_config = UmemConfig::builder()
                .fill_queue_size(QueueSize::new(NUM_FRAMES).unwrap())
                .comp_queue_size(QueueSize::new(NUM_FRAMES).unwrap())
                .build()
                .expect("invalid UMEM config");

            let (umem, descs) = Umem::new(
                umem_config,
                NonZeroU32::new(NUM_FRAMES).unwrap(),
                false,
            )
            .context("failed to create UMEM")?;

            let socket_config = SocketConfig::builder()
                .libbpf_flags(LibbpfFlags::XSK_LIBBPF_FLAGS_INHIBIT_PROG_LOAD)
                .bind_flags(bind_flags)
                .build();

            match Socket::new(socket_config, &umem, &iface, queue_id) {
                Ok((tx_q, rx_q, fq_cq)) => {
                    let (mut fill_q, comp_q) =
                        fq_cq.context("expected fill and completion queues")?;

                    // Seed the fill ring so the kernel has frames to write RX packets into.
                    unsafe { fill_q.produce(&descs) };

                    return Ok((
                        XskSocket {
                            umem,
                            rx_q,
                            tx_q,
                            fill_q,
                            comp_q,
                        },
                        mode,
                    ));
                }
                Err(_) if mode == XdpMode::ZeroCopy => continue,
                Err(e) => return Err(e).context("failed to create AF_XDP socket"),
            }
        }

        unreachable!()
    }

    /// Socket file descriptor for XSKS map registration.
    pub fn raw_fd(&self) -> RawFd {
        self.rx_q.fd().as_raw_fd()
    }

    /// Poll for received frames, writing descriptors into `descs`.
    /// Returns the number of frames received (0 on timeout).
    pub fn poll_recv(&mut self, descs: &mut [FrameDesc], timeout_ms: i32) -> usize {
        unsafe { self.rx_q.poll_and_consume(descs, timeout_ms) }.unwrap_or(0)
    }

    /// Get mutable access to a frame's packet data.
    ///
    /// # Safety
    /// The caller must ensure `desc` belongs to this socket's UMEM and is
    /// not simultaneously submitted to any queue.
    pub unsafe fn frame_mut<'a>(&'a self, desc: &'a mut FrameDesc) -> impl DerefMut<Target = [u8]> + 'a {
        unsafe { self.umem.data_mut(desc) }
    }

    /// Submit frames for transmission out the interface.
    /// Returns the number of frames actually enqueued.
    pub fn transmit(&mut self, descs: &[FrameDesc]) -> usize {
        if descs.is_empty() {
            return 0;
        }
        let n = unsafe { self.tx_q.produce(descs) };
        if n > 0 && self.tx_q.needs_wakeup() {
            let _ = self.tx_q.wakeup();
        }
        n
    }

    /// Return frames to the fill ring for reuse by the kernel.
    /// Returns the number of frames actually enqueued.
    pub fn refill(&mut self, descs: &[FrameDesc]) -> usize {
        if descs.is_empty() {
            return 0;
        }
        let n = unsafe { self.fill_q.produce(descs) };
        if n > 0 && self.fill_q.needs_wakeup() {
            let _ = self.fill_q.wakeup(self.rx_q.fd_mut(), 0);
        }
        n
    }

    /// Reclaim completed TX frames and return them to the fill ring.
    /// Returns `(consumed, refilled)` — any orphaned frames sit in
    /// `scratch[refilled..consumed]` and must be retried.
    pub fn complete(&mut self, scratch: &mut [FrameDesc]) -> (usize, usize) {
        let consumed = unsafe { self.comp_q.consume(scratch) };
        let refilled = if consumed > 0 {
            unsafe { self.fill_q.produce(&scratch[..consumed]) }
        } else {
            0
        };
        (consumed, refilled)
    }
}
