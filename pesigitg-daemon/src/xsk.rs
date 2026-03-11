//! AF_XDP socket wrapper using xsk-rs.
//!
//! Each worker thread owns one `XskSocket` bound to a specific NIC RX queue.
//! The socket receives packets redirected by the XDP program and provides
//! access to frame data for processing and retransmission.

use std::num::NonZeroU32;
use std::ops::DerefMut;
use std::os::fd::{AsRawFd, RawFd};

use anyhow::{Context, Result};
use xsk_rs::config::{SocketConfig, UmemConfig};
use xsk_rs::{CompQueue, FillQueue, FrameDesc, RxQueue, Socket, TxQueue, Umem};

const NUM_FRAMES: u32 = 4096;

pub struct XskSocket {
    umem: Umem,
    rx_q: RxQueue,
    tx_q: TxQueue,
    fill_q: FillQueue,
    comp_q: CompQueue,
}

impl XskSocket {
    /// Create a UMEM and AF_XDP socket bound to `queue_id` on `interface`.
    pub fn new(interface: &str, queue_id: u32) -> Result<Self> {
        let (umem, descs) = Umem::new(
            UmemConfig::default(),
            NonZeroU32::new(NUM_FRAMES).unwrap(),
            false,
        )
        .context("failed to create UMEM")?;

        let (tx_q, rx_q, fq_cq) = Socket::new(
            SocketConfig::default(),
            &umem,
            &interface.parse().context("invalid interface name")?,
            queue_id,
        )
        .context("failed to create AF_XDP socket")?;

        let (mut fill_q, comp_q) = fq_cq.context("expected fill and completion queues")?;

        // Seed the fill ring so the kernel has frames to write RX packets into.
        unsafe { fill_q.produce(&descs) };

        Ok(XskSocket {
            umem,
            rx_q,
            tx_q,
            fill_q,
            comp_q,
        })
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
    pub fn transmit(&mut self, descs: &[FrameDesc]) {
        if descs.is_empty() {
            return;
        }

        unsafe {
            self.tx_q.produce_and_wakeup(descs).ok();
        }
    }

    /// Return frames to the fill ring for reuse by the kernel.
    pub fn refill(&mut self, descs: &[FrameDesc]) {
        if descs.is_empty() {
            return;
        }

        unsafe {
            self.fill_q.produce(descs);
        }
    }

    /// Reclaim completed TX frames and return them to the fill ring.
    pub fn complete(&mut self, scratch: &mut [FrameDesc]) {
        let n = unsafe { self.comp_q.consume(scratch) };

        if n > 0 {
            unsafe { self.fill_q.produce(&scratch[..n]) };
        }
    }
}
