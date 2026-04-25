// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! Raw-syscall AF_XDP socket for the restart-adopt path (phase 2 spike).
//!
//! This module bypasses `xsk-rs` / `libbpf` entirely so that, in the
//! future, an AF_XDP socket FD + memfd-backed UMEM can be passed across
//! `systemctl restart` via systemd FDSTORE and rehydrated into a usable
//! socket without re-binding or re-registering UMEM (both single-shot
//! operations per-kernel-socket).
//!
//! For now this only implements the cold-boot path (`bootstrap`). That
//! exercises every piece of ABI glue the adopt path will need — ring
//! layout from `XDP_MMAP_OFFSETS`, memfd-backed UMEM, the four ring
//! `setsockopt`s in the right order, and `bind(AF_XDP)` — so that when
//! we wire up the real adopt entry point later it's a small delta.
//!
//! Operational methods (`poll_recv`, `transmit`, `refill`, `complete`)
//! are stubs at this stage. They'll land alongside the `WorkerSocket`
//! enum refactor once the creation path is confirmed on hardware.

#![allow(dead_code)]

use std::ffi::CString;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr::{self, NonNull};
use std::slice;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::frame::FrameView;

use anyhow::{Context, Result, bail};
use libc::{
    AF_XDP, MAP_FAILED, MAP_POPULATE, MAP_SHARED, MFD_CLOEXEC, PROT_READ, PROT_WRITE, SOCK_RAW,
    SOL_XDP, XDP_COPY, XDP_MMAP_OFFSETS, XDP_PGOFF_RX_RING, XDP_PGOFF_TX_RING,
    XDP_RING_NEED_WAKEUP, XDP_RX_RING, XDP_TX_RING, XDP_UMEM_COMPLETION_RING, XDP_UMEM_FILL_RING,
    XDP_UMEM_REG, XDP_USE_NEED_WAKEUP, XDP_ZEROCOPY, sockaddr, sockaddr_xdp, socklen_t, xdp_desc,
    xdp_mmap_offsets, xdp_ring_offset, xdp_umem_reg,
};

// linux/if_xdp.h page offsets for the two UMEM rings. Not yet in libc
// 0.2 as named consts; literal values match the kernel header.
const XDP_UMEM_PGOFF_FILL_RING: libc::off_t = 0x1_0000_0000;
const XDP_UMEM_PGOFF_COMPLETION_RING: libc::off_t = 0x1_8000_0000;

/// Default UMEM frame count used by [`AdoptedSocket::bootstrap`] and
/// expected by [`AdoptedSocket::adopt`]. Matches `xsk.rs::NUM_FRAMES`
/// so a cold-boot xsk-rs UMEM and an `AdoptedSocket` UMEM are
/// dimensionally interchangeable.
pub const DEFAULT_FRAME_COUNT: u32 = 4096;

/// Default UMEM chunk size (bytes per frame slot). 2048 matches
/// xsk-rs's default frame size and fits an MTU-1500 frame plus
/// headroom.
pub const DEFAULT_CHUNK_SIZE: u32 = 2048;

/// One of the four AF_XDP producer/consumer rings mapped into userspace.
///
/// `T` is the ring entry type: `u64` for fill/completion (plain UMEM
/// addresses) and [`xdp_desc`] for RX/TX.
struct Ring<T> {
    map_addr: NonNull<libc::c_void>,
    map_len: usize,
    producer: *mut AtomicU32,
    consumer: *mut AtomicU32,
    descs: *mut T,
    flags: *mut AtomicU32,
    size: u32,
    mask: u32,
}

impl<T> Drop for Ring<T> {
    fn drop(&mut self) {
        // SAFETY: `map_addr`/`map_len` came from a successful `mmap`.
        unsafe { libc::munmap(self.map_addr.as_ptr(), self.map_len) };
    }
}

// Ring pointers reference kernel-shared memory; they're `Send` because
// we don't hand them out across threads concurrently (each worker owns
// its own socket) and the kernel synchronises via the producer/consumer
// indices.
unsafe impl<T: Send> Send for Ring<T> {}

impl<T: Copy> Ring<T> {
    /// Produce `entries` into the ring (userspace-as-producer: fill/tx).
    /// Returns the number actually enqueued — the ring may be full.
    ///
    /// # Safety
    /// Must be the sole producer. For fill/tx rings the kernel is the
    /// consumer; for rx/comp the kernel is the producer and this must
    /// not be called.
    unsafe fn produce(&self, entries: &[T]) -> usize {
        if entries.is_empty() {
            return 0;
        }
        // SAFETY: producer is a valid atomic pointer from ring_mmap.
        let prod = unsafe { (*self.producer).load(Ordering::Relaxed) };
        let cons = unsafe { (*self.consumer).load(Ordering::Acquire) };
        let free = self.size.wrapping_sub(prod.wrapping_sub(cons));
        let n = (free as usize).min(entries.len());
        for (i, entry) in entries.iter().take(n).enumerate() {
            let idx = (prod.wrapping_add(i as u32) & self.mask) as usize;
            // SAFETY: idx is in [0, size), descs points to `size` Ts.
            unsafe { self.descs.add(idx).write(*entry) };
        }
        unsafe {
            (*self.producer).store(prod.wrapping_add(n as u32), Ordering::Release);
        }
        n
    }

    /// Consume from the ring (userspace-as-consumer: rx/comp).
    ///
    /// # Safety
    /// Must be the sole consumer. For rx/comp rings the kernel is the
    /// producer; for fill/tx this must not be called.
    unsafe fn consume(&self, out: &mut [T]) -> usize {
        if out.is_empty() {
            return 0;
        }
        // SAFETY: see `produce`.
        let cons = unsafe { (*self.consumer).load(Ordering::Relaxed) };
        let prod = unsafe { (*self.producer).load(Ordering::Acquire) };
        let available = prod.wrapping_sub(cons) as usize;
        let n = available.min(out.len());
        for (i, slot) in out.iter_mut().take(n).enumerate() {
            let idx = (cons.wrapping_add(i as u32) & self.mask) as usize;
            // SAFETY: idx is in [0, size), descs points to `size` Ts.
            *slot = unsafe { self.descs.add(idx).read() };
        }
        unsafe {
            (*self.consumer).store(cons.wrapping_add(n as u32), Ordering::Release);
        }
        n
    }

    fn needs_wakeup(&self) -> bool {
        // SAFETY: flags is a valid atomic pointer from ring_mmap.
        let f = unsafe { (*self.flags).load(Ordering::Relaxed) };
        f & XDP_RING_NEED_WAKEUP != 0
    }
}

/// Memfd-backed UMEM region. The FD is retained so it can be handed
/// across restart via `FDSTORE` in the future; the mapping is dropped
/// via `munmap` in [`Drop`].
struct Umem {
    fd: OwnedFd,
    addr: NonNull<u8>,
    len: usize,
    chunk_size: u32,
    frame_count: u32,
}

impl Drop for Umem {
    fn drop(&mut self) {
        // SAFETY: `addr`/`len` came from a successful `mmap`.
        unsafe { libc::munmap(self.addr.as_ptr().cast(), self.len) };
    }
}

impl Umem {
    /// Dismantle this UMEM without closing the backing memfd. Performs
    /// the `munmap` itself (the outer [`Drop`] would also close `fd`,
    /// which we need to preserve for handoff via FDSTORE).
    fn into_fd(self) -> OwnedFd {
        let me = mem::ManuallyDrop::new(self);
        // SAFETY: `addr`/`len` came from a successful `mmap`; unmap exactly once.
        unsafe { libc::munmap(me.addr.as_ptr().cast(), me.len) };
        // SAFETY: reading `fd` out of ManuallyDrop bypasses the outer
        // Drop (which would close it); we hand ownership to the caller.
        unsafe { ptr::read(&me.fd) }
    }
}

// Same reasoning as Ring: each worker owns its own Umem.
unsafe impl Send for Umem {}

/// An AF_XDP socket built from raw syscalls. Named to foreshadow its
/// future role: the same struct will later be constructed via
/// [`AdoptedSocket::adopt`] from FDs inherited across restart.
pub struct AdoptedSocket {
    fd: OwnedFd,
    umem: Umem,
    rx: Ring<xdp_desc>,
    tx: Ring<xdp_desc>,
    fill: Ring<u64>,
    comp: Ring<u64>,
    ifindex: u32,
    queue_id: u32,
}

impl AdoptedSocket {
    /// Build a fresh AF_XDP socket end-to-end via raw syscalls. This
    /// does not use libbpf or xsk-rs — on purpose. The sequence mirrors
    /// what `libbpf`'s `xsk_socket__create` does internally, which is
    /// also what we'll need to reproduce on the adopt path minus the
    /// setsockopts that have already been applied to the incoming FD.
    ///
    /// `frame_count` must be a power of two. `chunk_size` is the UMEM
    /// frame size (typically 2048 or 4096).
    pub fn bootstrap(
        interface: &str,
        queue_id: u32,
        frame_count: u32,
        chunk_size: u32,
        zerocopy: bool,
    ) -> Result<Self> {
        if !frame_count.is_power_of_two() {
            bail!("frame_count must be a power of two, got {frame_count}");
        }

        let fd = socket_af_xdp().context("socket(AF_XDP, SOCK_RAW)")?;

        let umem_len = (frame_count as usize) * (chunk_size as usize);
        let umem = umem_create(umem_len, frame_count, chunk_size)
            .context("creating memfd-backed UMEM")?;

        let reg = xdp_umem_reg {
            addr: umem.addr.as_ptr() as u64,
            len: umem.len as u64,
            chunk_size,
            headroom: 0,
            flags: 0,
            tx_metadata_len: 0,
        };
        setsockopt(&fd, XDP_UMEM_REG, &reg).context("setsockopt(XDP_UMEM_REG)")?;

        let ring_size = frame_count;
        setsockopt(&fd, XDP_UMEM_FILL_RING, &ring_size)
            .context("setsockopt(XDP_UMEM_FILL_RING)")?;
        setsockopt(&fd, XDP_UMEM_COMPLETION_RING, &ring_size)
            .context("setsockopt(XDP_UMEM_COMPLETION_RING)")?;
        setsockopt(&fd, XDP_RX_RING, &ring_size).context("setsockopt(XDP_RX_RING)")?;
        setsockopt(&fd, XDP_TX_RING, &ring_size).context("setsockopt(XDP_TX_RING)")?;

        let off: xdp_mmap_offsets =
            getsockopt(&fd, XDP_MMAP_OFFSETS).context("getsockopt(XDP_MMAP_OFFSETS)")?;

        let fill =
            ring_mmap::<u64>(&fd, XDP_UMEM_PGOFF_FILL_RING, &off.fr, ring_size).context("fill")?;
        let comp = ring_mmap::<u64>(&fd, XDP_UMEM_PGOFF_COMPLETION_RING, &off.cr, ring_size)
            .context("comp")?;
        let rx = ring_mmap::<xdp_desc>(&fd, XDP_PGOFF_RX_RING, &off.rx, ring_size).context("rx")?;
        let tx = ring_mmap::<xdp_desc>(&fd, XDP_PGOFF_TX_RING, &off.tx, ring_size).context("tx")?;

        let ifindex = crate::utils::if_nametoindex(interface)?;
        let mut flags: u16 = XDP_USE_NEED_WAKEUP;
        flags |= if zerocopy { XDP_ZEROCOPY } else { XDP_COPY };
        let addr = sockaddr_xdp {
            sxdp_family: AF_XDP as u16,
            sxdp_flags: flags,
            sxdp_ifindex: ifindex,
            sxdp_queue_id: queue_id,
            sxdp_shared_umem_fd: 0,
        };
        bind_af_xdp(&fd, &addr).context("bind(AF_XDP)")?;

        Ok(AdoptedSocket {
            fd,
            umem,
            rx,
            tx,
            fill,
            comp,
            ifindex,
            queue_id,
        })
    }

    /// Rehydrate an AF_XDP socket whose FDs were inherited across a
    /// systemd-FDSTORE restart. The caller provides the sockfd and the
    /// UMEM memfd verbatim from `LISTEN_FDS`, plus the `(frame_count,
    /// chunk_size)` we originally created it with (those aren't
    /// recoverable from the kernel — they come from config).
    ///
    /// This skips `socket`, `XDP_UMEM_REG`, all four ring-size
    /// setsockopts, and `bind` — all single-shot per-socket operations
    /// already performed on the incoming FD.
    pub fn adopt(
        sockfd: OwnedFd,
        umem_fd: OwnedFd,
        ifindex: u32,
        queue_id: u32,
        frame_count: u32,
        chunk_size: u32,
    ) -> Result<Self> {
        if !frame_count.is_power_of_two() {
            bail!("frame_count must be a power of two, got {frame_count}");
        }

        let umem_len = (frame_count as usize) * (chunk_size as usize);
        let umem =
            umem_mmap(umem_fd, umem_len, frame_count, chunk_size).context("mmap inherited UMEM")?;

        let off: xdp_mmap_offsets =
            getsockopt(&sockfd, XDP_MMAP_OFFSETS).context("getsockopt(XDP_MMAP_OFFSETS)")?;

        let ring_size = frame_count;
        let fill = ring_mmap::<u64>(&sockfd, XDP_UMEM_PGOFF_FILL_RING, &off.fr, ring_size)
            .context("fill")?;
        let comp = ring_mmap::<u64>(&sockfd, XDP_UMEM_PGOFF_COMPLETION_RING, &off.cr, ring_size)
            .context("comp")?;
        let rx =
            ring_mmap::<xdp_desc>(&sockfd, XDP_PGOFF_RX_RING, &off.rx, ring_size).context("rx")?;
        let tx =
            ring_mmap::<xdp_desc>(&sockfd, XDP_PGOFF_TX_RING, &off.tx, ring_size).context("tx")?;

        Ok(AdoptedSocket {
            fd: sockfd,
            umem,
            rx,
            tx,
            fill,
            comp,
            ifindex,
            queue_id,
        })
    }

    /// Dismantle this socket for handoff across restart. Ring mappings
    /// are unmapped (kernel-side state survives); the sockfd and UMEM
    /// memfd are returned unclosed for the caller to pass via FDSTORE.
    pub fn detach(self) -> (OwnedFd, OwnedFd) {
        let umem_fd = self.umem.into_fd();
        // `self.fd` moves out here; `self.rx/tx/fill/comp` are dropped
        // (each runs `munmap` in its `Drop` impl, which is harmless).
        (self.fd, umem_fd)
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Mutable view of the frame pointed at by `desc`. Returns a
    /// [`FrameView`] over the chunk's writable bytes (capacity ==
    /// `chunk_size`) with `desc.len` as the live length field.
    ///
    /// # Safety
    /// `desc` must belong to this socket's UMEM and must not be
    /// concurrently submitted to any ring while the returned view is
    /// live.
    pub unsafe fn frame_mut<'a>(&'a self, desc: &'a mut xdp_desc) -> AdoptedFrame<'a> {
        let chunk_size = self.umem.chunk_size as usize;
        let offset = desc.addr as usize;
        // SAFETY: caller asserts `desc` belongs to this UMEM, so
        // `offset..offset + chunk_size` lies within the mapping.
        let buf = unsafe {
            slice::from_raw_parts_mut(self.umem.addr.as_ptr().add(offset), chunk_size)
        };
        AdoptedFrame {
            buf,
            len: &mut desc.len,
        }
    }

    pub fn umem_fd(&self) -> RawFd {
        self.umem.fd.as_raw_fd()
    }

    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    pub fn queue_id(&self) -> u32 {
        self.queue_id
    }

    /// Poll for available RX frames with `timeout_ms` (negative = wait
    /// indefinitely, 0 = non-blocking), then drain into `descs`.
    /// Returns the number of descriptors written.
    ///
    /// If the fill ring's `XDP_RING_NEED_WAKEUP` is asserted, this
    /// pokes the kernel via `recvfrom(MSG_DONTWAIT)` before polling so
    /// drivers that need an explicit wake can pick up newly-produced
    /// fill entries.
    pub fn poll_recv(&mut self, descs: &mut [xdp_desc], timeout_ms: i32) -> usize {
        if self.fill.needs_wakeup() {
            let _ = wakeup_recvfrom(&self.fd);
        }

        let mut pfd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is a valid pollfd; single entry.
        let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if rc <= 0 {
            return 0;
        }
        // SAFETY: we are the sole consumer of the rx ring.
        unsafe { self.rx.consume(descs) }
    }

    /// Submit TX descriptors to the kernel via the tx ring. Returns
    /// the number actually enqueued — the ring may be full. If the
    /// kernel asserts `XDP_RING_NEED_WAKEUP` on the tx ring, poke it
    /// via `sendto(MSG_DONTWAIT)`.
    pub fn transmit(&mut self, descs: &[xdp_desc]) -> usize {
        // SAFETY: we are the sole producer of the tx ring.
        let n = unsafe { self.tx.produce(descs) };
        if n > 0 && self.tx.needs_wakeup() {
            let _ = wakeup_sendto(&self.fd);
        }
        n
    }

    /// Hand UMEM frame addresses back to the kernel via the fill ring.
    /// Returns the number actually enqueued — the fill ring may be
    /// full, in which case the caller should retry later.
    ///
    /// If the kernel asserts `XDP_RING_NEED_WAKEUP` on the fill ring
    /// after we produce, poke it via `recvfrom(MSG_DONTWAIT)`.
    pub fn refill(&mut self, addrs: &[u64]) -> usize {
        // SAFETY: we are the sole producer of the fill ring.
        let n = unsafe { self.fill.produce(addrs) };
        if n > 0 && self.fill.needs_wakeup() {
            let _ = wakeup_recvfrom(&self.fd);
        }
        n
    }

    /// Drain completed TX frame addresses from the completion ring
    /// into `scratch`. Returns the number of addresses consumed. The
    /// caller is responsible for handing them back via [`refill`].
    pub fn complete(&mut self, scratch: &mut [u64]) -> usize {
        // SAFETY: we are the sole consumer of the comp ring.
        unsafe { self.comp.consume(scratch) }
    }
}

// --- syscall helpers ---

fn socket_af_xdp() -> io::Result<OwnedFd> {
    // SAFETY: calling a libc socket syscall; return value is validated.
    let fd = unsafe { libc::socket(AF_XDP, SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd was just returned from socket() and is owned by us.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn setsockopt<T>(fd: &OwnedFd, name: i32, value: &T) -> io::Result<()> {
    // SAFETY: `value` is a valid &T, len is sizeof(T).
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            SOL_XDP,
            name,
            (value as *const T).cast(),
            mem::size_of::<T>() as socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn getsockopt<T>(fd: &OwnedFd, name: i32) -> io::Result<T> {
    // SAFETY: zero-init is valid for the POD structs this is used with
    // (`xdp_mmap_offsets`), and `len` tracks the write-back size.
    let mut val: T = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<T>() as socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            SOL_XDP,
            name,
            (&mut val as *mut T).cast(),
            &mut len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != mem::size_of::<T>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "getsockopt({name}) returned {len} bytes, expected {}",
                mem::size_of::<T>()
            ),
        ));
    }
    Ok(val)
}

/// Poke the kernel to pick up ring work when `XDP_RING_NEED_WAKEUP` is
/// asserted. The `recvfrom` is zero-length and non-blocking — the
/// kernel interprets any syscall on the sockfd as a wakeup. `EAGAIN`
/// is the expected success case (no data), so we swallow it.
fn wakeup_recvfrom(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: zero-length buffer, non-blocking flag, null src addr.
    let rc = unsafe {
        libc::recvfrom(
            fd.as_raw_fd(),
            ptr::null_mut(),
            0,
            libc::MSG_DONTWAIT,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if rc < 0 {
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::EAGAIN) | Some(libc::ENOBUFS) | Some(libc::EBUSY) => Ok(()),
            _ => Err(e),
        }
    } else {
        Ok(())
    }
}

/// TX-side counterpart to [`wakeup_recvfrom`]. The kernel treats any
/// `sendto` on the AF_XDP sockfd as a wakeup; a zero-length one avoids
/// actually enqueuing anything.
fn wakeup_sendto(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: zero-length buffer, non-blocking flag, null dest addr.
    let rc = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            ptr::null(),
            0,
            libc::MSG_DONTWAIT,
            ptr::null(),
            0,
        )
    };
    if rc < 0 {
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::EAGAIN) | Some(libc::ENOBUFS) | Some(libc::EBUSY) => Ok(()),
            _ => Err(e),
        }
    } else {
        Ok(())
    }
}

fn bind_af_xdp(fd: &OwnedFd, addr: &sockaddr_xdp) -> io::Result<()> {
    // SAFETY: `addr` is a valid `sockaddr_xdp`, cast to the generic
    // `sockaddr` type expected by libc::bind.
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (addr as *const sockaddr_xdp).cast::<sockaddr>(),
            mem::size_of::<sockaddr_xdp>() as socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// [`FrameView`] over a raw UMEM chunk. Writable capacity is the full
/// chunk size; `len` aliases the descriptor's `len` field so writes
/// via [`FrameView::resize`] flow into the next ring submission.
pub struct AdoptedFrame<'a> {
    buf: &'a mut [u8],
    len: &'a mut u32,
}

impl FrameView for AdoptedFrame<'_> {
    fn contents(&self) -> &[u8] {
        &self.buf[..*self.len as usize]
    }

    fn contents_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..*self.len as usize]
    }

    fn capacity(&mut self) -> usize {
        self.buf.len()
    }

    fn resize(&mut self, new_len: usize) -> Option<&mut [u8]> {
        if new_len > self.buf.len() {
            return None;
        }
        *self.len = new_len as u32;
        Some(&mut self.buf[..new_len])
    }
}

fn page_size() -> usize {
    // SAFETY: sysconf is always safe.
    let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    assert!(ps > 0, "sysconf(_SC_PAGESIZE) returned {ps}");
    ps as usize
}

fn umem_create(len: usize, frame_count: u32, chunk_size: u32) -> Result<Umem> {
    let name = CString::new("pesigitg-umem").unwrap();
    // SAFETY: `name` is a valid C string.
    let raw = unsafe { libc::memfd_create(name.as_ptr(), MFD_CLOEXEC) };
    if raw < 0 {
        return Err(io::Error::last_os_error()).context("memfd_create");
    }
    // SAFETY: raw was just returned from memfd_create and is ours.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    // SAFETY: `fd` is a valid fd.
    let rc = unsafe { libc::ftruncate(fd.as_raw_fd(), len as libc::off_t) };
    if rc < 0 {
        return Err(io::Error::last_os_error()).context("ftruncate(UMEM memfd)");
    }

    umem_mmap(fd, len, frame_count, chunk_size)
}

/// Map an already-sized memfd into this process as a UMEM region.
/// Shared between the cold-boot path (after `memfd_create` + `ftruncate`)
/// and the adopt path (where the memfd came in via FDSTORE).
fn umem_mmap(fd: OwnedFd, len: usize, frame_count: u32, chunk_size: u32) -> Result<Umem> {
    // SAFETY: mapping a sized memfd at fixed length; result checked.
    let addr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            len,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_POPULATE,
            fd.as_raw_fd(),
            0,
        )
    };
    if addr == MAP_FAILED {
        return Err(io::Error::last_os_error()).context("mmap(UMEM memfd)");
    }
    let addr = NonNull::new(addr.cast::<u8>())
        .expect("mmap returned non-MAP_FAILED but null, which should not happen");

    Ok(Umem {
        fd,
        addr,
        len,
        chunk_size,
        frame_count,
    })
}

fn ring_mmap<T>(
    fd: &OwnedFd,
    pgoff: libc::off_t,
    off: &xdp_ring_offset,
    size: u32,
) -> Result<Ring<T>> {
    // The mapping must cover the producer word, consumer word, flags
    // word, and the descriptor array. The kernel guarantees these all
    // fit within a single page-aligned mapping, but the offsets aren't
    // ordered — take the max.
    let desc_end = (off.desc as usize) + (size as usize) * mem::size_of::<T>();
    let mut map_len = desc_end;
    map_len = map_len.max((off.producer as usize) + mem::size_of::<u32>());
    map_len = map_len.max((off.consumer as usize) + mem::size_of::<u32>());
    map_len = map_len.max((off.flags as usize) + mem::size_of::<u32>());
    let ps = page_size();
    map_len = map_len.div_ceil(ps) * ps;

    // SAFETY: mapping a kernel-provided region; result checked.
    let addr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            map_len,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_POPULATE,
            fd.as_raw_fd(),
            pgoff,
        )
    };
    if addr == MAP_FAILED {
        return Err(io::Error::last_os_error()).context("mmap(ring)");
    }
    let map_addr = NonNull::new(addr)
        .expect("mmap returned non-MAP_FAILED but null, which should not happen");
    let base = addr.cast::<u8>();

    Ok(Ring {
        map_addr,
        map_len,
        // SAFETY: offsets are within the mapping by construction above.
        producer: unsafe { base.add(off.producer as usize) }.cast::<AtomicU32>(),
        consumer: unsafe { base.add(off.consumer as usize) }.cast::<AtomicU32>(),
        descs: unsafe { base.add(off.desc as usize) }.cast::<T>(),
        flags: unsafe { base.add(off.flags as usize) }.cast::<AtomicU32>(),
        size,
        mask: size - 1,
    })
}
