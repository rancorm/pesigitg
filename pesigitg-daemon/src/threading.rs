// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use libc::{AF_INET, SOCK_DGRAM, c_char, ioctl, socket};
use log::{debug, error, info, warn};
use nix::sched::{CpuSet, sched_setaffinity};
use nix::unistd::Pid;

use crate::config::route::ConfigTable;
use crate::conntable::ConnectionTable;
use crate::ebpf::EbpfHandle;
use crate::fdstore::InheritedFds;
use crate::frame::FrameView;
use crate::packet::{self, Verdict};
use crate::retry;
use crate::stats::{BatchStats, StatsTable, WorkerStats};
use crate::utils::num_cores;
use crate::worker_socket::AfXdpSocket;
use crate::xdp_adopt::{AdoptedSocket, DEFAULT_CHUNK_SIZE, DEFAULT_FRAME_COUNT};
use crate::xsk::XskSocket;

const ETHTOOL_GCHANNELS: u32 = 0x0000003c;
const SIOCETHTOOL: libc::c_ulong = 0x8946;

const BATCH_SIZE: usize = 64;
const POLL_TIMEOUT_MS: i32 = 100;

/// Per-frame dispatch decision produced inside the FrameView scope.
/// The borrow on `*desc` ends with the `FrameView`, so the worker
/// reads `*desc` (and copies it into the batch vecs) only after this
/// value has been returned.
enum Action {
    /// Retry datapath emitted a Retry response in place — push the
    /// descriptor straight onto the TX ring.
    Emitted,
    /// Normal pipeline ran; act on the resulting verdict.
    Verdict(Verdict),
}

#[repr(C)]
struct EthtoolChannels {
    cmd: u32,
    max_rx: u32,
    max_tx: u32,
    max_other: u32,
    max_combined: u32,
    rx_count: u32,
    tx_count: u32,
    other_count: u32,
    combined_count: u32,
}

#[repr(C)]
struct Ifreq {
    ifr_name: [c_char; 16],
    ifr_data: *mut EthtoolChannels,
}

pub struct ThreadConfig {
    pub queue_id: u32,
    pub core_id: usize,
}

pub fn get_hw_queues(interface: &str) -> std::io::Result<(u32, u32)> {
    let fd = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };

    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut channels = EthtoolChannels {
        cmd: ETHTOOL_GCHANNELS,
        ..unsafe { std::mem::zeroed() }
    };

    let mut ifr: Ifreq = unsafe { std::mem::zeroed() };
    let name = CString::new(interface).unwrap();
    let name_bytes = name.as_bytes_with_nul();

    ifr.ifr_name[..name_bytes.len()]
        .copy_from_slice(unsafe { &*(name_bytes as *const [u8] as *const [c_char]) });
    ifr.ifr_data = &mut channels;

    let ret = unsafe { ioctl(fd, SIOCETHTOOL as _, &mut ifr) };

    unsafe { libc::close(fd) };

    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // combined_count means each queue handles both RX and TX
    // If combined > 0, that's your queue count; otherwise use rx/tx separately
    Ok((channels.combined_count, channels.max_combined))
}

pub fn plan_threads(
    interface: &str,
    max_threads: Option<u32>,
) -> anyhow::Result<Vec<ThreadConfig>> {
    let (hw_queues, _) = get_hw_queues(interface).unwrap_or((1, 1));
    let available_cores = num_cores();
    let requested = max_threads.unwrap_or(hw_queues);
    let count = non_zero_worker_count(hw_queues, requested, available_cores)?;

    if count < requested {
        warn!(
            "worker count clamped to {} (requested {}, hw queues {}, cpu cores {})",
            count, requested, hw_queues, available_cores
        );
    }

    let numa_cores = select_cores(interface, count);

    Ok((0..count)
        .map(|i| ThreadConfig {
            queue_id: i,
            core_id: numa_cores[i as usize],
        })
        .collect())
}

/// Resolve the number of worker threads to spawn: the smaller of the NIC's
/// hardware queue count, the user-requested count, and the CPU cores
/// available for pinning. Prevents `plan_threads` from indexing past the
/// NUMA-local core list when the host has fewer cores than queues.
fn resolve_thread_count(hw_queues: u32, requested: u32, available_cores: usize) -> u32 {
    requested.min(hw_queues).min(available_cores as u32)
}

/// Same as `resolve_thread_count` but refuses to return zero. A zero
/// result means one of the three inputs is zero (the NIC reports no
/// combined channels, the args validator let through a zero request,
/// or the kernel reports no parallelism) — all unrecoverable, so fail
/// loudly at startup instead of silently spawning a no-op daemon.
fn non_zero_worker_count(
    hw_queues: u32,
    requested: u32,
    available_cores: usize,
) -> anyhow::Result<u32> {
    let count = resolve_thread_count(hw_queues, requested, available_cores);
    if count == 0 {
        anyhow::bail!(
            "no workers to spawn: hw queues = {}, requested = {}, cpu cores = {}",
            hw_queues,
            requested,
            available_cores
        );
    }
    Ok(count)
}

/// Pin the calling thread to a specific CPU core.
fn pin_to_core(core_id: usize) -> std::io::Result<()> {
    let mut cpuset = CpuSet::new();
    cpuset.set(core_id).map_err(std::io::Error::other)?;

    // Pid::from_raw(0) means the calling thread
    sched_setaffinity(Pid::from_raw(0), &cpuset).map_err(std::io::Error::other)
}

struct Worker {
    queue_id: u32,
    handle: JoinHandle<()>,
}

/// Lock-free liveness summary for the status API.
pub struct WorkerHealth {
    pub expected: usize,
    pub alive: AtomicUsize,
}

/// A pool of AF_XDP worker threads, one per NIC queue.
pub struct WorkerPool {
    workers: Vec<Worker>,
    shutdown: Arc<AtomicBool>,
    health: Arc<WorkerHealth>,
    /// Receives `(queue_id, sockfd, umem_fd)` triples from workers
    /// whose AF_XDP socket flavour can survive a SIGUSR2 handoff
    /// (see [`AfXdpSocket::detach_for_fdstore`]). Drained on
    /// `shutdown_for_handoff`; discarded by `shutdown`.
    fd_rx: mpsc::Receiver<(u32, OwnedFd, OwnedFd)>,
}

impl WorkerPool {
    /// Spawn one worker thread per `ThreadConfig`.
    ///
    /// Each thread is pinned to its assigned CPU core and processes
    /// packets from the corresponding NIC queue via AF_XDP.
    ///
    /// `inherited` carries `(sockfd, umem_fd)` pairs handed in from
    /// systemd's FDSTORE across a SIGUSR2 handoff. For each queue
    /// whose id appears in `inherited`, the worker rehydrates the
    /// socket via [`AdoptedSocket::adopt`] instead of cold-creating
    /// it; queues without a matching entry follow the cold-boot path.
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        threads: Vec<ThreadConfig>,
        interface: &str,
        local_mac: [u8; 6],
        config: Arc<RwLock<ConfigTable>>,
        ebpf: Arc<Mutex<EbpfHandle>>,
        shutdown: Arc<AtomicBool>,
        stats: Arc<StatsTable>,
        mut inherited: InheritedFds,
    ) -> Self {
        let mut workers = Vec::with_capacity(threads.len());
        let (fd_tx, fd_rx) = mpsc::channel::<(u32, OwnedFd, OwnedFd)>();

        for (worker_idx, tc) in threads.into_iter().enumerate() {
            let shutdown = Arc::clone(&shutdown);
            let config = Arc::clone(&config);
            let ebpf = Arc::clone(&ebpf);
            let stats = Arc::clone(&stats);
            let interface = interface.to_owned();
            let queue_id = tc.queue_id;
            let inherited_pair = inherited.by_queue.remove(&queue_id);
            let fd_tx = fd_tx.clone();

            let handle = thread::Builder::new()
                .name(format!("xdp-q{}", tc.queue_id))
                .spawn(move || {
                    if let Err(e) = pin_to_core(tc.core_id) {
                        error!(
                            "worker q{}: failed to pin to core {}: {}",
                            tc.queue_id, tc.core_id, e
                        );
                        return;
                    }

                    info!("worker q{}: started on core {}", tc.queue_id, tc.core_id);

                    match inherited_pair {
                        Some((sockfd, umem_fd)) => worker_loop_adopt(
                            &interface,
                            tc.queue_id,
                            sockfd,
                            umem_fd,
                            &local_mac,
                            &config,
                            &ebpf,
                            &shutdown,
                            stats.slot(worker_idx),
                            fd_tx,
                        ),
                        None => worker_loop(
                            &interface,
                            tc.queue_id,
                            &local_mac,
                            &config,
                            &ebpf,
                            &shutdown,
                            stats.slot(worker_idx),
                            fd_tx,
                        ),
                    }

                    info!("worker q{}: exiting", tc.queue_id);
                })
                .expect("failed to spawn worker thread");

            workers.push(Worker { queue_id, handle });
        }

        // Any inherited FD that didn't match a queue plan gets dropped
        // here, closing the FD. This is the "kept stale FDs in
        // FDSTORE" recovery path: nothing references them anymore.
        for (qid, _) in inherited.by_queue.drain() {
            warn!(
                "FDSTORE held inherited FDs for queue {} but no worker is planned for it; dropping",
                qid
            );
        }

        // Drop the original tx so the channel closes once every
        // worker thread (and thus every cloned tx) has exited.
        drop(fd_tx);

        let health = Arc::new(WorkerHealth {
            expected: workers.len(),
            alive: AtomicUsize::new(workers.len()),
        });

        WorkerPool {
            workers,
            shutdown,
            health,
            fd_rx,
        }
    }

    /// Queue IDs of worker threads that have exited.
    ///
    /// The shutdown flag being set is the normal exit path; callers
    /// should only treat a non-empty result as unexpected when shutdown
    /// has not been requested.
    pub fn dead_queues(&self) -> Vec<u32> {
        self.workers
            .iter()
            .filter(|w| w.handle.is_finished())
            .map(|w| w.queue_id)
            .collect()
    }

    /// Shared liveness handle for the status API (lock-free reads).
    pub fn health(&self) -> Arc<WorkerHealth> {
        Arc::clone(&self.health)
    }

    /// Publish the current alive-worker count to the shared health handle.
    /// Call once per main-loop iteration.
    pub fn refresh_health(&self) {
        let alive = self
            .workers
            .iter()
            .filter(|w| !w.handle.is_finished())
            .count();
        self.health.alive.store(alive, Ordering::Relaxed);
    }

    /// Signal all workers to stop and wait for them to finish.
    /// Cold path: any FDs workers offered via the FDSTORE channel
    /// are discarded (and closed on drop).
    pub fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);

        for w in self.workers.drain(..) {
            let _ = w.handle.join();
        }

        // Drain so the FDs are closed deterministically rather than
        // sitting in the channel until the pool itself drops.
        while self.fd_rx.try_recv().is_ok() {}
    }

    /// Handoff variant of [`shutdown`]: stops workers and returns
    /// every `(queue_id, sockfd, umem_fd)` triple they detached for
    /// FDSTORE export. Workers whose socket flavour is not
    /// memfd-backed (xsk-rs cold-boot) contribute nothing.
    ///
    /// Caller is expected to feed the result straight into
    /// [`crate::fdstore::export_to_systemd`]. The OwnedFds are kept
    /// open across the return — they only close when the caller
    /// drops them after the FDSTORE handoff completes.
    pub fn shutdown_for_handoff(&mut self) -> Vec<(u32, OwnedFd, OwnedFd)> {
        self.shutdown.store(true, Ordering::Relaxed);

        for w in self.workers.drain(..) {
            let _ = w.handle.join();
        }

        // All worker threads have joined → every cloned fd_tx is
        // dropped → channel closed. try_iter drains everything still
        // in the queue without blocking.
        self.fd_rx.try_iter().collect()
    }
}

/// Cold-boot worker entrypoint. Creates a fresh xsk-rs-backed
/// AF_XDP socket, registers it in the XSKS map, and runs the generic
/// hot loop. On clean exit, offers detached FDs to the FDSTORE
/// channel — `XskSocket::detach_for_fdstore` returns `None` (its
/// UMEM is `MAP_ANONYMOUS` with no backing FD), so this is a no-op
/// today; kept for symmetry with `worker_loop_adopt`.
#[allow(clippy::too_many_arguments)]
fn worker_loop(
    interface: &str,
    queue_id: u32,
    local_mac: &[u8; 6],
    config: &Arc<RwLock<ConfigTable>>,
    ebpf: &Arc<Mutex<EbpfHandle>>,
    shutdown: &AtomicBool,
    stats: &WorkerStats,
    fd_tx: mpsc::Sender<(u32, OwnedFd, OwnedFd)>,
) {
    let (xsk, xdp_mode) = match XskSocket::new(interface, queue_id) {
        Ok(s) => s,
        Err(e) => {
            error!(
                "worker q{}: failed to create AF_XDP socket: {:#}",
                queue_id, e
            );
            return;
        }
    };

    let fd = unsafe { BorrowedFd::borrow_raw(xsk.raw_fd()) };
    if let Err(e) = ebpf.lock().unwrap().register_xsk(queue_id, fd) {
        error!(
            "worker q{}: failed to register in XSKS map: {}",
            queue_id, e
        );
        return;
    }

    info!(
        "worker q{}: AF_XDP socket bound and registered ({})",
        queue_id, xdp_mode
    );

    let xsk = worker_loop_generic(xsk, queue_id, local_mac, config, shutdown, stats);
    if let Some((sock, umem)) = xsk.detach_for_fdstore() {
        let _ = fd_tx.send((queue_id, sock, umem));
    }
}

/// Warm-restart worker entrypoint. Rehydrates an [`AdoptedSocket`]
/// from the systemd-FDSTORE-inherited `(sockfd, umem_fd)` pair,
/// re-registers it in the XSKS map (the slot still references the
/// dead previous-pid FD, so the new daemon must overwrite it), and
/// runs the same hot loop the cold path uses. On clean exit, offers
/// the detached FDs to the FDSTORE channel for re-export.
#[allow(clippy::too_many_arguments)]
fn worker_loop_adopt(
    interface: &str,
    queue_id: u32,
    sockfd: OwnedFd,
    umem_fd: OwnedFd,
    local_mac: &[u8; 6],
    config: &Arc<RwLock<ConfigTable>>,
    ebpf: &Arc<Mutex<EbpfHandle>>,
    shutdown: &AtomicBool,
    stats: &WorkerStats,
    fd_tx: mpsc::Sender<(u32, OwnedFd, OwnedFd)>,
) {
    let ifindex = match crate::utils::if_nametoindex(interface) {
        Ok(i) => i,
        Err(e) => {
            error!(
                "worker q{}: if_nametoindex({}) failed: {:#}",
                queue_id, interface, e
            );
            return;
        }
    };

    let xsk = match AdoptedSocket::adopt(
        sockfd,
        umem_fd,
        ifindex,
        queue_id,
        DEFAULT_FRAME_COUNT,
        DEFAULT_CHUNK_SIZE,
    ) {
        Ok(s) => s,
        Err(e) => {
            error!(
                "worker q{}: failed to adopt AF_XDP socket from FDSTORE: {:#}",
                queue_id, e
            );
            return;
        }
    };

    let fd = unsafe { BorrowedFd::borrow_raw(xsk.raw_fd()) };
    if let Err(e) = ebpf.lock().unwrap().register_xsk(queue_id, fd) {
        error!(
            "worker q{}: failed to register adopted socket in XSKS map: {}",
            queue_id, e
        );
        return;
    }

    info!("worker q{}: AF_XDP socket adopted from FDSTORE", queue_id);

    let xsk = worker_loop_generic(xsk, queue_id, local_mac, config, shutdown, stats);
    if let Some((sock, umem)) = xsk.detach_for_fdstore() {
        let _ = fd_tx.send((queue_id, sock, umem));
    }
}

/// Per-queue hot loop, generic over the AF_XDP socket flavour. Runs
/// on a dedicated, pinned core, receiving packets redirected by the
/// XDP program and forwarding / replying via the same socket.
///
/// Returns the socket on clean exit so the caller can call
/// [`AfXdpSocket::detach_for_fdstore`] for handoff.
fn worker_loop_generic<S: AfXdpSocket>(
    mut xsk: S,
    queue_id: u32,
    local_mac: &[u8; 6],
    config: &Arc<RwLock<ConfigTable>>,
    shutdown: &AtomicBool,
    stats: &WorkerStats,
) -> S {
    let mut rx_descs = vec![S::zero_frame(); BATCH_SIZE];
    let mut comp_descs = vec![S::zero_frame(); BATCH_SIZE];
    let mut conn = ConnectionTable::new();
    // Worst-case backlog in one iteration: comp leftovers + tx leftovers
    // + recycle leftovers, each up to BATCH_SIZE. Sizing for 2*BATCH_SIZE
    // keeps the common overflow case (one of those three stalls) from
    // reallocating, while a sustained NIC stall will still grow it.
    let mut pending_fill: Vec<S::Frame> = Vec::with_capacity(BATCH_SIZE * 2);
    let mut tx_batch: Vec<S::Frame> = Vec::with_capacity(BATCH_SIZE);
    let mut recycle_batch: Vec<S::Frame> = Vec::with_capacity(BATCH_SIZE);

    let worker_start = Instant::now();
    let mut first_packet_logged = false;

    while !shutdown.load(Ordering::Relaxed) {
        // Drain frames that couldn't be refilled on prior iterations.
        if !pending_fill.is_empty() {
            let refilled = xsk.refill(&pending_fill);
            pending_fill.drain(..refilled);
        }

        // Always drain TX completions, even when idle.
        let (consumed, refilled) = xsk.complete(&mut comp_descs);
        if refilled < consumed {
            pending_fill.extend_from_slice(&comp_descs[refilled..consumed]);
        }

        let now = Instant::now();
        conn.maybe_sweep(now);

        let n = xsk.poll_recv(&mut rx_descs, POLL_TIMEOUT_MS);
        if n == 0 {
            continue;
        }

        // Wall-clock ms feeds the Retry token mint/verify path. One
        // sample per batch is plenty — token lifetimes are measured in
        // seconds.
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        if !first_packet_logged {
            debug!(
                "worker q{}: first packet at T+{:.2?}",
                queue_id,
                worker_start.elapsed()
            );
            first_packet_logged = true;
        }

        let config = config.read().expect("lock poisoned");

        tx_batch.clear();
        recycle_batch.clear();

        stats.record_rx(n as u64);

        let mut batch_stats = BatchStats::new();

        for desc in rx_descs[..n].iter_mut() {
            // Compute the dispatch decision in an inner scope so the
            // FrameView's borrow on `*desc` is released before we
            // copy the descriptor into the batch vecs below.
            let action: Action = {
                let mut data = unsafe { xsk.frame_view(desc) };

                // Retry fast path: if the classifier emits a Retry
                // packet in place of the Initial, ship it straight to
                // TX. Otherwise fall through to the normal routing
                // logic — Forward and Skip both defer to process_packet
                // so the CID path still runs.
                let (retry_outcome, retry_detail) =
                    retry::datapath::try_handle(&mut data, &config, local_mac, now_ms);
                batch_stats.record_retry(retry_outcome, retry_detail);
                match retry_outcome {
                    retry::datapath::Outcome::Emitted => Action::Emitted,
                    retry::datapath::Outcome::Forward | retry::datapath::Outcome::Skip => {
                        Action::Verdict(packet::process_packet(
                            data.contents_mut(),
                            &config,
                            &mut conn,
                            local_mac,
                            now,
                        ))
                    }
                }
            };
            let verdict = match action {
                Action::Emitted => {
                    tx_batch.push(*desc);
                    continue;
                }
                Action::Verdict(v) => v,
            };
            match verdict {
                Verdict::CidForward(config_id) => {
                    batch_stats.record_cid_forward(config_id);
                    tx_batch.push(*desc);
                }
                Verdict::CidForwardDraining(config_id) => {
                    batch_stats.record_cid_forward(config_id);
                    batch_stats.record_draining_forward();
                    tx_batch.push(*desc);
                }
                Verdict::FallbackForward => {
                    batch_stats.record_fallback_forward();
                    tx_batch.push(*desc);
                }
                Verdict::IcmpForward => {
                    batch_stats.record_icmp_forward();
                    tx_batch.push(*desc);
                }
                Verdict::CidUnroutable => {
                    batch_stats.record_cid_unroutable();
                    recycle_batch.push(*desc);
                }
                Verdict::Pass => {
                    batch_stats.record_pass();
                    recycle_batch.push(*desc);
                }
            }
        }

        batch_stats.flush(stats);

        drop(config);

        let sent = xsk.transmit(&tx_batch);
        if sent < tx_batch.len() {
            pending_fill.extend_from_slice(&tx_batch[sent..]);
        }

        let refilled = xsk.refill(&recycle_batch);
        if refilled < recycle_batch.len() {
            pending_fill.extend_from_slice(&recycle_batch[refilled..]);
        }

        stats.record_pending_fill(pending_fill.len() as u64);
    }

    xsk
}

fn select_cores(interface: &str, queue_count: u32) -> Vec<usize> {
    // Prefer cores on the same NUMA node as the NIC, and within each
    // NUMA bucket prefer SMT primaries before their hyperthread
    // siblings. On AMD EPYC NPS>1 (and anything else with multiple
    // NUMA nodes per socket) the CPU's `topology/physical_package_id`
    // reports the *socket*, not the node — so read node<N>/cpulist.

    let nic_numa =
        std::fs::read_to_string(format!("/sys/class/net/{}/device/numa_node", interface))
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok())
            .unwrap_or(0);

    let numa_map = read_cpu_numa_map_from(Path::new("/sys/devices/system/node"));
    let primaries = read_smt_primaries_from(Path::new("/sys/devices/system/cpu"));

    let cpus_with_smt: Vec<(usize, i32, bool)> = (0..num_cores())
        .map(|cpu| {
            let numa = numa_map.get(&cpu).copied().unwrap_or(0);
            // Empty primaries set => sysfs unreadable, treat every CPU
            // as a primary (no reordering).
            let is_primary = primaries.is_empty() || primaries.contains(&cpu);
            (cpu, numa, is_primary)
        })
        .collect();

    let cpus = order_primaries_first(&cpus_with_smt);
    pick_numa_local_cores(nic_numa, &cpus, queue_count)
}

/// Parse a Linux sysfs cpulist (e.g. `"0-7,16,24-31"`) into a flat list
/// of CPU ids. Malformed parts are silently skipped — this is a
/// best-effort read of a kernel-formatted file.
fn parse_cpulist(s: &str) -> Vec<usize> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part.split_once('-') {
            Some((lo, hi)) => {
                if let (Ok(lo), Ok(hi)) = (lo.parse::<usize>(), hi.parse::<usize>()) {
                    for cpu in lo..=hi {
                        out.push(cpu);
                    }
                }
            }
            None => {
                if let Ok(cpu) = part.parse::<usize>() {
                    out.push(cpu);
                }
            }
        }
    }
    out
}

/// Build a cpu->node map from `(node_id, cpulist)` pairs. Last writer
/// wins if a cpu appears under multiple nodes (shouldn't happen in
/// kernel-reported data).
fn build_cpu_numa_map(entries: &[(i32, &str)]) -> HashMap<usize, i32> {
    let mut map = HashMap::new();
    for &(node, cpulist) in entries {
        for cpu in parse_cpulist(cpulist) {
            map.insert(cpu, node);
        }
    }
    map
}

/// Enumerate `node<N>` directories under `node_root` and return a
/// cpu->node map built from their `cpulist` files. Returns an empty
/// map if the root is unreadable (non-NUMA kernels, containers without
/// the sysfs subtree, etc.) — callers fall back to treating every cpu
/// as node 0.
fn read_cpu_numa_map_from(node_root: &Path) -> HashMap<usize, i32> {
    let dir = match std::fs::read_dir(node_root) {
        Ok(d) => d,
        Err(_) => return HashMap::new(),
    };
    let mut entries: Vec<(i32, String)> = Vec::new();
    for e in dir.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        let Some(rest) = name.strip_prefix("node") else {
            continue;
        };
        let Ok(node) = rest.parse::<i32>() else {
            continue;
        };
        let cpulist_path = e.path().join("cpulist");
        if let Ok(s) = std::fs::read_to_string(&cpulist_path) {
            entries.push((node, s.trim().to_string()));
        }
    }
    let refs: Vec<(i32, &str)> = entries.iter().map(|(n, s)| (*n, s.as_str())).collect();
    build_cpu_numa_map(&refs)
}

/// A logical CPU is its physical core's "primary" when its id is the
/// lowest in the sysfs `thread_siblings_list`. Pinning primaries first
/// spreads load across distinct physical cores before doubling up on
/// SMT siblings, which share L1d/L2 and execution resources.
fn is_smt_primary(cpu: usize, siblings_list: &str) -> bool {
    parse_cpulist(siblings_list)
        .into_iter()
        .min()
        .is_some_and(|min| min == cpu)
}

/// Enumerate `cpu<N>` directories under `cpu_root`, read each CPU's
/// `topology/thread_siblings_list`, and return the set of primaries.
/// Returns an empty set when the subtree isn't readable — callers
/// treat that as "SMT info unavailable, don't reorder".
fn read_smt_primaries_from(cpu_root: &Path) -> HashSet<usize> {
    let mut primaries = HashSet::new();
    let dir = match std::fs::read_dir(cpu_root) {
        Ok(d) => d,
        Err(_) => return primaries,
    };
    for e in dir.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        let Some(rest) = name.strip_prefix("cpu") else {
            continue;
        };
        let Ok(cpu) = rest.parse::<usize>() else {
            continue;
        };
        let siblings_path = e.path().join("topology/thread_siblings_list");
        if let Ok(s) = std::fs::read_to_string(&siblings_path)
            && is_smt_primary(cpu, s.trim())
        {
            primaries.insert(cpu);
        }
    }
    primaries
}

/// Stable partition: primaries first, siblings after. Preserves CPU
/// order within each group so callers downstream (`pick_numa_local_cores`)
/// see primaries ahead of their SMT siblings within each NUMA bucket.
fn order_primaries_first(cpus: &[(usize, i32, bool)]) -> Vec<(usize, i32)> {
    let (primaries, siblings): (Vec<_>, Vec<_>) =
        cpus.iter().partition(|&&(_, _, is_primary)| is_primary);
    primaries
        .into_iter()
        .chain(siblings)
        .map(|&(cpu, numa, _)| (cpu, numa))
        .collect()
}

/// Pick up to `queue_count` CPU cores preferring those on the same NUMA
/// node as `nic_numa`, falling back to remote cores to fill the quota.
/// CPU order is preserved within each bucket.
fn pick_numa_local_cores(nic_numa: i32, cpus: &[(usize, i32)], queue_count: u32) -> Vec<usize> {
    let mut local = Vec::new();
    let mut remote = Vec::new();

    for &(cpu, numa) in cpus {
        if numa == nic_numa {
            local.push(cpu);
        } else {
            remote.push(cpu);
        }
    }

    local.extend(remote);
    local.truncate(queue_count as usize);
    local
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    // ---------- resolve_thread_count ----------

    #[test]
    fn resolve_thread_count_no_clamp_when_all_sufficient() {
        // Host has headroom: requested is the binding constraint.
        assert_eq!(resolve_thread_count(16, 8, 32), 8);
    }

    #[test]
    fn resolve_thread_count_clamped_by_hw_queues() {
        // User asked for more workers than the NIC can feed.
        assert_eq!(resolve_thread_count(4, 16, 32), 4);
    }

    #[test]
    fn resolve_thread_count_clamped_by_available_cores() {
        // Regression: panic when min(hw_queues, requested) > num_cores().
        assert_eq!(resolve_thread_count(64, 64, 16), 16);
    }

    #[test]
    fn resolve_thread_count_all_three_constraints_tie() {
        assert_eq!(resolve_thread_count(8, 8, 8), 8);
    }

    #[test]
    fn resolve_thread_count_zero_requested_returns_zero() {
        assert_eq!(resolve_thread_count(4, 0, 4), 0);
    }

    #[test]
    fn resolve_thread_count_zero_cores_returns_zero() {
        assert_eq!(resolve_thread_count(4, 4, 0), 0);
    }

    // ---------- non_zero_worker_count ----------

    #[test]
    fn non_zero_worker_count_succeeds_when_all_positive() {
        assert_eq!(non_zero_worker_count(4, 4, 8).unwrap(), 4);
    }

    #[test]
    fn non_zero_worker_count_errors_when_hw_queues_zero() {
        // Ethtool reports 0 combined channels — misconfigured NIC.
        let err = non_zero_worker_count(0, 4, 8).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("hw queues = 0"), "msg={msg}");
    }

    #[test]
    fn non_zero_worker_count_errors_when_available_cores_zero() {
        // Pathological: available_parallelism() returned 0.
        let err = non_zero_worker_count(4, 4, 0).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("cpu cores = 0"), "msg={msg}");
    }

    #[test]
    fn non_zero_worker_count_errors_when_requested_zero() {
        // args validator should already reject this, but belt-and-braces.
        let err = non_zero_worker_count(4, 0, 8).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("requested = 0"), "msg={msg}");
    }

    // ---------- parse_cpulist ----------

    #[test]
    fn parse_cpulist_single_range() {
        assert_eq!(parse_cpulist("0-5"), vec![0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn parse_cpulist_single_cpu() {
        assert_eq!(parse_cpulist("7"), vec![7]);
    }

    #[test]
    fn parse_cpulist_multiple_ranges() {
        // EPYC NPS=4 style: each node owns a non-contiguous CPU set.
        assert_eq!(parse_cpulist("0-3,16-19"), vec![0, 1, 2, 3, 16, 17, 18, 19]);
    }

    #[test]
    fn parse_cpulist_mixed_singles_and_ranges() {
        assert_eq!(parse_cpulist("0,2-3,7"), vec![0, 2, 3, 7]);
    }

    #[test]
    fn parse_cpulist_empty_string() {
        assert!(parse_cpulist("").is_empty());
    }

    #[test]
    fn parse_cpulist_skips_malformed_parts() {
        // Unparseable tokens should be dropped, not panic.
        assert_eq!(parse_cpulist("0-2,junk,5"), vec![0, 1, 2, 5]);
    }

    #[test]
    fn parse_cpulist_tolerates_whitespace() {
        assert_eq!(parse_cpulist(" 0-1 ,  4 "), vec![0, 1, 4]);
    }

    // ---------- build_cpu_numa_map ----------

    #[test]
    fn build_cpu_numa_map_single_node() {
        let map = build_cpu_numa_map(&[(0, "0-3")]);
        for cpu in 0..=3 {
            assert_eq!(map.get(&cpu), Some(&0));
        }
        assert!(!map.contains_key(&4));
    }

    #[test]
    fn build_cpu_numa_map_epyc_nps4_style() {
        // Regression for the socket-vs-NUMA bug: a single-socket AMD
        // with NPS=4 exposes four NUMA nodes, and each CPU belongs to
        // exactly one node — even though `physical_package_id` would
        // report socket 0 for all of them.
        let map = build_cpu_numa_map(&[(0, "0-3"), (1, "4-7"), (2, "8-11"), (3, "12-15")]);
        assert_eq!(map.get(&0), Some(&0));
        assert_eq!(map.get(&5), Some(&1));
        assert_eq!(map.get(&10), Some(&2));
        assert_eq!(map.get(&15), Some(&3));
    }

    #[test]
    fn build_cpu_numa_map_empty_input_yields_empty_map() {
        let map = build_cpu_numa_map(&[]);
        assert!(map.is_empty());
    }

    // ---------- is_smt_primary ----------

    #[test]
    fn is_smt_primary_true_for_min_sibling() {
        // Intel HT style: logical CPUs 0 and 8 share a physical core.
        assert!(is_smt_primary(0, "0,8"));
    }

    #[test]
    fn is_smt_primary_false_for_non_min_sibling() {
        assert!(!is_smt_primary(8, "0,8"));
    }

    #[test]
    fn is_smt_primary_true_when_no_siblings() {
        // Non-SMT CPU: sibling list is just itself.
        assert!(is_smt_primary(4, "4"));
    }

    #[test]
    fn is_smt_primary_handles_range_syntax() {
        // Some kernels emit thread_siblings_list as a range.
        assert!(is_smt_primary(2, "2-3"));
        assert!(!is_smt_primary(3, "2-3"));
    }

    #[test]
    fn is_smt_primary_false_on_unparseable_list() {
        // Empty / garbage => no min, no primary claim.
        assert!(!is_smt_primary(0, ""));
    }

    // ---------- order_primaries_first ----------

    #[test]
    fn order_primaries_first_separates_by_flag() {
        // 4 logical CPUs, SMT pairs (0,1) and (2,3) with 0 and 2 primary.
        let input = [(0, 0, true), (1, 0, false), (2, 0, true), (3, 0, false)];
        assert_eq!(
            order_primaries_first(&input),
            vec![(0, 0), (2, 0), (1, 0), (3, 0)]
        );
    }

    #[test]
    fn order_primaries_first_preserves_original_order_within_groups() {
        // Stability matters — NUMA ordering downstream depends on it.
        let input = [(5, 1, false), (0, 0, true), (3, 1, true), (2, 0, false)];
        assert_eq!(
            order_primaries_first(&input),
            vec![(0, 0), (3, 1), (5, 1), (2, 0)]
        );
    }

    #[test]
    fn order_primaries_first_no_primaries_preserves_all() {
        let input = [(0, 0, false), (1, 0, false)];
        assert_eq!(order_primaries_first(&input), vec![(0, 0), (1, 0)]);
    }

    #[test]
    fn order_primaries_first_all_primaries_preserves_all() {
        let input = [(0, 0, true), (1, 0, true)];
        assert_eq!(order_primaries_first(&input), vec![(0, 0), (1, 0)]);
    }

    #[test]
    fn order_primaries_first_then_pick_numa_prefers_physical_cores() {
        // End-to-end check: on an 8-logical, 4-physical box with the
        // NIC on node 0 and only 2 queues, we should pin queues to
        // two different physical cores (primaries 0 and 2), not both
        // siblings of the same physical core.
        let cpus = [
            (0, 0, true),  // core A primary
            (1, 0, false), // core A sibling
            (2, 0, true),  // core B primary
            (3, 0, false), // core B sibling
            (4, 0, true),  // core C primary
            (5, 0, false),
            (6, 0, true),
            (7, 0, false),
        ];
        let ordered = order_primaries_first(&cpus);
        let picked = pick_numa_local_cores(0, &ordered, 2);
        assert_eq!(picked, vec![0, 2]);
    }

    // ---------- pick_numa_local_cores ----------

    #[test]
    fn pick_numa_local_cores_prefers_local_numa() {
        let cpus = [(0, 1), (1, 0), (2, 1), (3, 0)];
        // nic on node 0: cpu 1 and 3 are local.
        let picked = pick_numa_local_cores(0, &cpus, 4);

        assert_eq!(picked, vec![1, 3, 0, 2]);
    }

    #[test]
    fn pick_numa_local_cores_fills_with_remote_when_local_insufficient() {
        let cpus = [(0, 0), (1, 1), (2, 1), (3, 1)];
        // Only cpu 0 is local; queue_count=3 needs two remote fillers.
        let picked = pick_numa_local_cores(0, &cpus, 3);

        assert_eq!(picked, vec![0, 1, 2]);
    }

    #[test]
    fn pick_numa_local_cores_truncates_to_queue_count() {
        let cpus = [(0, 0), (1, 0), (2, 0), (3, 0)];
        let picked = pick_numa_local_cores(0, &cpus, 2);

        assert_eq!(picked, vec![0, 1]);
    }

    #[test]
    fn pick_numa_local_cores_returns_empty_for_zero_queue_count() {
        let cpus = [(0, 0), (1, 1)];
        assert!(pick_numa_local_cores(0, &cpus, 0).is_empty());
    }

    #[test]
    fn pick_numa_local_cores_no_local_falls_entirely_to_remote() {
        let cpus = [(0, 1), (1, 1), (2, 1)];
        // nic on node 0 but no cpu reports node 0.
        let picked = pick_numa_local_cores(0, &cpus, 2);

        assert_eq!(picked, vec![0, 1]);
    }

    // ---------- WorkerPool lifecycle ----------

    fn park_worker(queue_id: u32, shutdown: Arc<AtomicBool>) -> Worker {
        let handle = thread::Builder::new()
            .name(format!("test-q{}", queue_id))
            .spawn(move || {
                while !shutdown.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(1));
                }
            })
            .expect("spawn test worker");
        Worker { queue_id, handle }
    }

    fn finished_worker(queue_id: u32) -> Worker {
        let (tx, rx) = mpsc::channel::<()>();
        let handle = thread::Builder::new()
            .name(format!("test-done-q{}", queue_id))
            .spawn(move || {
                let _ = rx.recv();
            })
            .expect("spawn test worker");
        drop(tx);
        // Wait until the thread observes the disconnect and exits.
        while !handle.is_finished() {
            thread::yield_now();
        }
        Worker { queue_id, handle }
    }

    fn test_pool(workers: Vec<Worker>, shutdown: Arc<AtomicBool>) -> WorkerPool {
        let health = Arc::new(WorkerHealth {
            expected: workers.len(),
            alive: AtomicUsize::new(workers.len()),
        });
        let (_fd_tx, fd_rx) = mpsc::channel::<(u32, OwnedFd, OwnedFd)>();
        WorkerPool {
            workers,
            shutdown,
            health,
            fd_rx,
        }
    }

    #[test]
    fn worker_pool_initial_health_matches_worker_count() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let workers = (0..3)
            .map(|q| park_worker(q, Arc::clone(&shutdown)))
            .collect();
        let mut pool = test_pool(workers, Arc::clone(&shutdown));

        let health = pool.health();
        assert_eq!(health.expected, 3);
        assert_eq!(health.alive.load(Ordering::Relaxed), 3);

        pool.shutdown();
    }

    #[test]
    fn refresh_health_reflects_finished_workers() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let workers = vec![
            park_worker(0, Arc::clone(&shutdown)),
            finished_worker(1),
            park_worker(2, Arc::clone(&shutdown)),
        ];

        let mut pool = test_pool(workers, Arc::clone(&shutdown));

        pool.refresh_health();
        assert_eq!(pool.health().alive.load(Ordering::Relaxed), 2);

        pool.shutdown();
    }

    #[test]
    fn dead_queues_returns_finished_worker_ids() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let workers = vec![
            park_worker(0, Arc::clone(&shutdown)),
            finished_worker(7),
            finished_worker(9),
        ];

        let mut pool = test_pool(workers, Arc::clone(&shutdown));

        let mut dead = pool.dead_queues();
        dead.sort();
        assert_eq!(dead, vec![7, 9]);

        pool.shutdown();
    }

    #[test]
    fn shutdown_sets_flag_joins_and_drains_workers() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let workers = (0..3)
            .map(|q| park_worker(q, Arc::clone(&shutdown)))
            .collect();
        let mut pool = test_pool(workers, Arc::clone(&shutdown));

        pool.shutdown();

        assert!(shutdown.load(Ordering::Relaxed));
        assert!(pool.workers.is_empty());
    }
}
