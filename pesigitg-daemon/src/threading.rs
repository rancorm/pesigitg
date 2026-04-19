// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

use std::collections::HashMap;
use std::ffi::CString;
use std::os::fd::BorrowedFd;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use libc::{AF_INET, SOCK_DGRAM, c_char, ioctl, socket};
use log::{debug, error, info, warn};
use nix::sched::{CpuSet, sched_setaffinity};
use nix::unistd::Pid;
use xsk_rs::FrameDesc;

use crate::config::route::ConfigTable;
use crate::conntable::ConnectionTable;
use crate::ebpf::EbpfHandle;
use crate::packet::{self, Verdict};
use crate::retry;
use crate::stats::{BatchStats, StatsTable, WorkerStats};
use crate::utils::num_cores;
use crate::xsk::XskSocket;

const ETHTOOL_GCHANNELS: u32 = 0x0000003c;
const SIOCETHTOOL: libc::c_ulong = 0x8946;

const BATCH_SIZE: usize = 64;
const POLL_TIMEOUT_MS: i32 = 100;

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

pub fn plan_threads(interface: &str, max_threads: Option<u32>) -> Vec<ThreadConfig> {
    let (hw_queues, _) = get_hw_queues(interface).unwrap_or((1, 1));
    let available_cores = num_cores();
    let requested = max_threads.unwrap_or(hw_queues);
    let count = resolve_thread_count(hw_queues, requested, available_cores);

    if count < requested {
        warn!(
            "worker count clamped to {} (requested {}, hw queues {}, cpu cores {})",
            count, requested, hw_queues, available_cores
        );
    }

    if count == 0 {
        return Vec::new();
    }

    let numa_cores = select_cores(interface, count);

    (0..count)
        .map(|i| ThreadConfig {
            queue_id: i,
            core_id: numa_cores[i as usize],
        })
        .collect()
}

/// Resolve the number of worker threads to spawn: the smaller of the NIC's
/// hardware queue count, the user-requested count, and the CPU cores
/// available for pinning. Prevents `plan_threads` from indexing past the
/// NUMA-local core list when the host has fewer cores than queues.
fn resolve_thread_count(hw_queues: u32, requested: u32, available_cores: usize) -> u32 {
    requested.min(hw_queues).min(available_cores as u32)
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
}

impl WorkerPool {
    /// Spawn one worker thread per `ThreadConfig`.
    ///
    /// Each thread is pinned to its assigned CPU core and processes
    /// packets from the corresponding NIC queue via AF_XDP.
    pub fn spawn(
        threads: Vec<ThreadConfig>,
        interface: &str,
        local_mac: [u8; 6],
        config: Arc<RwLock<ConfigTable>>,
        ebpf: Arc<Mutex<EbpfHandle>>,
        shutdown: Arc<AtomicBool>,
        stats: Arc<StatsTable>,
    ) -> Self {
        let mut workers = Vec::with_capacity(threads.len());

        for (worker_idx, tc) in threads.into_iter().enumerate() {
            let shutdown = Arc::clone(&shutdown);
            let config = Arc::clone(&config);
            let ebpf = Arc::clone(&ebpf);
            let stats = Arc::clone(&stats);
            let interface = interface.to_owned();
            let queue_id = tc.queue_id;

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

                    worker_loop(
                        &interface,
                        tc.queue_id,
                        &local_mac,
                        &config,
                        &ebpf,
                        &shutdown,
                        stats.slot(worker_idx),
                    );

                    info!("worker q{}: exiting", tc.queue_id);
                })
                .expect("failed to spawn worker thread");

            workers.push(Worker { queue_id, handle });
        }

        let health = Arc::new(WorkerHealth {
            expected: workers.len(),
            alive: AtomicUsize::new(workers.len()),
        });

        WorkerPool {
            workers,
            shutdown,
            health,
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
    pub fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);

        for w in self.workers.drain(..) {
            let _ = w.handle.join();
        }
    }
}

/// Per-queue worker loop.
///
/// This is the hot path — each invocation runs on a dedicated, pinned
/// core with an AF_XDP socket bound to `queue_id`, receiving packets
/// redirected by the XDP program.
fn worker_loop(
    interface: &str,
    queue_id: u32,
    local_mac: &[u8; 6],
    config: &Arc<RwLock<ConfigTable>>,
    ebpf: &Arc<Mutex<EbpfHandle>>,
    shutdown: &AtomicBool,
    stats: &WorkerStats,
) {
    let (mut xsk, xdp_mode) = match XskSocket::new(interface, queue_id) {
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

    let mut rx_descs = vec![FrameDesc::default(); BATCH_SIZE];
    let mut comp_descs = vec![FrameDesc::default(); BATCH_SIZE];
    let mut conn = ConnectionTable::new();
    let mut pending_fill: Vec<FrameDesc> = Vec::new();
    let mut tx_batch: Vec<FrameDesc> = Vec::with_capacity(BATCH_SIZE);
    let mut recycle_batch: Vec<FrameDesc> = Vec::with_capacity(BATCH_SIZE);

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
            let verdict = {
                let mut data = unsafe { xsk.frame_mut(desc) };

                // Retry fast path: if the classifier emits a Retry
                // packet in place of the Initial, ship it straight to
                // TX. Otherwise fall through to the normal routing
                // logic — Forward and Skip both defer to process_packet
                // so the CID path still runs.
                let (retry_outcome, retry_detail) =
                    retry::datapath::try_handle(&mut data, &config, local_mac, now_ms);
                batch_stats.record_retry(retry_outcome, retry_detail);
                match retry_outcome {
                    retry::datapath::Outcome::Emitted => {
                        tx_batch.push(*desc);
                        continue;
                    }
                    retry::datapath::Outcome::Forward | retry::datapath::Outcome::Skip => {}
                }

                packet::process_packet(&mut data, &config, &mut conn, local_mac, now)
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
}

fn select_cores(interface: &str, queue_count: u32) -> Vec<usize> {
    // Prefer cores on the same NUMA node as the NIC. On AMD EPYC
    // NPS>1 (and anything else with multiple NUMA nodes per socket)
    // the CPU's `topology/physical_package_id` reports the *socket*,
    // not the node — so read node<N>/cpulist instead.

    let nic_numa =
        std::fs::read_to_string(format!("/sys/class/net/{}/device/numa_node", interface))
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok())
            .unwrap_or(0);

    let numa_map = read_cpu_numa_map_from(Path::new("/sys/devices/system/node"));

    let cpus: Vec<(usize, i32)> = (0..num_cores())
        .map(|cpu| (cpu, numa_map.get(&cpu).copied().unwrap_or(0)))
        .collect();

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
        WorkerPool {
            workers,
            shutdown,
            health,
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
