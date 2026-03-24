use std::ffi::CString;
use std::os::fd::BorrowedFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};

use libc::{ioctl, socket, AF_INET, SOCK_DGRAM, c_char};
use log::{error, info};
use nix::sched::{sched_setaffinity, CpuSet};
use nix::unistd::Pid;
use xsk_rs::FrameDesc;

use crate::config::route::ConfigTable;
use crate::conntable::ConnectionTable;
use crate::ebpf::EbpfHandle;
use crate::packet::{self, Verdict};
use crate::stats::{StatsTable, WorkerStats};
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
    let (queue_count, _) = get_hw_queues(interface).unwrap_or((1, 1));
    let numa_cores = select_cores(interface, queue_count);

    let count = match max_threads {
        Some(max) => queue_count.min(max),
        None => queue_count,
    };

    (0..count)
        .map(|i| ThreadConfig {
            queue_id: i,
            core_id: numa_cores[i as usize],
        })
        .collect()
}

/// Pin the calling thread to a specific CPU core.
fn pin_to_core(core_id: usize) -> std::io::Result<()> {
    let mut cpuset = CpuSet::new();
    cpuset.set(core_id).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    // Pid::from_raw(0) means the calling thread
    sched_setaffinity(Pid::from_raw(0), &cpuset)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}

/// A pool of AF_XDP worker threads, one per NIC queue.
pub struct WorkerPool {
    handles: Vec<JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
}

impl WorkerPool {
    /// Spawn one worker thread per `ThreadConfig`.
    ///
    /// Each thread is pinned to its assigned CPU core and processes
    /// packets from the corresponding NIC queue via AF_XDP.
    pub fn spawn(
        threads: Vec<ThreadConfig>,
        interface: &str,
        config: Arc<RwLock<ConfigTable>>,
        ebpf: Arc<Mutex<EbpfHandle>>,
        shutdown: Arc<AtomicBool>,
        stats: Arc<StatsTable>,
    ) -> Self {
        let mut handles = Vec::with_capacity(threads.len());

        for (worker_idx, tc) in threads.into_iter().enumerate() {
            let shutdown = Arc::clone(&shutdown);
            let config = Arc::clone(&config);
            let ebpf = Arc::clone(&ebpf);
            let stats = Arc::clone(&stats);
            let interface = interface.to_owned();

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

                    info!(
                        "worker q{}: started on core {}",
                        tc.queue_id, tc.core_id
                    );

                    worker_loop(&interface, tc.queue_id, &config, &ebpf, &shutdown, stats.slot(worker_idx));

                    info!("worker q{}: exiting", tc.queue_id);
                })
                .expect("failed to spawn worker thread");

            handles.push(handle);
        }

        WorkerPool { handles, shutdown }
    }

    /// Signal all workers to stop and wait for them to finish.
    pub fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);

        for handle in self.handles.drain(..) {
            let _ = handle.join();
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
    config: &Arc<RwLock<ConfigTable>>,
    ebpf: &Arc<Mutex<EbpfHandle>>,
    shutdown: &AtomicBool,
    stats: &WorkerStats,
) {
    let (mut xsk, xdp_mode) = match XskSocket::new(interface, queue_id) {
        Ok(s) => s,
        Err(e) => {
            error!("worker q{}: failed to create AF_XDP socket: {:#}", queue_id, e);
            return;
        }
    };

    let fd = unsafe { BorrowedFd::borrow_raw(xsk.raw_fd()) };
    if let Err(e) = ebpf.lock().unwrap().register_xsk(queue_id, fd) {
        error!("worker q{}: failed to register in XSKS map: {}", queue_id, e);
        return;
    }

    info!("worker q{}: AF_XDP socket bound and registered ({})", queue_id, xdp_mode);

    let mut rx_descs = vec![FrameDesc::default(); BATCH_SIZE];
    let mut comp_descs = vec![FrameDesc::default(); BATCH_SIZE];
    let mut conn = ConnectionTable::new();
    let mut pending_fill: Vec<FrameDesc> = Vec::new();

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

        conn.maybe_sweep();

        let n = xsk.poll_recv(&mut rx_descs, POLL_TIMEOUT_MS);
        if n == 0 {
            continue;
        }

        let config = config.read().unwrap();

        let mut tx_batch = Vec::with_capacity(n);
        let mut recycle_batch = Vec::with_capacity(n);

        stats.record_rx(n as u64);

        for i in 0..n {
            let verdict = {
                let mut data = unsafe { xsk.frame_mut(&mut rx_descs[i]) };
                packet::process_packet(&mut *data, &config, &mut conn)
            };
            match verdict {
                Verdict::CidForward(config_id) => {
                    stats.record_cid_forward(config_id);
                    tx_batch.push(rx_descs[i]);
                }
                Verdict::FallbackForward => {
                    stats.record_fallback_forward();
                    tx_batch.push(rx_descs[i]);
                }
                Verdict::IcmpForward => {
                    stats.record_icmp_forward();
                    tx_batch.push(rx_descs[i]);
                }
                Verdict::Pass => {
                    stats.record_pass();
                    recycle_batch.push(rx_descs[i]);
                }
            }
        }

        drop(config);

        let sent = xsk.transmit(&tx_batch);
        if sent < tx_batch.len() {
            pending_fill.extend_from_slice(&tx_batch[sent..]);
        }

        let refilled = xsk.refill(&recycle_batch);
        if refilled < recycle_batch.len() {
            pending_fill.extend_from_slice(&recycle_batch[refilled..]);
        }
    }
}

fn select_cores(interface: &str, queue_count: u32) -> Vec<usize> {
    // Prefer cores on the same NUMA node as the NIC
    // Read from /sys/class/net/<interface>/device/numa_node
    // Then pick cores from that node

    let nic_numa = std::fs::read_to_string(format!("/sys/class/net/{}/device/numa_node", interface))
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
        .unwrap_or(0);

    let mut local_cores = Vec::new();
    let mut remote_cores = Vec::new();

    for cpu in 0..num_cores() {
        let path = format!("/sys/devices/system/cpu/cpu{}/topology/physical_package_id", cpu);
        let numa = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok())
            .unwrap_or(0);

        if numa == nic_numa {
            local_cores.push(cpu);
        } else {
            remote_cores.push(cpu);
        }
    }

    // Prefer NUMA-local cores, fall back to remote
    local_cores.extend(remote_cores);
    local_cores.truncate(queue_count as usize);
    local_cores
}
