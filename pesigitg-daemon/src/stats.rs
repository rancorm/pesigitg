use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

/// Per-worker packet counters, cache-line aligned to avoid false sharing.
///
/// Each worker owns one slot and writes to it exclusively. The main thread
/// reads all slots periodically to aggregate and log.
///
/// Uses `AtomicU64` with `Relaxed` ordering for soundness. The write path
/// uses load+store (not `fetch_add`) to avoid the x86 LOCK prefix — safe
/// because only one thread writes to each slot.
#[repr(C, align(128))]
pub struct WorkerStats {
    rx_packets: AtomicU64,
    forwarded: AtomicU64,
    cid_routed: AtomicU64,
    cid_by_config: [AtomicU64; 7],
    fallback_routed: AtomicU64,
    cid_unroutable: AtomicU64,
    icmp_forwarded: AtomicU64,
    passed: AtomicU64,
    pending_fill_peak: AtomicU64,
}

#[inline(always)]
fn inc(counter: &AtomicU64) {
    counter.store(counter.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
}

impl WorkerStats {
    fn new() -> Self {
        Self {
            rx_packets: AtomicU64::new(0),
            forwarded: AtomicU64::new(0),
            cid_routed: AtomicU64::new(0),
            cid_by_config: std::array::from_fn(|_| AtomicU64::new(0)),
            cid_unroutable: AtomicU64::new(0),
            fallback_routed: AtomicU64::new(0),
            icmp_forwarded: AtomicU64::new(0),
            passed: AtomicU64::new(0),
            pending_fill_peak: AtomicU64::new(0),
        }
    }

    #[inline(always)]
    pub fn record_rx(&self, n: u64) {
        let v = self.rx_packets.load(Ordering::Relaxed);
        self.rx_packets.store(v + n, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn record_cid_forward(&self, config_id: u8) {
        inc(&self.cid_routed);
        inc(&self.cid_by_config[config_id as usize]);
        inc(&self.forwarded);
    }

    #[inline(always)]
    pub fn record_cid_unroutable(&self) {
        inc(&self.cid_unroutable);
    }

    #[inline(always)]
    pub fn record_fallback_forward(&self) {
        inc(&self.fallback_routed);
        inc(&self.forwarded);
    }

    #[inline(always)]
    pub fn record_icmp_forward(&self) {
        inc(&self.icmp_forwarded);
        inc(&self.forwarded);
    }

    #[inline(always)]
    pub fn record_pass(&self) {
        inc(&self.passed);
    }

    #[inline(always)]
    pub fn record_pending_fill(&self, depth: u64) {
        if depth > self.pending_fill_peak.load(Ordering::Relaxed) {
            self.pending_fill_peak.store(depth, Ordering::Relaxed);
        }
    }
}

/// Snapshot of aggregate counters at a point in time.
#[derive(Default)]
pub struct Snapshot {
    pub rx_packets: u64,
    pub forwarded: u64,
    pub cid_routed: u64,
    pub cid_by_config: [u64; 7],
    pub cid_unroutable: u64,
    pub fallback_routed: u64,
    pub icmp_forwarded: u64,
    pub passed: u64,
    pub pending_fill_peak: u64,
}

impl Snapshot {
    pub fn delta(&self, prev: &Snapshot) -> Snapshot {
        let mut cid_by_config = [0u64; 7];

        for i in 0..7 {
            cid_by_config[i] = self.cid_by_config[i].wrapping_sub(prev.cid_by_config[i]);
        }
        
        Snapshot {
            rx_packets: self.rx_packets.wrapping_sub(prev.rx_packets),
            forwarded: self.forwarded.wrapping_sub(prev.forwarded),
            cid_routed: self.cid_routed.wrapping_sub(prev.cid_routed),
            cid_by_config,
            cid_unroutable: self.cid_unroutable.wrapping_sub(prev.cid_unroutable),
            fallback_routed: self.fallback_routed.wrapping_sub(prev.fallback_routed),
            icmp_forwarded: self.icmp_forwarded.wrapping_sub(prev.icmp_forwarded),
            passed: self.passed.wrapping_sub(prev.passed),
            pending_fill_peak: self.pending_fill_peak,
        }
    }

    /// Format per-config_id CID breakdown, only including non-zero entries.
    fn format_cid_by_config(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut any = false;

        for (id, &count) in self.cid_by_config.iter().enumerate() {
            if count > 0 {
                if !any {
                    f.write_str(" [")?;
                    any = true;
                } else {
                    f.write_str(" ")?;
                }
                write!(f, "c{}={}", id, count)?;
            }
        }

        if any {
            f.write_str("]")?;
        }

        Ok(())
    }
}

impl fmt::Display for Snapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rx={} fwd={} (cid={}",
            self.rx_packets, self.forwarded, self.cid_routed,
        )?;
        self.format_cid_by_config(f)?;
        if self.cid_unroutable > 0 {
            write!(f, " cid_unroutable={}", self.cid_unroutable)?;
        }
        write!(
            f,
            " fallback={} icmp={}) pass={}",
            self.fallback_routed, self.icmp_forwarded, self.passed,
        )?;
        if self.pending_fill_peak > 0 {
            write!(f, " pending_fill_peak={}", self.pending_fill_peak)?;
        }
        Ok(())
    }
}

/// Shared stats array, one slot per worker.
pub struct StatsTable {
    slots: Box<[WorkerStats]>,
}

impl StatsTable {
    pub fn new(num_workers: usize) -> Self {
        let slots = (0..num_workers)
            .map(|_| WorkerStats::new())
            .collect::<Vec<_>>()
            .into_boxed_slice();

        StatsTable { slots }
    }

    pub fn slot(&self, index: usize) -> &WorkerStats {
        &self.slots[index]
    }

    pub fn aggregate(&self) -> Snapshot {
        let mut total = Snapshot::default();
        
        for slot in self.slots.iter() {
            total.rx_packets += slot.rx_packets.load(Ordering::Relaxed);
            total.forwarded += slot.forwarded.load(Ordering::Relaxed);
            total.cid_routed += slot.cid_routed.load(Ordering::Relaxed);
            
            for i in 0..7 {
                total.cid_by_config[i] += slot.cid_by_config[i].load(Ordering::Relaxed);
            }
            
            total.cid_unroutable += slot.cid_unroutable.load(Ordering::Relaxed);
            total.fallback_routed += slot.fallback_routed.load(Ordering::Relaxed);
            total.icmp_forwarded += slot.icmp_forwarded.load(Ordering::Relaxed);
            total.passed += slot.passed.load(Ordering::Relaxed);
            let peak = slot.pending_fill_peak.load(Ordering::Relaxed);
            if peak > total.pending_fill_peak {
                total.pending_fill_peak = peak;
            }
        }

        total
    }
}
