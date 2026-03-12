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
    fallback_routed: AtomicU64,
    passed: AtomicU64,
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
            fallback_routed: AtomicU64::new(0),
            passed: AtomicU64::new(0),
        }
    }

    #[inline(always)]
    pub fn record_rx(&self, n: u64) {
        let v = self.rx_packets.load(Ordering::Relaxed);
        self.rx_packets.store(v + n, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn record_cid_forward(&self) {
        inc(&self.cid_routed);
        inc(&self.forwarded);
    }

    #[inline(always)]
    pub fn record_fallback_forward(&self) {
        inc(&self.fallback_routed);
        inc(&self.forwarded);
    }

    #[inline(always)]
    pub fn record_pass(&self) {
        inc(&self.passed);
    }
}

/// Snapshot of aggregate counters at a point in time.
#[derive(Default)]
pub struct Snapshot {
    pub rx_packets: u64,
    pub forwarded: u64,
    pub cid_routed: u64,
    pub fallback_routed: u64,
    pub passed: u64,
}

impl Snapshot {
    pub fn delta(&self, prev: &Snapshot) -> Snapshot {
        Snapshot {
            rx_packets: self.rx_packets.wrapping_sub(prev.rx_packets),
            forwarded: self.forwarded.wrapping_sub(prev.forwarded),
            cid_routed: self.cid_routed.wrapping_sub(prev.cid_routed),
            fallback_routed: self.fallback_routed.wrapping_sub(prev.fallback_routed),
            passed: self.passed.wrapping_sub(prev.passed),
        }
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
            total.fallback_routed += slot.fallback_routed.load(Ordering::Relaxed);
            total.passed += slot.passed.load(Ordering::Relaxed);
        }
        total
    }
}
