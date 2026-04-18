// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::retry::datapath::{Detail as RetryDetail, Outcome as RetryOutcome};

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
    draining_forwarded: AtomicU64,
    icmp_forwarded: AtomicU64,
    passed: AtomicU64,
    pending_fill_peak: AtomicU64,
    retry_initials_seen: AtomicU64,
    retry_issued: AtomicU64,
    retry_token_validated: AtomicU64,
    retry_token_invalid: AtomicU64,
    retry_token_expired: AtomicU64,
    retry_parse_error: AtomicU64,
}

#[inline(always)]
fn add(counter: &AtomicU64, n: u64) {
    counter.store(counter.load(Ordering::Relaxed) + n, Ordering::Relaxed);
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
            draining_forwarded: AtomicU64::new(0),
            icmp_forwarded: AtomicU64::new(0),
            passed: AtomicU64::new(0),
            pending_fill_peak: AtomicU64::new(0),
            retry_initials_seen: AtomicU64::new(0),
            retry_issued: AtomicU64::new(0),
            retry_token_validated: AtomicU64::new(0),
            retry_token_invalid: AtomicU64::new(0),
            retry_token_expired: AtomicU64::new(0),
            retry_parse_error: AtomicU64::new(0),
        }
    }

    #[inline(always)]
    pub fn record_rx(&self, n: u64) {
        add(&self.rx_packets, n);
    }

    #[inline(always)]
    pub fn record_pending_fill(&self, depth: u64) {
        if depth > self.pending_fill_peak.load(Ordering::Relaxed) {
            self.pending_fill_peak.store(depth, Ordering::Relaxed);
        }
    }
}

/// Thread-local batch accumulator for verdict counters.
///
/// Collects per-packet stats using plain `u64` fields during the packet
/// loop, then flushes to the shared `WorkerStats` atomics once per batch.
/// This reduces atomic store traffic from O(packets) to O(1) per batch.
pub struct BatchStats {
    forwarded: u64,
    cid_routed: u64,
    cid_by_config: [u64; 7],
    fallback_routed: u64,
    cid_unroutable: u64,
    draining_forwarded: u64,
    icmp_forwarded: u64,
    passed: u64,
    retry_initials_seen: u64,
    retry_issued: u64,
    retry_token_validated: u64,
    retry_token_invalid: u64,
    retry_token_expired: u64,
    retry_parse_error: u64,
}

impl BatchStats {
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            forwarded: 0,
            cid_routed: 0,
            cid_by_config: [0; 7],
            fallback_routed: 0,
            cid_unroutable: 0,
            draining_forwarded: 0,
            icmp_forwarded: 0,
            passed: 0,
            retry_initials_seen: 0,
            retry_issued: 0,
            retry_token_validated: 0,
            retry_token_invalid: 0,
            retry_token_expired: 0,
            retry_parse_error: 0,
        }
    }

    #[inline(always)]
    pub fn record_cid_forward(&mut self, config_id: u8) {
        self.cid_routed += 1;
        self.cid_by_config[config_id as usize] += 1;
        self.forwarded += 1;
    }

    #[inline(always)]
    pub fn record_fallback_forward(&mut self) {
        self.fallback_routed += 1;
        self.forwarded += 1;
    }

    #[inline(always)]
    pub fn record_icmp_forward(&mut self) {
        self.icmp_forwarded += 1;
        self.forwarded += 1;
    }

    #[inline(always)]
    pub fn record_draining_forward(&mut self) {
        self.draining_forwarded += 1;
    }

    #[inline(always)]
    pub fn record_cid_unroutable(&mut self) {
        self.cid_unroutable += 1;
    }

    #[inline(always)]
    pub fn record_pass(&mut self) {
        self.passed += 1;
    }

    /// Record a retry classifier result. `Detail::None` is a no-op so
    /// the hot-path cost when retry is disabled is a single match arm.
    #[inline(always)]
    pub fn record_retry(&mut self, outcome: RetryOutcome, detail: RetryDetail) {
        match detail {
            RetryDetail::None => return,
            RetryDetail::ParseError => self.retry_parse_error += 1,
            RetryDetail::TokenValid => self.retry_token_validated += 1,
            RetryDetail::TokenInvalid => self.retry_token_invalid += 1,
            RetryDetail::TokenExpired => self.retry_token_expired += 1,
            RetryDetail::Issued | RetryDetail::Observed => {}
        }
        self.retry_initials_seen += 1;
        if outcome == RetryOutcome::Emitted {
            self.retry_issued += 1;
        }
    }

    /// Flush accumulated counters into the shared atomic stats.
    #[inline(always)]
    pub fn flush(self, target: &WorkerStats) {
        if self.forwarded > 0 {
            add(&target.forwarded, self.forwarded);
        }
        if self.cid_routed > 0 {
            add(&target.cid_routed, self.cid_routed);
            for (i, &n) in self.cid_by_config.iter().enumerate() {
                if n > 0 {
                    add(&target.cid_by_config[i], n);
                }
            }
        }
        if self.fallback_routed > 0 {
            add(&target.fallback_routed, self.fallback_routed);
        }
        if self.cid_unroutable > 0 {
            add(&target.cid_unroutable, self.cid_unroutable);
        }
        if self.draining_forwarded > 0 {
            add(&target.draining_forwarded, self.draining_forwarded);
        }
        if self.icmp_forwarded > 0 {
            add(&target.icmp_forwarded, self.icmp_forwarded);
        }
        if self.passed > 0 {
            add(&target.passed, self.passed);
        }
        if self.retry_initials_seen > 0 {
            add(&target.retry_initials_seen, self.retry_initials_seen);
        }
        if self.retry_issued > 0 {
            add(&target.retry_issued, self.retry_issued);
        }
        if self.retry_token_validated > 0 {
            add(&target.retry_token_validated, self.retry_token_validated);
        }
        if self.retry_token_invalid > 0 {
            add(&target.retry_token_invalid, self.retry_token_invalid);
        }
        if self.retry_token_expired > 0 {
            add(&target.retry_token_expired, self.retry_token_expired);
        }
        if self.retry_parse_error > 0 {
            add(&target.retry_parse_error, self.retry_parse_error);
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
    pub draining_forwarded: u64,
    pub icmp_forwarded: u64,
    pub passed: u64,
    pub pending_fill_peak: u64,
    pub retry_initials_seen: u64,
    pub retry_issued: u64,
    pub retry_token_validated: u64,
    pub retry_token_invalid: u64,
    pub retry_token_expired: u64,
    pub retry_parse_error: u64,
}

impl Snapshot {
    pub fn delta(&self, prev: &Snapshot) -> Snapshot {
        let mut cid_by_config = [0u64; 7];

        for (i, slot) in cid_by_config.iter_mut().enumerate() {
            *slot = self.cid_by_config[i].wrapping_sub(prev.cid_by_config[i]);
        }

        Snapshot {
            rx_packets: self.rx_packets.wrapping_sub(prev.rx_packets),
            forwarded: self.forwarded.wrapping_sub(prev.forwarded),
            cid_routed: self.cid_routed.wrapping_sub(prev.cid_routed),
            cid_by_config,
            cid_unroutable: self.cid_unroutable.wrapping_sub(prev.cid_unroutable),
            fallback_routed: self.fallback_routed.wrapping_sub(prev.fallback_routed),
            draining_forwarded: self
                .draining_forwarded
                .wrapping_sub(prev.draining_forwarded),
            icmp_forwarded: self.icmp_forwarded.wrapping_sub(prev.icmp_forwarded),
            passed: self.passed.wrapping_sub(prev.passed),
            pending_fill_peak: self.pending_fill_peak,
            retry_initials_seen: self
                .retry_initials_seen
                .wrapping_sub(prev.retry_initials_seen),
            retry_issued: self.retry_issued.wrapping_sub(prev.retry_issued),
            retry_token_validated: self
                .retry_token_validated
                .wrapping_sub(prev.retry_token_validated),
            retry_token_invalid: self
                .retry_token_invalid
                .wrapping_sub(prev.retry_token_invalid),
            retry_token_expired: self
                .retry_token_expired
                .wrapping_sub(prev.retry_token_expired),
            retry_parse_error: self.retry_parse_error.wrapping_sub(prev.retry_parse_error),
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

        if self.draining_forwarded > 0 {
            write!(f, " draining={}", self.draining_forwarded)?;
        }

        write!(
            f,
            " fallback={} icmp={}) pass={}",
            self.fallback_routed, self.icmp_forwarded, self.passed,
        )?;

        if self.pending_fill_peak > 0 {
            write!(f, " pending_fill_peak={}", self.pending_fill_peak)?;
        }

        if self.retry_initials_seen > 0 {
            write!(
                f,
                " retry(seen={} issued={} valid={} invalid={} expired={} parse_err={})",
                self.retry_initials_seen,
                self.retry_issued,
                self.retry_token_validated,
                self.retry_token_invalid,
                self.retry_token_expired,
                self.retry_parse_error,
            )?;
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

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.slots.len()
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
            total.draining_forwarded += slot.draining_forwarded.load(Ordering::Relaxed);
            total.icmp_forwarded += slot.icmp_forwarded.load(Ordering::Relaxed);
            total.passed += slot.passed.load(Ordering::Relaxed);
            let peak = slot.pending_fill_peak.load(Ordering::Relaxed);
            if peak > total.pending_fill_peak {
                total.pending_fill_peak = peak;
            }
            total.retry_initials_seen += slot.retry_initials_seen.load(Ordering::Relaxed);
            total.retry_issued += slot.retry_issued.load(Ordering::Relaxed);
            total.retry_token_validated += slot.retry_token_validated.load(Ordering::Relaxed);
            total.retry_token_invalid += slot.retry_token_invalid.load(Ordering::Relaxed);
            total.retry_token_expired += slot.retry_token_expired.load(Ordering::Relaxed);
            total.retry_parse_error += slot.retry_parse_error.load(Ordering::Relaxed);
        }

        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot_with_all_ones() -> Snapshot {
        Snapshot {
            rx_packets: 1,
            forwarded: 1,
            cid_routed: 1,
            cid_by_config: [1; 7],
            cid_unroutable: 1,
            fallback_routed: 1,
            draining_forwarded: 1,
            icmp_forwarded: 1,
            passed: 1,
            pending_fill_peak: 1,
            retry_initials_seen: 1,
            retry_issued: 1,
            retry_token_validated: 1,
            retry_token_invalid: 1,
            retry_token_expired: 1,
            retry_parse_error: 1,
        }
    }

    #[test]
    fn delta_of_equal_snapshots_is_zero_linear_fields() {
        let s = snapshot_with_all_ones();
        let d = s.delta(&s);
        assert_eq!(d.rx_packets, 0);
        assert_eq!(d.forwarded, 0);
        assert_eq!(d.cid_routed, 0);
        assert_eq!(d.cid_by_config, [0; 7]);
        assert_eq!(d.cid_unroutable, 0);
        assert_eq!(d.fallback_routed, 0);
        assert_eq!(d.draining_forwarded, 0);
        assert_eq!(d.icmp_forwarded, 0);
        assert_eq!(d.passed, 0);
        assert_eq!(d.retry_initials_seen, 0);
        assert_eq!(d.retry_issued, 0);
        assert_eq!(d.retry_token_validated, 0);
        assert_eq!(d.retry_token_invalid, 0);
        assert_eq!(d.retry_token_expired, 0);
        assert_eq!(d.retry_parse_error, 0);
    }

    #[test]
    fn delta_preserves_pending_fill_peak_from_self() {
        // pending_fill_peak is a high-water mark, not a rate — delta keeps
        // the current value rather than subtracting the previous peak.
        let prev = Snapshot {
            pending_fill_peak: 10,
            ..Snapshot::default()
        };
        let cur = Snapshot {
            pending_fill_peak: 42,
            ..Snapshot::default()
        };
        assert_eq!(cur.delta(&prev).pending_fill_peak, 42);

        // Even if cur < prev (peak was observed earlier and not since),
        // delta must still report the current peak, not an underflow.
        let cur = Snapshot {
            pending_fill_peak: 5,
            ..Snapshot::default()
        };
        assert_eq!(cur.delta(&prev).pending_fill_peak, 5);
    }

    #[test]
    fn delta_subtracts_per_config_slot_elementwise() {
        let prev = Snapshot {
            cid_by_config: [0, 1, 2, 3, 4, 5, 6],
            ..Snapshot::default()
        };
        let cur = Snapshot {
            cid_by_config: [0, 2, 4, 6, 8, 10, 12],
            ..Snapshot::default()
        };
        assert_eq!(cur.delta(&prev).cid_by_config, [0, 1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn delta_uses_wrapping_sub_when_counters_are_reset() {
        // Linear counters are monotonic in production; wrapping_sub guards
        // against a hypothetical reset/rollover yielding a nonsensically
        // large delta rather than a panic.
        let prev = Snapshot {
            rx_packets: 100,
            ..Snapshot::default()
        };
        let cur = Snapshot {
            rx_packets: 40,
            ..Snapshot::default()
        };
        assert_eq!(cur.delta(&prev).rx_packets, u64::MAX - 60 + 1);
    }

    #[test]
    fn display_omits_cid_breakdown_when_all_zero() {
        let s = Snapshot::default();
        let out = format!("{}", s);
        assert!(!out.contains("c0="));
        assert!(!out.contains('['));
        assert!(out.contains("rx=0"));
    }

    #[test]
    fn display_includes_only_nonzero_cid_slots() {
        let mut s = Snapshot::default();
        s.cid_by_config[0] = 3;
        s.cid_by_config[2] = 5;
        let out = format!("{}", s);
        assert!(out.contains("c0=3"));
        assert!(out.contains("c2=5"));
        assert!(!out.contains("c1="));
        assert!(!out.contains("c3="));
    }

    #[test]
    fn display_omits_retry_section_when_no_initials_seen() {
        let s = Snapshot::default();
        let out = format!("{}", s);
        assert!(!out.contains("retry("));
    }

    #[test]
    fn display_includes_retry_section_when_initials_seen() {
        let s = Snapshot {
            retry_initials_seen: 5,
            retry_issued: 2,
            retry_token_validated: 1,
            retry_token_invalid: 1,
            retry_token_expired: 0,
            retry_parse_error: 1,
            ..Snapshot::default()
        };
        let out = format!("{}", s);
        assert!(out.contains("retry(seen=5"));
        assert!(out.contains("issued=2"));
        assert!(out.contains("parse_err=1"));
    }

    #[test]
    fn display_omits_draining_when_zero() {
        let s = Snapshot::default();
        let out = format!("{}", s);
        assert!(!out.contains("draining="));
    }

    #[test]
    fn display_omits_pending_fill_peak_when_zero() {
        let s = Snapshot::default();
        let out = format!("{}", s);
        assert!(!out.contains("pending_fill_peak"));
    }

    #[test]
    fn aggregate_of_empty_table_is_default() {
        let t = StatsTable::new(0);
        assert_eq!(t.len(), 0);
        let agg = t.aggregate();
        assert_eq!(agg.rx_packets, 0);
        assert_eq!(agg.pending_fill_peak, 0);
    }

    #[test]
    fn aggregate_sums_linear_counters_and_maxes_peak() {
        let t = StatsTable::new(3);
        t.slot(0).rx_packets.store(10, Ordering::Relaxed);
        t.slot(1).rx_packets.store(20, Ordering::Relaxed);
        t.slot(2).rx_packets.store(30, Ordering::Relaxed);

        t.slot(0).pending_fill_peak.store(5, Ordering::Relaxed);
        t.slot(1).pending_fill_peak.store(99, Ordering::Relaxed);
        t.slot(2).pending_fill_peak.store(12, Ordering::Relaxed);

        // cid_by_config per-slot must be summed element-wise.
        t.slot(0).cid_by_config[0].store(1, Ordering::Relaxed);
        t.slot(1).cid_by_config[0].store(2, Ordering::Relaxed);
        t.slot(2).cid_by_config[3].store(7, Ordering::Relaxed);

        let agg = t.aggregate();
        assert_eq!(agg.rx_packets, 60);
        assert_eq!(agg.pending_fill_peak, 99);
        assert_eq!(agg.cid_by_config[0], 3);
        assert_eq!(agg.cid_by_config[3], 7);
    }

    #[test]
    fn batch_flush_rolls_up_into_worker_stats() {
        let t = StatsTable::new(1);
        let mut batch = BatchStats::new();
        batch.record_cid_forward(2);
        batch.record_cid_forward(2);
        batch.record_fallback_forward();
        batch.record_icmp_forward();
        batch.record_draining_forward();
        batch.record_cid_unroutable();
        batch.record_pass();
        batch.flush(t.slot(0));

        let agg = t.aggregate();
        assert_eq!(agg.cid_routed, 2);
        assert_eq!(agg.cid_by_config[2], 2);
        // forwarded = cid_routed + fallback_routed + icmp_forwarded (not draining).
        assert_eq!(agg.forwarded, 2 + 1 + 1);
        assert_eq!(agg.fallback_routed, 1);
        assert_eq!(agg.icmp_forwarded, 1);
        assert_eq!(agg.draining_forwarded, 1);
        assert_eq!(agg.cid_unroutable, 1);
        assert_eq!(agg.passed, 1);
    }

    #[test]
    fn record_pending_fill_keeps_max_not_last() {
        let t = StatsTable::new(1);
        t.slot(0).record_pending_fill(50);
        t.slot(0).record_pending_fill(10); // lower — must not overwrite
        t.slot(0).record_pending_fill(30);
        assert_eq!(t.aggregate().pending_fill_peak, 50);
    }
}
