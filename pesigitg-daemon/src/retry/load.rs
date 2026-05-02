// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! Shared rate tracker for [`crate::config::retry::RetryMode::Load`].
//!
//! Workers count Initial classifications locally inside the batch loop,
//! then flush each batch's tally into a shared one-second sliding window
//! via a single [`LoadRateTracker::record_batch`] call. Per-Initial code
//! reads the current decision rate via [`LoadRateTracker::rate`] (a plain
//! relaxed load) — never a `fetch_add` — so the cross-worker cache line
//! is touched once per batch instead of once per packet.
//!
//! The returned value is the count from the **most recently completed**
//! window, so callers compare it against the configured trigger rate to
//! decide whether to engage Retry. This gives a deterministic up-to-one-
//! second lag on both engagement and disengagement — acceptable for the
//! "shed load only while flooded" use case.

use std::sync::atomic::{AtomicU64, Ordering};

/// Cross-worker Initial-rate counter used by `RetryMode::Load`.
#[derive(Debug)]
pub struct LoadRateTracker {
    /// Unix-epoch second of the window currently being filled.
    window_sec: AtomicU64,
    /// Events observed so far in the current window.
    window_count: AtomicU64,
    /// Count from the most recently completed window. This is what
    /// [`rate`](Self::rate) returns — the decision lags one window,
    /// which is the price of not locking.
    last_rate: AtomicU64,
}

impl LoadRateTracker {
    pub fn new() -> Self {
        Self {
            window_sec: AtomicU64::new(0),
            window_count: AtomicU64::new(0),
            last_rate: AtomicU64::new(0),
        }
    }

    /// Read the most recently completed window's rate without touching
    /// the shared counter. Used per-Initial in the hot path.
    #[inline(always)]
    pub fn rate(&self) -> u64 {
        self.last_rate.load(Ordering::Relaxed)
    }

    /// Flush a batch's tally into the shared window and rotate windows
    /// if the wall-clock second has advanced.
    ///
    /// `count == 0` is still useful to drive window rotation when a
    /// worker observes the second-tick boundary in an idle batch.
    pub fn record_batch(&self, count: u64, now_ms: u64) {
        let now_sec = now_ms / 1000;
        let cur = self.window_sec.load(Ordering::Relaxed);

        if now_sec != cur {
            // Exactly one worker wins the CAS and publishes the previous
            // window's count as the new `last_rate`. Losers fall through
            // and just fetch-add into whatever window is now current.
            if self
                .window_sec
                .compare_exchange(cur, now_sec, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                let prev = self.window_count.swap(0, Ordering::Relaxed);
                self.last_rate.store(prev, Ordering::Relaxed);
            }
        }

        if count > 0 {
            self.window_count.fetch_add(count, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_tracker_reports_zero_rate() {
        let t = LoadRateTracker::new();
        assert_eq!(t.rate(), 0);
    }

    #[test]
    fn first_window_observations_report_zero() {
        // Nothing has completed a window yet, so the decision rate stays
        // at zero for every observation inside the first second.
        let t = LoadRateTracker::new();
        for _ in 0..100 {
            t.record_batch(1, 0);
            assert_eq!(t.rate(), 0);
        }
    }

    #[test]
    fn completed_window_publishes_count() {
        let t = LoadRateTracker::new();
        // Seed window 0 with 50 observations across two batches.
        t.record_batch(1, 0);
        t.record_batch(49, 500);
        // Roll into window 1 — rate should now reflect window 0's 50.
        t.record_batch(0, 1_000);
        assert_eq!(t.rate(), 50);
    }

    #[test]
    fn rate_tracks_across_successive_windows() {
        let t = LoadRateTracker::new();
        // Window 0: 3 events.
        t.record_batch(3, 100);
        // Roll to window 1 and add 10 events.
        t.record_batch(10, 1_500);
        // During window 1 we should see window 0's rate (=3).
        assert_eq!(t.rate(), 3);
        // Roll to window 2 — now window 1's rate (=10) is published.
        t.record_batch(0, 2_100);
        assert_eq!(t.rate(), 10);
    }

    #[test]
    fn idle_gap_publishes_last_full_window() {
        let t = LoadRateTracker::new();
        t.record_batch(7, 100);
        // Jump five seconds forward — the prior window's 7 events are
        // the rate we now report.
        t.record_batch(0, 5_000);
        assert_eq!(t.rate(), 7);
    }

    #[test]
    fn record_batch_zero_is_a_noop_on_count() {
        // Window 0 stays empty, so when we roll into window 1 the
        // published rate is 0 — the all-zero record_batch did not
        // accidentally bump the counter.
        let t = LoadRateTracker::new();
        for _ in 0..10 {
            t.record_batch(0, 100);
        }
        t.record_batch(1, 1_000);
        assert_eq!(t.rate(), 0);
    }

    #[test]
    fn concurrent_observers_are_counted() {
        use std::sync::Arc;
        use std::thread;

        let t = Arc::new(LoadRateTracker::new());
        // Seed window 0.
        t.record_batch(1, 0);

        let threads = 8;
        let per_thread = 1_000;
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let t = Arc::clone(&t);
                thread::spawn(move || {
                    for _ in 0..per_thread {
                        // Worst case: every "batch" is one event.
                        t.record_batch(1, 500);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        // Roll into window 1 so the accumulated count is published.
        t.record_batch(0, 1_000);
        let reported = t.rate();
        let expected = threads * per_thread + 1;
        // Allow for the narrow window where the CAS winner swaps count to
        // zero while a straggler is mid-fetch_add; lower bound guards the
        // "we counted nothing" bug, upper bound guards the "counted twice"
        // bug.
        assert!(
            reported >= (expected - threads) as u64,
            "too low: {} < {}",
            reported,
            expected - threads,
        );
        assert!(
            reported <= expected as u64,
            "too high: {} > {}",
            reported,
            expected,
        );
    }
}
