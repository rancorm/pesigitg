// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

//! Shared rate tracker for [`crate::config::route::RetryMode::Load`].
//!
//! Workers call [`LoadRateTracker::observe_and_rate`] once per Initial
//! that reaches the Retry classifier in Load mode. The tracker maintains
//! a fixed one-second sliding window across every worker using plain
//! atomics — concurrent observations race but the race is bounded by a
//! single counter reset per second, so the rate estimate stays within a
//! handful of packets of the true count.
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
    /// [`observe_and_rate`](Self::observe_and_rate) returns — the rate
    /// decision lags one window, which is the price of not locking.
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

    /// Record one observation and return the last completed window's rate.
    ///
    /// `now_ms` is the current wall-clock time in milliseconds. Callers
    /// already sample it once per batch for the token path, so threading
    /// it through here costs nothing extra.
    pub fn observe_and_rate(&self, now_ms: u64) -> u64 {
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

        self.window_count.fetch_add(1, Ordering::Relaxed);
        self.last_rate.load(Ordering::Relaxed)
    }

    /// Inspect the last completed window's rate without counting an event.
    /// Used by stats dumps and tests.
    #[allow(dead_code)]
    pub fn rate(&self) -> u64 {
        self.last_rate.load(Ordering::Relaxed)
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
            assert_eq!(t.observe_and_rate(0), 0);
        }
    }

    #[test]
    fn completed_window_publishes_count() {
        let t = LoadRateTracker::new();
        // Seed one observation in window 0 so window_sec is non-zero.
        t.observe_and_rate(0);
        for _ in 0..49 {
            t.observe_and_rate(500);
        }
        // Roll into window 1 — returned rate should now be the 50 events
        // from window 0.
        assert_eq!(t.observe_and_rate(1_000), 50);
    }

    #[test]
    fn rate_tracks_across_successive_windows() {
        let t = LoadRateTracker::new();
        // Window 0: 3 events
        for _ in 0..3 {
            t.observe_and_rate(100);
        }
        // Roll to window 1 and add 10 events.
        t.observe_and_rate(1_000);
        for _ in 0..9 {
            t.observe_and_rate(1_500);
        }
        // During window 1 we should see window 0's rate (=3).
        assert_eq!(t.rate(), 3);
        // Roll to window 2 — now window 1's rate (=10) is published.
        t.observe_and_rate(2_100);
        assert_eq!(t.rate(), 10);
    }

    #[test]
    fn idle_gap_publishes_last_full_window() {
        let t = LoadRateTracker::new();
        for _ in 0..7 {
            t.observe_and_rate(100);
        }
        // Jump five seconds forward with one observation — the prior
        // window's 7 events are the rate we now report.
        t.observe_and_rate(5_000);
        assert_eq!(t.rate(), 7);
    }

    #[test]
    fn concurrent_observers_are_counted() {
        use std::sync::Arc;
        use std::thread;

        let t = Arc::new(LoadRateTracker::new());
        // Seed window 0.
        t.observe_and_rate(0);

        let threads = 8;
        let per_thread = 1_000;
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let t = Arc::clone(&t);
                thread::spawn(move || {
                    for _ in 0..per_thread {
                        t.observe_and_rate(500);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        // Roll into window 1 so the accumulated count is published.
        t.observe_and_rate(1_000);
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
