//! SPDX-License-Identifier: GPL-3.0-or-later
//! Host supervisor policies (P7 tiers 2–3 — pure, time-injected,
//! unit-tested here; commit 4 wires them to the drain loop and
//! control map, R21 qualifies them live).
//!
//! - Tier 2 (duty throttle): when ESTIMATED provider-call duty
//!   exceeds 10%, program SKIP-ALL (cause 5) until duty falls
//!   below 5% (hysteresis — no flapping at the line).
//! - Tier 3 (storm detector): when the ATTEMPT rate exceeds
//!   1k/s over a 100ms window, DETACH all member links (the
//!   invocation is abandoned — PARTIAL+STORM downstream) and
//!   re-attach only after the rate stays below 100/s for 1s.

/// Tier-2 cost model (P7 §5.4 — per admitted invocation):
/// 15µs fixed (entry + member-0 + retire) + (T+1) × 12.7µs per
/// walked slot. T comes from the oracle TRUE-T (proven or
/// candidate — cost is cost).
pub const TIER2_FIXED_NS: u64 = 15_000;
pub const TIER2_PER_SLOT_NS: u64 = 12_700;
/// Throttle on at >10% duty, off at <5% (hysteresis).
pub const TIER2_ON_PPM: u64 = 100_000;
pub const TIER2_OFF_PPM: u64 = 50_000;
/// Duty window: 1s sliding.
pub const TIER2_WINDOW_NS: u64 = 1_000_000_000;

pub fn estimate_cost_ns(true_t: u64) -> u64 {
    TIER2_FIXED_NS + (true_t + 1).saturating_mul(TIER2_PER_SLOT_NS)
}

/// Tier-2 duty throttle (pure over injected `now_ns`).
#[derive(Debug, Default)]
pub struct DutyThrottle {
    /// (completion time, estimated cost) samples inside the window.
    samples: std::collections::VecDeque<(u64, u64)>,
    window_cost_ns: u64,
    throttled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrottleAction {
    EngageSkipAll,
    ReleaseSkipAll,
}

impl DutyThrottle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn throttled(&self) -> bool {
        self.throttled
    }

    /// Age the window without a completion (idle polls release an
    /// engaged throttle once the trailing cost decays below the
    /// floor — otherwise only completions could release it).
    pub fn age(&mut self, now_ns: u64) -> Option<ThrottleAction> {
        self.gc(now_ns);
        if self.throttled {
            let duty_ppm = self.window_cost_ns * 1_000_000 / TIER2_WINDOW_NS;
            if duty_ppm < TIER2_OFF_PPM {
                self.throttled = false;
                return Some(ThrottleAction::ReleaseSkipAll);
            }
        }
        None
    }

    /// Expire samples outside the trailing window.
    fn gc(&mut self, now_ns: u64) {
        while let Some(&(t, c)) = self.samples.front() {
            if now_ns.saturating_sub(t) >= TIER2_WINDOW_NS {
                self.samples.pop_front();
                self.window_cost_ns -= c;
            } else {
                break;
            }
        }
    }

    /// Observe one completed invocation (oracle TRUE-T, proven or
    /// candidate) at `now_ns`. Returns the control actioniff the
    /// throttle state flips.
    pub fn observe(&mut self, now_ns: u64, true_t: u64) -> Option<ThrottleAction> {
        let cost = estimate_cost_ns(true_t);
        self.samples.push_back((now_ns, cost));
        self.window_cost_ns += cost;
        self.gc(now_ns);
        // Duty in ppm over the trailing window (window shorter
        // than 1s at startup still compares against the full
        // 1s — conservative: startup bursts throttle early).
        let duty_ppm = self.window_cost_ns * 1_000_000 / TIER2_WINDOW_NS;
        if !self.throttled && duty_ppm > TIER2_ON_PPM {
            self.throttled = true;
            Some(ThrottleAction::EngageSkipAll)
        } else if self.throttled && duty_ppm < TIER2_OFF_PPM {
            self.throttled = false;
            Some(ThrottleAction::ReleaseSkipAll)
        } else {
            None
        }
    }
}

/// Tier-3 storm detector (pure over injected `now_ns` + ATTEMPT
/// totals): 1k/s over 100ms ⟹ detach; re-attach after <100/s
/// for 1s.
pub const TIER3_WINDOW_NS: u64 = 100_000_000;
pub const TIER3_TRIP_PER_S: u64 = 1_000;
pub const TIER3_RESET_PER_S: u64 = 100;
pub const TIER3_RESET_QUIET_NS: u64 = 1_000_000_000;

#[derive(Debug, Default)]
pub struct StormDetector {
    samples: std::collections::VecDeque<(u64, u64)>,
    detached: bool,
    quiet_since: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StormAction {
    Detach,
    Reattach,
}

impl StormDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn detached(&self) -> bool {
        self.detached
    }

    /// Observe the ATTEMPT total at `now_ns`. Returns the action
    /// iff the detector state flips.
    pub fn observe(&mut self, now_ns: u64, attempts: u64) -> Option<StormAction> {
        self.samples.push_back((now_ns, attempts));
        while let Some(&(t, _)) = self.samples.front() {
            if now_ns.saturating_sub(t) >= TIER3_WINDOW_NS.max(TIER3_RESET_QUIET_NS) {
                self.samples.pop_front();
            } else {
                break;
            }
        }
        // Rate from the last two retained samples, annualized over
        // their real span: sparse 250ms production polls report
        // their true rate (a first-sample-in-100ms rule reports
        // zero at that spacing — the sample is the current one).
        // A lone sample reports zero, never a guess; counter
        // resets saturate to zero.
        let rate_per_s = match (self.samples.iter().rev().nth(1), self.samples.back()) {
            (Some(&(t0, a0)), Some(&(t1, a1))) if t1 > t0 => a1
                .saturating_sub(a0)
                .saturating_mul(1_000_000_000)
                .checked_div(t1 - t0)
                .unwrap_or(0),
            _ => 0,
        };
        if !self.detached && rate_per_s > TIER3_TRIP_PER_S {
            self.detached = true;
            self.quiet_since = None;
            return Some(StormAction::Detach);
        }
        if self.detached {
            if rate_per_s < TIER3_RESET_PER_S {
                match self.quiet_since {
                    None => self.quiet_since = Some(now_ns),
                    Some(q) if now_ns.saturating_sub(q) >= TIER3_RESET_QUIET_NS => {
                        self.detached = false;
                        self.quiet_since = None;
                        return Some(StormAction::Reattach);
                    }
                    _ => {}
                }
            } else {
                self.quiet_since = None;
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier2_engages_and_releases() {
        let mut t = DutyThrottle::new();
        // 1000 invocations with T=511 in 100ms: each costs
        // 15µs + 512×12.7µs ≈ 6.5ms ⟹ duty ≈ 65× ⟹ trips.
        let mut action = None;
        for i in 0..1000 {
            action = t.observe(i * 100_000, 511).or(action);
        }
        assert_eq!(action, Some(ThrottleAction::EngageSkipAll));
        assert!(t.throttled());
        // 2s of silence (one sample past the window — the old
        // samples age out; a single T=0 completion costs 27.7µs
        // ⟹ duty ≈ 0 ⟹ releases).
        let a = t.observe(3_000_000_000, 0);
        assert_eq!(a, Some(ThrottleAction::ReleaseSkipAll));
        assert!(!t.throttled());
    }

    #[test]
    fn tier2_hysteresis_no_flap() {
        let mut t = DutyThrottle::new();
        // Drive duty just over 10%: T=0 costs 27.7µs; 4000 in
        // 1s ⟹ 110.8ms ⟹ 11% ⟹ trips.
        for i in 0..4000 {
            t.observe(i * 250_000, 0);
        }
        assert!(t.throttled());
        // Duty between 5% and 10%: no release (hysteresis).
        // Age out half the window, add a trickle: observe at
        // 1.5s (2000 samples aged out, 2000 remain ⟹ 55.4ms ⟹
        // 5.5%) — still throttled, no action.
        let a = t.observe(1_500_000_000, 0);
        assert_eq!(a, None);
        assert!(t.throttled());
    }

    #[test]
    fn tier2_idle_never_trips() {
        let mut t = DutyThrottle::new();
        // 40/s (the tier-1 refill rate) at T=130: each costs
        // 15µs + 131×12.7µs ≈ 1.68ms ⟹ duty ≈ 6.7% — under
        // the line (tier-1 and tier-2 compose: the bucket caps
        // per-tid rate, duty caps aggregate cost).
        for i in 0..40 {
            let a = t.observe(i * 25_000_000, 130);
            assert_eq!(a, None);
        }
        assert!(!t.throttled());
    }

    #[test]
    fn tier3_trip_and_reattach() {
        let mut d = StormDetector::new();
        // 150 attempts in 100ms ⟹ 1500/s ⟹ trips.
        let mut action = None;
        for i in 0..150 {
            action = d.observe(i * 666_666, i + 1).or(action);
        }
        assert_eq!(action, Some(StormAction::Detach));
        assert!(d.detached());
        // Quiet: 5 attempts over the next 1.2s (< 100/s) ⟹
        // re-attach after 1s of quiet.
        let mut action = None;
        for i in 0..6 {
            action = d.observe(200_000_000 + i * 200_000_000, 150 + i).or(action);
        }
        assert_eq!(action, Some(StormAction::Reattach));
        assert!(!d.detached());
    }

    #[test]
    fn tier3_bursty_no_trip() {
        let mut d = StormDetector::new();
        // 50 attempts in 100ms ⟹ 500/s — under the line.
        for i in 0..50 {
            let a = d.observe(i * 2_000_000, i + 1);
            assert_eq!(a, None);
        }
        assert!(!d.detached());
    }

    #[test]
    fn tier3_reset_requires_sustained_quiet() {
        let mut d = StormDetector::new();
        for i in 0..150 {
            d.observe(i * 666_666, i + 1);
        }
        assert!(d.detached());
        // Brief quiet then another burst: the quiet clock resets.
        d.observe(200_000_000, 150);
        d.observe(300_000_000, 150);
        for i in 0..150 {
            d.observe(400_000_000 + i * 666_666, 151 + i);
        }
        assert!(d.detached());
        // Now a full quiet second ⟹ re-attach.
        let mut action = None;
        for i in 0..6 {
            action = d.observe(600_000_000 + i * 200_000_000, 300 + i).or(action);
        }
        assert_eq!(action, Some(StormAction::Reattach));
    }
}
