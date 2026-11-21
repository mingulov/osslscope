// SPDX-License-Identifier: GPL-3.0-or-later
//! 6C cardinality budget (§6C-12): 1024-epoch / 256-window caps,
//! deterministic admission, distribution-atomic units, counted
//! overflow. Adapters offer candidates in (P-number,
//! labelset-bytes) order with opt-in units last; the budget admits
//! in arrival order.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Per-epoch series cap (§6C-12).
pub const EPOCH_SERIES_CAP: usize = 1024;
/// Per-window new-series cap (§6C-12).
pub const WINDOW_NEW_SERIES_CAP: usize = 256;
/// Series per P-17 distribution unit (19 buckets + sum + count).
pub const UNIT_SERIES: usize = 21;

/// Precomputed default-schema maximum (§6C-12 proof): P-01: 4;
/// P-02/03/04: 3; P-05: 5; P-06: 3; P-07: 4; P-08: 12; P-09: 10;
/// P-10: 3; P-11/12/13/14/15: 5; P-16: 5; P-17: 5 × 21 = 105.
/// Total 159.
pub const fn default_series_max() -> usize {
    4 + 3 + 5 + 3 + 4 + 12 + 10 + 3 + 5 + 5 + 5 * UNIT_SERIES
}

/// One candidate series identity: (metric, sorted labelset bytes).
pub type SeriesKey = (String, String);

/// Window identity for admission accounting: (mode, generation,
/// window sequence, window sha). Same-window re-renders share it
/// (no per-render reset); distinct oneshot documents differ by
/// their sha.
pub type WindowId = (String, Option<u64>, Option<u64>, Option<String>);

/// Presenter-run + epoch admission state.
#[derive(Debug, Clone, Default)]
pub struct Budget {
    /// Admitted series this epoch (never deleted mid-epoch).
    admitted: BTreeSet<SeriesKey>,
    /// New series admitted in the current window.
    window_new: usize,
    /// Presenter-run omitted-series count (P-14, never reset).
    overflow: u64,
    /// Window the per-window budget currently binds (None until
    /// the first admission).
    window_id: Option<WindowId>,
}

impl Budget {
    /// Fresh budget (presenter-run start or epoch reset — the
    /// overflow count survives epoch resets via [`Self::reset_epoch`]).
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a new window (resets the per-window new-series count).
    pub fn begin_window(&mut self) {
        self.window_new = 0;
        self.window_id = None;
    }

    /// Bind the per-window budget to a window identity (item 20):
    /// resets the per-window new-series count ONLY when the
    /// identity changed (no per-render reset). Returns true for a
    /// genuinely new window (counting admission applies) and false
    /// for a same-window re-render (non-counting filter applies —
    /// re-offers must neither admit nor recount).
    pub fn begin_window_for(&mut self, id: WindowId) -> bool {
        if self.window_id.as_ref() == Some(&id) {
            return false;
        }
        self.window_id = Some(id);
        self.window_new = 0;
        true
    }

    /// Non-counting membership probe (same-window re-renders).
    pub fn is_admitted(&self, metric: &str, labelset: &str) -> bool {
        self.admitted
            .contains(&(metric.to_string(), labelset.to_string()))
    }

    /// Reset for a new epoch (admitted set + window binding cleared;
    /// overflow kept).
    pub fn reset_epoch(&mut self) {
        self.admitted.clear();
        self.window_new = 0;
        self.window_id = None;
    }

    /// Admit one default-schema series. Already-admitted series are
    /// free (not new). Returns false + counts 1 overflow when either
    /// cap binds.
    pub fn admit_series(&mut self, metric: &str, labelset: &str) -> bool {
        let key = (metric.to_string(), labelset.to_string());
        if self.admitted.contains(&key) {
            return true;
        }
        if self.admitted.len() >= EPOCH_SERIES_CAP || self.window_new >= WINDOW_NEW_SERIES_CAP {
            self.overflow = self.overflow.saturating_add(1);
            return false;
        }
        self.admitted.insert(key);
        self.window_new += 1;
        true
    }

    /// Admit one P-17 distribution unit atomically (all 21 series or
    /// none). `series` must hold exactly [`UNIT_SERIES`] keys in the
    /// caller's deterministic order. Already-admitted members are
    /// free; the unit is admitted whole iff every NEW member fits
    /// under BOTH caps, else the whole unit is omitted + counted.
    pub fn admit_unit(&mut self, series: &[SeriesKey]) -> bool {
        debug_assert_eq!(series.len(), UNIT_SERIES);
        let fresh: Vec<&SeriesKey> = series
            .iter()
            .filter(|k| !self.admitted.contains(*k))
            .collect();
        if self.admitted.len() + fresh.len() > EPOCH_SERIES_CAP
            || self.window_new + fresh.len() > WINDOW_NEW_SERIES_CAP
        {
            self.overflow = self.overflow.saturating_add(series.len() as u64);
            return false;
        }
        for key in fresh {
            self.admitted.insert(key.clone());
            self.window_new += 1;
        }
        true
    }

    /// Presenter-run omitted-series count (P-14).
    pub fn overflow(&self) -> u64 {
        self.overflow
    }

    /// Epoch admitted-series count.
    pub fn admitted_len(&self) -> usize {
        self.admitted.len()
    }

    /// Snapshot the checkpoint-bound admission state (P2fix2 item
    /// 13): the admitted set (epoch scope), the omitted-series
    /// count, and the bound window identity (same-window re-renders
    /// stay non-counting across restarts). The per-window new-count
    /// is intentionally absent (every new window opens a fresh
    /// §6C-12 per-window budget by rule).
    pub fn snapshot(&self) -> BudgetSnapshot {
        BudgetSnapshot {
            admitted: self.admitted.clone(),
            overflow: self.overflow,
            window_id: self.window_id.clone(),
        }
    }

    /// Restore checkpoint-bound admission state (see
    /// [`Self::snapshot`]). Call once after opening, before the
    /// first admission.
    pub fn restore(&mut self, snap: BudgetSnapshot) {
        self.admitted = snap.admitted;
        self.overflow = snap.overflow;
        self.window_id = snap.window_id;
        self.window_new = 0;
    }
}

/// Checkpoint-bound admission state (P2fix2 item 13 — persisted
/// with the source-bound checkpoint, validated on restore).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetSnapshot {
    /// Admitted series this epoch (never deleted mid-epoch).
    pub admitted: BTreeSet<SeriesKey>,
    /// Presenter-run omitted-series count (never reset, never
    /// recounted across restarts).
    pub overflow: u64,
    /// Window the per-window budget binds (restored binding keeps
    /// post-restart same-window re-renders non-counting).
    pub window_id: Option<WindowId>,
}

/// Sort series keys into the deterministic admission order
/// ((metric, labelset-bytes) ascending).
pub fn sort_series_keys(keys: &mut [SeriesKey]) {
    keys.sort();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_max_is_159() {
        assert_eq!(default_series_max(), 159);
    }

    #[test]
    fn first_window_opt_in_example_is_exact() {
        // §6C-12 recomputed example: 159 default + 4 whole units
        // (84) admitted = 243; the 5th unit omitted whole with all
        // later units: 261 × 21 = 5481 overflow.
        let mut b = Budget::new();
        b.begin_window();
        for i in 0..default_series_max() {
            assert!(b.admit_series("m", &format!("l={i:03}")));
        }
        let mut omitted = 0u64;
        for api in 20..=72u32 {
            for class in ["empty", "failure", "retry", "success", "unknown"] {
                let unit: Vec<SeriesKey> = (0..UNIT_SERIES)
                    .map(|s| {
                        (
                            "osslscope_dispatch_duration_nanoseconds".to_string(),
                            format!("api=\"{api}\",outcome_class=\"{class}\",s={s:02}"),
                        )
                    })
                    .collect();
                if !b.admit_unit(&unit) {
                    omitted += 1;
                }
            }
        }
        assert_eq!(omitted, 261);
        assert_eq!(b.overflow(), 261 * UNIT_SERIES as u64);
        assert_eq!(b.admitted_len(), 159 + 4 * UNIT_SERIES);
    }

    #[test]
    fn window_identity_binds_per_window_accounting() {
        // P2fix1 item 20: same-window re-renders neither admit nor
        // recount (no per-render reset); a new window refreshes.
        let mut b = Budget::new();
        let a = (
            "service".to_string(),
            Some(0),
            Some(7),
            Some("a".to_string()),
        );
        let c = (
            "service".to_string(),
            Some(0),
            Some(8),
            Some("c".to_string()),
        );
        assert!(b.begin_window_for(a.clone()));
        for i in 0..200 {
            assert!(b.admit_series("m", &format!("l={i:03}")));
        }
        // Same window: the budget does NOT reset (56 more fit).
        assert!(!b.begin_window_for(a.clone()));
        let mut fit = 0;
        for i in 200..300 {
            if b.admit_series("m", &format!("l={i:03}")) {
                fit += 1;
            }
        }
        assert_eq!(fit, 56);
        assert_eq!(b.overflow(), 44);
        // Non-counting probe sees admitted, not omitted.
        assert!(b.is_admitted("m", "l=000"));
        assert!(!b.is_admitted("m", "l=299"));
        // New window: fresh per-window budget, epoch set kept.
        assert!(b.begin_window_for(c));
        for i in 300..400 {
            assert!(b.admit_series("m", &format!("l={i:03}")));
        }
        assert_eq!(b.overflow(), 44);
    }

    #[test]
    fn later_windows_admit_until_epoch_binds_at_1020() {
        let mut b = Budget::new();
        b.begin_window();
        for i in 0..default_series_max() {
            assert!(b.admit_series("m", &format!("l={i:03}")));
        }
        let units: Vec<Vec<SeriesKey>> = (20..=72u32)
            .flat_map(|api| {
                ["empty", "failure", "retry", "success", "unknown"].map(move |class| {
                    (0..UNIT_SERIES)
                        .map(|s| {
                            (
                                "osslscope_dispatch_duration_nanoseconds".to_string(),
                                format!("api=\"{api}\",outcome_class=\"{class}\",s={s:02}"),
                            )
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        assert_eq!(units.len(), 265);
        for unit in &units {
            b.admit_unit(unit);
        }
        // Windows 2..: re-offer until no new admission.
        let mut admitted_units = 4usize;
        for _ in 2..=8 {
            b.begin_window();
            let mut fresh = 0;
            for unit in &units {
                if b.admit_unit(unit) {
                    // Count only newly completed units: a unit whose
                    // members were all already admitted is free.
                    fresh += 1;
                }
            }
            // `fresh` counts free re-admissions too; recompute new
            // units from the epoch total instead.
            let _ = fresh;
            let total_units = (b.admitted_len() - default_series_max()) / UNIT_SERIES;
            if total_units == admitted_units {
                break;
            }
            admitted_units = total_units;
        }
        assert_eq!(admitted_units, 41);
        assert_eq!(b.admitted_len(), 1020);
    }
}
