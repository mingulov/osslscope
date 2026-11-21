// SPDX-License-Identifier: GPL-3.0-or-later
//! C023/W102 qual verdicts (§6D-10): cell validity (VOID
//! conditions), estimators, and the three conjuncts. Pure and
//! host-testable; live legs in `tests/c023_qual.rs` build
//! [`CellData`] from real runs and call [`evaluate_cell`].

/// Frozen M-edge API IDs (the taken-path call tree: Q_digest,
/// CTX_new, Init/Update/Final, CTX_free).
pub const M_APIS: [u32; 6] = [64, 69, 20, 22, 23, 70];
/// Frozen fetch API ID (the unconditional per-op fetch).
pub const F_API: u32 = 10;
/// Intercepted callbacks per app op (M + F).
pub const EDGES_PER_OP: u64 = 7;
/// Paired-events floor (a quiet run is VOID).
pub const MIN_PAIRED: u64 = 1000;
/// Frozen matched-run op minimum (§6D-10 recipe: N ≥ 1000).
pub const MIN_OPS: u64 = 1000;
/// Added-latency budget in per-op diff units (4µs × 7 callbacks):
/// the exact verdict compares the median per-op diff against this
/// BEFORE any per-callback division (no rounding smuggles a pass).
pub const BUDGET_ADDED_DIFF_NS: i64 = BUDGET_ADDED_NS * EDGES_PER_OP as i64;
/// Added-latency budget (median over reps of per-op median added
/// latency per intercepted callback).
pub const BUDGET_ADDED_NS: i64 = 4_000;
/// Wall-ratio budget, frozen value (max over reps — the verdict
/// implements it in exact integers, see
/// [`latency_wall_verdict_exact`]).
pub const BUDGET_WALL_RATIO: f64 = 2.0;
/// Verdict repetitions per conjunct.
pub const MIN_REPS: usize = 5;
/// C023 latency/wall/rate acceptance state (D0-6 failure exit):
/// `true` while ANY conjunct is unclosed. Public CLI paths
/// ([`super::cli::resolve_public_trace_mode`]) force the
/// aggregate-only fallback while OPEN; only the isolated
/// qualification harness may program operational modes. Flips to
/// `false` ONLY via the C023 re-qualification reviewed amendment
/// (all three conjuncts closed on the frozen recipe).
pub const ACCEPTANCE_OPEN: bool = true;

/// Qual input derivation (M + F re-derived per pinned input; the
/// 3.5.5 derivation lives in the Phase 2 report).
#[derive(Clone, Copy, Debug)]
pub struct QualInput {
    /// M operational APIs (each exactly `app_ops` edges).
    pub m_apis: [u32; 6],
    /// The fetch API (exactly `app_ops` edges).
    pub fetch_api: u32,
}

/// OpenSSL 3.5.5 derivation (M = 6 + F = 1, taken-path walk).
pub const QUAL_3_5: QualInput = QualInput {
    m_apis: M_APIS,
    fetch_api: F_API,
};

/// One qual cell's observed data (live legs fill from real runs).
#[derive(Clone, Debug, Default)]
pub struct CellData {
    /// Offered app ops (harness schedule).
    pub app_ops: u64,
    /// Completed app ops (fixture-reported).
    pub completed: u64,
    /// Per-op harness latencies, ns (CLOCK_MONOTONIC around every op).
    pub per_op_ns: Vec<u64>,
    /// Run wall, ns (harness span).
    pub wall_ns: u64,
    /// Max schedule lateness, ns (rate cells: op start past deadline).
    pub max_late_ns: u64,
    /// Offered pace, ns (rate cells).
    pub pace_ns: u64,
    /// Observer: paired public-API events.
    pub paired: u64,
    /// Observer: finalized unpaired counts (both directions).
    pub unpaired_entries: u64,
    pub unpaired_results: u64,
    /// Observer: detail capped.
    pub capped: bool,
    /// Observer: 8 ring-loss lanes.
    pub ring_loss: [u64; 8],
    /// Observer: decode-domain unknown-ID records.
    pub rejected_unknown_api: u64,
    /// Producer pairing taint (P2fix3 NEW-12: the live assembly
    /// carries the producer's pairing-uncertain signal — any
    /// pairing-state corruption observed during the run VOIDs the
    /// cell, even when every count reconciles).
    pub pairing_tainted: bool,
    /// Observer: ATTEMPT edges by API ID (index = ID).
    pub api_attempts: Vec<u64>,
    /// Observer: RESULT edges by API ID (index = ID).
    pub api_results: Vec<u64>,
    /// Observer: received ATTEMPTs over the paired scope (family
    /// sums — the §6D-10 bridge input).
    pub received_attempts: u64,
    /// Observer: received RESULTs over the paired scope.
    pub received_results: u64,
    /// Observer: per-M-API aggregate gaps (map, depth, unpaired).
    pub m_edge_gaps: [(u64, u64, u64); 6],
    /// Observer: per-M-API aggregate entry counts (§6D-4a P1
    /// bridge input — entries == received edges under zero loss).
    pub m_edge_entries: [u64; 6],
    /// Observer: per-M-API aggregate row presence (a missing row is
    /// an unproven zero — fail closed, never a silent zero).
    pub m_rows_found: [bool; 6],
    /// The close batch vouched a successful scoped count read for
    /// the run scope (terminal receipt present).
    pub scoped_read_ok: bool,
    /// The harness timing receipt parsed strictly (every line
    /// well-formed, counts reconcile — malformed numbers are never
    /// silently zero).
    pub timings_valid: bool,
    /// Frozen schedule origin, CLOCK_MONOTONIC ns (op i slot =
    /// origin + i × pace; DELTA-10).
    pub schedule_origin_ns: u64,
    /// Frozen completion deadline, CLOCK_MONOTONIC ns
    /// (origin + offered × pace — the FULL offered population must
    /// finish by it; DELTA-10).
    pub completion_deadline_ns: u64,
    /// Final application operation's COMPLETION timestamp,
    /// CLOCK_MONOTONIC ns (P2fix2 item 12: the last op's t1 from
    /// the strict timing receipt — compared to the deadline above.
    /// Elapsed wall serves the wall conjunct only, never this
    /// rule).
    pub final_completion_ns: u64,
}

/// Cell kind (validity rules differ).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellKind {
    /// Latency/wall cells (capped VOIDs).
    LatencyWall,
    /// Rate cells (capped allowed + published; shortfall OPENS).
    Rate,
}

/// Cell disposition.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Verdict {
    /// Valid cell (numbers feed the conjunct estimators).
    Valid,
    /// VOID cell (validity condition failed; excluded from
    /// estimators with numbers published).
    Void { reason: &'static str },
    /// Rate schedule shortfall (gate OPEN with numbers).
    Open { reason: &'static str },
}

/// Evaluate one cell (§6D-10 cell validity, binding order).
pub fn evaluate_cell(cell: &CellData, input: &QualInput, kind: CellKind) -> Verdict {
    // Quiet runs are VOID, never passes.
    if cell.paired < MIN_PAIRED {
        return Verdict::Void { reason: "quiet" };
    }
    // Frozen recipe floor: matched runs carry N ≥ 1000 ops.
    if cell.app_ops < MIN_OPS {
        return Verdict::Void {
            reason: "under-minimum",
        };
    }
    // A malformed timing receipt VOIDs before any content check
    // (malformed numbers are never silently zero).
    if !cell.timings_valid {
        return Verdict::Void {
            reason: "timings-malformed",
        };
    }
    // Per-op harness timings missing for ANY op VOIDs the cell.
    if cell.per_op_ns.len() as u64 != cell.completed {
        return Verdict::Void {
            reason: "timings-incomplete",
        };
    }
    // Capped windows VOID latency/wall cells (rate cells publish).
    if cell.capped && kind == CellKind::LatencyWall {
        return Verdict::Void { reason: "capped" };
    }
    // Any ring lane > 0 VOIDs the cell.
    if cell.ring_loss.iter().any(|lane| *lane > 0) {
        return Verdict::Void {
            reason: "ring-loss",
        };
    }
    // Any M-edge aggregate gap VOIDs the cell.
    if cell
        .m_edge_gaps
        .iter()
        .any(|(map, depth, unpaired)| *map > 0 || *depth > 0 || *unpaired > 0)
    {
        return Verdict::Void {
            reason: "aggregate-gap",
        };
    }
    // Unknown-ID records VOID the cell.
    if cell.rejected_unknown_api > 0 {
        return Verdict::Void {
            reason: "rejected-unknown",
        };
    }
    // Producer pairing taint VOIDs the cell (P2fix3 NEW-12: the
    // live assembly carries the producer's pairing-uncertain
    // signal — a tainted fold is untrustworthy as validity
    // evidence, so any pairing-state corruption observed during
    // the run disqualifies the cell even when every count
    // reconciles).
    if cell.pairing_tainted {
        return Verdict::Void {
            reason: "pairing-tainted",
        };
    }
    // Exact two-direction conservation (§6D-10 binding equations):
    // every received edge lands in exactly one terminal bucket
    // (compared in u128 — no saturation can mask a surplus).
    if cell.received_attempts as u128 != cell.paired as u128 + cell.unpaired_entries as u128 {
        return Verdict::Void {
            reason: "conservation-attempt",
        };
    }
    if cell.received_results as u128 != cell.paired as u128 + cell.unpaired_results as u128 {
        return Verdict::Void {
            reason: "conservation-result",
        };
    }
    let attempts = |api: u32| cell.api_attempts.get(api as usize).copied().unwrap_or(0);
    let results = |api: u32| cell.api_results.get(api as usize).copied().unwrap_or(0);
    // Per-API multiset assertion (the M fail-safe).
    for api in input.m_apis {
        if attempts(api) != cell.app_ops {
            return Verdict::Void {
                reason: "multiset-deviation",
            };
        }
    }
    for api in 20..=72u32 {
        if !input.m_apis.contains(&api) && attempts(api) != 0 {
            return Verdict::Void {
                reason: "multiset-deviation",
            };
        }
    }
    // Fetch assertion (the F fail-safe).
    if attempts(input.fetch_api) != cell.app_ops {
        return Verdict::Void {
            reason: "fetch-deviation",
        };
    }
    for api in [11u32, 12, 13, 14, 15] {
        if attempts(api) != 0 {
            return Verdict::Void {
                reason: "fetch-deviation",
            };
        }
    }
    // The P1-A1 fetch extension (73..=80) folds fetch class 0: the
    // taken path emits none, so any edge here breaks the F
    // prediction exactly like 11..=15.
    for api in 73..=80u32 {
        if attempts(api) != 0 {
            return Verdict::Void {
                reason: "fetch-deviation",
            };
        }
    }
    // Lifecycle edges are exactly zero (warmup-confined).
    for api in 1..=6u32 {
        if attempts(api) != 0 {
            return Verdict::Void {
                reason: "lifecycle-edges",
            };
        }
    }
    // The observed RESULT vector agrees per API (no direction-only
    // surplus survives pairing once the workload prediction holds).
    for api in 0..81u32 {
        if results(api) != attempts(api) {
            return Verdict::Void {
                reason: "result-deviation",
            };
        }
    }
    // Exact allowed-ID populations (P2fix3 NEW-12): every slot
    // outside M+F reads exactly 0 in BOTH directions, over the
    // FULL vectors (any length — slots 0, 7..=9, 16..=19, and
    // 81+ included). A surplus in a forbidden slot that is also
    // added to the directional totals and `paired` passes every
    // equation above, so the population itself must be exact.
    // Sits AFTER the specific per-API arms (they diagnose shape
    // breaks first).
    let allowed = |api: usize| {
        let api = api as u32;
        input.m_apis.contains(&api) || api == input.fetch_api
    };
    for (api, v) in cell.api_attempts.iter().enumerate() {
        if *v != 0 && !allowed(api) {
            return Verdict::Void {
                reason: "forbidden-population",
            };
        }
    }
    for (api, v) in cell.api_results.iter().enumerate() {
        if *v != 0 && !allowed(api) {
            return Verdict::Void {
                reason: "forbidden-population",
            };
        }
    }
    // Per-API vectors reconcile to the conserved directional totals
    // (P2fix2 item 13): every received edge lands in exactly one API
    // slot — IDs outside every multiset range above (0, 7..=9,
    // 16..=19, 81+) cannot hide edges. Sits AFTER the specific
    // per-API arms (they diagnose shape breaks first) as the
    // unattributed-ID backstop (compared in u128 — no saturation
    // can mask a surplus).
    let attempt_sum: u128 = cell.api_attempts.iter().map(|v| *v as u128).sum();
    if attempt_sum != cell.received_attempts as u128 {
        return Verdict::Void {
            reason: "vector-conservation",
        };
    }
    let result_sum: u128 = cell.api_results.iter().map(|v| *v as u128).sum();
    if result_sum != cell.received_results as u128 {
        return Verdict::Void {
            reason: "vector-conservation",
        };
    }
    // Successful scoped reads: the close batch receipted the run
    // scope AND every M-edge aggregate row is present (a missing
    // row is an unproven zero — fail closed).
    if !cell.scoped_read_ok || cell.m_rows_found.iter().any(|f| !f) {
        return Verdict::Void {
            reason: "scoped-read",
        };
    }
    // Aggregate-entry bridge (§6D-4a P1): under the asserted-zero
    // gaps, aggregate entries equal received edges per M-API.
    for (i, api) in input.m_apis.iter().enumerate() {
        if cell.m_edge_entries[i] != attempts(*api) {
            return Verdict::Void {
                reason: "aggregate-bridge",
            };
        }
    }
    // Finalized unpaired counts are exactly zero, BOTH directions.
    if cell.unpaired_entries > 0 || cell.unpaired_results > 0 {
        return Verdict::Void {
            reason: "unpaired-finalize",
        };
    }
    // DELTA-10: the frozen completion deadline is exactly
    // origin + offered × pace. A malformed schedule input never
    // passes (paced or not); start lateness is published via
    // `max_late_ns`, never gated.
    let expected_deadline = (cell.schedule_origin_ns as u128)
        .saturating_add((cell.app_ops as u128).saturating_mul(cell.pace_ns as u128));
    if expected_deadline != cell.completion_deadline_ns as u128 {
        return Verdict::Void {
            reason: "schedule-origin",
        };
    }
    // The FULL offered population must finish: a shortfall OPENS a
    // rate cell (throughput verdict) and VOIDs a latency/wall cell
    // (the matched recipe broke — a validity failure).
    if cell.completed != cell.app_ops {
        return match kind {
            CellKind::Rate => Verdict::Open {
                reason: "schedule-shortfall",
            },
            CellKind::LatencyWall => Verdict::Void {
                reason: "schedule-shortfall",
            },
        };
    }
    // ... by the frozen completion deadline (paced runs only —
    // unpaced runs carry no offered schedule). The comparison uses
    // the final application's operation COMPLETION timestamp (its
    // t1), never elapsed wall (P2fix2 item 12).
    if cell.pace_ns > 0 && (cell.final_completion_ns as u128) > cell.completion_deadline_ns as u128
    {
        return match kind {
            CellKind::Rate => Verdict::Open {
                reason: "completion-deadline",
            },
            CellKind::LatencyWall => Verdict::Void {
                reason: "completion-deadline",
            },
        };
    }
    Verdict::Valid
}

/// Middle average of per-op latencies for even counts
/// (documented display choice; the exact verdict path uses
/// [`median2_ns`] and never this rounding).
pub fn median_ns(mut values: Vec<u64>) -> u64 {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    let mid = values.len() / 2;
    if values.len() % 2 == 1 {
        values[mid]
    } else {
        (values[mid - 1] + values[mid]) / 2
    }
}

/// Per-repetition added latency, ns per intercepted callback:
/// `(median(L_c) − median(L_a)) / 7` (signed; noise may read
/// negative — published, never clamped). DIAGNOSTIC display only
/// (documented truncation): the verdict compares exact doubled
/// diffs via [`added_diff2_ns`].
pub fn added_per_callback_ns(lat_c: &[u64], lat_a: &[u64]) -> i64 {
    let mc = median_ns(lat_c.to_vec()) as i64;
    let ma = median_ns(lat_a.to_vec()) as i64;
    (mc - ma) / EDGES_PER_OP as i64
}

/// Per-repetition wall ratio: `wall_c / wall_a`. DIAGNOSTIC
/// display only (float): the verdict compares `wall_c ≤ 2 ×
/// wall_a` in exact integers.
pub fn wall_ratio(wall_c: u64, wall_a: u64) -> f64 {
    if wall_a == 0 {
        return f64::INFINITY;
    }
    wall_c as f64 / wall_a as f64
}

/// Twice the lower-middle median of per-op latencies (exact —
/// no division, so even counts lose nothing).
pub fn median2_ns(mut values: Vec<u64>) -> u128 {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    if values.len() % 2 == 1 {
        2 * values[values.len() / 2] as u128
    } else {
        let mid = values.len() / 2;
        values[mid - 1] as u128 + values[mid] as u128
    }
}

/// Exact per-repetition added latency in doubled per-op-diff units:
/// `2 × (median(L_c) − median(L_a))` (signed; noise may read
/// negative — published, never clamped).
pub fn added_diff2_ns(lat_c: &[u64], lat_a: &[u64]) -> i128 {
    let mc = median2_ns(lat_c.to_vec());
    let ma = median2_ns(lat_a.to_vec());
    if mc >= ma {
        (mc - ma) as i128
    } else {
        -((ma - mc) as i128)
    }
}

/// Latency/wall conjunct verdict over ≥5 matched repetitions, with
/// the threshold comparison done EXACTLY before any division: the
/// median per-op diff must satisfy `median(diff) ≤ 4µs × 7`
/// (compared in doubled units, so no per-callback truncation and
/// no even-count averaging smuggle a pass), and every repetition
/// must satisfy `wall_c ≤ 2 × wall_a` in integers (no float ratio
/// rounds a boundary down). Either violated (or too few/unmatched
/// reps) ⇒ gate stays OPEN.
pub fn latency_wall_verdict_exact(diffs2: &[i128], walls: &[(u64, u64)]) -> bool {
    if diffs2.len() < MIN_REPS || walls.len() != diffs2.len() {
        return false;
    }
    let mut sorted = diffs2.to_vec();
    sorted.sort_unstable();
    // median(diff) ≤ 28000 ⟺ doubled-median ≤ 56000 (odd), or the
    // middle pair sums ≤ 112000 (even — still no division).
    let added_ok = if sorted.len() % 2 == 1 {
        sorted[sorted.len() / 2] <= 2 * BUDGET_ADDED_DIFF_NS as i128
    } else {
        let mid = sorted.len() / 2;
        sorted[mid - 1] + sorted[mid] <= 4 * BUDGET_ADDED_DIFF_NS as i128
    };
    if !added_ok {
        return false;
    }
    walls
        .iter()
        .all(|(c, a)| *a > 0 && (*c as u128) <= 2 * (*a as u128))
}

/// Rate conjunct verdict: every one of ≥5 rate cells valid (no
/// shortfall, no VOID). The frozen closure rule — currently
/// unmet (the live leg pins the honest all-VOID outcome until
/// re-qualification).
pub fn rate_verdict(cells: &[Verdict]) -> bool {
    cells.len() >= MIN_REPS && cells.iter().all(|v| *v == Verdict::Valid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_cell() -> CellData {
        let mut api_attempts = vec![0u64; 81];
        for api in M_APIS {
            api_attempts[api as usize] = 1000;
        }
        api_attempts[F_API as usize] = 1000;
        CellData {
            app_ops: 1000,
            completed: 1000,
            per_op_ns: vec![1000; 1000],
            wall_ns: 19_000_000_000,
            max_late_ns: 0,
            pace_ns: 20_000_000,
            paired: 7000,
            unpaired_entries: 0,
            unpaired_results: 0,
            capped: false,
            ring_loss: [0; 8],
            rejected_unknown_api: 0,
            pairing_tainted: false,
            api_attempts,
            api_results: {
                let mut v = vec![0u64; 81];
                for api in M_APIS {
                    v[api as usize] = 1000;
                }
                v[F_API as usize] = 1000;
                v
            },
            received_attempts: 7000,
            received_results: 7000,
            m_edge_gaps: [(0, 0, 0); 6],
            m_edge_entries: [1000; 6],
            m_rows_found: [true; 6],
            scoped_read_ok: true,
            timings_valid: true,
            schedule_origin_ns: 1_000_000_000,
            completion_deadline_ns: 21_000_000_000,
            final_completion_ns: 20_000_000_000,
        }
    }

    #[test]
    fn valid_cell_passes_both_kinds() {
        assert_eq!(
            evaluate_cell(&valid_cell(), &QUAL_3_5, CellKind::LatencyWall),
            Verdict::Valid
        );
        assert_eq!(
            evaluate_cell(&valid_cell(), &QUAL_3_5, CellKind::Rate),
            Verdict::Valid
        );
    }

    #[test]
    fn each_void_condition_fires() {
        let cases: Vec<(&str, Box<dyn Fn(&mut CellData)>, CellKind)> = vec![
            ("quiet", Box::new(|c| c.paired = 999), CellKind::LatencyWall),
            (
                "timings-incomplete",
                Box::new(|c| c.per_op_ns.truncate(999)),
                CellKind::LatencyWall,
            ),
            (
                "timings-malformed",
                Box::new(|c| c.timings_valid = false),
                CellKind::LatencyWall,
            ),
            (
                "under-minimum",
                Box::new(|c| {
                    c.app_ops = 999;
                    c.completed = 999;
                    c.per_op_ns.truncate(999);
                }),
                CellKind::LatencyWall,
            ),
            (
                "capped",
                Box::new(|c| c.capped = true),
                CellKind::LatencyWall,
            ),
            (
                "ring-loss",
                Box::new(|c| c.ring_loss[0] = 1),
                CellKind::LatencyWall,
            ),
            (
                "aggregate-gap",
                Box::new(|c| c.m_edge_gaps[2] = (0, 1, 0)),
                CellKind::LatencyWall,
            ),
            (
                "rejected-unknown",
                Box::new(|c| c.rejected_unknown_api = 1),
                CellKind::LatencyWall,
            ),
            (
                "multiset-deviation",
                Box::new(|c| c.api_attempts[64] = 999),
                CellKind::LatencyWall,
            ),
            (
                "multiset-deviation",
                Box::new(|c| c.api_attempts[21] = 1),
                CellKind::LatencyWall,
            ),
            (
                "fetch-deviation",
                Box::new(|c| c.api_attempts[10] = 999),
                CellKind::LatencyWall,
            ),
            (
                "fetch-deviation",
                Box::new(|c| c.api_attempts[11] = 1),
                CellKind::LatencyWall,
            ),
            (
                "fetch-deviation",
                Box::new(|c| c.api_attempts[73] = 1),
                CellKind::LatencyWall,
            ),
            (
                "lifecycle-edges",
                Box::new(|c| c.api_attempts[1] = 1),
                CellKind::LatencyWall,
            ),
            // Balanced orphans (P2fix2: unbalanced orphans are
            // unphysical — result-deviation forces per-API
            // agreement, so entries and results finalize together;
            // received stays 7000/7000 with paired 6999).
            (
                "unpaired-finalize",
                Box::new(|c| {
                    c.paired = 6999;
                    c.unpaired_entries = 1;
                    c.unpaired_results = 1;
                }),
                CellKind::LatencyWall,
            ),
            (
                "conservation-attempt",
                Box::new(|c| c.received_attempts = 6999),
                CellKind::LatencyWall,
            ),
            (
                "conservation-result",
                Box::new(|c| c.received_results = 7001),
                CellKind::LatencyWall,
            ),
            // P2fix3 NEW-12: forbidden-slot edges VOID on the exact
            // population arm (before the vector backstop below).
            (
                "forbidden-population",
                Box::new(|c| c.api_attempts.push(1)),
                CellKind::LatencyWall,
            ),
            (
                "forbidden-population",
                Box::new(|c| c.api_results.push(1)),
                CellKind::LatencyWall,
            ),
            // P2fix2 item 13 (codex NEW-P2g): per-API vectors
            // reconcile to the conserved directional totals — with
            // exact populations, an inflated directional total still
            // fires the vector backstop (conservation holds via
            // paired, but the vectors do not sum to it).
            (
                "vector-conservation",
                Box::new(|c| {
                    c.received_attempts += 1;
                    c.received_results += 1;
                    c.paired += 1;
                }),
                CellKind::LatencyWall,
            ),
            // Result-side backstop (attempt side reconciles, result
            // side does not — conservation holds via the orphan).
            (
                "vector-conservation",
                Box::new(|c| {
                    c.received_results += 1;
                    c.unpaired_results = 1;
                }),
                CellKind::LatencyWall,
            ),
            // P2fix3 NEW-12: producer pairing taint VOIDs.
            (
                "pairing-tainted",
                Box::new(|c| c.pairing_tainted = true),
                CellKind::LatencyWall,
            ),
            (
                "result-deviation",
                Box::new(|c| c.api_results[22] = 999),
                CellKind::LatencyWall,
            ),
            (
                "scoped-read",
                Box::new(|c| c.scoped_read_ok = false),
                CellKind::LatencyWall,
            ),
            (
                "scoped-read",
                Box::new(|c| c.m_rows_found[4] = false),
                CellKind::LatencyWall,
            ),
            (
                "aggregate-bridge",
                Box::new(|c| c.m_edge_entries[0] = 999),
                CellKind::LatencyWall,
            ),
        ];
        for (reason, mutate, kind) in cases {
            let mut cell = valid_cell();
            mutate(&mut cell);
            assert_eq!(
                evaluate_cell(&cell, &QUAL_3_5, kind),
                Verdict::Void { reason },
                "arm {reason}"
            );
        }
        // Rate cells publish capped (no VOID) but shortfall OPENS.
        let mut capped = valid_cell();
        capped.capped = true;
        assert_eq!(
            evaluate_cell(&capped, &QUAL_3_5, CellKind::Rate),
            Verdict::Valid
        );
        let mut short = valid_cell();
        short.completed = 999;
        short.per_op_ns.truncate(999);
        assert_eq!(
            evaluate_cell(&short, &QUAL_3_5, CellKind::Rate),
            Verdict::Open {
                reason: "schedule-shortfall"
            }
        );
        // A latency/wall shortfall VOIDs (the matched recipe broke).
        assert_eq!(
            evaluate_cell(&short, &QUAL_3_5, CellKind::LatencyWall),
            Verdict::Void {
                reason: "schedule-shortfall"
            }
        );
        // DELTA-10: start lateness is published, never gated — a
        // late-starting run that still finishes by the deadline is
        // not a shortfall.
        let mut late = valid_cell();
        late.max_late_ns = late.pace_ns + 1;
        assert_eq!(
            evaluate_cell(&late, &QUAL_3_5, CellKind::Rate),
            Verdict::Valid
        );
        // DELTA-10 (P2fix2 item 12): the FINAL application
        // operation's COMPLETION timestamp is compared to the
        // frozen deadline — elapsed wall gates nothing here (it
        // serves the wall conjunct only). A late completion misses
        // even with a tiny wall ...
        let mut miss = valid_cell();
        miss.wall_ns = 1000;
        miss.final_completion_ns = 21_000_000_001;
        assert_eq!(
            evaluate_cell(&miss, &QUAL_3_5, CellKind::Rate),
            Verdict::Open {
                reason: "completion-deadline"
            }
        );
        // Same miss VOIDs a latency/wall cell (the matched schedule
        // broke — a validity failure, not a throughput verdict).
        assert_eq!(
            evaluate_cell(&miss, &QUAL_3_5, CellKind::LatencyWall),
            Verdict::Void {
                reason: "completion-deadline"
            }
        );
        // ... and a huge wall with an early completion passes (the
        // wall conjunct judges walls, not this rule).
        let mut wall_only = valid_cell();
        wall_only.wall_ns = 20_000_000_001;
        wall_only.final_completion_ns = 20_000_000_000;
        assert_eq!(
            evaluate_cell(&wall_only, &QUAL_3_5, CellKind::Rate),
            Verdict::Valid
        );
        // Unpaced runs (pace 0) carry no offered schedule: the
        // deadline still derives exactly (origin + 0) but no
        // end-by-deadline rule applies.
        let mut unpaced = valid_cell();
        unpaced.pace_ns = 0;
        unpaced.completion_deadline_ns = unpaced.schedule_origin_ns;
        unpaced.wall_ns = u64::MAX - 1_000_000_000;
        assert_eq!(
            evaluate_cell(&unpaced, &QUAL_3_5, CellKind::Rate),
            Verdict::Valid
        );
        // A deadline that is not exactly origin + offered × pace
        // is a malformed schedule input (never a pass).
        let mut bad_dl = valid_cell();
        bad_dl.completion_deadline_ns += 1;
        assert_eq!(
            evaluate_cell(&bad_dl, &QUAL_3_5, CellKind::Rate),
            Verdict::Void {
                reason: "schedule-origin"
            }
        );
    }

    #[test]
    fn new12_forbidden_slot_surplus_voids_even_when_conserved() {
        // P2fix3 NEW-12: exact allowed-ID populations — one extra
        // pair in a FORBIDDEN slot (0, 7..=9, 16..=19, 81+) with
        // both directional totals AND paired raised to match passes
        // every conservation equation, but the population is
        // impossible (the workload predicts edges on M+F only) and
        // must VOID.
        for slot in [0u32, 7, 8, 9, 16, 19, 81, 90] {
            let mut cell = valid_cell();
            while cell.api_attempts.len() <= slot as usize {
                cell.api_attempts.push(0);
                cell.api_results.push(0);
            }
            cell.api_attempts[slot as usize] = 1;
            cell.api_results[slot as usize] = 1;
            cell.received_attempts += 1;
            cell.received_results += 1;
            cell.paired += 1;
            assert_eq!(
                evaluate_cell(&cell, &QUAL_3_5, CellKind::LatencyWall),
                Verdict::Void {
                    reason: "forbidden-population"
                },
                "slot {slot}"
            );
            assert_eq!(
                evaluate_cell(&cell, &QUAL_3_5, CellKind::Rate),
                Verdict::Void {
                    reason: "forbidden-population"
                },
                "slot {slot} (rate)"
            );
        }
        // A forbidden RESULT-only surplus (no matching attempt)
        // VOIDs the same way (both directions populate exactly).
        let mut cell = valid_cell();
        cell.api_results.push(1);
        assert_eq!(
            evaluate_cell(&cell, &QUAL_3_5, CellKind::LatencyWall),
            Verdict::Void {
                reason: "forbidden-population"
            }
        );
    }

    #[test]
    fn new12_tainted_cell_voids() {
        // P2fix3 NEW-12: producer pairing taint VOIDs the cell even
        // when every count reconciles (a tainted fold is
        // untrustworthy as validity evidence, both kinds).
        let mut cell = valid_cell();
        cell.pairing_tainted = true;
        assert_eq!(
            evaluate_cell(&cell, &QUAL_3_5, CellKind::LatencyWall),
            Verdict::Void {
                reason: "pairing-tainted"
            }
        );
        assert_eq!(
            evaluate_cell(&cell, &QUAL_3_5, CellKind::Rate),
            Verdict::Void {
                reason: "pairing-tainted"
            }
        );
    }

    #[test]
    fn estimators_and_conjuncts() {
        assert_eq!(median_ns(vec![]), 0);
        assert_eq!(median_ns(vec![5]), 5);
        assert_eq!(median_ns(vec![1, 9]), 5);
        assert_eq!(median_ns(vec![3, 1, 2]), 2);
        // (median_c − median_a)/7 (display only — documented
        // truncation, never verdict input).
        assert_eq!(added_per_callback_ns(&[7000, 7000, 7000], &[0, 0, 0]), 1000);
        assert_eq!(wall_ratio(200, 100), 2.0);
        assert!(wall_ratio(1, 0).is_infinite());
        // Exact doubled-unit medians (no rounding anywhere).
        assert_eq!(median2_ns(vec![]), 0);
        assert_eq!(median2_ns(vec![5]), 10);
        assert_eq!(median2_ns(vec![1, 9]), 10);
        assert_eq!(median2_ns(vec![3, 1, 2]), 4);
        assert_eq!(added_diff2_ns(&[7000, 7000, 7000], &[0, 0, 0]), 14000);
        // Exact verdict: per-op diff ≤ 28000 (diff2 ≤ 56000) and
        // every wall_c ≤ 2 × wall_a, compared before any division.
        assert!(latency_wall_verdict_exact(&[56000; 5], &[(200, 100); 5]));
        assert!(!latency_wall_verdict_exact(&[56001; 5], &[(100, 100); 5]));
        // The truncated division would smuggle 28001/7 = 4000
        // through; the exact comparison rejects it.
        assert!(!latency_wall_verdict_exact(&[56002; 5], &[(100, 100); 5]));
        assert!(!latency_wall_verdict_exact(
            &[0; 5],
            &[(200, 100), (200, 100), (200, 100), (200, 100), (201, 100)]
        ));
        // The float ratio rounds (2^53+1)/2^52 down to exactly 2.0;
        // the exact comparison rejects it.
        assert!(!latency_wall_verdict_exact(
            &[0; 5],
            &[(0x20000000000001, 0x10000000000000); 5]
        ));
        assert!(!latency_wall_verdict_exact(&[0; 4], &[(100, 100); 4]));
        assert!(!latency_wall_verdict_exact(&[0; 5], &[(100, 100); 4]));
        assert!(!latency_wall_verdict_exact(&[0; 5], &[(100, 0); 5]));
        assert!(rate_verdict(&[Verdict::Valid; 5]));
        assert!(!rate_verdict(&[Verdict::Valid; 4]));
        assert!(!rate_verdict(&[
            Verdict::Valid,
            Verdict::Valid,
            Verdict::Valid,
            Verdict::Valid,
            Verdict::Void { reason: "x" }
        ]));
    }
}
