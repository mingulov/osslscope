//! SPDX-License-Identifier: GPL-3.0-or-later
//! Discovery table completion and source-tagged loss (T03).
//!
//! A prefix with useful rows is not a complete table: every observed
//! provider/operation array needs termination proof (`TERMD`, read
//! from the BPF map) before its op can be COMPLETE, and every
//! read/reserve/map-update/orphan failure carries a source-tagged
//! counter. [`CoverageTracker`] is the host accounting unit:
//! `harvest::run` feeds it the decoded ring stream plus the
//! `TRUNC`/`TERMD`/`LOSS` map snapshots, and it answers
//! per-table state, unterminated ops, losses, and ranked gap
//! reasons. The fake-stream tests in `tests/discovery_coverage.rs`
//! exercise this same unit, so host accounting is pinned without a
//! privileged lane.
//!
//! [`CoverageDelta`] is the retention contract T06's
//! `DiscoveryDelta` consumes: reasons accumulate across polls and
//! are never dropped by a later clean poll.
use osslscope_ebpf_common as wire;
use std::collections::{HashMap, HashSet};

/// Userspace loss sources (host-local ids; the wire ids 1..=14 live
/// in `ebpf-common`). Orphan rows and undecodable ring bytes are
/// evidence loss, counted like any kernel-side failure.
pub const HOST_ORPHAN_ROW: u32 = 101;
pub const HOST_BAD_EVENT: u32 = 102;
pub const HOST_SHORT_EVENT: u32 = 103;
pub const HOST_UNKNOWN_KIND: u32 = 104;
pub const HOST_MAP_SNAPSHOT: u32 = 105;
pub const HOST_DRAIN_SHORTFALL: u32 = 106;
pub const HOST_EVICT_FAILED: u32 = 107;

/// Frozen gap-reason vocabulary owned here (schema's derived reasons
/// reference these; see [`primary_reason`] for the single ranking).
pub const REASON_FENCED_ROWS: &str = "fenced-rows";
pub const REASON_DISCOVERY_LOSS: &str = "discovery-loss";
pub const REASON_UNREADABLE_ALG: &str = "unreadable-alg";
pub const REASON_TRUNCATED_WALK: &str = "truncated-walk";
pub const REASON_PREFIX_WALK: &str = "prefix-walk";
pub const REASON_ZERO_ROW_OPS: &str = "zero-row-ops";

/// Total decoder for loss-source ids (wire + host). Unknown ids
/// (newer BPF than userspace) are `None`; callers render them as
/// `unknown_<id>` rather than dropping the count.
pub fn loss_source_name(src: u32) -> Option<&'static str> {
    Some(match src {
        wire::LOSS_RING_ALG => "ring_alg",
        wire::LOSS_RING_ROW => "ring_row",
        wire::LOSS_RING_TRIP => "ring_trip",
        wire::LOSS_RING_INIT => "ring_init",
        wire::LOSS_MAP_QUERY_NEXT => "map_query_next",
        wire::LOSS_MAP_TRUNC => "map_trunc",
        wire::LOSS_MAP_CALLS => "map_calls",
        wire::LOSS_MAP_TRIP => "map_trip",
        wire::LOSS_MAP_LGCALLS => "map_lgcalls",
        wire::LOSS_MAP_TERMD => "map_termd",
        wire::LOSS_PENDING_INIT_FULL => "pending_init_full",
        wire::LOSS_PENDING_QUERY_FULL => "pending_query_full",
        wire::LOSS_PENDING_INIT_MISS => "pending_init_miss",
        wire::LOSS_PENDING_QUERY_MISS => "pending_query_miss",
        wire::LOSS_INIT_SCAN => "init_scan",
        HOST_ORPHAN_ROW => "orphan_row",
        HOST_BAD_EVENT => "bad_event",
        HOST_SHORT_EVENT => "short_event",
        HOST_UNKNOWN_KIND => "unknown_kind",
        HOST_MAP_SNAPSHOT => "map_snapshot",
        HOST_DRAIN_SHORTFALL => "drain_shortfall",
        HOST_EVICT_FAILED => "evict_failed",
        _ => return None,
    })
}

/// Which gap classes are present. Integrity outranks completeness:
/// fenced rows (unverifiable claims) first, then pipeline loss, lost
/// slot identity, walk aborts/overflows, unfinished prefixes, and
/// finally queried-but-rowless ops.
pub struct ReasonFlags {
    pub fenced: bool,
    pub loss: bool,
    pub unreadable: bool,
    pub truncated: bool,
    pub prefix: bool,
    pub zero_row: bool,
}

/// All applicable reasons in rank order. This is the single ranking;
/// both the tracker and `schema::emit` derive from it.
pub fn ranked_reasons(f: &ReasonFlags) -> Vec<&'static str> {
    let mut out = Vec::new();
    if f.fenced {
        out.push(REASON_FENCED_ROWS);
    }
    if f.loss {
        out.push(REASON_DISCOVERY_LOSS);
    }
    if f.unreadable {
        out.push(REASON_UNREADABLE_ALG);
    }
    if f.truncated {
        out.push(REASON_TRUNCATED_WALK);
    }
    if f.prefix {
        out.push(REASON_PREFIX_WALK);
    }
    if f.zero_row {
        out.push(REASON_ZERO_ROW_OPS);
    }
    out
}

/// The derived PARTIAL reason: the top-ranked applicable gap.
pub fn primary_reason(f: &ReasonFlags) -> Option<&'static str> {
    ranked_reasons(f).into_iter().next()
}

/// Traversal state of one observed (op, array) table. Array bases
/// are internal join keys only — they never leave this module (see
/// [`CoverageTracker::unterminated_ops`], which reports op ids).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableState {
    Unseen,
    InProgress { walked: u32 },
    Terminated { len: u32 },
}

/// Host discovery accounting: feed the decoded ring stream during
/// the drain, then the end-of-run map snapshots.
///
/// Slot-level holes are caught twice: every drop path is counted
/// by construction (a lost ALG/ROW implies a ring-reserve failure
/// in `LOSS`, an orphan implies its ALG never decoded, and an
/// undecodable event is counted at the drop site), AND termination
/// requires the walked set to be exactly the proven slots — so a
/// stale proof, a skipped slot, or an unprocessed drain tail can
/// never read as whole even when no counter fired.
#[derive(Debug, Default)]
pub struct CoverageTracker {
    /// (op, array) → unique walked slot indices.
    walked: HashMap<(u32, u64), HashSet<u64>>,
    /// Observed (op, array) pairs (query-ret or alg evidence).
    observed: HashSet<(u32, u64)>,
    /// Array → (op, proven length) termination proofs.
    termd: HashMap<u64, (u32, u32)>,
    /// Op → TRUNC bits.
    trunc: HashMap<u32, u64>,
    /// Source → count (wire and host merged).
    losses: HashMap<u32, u64>,
    /// Slots whose identity was lost (unreadable/overlong names).
    lossy: u64,
}

impl CoverageTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// First-hit liveness for an array (op + array base join key).
    pub fn note_query_ret(&mut self, op: u32, arr: u64) {
        self.observed.insert((op, arr));
    }

    /// One classified ALG record. `lossy` marks unreadable/overlong
    /// names, whose slot identity is lost even though the walk
    /// position advanced.
    pub fn note_alg(&mut self, op: u32, arr: u64, idx: u64, lossy: bool) {
        self.observed.insert((op, arr));
        self.walked.entry((op, arr)).or_default().insert(idx);
        if lossy {
            self.lossy += 1;
        }
    }

    /// A ROW whose (array, index) has no ALG record: dropped, counted.
    pub fn note_orphan_row(&mut self) {
        *self.losses.entry(HOST_ORPHAN_ROW).or_default() += 1;
    }

    /// A dropped ring item: `src` is one of the `HOST_*` ids.
    /// (Also the counter for host-side map-operation failures such
    /// as failed array evictions.)
    pub fn note_bad_event(&mut self, src: u32) {
        debug_assert!(
            (HOST_ORPHAN_ROW..=HOST_EVICT_FAILED).contains(&src),
            "host loss source out of range: {src}"
        );
        *self.losses.entry(src).or_default() += 1;
    }

    /// `n` ring items left unprocessed when the drain stopped
    /// (bounded shortfall count; see the drain tail).
    pub fn note_drain_shortfall(&mut self, n: u64) {
        if n > 0 {
            *self.losses.entry(HOST_DRAIN_SHORTFALL).or_default() += n;
        }
    }

    /// A failed BPF map snapshot (setup or iteration): the map's
    /// contents are unknown, so the gap is explicit rather than
    /// read as empty.
    pub fn note_map_snapshot(&mut self) {
        *self.losses.entry(HOST_MAP_SNAPSHOT).or_default() += 1;
    }

    /// End-of-run `TERMD` snapshot: (array, packed op/len).
    pub fn ingest_termd(&mut self, rows: &[(u64, u64)]) {
        for (arr, v) in rows {
            let (op, len) = wire::split_termd(*v);
            self.termd.insert(*arr, (op, len));
        }
    }

    /// End-of-run `TRUNC` snapshot: (op, bits).
    pub fn ingest_trunc(&mut self, rows: &[(u32, u64)]) {
        for (op, bits) in rows {
            *self.trunc.entry(*op).or_default() |= *bits;
        }
    }

    /// End-of-run `LOSS` snapshot: (source, count). Zero counts are
    /// dropped; nonzero counts sum with host-side losses.
    pub fn ingest_losses(&mut self, rows: &[(u32, u64)]) {
        for (src, n) in rows {
            if *n > 0 {
                *self.losses.entry(*src).or_default() += *n;
            }
        }
    }

    /// Retire one (op, array) table incarnation: drop its walked set,
    /// observation, and termination proof, returning the gap it
    /// carried as a [`CoverageDelta`] for per-epoch retention (T06
    /// session epochs). Losses are global, not per-table, so they
    /// never travel here — only the table's own prefix/truncation
    /// reasons do.
    ///
    /// Callers retire when the array's mapping incarnation changes
    /// (reload/remap) or vanishes (unload). A terminated table
    /// retires silently (it carried no gap); anything observed but
    /// unterminated contributes its prefix, plus truncation while
    /// the op's TRUNC bits are set (TRUNC is kernel-sticky per op,
    /// so the bits stay for the next incarnation too).
    pub fn retire_table(&mut self, op: u32, arr: u64) -> CoverageDelta {
        let state = self.table_state(op, arr);
        let was_observed = self.observed.contains(&(op, arr));
        self.walked.remove(&(op, arr));
        self.observed.remove(&(op, arr));
        let drop_proof = matches!(self.termd.get(&arr), Some((top, _)) if *top == op);
        if drop_proof {
            self.termd.remove(&arr);
        }
        let mut reasons = Vec::new();
        if was_observed && !matches!(state, TableState::Terminated { .. }) {
            reasons.push(REASON_PREFIX_WALK.to_string());
        }
        if self.trunc.get(&op).is_some_and(|b| *b != 0) {
            reasons.push(REASON_TRUNCATED_WALK.to_string());
        }
        reasons.sort_unstable();
        CoverageDelta {
            reasons,
            losses: Vec::new(),
        }
    }

    pub fn table_state(&self, op: u32, arr: u64) -> TableState {
        if let Some((top, len)) = self.termd.get(&arr).copied() {
            // A proof for another op at the same base (address reuse
            // across reloads) proves nothing about this table.
            if top == op {
                // Exact coverage: the proof names `len` live slots
                // and the walked set must be exactly 0..len.
                // Anything else — skipped impl-less slots, lost
                // records, or a stale proof reused by a reloaded
                // array at the same base (ABA growth) — is still in
                // progress, never complete. (ABA shrinkage can feed
                // the walker out-of-bound reads; incarnation binding
                // is T06 epoch work — see the handoff residual.)
                let set = self.walked.get(&(op, arr));
                let n = set.map(|s| s.len()).unwrap_or(0);
                let exact =
                    n as u64 == len as u64 && set.is_none_or(|s| s.iter().all(|i| *i < len as u64));
                if exact {
                    return TableState::Terminated { len };
                }
                return TableState::InProgress { walked: n as u32 };
            }
        }
        match self.walked.get(&(op, arr)) {
            Some(set) if !set.is_empty() => TableState::InProgress {
                walked: set.len() as u32,
            },
            _ => {
                if self.observed.contains(&(op, arr)) {
                    TableState::InProgress { walked: 0 }
                } else {
                    TableState::Unseen
                }
            }
        }
    }

    /// Ops with at least one observed array lacking termination
    /// proof, sorted. Array bases stay internal; callers report op
    /// ids and counts only.
    pub fn unterminated_ops(&self) -> Vec<u32> {
        let mut ops: Vec<u32> = self
            .observed
            .iter()
            .filter(|(op, arr)| {
                !matches!(self.table_state(*op, *arr), TableState::Terminated { .. })
            })
            .map(|(op, _)| *op)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        ops.sort_unstable();
        ops
    }

    /// All nonzero TRUNC rows, sorted by op (for the doc's
    /// `truncated_ops` detail).
    pub fn truncated(&self) -> Vec<(u32, u64)> {
        let mut out: Vec<(u32, u64)> = self
            .trunc
            .iter()
            .filter(|(_, b)| **b != 0)
            .map(|(op, b)| (*op, *b))
            .collect();
        out.sort_unstable();
        out
    }

    /// All nonzero losses, sorted by source.
    pub fn losses(&self) -> Vec<(u32, u64)> {
        let mut out: Vec<(u32, u64)> = self
            .losses
            .iter()
            .filter(|(_, n)| **n > 0)
            .map(|(s, n)| (*s, *n))
            .collect();
        out.sort_unstable();
        out
    }

    /// Slots with lost identity (unreadable/overlong names).
    pub fn lossy_slots(&self) -> u64 {
        self.lossy
    }

    fn has_trunc(&self) -> bool {
        self.trunc.values().any(|b| *b != 0)
    }

    /// Whole iff every observed table terminated, no losses, no
    /// lossy slots, and no walk-shape flags. Vacuously true when
    /// nothing was observed (absence is explained by the caller's
    /// no-trigger doctrine, not here).
    pub fn is_complete(&self) -> bool {
        self.unterminated_ops().is_empty()
            && self.losses.values().all(|n| *n == 0)
            && self.lossy == 0
            && !self.has_trunc()
    }

    /// Applicable gap reasons in rank order (tracker domain: loss,
    /// unreadable, truncated, prefix — fence/zero-row belong to the
    /// schema/harvest layer and join the same ranking there).
    pub fn reasons(&self) -> Vec<String> {
        ranked_reasons(&ReasonFlags {
            fenced: false,
            loss: !self.losses().is_empty(),
            unreadable: self.lossy > 0,
            truncated: self.has_trunc(),
            prefix: !self.unterminated_ops().is_empty(),
            zero_row: false,
        })
        .into_iter()
        .map(str::to_string)
        .collect()
    }
}

/// One poll's worth of gaps. Reasons union (sorted, deduped) and
/// loss counters sum across [`CoverageDelta::accumulate`]; a clean
/// poll retains every earlier gap.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoverageDelta {
    pub reasons: Vec<String>,
    pub losses: Vec<(u32, u64)>,
}

impl CoverageDelta {
    pub fn accumulate(&mut self, next: &CoverageDelta) {
        for r in &next.reasons {
            if !self.reasons.contains(r) {
                self.reasons.push(r.clone());
            }
        }
        self.reasons.sort_unstable();
        let mut sums: HashMap<u32, u64> = self.losses.iter().copied().collect();
        for (src, n) in &next.losses {
            *sums.entry(*src).or_default() += *n;
        }
        self.losses = sums.into_iter().collect();
        self.losses.sort_unstable();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retire_preserves_gap_drops_proof() {
        // Epoch turnover: retiring an unterminated table returns its
        // prefix for retention, drops the walked set and the proof,
        // and leaves global losses untouched.
        let mut t = CoverageTracker::new();
        t.note_query_ret(1, ARR_TEST);
        t.note_alg(1, ARR_TEST, 0, false);
        t.ingest_termd(&[(ARR_TEST, wire::make_termd(1, 4))]);
        t.ingest_trunc(&[(1, wire::TRUNC_WALK_READ)]);
        t.ingest_losses(&[(wire::LOSS_RING_ROW, 2)]);
        let gap = t.retire_table(1, ARR_TEST);
        assert_eq!(
            gap,
            CoverageDelta {
                reasons: vec![
                    REASON_PREFIX_WALK.to_string(),
                    REASON_TRUNCATED_WALK.to_string()
                ],
                losses: vec![],
            }
        );
        assert_eq!(t.table_state(1, ARR_TEST), TableState::Unseen);
        assert!(t.unterminated_ops().is_empty());
        assert_eq!(t.losses(), vec![(wire::LOSS_RING_ROW, 2)]);
        // TRUNC is kernel-sticky per op: it stays for the next
        // incarnation (the kernel re-reports it on every join).
        assert_eq!(t.truncated(), vec![(1, wire::TRUNC_WALK_READ)]);

        // A terminated table retires silently.
        let mut t = CoverageTracker::new();
        t.note_query_ret(1, ARR_TEST);
        t.note_alg(1, ARR_TEST, 0, false);
        t.ingest_termd(&[(ARR_TEST, wire::make_termd(1, 1))]);
        assert_eq!(
            t.table_state(1, ARR_TEST),
            TableState::Terminated { len: 1 }
        );
        let gap = t.retire_table(1, ARR_TEST);
        assert!(gap.reasons.is_empty());
        assert_eq!(t.table_state(1, ARR_TEST), TableState::Unseen);

        // An unseen table retires silently too.
        let mut t = CoverageTracker::new();
        let gap = t.retire_table(9, ARR_TEST);
        assert!(gap.reasons.is_empty());
    }

    #[test]
    fn termd_op_mismatch_proves_nothing() {
        // Address reuse across reloads: a proof naming op 2 at this
        // base does not terminate the op-1 table there.
        let mut t = CoverageTracker::new();
        t.note_query_ret(1, ARR_TEST);
        t.ingest_termd(&[(ARR_TEST, wire::make_termd(2, 4))]);
        assert_eq!(
            t.table_state(1, ARR_TEST),
            TableState::InProgress { walked: 0 }
        );
        assert_eq!(t.unterminated_ops(), vec![1]);
    }

    const ARR_TEST: u64 = 0x7f00_2000;

    #[test]
    fn ranking_is_fence_first_zero_row_last() {
        let all = ranked_reasons(&ReasonFlags {
            fenced: true,
            loss: true,
            unreadable: true,
            truncated: true,
            prefix: true,
            zero_row: true,
        });
        assert_eq!(
            all,
            vec![
                REASON_FENCED_ROWS,
                REASON_DISCOVERY_LOSS,
                REASON_UNREADABLE_ALG,
                REASON_TRUNCATED_WALK,
                REASON_PREFIX_WALK,
                REASON_ZERO_ROW_OPS,
            ]
        );
        assert_eq!(
            primary_reason(&ReasonFlags {
                fenced: false,
                loss: false,
                unreadable: false,
                truncated: true,
                prefix: true,
                zero_row: true,
            }),
            Some(REASON_TRUNCATED_WALK)
        );
    }

    #[test]
    fn loss_names_cover_wire_and_host() {
        for src in 1..=15u32 {
            assert!(loss_source_name(src).is_some(), "wire source {src}");
        }
        for src in [
            HOST_ORPHAN_ROW,
            HOST_BAD_EVENT,
            HOST_SHORT_EVENT,
            HOST_UNKNOWN_KIND,
            HOST_MAP_SNAPSHOT,
            HOST_DRAIN_SHORTFALL,
            HOST_EVICT_FAILED,
        ] {
            assert!(loss_source_name(src).is_some(), "host source {src}");
        }
        assert_eq!(loss_source_name(0), None);
        assert_eq!(loss_source_name(16), None);
        assert_eq!(loss_source_name(100), None);
        assert_eq!(loss_source_name(108), None);
        assert_eq!(loss_source_name(u32::MAX), None);
    }
}
