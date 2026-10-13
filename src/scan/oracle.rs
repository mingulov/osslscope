//! SPDX-License-Identifier: GPL-3.0-or-later
//! Per-invocation join oracle (P7 item 4 core): joins the
//! scan-plane ring (CALL/RET/GUARD/SCAN-ALG/SCAN-ROW) by (tid,seq)
//! with per-drain cell snapshots (RCOUNT/SEQ) and counter deltas,
//! and emits one WALK-DONE host record per invocation plus
//! explicit findings. No BPF WALK-DONE event exists BY DECISION:
//! RET + cells + coverage already prove completion, so a kernel
//! completion event would duplicate the retire signal —
//! WALK-DONE is the oracle's output row, computed here.
//!
//! Soundness rules (implementable §5.2/§5.3 subset — each named):
//!
//! - JOIN (R0): every RET/GUARD/ALG/ROW joins to exactly one
//!   admitted CALL by (tid,seq); orphans are explicit findings,
//!   never silently absorbed.
//! - COMPLETE (R1): admitted + RET joined + retired-proven +
//!   every attached slot ≤ TRUE-T covered with a known status +
//!   no structural TRUNC bits (ALGS/DISPATCH/WALK_READ/WALK_NAME
//!   ⟹ data missing ⟹ PARTIAL) + guard disposition consistent.
//!   TRUNC WALK_EMPTY/WALK_NOIMP/NO_STORE are stable walk
//!   observations (Complete-compatible — NOIMP is per-op, not
//!   per-slot, so no per-slot set is observable).
//! - TRUE-T (R2): warm (known T, GEN match) → Proven(written T)
//!   unless a window hole or a walk beyond T contradicts the
//!   belief; cold → first attached absence, Proven iff nothing
//!   is covered beyond it (coverage-beyond ⟹ the absence is a
//!   hole, never silently the end); all-512-covered → Proven(512)
//!   (capped — GUARD EMPTY corroborates); GUARD VALID (slot 512
//!   live, 513-live violation) → Candidate(512) + Overfull; RET
//!   EMPTY → EmptyTable.
//! - TAINT (R3): a hinted successor take taints the newest open
//!   predecessor (superseded-nested — never silent).
//! - ABANDON (R4): a skip over an open RET-less invocation
//!   abandons it (record deleted, RET never coming); LOSS
//!   20/21/25/31 deltas attribute to the single candidate tid
//!   (admitting take + open predecessor) or raise an explicit
//!   unattributed-loss finding.
//! - PARTIAL (R5): holes, UNREADABLE, TRUNC, guard ERROR/VALID,
//!   and drain-loss corroboration stay explicit (missing or
//!   failed chunks and drain loss are PARTIAL, never silent).
//! - RETIRE (R6): retired-proven ⟺ RET joined AND (a successor
//!   quiet-admit on the tid, OR no successor activity + quiesced
//!   + IDLE cells).
//!
//!   Quiesced ACTIVE + RET + no successor activity ⟹ STALLED
//!   (finding; a later quiet-admit abandons, never miscloses as
//!   retired — the detach-stall ambiguity resolved).
//!
//! Per-tid ring order is causal (one thread ⟹ sequential entry
//! hits), so "later activity" is positional within a tid — the
//! only positional reasoning in the oracle, and it is sound.
//!
//! Worst-scan occupancy recompute (R18 decision 15 — the §5.6
//! arithmetic with actual item-4 sizes; WALK-DONE is a host
//! record: 0 on-ring bytes):
//!
//! ```text
//! CALL 32 + RET 48 + GUARD 48 + 512 × (SCAN-ALG 64 + 128 × SCAN-ROW 72)
//! = 128 + 512 × 9280 = 4,751,488 B = 4.53125 MiB
//! ```
//!
//! Two-way tick race: 2 × 4.53125 + 4 (governor) = 13.0625 ≤ 16
//! MiB — the 16MiB criterion re-verified below (margin 2.94MiB,
//! grows vs §5.6's 2.875).

use osslscope_ebpf_common as wire;
use std::collections::{BTreeMap, BTreeSet};

/// On-ring record sizes (payload rounded to 8 + 8B ringbuf header).
pub const ONRING_CALL: u64 = 32;
pub const ONRING_RET: u64 = 48;
pub const ONRING_GUARD: u64 = 48;
pub const ONRING_SCAN_ALG: u64 = 64;
pub const ONRING_SCAN_ROW: u64 = 72;

/// Worst-case one-scan on-ring bytes (T=511, all attached, full
/// 128-row dispatch per slot).
pub const WORST_SCAN_BYTES: u64 =
    ONRING_CALL + ONRING_RET + ONRING_GUARD + 512 * (ONRING_SCAN_ALG + 128 * ONRING_SCAN_ROW);

/// 16MiB criterion re-verified (R18 decision 15): two worst scans
/// admitted at the 4MiB governor line still fit.
const _: () = assert!(WORST_SCAN_BYTES == 4_751_488);
const _: () = assert!(
    2 * WORST_SCAN_BYTES + wire::GOVERNOR_MAX_OCCUPIED <= 16 << 20,
    "16MiB ring holds the two-way tick race"
);

/// Per-drain batch: decoded ring events (ring order preserved per
/// vec) + counter deltas + cell snapshot + oracle scope. The
/// backend samples cells once per drain (commit 4); legs and
/// tests construct batches directly.
#[derive(Debug, Default)]
pub struct ScanBatch {
    pub calls: Vec<wire::ScanCallEvent>,
    pub rets: Vec<wire::ScanRetEvent>,
    pub guards: Vec<wire::GuardEvent>,
    pub algs: Vec<wire::ScanAlgEvent>,
    pub rows: Vec<wire::ScanRowEvent>,
    /// Per-id LOSS deltas observed this drain.
    pub loss: BTreeMap<u32, u64>,
    /// Per-op TRUNC deltas observed this drain.
    pub trunc: BTreeMap<u32, u64>,
    /// RCOUNT snapshot: tid → (count, state).
    pub rcount: BTreeMap<u32, (u32, u32)>,
    /// SEQ snapshot: tid → (birth, ctr).
    pub seq: BTreeMap<u32, (u16, u64)>,
    /// No query in flight at drain (single-threaded legs,
    /// discovery quiesced drains). Retirement/stall inference is
    /// only sound quiesced — non-quiesced batches hold
    /// underdetermined invocations open (honest, never guessed).
    pub quiesced: bool,
}

/// Oracle scope: what the producer was asked to observe (item 6
/// selective load flows through here — unattached slots are
/// unobserved, never holes).
#[derive(Debug, Clone)]
pub struct OracleScope {
    /// Attached member slots (normally 0..512).
    pub attached: BTreeSet<u32>,
    /// Programmed EXPECTED (must equal attached.len() — the
    /// loader enforces; the oracle double-checks).
    pub expected: u32,
    /// Live membership epoch.
    pub epoch: u64,
    /// Known T-cache entries: array → (T, generation). Item 4
    /// writes the cache, so it knows what it wrote; legs inject.
    pub known_t: BTreeMap<u64, (u64, u64)>,
}

impl OracleScope {
    pub fn full() -> Self {
        Self {
            attached: (0..512).collect(),
            expected: 512,
            epoch: 1,
            known_t: BTreeMap::new(),
        }
    }
}

/// Termination confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrueT {
    Proven(u64),
    Candidate(u64),
    /// No array (RET EMPTY) or undecidable.
    EmptyTable,
    Unknown,
}

/// Why an invocation is partial (explicit, never silent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartialReason {
    Holes(Vec<u64>),
    Unreadable(Vec<u64>),
    /// TRUNC bits observed for the invocation's op.
    Trunc(u64),
    GuardError,
    /// Guard VALID: slot 512 live (513-live contract
    /// violation — the table extends beyond observation).
    Overfull,
    /// Ring-loss deltas corroborate missing records.
    DrainLoss,
}

/// Why an invocation was abandoned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbandonReason {
    /// A skip landed over its unretired, RET-less record.
    SkipVictim,
    /// Membership churned mid-flight (LOSS 25).
    Churned,
    /// SCAN record LRU-evicted (LOSS 20).
    Evicted,
    /// Retire cleanup failed (LOSS 21).
    RetireFailed,
    /// Take-time repair of a corrupt record (LOSS 31).
    StaleRepaired,
    /// Stalled (detach) then superseded.
    Stalled,
}

/// Per-invocation outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Complete {
        true_t: u64,
        /// Covered via a warm cache entry (T-skips expected).
        cached: bool,
    },
    Partial {
        reasons: Vec<PartialReason>,
    },
    Skipped {
        cause: u8,
    },
    Tainted {
        /// Seq of the superseding hinted take.
        by_seq: u64,
    },
    Abandoned {
        reason: AbandonReason,
    },
}

/// WALK-DONE host record: one per invocation, emitted at close.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkDone {
    pub tid: u32,
    pub seq: u64,
    pub op: u32,
    pub outcome: Outcome,
    pub true_t: TrueT,
    pub alg_count: usize,
    pub row_count: usize,
    pub guard: Option<wire::GuardEvent>,
}

/// Oracle finding (join-correctness and accounting — explicit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    OrphanRet { tid: u32, seq: u64 },
    OrphanGuard { tid: u32, seq: u64 },
    OrphanAlg { tid: u32, seq: u64, idx: u64 },
    OrphanRow { tid: u32, seq: u64, idx: u64 },
    DoubleRet { tid: u32, seq: u64 },
    UnattributedLoss { id: u32, delta: u64 },
    Stall { tid: u32, seq: u64 },
}

/// Drain timing hook (item 7, host half): per-batch record/byte
/// counts feed the tier-2/3 rate views (commit 4 wires the
/// supervisor; R21 qualifies rates live).
#[derive(Debug, Default, Clone, Copy)]
pub struct DrainStats {
    pub batches: u64,
    pub records: u64,
    pub bytes: u64,
    pub calls: u64,
}

impl DrainStats {
    fn observe(&mut self, b: &ScanBatch) {
        self.batches += 1;
        let records =
            (b.calls.len() + b.rets.len() + b.guards.len() + b.algs.len() + b.rows.len()) as u64;
        self.records += records;
        self.calls += b.calls.len() as u64;
        self.bytes += b.calls.len() as u64 * ONRING_CALL
            + b.rets.len() as u64 * ONRING_RET
            + b.guards.len() as u64 * ONRING_GUARD
            + b.algs.len() as u64 * ONRING_SCAN_ALG
            + b.rows.len() as u64 * ONRING_SCAN_ROW;
    }
}

/// One open invocation (admitted CALL, not yet closed).
#[derive(Debug)]
struct Open {
    call: wire::ScanCallEvent,
    ret: Option<wire::ScanRetEvent>,
    guard: Option<wire::GuardEvent>,
    algs: BTreeMap<u64, wire::ScanAlgEvent>,
    rows: u64,
    /// Position of the CALL in its batch (ring order = causal
    /// order per tid — used for later-activity checks within a
    /// batch; cross-batch order is batch order).
    batch: u64,
    pos: usize,
    stalled: bool,
}

/// The per-invocation join oracle (stateful across drains —
/// opens persist until a sound close fires).
#[derive(Debug, Default)]
pub struct Oracle {
    scope: Option<OracleScope>,
    open: BTreeMap<(u32, u64), Open>,
    done: Vec<WalkDone>,
    findings: Vec<Finding>,
    stats: DrainStats,
    batches: u64,
}

impl Oracle {
    pub fn new(scope: OracleScope) -> Self {
        assert_eq!(
            scope.expected as usize,
            scope.attached.len(),
            "EXPECTED matches the attached set (loader enforces; oracle double-checks)"
        );
        Self {
            scope: Some(scope),
            ..Self::default()
        }
    }

    pub fn done(&self) -> &[WalkDone] {
        &self.done
    }

    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    pub fn stats(&self) -> DrainStats {
        self.stats
    }

    pub fn open_count(&self) -> usize {
        self.open.len()
    }

    /// Ingest one drain batch (ring order within each vec).
    pub fn ingest(&mut self, b: &ScanBatch) {
        let scope = self.scope.clone().expect("oracle scope set");
        self.stats.observe(b);
        let batch = self.batches;
        self.batches += 1;

        // 1. CALLs in ring order: open admits, close skips, taint
        // predecessors on hint, abandon RET-less opens on skip.
        for (pos, c) in b.calls.iter().enumerate() {
            let (_hint, cause) = wire::split_call_flags(c.flags);
            if cause != wire::SKIP_ADMITTED {
                self.done.push(WalkDone {
                    tid: c.tid,
                    seq: 0,
                    op: c.op,
                    outcome: Outcome::Skipped { cause },
                    true_t: TrueT::Unknown,
                    alg_count: 0,
                    row_count: 0,
                    guard: None,
                });
                // R4: the skip deleted any standing record — opens
                // WITHOUT a joined RET can never complete (their
                // return will SCAN-miss, or already did without a
                // RET — either way no RET will join). Opens WITH a
                // RET are evidence-free (retired or stalled —
                // decided by later takes / quiesced cells).
                let victims: Vec<(u32, u64)> = self
                    .open
                    .iter()
                    .filter(|((t, _), o)| *t == c.tid && o.ret.is_none())
                    .map(|(k, _)| *k)
                    .collect();
                for k in victims {
                    let o = self.open.remove(&k).expect("victim open");
                    self.done.push(WalkDone {
                        tid: k.0,
                        seq: k.1,
                        op: o.call.op,
                        outcome: Outcome::Abandoned {
                            reason: AbandonReason::SkipVictim,
                        },
                        true_t: TrueT::Unknown,
                        alg_count: o.algs.len(),
                        row_count: o.rows as usize,
                        guard: o.guard,
                    });
                }
                continue;
            }
            // Admitted: hint taints the newest open predecessor.
            if _hint {
                let pred = self
                    .open
                    .iter()
                    .filter(|((t, s), _)| *t == c.tid && *s < c.seq)
                    .max_by_key(|((_, s), _)| *s)
                    .map(|(k, _)| *k);
                if let Some(k) = pred {
                    // Nested takes are routine (re-entrant
                    // providers) — the Tainted verdict carries
                    // the supersede, no finding needed.
                    let o = self.open.remove(&k).expect("predecessor open");
                    self.done.push(WalkDone {
                        tid: k.0,
                        seq: k.1,
                        op: o.call.op,
                        outcome: Outcome::Tainted { by_seq: c.seq },
                        true_t: TrueT::Unknown,
                        alg_count: o.algs.len(),
                        row_count: o.rows as usize,
                        guard: o.guard,
                    });
                }
            }
            self.open.insert(
                (c.tid, c.seq),
                Open {
                    call: *c,
                    ret: None,
                    guard: None,
                    algs: BTreeMap::new(),
                    rows: 0,
                    batch,
                    pos,
                    stalled: false,
                },
            );
        }

        // 2. Join RET/GUARD/ALG/ROW by (tid,seq) — orphans are
        // findings (R0).
        for r in &b.rets {
            match self.open.get_mut(&(r.tid, r.seq)) {
                Some(o) if o.ret.is_none() => o.ret = Some(*r),
                Some(_) => self.findings.push(Finding::DoubleRet {
                    tid: r.tid,
                    seq: r.seq,
                }),
                None => {
                    if !self.done.iter().any(|w| w.tid == r.tid && w.seq == r.seq) {
                        self.findings.push(Finding::OrphanRet {
                            tid: r.tid,
                            seq: r.seq,
                        });
                    }
                }
            }
        }
        for g in &b.guards {
            match self.open.get_mut(&(g.tid, g.seq)) {
                Some(o) => o.guard = Some(*g),
                None => {
                    if !self.done.iter().any(|w| w.tid == g.tid && w.seq == g.seq) {
                        self.findings.push(Finding::OrphanGuard {
                            tid: g.tid,
                            seq: g.seq,
                        });
                    }
                }
            }
        }
        for a in &b.algs {
            match self.open.get_mut(&(a.tid, a.seq)) {
                Some(o) => {
                    o.algs.insert(a.idx, *a);
                }
                None => {
                    if !self.done.iter().any(|w| w.tid == a.tid && w.seq == a.seq) {
                        self.findings.push(Finding::OrphanAlg {
                            tid: a.tid,
                            seq: a.seq,
                            idx: a.idx,
                        });
                    }
                }
            }
        }
        for r in &b.rows {
            match self.open.get_mut(&(r.tid, r.seq)) {
                Some(o) => o.rows += 1,
                None => {
                    if !self.done.iter().any(|w| w.tid == r.tid && w.seq == r.seq) {
                        self.findings.push(Finding::OrphanRow {
                            tid: r.tid,
                            seq: r.seq,
                            idx: r.idx,
                        });
                    }
                }
            }
        }

        // 3. LOSS attribution (R4): 20/21/25/31 deltas attribute
        // to the single candidate tid (admitting take + open
        // predecessor in this batch) or raise unattributed-loss.
        for id in [
            wire::LOSS_SCAN_EVICTED,
            wire::LOSS_RETIRE_FAIL,
            wire::LOSS_SCAN_CHURNED,
            wire::LOSS_STALE_REPAIRED,
        ] {
            let delta = b.loss.get(&id).copied().unwrap_or(0);
            if delta == 0 {
                continue;
            }
            let reason = match id {
                wire::LOSS_SCAN_EVICTED => AbandonReason::Evicted,
                wire::LOSS_RETIRE_FAIL => AbandonReason::RetireFailed,
                wire::LOSS_SCAN_CHURNED => AbandonReason::Churned,
                _ => AbandonReason::StaleRepaired,
            };
            // Candidate tids: tids with an admitting CALL in this
            // batch that hint-tainted a predecessor (the take that
            // witnessed the churn/evict), or — for RETIRE_FAIL —
            // tids whose open invocation has a joined RET.
            // Attribute to open invocations showing the matching
            // distress signature: Churned/Evicted/StaleRepaired
            // strike opens whose record is gone (a later hinted
            // take just tainted them — the take witnessed the
            // disturbance); RetireFailed strikes a RET-joined
            // open. Since the counters are global, attribute iff
            // EXACTLY ONE candidate tid exists in this batch.
            let mut tid_cands: BTreeSet<u32> = BTreeSet::new();
            for c in &b.calls {
                let (hint, cause) = wire::split_call_flags(c.flags);
                if cause != wire::SKIP_ADMITTED {
                    continue;
                }
                let has_open_pred = self.done.iter().any(|w| {
                    w.tid == c.tid
                        && matches!(w.outcome, Outcome::Tainted { by_seq } if by_seq == c.seq)
                });
                if hint && has_open_pred {
                    tid_cands.insert(c.tid);
                }
            }
            if id == wire::LOSS_RETIRE_FAIL {
                for ((t, _), o) in self.open.iter() {
                    if o.ret.is_some() {
                        tid_cands.insert(*t);
                    }
                }
            }
            if tid_cands.len() == 1 && delta == 1 {
                let t = *tid_cands.iter().next().unwrap();
                // Convert the tainted record (or stall the
                // RET-joined open) into the attributed abandon.
                if id == wire::LOSS_RETIRE_FAIL {
                    let key = self
                        .open
                        .iter()
                        .filter(|((tt, _), o)| *tt == t && o.ret.is_some())
                        .map(|(k, _)| *k)
                        .next();
                    if let Some(k) = key {
                        let o = self.open.remove(&k).expect("retire-fail open");
                        self.done.push(WalkDone {
                            tid: k.0,
                            seq: k.1,
                            op: o.call.op,
                            outcome: Outcome::Abandoned { reason },
                            true_t: TrueT::Unknown,
                            alg_count: o.algs.len(),
                            row_count: o.rows as usize,
                            guard: o.guard,
                        });
                        continue;
                    }
                } else if let Some(w) = self
                    .done
                    .iter_mut()
                    .rev()
                    .find(|w| w.tid == t && matches!(w.outcome, Outcome::Tainted { .. }))
                {
                    w.outcome = Outcome::Abandoned { reason };
                    continue;
                }
                self.findings.push(Finding::UnattributedLoss { id, delta });
            } else {
                self.findings.push(Finding::UnattributedLoss { id, delta });
            }
        }

        // 4. Closure (R6): for each open with a joined RET, ring
        // order per tid decides (later activity = any CALL on the
        // tid positioned after this CALL — same batch: higher
        // pos; earlier batches: any CALL in a later batch).
        let mut closable: Vec<(u32, u64)> = Vec::new();
        let mut stallable: Vec<(u32, u64)> = Vec::new();
        let mut stalled_quiet: Vec<(u32, u64)> = Vec::new();
        for ((t, s), o) in self.open.iter() {
            if o.ret.is_none() {
                continue;
            }
            // Later activity on t: (a) CALLs in later batches,
            // (b) CALLs later in this batch (pos > o.pos for
            // same-batch opens).
            let mut later: Vec<&wire::ScanCallEvent> = Vec::new();
            for (idx, c) in b.calls.iter().enumerate() {
                if c.tid != *t {
                    continue;
                }
                if o.batch == batch {
                    // Same batch: positional (ring order).
                    if idx > o.pos {
                        later.push(c);
                    }
                } else {
                    // Earlier batch open: every CALL in this
                    // batch is later activity.
                    later.push(c);
                }
            }
            if later.is_empty() {
                if !b.quiesced {
                    continue; // honestly open
                }
                match b.rcount.get(t) {
                    Some((_, st)) if *st == wire::RCOUNT_STATE_IDLE => closable.push((*t, *s)),
                    Some((_, st)) if *st == wire::RCOUNT_STATE_ACTIVE => {
                        stallable.push((*t, *s));
                    }
                    _ => closable.push((*t, *s)), // no record + quiesced ⟹ retired
                }
                continue;
            }
            // First later activity decides.
            let first = later[0];
            let (hint, cause) = wire::split_call_flags(first.flags);
            if cause != wire::SKIP_ADMITTED {
                continue; // skips are evidence-free for RET-joined opens
            }
            if hint {
                continue; // taint path already closed the predecessor (R3)
            }
            // Quiet successor: retired ⟹ close... unless the open
            // was stall-flagged (the detach-stall ambiguity: a
            // stall + skip + quiet-successor must abandon, never
            // misclose as retired).
            if o.stalled {
                stalled_quiet.push((*t, *s));
            } else {
                closable.push((*t, *s));
            }
        }
        for k in stallable {
            if let Some(o) = self.open.get_mut(&k) {
                if !o.stalled {
                    o.stalled = true;
                    self.findings.push(Finding::Stall { tid: k.0, seq: k.1 });
                }
            }
        }
        for k in stalled_quiet {
            if let Some(o) = self.open.remove(&k) {
                self.done.push(WalkDone {
                    tid: k.0,
                    seq: k.1,
                    op: o.call.op,
                    outcome: Outcome::Abandoned {
                        reason: AbandonReason::Stalled,
                    },
                    true_t: TrueT::Unknown,
                    alg_count: o.algs.len(),
                    row_count: o.rows as usize,
                    guard: o.guard,
                });
            }
        }
        for k in closable {
            if let Some(o) = self.open.remove(&k) {
                let w = self.evaluate(&scope, &k, &o, b);
                self.done.push(w);
            }
        }
    }

    /// Evaluate a retired-proven invocation (R1/R2/R5).
    fn evaluate(&self, scope: &OracleScope, key: &(u32, u64), o: &Open, b: &ScanBatch) -> WalkDone {
        let ret = o.ret.expect("RET joined");
        let mut reasons: Vec<PartialReason> = Vec::new();

        // RET EMPTY: no array — complete-empty, no coverage needed.
        if ret.flags & wire::RET_FLAG_EMPTY != 0 {
            return WalkDone {
                tid: key.0,
                seq: key.1,
                op: o.call.op,
                outcome: Outcome::Complete {
                    true_t: 0,
                    cached: false,
                },
                true_t: TrueT::EmptyTable,
                alg_count: o.algs.len(),
                row_count: o.rows as usize,
                guard: o.guard,
            };
        }

        // Warm belief: the RET carries the invocation's array
        // id + generation directly (no ALG inference needed).
        let warm: Option<(u64, u64)> = scope
            .known_t
            .get(&ret.arr)
            .copied()
            .filter(|(_, g)| *g == ret.generation);

        // Coverage over attached slots. Members read by INDEX
        // (not sequentially), so coverage beyond the first
        // absence CONTRADICTS the terminator — the absence is a
        // hole (sparse table, lost record, or cookie-mismatch),
        // never silently the end.
        let attached: Vec<u64> = scope.attached.iter().map(|j| *j as u64).collect();
        let max_cov: Option<u64> = o
            .algs
            .keys()
            .filter(|j| scope.attached.contains(&(**j as u32)))
            .max()
            .copied();
        // First attached absence (scope-confined: unattached
        // slots are unobserved, never evidence). None ⟹ every
        // attached slot covered — termination is then proven
        // only at the full-scope edge (512, capped); a
        // selective edge leaves TRUE-T a Candidate (the
        // terminator sits beyond the observed window).
        let missing: Option<u64> = attached.iter().copied().find(|j| !o.algs.contains_key(j));
        let edge: u64 = attached.iter().max().map(|m| m + 1).unwrap_or(0);
        let first_abs = missing.unwrap_or(edge);
        let covered_beyond = match (missing, max_cov) {
            (Some(f), Some(m)) => m >= f,
            _ => false,
        };
        let walked_beyond = match (warm, max_cov) {
            (Some((tw, _)), Some(m)) => m > tw,
            _ => false,
        };
        // Coverage obligation: the warm window plus the
        // evidenced range. Members > tw T-skip silent by
        // design — but once coverage exists beyond tw (stale
        // belief), silence inside the evidenced range is a
        // hole (skipped-by-stale-belief vs walked-empty is
        // ambiguous ⟹ conservative hole).
        let t_limit: u64 = match (warm, max_cov) {
            (Some((tw, _)), Some(m)) => (tw + 1).max(m + 1),
            (Some((tw, _)), None) => tw + 1,
            (None, Some(m)) => m + 1,
            (None, None) => 512,
        };
        // TRUE-T: the warm belief stands (Proven) iff nothing
        // contradicts it — any window hole could hide a shrunk
        // table (loss-silence vs empty-silence is
        // indistinguishable) and any walk beyond tw proves
        // staleness. Cold: the first absence is the terminator
        // iff nothing is covered beyond it.
        let true_t = match warm {
            Some((tw, _)) if !walked_beyond && !covered_beyond => {
                // Window holes still demote (a hole could hide
                // a shrunk table — loss-silence vs empty-silence
                // is indistinguishable).
                let window_hole = (0..=tw)
                    .any(|j| scope.attached.contains(&(j as u32)) && !o.algs.contains_key(&j));
                if window_hole {
                    TrueT::Candidate(first_abs)
                } else {
                    TrueT::Proven(tw)
                }
            }
            Some(_) => TrueT::Candidate(first_abs),
            None if max_cov.is_none() => TrueT::Unknown,
            // Cold: the first attached absence is the
            // terminator iff nothing is covered beyond it; a
            // fully-covered selective scope proves the window,
            // not the terminator (Candidate at the edge).
            None if !covered_beyond && missing.is_some() => TrueT::Proven(first_abs),
            None if !covered_beyond && edge == 512 => TrueT::Proven(512),
            None => TrueT::Candidate(first_abs),
        };

        // Holes: attached slots < t_limit without ALG.
        let holes: Vec<u64> = attached
            .iter()
            .copied()
            .filter(|j| *j < t_limit && !o.algs.contains_key(j))
            .collect();
        if !holes.is_empty() {
            reasons.push(PartialReason::Holes(holes));
        }
        // UNREADABLE: explicit unknowns.
        let unread: Vec<u64> = o
            .algs
            .values()
            .filter(|a| a.status == wire::ALG_UNREADABLE && a.idx < t_limit)
            .map(|a| a.idx)
            .collect();
        if !unread.is_empty() {
            reasons.push(PartialReason::Unreadable(unread));
        }
        // TRUNC bits for the invocation's op: structural bits
        // (records/classifications missing) ⟹ PARTIAL;
        // WALK_EMPTY/WALK_NOIMP/NO_STORE are stable walk
        // observations (Complete-compatible).
        let trunc = b.trunc.get(&o.call.op).copied().unwrap_or(0);
        let structural = trunc
            & (wire::TRUNC_ALGS
                | wire::TRUNC_DISPATCH
                | wire::TRUNC_WALK_READ
                | wire::TRUNC_WALK_NAME);
        if structural != 0 {
            reasons.push(PartialReason::Trunc(structural));
        }
        // Guard disposition: VALID reads slot 512 live
        // (513-live contract violation — the table extends
        // beyond observation ⟹ TRUE-T demotes to the capped
        // Candidate, never Proven); ERROR is a tail-read
        // abort (PARTIAL, TRUE-T stands); EMPTY corroborates
        // full (no-op).
        let mut true_t = true_t;
        if let Some(g) = o.guard {
            if g.verdict == wire::GUARD_ERROR {
                reasons.push(PartialReason::GuardError);
            } else if g.verdict == wire::GUARD_VALID {
                true_t = TrueT::Candidate(512);
                reasons.push(PartialReason::Overfull);
            }
        }
        // Drain-loss corroboration: ring-loss deltas in this
        // batch with holes/orphans present → the loss explains
        // the gaps (else the loss is a surprise — finding).
        let ring_loss: u64 = [
            wire::LOSS_RING_CALL,
            wire::LOSS_RING_RET,
            wire::LOSS_RING_GUARD,
            wire::LOSS_RING_ALG,
            wire::LOSS_RING_ROW,
        ]
        .iter()
        .map(|id| b.loss.get(id).copied().unwrap_or(0))
        .sum();
        let gaps = reasons.iter().any(|r| {
            matches!(
                r,
                PartialReason::Holes(_) | PartialReason::Unreadable(_) | PartialReason::Trunc(_)
            )
        });
        let orphans = self.findings.iter().any(|f| {
            matches!(
                f,
                Finding::OrphanRet { .. }
                    | Finding::OrphanGuard { .. }
                    | Finding::OrphanAlg { .. }
                    | Finding::OrphanRow { .. }
            )
        });
        if ring_loss > 0 {
            if gaps || orphans {
                reasons.push(PartialReason::DrainLoss);
            } else {
                // Surprise loss (no gaps to explain it) — fail
                // loud, but do not taint an otherwise complete
                // verdict with an unattributable delta... except
                // the loss DID eat a record addressed to someone:
                // conservatively partial.
                reasons.push(PartialReason::DrainLoss);
            }
        }

        let outcome = if reasons.is_empty() {
            let t = match true_t {
                TrueT::Proven(t) | TrueT::Candidate(t) => t,
                TrueT::EmptyTable | TrueT::Unknown => 0,
            };
            Outcome::Complete {
                true_t: t,
                cached: warm.is_some(),
            }
        } else {
            Outcome::Partial { reasons }
        };
        WalkDone {
            tid: key.0,
            seq: key.1,
            op: o.call.op,
            outcome,
            true_t,
            alg_count: o.algs.len(),
            row_count: o.rows as usize,
            guard: o.guard,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TID: u32 = 4242;
    const ARR: u64 = 0x7000;

    fn call(seq: u64, hint: bool, cause: u8) -> wire::ScanCallEvent {
        wire::ScanCallEvent {
            kind: wire::KIND_SCAN_CALL,
            op: 7,
            tid: TID,
            flags: wire::make_call_flags(hint, cause),
            seq,
        }
    }

    fn ret(seq: u64, generation: u64, empty: bool) -> wire::ScanRetEvent {
        wire::ScanRetEvent {
            kind: wire::KIND_SCAN_RET,
            op: 7,
            flags: if empty { wire::RET_FLAG_EMPTY } else { 0 },
            tid: TID,
            seq,
            arr: ARR,
            generation,
        }
    }

    fn alg(seq: u64, idx: u64, status: u8) -> wire::ScanAlgEvent {
        wire::ScanAlgEvent {
            kind: wire::KIND_SCAN_ALG,
            op: 7,
            class: 1,
            status,
            weak: 0,
            _pad: 0,
            arr: ARR,
            idx,
            generation: 0,
            tid: TID,
            _pad2: 0,
            seq,
        }
    }

    fn idle_batch() -> ScanBatch {
        let mut b = ScanBatch {
            quiesced: true,
            ..ScanBatch::default()
        };
        b.rcount.insert(TID, (0, wire::RCOUNT_STATE_IDLE));
        b.seq.insert(TID, (1, 0));
        b
    }

    #[test]
    fn oracle_cold_complete_proven() {
        // Cold, 3-live table: ALGs 0..2, silence beyond ⟹
        // Proven(3), Complete.
        let mut o = Oracle::new(OracleScope::full());
        let mut b = idle_batch();
        b.calls.push(call(0, false, wire::SKIP_ADMITTED));
        b.rets.push(ret(0, 0, false));
        for j in 0..3 {
            b.algs.push(alg(0, j, wire::ALG_OK));
        }
        o.ingest(&b);
        assert_eq!(o.done.len(), 1);
        let w = &o.done[0];
        assert_eq!(w.true_t, TrueT::Proven(3));
        assert!(matches!(
            w.outcome,
            Outcome::Complete {
                true_t: 3,
                cached: false,
                ..
            }
        ));
        assert!(o.findings.is_empty());
    }

    #[test]
    fn oracle_empty_table() {
        let mut o = Oracle::new(OracleScope::full());
        let mut b = idle_batch();
        b.calls.push(call(0, false, wire::SKIP_ADMITTED));
        b.rets.push(ret(0, 0, true));
        o.ingest(&b);
        assert_eq!(o.done.len(), 1);
        assert_eq!(o.done[0].true_t, TrueT::EmptyTable);
        assert!(matches!(o.done[0].outcome, Outcome::Complete { .. }));
    }

    #[test]
    fn oracle_hole_is_partial() {
        let mut o = Oracle::new(OracleScope::full());
        let mut b = idle_batch();
        b.calls.push(call(0, false, wire::SKIP_ADMITTED));
        b.rets.push(ret(0, 0, false));
        b.algs.push(alg(0, 0, wire::ALG_OK));
        b.algs.push(alg(0, 2, wire::ALG_OK)); // 1 missing
        o.ingest(&b);
        assert_eq!(o.done.len(), 1);
        // Cold: coverage at 2 contradicts the terminator-at-1,
        // so slot 1 is a hole (PARTIAL) and TRUE-T demotes to
        // Candidate(1) — the table extends, exact T unknown.
        assert_eq!(o.done[0].true_t, TrueT::Candidate(1));
        assert!(matches!(o.done[0].outcome, Outcome::Partial { .. }));
    }

    #[test]
    fn oracle_taint_and_skip_victim() {
        let mut o = Oracle::new(OracleScope::full());
        // Batch 1: admitted, no RET yet (still open).
        let mut b1 = ScanBatch {
            quiesced: false,
            ..ScanBatch::default()
        };
        b1.calls.push(call(0, false, wire::SKIP_ADMITTED));
        o.ingest(&b1);
        assert_eq!(o.open_count(), 1);
        // Batch 2: nested admitted take with hint taints seq 0.
        let mut b2 = ScanBatch {
            quiesced: false,
            ..ScanBatch::default()
        };
        b2.calls.push(call(1, true, wire::SKIP_ADMITTED));
        o.ingest(&b2);
        assert!(matches!(o.done[0].outcome, Outcome::Tainted { by_seq: 1 }));
        // Batch 3: skip over the RET-less seq 1 ⟹ abandoned.
        // (The skip CALL records first; the abandon is its
        // consequence.)
        let mut b3 = idle_batch();
        b3.calls.push(call(0, false, wire::SKIP_RING_PRESSURE));
        o.ingest(&b3);
        assert!(matches!(o.done[1].outcome, Outcome::Skipped { .. }));
        assert!(matches!(
            o.done[2].outcome,
            Outcome::Abandoned {
                reason: AbandonReason::SkipVictim
            }
        ));
    }

    #[test]
    fn oracle_selective_scope() {
        // Attached {0,1,2,3} only: absence beyond 3 is
        // unobserved (never holes). Cold + fully-covered
        // window ⟹ Complete, but TRUE-T is Candidate(4) — the
        // scope proves the window, not the terminator.
        let mut scope = OracleScope::full();
        scope.attached = (0..4).collect();
        scope.expected = 4;
        let mut o = Oracle::new(scope);
        let mut b = idle_batch();
        b.calls.push(call(0, false, wire::SKIP_ADMITTED));
        b.rets.push(ret(0, 0, false));
        for j in 0..4 {
            b.algs.push(alg(0, j, wire::ALG_OK));
        }
        o.ingest(&b);
        assert_eq!(o.done.len(), 1);
        assert_eq!(o.done[0].true_t, TrueT::Candidate(4));
        assert!(matches!(o.done[0].outcome, Outcome::Complete { .. }));
    }

    #[test]
    fn oracle_selective_terminator_inside() {
        // Selective scope CAN prove termination when the
        // terminator lands inside the window: attached
        // {0,1,2,3}, slot 3 silent ⟹ Proven(3).
        let mut scope = OracleScope::full();
        scope.attached = (0..4).collect();
        scope.expected = 4;
        let mut o = Oracle::new(scope);
        let mut b = idle_batch();
        b.calls.push(call(0, false, wire::SKIP_ADMITTED));
        b.rets.push(ret(0, 0, false));
        for j in 0..3 {
            b.algs.push(alg(0, j, wire::ALG_OK));
        }
        o.ingest(&b);
        assert_eq!(o.done.len(), 1);
        assert_eq!(o.done[0].true_t, TrueT::Proven(3));
        assert!(matches!(o.done[0].outcome, Outcome::Complete { .. }));
    }

    #[test]
    fn oracle_warm_proven() {
        let mut scope = OracleScope::full();
        scope.known_t.insert(ARR, (9, 5));
        let mut o = Oracle::new(scope);
        let mut b = idle_batch();
        b.calls.push(call(3, false, wire::SKIP_ADMITTED));
        b.rets.push(ret(3, 5, false));
        for j in 0..10 {
            b.algs.push(alg(3, j, wire::ALG_OK));
        }
        o.ingest(&b);
        assert_eq!(o.done.len(), 1);
        assert_eq!(o.done[0].true_t, TrueT::Proven(9));
        assert!(matches!(
            o.done[0].outcome,
            Outcome::Complete {
                true_t: 9,
                cached: true,
                ..
            }
        ));
    }

    #[test]
    fn oracle_quiet_successor_closes() {
        // Non-quiesced batches: the open stays open until a
        // quiet successor arrives (cross-batch R6).
        let mut o = Oracle::new(OracleScope::full());
        let mut b1 = ScanBatch {
            quiesced: false,
            ..ScanBatch::default()
        };
        b1.calls.push(call(0, false, wire::SKIP_ADMITTED));
        b1.rets.push(ret(0, 0, false));
        b1.algs.push(alg(0, 0, wire::ALG_OK));
        o.ingest(&b1);
        assert_eq!(o.open_count(), 1);
        let mut b2 = ScanBatch {
            quiesced: false,
            ..ScanBatch::default()
        };
        b2.calls.push(call(1, false, wire::SKIP_ADMITTED));
        o.ingest(&b2);
        assert_eq!(o.done.len(), 1);
        assert_eq!(o.done[0].seq, 0);
        assert!(matches!(o.done[0].outcome, Outcome::Complete { .. }));
        assert_eq!(o.open_count(), 1); // seq 1 still open
    }

    #[test]
    fn oracle_orphan_and_double_ret() {
        let mut o = Oracle::new(OracleScope::full());
        let mut b = idle_batch();
        b.rets.push(ret(9, 0, false)); // no CALL ⟹ orphan
        b.calls.push(call(0, false, wire::SKIP_ADMITTED));
        b.rets.push(ret(0, 0, false));
        b.rets.push(ret(0, 0, false)); // double
        o.ingest(&b);
        assert!(
            o.findings
                .contains(&Finding::OrphanRet { tid: TID, seq: 9 })
        );
        assert!(
            o.findings
                .contains(&Finding::DoubleRet { tid: TID, seq: 0 })
        );
    }

    #[test]
    fn oracle_stall_flagged() {
        // Quiesced + RET + ACTIVE + no successor ⟹ stalled
        // (finding, stays open).
        let mut o = Oracle::new(OracleScope::full());
        let mut b = ScanBatch {
            quiesced: true,
            ..ScanBatch::default()
        };
        b.rcount.insert(TID, (7, wire::RCOUNT_STATE_ACTIVE));
        b.calls.push(call(0, false, wire::SKIP_ADMITTED));
        b.rets.push(ret(0, 0, false));
        o.ingest(&b);
        assert_eq!(o.open_count(), 1);
        assert!(o.findings.contains(&Finding::Stall { tid: TID, seq: 0 }));
        // A later quiet successor abandons (never miscloses).
        let mut b2 = ScanBatch {
            quiesced: false,
            ..ScanBatch::default()
        };
        b2.calls.push(call(1, false, wire::SKIP_ADMITTED));
        o.ingest(&b2);
        assert!(matches!(
            o.done[0].outcome,
            Outcome::Abandoned {
                reason: AbandonReason::Stalled
            }
        ));
    }

    #[test]
    fn oracle_drain_stats() {
        let mut o = Oracle::new(OracleScope::full());
        let mut b = idle_batch();
        b.calls.push(call(0, false, wire::SKIP_ADMITTED));
        b.rets.push(ret(0, 0, false));
        o.ingest(&b);
        let s = o.stats();
        assert_eq!(s.batches, 1);
        assert_eq!(s.records, 2);
        assert_eq!(s.bytes, ONRING_CALL + ONRING_RET);
    }
}
