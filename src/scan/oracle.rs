//! SPDX-License-Identifier: GPL-3.0-or-later
//! Per-invocation join oracle (P7 item 4 core): joins the
//! scan-plane ring (CALL/RET/GUARD/SCAN-ALG/SCAN-ROW) by (tid,seq)
//! with per-drain cell snapshots (RCOUNT/SEQ) and counter deltas,
//! and emits one WALK-DONE host record per invocation plus
//! explicit findings.
//!
//! Completion evidence is per-slot and explicit: every
//! successfully-read member slot emits exactly one SCAN-ALG
//! read-status record (classifier verdict, EMPTY, NOIMP, or
//! UNREADABLE). Silence proves nothing — only tuple-read aborts
//! stay silent (flagged), and a missing record is a hole until
//! proven otherwise. WALK-DONE is the oracle's output row,
//! computed here by joining those records.
//!
//! Soundness rules (implementable §5.2/§5.3 subset — each named):
//!
//! - JOIN (R0): every RET/GUARD/ALG/ROW joins to exactly one
//!   admitted CALL by (tid,seq) in drain order; orphans are
//!   explicit findings, never silently absorbed. Second records
//!   for one slot/key are kept-first + explicit findings (never
//!   overwrite).
//! - COMPLETE (R1): admitted + RET joined + retired-proven +
//!   every attached slot below TRUE-T covered with a known
//!   status + explicit terminator (min-EMPTY, or GUARD EMPTY at
//!   512) + no failed chunks + guard disposition consistent +
//!   no retained TRUNC except beyond-terminator WALK_NAME noise
//!   (ALGS/DISPATCH/NO_STORE/WALK_READ ⟹ PARTIAL — a dispatch
//!   read failure hides behind a readable ALG prefix, so
//!   WALK_READ is indistinguishable from past-terminator tuple
//!   noise and retained fail-closed; WALK_NAME explains prefix
//!   gaps, else it is discarded with its reads). TRUNC
//!   WALK_EMPTY/WALK_NOIMP are stable walk observations
//!   (Complete-compatible). COMPLETE requires Proven —
//!   Candidate/Unknown never completes.
//! - TRUE-T (R2): min-EMPTY over explicit records (beyond-T
//!   observations are meaningless and discarded); no EMPTY in a
//!   fully-covered full scope ⟹ the guard decides (EMPTY ⟹
//!   Proven(512), VALID ⟹ Candidate(512) + Overfull, ERROR ⟹
//!   Partial, missing ⟹ Candidate(512) + GuardMissing); RET
//!   EMPTY → EmptyTable. Warm beliefs stand only uncontradicted:
//!   fresh EMPTY below T ⟹ shrink (Proven(new) + CacheShrink);
//!   positive walked evidence beyond T without a terminator ⟹
//!   stale (Candidate(lowest-consistent) + CacheStale); a
//!   walked-but-unproven terminator slot with nothing beyond ⟹
//!   stale (Candidate(cached) + CacheStale — the cached T cannot
//!   stand without its proof); generation turnover ⟹ cold rules
//!   + GenStale.
//! - TAINT (R3): the nesting rule-set (multi-array per key,
//!   duplicate slot) taints BOTH invocations stickily, keeps the
//!   slots (first record wins — array+idx are
//!   rv/positional-trustworthy), forces op UNKNOWN, and raises
//!   Nested findings. A kernel hint alone never taints (hint +
//!   rule-hit = nested certain; hint alone = stale-retire race,
//!   ignored when the evidence closes clean).
//! - ABANDON (R4): a skip over an open RET-less invocation
//!   abandons it (record deleted, RET never coming); a RET-less
//!   open past 5s abandons as Hung (sticky policy, cascades to
//!   same-tid RET-less outers; a late RET joins as LATE with the
//!   verdict standing); LOSS 20/21/25/31 deltas attribute to the
//!   single candidate tid or raise an explicit
//!   unattributed-loss finding. Ring loss with no evaluable
//!   invocation is a window finding.
//! - PARTIAL (R5): holes, UNREADABLE, unobserved selective slots,
//!   TRUNC, guard ERROR/VALID/missing, cache contradictions,
//!   generation mismatch, retained drain loss, and raced TRUNC
//!   drains stay explicit (missing or failed chunks and drain
//!   loss are PARTIAL, never silent). Loss/TRUNC history is
//!   retained per open across drains and evaluated over the full
//!   invocation, not the closing batch.
//! - RETIRE (R6): retired-proven ⟺ RET joined AND (a successor
//!   quiet-admit on the tid, OR no later admitted activity +
//!   quiesced + IDLE cells, OR the window-edge backstop). Later
//!   skips never block evaluation (cut-off members surface as
//!   holes).
//!
//!   Quiesced ACTIVE + RET + no successor activity ⟹ STALLED
//!   (finding; a later quiet-admit abandons, never miscloses as
//!   retired — the detach-stall ambiguity resolved).
//!
//! Per-tid ring order is causal (one thread ⟹ sequential entry
//! hits), so drain order within a tid is the join order — the
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
//! grows vs §5.6's 2.875). Explicit EMPTY/NOIMP records ride the
//! already-budgeted 512 ALG slots (every cold slot emits exactly
//! one ALG), so the worst case is unchanged.

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

/// Forced op on tainted invocations (nesting rule-set: slots are
/// kept — array+idx are rv/positional-trustworthy — but the op is
/// unknowable once two invocations' evidence mixed).
pub const UNKNOWN_OP: u32 = u32::MAX;

/// Hung-scan abandonment age (accepted 5s sticky policy).
pub const HUNG_NS: u64 = 5_000_000_000;

/// 16MiB criterion re-verified (R18 decision 15): two worst scans
/// admitted at the 4MiB governor line still fit.
const _: () = assert!(WORST_SCAN_BYTES == 4_751_488);
const _: () = assert!(
    2 * WORST_SCAN_BYTES + wire::GOVERNOR_MAX_OCCUPIED <= 16 << 20,
    "16MiB ring holds the two-way tick race"
);

/// Position of one ring record inside a [`ScanBatch`]: the drain
/// order across kinds (CALLs/RETs/ALGs interleave on the ring;
/// per-kind vecs alone lose that causality). `push_*` maintains
/// this; the oracle joins in drain order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchPos {
    Call(usize),
    Ret(usize),
    Guard(usize),
    Alg(usize),
    Row(usize),
}

/// Per-drain batch: decoded ring events (ring order preserved in
/// [`ScanBatch::order`]) + counter deltas + cell snapshot + oracle
/// scope. The backend samples cells once per drain; legs and tests
/// construct batches directly via `push_*` (which records the
/// drain order) or via explicit vec pushes (legacy: kind-grouped
/// order — only sound for single-key batches).
#[derive(Debug, Default)]
pub struct ScanBatch {
    pub calls: Vec<wire::ScanCallEvent>,
    pub rets: Vec<wire::ScanRetEvent>,
    pub guards: Vec<wire::GuardEvent>,
    pub algs: Vec<wire::ScanAlgEvent>,
    pub rows: Vec<wire::ScanRowEvent>,
    /// Drain order across the five vecs (parallel to the pushes).
    /// Empty ⟺ legacy kind-grouped processing (CALLs, RETs,
    /// GUARDs, ALGs, ROWs) — kept only so pre-causal fixtures
    /// still parse; production and all migrated fixtures fill it.
    pub order: Vec<BatchPos>,
    /// Batch time in ns since the backend epoch (hung-scan
    /// abandonment compares open age against it; 0 in timeless
    /// fixtures ⟹ no aging).
    pub now_ns: u64,
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
    /// The TRUNC drain raced a concurrent flag (the backend's
    /// generation guard advanced across the clear window, so a
    /// flag may have been erased unread) — every open this batch
    /// spanned degrades explicitly.
    pub trunc_race: bool,
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

impl ScanBatch {
    /// Ring-order completeness: every record appears in `order`
    /// exactly once (production invariant; fixtures assert it).
    pub fn order_sound(&self) -> bool {
        let total = self.calls.len()
            + self.rets.len()
            + self.guards.len()
            + self.algs.len()
            + self.rows.len();
        if self.order.len() != total {
            return false;
        }
        let mut seen_c = vec![false; self.calls.len()];
        let mut seen_r = vec![false; self.rets.len()];
        let mut seen_g = vec![false; self.guards.len()];
        let mut seen_a = vec![false; self.algs.len()];
        let mut seen_w = vec![false; self.rows.len()];
        for p in &self.order {
            let slot = match *p {
                BatchPos::Call(i) => seen_c.get_mut(i),
                BatchPos::Ret(i) => seen_r.get_mut(i),
                BatchPos::Guard(i) => seen_g.get_mut(i),
                BatchPos::Alg(i) => seen_a.get_mut(i),
                BatchPos::Row(i) => seen_w.get_mut(i),
            };
            match slot {
                Some(false) => *slot.unwrap() = true,
                _ => return false,
            }
        }
        true
    }

    pub fn push_call(&mut self, e: wire::ScanCallEvent) {
        self.calls.push(e);
        self.order.push(BatchPos::Call(self.calls.len() - 1));
    }

    pub fn push_ret(&mut self, e: wire::ScanRetEvent) {
        self.rets.push(e);
        self.order.push(BatchPos::Ret(self.rets.len() - 1));
    }

    pub fn push_guard(&mut self, e: wire::GuardEvent) {
        self.guards.push(e);
        self.order.push(BatchPos::Guard(self.guards.len() - 1));
    }

    pub fn push_alg(&mut self, e: wire::ScanAlgEvent) {
        self.algs.push(e);
        self.order.push(BatchPos::Alg(self.algs.len() - 1));
    }

    pub fn push_row(&mut self, e: wire::ScanRowEvent) {
        self.rows.push(e);
        self.order.push(BatchPos::Row(self.rows.len() - 1));
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
    /// Selective scope: slots below the evidenced terminator were
    /// never attached, so the prefix is unprovable (missing chunks
    /// stay explicit PARTIAL, never silent).
    UnobservedSlots(Vec<u64>),
    /// Full 512-slot coverage without the GUARD EMPTY clean-full
    /// proof (the guard is the 512-terminator evidence).
    GuardMissing,
    /// Warm belief contradicted by a fresh terminator below the
    /// cached T (shrunk table): the cache is updated to the
    /// observed terminator, this verdict stays partial.
    CacheShrink {
        cached: u64,
        observed: u64,
    },
    /// Warm belief contradicted by walked evidence beyond the
    /// cached T (grown table): the cache is invalidated (cold
    /// re-probe), this verdict stays partial.
    CacheStale {
        cached: u64,
    },
    /// The invocation's generation no longer matches the cached
    /// one (provider turnover): the cache row is invalidated.
    GenStale {
        expected: u64,
        observed: u64,
    },
    /// Slot evidence generations disagree with the RET generation
    /// (cross-epoch join — inconsistent evidence).
    GenMixed,
    /// Window closed with no RET joined (dangling call —
    /// retained for taxonomy stability; the backstop taints both
    /// correlated sequences instead of emitting this).
    DanglingCall,
    /// Defensive: a Candidate/Unknown TRUE-T reached the verdict
    /// with no other reason (unreachable by construction — every
    /// unproven-terminator path names its reason; fail-closed).
    TerminatorUnproven,
    /// The TRUNC drain raced a concurrent producer flag (a flag
    /// may have been erased unread — fail-closed PARTIAL).
    TruncDrainRace,
    /// A dispatch row carried a foreign array id (evidence
    /// inconsistent with the joined RET's array).
    RowArrayMismatch,
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
    /// Tier-3 storm detach cut observation mid-flight (the
    /// capture layer reports PARTIAL+STORM).
    Detached,
    /// Pre-window open fenced at the window edge (baseline
    /// discipline: a setup-slice CALL never joins an
    /// in-window return).
    PreWindow,
    /// No RET within 5s of the CALL (presumed-hung sticky
    /// policy — scheduling can exceed any timeout, so this is a
    /// policy verdict, not proof of non-return; a late RET joins
    /// as LATE with the verdict standing).
    Hung,
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
    /// Invocation array id (from the RET; 0 when no RET joined).
    pub arr: u64,
    pub outcome: Outcome,
    pub true_t: TrueT,
    pub alg_count: usize,
    pub row_count: usize,
    pub guard: Option<wire::GuardEvent>,
    /// Joined slot identities, idx order (Complete, Partial, and
    /// Tainted records retain them; Skipped/Abandoned/Empty carry
    /// what joined, possibly none).
    pub algs: Vec<AlgIdentity>,
    /// CALL-time in the backend clock domain (the capture passes
    /// its monotonic base at attach, so this is capture-ns in
    /// production — the inventory adaptation's event instant).
    pub event_ns: u64,
    /// Retained dispatch rows (array/generation/callback data —
    /// consistency-checked at close; rides the record for
    /// callback relocation and inventory adaptation).
    pub rows: Vec<wire::ScanRowEvent>,
}

/// One joined slot identity (the per-slot evidence a WALK-DONE
/// retains for inventory adaptation — class + read status, not
/// the full ring record).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlgIdentity {
    pub idx: u64,
    pub class: u16,
    pub status: u8,
    pub weak: u8,
}

/// Joined slot identities of an open, in idx order.
fn open_identities(o: &Open) -> Vec<AlgIdentity> {
    o.algs
        .iter()
        .map(|(idx, a)| AlgIdentity {
            idx: *idx,
            class: a.class,
            status: a.status,
            weak: a.weak,
        })
        .collect()
}

/// Oracle finding (join-correctness and accounting — explicit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    OrphanRet {
        tid: u32,
        seq: u64,
    },
    OrphanGuard {
        tid: u32,
        seq: u64,
    },
    OrphanAlg {
        tid: u32,
        seq: u64,
        idx: u64,
    },
    OrphanRow {
        tid: u32,
        seq: u64,
        idx: u64,
    },
    DoubleRet {
        tid: u32,
        seq: u64,
    },
    DoubleGuard {
        tid: u32,
        seq: u64,
    },
    UnattributedLoss {
        id: u32,
        delta: u64,
    },
    Stall {
        tid: u32,
        seq: u64,
    },
    /// Ring loss with no evaluable invocation (no opens, no closes
    /// in the drain — a window-level finding, never dropped).
    WindowLoss {
        delta: u64,
    },
    /// A RET for a hung-abandoned invocation (recovery evidence:
    /// the array is noted, the abandon verdict stands).
    LateRet {
        tid: u32,
        seq: u64,
        arr: u64,
    },
    /// A nesting rule fired (multi-array / duplicate-slot): both
    /// invocations tainted, slots kept (first record wins).
    Nested {
        tid: u32,
        seq: u64,
        by_seq: u64,
    },
    /// Second ALG for an already-covered slot (same-record
    /// overwrite — the first record is kept).
    DuplicateSlot {
        tid: u32,
        seq: u64,
        idx: u64,
    },
    /// ROW for a slot whose ALG is not a walked classifier verdict
    /// (EMPTY/NOIMP/UNREADABLE slots emit no rows).
    StrayRow {
        tid: u32,
        seq: u64,
        idx: u64,
    },
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
    /// Row indexes (multiset size = rows): consistency-checked at
    /// close (rows for non-walked slots are stray findings).
    row_idxs: Vec<u64>,
    /// Retained row records (array/generation/callback data —
    /// consistency-checked at close, then rides the WALK-DONE).
    row_events: Vec<wire::ScanRowEvent>,
    /// Position of the CALL in its batch (ring order = causal
    /// order per tid — used for later-activity checks within a
    /// batch; cross-batch order is batch order).
    batch: u64,
    pos: usize,
    stalled: bool,
    /// First-seen batch time (hung-scan age baseline).
    first_seen_ns: u64,
    /// Accumulated TRUNC bits for the invocation's op over every
    /// drain the open spanned (retained history — the closing
    /// batch alone never decides).
    trunc_accum: u64,
    /// Accumulated ring-loss deltas over every drain the open
    /// spanned (any retained loss degrades the verdict — R18
    /// COMPLETE requires ring-loss quiescence).
    ring_loss_accum: u64,
    /// A TRUNC drain raced a concurrent flag while this open
    /// spanned it (fail-closed PARTIAL at close).
    trunc_race_accum: bool,
    /// A hinted successor take arrived over this open (recorded,
    /// never tainting alone — hint + rule-hit = nested certain).
    hint_seen: bool,
    /// Sticky nesting taint (rule-hit): the close verdict is
    /// Tainted with the correlated seq, evidence retained.
    tainted_by: Option<u64>,
    /// Distinct arrays observed in slot evidence (multi-array
    /// rule input — more than one fires the nesting rule-set).
    arrs: BTreeSet<u64>,
    /// Slot evidence generations disagree with the RET generation
    /// (checked both directions — ALG-after-RET and RET-after-ALG).
    gen_mixed: bool,
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
    /// Post-drain outcome evidence (bounded): production takes
    /// `done` every poll, so late joins and straggler records
    /// consult this after `done` — a consumed key is absorbed
    /// (or LATE-joined when hung), never orphaned. Skipped
    /// outcomes are not joinable and stay out.
    recent: BTreeMap<(u32, u64), RecentClose>,
    recent_order: std::collections::VecDeque<(u32, u64)>,
}

/// Post-drain close evidence for one key (the minimum a late join
/// needs: existence + hung-ness — immune to retro-taint, which
/// rewrites `done`, never this).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecentClose {
    hung: bool,
}

/// Bound on retained post-drain closes (FIFO eviction — late
/// joins past the bound orphan honestly).
const RECENT_CAP: usize = 4096;

/// Where a closed key's evidence lives (live verdict or
/// post-drain memory — both answer late joins).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClosedAs {
    Done { hung: bool },
    Recent { hung: bool },
}

impl ClosedAs {
    fn hung(self) -> bool {
        match self {
            ClosedAs::Done { hung } | ClosedAs::Recent { hung } => hung,
        }
    }
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

    /// Record what the backend wrote to T_CACHE (keeps the warm
    /// belief truthful — the oracle knows what item 4 wrote).
    pub fn note_warm(&mut self, arr: u64, t: u64, generation: u64) {
        if let Some(scope) = self.scope.as_mut() {
            scope.known_t.insert(arr, (t, generation));
        }
    }

    /// Standing warm belief for an array, if any (the backend
    /// warms idempotently — an identical rewrite reports nothing).
    pub fn warm_belief(&self, arr: u64) -> Option<(u64, u64)> {
        self.scope.as_ref()?.known_t.get(&arr).copied()
    }

    /// Drop a warm belief (cache healing: grown tables and
    /// generation turnover invalidate; the next scan re-probes
    /// cold).
    pub fn note_invalidate(&mut self, arr: u64) {
        if let Some(scope) = self.scope.as_mut() {
            scope.known_t.remove(&arr);
        }
    }

    /// Drop every warm belief (provider turnover: array addresses
    /// may be reused by the new provider, so no cached T survives
    /// the epoch — the next scans re-probe cold).
    pub fn reset_beliefs(&mut self) {
        if let Some(scope) = self.scope.as_mut() {
            scope.known_t.clear();
        }
    }

    /// Window-edge close (the trailing-scan backstop): hung aging
    /// first (RET-less opens past 5s abandon as Hung), then every
    /// remaining open closes — RET-joined opens evaluate on their
    /// retained evidence, RET-less opens taint both correlated
    /// sequences (their own close carries UNKNOWN op). Nothing is
    /// ever dropped.
    pub fn finish(&mut self, now_ns: u64) {
        self.age_opens(now_ns);
        let scope = self.scope.clone().expect("oracle scope set");
        let keys: Vec<(u32, u64)> = self.open.keys().copied().collect();
        for k in keys {
            let o = self.open.remove(&k).expect("finish open");
            self.check_stray_rows(&k, &o);
            if let Some(by_seq) = o.tainted_by {
                self.push_done(WalkDone {
                    tid: k.0,
                    seq: k.1,
                    op: UNKNOWN_OP,
                    outcome: Outcome::Tainted { by_seq },
                    true_t: TrueT::Unknown,
                    arr: o.ret.map(|r| r.arr).unwrap_or(0),
                    alg_count: o.algs.len(),
                    row_count: o.rows as usize,
                    guard: o.guard,
                    algs: open_identities(&o),
                    event_ns: o.first_seen_ns,
                    rows: o.row_events.clone(),
                });
                continue;
            }
            if o.ret.is_none() {
                // Dangling CALL (no RET will ever join): the join
                // key's 1:1 CALL/RET correspondence is broken, so
                // BOTH correlated sequences taint — this close
                // carries UNKNOWN op, and the pair taints
                // stickily (open), by rewrite (live verdict), or
                // by finding alone (consumed verdict).
                let (pair, by_seq) = self.correlate(k.0, k.1);
                self.taint_pair(k.0, k.1, pair, by_seq);
                self.findings.push(Finding::Nested {
                    tid: k.0,
                    seq: k.1,
                    by_seq,
                });
                self.push_done(WalkDone {
                    tid: k.0,
                    seq: k.1,
                    op: UNKNOWN_OP,
                    outcome: Outcome::Tainted { by_seq },
                    true_t: TrueT::Unknown,
                    arr: 0,
                    alg_count: o.algs.len(),
                    row_count: o.rows as usize,
                    guard: o.guard,
                    algs: open_identities(&o),
                    event_ns: o.first_seen_ns,
                    rows: o.row_events.clone(),
                });
                continue;
            }
            let w = Self::evaluate(&scope, &k, &o);
            self.push_done(w);
        }
    }

    /// Abandon every open invocation (tier-3 detach: no member
    /// will ever fire again, so no RET can join — the opens are
    /// explicitly closed, never leaked across storms).
    pub fn abandon_all(&mut self, reason: AbandonReason) {
        let keys: Vec<(u32, u64)> = self.open.keys().copied().collect();
        for k in keys {
            let o = self.open.remove(&k).expect("open abandoned");
            self.push_done(WalkDone {
                tid: k.0,
                seq: k.1,
                op: o.call.op,
                outcome: Outcome::Abandoned { reason },
                true_t: TrueT::Unknown,
                arr: o.ret.map(|r| r.arr).unwrap_or(0),
                alg_count: o.algs.len(),
                row_count: o.rows as usize,
                guard: o.guard,
                algs: open_identities(&o),
                event_ns: o.first_seen_ns,
                rows: o.row_events.clone(),
            });
        }
    }

    /// Drain completed records (report-scale consumption — long
    /// runs take incrementally instead of growing `done`).
    pub fn take_done(&mut self) -> Vec<WalkDone> {
        std::mem::take(&mut self.done)
    }

    /// Drain findings (same incremental discipline as done).
    pub fn take_findings(&mut self) -> Vec<Finding> {
        std::mem::take(&mut self.findings)
    }

    /// Close one invocation: records the post-drain evidence,
    /// then pushes the verdict (every close funnels here, so
    /// `recent` observes every joinable outcome exactly once).
    fn push_done(&mut self, w: WalkDone) {
        let hung = matches!(
            w.outcome,
            Outcome::Abandoned {
                reason: AbandonReason::Hung
            }
        );
        let joinable = !matches!(w.outcome, Outcome::Skipped { .. });
        if joinable {
            let key = (w.tid, w.seq);
            if !self.recent.contains_key(&key) {
                self.recent_order.push_back(key);
            }
            self.recent.insert(key, RecentClose { hung });
            while self.recent_order.len() > RECENT_CAP {
                if let Some(old) = self.recent_order.pop_front() {
                    self.recent.remove(&old);
                }
            }
        }
        self.done.push(w);
    }

    /// A key's close evidence, if any: live `done` first (it
    /// carries retro-taints), post-drain `recent` after.
    fn closed(&self, tid: u32, seq: u64) -> Option<ClosedAs> {
        if let Some(w) = self.done.iter().find(|w| w.tid == tid && w.seq == seq) {
            return Some(ClosedAs::Done {
                hung: matches!(
                    w.outcome,
                    Outcome::Abandoned {
                        reason: AbandonReason::Hung
                    }
                ),
            });
        }
        self.recent
            .get(&(tid, seq))
            .map(|r| ClosedAs::Recent { hung: r.hung })
    }

    /// Ingest one drain batch (drain order across kinds when
    /// `order` is sound, else legacy kind-grouped order for
    /// single-key fixtures).
    pub fn ingest(&mut self, b: &ScanBatch) {
        let scope = self.scope.clone().expect("oracle scope set");
        self.stats.observe(b);
        let batch = self.batches;
        self.batches += 1;

        // 1. Ring records in drain order (causal per tid).
        if !b.order.is_empty() {
            debug_assert!(b.order_sound(), "batch order covers every record once");
            for (pos, p) in b.order.iter().enumerate() {
                match *p {
                    BatchPos::Call(i) => self.ingest_call(&b.calls[i], batch, pos, b.now_ns),
                    BatchPos::Ret(i) => self.ingest_ret(&b.rets[i]),
                    BatchPos::Guard(i) => self.ingest_guard(&b.guards[i]),
                    BatchPos::Alg(i) => self.ingest_alg(&b.algs[i]),
                    BatchPos::Row(i) => self.ingest_row(&b.rows[i]),
                }
            }
        } else {
            for (pos, c) in b.calls.iter().enumerate() {
                self.ingest_call(c, batch, pos, b.now_ns);
            }
            for r in &b.rets {
                self.ingest_ret(r);
            }
            for g in &b.guards {
                self.ingest_guard(g);
            }
            for a in &b.algs {
                self.ingest_alg(a);
            }
            for r in &b.rows {
                self.ingest_row(r);
            }
        }

        // 2. Retain loss/TRUNC history on every open spanning this
        // drain (R5 — evaluated over the full invocation, never
        // the closing batch alone).
        let ring_delta: u64 = [
            wire::LOSS_RING_CALL,
            wire::LOSS_RING_RET,
            wire::LOSS_RING_GUARD,
            wire::LOSS_RING_ALG,
            wire::LOSS_RING_ROW,
        ]
        .iter()
        .map(|id| b.loss.get(id).copied().unwrap_or(0))
        .sum();
        for o in self.open.values_mut() {
            o.ring_loss_accum = o.ring_loss_accum.saturating_add(ring_delta);
            o.trunc_accum |= b.trunc.get(&o.call.op).copied().unwrap_or(0);
            o.trunc_race_accum |= b.trunc_race;
        }
        // Window-loss input: opens present after the joins absorb
        // the deltas above; with no opens the loss is window-level.
        let had_opens = !self.open.is_empty();

        // 3. LOSS attribution (R4): 20/21/25/31 deltas attribute to
        // the single candidate tid or raise unattributed-loss.
        self.attribute_loss(b);

        // 4. Hung aging: RET-less opens past 5s abandon (sticky
        // policy + same-tid RET-less cascade).
        self.age_opens(b.now_ns);

        // 5. Closure (R6): RET-joined opens close on a later
        // admitted take, quiesced cells, or stay honestly open.
        self.close_ready(&scope, b, batch);

        // 6. Ring loss with no evaluable invocation is a window
        // finding, never dropped.
        if ring_delta > 0 && !had_opens {
            self.findings
                .push(Finding::WindowLoss { delta: ring_delta });
        }
    }

    /// Ingest one CALL: skips close immediately + abandon RET-less
    /// opens; admits open (a duplicate key taints the standing
    /// open — same-record overwrite, never silent replacement);
    /// hints are recorded on the predecessor, never tainting alone.
    fn ingest_call(&mut self, c: &wire::ScanCallEvent, batch: u64, pos: usize, now_ns: u64) {
        let (hint, cause) = wire::split_call_flags(c.flags);
        if cause != wire::SKIP_ADMITTED {
            self.push_done(WalkDone {
                tid: c.tid,
                seq: 0,
                op: c.op,
                outcome: Outcome::Skipped { cause },
                arr: 0,
                true_t: TrueT::Unknown,
                alg_count: 0,
                row_count: 0,
                guard: None,
                algs: Vec::new(),
                event_ns: now_ns,
                rows: Vec::new(),
            });
            // R4: the skip deleted any standing record — opens
            // WITHOUT a joined RET can never complete (their
            // return will SCAN-miss, or already did without a RET
            // — either way no RET will join). Opens WITH a RET
            // keep their evidence (cut-off members surface as
            // holes at evaluation).
            let victims: Vec<(u32, u64)> = self
                .open
                .iter()
                .filter(|((t, _), o)| *t == c.tid && o.ret.is_none())
                .map(|(k, _)| *k)
                .collect();
            for k in victims {
                let o = self.open.remove(&k).expect("victim open");
                self.push_done(WalkDone {
                    tid: k.0,
                    seq: k.1,
                    op: o.call.op,
                    outcome: Outcome::Abandoned {
                        reason: AbandonReason::SkipVictim,
                    },
                    true_t: TrueT::Unknown,
                    arr: o.ret.map(|r| r.arr).unwrap_or(0),
                    alg_count: o.algs.len(),
                    row_count: o.rows as usize,
                    guard: o.guard,
                    algs: open_identities(&o),
                    event_ns: o.first_seen_ns,
                    rows: o.row_events.clone(),
                });
            }
            return;
        }
        // Admitted: a hint records on the newest open predecessor
        // (corroboration input — taint needs a rule-hit too).
        if hint {
            let pred = self
                .open
                .iter()
                .filter(|((t, s), _)| *t == c.tid && *s < c.seq)
                .max_by_key(|((_, s), _)| *s)
                .map(|(k, _)| *k);
            if let Some(k) = pred {
                if let Some(o) = self.open.get_mut(&k) {
                    o.hint_seen = true;
                }
            }
        }
        // Duplicate keys never reuse ids (§5.1): a standing open
        // under the re-admitted key is same-record overwrite —
        // taint it with its evidence kept, then open the new one.
        if let Some(old) = self.open.remove(&(c.tid, c.seq)) {
            self.findings.push(Finding::Nested {
                tid: c.tid,
                seq: c.seq,
                by_seq: c.seq,
            });
            self.push_done(WalkDone {
                tid: c.tid,
                seq: c.seq,
                op: UNKNOWN_OP,
                outcome: Outcome::Tainted { by_seq: c.seq },
                true_t: TrueT::Unknown,
                arr: old.ret.map(|r| r.arr).unwrap_or(0),
                alg_count: old.algs.len(),
                row_count: old.rows as usize,
                guard: old.guard,
                algs: open_identities(&old),
                event_ns: old.first_seen_ns,
                rows: old.row_events.clone(),
            });
        }
        self.open.insert(
            (c.tid, c.seq),
            Open {
                call: *c,
                ret: None,
                guard: None,
                algs: BTreeMap::new(),
                rows: 0,
                row_idxs: Vec::new(),
                row_events: Vec::new(),
                batch,
                pos,
                stalled: false,
                first_seen_ns: now_ns,
                trunc_accum: 0,
                ring_loss_accum: 0,
                trunc_race_accum: false,
                hint_seen: false,
                tainted_by: None,
                arrs: BTreeSet::new(),
                gen_mixed: false,
            },
        );
    }

    /// Ingest one RET: joins by key (double joins are findings);
    /// unknown keys are orphans — except a RET for a
    /// hung-abandoned invocation, which joins as LATE (coverage
    /// noted, verdict standing).
    fn ingest_ret(&mut self, r: &wire::ScanRetEvent) {
        match self.open.get_mut(&(r.tid, r.seq)) {
            Some(o) if o.ret.is_none() => {
                // ALG-before-RET direction of the generation check.
                if o.algs.values().any(|a| a.generation != r.generation) {
                    o.gen_mixed = true;
                }
                o.ret = Some(*r);
            }
            Some(_) => self.findings.push(Finding::DoubleRet {
                tid: r.tid,
                seq: r.seq,
            }),
            None => match self.closed(r.tid, r.seq) {
                // Hung verdict (live or post-drain): LATE join,
                // verdict standing.
                Some(c) if c.hung() => self.findings.push(Finding::LateRet {
                    tid: r.tid,
                    seq: r.seq,
                    arr: r.arr,
                }),
                // Straggler for a closed, consumed key: absorbed
                // (cross-CPU ring skew delivers it after the
                // close — the outcome evidence already stands).
                Some(_) => {}
                None => self.findings.push(Finding::OrphanRet {
                    tid: r.tid,
                    seq: r.seq,
                }),
            },
        }
    }

    /// Ingest one GUARD: joins by key, kept-first (a second guard
    /// for one key is a finding, never an overwrite).
    fn ingest_guard(&mut self, g: &wire::GuardEvent) {
        match self.open.get_mut(&(g.tid, g.seq)) {
            Some(o) if o.guard.is_none() => o.guard = Some(*g),
            Some(_) => self.findings.push(Finding::DoubleGuard {
                tid: g.tid,
                seq: g.seq,
            }),
            None => {
                if self.closed(g.tid, g.seq).is_none() {
                    self.findings.push(Finding::OrphanGuard {
                        tid: g.tid,
                        seq: g.seq,
                    });
                }
            }
        }
    }

    /// Ingest one ALG: joins by key (kept-first on duplicate
    /// slots), enforcing the nesting rule-set inline —
    /// multi-array and duplicate-slot evidence taints both
    /// invocations with the slots kept.
    fn ingest_alg(&mut self, a: &wire::ScanAlgEvent) {
        let key = (a.tid, a.seq);
        let Some(o) = self.open.get_mut(&key) else {
            if self.closed(a.tid, a.seq).is_none() {
                self.findings.push(Finding::OrphanAlg {
                    tid: a.tid,
                    seq: a.seq,
                    idx: a.idx,
                });
            }
            return;
        };
        // Duplicate slot: same-record overwrite — keep the first,
        // fire the nesting rule-set (once: already-tainted opens
        // just accumulate).
        if o.algs.contains_key(&a.idx) {
            self.findings.push(Finding::DuplicateSlot {
                tid: a.tid,
                seq: a.seq,
                idx: a.idx,
            });
            if o.tainted_by.is_none() {
                self.fire_nesting(a.tid, a.seq);
            }
            return;
        }
        // Multi-array rule: a second array under one key fires the
        // nesting rule-set (the record itself is kept — slots are
        // rv/positional-trustworthy).
        let multi = !o.arrs.is_empty() && !o.arrs.contains(&a.arr);
        o.arrs.insert(a.arr);
        // RET-before-ALG direction of the generation check.
        if let Some(ret) = o.ret {
            if a.generation != ret.generation {
                o.gen_mixed = true;
            }
        }
        o.algs.insert(a.idx, *a);
        if multi && self.open.get(&key).and_then(|o| o.tainted_by).is_none() {
            self.fire_nesting(a.tid, a.seq);
        }
    }

    /// Ingest one ROW: retained whole (array/generation/
    /// callback data — consistency with the slot verdict and
    /// the RET is checked at close; the record rides the
    /// WALK-DONE for relocation and adaptation).
    fn ingest_row(&mut self, r: &wire::ScanRowEvent) {
        match self.open.get_mut(&(r.tid, r.seq)) {
            Some(o) => {
                o.rows += 1;
                o.row_idxs.push(r.idx);
                o.row_events.push(*r);
            }
            None => {
                if self.closed(r.tid, r.seq).is_none() {
                    self.findings.push(Finding::OrphanRow {
                        tid: r.tid,
                        seq: r.seq,
                        idx: r.idx,
                    });
                }
            }
        }
    }

    /// Fire the nesting rule-set on `key`: BOTH correlated
    /// sequences taint stickily (the current open keeps
    /// accumulating positive evidence — nothing is dropped at
    /// fire time — and closes Tainted with all of it) and the
    /// Nested finding names the correlation.
    fn fire_nesting(&mut self, tid: u32, seq: u64) {
        let (pair, by_seq) = self.correlate(tid, seq);
        if let Some(k) = pair {
            if let Some(o) = self.open.get_mut(&k) {
                o.tainted_by = Some(seq);
            }
        }
        if let Some(o) = self.open.get_mut(&(tid, seq)) {
            o.tainted_by = Some(by_seq);
        }
        self.findings.push(Finding::Nested { tid, seq, by_seq });
    }

    /// Correlate `key` with its nesting pair: the newest *other*
    /// open on the tid, else the newest done seq on the tid
    /// (already closed — correlation noted), else the key itself
    /// (solo misattribution — defensive).
    fn correlate(&self, tid: u32, seq: u64) -> (Option<(u32, u64)>, u64) {
        let pair: Option<(u32, u64)> = self
            .open
            .keys()
            .filter(|(t, s)| *t == tid && *s != seq)
            .max_by_key(|(_, s)| *s)
            .copied();
        let by_seq = match pair {
            Some((_, s)) => s,
            None => self
                .done
                .iter()
                .filter(|w| w.tid == tid && w.seq != seq)
                .map(|w| w.seq)
                .max()
                .unwrap_or(seq),
        };
        (pair, by_seq)
    }

    /// Taint the correlated sequence of a dangling close: a live
    /// open taints stickily (its close verdict becomes Tainted);
    /// an already-closed live verdict is rewritten in place
    /// (evidence kept, op forced UNKNOWN — the standing verdict
    /// rested on mixed evidence); a consumed (drained) verdict is
    /// beyond rewriting, so the Nested finding below is its only
    /// mark.
    fn taint_pair(&mut self, tid: u32, seq: u64, pair: Option<(u32, u64)>, by_seq: u64) {
        if let Some(k) = pair {
            if let Some(o) = self.open.get_mut(&k) {
                o.tainted_by = Some(seq);
            }
            return;
        }
        if by_seq == seq {
            return;
        }
        if let Some(w) = self
            .done
            .iter_mut()
            .filter(|w| w.tid == tid && w.seq == by_seq)
            .last()
        {
            w.outcome = Outcome::Tainted { by_seq: seq };
            w.op = UNKNOWN_OP;
        }
    }

    /// LOSS attribution (R4): 20/21/25/31 deltas attribute to
    /// the single candidate tid or raise an explicit
    /// unattributed-loss finding. Churn-class candidates are tids
    /// with a hinted admitted take in this batch (the take that
    /// witnessed the disturbance); RETIRE_FAIL candidates are tids
    /// with a RET-joined open.
    fn attribute_loss(&mut self, b: &ScanBatch) {
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
            let mut tid_cands: BTreeSet<u32> = BTreeSet::new();
            if id == wire::LOSS_RETIRE_FAIL {
                for ((t, _), o) in self.open.iter() {
                    if o.ret.is_some() {
                        tid_cands.insert(*t);
                    }
                }
            } else {
                for c in &b.calls {
                    let (hint, cause) = wire::split_call_flags(c.flags);
                    if cause == wire::SKIP_ADMITTED && hint {
                        tid_cands.insert(c.tid);
                    }
                }
            }
            if tid_cands.len() == 1 && delta == 1 {
                let t = *tid_cands.iter().next().unwrap();
                // Exactly one candidate open, else the delta is
                // ambiguous (never guessed).
                let cands: Vec<(u32, u64)> = if id == wire::LOSS_RETIRE_FAIL {
                    self.open
                        .iter()
                        .filter(|((tt, _), o)| *tt == t && o.ret.is_some())
                        .map(|(k, _)| *k)
                        .collect()
                } else {
                    // Hint-marked opens on the tid (a hinted take
                    // marks exactly its predecessor — the take
                    // witnessed that open's record disturbance).
                    self.open
                        .iter()
                        .filter(|((tt, _), o)| *tt == t && o.hint_seen)
                        .map(|(k, _)| *k)
                        .collect()
                };
                let key = match cands.as_slice() {
                    [k] => Some(*k),
                    _ => None,
                };
                if let Some(k) = key {
                    let o = self.open.remove(&k).expect("attributed open");
                    self.push_done(WalkDone {
                        tid: k.0,
                        seq: k.1,
                        op: o.call.op,
                        outcome: Outcome::Abandoned { reason },
                        true_t: TrueT::Unknown,
                        arr: o.ret.map(|r| r.arr).unwrap_or(0),
                        alg_count: o.algs.len(),
                        row_count: o.rows as usize,
                        guard: o.guard,
                        algs: open_identities(&o),
                        event_ns: o.first_seen_ns,
                        rows: o.row_events.clone(),
                    });
                    continue;
                }
                self.findings.push(Finding::UnattributedLoss { id, delta });
            } else {
                self.findings.push(Finding::UnattributedLoss { id, delta });
            }
        }
    }

    /// Hung aging (R4): RET-less opens older than 5s abandon as
    /// Hung; the abandonment cascades to same-tid RET-less outers
    /// (nested-outer ambiguity — sticky-both). RET-joined opens
    /// never age out (evidence in hand closes on succession, the
    /// stall path, or the window backstop). Timeless batches
    /// (`now_ns == 0`) never age.
    fn age_opens(&mut self, now_ns: u64) {
        if now_ns == 0 {
            return;
        }
        let hung: Vec<(u32, u64)> = self
            .open
            .iter()
            .filter(|(_, o)| o.ret.is_none() && now_ns.saturating_sub(o.first_seen_ns) > HUNG_NS)
            .map(|(k, _)| *k)
            .collect();
        if hung.is_empty() {
            return;
        }
        let hung_tids: BTreeSet<u32> = hung.iter().map(|(t, _)| *t).collect();
        // Cascade: every RET-less open on a hung tid abandons with
        // it (the outer may have returned into superseded state —
        // indistinguishable, so sticky-both).
        let cascade: Vec<(u32, u64)> = self
            .open
            .iter()
            .filter(|((t, _), o)| hung_tids.contains(t) && o.ret.is_none())
            .map(|(k, _)| *k)
            .collect();
        for k in cascade {
            let o = self.open.remove(&k).expect("hung open");
            self.push_done(WalkDone {
                tid: k.0,
                seq: k.1,
                op: o.call.op,
                outcome: Outcome::Abandoned {
                    reason: AbandonReason::Hung,
                },
                true_t: TrueT::Unknown,
                arr: o.ret.map(|r| r.arr).unwrap_or(0),
                alg_count: o.algs.len(),
                row_count: o.rows as usize,
                guard: o.guard,
                algs: open_identities(&o),
                event_ns: o.first_seen_ns,
                rows: o.row_events.clone(),
            });
        }
    }

    /// Closure (R6): for each open with a joined RET, a later
    /// *admitted* take on the tid closes it (stalled opens abandon
    /// instead — the detach-stall ambiguity); with no later
    /// admitted take, quiesced cells decide (IDLE/missing ⟹
    /// close, ACTIVE ⟹ stall); non-quiesced batches hold
    /// underdetermined invocations open. Later skips never block
    /// evaluation (cut-off members surface as holes).
    fn close_ready(&mut self, scope: &OracleScope, b: &ScanBatch, batch: u64) {
        // Admitted CALLs with their ring positions (causal order
        // when `order` is sound, else kind-grouped positions —
        // same-batch compares stay within one convention).
        let admitted: Vec<(usize, &wire::ScanCallEvent)> = if !b.order.is_empty() {
            b.order
                .iter()
                .enumerate()
                .filter_map(|(ring, p)| match *p {
                    BatchPos::Call(i) => Some((ring, &b.calls[i])),
                    _ => None,
                })
                .filter(|(_, c)| wire::split_call_flags(c.flags).1 == wire::SKIP_ADMITTED)
                .collect()
        } else {
            b.calls
                .iter()
                .enumerate()
                .filter(|(_, c)| wire::split_call_flags(c.flags).1 == wire::SKIP_ADMITTED)
                .collect()
        };
        let mut closable: Vec<(u32, u64)> = Vec::new();
        let mut stallable: Vec<(u32, u64)> = Vec::new();
        let mut stalled_quiet: Vec<(u32, u64)> = Vec::new();
        for ((t, s), o) in self.open.iter() {
            if o.ret.is_none() {
                continue;
            }
            let later_admitted = admitted
                .iter()
                .any(|(pos, c)| c.tid == *t && (o.batch != batch || *pos > o.pos) && c.seq != *s);
            if !later_admitted {
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
            // A later admitted take closed the window on this
            // invocation: stalled opens abandon (the thread moved
            // on without retiring — detach-stall resolved),
            // others evaluate on retained evidence.
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
                self.push_done(WalkDone {
                    tid: k.0,
                    seq: k.1,
                    op: o.call.op,
                    outcome: Outcome::Abandoned {
                        reason: AbandonReason::Stalled,
                    },
                    true_t: TrueT::Unknown,
                    arr: o.ret.map(|r| r.arr).unwrap_or(0),
                    alg_count: o.algs.len(),
                    row_count: o.rows as usize,
                    guard: o.guard,
                    algs: open_identities(&o),
                    event_ns: o.first_seen_ns,
                    rows: o.row_events.clone(),
                });
            }
        }
        for k in closable {
            if let Some(o) = self.open.remove(&k) {
                // Stray-row consistency is finding-bearing, so it
                // runs here (mutable) rather than in `evaluate`.
                self.check_stray_rows(&k, &o);
                // Taint short-circuit keeps the evidence (the
                // verdict carries the supersede).
                if let Some(by_seq) = o.tainted_by {
                    self.push_done(WalkDone {
                        tid: k.0,
                        seq: k.1,
                        op: UNKNOWN_OP,
                        outcome: Outcome::Tainted { by_seq },
                        true_t: TrueT::Unknown,
                        arr: o.ret.map(|r| r.arr).unwrap_or(0),
                        alg_count: o.algs.len(),
                        row_count: o.rows as usize,
                        guard: o.guard,
                        algs: open_identities(&o),
                        event_ns: o.first_seen_ns,
                        rows: o.row_events.clone(),
                    });
                    continue;
                }
                let w = Self::evaluate(scope, &k, &o);
                self.push_done(w);
            }
        }
    }

    /// ROW/ALG consistency: rows for slots with no walked
    /// classifier verdict are stray findings (EMPTY/NOIMP/
    /// UNREADABLE slots emit no rows; rows for missing slots are
    /// covered by the hole the missing ALG already earns).
    fn check_stray_rows(&mut self, key: &(u32, u64), o: &Open) {
        for idx in &o.row_idxs {
            match o.algs.get(idx) {
                None => {}
                Some(a)
                    if matches!(
                        a.status,
                        wire::ALG_OK
                            | wire::ALG_UNKNOWN
                            | wire::ALG_OVERLONG
                            | wire::ALG_TRUNCATED
                            | wire::ALG_MIXED
                    ) => {}
                Some(_) => self.findings.push(Finding::StrayRow {
                    tid: key.0,
                    seq: key.1,
                    idx: *idx,
                }),
            }
        }
    }

    /// Evaluate a retired-proven invocation (R1/R2/R5) on its
    /// retained evidence: explicit terminator (min-EMPTY, or the
    /// guard at 512), prefix coverage, warm-belief agreement,
    /// generation consistency, retained TRUNC/loss, and guard
    /// disposition. COMPLETE requires Proven — every
    /// Candidate/Unknown path names its PARTIAL reason.
    fn evaluate(scope: &OracleScope, key: &(u32, u64), o: &Open) -> WalkDone {
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
                arr: ret.arr,
                alg_count: o.algs.len(),
                row_count: o.rows as usize,
                guard: o.guard,
                algs: open_identities(o),
                event_ns: o.first_seen_ns,
                rows: o.row_events.clone(),
            };
        }

        // Warm belief: the RET carries the invocation's array id +
        // generation directly (no ALG inference needed). A cached
        // entry under a foreign generation is turnover (cold
        // rules + the stale row flagged for invalidation) —
        // except generation 0, which the producer stamps when no
        // epoch was recorded at fire time (GEN install happens at
        // the first close, so the successor always stamps 0 and
        // closes against epoch 1). Turnover-spanning opens never
        // close normally (turnover abandons them), so observed 0
        // is unrecorded-at-fire, never a superseded epoch: cold
        // rules re-prove, no GenStale.
        let cached: Option<(u64, u64)> = scope.known_t.get(&ret.arr).copied();
        let warm: Option<u64> = cached.filter(|(_, g)| *g == ret.generation).map(|(t, _)| t);
        if let Some((_, g)) = cached {
            if g != ret.generation && ret.generation != 0 {
                reasons.push(PartialReason::GenStale {
                    expected: g,
                    observed: ret.generation,
                });
            }
        }

        // Explicit terminator: min-EMPTY over attached slots.
        // Records beyond it are meaningless and discarded (past-T
        // memory may fault or hold adjacent-table bytes); only a
        // missing record below it is a hole.
        let attached = &scope.attached;
        let min_empty: Option<u64> = o
            .algs
            .iter()
            .filter(|(j, a)| attached.contains(&(**j as u32)) && a.status == wire::ALG_EMPTY)
            .map(|(j, _)| *j)
            .min();
        let edge: u64 = attached.iter().max().map(|m| *m as u64 + 1).unwrap_or(0);
        let t_obs = min_empty.unwrap_or(edge);

        // Prefix evidence below the observed terminator.
        let mut holes: Vec<u64> = Vec::new();
        let mut unread: Vec<u64> = Vec::new();
        for j in attached.iter() {
            let j = *j as u64;
            if j >= t_obs {
                continue;
            }
            match o.algs.get(&j) {
                None => holes.push(j),
                Some(a) if a.status == wire::ALG_UNREADABLE => unread.push(j),
                _ => {}
            }
        }
        // Selective scope: attached-missing slots below the
        // terminator are unobserved (never silent); when no
        // terminator lands in the window, every unattached slot
        // below 512 is terminator-region unobserved.
        let unobs_limit = if min_empty.is_some() { t_obs } else { 512 };
        let unobs: Vec<u64> = (0..unobs_limit)
            .filter(|j| !attached.contains(&(*j as u32)))
            .collect();
        if !holes.is_empty() {
            reasons.push(PartialReason::Holes(holes));
        }
        if !unread.is_empty() {
            reasons.push(PartialReason::Unreadable(unread));
        }
        if !unobs.is_empty() {
            reasons.push(PartialReason::UnobservedSlots(unobs));
        }

        // Generation consistency over the joined slot and row
        // evidence (checked both ALG directions at ingest; rows
        // join here — a cross-epoch row is inconsistent evidence).
        if o.gen_mixed
            || o.algs.values().any(|a| a.generation != ret.generation)
            || o.row_events.iter().any(|r| r.generation != ret.generation)
        {
            reasons.push(PartialReason::GenMixed);
        }

        // ROW/array consistency over the retained dispatch rows
        // (every row names its array — a foreign array is
        // evidence inconsistent with the joined RET).
        if o.row_events.iter().any(|r| r.aux != ret.arr) {
            reasons.push(PartialReason::RowArrayMismatch);
        }

        // TRUE-T (R2): the explicit terminator decides; the warm
        // belief only stands uncontradicted; 512 falls to the
        // guard (a proven terminator below 512 discards any guard
        // observation — past-T noise, never evidence).
        let true_t = match (warm, min_empty) {
            // Fresh terminator below the cached T: the table
            // shrank (the backend updates the cache from the
            // reason; this verdict stays partial).
            (Some(tw), Some(t)) if t < tw => {
                reasons.push(PartialReason::CacheShrink {
                    cached: tw,
                    observed: t,
                });
                TrueT::Proven(t)
            }
            // Fresh terminator beyond the cached T: the table
            // grew (the backend invalidates from the reason;
            // cold re-probe heals).
            (Some(tw), Some(t)) if t > tw => {
                reasons.push(PartialReason::CacheStale { cached: tw });
                TrueT::Proven(t)
            }
            // Warm belief re-proven by a fresh terminator at T.
            (Some(tw), Some(_)) => TrueT::Proven(tw),
            // Warm belief, terminator unobserved: positive walked
            // evidence beyond T proves growth (stale — the lowest
            // consistent terminator bounds the new T); otherwise
            // the terminator proof is missing — the walked
            // terminator slot came back live, faulted, or
            // unreadable, so the cached T cannot stand (stale —
            // the backend invalidates and the next scan
            // re-probes cold). Only a terminator slot outside
            // the attached set keeps the belief (unobservable —
            // the UnobservedSlots reason already partials).
            (Some(tw), None) => {
                let positive_beyond: Vec<u64> = o
                    .algs
                    .iter()
                    .filter(|(j, a)| {
                        **j > tw
                            && attached.contains(&(**j as u32))
                            && !matches!(a.status, wire::ALG_EMPTY | wire::ALG_UNREADABLE)
                    })
                    .map(|(j, _)| *j)
                    .collect();
                if let Some(floor) = positive_beyond.iter().max().map(|m| m + 1) {
                    reasons.push(PartialReason::CacheStale { cached: tw });
                    TrueT::Candidate(floor)
                } else if tw == 512 {
                    // A 512 belief still needs its fresh boundary
                    // proof every scan (the guard read).
                    Self::cover_512(scope, o, &mut reasons)
                } else if attached.contains(&(tw as u32)) {
                    reasons.push(PartialReason::CacheStale { cached: tw });
                    TrueT::Candidate(tw)
                } else {
                    TrueT::Proven(tw)
                }
            }
            // Cold: the explicit terminator proves T.
            (None, Some(t)) => TrueT::Proven(t),
            // Cold, no terminator in the window: 512-case below.
            (None, None) => Self::cover_512(scope, o, &mut reasons),
        };

        // Retained TRUNC (R5): ALGS/DISPATCH/NO_STORE are
        // unscoped-structural (always PARTIAL — NO_STORE is never
        // Complete-compatible per the wire contract). WALK_READ
        // is always retained too: the producer emits ALG before
        // walking dispatch, so a dispatch read failure hides
        // behind a readable prefix — the bit is indistinguishable
        // from past-terminator tuple noise, and fail-closed keeps
        // it (same honesty class as DISPATCH overflow). WALK_NAME
        // explains prefix gaps, else it is beyond-terminator
        // noise discarded with its reads (a below-terminator
        // name failure always leaves an UNREADABLE gap).
        let mut trunc_bits = o.trunc_accum
            & (wire::TRUNC_ALGS
                | wire::TRUNC_DISPATCH
                | wire::TRUNC_NO_STORE
                | wire::TRUNC_WALK_READ);
        let gaps = reasons.iter().any(|r| {
            matches!(
                r,
                PartialReason::Holes(_)
                    | PartialReason::Unreadable(_)
                    | PartialReason::UnobservedSlots(_)
            )
        });
        if gaps {
            trunc_bits |= o.trunc_accum & wire::TRUNC_WALK_NAME;
        }
        if trunc_bits != 0 {
            reasons.push(PartialReason::Trunc(trunc_bits));
        }

        // Retained ring loss degrades the verdict unconditionally
        // (R18 COMPLETE requires ring-loss quiescence — dropped
        // ROWs leave ALG coverage intact but the dispatch
        // evidence is provably incomplete).
        if o.ring_loss_accum > 0 {
            reasons.push(PartialReason::DrainLoss);
        }

        // A raced TRUNC drain may have erased a concurrent flag
        // unread — the invocation it spanned degrades
        // explicitly, never silently.
        if o.trunc_race_accum {
            reasons.push(PartialReason::TruncDrainRace);
        }

        // COMPLETE requires Proven (defensive: unreachable by
        // construction — every Candidate path above names its
        // reason — but fail-closed).
        if reasons.is_empty() && !matches!(true_t, TrueT::Proven(_)) {
            reasons.push(PartialReason::TerminatorUnproven);
        }
        let outcome = if reasons.is_empty() {
            let t = match true_t {
                TrueT::Proven(t) => t,
                TrueT::EmptyTable | TrueT::Candidate(_) | TrueT::Unknown => 0,
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
            arr: ret.arr,
            alg_count: o.algs.len(),
            row_count: o.rows as usize,
            guard: o.guard,
            algs: open_identities(o),
            event_ns: o.first_seen_ns,
            rows: o.row_events.clone(),
        }
    }

    /// The 512-case: no terminator below 512 observed, so the
    /// guard read is the boundary evidence (missing ⟹ unproven;
    /// VALID ⟹ the table extends beyond observation; ERROR ⟹ the
    /// tail read aborted). Selective scopes never reach Proven
    /// here (the edge is a window, not a terminator).
    fn cover_512(scope: &OracleScope, o: &Open, reasons: &mut Vec<PartialReason>) -> TrueT {
        let edge: u64 = scope
            .attached
            .iter()
            .max()
            .map(|m| *m as u64 + 1)
            .unwrap_or(0);
        if edge != 512 {
            return TrueT::Candidate(edge);
        }
        match o.guard {
            Some(g) if g.verdict == wire::GUARD_EMPTY => TrueT::Proven(512),
            Some(g) if g.verdict == wire::GUARD_VALID => {
                reasons.push(PartialReason::Overfull);
                TrueT::Candidate(512)
            }
            Some(_) => {
                reasons.push(PartialReason::GuardError);
                TrueT::Candidate(512)
            }
            None => {
                reasons.push(PartialReason::GuardMissing);
                TrueT::Candidate(512)
            }
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
        alg_gen(seq, idx, status, 0)
    }

    fn alg_gen(seq: u64, idx: u64, status: u8, generation: u64) -> wire::ScanAlgEvent {
        wire::ScanAlgEvent {
            kind: wire::KIND_SCAN_ALG,
            op: 7,
            class: if status == wire::ALG_OK {
                1
            } else {
                wire::OTHER_CLASS
            },
            status,
            weak: 0,
            _pad: 0,
            arr: ARR,
            idx,
            generation,
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
        // Cold, 3-live table: ALGs 0..2 + explicit EMPTY@3 ⟹
        // Proven(3), Complete (beyond-T reads discarded).
        let mut o = Oracle::new(OracleScope::full());
        let mut b = idle_batch();
        b.push_call(call(0, false, wire::SKIP_ADMITTED));
        b.push_ret(ret(0, 0, false));
        for j in 0..3 {
            b.push_alg(alg(0, j, wire::ALG_OK));
        }
        b.push_alg(alg(0, 3, wire::ALG_EMPTY));
        assert!(b.order_sound());
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
        b.push_call(call(0, false, wire::SKIP_ADMITTED));
        b.push_ret(ret(0, 0, true));
        o.ingest(&b);
        assert_eq!(o.done.len(), 1);
        assert_eq!(o.done[0].true_t, TrueT::EmptyTable);
        assert!(matches!(o.done[0].outcome, Outcome::Complete { .. }));
    }

    #[test]
    fn oracle_hole_is_partial() {
        let mut o = Oracle::new(OracleScope::full());
        let mut b = idle_batch();
        b.push_call(call(0, false, wire::SKIP_ADMITTED));
        b.push_ret(ret(0, 0, false));
        b.push_alg(alg(0, 0, wire::ALG_OK));
        b.push_alg(alg(0, 2, wire::ALG_OK)); // 1 missing
        b.push_alg(alg(0, 3, wire::ALG_EMPTY));
        o.ingest(&b);
        assert_eq!(o.done.len(), 1);
        // The terminator is explicit (Proven(3)) but slot 1 has no
        // record — a hole (PARTIAL with the exact set).
        assert_eq!(o.done[0].true_t, TrueT::Proven(3));
        assert!(matches!(
            o.done[0].outcome,
            Outcome::Partial { ref reasons } if reasons.contains(&PartialReason::Holes(vec![1]))
        ));
    }

    #[test]
    fn oracle_hint_rule_taint_and_skip_victim() {
        let mut o = Oracle::new(OracleScope::full());
        // Batch 1: admitted, no RET yet (still open).
        let mut b1 = ScanBatch {
            quiesced: false,
            ..ScanBatch::default()
        };
        b1.push_call(call(0, false, wire::SKIP_ADMITTED));
        o.ingest(&b1);
        assert_eq!(o.open_count(), 1);
        // Batch 2: nested admitted take with hint (recorded, not
        // tainting) + a duplicate slot under seq 0 (rule-hit ⟹
        // both tainted, predecessor closes immediately).
        let mut b2 = ScanBatch {
            quiesced: false,
            ..ScanBatch::default()
        };
        b2.push_call(call(1, true, wire::SKIP_ADMITTED));
        b2.push_ret(ret(0, 0, false));
        b2.push_alg(alg(0, 0, wire::ALG_OK));
        b2.push_alg(alg(0, 0, wire::ALG_OK));
        o.ingest(&b2);
        assert!(matches!(o.done[0].outcome, Outcome::Tainted { by_seq: 1 }));
        assert_eq!(o.done[0].op, UNKNOWN_OP);
        assert_eq!(o.done[0].alg_count, 1, "first record kept");
        // Batch 3: skip over the RET-less seq 1 ⟹ abandoned.
        // (The skip CALL records first; the abandon is its
        // consequence.)
        let mut b3 = idle_batch();
        b3.push_call(call(0, false, wire::SKIP_RING_PRESSURE));
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
        // window ⟹ Candidate(4) + explicit PARTIAL for the
        // unobserved terminator region (Candidate never
        // completes).
        let mut scope = OracleScope::full();
        scope.attached = (0..4).collect();
        scope.expected = 4;
        let mut o = Oracle::new(scope);
        let mut b = idle_batch();
        b.push_call(call(0, false, wire::SKIP_ADMITTED));
        b.push_ret(ret(0, 0, false));
        for j in 0..4 {
            b.push_alg(alg(0, j, wire::ALG_OK));
        }
        o.ingest(&b);
        assert_eq!(o.done.len(), 1);
        assert_eq!(o.done[0].true_t, TrueT::Candidate(4));
        assert!(matches!(
            o.done[0].outcome,
            Outcome::Partial { ref reasons } if reasons
                .iter()
                .any(|r| matches!(r, PartialReason::UnobservedSlots(_)))
        ));
    }

    #[test]
    fn oracle_selective_terminator_inside() {
        // Selective scope CAN prove termination when the
        // terminator lands inside the window: attached
        // {0,1,2,3}, explicit EMPTY@3 ⟹ Proven(3), Complete
        // (unattached slots beyond the terminator are
        // discarded, not unobserved).
        let mut scope = OracleScope::full();
        scope.attached = (0..4).collect();
        scope.expected = 4;
        let mut o = Oracle::new(scope);
        let mut b = idle_batch();
        b.push_call(call(0, false, wire::SKIP_ADMITTED));
        b.push_ret(ret(0, 0, false));
        for j in 0..3 {
            b.push_alg(alg(0, j, wire::ALG_OK));
        }
        b.push_alg(alg(0, 3, wire::ALG_EMPTY));
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
        b.push_call(call(3, false, wire::SKIP_ADMITTED));
        b.push_ret(ret(3, 5, false));
        // Warm window re-walks j ≤ 9 (same generation as the
        // RET) with a fresh terminator at 9; j > 9 skips
        // silent (no records — the cache covers them).
        for j in 0..9 {
            b.push_alg(alg_gen(3, j, wire::ALG_OK, 5));
        }
        b.push_alg(alg_gen(3, 9, wire::ALG_EMPTY, 5));
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
        b1.push_call(call(0, false, wire::SKIP_ADMITTED));
        b1.push_ret(ret(0, 0, false));
        b1.push_alg(alg(0, 0, wire::ALG_OK));
        b1.push_alg(alg(0, 1, wire::ALG_EMPTY));
        o.ingest(&b1);
        assert_eq!(o.open_count(), 1);
        let mut b2 = ScanBatch {
            quiesced: false,
            ..ScanBatch::default()
        };
        b2.push_call(call(1, false, wire::SKIP_ADMITTED));
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
        b.push_ret(ret(9, 0, false)); // no CALL ⟹ orphan
        b.push_call(call(0, false, wire::SKIP_ADMITTED));
        b.push_ret(ret(0, 0, false));
        b.push_ret(ret(0, 0, false)); // double
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
        b.push_call(call(0, false, wire::SKIP_ADMITTED));
        b.push_ret(ret(0, 0, false));
        o.ingest(&b);
        assert_eq!(o.open_count(), 1);
        assert!(o.findings.contains(&Finding::Stall { tid: TID, seq: 0 }));
        // A later quiet successor abandons (never miscloses).
        let mut b2 = ScanBatch {
            quiesced: false,
            ..ScanBatch::default()
        };
        b2.push_call(call(1, false, wire::SKIP_ADMITTED));
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
        b.push_call(call(0, false, wire::SKIP_ADMITTED));
        b.push_ret(ret(0, 0, false));
        o.ingest(&b);
        let s = o.stats();
        assert_eq!(s.batches, 1);
        assert_eq!(s.records, 2);
        assert_eq!(s.bytes, ONRING_CALL + ONRING_RET);
    }

    #[test]
    fn oracle_note_warm_abandon_take() {
        // Backend-support methods: note_warm keeps the belief
        // truthful, abandon_all closes opens explicitly,
        // take_* drains incrementally.
        let mut o = Oracle::new(OracleScope::full());
        o.note_warm(ARR, 9, 5);
        let mut b = idle_batch();
        b.push_call(call(3, false, wire::SKIP_ADMITTED));
        b.push_ret(ret(3, 5, false));
        for j in 0..9 {
            b.push_alg(alg_gen(3, j, wire::ALG_OK, 5));
        }
        b.push_alg(alg_gen(3, 9, wire::ALG_EMPTY, 5));
        // A second invocation stays open (no RET).
        b.push_call(call(4, false, wire::SKIP_ADMITTED));
        o.ingest(&b);
        assert_eq!(o.done.len(), 1);
        assert!(matches!(
            o.done[0].outcome,
            Outcome::Complete { cached: true, .. }
        ));
        o.abandon_all(AbandonReason::Detached);
        assert_eq!(o.open_count(), 0);
        assert!(matches!(
            o.done[1].outcome,
            Outcome::Abandoned {
                reason: AbandonReason::Detached
            }
        ));
        assert_eq!(o.done[1].seq, 4);
        let done = o.take_done();
        assert_eq!(done.len(), 2);
        assert!(o.done.is_empty());
        let findings = o.take_findings();
        assert!(findings.is_empty());
    }
}
