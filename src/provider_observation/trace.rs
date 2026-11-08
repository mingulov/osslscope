// SPDX-License-Identifier: GPL-3.0-or-later
//! 6D trace data plane (T8.2a): mode words, family demux, pairing core,
//! detail caps, and lane surfacing. Output projections (§6D-2 class
//! counts, §6D-3 histograms, §6D-7 record JSON, status/modes CLI) belong
//! to T8.2b/c; this module produces streaming folds (per-class counts,
//! per-class latency distributions, per-API edge counts), retained
//! detail, exemplars, and counters.
use super::wire::contract as c;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

/// `TRACE_MODE` map words (§6D-9 order, single-sourced from the BPF contract).
pub use c::{
    TRACE_MODE_ALL, TRACE_MODE_LATENCY, TRACE_MODE_METADATA, TRACE_MODE_OFF, TRACE_MODE_STATUS,
};

/// Edge-bearing predicate (§6D-0 D0-1): only 2/3/4 pair.
pub fn trace_mode_edge_bearing(mode: u32) -> bool {
    c::trace_edge_bearing(mode)
}

/// ATTEMPT/RESULT family (§6D-1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TraceFamily {
    /// Lifecycle-pair IDs (1..=9, 16..=19); ATTEMPT/RESULT wire-valid on 1..=6.
    Lifecycle,
    /// Fetch carve-out (10..=15).
    Fetch,
    /// Operational exports (20..=72).
    PublicApi,
}

impl TraceFamily {
    /// Stable slot for received-count arrays.
    pub fn index(self) -> usize {
        match self {
            TraceFamily::Lifecycle => 0,
            TraceFamily::Fetch => 1,
            TraceFamily::PublicApi => 2,
        }
    }
}

/// Family demux BEFORE unknown-ID rejection (§6D-1). `None` ⟺ {0} ∪ {73+}.
pub fn demux(api: u32) -> Option<TraceFamily> {
    match api {
        1..=9 | 16..=19 => Some(TraceFamily::Lifecycle),
        10..=15 => Some(TraceFamily::Fetch),
        20..=72 => Some(TraceFamily::PublicApi),
        _ => None,
    }
}

/// Fold-input class (F5 / frozen §6D-2 arm 1): operational pairs
/// keep the raw outcome class; fetch and lifecycle pairs classify
/// class 0 `unknown` BY FUNCTION. Total over the demux: unknown
/// IDs (unreachable on the wire-valid path — the decoder arm owns
/// validity) also fold 0.
fn pair_class(api: u32, outcome: u32) -> u32 {
    match demux(api) {
        Some(TraceFamily::PublicApi) => outcome.min(4),
        _ => 0,
    }
}

/// Pair key (§6D-6): thread key + cookie + invocation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PairKey {
    /// Executing pid (never the submitting one).
    pub pid: u32,
    /// Executing tid.
    pub tid: u32,
    /// Scope/authority generation (cross-generation pairing forbidden).
    pub generation: u64,
    /// BPF/host map cookie (never output raw).
    pub cookie: u64,
    /// Pending-path invocation counter.
    pub invocation: u64,
}

/// `key_hash16` (§6D-6): lowercase hex of the first 8 bytes of SHA-256
/// over `le64(cookie) || le64(generation)`.
pub fn key_hash16(cookie: u64, generation: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cookie.to_le_bytes());
    hasher.update(generation.to_le_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Hash-bound pairing identity for producer outputs (§6D-6): the full
/// pairing identity MINUS the raw cookie. Pairing maps keep full keys;
/// everything leaving the pairing core carries this form.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HashedKey {
    /// Executing pid.
    pub pid: u32,
    /// Executing tid.
    pub tid: u32,
    /// Scope/authority generation.
    pub generation: u64,
    /// `key_hash16` over the cookie.
    pub key_hash16: String,
    /// Pending-path invocation counter.
    pub invocation: u64,
}

impl HashedKey {
    /// Bind a full pairing key to its output form.
    pub fn of(key: &PairKey) -> Self {
        Self {
            pid: key.pid,
            tid: key.tid,
            generation: key.generation,
            key_hash16: key_hash16(key.cookie, key.generation),
            invocation: key.invocation,
        }
    }
}

/// Decoded ATTEMPT edge (producer input).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AttemptEdge {
    /// Pair key.
    pub key: PairKey,
    /// API ID (wire-valid).
    pub api: u32,
    /// Producer CLOCK_MONOTONIC timestamp.
    pub monotonic_ns: u64,
}

/// Decoded RESULT edge (producer input).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ResultEdge {
    /// Pair key.
    pub key: PairKey,
    /// API ID (wire-valid).
    pub api: u32,
    /// Producer CLOCK_MONOTONIC timestamp.
    pub monotonic_ns: u64,
    /// RAW `record.outcome` (0..4), never the folded payload.
    pub outcome: u32,
}

/// Frozen §6D-3 finite histogram edges (ns, ascending, verbatim).
pub const TRACE_HISTOGRAM_EDGES: [u64; 18] = [
    50, 100, 250, 500, 1000, 2000, 4000, 8000, 16000, 32000, 64000, 128000, 256000, 512000,
    1000000, 2000000, 5000000, 10000000,
];

/// One §6D-3 default-keyed latency distribution: cumulative buckets
/// in `le` order (`buckets[18]` counts ≤ `+Inf`, so `buckets[18] ==
/// count` always) plus saturating `sum` (ns) + `count`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TraceHistogram {
    /// Cumulative bucket counts (element `i` = observations ≤ edge
    /// `i`; element 18 = observations ≤ `+Inf`).
    pub buckets: [u64; 19],
    /// Saturating sum of folded durations (ns).
    pub sum: u64,
    /// Folded observation count.
    pub count: u64,
}

impl TraceHistogram {
    /// Fold one usable operational duration (ns, §6D-3).
    fn fold(&mut self, duration_ns: u64) {
        let mut index = TRACE_HISTOGRAM_EDGES.len();
        for (at, edge) in TRACE_HISTOGRAM_EDGES.iter().enumerate() {
            if duration_ns <= *edge {
                index = at;
                break;
            }
        }
        for bucket in self.buckets.iter_mut().skip(index) {
            *bucket = bucket.saturating_add(1);
        }
        self.sum = self.sum.saturating_add(duration_ns);
        self.count = self.count.saturating_add(1);
    }
}

/// Unpaired-exemplar direction (§6D-6).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExemplarDir {
    /// Unpaired ATTEMPT.
    Entry,
    /// Unpaired RESULT.
    Result,
}

/// Unpaired exemplar key (§6D-6): hashes, never raw cookies.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TraceExemplar {
    /// Direction.
    pub dir: ExemplarDir,
    /// `key_hash16` of the key.
    pub key_hash16: String,
    /// API ID.
    pub api: u32,
    /// Close-time age in ns.
    pub age_ns: u64,
}

/// Retained detail rows per window (§6D-5: 4096).
pub const TRACE_DETAIL_MAX_ROWS: usize = 4096;
/// Retained detail bytes per window (§6D-5: 1 MiB).
pub const TRACE_DETAIL_MAX_BYTES: usize = 1_048_576;

/// Pairing-correctness cap, G1 (§6D-5 reading): ACCOUNTING
/// (distributions + counters) is O(1) fixed small state, but
/// pairing-correctness state (pending/HW) CANNOT be O(1) —
/// distinguishing dup from fresh needs consumed-memory (proven
/// by F3) — so it is FIXED-CAPPED correctness state with
/// kernel-mirrored bounds. BPF `PENDING`/`THREADS`/`API_THREADS`
/// are 4096-entry maps; the host mirrors 4096 per pairing
/// structure (pending ATTEMPTs, pending RESULTs, scopes,
/// tombstones). FIFO eviction (oldest first): every evicted
/// pending counts unpaired immediately (+ exemplar) but NEVER
/// advances the high-water (eviction ≠ consumption — the
/// counterpart may still arrive; terminal buckets stay
/// correct). Single-sourced from the kernel bound so the
/// mirror cannot drift.
pub const TRACE_PAIRING_CAP: usize = c::MAX_PENDING as usize;

/// One retained detail row: a received edge.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RetainedEdge {
    /// 1 = ATTEMPT, 2 = RESULT.
    pub kind: u32,
    /// Hash-bound pair key (never the raw cookie).
    pub key: HashedKey,
    /// API ID.
    pub api: u32,
    /// Producer timestamp.
    pub monotonic_ns: u64,
    /// RAW outcome word (0 on ATTEMPT).
    pub outcome: u32,
}

impl RetainedEdge {
    /// Accounted bytes: canonical compact-encoding length
    /// (`{"k":…,"pid":…,"tid":…,"gen":…,"h":"…","inv":…,"api":…,"ns":…,"o":…}`).
    pub fn retained_bytes(&self) -> usize {
        format!(
            "{{\"k\":{},\"pid\":{},\"tid\":{},\"gen\":{},\"h\":\"{}\",\"inv\":{},\"api\":{},\"ns\":{},\"o\":{}}}",
            self.kind,
            self.key.pid,
            self.key.tid,
            self.key.generation,
            self.key.key_hash16,
            self.key.invocation,
            self.api,
            self.monotonic_ns,
            self.outcome,
        )
        .len()
    }
}

/// Received-domain counts by family slot (§6D-10 bridge input).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ReceivedCounts {
    /// ATTEMPTs by family slot.
    pub attempts: [u64; 3],
    /// RESULTs by family slot.
    pub results: [u64; 3],
}

/// Sealed per-window trace record (data-plane half; JSON is T8.2b).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ClosedTraceWindow {
    /// Producer window sequence.
    pub window_seq: u64,
    /// Active mode word.
    pub mode: u32,
    /// Window pairs formed.
    pub paired: u64,
    /// Window unpaired ATTEMPTs.
    pub unpaired_entries: u64,
    /// Window unpaired RESULTs.
    pub unpaired_results: u64,
    /// Window received edges by family.
    pub received: ReceivedCounts,
    /// `LOSS_DEPTH` lane delta (IS the lane, §6D-4).
    pub depth_exceeded: u64,
    /// Dropped detail rows (§6D-5).
    pub dropped: u64,
    /// Cap-hit flag (§6D-5).
    pub capped: bool,
    /// Nonmonotonic pairs (§6D-3 sole accounting).
    pub nonmonotonic_pairs: u64,
    /// Decode-domain unknown-ID records (§6D-1).
    pub rejected_unknown_api: u64,
    /// Per-window lane deltas.
    pub ring_loss: [u64; 8],
    /// Retained detail rows (keep-first, capped).
    pub detail: Vec<RetainedEdge>,
    /// Window pairs by class ID (§6D-2/§6D-7 `class_window`; sums to
    /// `paired`. 2c projection order: success/failure/empty/retry/
    /// unknown = slots 1/2/3/4/0).
    pub class_counts: [u64; 5],
    /// Window latency distributions by class ID (§6D-3 default
    /// keying; operational pairs only).
    pub histograms: [TraceHistogram; 5],
    /// Window ATTEMPT edges by API ID (§6D-10 multiset/fetch
    /// inputs; slot 0 unused).
    pub api_attempts: [u64; 73],
    /// Window RESULT edges by API ID (slot 0 unused).
    pub api_results: [u64; 73],
    /// Exemplars (≤8 per direction).
    pub exemplars: Vec<TraceExemplar>,
}

/// Cumulative session totals.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TraceTotals {
    /// Cumulative pairs by class ID (2c's `class_epoch` input).
    pub class_counts: [u64; 5],
    /// Cumulative latency distributions by class ID.
    pub histograms: [TraceHistogram; 5],
    /// Cumulative pairs.
    pub paired: u64,
    /// Cumulative unpaired ATTEMPTs.
    pub unpaired_entries: u64,
    /// Cumulative unpaired RESULTs.
    pub unpaired_results: u64,
    /// Cumulative received edges by family.
    pub received: ReceivedCounts,
    /// Cumulative dropped detail rows.
    pub dropped: u64,
    /// Cumulative nonmonotonic pairs.
    pub nonmonotonic_pairs: u64,
    /// Cumulative unknown-ID records.
    pub rejected_unknown_api: u64,
    /// Windows closed.
    pub windows: u64,
    /// Capped windows.
    pub capped_windows: u64,
}

/// Trace data-plane producer: demux + pairing + caps + counters.
pub struct TraceProducer {
    /// Active mode word.
    mode: u32,
    /// Row budget.
    max_rows: usize,
    /// Byte budget.
    max_bytes: usize,
    /// Pending ATTEMPTs by key (G1: ≤ cap, FIFO-evicted).
    pending_attempts: HashMap<PairKey, PendingEdge>,
    /// FIFO index: (insert window, sequence) → key. Bounded by
    /// the cap (exactly one entry per pending).
    pending_attempt_order: BTreeMap<(u64, u64), PairKey>,
    /// Pending RESULTs by key (G1: ≤ cap, FIFO-evicted).
    pending_results: HashMap<PairKey, PendingEdge>,
    /// FIFO index for pending RESULTs (bounded by the cap).
    pending_result_order: BTreeMap<(u64, u64), PairKey>,
    /// Per-scope invocation high-water (F3: consumed keys never re-pair).
    inv_hw: HashMap<ScopeKey, ScopeHw>,
    /// FIFO index for scopes (bounded by the cap).
    scope_order: BTreeMap<(u64, u64), ScopeKey>,
    /// Insertion sequence (monotonic; wrapping — 2^64 inserts
    /// unreachable, and every index entry dies with its map).
    order_seq: u64,
    /// Current window sequence.
    window: u64,
    /// Last-seen cumulative lanes.
    last_loss: [u64; 8],
    /// Cumulative totals.
    totals: TraceTotals,
    /// Window detail rows.
    detail: Vec<RetainedEdge>,
    /// Window detail bytes.
    detail_bytes: usize,
    /// Window cap flag.
    capped: bool,
    /// Window dropped rows.
    dropped: u64,
    /// Window pairs by class ID.
    class_counts: [u64; 5],
    /// Window latency distributions by class ID.
    histograms: [TraceHistogram; 5],
    /// Window ATTEMPT edges by API ID.
    api_attempts: [u64; 73],
    /// Window RESULT edges by API ID.
    api_results: [u64; 73],
    /// Window exemplars.
    exemplars: Vec<TraceExemplar>,
    /// Window paired count.
    paired: u64,
    /// Window unpaired ATTEMPTs.
    unpaired_entries: u64,
    /// Window unpaired RESULTs.
    unpaired_results: u64,
    /// Window received.
    received: ReceivedCounts,
    /// Window nonmonotonic pairs.
    nonmonotonic_pairs: u64,
    /// Window rejected records.
    rejected_unknown_api: u64,
}

/// A held edge awaiting its counterpart (N → N+1 carry).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct PendingEdge {
    /// Window of arrival.
    window: u64,
    /// API ID.
    api: u32,
    /// Producer timestamp.
    monotonic_ns: u64,
    /// RAW outcome (RESULT only).
    outcome: u32,
    /// Insertion sequence (FIFO order key with `window`).
    seq: u64,
}

/// Pairing scope: the THREADS-row scope (contract `ThreadKey` —
/// `pid`, `tid`, `generation` — the key `invocation` counts under).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct ScopeKey {
    /// Executing pid.
    pid: u32,
    /// Executing tid.
    tid: u32,
    /// Scope/authority generation.
    generation: u64,
}

impl ScopeKey {
    /// Project a full pairing key to its scope.
    fn of(key: &PairKey) -> Self {
        Self {
            pid: key.pid,
            tid: key.tid,
            generation: key.generation,
        }
    }
}

/// Per-scope invocation high-water (F3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct ScopeHw {
    /// Highest consumed invocation, once any pair/expiry/finalize
    /// ran in this scope (`None` = nothing consumed yet).
    hw: Option<u64>,
    /// Internal window of the last observed edge in this scope.
    last_window: u64,
    /// Insertion window (FIFO order key with `seq`; NEVER
    /// refreshed — eviction is insertion-ordered, not LRU).
    insert_window: u64,
    /// Insertion sequence.
    seq: u64,
}

impl TraceProducer {
    /// Frozen defaults: mode off, §6D-5 caps.
    pub fn new() -> Self {
        Self::with_caps(TRACE_DETAIL_MAX_ROWS, TRACE_DETAIL_MAX_BYTES)
    }

    /// Test/custom budgets; production uses [`TraceProducer::new`].
    pub fn with_caps(max_rows: usize, max_bytes: usize) -> Self {
        Self {
            mode: TRACE_MODE_OFF,
            max_rows,
            max_bytes,
            pending_attempts: HashMap::new(),
            pending_attempt_order: BTreeMap::new(),
            pending_results: HashMap::new(),
            pending_result_order: BTreeMap::new(),
            inv_hw: HashMap::new(),
            scope_order: BTreeMap::new(),
            order_seq: 0,
            window: 0,
            last_loss: [0; 8],
            totals: TraceTotals::default(),
            detail: Vec::new(),
            detail_bytes: 0,
            capped: false,
            dropped: 0,
            class_counts: [0; 5],
            histograms: [TraceHistogram::default(); 5],
            api_attempts: [0; 73],
            api_results: [0; 73],
            exemplars: Vec::new(),
            paired: 0,
            unpaired_entries: 0,
            unpaired_results: 0,
            received: ReceivedCounts::default(),
            nonmonotonic_pairs: 0,
            rejected_unknown_api: 0,
        }
    }

    /// Host mode gate (BPF map programmed separately by the session).
    pub fn set_mode(&mut self, mode: u32) {
        self.mode = mode;
    }

    /// Active mode word.
    pub fn mode(&self) -> u32 {
        self.mode
    }

    /// Feed a decoded ATTEMPT (received always counted; pairing gated).
    pub fn attempt(&mut self, edge: AttemptEdge) {
        if let Some(family) = demux(edge.api) {
            let slot = family.index();
            self.received.attempts[slot] = self.received.attempts[slot].saturating_add(1);
            self.totals.received.attempts[slot] =
                self.totals.received.attempts[slot].saturating_add(1);
        }
        // F2: received-domain per-API partition (§6D-10
        // multiset/fetch inputs) — folds for EVERY edge
        // regardless of mode or caps.
        if (edge.api as usize) < self.api_attempts.len() {
            let slot = edge.api as usize;
            self.api_attempts[slot] = self.api_attempts[slot].saturating_add(1);
        }
        if !trace_mode_edge_bearing(self.mode) {
            return;
        }
        self.retain(RetainedEdge {
            kind: 1,
            key: HashedKey::of(&edge.key),
            api: edge.api,
            monotonic_ns: edge.monotonic_ns,
            outcome: 0,
        });
        self.touch_scope(&edge.key);
        // F4: a held RESULT pairs only in its arrival window
        // (frozen §6D-6 is forward-only: the RESULT lands in the
        // ATTEMPT's SAME or NEXT window — same-window inversion
        // still pairs, cross-window reverse carry never does).
        let held_same_window = self
            .pending_results
            .get(&edge.key)
            .is_some_and(|held| held.window == self.window);
        if held_same_window {
            let held = self
                .pending_result_remove(&edge.key)
                .expect("held RESULT just observed");
            self.pair(
                edge.key,
                edge.api,
                edge.monotonic_ns,
                held.monotonic_ns,
                held.outcome,
            );
        } else if self.pending_results.contains_key(&edge.key) {
            // G2: cross-window held RESULT — STALE. It can never
            // pair afterward (any same-key future ATTEMPT lands
            // same-or-later window = reverse or dup), so evict it
            // as unpaired-R immediately (+ exemplar, no HW
            // advance — the newcomer below may be the legitimate
            // pair). Killing it at block time leaves no lingering
            // dead state whose liveness could shield later dups
            // from the high-water; window attribution is identical
            // to close-expiry. Load-bearing order: evict-stale →
            // HW → pending.
            if let Some(held) = self.pending_result_remove(&edge.key) {
                self.unpaired_results = self.unpaired_results.saturating_add(1);
                self.totals.unpaired_results = self.totals.unpaired_results.saturating_add(1);
                self.push_live_exemplar(ExemplarDir::Result, edge.key, held.api);
            }
            if self.is_hw_dup(&edge.key) {
                self.unpaired_entries = self.unpaired_entries.saturating_add(1);
                self.totals.unpaired_entries = self.totals.unpaired_entries.saturating_add(1);
            } else if self.pending_attempts.contains_key(&edge.key) {
                // The anomaly when an ATTEMPT is already live
                // (same bucket as the HW-dup above — both
                // conserve the newcomer as unpaired immediately).
                self.unpaired_entries = self.unpaired_entries.saturating_add(1);
                self.totals.unpaired_entries = self.totals.unpaired_entries.saturating_add(1);
            } else {
                // Fresh key: pending-then-correct as before.
                self.pending_attempt_insert(edge.key, edge.api, edge.monotonic_ns);
            }
        } else if self.pending_attempts.contains_key(&edge.key) {
            // Duplicate ATTEMPT on a live key (BPF never emits this):
            // the newcomer is the anomaly — conserve it as unpaired
            // immediately and keep the pairable original pending.
            self.unpaired_entries = self.unpaired_entries.saturating_add(1);
            self.totals.unpaired_entries = self.totals.unpaired_entries.saturating_add(1);
        } else if self.is_hw_dup(&edge.key) {
            // F3: consumed-or-older invocation with no live state —
            // a replay, never a re-pair (frozen §6D-6).
            self.unpaired_entries = self.unpaired_entries.saturating_add(1);
            self.totals.unpaired_entries = self.totals.unpaired_entries.saturating_add(1);
        } else {
            self.pending_attempt_insert(edge.key, edge.api, edge.monotonic_ns);
        }
    }

    /// Feed a decoded RESULT (received always counted; pairing gated).
    pub fn result(&mut self, edge: ResultEdge) {
        if let Some(family) = demux(edge.api) {
            let slot = family.index();
            self.received.results[slot] = self.received.results[slot].saturating_add(1);
            self.totals.received.results[slot] =
                self.totals.received.results[slot].saturating_add(1);
        }
        // F2: received-domain per-API partition — folds for EVERY
        // edge regardless of mode or caps.
        if (edge.api as usize) < self.api_results.len() {
            let slot = edge.api as usize;
            self.api_results[slot] = self.api_results[slot].saturating_add(1);
        }
        if !trace_mode_edge_bearing(self.mode) {
            return;
        }
        self.retain(RetainedEdge {
            kind: 2,
            key: HashedKey::of(&edge.key),
            api: edge.api,
            monotonic_ns: edge.monotonic_ns,
            outcome: edge.outcome,
        });
        self.touch_scope(&edge.key);
        if let Some(held) = self.pending_attempt_remove(&edge.key) {
            self.pair(
                edge.key,
                held.api,
                held.monotonic_ns,
                edge.monotonic_ns,
                edge.outcome,
            );
        } else if self.pending_results.contains_key(&edge.key) {
            // Duplicate RESULT on a live key: conserve the newcomer
            // as unpaired immediately, keep the original pending.
            self.unpaired_results = self.unpaired_results.saturating_add(1);
            self.totals.unpaired_results = self.totals.unpaired_results.saturating_add(1);
        } else if self.is_hw_dup(&edge.key) {
            // F3: consumed-or-older invocation with no live state —
            // a replay, never a re-pair (frozen §6D-6).
            self.unpaired_results = self.unpaired_results.saturating_add(1);
            self.totals.unpaired_results = self.totals.unpaired_results.saturating_add(1);
        } else {
            self.pending_result_insert(edge.key, edge.api, edge.monotonic_ns, edge.outcome);
        }
    }

    /// Count one decode-domain unknown-ID record.
    pub fn reject_unknown(&mut self) {
        self.rejected_unknown_api = self.rejected_unknown_api.saturating_add(1);
        self.totals.rejected_unknown_api = self.totals.rejected_unknown_api.saturating_add(1);
    }

    /// Seal the current window; `loss_abs` is the cumulative 8-lane read.
    pub fn close_window(
        &mut self,
        window_seq: u64,
        now_ns: u64,
        loss_abs: [u64; 8],
    ) -> ClosedTraceWindow {
        let current = self.window;
        // G1: close-time stale-key vectors are bounded by the
        // caps — at most one stale key per held edge (no change).
        let stale_attempts: Vec<PairKey> = self
            .pending_attempts
            .iter()
            .filter(|(_, held)| held.window < current)
            .map(|(key, _)| *key)
            .collect();
        for key in stale_attempts {
            if let Some(held) = self.pending_attempt_remove(&key) {
                self.unpaired_entries = self.unpaired_entries.saturating_add(1);
                self.totals.unpaired_entries = self.totals.unpaired_entries.saturating_add(1);
                self.push_exemplar(ExemplarDir::Entry, key, held, now_ns);
                self.advance_hw(&key);
            }
        }
        let stale_results: Vec<PairKey> = self
            .pending_results
            .iter()
            .filter(|(_, held)| held.window < current)
            .map(|(key, _)| *key)
            .collect();
        for key in stale_results {
            if let Some(held) = self.pending_result_remove(&key) {
                self.unpaired_results = self.unpaired_results.saturating_add(1);
                self.totals.unpaired_results = self.totals.unpaired_results.saturating_add(1);
                self.push_exemplar(ExemplarDir::Result, key, held, now_ns);
                self.advance_hw(&key);
            }
        }
        // F3: scopes idle >1 window drop their high-water at roll.
        // Residual (disclosed): an ancient replay after expiry can
        // re-pair. BPF never emits dups — a replay implies
        // host-side duplication, and live pending always keeps its
        // scope (pending arrives recently by construction).
        let current = self.window;
        let idle_scopes: Vec<ScopeKey> = self
            .inv_hw
            .iter()
            .filter(|(_, scope)| current.saturating_sub(scope.last_window) > 1)
            .map(|(scope, _)| *scope)
            .collect();
        // G1: bounded by the scope cap (one entry per scope).
        for scope in idle_scopes {
            if let Some(hw) = self.inv_hw.remove(&scope) {
                self.scope_order.remove(&(hw.insert_window, hw.seq));
            }
        }
        let mut ring_loss = [0u64; 8];
        for index in 0..8 {
            ring_loss[index] = loss_abs[index].saturating_sub(self.last_loss[index]);
            self.last_loss[index] = loss_abs[index];
        }
        let sealed = ClosedTraceWindow {
            window_seq,
            mode: self.mode,
            paired: self.paired,
            unpaired_entries: self.unpaired_entries,
            unpaired_results: self.unpaired_results,
            received: self.received,
            depth_exceeded: ring_loss[2],
            dropped: self.dropped,
            capped: self.capped,
            nonmonotonic_pairs: self.nonmonotonic_pairs,
            rejected_unknown_api: self.rejected_unknown_api,
            ring_loss,
            detail: std::mem::take(&mut self.detail),
            class_counts: std::mem::take(&mut self.class_counts),
            histograms: std::mem::take(&mut self.histograms),
            api_attempts: std::mem::replace(&mut self.api_attempts, [0; 73]),
            api_results: std::mem::replace(&mut self.api_results, [0; 73]),
            exemplars: std::mem::take(&mut self.exemplars),
        };
        if sealed.capped {
            self.totals.capped_windows = self.totals.capped_windows.saturating_add(1);
        }
        self.totals.windows = self.totals.windows.saturating_add(1);
        self.detail_bytes = 0;
        self.capped = false;
        self.dropped = 0;
        self.paired = 0;
        self.unpaired_entries = 0;
        self.unpaired_results = 0;
        self.received = ReceivedCounts::default();
        self.nonmonotonic_pairs = 0;
        self.rejected_unknown_api = 0;
        self.window = self.window.saturating_add(1);
        sealed
    }

    /// Terminal finalize: every held edge lands unpaired.
    pub fn finalize(&mut self, now_ns: u64) {
        for (key, held) in std::mem::take(&mut self.pending_attempts) {
            self.unpaired_entries = self.unpaired_entries.saturating_add(1);
            self.totals.unpaired_entries = self.totals.unpaired_entries.saturating_add(1);
            self.push_exemplar(ExemplarDir::Entry, key, held, now_ns);
            self.advance_hw(&key);
        }
        self.pending_attempt_order.clear();
        for (key, held) in std::mem::take(&mut self.pending_results) {
            self.unpaired_results = self.unpaired_results.saturating_add(1);
            self.totals.unpaired_results = self.totals.unpaired_results.saturating_add(1);
            self.push_exemplar(ExemplarDir::Result, key, held, now_ns);
            self.advance_hw(&key);
        }
        self.pending_result_order.clear();
    }

    /// Cumulative totals.
    pub fn totals(&self) -> TraceTotals {
        self.totals
    }

    /// Next FIFO insertion sequence.
    fn next_seq(&mut self) -> u64 {
        let seq = self.order_seq;
        self.order_seq = self.order_seq.wrapping_add(1);
        seq
    }

    /// Insert a held ATTEMPT (G1: cap-enforced FIFO). Callers
    /// insert absent keys — a present key is replaced with its
    /// index entry refreshed so the order index stays exact.
    fn pending_attempt_insert(&mut self, key: PairKey, api: u32, monotonic_ns: u64) {
        if let Some(old) = self.pending_attempts.get(&key) {
            let order = (old.window, old.seq);
            self.pending_attempt_order.remove(&order);
        }
        if self.pending_attempts.len() >= TRACE_PAIRING_CAP {
            self.evict_oldest_attempt();
        }
        let window = self.window;
        let seq = self.next_seq();
        self.pending_attempt_order.insert((window, seq), key);
        self.pending_attempts.insert(
            key,
            PendingEdge {
                window,
                api,
                monotonic_ns,
                outcome: 0,
                seq,
            },
        );
    }

    /// Index-maintaining removal of a held ATTEMPT.
    fn pending_attempt_remove(&mut self, key: &PairKey) -> Option<PendingEdge> {
        let held = self.pending_attempts.remove(key)?;
        self.pending_attempt_order.remove(&(held.window, held.seq));
        Some(held)
    }

    /// Insert a held RESULT (G1: cap-enforced FIFO).
    fn pending_result_insert(&mut self, key: PairKey, api: u32, monotonic_ns: u64, outcome: u32) {
        if let Some(old) = self.pending_results.get(&key) {
            let order = (old.window, old.seq);
            self.pending_result_order.remove(&order);
        }
        if self.pending_results.len() >= TRACE_PAIRING_CAP {
            self.evict_oldest_result();
        }
        let window = self.window;
        let seq = self.next_seq();
        self.pending_result_order.insert((window, seq), key);
        self.pending_results.insert(
            key,
            PendingEdge {
                window,
                api,
                monotonic_ns,
                outcome,
                seq,
            },
        );
    }

    /// Index-maintaining removal of a held RESULT.
    fn pending_result_remove(&mut self, key: &PairKey) -> Option<PendingEdge> {
        let held = self.pending_results.remove(key)?;
        self.pending_result_order.remove(&(held.window, held.seq));
        Some(held)
    }

    /// Evict the oldest pending ATTEMPT (FIFO cap enforcement):
    /// visible unpaired count + exemplar, NEVER an HW advance
    /// (eviction ≠ consumption — the counterpart may still
    /// arrive; terminal buckets stay correct).
    fn evict_oldest_attempt(&mut self) {
        let Some((&order, &key)) = self.pending_attempt_order.iter().next() else {
            return;
        };
        self.pending_attempt_order.remove(&order);
        if let Some(held) = self.pending_attempts.remove(&key) {
            self.unpaired_entries = self.unpaired_entries.saturating_add(1);
            self.totals.unpaired_entries = self.totals.unpaired_entries.saturating_add(1);
            self.push_live_exemplar(ExemplarDir::Entry, key, held.api);
        }
    }

    /// Evict the oldest pending RESULT (FIFO cap enforcement):
    /// visible unpaired count + exemplar, never an HW advance.
    fn evict_oldest_result(&mut self) {
        let Some((&order, &key)) = self.pending_result_order.iter().next() else {
            return;
        };
        self.pending_result_order.remove(&order);
        if let Some(held) = self.pending_results.remove(&key) {
            self.unpaired_results = self.unpaired_results.saturating_add(1);
            self.totals.unpaired_results = self.totals.unpaired_results.saturating_add(1);
            self.push_live_exemplar(ExemplarDir::Result, key, held.api);
        }
    }

    /// Evict the oldest scope (FIFO): drops HW ONLY — pending
    /// entries are self-sufficient (keyed pairing needs no HW),
    /// so held pairs still complete. Disclosed residual: a
    /// consumed key in an evicted scope can re-pair (same class
    /// as the idle-expiry residual).
    fn evict_oldest_scope(&mut self) {
        let Some((&order, &scope)) = self.scope_order.iter().next() else {
            return;
        };
        self.scope_order.remove(&order);
        self.inv_hw.remove(&scope);
    }

    /// Cap-enforced scope entry (sole scope-insert path: touch +
    /// HW advance both funnel here).
    fn scope_or_insert(&mut self, scope: ScopeKey) -> &mut ScopeHw {
        if !self.inv_hw.contains_key(&scope) {
            if self.inv_hw.len() >= TRACE_PAIRING_CAP {
                self.evict_oldest_scope();
            }
            let window = self.window;
            let seq = self.next_seq();
            self.scope_order.insert((window, seq), scope);
            self.inv_hw.insert(
                scope,
                ScopeHw {
                    hw: None,
                    last_window: window,
                    insert_window: window,
                    seq,
                },
            );
        }
        self.inv_hw.get_mut(&scope).expect("scope just inserted")
    }

    /// Mark scope activity: every post-gate edge arrival stamps the
    /// scope's window (idle-drop keys on arrivals only).
    fn touch_scope(&mut self, key: &PairKey) {
        let window = self.window;
        self.scope_or_insert(ScopeKey::of(key)).last_window = window;
    }

    /// F3 replay check: a consumed-or-older invocation with NO live
    /// state is a dup. Call only when no pending entry holds `key`
    /// in either direction — live state means unconsumed (nested
    /// per-thread invocations interleave, so a live counterpart
    /// always pairs and the high-water never overrides it).
    fn is_hw_dup(&self, key: &PairKey) -> bool {
        self.inv_hw
            .get(&ScopeKey::of(key))
            .is_some_and(|scope| scope.hw.is_some_and(|hw| key.invocation <= hw))
    }

    /// Advance the scope high-water past a consumed invocation
    /// (pair/expiry/finalize). Deliberately not activity: the
    /// idle-drop clock runs on arrivals, not bookkeeping.
    fn advance_hw(&mut self, key: &PairKey) {
        let entry = self.scope_or_insert(ScopeKey::of(key));
        entry.hw = Some(entry.hw.map_or(key.invocation, |hw| hw.max(key.invocation)));
    }

    fn pair(&mut self, key: PairKey, api: u32, attempt_ns: u64, result_ns: u64, outcome: u32) {
        self.advance_hw(&key);
        let class = pair_class(api, outcome);
        // §6D-3: zero/negative deltas are unusable durations but real pairs.
        let nonmonotonic = result_ns <= attempt_ns;
        let duration_ns = if nonmonotonic {
            0
        } else {
            result_ns - attempt_ns
        };
        // F2: streaming fold into fixed small state (5 class counts
        // + 5 distributions + counters) — exact under caps. "Pairs
        // COMPLETE under caps" (§6D-5) means counts complete:
        // retaining every pair row would contradict
        // fixed-small-state, so no pair rows are kept.
        let slot = class as usize;
        self.class_counts[slot] = self.class_counts[slot].saturating_add(1);
        self.totals.class_counts[slot] = self.totals.class_counts[slot].saturating_add(1);
        if !nonmonotonic && demux(api) == Some(TraceFamily::PublicApi) {
            self.histograms[slot].fold(duration_ns);
            self.totals.histograms[slot].fold(duration_ns);
        }
        self.paired = self.paired.saturating_add(1);
        self.totals.paired = self.totals.paired.saturating_add(1);
        if nonmonotonic {
            self.nonmonotonic_pairs = self.nonmonotonic_pairs.saturating_add(1);
            self.totals.nonmonotonic_pairs = self.totals.nonmonotonic_pairs.saturating_add(1);
        }
    }

    fn retain(&mut self, row: RetainedEdge) {
        if self.capped {
            self.dropped = self.dropped.saturating_add(1);
            self.totals.dropped = self.totals.dropped.saturating_add(1);
            return;
        }
        let bytes = row.retained_bytes();
        if self.detail.len() >= self.max_rows
            || self.detail_bytes.saturating_add(bytes) > self.max_bytes
        {
            self.capped = true;
            self.dropped = self.dropped.saturating_add(1);
            self.totals.dropped = self.totals.dropped.saturating_add(1);
            return;
        }
        self.detail.push(row);
        self.detail_bytes = self.detail_bytes.saturating_add(bytes);
    }

    fn push_exemplar(&mut self, dir: ExemplarDir, key: PairKey, held: PendingEdge, now_ns: u64) {
        let seen = self.exemplars.iter().filter(|e| e.dir == dir).count();
        if seen >= 8 {
            return;
        }
        self.exemplars.push(TraceExemplar {
            dir,
            key_hash16: key_hash16(key.cookie, key.generation),
            api: held.api,
            age_ns: now_ns.saturating_sub(held.monotonic_ns),
        });
    }

    /// Live exemplar (eviction/immediate paths): the feed path
    /// carries no clock, so age is 0 (just observed — for an
    /// evicted hold this understates its hold time; the count,
    /// never the age, is the conserved quantity). Self-capping
    /// (≤8 per direction per window) like close-time exemplars.
    fn push_live_exemplar(&mut self, dir: ExemplarDir, key: PairKey, api: u32) {
        let seen = self.exemplars.iter().filter(|e| e.dir == dir).count();
        if seen >= 8 {
            return;
        }
        self.exemplars.push(TraceExemplar {
            dir,
            key_hash16: key_hash16(key.cookie, key.generation),
            api,
            age_ns: 0,
        });
    }

    /// Test-only FIFO-index integrity pin: every index entry
    /// resolves to its map entry and back.
    #[cfg(test)]
    fn check_indexes(&self) {
        assert_eq!(
            self.pending_attempts.len(),
            self.pending_attempt_order.len(),
            "attempt index"
        );
        assert_eq!(
            self.pending_results.len(),
            self.pending_result_order.len(),
            "result index"
        );
        assert_eq!(self.inv_hw.len(), self.scope_order.len(), "scope index");
        for ((window, seq), key) in &self.pending_attempt_order {
            let held = self
                .pending_attempts
                .get(key)
                .expect("attempt order resolves");
            assert_eq!((held.window, held.seq), (*window, *seq));
        }
        for ((window, seq), key) in &self.pending_result_order {
            let held = self
                .pending_results
                .get(key)
                .expect("result order resolves");
            assert_eq!((held.window, held.seq), (*window, *seq));
        }
        for ((window, seq), scope) in &self.scope_order {
            let hw = self.inv_hw.get(scope).expect("scope order resolves");
            assert_eq!((hw.insert_window, hw.seq), (*window, *seq));
        }
    }
}

impl Default for TraceProducer {
    fn default() -> Self {
        Self::new()
    }
}

/// Subset check (§6D-4): trace depth overflow ⊇ aggregate depth overflow.
pub fn depth_subset_holds(trace_depth_exceeded: u64, aggregate_depth: u64) -> bool {
    trace_depth_exceeded >= aggregate_depth
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(pid: u32, tid: u32, generation: u64, cookie: u64, invocation: u64) -> PairKey {
        PairKey {
            pid,
            tid,
            generation,
            cookie,
            invocation,
        }
    }

    fn attempt(key: PairKey, api: u32, ns: u64) -> AttemptEdge {
        AttemptEdge {
            key,
            api,
            monotonic_ns: ns,
        }
    }

    fn result(key: PairKey, api: u32, ns: u64, outcome: u32) -> ResultEdge {
        ResultEdge {
            key,
            api,
            monotonic_ns: ns,
            outcome,
        }
    }

    fn edge_bearing() -> TraceProducer {
        let mut p = TraceProducer::new();
        p.set_mode(TRACE_MODE_LATENCY);
        p
    }

    #[test]
    fn mode_words_match_frozen_order() {
        assert_eq!(
            (
                TRACE_MODE_OFF,
                TRACE_MODE_METADATA,
                TRACE_MODE_LATENCY,
                TRACE_MODE_STATUS,
                TRACE_MODE_ALL
            ),
            (0, 1, 2, 3, 4)
        );
        for mode in [0, 1, 5, 6, 100, u32::MAX] {
            assert!(!trace_mode_edge_bearing(mode), "mode {mode}");
        }
        for mode in [2, 3, 4] {
            assert!(trace_mode_edge_bearing(mode), "mode {mode}");
        }
    }

    #[test]
    fn demux_families_are_exact() {
        for api in (1..=9).chain(16..=19) {
            assert_eq!(demux(api), Some(TraceFamily::Lifecycle), "api {api}");
        }
        for api in 10..=15 {
            assert_eq!(demux(api), Some(TraceFamily::Fetch), "api {api}");
        }
        for api in 20..=72 {
            assert_eq!(demux(api), Some(TraceFamily::PublicApi), "api {api}");
        }
        for api in [0, 73, 74, 100, 1000, u32::MAX] {
            assert_eq!(demux(api), None, "api {api}");
        }
        assert_eq!(
            (
                TraceFamily::Lifecycle.index(),
                TraceFamily::Fetch.index(),
                TraceFamily::PublicApi.index()
            ),
            (0, 1, 2)
        );
    }

    #[test]
    fn key_hash16_vector_and_scoping() {
        assert_eq!(key_hash16(1, 1), "814dd7b9784d57c1");
        assert_eq!(key_hash16(1, 2), "0c730b69905c5ef7");
        assert_eq!(key_hash16(7, 1), "70bed0fe3b332b7b");
        let h = key_hash16(12345, 67890);
        assert_eq!(h.len(), 16);
        assert!(
            h.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert_ne!(key_hash16(9, 3), key_hash16(9, 4));
    }

    #[test]
    fn pairing_basic_and_raw_class() {
        let mut p = edge_bearing();
        let k = key(10, 11, 1, 100, 7);
        p.attempt(attempt(k, 20, 1000));
        p.result(result(k, 20, 1500, 3));
        let w = p.close_window(0, 2000, [0; 8]);
        assert_eq!(w.paired, 1);
        assert_eq!(w.unpaired_entries, 0);
        assert_eq!(w.unpaired_results, 0);
        assert_eq!(w.class_counts, [0, 0, 0, 1, 0]);
        assert_eq!(w.nonmonotonic_pairs, 0);
        let h = &w.histograms[3];
        assert_eq!((h.count, h.sum), (1, 500));
        assert_eq!(&h.buckets[0..3], &[0, 0, 0]);
        assert_eq!(h.buckets[3], 1);
        assert_eq!(h.buckets[18], h.count);
        assert_eq!(w.received.attempts, [0, 0, 1]);
        assert_eq!(w.received.results, [0, 0, 1]);
    }

    #[test]
    fn pairing_second_result_is_unpaired() {
        let mut p = edge_bearing();
        let k = key(10, 11, 1, 100, 7);
        p.attempt(attempt(k, 20, 1000));
        p.result(result(k, 20, 1500, 1));
        p.result(result(k, 20, 1600, 1));
        p.finalize(2000);
        let t = p.totals();
        assert_eq!(t.paired, 1);
        assert_eq!(t.unpaired_results, 1);
        assert_eq!(t.unpaired_entries, 0);
        assert_eq!(t.received.attempts, [0, 0, 1]);
        assert_eq!(t.received.results, [0, 0, 2]);
    }

    #[test]
    fn invocation_high_water_blocks_repair() {
        // F3 (codex R1-3): A R R A on one key → 1 pair +
        // 1 unpaired-R + 1 unpaired-A (frozen §6D-6: a second
        // RESULT on a consumed key is unpaired, never a re-pair).
        let mut p = edge_bearing();
        let k = key(10, 11, 1, 100, 7);
        p.attempt(attempt(k, 20, 1000));
        p.result(result(k, 20, 1500, 1));
        p.result(result(k, 20, 1600, 1));
        p.attempt(attempt(k, 20, 1700));
        p.finalize(2000);
        let t = p.totals();
        assert_eq!(t.paired, 1);
        assert_eq!(t.unpaired_results, 1);
        assert_eq!(t.unpaired_entries, 1);
        let ra: u64 = t.received.attempts.iter().sum();
        let rr: u64 = t.received.results.iter().sum();
        assert_eq!(ra, t.paired + t.unpaired_entries);
        assert_eq!(rr, t.paired + t.unpaired_results);
    }

    #[test]
    fn high_water_keeps_nested_pairs() {
        // F3 refinement pin: per-thread invocations interleave
        // under nesting (outer A5, inner A6/R6, outer R5); a live
        // counterpart always pairs — the high-water never
        // overrides live pending state.
        let mut p = edge_bearing();
        let outer = key(10, 11, 1, 100, 5);
        let inner = key(10, 11, 1, 200, 6);
        p.attempt(attempt(outer, 20, 1000));
        p.attempt(attempt(inner, 22, 1100));
        p.result(result(inner, 22, 1500, 1));
        p.result(result(outer, 20, 1600, 1));
        p.finalize(2000);
        let t = p.totals();
        assert_eq!(
            (t.paired, t.unpaired_entries, t.unpaired_results),
            (2, 0, 0)
        );
    }

    #[test]
    fn high_water_blocks_cross_window_dups() {
        // F3: a consumed key replayed in the next window yields
        // dups, never a re-pair; conservation stays exact.
        let mut p = edge_bearing();
        let k = key(10, 11, 1, 100, 7);
        p.attempt(attempt(k, 20, 1000));
        p.result(result(k, 20, 1500, 1));
        p.close_window(0, 2000, [0; 8]);
        p.attempt(attempt(k, 20, 2500));
        p.result(result(k, 20, 2600, 1));
        p.finalize(3000);
        let t = p.totals();
        assert_eq!(t.paired, 1);
        assert_eq!(t.unpaired_entries, 1);
        assert_eq!(t.unpaired_results, 1);
        let ra: u64 = t.received.attempts.iter().sum();
        let rr: u64 = t.received.results.iter().sum();
        assert_eq!(ra, t.paired + t.unpaired_entries);
        assert_eq!(rr, t.paired + t.unpaired_results);
    }

    #[test]
    fn scope_expiry_drops_idle_high_water() {
        // F3 disclosed residual: scopes idle >1 window drop
        // their high-water at roll, so an ancient replay after
        // expiry re-pairs (BPF never emits dups — replays only
        // arise from host-side duplication).
        let mut p = edge_bearing();
        let k = key(10, 11, 1, 100, 7);
        p.attempt(attempt(k, 20, 1000));
        p.result(result(k, 20, 1500, 1));
        p.close_window(0, 2000, [0; 8]);
        p.close_window(1, 3000, [0; 8]);
        p.close_window(2, 4000, [0; 8]);
        p.attempt(attempt(k, 20, 5000));
        p.result(result(k, 20, 5500, 1));
        p.finalize(6000);
        assert_eq!(p.totals().paired, 2);
    }

    #[test]
    fn pairing_carry_pairs_next_window() {
        let mut p = edge_bearing();
        let k = key(10, 11, 1, 100, 7);
        p.attempt(attempt(k, 20, 1000));
        let w0 = p.close_window(0, 1500, [0; 8]);
        assert_eq!(
            (w0.paired, w0.unpaired_entries, w0.unpaired_results),
            (0, 0, 0)
        );
        p.result(result(k, 20, 2500, 1));
        let w1 = p.close_window(1, 3000, [0; 8]);
        assert_eq!(w1.paired, 1);
        assert_eq!((w1.unpaired_entries, w1.unpaired_results), (0, 0));
    }

    #[test]
    fn reverse_carry_never_pairs() {
        // F4 (codex R1-4): R(N) → close → A(N+1) must NOT pair
        // (frozen §6D-6: the RESULT lands in the ATTEMPT's SAME
        // or NEXT window — forward only). R expires unpaired; A
        // goes pending, then pairs with a fresh RESULT
        // (pending-then-correct); conservation stays exact.
        let mut p = edge_bearing();
        let k = key(10, 11, 1, 100, 7);
        p.result(result(k, 20, 1000, 1));
        p.close_window(0, 1500, [0; 8]);
        p.attempt(attempt(k, 20, 2000));
        let w1 = p.close_window(1, 2500, [0; 8]);
        assert_eq!(w1.paired, 0);
        assert_eq!(w1.unpaired_results, 1);
        assert_eq!(w1.unpaired_entries, 0);
        p.result(result(k, 20, 3000, 1));
        p.finalize(3500);
        let t = p.totals();
        assert_eq!(t.paired, 1);
        assert_eq!((t.unpaired_entries, t.unpaired_results), (0, 1));
        let ra: u64 = t.received.attempts.iter().sum();
        let rr: u64 = t.received.results.iter().sum();
        assert_eq!(ra, t.paired + t.unpaired_entries);
        assert_eq!(rr, t.paired + t.unpaired_results);
    }

    #[test]
    fn f4_block_evicts_stale_orphan_never_repairs() {
        // G2 (codex R2-2): the exact 6-step trace. The stale
        // cross-window R-orphan is evicted as unpaired-R the
        // moment it blocks a same-key ATTEMPT (it can never pair
        // afterward), so its liveness cannot shield later dups
        // from the high-water: 1 pair + 1E + 2R.
        let mut p = edge_bearing();
        let k = key(10, 11, 1, 100, 7);
        p.result(result(k, 20, 1000, 1));
        p.close_window(0, 1500, [0; 8]);
        p.attempt(attempt(k, 20, 2000));
        p.result(result(k, 20, 2500, 1));
        p.attempt(attempt(k, 20, 2600));
        p.result(result(k, 20, 2700, 1));
        p.finalize(3000);
        let t = p.totals();
        assert_eq!(t.paired, 1);
        assert_eq!(t.unpaired_entries, 1);
        assert_eq!(t.unpaired_results, 2);
        let ra: u64 = t.received.attempts.iter().sum();
        let rr: u64 = t.received.results.iter().sum();
        assert_eq!(ra, t.paired + t.unpaired_entries);
        assert_eq!(rr, t.paired + t.unpaired_results);
        let w = p.close_window(1, 3100, [0; 8]);
        assert!(
            w.exemplars
                .iter()
                .any(|e| e.dir == ExemplarDir::Result && e.key_hash16 == key_hash16(100, 1)),
            "evicted orphan leaves a Result exemplar: {:?}",
            w.exemplars
        );
    }

    #[test]
    fn reverse_carry_without_early_close() {
        // G2: reverse carry WITHOUT the early close — the stale
        // R-orphan is evicted (visible) at the blocking ATTEMPT,
        // not at the next close; the fresh pair still completes.
        let mut p = edge_bearing();
        let k = key(10, 11, 1, 100, 7);
        p.result(result(k, 20, 1000, 1));
        p.close_window(0, 1500, [0; 8]);
        p.attempt(attempt(k, 20, 2000));
        assert_eq!(p.totals().unpaired_results, 1);
        p.result(result(k, 20, 2500, 1));
        p.close_window(1, 3000, [0; 8]);
        p.finalize(3500);
        let t = p.totals();
        assert_eq!(t.paired, 1);
        assert_eq!((t.unpaired_entries, t.unpaired_results), (0, 1));
        let ra: u64 = t.received.attempts.iter().sum();
        let rr: u64 = t.received.results.iter().sum();
        assert_eq!(ra, t.paired + t.unpaired_entries);
        assert_eq!(rr, t.paired + t.unpaired_results);
    }

    #[test]
    fn same_window_inversion_still_pairs() {
        // F4: same-window R-then-A arrival inversion keeps
        // pairing (only the cross-window reverse carry is
        // forbidden).
        let mut p = edge_bearing();
        let k = key(10, 11, 1, 100, 7);
        p.result(result(k, 20, 1500, 1));
        p.attempt(attempt(k, 20, 1000));
        let w = p.close_window(0, 2000, [0; 8]);
        assert_eq!(w.paired, 1);
        assert_eq!((w.unpaired_entries, w.unpaired_results), (0, 0));
    }

    #[test]
    fn pairing_expires_after_carry_window() {
        let mut p = edge_bearing();
        let k = key(10, 11, 1, 100, 7);
        p.attempt(attempt(k, 20, 1000));
        p.close_window(0, 1500, [0; 8]);
        let w1 = p.close_window(1, 2500, [0; 8]);
        assert_eq!(w1.unpaired_entries, 1);
        assert_eq!(w1.paired, 0);
        assert_eq!(w1.exemplars.len(), 1);
        assert_eq!(w1.exemplars[0].dir, ExemplarDir::Entry);
        assert_eq!(w1.exemplars[0].key_hash16, key_hash16(100, 1));
    }

    #[test]
    fn pairing_cross_generation_forbidden() {
        let mut p = edge_bearing();
        p.attempt(attempt(key(10, 11, 1, 100, 7), 20, 1000));
        p.result(result(key(10, 11, 2, 100, 7), 20, 1500, 1));
        p.close_window(0, 2000, [0; 8]);
        p.close_window(1, 3000, [0; 8]);
        p.finalize(4000);
        let t = p.totals();
        assert_eq!(t.paired, 0);
        assert_eq!(t.unpaired_entries, 1);
        assert_eq!(t.unpaired_results, 1);
    }

    #[test]
    fn pairing_straddlers_unpaired_whole() {
        let mut p = edge_bearing();
        p.attempt(attempt(key(10, 11, 1, 100, 7), 20, 1000));
        p.result(result(key(10, 11, 1, 200, 8), 22, 1500, 1));
        p.close_window(0, 2000, [0; 8]);
        p.close_window(1, 3000, [0; 8]);
        let t = p.totals();
        assert_eq!(t.paired, 0);
        assert_eq!(t.unpaired_entries, 1);
        assert_eq!(t.unpaired_results, 1);
    }

    #[test]
    fn fetch_and_lifecycle_pairs_fold_class_zero() {
        // F5 (codex R1-5): fetch (10..=15) and lifecycle (1..=6)
        // pairs classify class 0 by function (frozen §6D-2 arm
        // 1 — `operational_api` covers 20..=72 only);
        // operational pairs keep the raw outcome class.
        // Per-family attribution, not global: each (api, class).
        let mut p = edge_bearing();
        let fetch = key(10, 11, 1, 100, 7);
        p.attempt(attempt(fetch, 10, 1000));
        p.result(result(fetch, 10, 1500, 1));
        let life = key(10, 11, 1, 101, 8);
        p.attempt(attempt(life, 2, 1100));
        p.result(result(life, 2, 1600, 2));
        let op = key(10, 11, 1, 102, 9);
        p.attempt(attempt(op, 20, 1200));
        p.result(result(op, 20, 1700, 3));
        let w = p.close_window(0, 2000, [0; 8]);
        assert_eq!(w.paired, 3);
        // Per-family attribution through the folds: fetch +
        // lifecycle land class-0, the operational pair keeps its
        // raw outcome class — and only the operational pair is
        // histogrammed (duration 500).
        assert_eq!(w.class_counts, [2, 0, 0, 1, 0]);
        assert_eq!(w.class_counts.iter().sum::<u64>(), w.paired);
        for (c, h) in w.histograms.iter().enumerate() {
            if c == 3 {
                assert_eq!((h.count, h.sum), (1, 500));
            } else {
                assert_eq!((h.count, h.sum), (0, 0), "class {c}");
            }
        }
        assert_eq!(
            (w.api_attempts[2], w.api_attempts[10], w.api_attempts[20]),
            (1, 1, 1)
        );
    }

    #[test]
    fn pair_class_normalizes_by_family() {
        // F5 helper pin: total over the demux, all five outcomes.
        for api in (1..=9).chain(10..=15).chain(16..=19) {
            for outcome in 0..=4 {
                assert_eq!(pair_class(api, outcome), 0, "api {api}");
            }
        }
        for api in 20..=72 {
            for outcome in 0..=4 {
                assert_eq!(pair_class(api, outcome), outcome, "api {api}");
            }
        }
        for api in [0, 73, 100, u32::MAX] {
            assert_eq!(pair_class(api, 1), 0, "api {api}");
        }
    }

    #[test]
    fn pairing_partition_is_exact() {
        let mut p = edge_bearing();
        for i in 0..50u64 {
            let k = key(10, 11, 1, 100 + i, i + 1);
            p.attempt(attempt(k, 20, 1000 + i));
            if i % 2 == 0 {
                p.result(result(k, 20, 2000 + i, 1));
            }
        }
        p.close_window(0, 5000, [0; 8]);
        p.close_window(1, 6000, [0; 8]);
        p.finalize(7000);
        let t = p.totals();
        let ra: u64 = t.received.attempts.iter().sum();
        let rr: u64 = t.received.results.iter().sum();
        assert_eq!(ra, t.paired + t.unpaired_entries);
        assert_eq!(rr, t.paired + t.unpaired_results);
        assert_eq!(
            (t.paired, t.unpaired_entries, t.unpaired_results),
            (25, 25, 0)
        );
    }

    #[test]
    fn mode_gate_ignores_edges_when_not_edge_bearing() {
        for mode in [TRACE_MODE_OFF, TRACE_MODE_METADATA] {
            let mut p = TraceProducer::new();
            p.set_mode(mode);
            let k = key(10, 11, 1, 100, 7);
            p.attempt(attempt(k, 20, 1000));
            p.result(result(k, 20, 1500, 1));
            p.attempt(attempt(key(10, 11, 1, 101, 8), 10, 1100));
            p.reject_unknown();
            p.close_window(0, 2000, [0; 8]);
            p.finalize(3000);
            let t = p.totals();
            assert_eq!(t.paired, 0, "mode {mode}");
            assert_eq!(t.unpaired_entries, 0, "mode {mode}");
            assert_eq!(t.unpaired_results, 0, "mode {mode}");
            assert_eq!(t.dropped, 0, "mode {mode}");
            let ra: u64 = t.received.attempts.iter().sum();
            assert_eq!(ra, 2, "mode {mode}: received still counted");
            assert_eq!(
                t.rejected_unknown_api, 1,
                "mode {mode}: rejected still counted"
            );
        }
    }

    #[test]
    fn frozen_caps_values() {
        assert_eq!(TRACE_DETAIL_MAX_ROWS, 4096);
        assert_eq!(TRACE_DETAIL_MAX_BYTES, 1_048_576);
    }

    #[test]
    fn pairing_cap_mirrors_kernel() {
        // G1: the host pairing bound IS the kernel PENDING bound
        // (single-sourced — the mirror cannot drift).
        assert_eq!(TRACE_PAIRING_CAP, 4096);
        assert_eq!(TRACE_PAIRING_CAP, c::MAX_PENDING as usize);
    }

    #[test]
    fn caps_rows_keep_first_and_pairs_survive() {
        let mut p = TraceProducer::with_caps(4, usize::MAX);
        p.set_mode(TRACE_MODE_ALL);
        for i in 0..10u64 {
            let k = key(10, 11, 1, 100 + i, i + 1);
            p.attempt(attempt(k, 20, 1000 + i));
            p.result(result(k, 20, 2000 + i, 1));
        }
        let w = p.close_window(0, 5000, [0; 8]);
        assert!(w.capped);
        assert_eq!(w.detail.len(), 4);
        assert_eq!(w.dropped, 16);
        assert_eq!(w.paired, 10);
        assert_eq!(w.class_counts.iter().sum::<u64>(), w.paired);
        assert_eq!(w.unpaired_entries, 0);
        assert_eq!(w.unpaired_results, 0);
    }

    #[test]
    fn caps_bytes_drop_detail_only() {
        let mut probe = TraceProducer::with_caps(usize::MAX, usize::MAX);
        probe.set_mode(TRACE_MODE_ALL);
        let k = key(10, 11, 1, 100, 7);
        probe.attempt(attempt(k, 20, 1000));
        let one = RetainedEdge {
            kind: 1,
            key: HashedKey::of(&k),
            api: 20,
            monotonic_ns: 1000,
            outcome: 0,
        }
        .retained_bytes();
        assert!(one > 0);

        let mut p = TraceProducer::with_caps(usize::MAX, one);
        p.set_mode(TRACE_MODE_ALL);
        for i in 0..4u64 {
            let k = key(10, 11, 1, 200 + i, i + 1);
            p.attempt(attempt(k, 20, 1000 + i));
            p.result(result(k, 20, 2000 + i, 1));
        }
        let w = p.close_window(0, 5000, [0; 8]);
        assert!(w.capped);
        assert_eq!(w.detail.len(), 1);
        assert_eq!(w.dropped, 7);
        assert_eq!(w.paired, 4);
        let t = p.totals();
        assert_eq!(t.capped_windows, 1);
        assert_eq!(t.dropped, 7);
    }

    #[test]
    fn nonmonotonic_pairs_counted_not_histogrammed() {
        let mut p = edge_bearing();
        let neg = key(10, 11, 1, 100, 7);
        p.attempt(attempt(neg, 20, 2000));
        p.result(result(neg, 20, 1500, 1));
        let zero = key(10, 11, 1, 101, 8);
        p.attempt(attempt(zero, 20, 2000));
        p.result(result(zero, 20, 2000, 2));
        let ok = key(10, 11, 1, 102, 9);
        p.attempt(attempt(ok, 20, 1000));
        p.result(result(ok, 20, 1500, 1));
        let w = p.close_window(0, 5000, [0; 8]);
        assert_eq!(w.paired, 3);
        assert_eq!(w.nonmonotonic_pairs, 2);
        let hist_total: u64 = w.histograms.iter().map(|h| h.count).sum();
        assert_eq!(hist_total, 1);
        assert_eq!((w.histograms[1].count, w.histograms[1].sum), (1, 500));
    }

    #[test]
    fn exemplars_bounded_per_direction() {
        let mut p = edge_bearing();
        for i in 0..20u64 {
            p.attempt(attempt(key(10, 11, 1, 100 + i, i + 1), 20, 1000 + i));
            p.result(result(key(10, 11, 1, 500 + i, 100 + i), 22, 1500 + i, 1));
        }
        p.close_window(0, 5000, [0; 8]);
        let w = p.close_window(1, 6000, [0; 8]);
        assert_eq!(w.unpaired_entries, 20);
        assert_eq!(w.unpaired_results, 20);
        let entries = w
            .exemplars
            .iter()
            .filter(|e| e.dir == ExemplarDir::Entry)
            .count();
        let results = w
            .exemplars
            .iter()
            .filter(|e| e.dir == ExemplarDir::Result)
            .count();
        assert_eq!((entries, results), (8, 8));
    }

    #[test]
    fn finalize_is_terminal() {
        let mut p = edge_bearing();
        p.attempt(attempt(key(10, 11, 1, 100, 7), 20, 1000));
        p.finalize(2000);
        let t = p.totals();
        assert_eq!(
            (t.paired, t.unpaired_entries, t.unpaired_results),
            (0, 1, 0)
        );
        p.finalize(3000);
        let t = p.totals();
        assert_eq!(
            (t.paired, t.unpaired_entries, t.unpaired_results),
            (0, 1, 0)
        );
    }

    #[test]
    fn rejected_unknown_counted() {
        let mut p = edge_bearing();
        p.reject_unknown();
        p.reject_unknown();
        let w = p.close_window(0, 2000, [0; 8]);
        assert_eq!(w.rejected_unknown_api, 2);
        assert_eq!(p.totals().rejected_unknown_api, 2);
    }

    #[test]
    fn lane_deltas_surface_per_window() {
        let mut p = edge_bearing();
        let w0 = p.close_window(0, 2000, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(w0.ring_loss, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(w0.depth_exceeded, 3);
        let w1 = p.close_window(1, 3000, [1, 2, 5, 4, 5, 6, 7, 8]);
        assert_eq!(w1.ring_loss, [0, 0, 2, 0, 0, 0, 0, 0]);
        assert_eq!(w1.depth_exceeded, 2);
    }

    #[test]
    fn duplicate_edges_conserve_newcomer_unpaired() {
        let mut p = edge_bearing();
        let k = key(10, 11, 1, 100, 7);
        p.attempt(attempt(k, 20, 1000));
        p.attempt(attempt(k, 20, 1100));
        p.result(result(k, 20, 1500, 1));
        p.finalize(2000);
        let t = p.totals();
        assert_eq!(t.paired, 1);
        assert_eq!(t.unpaired_entries, 1);
        assert_eq!(t.unpaired_results, 0);
        let ra: u64 = t.received.attempts.iter().sum();
        assert_eq!(ra, t.paired + t.unpaired_entries);
    }

    #[test]
    fn outputs_carry_hashes_not_cookies() {
        let mut p = edge_bearing();
        let k = key(10, 11, 1, 100, 7);
        p.attempt(attempt(k, 20, 1000));
        p.result(result(k, 20, 1500, 1));
        p.attempt(attempt(key(10, 11, 1, 101, 8), 22, 1100));
        let w0 = p.close_window(0, 2000, [0; 8]);
        assert_eq!(w0.paired, 1);
        assert_eq!(w0.detail.len(), 3);
        assert_eq!(w0.detail[0].key.key_hash16, key_hash16(100, 1));
        let w = p.close_window(1, 3000, [0; 8]);
        assert_eq!(w.unpaired_entries, 1);
        assert_eq!(w.exemplars.len(), 1);
        assert_eq!(w.exemplars[0].key_hash16, key_hash16(101, 1));
    }

    #[test]
    fn folds_are_exact_under_forced_caps() {
        // F2 (codex R1-2): caps bind DETAIL, never accounting —
        // a capped window's class/histogram/per-API folds stay
        // COMPLETE (frozen §6D-5: fixed small state).
        let mut p = TraceProducer::with_caps(4, usize::MAX);
        p.set_mode(TRACE_MODE_ALL);
        for i in 0..10u64 {
            let k = key(10, 11, 1, 100 + i, i + 1);
            p.attempt(attempt(k, 20, 1000 + i));
            p.result(result(k, 20, 2000 + i, 1));
        }
        let w = p.close_window(0, 5000, [0; 8]);
        assert!(w.capped);
        assert_eq!(w.detail.len(), 4);
        assert_eq!(w.dropped, 16);
        assert_eq!(w.paired, 10);
        assert_eq!(w.class_counts, [0, 10, 0, 0, 0]);
        assert_eq!(w.class_counts.iter().sum::<u64>(), w.paired);
        let h = &w.histograms[1];
        assert_eq!((h.count, h.sum), (10, 10_000));
        assert_eq!(&h.buckets[0..4], &[0, 0, 0, 0]);
        assert!(h.buckets[4..].iter().all(|b| *b == 10));
        assert_eq!(h.buckets[18], h.count);
        for (c, h) in w.histograms.iter().enumerate() {
            if c != 1 {
                assert_eq!((h.count, h.sum), (0, 0), "class {c}");
            }
        }
        assert_eq!(w.api_attempts[20], 10);
        assert_eq!(w.api_results[20], 10);
        assert_eq!(w.api_attempts.iter().sum::<u64>(), 10);
        assert_eq!(w.api_results.iter().sum::<u64>(), 10);
    }

    #[test]
    fn histogram_fold_is_cumulative_and_operational_only() {
        // F2 + F5: cumulative buckets in `le` order (§6D-3),
        // fetch pairs and nonmonotonic pairs never histogrammed
        // (but still counted in `paired` + class totals).
        let mut p = edge_bearing();
        let op = key(10, 11, 1, 100, 7);
        p.attempt(attempt(op, 20, 1000));
        p.result(result(op, 20, 1500, 1));
        let fetch = key(10, 11, 1, 101, 8);
        p.attempt(attempt(fetch, 10, 2000));
        p.result(result(fetch, 10, 2600, 1));
        let skew = key(10, 11, 1, 102, 9);
        p.attempt(attempt(skew, 22, 5000));
        p.result(result(skew, 22, 4000, 2));
        let w = p.close_window(0, 6000, [0; 8]);
        assert_eq!(w.paired, 3);
        assert_eq!(w.nonmonotonic_pairs, 1);
        assert_eq!(w.class_counts, [1, 1, 1, 0, 0]);
        let h = &w.histograms[1];
        assert_eq!((h.count, h.sum), (1, 500));
        assert_eq!(&h.buckets[0..3], &[0, 0, 0]);
        assert!(h.buckets[3..].iter().all(|b| *b == 1));
        assert_eq!(h.buckets[18], h.count);
        for (c, h) in w.histograms.iter().enumerate() {
            if c != 1 {
                assert_eq!((h.count, h.sum), (0, 0), "class {c}");
            }
        }
        assert_eq!(w.api_attempts[10], 1);
        assert_eq!(w.api_attempts[20], 1);
        assert_eq!(w.api_attempts[22], 1);
    }

    #[test]
    fn totals_fold_classes_and_histograms_across_windows() {
        // F2: the epoch fold (2c's `class_epoch` input) accumulates
        // per-class counts + distributions over sealed windows.
        let mut p = edge_bearing();
        let a = key(10, 11, 1, 100, 7);
        p.attempt(attempt(a, 20, 1000));
        p.result(result(a, 20, 1500, 1));
        p.close_window(0, 2000, [0; 8]);
        let b = key(10, 11, 1, 101, 8);
        p.attempt(attempt(b, 20, 3000));
        p.result(result(b, 20, 4000, 2));
        p.close_window(1, 5000, [0; 8]);
        let t = p.totals();
        assert_eq!(t.paired, 2);
        assert_eq!(t.class_counts, [0, 1, 1, 0, 0]);
        assert_eq!((t.histograms[1].count, t.histograms[1].sum), (1, 500));
        assert_eq!((t.histograms[2].count, t.histograms[2].sum), (1, 1000));
    }

    #[test]
    fn depth_subset_helper() {
        assert!(depth_subset_holds(5, 3));
        assert!(depth_subset_holds(0, 0));
        assert!(depth_subset_holds(4, 4));
        assert!(!depth_subset_holds(3, 5));
        assert!(!depth_subset_holds(0, 1));
    }

    #[test]
    fn pairing_pending_caps_fifo_evict_visible() {
        // G1 (codex R2-1): pending maps are FIXED-CAPPED at the
        // kernel-mirrored bound (4096). Flood 3×cap sequential
        // unpaireables per direction: lens stay ≤ cap DURING the
        // feed, every eviction is a visible unpaired count (+
        // exemplar), tightly interleaved legit pairs still pair,
        // conservation stays exact.
        let mut p = edge_bearing();
        let cap = 4096usize;
        let mut legit = 0u64;
        for i in 0..3 * cap as u64 {
            let k = key(10 + (i % 50) as u32, 1000 + i as u32, 1, 100 + i, i + 1);
            p.attempt(attempt(k, 20, 1000 + i));
            if i % 1000 == 999 {
                let l = key(7, 7, 1, 900_000 + legit, 5000 + legit);
                p.attempt(attempt(l, 20, 5_000_000 + legit));
                p.result(result(l, 20, 5_000_001 + legit, 1));
                legit += 1;
            }
            if i % 512 == 511 {
                assert!(
                    p.pending_attempts.len() <= cap,
                    "attempts {}",
                    p.pending_attempts.len()
                );
                assert!(p.inv_hw.len() <= cap, "scopes {}", p.inv_hw.len());
                p.check_indexes();
            }
        }
        for i in 0..3 * cap as u64 {
            let k = key(
                20 + (i % 50) as u32,
                500_000 + i as u32,
                1,
                700_000 + i,
                i + 1,
            );
            p.result(result(k, 20, 9_000_000 + i, 1));
            if i % 512 == 511 {
                assert!(
                    p.pending_results.len() <= cap,
                    "results {}",
                    p.pending_results.len()
                );
                assert!(p.inv_hw.len() <= cap, "scopes {}", p.inv_hw.len());
                p.check_indexes();
            }
        }
        p.check_indexes();
        p.finalize(20_000_000);
        let w = p.close_window(0, 20_000_001, [0; 8]);
        let t = p.totals();
        assert_eq!(legit, 12);
        assert_eq!(t.paired, legit);
        assert_eq!(t.unpaired_entries, 3 * cap as u64);
        assert_eq!(t.unpaired_results, 3 * cap as u64);
        let ra: u64 = t.received.attempts.iter().sum();
        let rr: u64 = t.received.results.iter().sum();
        assert_eq!(ra, t.paired + t.unpaired_entries);
        assert_eq!(rr, t.paired + t.unpaired_results);
        let entries = w
            .exemplars
            .iter()
            .filter(|e| e.dir == ExemplarDir::Entry)
            .count();
        let results = w
            .exemplars
            .iter()
            .filter(|e| e.dir == ExemplarDir::Result)
            .count();
        assert_eq!((entries, results), (8, 8));
    }

    #[test]
    fn scope_cap_evicts_hw_only_pending_self_sufficient() {
        // G1: scopes FIXED-CAPPED (4096, kernel THREADS mirror).
        // Eviction drops HW only: held pendings still pair, a
        // consumed key in an EVICTED scope re-pairs (disclosed
        // residual, same class as idle-expiry) while a RETAINED
        // scope still dups (F3 intact under caps).
        let mut p = edge_bearing();
        for i in 0..5000u64 {
            let f = key(100, 2000 + i as u32, 1, 5000 + i, 10);
            p.attempt(attempt(f, 20, 1000 + i));
            p.result(result(f, 20, 2_000_000 + i, 1));
        }
        assert!(p.inv_hw.len() <= 4096, "scopes {}", p.inv_hw.len());
        p.check_indexes();
        let k = key(100, 2000, 1, 5000, 11);
        p.attempt(attempt(k, 20, 50_000));
        p.result(result(k, 20, 50_001, 1));
        let r = key(100, 2001, 1, 5001, 10);
        p.attempt(attempt(r, 20, 60_000));
        p.result(result(r, 20, 60_001, 1));
        let d = key(100, 6999, 1, 9999, 10);
        p.attempt(attempt(d, 20, 70_000));
        p.result(result(d, 20, 70_001, 1));
        p.finalize(80_000);
        let t = p.totals();
        assert_eq!(t.paired, 5002);
        assert_eq!((t.unpaired_entries, t.unpaired_results), (1, 1));
        let ra: u64 = t.received.attempts.iter().sum();
        let rr: u64 = t.received.results.iter().sum();
        assert_eq!(ra, t.paired + t.unpaired_entries);
        assert_eq!(rr, t.paired + t.unpaired_results);
    }

    #[test]
    fn folds_exact_under_forced_caps_with_unmatched_flood() {
        // G1 extension of the forced-caps pin: DETAIL caps bind
        // rows while pairing caps bind state — folds stay
        // COMPLETE and pairing lens stay ≤ cap under an unmatched
        // flood (the R2-forced-cap hole: immediate pairs only).
        let mut p = TraceProducer::with_caps(4, usize::MAX);
        p.set_mode(TRACE_MODE_ALL);
        for i in 0..10u64 {
            let k = key(10, 11, 1, 100 + i, i + 1);
            p.attempt(attempt(k, 20, 1000 + i));
            p.result(result(k, 20, 2000 + i, 1));
        }
        let cap = 4096usize;
        for i in 0..3 * cap as u64 {
            let u = key(30, 800_000 + i as u32, 1, 900_000 + i, 1);
            p.attempt(attempt(u, 20, 100_000 + i));
        }
        assert!(
            p.pending_attempts.len() <= cap,
            "attempts {}",
            p.pending_attempts.len()
        );
        assert!(p.inv_hw.len() <= cap, "scopes {}", p.inv_hw.len());
        p.check_indexes();
        p.finalize(20_000_000);
        let w = p.close_window(0, 20_000_001, [0; 8]);
        assert!(w.capped);
        assert_eq!(w.detail.len(), 4);
        assert_eq!(w.dropped, 20 + 3 * cap as u64 - 4);
        assert_eq!(w.paired, 10);
        assert_eq!(w.class_counts, [0, 10, 0, 0, 0]);
        assert_eq!(w.unpaired_entries, 3 * cap as u64);
        assert_eq!(w.unpaired_results, 0);
        assert_eq!(w.api_attempts[20], 10 + 3 * cap as u64);
        assert_eq!(w.api_results[20], 10);
        let h = &w.histograms[1];
        assert_eq!((h.count, h.sum), (10, 10_000));
    }
}
