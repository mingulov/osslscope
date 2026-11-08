// SPDX-License-Identifier: GPL-3.0-or-later
//! 6D trace data plane (T8.2a): mode words, family demux, pairing core,
//! detail caps, and lane surfacing. Output projections (§6D-2 class
//! counts, §6D-3 histograms, §6D-7 record JSON, status/modes CLI) belong
//! to T8.2b/c; this module produces paired edges, terminal buckets,
//! retained detail, and counters.
use super::wire::contract as c;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

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

/// A paired ATTEMPT/RESULT (§6D-6).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PairedEdge {
    /// Hash-bound pair key (never the raw cookie).
    pub key: HashedKey,
    /// API ID.
    pub api: u32,
    /// RAW return class (0..4, §6D-2 function value).
    pub class: u32,
    /// ATTEMPT timestamp.
    pub attempt_ns: u64,
    /// RESULT timestamp.
    pub result_ns: u64,
    /// `result_ns - attempt_ns`; valid iff `!nonmonotonic`.
    pub duration_ns: u64,
    /// Zero/negative delta (§6D-3 exclusion; still a pair).
    pub nonmonotonic: bool,
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
    /// Window pairs (streaming-exact under caps).
    pub pairs: Vec<PairedEdge>,
    /// Exemplars (≤8 per direction).
    pub exemplars: Vec<TraceExemplar>,
}

/// Cumulative session totals.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TraceTotals {
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
    /// Pending ATTEMPTs by key.
    pending_attempts: HashMap<PairKey, PendingEdge>,
    /// Pending RESULTs by key.
    pending_results: HashMap<PairKey, PendingEdge>,
    /// Per-scope invocation high-water (F3: consumed keys never re-pair).
    inv_hw: HashMap<ScopeKey, ScopeHw>,
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
    /// Window pairs.
    pairs: Vec<PairedEdge>,
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
            pending_results: HashMap::new(),
            inv_hw: HashMap::new(),
            window: 0,
            last_loss: [0; 8],
            totals: TraceTotals::default(),
            detail: Vec::new(),
            detail_bytes: 0,
            capped: false,
            dropped: 0,
            pairs: Vec::new(),
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
                .pending_results
                .remove(&edge.key)
                .expect("held RESULT just observed");
            self.pair(
                edge.key,
                edge.api,
                edge.monotonic_ns,
                held.monotonic_ns,
                held.outcome,
            );
        } else if self.pending_results.contains_key(&edge.key) {
            // Cross-window held RESULT: the key is unconsumed, so
            // live-state precedence skips the high-water — the
            // newcomer goes pending (pending-then-correct), or is
            // the anomaly when an ATTEMPT is already live.
            if self.pending_attempts.contains_key(&edge.key) {
                self.unpaired_entries = self.unpaired_entries.saturating_add(1);
                self.totals.unpaired_entries = self.totals.unpaired_entries.saturating_add(1);
            } else {
                self.pending_attempts.insert(
                    edge.key,
                    PendingEdge {
                        window: self.window,
                        api: edge.api,
                        monotonic_ns: edge.monotonic_ns,
                        outcome: 0,
                    },
                );
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
            self.pending_attempts.insert(
                edge.key,
                PendingEdge {
                    window: self.window,
                    api: edge.api,
                    monotonic_ns: edge.monotonic_ns,
                    outcome: 0,
                },
            );
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
        if let Some(held) = self.pending_attempts.remove(&edge.key) {
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
            self.pending_results.insert(
                edge.key,
                PendingEdge {
                    window: self.window,
                    api: edge.api,
                    monotonic_ns: edge.monotonic_ns,
                    outcome: edge.outcome,
                },
            );
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
        let stale_attempts: Vec<PairKey> = self
            .pending_attempts
            .iter()
            .filter(|(_, held)| held.window < current)
            .map(|(key, _)| *key)
            .collect();
        for key in stale_attempts {
            if let Some(held) = self.pending_attempts.remove(&key) {
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
            if let Some(held) = self.pending_results.remove(&key) {
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
        self.inv_hw
            .retain(|_, scope| current.saturating_sub(scope.last_window) <= 1);
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
            pairs: std::mem::take(&mut self.pairs),
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
        for (key, held) in std::mem::take(&mut self.pending_results) {
            self.unpaired_results = self.unpaired_results.saturating_add(1);
            self.totals.unpaired_results = self.totals.unpaired_results.saturating_add(1);
            self.push_exemplar(ExemplarDir::Result, key, held, now_ns);
            self.advance_hw(&key);
        }
    }

    /// Cumulative totals.
    pub fn totals(&self) -> TraceTotals {
        self.totals
    }

    /// Mark scope activity: every post-gate edge arrival stamps the
    /// scope's window (idle-drop keys on arrivals only).
    fn touch_scope(&mut self, key: &PairKey) {
        let window = self.window;
        self.inv_hw
            .entry(ScopeKey::of(key))
            .or_insert(ScopeHw {
                hw: None,
                last_window: window,
            })
            .last_window = window;
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
        let scope = ScopeKey::of(key);
        let window = self.window;
        let entry = self.inv_hw.entry(scope).or_insert(ScopeHw {
            hw: None,
            last_window: window,
        });
        entry.hw = Some(entry.hw.map_or(key.invocation, |hw| hw.max(key.invocation)));
    }

    fn pair(&mut self, key: PairKey, api: u32, attempt_ns: u64, result_ns: u64, class: u32) {
        self.advance_hw(&key);
        // §6D-3: zero/negative deltas are unusable durations but real pairs.
        let nonmonotonic = result_ns <= attempt_ns;
        let duration_ns = if nonmonotonic {
            0
        } else {
            result_ns - attempt_ns
        };
        self.pairs.push(PairedEdge {
            key: HashedKey::of(&key),
            api,
            class,
            attempt_ns,
            result_ns,
            duration_ns,
            nonmonotonic,
        });
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
        assert_eq!(w.pairs.len(), 1);
        let pair = &w.pairs[0];
        assert_eq!(pair.class, 3);
        assert_eq!(pair.duration_ns, 500);
        assert!(!pair.nonmonotonic);
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
        assert_eq!(w.pairs.len(), 10);
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
        assert_eq!(w.pairs.iter().filter(|e| e.nonmonotonic).count(), 2);
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
        assert_eq!(w0.pairs.len(), 1);
        assert_eq!(w0.pairs[0].key.key_hash16, key_hash16(100, 1));
        assert_eq!(
            (
                w0.pairs[0].key.pid,
                w0.pairs[0].key.tid,
                w0.pairs[0].key.generation,
                w0.pairs[0].key.invocation
            ),
            (10, 11, 1, 7)
        );
        assert_eq!(w0.detail.len(), 3);
        assert_eq!(w0.detail[0].key.key_hash16, key_hash16(100, 1));
        let w = p.close_window(1, 3000, [0; 8]);
        assert_eq!(w.unpaired_entries, 1);
        assert_eq!(w.exemplars.len(), 1);
        assert_eq!(w.exemplars[0].key_hash16, key_hash16(101, 1));
    }

    #[test]
    fn depth_subset_helper() {
        assert!(depth_subset_holds(5, 3));
        assert!(depth_subset_holds(0, 0));
        assert!(depth_subset_holds(4, 4));
        assert!(!depth_subset_holds(3, 5));
        assert!(!depth_subset_holds(0, 1));
    }
}
