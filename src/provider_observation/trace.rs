// SPDX-License-Identifier: GPL-3.0-or-later
//! 6D trace data plane (T8.2a): mode words, family demux, pairing core,
//! detail caps, and lane surfacing. Output projections (§6D-2 class
//! counts, §6D-3 histograms, §6D-7 record JSON, status/modes CLI) belong
//! to T8.2b/c; this module produces paired edges, terminal buckets,
//! retained detail, and counters.
use std::collections::HashMap;

/// `TRACE_MODE` map words (§6D-9 order, shared BPF/host).
pub const TRACE_MODE_OFF: u32 = 0;
/// `TRACE_MODE` map words (§6D-9 order, shared BPF/host).
pub const TRACE_MODE_METADATA: u32 = 1;
/// `TRACE_MODE` map words (§6D-9 order, shared BPF/host).
pub const TRACE_MODE_LATENCY: u32 = 2;
/// `TRACE_MODE` map words (§6D-9 order, shared BPF/host).
pub const TRACE_MODE_STATUS: u32 = 3;
/// `TRACE_MODE` map words (§6D-9 order, shared BPF/host).
pub const TRACE_MODE_ALL: u32 = 4;

/// Edge-bearing predicate (§6D-0 D0-1): only 2/3/4 pair.
pub fn trace_mode_edge_bearing(_mode: u32) -> bool {
    todo!()
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
        todo!()
    }
}

/// Family demux BEFORE unknown-ID rejection (§6D-1). `None` ⟺ {0} ∪ {73+}.
pub fn demux(_api: u32) -> Option<TraceFamily> {
    todo!()
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
pub fn key_hash16(_cookie: u64, _generation: u64) -> String {
    todo!()
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
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PairedEdge {
    /// Pair key.
    pub key: PairKey,
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
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RetainedEdge {
    /// 1 = ATTEMPT, 2 = RESULT.
    pub kind: u32,
    /// Pair key.
    pub key: PairKey,
    /// API ID.
    pub api: u32,
    /// Producer timestamp.
    pub monotonic_ns: u64,
    /// RAW outcome word (0 on ATTEMPT).
    pub outcome: u32,
}

impl RetainedEdge {
    /// Accounted bytes: canonical compact-encoding length.
    pub fn retained_bytes(&self) -> usize {
        todo!()
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
#[allow(dead_code)]
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
    pub(crate) unpaired_results: u64,
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

impl TraceProducer {
    /// Frozen defaults: mode off, §6D-5 caps.
    pub fn new() -> Self {
        todo!()
    }

    /// Test/custom budgets; production uses [`TraceProducer::new`].
    pub fn with_caps(_max_rows: usize, _max_bytes: usize) -> Self {
        todo!()
    }

    /// Host mode gate (BPF map programmed separately by the session).
    pub fn set_mode(&mut self, _mode: u32) {
        todo!()
    }

    /// Active mode word.
    pub fn mode(&self) -> u32 {
        todo!()
    }

    /// Feed a decoded ATTEMPT (received always counted; pairing gated).
    pub fn attempt(&mut self, _edge: AttemptEdge) {
        todo!()
    }

    /// Feed a decoded RESULT (received always counted; pairing gated).
    pub fn result(&mut self, _edge: ResultEdge) {
        todo!()
    }

    /// Count one decode-domain unknown-ID record.
    pub fn reject_unknown(&mut self) {
        todo!()
    }

    /// Seal the current window; `loss_abs` is the cumulative 8-lane read.
    pub fn close_window(
        &mut self,
        _window_seq: u64,
        _now_ns: u64,
        _loss_abs: [u64; 8],
    ) -> ClosedTraceWindow {
        todo!()
    }

    /// Terminal finalize: every held edge lands unpaired.
    pub fn finalize(&mut self, _now_ns: u64) {
        todo!()
    }

    /// Cumulative totals.
    pub fn totals(&self) -> TraceTotals {
        todo!()
    }
}

impl Default for TraceProducer {
    fn default() -> Self {
        todo!()
    }
}

/// Subset check (§6D-4): trace depth overflow ⊇ aggregate depth overflow.
pub fn depth_subset_holds(_trace_depth_exceeded: u64, _aggregate_depth: u64) -> bool {
    todo!()
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
            key: k,
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
    fn depth_subset_helper() {
        assert!(depth_subset_holds(5, 3));
        assert!(depth_subset_holds(0, 0));
        assert!(depth_subset_holds(4, 4));
        assert!(!depth_subset_holds(3, 5));
        assert!(!depth_subset_holds(0, 1));
    }
}
