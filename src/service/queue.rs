//! SPDX-License-Identifier: GPL-3.0-or-later
//! §5.2 stream queue, eviction, drop ledger.
//!
//! The queue holds rendered stream records (one JSONL line each)
//! between the finalizer and the stream writer. A record enqueues
//! only if both caps still hold; otherwise the queue evicts
//! OLDEST-first (freshest survives) and each eviction folds into a
//! 64-entry drop ledger (same-cause merge, visible fold count). The
//! ledger is a fixed in-memory structure, NOT queued records: at each
//! window boundary it emits one `drop-marker` covering evictions
//! since the previous marker. Spans clear ONLY on newline-delivery
//! of their OWN marker (marker-specific coverage snapshots —
//! R1 C1); same-cause folds always merge (one span per cause).

use std::collections::VecDeque;

use crate::service::envelope::{DropLedgerEntry, DropReason};

/// Ledger cap (mirrors the 6A `SessionLoss` 64 intervals).
pub const LEDGER_CAP: usize = 64;

/// One queued stream record: rendered bytes + its window seq (the
/// ledger's fold identity).
#[derive(Debug, Clone)]
pub struct QueuedRecord {
    /// Window seq this record belongs to (refs) or was emitted at
    /// (markers).
    pub seq: u64,
    /// Rendered line bytes WITHOUT the terminating newline.
    pub bytes: Vec<u8>,
}

impl QueuedRecord {
    /// Whole-record bytes for accounting: the record is delivered iff
    /// its terminating newline reached the tap, so the newline is
    /// part of the delivered unit.
    pub fn full_bytes(&self) -> u64 {
        self.bytes.len() as u64 + 1
    }
}

/// Identify a stream record from its rendered bytes (kind word +
/// seq/at_seq — parsed, never parallel-tracked).
pub(crate) fn stream_record_identity(bytes: &[u8]) -> (String, u64) {
    let value = serde_json::from_slice::<serde_json::Value>(bytes).ok();
    let kind = value
        .as_ref()
        .and_then(|v| v.get("kind"))
        .and_then(|k| k.as_str())
        .unwrap_or("")
        .to_string();
    let seq = value
        .as_ref()
        .and_then(|v| v.get("seq").or_else(|| v.get("at_seq")))
        .and_then(|s| s.as_u64())
        .unwrap_or(0);
    (kind, seq)
}

/// Marker-specific coverage delta (R1 C1): the span growth one
/// emitted marker covers BEYOND all older markers (cumulative
/// markers, disjoint deltas — ascending by marker). Delivery of
/// marker M proves M's whole cumulative content, so it subtracts
/// every delta ≤ M (an evicted marker's delta clears under any
/// newer delivery — no unmark path, §5.2). A delivery NEVER
/// touches deltas > M (R1 C1(b): an old delivery never erases
/// newer-only drops).
#[derive(Debug, Clone)]
pub struct SpanCoverage {
    pub marker: u64,
    pub records: u64,
    pub bytes: u64,
    pub folds: u64,
    /// Fold-serial interval `(start, end]` this delta covers (R3
    /// Gate 4 F3: per-span fold chronology — strikes match their
    /// fold token against these intervals, never window
    /// sequence). Contiguous across the span's deltas.
    pub start: u64,
    pub end: u64,
    /// Dead ⟺ the marker will never deliver (retired — evicted,
    /// failed, uncertain). Merges into its successor (whose marker
    /// truly covers the merged interval); flags when newest until
    /// the next append. Live deltas are never merged (R3 F4).
    pub dead: bool,
}

/// Folded drop span (the §5.2 ledger entry shape + merge state).
#[derive(Debug, Clone)]
pub struct LedgerSpan {
    pub first_seq: u64,
    pub last_seq: u64,
    pub records: u64,
    pub bytes: u64,
    pub folds: u64,
    pub reason: DropReason,
    /// Marker coverage deltas, ascending (empty ⟺ never covered —
    /// every record is uncovered growth). Same-cause folds ALWAYS
    /// merge here (bounded: one span per cause); the deltas — not
    /// a merge ban — distinguish covered drops from new growth.
    pub covering: Vec<SpanCoverage>,
    /// Per-span fold serial (R3 Gate 4 F3: every fold takes the
    /// next serial as its cohort token; 0 ⟺ no fold yet).
    pub fold_serial: u64,
    /// Max fold-serial boundary delivered so far (a strike at or
    /// below this already left the span at delivery — no-op,
    /// never a double-subtract).
    pub delivered_through: u64,
}

impl LedgerSpan {
    fn fresh(seq: u64, bytes: u64, reason: DropReason) -> Self {
        Self {
            first_seq: seq,
            last_seq: seq,
            records: 1,
            bytes,
            folds: 0,
            reason,
            covering: Vec::new(),
            fold_serial: 1,
            delivered_through: 0,
        }
    }

    /// Same-cause merge (the 6A coalescing rule): extend the span,
    /// bump the visible fold count.
    fn merge(&mut self, seq: u64, bytes: u64) {
        self.first_seq = self.first_seq.min(seq);
        self.last_seq = self.last_seq.max(seq);
        self.records += 1;
        self.bytes += bytes;
        self.folds += 1;
    }

    pub fn entry(&self) -> DropLedgerEntry {
        DropLedgerEntry {
            first_seq: self.first_seq,
            last_seq: self.last_seq,
            records: self.records,
            bytes: self.bytes,
            folds: self.folds,
            reason: self.reason,
        }
    }
}

/// The bounded stream queue + drop ledger (§5.2).
#[derive(Debug)]
pub struct StreamQueue {
    queue_bytes: u64,
    queue_events: u64,
    queued: VecDeque<QueuedRecord>,
    queued_bytes: u64,
    /// Uncleared ledger spans (NET of recovery — strikes mutate).
    spans: Vec<LedgerSpan>,
    /// GROSS fold-time monotone totals (never struck, §7.2).
    gross_records: u64,
    gross_bytes: u64,
    gross_by_reason: [(u64, u64); 3],
}

impl StreamQueue {
    pub fn new(queue_bytes: u64, queue_events: u64) -> Self {
        Self {
            queue_bytes,
            queue_events,
            queued: VecDeque::new(),
            queued_bytes: 0,
            spans: Vec::new(),
            gross_records: 0,
            gross_bytes: 0,
            gross_by_reason: [(0, 0); 3],
        }
    }

    fn reason_idx(reason: DropReason) -> usize {
        match reason {
            DropReason::QueueFull => 0,
            DropReason::Epipe => 1,
            DropReason::StreamAbandoned => 2,
        }
    }

    pub fn queued_records(&self) -> u64 {
        self.queued.len() as u64
    }

    pub fn queued_bytes(&self) -> u64 {
        self.queued_bytes
    }

    /// Fold one dropped record into the ledger + gross totals.
    /// Same-cause merging is MANDATORY (Control 1: unmerged
    /// same-cause spans are FAIL) — every cause merges into its
    /// ONE span, covered or not (coverage deltas, not a merge
    /// ban, distinguish covered drops from new growth — R1 C1).
    /// Bounded: one span per cause (3 reasons), so the
    /// 64-cap never binds; gross totals charge first, so even a
    /// hypothetical overflow stays explicit in the totals, never
    /// quiet. Each span keeps `0 ≤ folds ≤ records − 1` exactly.
    /// Returns the fold's cohort token (the span's fold serial —
    /// R3 Gate 4 F3: recovery matches this token against delta
    /// intervals, never window sequence; the caller threads it to
    /// `strike` via the in-flight record).
    pub fn fold(&mut self, seq: u64, bytes: u64, reason: DropReason) -> u64 {
        self.gross_records += 1;
        self.gross_bytes += bytes;
        let slot = &mut self.gross_by_reason[Self::reason_idx(reason)];
        slot.0 += 1;
        slot.1 += bytes;
        if let Some(span) = self.spans.iter_mut().find(|s| s.reason == reason) {
            span.merge(seq, bytes);
            span.fold_serial += 1;
            return span.fold_serial;
        }
        debug_assert!(self.spans.len() < LEDGER_CAP);
        if self.spans.len() < LEDGER_CAP {
            self.spans.push(LedgerSpan::fresh(seq, bytes, reason));
            return 1;
        }
        0
    }

    /// Enqueue one rendered record. Evicts oldest-first while either
    /// cap would break; a record larger than `--queue-bytes` alone is
    /// accounted as dropped without enqueueing (never an evict loop).
    /// Evicted markers retire (R3 Gate 4 F4 — they never deliver).
    pub fn enqueue(&mut self, record: QueuedRecord) {
        let size = record.full_bytes();
        if size > self.queue_bytes {
            self.fold(record.seq, size, DropReason::QueueFull);
            self.retire_evicted_marker(&record.bytes);
            return;
        }
        while !self.queued.is_empty()
            && (self.queued.len() as u64 >= self.queue_events
                || self.queued_bytes + size > self.queue_bytes)
        {
            if let Some(old) = self.queued.pop_front() {
                self.queued_bytes -= old.full_bytes();
                let seq = old.seq;
                let bytes = old.full_bytes();
                self.fold(seq, bytes, DropReason::QueueFull);
                self.retire_evicted_marker(&old.bytes);
            }
        }
        // After evicting everything the record still fits (size ≤
        // cap proven above; events ≥ 1 by the [64,4096] range).
        self.queued_bytes += size;
        self.queued.push_back(record);
    }

    /// Retire an evicted (or never-enqueued) marker's delta (R3
    /// Gate 4 F4): the marker never delivers, so its claim merges
    /// away. Identity from the rendered bytes. Non-markers no-op.
    fn retire_evicted_marker(&mut self, bytes: &[u8]) {
        let (kind, at_seq) = stream_record_identity(bytes);
        if kind == "drop-marker" {
            self.retire_marker(at_seq);
        }
    }

    /// Pop the oldest queued record for the tap writer.
    pub fn pop(&mut self) -> Option<QueuedRecord> {
        let record = self.queued.pop_front()?;
        self.queued_bytes -= record.full_bytes();
        Some(record)
    }

    /// Uncleared spans (NET of recovery) for marker emission /
    /// `stream_pending[]` — every records>0 span, covered or not
    /// (covered-but-undelivered spans are uncleared).
    pub fn spans(&self) -> Vec<DropLedgerEntry> {
        self.spans
            .iter()
            .filter(|s| s.records > 0)
            .map(LedgerSpan::entry)
            .collect()
    }

    /// Spans needing marker coverage (uncovered growth, records>0).
    pub fn uncovered(&self) -> Vec<DropLedgerEntry> {
        self.spans
            .iter()
            .filter(|s| s.records > 0 && Self::has_growth(s))
            .map(LedgerSpan::entry)
            .collect()
    }

    /// Records already covered by emitted markers (Σ deltas —
    /// strikes shrink the span, never the deltas, so growth is
    /// exactly post-coverage folds).
    fn covered_records(span: &LedgerSpan) -> u64 {
        span.covering.iter().map(|c| c.records).sum()
    }

    /// Uncovered growth ⟺ folded past the covered prefix.
    fn has_growth(span: &LedgerSpan) -> bool {
        span.records > Self::covered_records(span)
    }

    /// A new marker is needed iff uncovered folds exist (a marker
    /// was emitted with no new folds since → no marker, §5.2).
    pub fn has_pending_spans(&self) -> bool {
        self.spans
            .iter()
            .any(|s| s.records > 0 && Self::has_growth(s))
    }

    /// Cover every records>0 span with `marker` (call at marker
    /// build — the emitted marker carries `spans()` verbatim,
    /// covered or not). Each span with uncovered growth appends
    /// its delta (an unchanged span needs no entry — any newer
    /// delivery re-proves its old deltas, §5.2). R3 Gate 4 F4:
    /// every undelivered marker keeps its EXACT delta (delivery in
    /// any order stays exact — no live claim is ever merged); only
    /// DEAD markers (retired — provably never delivering) merge
    /// into their successor, whose marker truly covers the merged
    /// interval (cumulative emission). Bound: live deltas ⟺ live
    /// markers ≤ queued + in-flight records (queue caps); dead
    /// entries ≤ 1 per span (the flagged newest, merged at the
    /// next append).
    /// Zero-record uncovered spans sweep here (struck-empty —
    /// their bytes already recovered).
    pub fn mark_all(&mut self, marker: u64) {
        self.spans
            .retain(|s| s.records > 0 || !s.covering.is_empty());
        for span in self.spans.iter_mut() {
            if span.records == 0 || !Self::has_growth(span) {
                continue;
            }
            let (mut dr, mut db, mut df) = (span.records, span.bytes, span.folds);
            for c in span.covering.iter() {
                dr = dr.saturating_sub(c.records);
                db = db.saturating_sub(c.bytes);
                df = df.saturating_sub(c.folds);
            }
            // Merge dead deltas into their successor (a dead marker
            // never delivers, so its claim rides the next-newer
            // delta exactly; the flagged newest merges once this
            // append gives it a successor).
            let mut i = 0usize;
            while i + 1 < span.covering.len() {
                if span.covering[i].dead {
                    Self::merge_into_successor(&mut span.covering, i);
                } else {
                    i += 1;
                }
            }
            let start = span.covering.last().map(|c| c.end).unwrap_or(0);
            span.covering.push(SpanCoverage {
                marker,
                records: dr,
                bytes: db,
                folds: df,
                start,
                end: span.fold_serial,
                dead: false,
            });
        }
    }

    /// Merge delta `i` into its successor (the successor exists;
    /// live-or-dead the claims union exactly — the successor's
    /// marker truly covers the merged interval).
    fn merge_into_successor(covering: &mut Vec<SpanCoverage>, i: usize) {
        let dead = covering.remove(i);
        let succ = &mut covering[i];
        succ.records = succ.records.saturating_add(dead.records);
        succ.bytes = succ.bytes.saturating_add(dead.bytes);
        succ.folds = succ
            .folds
            .saturating_add(dead.folds)
            .min(succ.records.saturating_sub(1));
        succ.start = dead.start;
    }

    /// Retire marker `marker`'s coverage delta (R3 Gate 4 F4): the
    /// marker will never deliver (evicted from the queue, failed
    /// dispatch, uncertain — the coordinator reports every death),
    /// so its claim merges into its successor, or flags when
    /// newest (merged at the next append). Markers without deltas
    /// (never covered, already cleared, unknown) no-op, as do
    /// repeat retirements.
    pub fn retire_marker(&mut self, marker: u64) {
        for span in self.spans.iter_mut() {
            let Some(i) = span.covering.iter().position(|c| c.marker == marker) else {
                continue;
            };
            if i + 1 < span.covering.len() {
                Self::merge_into_successor(&mut span.covering, i);
            } else {
                span.covering[i].dead = true;
            }
        }
    }

    /// Clear on newline-delivery of marker `marker`: the delivery
    /// proves the marker's whole cumulative content, so each span
    /// subtracts every delta ≤ `marker` (saturating — struck bytes
    /// already recovered; delivery clears coverage, never
    /// double-corrects — the arithmetic mirrors the Control-1
    /// equation gross − recovered − delivered-claimed exactly, in
    /// every delivery order). Deltas > `marker` are untouched (R1
    /// C1(b): an old delivery never erases newer-only drops).
    /// Fully-cleared spans drop; partials stay pending (their
    /// post-delivery growth needs the next marker). The span's seq
    /// range is preserved across partial clears (records/bytes /
    /// folds stay exact; the range still names the span's
    /// eviction range).
    pub fn clear_marker(&mut self, marker: u64) {
        for span in self.spans.iter_mut() {
            let (mut dr, mut db, mut df) = (0u64, 0u64, 0u64);
            let mut delivered = span.delivered_through;
            span.covering.retain(|c| {
                if c.marker <= marker {
                    dr = dr.saturating_add(c.records);
                    db = db.saturating_add(c.bytes);
                    df = df.saturating_add(c.folds);
                    delivered = delivered.max(c.end);
                    false
                } else {
                    true
                }
            });
            span.delivered_through = delivered;
            span.records = span.records.saturating_sub(dr);
            span.bytes = span.bytes.saturating_sub(db);
            span.folds = span
                .folds
                .saturating_sub(df)
                .min(span.records.saturating_sub(1));
        }
        self.spans
            .retain(|s| s.records > 0 || !s.covering.is_empty());
    }

    /// Strike a landed record OUT of the folded spans (gross totals
    /// stay; §7.2 gross/net split). Strikes newest-first within the
    /// named cause; returns the struck (records, bytes). R3 Gate 4
    /// F3: the strike binds to the fold cohort via `fold_token`
    /// (the token `fold` returned — fold chronology, never window
    /// sequence: an old queued record can fold after a newer
    /// marker). The delta whose interval contains the token
    /// shrinks with the span, preserving
    /// `growth = records − Σdeltas` so old-marker acks never erase
    /// newer-only drops. Uncovered strikes (no containing delta)
    /// shrink the span alone (exact: no claim to adjust). A strike
    /// at or below the delivered boundary no-ops (its growth
    /// already left the span at delivery — never a
    /// double-subtract). Token 0 (unset — defensive, unreachable
    /// in production) shrinks the span alone, saturating.
    pub fn strike(
        &mut self,
        seq: u64,
        bytes: u64,
        reason: DropReason,
        fold_token: u64,
    ) -> (u64, u64) {
        // Find the newest span of this cause covering seq.
        let mut struck_records = 0u64;
        let mut struck_bytes = 0u64;
        for span in self.spans.iter_mut().rev() {
            if span.reason != reason || span.records == 0 {
                continue;
            }
            if seq < span.first_seq || seq > span.last_seq {
                continue;
            }
            // Already delivered ⟹ the growth left the span at
            // delivery: no-op (re-shrinking would double-subtract
            // into newer growth).
            if fold_token != 0 && fold_token <= span.delivered_through {
                break;
            }
            // Strike one record's bytes from this span. The struck
            // record takes its merge with it (`folds − 1`), which
            // preserves `0 ≤ folds ≤ records − 1` exactly (Control 1
            // checks the invariant on every span, marker-carried or
            // pending). Saturating: a strike never drives a span
            // negative (single strikes are exact; doubles clamp).
            span.records = span.records.saturating_sub(1);
            span.bytes = span.bytes.saturating_sub(bytes);
            span.folds = span.folds.saturating_sub(1);
            // Shrink the proving delta (the struck record leaves its
            // coverage claim with it, so the old claim never erases
            // newer growth at delivery).
            if fold_token != 0 {
                if let Some(c) = span
                    .covering
                    .iter_mut()
                    .find(|c| c.start < fold_token && fold_token <= c.end && c.records > 0)
                {
                    c.records = c.records.saturating_sub(1);
                    c.bytes = c.bytes.saturating_sub(bytes);
                    c.folds = c.folds.saturating_sub(1).min(c.records.saturating_sub(1));
                }
            }
            struck_records = 1;
            struck_bytes = bytes;
            break;
        }
        // Emptied spans sweep at the next `mark_all` (covered
        // empties clear at delivery; uncovered empties carry
        // nothing) — strikes never remove (positions stay stable
        // under delivery clears).
        (struck_records, struck_bytes)
    }

    pub fn gross(&self) -> (u64, u64) {
        (self.gross_records, self.gross_bytes)
    }

    pub fn gross_by_reason(&self, reason: DropReason) -> (u64, u64) {
        self.gross_by_reason[Self::reason_idx(reason)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(seq: u64, size: usize) -> QueuedRecord {
        QueuedRecord {
            seq,
            bytes: vec![b'x'; size],
        }
    }

    #[test]
    fn evicts_oldest_first_freshest_survives() {
        let mut q = StreamQueue::new(100, 64);
        q.enqueue(rec(1, 40)); // 41 bytes
        q.enqueue(rec(2, 40)); // 41 bytes → 82 total
        q.enqueue(rec(3, 40)); // evicts seq 1 (82+41 > 100)
        assert_eq!(q.queued_records(), 2);
        assert_eq!(q.pop().unwrap().seq, 2);
        assert_eq!(q.pop().unwrap().seq, 3);
        assert!(q.pop().is_none());
        let (records, bytes) = q.gross();
        assert_eq!((records, bytes), (1, 41));
        assert_eq!(q.gross_by_reason(DropReason::QueueFull), (1, 41));
    }

    #[test]
    fn oversize_record_never_enqueues_never_loops() {
        let mut q = StreamQueue::new(100, 64);
        q.enqueue(rec(1, 200));
        assert_eq!(q.queued_records(), 0);
        assert_eq!(q.gross(), (1, 201));
    }

    #[test]
    fn same_cause_merges_with_visible_folds() {
        let mut q = StreamQueue::new(100, 64);
        for seq in 1..=5 {
            q.enqueue(rec(seq, 40)); // each evicts the last
        }
        let spans = q.spans();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].reason, DropReason::QueueFull);
        assert_eq!(spans[0].records, 3);
        assert_eq!(spans[0].folds, 2);
        assert!(spans[0].folds < spans[0].records);
        assert_eq!((spans[0].first_seq, spans[0].last_seq), (1, 3));
    }

    #[test]
    fn strike_keeps_gross_net_split_and_invariant() {
        let mut q = StreamQueue::new(100, 64);
        for seq in 1..=4 {
            q.enqueue(rec(seq, 40));
        }
        // Gross: 2 folded (seqs 1..=2).
        assert_eq!(q.gross(), (2, 82));
        // One landed late: strike it (NET), gross stays. (The
        // struck seq 2 is the second QueueFull fold — token 2.)
        let (r, b) = q.strike(2, 41, DropReason::QueueFull, 2);
        assert_eq!((r, b), (1, 41));
        assert_eq!(q.gross(), (2, 82));
        let spans = q.spans();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].records, 1);
        assert!(spans[0].folds <= spans[0].records.saturating_sub(1));
        // Marker emission covers; delivery of that marker
        // subtracts exactly its snapshot (new folds past coverage
        // merge into the same span as uncovered growth — R1 C1).
        assert!(q.has_pending_spans());
        q.mark_all(7);
        assert!(!q.has_pending_spans());
        q.fold(9, 41, DropReason::QueueFull);
        assert!(q.has_pending_spans());
        assert_eq!(q.spans().len(), 1);
        assert_eq!(q.spans()[0].records, 2);
        q.clear_marker(7);
        assert_eq!(q.spans().len(), 1);
        assert_eq!(q.spans()[0].records, 1);
        assert!(q.has_pending_spans(), "post-snapshot growth stays pending");
    }

    /// R1 C1(a) under the R3 F4 contract: repeated direct
    /// `fold → mark_all` without delivery keeps every marker's
    /// EXACT claim (no thinning of live markers — any-order
    /// delivery stays exact; a 64-cap cannot hold 65+ live claims
    /// exactly). Direct marks are all-live (no deaths reported),
    /// so `covering` grows with the marks BY DESIGN; the
    /// production bound (queue + retire) is pinned
    /// production-shaped below.
    #[test]
    fn repeated_undelivered_markers_stay_exact() {
        let mut q = StreamQueue::new(100, 64);
        for seq in 1..=70u64 {
            q.fold(seq, 41, DropReason::QueueFull);
            q.mark_all(seq);
        }
        assert_eq!(q.gross(), (70, 70 * 41));
        let spans = q.spans();
        assert!(
            spans.len() <= LEDGER_CAP,
            "bounded: {} spans (cap {LEDGER_CAP})",
            spans.len()
        );
        let covered: u64 = spans.iter().map(|s| s.records).sum();
        assert_eq!(covered, 70, "no quiet loss: all 70 folds covered");
        for s in &spans {
            assert!(
                s.folds <= s.records.saturating_sub(1),
                "fold invariant holds: {s:?}"
            );
        }
        // Every marker's own delivery is exact (in-order here;
        // out-of-order is pinned above).
        for m in 1..=70u64 {
            q.clear_marker(m);
            let left: u64 = q.spans().iter().map(|s| s.records).sum();
            assert_eq!(left, 70 - m, "pending exact after clear({m})");
        }
        assert!(q.spans().is_empty());
    }

    /// R3 Gate 4 F4 (production bound): markers flowing through a
    /// small queue — evicted markers retire, delivered markers
    /// clear — keep per-span coverage ≤ queued + 1 (the flagged
    /// dead newest) at every step, with exact gross accounting
    /// throughout (enqueued − popped − queued ⟺ evicted).
    #[test]
    fn production_shaped_markers_stay_bounded_and_exact() {
        let mut q = StreamQueue::new(65536, 8);
        let (mut enqueued, mut popped, mut marks) = (0u64, 0u64, 0u64);
        for n in 1..=50u64 {
            // Two records per round (the 8-event queue churns —
            // oldest evict as QueueFull folds with growth).
            q.enqueue(rec(n * 2, 40));
            q.enqueue(rec(n * 2 + 1, 40));
            enqueued += 2;
            if q.has_pending_spans() {
                q.mark_all(n);
                marks += 1;
                let line = format!("{{\"kind\":\"drop-marker\",\"at_seq\":{n}}}").into_bytes();
                q.enqueue(QueuedRecord {
                    seq: n,
                    bytes: line,
                });
                enqueued += 1;
            }
            // Dispatch promptly: pop one, deliver markers in order.
            if let Some(popped_rec) = q.pop() {
                popped += 1;
                let (kind, at) = stream_record_identity(&popped_rec.bytes);
                if kind == "drop-marker" {
                    q.clear_marker(at);
                }
            }
            // Bound at every step: live deltas ≤ queued + 1.
            for s in q.spans.iter() {
                assert!(
                    s.covering.len() as u64 <= q.queued_records() + 1,
                    "coverage bounded by live markers (round {n}: {} deltas, {} queued)",
                    s.covering.len(),
                    q.queued_records()
                );
            }
        }
        assert!(marks >= 1, "marks must flow (got {marks})");
        // Exact eviction accounting (no quiet loss/gain — every
        // record enqueued is popped, queued, or folded).
        let evicted = enqueued - popped - q.queued_records();
        assert_eq!(q.gross().0, evicted);
        assert!(q.gross().1 >= evicted, "every fold carries bytes");
        // Drain: pop everything, clear every marker, then one final
        // mark covers any flagged-dead tail and clears it.
        while let Some(popped_rec) = q.pop() {
            let (kind, at) = stream_record_identity(&popped_rec.bytes);
            if kind == "drop-marker" {
                q.clear_marker(at);
            }
        }
        q.mark_all(51);
        q.clear_marker(51);
        assert!(
            q.spans().is_empty(),
            "all proven drops clear, got {:?}",
            q.spans()
        );
    }

    /// R1 C1(b): delivering an OLD marker must not erase drops
    /// covered only by a NEWER undelivered marker.
    #[test]
    fn old_marker_delivery_keeps_newer_coverage() {
        let mut q = StreamQueue::new(100, 64);
        for seq in 1..=5u64 {
            q.fold(seq, 41, DropReason::QueueFull);
        }
        q.mark_all(1); // marker 1 covers the first 5
        for seq in 6..=8u64 {
            q.fold(seq, 41, DropReason::QueueFull);
        }
        q.mark_all(2); // marker 2 covers all 8
        q.clear_marker(1); // marker 1 delivers (old)
        let spans = q.spans();
        let covered: u64 = spans.iter().map(|s| s.records).sum();
        assert_eq!(
            covered, 3,
            "newer-only coverage survives old-marker delivery"
        );
        q.clear_marker(2); // marker 2 delivers (new)
        assert!(q.spans().is_empty(), "all proven drops clear");
        assert_eq!(q.gross(), (8, 8 * 41), "gross untouched by clears");
    }

    /// Reversed delivery order (new marker first) clears the full
    /// cumulative proof at once; the older delivery after is a
    /// no-op (its content was already proven).
    #[test]
    fn reversed_delivery_clears_cumulative_once() {
        let mut q = StreamQueue::new(100, 64);
        for seq in 1..=5u64 {
            q.fold(seq, 41, DropReason::QueueFull);
        }
        q.mark_all(1);
        for seq in 6..=8u64 {
            q.fold(seq, 41, DropReason::QueueFull);
        }
        q.mark_all(2);
        q.clear_marker(2); // new first: proves all 8
        assert!(q.spans().is_empty());
        q.clear_marker(1); // old after: no-op
        assert!(q.spans().is_empty());
        assert_eq!(q.gross(), (8, 8 * 41));
    }

    #[test]
    fn marker_loss_impossible_spans_carry_forward() {
        let mut q = StreamQueue::new(100, 64);
        q.enqueue(rec(1, 40));
        q.enqueue(rec(2, 40));
        q.enqueue(rec(3, 40)); // evicts seq 1
        // Marker emitted but evicted before delivery: spans stay.
        assert!(q.has_pending_spans());
        q.enqueue(rec(4, 200)); // oversize: folds into the same span
        let spans = q.spans();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].records, 2);
    }

    /// R2 Gate 4a (F6): recovery must update coverage deltas, not
    /// just span totals — an old-marker ack after `strike` + new
    /// `fold` must not erase the new drop. Adopted from the R2
    /// linked queue probe.
    #[test]
    fn recovered_old_drop_must_not_erase_new_drop() {
        use crate::service::envelope::DropReason::QueueFull;
        let mut q = StreamQueue::new(65536, 64);
        let t1 = q.fold(1, 10, QueueFull);
        q.mark_all(1);
        assert_eq!(q.strike(1, 10, QueueFull, t1), (1, 10));
        q.fold(2, 20, QueueFull);
        assert!(
            q.has_pending_spans(),
            "new uncovered drop must stay pending"
        );
        q.clear_marker(1);
        assert_eq!(
            q.spans().iter().map(|s| s.records).sum::<u64>(),
            1,
            "new drop must remain"
        );
    }

    /// R3 Gate 4 (F3): recovery must bind to the actual folded
    /// cohort, not window sequence — an old queued record can fold
    /// AFTER a newer marker, so `marker ≥ seq` misidentifies its
    /// cohort. Unequal byte lengths (equal fixtures mask byte
    /// misaccounting). Adopted from the R3 linked probe
    /// (`late_strike_underclaims_new_bytes`).
    #[test]
    fn strike_binds_fold_cohort_not_window_sequence() {
        use crate::service::envelope::DropReason::Epipe;
        let mut q = StreamQueue::new(65536, 4096);
        q.fold(1, 10, Epipe);
        q.mark_all(10);
        let t2 = q.fold(2, 20, Epipe);
        q.mark_all(11);
        q.fold(3, 30, Epipe);
        q.strike(2, 20, Epipe, t2);
        q.clear_marker(11);
        let n: u64 = q.spans().iter().map(|s| s.records).sum();
        let b: u64 = q.spans().iter().map(|s| s.bytes).sum();
        assert_eq!((n, b), (1, 30), "uncovered record 3 is 30 bytes");
    }

    /// R3 Gate 4 (F3): a late old-sequence record recovered before
    /// its prior marker delivers must not stay pending. Adopted
    /// from the R3 linked probe (`late_old_record_strike`).
    #[test]
    fn strike_of_old_record_clears_with_prior_marker() {
        use crate::service::envelope::DropReason::Epipe;
        let mut q = StreamQueue::new(65536, 4096);
        q.fold(1, 10, Epipe);
        q.mark_all(10);
        let t2 = q.fold(2, 20, Epipe);
        assert_eq!(q.strike(2, 20, Epipe, t2), (1, 20));
        q.clear_marker(10);
        let n: u64 = q.spans().iter().map(|s| s.records).sum();
        let b: u64 = q.spans().iter().map(|s| s.bytes).sum();
        assert_eq!((n, b), (0, 0), "acked drop must not stay pending");
    }

    /// Recovery of an already-delivered fold must no-op (its
    /// growth was delivered-proven and left the span at delivery;
    /// re-shrinking would double-subtract into newer growth).
    #[test]
    fn strike_after_delivery_is_noop() {
        use crate::service::envelope::DropReason::Epipe;
        let mut q = StreamQueue::new(65536, 4096);
        let t1 = q.fold(1, 10, Epipe);
        q.mark_all(1);
        q.fold(2, 20, Epipe);
        q.mark_all(2);
        q.clear_marker(1);
        assert_eq!(q.strike(1, 10, Epipe, t1), (0, 0));
        let spans = q.spans();
        assert_eq!(spans.len(), 1);
        assert_eq!((spans[0].records, spans[0].bytes), (1, 20));
        q.clear_marker(2);
        assert!(q.spans().is_empty());
    }

    /// R3 Gate 4 (F4): delivering a thinned marker itself must
    /// stay exact — 65 folds + `clear(63)` leaves the 2 records
    /// past 63's coverage, not 3. Adopted from the R3 linked probe
    /// (`thinned_marker_delivered`).
    #[test]
    fn delivering_thinned_marker_itself_stays_exact() {
        use crate::service::envelope::DropReason::Epipe;
        let mut q = StreamQueue::new(65536, 4096);
        for n in 1..=65 {
            q.fold(n, 10, Epipe);
            q.mark_all(n);
        }
        q.clear_marker(63);
        let n: u64 = q.spans().iter().map(|s| s.records).sum();
        assert_eq!(n, 2, "65 folds, marker 63 delivered: pending must be 2");
    }

    /// R3 Gate 4 (F4): out-of-order delivery across thinned
    /// markers stays exact at every step.
    #[test]
    fn out_of_order_marker_delivery_stays_exact() {
        use crate::service::envelope::DropReason::Epipe;
        let mut q = StreamQueue::new(65536, 4096);
        for n in 1..=65 {
            q.fold(n, 10, Epipe);
            q.mark_all(n);
        }
        let pending = |q: &StreamQueue| {
            q.spans()
                .iter()
                .map(|s| (s.records, s.bytes))
                .fold((0u64, 0u64), |(nr, nb), (r, b)| (nr + r, nb + b))
        };
        q.clear_marker(60);
        assert_eq!(pending(&q), (5, 50));
        q.clear_marker(63);
        assert_eq!(pending(&q), (2, 20));
        q.clear_marker(65);
        assert_eq!(pending(&q), (0, 0));
        q.clear_marker(1);
        assert_eq!(pending(&q), (0, 0));
    }

    /// R2 Gate 4b (F6): cumulative markers must clear everything
    /// they prove, even after coverage thinning — 70 `fold→mark`
    /// + `clear(70)` must leave nothing. Adopted from the R2 linked
    /// queue probe.
    #[test]
    fn newest_cumulative_marker_must_clear_all_after_thinning() {
        use crate::service::envelope::DropReason::QueueFull;
        let mut q = StreamQueue::new(65536, 64);
        for seq in 1..=70 {
            q.fold(seq, 41, QueueFull);
            q.mark_all(seq);
        }
        q.clear_marker(70);
        assert!(
            q.spans().is_empty(),
            "all 70 drops were proven by marker 70, got {:?}",
            q.spans()
        );
    }
}
