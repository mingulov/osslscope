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
//! since the previous marker. Spans clear ONLY on newline-delivery.

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

/// Folded drop span (the §5.2 ledger entry shape + merge state).
#[derive(Debug, Clone)]
pub struct LedgerSpan {
    pub first_seq: u64,
    pub last_seq: u64,
    pub records: u64,
    pub bytes: u64,
    pub folds: u64,
    pub reason: DropReason,
    /// Covered by an emitted marker (marker-carried, awaiting
    /// newline-delivery to clear). New folds NEVER merge into
    /// marked spans (their content is already marker-rendered —
    /// merging would hide uncovered bytes under old coverage);
    /// each marker build re-covers every records>0 span (marked or
    /// not — the delayed marker covers both spans, §5.2), so an
    /// evicted marker needs no unmark path.
    pub marked: bool,
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
            marked: false,
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
    /// UNMARKED span. Marked (marker-covered) spans never absorb
    /// new folds (their content is already rendered into an
    /// emitted marker); a same-cause fold past a marked span opens
    /// a second unmarked span (same reason, disjoint coverage —
    /// each span keeps `0 ≤ folds ≤ records − 1` exactly, and the
    /// 64-cap still never binds: ≤2 spans per cause).
    pub fn fold(&mut self, seq: u64, bytes: u64, reason: DropReason) {
        self.gross_records += 1;
        self.gross_bytes += bytes;
        let slot = &mut self.gross_by_reason[Self::reason_idx(reason)];
        slot.0 += 1;
        slot.1 += bytes;
        if let Some(span) = self
            .spans
            .iter_mut()
            .find(|s| s.reason == reason && !s.marked)
        {
            span.merge(seq, bytes);
            return;
        }
        debug_assert!(self.spans.len() < LEDGER_CAP);
        if self.spans.len() < LEDGER_CAP {
            self.spans.push(LedgerSpan::fresh(seq, bytes, reason));
        }
    }

    /// Enqueue one rendered record. Evicts oldest-first while either
    /// cap would break; a record larger than `--queue-bytes` alone is
    /// accounted as dropped without enqueueing (never an evict loop).
    pub fn enqueue(&mut self, record: QueuedRecord) {
        let size = record.full_bytes();
        if size > self.queue_bytes {
            self.fold(record.seq, size, DropReason::QueueFull);
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
            }
        }
        // After evicting everything the record still fits (size ≤
        // cap proven above; events ≥ 1 by the [64,4096] range).
        self.queued_bytes += size;
        self.queued.push_back(record);
    }

    /// Pop the oldest queued record for the tap writer.
    pub fn pop(&mut self) -> Option<QueuedRecord> {
        let record = self.queued.pop_front()?;
        self.queued_bytes -= record.full_bytes();
        Some(record)
    }

    /// Uncleared spans (NET of recovery) for marker emission /
    /// `stream_pending[]` — every records>0 span, marked or not
    /// (marked-but-undelivered spans are uncleared).
    pub fn spans(&self) -> Vec<DropLedgerEntry> {
        self.spans
            .iter()
            .filter(|s| s.records > 0)
            .map(LedgerSpan::entry)
            .collect()
    }

    /// Spans needing marker coverage (unmarked, records>0).
    pub fn uncovered(&self) -> Vec<DropLedgerEntry> {
        self.spans
            .iter()
            .filter(|s| !s.marked && s.records > 0)
            .map(LedgerSpan::entry)
            .collect()
    }

    /// A new marker is needed iff uncovered folds exist (a marker
    /// was emitted with no new folds since → no marker, §5.2).
    pub fn has_pending_spans(&self) -> bool {
        self.spans.iter().any(|s| !s.marked && s.records > 0)
    }

    /// Cover every records>0 span (call at marker build — the
    /// emitted marker carries `spans()` verbatim, marked or not).
    /// Zero-record spans sweep here (struck-empty, unmarked — their
    /// bytes already recovered; marked zero spans clear at
    /// delivery).
    pub fn mark_all(&mut self) {
        self.spans.retain(|s| s.records > 0 || s.marked);
        for span in self.spans.iter_mut() {
            if span.records > 0 {
                span.marked = true;
            }
        }
    }

    /// Clear marker-covered spans on newline-delivery of their
    /// marker (struck bytes already recovered — delivery clears
    /// coverage, never double-corrects).
    pub fn clear_marked(&mut self) {
        self.spans.retain(|s| !s.marked);
    }

    /// Strike a landed record OUT of the folded spans (gross totals
    /// stay; §7.2 gross/net split). Strikes newest-first within the
    /// named cause; returns the struck (records, bytes).
    pub fn strike(&mut self, seq: u64, bytes: u64, reason: DropReason) -> (u64, u64) {
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
            // Strike one record's bytes from this span. The struck
            // record takes its merge with it (`folds − 1`), which
            // preserves `0 ≤ folds ≤ records − 1` exactly (Control 1
            // checks the invariant on every span, marker-carried or
            // pending).
            span.records -= 1;
            span.bytes = span.bytes.saturating_sub(bytes);
            span.folds = span.folds.saturating_sub(1);
            struck_records = 1;
            struck_bytes = bytes;
            break;
        }
        // Emptied spans sweep at the next `mark_all` (marked
        // empties clear at delivery; unmarked empties carry
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
        // One landed late: strike it (NET), gross stays.
        let (r, b) = q.strike(2, 41, DropReason::QueueFull);
        assert_eq!((r, b), (1, 41));
        assert_eq!(q.gross(), (2, 82));
        let spans = q.spans();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].records, 1);
        assert!(spans[0].folds <= spans[0].records.saturating_sub(1));
        // Marker emission covers; delivery clears exactly the
        // covered spans (new folds past coverage open a sibling).
        assert!(q.has_pending_spans());
        q.mark_all();
        assert!(!q.has_pending_spans());
        q.fold(9, 41, DropReason::QueueFull);
        assert!(q.has_pending_spans());
        assert_eq!(q.spans().len(), 2);
        q.clear_marked();
        assert_eq!(q.spans().len(), 1);
        assert_eq!(q.spans()[0].records, 1);
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
}
