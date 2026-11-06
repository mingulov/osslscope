//! SPDX-License-Identifier: GPL-3.0-or-later
//! 6B envelope + boundary shapes (§§10–11, `service-window-v1`,
//! stream `StreamRecord`s, `service-run-v1`).
//!
//! T7.4-frozen L2 marking: positive-count/empty-bounds rows carry
//! EXPLICITLY UNKNOWN hit intervals — contributor bounds are
//! `Option` (`None` = unknown, never merged), the site_sources entry
//! carries `hit_interval_known`, and a fully-unknown merged row uses
//! the inverted pair (`first_ns = u64::MAX`, `last_ns = 0`) PLUS the
//! marking. Fallback endpoints NEVER enter `first_ns`/`last_ns`.

use crate::evidence::{CaptureDocument, DispositionRecord, ObjectId, OpensslVersion, TargetRecord};
use crate::service::state::{AbandonReason, PolicyIdentity, RunId};

/// `WindowEnvelope` schema word.
pub const SCHEMA_WINDOW: &str = "service-window-v1";

/// Fully-unknown hit-interval sentinel (L2): inverted by
/// construction, always paired with
/// `hit_interval_known == false`. Consumers MUST read the marking;
/// the pair alone fails every containment check by design.
pub const UNKNOWN_FIRST_NS: u64 = u64::MAX;
pub const UNKNOWN_LAST_NS: u64 = 0;

/// Window span: `CaptureWindow` shape + the `accum_cut` flag.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WindowSpan {
    pub requested_start_ns: u64,
    pub requested_end_ns: u64,
    pub effective_start_ns: u64,
    pub effective_end_ns: u64,
    pub signal_cut: bool,
    pub accum_cut: bool,
}

/// Single-tick budget exceed note (§5.1).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccumExceeded {
    pub bytes: u64,
}

/// Spill placement note (§5.1).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct Spilled {
    pub records: u64,
    pub bytes: u64,
}

/// Admission-tick span + carry note (§5.1).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TickSpan {
    pub first_tick: u64,
    pub last_tick: u64,
    pub carried_records: u32,
    pub carried_from_seq: Option<u64>,
}

/// One contributing member (§11.1 `members[]`): identity + per-member
/// facts. `clamp` is the T7.4 L3 note: this member's saturating
/// `max(0, open − close)` clamped units this window (0 on stable
/// windows — the residual-formula input). `loss` is the T7.4
/// additive window-loss projection (the §11.1 set-difference result
/// the §9 coverage oracle reads as "envelope loss intersections").
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MemberEntry {
    pub pid: u32,
    pub starttime: u64,
    pub segment: u64,
    pub image_epoch: u64,
    pub target: TargetRecord,
    pub openssl: OpensslVersion,
    pub disposition: Option<DispositionRecord>,
    pub retired: bool,
    #[serde(default)]
    pub clamp: u64,
    #[serde(default)]
    pub loss: MemberWindowLoss,
}

/// Window loss projection per member (§11.1 loss intersection).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct MemberWindowLoss {
    pub loss_delta: u64,
    pub lost_windows: Vec<LostWindowView>,
    pub coalesced_delta: u64,
    pub deferred_ticks_delta: u64,
    pub deferred_first_tick: u64,
    pub deferred_last_tick: u64,
    #[serde(default)]
    pub ring_delta: [u64; 8],
}

/// One clipped lost interval `[start_tick, end_tick)`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LostWindowView {
    pub start_tick: u64,
    pub end_tick: u64,
    pub cause: String,
}

/// Site reference inside `site_sources[]` (mirrors `SiteKey`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SiteRef {
    pub object: ObjectId,
    pub device: u64,
    pub inode: u64,
    pub offset: u64,
}

/// One contributor's bounds (L2): sealed or unknown. `None` bounds
/// are NEVER merged into the row's `first_ns`/`last_ns`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ContributorEntry {
    pub segment: u64,
    pub image_epoch: u64,
    pub calls: u64,
    pub first_ns: Option<u64>,
    pub last_ns: Option<u64>,
    pub bounds_known: bool,
}

/// Cross-member provenance per merged site row, 1:1 (§11.1).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SiteSourceEntry {
    pub site: SiteRef,
    pub generation: u32,
    pub calls: u64,
    /// L2: false ⟺ zero known contributors (the merged row's
    /// interval is EXPLICITLY UNKNOWN).
    pub hit_interval_known: bool,
    pub contributors: Vec<ContributorEntry>,
}

/// Per-window finalized record (`service-window-v1`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WindowEnvelope {
    pub schema: String,
    pub seq: u64,
    pub generation: u64,
    pub run_id: RunId,
    pub window: WindowSpan,
    pub accum_exceeded: Option<AccumExceeded>,
    pub spilled: Spilled,
    pub staging_peak_bytes: u64,
    pub tick_span: TickSpan,
    pub policy: Option<PolicyIdentity>,
    pub members: Vec<MemberEntry>,
    pub site_sources: Vec<SiteSourceEntry>,
    /// Verbatim `crypto-watch-v1` envelopes (round-trip equality).
    pub crypto_watch: Vec<serde_json::Value>,
    pub document: CaptureDocument,
}

/// Split a rendered envelope (with EMPTY `crypto_watch`) at the
/// array site for streaming publication (R1 finding 2b): returns
/// `(head, tail)` such that `head + "[" + inner + "]" + tail` is
/// byte-identical to the old NEEDLE splice. `None` ⟺ the needle is
/// absent (fail closed — same as the old `!spliced` arm).
pub fn split_envelope_at_array(rendered: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    const NEEDLE: &[u8] = b"\"crypto_watch\":[]";
    let pos = rendered.windows(NEEDLE.len()).position(|w| w == NEEDLE)?;
    let arr = pos + NEEDLE.len() - 2;
    Some((rendered[..arr].to_vec(), rendered[arr + 2..].to_vec()))
}

/// Drop-ledger reasons (§5.2 legend).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DropReason {
    QueueFull,
    Epipe,
    StreamAbandoned,
}

/// Drop-ledger entry shape (§5.2, frozen).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DropLedgerEntry {
    pub first_seq: u64,
    pub last_seq: u64,
    pub records: u64,
    pub bytes: u64,
    pub folds: u64,
    pub reason: DropReason,
}

/// Stream JSONL `StreamRecord` (§10 boundary).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum StreamRecord {
    /// Reference to a durable window file (sha256 over the bytes).
    WindowRef {
        schema: String,
        generation: u64,
        seq: u64,
        sha256: String,
    },
    /// Drop-marker covering evictions since the previous marker.
    DropMarker {
        schema: String,
        at_seq: u64,
        generation: u64,
        stream_gaps: Vec<DropLedgerEntry>,
    },
}

/// `abandoned` attempt-history note (§4.4).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AbandonedNote {
    pub seq: u64,
    pub run_id: RunId,
    pub generation: u64,
    pub requested_start_ns: u64,
    pub requested_end_ns: u64,
    pub reason: AbandonReason,
    pub cut_tail_ns: Option<CutTail>,
}

/// Orphaned `accum_cut` tail `[effective_end, requested_end]` (§4.4).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CutTail {
    pub effective_end_ns: u64,
    pub requested_end_ns: u64,
}

/// Sealing/recovering run's orphan-tail carrier (§4.4).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OrphanCutTail {
    pub seq: u64,
    pub effective_end_ns: u64,
    pub requested_end_ns: u64,
}

/// Uncertain publish (link landed, dir fsync failed, §4.2).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DurabilityUncertain {
    pub seq: u64,
}

/// Adopted-publish note (§4.4 open+present row).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CommitRecovered {
    pub seq: u64,
}

/// Quota record (§6.2).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct QuotaExceeded {
    pub bytes: u64,
    pub cap: u64,
    pub cause: QuotaCause,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaCause {
    ProtectedEvidence,
    DeletionFailure,
}

/// Per-reason drop totals (§7.3 summary).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct ReasonTotals {
    pub records: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct ByReason {
    pub queue_full: ReasonTotals,
    pub epipe: ReasonTotals,
    pub stream_abandoned: ReasonTotals,
}

/// GROSS fold-time monotone totals (never struck, §7.2).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct StreamDrops {
    pub records: u64,
    pub bytes: u64,
    pub by_reason: ByReason,
}

/// Recovery-struck amount (§7.2).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct TapRecovered {
    pub records: u64,
    pub bytes: u64,
}

/// Cutoff-frozen unreconciled tap op (§7.2).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TapUncertain {
    pub op: String,
    pub record: UncertainRecord,
    pub dest: UncertainDest,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UncertainRecord {
    pub kind: String,
    pub seq: Option<u64>,
    pub span: Option<(u64, u64)>,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UncertainDest {
    pub path: String,
    pub dev: u64,
    pub ino: u64,
}

/// Overflow counters keep bytes but not identity (§7.2).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct UncertainOverflow {
    pub ops: u64,
    pub bytes: u64,
}

/// Reconciled rotation-tail extension (§6.1).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RotationTail {
    pub file: String,
    pub extra_records: u64,
    pub extra_bytes: u64,
}

/// Worker-op outcomes (§7.2 failure accounting).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpOutcome {
    Done,
    Expired,
    Cancelled,
    Lost,
    Failed,
    WorkerUnavailable,
}

/// One accounted op (§7.2).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CloseOp {
    pub op: String,
    pub outcome: OpOutcome,
}

/// `run-summary.json` (`service-run-v1`, §7.3).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RunSummary {
    pub schema: String,
    pub run_id: RunId,
    pub generation: u64,
    pub run_origin_ns: u64,
    pub first_seq: Option<u64>,
    pub last_seq: Option<u64>,
    pub abandoned: Vec<AbandonedNote>,
    #[serde(default)]
    pub abandoned_overflow: u64,
    pub commit_recovered: Option<CommitRecovered>,
    pub orphan_cut_tail: Option<OrphanCutTail>,
    pub durability_uncertain: Option<DurabilityUncertain>,
    pub final_close_completed_ns: Option<u64>,
    #[serde(default)]
    pub close_unmeasured: Vec<u64>,
    #[serde(default)]
    pub reloads_adopted: u64,
    #[serde(default)]
    pub reloads_rejected: u64,
    #[serde(default)]
    pub windows_cut_accum: u64,
    pub quota_exceeded: Option<QuotaExceeded>,
    pub stream_drops: StreamDrops,
    pub tap_recovered: TapRecovered,
    #[serde(default)]
    pub tap_uncertain: Vec<TapUncertain>,
    #[serde(default)]
    pub tap_uncertain_overflow: UncertainOverflow,
    #[serde(default)]
    pub stream_pending: Vec<DropLedgerEntry>,
    #[serde(default)]
    pub rotation_tail: Vec<RotationTail>,
    #[serde(default)]
    pub rotation_tail_overflow: u64,
    #[serde(default)]
    pub close_accounting: Vec<CloseOp>,
    #[serde(default)]
    pub close_accounting_overflow: u64,
    #[serde(default)]
    pub diagnostics_dropped: u64,
    pub exit: u8,
}

impl RunSummary {
    pub fn blank(run_id: RunId, generation: u64, run_origin_ns: u64) -> Self {
        Self {
            schema: crate::service::state::SCHEMA_RUN.to_string(),
            run_id,
            generation,
            run_origin_ns,
            first_seq: None,
            last_seq: None,
            abandoned: Vec::new(),
            abandoned_overflow: 0,
            commit_recovered: None,
            orphan_cut_tail: None,
            durability_uncertain: None,
            final_close_completed_ns: None,
            close_unmeasured: Vec::new(),
            reloads_adopted: 0,
            reloads_rejected: 0,
            windows_cut_accum: 0,
            quota_exceeded: None,
            stream_drops: StreamDrops::default(),
            tap_recovered: TapRecovered::default(),
            tap_uncertain: Vec::new(),
            tap_uncertain_overflow: UncertainOverflow::default(),
            stream_pending: Vec::new(),
            rotation_tail: Vec::new(),
            rotation_tail_overflow: 0,
            close_accounting: Vec::new(),
            close_accounting_overflow: 0,
            diagnostics_dropped: 0,
            exit: 4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// L2 shape lock: unknown contributors carry `None` bounds +
    /// `bounds_known == false`; the row marks `hit_interval_known`.
    #[test]
    fn l2_unknown_marking_shape() {
        let c = ContributorEntry {
            segment: 1,
            image_epoch: 0,
            calls: 9,
            first_ns: None,
            last_ns: None,
            bounds_known: false,
        };
        let e = SiteSourceEntry {
            site: SiteRef {
                object: ObjectId("o".to_string()),
                device: 1,
                inode: 2,
                offset: 3,
            },
            generation: 0,
            calls: 9,
            hit_interval_known: false,
            contributors: vec![c],
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["hit_interval_known"], false);
        assert_eq!(v["contributors"][0]["first_ns"], serde_json::Value::Null);
        assert_eq!(v["contributors"][0]["bounds_known"], false);
        // The sentinel pair is inverted by construction.
        const _: () = assert!(UNKNOWN_FIRST_NS > UNKNOWN_LAST_NS);
    }

    /// Streaming split/join is byte-identical to the old NEEDLE
    /// splice (R1 finding 2b — "NEEDLE capacity respected"): the
    /// envelope renders `"crypto_watch":[]` exactly once (string
    /// values render with ESCAPED quotes, so no value can match
    /// the unescaped pattern — the battery below embeds hostile
    /// near-misses), and `head + "[" + inner + "]" + tail` equals
    /// the spliced bytes for every inner (empty, one, many).
    #[test]
    fn streaming_split_matches_splice_byte_identical() {
        fn splice(rendered: &[u8], inner: &[u8]) -> Vec<u8> {
            const NEEDLE: &[u8] = b"\"crypto_watch\":[]";
            let mut bytes = rendered.to_vec();
            let pos = bytes
                .windows(NEEDLE.len())
                .position(|w| w == NEEDLE)
                .expect("needle present");
            let arr = pos + NEEDLE.len() - 2;
            let mut array = Vec::with_capacity(inner.len() + 2);
            array.push(b'[');
            array.extend_from_slice(inner);
            array.push(b']');
            bytes.splice(arr..arr + 2, array.iter().copied());
            bytes
        }
        let rendered = br#"{"schema":"service-window-v1","seq":3,"note":"say \"crypto_watch\":[] loudly","nested":{"crypto_watch":[1]},"crypto_watch":[],"document":{"a":[1,2]}}"#.to_vec();
        for inner in [
            Vec::new(),
            br#"{"k":1}"#.to_vec(),
            br#"{"k":1},{"k":[2,{"crypto_watch":[]}]}"#.to_vec(),
        ] {
            let (head, tail) = split_envelope_at_array(&rendered).expect("needle splits");
            let mut joined = Vec::with_capacity(head.len() + tail.len() + inner.len() + 2);
            joined.extend_from_slice(&head);
            joined.push(b'[');
            joined.extend_from_slice(&inner);
            joined.push(b']');
            joined.extend_from_slice(&tail);
            assert_eq!(joined, splice(&rendered, &inner), "inner {inner:?}");
        }
        // No needle (corrupt render): fail closed, never a guess.
        assert!(split_envelope_at_array(b"{}").is_none());
        assert!(split_envelope_at_array(b"{\"crypto_watch\":[1]}").is_none());
    }

    #[test]
    fn stream_records_match_boundary_shapes() {
        let r = StreamRecord::WindowRef {
            schema: SCHEMA_WINDOW.to_string(),
            generation: 0,
            seq: 4,
            sha256: "ab".to_string(),
        };
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            serde_json::json!({
                "schema": "service-window-v1", "kind": "window-ref",
                "generation": 0, "seq": 4, "sha256": "ab",
            })
        );
        let m = StreamRecord::DropMarker {
            schema: SCHEMA_WINDOW.to_string(),
            at_seq: 5,
            generation: 0,
            stream_gaps: vec![DropLedgerEntry {
                first_seq: 1,
                last_seq: 2,
                records: 3,
                bytes: 4,
                folds: 1,
                reason: DropReason::QueueFull,
            }],
        };
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["kind"], "drop-marker");
        assert_eq!(v["stream_gaps"][0]["reason"], "queue_full");
    }
}
