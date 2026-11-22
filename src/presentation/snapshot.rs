// SPDX-License-Identifier: GPL-3.0-or-later
//! 6C presentation snapshot (§6C-1): `OperatorSnapshot`, the
//! dual-path (service envelope / oneshot doc_json) fold, epoch
//! accumulators, checkpoint, and the unknown-registry invariant.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Presentation schema word (†, §6C-1).
pub const SCHEMA: &str = "osslscope-presentation-v1";
/// Presenter checkpoint schema word (†, §6C-1c).
/// Checkpoint schema v4 (P2fix6 NEW-35 — accumulators carry the
/// retained current-run summary gross alongside the early-adopted
/// summary + the export accumulation starts; older checkpoints
/// discard + replay through the designed migration below).
pub const CHECKPOINT_SCHEMA: &str = "osslscope-presenter-checkpoint-v4";

/// Bounded regular-file intake bound for the checkpoint file
/// (P2fix13 NEW-76): writer output is budget-bounded
/// accumulator state (kilobytes in practice); 64 MiB sits far
/// above any admitted snapshot while keeping a substituted
/// or garbage target from consuming unbounded memory at load.
const CHECKPOINT_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Flagged-entry note words (†, §6C-1d). These are NOTES, not
/// reasons: they ride flagged entries' `note` field, never the
/// reason word (the 9 frozen reasons live in [`is_reason`]).
pub const NOTE_SUMMARY_MISMATCH: &str = "summary_mismatch";
pub const NOTE_SEALED_FROM_CLOSE: &str = "sealed_from_close_no_summary";
/// Combined sticky spelling (both notes on one flagged
/// accumulator — legitimate §6C-1d output, P2fix2 item 13).
pub const NOTE_SEALED_AND_MISMATCH: &str = "sealed_from_close_no_summary+summary_mismatch";

/// Stage-write fault injection (P2fix7 NEW-45, test-only):
/// remaining injected EIO failures at the checkpoint stage
/// write — each armed failure fails the stage write AFTER the
/// owned stage is created, so the production pre-commit cleanup
/// must remove it. Inert at zero. `pub(crate)` so the export
/// staged-retry pin arms it.
#[cfg(test)]
pub(crate) mod stage_fault {
    thread_local! { static FAIL_STAGE_WRITE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) }; }
    /// Arm `n` injected stage-write failures.
    pub fn arm(n: u64) {
        FAIL_STAGE_WRITE.with(|f| f.set(n));
    }
    /// Take one injected failure (true = fail this write).
    pub fn take() -> bool {
        FAIL_STAGE_WRITE.with(|f| {
            let n = f.get();
            if n > 0 {
                f.set(n - 1);
                true
            } else {
                false
            }
        })
    }
}

/// True when `reason` is one of the 9 frozen §6C-4 words.
pub fn is_reason(word: &str) -> bool {
    matches!(
        word,
        "oneshot_no_sequence"
            | "trace_disabled"
            | "stream_unconfigured"
            | "observe_only"
            | "unstable_snapshot"
            | "gap_covered"
            | "not_yet_observed"
            | "opt_in_disabled"
            | "api_unavailable"
    )
}

// --- Snapshot types (§6C-1, field-for-field) ---

/// Unknown-registry entry (§6C-4). `note` carries the §6C-1d
/// mismatch/seal notes on flagged stream entries only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnknownEntry {
    pub path: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Legacy-partition lane counts (C-14).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lanes {
    pub legacy_exclusive: u64,
    pub non_legacy_exclusive: u64,
    pub shared_ambiguous: u64,
    pub unfenced_tails: u64,
}

impl Lanes {
    pub fn sum(self) -> u64 {
        self.legacy_exclusive
            .saturating_add(self.non_legacy_exclusive)
            .saturating_add(self.shared_ambiguous)
            .saturating_add(self.unfenced_tails)
    }
}

/// Epoch PUBLIC-API 3-fold (§6C-1 `by_outcome`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByOutcome {
    pub success: u64,
    pub failure: u64,
    pub unknown: u64,
}

/// Per-class pair counts (§6D-7 class maps).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassCounts {
    pub success: u64,
    pub failure: u64,
    pub empty: u64,
    pub retry: u64,
    pub unknown: u64,
}

impl ClassCounts {
    pub fn sum(self) -> u64 {
        self.success
            .saturating_add(self.failure)
            .saturating_add(self.empty)
            .saturating_add(self.retry)
            .saturating_add(self.unknown)
    }

    /// The frozen `Failure ← {failure, empty, retry}` fold (§6D-2).
    pub fn by_outcome(self) -> ByOutcome {
        ByOutcome {
            success: self.success,
            failure: self
                .failure
                .saturating_add(self.empty)
                .saturating_add(self.retry),
            unknown: self.unknown,
        }
    }
}

/// Epoch partial/fatal windows by first gap class (P-09, §6C-5 order).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochPartial {
    pub unknown_denominator: u64,
    pub undiscovered_sites: u64,
    pub unattached_sites: u64,
    pub loss: u64,
    pub unattributed_calls: u64,
    pub startup_gap: u64,
    pub tail_gap: u64,
    pub signal_cut: u64,
    pub visibility_lost: u64,
    pub no_reasons: u64,
}

/// Epoch lost-interval events by cause (P-08, C-01 order).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochByCause {
    pub corpse_wait: u64,
    pub cgroup_move: u64,
    pub membership_unknown: u64,
    pub ring_loss: u64,
    pub connector_drops: u64,
    pub connector_enobufs: u64,
    pub scan_loss: u64,
    pub signal_prefix_unwitnessed: u64,
    pub drain_pending: u64,
    pub exec_spanning_aggregate: u64,
    pub coalesced_loss: u64,
    pub skipped_tick: u64,
}

/// One lost interval (frozen keys).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LostInterval {
    pub start_tick: u64,
    pub end_tick: u64,
    pub cause: String,
}

/// Window-close session loss (§6C-1 `loss.session`, C-01 shape).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionLossShape {
    pub ring: [u64; 8],
    pub connector_drops: u64,
    pub connector_enobufs: u64,
    pub scan_loss: u64,
    pub signal_dropped: u64,
    pub signal_prefix_unwitnessed: u64,
    pub drain_pending: u64,
    pub polling_fallback: bool,
    pub unattributed_events: u64,
    pub admitted_exit_artifacts: u64,
    pub lost_intervals: Vec<LostInterval>,
    pub coalesced: u64,
}

/// Per-reason drop totals.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReasonTotals {
    pub records: u64,
    pub bytes: u64,
}

/// Stream drops block (§6C-1 `stream`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamBlock {
    pub drops: StreamDropsShape,
    pub pending_spans: Option<u64>,
}

/// GROSS drop totals by reason.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamDropsShape {
    pub records: u64,
    pub bytes: u64,
    pub queue_full: ReasonTotals,
    pub epipe: ReasonTotals,
    pub stream_abandoned: ReasonTotals,
}

/// Component-wise gross maxima (P2fix6 NEW-35): max wins per
/// component, never added (the frozen reconcile rule).
fn max_stream_drops(a: StreamDropsShape, b: StreamDropsShape) -> StreamDropsShape {
    let max_totals = |x: ReasonTotals, y: ReasonTotals| ReasonTotals {
        records: x.records.max(y.records),
        bytes: x.bytes.max(y.bytes),
    };
    StreamDropsShape {
        records: a.records.max(b.records),
        bytes: a.bytes.max(b.bytes),
        queue_full: max_totals(a.queue_full, b.queue_full),
        epipe: max_totals(a.epipe, b.epipe),
        stream_abandoned: max_totals(a.stream_abandoned, b.stream_abandoned),
    }
}

/// One latency distribution (cumulative `le` buckets, §6D-3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Distribution {
    pub buckets: [u64; 19],
    pub sum: u64,
    pub count: u64,
}

/// Per-API distributions (sparse L1, §6D-3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByApiEntry {
    pub success: Distribution,
    pub failure: Distribution,
    pub empty: Distribution,
    pub retry: Distribution,
    pub unknown: Distribution,
}

/// Epoch-accumulated histograms (§6C-1 `histograms`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistogramsBlock {
    pub edges: String,
    pub first_seq: u64,
    pub last_seq: u64,
    pub unmeasured_seqs: Vec<[u64; 2]>,
    pub capped_folded: u64,
    pub success: Distribution,
    pub failure: Distribution,
    pub empty: Distribution,
    pub retry: Distribution,
    pub unknown: Distribution,
    pub by_api: Option<BTreeMap<String, ByApiEntry>>,
    pub by_api_availability: Option<BTreeMap<String, String>>,
}

/// Trace exemplar (§6D-7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceExemplarShape {
    pub dir: String,
    pub key_hash16: String,
    pub api: u32,
    pub age_ns: u64,
}

/// Per-window 6D loss block (§6D-7 record).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceBlock {
    pub window_seq: u64,
    pub mode: String,
    pub paired: u64,
    pub trace_unpaired_entries: u64,
    pub trace_unpaired_results: u64,
    pub trace_depth_exceeded: u64,
    pub trace_dropped: u64,
    pub trace_capped: bool,
    pub trace_nonmonotonic_pairs: u64,
    pub trace_rejected_unknown_api: u64,
    pub ring_loss: [u64; 8],
    /// Window pairs by class (None while the window is
    /// pairing-uncertain — interpreted status withholds, raw
    /// counters above stay).
    pub class_window: Option<ClassCounts>,
    /// Epoch pairs by class (None while the epoch is
    /// pairing-uncertain, and always None on the service path —
    /// DELTA-2 withholds epoch trace series until the per-window
    /// producer contract exists; latest-wins survives only for
    /// cumulative snapshots from one verified producer run).
    pub class_epoch: Option<ClassCounts>,
    /// Window pairing-uncertainty (withholding marker — explains
    /// withheld classes; raw evidence, never null).
    #[serde(default)]
    pub pairing_uncertain: bool,
    /// Uncertainty reasons (empty unless uncertain).
    #[serde(default)]
    pub pairing_uncertainty: Vec<String>,
    /// Unbound window scope (P2fix3 NEW-P2e — carried from the
    /// sealed summary; the paired count above is a scope-marked
    /// diagnostic when set, never window-scoped evidence).
    #[serde(
        default,
        skip_serializing_if = "crate::provider_observation::trace::is_false"
    )]
    pub cut_unbound: bool,
    pub unmeasured_seqs: Vec<[u64; 2]>,
    #[serde(default)]
    pub gaps: Vec<serde_json::Value>,
    #[serde(default)]
    pub gap_overflow: u64,
    #[serde(default)]
    pub exemplars: Vec<TraceExemplarShape>,
}

/// Snapshot source (§6C-1 `source`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    pub mode: String,
    pub generation: Option<u64>,
    pub run_id: Option<RunIdShape>,
    pub window_seq: Option<u64>,
    pub window_sha256: Option<String>,
}

/// Preserved failed-unpublished epoch (P2fix11 NEW-67): the
/// accepted final state of an epoch that suffered a scan/build
/// failure, never published, and was then reset away by a
/// generation change. Its prefix counts + uncertainty survive
/// the reset (instead of being discarded) so the terminal
/// `PREVIOUS EPOCH` line and the follow JSON frame report the
/// TRUE previous epoch WITH its uncertainty. Checkpoint-
/// persisted (absent when none — the only other
/// backward-compatible absence besides admission).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreservedEpoch {
    pub generation: u64,
    pub window_seq: u64,
    pub calls_total: u64,
    pub lanes: [u64; 4],
    /// Sorted uncertainty flags (the closed 8-word vocabulary).
    pub unstable: Vec<String>,
    /// Unmeasured ranges at the epoch's final scan.
    pub unmeasured: Vec<[u64; 2]>,
}

/// Attempt identity (ATTEMPT identity, not epoch, §6C-3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunIdShape {
    pub pid: u32,
    pub starttime: u64,
    pub boot_id: String,
}

/// Window span + cuts (§6C-1 `window`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowBlock {
    pub requested_start_ns: u64,
    pub requested_end_ns: u64,
    pub effective_start_ns: u64,
    pub effective_end_ns: u64,
    pub signal_cut: bool,
    pub accum_cut: bool,
}

/// Completeness block (§6C-1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletenessBlock {
    pub state: Option<String>,
    #[serde(default)]
    pub reasons: Vec<String>,
    pub epoch_partial_by_class: EpochPartial,
}

/// Active policy identity (§6C-1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyActive {
    pub sha256: String,
    pub version: i64,
    pub rule_count: u64,
    pub adopted_seq: Option<u64>,
}

/// Policy block (§6C-1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBlock {
    pub active: Option<PolicyActive>,
    pub outcome: Option<String>,
}

/// Counts block (§6C-1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CountsBlock {
    pub calls_total: u64,
    pub calls_window: Option<u64>,
    pub lanes: Lanes,
    pub lanes_window: Option<Lanes>,
    pub site_rows: Option<u64>,
    pub by_outcome: Option<ByOutcome>,
}

/// Members block (§6C-1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembersBlock {
    pub observed: Option<u64>,
    pub retired_in_window: Option<u64>,
    pub retired_epoch: u64,
    pub deferred_depth: Option<u64>,
}

/// Loss block (§6C-1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LossBlock {
    pub session: Option<SessionLossShape>,
    pub epoch_by_cause: EpochByCause,
    #[serde(default)]
    pub counters: Vec<serde_json::Value>,
}

/// Health block (§6C-1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthBlock {
    pub snapshot_age_ns: Option<u64>,
    pub stale: bool,
}

/// Presenter-run stats (§6C-1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresenterStats {
    pub epoch_changes: u64,
    pub series_overflow: u64,
}

/// ONE immutable `OperatorSnapshot` per refresh (§6C-1). Every
/// `Option` serializes (nulls carry unknown entries — no
/// `skip_serializing_if` anywhere on this struct).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorSnapshot {
    pub schema: String,
    pub snapshot_seq: u64,
    pub produced_wall_ns: u64,
    pub produced_monotonic_ns: u64,
    pub source: Source,
    pub window: Option<WindowBlock>,
    pub completeness: CompletenessBlock,
    pub policy: PolicyBlock,
    pub exit_hint: Option<u8>,
    pub counts: CountsBlock,
    pub members: MembersBlock,
    pub loss: LossBlock,
    pub stream: Option<StreamBlock>,
    pub trace: Option<TraceBlock>,
    pub histograms: Option<HistogramsBlock>,
    pub health: HealthBlock,
    pub presenter: PresenterStats,
    #[serde(default)]
    pub unknown: Vec<UnknownEntry>,
    /// Alert markers for windows folded in THIS build (loss, cut,
    /// partial/fatal, violation — item 25): every folded window's
    /// markers ride here (not just the latest), so coalesced
    /// windows keep their facts; watch accumulates these sticky
    /// across frames. Empty when no window folded.
    #[serde(default)]
    pub markers: Vec<String>,
}

impl OperatorSnapshot {
    /// Unknown-registry invariant (§6C-4): every null has exactly
    /// one entry; entries are null-kind (path null, reason ≠
    /// `unstable_snapshot`) or flagged-kind (path non-null, reason
    /// == `unstable_snapshot`); reasons are closed-vocabulary.
    pub fn check_unknown_invariant(&self) -> Result<(), String> {
        let value = serde_json::to_value(self).map_err(|e| e.to_string())?;
        let mut nulls = Vec::new();
        collect_nulls(&value, String::new(), &mut nulls);
        // The `unknown` array itself never contributes null paths.
        nulls
            .retain(|p| p != "unknown" && !p.starts_with("unknown.") && !p.starts_with("unknown["));
        // `note` uses skip_serializing_if(None) so absent notes are
        // not nulls; present notes are non-null. No carve-out needed.
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for entry in &self.unknown {
            if !is_reason(&entry.reason) {
                return Err(format!("unknown reason word: {}", entry.reason));
            }
            *counts.entry(entry.path.as_str()).or_default() += 1;
            let node = resolve(&value, &entry.path);
            match node {
                // Sparse absence reads as null (the §6D-3
                // `api_unavailable` entries over absent L1
                // subtrees); only null-kind reasons may sit on
                // absent paths.
                None => {
                    if entry.reason == "unstable_snapshot" {
                        return Err(format!("unstable_snapshot on absent path: {}", entry.path));
                    }
                }
                Some(v) if v.is_null() => {
                    if entry.reason == "unstable_snapshot" {
                        return Err(format!("unstable_snapshot on null path: {}", entry.path));
                    }
                }
                Some(_) => {
                    if entry.reason != "unstable_snapshot" {
                        return Err(format!(
                            "non-unstable entry on non-null path: {}",
                            entry.path
                        ));
                    }
                }
            }
            // P2fix2 item 13: the combined sticky spelling (both
            // seal-from-close AND summary-mismatch on one flagged
            // accumulator) is legitimate §6C-1d output — the
            // single-word check above used to reject the build's own
            // combined note (latent: no exercised path set both).
            if entry.note.is_some()
                && !(entry.note.as_deref() == Some(NOTE_SUMMARY_MISMATCH)
                    || entry.note.as_deref() == Some(NOTE_SEALED_FROM_CLOSE)
                    || entry.note.as_deref() == Some(NOTE_SEALED_AND_MISMATCH))
            {
                return Err(format!("bad note on {}", entry.path));
            }
        }
        for path in &nulls {
            match counts.get(path.as_str()) {
                Some(1) => {}
                Some(n) => return Err(format!("{n} entries on null path: {path}")),
                None => return Err(format!("null without entry: {path}")),
            }
        }
        // No entry may hide under a null object.
        for entry in &self.unknown {
            let mut prefix = String::new();
            for seg in entry.path.split('.') {
                if !prefix.is_empty() {
                    prefix.push('.');
                }
                prefix.push_str(seg);
                if prefix != entry.path && nulls.iter().any(|n| n == &prefix) {
                    return Err(format!("entry under null object: {}", entry.path));
                }
            }
        }
        Ok(())
    }
}

/// Render one path segment (§6C-4 path spelling).
fn push_segment(path: &mut String, key: &str) {
    if !path.is_empty() {
        path.push('.');
    }
    if key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        path.push_str(key);
    } else {
        path.push('"');
        path.push_str(key);
        path.push('"');
    }
}

fn collect_nulls(value: &serde_json::Value, prefix: String, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Null => out.push(prefix),
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let mut p = prefix.clone();
                push_segment(&mut p, k);
                collect_nulls(v, p, out);
            }
        }
        serde_json::Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                collect_nulls(v, format!("{prefix}[{i}]"), out);
            }
        }
        _ => {}
    }
}

fn resolve<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    if path.is_empty() {
        return Some(value);
    }
    // Paths are segment-joined with '.'; our emitted paths never
    // contain quoted segments except by_api IDs (Slice C), which the
    // resolver below handles.
    let mut node = value;
    let mut rest = path;
    while !rest.is_empty() {
        let (seg, tail) = if let Some(stripped) = rest.strip_prefix('"') {
            let end = stripped.find('"')?;
            let seg = &stripped[..end];
            let tail = &stripped[end + 1..];
            (seg.to_string(), tail.strip_prefix('.').unwrap_or(tail))
        } else {
            match rest.find('.') {
                Some(i) => (rest[..i].to_string(), &rest[i + 1..]),
                None => (rest.to_string(), ""),
            }
        };
        // Array index suffix: `name[3]`.
        if let Some(br) = seg.find('[') {
            let name = &seg[..br];
            let idx: usize = seg[br + 1..].strip_suffix(']')?.parse().ok()?;
            node = node.get(name)?.get(idx)?;
        } else {
            node = node.get(&seg)?;
        }
        rest = tail;
    }
    Some(node)
}

// --- Small tolerant readers ---

pub(crate) fn u64_at(v: &serde_json::Value, key: &str) -> Option<u64> {
    v.get(key)?.as_u64()
}

pub(crate) fn i64_at(v: &serde_json::Value, key: &str) -> Option<i64> {
    v.get(key)?.as_i64()
}

pub(crate) fn str_at<'a>(v: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    v.get(key)?.as_str()
}

pub(crate) fn bool_at(v: &serde_json::Value, key: &str) -> Option<bool> {
    v.get(key)?.as_bool()
}

pub(crate) fn arr_at<'a>(
    v: &'a serde_json::Value,
    key: &str,
) -> Option<&'a Vec<serde_json::Value>> {
    v.get(key)?.as_array()
}

pub(crate) fn obj_at<'a>(v: &'a serde_json::Value, key: &str) -> Option<&'a serde_json::Value> {
    v.get(key).filter(|x| x.is_object())
}

/// Persisted free-string rule (P2fix2 items 24+7): nonempty,
/// bounded length, no control characters, no path separators.
/// The outer bound every persisted string passes; typed
/// vocabularies below refine it per field (P2fix3 PRIVACY).
fn valid_token(s: &str, max_chars: usize) -> bool {
    let len = s.chars().count();
    if len == 0 || len > max_chars {
        return false;
    }
    !s.chars().any(|c| c.is_control() || c == '/' || c == '\\')
}

/// Producer-owned counter-name vocabulary (P2fix4 PRIVACY —
/// closed per-family tables, each member cited to its emission
/// site; no free text in recognized families). Dotted families
/// the producers emit (`count.`, `capture.`, `discovery.`,
/// `engine.`, `focused.`, `kernel.`, `legacy.`, `lifecycle.`,
/// `snapshot.`, `target.`, `traversal.`, `window.`), the bare
/// discovery loss-source words (reverse-mapped from
/// [`crate::discovery::coverage::loss_source_name`] — no
/// duplicated table, no drift), typed `unknown_<id>` (u32 —
/// `classify_loss`), the produced underscore words, and
/// `typed_pin_missing`. Colon spellings have no counter
/// producer (the `legacy:` strings are FD tags, not counters)
/// and reject, as do test-only names (`engine.poll_loss`,
/// `discovery.table_aborted`, `focused.test`) and every
/// unlisted suffix.
fn valid_counter_name(name: &str) -> bool {
    if !valid_token(name, COUNTER_NAME_MAX) {
        return false;
    }
    if let Some(dot) = name.find(['.', ':']) {
        // ':' rides no counter family (no producer emits colon
        // counter names); exactly one separator.
        if name.as_bytes()[dot] == b':' {
            return false;
        }
        let (family, suffix) = name.split_at(dot);
        let suffix = &suffix[1..];
        if suffix.is_empty() || suffix.contains(['.', ':']) {
            return false;
        }
        return match family {
            // count_session.rs record_loss + counter() (+ the
            // lat_bucket_{00..=15} histogram over lat_cum[16]).
            "count" => {
                matches!(
                    suffix,
                    "close_failed"
                        | "close_time_uncertain"
                        | "drain_read_failed"
                        | "drain_unenumerated"
                        | "owner_capacity"
                        | "owner_failed"
                        | "quiescence_unknown"
                        | "reference_inventory_invalid"
                        | "map_insert_dropped"
                        | "unattributed"
                        | "drain_shortfall"
                        | "ledger_admitted"
                        | "missed_attaches"
                        | "unresolved_offsets"
                        | "stale_events"
                        | "fences"
                        | "drained_keys"
                        | "drain_passes"
                        | "drain_pass_ns_total"
                        | "drain_pass_ns_max"
                        | "drain_rss_bytes"
                        | "lat_samples"
                        | "lat_median_ns"
                        | "lat_p99_ns"
                        | "ledger_delta"
                        | "ledger_unreconciled"
                ) || valid_lat_bucket(suffix)
            }
            // capture.rs + capture/profiled.rs typed_counter +
            // report.rs capture.no_observation.
            "capture" => matches!(
                suffix,
                "over_budget" | "close_time_uncertain" | "no_observation"
            ),
            // capture.rs typed_counter (25 sites).
            "discovery" => matches!(
                suffix,
                "attach_failed"
                    | "attaches"
                    | "budget_exhausted"
                    | "close_candidates"
                    | "close_join_skipped"
                    | "close_remembered"
                    | "events_consumed"
                    | "finish_failed"
                    | "late_attach_sites"
                    | "lossy_slots"
                    | "maps_read_failed"
                    | "mixed_classes"
                    | "new_mapping_sites"
                    | "pre_window_queries"
                    | "provider_reloads"
                    | "queries_observed"
                    | "relevance_capped"
                    | "site_identity_refreshed"
                    | "table_retired"
                    | "truncated_walk"
                    | "unbacked_candidate"
                    | "unparsed_device"
                    | "unparsed_object_dev"
                    | "unresolved_stage2"
                    | "unverified_read"
            ),
            // capture.rs typed_counter (sole engine producer).
            "engine" => suffix == "observation_unkeyed",
            // focused_capture.rs loss() + observation_loss() +
            // engine_absent/addrtaken.
            "focused" => matches!(
                suffix,
                "first_query_unknown"
                    | "interval_unknown"
                    | "ambiguity"
                    | "observation_loss"
                    | "identity_unknown"
                    | "limit"
                    | "companions_unavailable"
                    | "tracing_unavailable"
                    | "observation_attach"
                    | "attach_refused_quarantined"
                    | "read_unknown"
                    | "engine_absent"
                    | "engine_addrtaken"
                    | "first_call_unknown"
                    | "finality_unknown"
                    | "unattributed"
                    | "metadata_output_limit"
                    | "metadata_omitted_sites"
                    | "metadata_omitted_associations"
                    | "engine_unkeyed"
                    | "engine_unplanned"
                    | "engine_module_skipped"
                    | "engine_uninstrumented"
                    | "startup_partial"
                    | "inventory_partial"
                    | "attribution_refused"
                    | "attribution_projection_refused"
            ),
            // doctor.rs sysctl counters (closed triple).
            "kernel" => matches!(
                suffix,
                "kptr_restrict" | "perf_event_paranoid" | "unprivileged_bpf_disabled"
            ),
            // capture.rs typed_counter (7 sites).
            "legacy" => matches!(
                suffix,
                "close_tail_lgcalls"
                    | "close_tail_trip"
                    | "engine_uninstrumented"
                    | "lowlevel_uninstrumented"
                    | "meth_uninstrumented"
                    | "straddling_poll_lgcalls"
                    | "straddling_poll_trip"
            ),
            // capture.rs typed_counter + service/snapshot.rs
            // lane_counter (same names).
            "lifecycle" => matches!(
                suffix,
                "drain_pending"
                    | "exec_gap"
                    | "fork_exec_ignored"
                    | "no_witness"
                    | "polling_fallback"
                    | "scan_loss"
                    | "signal_dropped"
                    | "signal_prefix_unwitnessed"
            ),
            // service/snapshot.rs (sole snapshot producer).
            "snapshot" => suffix == "member_unsealed",
            // capture.rs typed_counter (sole target producer).
            "target" => suffix == "finish_failed",
            // capture.rs typed_counter (5 sites).
            "traversal" => matches!(
                suffix,
                "storm" | "throttled" | "finish_error" | "incomplete" | "unjoined"
            ),
            // service/snapshot.rs (sole window producer).
            "window" => suffix == "accum_cut",
            _ => false,
        };
    }
    // Bare words (loss-source table first — `unknown_kind` is
    // a table word, not an `unknown_<id>` miss).
    if name == "typed_pin_missing" || is_loss_source_word(name) {
        return true;
    }
    // Produced underscore words: trace_loss_counters (6),
    // focused_count gap()/failure() (16), snapshot_unstable.
    if let Some(rest) = name.strip_prefix("trace_") {
        return matches!(
            rest,
            "dropped"
                | "unpaired_entries"
                | "unpaired_results"
                | "depth_exceeded"
                | "nonmonotonic_pairs"
                | "rejected_unknown_api"
        );
    }
    if let Some(rest) = name.strip_prefix("focused_") {
        return matches!(
            rest,
            "cut_unavailable"
                | "dropfail"
                | "fence_gen_exhausted"
                | "fence_gen_unwritten"
                | "final_snapshot_unavailable"
                | "ledger_mismatch"
                | "metadata_changed"
                | "namespace_failures"
                | "saturated"
                | "unattributed"
                | "namespace"
                | "identity"
                | "attach"
                | "resource"
                | "close"
                | "read"
        );
    }
    if let Some(rest) = name.strip_prefix("snapshot_") {
        return rest == "unstable";
    }
    if let Some(id) = name.strip_prefix("unknown_") {
        return !id.is_empty() && id.len() <= 10 && id.bytes().all(|b| b.is_ascii_digit());
    }
    false
}

/// c8 latency-bucket counter suffix (count_session.rs:
/// `count.lat_bucket_{k:02}` over `lat_cum[16]` — k in 0..=15).
fn valid_lat_bucket(suffix: &str) -> bool {
    let Some(digits) = suffix.strip_prefix("lat_bucket_") else {
        return false;
    };
    if digits.len() != 2 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    digits.parse::<u32>().is_ok_and(|k| k <= 15)
}

/// Reverse-map a bare word through the producer's loss-source
/// table (no literal duplication — the table stays the single
/// home of the words).
fn is_loss_source_word(name: &str) -> bool {
    (0..65536u32).any(|src| crate::discovery::coverage::loss_source_name(src) == Some(name))
}

/// Actual reason-word vocabulary (P2fix3 PRIVACY): bare words
/// plus per-kind suffixes (loss counters, scopes, causes) — each
/// suffix validates against its own vocabulary, never free text.
/// Shared by both presenter paths (producer words from
/// `gap_reason_short` share these spellings).
fn valid_reason_word(word: &str) -> bool {
    if !valid_token(word, REASON_WORD_MAX) {
        return false;
    }
    if matches!(
        word,
        "unattributed-calls" | "startup-gap" | "tail-gap" | "signal-cut"
    ) {
        return true;
    }
    let (kind, suffix) = match word.split_once(':') {
        Some((k, s)) => (k, s),
        None => return false,
    };
    match kind {
        "unknown-denominator" | "undiscovered-sites" | "unattached-sites" => valid_scope(suffix),
        "loss" => valid_counter_name(suffix),
        "visibility-lost" => suffix == "corpse_wait",
        _ => false,
    }
}

/// Producer-owned coverage-scope vocabulary: the closed
/// literals (capture.rs, focused_capture.rs, service/snapshot.rs)
/// plus `op:<u32>` (capture.rs adapter op index — u32 digits)
/// and `profile:<id>` (capture/profiled.rs — the EXACT
/// catalogue-identity rule from profile.rs parse_catalogue:
/// 1..=128 chars, ASCII alphanumeric + `-_`, no dots).
fn valid_scope(scope: &str) -> bool {
    if matches!(scope, "legacy" | "dispatch" | "focused.execution") {
        return true;
    }
    if let Some(op) = scope.strip_prefix("op:") {
        return !op.is_empty() && op.len() <= 10 && op.bytes().all(|b| b.is_ascii_digit());
    }
    if let Some(profile) = scope.strip_prefix("profile:") {
        return !profile.is_empty()
            && profile.len() <= 128
            && profile
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    }
    false
}

/// Actual boot-ID identity format (P2fix3 PRIVACY): kernel UUID
/// text (`/proc/sys/kernel/random/boot_id` — 8-4-4-4-12 hex with
/// fixed dashes), not a free string.
fn valid_boot_id(boot_id: &str) -> bool {
    let b = boot_id.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (i, c) in b.iter().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            if *c != b'-' {
                return false;
            }
        } else if !c.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// Counter name bound (dotted identifiers — far below this).
const COUNTER_NAME_MAX: usize = 128;
/// Completeness reason-word bound (fixed prefix + bounded suffix).
const REASON_WORD_MAX: usize = 512;

/// Validate one persisted counter record (P2fix2 item 24 — no
/// wholesale counter-JSON clone): closed kind/units/source
/// vocabularies in the path's spelling (producer PascalCase,
/// doc_json kebab), actual counter-name vocabulary (P2fix3
/// PRIVACY), u64 value. Valid records pass through verbatim
/// (dual-path agreement preserved); malformed records reject the
/// document (loss evidence never half-reads).
fn validate_counter(v: &serde_json::Value, doc_json: bool) -> bool {
    // Closed record shape (exactly the five typed keys — unknown
    // keys could smuggle unbounded strings past the checks below).
    let Some(obj) = v.as_object() else {
        return false;
    };
    if obj.len() != 5
        || !obj.contains_key("name")
        || !obj.contains_key("kind")
        || !obj.contains_key("units")
        || !obj.contains_key("source")
        || !obj.contains_key("value")
    {
        return false;
    }
    let (kinds, units, sources): (&[&str], &[&str], &[&str]) = if doc_json {
        (
            &["loss", "activity"],
            &["calls", "sites", "table-rows", "events", "probes"],
            &[
                "kernel-ring",
                "kernel-map",
                "discovery",
                "attach",
                "drain",
                "lifecycle",
                "setup",
            ],
        )
    } else {
        (
            &["Loss", "Activity"],
            &["Calls", "Sites", "TableRows", "Events", "Probes"],
            &[
                "KernelRing",
                "KernelMap",
                "Discovery",
                "Attach",
                "Drain",
                "Lifecycle",
                "Setup",
            ],
        )
    };
    let Some(kind) = str_at(v, "kind") else {
        return false;
    };
    let Some(units_word) = str_at(v, "units") else {
        return false;
    };
    let Some(source) = str_at(v, "source") else {
        return false;
    };
    let Some(name) = str_at(v, "name") else {
        return false;
    };
    kinds.contains(&kind)
        && units.contains(&units_word)
        && sources.contains(&source)
        && valid_counter_name(name)
        && u64_at(v, "value").is_some()
}

/// CLOCK_MONOTONIC nanoseconds (LiveClock domain, §6C-2).
pub fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime with a valid out-pointer.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if rc != 0 {
        return 0;
    }
    (ts.tv_sec.max(0) as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec.max(0) as u64)
}

/// Wall-clock nanoseconds (context only, §6C-2).
pub fn wall_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

/// Lowercase hex sha256 over bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let d = h.finalize();
    let mut out = String::with_capacity(64);
    for b in d {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Fallback window duration (seconds) for the staleness rule when
/// a snapshot carries no usable requested span (degenerate file).
/// The rule derives from the SOURCE's requested span, never from
/// this default — both CLIs pass it only as the degenerate
/// fallback (item 18).
pub const WINDOW_SECS_FALLBACK: u64 = 30;

/// Freshness at a build/serve instant (one shared rule): age from
/// the source's effective end, stale past twice the source's
/// requested span (fallback when the span is degenerate);
/// pre-first-window is stale without age.
pub(crate) fn snapshot_freshness(
    window: Option<&WindowBlock>,
    fallback_secs: u64,
    now_mono_ns: u64,
) -> (Option<u64>, bool) {
    match window {
        None => (None, true),
        Some(w) => {
            let age = now_mono_ns.saturating_sub(w.effective_end_ns);
            let span = w.requested_end_ns.saturating_sub(w.requested_start_ns);
            let limit = if span > 0 {
                span.saturating_mul(2)
            } else {
                fallback_secs
                    .saturating_mul(1_000_000_000)
                    .saturating_mul(2)
            };
            (Some(age), age > limit)
        }
    }
}

/// Checkpoint sibling path: `<out-DIR>.checkpoint.json` (§6C-1c).
/// Trailing slashes strip before the suffix appends (P2fix3 NEW-13:
/// `--out DIR/` checkpoints BESIDE the directory, never inside it
/// — consumers stay read-only on the producer dir).
pub fn checkpoint_default(out_dir: &Path) -> PathBuf {
    let mut text = out_dir.as_os_str().to_string_lossy().into_owned();
    while text.len() > 1 && text.ends_with('/') {
        text.pop();
    }
    if text.is_empty() {
        text = out_dir.as_os_str().to_string_lossy().into_owned();
    }
    text.push_str(".checkpoint.json");
    PathBuf::from(text)
}

/// Checkpoint placement (P2fix4 NEW-13/NEW-18): refuse when the
/// checkpoint would land inside-or-equal the producer out-DIR.
/// Both sides canonicalize (an EMPTY checkpoint parent resolves
/// against the current working directory — `--out . --checkpoint
/// ckpt.json` from the producer dir refuses); inside-or-equal
/// refuses. Unresolvable sides (initially absent directories)
/// pass HERE — enforcement re-runs at every write, so the
/// condition still holds once the directories become available
/// (the outage-then-recover flow stays legitimate: absent dirs
/// fail downstream reads/writes loudly, never silently inside).
fn check_checkpoint_placement(out_dir: &Path, checkpoint: &Path) -> Result<(), String> {
    let parent = checkpoint.parent().unwrap_or_else(|| Path::new(""));
    let parent = if parent.as_os_str().is_empty() {
        std::env::current_dir().map_err(|e| format!("unresolvable checkpoint dir ({e})"))?
    } else {
        parent.to_path_buf()
    };
    let (Ok(out_canon), Ok(parent_canon)) = (
        std::fs::canonicalize(out_dir),
        std::fs::canonicalize(&parent),
    ) else {
        return Ok(());
    };
    if parent_canon == out_canon || parent_canon.starts_with(&out_canon) {
        return Err(format!(
            "checkpoint must live outside the producer out-DIR (not {})",
            checkpoint.display()
        ));
    }
    Ok(())
}

/// True when `flag` is one of the 8 closed accumulator-vocabulary
/// words (P2fix3 NEW-4 — the writer's vocabulary; shared by the
/// live `unstable` set and the NEW-67 preserved record).
fn valid_unstable_flag(flag: &str) -> bool {
    matches!(
        flag,
        "counts.calls_total"
            | "counts.lanes"
            | "members.retired_epoch"
            | "counts.by_outcome"
            | "loss.epoch_by_cause"
            | "completeness.epoch_partial_by_class"
            | "histograms"
            | "stream.drops"
    )
}

/// Strict preserved-epoch reader (P2fix11 NEW-67): every field
/// required + typed, flags in the closed vocabulary, ranges
/// well-shaped pairs — a malformed record refuses (never
/// defaulted into the previous-epoch slot).
fn read_previous_epoch_strict(v: &serde_json::Value) -> Option<PreservedEpoch> {
    let obj = v.as_object()?;
    let generation = obj.get("generation")?.as_u64()?;
    let window_seq = obj.get("window_seq")?.as_u64()?;
    let calls_total = obj.get("calls_total")?.as_u64()?;
    let lanes: [u64; 4] = serde_json::from_value(obj.get("lanes")?.clone()).ok()?;
    let mut unstable = Vec::new();
    for s in obj.get("unstable")?.as_array()? {
        let flag = s.as_str()?;
        if !valid_unstable_flag(flag) {
            return None;
        }
        unstable.push(flag.to_string());
    }
    let unmeasured: Vec<[u64; 2]> = serde_json::from_value(obj.get("unmeasured")?.clone()).ok()?;
    Some(PreservedEpoch {
        generation,
        window_seq,
        calls_total,
        lanes,
        unstable,
        unmeasured,
    })
}

/// Canonical preserved-epoch flags (P2fix12 NEW-72): sorted +
/// unique over the closed vocabulary (the writer emits a
/// `BTreeSet` iteration — unsorted, duplicated, or foreign
/// flags are crafted content, never writer output).
fn preserved_flags_canonical(unstable: &[String]) -> bool {
    unstable.windows(2).all(|w| w[0] < w[1])
}

/// Canonical preserved-epoch ranges (P2fix12 NEW-72): every
/// range well-formed (`[a, b]` with `a <= b`) and the list
/// sorted + merged (each start clears the previous end by ≥
/// 2 — reversed, unsorted, overlapping, or
/// adjacency-mergeable pairs are crafted content; the
/// writer's push/union merge both).
fn preserved_ranges_canonical(unmeasured: &[[u64; 2]]) -> bool {
    let mut prev_end: Option<u64> = None;
    for [a, b] in unmeasured {
        if a > b {
            return false;
        }
        if let Some(end) = prev_end {
            if a.saturating_sub(end) < 2 {
                return false;
            }
        }
        prev_end = Some(*b);
    }
    true
}

/// Canonical checkpoint-parent identity for directory anchoring
/// (P2fix6 NEW-34): the (device, inode) the presenter binds at
/// open (or at first resolution when the dir is absent —
/// `None`, the NEW-18 deferral). Path strings do not hold
/// identity through create/rename, so every write re-stats the
/// validated parent and refuses on mismatch (replaced parent —
/// fail closed, loudly).
fn checkpoint_parent_id(checkpoint: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    let parent = checkpoint.parent().unwrap_or_else(|| Path::new(""));
    let parent = if parent.as_os_str().is_empty() {
        std::env::current_dir().ok()?
    } else {
        parent.to_path_buf()
    };
    let canon = std::fs::canonicalize(&parent).ok()?;
    let md = std::fs::metadata(&canon).ok()?;
    Some((md.dev(), md.ino()))
}

/// Prove containment + identity of an OPENED checkpoint parent
/// (P2fix7 NEW-44, reworked P2fix8 NEW-50): the directory is
/// opened FIRST, then TWO separate checks run — pathname
/// OCCUPANCY (the path's current occupant must BE the opened
/// fd — a pure identity check, carrying no containment) and
/// fd-anchored CONTAINMENT (outside-ness proven on the OPENED
/// fd itself by walking its real ancestry — no
/// canonicalize-then-metadata split across a swap: a path that
/// resolves outside for one lookup and inside for the next can
/// no longer bless an inside directory). The returned identity
/// is the OPENED fd's own (device, inode) — the SAME directory
/// the staging below runs in (dirfd-relative), validated before
/// any staging write. (No `/proc/self/fd` readlink: the kernel
/// tracks the fd across renames, so a readlink would follow the
/// fd instead of checking the path — the match must anchor the
/// PATH's current occupant to the fd.)
fn validate_opened_parent(
    dir_fd: &std::fs::File,
    parent: &Path,
    out_dir: &Path,
    display: &Path,
) -> std::io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    // Occupancy (pure identity — the path's CURRENT occupant
    // must BE the opened fd; a substitution between open and
    // validation fails closed, never binds the stranger).
    let canon = std::fs::canonicalize(parent).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "osslscope: checkpoint dir unresolvable at write: {} ({e})",
                display.display()
            ),
        )
    })?;
    // Fault injection (P2fix8 NEW-50, test-only): run the armed
    // swap between the canonicalize and the metadata lookup
    // (the exact fp-confirmed interleave — inert at zero).
    #[cfg(test)]
    parent_swap_hook::take_and_run();
    let current = std::fs::metadata(&canon).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "osslscope: checkpoint dir unstatable at write: {} ({e})",
                display.display()
            ),
        )
    })?;
    let opened = dir_fd.metadata()?;
    if (current.dev(), current.ino()) != (opened.dev(), opened.ino()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "osslscope: checkpoint dir swapped during write (not {})",
                display.display()
            ),
        ));
    }
    // Containment on the OPENED fd itself (P2fix8 NEW-50).
    if !opened_dir_is_outside(dir_fd, out_dir, display)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "osslscope: checkpoint must live outside the producer out-DIR (not {})",
                display.display()
            ),
        ));
    }
    Ok((opened.dev(), opened.ino()))
}

/// Outside-ness of an OPENED directory (P2fix8 NEW-50):
/// fd-anchored ancestry — the checked side resolves NO
/// pathname (each step opens `..` relative to the current fd,
/// so symlink games on the path string cannot enter the
/// proof). The producer dir opens once for its identity; the
/// walk refuses on inside-or-equal and accepts at the
/// filesystem root (where `..` is self). Bounded (fail
/// closed past the cap); a non-directory fd refuses via the
/// first openat (ENOTDIR).
fn opened_dir_is_outside(
    dir_fd: &std::fs::File,
    out_dir: &Path,
    display: &Path,
) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::io::AsRawFd as _;
    let out_id = {
        let out_fd = std::fs::File::open(out_dir).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "osslscope: producer out-DIR unresolvable at write: {} ({e})",
                    out_dir.display()
                ),
            )
        })?;
        let md = out_fd.metadata()?;
        (md.dev(), md.ino())
    };
    let opened = dir_fd.metadata()?;
    let mut cur_id = (opened.dev(), opened.ino());
    if cur_id == out_id {
        return Ok(false);
    }
    let mut cur = dir_fd.try_clone()?;
    let dotdot = std::ffi::CString::new("..").expect("static");
    for _ in 0..65536 {
        // SAFETY: cur is a live fd; ".." is a NUL-free name
        // (never a symlink — O_NOFOLLOW only hardens).
        let fd = unsafe {
            libc::openat(
                cur.as_raw_fd(),
                dotdot.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "osslscope: checkpoint dir ancestry unreadable at write: {} ({})",
                    display.display(),
                    std::io::Error::last_os_error()
                ),
            ));
        }
        // SAFETY: openat returned a fresh owned fd.
        let parent = unsafe {
            use std::os::fd::FromRawFd as _;
            std::fs::File::from(std::os::fd::OwnedFd::from_raw_fd(fd))
        };
        let md = parent.metadata()?;
        let parent_id = (md.dev(), md.ino());
        if parent_id == out_id {
            return Ok(false);
        }
        if parent_id == cur_id {
            return Ok(true);
        }
        cur = parent;
        cur_id = parent_id;
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "osslscope: checkpoint dir ancestry too deep at write: {}",
            display.display()
        ),
    ))
}

/// Test-only tripwire observation probe (P2fix13 NEW-74):
/// how many `IN_MOVE_SELF` events the placement guard drained
/// since the last take (lets a pin prove a reversed move was
/// DETECTED even when the ancestry ends outside again).
/// Production never reads it.
#[cfg(test)]
pub(crate) mod tripwire_probe {
    use std::cell::Cell;
    thread_local! {
        static MOVES: Cell<u64> = const { Cell::new(0) };
    }
    pub fn record(n: u64) {
        MOVES.with(|m| m.set(m.get().saturating_add(n)));
    }
    pub fn take() -> u64 {
        MOVES.with(|m| m.replace(0))
    }
}

/// Placement precondition guard (P2fix13 NEW-74): the
/// outside-the-producer precondition must HOLD THROUGH every
/// mutation of the checkpoint write (staging, publish,
/// cleanup), not merely sample true at instants. The guard
/// arms an inotify watch (`IN_MOVE_SELF`/`IN_DELETE_SELF`)
/// on the opened checkpoint parent and EVERY ancestor bound
/// by fd (via `/proc/self/fd`, so the watch binds the
/// opened inodes themselves, never a pathname resolution):
/// any relocation of the chain during the write leaves a
/// queued event even when it reverses before the next
/// check, and queue overflow or chain destruction refuses
/// (placement cannot be established). Every mutation runs
/// fused behind `prove_before` (drain + link-count +
/// fd-anchored ancestry) and major steps re-prove with
/// `prove_after` (any event in the step's wake refuses —
/// the mutation may have raced a move). A failed proof
/// performs NO further mutation, cleanup included (an owned
/// stage is left in place and reported, never unlinked on
/// an fd that cannot be proven outside).
struct PlacementGuard {
    notify: std::fs::File,
    /// Ancestor fds (parent first) kept open for the write's
    /// duration (the watches bind their inodes).
    _chain: Vec<std::fs::File>,
}

/// Placement refusal for `step` (P2fix13 NEW-74): every
/// placement failure names the producer containment the same
/// way the carried pins match on, with the step inline.
fn placement_error(step: &str, reason: &str, display: &Path) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "osslscope: checkpoint dir no longer outside the producer out-DIR at {step} ({reason}; not {})",
            display.display()
        ),
    )
}

/// Ancestor fds of an OPENED directory (P2fix13 NEW-74):
/// the fd itself, then each `..` hop (fd-anchored, no
/// pathname) up to the filesystem root (where `..` is
/// self). Bounded (fail closed past the cap), mirroring
/// `opened_dir_is_outside`.
fn ancestry_chain(dir_fd: &std::fs::File, display: &Path) -> std::io::Result<Vec<std::fs::File>> {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::io::AsRawFd as _;
    let mut chain = vec![dir_fd.try_clone()?];
    let dotdot = std::ffi::CString::new("..").expect("static");
    for _ in 0..65536 {
        let cur = chain.last().expect("nonempty chain");
        let cur_md = cur.metadata()?;
        let cur_id = (cur_md.dev(), cur_md.ino());
        // SAFETY: cur is a live fd; ".." is a NUL-free name.
        let fd = unsafe {
            libc::openat(
                cur.as_raw_fd(),
                dotdot.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "osslscope: checkpoint dir ancestry unreadable at write: {} ({})",
                    display.display(),
                    std::io::Error::last_os_error()
                ),
            ));
        }
        // SAFETY: openat returned a fresh owned fd.
        let parent = unsafe {
            use std::os::fd::FromRawFd as _;
            std::fs::File::from(std::os::fd::OwnedFd::from_raw_fd(fd))
        };
        let md = parent.metadata()?;
        if (md.dev(), md.ino()) == cur_id {
            return Ok(chain);
        }
        chain.push(parent);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "osslscope: checkpoint dir ancestry too deep at write: {}",
            display.display()
        ),
    ))
}

/// Outcome of one tripwire drain (P2fix13 NEW-74).
struct TripwireDrain {
    /// Any queued event at all (a move, at minimum, was
    /// observed — position changed sometime since the last
    /// drain, even if it reversed since).
    events: bool,
}

impl PlacementGuard {
    const WATCH_MASK: u32 = libc::IN_MOVE_SELF | libc::IN_DELETE_SELF;

    /// Arm the tripwire on the opened parent + ancestry
    /// (P2fix13 NEW-74). Failure refuses BEFORE any mutation
    /// (placement through the write cannot be established).
    fn arm(dir_fd: &std::fs::File, display: &Path) -> std::io::Result<Self> {
        use std::os::unix::fs::MetadataExt as _;
        use std::os::unix::io::AsRawFd as _;
        let chain = ancestry_chain(dir_fd, display)?;
        // SAFETY: no arguments to validate.
        let notify_fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if notify_fd < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "osslscope: checkpoint placement watch could not be established (not {}): {}",
                    display.display(),
                    std::io::Error::last_os_error()
                ),
            ));
        }
        // SAFETY: inotify_init1 returned a fresh owned fd.
        let notify = unsafe {
            use std::os::fd::FromRawFd as _;
            std::fs::File::from(std::os::fd::OwnedFd::from_raw_fd(notify_fd))
        };
        let mut watched: Vec<(u64, u64)> = Vec::new();
        for dir in &chain {
            let md = dir.metadata()?;
            let id = (md.dev(), md.ino());
            if watched.contains(&id) {
                continue;
            }
            watched.push(id);
            // Bind the watch to the OPENED inode via its
            // /proc/self/fd magic link (never a pathname
            // resolution through the movable tree).
            let proc = std::ffi::CString::new(format!("/proc/self/fd/{}", dir.as_raw_fd()))
                .expect("static shape");
            // SAFETY: notify + dir fds live; proc is NUL-free.
            let wd = unsafe {
                libc::inotify_add_watch(notify.as_raw_fd(), proc.as_ptr(), Self::WATCH_MASK)
            };
            if wd < 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "osslscope: checkpoint placement watch could not be established (not {}): {}",
                        display.display(),
                        std::io::Error::last_os_error()
                    ),
                ));
            }
        }
        Ok(Self {
            notify,
            _chain: chain,
        })
    }

    /// Drain queued tripwire events (P2fix13 NEW-74): queue
    /// overflow or a destroyed chain link (delete/unmount/
    /// ignored) means placement can no longer be established
    /// for `step` and refuses; observed moves are recorded
    /// (the ancestry re-proof decides the present position —
    /// mutations are fused behind drains, so a move observed
    /// here overlapped none).
    fn drain(&self, step: &str, display: &Path) -> std::io::Result<TripwireDrain> {
        use std::io::Read as _;
        let mut notify = &self.notify;
        let mut events = false;
        let mut buf = [0u8; 4096];
        loop {
            match notify.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let mut at = 0usize;
                    while at + 16 <= n {
                        let wd =
                            i32::from_ne_bytes(buf[at..at + 4].try_into().expect("header field"));
                        let mask = u32::from_ne_bytes(
                            buf[at + 4..at + 8].try_into().expect("header field"),
                        );
                        let len = u32::from_ne_bytes(
                            buf[at + 12..at + 16].try_into().expect("header field"),
                        ) as usize;
                        if wd == -1 || mask & libc::IN_Q_OVERFLOW != 0 {
                            return Err(placement_error(
                                step,
                                "placement could not be established: movement watch overflowed",
                                display,
                            ));
                        }
                        if mask & (libc::IN_DELETE_SELF | libc::IN_UNMOUNT | libc::IN_IGNORED) != 0
                        {
                            return Err(placement_error(
                                step,
                                "checkpoint dir ancestry destroyed during write",
                                display,
                            ));
                        }
                        events = true;
                        #[cfg(test)]
                        if mask & libc::IN_MOVE_SELF != 0 {
                            tripwire_probe::record(1);
                        }
                        at += 16 + len;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(TripwireDrain { events })
    }

    /// Present-position proof shared by both envelopes
    /// (P2fix13 NEW-74): the opened dir still linked (a
    /// removed dir's `..` self-loop would otherwise read as
    /// the filesystem root) and fd-anchored outside the
    /// producer out-DIR right now.
    fn prove_position(
        &self,
        dir_fd: &std::fs::File,
        out_dir: &Path,
        step: &str,
        display: &Path,
    ) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt as _;
        if dir_fd.metadata()?.nlink() == 0 {
            return Err(placement_error(
                step,
                "checkpoint dir unlinked during write",
                display,
            ));
        }
        if !opened_dir_is_outside(dir_fd, out_dir, display)? {
            return Err(placement_error(step, "reparented during write", display));
        }
        Ok(())
    }

    /// Fused pre-mutation proof (P2fix13 NEW-74): drain the
    /// tripwire (any move since the last drain overlapped no
    /// mutation — mutations only ever follow this proof),
    /// then prove the present position. The caller performs
    /// its mutation immediately after this returns, with no
    /// interposition between.
    fn prove_before(
        &self,
        dir_fd: &std::fs::File,
        out_dir: &Path,
        step: &str,
        display: &Path,
    ) -> std::io::Result<()> {
        let _ = self.drain(step, display)?;
        self.prove_position(dir_fd, out_dir, step, display)
    }

    /// Post-mutation re-proof (P2fix13 NEW-74): an event in
    /// the just-run step's wake means the mutation may have
    /// raced a move — refuse before anything else mutates
    /// (the publish gate below still withholds authority);
    /// then prove the present position.
    fn prove_after(
        &self,
        dir_fd: &std::fs::File,
        out_dir: &Path,
        step: &str,
        display: &Path,
    ) -> std::io::Result<()> {
        let drained = self.drain(step, display)?;
        if drained.events {
            return Err(placement_error(step, "moved during write", display));
        }
        self.prove_position(dir_fd, out_dir, step, display)
    }
}

/// Append the left-stage note to a refused write
/// (P2fix13 NEW-74, P2fix14 NEW-80): the owned stage could
/// not be verified for removal (its name no longer refers to
/// our own stage inode — or removal failed), so NOTHING is
/// unlinked and the residue is declared loudly instead —
/// never silently leaked, never a blind unlink.
fn with_stage_left_note(primary: std::io::Error) -> std::io::Error {
    std::io::Error::new(
        primary.kind(),
        format!(
            "{primary} (stage left in place: own bytes could not be verified for removal — operator must intervene)"
        ),
    )
}

/// `renameat2` flags (Linux UAPI — libc 0.2.189 exposes the
/// syscall on gnu but not these constants).
const RENAME_NOREPLACE: libc::c_uint = 1;
const RENAME_EXCHANGE: libc::c_uint = 2;

/// `renameat2` on two dirfd-relative names (P2fix14 NEW-80).
fn renameat2_result(
    dir_fd: &std::fs::File,
    a: &std::ffi::CString,
    b: &std::ffi::CString,
    flags: libc::c_uint,
) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd as _;
    #[cfg(test)]
    publish_probe::record();
    // SAFETY: dir_fd is live; both are NUL-free file names in it.
    if unsafe {
        libc::renameat2(
            dir_fd.as_raw_fd(),
            a.as_ptr(),
            dir_fd.as_raw_fd(),
            b.as_ptr(),
            flags,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Publish-syscall capability probe (P2fix14 NEW-80): the
/// conditional publish needs `renameat2` EXCHANGE (present
/// target) + NOREPLACE (absent target) on THIS filesystem.
/// Zero-mutation: both flags are probed against names verified
/// absent — `ENOENT` proves the filesystem parsed the flags
/// (supported); anything else (notably `EINVAL`/`ENOSYS`)
/// refuses BEFORE writing (the target-identity invariant
/// cannot be established there).
fn probe_publish_support(dir_fd: &std::fs::File, display: &Path) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd as _;
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    for attempt in 0..4u32 {
        let a = std::ffi::CString::new(format!(".osslscope-probe-{pid}-{nanos}-{attempt}a"))
            .expect("static shape");
        let b = std::ffi::CString::new(format!(".osslscope-probe-{pid}-{nanos}-{attempt}b"))
            .expect("static shape");
        // Both names must be absent (a present name would be
        // swapped by the probe — never probe a live name).
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: dir_fd is live; the names are NUL-free; st
        // outlives the calls.
        let present_a = unsafe {
            libc::fstatat(
                dir_fd.as_raw_fd(),
                a.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0;
        let present_b = unsafe {
            libc::fstatat(
                dir_fd.as_raw_fd(),
                b.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0;
        if present_a || present_b {
            continue;
        }
        for (flags, name) in [
            (RENAME_EXCHANGE, "exchange"),
            (RENAME_NOREPLACE, "noreplace"),
        ] {
            if renameat2_result(dir_fd, &a, &b, flags).is_ok() {
                // Impossible (both names verified absent) —
                // fail closed.
                return Err(publish_unsupported(display, name, "unexpected success"));
            }
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(publish_unsupported(display, name, &e.to_string()));
            }
        }
        return Ok(());
    }
    Err(publish_unsupported(
        display,
        "probe",
        "no fresh probe names",
    ))
}

/// Refuse-before-writing on an unpublishable filesystem
/// (P2fix14 NEW-80 — the invariant cannot be established).
fn publish_unsupported(display: &Path, what: &str, detail: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!(
            "osslscope: checkpoint publish requires renameat2 ({what}) on this filesystem — refusing before writing (not {}): {detail}",
            display.display()
        ),
    )
}

/// (dev, ino) identity of an open file (P2fix14 NEW-80).
fn file_id(f: &std::fs::File) -> std::io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    let md = f.metadata()?;
    Ok((md.dev(), md.ino()))
}

/// (dev, ino) currently under a dirfd-relative name
/// (P2fix14 NEW-80 — `None` when absent/unreadable; the
/// caller declares instead of touching).
fn name_id(dir_fd: &std::fs::File, name: &std::ffi::CString) -> Option<(u64, u64)> {
    use std::os::unix::io::AsRawFd as _;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: dir_fd is live; the name is NUL-free; st
    // outlives the call.
    let rc = unsafe {
        libc::fstatat(
            dir_fd.as_raw_fd(),
            name.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        return None;
    }
    Some((st.st_dev, st.st_ino))
}

/// True iff the dirfd-relative `name` currently refers to
/// `id` (P2fix14 NEW-80 — a move of the directory cannot
/// rebind entries, so this verification is move-immune; only
/// a direct entry manipulation between verify and use can
/// defeat it, and stage names are per-write unique). Absent
/// (or stat failure) reads false — never an error (the
/// caller declares the residue instead of touching it).
fn name_refers_to(dir_fd: &std::fs::File, name: &std::ffi::CString, id: (u64, u64)) -> bool {
    use std::os::unix::io::AsRawFd as _;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: dir_fd is live; the name is NUL-free; st
    // outlives the call.
    let rc = unsafe {
        libc::fstatat(
            dir_fd.as_raw_fd(),
            name.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        return false;
    }
    (st.st_dev, st.st_ino) == id
}

/// Identity-conditional owned removal (P2fix15 NEW-87 —
/// verification-then-`unlinkat` is CONFIRMED, not trusted):
/// remove `name` ONLY IF it refers to `expect`. An `O_PATH`
/// open pins the inode across the call; `fstat` verifies it
/// (mismatch ⇒ `Ok(false)` — left declared, never a blind
/// unlink); `unlinkat` removes the name; then the STILL-OPEN
/// fd confirms OUR inode lost its link (its link count
/// dropped by exactly one) and the name is gone. A rebind
/// between verify and use is DETECTED (our link count
/// intact while the name went away ⇒ a foreign object was
/// unlinked instead — declared loudly, never success).
/// True prevention is unexpressible (no conditional-unlink
/// syscall exists); moves cannot rebind entries, so only
/// true-concurrent DIRECT entry manipulation reaches the
/// residual window (hostile-only — the move threat model
/// never does). `Err` is a failed unlink or a detected
/// rebound; `Ok(true)` removed-and-confirmed our own entry.
fn unlink_owned(
    dir_fd: &std::fs::File,
    name: &std::ffi::CString,
    expect: (u64, u64),
) -> std::io::Result<bool> {
    use std::os::unix::io::AsRawFd as _;
    // SAFETY: dir_fd is live; the name is a NUL-free file
    // name in it (`O_PATH` never follows, never stalls —
    // FIFOs, symlinks, and directories open uniformly and
    // fail the identity compare below).
    let fd = unsafe {
        libc::openat(
            dir_fd.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Ok(false);
    }
    // SAFETY: openat returned a fresh owned fd.
    let pinned = unsafe {
        use std::os::fd::FromRawFd as _;
        std::fs::File::from(std::os::fd::OwnedFd::from_raw_fd(fd))
    };
    let mut before: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: pinned is live; `before` outlives the call.
    if unsafe { libc::fstat(pinned.as_raw_fd(), &mut before) } != 0 {
        return Ok(false);
    }
    if (before.st_dev, before.st_ino) != expect {
        return Ok(false);
    }
    let links_before = before.st_nlink;
    // Fault injection (P2fix15 NEW-87, test-only): run the
    // armed entry hook between verification and use (the
    // verify→unlink interval — inert at zero).
    #[cfg(test)]
    unlink_hook::take_and_run();
    unlink_checked(dir_fd, name)?;
    // Confirm: OUR inode lost exactly one link and the name
    // is gone (a rebound name removed a FOREIGN object —
    // our count intact — and must be declared loudly).
    let mut after: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: pinned is live; `after` outlives the call.
    if unsafe { libc::fstat(pinned.as_raw_fd(), &mut after) } != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "osslscope: owned removal unconfirmable (lost our own entry tracking — operator must inspect)",
        ));
    }
    if after.st_nlink != links_before.saturating_sub(1) || name_id(dir_fd, name).is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "osslscope: owned removal hit a rebound name (the name went away but our own entry still stands — a foreign object may have been unlinked instead; operator must inspect)",
        ));
    }
    Ok(true)
}

/// Attempt the identity-verified own-stage removal (P2fix14
/// NEW-80, confirmed P2fix15 NEW-87): `Ok(true)` removed
/// our own stage (confirmed), `Ok(false)` means the name no
/// longer refers to our own stage inode (left declared —
/// never a blind unlink), `Err` is a failed unlink of a
/// verified-own stage or a detected rebound.
fn try_withdraw_stage(
    dir_fd: &std::fs::File,
    stage_c: &std::ffi::CString,
    own_id: (u64, u64),
) -> std::io::Result<bool> {
    unlink_owned(dir_fd, stage_c, own_id)
}

/// Append the placement-bound leave note to a refused write
/// (P2fix15 NEW-87 — withdrawal is PLACEMENT-BOUND): the
/// owned stage is NOT unlinked beneath an unproven directory
/// (a removal there is itself an inside mutation) — it
/// stands declared instead (never published, never silent —
/// operator must intervene).
fn with_stage_left_unproven_note(primary: std::io::Error) -> std::io::Error {
    std::io::Error::new(
        primary.kind(),
        format!(
            "{primary} (stage left in place: placement unproven — no removal beneath the producer; operator must intervene)"
        ),
    )
}

/// Withdraw the owned stage after a refused write (P2fix14
/// NEW-80, placement-bound P2fix15 NEW-87): the stage is
/// exclusively ours (O_EXCL this call) — re-prove placement
/// IMMEDIATELY before the removal (a concurrent move since
/// the last proof leaves the stage standing declared
/// instead — no unlink beneath the producer), then remove it
/// by identity-confirmed unlink and return `primary`
/// UNCHANGED on success (raw error preserved — the EIO
/// pin). On identity mismatch (or unlink failure) the
/// residue is declared loudly (the primary leads).
#[allow(clippy::too_many_arguments)]
fn withdraw_stage(
    guard: &PlacementGuard,
    dir_fd: &std::fs::File,
    out_dir: &Path,
    step: &str,
    display: &Path,
    stage_c: &std::ffi::CString,
    own_id: (u64, u64),
    primary: std::io::Error,
) -> std::io::Error {
    if guard.prove_before(dir_fd, out_dir, step, display).is_err() {
        return with_stage_left_unproven_note(primary);
    }
    match try_withdraw_stage(dir_fd, stage_c, own_id) {
        Ok(true) => primary,
        Ok(false) => with_stage_left_note(primary),
        Err(cleanup) => with_stage_cleanup_note(primary, cleanup),
    }
}

/// Refuse after a placement proof failed (P2fix15 NEW-87 —
/// supersedes the P2fix14 NEW-80 `refuse_withdrawn`): the
/// owned stage is LEFT standing and DECLARED (never
/// unlinked — withdrawal is placement-bound, and a removal
/// beneath an unproven directory is itself an inside
/// mutation). The stage never published, so authority is
/// unaffected — but the bytes stand declared, never
/// silently leaked.
fn refuse_leaving_stage(placement: std::io::Error) -> std::io::Error {
    with_stage_left_unproven_note(placement)
}

/// Raw dirfd-relative target stat (P2fix14 NEW-80 — no
/// refusal: the gate and the publish-failure diagnosis share
/// it).
enum TargetRaw {
    Absent,
    Regular((u64, u64)),
    NonRegular,
    Unreadable,
}

/// Stat the publish target WITHOUT following links (a stat
/// cannot stall — P2fix13 NEW-76).
fn stat_target_raw(dir_fd: &std::fs::File, target_c: &std::ffi::CString) -> TargetRaw {
    use std::os::unix::io::AsRawFd as _;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: dir_fd is live; the name is a NUL-free file
    // name in it; st outlives the call.
    let rc = unsafe {
        libc::fstatat(
            dir_fd.as_raw_fd(),
            target_c.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        return if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
            TargetRaw::Absent
        } else {
            TargetRaw::Unreadable
        };
    }
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return TargetRaw::NonRegular;
    }
    TargetRaw::Regular((st.st_dev, st.st_ino))
}

/// The nonregular-target refusal (P2fix13 NEW-76 wording —
/// shared by the early gate and the fused publish gate).
fn not_regular_target(display: &Path) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!(
            "osslscope: checkpoint target is not a regular file (refusing to replace it; not {})",
            display.display()
        ),
    )
}

/// Outcome of a settled checkpoint flush (P2fix15 NEW-89):
/// the commit is DURABLE when this returns (the caller
/// advances live state); `residue` names post-settlement
/// cleanup leftovers that report SEPARATELY — never as
/// flush failure (live already advanced past them) and
/// never silently (the caller surfaces each entry to the
/// operator). Empty on a clean commit.
#[derive(Debug, Clone, Default)]
pub struct FlushOutcome {
    /// Declared cleanup residue (stage names / notes).
    pub residue: Vec<String>,
}

impl FlushOutcome {
    /// A commit with no residue.
    pub fn clean() -> Self {
        Self::default()
    }

    /// True when the commit left no residue.
    pub fn is_clean(&self) -> bool {
        self.residue.is_empty()
    }
}

/// Settlement-record schema (P2fix15 NEW-88 — the durable
/// settlement discriminator: which checkpoint bytes the last
/// write SETTLED, so reopen tells a settled target from an
/// unconfirmed replacement after interruption).
const SETTLED_SCHEMA: &str = "osslscope-checkpoint-settled-v1";

/// Sibling settlement-record path for a checkpoint path
/// (P2fix15 NEW-88 — `<target>.settled` beside the target).
fn settled_path(checkpoint: &Path) -> PathBuf {
    let mut name = checkpoint
        .file_name()
        .map(|n| n.to_owned())
        .unwrap_or_default();
    name.push(".settled");
    match checkpoint.parent() {
        Some(parent) => parent.join(&name),
        None => PathBuf::from(name),
    }
}

/// The parsed settlement record (P2fix15 NEW-88): the
/// content identity the last write settled.
pub(crate) struct SettledRecord {
    /// Embedded `sha256` of the SETTLED checkpoint bytes.
    pub(crate) target_sha256: String,
    /// `checkpoint_seq` the settling write stamped.
    pub(crate) checkpoint_seq: u64,
}

/// Render a settlement record's canonical bytes (P2fix15
/// NEW-88 — struct field order is fixed, so re-rendering
/// restores content-identical records).
fn render_settlement_record(rec: &SettledRecord) -> Vec<u8> {
    let mut body = serde_json::json!({
        "schema": SETTLED_SCHEMA,
        "target_sha256": rec.target_sha256,
        "checkpoint_seq": rec.checkpoint_seq,
    });
    let bytes = serde_json::to_vec(&body).unwrap_or_default();
    let hash = sha256_hex(&bytes);
    if let Some(obj) = body.as_object_mut() {
        obj.insert("sha256".to_string(), serde_json::json!(hash));
    }
    serde_json::to_vec(&body).unwrap_or_default()
}

/// Parse settlement-record bytes (P2fix15 NEW-88): schema +
/// 64-hex target identity + sequence + self-hash — `Err`
/// names the defect (torn or foreign content never parses).
fn parse_settlement_record(bytes: &[u8]) -> Result<SettledRecord, &'static str> {
    let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| "unparseable")?;
    if str_at(&v, "schema") != Some(SETTLED_SCHEMA) {
        return Err("foreign schema");
    }
    let target_sha256 = str_at(&v, "target_sha256").ok_or("missing target identity")?;
    if target_sha256.len() != 64 || !target_sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("malformed target identity");
    }
    let checkpoint_seq = u64_at(&v, "checkpoint_seq").ok_or("missing sequence")?;
    let want = str_at(&v, "sha256").ok_or("missing hash")?;
    let mut bare = v.clone();
    if let Some(obj) = bare.as_object_mut() {
        obj.remove("sha256");
    }
    let bare_bytes = serde_json::to_vec(&bare).unwrap_or_default();
    if sha256_hex(&bare_bytes) != want {
        return Err("hash mismatch");
    }
    Ok(SettledRecord {
        target_sha256: target_sha256.to_string(),
        checkpoint_seq,
    })
}

/// Read the settlement record beside a checkpoint (P2fix15
/// NEW-88): `None` when absent (legacy checkpoints and
/// never-settled dirs adopt the target exactly as before —
/// no silent behavior change); `Err` when anything stands
/// that is not OUR valid record (torn, foreign, nonregular,
/// or unreadable — reopen refuses past it loudly, never
/// adopting around it). Bounded regular-file intake (the
/// checkpoint intake — a substituted FIFO never stalls).
fn read_settlement_record(checkpoint: &Path) -> std::io::Result<Option<SettledRecord>> {
    let path = settled_path(checkpoint);
    let Some(bytes) = read_checkpoint_file(&path).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "osslscope: checkpoint settlement record unreadable ({path}): {e} (operator must inspect; refusing — never adopt past it)",
                path = path.display()
            ),
        )
    })?
    else {
        return Ok(None);
    };
    parse_settlement_record(&bytes)
        .map(Some)
        .map_err(|defect| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "osslscope: checkpoint settlement record invalid ({defect}): {} (operator must inspect; refusing — never adopt past it)",
                    path.display()
                ),
            )
        })
}

/// Scan the checkpoint directory for a stage carrying the
/// SETTLED bytes (P2fix15 NEW-88): after interruption the
/// marker-bound prior stands under a `<target>.staging-*`
/// name — return its hash-verified bytes when one matches
/// `want_sha256` (`None` when none does — junk entries
/// skip quietly; the flush residue scan declares them).
/// Bounded (regular files only, intake-capped, never
/// following links) and count-capped (fail closed past 64
/// candidates — operator intervenes).
fn scan_settled_stage(checkpoint: &Path, want_sha256: &str) -> std::io::Result<Option<Vec<u8>>> {
    let parent = checkpoint.parent().unwrap_or_else(|| Path::new(""));
    let parent = if parent.as_os_str().is_empty() {
        std::env::current_dir().map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!(
                    "osslscope: checkpoint dir unresolvable during settlement recovery ({e}; not {})",
                    checkpoint.display()
                ),
            )
        })?
    } else {
        parent.to_path_buf()
    };
    let target_name = checkpoint
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let prefix = format!("{target_name}.staging-");
    let entries = std::fs::read_dir(&parent).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "osslscope: checkpoint dir unreadable during settlement recovery ({e}; not {})",
                checkpoint.display()
            ),
        )
    })?;
    let mut candidates = 0u32;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(&prefix) {
            continue;
        }
        candidates += 1;
        if candidates > 64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "osslscope: too many checkpoint stages during settlement recovery (not {}) — operator must intervene",
                    checkpoint.display()
                ),
            ));
        }
        // Junk skips quietly (nonregular, unreadable,
        // unparseable, hash-mismatched — residue the flush
        // scan declares; recovery only ever adopts
        // hash-verified marker-bound bytes).
        let path = parent.join(&name);
        let Ok(Some(bytes)) = read_checkpoint_file(&path) else {
            continue;
        };
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        let Some(sha) = str_at(&v, "sha256") else {
            continue;
        };
        if sha != want_sha256 {
            continue;
        }
        let mut bare = v.clone();
        if let Some(obj) = bare.as_object_mut() {
            obj.remove("sha256");
        }
        let bare_bytes = serde_json::to_vec(&bare).unwrap_or_default();
        if sha256_hex(&bare_bytes) != sha {
            continue;
        }
        return Ok(Some(bytes));
    }
    Ok(None)
}

/// Which conditional-publish arm the fused gate selected
/// (P2fix14 NEW-80; `Copy` P2fix15 — the arm is consulted
/// at every post-publish step, never consumed).
#[derive(Debug, Clone, Copy)]
enum PublishArm {
    /// Target absent at the gate: NOREPLACE (anything raced
    /// in refuses with EEXIST — nothing to preserve, nothing
    /// to restore).
    Absent,
    /// Regular target with this identity at the gate:
    /// EXCHANGE (the post-publish verify binds the identity;
    /// a withdrawal swaps it back — the substitution arm
    /// rebinds this slot to the SUBSTITUTE's identity, which
    /// is what the swapback restores).
    Present((u64, u64)),
}

/// Name a failed conditional publish truthfully (P2fix14
/// NEW-80): when the target explains the failure
/// (substituted, appeared, or vanished after the gate), the
/// refusal names THAT (never a bare errno); otherwise the raw
/// error leads. Either way nothing published (NOREPLACE) or
/// nothing swapped (EXCHANGE) — the prior bytes stand.
fn explain_publish_error(
    dir_fd: &std::fs::File,
    target_c: &std::ffi::CString,
    display: &Path,
    arm: &PublishArm,
    err: std::io::Error,
) -> std::io::Error {
    let substituted = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "osslscope: checkpoint publish refused: target substituted after the gate (the substituted object is preserved; nothing published; not {})",
                display.display()
            ),
        )
    };
    match (arm, stat_target_raw(dir_fd, target_c)) {
        (PublishArm::Absent, TargetRaw::Absent | TargetRaw::Unreadable) => err,
        (PublishArm::Absent, _) => std::io::Error::new(
            err.kind(),
            format!(
                "osslscope: checkpoint publish refused: target appeared after the gate (nothing published; not {}): {err}",
                display.display()
            ),
        ),
        (PublishArm::Present(_), TargetRaw::NonRegular) => substituted(),
        (PublishArm::Present(old), TargetRaw::Regular(id)) if id != *old => substituted(),
        (PublishArm::Present(_), TargetRaw::Absent) => std::io::Error::new(
            err.kind(),
            format!(
                "osslscope: checkpoint publish refused: target vanished after the gate (nothing published; not {}): {err}",
                display.display()
            ),
        ),
        (PublishArm::Present(_), _) => err,
    }
}

/// Declare an ambiguous settlement (P2fix14 NEW-80/NEW-81,
/// reopen rule P2fix15 NEW-88): verification failed where
/// withdrawal is unsafe (state unknown) — NOTHING further is
/// touched; the operator inspects, and reopen applies the
/// settlement record (marker-bound prior or loud refusal —
/// never a blind adoption of the standing bytes).
fn ambiguous_settlement(primary: std::io::Error, detail: &str) -> std::io::Error {
    std::io::Error::new(
        primary.kind(),
        format!(
            "{primary} (settlement ambiguous: {detail} — operator must inspect; reopen applies the settlement record)"
        ),
    )
}

/// Read a dirfd-relative name's full bytes WITHOUT
/// following links (P2fix15 NEW-88 — the commit-time
/// settlement freshness read): `Ok(None)` when absent,
/// `Err` on any other failure (fail closed — the caller
/// refuses). Never stalls (no FIFOs opened — `O_NOFOLLOW`
/// + regular-only: nonregular names fail closed too).
fn read_name_bytes(
    dir_fd: &std::fs::File,
    name: &std::ffi::CString,
) -> std::io::Result<Option<Vec<u8>>> {
    use std::os::unix::io::AsRawFd as _;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: dir_fd is live; the name is NUL-free; st
    // outlives the call.
    if unsafe {
        libc::fstatat(
            dir_fd.as_raw_fd(),
            name.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(std::io::Error::last_os_error())
        };
    }
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "osslscope: settlement record slot is not a regular file",
        ));
    }
    // SAFETY: dir_fd is live; the name is NUL-free.
    let fd = unsafe {
        libc::openat(
            dir_fd.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: openat returned a fresh owned fd.
    let mut file = unsafe {
        use std::os::fd::FromRawFd as _;
        std::fs::File::from(std::os::fd::OwnedFd::from_raw_fd(fd))
    };
    let mut out = Vec::new();
    {
        use std::io::Read as _;
        // Bounded (records are small; anything past 1 MiB
        // fails closed — never unbounded).
        file.by_ref().take(1024 * 1024 + 1).read_to_end(&mut out)?;
    }
    if out.len() > 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "osslscope: settlement record slot oversize",
        ));
    }
    Ok(Some(out))
}

/// A failed settlement-record publish (P2fix15 NEW-88):
/// the error PLUS whether the record rename ran (`Some` —
/// our record stands at the name and withdrawal restores
/// the pre-write authority over it; `None` — the record
/// still carries the pre-write authority).
struct MarkerAttempt {
    err: std::io::Error,
    replaced: Option<(u64, u64)>,
}

/// Whether the settlement record was replaced during the
/// write being remediated (P2fix15 NEW-88 — withdrawal
/// restores the FULL pre-write durable state: target bytes
/// AND the settlement record).
enum MarkerState {
    /// The record still carries the pre-write authority
    /// (absent or `settled_before`) — withdrawal leaves it.
    Untouched,
    /// Our marker publish renamed onto the record name (our
    /// record stands under this identity) — withdrawal
    /// restores `settled_before` (or absence) over it.
    Replaced {
        /// Identity of OUR record at the record name (a
        /// rebind since our rename refuses the restore —
        /// never replace a foreign object).
        our_id: (u64, u64),
    },
}

/// Append the left-standing note to a refused write (P2fix15
/// NEW-87/NEW-88 — placement-bound withdrawal): the
/// unsettled publish is NOT swapped back beneath an
/// unproven directory (a swapback there is itself an inside
/// mutation) — it stands declared instead, and prior
/// authority survives via the settlement record (reopen
/// adopts the marker-bound prior, never the unconfirmed
/// replacement). The primary leads; the operator inspects.
fn with_publish_left_standing_note(primary: std::io::Error) -> std::io::Error {
    std::io::Error::new(
        primary.kind(),
        format!(
            "{primary} (unsettled publish left standing: placement unproven — no swapback beneath the producer; prior checkpoint remains authoritative via the settlement record; operator must inspect)"
        ),
    )
}

/// Append the withdrawal-unconfirmed note to a refused write
/// (P2fix15 NEW-88): the swapback + removal ran but the
/// confirming directory sync failed — crash states still
/// converge on the prior via the settlement record (the
/// record was untouched), but the withdrawal itself is not
/// yet durable. The primary leads.
fn with_withdrawal_unconfirmed_note(
    primary: std::io::Error,
    sync: std::io::Error,
) -> std::io::Error {
    std::io::Error::new(
        primary.kind(),
        format!("{primary} (withdrawal unconfirmed: directory sync failed: {sync})"),
    )
}

/// Withdraw an UNSETTLED publish (P2fix14 NEW-80/NEW-81,
/// placement-bound + durable P2fix15 NEW-87/NEW-88): the
/// publish syscall ran but post-verification (identity,
/// tripwire, position), the settle sync, or the settlement
/// publish refused it. Placement is re-proven FIRST — a
/// swapback or removal beneath the producer is itself an
/// inside mutation, so an unproven directory leaves the
/// unsettled publish STANDING declared (prior authority
/// survives via the settlement record — never a blind
/// adoption). Otherwise swap the exchange back (EXCHANGE
/// arm) or remove our own target entry (NOREPLACE arm),
/// identity-confirmed at every step, sync the directory
/// (DURABLE withdrawal — a failed settlement never leaves
/// the replacement authoritative across a crash), restore
/// the pre-write settlement record when our marker publish
/// replaced it, and return `primary` with the remediation
/// `outcome` declared. On any verification failure NOTHING
/// further is touched and the ambiguity is declared loudly.
#[allow(clippy::too_many_arguments)]
fn remediate_unsettled_publish(
    guard: &PlacementGuard,
    dir_fd: &std::fs::File,
    out_dir: &Path,
    step: &str,
    display: &Path,
    stage_c: &std::ffi::CString,
    target_c: &std::ffi::CString,
    settled_c: &std::ffi::CString,
    arm: &PublishArm,
    own_id: (u64, u64),
    outcome: &str,
    primary: std::io::Error,
    settled_before: &Option<SettledRecord>,
    marker: &MarkerState,
) -> std::io::Error {
    let withdrawn = |primary: std::io::Error| {
        std::io::Error::new(
            primary.kind(),
            format!("{primary} (unsettled publish withdrawn: {outcome})"),
        )
    };
    // Placement FIRST (P2fix15 NEW-87): no swapback and no
    // removal beneath an unproven directory — the unsettled
    // publish stands declared instead (prior authority via
    // the settlement record).
    if guard.prove_before(dir_fd, out_dir, step, display).is_err() {
        return with_publish_left_standing_note(primary);
    }
    match arm {
        PublishArm::Present(old_id) => {
            // Swap back: target→prior, stage→ours.
            if renameat2_result(dir_fd, stage_c, target_c, RENAME_EXCHANGE).is_err() {
                return ambiguous_settlement(primary, "swapback failed");
            }
            if !name_refers_to(dir_fd, target_c, *old_id)
                || !name_refers_to(dir_fd, stage_c, own_id)
            {
                return ambiguous_settlement(primary, "swapback verification failed");
            }
            match unlink_owned(dir_fd, stage_c, own_id) {
                Ok(true) => {}
                Ok(false) => {
                    return ambiguous_settlement(
                        primary,
                        "own stage identity changed during withdrawal",
                    );
                }
                Err(cleanup) => return with_stage_cleanup_note(primary, cleanup),
            }
        }
        PublishArm::Absent => {
            // Remove our own target entry (absence restored).
            match unlink_owned(dir_fd, target_c, own_id) {
                Ok(true) => {}
                Ok(false) => {
                    return ambiguous_settlement(primary, "target no longer carries our bytes");
                }
                Err(cleanup) => return with_stage_cleanup_note(primary, cleanup),
            }
        }
    }
    // Durable withdrawal (P2fix15 NEW-88): the swapback +
    // removal sync before the failure returns — every crash
    // state converges on the prior via the settlement
    // record (which the write below restores when ours
    // replaced it).
    if let Err(sync) = dir_fd.sync_all() {
        return with_withdrawal_unconfirmed_note(primary, sync);
    }
    // Settlement-record restore (P2fix15 NEW-88): when our
    // marker publish replaced the record, restore the
    // pre-write authority (the record, or absence) —
    // identity-confirmed (never replace a rebound name).
    match marker {
        MarkerState::Untouched => withdrawn(primary),
        MarkerState::Replaced { our_id } => {
            // Placement again before the restore mutations
            // (a move since the entry proof leaves the
            // record untouched — reopen refuses past the
            // mismatch loudly, never adopting around it).
            if guard
                .prove_before(dir_fd, out_dir, "settlement restore", display)
                .is_err()
            {
                return ambiguous_settlement(primary, "placement lost during settlement restore");
            }
            if !name_refers_to(dir_fd, settled_c, *our_id) {
                return ambiguous_settlement(
                    primary,
                    "settlement record changed under our own marker publish",
                );
            }
            match settled_before {
                Some(rec) => {
                    let bytes = render_settlement_record(rec);
                    // Stage + rename over our own record (the
                    // name still refers to our marker — the
                    // rename only ever replaces our own
                    // bytes; a failure declares loudly).
                    let nanos = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos())
                        .unwrap_or(0);
                    let tmp_c = std::ffi::CString::new(format!(
                        "{}-staging-restore-{}-{nanos}.tmp",
                        settled_c.to_string_lossy(),
                        std::process::id()
                    ))
                    .unwrap_or_else(|_| settled_c.clone());
                    if stage_and_rename(dir_fd, &tmp_c, settled_c, &bytes).is_err() {
                        return ambiguous_settlement(primary, "settlement record restore failed");
                    }
                    if dir_fd.sync_all().is_err() {
                        return ambiguous_settlement(
                            primary,
                            "settlement record restore unconfirmed",
                        );
                    }
                    // Readback: the restored name must carry
                    // the restored bytes (a rebind since the
                    // rename declares loudly — never trusted).
                    match read_name_bytes(dir_fd, settled_c) {
                        Ok(Some(back)) if back == bytes => {}
                        _ => {
                            return ambiguous_settlement(
                                primary,
                                "settlement record restore readback mismatch",
                            );
                        }
                    }
                    withdrawn(primary)
                }
                None => match unlink_owned(dir_fd, settled_c, *our_id) {
                    Ok(true) => {
                        if dir_fd.sync_all().is_err() {
                            return ambiguous_settlement(
                                primary,
                                "settlement record removal unconfirmed",
                            );
                        }
                        withdrawn(primary)
                    }
                    Ok(false) => ambiguous_settlement(
                        primary,
                        "settlement record changed under our own marker publish",
                    ),
                    Err(cleanup) => with_stage_cleanup_note(primary, cleanup),
                },
            }
        }
    }
}

/// Stage bytes under a fresh dirfd-relative name and rename
/// them onto `dest` (P2fix15 NEW-88 — the settlement-record
/// publish/restore primitive): O_EXCL staging (never follows,
/// never truncates a live name), fsync, plain rename onto
/// the destination. The caller freshness-checks `dest`
/// before (replace ours-or-absent only) and readback-checks
/// after. Returns the staged file's identity for the
/// caller's freshness tracking.
fn stage_and_rename(
    dir_fd: &std::fs::File,
    stage_c: &std::ffi::CString,
    dest_c: &std::ffi::CString,
    bytes: &[u8],
) -> std::io::Result<(u64, u64)> {
    use std::os::unix::io::AsRawFd as _;
    // SAFETY: dir_fd is a live open directory fd; the stage
    // name is NUL-free.
    let fd = unsafe {
        libc::openat(
            dir_fd.as_raw_fd(),
            stage_c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o644,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: openat returned a fresh owned fd (O_EXCL
    // created it — exclusively ours).
    let file = unsafe {
        use std::os::fd::FromRawFd as _;
        std::fs::File::from(std::os::fd::OwnedFd::from_raw_fd(fd))
    };
    {
        use std::io::Write as _;
        let mut file = &file;
        file.write_all(bytes)?;
    }
    file.sync_all()?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: the file is live; st outlives the call.
    if unsafe { libc::fstat(file.as_raw_fd(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let id = (st.st_dev, st.st_ino);
    // SAFETY: dir_fd is live; both names are NUL-free file
    // names in it.
    if unsafe {
        libc::renameat(
            dir_fd.as_raw_fd(),
            stage_c.as_ptr(),
            dir_fd.as_raw_fd(),
            dest_c.as_ptr(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(id)
}

/// Test-only one-shot swap hook (P2fix8 NEW-50): armed by the
/// pin, run once between the occupancy canonicalize and the
/// metadata lookup (the fp-confirmed interleave — a path that
/// resolves outside for one lookup and inside for the next).
/// Inert unless armed; production never arms it.
#[cfg(test)]
mod parent_swap_hook {
    use std::cell::RefCell;
    thread_local! {
        static HOOK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }
    pub fn arm(hook: impl FnOnce() + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }
    pub fn take_and_run() {
        if let Some(hook) = HOOK.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }
    pub fn disarm() {
        HOOK.with(|h| *h.borrow_mut() = None);
    }
}

/// Test-only one-shot pre-commit relocation hook (P2fix9
/// NEW-56): armed by the pin, run once after the stage write
/// and before the commit rename (proves outside placement
/// holds THROUGH the commit — a dir reparented under the
/// producer tree after staging must not commit there). Inert
/// unless armed; production never arms it.
#[cfg(test)]
mod pre_commit_hook {
    use std::cell::RefCell;
    thread_local! {
        static HOOK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }
    pub fn arm(hook: impl FnOnce() + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }
    pub fn take_and_run() {
        if let Some(hook) = HOOK.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }
    pub fn disarm() {
        HOOK.with(|h| *h.borrow_mut() = None);
    }
}

/// Test-only one-shot directory-sync fault injection (P2fix14
/// NEW-81): remaining injected directory-sync failures at the
/// checkpoint settle step — each armed failure fails the
/// directory sync AFTER the conditional publish, so the
/// commit must withdraw the unsettled publish (prior bytes
/// authoritative again) and report failure. Inert at zero.
/// `pub(crate)` so the export refresh/shutdown pins arm it.
#[cfg(test)]
pub(crate) mod dir_sync_fault {
    thread_local! { static FAIL_DIR_SYNC: std::cell::Cell<u64> = const { std::cell::Cell::new(0) }; }
    /// Arm `n` injected directory-sync failures.
    pub fn arm(n: u64) {
        FAIL_DIR_SYNC.with(|f| f.set(n));
    }
    /// Take one injected failure (true = fail this sync).
    pub fn take() -> bool {
        FAIL_DIR_SYNC.with(|f| {
            let n = f.get();
            if n > 0 {
                f.set(n - 1);
                true
            } else {
                false
            }
        })
    }
}

/// Test-only one-shot relocation hook (P2fix8 NEW-50): armed by
/// the pin, run once after checkpoint-parent validation and
/// before the first staging write (proves placement stabilizes
/// through the validated fd + dirfd-relative staging, never by
/// re-resolving the path). Inert unless armed; production never
/// arms it.
#[cfg(test)]
mod post_validation_hook {
    use std::cell::RefCell;
    thread_local! {
        static HOOK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }
    pub fn arm(hook: impl FnOnce() + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }
    pub fn take_and_run() {
        if let Some(hook) = HOOK.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }
    pub fn disarm() {
        HOOK.with(|h| *h.borrow_mut() = None);
    }
}

/// Test-only one-shot relocation hook (P2fix10 NEW-61): armed by
/// the pin, run once AFTER the staging ancestry re-check
/// SUCCEEDS and before stage creation (proves placement holds
/// THROUGH creation — a dir reparented under the producer tree
/// after the last successful staging check must refuse before
/// creating anything). Inert unless armed; production never
/// arms it.
#[cfg(test)]
mod post_staging_check_hook {
    use std::cell::RefCell;
    thread_local! {
        static HOOK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }
    pub fn arm(hook: impl FnOnce() + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }
    pub fn take_and_run() {
        if let Some(hook) = HOOK.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }
    pub fn disarm() {
        HOOK.with(|h| *h.borrow_mut() = None);
    }
}

/// Test-only one-shot relocation hook (P2fix10 NEW-61): armed by
/// the pin, run once after stage creation (the owned stage is
/// EMPTY here) and before the first byte is written (the
/// mid-write pin — a dir reparented under the producer tree
/// after creation must refuse with ZERO bytes written).
/// Inert unless armed; production never arms it.
#[cfg(test)]
mod pre_first_write_hook {
    use std::cell::RefCell;
    thread_local! {
        static HOOK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }
    pub fn arm(hook: impl FnOnce() + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }
    pub fn take_and_run() {
        if let Some(hook) = HOOK.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }
    pub fn disarm() {
        HOOK.with(|h| *h.borrow_mut() = None);
    }
}

/// Test-only one-shot relocation hook (P2fix10 NEW-61): armed by
/// the pin, run once AFTER the commit ancestry re-check
/// SUCCEEDS and before the commit rename (proves placement
/// holds THROUGH the rename — a dir reparented under the
/// producer tree after the last successful commit check must
/// refuse the rename and clean the owned stage). Inert unless
/// armed; production never arms it.
#[cfg(test)]
mod post_commit_check_hook {
    use std::cell::RefCell;
    thread_local! {
        static HOOK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }
    pub fn arm(hook: impl FnOnce() + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }
    pub fn take_and_run() {
        if let Some(hook) = HOOK.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }
    pub fn disarm() {
        HOOK.with(|h| *h.borrow_mut() = None);
    }
}

/// Test-only one-shot relocation hook (P2fix11 NEW-66,
/// repositioned P2fix13 NEW-74): armed by the pin, run once
/// at the creation envelope boundary — after the staging
/// check succeeds, BEFORE the fused pre-creation proof (a
/// dir reparented under the producer tree here must refuse
/// at that proof with ZERO bytes staged and no creation at
/// all; the proof→syscall gap itself carries no hook point).
/// Inert unless armed; production never arms it.
#[cfg(test)]
mod post_create_check_hook {
    use std::cell::RefCell;
    thread_local! {
        static HOOK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }
    pub fn arm(hook: impl FnOnce() + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }
    pub fn take_and_run() {
        if let Some(hook) = HOOK.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }
    pub fn disarm() {
        HOOK.with(|h| *h.borrow_mut() = None);
    }
}

/// Test-only one-shot relocation hook (P2fix11 NEW-66): armed by
/// the pin, run once AFTER the first bytes land in the owned
/// stage and before its fsync (the TRUE mid-write pin — the
/// stage is NON-empty here, unlike the pre-first-byte hook
/// above; a dir reparented under the producer tree mid-write
/// must refuse at the post-write re-proof with the bytes
/// never publishing and no further mutation). Inert unless
/// armed; production never arms it.
#[cfg(test)]
mod mid_write_hook {
    use std::cell::RefCell;
    thread_local! {
        static HOOK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }
    pub fn arm(hook: impl FnOnce() + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }
    pub fn take_and_run() {
        if let Some(hook) = HOOK.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }
    pub fn disarm() {
        HOOK.with(|h| *h.borrow_mut() = None);
    }
}

/// Test-only one-shot relocation hook (P2fix11 NEW-66,
/// repositioned P2fix13 NEW-74/75): armed by the pin, run once
/// at the publish envelope boundary — after the commit checks
/// succeed, BEFORE the fused publish proof (a dir reparented
/// under the producer tree here must refuse at that proof
/// with the rename NEVER running and the previously
/// committed bytes still authoritative; an outside→outside
/// move here must still commit — NEW-50 stabilization at the
/// last instant). Inert unless armed; production never
/// arms it.
#[cfg(test)]
mod pre_rename_hook {
    use std::cell::RefCell;
    thread_local! {
        static HOOK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }
    pub fn arm(hook: impl FnOnce() + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }
    pub fn take_and_run() {
        if let Some(hook) = HOOK.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }
    pub fn disarm() {
        HOOK.with(|h| *h.borrow_mut() = None);
    }
}

/// Test-only one-shot substitution hook (P2fix14 NEW-80):
/// armed by the pin, run once AFTER the fused publish-gate
/// target stat SUCCEEDS and before the conditional publish
/// (proves target identity holds THROUGH the publish — an
/// object substituted after the regularity check must be
/// detected and preserved, never replaced). Inert unless
/// armed; production never arms it. `pub(crate)` so the
/// export publish-boundary pin arms it.
#[cfg(test)]
pub(crate) mod pre_exchange_hook {
    use std::cell::RefCell;
    thread_local! {
        static HOOK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }
    pub fn arm(hook: impl FnOnce() + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }
    pub fn take_and_run() {
        if let Some(hook) = HOOK.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }
    pub fn disarm() {
        HOOK.with(|h| *h.borrow_mut() = None);
    }
}

/// Test-only one-shot relocation hook (P2fix14 NEW-80): armed
/// by the pin, run once AFTER the conditional publish and
/// before the post-publish verification (proves the
/// proof→syscall interval is pinned — a move there, including
/// one that reverses before the next check, must withdraw the
/// unsettled publish instead of completing it). Inert unless
/// armed; production never arms it. `pub(crate)` so the
/// export failed-withdrawal pin arms it.
#[cfg(test)]
pub(crate) mod post_exchange_hook {
    use std::cell::RefCell;
    thread_local! {
        static HOOK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }
    pub fn arm(hook: impl FnOnce() + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }
    pub fn take_and_run() {
        if let Some(hook) = HOOK.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }
    pub fn disarm() {
        HOOK.with(|h| *h.borrow_mut() = None);
    }
}

/// Test-only one-shot relocation hook (P2fix15 NEW-87): armed
/// by the pin, run once AFTER the final post-publish position
/// proof SUCCEEDS and before the settle-sync proof (proves
/// placement holds THROUGH settlement — a move there must
/// refuse BEFORE the directory sync runs, with no swapback
/// beneath the producer and prior authority preserved via
/// the settlement record). Inert unless armed; production
/// never arms it.
#[cfg(test)]
mod post_position_hook {
    use std::cell::RefCell;
    thread_local! {
        static HOOK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }
    pub fn arm(hook: impl FnOnce() + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }
    pub fn take_and_run() {
        if let Some(hook) = HOOK.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }
    pub fn disarm() {
        HOOK.with(|h| *h.borrow_mut() = None);
    }
}

/// Test-only one-shot entry hook (P2fix15 NEW-87): armed by
/// the pin, run once INSIDE the identity-conditional unlink
/// between its verification and the `unlinkat` (proves the
/// verify→unlink interval is confirmed, not trusted — a
/// rebind there must be DETECTED by the post-unlink
/// confirmation and declared loudly, never silent success).
/// Inert unless armed; production never arms it.
#[cfg(test)]
mod unlink_hook {
    use std::cell::RefCell;
    thread_local! {
        static HOOK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }
    pub fn arm(hook: impl FnOnce() + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }
    pub fn take_and_run() {
        if let Some(hook) = HOOK.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }
    pub fn disarm() {
        HOOK.with(|h| *h.borrow_mut() = None);
    }
}

/// Test-only post-settlement cleanup fault injection (P2fix15
/// NEW-89): remaining injected failures at the settled
/// commit's prior-bytes removal — each armed failure fails
/// the cleanup AFTER the commit settled, so the flush must
/// report `Ok` WITH the residue (live advances) instead of
/// failing. Inert at zero. `pub(crate)` so the export
/// sink/shutdown/reopen pin arms it.
#[cfg(test)]
pub(crate) mod settle_cleanup_fault {
    thread_local! { static FAIL_CLEANUP: std::cell::Cell<u64> = const { std::cell::Cell::new(0) }; }
    /// Arm `n` injected post-settlement cleanup failures.
    pub fn arm(n: u64) {
        FAIL_CLEANUP.with(|f| f.set(n));
    }
    /// Take one injected failure (true = fail this cleanup).
    pub fn take() -> bool {
        FAIL_CLEANUP.with(|f| {
            let n = f.get();
            if n > 0 {
                f.set(n - 1);
                true
            } else {
                false
            }
        })
    }
}

/// Test-only publish-syscall observation probe (P2fix15
/// NEW-87): how many conditional-publish syscalls ran since
/// the last take (lets a pin prove a refused publish NEVER
/// RAN, not merely that it was withdrawn after). Production
/// never reads it.
#[cfg(test)]
pub(crate) mod publish_probe {
    use std::cell::Cell;
    thread_local! {
        static PUBLISHES: Cell<u64> = const { Cell::new(0) };
    }
    pub fn record() {
        PUBLISHES.with(|m| m.set(m.get().saturating_add(1)));
    }
    pub fn take() -> u64 {
        PUBLISHES.with(|m| m.replace(0))
    }
}

/// Test-only directory-sync observation probe (P2fix15
/// NEW-87): how many checkpoint-dir `sync_all` calls ran
/// since the last take (lets a pin prove a refused
/// settlement NEVER SYNCED). Production never reads it.
#[cfg(test)]
pub(crate) mod dir_sync_probe {
    use std::cell::Cell;
    thread_local! {
        static SYNCS: Cell<u64> = const { Cell::new(0) };
    }
    pub fn record() {
        SYNCS.with(|m| m.set(m.get().saturating_add(1)));
    }
    pub fn take() -> u64 {
        SYNCS.with(|m| m.replace(0))
    }
}

/// Open the checkpoint parent, then validate the SAME opened
/// directory (P2fix7 NEW-44 — no pathname-check-then-reopen
/// gap). `parent` is the resolved parent path (empty already
/// mapped to the cwd by the caller); `display` names the
/// checkpoint in diagnostics.
fn open_validated_checkpoint_parent(
    parent: &Path,
    out_dir: &Path,
    display: &Path,
) -> std::io::Result<(std::fs::File, (u64, u64))> {
    let dir_fd = std::fs::File::open(parent).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "osslscope: checkpoint dir unresolvable at write: {} ({e})",
                parent.display()
            ),
        )
    })?;
    let id = validate_opened_parent(&dir_fd, parent, out_dir, display)?;
    Ok((dir_fd, id))
}

/// Unlink a dirfd-relative name, CHECKED (P2fix12 NEW-69 —
/// cleanup must not ignore unlink failures: the caller
/// surfaces the failure loudly — the operator must know a
/// stage/target leaked).
fn unlink_checked(dir_fd: &std::fs::File, name: &std::ffi::CString) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd as _;
    // SAFETY: dir_fd is live; the name is a NUL-free file name in it.
    if unsafe { libc::unlinkat(dir_fd.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Attach a failed-cleanup note to a primary write error
/// (P2fix12 NEW-69): the primary error LEADS (kind + text
/// preserved — callers matching on it keep working) and the
/// cleanup failure rides along loudly (never swallowed).
fn with_stage_cleanup_note(primary: std::io::Error, cleanup: std::io::Error) -> std::io::Error {
    std::io::Error::new(
        primary.kind(),
        format!("{primary} (stage cleanup failed: {cleanup})"),
    )
}

/// Bounded regular-file checkpoint intake (P2fix13 NEW-76):
/// the ONLY read of the checkpoint file contents. Stats
/// WITHOUT following links first (a nonregular target —
/// FIFO, directory, symlink, socket, device — refuses by
/// KIND naming regularity, before any open is attempted, so
/// no open can stall or touch the object); then opens
/// nonblocking and re-proves the OPENED fd as regular (the
/// stat→open race cannot bless a substituted object), and
/// requires it within `CHECKPOINT_MAX_BYTES` (fstat + a
/// capped read that still refuses a file growing past the
/// bound). Absent ⇒ `None` (fresh start); any other
/// failure refuses (an unreadable checkpoint must never
/// silently reset state — torn CONTENT still takes the
/// §6C-1c discard path above because those bytes were read
/// successfully).
fn read_checkpoint_file(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    use std::os::unix::ffi::OsStrExt as _;
    let lossy = path.display();
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "osslscope: checkpoint path is not a valid file name",
        )
    })?;
    let not_regular = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "osslscope: checkpoint target is not a regular file (refusing intake; {lossy})"
            ),
        )
    };
    // SAFETY: zeroed stat is the C out-parameter idiom; the
    // path is a NUL-free C string.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: st outlives the call.
    if unsafe { libc::lstat(c.as_ptr(), &mut st as *mut libc::stat) } != 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(std::io::Error::new(
            e.kind(),
            format!("osslscope: checkpoint unreadable at open ({lossy}): {e}"),
        ));
    }
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(not_regular());
    }
    // SAFETY: the path is a NUL-free C string.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(std::io::Error::new(
            e.kind(),
            format!("osslscope: checkpoint unreadable at open ({lossy}): {e}"),
        ));
    }
    // SAFETY: open returned a fresh owned fd.
    let mut file = unsafe {
        use std::os::fd::FromRawFd as _;
        std::fs::File::from(std::os::fd::OwnedFd::from_raw_fd(fd))
    };
    let md = file.metadata()?;
    if !md.is_file() {
        return Err(not_regular());
    }
    if md.len() > CHECKPOINT_MAX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "osslscope: checkpoint exceeds the intake bound ({CHECKPOINT_MAX_BYTES} bytes; {lossy})"
            ),
        ));
    }
    use std::io::Read as _;
    let mut bytes = Vec::with_capacity(md.len() as usize);
    let mut chunk = [0u8; 8192];
    loop {
        match file.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                bytes.extend_from_slice(&chunk[..n]);
                if bytes.len() as u64 > CHECKPOINT_MAX_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "osslscope: checkpoint exceeds the intake bound ({CHECKPOINT_MAX_BYTES} bytes; {lossy})"
                        ),
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(Some(bytes))
}

// --- Shared document signals (the C-08 dual path) ---

/// Completeness kind shared by both document shapes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum StatusKind {
    #[default]
    Complete,
    Partial,
    Fatal,
}

/// Fatal kinds that affect the shared exit math.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FatalKindWord {
    Recycled,
    AttachZero,
    Environment,
    Runtime,
}

/// Document signals both readers produce (§6C-1 shared functions
/// feed on these; the dual-path test pins their agreement).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DocSignals {
    pub state: String,
    pub reasons: Vec<String>,
    pub lanes: [u64; 4],
    pub site_rows: u64,
    /// Counters verbatim per path (spellings differ; the agreement
    /// test pins count + names + values + kind-fold).
    pub counters: Vec<serde_json::Value>,
    /// Policy outcome word (`pass`/`violation`/`inconclusive`/
    /// `no_verdict`/`observe_only`).
    pub outcome: String,
    pub status_kind: Option<StatusKind>,
    pub fatal_kind: Option<FatalKindWord>,
    /// Proved ENGINE evidence (service: real; doc_json: false —
    /// doc_json carries no engine plane, documented residual).
    pub proved_engine: bool,
    /// v2.9 trace projection (both shapes carry `trace_summary`).
    pub trace: Option<TraceSummaryData>,
}

/// Typed v2.9 trace projection (reuses the producer type).
pub type TraceSummaryData = crate::provider_observation::trace::TraceSummary;

/// Shared trace intake (P2fix3 GATE29): run the ONE
/// document-level contract over a document of the given shape
/// (`None` = reject — malformed trace never projects). The
/// version trigger binds the shape's CANONICAL discriminator
/// (P2fix8 NEW-51 — producer `schema`, doc_json
/// `schema_version`; a foreign alias rejects).
fn contract_trace(
    doc: &serde_json::Value,
    shape: crate::provider_observation::trace::DocShape,
) -> Option<Option<TraceSummaryData>> {
    use crate::provider_observation::trace as t;
    let parsed = doc
        .get("trace_summary")
        .map(t::parse_trace_section)
        .transpose()
        .ok()?;
    let minor = t::canonical_minor(doc, shape).ok()?;
    t::check_trace_contract(minor, parsed.as_ref(), doc.get("api_activity")).ok()
}

/// Read producer-shaped `CaptureDocument` signals (service envelope
/// `document`, C-02/C-04 field names).
pub fn signals_from_producer(doc: &serde_json::Value) -> Option<DocSignals> {
    let status = doc.get("status")?;
    // Both spellings: serde unit `"Complete"` and object
    // `{"Partial": {...}}` (externally tagged).
    let word = status.as_str().map(|s| s.to_string()).or_else(|| {
        status
            .as_object()
            .and_then(|o| o.keys().next().map(|k| k.to_string()))
    })?;
    let (state, kind) = match word.as_str() {
        "Complete" => ("complete", StatusKind::Complete),
        "Partial" => ("partial", StatusKind::Partial),
        "Fatal" => ("fatal", StatusKind::Fatal),
        _ => return None,
    };
    // Reason words via the SHARED function (no re-spelling): parse
    // the typed status, then map each reason.
    let typed: crate::evidence::Completeness = serde_json::from_value(status.clone()).ok()?;
    let reasons: Vec<String> = match &typed {
        crate::evidence::Completeness::Complete => vec![],
        crate::evidence::Completeness::Partial { reasons }
        | crate::evidence::Completeness::Fatal { reasons, .. } => reasons
            .iter()
            .map(crate::report::gap_reason_short)
            .collect(),
    };
    // Reason vocabulary (P2fix3 PRIVACY): actual per-kind
    // suffix vocabularies before any sink (markers, snapshot
    // JSON, adapters).
    if reasons.iter().any(|w| !valid_reason_word(w)) {
        return None;
    }
    let part = obj_at(doc, "legacy_partition")?;
    let lanes = [
        u64_at(part, "legacy_exclusive")?,
        u64_at(part, "non_legacy_exclusive")?,
        u64_at(part, "shared_ambiguous")?,
        // Producer field is `unfenced_tails`.
        u64_at(part, "unfenced_tails")?,
    ];
    let site_rows = arr_at(doc, "sites").map(|s| s.len() as u64).unwrap_or(0);
    // Typed + bounded counters (P2fix2 item 24 — no wholesale
    // counter-JSON clone): every record validates before it can
    // reach a sink; one malformed record rejects the document.
    let counters = arr_at(doc, "counters").cloned().unwrap_or_default();
    if counters.iter().any(|c| !validate_counter(c, false)) {
        return None;
    }
    let outcome = match doc.get("policy") {
        None | Some(serde_json::Value::Null) => "observe_only".to_string(),
        Some(p) => match str_at(p, "verdict") {
            // Producer `PolicyVerdict` serializes `Pass`/`Violation`/
            // `Inconclusive`/`NoVerdict`.
            Some("Pass") => "pass".to_string(),
            Some("Violation") => "violation".to_string(),
            Some("Inconclusive") => "inconclusive".to_string(),
            Some("NoVerdict") => "no_verdict".to_string(),
            _ => return None,
        },
    };
    let fatal_kind = match &typed {
        crate::evidence::Completeness::Fatal { kind, .. } => Some(match kind {
            crate::evidence::FatalKind::Recycled => FatalKindWord::Recycled,
            crate::evidence::FatalKind::AttachZero => FatalKindWord::AttachZero,
            crate::evidence::FatalKind::Environment(_) => FatalKindWord::Environment,
            crate::evidence::FatalKind::Runtime(_) => FatalKindWord::Runtime,
        }),
        _ => None,
    };
    // Typed parse for the engine plane (tolerant: absent ⇒ false).
    let proved_engine = serde_json::from_value::<crate::evidence::CaptureDocument>(doc.clone())
        .map(|d| d.has_proved_engine_evidence())
        .unwrap_or(false);
    // Strict trace intake (P2fix3 GATE29 — ONE document-level
    // contract): parse + the section/version triggers,
    // required-vs-withheld, inner/outer coherence, conservation,
    // and coverage-vs-api_activity reconciliation — malformed
    // trace rejects the document before rendering/checkpointing
    // (never a silent None). Producer shape: canonical `schema`
    // (P2fix8 NEW-51).
    let trace = contract_trace(doc, crate::provider_observation::trace::DocShape::Producer)?;
    Some(DocSignals {
        state: state.to_string(),
        reasons,
        lanes,
        site_rows,
        counters,
        outcome,
        status_kind: Some(kind),
        fatal_kind,
        proved_engine,
        trace,
    })
}

/// Map one doc_json reason object back to its `gap_reason_short`
/// word (inverse of `gap_reason_json`).
fn doc_json_reason_word(r: &serde_json::Value) -> Option<String> {
    let kind = str_at(r, "kind")?;
    Some(match kind {
        "unknown-denominator" => format!("unknown-denominator:{}", str_at(r, "scope")?),
        "undiscovered-sites" => format!("undiscovered-sites:{}", str_at(r, "scope")?),
        "unattached-sites" => format!("unattached-sites:{}", str_at(r, "scope")?),
        "loss" => format!("loss:{}", str_at(r, "counter")?),
        "unattributed-calls" => "unattributed-calls".to_string(),
        "startup-gap" => "startup-gap".to_string(),
        "tail-gap" => "tail-gap".to_string(),
        "signal-cut" => "signal-cut".to_string(),
        "visibility-lost" => format!("visibility-lost:{}", str_at(r, "cause")?),
        _ => return None,
    })
}

/// Read doc_json-shaped signals (oneshot, C-07 field names, tolerant).
pub fn signals_from_doc_json(doc: &serde_json::Value) -> Option<DocSignals> {
    let completeness = obj_at(doc, "completeness")?;
    let (state, kind) = match str_at(completeness, "status")? {
        "COMPLETE" => ("complete", StatusKind::Complete),
        "PARTIAL" => ("partial", StatusKind::Partial),
        "FATAL" => ("fatal", StatusKind::Fatal),
        _ => return None,
    };
    let mut reasons = Vec::new();
    for r in arr_at(completeness, "reasons").cloned().unwrap_or_default() {
        reasons.push(doc_json_reason_word(&r)?);
    }
    // Same reason-vocabulary rule as the producer path.
    if reasons.iter().any(|w| !valid_reason_word(w)) {
        return None;
    }
    // doc_json lanes carry the `_calls` suffix (and `unfenced_tail`
    // singular) — the tolerant spelling arm.
    let part = obj_at(doc, "legacy_partition")?;
    let lanes = [
        u64_at(part, "legacy_exclusive_calls")?,
        u64_at(part, "non_legacy_exclusive_calls")?,
        u64_at(part, "shared_ambiguous_calls")?,
        u64_at(part, "unfenced_tail_calls")?,
    ];
    let site_rows = arr_at(doc, "sites").map(|s| s.len() as u64).unwrap_or(0);
    // Same typed + bounded counter rule as the producer path
    // (doc_json kebab spellings).
    let counters = arr_at(completeness, "counters")
        .cloned()
        .unwrap_or_default();
    if counters.iter().any(|c| !validate_counter(c, true)) {
        return None;
    }
    let outcome = match doc.get("policy") {
        None | Some(serde_json::Value::Null) => "observe_only".to_string(),
        Some(p) => match str_at(p, "verdict")? {
            "pass" => "pass".to_string(),
            "violation" => "violation".to_string(),
            "inconclusive" => "inconclusive".to_string(),
            "no-verdict" => "no_verdict".to_string(),
            _ => return None,
        },
    };
    let fatal_kind = if kind == StatusKind::Fatal {
        let fk = obj_at(completeness, "fatal_kind")?;
        Some(match str_at(fk, "kind")? {
            "recycled" => FatalKindWord::Recycled,
            "attach-zero" => FatalKindWord::AttachZero,
            "environment" => FatalKindWord::Environment,
            "runtime" => FatalKindWord::Runtime,
            _ => return None,
        })
    } else {
        None
    };
    // Strict trace intake (P2fix3 GATE29 — the SAME contract
    // as the producer path): a PRESENT section must parse AND
    // validate. doc_json shape: canonical `schema_version`
    // (P2fix8 NEW-51).
    let trace = contract_trace(doc, crate::provider_observation::trace::DocShape::Raw)?;
    // The doc_json R05 `engine_observations` plane carries the
    // proved-ENGINE usability signal (DELTA-6 parity). The flat
    // projection spelling (`window` word + `calls`) applies the
    // SAME rule as the typed `is_proved` predicate (in-window
    // calls), pinned by the cross-path parity test (fail closed —
    // a malformed plane proves nothing, never a silent default).
    let proved_engine = arr_at(doc, "engine_observations")
        .map(|obs| {
            obs.iter().any(|o| {
                u64_at(o, "calls").unwrap_or(0) > 0 && str_at(o, "window") == Some("in-window")
            })
        })
        .unwrap_or(false);
    Some(DocSignals {
        state: state.to_string(),
        reasons,
        lanes,
        site_rows,
        counters,
        outcome,
        status_kind: Some(kind),
        fatal_kind,
        proved_engine,
        trace,
    })
}

/// Read either document shape (producer first, doc_json fallback).
pub fn signals_from_doc(doc: &serde_json::Value) -> Option<DocSignals> {
    signals_from_producer(doc).or_else(|| signals_from_doc_json(doc))
}

/// Minimal typed document for the SHARED exit math: `exit_for`
/// reads only the status kind, fatal usability, and delivery. Reasons
/// never enter exit math, so the reconstruction carries none.
fn typed_doc_for_exit(sig: &DocSignals) -> Option<crate::evidence::CaptureDocument> {
    use crate::evidence::{Completeness, FatalKind};
    let status = match (sig.status_kind?, sig.fatal_kind) {
        (StatusKind::Complete, _) => Completeness::Complete,
        (StatusKind::Partial, _) => Completeness::Partial { reasons: vec![] },
        (StatusKind::Fatal, Some(k)) => Completeness::Fatal {
            kind: match k {
                FatalKindWord::Recycled => FatalKind::Recycled,
                FatalKindWord::AttachZero => FatalKind::AttachZero,
                FatalKindWord::Environment => FatalKind::Environment(String::new()),
                FatalKindWord::Runtime => FatalKind::Runtime(String::new()),
            },
            reasons: vec![],
        },
        (StatusKind::Fatal, None) => return None,
    };
    // Engine plane: when the signal carries proved ENGINE evidence
    // (service path, typed), the exit math needs one qualifying
    // observation (`calls > 0` in-window — the exact
    // `has_proved_engine_evidence` predicate input, not fabricated
    // evidence: the bit came from the real document).
    let mut doc = minimal_capture_document(status);
    if sig.proved_engine {
        doc.engine_observations = vec![crate::evidence::EngineObservation {
            key: crate::evidence::SiteKey {
                object: crate::evidence::ObjectId(String::new()),
                device: 0,
                inode: 0,
                offset: 0,
            },
            generation: 0,
            entrypoint: 0,
            calls: 1,
            window: crate::evidence::EngineWindow::InWindow,
        }];
    }
    Some(doc)
}

fn minimal_capture_document(
    status: crate::evidence::Completeness,
) -> crate::evidence::CaptureDocument {
    crate::evidence::CaptureDocument {
        algorithm_identities: vec![],
        site_provenance: vec![],
        api_activity: vec![],
        candidate_associations: vec![],
        schema: String::new(),
        package_build: None,
        count_object: None,
        status,
        window: crate::evidence::CaptureWindow {
            requested_start_ns: 0,
            requested_end_ns: 0,
            effective_start_ns: 0,
            effective_end_ns: 0,
            signal_cut: false,
            count_admission: None,
        },
        sites: vec![],
        fenced: vec![],
        objects: vec![],
        coverage: vec![],
        counters: vec![],
        target: crate::evidence::TargetRecord::unknown(),
        openssl: crate::evidence::OpensslVersion::unknown(),
        disposition: None,
        policy: None,
        legacy_partition: crate::evidence::LegacyCallPartition::default(),
        engine_observations: vec![],
        context: None,
        traversal: None,
        selected_objects: None,
        attach_diagnostics: vec![],
        refusal_diagnostics: vec![],
        membership: None,
        execution_attributions: vec![],
        algorithm_selectors: vec![],
        attribution_bounds: None,
        request_evidence: None,
        trace_summary: None,
    }
}

/// Alert markers for one folded window (§6C-9 stickiness input —
/// item 25): partial/fatal (completeness), cut (signal/accum),
/// violation (policy), and loss (counters or ring evidence).
/// Every folded window records these (not just the latest), so
/// coalesced windows keep their facts through the fold.
pub(crate) fn window_markers(
    seq: u64,
    sig: &DocSignals,
    window: &WindowBlock,
    session_loss: Option<&SessionLossShape>,
) -> Vec<String> {
    let mut out = vec![];
    match sig.state.as_str() {
        "partial" => out.push(format!(
            "partial seq={seq} reasons={}",
            sig.reasons.join(",")
        )),
        "fatal" => out.push(format!("fatal seq={seq} reasons={}", sig.reasons.join(","))),
        _ => {}
    }
    if window.signal_cut || window.accum_cut {
        out.push(format!(
            "cut seq={seq} signal={} accum={}",
            window.signal_cut, window.accum_cut
        ));
    }
    if sig.outcome == "violation" {
        out.push(format!("violation seq={seq}"));
    }
    let ring_sum: u64 = session_loss.map(|s| s.ring.iter().sum()).unwrap_or(0);
    if !sig.counters.is_empty() || ring_sum > 0 {
        out.push(format!(
            "loss seq={seq} counters={} ring_loss={ring_sum}",
            sig.counters.len()
        ));
    }
    out
}

/// Counter-kind order for `loss.counters[]` (Loss-kind first,
/// then Activity — stable within kind).
fn counter_kind_rank(c: &serde_json::Value) -> u8 {
    let kind = c
        .get("kind")
        .and_then(|k| k.as_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if kind == "loss" { 0 } else { 1 }
}

/// Sort counters Loss-first (stable, verbatim records).
pub fn sort_counters_loss_first(counters: &mut [serde_json::Value]) {
    counters.sort_by_key(counter_kind_rank);
}

/// `exit_hint` via the SHARED `report::exit_for` (C-06): the outcome
/// word maps to `PolicyOutcome`, delivery reads clean (the presenter
/// delivers nothing itself).
pub fn exit_hint_for(sig: &DocSignals) -> Option<u8> {
    use crate::policy::PolicyOutcome;
    let outcome = match sig.outcome.as_str() {
        "pass" => PolicyOutcome::Pass,
        "violation" => PolicyOutcome::Violation,
        "inconclusive" => PolicyOutcome::Inconclusive,
        "no_verdict" | "observe_only" => PolicyOutcome::NoVerdict,
        _ => return None,
    };
    let doc = typed_doc_for_exit(sig)?;
    let delivery = crate::report::DeliveryResult {
        primary: crate::report::ArtifactOutcome {
            dest: String::new(),
            ok: true,
            bytes: 0,
            error: None,
        },
        cbom: None,
        diagnostics: vec![],
    };
    Some(crate::report::exit_for(outcome, None, &doc, &delivery))
}

// --- Epoch fold state + checkpoint (§6C-1/§6C-1c) ---

/// Per-(run, member) counted ranges (§6C-1b dedup state).
pub type CountedRanges = BTreeMap<String, Vec<[u64; 2]>>;

/// Sealed run GROSS (§6C-1c/§6C-1d checkpoint state).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedGross {
    pub records: u64,
    pub bytes: u64,
    pub queue_full: ReasonTotals,
    pub epipe: ReasonTotals,
    pub stream_abandoned: ReasonTotals,
    /// `summary` or `close`.
    pub source: String,
    /// Sticky tail note (null or `sealed_from_close_no_summary`).
    pub tail_note: Option<String>,
    /// Proven idempotent (later matching summary added 0).
    pub idempotent: bool,
}

/// Latest folded window (window-scoped snapshot inputs).
/// Checkpoint-persisted (§6C-1c): a restart with no new windows
/// re-serves last-good, never pre-first-window.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LatestWindow {
    seq: u64,
    sha: String,
    generation: u64,
    run_id: RunIdShape,
    window: WindowBlock,
    signals: DocSignals,
    members_observed: u64,
    members_retired: u64,
    deferred_depth: Option<u64>,
    session_loss: Option<SessionLossShape>,
    policy_active: Option<PolicyActive>,
    /// Source document schema minor (P2fix3 GATE29 — restore
    /// re-runs the document-level trigger on it).
    schema_minor: Option<u64>,
    /// Source document api_activity rows (P2fix3 GATE29 — restore
    /// re-runs coverage reconciliation on them; empty when the
    /// source carried none).
    api_activity: Vec<serde_json::Value>,
}

/// Presenter fold state (service mode).
#[derive(Debug, Clone)]
pub struct Presenter {
    out_dir: PathBuf,
    checkpoint_path: PathBuf,
    /// Bound checkpoint-parent identity (P2fix6 NEW-34):
    /// (device, inode) captured at open — `None` while the dir
    /// is unresolvable (the NEW-18 absent-dir deferral; the
    /// first successful write binds it). Every write re-stats
    /// the validated parent and refuses on mismatch. Runtime
    /// binding only (never checkpoint-persisted).
    checkpoint_parent_id: Option<(u64, u64)>,
    window_secs: u64,
    command: String,
    generation: Option<u64>,
    watermark: Option<u64>,
    snapshot_seq: u64,
    checkpoint_seq: u64,
    calls_total: u64,
    lanes: [u64; 4],
    retired_epoch: u64,
    epoch_by_cause: [u64; 12],
    epoch_partial: [u64; 10],
    /// Trace unmeasured ranges (retention gaps + folded-but-null
    /// windows — raw-plane coverage evidence; epoch trace folds
    /// are withheld on the service path until the per-window
    /// producer contract exists, DELTA-2).
    trace_unmeasured: Vec<[u64; 2]>,
    epoch_changes: u64,
    series_overflow: u64,
    counted: CountedRanges,
    sealed: BTreeMap<String, SealedGross>,
    current_run: Option<String>,
    current_gross: StreamDropsShape,
    /// Early-adopted summary gross for the CURRENT run (P2fix4
    /// NEW-15): a summary adopted before its run's windows unseals
    /// into this slot at transition (one authoritative gross per
    /// run at every refresh — the sealed entry must not survive
    /// beside the live close). Seeded into `current_gross`;
    /// reconcile-then-sealed at transition-away; cleared at
    /// epoch reset; checkpoint-persisted.
    adopted_summary: Option<StreamDropsShape>,
    /// Observed close vector for the CURRENT run (P2fix5 NEW-30):
    /// the running max over FOLDED CLOSES ONLY — never seeded
    /// with summary maxima (unlike `current_gross`, which is the
    /// publish running max). Retained SEPARATELY from the adopted
    /// summary through restart so the seal derives provenance
    /// from the true observed-vs-summary pair (a seeded vector
    /// cannot show mixed lead/lag). Reset at transition +
    /// epoch reset; checkpoint-persisted.
    current_close: StreamDropsShape,
    /// Retained current-run summary gross (P2fix6 NEW-35): EVERY
    /// validated summary adopted while its run is current
    /// max-merges here (in addition to the publish running max),
    /// so the seal reconciles the true observed-vs-summary pair
    /// even after the singleton summary file is replaced by a
    /// successor summary. Without this slot the seal reads only
    /// `current_close` and invents a missing-summary marker for
    /// a run whose summary WAS adopted. Reset at transition +
    /// epoch reset; checkpoint-persisted.
    current_summary: Option<StreamDropsShape>,
    stream_seen_configured: bool,
    /// Sticky stream notes (§6C-1d).
    stream_sealed_note: bool,
    stream_mismatch_note: bool,
    /// Accumulator paths carrying flagged `unstable_snapshot`.
    unstable: std::collections::BTreeSet<String>,
    latest: Option<LatestWindow>,
    /// Pending alert markers (per folded window; drained into each
    /// snapshot by `build`).
    pending_markers: Vec<String>,
    /// Checkpoint-bound admission state (P2fix2 item 13): the
    /// export loop saves the budget snapshot here after every
    /// admission (persisted by the next checkpoint write) and takes
    /// it once after opening (restored budget — no re-admission
    /// churn, no omission recount across restarts).
    admission: Option<super::budget::BudgetSnapshot>,
    /// Checkpoint-bound accumulation starts (P2fix4 NEW-16):
    /// (epoch_start, run_start) wall anchors for OTLP cumulative
    /// sums — saved with every joint commit, taken once after
    /// opening (a same-generation restart keeps the epoch's
    /// start instead of emitting zero).
    export_starts: Option<(u64, u64)>,
    /// Pre-first-window sequence/policy state.
    seq_generation: Option<u64>,
    seq_run_id: Option<RunIdShape>,
    policy_status_active: Option<PolicyActive>,
    /// Preserved failed-unpublished epoch (P2fix11 NEW-67 —
    /// checkpoint-persisted, absent when none).
    previous_epoch: Option<PreservedEpoch>,
    /// Generation of the last `build_service` success (a framed
    /// publication — staged-only builds don't publish).
    /// Runtime-only (never persisted).
    published_generation: Option<u64>,
    /// Watermark tip at the last framed publication (P2fix12
    /// NEW-71 — the published tip: a reset preserves the
    /// tenure's FINAL accepted prefix when it advanced past
    /// this tip or accrued failure since, instead of clearing
    /// it just because the generation matches). Runtime-only
    /// (never persisted; always set/cleared with
    /// `published_generation`).
    published_tip: Option<u64>,
    /// Generation current when the last scan/build failure fired
    /// (runtime-only). A successful scan heals it; a reset
    /// clears it (the new tenure starts clean).
    failed_generation: Option<u64>,
    /// True once the current tenure folded ≥1 window
    /// (runtime-only; restore derives it from the watermark).
    epoch_folded: bool,
    /// Live epoch state as of the last fold / scan end / adopt /
    /// restore (runtime-only): the capture source at a
    /// generation reset — the CURRENT scan's gap detections must
    /// not leak into the OUTGOING epoch's preserved finals.
    epoch_preview: Option<PreservedEpoch>,
    /// Tenure open at restore (P2fix14 NEW-83, runtime-only):
    /// the restored generation, consumed by the first reset
    /// that leaves it. A first-scan reset FROM this tenure
    /// preserves its finals (the generation ACTUALLY being
    /// left), never the stale retained record.
    restored_generation: Option<u64>,
    /// Filename sequence the CURRENT scan rejected at
    /// (P2fix15 NEW-91, runtime-only): set where the scan
    /// loop breaks on its first failure, cleared at every
    /// scan start — the watch outage note names it beside
    /// the accepted tip on the SAME line (same-scan proof).
    /// `None` when the scan rejected nothing (or failed
    /// before scanning) — the note says `none` instead of
    /// naming a stale window.
    last_rejected_seq: Option<u64>,
    /// Prior-settlement recovery at open (P2fix15 NEW-88,
    /// runtime-only): true when the target stood
    /// hash-valid but UNCONFIRMED (settlement-record
    /// mismatch) and the open adopted the marker-bound
    /// prior from a standing stage instead — the operator
    /// warning printed at recovery names the checkpoint.
    recovered_prior: bool,
    /// Post-settlement residue of the last settled flush
    /// (P2fix15 NEW-89, runtime-only): names cleanup the
    /// commit left behind — the caller drains it via
    /// `take_flush_residue` and reports each entry (the
    /// commit stands either way).
    last_flush_residue: Vec<String>,
}

impl Presenter {
    /// Open a service-mode presenter over `out_dir`.
    pub fn open(out_dir: &Path, window_secs: u64) -> std::io::Result<Self> {
        Self::open_as(out_dir, window_secs, "export")
    }

    /// Open with an explicit owner command word (`export`/`watch`).
    pub fn open_as(out_dir: &Path, window_secs: u64, command: &str) -> std::io::Result<Self> {
        Self::open_with_checkpoint(out_dir, &checkpoint_default(out_dir), window_secs, command)
    }

    /// Open with an explicit checkpoint path (`--checkpoint`).
    pub fn open_with_checkpoint(
        out_dir: &Path,
        checkpoint: &Path,
        window_secs: u64,
        command: &str,
    ) -> std::io::Result<Self> {
        // Placement (P2fix3 NEW-13, P2fix4 NEW-13/NEW-18): the
        // checkpoint lives OUTSIDE the producer out-DIR (default
        // and explicit paths alike — consumers are read-only on
        // it). Checked here AND at every write.
        check_checkpoint_placement(out_dir, checkpoint).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("osslscope: {e}"))
        })?;
        let mut p = Self {
            out_dir: out_dir.to_path_buf(),
            checkpoint_path: checkpoint.to_path_buf(),
            checkpoint_parent_id: checkpoint_parent_id(checkpoint),
            window_secs: window_secs.max(1),
            command: command.to_string(),
            generation: None,
            watermark: None,
            snapshot_seq: 0,
            checkpoint_seq: 0,
            calls_total: 0,
            lanes: [0; 4],
            retired_epoch: 0,
            epoch_by_cause: [0; 12],
            epoch_partial: [0; 10],
            trace_unmeasured: vec![],
            epoch_changes: 0,
            series_overflow: 0,
            counted: BTreeMap::new(),
            sealed: BTreeMap::new(),
            current_run: None,
            current_gross: StreamDropsShape {
                records: 0,
                bytes: 0,
                queue_full: ReasonTotals::default(),
                epipe: ReasonTotals::default(),
                stream_abandoned: ReasonTotals::default(),
            },
            adopted_summary: None,
            current_close: StreamDropsShape::default(),
            current_summary: None,
            stream_seen_configured: false,
            stream_sealed_note: false,
            stream_mismatch_note: false,
            unstable: std::collections::BTreeSet::new(),
            latest: None,
            pending_markers: vec![],
            admission: None,
            export_starts: None,
            seq_generation: None,
            seq_run_id: None,
            policy_status_active: None,
            previous_epoch: None,
            published_generation: None,
            published_tip: None,
            failed_generation: None,
            epoch_folded: false,
            epoch_preview: None,
            restored_generation: None,
            last_rejected_seq: None,
            recovered_prior: false,
            last_flush_residue: Vec::new(),
        };
        p.load_checkpoint()?;
        Ok(p)
    }

    /// Preserved failed-unpublished epoch (P2fix11 NEW-67): the
    /// accepted final state of the previous epoch when a
    /// generation reset discarded it after a failure without a
    /// publication — the watch loop's `PREVIOUS EPOCH` source
    /// (preferred over last-good on a generation change).
    pub fn previous_epoch(&self) -> Option<PreservedEpoch> {
        self.previous_epoch.clone()
    }

    /// Folded tip for the watch outage note (P2fix14 NEW-84):
    /// the accepted (generation, watermark) the live scan
    /// holds (a failed scan keeps its accepted prefix — the
    /// note names the tip AT the rejection, same scan).
    pub fn folded_tip(&self) -> (Option<u64>, Option<u64>) {
        (self.generation, self.watermark)
    }

    /// Rejected window for the watch outage note (P2fix15
    /// NEW-91): the filename sequence the current scan
    /// broke at (`None` when it rejected nothing) — named
    /// on the SAME line as the accepted tip (same scan).
    pub fn rejected_window(&self) -> Option<u64> {
        self.last_rejected_seq
    }

    /// Prior-settlement recovery at open (P2fix15 NEW-88):
    /// true when this presenter recovered by adopting the
    /// marker-bound prior (the standing target was
    /// hash-valid but unconfirmed).
    pub fn recovered_unsettled_prior(&self) -> bool {
        self.recovered_prior
    }

    /// Take the last settled flush's post-settlement
    /// residue (P2fix15 NEW-89): each entry names cleanup
    /// the commit left behind — the caller reports them
    /// (the commit stands either way).
    pub fn take_flush_residue(&mut self) -> Vec<String> {
        std::mem::take(&mut self.last_flush_residue)
    }

    /// Fold totals for cross-module pins (P2fix15 NEW-88):
    /// the live (`calls_total`, four lanes) — lets the
    /// export recovery pins assert exact reopen accounting
    /// without reaching into fold state.
    pub fn fold_totals(&self) -> (u64, [u64; 4]) {
        (self.calls_total, self.lanes)
    }

    /// Refresh the epoch preview from live state (P2fix11 NEW-67):
    /// the capture source at a generation reset. Called after
    /// every fold, at scan end (both exits), after summary
    /// adoption, and at restore — so the reset captures the
    /// OUTGOING epoch's finals, never the current scan's own
    /// gap detections. No-op before the first adoption.
    fn refresh_epoch_preview(&mut self) {
        let (Some(generation), Some(window_seq)) = (self.generation, self.watermark) else {
            return;
        };
        self.epoch_preview = Some(PreservedEpoch {
            generation,
            window_seq,
            calls_total: self.calls_total,
            lanes: self.lanes,
            unstable: self.unstable.iter().cloned().collect(),
            unmeasured: self.trace_unmeasured.clone(),
        });
    }

    /// Test seam: fold one parsed envelope (real fold path, no I/O).
    pub fn fold_test_envelope(&mut self, env: &serde_json::Value, sha: &str) -> Result<(), String> {
        self.fold_envelope(env, sha, None)
    }

    /// Test seam: current snapshot without I/O.
    pub fn snapshot(&mut self) -> Result<OperatorSnapshot, String> {
        self.build()
    }

    /// Adopt an exporter overflow count into presenter-run state.
    pub fn adopt_overflow(&mut self, overflow: u64) {
        self.series_overflow = self.series_overflow.max(overflow);
    }

    /// Save checkpoint-bound admission state (export loop: after
    /// every admission; persisted by the next checkpoint write).
    pub fn save_admission(&mut self, snap: super::budget::BudgetSnapshot) {
        self.admission = Some(snap);
    }

    /// Flush the checkpoint NOW (export loop: after a generation
    /// change the new watermark + the new admission commit
    /// together BEFORE the new snapshot serves — P2fix3 NEW-9).
    /// The outcome reports post-settlement residue SEPARATELY
    /// (P2fix15 NEW-89 — a settled commit is `Ok` even when
    /// cleanup left residue; the caller advances live state
    /// and surfaces the residue to the operator).
    pub fn flush_checkpoint(&mut self) -> std::io::Result<FlushOutcome> {
        self.write_checkpoint()
    }

    /// Take restored checkpoint-bound admission state (export loop:
    /// once after opening, before the first admission; `None` when
    /// the checkpoint carries none — fresh budget).
    pub fn take_admission(&mut self) -> Option<super::budget::BudgetSnapshot> {
        self.admission.take()
    }

    /// Read restored checkpoint-bound admission state WITHOUT
    /// stripping the live presenter (P2fix6 NEW-33 — the export
    /// loop's restore path: the presenter keeps the last
    /// committed values, so a failed first refresh + shutdown
    /// re-persists them instead of nulling the checkpoint).
    pub fn peek_admission(&self) -> Option<super::budget::BudgetSnapshot> {
        self.admission.clone()
    }

    /// Save checkpoint-bound accumulation starts (export loop:
    /// with every joint commit, before the write).
    pub fn save_export_starts(&mut self, epoch_start: u64, run_start: u64) {
        self.export_starts = Some((epoch_start, run_start));
    }

    /// Take restored accumulation starts (export loop: once after
    /// opening; `None` when the checkpoint carries none — first
    /// refresh binds from its snapshot).
    pub fn take_export_starts(&mut self) -> Option<(u64, u64)> {
        self.export_starts.take()
    }

    /// Read restored accumulation starts WITHOUT stripping the
    /// live presenter (P2fix6 NEW-33 — the export loop's restore
    /// path; see [`Self::peek_admission`]).
    pub fn peek_export_starts(&self) -> Option<(u64, u64)> {
        self.export_starts
    }

    /// Committed presenter-run omission total (P-14) for the export
    /// loop's publish step (P2fix5 NEW-22): both sinks render this
    /// post-admission value, never the pre-admission snapshot's.
    pub(crate) fn committed_series_overflow(&self) -> u64 {
        self.series_overflow
    }

    /// Test-only live-state fingerprint (P2fix5 NEW-22): the full
    /// staged+committed state (fold, watermark, generation,
    /// admission, omissions, starts, sequences, markers) minus the
    /// volatile owner block. A failed refresh must leave it
    /// byte-identical.
    #[cfg(test)]
    pub(crate) fn test_live_fingerprint(&self) -> serde_json::Value {
        let mut body = self.checkpoint_body();
        if let Some(obj) = body.as_object_mut() {
            obj.remove("owner");
            obj.insert(
                "pending_markers".to_string(),
                serde_json::json!(self.pending_markers),
            );
        }
        body
    }

    /// Read sequence/policy/summary sidecars (tolerant).
    fn read_sidecars(&mut self) {
        if let Ok(body) = std::fs::read(self.out_dir.join("sequence.json")) {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body) {
                self.seq_generation = u64_at(&v, "generation");
                if let Some(run) = obj_at(&v, "run_id") {
                    self.seq_run_id = read_run_id(run);
                }
            }
        }
        if let Ok(body) = std::fs::read(self.out_dir.join("policy-status.json")) {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body) {
                if let Some(active) = obj_at(&v, "active") {
                    self.policy_status_active = read_policy_active(active);
                }
            }
        }
    }

    /// Full service build: fold new windows, adopt the summary,
    /// checkpoint, return the snapshot.
    pub fn build_service(&mut self) -> Result<OperatorSnapshot, String> {
        let snap = self.build_service_staged()?;
        let outcome = match self.write_checkpoint() {
            Ok(outcome) => outcome,
            Err(e) => {
                // The epoch folded cleanly but never published (the
                // checkpoint refused) — a failure in its tenure
                // (P2fix11 NEW-67).
                self.failed_generation = self.generation;
                return Err(e.to_string());
            }
        };
        // Settled (P2fix15 NEW-89): post-settlement residue
        // reports separately — the caller drains it (the
        // commit stands either way).
        self.last_flush_residue = outcome.residue;
        // Framed publication (P2fix11 NEW-67): this generation is
        // published — and any preserved record OF it is stale
        // (same-generation recovery supersedes the mid-failure
        // capture; last-good covers it now). The published tip
        // pins the watermark last-good covers (P2fix12 NEW-71
        // — a later reset compares the FINAL prefix against
        // it).
        self.published_generation = self.generation;
        self.published_tip = self.watermark;
        if self
            .previous_epoch
            .as_ref()
            .is_some_and(|p| Some(p.generation) == self.published_generation)
        {
            self.previous_epoch = None;
        }
        Ok(snap)
    }

    /// Staged service build (P2fix4 NEW-16): fold new windows,
    /// adopt the summary, validate + build — WITHOUT committing
    /// the checkpoint. The export refresh path stages first, then
    /// commits snapshot + watermark + admission + omissions ONCE
    /// (jointly, after admission) before publishing — no
    /// intermediate checkpoint with a new watermark beside a stale
    /// admission ever lands.
    pub fn build_service_staged(&mut self) -> Result<OperatorSnapshot, String> {
        // A new scan rejects nothing yet (P2fix15 NEW-91 —
        // the outage note never names a stale window).
        self.last_rejected_seq = None;
        if !self.out_dir.is_dir() {
            // Every staged failure marks its tenure (P2fix11
            // NEW-67 — a failed-unpublished epoch later reset
            // away preserves its accepted evidence).
            self.failed_generation = self.generation;
            return Err(format!(
                "osslscope: unreadable out-DIR: {}",
                self.out_dir.display()
            ));
        }
        self.read_sidecars();
        // Scan window files (seq order).
        let mut seqs: Vec<u64> = vec![];
        let entries = match std::fs::read_dir(&self.out_dir) {
            Ok(entries) => entries,
            Err(e) => {
                self.failed_generation = self.generation;
                return Err(format!("osslscope: unreadable out-DIR: {e}"));
            }
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(seq) = parse_window_name(&name) {
                seqs.push(seq);
            }
        }
        seqs.sort_unstable();
        // Fresh start below the oldest retained file: pre-retention
        // seqs are UNKNOWN (§6C-1c).
        let from = match self.watermark {
            Some(w) => w.saturating_add(1),
            None => seqs.first().copied().unwrap_or(0),
        };
        // Recovery flags set DURING this scan (P2fix2 item 13): a
        // mid-scan generation reset clears epoch flags — re-union
        // these afterwards so a just-detected retention hole (or
        // pre-retention prefix) is never erased by a later reset in
        // the same build. Only scan-added flags re-union (captured
        // per call-site below — older sticky flags still clear at
        // the epoch boundary, by design).
        let mut scan_added: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        // Scan-added unmeasured ranges (P2fix3 NEW-P2c): the twin
        // of the flag set above — retention holes and
        // folded-but-null windows detected during THIS scan
        // re-union after a mid-scan generation reset (older
        // ranges still clear at the epoch boundary, by design).
        let mut scan_added_ranges: Vec<[u64; 2]> = vec![];
        if self.watermark.is_none()
            && let Some(&oldest) = seqs.first()
            && oldest > 0
        {
            // Per-gap record (P2fix4 NEW-P2c): the flags raised
            // for THIS gap re-union after a mid-scan generation
            // reset — the full post-flag set, never a
            // set-difference (an already-set flag raised again
            // must not disappear).
            self.flag_epoch_unstable();
            scan_added.extend(self.unstable.iter().cloned());
        }
        let mut expect = from;
        // First scan failure (P2fix10 NEW-65): the loop BREAKS on
        // it instead of returning — the re-union below runs on
        // EVERY exit (success AND failure), so a rejected later
        // window never orphans the valid prefix's gap flags +
        // ranges beneath an advanced watermark.
        let mut scan_error: Option<String> = None;
        for &seq in seqs.iter().filter(|s| **s >= from) {
            if seq > expect {
                // Retention gap: best-prefix suffix + flags + ranges.
                // Per-gap record (P2fix4 NEW-P2c — same rule as the
                // prefix gap above: full post-flag set, never a
                // set-difference).
                self.flag_epoch_unstable();
                scan_added.extend(self.unstable.iter().cloned());
                push_range(&mut self.trace_unmeasured, [expect, seq - 1]);
                push_range(&mut scan_added_ranges, [expect, seq - 1]);
            }
            let folded = (|| -> Result<(), String> {
                let path = self.out_dir.join(format!("window-{seq:010}.json"));
                let bytes = std::fs::read(&path)
                    .map_err(|e| format!("osslscope: unreadable window {seq}: {e}"))?;
                let sha = sha256_hex(&bytes);
                let env: serde_json::Value = serde_json::from_slice(&bytes)
                    .map_err(|e| format!("osslscope: corrupt window {seq}: {e}"))?;
                // Envelope/filename sequence binding (P2fix2 item 22): a
                // misnamed file must reject before it folds under the
                // wrong sequence (watermark corruption, never silent).
                match u64_at(&env, "seq") {
                    Some(s) if s == seq => {}
                    Some(s) => {
                        return Err(format!(
                            "osslscope: window file {seq} carries envelope seq {s}"
                        ));
                    }
                    None => {
                        return Err(format!("osslscope: envelope without seq: file {seq}"));
                    }
                }
                // Raw duplicate-key rejection on the envelope bytes
                // (P2fix2 item 13 — whole-envelope strict: a repeated
                // `document` or nested key would conceal the unchecked
                // section under last-wins; subsumes the item-23
                // trace-section check on this path).
                let text = std::str::from_utf8(&bytes)
                    .map_err(|e| format!("osslscope: corrupt window {seq}: {e}"))?;
                crate::schema::check_envelope_raw_duplicates(text)
                    .map_err(|e| format!("osslscope: corrupt window {seq}: {e}"))?;
                self.fold_envelope(&env, &sha, Some(&mut scan_added_ranges))?;
                Ok(())
            })();
            match folded {
                Ok(()) => {
                    expect = seq.saturating_add(1);
                }
                Err(e) => {
                    // The scan broke AT this window (P2fix15
                    // NEW-91 — the outage note's explicit
                    // rejected window, same scan as the tip).
                    self.last_rejected_seq = Some(seq);
                    scan_error = Some(e);
                    break;
                }
            }
        }
        // Re-union scan-added recovery flags (a mid-scan generation
        // reset above may have cleared them — the hole/prefix they
        // describe belongs to this build's adopted state). Runs on
        // EVERY exit (P2fix10 NEW-65 — success AND failure: a
        // failed scan preserves the valid prefix's gap evidence
        // with its advanced watermark instead of orphaning the
        // missing span).
        self.unstable.extend(scan_added);
        // Re-union scan-added unmeasured ranges (same rule — the
        // missing ranges detected during this scan survive the
        // reset with their flags, on success AND failure). A
        // SORTED union (P2fix10 NEW-65): pre-reset ranges merge
        // back over post-reset folded ranges out of order.
        union_ranges(&mut self.trace_unmeasured, scan_added_ranges);
        // Scan-end preview (P2fix11 NEW-67 — both exits): the
        // failed scan's preserved prefix IS the epoch's final
        // until recovery supersedes it.
        self.refresh_epoch_preview();
        if let Some(e) = scan_error {
            self.failed_generation = self.generation;
            return Err(e);
        }
        self.adopt_summary();
        // Post-adoption preview (P2fix11 NEW-67): adoption can
        // flag the epoch (mismatch notes) — the preview tracks
        // it before any later reset captures.
        self.refresh_epoch_preview();
        // Validate the completed snapshot BEFORE committing the
        // checkpoint (P2fix3 NEW-2): a failed build commits
        // nothing (and keeps its sequence + markers for the
        // retry — the checkpoint always matches the last
        // validated snapshot). Staged: return the snapshot
        // WITHOUT writing (`build_service` writes after this
        // returns; the export refresh path commits jointly after
        // admission instead).
        let seq_before = self.snapshot_seq;
        let markers_before = self.pending_markers.clone();
        match self.build() {
            // A successful scan heals the tenure (P2fix11 NEW-67
            // — recovery supersedes the mid-failure mark).
            Ok(snap) => {
                self.failed_generation = None;
                Ok(snap)
            }
            Err(e) => {
                self.snapshot_seq = seq_before;
                self.pending_markers = markers_before;
                self.failed_generation = self.generation;
                Err(e)
            }
        }
    }

    /// One-shot snapshot from a single document (no epoch).
    pub fn oneshot(doc: &serde_json::Value) -> Result<OperatorSnapshot, String> {
        let sig =
            signals_from_doc(doc).ok_or_else(|| "osslscope: unreadable document".to_string())?;
        let bytes = serde_json::to_vec(doc).map_err(|e| e.to_string())?;
        let mut unknown: Vec<UnknownEntry> = vec![];
        let window = read_doc_window(doc);
        let calls_window = sig.lanes.iter().sum();
        let mut counters = sig.counters.clone();
        sort_counters_loss_first(&mut counters);
        let exit_hint = exit_hint_for(&sig);
        // Trace plane: the single document's summary projects
        // directly (one-window fold; first/last seq 0/0).
        let trace_input = sig.trace.as_ref();
        // Latest-wins survives ONLY here (one cumulative snapshot
        // from one verified producer run — DELTA-2); withheld
        // epoch classes (uncertain) null the outcome fold.
        let by_outcome = trace_input.and_then(|ts| {
            ts.class_epoch.as_ref().map(|ce| {
                ClassCounts {
                    success: ce.success,
                    failure: ce.failure,
                    empty: ce.empty,
                    retry: ce.retry,
                    unknown: ce.unknown,
                }
                .by_outcome()
            })
        });
        let trace: Option<TraceBlock> = trace_input.map(|ts| TraceBlock {
            window_seq: ts.window.window_seq,
            mode: ts.mode.clone(),
            paired: ts.window.paired,
            trace_unpaired_entries: ts.window.trace_unpaired_entries,
            trace_unpaired_results: ts.window.trace_unpaired_results,
            trace_depth_exceeded: ts.window.trace_depth_exceeded,
            trace_dropped: ts.window.trace_dropped,
            trace_capped: ts.window.trace_capped,
            trace_nonmonotonic_pairs: ts.window.trace_nonmonotonic_pairs,
            trace_rejected_unknown_api: ts.window.trace_rejected_unknown_api,
            ring_loss: ts.window.ring_loss,
            class_window: ts.window.class_window.as_ref().map(|c| ClassCounts {
                success: c.success,
                failure: c.failure,
                empty: c.empty,
                retry: c.retry,
                unknown: c.unknown,
            }),
            class_epoch: ts.class_epoch.as_ref().map(|c| ClassCounts {
                success: c.success,
                failure: c.failure,
                empty: c.empty,
                retry: c.retry,
                unknown: c.unknown,
            }),
            pairing_uncertain: ts.window.pairing_uncertain,
            pairing_uncertainty: ts.window.pairing_uncertainty.clone(),
            cut_unbound: ts.window.cut_unbound,
            unmeasured_seqs: vec![],
            gaps: ts.window.gaps.clone(),
            gap_overflow: ts.window.gap_overflow,
            exemplars: ts
                .window
                .exemplars
                .iter()
                .map(|e| TraceExemplarShape {
                    dir: e.dir.clone(),
                    key_hash16: e.key_hash16.clone(),
                    api: e.api,
                    age_ns: e.age_ns,
                })
                .collect(),
        });
        let histograms: Option<HistogramsBlock> = trace_input.and_then(|ts| {
            ts.histograms.as_ref().map(|h| HistogramsBlock {
                edges: h.edges.clone(),
                first_seq: 0,
                last_seq: 0,
                unmeasured_seqs: vec![],
                capped_folded: u64::from(ts.window.trace_capped),
                success: dist_from(&h.success),
                failure: dist_from(&h.failure),
                empty: dist_from(&h.empty),
                retry: dist_from(&h.retry),
                unknown: dist_from(&h.unknown),
                by_api: ts.by_api.as_ref().map(|m| {
                    m.iter()
                        .map(|(id, e)| {
                            (
                                id.clone(),
                                ByApiEntry {
                                    success: dist_from(&e.success),
                                    failure: dist_from(&e.failure),
                                    empty: dist_from(&e.empty),
                                    retry: dist_from(&e.retry),
                                    unknown: dist_from(&e.unknown),
                                },
                            )
                        })
                        .collect()
                }),
                by_api_availability: ts.by_api_availability.clone(),
            })
        });
        let mut snap = OperatorSnapshot {
            schema: SCHEMA.to_string(),
            snapshot_seq: 0,
            produced_wall_ns: wall_ns(),
            produced_monotonic_ns: monotonic_ns(),
            source: Source {
                mode: "oneshot".to_string(),
                generation: None,
                run_id: None,
                window_seq: None,
                window_sha256: Some(sha256_hex(&bytes)),
            },
            window: window.clone(),
            completeness: CompletenessBlock {
                state: Some(sig.state.clone()),
                reasons: sig.reasons.clone(),
                epoch_partial_by_class: partial_for_window(&sig.state, &sig.reasons),
            },
            policy: PolicyBlock {
                active: None,
                outcome: Some(sig.outcome.clone()),
            },
            exit_hint,
            counts: CountsBlock {
                calls_total: calls_window,
                calls_window: Some(calls_window),
                lanes: Lanes {
                    legacy_exclusive: sig.lanes[0],
                    non_legacy_exclusive: sig.lanes[1],
                    shared_ambiguous: sig.lanes[2],
                    unfenced_tails: sig.lanes[3],
                },
                lanes_window: Some(Lanes {
                    legacy_exclusive: sig.lanes[0],
                    non_legacy_exclusive: sig.lanes[1],
                    shared_ambiguous: sig.lanes[2],
                    unfenced_tails: sig.lanes[3],
                }),
                site_rows: Some(sig.site_rows),
                by_outcome,
            },
            members: MembersBlock {
                observed: None,
                retired_in_window: None,
                retired_epoch: 0,
                deferred_depth: None,
            },
            loss: LossBlock {
                session: None,
                epoch_by_cause: EpochByCause::default(),
                counters,
            },
            stream: None,
            trace,
            histograms,
            health: HealthBlock {
                snapshot_age_ns: window
                    .as_ref()
                    .map(|w| monotonic_ns().saturating_sub(w.effective_end_ns)),
                // A finished document is complete truth, never stale.
                stale: false,
            },
            presenter: PresenterStats {
                epoch_changes: 0,
                series_overflow: 0,
            },
            unknown: vec![],
            // No fold occurred (single document — current state
            // shows directly, no markers).
            markers: vec![],
        };
        for path in [
            "source.generation",
            "source.run_id",
            "source.window_seq",
            "members.observed",
            "members.retired_in_window",
            "members.deferred_depth",
            "loss.session",
        ] {
            unknown.push(UnknownEntry {
                path: path.to_string(),
                reason: "oneshot_no_sequence".to_string(),
                note: None,
            });
        }
        // `policy.active` is null in oneshot (no envelope/policy
        // sidecar identity): the observe-only reason.
        unknown.push(UnknownEntry {
            path: "policy.active".to_string(),
            reason: "observe_only".to_string(),
            note: None,
        });
        unknown.push(UnknownEntry {
            path: "stream".to_string(),
            reason: "stream_unconfigured".to_string(),
            note: None,
        });
        if snap.counts.by_outcome.is_none() {
            unknown.push(UnknownEntry {
                path: "counts.by_outcome".to_string(),
                reason: "trace_disabled".to_string(),
                note: None,
            });
        }
        if snap.trace.is_none() {
            unknown.push(UnknownEntry {
                path: "trace".to_string(),
                reason: "trace_disabled".to_string(),
                note: None,
            });
        }
        // Withheld classes inside a present trace block (pairing
        // uncertainty, item 3 — the `trace_disabled` reason covers
        // the trace plane's unavailable interpreted series:
        // disabled, withheld-pending-contract, withheld-uncertain;
        // the block's `pairing_uncertain` flag says which).
        if let Some(t) = snap.trace.as_ref() {
            if t.class_window.is_none() {
                unknown.push(UnknownEntry {
                    path: "trace.class_window".to_string(),
                    reason: "trace_disabled".to_string(),
                    note: None,
                });
            }
            if t.class_epoch.is_none() {
                unknown.push(UnknownEntry {
                    path: "trace.class_epoch".to_string(),
                    reason: "trace_disabled".to_string(),
                    note: None,
                });
            }
        }
        if snap.histograms.is_none() {
            unknown.push(UnknownEntry {
                path: "histograms".to_string(),
                reason: "trace_disabled".to_string(),
                note: None,
            });
        }
        push_by_api_unknowns(snap.histograms.as_ref(), &mut unknown);
        if snap.window.is_none() {
            unknown.push(UnknownEntry {
                path: "window".to_string(),
                reason: "not_yet_observed".to_string(),
                note: None,
            });
        }
        if snap.health.snapshot_age_ns.is_none() {
            unknown.push(UnknownEntry {
                path: "health.snapshot_age_ns".to_string(),
                reason: "not_yet_observed".to_string(),
                note: None,
            });
        }
        if snap.exit_hint.is_none() {
            unknown.push(UnknownEntry {
                path: "exit_hint".to_string(),
                reason: "gap_covered".to_string(),
                note: None,
            });
        }
        snap.unknown = unknown;
        snap.check_unknown_invariant()?;
        Ok(snap)
    }
}

impl Presenter {
    /// Fold one window envelope (seq order, §6C-1 rules).
    /// Validates the envelope (fields + document signals) BEFORE
    /// mutating any epoch state (P2fix2 item 22): a rejected
    /// envelope — newer generation or not — never resets the live
    /// epoch, seals runs, or advances the watermark first.
    /// `scan_ranges` (P2fix3 NEW-P2c) collects this fold's
    /// unmeasured-range additions for the scan driver (which
    /// re-unions them after a mid-scan generation reset); `None`
    /// outside a scan.
    fn fold_envelope(
        &mut self,
        env: &serde_json::Value,
        sha: &str,
        scan_ranges: Option<&mut Vec<[u64; 2]>>,
    ) -> Result<(), String> {
        // --- Validate everything fallible first (no mutation). ---
        let seq = u64_at(env, "seq").ok_or_else(|| "envelope without seq".to_string())?;
        let generation =
            u64_at(env, "generation").ok_or_else(|| "envelope without generation".to_string())?;
        // Exact window source identity (P2fix9 NEW-57): the
        // envelope must BE a service window — a wrong-schema
        // artifact never drives the fold (checked BEFORE any
        // mutation, like the summary gate).
        if str_at(env, "schema") != Some(crate::service::envelope::SCHEMA_WINDOW) {
            return Err("envelope without service-window-v1 schema".to_string());
        }
        let run_value =
            obj_at(env, "run_id").ok_or_else(|| "envelope without run_id".to_string())?;
        let run_id = read_run_id(run_value).ok_or_else(|| "bad run_id".to_string())?;
        // Full run identity (P2fix3 NEW-P2b — pid + starttime +
        // FULL boot_id: truncated tags merge distinct runs that
        // share a boot prefix and lose a gross).
        let run_tag = format!("{}-{}-{}", run_id.pid, run_id.starttime, run_id.boot_id);
        let span = obj_at(env, "window").ok_or_else(|| "envelope without window".to_string())?;
        let window = WindowBlock {
            requested_start_ns: u64_at(span, "requested_start_ns").unwrap_or(0),
            requested_end_ns: u64_at(span, "requested_end_ns").unwrap_or(0),
            effective_start_ns: u64_at(span, "effective_start_ns").unwrap_or(0),
            effective_end_ns: u64_at(span, "effective_end_ns").unwrap_or(0),
            signal_cut: bool_at(span, "signal_cut").unwrap_or(false),
            accum_cut: bool_at(span, "accum_cut").unwrap_or(false),
        };
        let doc = obj_at(env, "document").ok_or_else(|| "envelope without document".to_string())?;
        let sig = signals_from_producer(doc).ok_or_else(|| "unreadable document".to_string())?;
        // Persisted minor (P2fix8 NEW-51): derived here (before
        // ANY mutation) from the producer CANONICAL
        // discriminator — a foreign alias rejects the window
        // above (via `sig`), never persists a bypassed minor.
        let schema_minor = crate::provider_observation::trace::canonical_minor(
            doc,
            crate::provider_observation::trace::DocShape::Producer,
        )
        .map_err(|e| format!("discriminator: {e}"))?;
        // Session loss + deferred depth validate here too (typed +
        // bounded End tallies — a malformed tally rejects before
        // any mutation, like the document above).
        let (session_loss, deferred_depth) = read_end_tallies(env)?;
        // Present window gross validates here too (P2fix8 NEW-53
        // — strict shape + conservation BEFORE the window
        // mutates fold state; a malformed gross rejects the
        // whole envelope, like the tallies). Only ABSENCE reads
        // the documented legacy zeros (P2fix9 NEW-57 — a
        // SUPPLIED non-object gross (null/scalar/array) is
        // present-but-invalid and rejects, never zero-folds).
        let validated_close: Option<StreamDropsShape> = match env.get("stream_gross_close") {
            None => None,
            Some(g) if g.is_object() => {
                let shape = read_stream_drops_strict(g)
                    .ok_or_else(|| "stream_gross_close: malformed gross".to_string())?;
                if !stream_drops_conserves(&shape) {
                    return Err(
                        "stream_gross_close: gross totals must equal per-reason sums".to_string(),
                    );
                }
                Some(shape)
            }
            Some(_) => {
                return Err("stream_gross_close: present gross must be an object".to_string());
            }
        };
        // Supplied configuration marker (P2fix9 NEW-57): a
        // present marker must be a bool — validated BEFORE
        // mutation (previously a non-bool marker silently read
        // as false). Absent stays false (old producers).
        if let Some(marker) = env.get("stream_configured") {
            if !marker.is_boolean() {
                return Err("stream_configured: present marker must be a bool".to_string());
            }
        }
        let configured_marker = bool_at(env, "stream_configured").unwrap_or(false);
        let policy_active = obj_at(env, "policy").and_then(read_policy_active);
        // --- Validated: mutate. ---
        if self.generation != Some(generation) {
            if self.generation.is_some() {
                self.epoch_changes = self.epoch_changes.saturating_add(1);
            }
            // Preserve a failed-unpublished epoch across the
            // reset (P2fix11 NEW-67): when the outgoing epoch
            // accepted windows, suffered a scan/build failure,
            // and never published, its prefix counts +
            // uncertainty survive as the previous-epoch record
            // (captured from the preview — the outgoing epoch's
            // finals, never the current scan's own gap
            // detections). A published outgoing epoch with no
            // post-publication advance or failure clears any
            // older record (last-good covers it — P2fix12
            // NEW-71 keeps the clear there, and preserves the
            // FINAL prefix + uncertainty otherwise). A clean
            // UNPUBLISHED outgoing epoch KEEPS any existing
            // record (P2fix13 NEW-77): in a coalesced recovery
            // scan another reset may have just preserved the
            // immediately preceding accepted epoch (gen-1
            // prefix-failed, then gen 2 folds clean and gen 3
            // resets it in the same scan) — clearing there
            // discards the accepted predecessor and the
            // terminal falls back to a stale frame. The record
            // is only ever replaced by a newer preserved epoch
            // or cleared by a clean PUBLISHED tenure (whose
            // last-good is exact and newer).
            if let Some(old) = self.generation {
                if self.published_generation == Some(old) {
                    // Published tenure (P2fix12 NEW-71):
                    // last-good covers the PUBLISHED tip — but
                    // windows accepted AFTER publication (or
                    // uncertainty accrued since a rejected tail)
                    // are NOT in last-good, so a reset that
                    // cleared on the generation match would drop
                    // the final accepted prefix + uncertainty
                    // (and the terminal would show stale
                    // last-good counts). Preserve the final
                    // prefix when it advanced past the
                    // published tip or the tenure failed since;
                    // only a tenure with no post-publication
                    // advance AND no failure clears (last-good
                    // is exact there). With an advance/failure
                    // but no usable preview, keep any existing
                    // record (P2fix13 NEW-77 — never discard the
                    // accepted predecessor on missing evidence).
                    let advanced = matches!(
                        (&self.epoch_preview, self.published_tip),
                        (Some(p), Some(t)) if p.generation == old && p.window_seq > t
                    );
                    let failed = self.failed_generation == Some(old);
                    if (advanced || failed)
                        && let Some(preview) = self.epoch_preview.clone()
                        && preview.generation == old
                    {
                        self.previous_epoch = Some(preview);
                    } else if !advanced && !failed {
                        self.previous_epoch = None;
                    }
                } else if self.restored_generation == Some(old)
                    && let Some(preview) = self.epoch_preview.clone()
                    && preview.generation == old
                {
                    // Restored tenure left on its first scan
                    // (P2fix14 NEW-83): the outgoing epoch is
                    // the tenure open at restore — preserve
                    // its finals (the generation ACTUALLY
                    // being left), never the stale retained
                    // record (a NEW-77 keep here would present
                    // a pre-restart record as the predecessor
                    // of a post-restart transition). The
                    // published tenure above keeps precedence
                    // (a published-then-continued tenure
                    // follows NEW-71); same-generation folds
                    // keep the tenure live (no reset);
                    // `reset_epoch` consumes the marker.
                    self.previous_epoch = Some(preview);
                } else if self.epoch_folded
                    && self.failed_generation == Some(old)
                    && let Some(preview) = self.epoch_preview.clone()
                    && preview.generation == old
                {
                    self.previous_epoch = Some(preview);
                }
                // Else (clean unpublished outgoing): keep any
                // existing record (P2fix13 NEW-77).
            }
            self.reset_epoch(generation);
        }
        // Seal-on-transition (§6C-1d): first sighting of next-run
        // data freezes the departed run's last close GROSS.
        if self.current_run.as_deref() != Some(run_tag.as_str()) {
            if let Some(prev) = self.current_run.clone() {
                self.seal_from_close(&prev);
            }
            self.current_run = Some(run_tag.clone());
            self.current_gross = StreamDropsShape {
                records: 0,
                bytes: 0,
                queue_full: ReasonTotals::default(),
                epipe: ReasonTotals::default(),
                stream_abandoned: ReasonTotals::default(),
            };
            // The observed close vector restarts unseeded (P2fix5
            // NEW-30 — summary maxima seed the publish max below,
            // never this vector), and the retained current-run
            // summary restarts empty (P2fix6 NEW-35 — the
            // departed run's seal consumed its own above).
            self.current_close = StreamDropsShape::default();
            self.current_summary = None;
            // Unseal-on-transition (P2fix4 NEW-15): a summary
            // adopted BEFORE this run's windows moves from
            // `sealed` into the adopted slot (one authoritative
            // gross per run — the sealed entry must not survive
            // beside the live close) and seeds the running max.
            self.adopted_summary = self
                .sealed
                .remove(run_tag.as_str())
                .map(|s| StreamDropsShape {
                    records: s.records,
                    bytes: s.bytes,
                    queue_full: s.queue_full,
                    epipe: s.epipe,
                    stream_abandoned: s.stream_abandoned,
                });
            if let Some(a) = self.adopted_summary {
                self.current_gross.records = self.current_gross.records.max(a.records);
                self.current_gross.bytes = self.current_gross.bytes.max(a.bytes);
                self.current_gross.queue_full.records = self
                    .current_gross
                    .queue_full
                    .records
                    .max(a.queue_full.records);
                self.current_gross.queue_full.bytes =
                    self.current_gross.queue_full.bytes.max(a.queue_full.bytes);
                self.current_gross.epipe.records =
                    self.current_gross.epipe.records.max(a.epipe.records);
                self.current_gross.epipe.bytes = self.current_gross.epipe.bytes.max(a.epipe.bytes);
                self.current_gross.stream_abandoned.records = self
                    .current_gross
                    .stream_abandoned
                    .records
                    .max(a.stream_abandoned.records);
                self.current_gross.stream_abandoned.bytes = self
                    .current_gross
                    .stream_abandoned
                    .bytes
                    .max(a.stream_abandoned.bytes);
            }
        }
        // Epoch folds (deltas tile exactly, §6C-1).
        let calls_window: u64 = sig.lanes.iter().sum();
        self.calls_total = self.calls_total.saturating_add(calls_window);
        for (i, lane) in sig.lanes.iter().enumerate() {
            self.lanes[i] = self.lanes[i].saturating_add(*lane);
        }
        fold_partial(&mut self.epoch_partial, &sig.state, &sig.reasons);
        // Members.
        let mut observed = 0u64;
        let mut retired = 0u64;
        if let Some(members) = arr_at(env, "members") {
            for m in members {
                if bool_at(m, "retired").unwrap_or(false) {
                    retired = retired.saturating_add(1);
                } else {
                    observed = observed.saturating_add(1);
                }
            }
        }
        self.retired_epoch = self.retired_epoch.saturating_add(retired);
        // Canonical loss fold (§6C-1b): window views + seal ledgers,
        // exactly-once per interval.
        self.fold_member_views(env, &run_tag);
        self.fold_seal_ledgers(env, &run_tag);
        // Stream close GROSS (additive † field; zeros when unset
        // — the documented absent legacy field). The present
        // value was validated up front (P2fix8 NEW-53 — no
        // zero-defaulting reader on this path anymore).
        let close = validated_close.unwrap_or(StreamDropsShape {
            records: 0,
            bytes: 0,
            queue_full: ReasonTotals::default(),
            epipe: ReasonTotals::default(),
            stream_abandoned: ReasonTotals::default(),
        });
        let mut configured = false;
        // Configured-ness comes ONLY from the explicit marker (a
        // zero-valued additive field is unconfigured, not
        // configured-quiet) or from observed nonzero GROSS (old
        // producers without the marker).
        if configured_marker {
            configured = true;
        }
        if close.records > 0 || close.bytes > 0 {
            configured = true;
        }
        // Running max (GROSS never struck; a decrease on ANY
        // of the 8 record/byte components flags — P2fix3 NEW-P2b:
        // totals can hold while a reason shifts, which is corrupt
        // per the frozen monotone rule).
        let decreased = close.records < self.current_gross.records
            || close.bytes < self.current_gross.bytes
            || close.queue_full.records < self.current_gross.queue_full.records
            || close.queue_full.bytes < self.current_gross.queue_full.bytes
            || close.epipe.records < self.current_gross.epipe.records
            || close.epipe.bytes < self.current_gross.epipe.bytes
            || close.stream_abandoned.records < self.current_gross.stream_abandoned.records
            || close.stream_abandoned.bytes < self.current_gross.stream_abandoned.bytes;
        self.current_gross.records = self.current_gross.records.max(close.records);
        self.current_gross.bytes = self.current_gross.bytes.max(close.bytes);
        for (cur, new) in [
            (&mut self.current_gross.queue_full, close.queue_full),
            (&mut self.current_gross.epipe, close.epipe),
            (
                &mut self.current_gross.stream_abandoned,
                close.stream_abandoned,
            ),
        ] {
            cur.records = cur.records.max(new.records);
            cur.bytes = cur.bytes.max(new.bytes);
        }
        // Observed close vector (P2fix5 NEW-30): the same running
        // max over folded closes ONLY (never seeded — provenance
        // needs the true observed-vs-summary pair at seal).
        self.current_close.records = self.current_close.records.max(close.records);
        self.current_close.bytes = self.current_close.bytes.max(close.bytes);
        for (cur, new) in [
            (&mut self.current_close.queue_full, close.queue_full),
            (&mut self.current_close.epipe, close.epipe),
            (
                &mut self.current_close.stream_abandoned,
                close.stream_abandoned,
            ),
        ] {
            cur.records = cur.records.max(new.records);
            cur.bytes = cur.bytes.max(new.bytes);
        }
        if decreased {
            self.unstable.insert("stream.drops".to_string());
        }
        // Adopted-vs-close compare (P2fix4 NEW-15): the folded
        // close disagrees with the early-adopted summary on ANY
        // of the 8 components → mismatch (the max already won
        // above; exact agreement stays clean per the frozen
        // match-clean rule).
        if self.adopted_summary.is_some_and(|a| a != close) {
            self.stream_mismatch_note = true;
            self.unstable.insert("stream.drops".to_string());
        }
        if configured {
            self.stream_seen_configured = true;
        }
        // Alert markers for THIS window (item 25 — every folded
        // window records, not just the latest). Session loss +
        // policy identity validated up front (see above).
        self.pending_markers
            .extend(window_markers(seq, &sig, &window, session_loss.as_ref()));
        // Trace plane (DELTA-2 rescope): service windows carry
        // run-cumulative projections, not the frozen §6D-3 per-
        // window additive fields — latest-wins across a service
        // epoch would misreport on any producer restart, so epoch
        // trace series (class_epoch, histograms, by_outcome) are
        // WITHHELD on the service path until the per-window
        // producer contract exists. The per-window raw trace block
        // still projects from the latest window (build); only the
        // epoch interpreted folds are dark. Folded-but-null windows
        // extend the trace unmeasured span (retention/coverage
        // evidence for the raw plane).
        if sig.trace.is_none() {
            push_range(&mut self.trace_unmeasured, [seq, seq]);
            if let Some(sink) = scan_ranges {
                push_range(sink, [seq, seq]);
            }
        }
        // Source version + activity rows (P2fix3 GATE29 — the
        // checkpoint carries what restore re-validates: the minor
        // for the section/version trigger, the rows for coverage
        // reconciliation). `schema_minor` was derived up front
        // from the producer canonical discriminator (P2fix8
        // NEW-51).
        let api_activity = doc
            .get("api_activity")
            .and_then(|a| a.as_array())
            .cloned()
            .unwrap_or_default();
        self.latest = Some(LatestWindow {
            seq,
            sha: sha.to_string(),
            generation,
            run_id,
            window,
            signals: sig,
            members_observed: observed,
            members_retired: retired,
            deferred_depth,
            session_loss,
            policy_active,
            schema_minor,
            api_activity,
        });
        self.watermark = Some(seq);
        // The tenure folded (P2fix11 NEW-67): mark + refresh the
        // preview (the per-fold refresh keeps mid-scan
        // multi-generation resets exact).
        self.epoch_folded = true;
        self.refresh_epoch_preview();
        Ok(())
    }

    /// Reset epoch accumulators (§6C-3); presenter-run state survives.
    /// Recovery flags (torn checkpoint, pre-retention prefix) survive
    /// the FIRST adoption (they describe the adopted epoch's own
    /// prefix — item 20); later adoptions start clean. Pending
    /// markers reset with the epoch (P2fix2 item 13 — markers bind
    /// to their generation like every other epoch accumulator;
    /// pending markers never cross generations).
    fn reset_epoch(&mut self, generation: u64) {
        let first = self.generation.is_none();
        let keep = if first {
            std::mem::take(&mut self.unstable)
        } else {
            std::collections::BTreeSet::new()
        };
        self.pending_markers.clear();
        self.generation = Some(generation);
        self.calls_total = 0;
        self.lanes = [0; 4];
        self.retired_epoch = 0;
        self.epoch_by_cause = [0; 12];
        self.epoch_partial = [0; 10];
        self.trace_unmeasured = vec![];
        self.counted = BTreeMap::new();
        self.sealed = BTreeMap::new();
        self.current_run = None;
        self.current_gross = StreamDropsShape {
            records: 0,
            bytes: 0,
            queue_full: ReasonTotals::default(),
            epipe: ReasonTotals::default(),
            stream_abandoned: ReasonTotals::default(),
        };
        self.adopted_summary = None;
        self.current_close = StreamDropsShape::default();
        self.current_summary = None;
        self.stream_seen_configured = false;
        self.stream_sealed_note = false;
        self.stream_mismatch_note = false;
        self.unstable = keep;
        // The new tenure starts clean (P2fix11 NEW-67): no folds
        // yet, no failure yet. (The preview still describes the
        // outgoing epoch until the first fold refreshes it —
        // exactly what the reset capture above reads.) The
        // restored-tenure marker is consumed (P2fix14 NEW-83 —
        // the reset left it).
        self.epoch_folded = false;
        self.failed_generation = None;
        self.restored_generation = None;
    }

    /// Flag every epoch accumulator `unstable_snapshot` (§6C-1c).
    fn flag_epoch_unstable(&mut self) {
        for path in [
            "counts.calls_total",
            "counts.lanes",
            "members.retired_epoch",
            "counts.by_outcome",
            "loss.epoch_by_cause",
            "completeness.epoch_partial_by_class",
            "histograms",
            "stream.drops",
        ] {
            self.unstable.insert(path.to_string());
        }
    }

    /// Fold `members[].loss.lost_windows` set-difference views (§6C-1b).
    fn fold_member_views(&mut self, env: &serde_json::Value, run_tag: &str) {
        let Some(members) = arr_at(env, "members") else {
            return;
        };
        for m in members {
            let (Some(pid), Some(st), Some(seg)) = (
                u64_at(m, "pid"),
                u64_at(m, "starttime"),
                u64_at(m, "segment"),
            ) else {
                continue;
            };
            let key = format!("{run_tag}:{pid}:{st}:{seg}");
            let Some(loss) = obj_at(m, "loss") else {
                continue;
            };
            let Some(views) = arr_at(loss, "lost_windows") else {
                continue;
            };
            for w in views {
                let (Some(s), Some(e)) = (u64_at(w, "start_tick"), u64_at(w, "end_tick")) else {
                    continue;
                };
                let cause = str_at(w, "cause").unwrap_or_default();
                self.count_interval(&key, [s, e], cause);
            }
        }
    }

    /// Fold `ProcessObservation.loss` seal ledgers (§6C-1b) from
    /// the REAL flattened `kind` records (internally tagged —
    /// `{"kind": "process_observation", ...}` with the actual
    /// `segment` on the record, never a nested `record.*` shape).
    fn fold_seal_ledgers(&mut self, env: &serde_json::Value, run_tag: &str) {
        let Some(records) = arr_at(env, "crypto_watch") else {
            return;
        };
        for rec in records {
            if str_at(rec, "kind") != Some("process_observation") {
                continue;
            }
            let (Some(pid), Some(st), Some(seg)) = (
                obj_at(rec, "incarnation").and_then(|i| u64_at(i, "pid")),
                obj_at(rec, "incarnation").and_then(|i| u64_at(i, "starttime")),
                u64_at(rec, "segment"),
            ) else {
                // Unkeyable seal (skip + flag — never miscount).
                self.unstable.insert("loss.epoch_by_cause".to_string());
                continue;
            };
            let key = format!("{run_tag}:{pid}:{st}:{seg}");
            let Some(loss) = obj_at(rec, "loss") else {
                continue;
            };
            let Some(windows) = arr_at(loss, "lost_windows") else {
                continue;
            };
            for w in windows {
                let (Some(s), Some(e)) = (u64_at(w, "start_tick"), u64_at(w, "end_tick")) else {
                    continue;
                };
                let cause = str_at(w, "cause").unwrap_or_default();
                self.count_interval(&key, [s, e], cause);
            }
        }
    }

    /// Count one interval's set-difference-new clips (§6C-1b).
    fn count_interval(&mut self, key: &str, range: [u64; 2], cause: &str) {
        if range[1] <= range[0] {
            return;
        }
        let Some(idx) = crate::presentation::labels::loss_cause_index(cause) else {
            // Unknown cause word (corrupt/future producer): skip +
            // flag — never invent a bucket.
            self.unstable.insert("loss.epoch_by_cause".to_string());
            return;
        };
        let entry = self.counted.entry(key.to_string()).or_default();
        // Subtract already-counted coverage; count new clips.
        let mut fresh: Vec<[u64; 2]> = vec![range];
        for counted in entry.iter() {
            let mut next = Vec::with_capacity(fresh.len() + 1);
            for [s, e] in fresh {
                if e <= counted[0] || s >= counted[1] {
                    next.push([s, e]);
                } else {
                    if s < counted[0] {
                        next.push([s, counted[0]]);
                    }
                    if e > counted[1] {
                        next.push([counted[1], e]);
                    }
                }
            }
            fresh = next;
        }
        for clip in &fresh {
            if clip[1] > clip[0] {
                self.epoch_by_cause[idx] = self.epoch_by_cause[idx].saturating_add(1);
            }
        }
        // Merge the input range into counted state.
        entry.push(range);
        entry.sort_unstable();
        let mut merged: Vec<[u64; 2]> = Vec::with_capacity(entry.len());
        for [s, e] in entry.iter() {
            if let Some(last) = merged.last_mut() {
                if *s <= last[1] {
                    last[1] = last[1].max(*e);
                    continue;
                }
            }
            merged.push([*s, *e]);
        }
        *entry = merged;
    }

    /// Seal-on-transition (§6C-1d): freeze the departed run's last
    /// close GROSS into the sealed sum. When the run already
    /// sealed from its summary (summary-before-window arrival),
    /// compare-then-mark instead of dropping the close gross
    /// (P2fix3 NEW-P2b): exactly one gross survives — equal
    /// proves idempotent, above merges up, below keeps the
    /// sealed high (epoch counters never decrease) — and any
    /// difference flags `summary_mismatch` with provenance.
    /// (P2fix4 NEW-15: the early-adopted summary unseals at
    /// transition, so the live close reconciles against the
    /// adopted slot below; the sealed-entry arm survives for the
    /// summary-after-seal arrival order.)
    /// Seals from the OBSERVED close vector (P2fix5 NEW-30 — the
    /// publish running max may carry seeded summary maxima, so
    /// provenance derives from the true observed-vs-summary pair
    /// instead; sealed values are per-component maxima either
    /// way).
    fn seal_from_close(&mut self, run_tag: &str) {
        let mut g = self.current_close;
        // Adopted reconcile (P2fix4 NEW-15, P2fix6 NEW-35): the
        // early-adopted summary (pre-window arrival) AND every
        // current-run summary (retained separately) rejoin their
        // run's gross here — max wins per component (any
        // close/summary disagreement already latched
        // `summary_mismatch` at fold/adopt time; exact agreement
        // seals clean with the summary's provenance — no
        // sealed-from-close note, a summary exists). Both slots
        // drain (the seal consumes this run's summaries).
        let summary = match (self.adopted_summary.take(), self.current_summary.take()) {
            (None, None) => None,
            (a, None) => a,
            (None, b) => b,
            (Some(a), Some(b)) => Some(max_stream_drops(a, b)),
        };
        if let Some(a) = summary {
            let close_wins = g.records >= a.records
                && g.bytes >= a.bytes
                && g.queue_full.records >= a.queue_full.records
                && g.queue_full.bytes >= a.queue_full.bytes
                && g.epipe.records >= a.epipe.records
                && g.epipe.bytes >= a.epipe.bytes
                && g.stream_abandoned.records >= a.stream_abandoned.records
                && g.stream_abandoned.bytes >= a.stream_abandoned.bytes;
            let summary_wins = a.records >= g.records
                && a.bytes >= g.bytes
                && a.queue_full.records >= g.queue_full.records
                && a.queue_full.bytes >= g.queue_full.bytes
                && a.epipe.records >= g.epipe.records
                && a.epipe.bytes >= g.epipe.bytes
                && a.stream_abandoned.records >= g.stream_abandoned.records
                && a.stream_abandoned.bytes >= g.stream_abandoned.bytes;
            g.records = g.records.max(a.records);
            g.bytes = g.bytes.max(a.bytes);
            g.queue_full.records = g.queue_full.records.max(a.queue_full.records);
            g.queue_full.bytes = g.queue_full.bytes.max(a.queue_full.bytes);
            g.epipe.records = g.epipe.records.max(a.epipe.records);
            g.epipe.bytes = g.epipe.bytes.max(a.epipe.bytes);
            g.stream_abandoned.records = g.stream_abandoned.records.max(a.stream_abandoned.records);
            g.stream_abandoned.bytes = g.stream_abandoned.bytes.max(a.stream_abandoned.bytes);
            let source = if close_wins && summary_wins {
                "summary"
            } else if close_wins {
                "close"
            } else if summary_wins {
                "summary"
            } else {
                "mixed"
            };
            self.sealed.insert(
                run_tag.to_string(),
                SealedGross {
                    records: g.records,
                    bytes: g.bytes,
                    queue_full: g.queue_full,
                    epipe: g.epipe,
                    stream_abandoned: g.stream_abandoned,
                    source: source.to_string(),
                    tail_note: None,
                    idempotent: false,
                },
            );
            return;
        }
        if let Some(s) = self.sealed.get_mut(run_tag) {
            let same = s.records == g.records
                && s.bytes == g.bytes
                && s.queue_full == g.queue_full
                && s.epipe == g.epipe
                && s.stream_abandoned == g.stream_abandoned;
            if same {
                s.idempotent = true;
                return;
            }
            s.records = s.records.max(g.records);
            s.bytes = s.bytes.max(g.bytes);
            s.queue_full.records = s.queue_full.records.max(g.queue_full.records);
            s.queue_full.bytes = s.queue_full.bytes.max(g.queue_full.bytes);
            s.epipe.records = s.epipe.records.max(g.epipe.records);
            s.epipe.bytes = s.epipe.bytes.max(g.epipe.bytes);
            s.stream_abandoned.records = s.stream_abandoned.records.max(g.stream_abandoned.records);
            s.stream_abandoned.bytes = s.stream_abandoned.bytes.max(g.stream_abandoned.bytes);
            self.stream_mismatch_note = true;
            self.unstable.insert("stream.drops".to_string());
            return;
        }
        self.sealed.insert(
            run_tag.to_string(),
            SealedGross {
                records: g.records,
                bytes: g.bytes,
                queue_full: g.queue_full,
                epipe: g.epipe,
                stream_abandoned: g.stream_abandoned,
                source: "close".to_string(),
                tail_note: Some(NOTE_SEALED_FROM_CLOSE.to_string()),
                idempotent: false,
            },
        );
        self.stream_sealed_note = true;
        self.unstable.insert("stream.drops".to_string());
    }

    /// Checkpoint body (canonical JSON without the hash).
    fn checkpoint_body(&self) -> serde_json::Value {
        let mut body = serde_json::json!({
            "schema": CHECKPOINT_SCHEMA,
            "out_dir": self.out_dir.to_string_lossy(),
            "owner": {"command": self.command, "pid": std::process::id(), "started_wall_ns": wall_ns()},
            "generation": self.generation,
            "watermark_seq": self.watermark,
            "checkpoint_seq": self.checkpoint_seq,
            "snapshot_seq": self.snapshot_seq,
            "accumulators": {
                "calls_total": self.calls_total,
                "lanes": self.lanes,
                "retired_epoch": self.retired_epoch,
                "epoch_by_cause": self.epoch_by_cause,
                "epoch_partial": self.epoch_partial,
                "trace_unmeasured": self.trace_unmeasured,
                "epoch_changes": self.epoch_changes,
                "series_overflow": self.series_overflow,
                "counted": self.counted,
                "sealed": self.sealed,
                "current_run": self.current_run,
                "current_gross": {
                    "records": self.current_gross.records,
                    "bytes": self.current_gross.bytes,
                    "queue_full": self.current_gross.queue_full,
                    "epipe": self.current_gross.epipe,
                    "stream_abandoned": self.current_gross.stream_abandoned,
                },
                "current_close": {
                    "records": self.current_close.records,
                    "bytes": self.current_close.bytes,
                    "queue_full": self.current_close.queue_full,
                    "epipe": self.current_close.epipe,
                    "stream_abandoned": self.current_close.stream_abandoned,
                },
                "adopted_summary": self.adopted_summary,
                "current_summary": self.current_summary,
                "stream_seen_configured": self.stream_seen_configured,
                "stream_sealed_note": self.stream_sealed_note,
                "stream_mismatch_note": self.stream_mismatch_note,
                "unstable": self.unstable.iter().collect::<Vec<_>>(),
                "latest": self.latest,
                "admission": self.admission,
                "export_starts": self.export_starts.map(|(e, r)| serde_json::json!([e, r])),
            },
        });
        // Preserved failed-unpublished epoch (P2fix11 NEW-67):
        // written ONLY when one exists (absent otherwise —
        // checkpoints without preservation stay byte-identical
        // to before; absent restores to None).
        if let Some(prev) = &self.previous_epoch {
            if let Some(acc) = body.get_mut("accumulators").and_then(|a| a.as_object_mut()) {
                acc.insert(
                    "previous_epoch".to_string(),
                    serde_json::to_value(prev).unwrap_or(serde_json::Value::Null),
                );
            }
        }
        body
    }

    /// Finalize the checkpoint bytes (P2fix14 NEW-82): stamp
    /// the CURRENT sequences, serialize bare, attach the
    /// sha256, serialize final — the EXACT bytes the commit
    /// would stage. The caller increments `checkpoint_seq`
    /// first (so sizing probes set the sequence directly and
    /// observe byte-identical output). Pure (no envelope
    /// check — the commit path checks via
    /// `checkpoint_bytes_checked` below).
    fn checkpoint_bytes_raw(&self) -> std::io::Result<Vec<u8>> {
        let mut body = self.checkpoint_body();
        // Refresh the sequence fields (the caller bumped
        // `checkpoint_seq` already).
        if let Some(obj) = body.as_object_mut() {
            obj.insert(
                "checkpoint_seq".to_string(),
                serde_json::json!(self.checkpoint_seq),
            );
            obj.insert(
                "snapshot_seq".to_string(),
                serde_json::json!(self.snapshot_seq),
            );
        }
        let bytes = serde_json::to_vec(&body)?;
        let hash = sha256_hex(&bytes);
        if let Some(obj) = body.as_object_mut() {
            obj.insert("sha256".to_string(), serde_json::json!(hash));
        }
        serde_json::to_vec(&body).map_err(std::io::Error::from)
    }

    /// Finalize + enforce the writer envelope (P2fix14 NEW-82):
    /// the SAME 64 MiB bound the intake enforces (`==`
    /// commits and reopens, `>` refuses BEFORE staging — an
    /// oversize fold never disturbs the prior checkpoint).
    fn checkpoint_bytes_checked(&self) -> std::io::Result<Vec<u8>> {
        let bytes = self.checkpoint_bytes_raw()?;
        if bytes.len() as u64 > CHECKPOINT_MAX_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "osslscope: checkpoint body exceeds the intake bound ({} > {CHECKPOINT_MAX_BYTES} bytes; refusing before staging — prior checkpoint preserved): {}",
                    bytes.len(),
                    self.checkpoint_path.display()
                ),
            ));
        }
        Ok(bytes)
    }

    /// Load the checkpoint (absent ⇒ fresh; torn ⇒ discard + replay
    /// with unstable-all; owner-busy ⇒ usage error; unconfirmed
    /// target ⇒ marker-bound prior or loud refusal — P2fix15
    /// NEW-88).
    fn load_checkpoint(&mut self) -> std::io::Result<()> {
        // Bounded regular-file intake (P2fix13 NEW-76 — a
        // nonregular or oversize target refuses the open
        // loudly; absent stays a fresh start).
        let Some(mut body) = read_checkpoint_file(&self.checkpoint_path)? else {
            return Ok(());
        };
        let mut v: serde_json::Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => {
                self.flag_epoch_unstable();
                return Ok(());
            }
        };
        // Owner check: a live foreign owner ⇒ usage error.
        if let Some(owner) = obj_at(&v, "owner") {
            let pid = u64_at(owner, "pid").unwrap_or(0);
            if pid != 0 && pid as u32 != std::process::id() && pid_alive(pid as u32) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!(
                        "osslscope: checkpoint busy (owner pid {pid}) — pass a distinct --checkpoint PATH"
                    ),
                ));
            }
        }
        // Hash check (torn ⇒ discard + replay + unstable-all).
        let want = str_at(&v, "sha256").unwrap_or_default();
        let mut bare = v.clone();
        if let Some(obj) = bare.as_object_mut() {
            obj.remove("sha256");
        }
        let bytes = serde_json::to_vec(&bare).unwrap_or_default();
        if sha256_hex(&bytes) != want {
            self.flag_epoch_unstable();
            return Ok(());
        }
        // Settlement authority (P2fix15 NEW-88): a hash-valid
        // target the settlement record does NOT confirm is an
        // UNCONFIRMED replacement (interrupted or withdrawn
        // publish) — adopt the marker-bound prior from a
        // standing stage when one matches (recovery, warned),
        // else refuse loudly (never adopt it, never silently
        // reset). Absent record ⇒ legacy adoption (older
        // checkpoints behave exactly as before); torn
        // targets took the discard path above (never
        // adopted); a torn/foreign record refuses past it
        // (never adopted around).
        if let Some(rec) = read_settlement_record(&self.checkpoint_path)? {
            if rec.target_sha256 != want {
                match scan_settled_stage(&self.checkpoint_path, &rec.target_sha256)? {
                    Some(prior) => {
                        eprintln!(
                            "osslscope: checkpoint target unconfirmed ({}) — adopted the marker-bound prior (settlement-record recovery); operator should inspect",
                            self.checkpoint_path.display()
                        );
                        body = prior;
                        v = serde_json::from_slice(&body).map_err(|_| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "osslscope: corrupt checkpoint recovered prior",
                            )
                        })?;
                        self.recovered_prior = true;
                    }
                    None => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "osslscope: checkpoint target unconfirmed (settlement-record mismatch: settled is a different transaction; not {}) — the standing replacement never settled and no marker-bound prior stage stands; refusing (never adopt, never reset)",
                                self.checkpoint_path.display()
                            ),
                        ));
                    }
                }
            }
        }
        // Pre-normalization duplicate check (P2fix5 NEW-27): the
        // checkpoint is our own format (the writer never emits
        // duplicates), so ANY duplicate member under a valid hash
        // is present-but-invalid content — refuse loudly (strict
        // restore, never silent last-wins). Runs on the raw TEXT:
        // the parsed Value above already collapsed.
        let corrupt = |what: &str| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("osslscope: corrupt checkpoint {what}"),
            )
        };
        let text = std::str::from_utf8(&body).map_err(|_| corrupt("utf8"))?;
        crate::schema::check_envelope_raw_duplicates(text).map_err(|_| corrupt("duplicates"))?;
        if str_at(&v, "schema") != Some(CHECKPOINT_SCHEMA) {
            self.flag_epoch_unstable();
            return Ok(());
        }
        let Some(acc) = obj_at(&v, "accumulators") else {
            self.flag_epoch_unstable();
            return Ok(());
        };
        // Source-directory binding (P2fix2 item 22): a checkpoint
        // applies to its own out-DIR only (canonicalized both
        // sides) — a foreign out-DIR (misuse or tamper) refuses
        // loudly instead of applying foreign watermarks. Absent or
        // unresolvable paths refuse the same way (fail closed).
        let bound = match str_at(&v, "out_dir") {
            Some(stored) => {
                let live = std::fs::canonicalize(&self.out_dir).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "osslscope: checkpoint source out-DIR unresolvable",
                    )
                })?;
                let want = std::fs::canonicalize(stored).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "osslscope: checkpoint bound to an unresolvable out-DIR",
                    )
                })?;
                live == want
            }
            None => false,
        };
        if !bound {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "osslscope: checkpoint bound to another out-DIR (not {}) — delete it or pass a distinct --checkpoint PATH",
                    self.out_dir.display()
                ),
            ));
        }
        // Strict restore (P2fix2 item 22): validate EVERYTHING into
        // locals BEFORE applying anything — the watermark applies
        // only onto validated state. Present-but-invalid content
        // under a valid hash (tamper or writer bug) refuses loudly
        // (never silent defaults — a rejected newer-generation
        // document must not reset live state, and neither must a
        // corrupt restore).
        let bad = |what: &str| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("osslscope: corrupt checkpoint {what}"),
            )
        };
        let req_u64 = |obj: &serde_json::Value, key: &str| -> std::io::Result<u64> {
            u64_at(obj, key).ok_or_else(|| bad(key))
        };
        let opt_u64 = |obj: &serde_json::Value, key: &str| -> std::io::Result<Option<u64>> {
            match obj.get(key) {
                None => Err(bad(key)),
                Some(serde_json::Value::Null) => Ok(None),
                Some(n) => n.as_u64().map(Some).ok_or_else(|| bad(key)),
            }
        };
        let generation = opt_u64(&v, "generation")?;
        let watermark = opt_u64(&v, "watermark_seq")?;
        let checkpoint_seq = req_u64(&v, "checkpoint_seq")?;
        let snapshot_seq = req_u64(&v, "snapshot_seq")?;
        let calls_total = req_u64(acc, "calls_total")?;
        let lanes = read_u64_4_strict(acc.get("lanes")).ok_or_else(|| bad("lanes"))?;
        let retired_epoch = req_u64(acc, "retired_epoch")?;
        let epoch_by_cause =
            read_u64_12_strict(acc.get("epoch_by_cause")).ok_or_else(|| bad("epoch_by_cause"))?;
        let epoch_partial =
            read_u64_10_strict(acc.get("epoch_partial")).ok_or_else(|| bad("epoch_partial"))?;
        let trace_unmeasured: Vec<[u64; 2]> = acc
            .get("trace_unmeasured")
            .and_then(|u| serde_json::from_value(u.clone()).ok())
            .ok_or_else(|| bad("trace_unmeasured"))?;
        let epoch_changes = req_u64(acc, "epoch_changes")?;
        let series_overflow = req_u64(acc, "series_overflow")?;
        let counted: CountedRanges = acc
            .get("counted")
            .and_then(|c| serde_json::from_value(c.clone()).ok())
            .ok_or_else(|| bad("counted"))?;
        let sealed: BTreeMap<String, SealedGross> = acc
            .get("sealed")
            .and_then(|c| serde_json::from_value(c.clone()).ok())
            .ok_or_else(|| bad("sealed"))?;
        let current_run: Option<String> = match acc.get("current_run") {
            None => return Err(bad("current_run")),
            Some(serde_json::Value::Null) => None,
            Some(s) => Some(s.as_str().ok_or_else(|| bad("current_run"))?.to_string()),
        };
        let current_gross = match obj_at(acc, "current_gross") {
            Some(g) => read_stream_drops_strict(g).ok_or_else(|| bad("current_gross"))?,
            None => return Err(bad("current_gross")),
        };
        // Observed close vector (P2fix5 NEW-30 — always written;
        // absent refuses like every v3 field above: provenance
        // needs the true observed-vs-summary pair, and a default
        // zero would forge it).
        let current_close = match obj_at(acc, "current_close") {
            Some(g) => read_stream_drops_strict(g).ok_or_else(|| bad("current_close"))?,
            None => return Err(bad("current_close")),
        };
        // Early-adopted summary gross (P2fix4 NEW-15 — always
        // written; absent refuses like every v4 field above).
        let adopted_summary: Option<StreamDropsShape> = match acc.get("adopted_summary") {
            None => return Err(bad("adopted_summary")),
            Some(serde_json::Value::Null) => None,
            Some(g) => Some(read_stream_drops_strict(g).ok_or_else(|| bad("adopted_summary"))?),
        };
        // Retained current-run summary gross (P2fix6 NEW-35 —
        // always written; absent refuses like every v4 field
        // above).
        let current_summary: Option<StreamDropsShape> = match acc.get("current_summary") {
            None => return Err(bad("current_summary")),
            Some(serde_json::Value::Null) => None,
            Some(g) => Some(read_stream_drops_strict(g).ok_or_else(|| bad("current_summary"))?),
        };
        let req_bool =
            |key: &str| -> std::io::Result<bool> { bool_at(acc, key).ok_or_else(|| bad(key)) };
        let stream_seen_configured = req_bool("stream_seen_configured")?;
        let stream_sealed_note = req_bool("stream_sealed_note")?;
        let stream_mismatch_note = req_bool("stream_mismatch_note")?;
        // Recovery flags (P2fix3 NEW-4): the closed accumulator
        // set — a crafted flag would flow into snapshot unknown
        // paths and frames, so anything outside the writer's
        // vocabulary refuses.
        let unstable: Vec<String> = match arr_at(acc, "unstable") {
            Some(u) => {
                let mut out = Vec::with_capacity(u.len());
                for s in u {
                    let flag = s.as_str().ok_or_else(|| bad("unstable"))?;
                    if !valid_unstable_flag(flag) {
                        return Err(bad("unstable"));
                    }
                    out.push(flag.to_string());
                }
                out
            }
            None => return Err(bad("unstable")),
        };
        // Restored windows re-validate like fresh intake (GATE29 —
        // restored checkpoints enforce the same strict rules,
        // including the trace summary gate; P2fix3 NEW-4 — the
        // SAME typed validation fresh intake applies: counters
        // (either closed spelling), reason words, run identity,
        // loss causes, policy digests — restored state never
        // bypasses the validators).
        let latest: Option<LatestWindow> = match acc.get("latest") {
            None => return Err(bad("latest")),
            Some(serde_json::Value::Null) => None,
            Some(l) => {
                // Required-nullable presence (P2fix4 NEW-19/GATE29):
                // the raw restored trace section enforces the SAME
                // presence + null rules as intake BEFORE typed
                // normalization — absent-vs-null stays distinct
                // through restore (present-null applies, absent
                // refuses, explicit null on non-nullables refuses).
                if let Some(ts) = l
                    .get("signals")
                    .and_then(|s| s.get("trace"))
                    .filter(|t| !t.is_null())
                {
                    crate::provider_observation::trace::check_trace_shape_presence(ts)
                        .map_err(|_| bad("latest.trace"))?;
                }
                let w: LatestWindow =
                    serde_json::from_value(l.clone()).map_err(|_| bad("latest"))?;
                if let Some(ts) = w.signals.trace.as_ref() {
                    ts.validate().map_err(|_| bad("latest.trace"))?;
                }
                // Document-level contract (P2fix3 GATE29 — restore
                // re-runs the SAME contract on the persisted minor
                // + section + activity rows: trigger both
                // directions + coverage reconciliation).
                crate::provider_observation::trace::check_trace_contract(
                    w.schema_minor,
                    w.signals.trace.as_ref(),
                    Some(&serde_json::Value::Array(w.api_activity.clone())),
                )
                .map_err(|_| bad("latest.contract"))?;
                if !matches!(w.signals.state.as_str(), "complete" | "partial" | "fatal") {
                    return Err(bad("latest.state"));
                }
                if !matches!(
                    w.signals.outcome.as_str(),
                    "pass" | "violation" | "inconclusive" | "no_verdict" | "observe_only"
                ) {
                    return Err(bad("latest.outcome"));
                }
                if w.signals.reasons.iter().any(|r| !valid_reason_word(r)) {
                    return Err(bad("latest.reasons"));
                }
                if w.signals
                    .counters
                    .iter()
                    .any(|c| !(validate_counter(c, false) || validate_counter(c, true)))
                {
                    return Err(bad("latest.counters"));
                }
                if !valid_boot_id(&w.run_id.boot_id) {
                    return Err(bad("latest.run_id"));
                }
                if let Some(loss) = w.session_loss.as_ref() {
                    if loss.lost_intervals.iter().any(|it| {
                        crate::presentation::labels::loss_cause_index(&it.cause).is_none()
                    }) {
                        return Err(bad("latest.loss_causes"));
                    }
                }
                if let Some(active) = w.policy_active.as_ref() {
                    if active.sha256.len() != 64
                        || !active.sha256.bytes().all(|b| b.is_ascii_hexdigit())
                    {
                        return Err(bad("latest.policy_digest"));
                    }
                }
                // Restored window digest (P2fix4 NEW-4/PRIVACY —
                // the sha publishes as `window_sha256`, so a
                // non-digest refuses instead of projecting).
                if w.sha.len() != 64 || !w.sha.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(bad("latest.sha"));
                }
                Some(w)
            }
        };
        // Checkpoint-bound admission (P2fix2 item 13): validated
        // shape (set bounded by the epoch cap). Absent on old
        // checkpoints (fresh budget — the only backward-compatible
        // absence; every field above is always written).
        let admission: Option<super::budget::BudgetSnapshot> = match acc.get("admission") {
            None | Some(serde_json::Value::Null) => None,
            Some(a) => {
                let snap: super::budget::BudgetSnapshot =
                    serde_json::from_value(a.clone()).map_err(|_| bad("admission"))?;
                if snap.admitted.len() > super::budget::EPOCH_SERIES_CAP {
                    return Err(bad("admission"));
                }
                Some(snap)
            }
        };
        // Export accumulation starts (P2fix4 NEW-16 — always
        // written; null on watch-path checkpoints that never
        // saved any; malformed refuses).
        let export_starts: Option<(u64, u64)> = match acc.get("export_starts") {
            None => return Err(bad("export_starts")),
            Some(serde_json::Value::Null) => None,
            Some(v) => {
                let pair = v.as_array().ok_or_else(|| bad("export_starts"))?;
                if pair.len() != 2 {
                    return Err(bad("export_starts"));
                }
                let e = pair[0].as_u64().ok_or_else(|| bad("export_starts"))?;
                let r = pair[1].as_u64().ok_or_else(|| bad("export_starts"))?;
                Some((e, r))
            }
        };
        // Bound-state cross-check (P2fix3 NEW-2): the watermark
        // binds to the restored latest window — a hash-valid
        // watermark unrelated to latest.seq/generation (tamper or
        // writer bug) refuses loudly, never applies. Empty state
        // binds empty (all three absent together).
        match (&latest, watermark, generation) {
            (None, None, None) => {}
            (Some(w), Some(wm), Some(g)) if wm == w.seq && g == w.generation => {}
            _ => return Err(bad("watermark/generation/latest binding")),
        }
        // Preserved failed-unpublished epoch (P2fix11 NEW-67):
        // absent/null on checkpoints without preservation (the
        // second backward-compatible absence); present records
        // validate strictly (a malformed record refuses — never
        // defaulted into the previous-epoch slot).
        let previous_epoch: Option<PreservedEpoch> = match acc.get("previous_epoch") {
            None | Some(serde_json::Value::Null) => None,
            Some(p) => Some(read_previous_epoch_strict(p).ok_or_else(|| bad("previous_epoch"))?),
        };
        // Previous-epoch binding (P2fix12 NEW-72): a present
        // record binds to a DISTINCT preceding epoch with an
        // EARLIER tip and canonical flags + ranges — a
        // hash-valid record with no current watermark, a
        // same-generation tag, a tip at-or-after the current
        // tip, or non-canonical uncertainty refuses loudly
        // (never applied as earlier evidence). The writer's
        // saturated lane-sum invariant binds too (P2fix13
        // NEW-79): the fold keeps `calls_total` the saturated
        // sum of the four lanes (each fold adds the window's
        // lane sum saturated — proof in the fold drain), so a
        // hash-valid record disagreeing with its own lanes is
        // crafted content and refuses the same way.
        if let Some(p) = previous_epoch.as_ref() {
            let Some(wm) = watermark else {
                return Err(bad("previous_epoch without watermark"));
            };
            let Some(g) = generation else {
                return Err(bad("previous_epoch without generation"));
            };
            if p.generation == g {
                return Err(bad("previous_epoch not preceding"));
            }
            if p.window_seq >= wm {
                return Err(bad("previous_epoch tip not earlier"));
            }
            if !preserved_flags_canonical(&p.unstable) {
                return Err(bad("previous_epoch flags not canonical"));
            }
            if !preserved_ranges_canonical(&p.unmeasured) {
                return Err(bad("previous_epoch ranges not canonical"));
            }
            if p.calls_total
                != p.lanes
                    .iter()
                    .fold(0u64, |acc, &lane| acc.saturating_add(lane))
            {
                return Err(bad("previous_epoch calls_total"));
            }
        }
        // Validated: apply.
        self.generation = generation;
        self.watermark = watermark;
        self.checkpoint_seq = checkpoint_seq;
        self.snapshot_seq = snapshot_seq;
        self.calls_total = calls_total;
        self.lanes = lanes;
        self.retired_epoch = retired_epoch;
        self.epoch_by_cause = epoch_by_cause;
        self.epoch_partial = epoch_partial;
        self.trace_unmeasured = trace_unmeasured;
        self.epoch_changes = epoch_changes;
        self.series_overflow = series_overflow;
        self.counted = counted;
        self.sealed = sealed;
        self.current_run = current_run;
        self.current_gross = current_gross;
        self.current_close = current_close;
        self.adopted_summary = adopted_summary;
        self.current_summary = current_summary;
        self.stream_seen_configured = stream_seen_configured;
        self.stream_sealed_note = stream_sealed_note;
        self.stream_mismatch_note = stream_mismatch_note;
        self.unstable.extend(unstable);
        self.latest = latest;
        self.admission = admission;
        self.export_starts = export_starts;
        self.previous_epoch = previous_epoch;
        // Restored-tenure state (P2fix11 NEW-67): the restored
        // epoch folded iff a watermark binds (the cross-check
        // above ties watermark+latest+generation together); the
        // preview initializes from the restored accumulators so
        // a first-scan reset captures them exactly; no tenure has
        // published or failed under this presenter yet (the
        // published tip clears with its generation — P2fix12
        // NEW-71).
        self.epoch_folded = watermark.is_some();
        self.published_generation = None;
        self.published_tip = None;
        self.failed_generation = None;
        // The restored tenure (P2fix14 NEW-83): a first-scan
        // reset FROM it preserves its finals (consumed by
        // `reset_epoch`).
        self.restored_generation = generation;
        self.refresh_epoch_preview();
        Ok(())
    }

    /// Establish the checkpoint-write placement precondition
    /// (P2fix12 NEW-69 — the SINGLE establishment point, run
    /// BEFORE any mutation): open the checkpoint parent, prove
    /// occupancy + fd-anchored outside-ness on the SAME opened
    /// directory (P2fix5 NEW-26, P2fix7 NEW-44 — no
    /// pathname-check-then-reopen gap), and bind its identity
    /// to the open-time binding (P2fix6 NEW-34 — a replaced
    /// parent fails closed, a first resolution binds, the
    /// NEW-18 absent-dir deferral). Refusal here performs ZERO
    /// mutations (no stage exists yet, nothing to clean — the
    /// loud error is the whole effect).
    fn establish_write_precondition(&mut self, parent: &Path) -> std::io::Result<std::fs::File> {
        let (dir_fd, parent_id) =
            open_validated_checkpoint_parent(parent, &self.out_dir, &self.checkpoint_path)?;
        match self.checkpoint_parent_id {
            Some(bound) if bound == parent_id => {}
            Some(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "osslscope: checkpoint dir replaced since open (not {})",
                        self.checkpoint_path.display()
                    ),
                ));
            }
            None => {
                self.checkpoint_parent_id = Some(parent_id);
            }
        }
        Ok(dir_fd)
    }

    /// Publish-fused target intake gate (P2fix13 NEW-76 —
    /// the refresh arm): the publish rename may replace only
    /// an absent or regular-file target. A substituted
    /// nonregular target (FIFO, directory, symlink, device)
    /// refuses WITHOUT opening it (a stat cannot stall), so
    /// refresh and shutdown stay bounded after substitution
    /// and the foreign object is never destroyed by the
    /// rename.
    fn check_target_replaceable(
        &self,
        dir_fd: &std::fs::File,
        target_c: &std::ffi::CString,
    ) -> std::io::Result<()> {
        match stat_target_raw(dir_fd, target_c) {
            TargetRaw::Absent | TargetRaw::Regular(_) => Ok(()),
            TargetRaw::NonRegular => Err(not_regular_target(&self.checkpoint_path)),
            TargetRaw::Unreadable => Err(std::io::Error::last_os_error()),
        }
    }

    /// Fused publish-gate target stat (P2fix14 NEW-80): the
    /// arm the conditional publish binds — `Absent`
    /// (NOREPLACE) or `Present((dev, ino))` (EXCHANGE). A
    /// nonregular target refuses with the SAME regularity
    /// wording the early gate uses; anything unreadable fails
    /// closed.
    fn stat_publish_target(
        &self,
        dir_fd: &std::fs::File,
        target_c: &std::ffi::CString,
    ) -> std::io::Result<PublishArm> {
        match stat_target_raw(dir_fd, target_c) {
            TargetRaw::Absent => Ok(PublishArm::Absent),
            TargetRaw::Regular(id) => Ok(PublishArm::Present(id)),
            TargetRaw::NonRegular => Err(not_regular_target(&self.checkpoint_path)),
            TargetRaw::Unreadable => Err(std::io::Error::last_os_error()),
        }
    }

    /// Early settlement-record gate (P2fix15 NEW-87/NEW-88 —
    /// refuse unsafe destinations BEFORE staging): the
    /// `<target>.settled` name must be absent or OUR OWN
    /// valid record — a foreign object there (nonregular or
    /// foreign bytes) refuses with ZERO staging (the slot is
    /// never replaced blindly). Returns the pre-write record
    /// (restored by withdrawal when our marker publish
    /// replaced it; the commit-time CONTENT recheck
    /// re-confirms it — the gate is fail-fast, the recheck
    /// is the enforcement).
    fn check_settled_replaceable(
        &self,
        dir_fd: &std::fs::File,
        settled_c: &std::ffi::CString,
    ) -> std::io::Result<Option<SettledRecord>> {
        match stat_target_raw(dir_fd, settled_c) {
            TargetRaw::Absent => Ok(None),
            TargetRaw::Regular(_) => match read_settlement_record(&self.checkpoint_path) {
                Ok(rec) => Ok(rec),
                Err(e) => Err(std::io::Error::new(
                    e.kind(),
                    format!(
                        "osslscope: checkpoint settlement record slot holds foreign content (refusing to replace it before staging; not {}): {e}",
                        self.checkpoint_path.display()
                    ),
                )),
            },
            TargetRaw::NonRegular => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "osslscope: checkpoint settlement record slot is not a regular file (refusing to replace it; not {})",
                    self.checkpoint_path.display()
                ),
            )),
            TargetRaw::Unreadable => Err(std::io::Error::last_os_error()),
        }
    }

    /// Publish the settlement record (P2fix15 NEW-88 — the
    /// durable settlement discriminator): stage our record
    /// (O_EXCL, placement-proven), rename it onto the record
    /// name (freshness-checked: absent-or-ours CONTENT only —
    /// never a raced-in object, not even an in-place
    /// rewrite of our own inode), read it back
    /// (byte-identical), fsync it, and sync the directory.
    /// Every mutation runs fused behind a guard proof; the
    /// owned marker stage is withdrawn on failure
    /// (placement-bound — left declared when unproven).
    /// Returns OUR record's identity at the record name. On
    /// failure returns the error PLUS whether the rename ran
    /// (`Some(our_id)` — the caller remediates WITH marker
    /// restore; `None` — the record still carries the
    /// pre-write authority).
    fn commit_settlement_record(
        &self,
        guard: &PlacementGuard,
        dir_fd: &std::fs::File,
        target_name: &std::ffi::OsStr,
        settled_c: &std::ffi::CString,
        rec: &SettledRecord,
        settled_before: &Option<SettledRecord>,
    ) -> Result<(u64, u64), MarkerAttempt> {
        use std::os::fd::FromRawFd as _;
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::io::AsRawFd as _;
        let bytes = render_settlement_record(rec);
        let pid = std::process::id();
        let seq = self.checkpoint_seq;
        let withdraw_marker = |dir_fd: &std::fs::File,
                               marker_c: &std::ffi::CString,
                               marker_id: (u64, u64),
                               err: std::io::Error| {
            if guard
                .prove_before(
                    dir_fd,
                    &self.out_dir,
                    "settlement withdrawal",
                    &self.checkpoint_path,
                )
                .is_err()
            {
                return with_stage_left_unproven_note(err);
            }
            match unlink_owned(dir_fd, marker_c, marker_id) {
                Ok(true) => err,
                Ok(false) => with_stage_left_note(err),
                Err(cleanup) => with_stage_cleanup_note(err, cleanup),
            }
        };
        let mut attempt = 0u32;
        let (marker_file, marker_c, marker_id) = loop {
            if attempt >= 16 {
                return Err(MarkerAttempt {
                    err: std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!(
                            "osslscope: settlement staging crowded (not {})",
                            self.checkpoint_path.display()
                        ),
                    ),
                    replaced: None,
                });
            }
            if let Err(e) = guard.prove_before(
                dir_fd,
                &self.out_dir,
                "settlement stage",
                &self.checkpoint_path,
            ) {
                return Err(MarkerAttempt {
                    err: e,
                    replaced: None,
                });
            }
            let mut name = std::ffi::OsString::from(target_name);
            name.push(format!(".settled-staging-{pid}-{seq}.{attempt}.tmp"));
            let Ok(marker_c) = std::ffi::CString::new(name.as_os_str().as_bytes()) else {
                return Err(MarkerAttempt {
                    err: std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "osslscope: checkpoint path without a file name",
                    ),
                    replaced: None,
                });
            };
            // SAFETY: dir_fd is a live open directory fd; the
            // name is a NUL-free file name.
            let fd = unsafe {
                libc::openat(
                    dir_fd.as_raw_fd(),
                    marker_c.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
                    0o644,
                )
            };
            if fd < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    attempt += 1;
                    continue;
                }
                return Err(MarkerAttempt {
                    err: e,
                    replaced: None,
                });
            }
            // SAFETY: openat returned a fresh owned fd (O_EXCL
            // created it — exclusively ours).
            let file = unsafe { std::fs::File::from(std::os::fd::OwnedFd::from_raw_fd(fd)) };
            let id = match file_id(&file) {
                Ok(id) => id,
                Err(e) => {
                    let _ = unlink_checked(dir_fd, &marker_c);
                    return Err(MarkerAttempt {
                        err: e,
                        replaced: None,
                    });
                }
            };
            break (file, marker_c, id);
        };
        {
            use std::io::Write as _;
            let mut marker_file = &marker_file;
            if let Err(e) = marker_file.write_all(&bytes) {
                return Err(MarkerAttempt {
                    err: withdraw_marker(dir_fd, &marker_c, marker_id, e),
                    replaced: None,
                });
            }
        }
        if let Err(e) = marker_file.sync_all() {
            return Err(MarkerAttempt {
                err: withdraw_marker(dir_fd, &marker_c, marker_id, e),
                replaced: None,
            });
        }
        if let Err(e) = guard.prove_after(
            dir_fd,
            &self.out_dir,
            "settlement stage (post)",
            &self.checkpoint_path,
        ) {
            return Err(MarkerAttempt {
                err: withdraw_marker(dir_fd, &marker_c, marker_id, e),
                replaced: None,
            });
        }
        if let Err(e) = guard.prove_before(
            dir_fd,
            &self.out_dir,
            "settlement publish",
            &self.checkpoint_path,
        ) {
            return Err(MarkerAttempt {
                err: withdraw_marker(dir_fd, &marker_c, marker_id, e),
                replaced: None,
            });
        }
        // Freshness (CONTENT — an in-place rewrite keeps
        // the inode, so identity alone cannot see it): the
        // record name must still carry the pre-write bytes
        // (absent-or-ours, byte-identical — a raced-in
        // object refuses, never replaced blindly).
        let expected = settled_before.as_ref().map(render_settlement_record);
        let fresh = match read_name_bytes(dir_fd, settled_c) {
            Ok(current) => current == expected,
            Err(_) => false,
        };
        if !fresh {
            let e = std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "osslscope: checkpoint settlement record slot changed after the gate (not {})",
                    self.checkpoint_path.display()
                ),
            );
            return Err(MarkerAttempt {
                err: withdraw_marker(dir_fd, &marker_c, marker_id, e),
                replaced: None,
            });
        }
        // SAFETY: dir_fd is live; both names are NUL-free
        // file names in it.
        if unsafe {
            libc::renameat(
                dir_fd.as_raw_fd(),
                marker_c.as_ptr(),
                dir_fd.as_raw_fd(),
                settled_c.as_ptr(),
            )
        } != 0
        {
            let e = std::io::Error::last_os_error();
            return Err(MarkerAttempt {
                err: withdraw_marker(dir_fd, &marker_c, marker_id, e),
                replaced: None,
            });
        }
        // The rename RAN (our record stands at the name —
        // failures below remediate WITH marker restore).
        let failed = |detail: &str| MarkerAttempt {
            err: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "osslscope: checkpoint settlement publish failed ({detail}; not {})",
                    self.checkpoint_path.display()
                ),
            ),
            replaced: Some(marker_id),
        };
        // Readback: the record name must carry OUR bytes
        // (byte-identical — a rebind since the rename
        // restores over nothing foreign: the restore
        // re-checks identity first).
        let readback = (|| -> std::io::Result<Vec<u8>> {
            use std::io::Read as _;
            // SAFETY: dir_fd is live; the name is NUL-free.
            let fd = unsafe {
                libc::openat(
                    dir_fd.as_raw_fd(),
                    settled_c.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: openat returned a fresh owned fd.
            let mut file = unsafe { std::fs::File::from(std::os::fd::OwnedFd::from_raw_fd(fd)) };
            let mut out = Vec::new();
            file.read_to_end(&mut out)?;
            file.sync_all()?;
            Ok(out)
        })();
        match readback {
            Ok(back) if back == bytes => {}
            _ => return Err(failed("record readback mismatch")),
        }
        if dir_fd.sync_all().is_err() {
            return Err(failed("directory sync failed"));
        }
        Ok(marker_id)
    }

    /// Stale stage names in the checkpoint directory (P2fix15
    /// NEW-89 — the flush residue scan): every
    /// `<target>.staging-*` and `<target>.settled-staging-*`
    /// name still standing when a commit settles (our own
    /// stage was consumed or removed — anything found is a
    /// leftover of an interrupted or withdrawn write).
    /// Sorted, capped (past 1024 the scan truncates with a
    /// note — never unbounded).
    fn scan_stage_residue(&self, parent: &Path) -> Vec<String> {
        let target_name = self
            .checkpoint_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let data_prefix = format!("{target_name}.staging-");
        let marker_prefix = format!("{target_name}.settled-staging-");
        let mut out: Vec<String> = vec![];
        let Ok(entries) = std::fs::read_dir(parent) else {
            return out;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(&data_prefix) || name.starts_with(&marker_prefix) {
                out.push(name);
                if out.len() > 1024 {
                    out.push(
                        "(truncated: more stage residue stands — operator must list)".to_string(),
                    );
                    break;
                }
            }
        }
        out.sort();
        out
    }

    /// Atomic checkpoint write (stage + conditional publish +
    /// verified settle + settlement record), placement-held
    /// and identity-bound through every mutation (P2fix14
    /// NEW-80/NEW-81, hardened P2fix15 NEW-87/NEW-88/NEW-89):
    ///
    /// The placement precondition HOLDS THROUGH the write:
    /// after the NEW-69 establishment, a `PlacementGuard`
    /// tripwire watches the opened parent and ancestry;
    /// every mutation runs fused behind a guard proof, and a
    /// failed proof LEAVES the owned stage standing declared
    /// (withdrawal is PLACEMENT-BOUND — a removal beneath an
    /// unproven directory is itself an inside mutation).
    /// Publish is CONDITIONAL on the fused gate identity:
    /// NOREPLACE onto an absent target, EXCHANGE onto a
    /// present one — a substitution after the regularity
    /// check is detected (post-publish identity) and
    /// preserved (swapback), never replaced. Post-publish
    /// verification (identity + tripwire + position) pins
    /// the proof→syscall interval; placement is re-proven
    /// fused before the EXCHANGE, before the settle sync,
    /// and after it: any move in those intervals remediates
    /// placement-bound (swapback outside, or the unsettled
    /// publish left STANDING declared inside — prior
    /// authority via the settlement record), never success.
    /// Commit acknowledgment reflects DURABLE settlement:
    /// the directory sync runs before the success return, a
    /// sync failure withdraws durably + reports FAILURE
    /// (never success), and the settlement record publishes
    /// after (reopen tells settled from unconfirmed across
    /// interruption). Post-settlement cleanup leftovers
    /// report SEPARATELY on the outcome (the settled commit
    /// stands — live advances past them). No
    /// in-memory-only preservation window exists.
    fn write_checkpoint(&mut self) -> std::io::Result<FlushOutcome> {
        // Placement at every write (P2fix4 NEW-13/NEW-18): an
        // initially absent directory that became available after
        // open still holds the outside-producer condition — the
        // write refuses loudly instead of landing inside.
        check_checkpoint_placement(&self.out_dir, &self.checkpoint_path).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("osslscope: {e}"))
        })?;
        // Placement precondition (P2fix12 NEW-69): establish
        // BEFORE any mutation — refusal here performs ZERO
        // mutations. Every step below is dirfd-relative
        // (openat/renameat/unlinkat), never a path string.
        let parent = self
            .checkpoint_path
            .parent()
            .unwrap_or_else(|| Path::new(""));
        let parent = if parent.as_os_str().is_empty() {
            std::env::current_dir()?
        } else {
            parent.to_path_buf()
        };
        let dir_fd = self.establish_write_precondition(&parent)?;
        // Publish-syscall capability (P2fix14 NEW-80): refuse
        // BEFORE writing when the conditional publish cannot
        // be established on this filesystem (zero mutation —
        // before the guard arms).
        probe_publish_support(&dir_fd, &self.checkpoint_path)?;
        // Placement tripwire (P2fix13 NEW-74): arm the guard
        // on the SAME opened directory before any mutation —
        // refusal here is still zero-mutation.
        let guard = PlacementGuard::arm(&dir_fd, &self.checkpoint_path)?;
        // Fault injection (P2fix8 NEW-50, test-only): run the
        // armed relocation after validation, before the first
        // staging write (placement must stabilize through the
        // validated fd — inert at zero).
        #[cfg(test)]
        post_validation_hook::take_and_run();
        // Outside placement THROUGH staging (P2fix9 NEW-56,
        // P2fix13 NEW-74): fused guard proof before the
        // staging sequence begins. Ancestry-only (the NEW-50
        // outside-rename control requires proceeding when
        // only the PATH moved). Refusal precedes ANY write
        // (zero bytes land inside, no stage exists yet).
        guard.prove_before(&dir_fd, &self.out_dir, "staging", &self.checkpoint_path)?;
        let bad_name = |what: &str| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("osslscope: checkpoint {what} without a file name"),
            )
        };
        let target_name = self
            .checkpoint_path
            .file_name()
            .ok_or_else(|| bad_name("path"))?;
        use std::os::unix::ffi::OsStrExt as _;
        let target_c =
            std::ffi::CString::new(target_name.as_bytes()).map_err(|_| bad_name("path"))?;
        // Early target gate (P2fix14 NEW-80 — refuse BEFORE
        // writing): a nonregular target standing before the
        // write refuses here with ZERO staging (the late fused
        // gate below stays as the freshness check the
        // conditional publish binds).
        self.check_target_replaceable(&dir_fd, &target_c)?;
        let mut settled_name = std::ffi::OsString::from(target_name);
        settled_name.push(".settled");
        let settled_c = std::ffi::CString::new(settled_name.as_os_str().as_bytes())
            .map_err(|_| bad_name("settlement record"))?;
        // Early settlement-record gate (P2fix15 NEW-87/NEW-88
        // — refuse unsafe destinations BEFORE staging): a
        // foreign object at the record name refuses here with
        // ZERO staging. Captures the pre-write record (the
        // withdrawal restores it when our marker publish
        // replaced it) + the commit-time freshness baseline.
        let settled_before = self.check_settled_replaceable(&dir_fd, &settled_c)?;
        self.checkpoint_seq = self.checkpoint_seq.saturating_add(1);
        // Finalize the commit bytes (P2fix14 NEW-82 — the
        // envelope check refuses oversize folds BEFORE
        // staging, so the prior checkpoint is never
        // disturbed).
        let bytes = self.checkpoint_bytes_checked()?;
        // Exclusively owned staging (P2fix6 NEW-34, supersedes the
        // P2fix5 NEW-26 predictable-name protocol): the staging
        // name is unique per (target, pid, seq, attempt), so
        // distinct checkpoint names never share a stage (no
        // stem-shared predictable name) and no writer ever
        // unlinks a stage it did not create this call (no
        // cross-writer unlink of an active stage — a pre-existing
        // name bumps the attempt, bounded; residue from pid reuse
        // is inert, never adopted). Created dirfd-relative via
        // openat with O_EXCL + O_NOFOLLOW (an alias planted in the
        // gap fails closed instead of redirecting); no step here
        // follows a link or touches a path string.
        use std::os::fd::FromRawFd as _;
        use std::os::unix::io::AsRawFd as _;
        let pid = std::process::id();
        let seq = self.checkpoint_seq;
        let mut attempt = 0u32;
        // Fault injection (P2fix10 NEW-61, test-only): run the
        // armed relocation AFTER the staging re-check SUCCEEDS,
        // before the creation envelope (placement must hold
        // THROUGH creation — inert at zero).
        #[cfg(test)]
        post_staging_check_hook::take_and_run();
        // Fault injection (P2fix11 NEW-66, repositioned P2fix13
        // NEW-74, test-only): run the armed relocation at the
        // creation envelope boundary, before the fused
        // pre-creation proof (inert at zero).
        #[cfg(test)]
        post_create_check_hook::take_and_run();
        let (mut stage_file, stage_c) = loop {
            if attempt >= 16 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!(
                        "osslscope: checkpoint staging crowded (not {})",
                        self.checkpoint_path.display()
                    ),
                ));
            }
            // Outside placement AT stage creation (P2fix10
            // NEW-61, P2fix13 NEW-74): fused guard proof
            // immediately before the openat (no hook point
            // between this proof and the syscall — a
            // relocation scheduled at the envelope boundary
            // is caught HERE, before any staging mutation).
            // Ancestry-only (same rule as above).
            guard.prove_before(
                &dir_fd,
                &self.out_dir,
                "stage creation",
                &self.checkpoint_path,
            )?;
            let mut name = std::ffi::OsString::from(target_name);
            name.push(format!(".staging-{pid}-{seq}.{attempt}.tmp"));
            let stage_c = std::ffi::CString::new(name.as_os_str().as_bytes())
                .map_err(|_| bad_name("path"))?;
            // SAFETY: dir_fd is a live open directory fd; the
            // name is a NUL-free file name (no slashes — it
            // extends the target's own file name).
            let fd = unsafe {
                libc::openat(
                    dir_fd.as_raw_fd(),
                    stage_c.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
                    0o644,
                )
            };
            if fd < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    attempt += 1;
                    continue;
                }
                return Err(e);
            }
            // SAFETY: openat returned a fresh owned fd (O_EXCL
            // created it — exclusively ours).
            let file = unsafe { std::fs::File::from(std::os::fd::OwnedFd::from_raw_fd(fd)) };
            break (file, stage_c);
        };
        // Own-stage identity (P2fix14 NEW-80): every later
        // withdrawal/removal verifies the stage name still
        // refers to THIS inode (a move cannot rebind it).
        let stage_id = match file_id(&stage_file) {
            Ok(id) => id,
            Err(e) => {
                // Unreachable in practice (fstat of a live
                // just-created fd) — best-effort remove the
                // name O_EXCL proved ours, then fail loud.
                let _ = unlink_checked(&dir_fd, &stage_c);
                return Err(e);
            }
        };
        // Outside placement AFTER stage creation (P2fix11
        // NEW-66, P2fix13 NEW-74, P2fix14 NEW-80): immediate
        // guard re-proof fused with the openat above (a
        // true-concurrent move racing the creation trips here,
        // before any byte exists). On failure the EMPTY owned
        // stage is WITHDRAWN by identity-verified removal
        // (never left beneath a possibly-inside directory).
        if let Err(e) = guard.prove_after(
            &dir_fd,
            &self.out_dir,
            "stage creation (post)",
            &self.checkpoint_path,
        ) {
            return Err(refuse_leaving_stage(e));
        }
        {
            use std::io::Write as _;
            // Fault injection (P2fix7 NEW-45, test-only): fail the
            // stage write with EIO AFTER the owned stage is
            // created (inert at zero — production always writes).
            #[cfg(test)]
            let injected = stage_fault::take();
            #[cfg(not(test))]
            let injected = false;
            // Fault injection (P2fix10 NEW-61, test-only): run
            // the armed mid-write relocation after stage
            // creation (the owned stage is EMPTY here), before
            // the first byte (inert at zero).
            #[cfg(test)]
            pre_first_write_hook::take_and_run();
            // Outside placement AT the first byte (P2fix10
            // NEW-61, P2fix13 NEW-74, P2fix14 NEW-80): fused
            // guard proof immediately before write_all (no
            // hook point between). The owned stage is EMPTY
            // here, so a refusal writes ZERO bytes (and the
            // empty stage is withdrawn by identity-verified
            // removal).
            if let Err(e) =
                guard.prove_before(&dir_fd, &self.out_dir, "first write", &self.checkpoint_path)
            {
                return Err(refuse_leaving_stage(e));
            }
            let written = (|| -> std::io::Result<()> {
                if injected {
                    return Err(std::io::Error::from_raw_os_error(libc::EIO));
                }
                stage_file.write_all(&bytes)?;
                Ok(())
            })();
            if let Err(e) = written {
                return Err(withdraw_stage(
                    &guard,
                    &dir_fd,
                    &self.out_dir,
                    "stage write withdrawal",
                    &self.checkpoint_path,
                    &stage_c,
                    stage_id,
                    e,
                ));
            }
            // Fault injection (P2fix11 NEW-66, test-only):
            // run the armed relocation AFTER the first bytes
            // land (the owned stage is NON-empty here) and
            // before the fsync (the TRUE mid-write pin —
            // inert at zero).
            #[cfg(test)]
            mid_write_hook::take_and_run();
            // Outside placement AFTER the data write (P2fix11
            // NEW-66, P2fix13 NEW-74, P2fix14 NEW-80): guard
            // re-proof fused with the write above (a mid-write
            // move refuses BEFORE the sync; the staged bytes
            // are withdrawn by identity-verified removal and
            // never publish).
            if let Err(e) = guard.prove_after(
                &dir_fd,
                &self.out_dir,
                "first write (post)",
                &self.checkpoint_path,
            ) {
                return Err(refuse_leaving_stage(e));
            }
            if let Err(e) = stage_file.sync_all() {
                return Err(withdraw_stage(
                    &guard,
                    &dir_fd,
                    &self.out_dir,
                    "stage sync withdrawal",
                    &self.checkpoint_path,
                    &stage_c,
                    stage_id,
                    e,
                ));
            }
        }
        // Fault injection (P2fix9 NEW-56, test-only): run the
        // armed pre-commit relocation after the stage write,
        // before the commit proof (placement must hold THROUGH
        // the commit — inert at zero).
        #[cfg(test)]
        pre_commit_hook::take_and_run();
        // Outside placement THROUGH the commit (P2fix9 NEW-56,
        // P2fix13 NEW-74, P2fix14 NEW-80): fused guard proof —
        // a dir reparented under the producer tree after
        // staging must not commit there (the stage is
        // withdrawn by identity-verified removal).
        if let Err(e) = guard.prove_before(&dir_fd, &self.out_dir, "commit", &self.checkpoint_path)
        {
            return Err(refuse_leaving_stage(e));
        }
        // Fault injection (P2fix10 NEW-61, test-only): run the
        // armed relocation AFTER the commit re-check SUCCEEDS,
        // before the publish proof (placement must hold
        // THROUGH the publish — inert at zero).
        #[cfg(test)]
        post_commit_check_hook::take_and_run();
        // Fault injection (P2fix11 NEW-66, repositioned P2fix13
        // NEW-74/75, test-only): run the armed relocation at
        // the publish envelope boundary, before the fused
        // publish proof (inert at zero).
        #[cfg(test)]
        pre_rename_hook::take_and_run();
        // PUBLISH proof (P2fix13 NEW-74/NEW-75 — the FINAL
        // pre-publish proof, fused with the publish gate
        // below; no hook point and no other work intervenes):
        // a dir reparented under the producer tree refuses
        // HERE, with the previously committed bytes still the
        // durable authority (the target was never touched —
        // no restore exists or is needed). Ancestry-only
        // (the NEW-50 outside→outside move at the last
        // instant still commits through the validated fd).
        if let Err(e) = guard.prove_before(
            &dir_fd,
            &self.out_dir,
            "commit rename",
            &self.checkpoint_path,
        ) {
            return Err(refuse_leaving_stage(e));
        }
        // Fused publish-gate target stat (P2fix14 NEW-80): the
        // identity the conditional publish binds (stat-only —
        // a substituted FIFO refuses promptly and survives).
        let arm = match self.stat_publish_target(&dir_fd, &target_c) {
            Ok(arm) => arm,
            Err(e) => {
                return Err(withdraw_stage(
                    &guard,
                    &dir_fd,
                    &self.out_dir,
                    "publish gate withdrawal",
                    &self.checkpoint_path,
                    &stage_c,
                    stage_id,
                    e,
                ));
            }
        };
        // Fault injection (P2fix14 NEW-80, test-only): run the
        // armed target substitution AFTER the gate stat
        // SUCCEEDS, before the publish (target identity must
        // hold THROUGH the publish — inert at zero).
        #[cfg(test)]
        pre_exchange_hook::take_and_run();
        // Stage freshness (P2fix14 NEW-80): the stage name
        // must still refer to OUR OWN stage inode — a rebound
        // stage name refuses BEFORE the publish (never renamed
        // onto the target, never unlinked — the foreign object
        // is preserved and declared).
        if !name_refers_to(&dir_fd, &stage_c, stage_id) {
            let e = std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "osslscope: checkpoint publish refused: stage identity changed after creation (not {})",
                    self.checkpoint_path.display()
                ),
            );
            return Err(withdraw_stage(
                &guard,
                &dir_fd,
                &self.out_dir,
                "stage freshness withdrawal",
                &self.checkpoint_path,
                &stage_c,
                stage_id,
                e,
            ));
        }
        // EXCHANGE proof (P2fix15 NEW-87 — the FINAL
        // pre-publish proof, fused with the publish syscall
        // below; no hook point and no other work intervenes):
        // a move after the gate refuses HERE, before the
        // exchange can run beneath the producer (the owned
        // stage stands declared — withdrawal is
        // placement-bound).
        if let Err(e) =
            guard.prove_before(&dir_fd, &self.out_dir, "exchange", &self.checkpoint_path)
        {
            return Err(refuse_leaving_stage(e));
        }
        // Post-settlement residue accumulator (P2fix15 NEW-89
        // — a settled commit reports leftovers separately,
        // never as failure).
        let mut residue: Vec<String> = vec![];
        // Conditional publish (P2fix14 NEW-80 — supersedes the
        // P2fix13 plain rename): NOREPLACE onto an absent
        // target (anything raced in refuses with EEXIST),
        // EXCHANGE onto a present one (the prior bytes move
        // under the stage name — still ours to swap back
        // until the commit settles). Either syscall is atomic;
        // on failure the prior bytes stand untouched.
        let publish_flags = match arm {
            PublishArm::Absent => RENAME_NOREPLACE,
            PublishArm::Present(_) => RENAME_EXCHANGE,
        };
        if let Err(e) = renameat2_result(&dir_fd, &stage_c, &target_c, publish_flags) {
            let named = explain_publish_error(&dir_fd, &target_c, &self.checkpoint_path, &arm, e);
            return Err(withdraw_stage(
                &guard,
                &dir_fd,
                &self.out_dir,
                "publish withdrawal",
                &self.checkpoint_path,
                &stage_c,
                stage_id,
                named,
            ));
        }
        // Fault injection (P2fix14 NEW-80, test-only): run the
        // armed relocation AFTER the publish syscall, before
        // the post-publish verification (the proof→syscall
        // interval pin — inert at zero).
        #[cfg(test)]
        post_exchange_hook::take_and_run();
        // Post-publish verification (P2fix14 NEW-80 — the
        // interval pin, closing the last check-to-use gap):
        // OUR bytes must occupy the target name (a rebind
        // after the publish is hostile-ambiguous — swapback
        // would be unsafe, so NOTHING further is touched and
        // the ambiguity is declared loudly).
        if !name_refers_to(&dir_fd, &target_c, stage_id) {
            let e = std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "osslscope: checkpoint publish verification failed: target no longer carries the published bytes (not {})",
                    self.checkpoint_path.display()
                ),
            );
            return Err(ambiguous_settlement(e, "post-publish target rebind"));
        }
        if let PublishArm::Present(old_id) = arm {
            // Substitution detector: after the exchange the
            // stage name must carry the GATED prior identity —
            // anything else is an object substituted after the
            // gate (now sitting under the stage name): swap
            // back (the substitute returns to the target
            // PRESERVED — exchange only ever relinked it) and
            // refuse. The swapback binds the SUBSTITUTE's
            // identity (captured here — the gated prior may
            // have been moved aside by the substitution
            // itself), never the gated one.
            if !name_refers_to(&dir_fd, &stage_c, old_id) {
                let e = std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "osslscope: checkpoint publish refused: target substituted after the gate (the substituted object is preserved; nothing published; not {})",
                        self.checkpoint_path.display()
                    ),
                );
                let sub_id = match name_id(&dir_fd, &stage_c) {
                    Some(id) if id != stage_id => id,
                    _ => {
                        return Err(ambiguous_settlement(e, "substitute identity unreadable"));
                    }
                };
                // From the swap's perspective the substitute
                // IS the prior (swapback restores target→it).
                let sub_arm = PublishArm::Present(sub_id);
                return Err(remediate_unsettled_publish(
                    &guard,
                    &dir_fd,
                    &self.out_dir,
                    "substitution withdrawal",
                    &self.checkpoint_path,
                    &stage_c,
                    &target_c,
                    &settled_c,
                    &sub_arm,
                    stage_id,
                    "substituted target restored",
                    e,
                    &settled_before,
                    &MarkerState::Untouched,
                ));
            }
        } else {
            // NOREPLACE consumed the stage name — it must be
            // gone (a replanted stage name is foreign: the
            // publish stands, the residue is REPORTED
            // separately (P2fix15 NEW-89 — the commit is not
            // failed by it), nothing is unlinked).
            if name_id(&dir_fd, &stage_c).is_some() {
                residue.push(format!(
                    "foreign stage name replanted after NOREPLACE publish (never unlinked): {}",
                    stage_c.to_string_lossy()
                ));
            }
        }
        // Unsettled-publish withdrawal with the pre-write
        // settlement authority still in place (P2fix15 —
        // every refusal below runs before our marker publish
        // replaced the record, so withdrawal never restores
        // the record here; the marker-commit failure below
        // remediates with restore instead).
        let remediate = |step: &str, outcome: &str, primary: std::io::Error| {
            remediate_unsettled_publish(
                &guard,
                &dir_fd,
                &self.out_dir,
                step,
                &self.checkpoint_path,
                &stage_c,
                &target_c,
                &settled_c,
                &arm,
                stage_id,
                outcome,
                primary,
                &settled_before,
                &MarkerState::Untouched,
            )
        };
        let outcome = match arm {
            PublishArm::Present(_) => "prior checkpoint restored",
            PublishArm::Absent => "no checkpoint published",
        };
        // Interval tripwire: any event in the publish's wake
        // means a move overlapped the syscall (including one
        // that reversed before this check) — WITHDRAW the
        // unsettled publish when placement allows (prior
        // bytes authoritative again) or leave it STANDING
        // declared when placement is unproven (prior
        // authority via the settlement record) — never
        // complete it, never success.
        let drained = match guard.drain("publish (post)", &self.checkpoint_path) {
            Ok(drained) => drained,
            Err(e) => {
                return Err(remediate("interval withdrawal", outcome, e));
            }
        };
        if drained.events {
            let e = placement_error(
                "publish (post)",
                "moved during write",
                &self.checkpoint_path,
            );
            return Err(remediate("interval withdrawal", outcome, e));
        }
        // Position NOW (a move that ended inside remediates
        // the same way — placement-bound).
        if let Err(e) = guard.prove_position(
            &dir_fd,
            &self.out_dir,
            "publish (post)",
            &self.checkpoint_path,
        ) {
            return Err(remediate("post-publish withdrawal", outcome, e));
        }
        // Fault injection (P2fix15 NEW-87, test-only): run the
        // armed relocation AFTER the final post-publish
        // position proof SUCCEEDS, before the settle-sync
        // proof (placement must hold THROUGH settlement —
        // inert at zero).
        #[cfg(test)]
        post_position_hook::take_and_run();
        // SETTLE-SYNC proof (P2fix15 NEW-87 — fused with the
        // directory sync below; no hook point and no other
        // work intervenes): a move after the final position
        // proof refuses HERE, before the sync can run
        // beneath the producer (the unsettled publish
        // remediates placement-bound — standing declared
        // when inside, never swapped back there).
        if let Err(e) =
            guard.prove_before(&dir_fd, &self.out_dir, "settle sync", &self.checkpoint_path)
        {
            return Err(remediate("settle-sync withdrawal", outcome, e));
        }
        // Settle: the directory sync (P2fix14 NEW-81 —
        // acknowledgment reflects DURABLE settlement now). A
        // sync failure WITHDRAWS the unsettled publish (prior
        // bytes authoritative again — never an unpublished
        // replacement) and reports FAILURE — never success.
        #[cfg(test)]
        let sync_injected = dir_sync_fault::take();
        #[cfg(not(test))]
        let sync_injected = false;
        let sync_err: Option<std::io::Error> = if sync_injected {
            Some(std::io::Error::from_raw_os_error(libc::EIO))
        } else {
            #[cfg(test)]
            dir_sync_probe::record();
            dir_fd.sync_all().err()
        };
        if let Some(e) = sync_err {
            let e = std::io::Error::new(
                e.kind(),
                format!(
                    "osslscope: checkpoint directory sync failed ({e}; settlement unconfirmed; not {})",
                    self.checkpoint_path.display()
                ),
            );
            return Err(remediate("settle-sync withdrawal", outcome, e));
        }
        // Post-sync re-proof (P2fix15 NEW-87): an event in
        // the sync's wake means a move overlapped
        // settlement — remediate (placement-bound) instead
        // of completing, never success.
        if let Err(e) = guard.prove_after(
            &dir_fd,
            &self.out_dir,
            "settle sync (post)",
            &self.checkpoint_path,
        ) {
            return Err(remediate("settle-sync withdrawal", outcome, e));
        }
        // Settlement record (P2fix15 NEW-88 — the durable
        // settlement discriminator): publish OUR record over
        // the pre-write authority (the commit is SETTLED
        // once this lands — reopen adopts these bytes). A
        // publish failure remediates WITH marker restore
        // (the pre-write record — or absence — returns, so
        // reopen converges on the prior either way).
        let our_record = SettledRecord {
            target_sha256: {
                let v: serde_json::Value =
                    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
                str_at(&v, "sha256").unwrap_or_default().to_string()
            },
            checkpoint_seq: self.checkpoint_seq,
        };
        if let Err(attempt) = self.commit_settlement_record(
            &guard,
            &dir_fd,
            target_name,
            &settled_c,
            &our_record,
            &settled_before,
        ) {
            let marker = match attempt.replaced {
                Some(our_id) => MarkerState::Replaced { our_id },
                None => MarkerState::Untouched,
            };
            return Err(remediate_unsettled_publish(
                &guard,
                &dir_fd,
                &self.out_dir,
                "settlement withdrawal",
                &self.checkpoint_path,
                &stage_c,
                &target_c,
                &settled_c,
                &arm,
                stage_id,
                outcome,
                attempt.err,
                &settled_before,
                &marker,
            ));
        }
        // EXCHANGE arm: remove the prior bytes (the commit's
        // only destructive step — identity-confirmed: the
        // stage name must still carry the GATED prior
        // identity, or nothing is unlinked and the residue is
        // REPORTED). The commit SETTLED above (publish +
        // record durable), so cleanup leftovers report
        // SEPARATELY (P2fix15 NEW-89 — the outcome carries
        // them; live already advanced past them) — never as
        // flush failure.
        if let PublishArm::Present(old_id) = arm {
            let stage_name = stage_c.to_string_lossy().into_owned();
            if !name_refers_to(&dir_fd, &stage_c, old_id) {
                residue.push(format!(
                    "prior-bytes stage identity changed after settlement (never unlinked): {stage_name}"
                ));
            } else {
                // Fault injection (P2fix15 NEW-89, test-only):
                // fail the post-settlement cleanup AFTER the
                // commit settled (inert at zero — production
                // removes).
                #[cfg(test)]
                let cleanup_injected = settle_cleanup_fault::take();
                #[cfg(not(test))]
                let cleanup_injected = false;
                let cleanup_err: Option<std::io::Error> = if cleanup_injected {
                    Some(std::io::Error::from_raw_os_error(libc::EIO))
                } else {
                    match unlink_owned(&dir_fd, &stage_c, old_id) {
                        Ok(true) => None,
                        Ok(false) => Some(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "stage identity changed during settled cleanup",
                        )),
                        Err(e) => Some(e),
                    }
                };
                if let Some(cleanup) = cleanup_err {
                    residue.push(format!(
                        "{stage_name}: prior-bytes cleanup failed: {cleanup}"
                    ));
                }
            }
        }
        // Stale-stage scan (P2fix15 NEW-89): anything still
        // standing is a leftover of an interrupted or
        // withdrawn write — declared on the outcome (names
        // already reported above are not duplicated).
        for stale in self.scan_stage_residue(&parent) {
            if !residue.iter().any(|e| e.contains(&stale)) {
                residue.push(format!("stale stage left standing: {stale}"));
            }
        }
        // Post-completion external renames of the directory
        // are outside any writer's control.
        Ok(FlushOutcome { residue })
    }

    /// Adopt `run-summary.json` (compare-then-mark, §6C-1d).
    fn adopt_summary(&mut self) {
        let Ok(body) = std::fs::read(self.out_dir.join("run-summary.json")) else {
            return;
        };
        let Ok(summary) = serde_json::from_slice::<serde_json::Value>(&body) else {
            return;
        };
        // Source identity + raw uniqueness BEFORE anything
        // mutates fold state (P2fix8 NEW-53): the summary must
        // BE a service run summary (exact `service-run-v1`
        // discriminator — wrong-schema artifacts never drive
        // authoritative sealing) with unique raw keys
        // (machine-written JSON never legitimately duplicates —
        // whole-tree strict, like envelopes). A malformed
        // summary ignores the WHOLE file (all-or-nothing).
        if str_at(&summary, "schema") != Some(crate::service::state::SCHEMA_RUN) {
            return;
        }
        let Ok(text) = std::str::from_utf8(&body) else {
            return;
        };
        if crate::schema::check_envelope_raw_duplicates(text).is_err() {
            return;
        }
        let Some(run) = obj_at(&summary, "run_id").and_then(read_run_id) else {
            return;
        };
        // Generation binding (P2fix2 item 13): a summary adopts into
        // its own generation only — a foreign-generation (or
        // unbound: absent generation, or no folded epoch to bind
        // to) summary never merges (one gross per run, per epoch).
        let Some(generation) = u64_at(&summary, "generation") else {
            return;
        };
        if self.generation != Some(generation) {
            return;
        }
        // Full run identity (P2fix3 NEW-P2b — same rule as the
        // fold path above; adoption binds the identical tag).
        let tag = format!("{}-{}-{}", run.pid, run.starttime, run.boot_id);
        let Some(drops) = obj_at(&summary, "stream_drops") else {
            return;
        };
        // Strict gross + source shape BEFORE adopting or
        // transitioning (P2fix7 NEW-46 — no zero-defaults into
        // the authority slot; no sealing a departed run on a
        // defaulted summary): a malformed gross (missing
        // components, wrong types, either reason shape) or a
        // present-but-non-bool marker ignores the WHOLE summary
        // (the live fold continues — adoption is all-or-nothing).
        // P2fix8 NEW-53: the gross must also CONSERVE (totals
        // equal the per-reason sums — numerically impossible
        // gross never enters the authority slot).
        let Some(gross) = read_stream_drops_strict(drops) else {
            return;
        };
        if !stream_drops_conserves(&gross) {
            return;
        }
        if let Some(marker) = summary.get("stream_configured") {
            if !marker.is_boolean() {
                return;
            }
        }
        if bool_at(&summary, "stream_configured").unwrap_or(false) {
            self.stream_seen_configured = true;
        }
        // One authoritative gross per run (item 19): a summary for
        // the CURRENT run cross-checks STRICTLY against the last
        // folded close (P2fix3 NEW-P2b — the frozen rule: match ⇒
        // clean, mismatch ⇒ adopt the max + flag): max wins, never
        // added; only departed runs seal. ANY difference across
        // the 8 record/byte components — mixed lead/lag OR uniform
        // above/below — flags (a uniformly different final
        // summary is a disagreement, never silent convergence).
        if Some(tag.as_str()) == self.current_run.as_deref() {
            let live = self.current_gross;
            let same = live.records == gross.records
                && live.bytes == gross.bytes
                && live.queue_full == gross.queue_full
                && live.epipe == gross.epipe
                && live.stream_abandoned == gross.stream_abandoned;
            self.current_gross.records = self.current_gross.records.max(gross.records);
            self.current_gross.bytes = self.current_gross.bytes.max(gross.bytes);
            for (cur, new) in [
                (&mut self.current_gross.queue_full, gross.queue_full),
                (&mut self.current_gross.epipe, gross.epipe),
                (
                    &mut self.current_gross.stream_abandoned,
                    gross.stream_abandoned,
                ),
            ] {
                cur.records = cur.records.max(new.records);
                cur.bytes = cur.bytes.max(new.bytes);
            }
            // Retain EVERY validated current-run summary
            // separately (P2fix6 NEW-35): max-merge into the
            // durable slot so the seal reconciles it even after
            // the singleton file moves on to a successor.
            self.current_summary = Some(match self.current_summary {
                None => gross,
                Some(prev) => max_stream_drops(prev, gross),
            });
            if !same {
                self.stream_mismatch_note = true;
                self.unstable.insert("stream.drops".to_string());
            }
            return;
        }
        match self.sealed.get(&tag).cloned() {
            None => {
                // Successor summary (P2fix5 NEW-30 — the frozen
                // seal-on-transition rule fires on the FIRST
                // adopted summary naming a NEW run_id, not just on
                // its first window): seal the departed run FIRST
                // (with its missing-summary marker when no summary
                // exists for it — `seal_from_close` carries that),
                // then park with no live run until the successor's
                // first window transitions (its sealed entry
                // unseals into the adopted slot there, as before).
                // A late summary for an already-sealed run takes
                // the compare arm below (no seal — it names no
                // successor).
                if let Some(prev) = self.current_run.clone() {
                    self.seal_from_close(&prev);
                }
                self.current_run = None;
                self.current_gross = StreamDropsShape::default();
                self.current_close = StreamDropsShape::default();
                self.current_summary = None;
                // Fresh authoritative adoption.
                self.sealed.insert(
                    tag,
                    SealedGross {
                        records: gross.records,
                        bytes: gross.bytes,
                        queue_full: gross.queue_full,
                        epipe: gross.epipe,
                        stream_abandoned: gross.stream_abandoned,
                        source: "summary".to_string(),
                        tail_note: None,
                        idempotent: false,
                    },
                );
            }
            Some(sealed) => {
                // Compare-then-mark: exact match ⇒ idempotent;
                // summary above ⇒ add the delta + mismatch; summary
                // below ⇒ keep sealed + mismatch.
                let same = sealed.records == gross.records
                    && sealed.bytes == gross.bytes
                    && sealed.queue_full == gross.queue_full
                    && sealed.epipe == gross.epipe
                    && sealed.stream_abandoned == gross.stream_abandoned;
                if same {
                    if let Some(s) = self.sealed.get_mut(&tag) {
                        s.idempotent = true;
                    }
                } else {
                    // All 8 record/byte components (P2fix2 item 13 —
                    // per-reason bytes count like records: a
                    // bytes-only lead still adds its delta).
                    let above = gross.records > sealed.records
                        || gross.bytes > sealed.bytes
                        || gross.queue_full.records > sealed.queue_full.records
                        || gross.queue_full.bytes > sealed.queue_full.bytes
                        || gross.epipe.records > sealed.epipe.records
                        || gross.epipe.bytes > sealed.epipe.bytes
                        || gross.stream_abandoned.records > sealed.stream_abandoned.records
                        || gross.stream_abandoned.bytes > sealed.stream_abandoned.bytes;
                    if above {
                        if let Some(s) = self.sealed.get_mut(&tag) {
                            s.records = s.records.max(gross.records);
                            s.bytes = s.bytes.max(gross.bytes);
                            s.queue_full.records =
                                s.queue_full.records.max(gross.queue_full.records);
                            s.queue_full.bytes = s.queue_full.bytes.max(gross.queue_full.bytes);
                            s.epipe.records = s.epipe.records.max(gross.epipe.records);
                            s.epipe.bytes = s.epipe.bytes.max(gross.epipe.bytes);
                            s.stream_abandoned.records = s
                                .stream_abandoned
                                .records
                                .max(gross.stream_abandoned.records);
                            s.stream_abandoned.bytes =
                                s.stream_abandoned.bytes.max(gross.stream_abandoned.bytes);
                        }
                    }
                    self.stream_mismatch_note = true;
                    self.unstable.insert("stream.drops".to_string());
                }
            }
        }
    }

    /// Build the current snapshot (§6C-1 + §6C-4 pre-first-window).
    fn build(&mut self) -> Result<OperatorSnapshot, String> {
        // `snapshot_seq` starts 0: use-then-increment (strictly
        // increasing per presenter run, never reused).
        let seq = self.snapshot_seq;
        self.snapshot_seq = self.snapshot_seq.saturating_add(1);
        let produced_wall = wall_ns();
        let produced_mono = monotonic_ns();
        let mut unknown: Vec<UnknownEntry> = vec![];
        // Stream flagged note (combined sticky spelling when both).
        let stream_note = match (self.stream_sealed_note, self.stream_mismatch_note) {
            (true, true) => Some(NOTE_SEALED_AND_MISMATCH.to_string()),
            (true, false) => Some(NOTE_SEALED_FROM_CLOSE.to_string()),
            (false, true) => Some(NOTE_SUMMARY_MISMATCH.to_string()),
            (false, false) => None,
        };
        let Some(latest) = self.latest.clone() else {
            return self.build_pre_first(seq, produced_wall, produced_mono);
        };
        let calls_window: u64 = latest.signals.lanes.iter().sum();
        let mut counters = latest.signals.counters.clone();
        sort_counters_loss_first(&mut counters);
        let (age, stale) =
            snapshot_freshness(Some(&latest.window), self.window_secs, produced_mono);
        let age = age.unwrap_or(0);
        // Epoch stream GROSS = sealed + current (§6C-1d).
        let mut drops = self.current_gross;
        for s in self.sealed.values() {
            drops.records = drops.records.saturating_add(s.records);
            drops.bytes = drops.bytes.saturating_add(s.bytes);
            drops.queue_full.records = drops
                .queue_full
                .records
                .saturating_add(s.queue_full.records);
            drops.queue_full.bytes = drops.queue_full.bytes.saturating_add(s.queue_full.bytes);
            drops.epipe.records = drops.epipe.records.saturating_add(s.epipe.records);
            drops.epipe.bytes = drops.epipe.bytes.saturating_add(s.epipe.bytes);
            drops.stream_abandoned.records = drops
                .stream_abandoned
                .records
                .saturating_add(s.stream_abandoned.records);
            drops.stream_abandoned.bytes = drops
                .stream_abandoned
                .bytes
                .saturating_add(s.stream_abandoned.bytes);
        }
        let stream = if self.stream_seen_configured {
            Some(StreamBlock {
                drops,
                // Tap-following deferred (residual): span counts are
                // never silently zero.
                pending_spans: None,
            })
        } else {
            None
        };
        // Trace plane (DELTA-2 rescope): the raw per-window block
        // projects from the LATEST window's summary only; the epoch
        // interpreted folds (class_epoch, histograms, by_outcome)
        // are WITHHELD on the service path until the per-window
        // producer contract exists (a null latest window nulls the
        // raw block too, even mid-epoch).
        // OPEN fence (P2fix2 items 24+9): while C023 acceptance is
        // OPEN, public persisted-window consumption is
        // aggregate-only — a stored OPERATIONAL summary (edge-bearing
        // mode without fallback: latency/status/all) must not supply
        // interpreted classes or exemplars (raw counters/lanes/loss
        // flow; aggregate-only fallback/metadata summaries project
        // — the producer gates operational pairing there, so no
        // operational content can hide in their classes; the fence
        // lifts only via the re-qualification amendment).
        let fenced = |ts: &TraceSummaryData| {
            crate::provider_observation::c023::ACCEPTANCE_OPEN
                && matches!(ts.mode.as_str(), "latency" | "status" | "all")
                && !ts.fallback
        };
        // Fallback-family enforcement (P2fix3 NEW-3): a stored
        // fallback-shaped record withholds its interpreted
        // classes + exemplars unless it carries ONLY
        // fallback-family content (intake validate() rejects such
        // records, and this projection enforces independently —
        // stored fallback-shaped records cannot disclose
        // operational exemplars through here).
        let family_broken =
            |ts: &TraceSummaryData| !crate::provider_observation::trace::fallback_family_clean(ts);
        let trace_input = latest.signals.trace.as_ref();
        let by_outcome = None;
        let trace: Option<TraceBlock> = trace_input.map(|ts| TraceBlock {
            window_seq: ts.window.window_seq,
            mode: ts.mode.clone(),
            paired: ts.window.paired,
            trace_unpaired_entries: ts.window.trace_unpaired_entries,
            trace_unpaired_results: ts.window.trace_unpaired_results,
            trace_depth_exceeded: ts.window.trace_depth_exceeded,
            trace_dropped: ts.window.trace_dropped,
            trace_capped: ts.window.trace_capped,
            trace_nonmonotonic_pairs: ts.window.trace_nonmonotonic_pairs,
            trace_rejected_unknown_api: ts.window.trace_rejected_unknown_api,
            ring_loss: ts.window.ring_loss,
            class_window: if fenced(ts) || family_broken(ts) {
                None
            } else {
                ts.window.class_window.as_ref().map(|c| ClassCounts {
                    success: c.success,
                    failure: c.failure,
                    empty: c.empty,
                    retry: c.retry,
                    unknown: c.unknown,
                })
            },
            class_epoch: None,
            pairing_uncertain: ts.window.pairing_uncertain,
            pairing_uncertainty: ts.window.pairing_uncertainty.clone(),
            cut_unbound: ts.window.cut_unbound,
            unmeasured_seqs: self.trace_unmeasured.clone(),
            gaps: ts.window.gaps.clone(),
            gap_overflow: ts.window.gap_overflow,
            exemplars: if fenced(ts) || family_broken(ts) {
                vec![]
            } else {
                ts.window
                    .exemplars
                    .iter()
                    .map(|e| TraceExemplarShape {
                        dir: e.dir.clone(),
                        key_hash16: e.key_hash16.clone(),
                        api: e.api,
                        age_ns: e.age_ns,
                    })
                    .collect()
            },
        });
        // Epoch histograms withheld on the service path (DELTA-2
        // rescope — same rule as class_epoch above).
        let histograms: Option<HistogramsBlock> = None;
        let snap = OperatorSnapshot {
            schema: SCHEMA.to_string(),
            snapshot_seq: seq,
            produced_wall_ns: produced_wall,
            produced_monotonic_ns: produced_mono,
            source: Source {
                mode: "service".to_string(),
                generation: Some(latest.generation),
                run_id: Some(latest.run_id.clone()),
                window_seq: Some(latest.seq),
                window_sha256: Some(latest.sha.clone()),
            },
            window: Some(latest.window.clone()),
            completeness: CompletenessBlock {
                state: Some(latest.signals.state.clone()),
                reasons: latest.signals.reasons.clone(),
                epoch_partial_by_class: EpochPartial {
                    unknown_denominator: self.epoch_partial[0],
                    undiscovered_sites: self.epoch_partial[1],
                    unattached_sites: self.epoch_partial[2],
                    loss: self.epoch_partial[3],
                    unattributed_calls: self.epoch_partial[4],
                    startup_gap: self.epoch_partial[5],
                    tail_gap: self.epoch_partial[6],
                    signal_cut: self.epoch_partial[7],
                    visibility_lost: self.epoch_partial[8],
                    no_reasons: self.epoch_partial[9],
                },
            },
            policy: PolicyBlock {
                active: latest
                    .policy_active
                    .clone()
                    .or_else(|| self.policy_status_active.clone()),
                outcome: Some(latest.signals.outcome.clone()),
            },
            exit_hint: exit_hint_for(&latest.signals),
            counts: CountsBlock {
                calls_total: self.calls_total,
                calls_window: Some(calls_window),
                lanes: Lanes {
                    legacy_exclusive: self.lanes[0],
                    non_legacy_exclusive: self.lanes[1],
                    shared_ambiguous: self.lanes[2],
                    unfenced_tails: self.lanes[3],
                },
                lanes_window: Some(Lanes {
                    legacy_exclusive: latest.signals.lanes[0],
                    non_legacy_exclusive: latest.signals.lanes[1],
                    shared_ambiguous: latest.signals.lanes[2],
                    unfenced_tails: latest.signals.lanes[3],
                }),
                site_rows: Some(latest.signals.site_rows),
                by_outcome,
            },
            members: MembersBlock {
                observed: Some(latest.members_observed),
                retired_in_window: Some(latest.members_retired),
                retired_epoch: self.retired_epoch,
                deferred_depth: latest.deferred_depth,
            },
            loss: LossBlock {
                session: latest.session_loss.clone(),
                epoch_by_cause: EpochByCause {
                    corpse_wait: self.epoch_by_cause[0],
                    cgroup_move: self.epoch_by_cause[1],
                    membership_unknown: self.epoch_by_cause[2],
                    ring_loss: self.epoch_by_cause[3],
                    connector_drops: self.epoch_by_cause[4],
                    connector_enobufs: self.epoch_by_cause[5],
                    scan_loss: self.epoch_by_cause[6],
                    signal_prefix_unwitnessed: self.epoch_by_cause[7],
                    drain_pending: self.epoch_by_cause[8],
                    exec_spanning_aggregate: self.epoch_by_cause[9],
                    coalesced_loss: self.epoch_by_cause[10],
                    skipped_tick: self.epoch_by_cause[11],
                },
                counters,
            },
            stream,
            trace,
            histograms,
            health: HealthBlock {
                snapshot_age_ns: Some(age),
                stale,
            },
            presenter: PresenterStats {
                epoch_changes: self.epoch_changes,
                series_overflow: self.series_overflow,
            },
            unknown: vec![],
            // Drain this build's folded-window markers (item 25).
            markers: std::mem::take(&mut self.pending_markers),
        };
        // Null-kind entries.
        if snap.policy.active.is_none() {
            unknown.push(UnknownEntry {
                path: "policy.active".to_string(),
                reason: "observe_only".to_string(),
                note: None,
            });
        }
        if let Some(active) = snap.policy.active.as_ref() {
            if active.adopted_seq.is_none() {
                unknown.push(UnknownEntry {
                    path: "policy.active.adopted_seq".to_string(),
                    reason: "not_yet_observed".to_string(),
                    note: None,
                });
            }
        }
        if snap.exit_hint.is_none() {
            unknown.push(UnknownEntry {
                path: "exit_hint".to_string(),
                reason: "gap_covered".to_string(),
                note: None,
            });
        }
        if snap.members.deferred_depth.is_none() {
            unknown.push(UnknownEntry {
                path: "members.deferred_depth".to_string(),
                reason: "not_yet_observed".to_string(),
                note: None,
            });
        }
        if snap.loss.session.is_none() {
            unknown.push(UnknownEntry {
                path: "loss.session".to_string(),
                reason: "not_yet_observed".to_string(),
                note: None,
            });
        }
        match snap.stream.as_ref() {
            None => unknown.push(UnknownEntry {
                path: "stream".to_string(),
                reason: "stream_unconfigured".to_string(),
                note: None,
            }),
            Some(s) if s.pending_spans.is_none() => unknown.push(UnknownEntry {
                path: "stream.pending_spans".to_string(),
                reason: "not_yet_observed".to_string(),
                note: None,
            }),
            _ => {}
        }
        if snap.counts.by_outcome.is_none() {
            unknown.push(UnknownEntry {
                path: "counts.by_outcome".to_string(),
                reason: "trace_disabled".to_string(),
                note: None,
            });
        }
        if snap.trace.is_none() {
            unknown.push(UnknownEntry {
                path: "trace".to_string(),
                reason: "trace_disabled".to_string(),
                note: None,
            });
        }
        // Withheld classes inside a present trace block (pairing
        // uncertainty + DELTA-2 service withhold — same reason rule
        // as oneshot; the block's `pairing_uncertain` flag says
        // which).
        if let Some(t) = snap.trace.as_ref() {
            if t.class_window.is_none() {
                unknown.push(UnknownEntry {
                    path: "trace.class_window".to_string(),
                    reason: "trace_disabled".to_string(),
                    note: None,
                });
            }
            if t.class_epoch.is_none() {
                unknown.push(UnknownEntry {
                    path: "trace.class_epoch".to_string(),
                    reason: "trace_disabled".to_string(),
                    note: None,
                });
            }
        }
        if snap.histograms.is_none() {
            unknown.push(UnknownEntry {
                path: "histograms".to_string(),
                reason: "trace_disabled".to_string(),
                note: None,
            });
        }
        push_by_api_unknowns(snap.histograms.as_ref(), &mut unknown);
        // Flagged-kind entries (unstable accumulators).
        for path in self.unstable.iter() {
            // Only flag paths that are non-null in this snapshot
            // (a flag on a null path is a presenter bug per §6C-4 —
            // e.g. `counts.by_outcome` while trace is disabled).
            let present = match path.as_str() {
                "counts.calls_total"
                | "counts.lanes"
                | "members.retired_epoch"
                | "loss.epoch_by_cause"
                | "completeness.epoch_partial_by_class" => true,
                "counts.by_outcome" => snap.counts.by_outcome.is_some(),
                "histograms" => snap.histograms.is_some(),
                "stream.drops" => snap.stream.is_some(),
                _ => false,
            };
            if !present {
                continue;
            }
            if path == "stream.drops" {
                unknown.push(UnknownEntry {
                    path: path.clone(),
                    reason: "unstable_snapshot".to_string(),
                    note: stream_note.clone(),
                });
            } else {
                push_flag(&mut unknown, path);
            }
        }
        let mut snap = snap;
        snap.unknown = unknown;
        snap.check_unknown_invariant()?;
        Ok(snap)
    }

    /// Pre-first-window snapshot (§6C-4).
    fn build_pre_first(
        &mut self,
        seq: u64,
        produced_wall: u64,
        produced_mono: u64,
    ) -> Result<OperatorSnapshot, String> {
        let mut unknown: Vec<UnknownEntry> = vec![];
        let snap = OperatorSnapshot {
            schema: SCHEMA.to_string(),
            snapshot_seq: seq,
            produced_wall_ns: produced_wall,
            produced_monotonic_ns: produced_mono,
            source: Source {
                mode: "service".to_string(),
                generation: self.seq_generation,
                run_id: self.seq_run_id.clone(),
                window_seq: None,
                window_sha256: None,
            },
            window: None,
            completeness: CompletenessBlock {
                state: None,
                reasons: vec![],
                epoch_partial_by_class: EpochPartial::default(),
            },
            policy: PolicyBlock {
                active: self.policy_status_active.clone(),
                outcome: None,
            },
            exit_hint: None,
            counts: CountsBlock {
                calls_total: 0,
                calls_window: None,
                lanes: Lanes::default(),
                lanes_window: None,
                site_rows: None,
                by_outcome: None,
            },
            members: MembersBlock {
                observed: None,
                retired_in_window: None,
                retired_epoch: 0,
                deferred_depth: None,
            },
            loss: LossBlock {
                session: None,
                epoch_by_cause: EpochByCause::default(),
                counters: vec![],
            },
            stream: None,
            trace: None,
            histograms: None,
            health: HealthBlock {
                snapshot_age_ns: None,
                stale: true,
            },
            presenter: PresenterStats {
                epoch_changes: self.epoch_changes,
                series_overflow: self.series_overflow,
            },
            unknown: vec![],
            markers: std::mem::take(&mut self.pending_markers),
        };
        if snap.source.generation.is_none() {
            unknown.push(UnknownEntry {
                path: "source.generation".to_string(),
                reason: "not_yet_observed".to_string(),
                note: None,
            });
        }
        if snap.source.run_id.is_none() {
            unknown.push(UnknownEntry {
                path: "source.run_id".to_string(),
                reason: "not_yet_observed".to_string(),
                note: None,
            });
        }
        for path in [
            "source.window_seq",
            "source.window_sha256",
            "window",
            "completeness.state",
            "policy.outcome",
            "exit_hint",
            "counts.calls_window",
            "counts.lanes_window",
            "counts.site_rows",
            "members.observed",
            "members.retired_in_window",
            "members.deferred_depth",
            "loss.session",
            "health.snapshot_age_ns",
        ] {
            unknown.push(UnknownEntry {
                path: path.to_string(),
                reason: "not_yet_observed".to_string(),
                note: None,
            });
        }
        if snap.policy.active.is_none() {
            unknown.push(UnknownEntry {
                path: "policy.active".to_string(),
                reason: "observe_only".to_string(),
                note: None,
            });
        }
        if let Some(active) = snap.policy.active.as_ref() {
            if active.adopted_seq.is_none() {
                unknown.push(UnknownEntry {
                    path: "policy.active.adopted_seq".to_string(),
                    reason: "not_yet_observed".to_string(),
                    note: None,
                });
            }
        }
        unknown.push(UnknownEntry {
            path: "stream".to_string(),
            reason: "stream_unconfigured".to_string(),
            note: None,
        });
        // Priority rule: `trace_disabled` wins over
        // `not_yet_observed` at trace paths.
        for path in ["counts.by_outcome", "trace", "histograms"] {
            unknown.push(UnknownEntry {
                path: path.to_string(),
                reason: "trace_disabled".to_string(),
                note: None,
            });
        }
        let mut snap = snap;
        snap.unknown = unknown;
        snap.check_unknown_invariant()?;
        Ok(snap)
    }
}

// --- Free helpers ---

fn push_flag(unknown: &mut Vec<UnknownEntry>, path: &str) {
    unknown.push(UnknownEntry {
        path: path.to_string(),
        reason: "unstable_snapshot".to_string(),
        note: None,
    });
}

/// By-api unknown entries (§6D-3): a non-null histograms block with
/// null `by_api`/`by_api_availability` takes `opt_in_disabled` on
/// both; a non-null `by_api` takes `api_unavailable` per
/// non-covered API over its absent L1 subtree.
fn push_by_api_unknowns(hist: Option<&HistogramsBlock>, unknown: &mut Vec<UnknownEntry>) {
    let Some(h) = hist else {
        return;
    };
    if h.by_api.is_none() {
        unknown.push(UnknownEntry {
            path: "histograms.by_api".to_string(),
            reason: "opt_in_disabled".to_string(),
            note: None,
        });
    }
    if h.by_api_availability.is_none() {
        unknown.push(UnknownEntry {
            path: "histograms.by_api_availability".to_string(),
            reason: "opt_in_disabled".to_string(),
            note: None,
        });
    }
    if let (Some(by_api), Some(avail)) = (h.by_api.as_ref(), h.by_api_availability.as_ref()) {
        for (id, word) in avail.iter() {
            if word != "covered" && !by_api.contains_key(id) {
                unknown.push(UnknownEntry {
                    path: format!("histograms.by_api.\"{id}\""),
                    reason: "api_unavailable".to_string(),
                    note: None,
                });
            }
        }
    }
}

/// Parse `window-<seq:010>.json` names (minimum width 10).
fn parse_window_name(name: &str) -> Option<u64> {
    let rest = name.strip_prefix("window-")?.strip_suffix(".json")?;
    if rest.len() < 10 || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    rest.parse().ok()
}

/// Append-merge one inclusive seq range (ascending, non-overlapping).
fn push_range(ranges: &mut Vec<[u64; 2]>, range: [u64; 2]) {
    if let Some(last) = ranges.last_mut() {
        if range[0] <= last[1].saturating_add(1) {
            last[1] = last[1].max(range[1]);
            return;
        }
    }
    ranges.push(range);
}

/// Sorted union of unmeasured-range lists (P2fix10 NEW-65): the
/// scan re-union merges PRE-reset detected ranges back over
/// POST-reset folded ranges — the two lists overlap OUT OF
/// ORDER (a plain tail-merge keeps only the tail and drops the
/// earlier prefix), so sort + merge instead of pushing.
fn union_ranges(dst: &mut Vec<[u64; 2]>, src: Vec<[u64; 2]>) {
    dst.extend(src);
    dst.sort_unstable();
    let mut merged: Vec<[u64; 2]> = Vec::with_capacity(dst.len());
    for range in dst.drain(..) {
        if let Some(last) = merged.last_mut() {
            if range[0] <= last[1].saturating_add(1) {
                last[1] = last[1].max(range[1]);
                continue;
            }
        }
        merged.push(range);
    }
    *dst = merged;
}

/// Typed run identity (P2fix2 items 24+7, P2fix3 PRIVACY): pid
/// fits u32 (no silent truncation), boot ID validates as kernel
/// UUID text (no raw/arbitrary text into run tags or OTLP
/// resources). Malformed identities reject their envelope
/// (identity evidence, never half-read).
fn read_run_id(v: &serde_json::Value) -> Option<RunIdShape> {
    let pid = u64_at(v, "pid")?;
    if pid > u64::from(u32::MAX) {
        return None;
    }
    let boot_id = str_at(v, "boot_id")?;
    if !valid_boot_id(boot_id) {
        return None;
    }
    Some(RunIdShape {
        pid: pid as u32,
        starttime: u64_at(v, "starttime")?,
        boot_id: boot_id.to_string(),
    })
}

/// Typed policy identity (P2fix2 items 24+7): the digest keeps
/// 64-hex (malformed digests fail closed to `None` — context, not
/// evidence — so the window survives with `observe_only` while the
/// digest never shows).
fn read_policy_active(v: &serde_json::Value) -> Option<PolicyActive> {
    let sha256 = str_at(v, "sha256")?;
    if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(PolicyActive {
        sha256: sha256.to_string(),
        version: i64_at(v, "version")?,
        rule_count: u64_at(v, "rule_count")?,
        adopted_seq: match v.get("adopted_seq") {
            None | Some(serde_json::Value::Null) => None,
            Some(n) => Some(n.as_u64()?),
        },
    })
}

/// Window span from either document shape (producer `window` object
/// or doc_json `window` object; oneshot `accum_cut` is honestly
/// false — single-shot capture has no accumulation phase).
fn read_doc_window(doc: &serde_json::Value) -> Option<WindowBlock> {
    let w = obj_at(doc, "window")?;
    Some(WindowBlock {
        requested_start_ns: u64_at(w, "requested_start_ns")?,
        requested_end_ns: u64_at(w, "requested_end_ns")?,
        effective_start_ns: u64_at(w, "effective_start_ns")?,
        effective_end_ns: u64_at(w, "effective_end_ns")?,
        signal_cut: bool_at(w, "signal_cut").unwrap_or(false),
        accum_cut: bool_at(w, "accum_cut").unwrap_or(false),
    })
}

/// First-gap-class fold for one window (§6C-1/§6C-5 spelling rule).
fn fold_partial(epoch: &mut [u64; 10], state: &str, reasons: &[String]) {
    if state == "complete" {
        return;
    }
    if state == "fatal" && reasons.is_empty() {
        epoch[9] = epoch[9].saturating_add(1);
        return;
    }
    if let Some(first) = reasons.first() {
        let folded = crate::presentation::labels::fold_word(first);
        if let Some(idx) = crate::presentation::labels::gap_class_index(&folded) {
            epoch[idx] = epoch[idx].saturating_add(1);
        } else if state == "fatal" {
            epoch[9] = epoch[9].saturating_add(1);
        }
    } else if state == "fatal" {
        epoch[9] = epoch[9].saturating_add(1);
    }
}

fn partial_for_window(state: &str, reasons: &[String]) -> EpochPartial {
    let mut epoch = [0u64; 10];
    fold_partial(&mut epoch, state, reasons);
    EpochPartial {
        unknown_denominator: epoch[0],
        undiscovered_sites: epoch[1],
        unattached_sites: epoch[2],
        loss: epoch[3],
        unattributed_calls: epoch[4],
        startup_gap: epoch[5],
        tail_gap: epoch[6],
        signal_cut: epoch[7],
        visibility_lost: epoch[8],
        no_reasons: epoch[9],
    }
}

// P2fix8 NEW-53: the lenient zero-defaulting gross readers
// were REMOVED — both intake paths (summary adoption, present
// window gross) read strict + conservation-checked via
// `read_stream_drops_strict` + `stream_drops_conserves`.

/// Latest `End` record's session loss + deferred depth (P2fix2
/// item 24 — typed + bounded, REAL flattened `kind` shape). Absent
/// sections default (backward-compatible with older producers);
/// PRESENT-but-malformed values reject the envelope (no silent
/// zeros, no copied loss causes — loss evidence never half-reads).
fn read_end_tallies(
    env: &serde_json::Value,
) -> Result<(Option<SessionLossShape>, Option<u64>), String> {
    let Some(records) = arr_at(env, "crypto_watch") else {
        return Ok((None, None));
    };
    let mut out: Option<(SessionLossShape, Option<u64>)> = None;
    for rec in records {
        if str_at(rec, "kind") != Some("end") {
            continue;
        }
        let depth = match rec.get("peak_deferred_depth") {
            None | Some(serde_json::Value::Null) => None,
            Some(n) => Some(
                n.as_u64()
                    .ok_or_else(|| "end peak_deferred_depth must be u64".to_string())?,
            ),
        };
        // Absent `session_loss` skips (no loss evidence on this
        // end record); PRESENT-but-nonobject rejects (P2fix4
        // NEW-11 — a supplied invalid shape, never skipped).
        let loss = match rec.get("session_loss") {
            None => continue,
            Some(v) if v.is_object() => v,
            Some(_) => return Err("end session_loss must be an object".to_string()),
        };
        // Strict ring (the typed producer always emits 8 lanes).
        // ABSENT reads legacy zeros; PRESENT — including explicit
        // null — validates strictly (P2fix4 NEW-11 — the legacy
        // default is reserved for absent data; a supplied null is
        // a supplied invalid shape, never quiet zeros).
        let ring = match loss.get("ring") {
            None => [0; 8],
            Some(serde_json::Value::Null) => {
                return Err("end ring must be an array".to_string());
            }
            Some(v) => {
                let r = v
                    .as_array()
                    .ok_or_else(|| "end ring must be an array".to_string())?;
                if r.len() != 8 {
                    return Err("end ring must carry 8 lanes".to_string());
                }
                let mut a = [0u64; 8];
                for (i, v) in r.iter().enumerate() {
                    a[i] = v
                        .as_u64()
                        .ok_or_else(|| "end ring lanes must be u64".to_string())?;
                }
                a
            }
        };
        // Closed cause vocabulary (never copied verbatim).
        let mut intervals = vec![];
        if let Some(items) = arr_at(loss, "lost_intervals") {
            for it in items {
                let cause = str_at(it, "cause").unwrap_or_default();
                if crate::presentation::labels::loss_cause_index(cause).is_none() {
                    // The FIELD refuses, never the value (P2fix3
                    // NEW-4 — rejected input stays out of terminal
                    // diagnostics).
                    return Err("end lost_intervals: bad cause".to_string());
                }
                intervals.push(LostInterval {
                    start_tick: u64_at(it, "start_tick")
                        .ok_or_else(|| "lost interval ticks must be u64".to_string())?,
                    end_tick: u64_at(it, "end_tick")
                        .ok_or_else(|| "lost interval ticks must be u64".to_string())?,
                    cause: cause.to_string(),
                });
            }
        } else if loss.get("lost_intervals").is_some() {
            return Err("end lost_intervals must be an array".to_string());
        }
        // Strict-present numerics (absent ⇒ 0 — older producers).
        let req_u64 = |key: &str| -> Result<u64, String> {
            match loss.get(key) {
                None | Some(serde_json::Value::Null) => Ok(0),
                Some(n) => n.as_u64().ok_or_else(|| format!("end {key} must be u64")),
            }
        };
        let polling_fallback = match loss.get("polling_fallback") {
            None | Some(serde_json::Value::Null) => false,
            Some(b) => b
                .as_bool()
                .ok_or_else(|| "end polling_fallback must be bool".to_string())?,
        };
        out = Some((
            SessionLossShape {
                ring,
                connector_drops: req_u64("connector_drops")?,
                connector_enobufs: req_u64("connector_enobufs")?,
                scan_loss: req_u64("scan_loss")?,
                signal_dropped: req_u64("signal_dropped")?,
                signal_prefix_unwitnessed: req_u64("signal_prefix_unwitnessed")?,
                drain_pending: req_u64("drain_pending")?,
                polling_fallback,
                unattributed_events: req_u64("unattributed_events")?,
                admitted_exit_artifacts: req_u64("admitted_exit_artifacts")?,
                lost_intervals: intervals,
                coalesced: req_u64("coalesced")?,
            },
            depth,
        ));
    }
    Ok(out.map(|(s, d)| (Some(s), d)).unwrap_or((None, None)))
}

/// Producer distribution → snapshot distribution (same form).
fn dist_from(d: &crate::provider_observation::trace::TraceDistribution) -> Distribution {
    Distribution {
        buckets: d.buckets,
        sum: d.sum,
        count: d.count,
    }
}

fn pid_alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// Strict fixed-array reads (P2fix2 item 22 — checkpoint restore):
/// exact length, all u64, else `None` (never silent zeros).
fn read_u64_4_strict(v: Option<&serde_json::Value>) -> Option<[u64; 4]> {
    let a = v?.as_array()?;
    if a.len() != 4 {
        return None;
    }
    let mut out = [0u64; 4];
    for (i, x) in a.iter().enumerate() {
        out[i] = x.as_u64()?;
    }
    Some(out)
}

fn read_u64_10_strict(v: Option<&serde_json::Value>) -> Option<[u64; 10]> {
    let a = v?.as_array()?;
    if a.len() != 10 {
        return None;
    }
    let mut out = [0u64; 10];
    for (i, x) in a.iter().enumerate() {
        out[i] = x.as_u64()?;
    }
    Some(out)
}

fn read_u64_12_strict(v: Option<&serde_json::Value>) -> Option<[u64; 12]> {
    let a = v?.as_array()?;
    if a.len() != 12 {
        return None;
    }
    let mut out = [0u64; 12];
    for (i, x) in a.iter().enumerate() {
        out[i] = x.as_u64()?;
    }
    Some(out)
}

/// Strict stream-drops read (P2fix2 item 22 — checkpoint restore):
/// the writer's full flattened shape (records/bytes + all three
/// reason objects with records/bytes, all u64), else `None`.
fn read_stream_drops_strict(v: &serde_json::Value) -> Option<StreamDropsShape> {
    let reason_at = |o: &serde_json::Value, key: &str| -> Option<ReasonTotals> {
        let o = obj_at(o, key)?;
        Some(ReasonTotals {
            records: u64_at(o, "records")?,
            bytes: u64_at(o, "bytes")?,
        })
    };
    // Both gross shapes (P2fix7 NEW-46 — typed `by_reason`
    // wins when present, like the lenient reader): every
    // component required with exact types — nothing
    // zero-defaults.
    let (queue_full, epipe, stream_abandoned) = if v.get("by_reason").is_some() {
        let by = obj_at(v, "by_reason")?;
        (
            reason_at(by, "queue_full")?,
            reason_at(by, "epipe")?,
            reason_at(by, "stream_abandoned")?,
        )
    } else {
        (
            reason_at(v, "queue_full")?,
            reason_at(v, "epipe")?,
            reason_at(v, "stream_abandoned")?,
        )
    };
    Some(StreamDropsShape {
        records: u64_at(v, "records")?,
        bytes: u64_at(v, "bytes")?,
        queue_full,
        epipe,
        stream_abandoned,
    })
}

/// Gross conservation (P2fix8 NEW-53): the producer charges
/// gross + reason together on every fold (`queue.fold` — each
/// dropped record adds 1 to gross records and 1 to its reason,
/// bytes likewise), so incoming gross totals MUST equal the
/// per-reason sums exactly. Applies to INCOMING artifacts only
/// (summary files, present window gross) — merged slots
/// (`current_gross`/`current_close` running maxes) need not
/// conserve (max-merging two conserving vectors can split
/// totals from reasons) and are validated for shape only.
/// u128 sums (exact even near u64::MAX — no wrap).
fn stream_drops_conserves(shape: &StreamDropsShape) -> bool {
    let reason_records = shape.queue_full.records as u128
        + shape.epipe.records as u128
        + shape.stream_abandoned.records as u128;
    let reason_bytes = shape.queue_full.bytes as u128
        + shape.epipe.bytes as u128
        + shape.stream_abandoned.bytes as u128;
    shape.records as u128 == reason_records && shape.bytes as u128 == reason_bytes
}

// --- Test builders (unit-test fixtures through the real fold; NOT
// frozen payloads — compat goldens come from real runs) ---

/// Minimal producer-shaped document (`calls` in the legacy lane).
pub fn test_document(calls: u64, state: &str) -> serde_json::Value {
    // Real producer spellings (externally tagged): unit
    // `"Complete"`, `{"Partial": {...}}`, `{"Fatal": {...}}` with
    // unit reason `"SignalCut"`.
    let status = match state {
        "partial" => serde_json::json!({"Partial": {"reasons": ["SignalCut"]}}),
        "fatal" => serde_json::json!({"Fatal": {"kind": "Recycled", "reasons": []}}),
        _ => serde_json::json!("Complete"),
    };
    serde_json::json!({
        "status": status,
        "legacy_partition": {
            "legacy_exclusive": calls,
            "non_legacy_exclusive": 0,
            "shared_ambiguous": 0,
            "unfenced_tails": 0,
        },
        "sites": [],
        "counters": [],
        "window": {
            "requested_start_ns": 1,
            "requested_end_ns": 2,
            "effective_start_ns": 3,
            "effective_end_ns": 4,
            "signal_cut": false,
        },
    })
}

/// Minimal window envelope around a producer-shaped document.
pub fn test_envelope_with_doc(
    seq: u64,
    generation: u64,
    run: serde_json::Value,
    doc: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "schema": "service-window-v1",
        "seq": seq,
        "generation": generation,
        "run_id": run,
        "window": {
            "requested_start_ns": 1,
            "requested_end_ns": 2,
            "effective_start_ns": 3,
            "effective_end_ns": 4,
            "signal_cut": false,
            "accum_cut": false,
        },
        "members": [],
        "site_sources": [],
        "crypto_watch": [],
        "document": doc,
    })
}

/// Minimal window envelope (`calls` in the legacy lane, COMPLETE).
pub fn test_envelope(
    seq: u64,
    generation: u64,
    run: serde_json::Value,
    calls: u64,
) -> serde_json::Value {
    test_envelope_with_doc(seq, generation, run, test_document(calls, "complete"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "p2fix7-new45-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn staging_residue(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".staging-"))
            .collect()
    }

    /// The single declared stage left by a placement refusal
    /// (P2fix13 NEW-74 — cleanup is placement-gated, so the
    /// stage remains exactly as it stood when placement
    /// failed): asserts exactly one residue entry and returns
    /// (name, byte length, embedded `checkpoint_seq` when the
    /// stage carries a parseable body — proving which write
    /// it belonged to and that nothing mutated it since).
    fn single_left_stage(dir: &Path) -> (String, u64, Option<u64>) {
        let residue = staging_residue(dir);
        assert_eq!(
            residue.len(),
            1,
            "exactly one declared stage: {residue:?} in {}",
            dir.display()
        );
        let bytes = std::fs::read(dir.join(&residue[0])).unwrap();
        let seq = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|v| v.get("checkpoint_seq").and_then(|s| s.as_u64()));
        (residue.into_iter().next().unwrap(), bytes.len() as u64, seq)
    }

    #[test]
    fn new45_stage_cleaned_on_write_failure_recovers() {
        // P2fix7 NEW-45: 20 consecutive stage-write failures at a
        // FIXED checkpoint_seq (the export staged-retry shape —
        // the same committed sequence retried): every failure is
        // the injected EIO (never "staging crowded") and leaves
        // ZERO residue; disarm (storage recovers) → the
        // same-seq retry commits a valid checkpoint that
        // reloads. Pre-fix: each failure leaks its stage; past
        // 16 the names exhaust and the post-recovery retry still
        // fails (wedged offline).
        let base = unique_dir("stage-cleanup");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let ckpt = base.join("ckpt.json");
        let mut p = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").unwrap();
        p.build_service().expect("first fold commits");
        super::stage_fault::arm(20);
        for i in 0..20 {
            p.checkpoint_seq = 41;
            let err = p
                .flush_checkpoint()
                .expect_err("injected failure fails the flush");
            assert_eq!(
                err.raw_os_error(),
                Some(libc::EIO),
                "attempt {i}: the injected EIO surfaces (never crowded): {err:?}"
            );
            assert!(
                staging_residue(base.as_path()).is_empty(),
                "attempt {i}: no stage residue: {:?}",
                staging_residue(base.as_path())
            );
        }
        p.checkpoint_seq = 41;
        p.flush_checkpoint().expect("post-recovery retry commits");
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
        assert_eq!(v["checkpoint_seq"], 42);
        assert_eq!(v["watermark_seq"], 0);
        assert!(
            staging_residue(base.as_path()).is_empty(),
            "no residue after recovery: {:?}",
            staging_residue(base.as_path())
        );
        Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("recovery reloads");
        let _ = std::fs::remove_dir_all(&base);
    }

    fn dir_id(path: &Path) -> (u64, u64) {
        use std::os::unix::fs::MetadataExt as _;
        let md = std::fs::metadata(path).unwrap();
        (md.dev(), md.ino())
    }

    #[test]
    fn new44_opened_parent_validation() {
        // P2fix7 NEW-44: containment + identity bind to the SAME
        // OPENED directory — a path that vanished (C1) or was
        // substituted (C2: replacement during deferred first
        // resolution — the fd is unbound, the path moved) between
        // open and validation fails closed; a stable outside dir
        // (C3) validates to the fd's own identity, an inside dir
        // refuses, and a symlink parent resolves through.
        // Pre-fix shape (naive helper): C2 BINDS the substitute
        // (RED).
        let base = unique_dir("opened-parent");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let display = base.join("ckpt.json");
        // C1: vanished path (rmdir — the parent path no longer
        // resolves, even though the fd stays open).
        let v = base.join("v");
        std::fs::create_dir_all(&v).unwrap();
        let fd = std::fs::File::open(&v).unwrap();
        std::fs::remove_dir(&v).unwrap();
        assert!(
            super::validate_opened_parent(&fd, &v, &out, &display).is_err(),
            "a vanished path fails closed"
        );
        // C2: substituted path (replacement during deferred first
        // resolution — open-then-swap-then-validate: the fd pins
        // X while the path now names Y).
        let p = base.join("p");
        let x = base.join("x-real");
        std::fs::create_dir_all(&x).unwrap();
        std::fs::rename(&x, &p).unwrap();
        let fd = std::fs::File::open(&p).unwrap();
        let opened_id = dir_id(&p);
        std::fs::rename(&p, &x).unwrap();
        std::fs::create_dir_all(&p).unwrap();
        let substituted_id = dir_id(&p);
        assert_ne!(opened_id, substituted_id, "premise: distinct identities");
        let err = super::validate_opened_parent(&fd, &p, &out, &display)
            .expect_err("a substituted directory must not validate");
        assert!(
            format!("{err:?}").contains("swapped"),
            "the refusal names the swap: {err:?}"
        );
        // C3 controls: stable outside validates to the fd's own
        // identity; inside refuses; a symlink parent resolves
        // through to the target identity.
        let s = base.join("stable");
        std::fs::create_dir_all(&s).unwrap();
        let fd = std::fs::File::open(&s).unwrap();
        assert_eq!(
            super::validate_opened_parent(&fd, &s, &out, &display).unwrap(),
            dir_id(&s),
            "stable outside validates to the fd identity"
        );
        let inner = out.join("inner");
        std::fs::create_dir_all(&inner).unwrap();
        let fd = std::fs::File::open(&inner).unwrap();
        assert!(
            super::validate_opened_parent(&fd, &inner, &out, &display).is_err(),
            "an inside dir refuses"
        );
        let link = base.join("link");
        std::os::unix::fs::symlink(&s, &link).unwrap();
        let fd = std::fs::File::open(&link).unwrap();
        assert_eq!(
            super::validate_opened_parent(&fd, &link, &out, &display).unwrap(),
            dir_id(&s),
            "a symlink parent resolves to the target identity"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new50_inside_substitution_between_checks_refuses() {
        // P2fix8 NEW-50: the fp-confirmed canonicalize/metadata
        // split — a path resolving OUTSIDE for the canonicalize
        // and INSIDE for the metadata lookup must NOT bless the
        // inside directory. The fd opens on the inside dir
        // (stays put); the parent path names a real outside dir
        // at entry; the armed hook swaps the canonical path to a
        // symlink over the inside dir between the two lookups
        // (occupancy then matches the fd — the path DOES name
        // it — so only fd-anchored containment convicts).
        // Pre-fix (occupancy-only decision): binds the inside
        // identity (RED). Post-fix: refuses naming outside-ness.
        let base = unique_dir("inside-substitution");
        let out = base.join("out");
        let inner = out.join("inner");
        std::fs::create_dir_all(&inner).unwrap();
        let x = base.join("x");
        std::fs::create_dir_all(&x).unwrap();
        let display = base.join("ckpt.json");
        let fd = std::fs::File::open(&inner).unwrap();
        let inner_id = dir_id(&inner);
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran2 = ran.clone();
        let (x_moved, inner_p) = (x.clone(), inner.clone());
        super::parent_swap_hook::arm(move || {
            std::fs::rename(&x_moved, x_moved.with_extension("saved")).unwrap();
            std::os::unix::fs::symlink(&inner_p, &x_moved).unwrap();
            ran2.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        let err = super::validate_opened_parent(&fd, &x, &out, &display)
            .expect_err("inside substitution between the checks must not validate");
        assert!(
            ran.load(std::sync::atomic::Ordering::Relaxed),
            "the hook ran between the lookups"
        );
        assert!(
            format!("{err:?}").contains("outside the producer out-DIR"),
            "fd-anchored containment names itself: {err:?}"
        );
        assert_eq!(
            dir_id(&inner),
            inner_id,
            "premise: the fd target stayed put"
        );
        super::parent_swap_hook::disarm();
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new50_destination_relocation_after_final_check_stays_stable() {
        // P2fix8 NEW-50, probe moved P2fix11 NEW-66 (NEW-50-OPEN):
        // placement stabilizes through the WHOLE mutation path —
        // a destination relocation AFTER the FINAL successful
        // check (the fused pre-rename proof — the last instant)
        // cannot redirect the bytes: the write lands in the
        // VALIDATED fd (dirfd-relative), never by re-resolving
        // the path. The armed hook renames the validated parent
        // away and replants the path as a symlink over the
        // inside dir; the flush still commits into the moved
        // directory and the inside dir stays empty. (Guard pin —
        // dirfd-relative staging holds pre/post; it proves the
        // stabilization half of NEW-50 at the last instant.)
        let base = unique_dir("destination-relocation");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let inner = out.join("inner");
        std::fs::create_dir_all(&inner).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        let moved = base.join("p-moved");
        let (p2, moved2, inner2) = (p.clone(), moved.clone(), inner.clone());
        super::pre_rename_hook::arm(move || {
            std::fs::rename(&p2, &moved2).unwrap();
            std::os::unix::fs::symlink(&inner2, &p2).unwrap();
        });
        presenter
            .flush_checkpoint()
            .expect("relocation after the final check still commits");
        super::pre_rename_hook::disarm();
        let moved_ckpt = moved.join("ckpt.json");
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&moved_ckpt).unwrap()).unwrap();
        assert!(
            v.get("checkpoint_seq").and_then(|s| s.as_u64()).is_some(),
            "the moved dir holds a valid checkpoint: {v:?}"
        );
        Presenter::open_with_checkpoint(&out, &moved_ckpt, 1, "export")
            .expect("the relocated checkpoint reloads");
        assert!(
            std::fs::read_dir(&inner).unwrap().next().is_none(),
            "the inside dir stays empty"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new56_opened_dir_reparented_under_producer_refuses_without_writes() {
        // P2fix9 NEW-56 (+ NEW-13/NEW-26/NEW-34/NEW-50-OPEN):
        // outside placement holds THROUGH staging — an opened
        // checkpoint dir reparented UNDER the producer out-DIR
        // after validation refuses with ZERO writes there. The
        // armed relocation hook moves the validated parent INTO
        // the producer tree after validation, before the first
        // staging write. Pre-fix: the staging openat lands
        // bytes inside (RED). Post-fix: the pre-staging
        // ancestry re-check refuses before any write (GREEN).
        let base = unique_dir("reparent-under-producer");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        let before = std::fs::read(&ckpt).unwrap();
        let target = out.join("p-moved");
        let (p2, target2) = (p.clone(), target.clone());
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran2 = ran.clone();
        super::post_validation_hook::arm(move || {
            std::fs::rename(&p2, &target2).unwrap();
            ran2.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        let err = presenter
            .flush_checkpoint()
            .expect_err("reparent under the producer tree must refuse");
        super::post_validation_hook::disarm();
        assert!(
            ran.load(std::sync::atomic::Ordering::Relaxed),
            "the relocation hook ran after validation"
        );
        assert!(
            format!("{err:?}").contains("outside the producer out-DIR"),
            "the refusal names placement: {err:?}"
        );
        // ZERO writes: no stage residue in the moved dir, and
        // the pre-existing checkpoint bytes are untouched.
        assert!(
            staging_residue(&target).is_empty(),
            "no stage file was created inside: {:?}",
            staging_residue(&target)
        );
        assert_eq!(
            std::fs::read(target.join("ckpt.json")).unwrap(),
            before,
            "the moved checkpoint bytes are untouched"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new56_reparent_between_staging_and_commit_refuses_commit() {
        // P2fix9 NEW-56 (P2fix15 NEW-87 semantics — supersedes
        // the P2fix14 NEW-80 withdrawal: withdrawal is
        // placement-bound — no unlink beneath the producer):
        // outside placement holds THROUGH the commit — a dir
        // reparented under the producer tree AFTER the stage
        // write refuses the publish (the target name never
        // appears there) and the owned stage stands DECLARED
        // (never unlinked beneath the moved dir). Pre-fix:
        // the rename commits inside (RED).
        let base = unique_dir("reparent-before-commit");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        let before = std::fs::read(&ckpt).unwrap();
        let target = out.join("p-moved");
        let (p2, target2) = (p.clone(), target.clone());
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran2 = ran.clone();
        super::pre_commit_hook::arm(move || {
            std::fs::rename(&p2, &target2).unwrap();
            ran2.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        let err = presenter
            .flush_checkpoint()
            .expect_err("reparent before the commit must refuse");
        super::pre_commit_hook::disarm();
        assert!(
            ran.load(std::sync::atomic::Ordering::Relaxed),
            "the pre-commit hook ran after staging"
        );
        assert!(
            format!("{err:?}").contains("outside the producer out-DIR"),
            "the refusal names placement: {err:?}"
        );
        assert_eq!(
            std::fs::read(target.join("ckpt.json")).unwrap(),
            before,
            "the commit never replaced the checkpoint"
        );
        // The refused write's stage stands declared after
        // the move (P2fix15 NEW-87 — never unlinked beneath
        // the producer), and the refusal declares it.
        assert!(
            format!("{err:?}").contains("stage left in place"),
            "the refusal declares the left stage: {err:?}"
        );
        let (stage_name, stage_len, stage_seq) = single_left_stage(&target);
        assert!(stage_len > 0, "the declared stage carries the written body");
        assert_eq!(
            stage_seq,
            Some(presenter.checkpoint_seq),
            "the declared stage is this write's ({stage_name})"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new61_reparent_after_staging_check_refuses_before_creation() {
        // P2fix10 NEW-61 (+ NEW-13/NEW-26/NEW-34/NEW-50/NEW-56-OPEN):
        // the relocation hook fires AFTER the staging re-check
        // SUCCEEDS (after the last successful staging check) — the
        // fused pre-creation check must refuse before ANY staging
        // mutation (zero residue, pre-existing bytes untouched).
        // Pre-fix: the stage is created + committed inside (RED).
        let base = unique_dir("reparent-after-staging-check");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        let before = std::fs::read(&ckpt).unwrap();
        let target = out.join("p-moved");
        let (p2, target2) = (p.clone(), target.clone());
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran2 = ran.clone();
        super::post_staging_check_hook::arm(move || {
            std::fs::rename(&p2, &target2).unwrap();
            ran2.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        let err = presenter
            .flush_checkpoint()
            .expect_err("reparent after the staging check must refuse");
        super::post_staging_check_hook::disarm();
        assert!(
            ran.load(std::sync::atomic::Ordering::Relaxed),
            "the relocation hook ran after the staging check"
        );
        assert!(
            format!("{err:?}").contains("at stage creation"),
            "the refusal names the fused checkpoint: {err:?}"
        );
        assert!(
            staging_residue(&target).is_empty(),
            "no stage file was created inside: {:?}",
            staging_residue(&target)
        );
        assert_eq!(
            std::fs::read(target.join("ckpt.json")).unwrap(),
            before,
            "the moved checkpoint bytes are untouched"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new61_mid_write_move_refuses_with_zero_bytes() {
        // P2fix10 NEW-61 mid-write pin (P2fix14 NEW-80
        // semantics — supersedes the P2fix13 left-declared
        // contract): the hook fires after stage creation (the
        // owned stage is EMPTY) and before the first byte —
        // the fused pre-write proof must refuse with ZERO
        // bytes written, and the empty stage is WITHDRAWN by
        // identity-verified removal (the hook records the
        // stage size at move time: empty). Pre-fix: the bytes
        // are written + committed inside (RED).
        let base = unique_dir("mid-write-move");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        let before = std::fs::read(&ckpt).unwrap();
        let target = out.join("p-moved");
        let (p2, target2) = (p.clone(), target.clone());
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran2 = ran.clone();
        let size_at_move = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX));
        let size2 = size_at_move.clone();
        super::pre_first_write_hook::arm(move || {
            // The owned stage exists but is EMPTY (no byte has
            // been written yet — record its size as the proof).
            let mut stage_len = None;
            for entry in std::fs::read_dir(&p2).unwrap() {
                let entry = entry.unwrap();
                if entry.file_name().to_string_lossy().contains(".staging-") {
                    stage_len = Some(entry.metadata().unwrap().len());
                }
            }
            size2.store(
                stage_len.expect("the empty stage exists at move time"),
                std::sync::atomic::Ordering::Relaxed,
            );
            std::fs::rename(&p2, &target2).unwrap();
            ran2.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        let err = presenter
            .flush_checkpoint()
            .expect_err("a mid-write move must refuse");
        super::pre_first_write_hook::disarm();
        assert!(
            ran.load(std::sync::atomic::Ordering::Relaxed),
            "the mid-write hook ran after stage creation"
        );
        assert_eq!(
            size_at_move.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "the stage was EMPTY at move time (zero bytes precede the refusal)"
        );
        assert!(
            format!("{err:?}").contains("at first write"),
            "the refusal names the fused checkpoint: {err:?}"
        );
        // The EMPTY stage stands declared (P2fix15 NEW-87 —
        // never unlinked beneath the producer): zero bytes
        // were ever written, and the refusal declares it.
        assert!(
            format!("{err:?}").contains("stage left in place"),
            "the refusal declares the left stage: {err:?}"
        );
        let (stage_name, stage_len, stage_seq) = single_left_stage(&target);
        assert_eq!(
            stage_len, 0,
            "zero bytes in the declared stage ({stage_name})"
        );
        assert_eq!(stage_seq, None, "the empty stage carries no body");
        assert_eq!(
            std::fs::read(target.join("ckpt.json")).unwrap(),
            before,
            "the moved checkpoint bytes are untouched"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new61_reparent_after_commit_check_refuses_rename() {
        // P2fix10 NEW-61 (+ NEW-13/NEW-26/NEW-34/NEW-50/NEW-56-OPEN;
        // P2fix15 NEW-87 leave — supersedes the P2fix14 NEW-80
        // withdrawal: withdrawal is placement-bound): the
        // hook fires AFTER the commit re-check SUCCEEDS — the
        // fused publish proof must refuse with the publish
        // NEVER running (checkpoint bytes untouched, the
        // written stage standing declared).
        // Pre-fix: the rename commits inside (RED).
        let base = unique_dir("reparent-after-commit-check");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        let before = std::fs::read(&ckpt).unwrap();
        let target = out.join("p-moved");
        let (p2, target2) = (p.clone(), target.clone());
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran2 = ran.clone();
        super::post_commit_check_hook::arm(move || {
            std::fs::rename(&p2, &target2).unwrap();
            ran2.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        let err = presenter
            .flush_checkpoint()
            .expect_err("reparent after the commit check must refuse");
        super::post_commit_check_hook::disarm();
        assert!(
            ran.load(std::sync::atomic::Ordering::Relaxed),
            "the relocation hook ran after the commit check"
        );
        assert!(
            format!("{err:?}").contains("at commit rename"),
            "the refusal names the fused checkpoint: {err:?}"
        );
        assert_eq!(
            std::fs::read(target.join("ckpt.json")).unwrap(),
            before,
            "the commit never replaced the checkpoint"
        );
        // The refused write's stage stands declared after
        // the move (P2fix15 NEW-87 — never unlinked beneath
        // the producer), and the refusal declares it.
        assert!(
            format!("{err:?}").contains("stage left in place"),
            "the refusal declares the left stage: {err:?}"
        );
        let (stage_name, stage_len, stage_seq) = single_left_stage(&target);
        assert!(stage_len > 0, "the declared stage carries the written body");
        assert_eq!(
            stage_seq,
            Some(presenter.checkpoint_seq),
            "the declared stage is this write's ({stage_name})"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new66_reparent_after_create_check_refuses_with_zero_staged() {
        // P2fix11 NEW-66 (+ NEW-13/NEW-26/NEW-34/NEW-50/NEW-56/
        // NEW-61-OPEN; repositioned P2fix13 NEW-74): the
        // relocation hook fires at the creation envelope
        // boundary, before the fused pre-creation proof — the
        // proof itself must refuse with NO creation at all
        // (absence of the inside mutation, not a created-then-
        // rolled-back stage: zero residue, pre-existing bytes
        // untouched). Pre-fix: the stage is created inside and
        // the refusal lands late (RED).
        let base = unique_dir("reparent-after-create-check");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        let before = std::fs::read(&ckpt).unwrap();
        let target = out.join("p-moved");
        let (p2, target2) = (p.clone(), target.clone());
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran2 = ran.clone();
        super::post_create_check_hook::arm(move || {
            std::fs::rename(&p2, &target2).unwrap();
            ran2.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        let err = presenter
            .flush_checkpoint()
            .expect_err("reparent after the creation check must refuse");
        super::post_create_check_hook::disarm();
        assert!(
            ran.load(std::sync::atomic::Ordering::Relaxed),
            "the relocation hook ran after the creation check"
        );
        assert!(
            format!("{err:?}").contains("at stage creation")
                && !format!("{err:?}").contains("(post)"),
            "the refusal names the fused pre-creation proof (no creation ran): {err:?}"
        );
        assert!(
            staging_residue(&target).is_empty(),
            "no stage file was created inside: {:?}",
            staging_residue(&target)
        );
        assert_eq!(
            std::fs::read(target.join("ckpt.json")).unwrap(),
            before,
            "the moved checkpoint bytes are untouched"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new66_true_mid_write_move_refuses_without_further_mutation() {
        // P2fix11 NEW-66 (+ NEW-61-OPEN — the TRUE mid-write
        // pin; P2fix15 NEW-87 semantics, supersedes the
        // P2fix14 NEW-80 withdrawal: withdrawal is
        // placement-bound): the hook fires AFTER the first
        // bytes land in the owned stage (NON-empty — recorded
        // as the proof) and before the fsync — the post-write
        // re-proof must refuse with NO forward mutation (no
        // sync, no publish) and the staged bytes standing
        // DECLARED (never unlinked beneath the moved dir,
        // pre-existing bytes untouched). Pre-fix: the bytes
        // sit inside through the sync and the refusal lands
        // late (RED).
        let base = unique_dir("true-mid-write-move");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        let before = std::fs::read(&ckpt).unwrap();
        let target = out.join("p-moved");
        let (p2, target2) = (p.clone(), target.clone());
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran2 = ran.clone();
        let size_at_move = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let size2 = size_at_move.clone();
        super::mid_write_hook::arm(move || {
            // The owned stage exists and is NON-empty (bytes
            // have landed — record its size as the proof).
            let mut stage_len = None;
            for entry in std::fs::read_dir(&p2).unwrap() {
                let entry = entry.unwrap();
                if entry.file_name().to_string_lossy().contains(".staging-") {
                    stage_len = Some(entry.metadata().unwrap().len());
                }
            }
            size2.store(
                stage_len.expect("the non-empty stage exists at move time"),
                std::sync::atomic::Ordering::Relaxed,
            );
            std::fs::rename(&p2, &target2).unwrap();
            ran2.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        let err = presenter
            .flush_checkpoint()
            .expect_err("a true mid-write move must refuse");
        super::mid_write_hook::disarm();
        assert!(
            ran.load(std::sync::atomic::Ordering::Relaxed),
            "the mid-write hook ran after the first bytes"
        );
        assert!(
            size_at_move.load(std::sync::atomic::Ordering::Relaxed) > 0,
            "the stage was NON-empty at move time (bytes precede the refusal)"
        );
        assert!(
            format!("{err:?}").contains("at first write (post)"),
            "the refusal names the post-write re-proof: {err:?}"
        );
        // No byte landed after the move (P2fix15 NEW-87):
        // the write stopped at the re-proof, and the staged
        // bytes stand DECLARED (never unlinked beneath the
        // moved dir) — the refusal declares them.
        assert!(
            format!("{err:?}").contains("stage left in place"),
            "the refusal declares the left stage: {err:?}"
        );
        let (stage_name, stage_len, stage_seq) = single_left_stage(&target);
        assert!(
            stage_len == size_at_move.load(std::sync::atomic::Ordering::Relaxed),
            "no byte landed after the move ({stage_name})"
        );
        assert_eq!(
            stage_seq,
            Some(presenter.checkpoint_seq),
            "the declared stage is this write's ({stage_name})"
        );
        assert_eq!(
            std::fs::read(target.join("ckpt.json")).unwrap(),
            before,
            "the moved checkpoint bytes are untouched"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new75_late_abort_never_replaces_committed_bytes() {
        // P2fix13 NEW-75 (+ NEW-2/NEW-9/NEW-16/NEW-22/NEW-33/
        // NEW-50/NEW-56/NEW-66/NEW-70-OPEN — SUPERSEDES the
        // P2fix12 NEW-70 post-rename-restore pin: codex R13
        // rejects overwriting + syncing the target before
        // placement resolves with the prior bytes held only
        // in memory), leave arm P2fix15 NEW-87 (supersedes
        // the P2fix14 NEW-80 withdrawal: withdrawal is
        // placement-bound — no unlink beneath the producer).
        // Publish-last: the relocation hook fires at the
        // publish envelope boundary (after the commit checks,
        // before the fused publish proof) — the proof refuses
        // with the publish NEVER running: the last COMMITTED
        // bytes remain the durable authority (never replaced,
        // so nothing needs restoring and no restore file is
        // ever written), the written stage stands DECLARED
        // (never unlinked beneath the moved dir), and a
        // reopen after the dir is returned outside adopts the
        // prior transaction exactly.
        let base = unique_dir("late-abort-authority");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        let before = std::fs::read(&ckpt).unwrap();
        let before_seq = presenter.checkpoint_seq;
        let target = out.join("p-moved");
        let (p2, target2) = (p.clone(), target.clone());
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran2 = ran.clone();
        super::pre_rename_hook::arm(move || {
            std::fs::rename(&p2, &target2).unwrap();
            ran2.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        let err = presenter
            .flush_checkpoint()
            .expect_err("reparent at the publish boundary must refuse");
        super::pre_rename_hook::disarm();
        assert!(
            ran.load(std::sync::atomic::Ordering::Relaxed),
            "the relocation hook ran at the publish boundary"
        );
        assert!(
            format!("{err:?}").contains("at commit rename"),
            "the refusal names the fused publish proof: {err:?}"
        );
        assert_eq!(
            std::fs::read(target.join("ckpt.json")).unwrap(),
            before,
            "the last COMMITTED bytes were never replaced (publish-last — no restore needed)"
        );
        assert!(
            format!("{err:?}").contains("stage left in place"),
            "the refusal declares the left stage: {err:?}"
        );
        // Declared inside residue ONLY (P2fix15 NEW-87): the
        // moved dir holds the pre-existing checkpoint + its
        // settlement record + the refused write's declared
        // stage (never unlinked beneath the producer — no
        // restore file, no replacement).
        let (stage_name, stage_len, stage_seq) = single_left_stage(&target);
        assert!(stage_len > 0, "the declared stage carries the written body");
        assert_eq!(
            stage_seq,
            Some(presenter.checkpoint_seq),
            "the declared stage is this write's ({stage_name})"
        );
        let mut entries: Vec<String> = std::fs::read_dir(&target)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        entries.sort();
        assert_eq!(
            entries,
            vec![
                "ckpt.json".to_string(),
                "ckpt.json.settled".to_string(),
                stage_name,
            ],
            "only the committed checkpoint + its record + the declared stage stand inside: {entries:?}"
        );
        // Reopen adopts the prior transaction exactly (the
        // dir returned outside first — a checkpoint inside
        // the producer tree refuses at open by placement).
        let back = base.join("p-back");
        std::fs::rename(&target, &back).unwrap();
        let q = Presenter::open_with_checkpoint(&out, &back.join("ckpt.json"), 1, "export")
            .expect("reopen on the prior committed checkpoint");
        assert_eq!(
            q.checkpoint_seq, before_seq,
            "reopen adopts the prior committed sequence, never the refused stage"
        );
        assert_eq!(q.watermark, Some(0), "the prior watermark stands");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new66_eio_cleanup_completes_in_relocated_dir() {
        // P2fix11 NEW-66 (cleanup arm): the rollback direction is
        // always safe — an EIO stage-write failure in a RELOCATED
        // (outside→outside) dir still surfaces EIO and still
        // unlinks the owned stage (zero residue in the moved
        // dir, pre-existing bytes untouched). Guard pin (holds
        // pre/post — it proves cleanup executes THROUGH a
        // relocation rather than stranding the stage).
        let base = unique_dir("eio-cleanup-relocated");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        let before = std::fs::read(&ckpt).unwrap();
        let moved = base.join("p-eio");
        let (p2, moved2) = (p.clone(), moved.clone());
        super::post_validation_hook::arm(move || {
            std::fs::rename(&p2, &moved2).unwrap();
        });
        super::stage_fault::arm(1);
        let err = presenter
            .flush_checkpoint()
            .expect_err("the injected EIO must fail the flush");
        super::post_validation_hook::disarm();
        assert_eq!(
            err.raw_os_error(),
            Some(libc::EIO),
            "the injected EIO surfaces: {err:?}"
        );
        assert!(
            staging_residue(&moved).is_empty(),
            "cleanup unlinks the stage in the moved dir: {:?}",
            staging_residue(&moved)
        );
        assert_eq!(
            std::fs::read(moved.join("ckpt.json")).unwrap(),
            before,
            "the moved checkpoint bytes are untouched"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new66_coordinated_reparent_storm_never_persists_inside() {
        // P2fix11 NEW-66 storm guard (COORDINATED — free-running
        // swappers phase-lock into zero-trip trajectories, per
        // the NEW-44 precedent): a swapper thread reparents the
        // checkpoint dir OBJECT between outside (base/p) and
        // inside (out/p-storm) on main's orders — parked-outside
        // attempts commit, parked-inside attempts cannot resolve
        // (open race, accounted), and storm attempts race the
        // move mid-flight. EVERY attempt is accounted (committed
        // / post-bump placement-refused / other); every surviving
        // checkpoint carries a committed sequence (never a
        // refused one) and every persisting stage belongs to an
        // uncommitted attempt (P2fix13 NEW-74 — placement-gated
        // cleanup leaves declared stages). (The hook pins above
        // carry the RED→GREEN; this pin proves the end-to-end
        // invariant holds its accounting under real races.)
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
        let base = unique_dir("reparent-storm");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        let ps = out.join("p-storm");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        // Modes: 0 park outside, 1 park inside, 2 storm.
        let mode = Arc::new(AtomicU8::new(0));
        let ack = Arc::new(AtomicU8::new(0));
        let done = Arc::new(AtomicBool::new(false));
        let swapper = {
            let (done, mode, ack) = (done.clone(), mode.clone(), ack.clone());
            let (p, ps) = (p.clone(), ps.clone());
            std::thread::spawn(move || {
                let mut parked = 255u8;
                while !done.load(Ordering::Relaxed) {
                    match mode.load(Ordering::Acquire) {
                        2 => {
                            // Storm: tight outside↔inside flips
                            // of the dir OBJECT (a flip inside a
                            // PROVE→MUTATE→RE-PROVE window trips
                            // the next re-proof + rollback).
                            if p.exists() {
                                let _ = std::fs::rename(&p, &ps);
                            } else {
                                let _ = std::fs::rename(&ps, &p);
                            }
                            parked = 255;
                            ack.store(2, Ordering::Release);
                        }
                        m => {
                            if parked != m {
                                match m {
                                    1 => {
                                        let _ = std::fs::rename(&p, &ps);
                                    }
                                    _ => {
                                        let _ = std::fs::rename(&ps, &p);
                                    }
                                }
                                parked = m;
                            }
                            ack.store(m, Ordering::Release);
                            std::thread::sleep(std::time::Duration::from_micros(100));
                        }
                    }
                }
            })
        };
        let park = |m: u8| {
            mode.store(m, Ordering::Release);
            let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while ack.load(Ordering::Acquire) != m {
                assert!(
                    std::time::Instant::now() < end,
                    "swapper stuck entering mode {m}"
                );
                std::thread::yield_now();
            }
            // Settle: the parked mode re-asserts every 100µs, so
            // one sleep past the ack proves the placement held.
            std::thread::sleep(std::time::Duration::from_millis(2));
        };
        fn attempt(
            presenter: &mut Presenter,
            committed: &mut Vec<u64>,
            refused: &mut Vec<u64>,
            other: &mut u64,
        ) {
            // Sequences record POST-flush (the flush bumps its
            // sequence only past validation — a predicted
            // pre-flush sequence double-records across buckets
            // when a pre-bump refusal precedes a later commit).
            let before = presenter.checkpoint_seq;
            match presenter.flush_checkpoint() {
                Ok(_) => committed.push(presenter.checkpoint_seq),
                Err(e) => {
                    let after = presenter.checkpoint_seq;
                    let msg = format!("{e:?}");
                    if msg.contains("outside the producer out-DIR") && after != before {
                        refused.push(after);
                    } else {
                        // Open/binding races + pre-bump placement
                        // refusals: counted, with no sequence
                        // footprint to correlate.
                        *other += 1;
                    }
                }
            }
        }
        let mut committed: Vec<u64> = vec![];
        let mut refused: Vec<u64> = vec![];
        let mut other: u64 = 0;
        // Parked-outside attempts commit (deterministic ends).
        park(0);
        attempt(&mut presenter, &mut committed, &mut refused, &mut other);
        attempt(&mut presenter, &mut committed, &mut refused, &mut other);
        assert_eq!(committed.len(), 2, "parked-outside attempts commit");
        // Storm: 300 attempts against the tight flip loop.
        park(2);
        for _ in 0..300 {
            attempt(&mut presenter, &mut committed, &mut refused, &mut other);
        }
        // Park outside and close deterministically.
        park(0);
        attempt(&mut presenter, &mut committed, &mut refused, &mut other);
        attempt(&mut presenter, &mut committed, &mut refused, &mut other);
        done.store(true, Ordering::Relaxed);
        swapper.join().expect("the swapper joins");
        // Park the object outside for the final scan.
        let _ = std::fs::rename(&ps, &p);
        let total = committed.len() + refused.len() + other as usize;
        assert_eq!(total, 304, "every attempt is accounted");
        assert!(
            committed.len() >= 4,
            "parked attempts commit (storm progress not required)"
        );
        // Stage residue accounting (P2fix13 NEW-74 —
        // placement-gated cleanup legitimately LEAVES stages
        // whose placement failed mid-flight; supersedes the
        // zero-residue expectation): every persisting stage
        // belongs to an UNCOMMITTED attempt (its filename
        // sequence was never committed), and no residue is
        // ever a checkpoint (adoption reads the target name
        // only — the surviving-checkpoint audit below binds).
        for dir in [&p, &ps] {
            if dir.is_dir() {
                for name in staging_residue(dir) {
                    // `{target}.staging-{pid}-{seq}.{attempt}.tmp`
                    let seq: u64 = name
                        .rsplit(".staging-")
                        .next()
                        .and_then(|rest| rest.split('-').nth(1))
                        .and_then(|s| s.split('.').next())
                        .and_then(|s| s.parse().ok())
                        .expect("stage name carries its sequence");
                    assert!(
                        !committed.contains(&seq),
                        "residue stage seq {seq} never committed ({name})"
                    );
                }
            }
        }
        // Every surviving checkpoint carries a COMMITTED
        // sequence (never a refused one).
        for dir in [&p, &ps] {
            let cand = dir.join("ckpt.json");
            if cand.is_file() {
                let v: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&cand).unwrap()).unwrap();
                let seq = v
                    .get("checkpoint_seq")
                    .and_then(|s| s.as_u64())
                    .expect("the checkpoint carries its sequence");
                assert!(
                    committed.contains(&seq),
                    "surviving checkpoint seq {seq} committed (not refused)"
                );
                assert!(
                    !refused.contains(&seq),
                    "no refused sequence persists in a checkpoint"
                );
            }
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new65_failed_scan_preserves_valid_prefix_gap_evidence() {
        // P2fix10 NEW-65 (+ NEW-P2c/NEW-P2h/NEW-2/NEW-57-OPEN): a
        // valid new-generation window follows a retention hole
        // and a later window rejects — the failed scan must
        // preserve the valid prefix's gap flags + ranges (no
        // watermark advance orphans the missing span). Window 1
        // is missing (hole), window 2 is a valid gen-2 window
        // (its reset clears the flags mid-scan), window 3
        // rejects. Pre-fix: the error skips the re-union, so the
        // live presenter holds an advanced watermark with EMPTY
        // flags + the hole range missing (RED).
        let base = unique_dir("failed-scan-gap-evidence");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        for (seq, generation) in [(0u64, 0u64), (2u64, 1u64)] {
            std::fs::write(
                out.join(format!("window-{seq:010}.json")),
                serde_json::to_string(&test_envelope(seq, generation, run.clone(), 10)).unwrap(),
            )
            .unwrap();
        }
        let mut bad = test_envelope(3, 1, run, 10);
        bad["schema"] = serde_json::json!("service-window-v9");
        std::fs::write(
            out.join("window-0000000003.json"),
            serde_json::to_string(&bad).unwrap(),
        )
        .unwrap();
        let ckpt = base.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        let err = presenter
            .build_service_staged()
            .expect_err("the rejected window-3 must fail the scan");
        assert!(
            format!("{err:?}").contains("service-window-v1"),
            "the failure names the rejected window: {err:?}"
        );
        // The valid prefix folded (watermark advanced past the
        // hole) — and its gap evidence is preserved with it.
        assert_eq!(
            presenter.watermark,
            Some(2),
            "the valid prefix advanced the watermark"
        );
        assert_eq!(
            presenter.unstable,
            [
                "completeness.epoch_partial_by_class",
                "counts.by_outcome",
                "counts.calls_total",
                "counts.lanes",
                "histograms",
                "loss.epoch_by_cause",
                "members.retired_epoch",
                "stream.drops",
            ]
            .into_iter()
            .map(str::to_string)
            .collect::<std::collections::BTreeSet<String>>(),
            "the hole flags survive the mid-scan reset + failure"
        );
        // Folded-but-null windows tile [0,0] + [2,2] around the
        // [1,1] hole — the preserved evidence covers the hole.
        assert_eq!(
            presenter.trace_unmeasured,
            vec![[0u64, 2u64]],
            "the hole range survives the mid-scan reset + failure"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new65_success_scan_unions_prefix_ranges_across_reset() {
        // P2fix10 NEW-65 (re-union half): the scan re-union is a
        // SORTED union — pre-reset detected ranges merge back
        // over post-reset folded ranges without dropping the
        // earlier prefix (a plain tail-merge keeps only the tail:
        // [[2,3]], losing the [0,1] hole evidence on the SUCCESS
        // path too). Pre-fix: [[2,3]] (RED).
        let base = unique_dir("success-scan-union");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        for (seq, generation) in [(0u64, 0u64), (2u64, 1u64), (3u64, 1u64)] {
            std::fs::write(
                out.join(format!("window-{seq:010}.json")),
                serde_json::to_string(&test_envelope(seq, generation, run.clone(), 10)).unwrap(),
            )
            .unwrap();
        }
        let ckpt = base.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("the valid scan builds");
        assert_eq!(
            presenter.trace_unmeasured,
            vec![[0u64, 3u64]],
            "the pre-reset prefix survives the re-union"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new67_reset_preserves_failed_epoch_and_restores() {
        // P2fix11 NEW-67 (capture + persist + restore half — the
        // follow pins above carry the loop/formats/line): publish
        // gen 0, consume a valid gen-1 prefix after a hole,
        // reject its tail, then recover into gen 2 after
        // retention removes the bad tail. The gen-2 reset must
        // preserve gen 1's accepted prefix counts + uncertainty
        // (the outgoing scan's own gap must NOT leak into the
        // preserved finals); the checkpoint persists the record;
        // a reopen restores it. Pre-fix: no record exists (RED).
        let base = unique_dir("failed-epoch-capture");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run.clone(), 10)).unwrap(),
        )
        .unwrap();
        let ckpt = base.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("gen 0 publishes");
        assert_eq!(presenter.previous_epoch(), None, "nothing preserved yet");
        for (seq, generation) in [(2u64, 1u64)] {
            std::fs::write(
                out.join(format!("window-{seq:010}.json")),
                serde_json::to_string(&test_envelope(seq, generation, run.clone(), 10)).unwrap(),
            )
            .unwrap();
        }
        let mut bad = test_envelope(3, 1, run.clone(), 10);
        bad["schema"] = serde_json::json!("service-window-v9");
        std::fs::write(
            out.join("window-0000000003.json"),
            serde_json::to_string(&bad).unwrap(),
        )
        .unwrap();
        presenter
            .build_service_staged()
            .expect_err("the rejected tail fails the scan");
        // Retention removes the bad tail; gen 2 lands.
        std::fs::remove_file(out.join("window-0000000003.json")).unwrap();
        std::fs::write(
            out.join("window-0000000004.json"),
            serde_json::to_string(&test_envelope(4, 2, run.clone(), 10)).unwrap(),
        )
        .unwrap();
        let snap = presenter.build_service().expect("recovery builds");
        assert_eq!(
            snap.source.generation,
            Some(2),
            "recovery advances to gen 2"
        );
        let prev = presenter
            .previous_epoch()
            .expect("the gen-2 reset preserves gen 1");
        assert_eq!(prev.generation, 1, "the preserved generation is gen 1");
        assert_eq!(prev.window_seq, 2, "the preserved window is the prefix tip");
        assert_eq!(
            prev.calls_total, 10,
            "the preserved counts are the prefix counts"
        );
        assert_eq!(
            prev.lanes,
            [10, 0, 0, 0],
            "the preserved lanes are the prefix lanes"
        );
        assert!(
            prev.unstable.iter().any(|f| f == "counts.calls_total"),
            "the preserved uncertainty flags survive: {:?}",
            prev.unstable
        );
        assert_eq!(
            prev.unmeasured,
            vec![[1u64, 2u64]],
            "the preserved ranges are gen 1's finals (the [1,1] hole + the \
             untraced win2 folded-but-null span — and NOT the outgoing \
             scan's own [3,3] gap)"
        );
        // The checkpoint persists the record; a reopen restores it.
        let ckpt_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&ckpt).unwrap()).unwrap();
        assert_eq!(
            ckpt_json["accumulators"]["previous_epoch"]["generation"],
            serde_json::json!(1),
            "the checkpoint persists the intervening epoch"
        );
        drop(presenter);
        let mut q = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
            .expect("the recovery checkpoint reloads");
        let prev2 = q
            .previous_epoch()
            .expect("the preserved epoch survives the reopen");
        assert_eq!(prev2, prev, "the reopen restores the record exactly");
        let snap2 = q.build_service().expect("the reopened presenter rebuilds");
        assert_eq!(snap2.source.generation, Some(2), "still gen 2 after reopen");
        assert_eq!(
            q.previous_epoch().as_ref().map(|p| p.generation),
            Some(1),
            "the record survives a same-generation rebuild"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new44_concurrent_parent_swap_never_lands_unvalidated() {
        // P2fix7 NEW-44 race pin (COORDINATED — free-running
        // swappers phase-lock into zero-trip trajectories),
        // storm widened P2fix8 NEW-50: main parks the parent
        // path (dangling/X1/inner) or orders a tight
        // X1↔X2↔inner flip storm (inside substitution WHILE
        // UNSTABLE — alternating-outside-only is insufficient),
        // then runs a deferred-first-resolution flush
        // (open-while-parked-dangling, so every open binds None
        // — strict). Calm-X1 attempts commit + reload strictly;
        // calm-inner attempts refuse on containment before any
        // staging write; storm attempts trip the occupant match,
        // refuse at containment, or bind X1/X2 only. EVERY
        // attempt is accounted; the inside dir never receives a
        // byte. (The C2 pin above carries the RED→GREEN; this
        // pin proves the end-to-end invariant under real races.)
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        let base = unique_dir("parent-swap");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let x1 = base.join("x1");
        let x2 = base.join("x2");
        let inner = out.join("inner");
        std::fs::create_dir_all(&x1).unwrap();
        std::fs::create_dir_all(&x2).unwrap();
        std::fs::create_dir_all(&inner).unwrap();
        let x1_id = dir_id(&x1);
        let x2_id = dir_id(&x2);
        let inner_id = dir_id(&inner);
        let p = base.join("p");
        let ckpt = p.join("ckpt.json");
        // Coordinated race (deterministic — free-running
        // swappers phase-lock into zero-trip trajectories):
        // main parks the path (dangling/X1/inner) or orders a
        // flip storm (X1↔X2, tight) via `mode`, and the swapper
        // echoes through `ack`. Modes: 0 dangling, 1 X1,
        // 2 storm, 3 inner.
        use std::sync::atomic::AtomicU8;
        let mode = Arc::new(AtomicU8::new(0));
        let ack = Arc::new(AtomicU8::new(0));
        let done = Arc::new(AtomicBool::new(false));
        let swapper = {
            let (done, mode, ack) = (done.clone(), mode.clone(), ack.clone());
            let (p, x1, x2, inner) = (p.clone(), x1.clone(), x2.clone(), inner.clone());
            std::thread::spawn(move || {
                let tmp = p.with_extension("swap-tmp");
                let plant = |t: &Path| {
                    let _ = std::fs::remove_file(&tmp);
                    if std::os::unix::fs::symlink(t, &tmp).is_ok() {
                        let _ = std::fs::rename(&tmp, &p);
                    }
                };
                let mut parked = 255u8;
                let mut n = 0u64;
                while !done.load(Ordering::Relaxed) {
                    match mode.load(Ordering::Acquire) {
                        2 => {
                            // Storm: tight X1↔X2↔inner flips
                            // (P2fix8 NEW-50 — inside
                            // substitution WHILE UNSTABLE, not
                            // just alternating-outside: every
                            // flip inside an open→validate
                            // window trips the occupant match,
                            // and any open binding inner must
                            // refuse at fd-anchored
                            // containment). Invalidates `parked`
                            // (the storm leaves an unknown
                            // target, so the next park must
                            // re-act).
                            plant(match n % 3 {
                                0 => &x1,
                                1 => &x2,
                                _ => &inner,
                            });
                            n += 1;
                            parked = 255;
                            ack.store(2, Ordering::Release);
                        }
                        m => {
                            // Parked: plant ONCE per mode entry
                            // (re-planting would flicker the
                            // path under the parked attempt).
                            if parked != m {
                                match m {
                                    1 => plant(&x1),
                                    3 => plant(&inner),
                                    _ => {
                                        let _ = std::fs::remove_file(&p);
                                    }
                                }
                                parked = m;
                            }
                            ack.store(m, Ordering::Release);
                            std::thread::sleep(std::time::Duration::from_micros(100));
                        }
                    }
                }
            })
        };
        let park = |m: u8| {
            mode.store(m, Ordering::Release);
            let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while ack.load(Ordering::Acquire) != m {
                assert!(
                    std::time::Instant::now() < end,
                    "swapper stuck entering mode {m}"
                );
                std::thread::yield_now();
            }
        };
        let inner_entries = || {
            std::fs::read_dir(&inner)
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        };
        let mut ok = 0u32;
        let mut refused = 0u32;
        let mut swapped = 0u32;
        // 420 coordinated deferred attempts
        // (open-while-parked-dangling, so every open binds None —
        // strict): 10 calm-X1 (stable success + strict reload),
        // 10 calm-inner (containment refusal before any staging
        // write), 400 storm (tight X1↔X2↔inner flips across
        // open→validate windows — trips are ~3%/attempt on this
        // fs, so volume carries the occupant-match proof while
        // successes bind X1/X2 only and inner never lands).
        for attempt in 0..420 {
            park(0);
            let mut presenter = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
                .expect("parked-dangling open succeeds");
            assert!(
                presenter.checkpoint_parent_id.is_none(),
                "attempt {attempt}: deferred (unbound) open"
            );
            if attempt < 10 {
                // Calm X1: stable outside success.
                park(1);
                presenter
                    .flush_checkpoint()
                    .expect("attempt {attempt}: stable outside commits");
                ok += 1;
                assert_eq!(
                    presenter.checkpoint_parent_id,
                    Some(x1_id),
                    "attempt {attempt}: binds the validated X1 identity"
                );
                Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
                    .expect("attempt {attempt}: the committed bytes reload");
            } else if attempt < 20 {
                // Calm inner: containment refusal before any
                // staging write.
                park(3);
                let err = presenter
                    .flush_checkpoint()
                    .err()
                    .expect("attempt {attempt}: inside placement refuses");
                refused += 1;
                assert!(
                    format!("{err:?}").contains("outside the producer out-DIR"),
                    "attempt {attempt}: containment names itself: {err:?}"
                );
            } else {
                // Storm: tight X1↔X2↔inner flips across the
                // open→validate window.
                park(2);
                match presenter.flush_checkpoint() {
                    Ok(_) => {
                        ok += 1;
                        let bound = presenter.checkpoint_parent_id.unwrap();
                        assert!(
                            bound == x1_id || bound == x2_id,
                            "attempt {attempt}: success binds a validated outside identity: {bound:?}"
                        );
                        assert_ne!(
                            bound, inner_id,
                            "attempt {attempt}: never the inside identity"
                        );
                    }
                    Err(e) => {
                        refused += 1;
                        if format!("{e:?}").contains("swapped") {
                            swapped += 1;
                        }
                    }
                }
            }
            assert!(
                inner_entries().is_empty(),
                "attempt {attempt}: the inside dir stays empty: {:?}",
                inner_entries()
            );
        }
        park(0);
        done.store(true, Ordering::Relaxed);
        swapper.join().unwrap();
        assert_eq!(ok + refused, 420, "every attempt accounted");
        assert!(ok >= 10, "stable windows succeed");
        assert!(refused >= 10, "inside + raced windows fail closed");
        assert!(swapped >= 1, "mid-write swaps trip the occupant match");
        let inner_entries: Vec<_> = std::fs::read_dir(&inner)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(inner_entries.is_empty(), "inside stays empty at the end");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new75_unreadable_regular_target_replaced_without_read() {
        // P2fix13 NEW-75 (supersedes the P2fix12 NEW-70
        // preservation-readability pin): publish-last removed
        // the preservation read — the write path never reads
        // the target, so an UNREADABLE regular target no
        // longer blocks the commit (durability on refusal no
        // longer depends on reading the bytes back: a refusal
        // never replaces them in the first place). The flush
        // replaces it through the ordinary rename (directory
        // write permission governs) and the fresh checkpoint
        // reloads. (Startup INTAKE unreadability is NEW-76's
        // refusal, pinned separately.)
        use std::os::unix::fs::PermissionsExt as _;
        let base = unique_dir("unreadable-target");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        let before = std::fs::read(&ckpt).unwrap();
        let seq_before = presenter.checkpoint_seq;
        std::fs::set_permissions(&ckpt, std::fs::Permissions::from_mode(0o000)).unwrap();
        presenter
            .flush_checkpoint()
            .expect("the write path never reads the target (publish-last)");
        let after = std::fs::read(&ckpt).unwrap();
        assert_ne!(after, before, "the commit replaced the unreadable target");
        let v: serde_json::Value = serde_json::from_slice(&after).unwrap();
        assert_eq!(
            v["checkpoint_seq"],
            serde_json::json!(seq_before + 1),
            "the replacement carries the new sequence"
        );
        Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
            .expect("the fresh checkpoint reloads");
        assert!(
            staging_residue(&p).is_empty(),
            "zero stage residue after the commit: {:?}",
            staging_residue(&p)
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new69_cleanup_unlink_failure_surfaces() {
        // P2fix12 NEW-69 (+ NEW-26/NEW-45 scope): cleanup must
        // not ignore unlink failures — an EIO stage-write
        // failure in a directory that then resists the
        // cleanup unlink (read-only) surfaces BOTH the write
        // failure AND the cleanup failure (loudly — the
        // operator must know the stage leaked). Pre-fix: the
        // error is the bare EIO (the failed unlink is
        // swallowed) (RED).
        use std::os::unix::fs::PermissionsExt as _;
        let base = unique_dir("cleanup-unlink-failure");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        // After stage creation, before the first byte: lock
        // the dir read-only (the cleanup unlink then fails
        // EACCES) + inject the EIO write failure.
        let p2 = p.clone();
        super::pre_first_write_hook::arm(move || {
            std::fs::set_permissions(&p2, std::fs::Permissions::from_mode(0o555)).unwrap();
        });
        super::stage_fault::arm(1);
        let err = presenter
            .flush_checkpoint()
            .expect_err("the injected EIO must fail the flush");
        super::pre_first_write_hook::disarm();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        // The primary error LEADS (the EIO text survives) and
        // the failed cleanup rides along (composite message —
        // the codebase idiom; `Error::new` keeps kind + text).
        assert!(
            format!("{err:?}").contains("Input/output error"),
            "the injected EIO stays the primary error: {err:?}"
        );
        assert!(
            format!("{err:?}").contains("cleanup"),
            "the failed cleanup unlink surfaces in the error: {err:?}"
        );
        assert!(
            !staging_residue(&p).is_empty(),
            "premise: the stage really leaked (the unlink genuinely failed)"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new69_movement_within_mutation_interval_accounted() {
        // P2fix12 NEW-69 (+ NEW-13/NEW-26/NEW-34/NEW-50/NEW-56/
        // NEW-61/NEW-66-OPEN; P2fix15 NEW-87 semantics —
        // supersedes the P2fix14 NEW-80 withdrawal:
        // withdrawal is placement-bound): movement scheduled
        // at EVERY hook point WITHIN the mutation interval
        // refuses with the last committed bytes intact (never
        // replaced — publish-last): moves before stage
        // creation leave no stage at all; a move at/after
        // creation leaves the owned stage standing DECLARED
        // (never unlinked beneath the producer — the refusal
        // declares it). Pre-fix: late schedules mutate
        // beneath the producer and the final gap restores
        // from memory (RED).
        let points = [
            "post_validation",
            "post_staging_check",
            "post_create_check",
            "pre_first_write",
            "mid_write",
            "pre_commit",
            "post_commit_check",
            "pre_rename",
        ];
        for point in points {
            let base = unique_dir(&format!("mutation-interval-{point}"));
            let out = base.join("out");
            std::fs::create_dir_all(&out).unwrap();
            let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
            std::fs::write(
                out.join("window-0000000000.json"),
                serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
            )
            .unwrap();
            let p = base.join("p");
            std::fs::create_dir_all(&p).unwrap();
            let ckpt = p.join("ckpt.json");
            let mut presenter =
                Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
            presenter.build_service().expect("first fold commits");
            let before = std::fs::read(&ckpt).unwrap();
            let target = out.join("p-moved");
            let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let mk = || {
                let (p2, target2, ran2) = (p.clone(), target.clone(), ran.clone());
                move || {
                    std::fs::rename(&p2, &target2).unwrap();
                    ran2.store(true, std::sync::atomic::Ordering::Relaxed);
                }
            };
            match point {
                "post_validation" => super::post_validation_hook::arm(mk()),
                "post_staging_check" => super::post_staging_check_hook::arm(mk()),
                "post_create_check" => super::post_create_check_hook::arm(mk()),
                "pre_first_write" => super::pre_first_write_hook::arm(mk()),
                "mid_write" => super::mid_write_hook::arm(mk()),
                "pre_commit" => super::pre_commit_hook::arm(mk()),
                "post_commit_check" => super::post_commit_check_hook::arm(mk()),
                "pre_rename" => super::pre_rename_hook::arm(mk()),
                _ => unreachable!(),
            }
            let err = presenter
                .flush_checkpoint()
                .expect_err(&format!("a move at {point} must refuse"));
            match point {
                "post_validation" => super::post_validation_hook::disarm(),
                "post_staging_check" => super::post_staging_check_hook::disarm(),
                "post_create_check" => super::post_create_check_hook::disarm(),
                "pre_first_write" => super::pre_first_write_hook::disarm(),
                "mid_write" => super::mid_write_hook::disarm(),
                "pre_commit" => super::pre_commit_hook::disarm(),
                "post_commit_check" => super::post_commit_check_hook::disarm(),
                "pre_rename" => super::pre_rename_hook::disarm(),
                _ => unreachable!(),
            }
            assert!(
                ran.load(std::sync::atomic::Ordering::Relaxed),
                "the {point} hook ran"
            );
            assert!(
                format!("{err:?}").contains("outside the producer out-DIR"),
                "the {point} refusal names placement: {err:?}"
            );
            // Declared residue per point (P2fix15 NEW-87):
            // pre-creation envelopes created no stage; later
            // points leave the owned stage standing declared
            // (never unlinked beneath the producer — the
            // refusal declares it); no restore file ever
            // appears.
            let entries: Vec<String> = std::fs::read_dir(&target)
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            assert!(
                entries.iter().all(|n| !n.contains(".restore-")),
                "no restore write after a {point} move: {entries:?}"
            );
            match point {
                "post_validation" | "post_staging_check" | "post_create_check" => {
                    assert!(
                        staging_residue(&target).is_empty(),
                        "no stage was created before a {point} refusal: {:?}",
                        staging_residue(&target)
                    );
                }
                _ => {
                    assert!(
                        format!("{err:?}").contains("stage left in place"),
                        "the {point} refusal declares the left stage: {err:?}"
                    );
                    let (stage_name, _, _) = single_left_stage(&target);
                    assert!(!stage_name.is_empty(), "the {point} stage stands declared");
                }
            }
            assert_eq!(
                std::fs::read(target.join("ckpt.json")).unwrap(),
                before,
                "the committed bytes survive a {point} move (never replaced)"
            );
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    #[test]
    fn new76_socket_checkpoint_refuses_by_kind() {
        // P2fix13 NEW-76 (socket arm — promoted from the
        // Tier-1 probe that found the ENXIO path bypassed
        // the regularity wording): a unix-domain SOCKET at
        // the checkpoint path refuses by KIND naming
        // regularity, before any open is attempted (the
        // open itself would refuse ENXIO without touching
        // the object, so a connect attempt can never stall
        // intake).
        use std::os::unix::net::UnixListener;
        let base = unique_dir("intake-socket");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let ckpt = base.join("ckpt.json");
        let _sock = UnixListener::bind(&ckpt).expect("bind the socket");
        let err = open_bounded(&out, &ckpt, 10).expect("a socket refuses promptly");
        assert!(
            err.contains("regular file"),
            "the socket refusal names regularity: {err}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new74_tripwire_observes_move_self_and_delete_via_fd_watch() {
        // P2fix13 NEW-74 (mechanism premise): the guard's
        // fd-bound inotify watch observes the OPENED
        // directory's own relocation (through its
        // `/proc/self/fd` binding, never a pathname
        // resolution) — including a move that REVERSES
        // between drains — and chain destruction refuses.
        let base = unique_dir("tripwire-mechanism");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let display = p.join("ckpt.json");
        let fd = std::fs::File::open(&p).unwrap();
        let guard = super::PlacementGuard::arm(&fd, &display).expect("the guard arms");
        // Still + outside: both envelopes prove.
        guard
            .prove_before(&fd, &out, "staging", &display)
            .expect("stationary outside proves");
        guard
            .prove_after(&fd, &out, "staging", &display)
            .expect("no wake events while stationary");
        // Move inside and BACK between drains: the movement
        // is observed (move_self recorded), the pre-mutation
        // envelope still proves on present position (no
        // mutation overlapped the excursion), and the
        // post-mutation envelope refuses a step whose wake
        // contains a move.
        assert_eq!(super::tripwire_probe::take(), 0);
        let inside = out.join("p-in");
        let back = base.join("p-back");
        std::fs::rename(&p, &inside).unwrap();
        std::fs::rename(&inside, &back).unwrap();
        guard
            .prove_before(&fd, &out, "commit", &display)
            .expect("reversed excursion: present position outside proves");
        assert!(
            super::tripwire_probe::take() >= 1,
            "the reversed move was DETECTED by the tripwire"
        );
        // A move in a step's wake refuses that step.
        std::fs::rename(&back, &p).unwrap();
        guard
            .prove_before(&fd, &out, "first write", &display)
            .expect("drain the scheduling move");
        let moved = base.join("p-moved");
        std::fs::rename(&p, &moved).unwrap();
        assert!(
            guard
                .prove_after(&fd, &out, "first write (post)", &display)
                .is_err(),
            "a move in the step's wake refuses"
        );
        // Parked inside: present position refuses.
        let inside2 = out.join("p-in2");
        std::fs::rename(&moved, &inside2).unwrap();
        assert!(
            guard
                .prove_before(&fd, &out, "commit rename", &display)
                .is_err(),
            "inside placement refuses"
        );
        // Chain destruction refuses (watch destroyed/unlinked).
        std::fs::remove_dir_all(&inside2).unwrap();
        assert!(
            guard.prove_before(&fd, &out, "cleanup", &display).is_err(),
            "a destroyed ancestry refuses"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new74_reverse_move_detected_with_no_inside_mutation() {
        // P2fix13 NEW-74 (reverse schedule): a relocation
        // that moves the checkpoint dir UNDER the producer
        // and back outside again BETWEEN envelopes (it
        // reverses before the next check) cannot produce an
        // inside mutation: every mutation is fused behind a
        // tripwire drain + ancestry proof, the excursion is
        // DETECTED (probe), the commit lands through the
        // validated fd at its outside destination, and the
        // producer tree is left with exactly what it held
        // before (no stage, no checkpoint, no new entry).
        // Two arms: reversal to a DIFFERENT outside path,
        // and reversal to the ORIGINAL path (ancestry
        // indistinguishable — the tripwire is the detector).
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        for (tag, back_to_original) in [("reverse-relocated", false), ("reverse-original", true)] {
            let base = unique_dir(tag);
            let out = base.join("out");
            std::fs::create_dir_all(&out).unwrap();
            std::fs::write(
                out.join("window-0000000000.json"),
                serde_json::to_string(&test_envelope(0, 0, run.clone(), 10)).unwrap(),
            )
            .unwrap();
            let out_before: Vec<String> = std::fs::read_dir(&out)
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            let p = base.join("p");
            std::fs::create_dir_all(&p).unwrap();
            let ckpt = p.join("ckpt.json");
            let mut presenter =
                Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
            presenter.build_service().expect("first fold commits");
            let seq_before = presenter.checkpoint_seq;
            let inside = out.join("p-inside");
            let dest = if back_to_original {
                p.clone()
            } else {
                base.join("p-relocated")
            };
            let (p2, in2, dest2) = (p.clone(), inside.clone(), dest.clone());
            let _ = super::tripwire_probe::take();
            // ONE hook invocation performs the whole
            // excursion (inside + back) between envelopes.
            super::pre_commit_hook::arm(move || {
                std::fs::rename(&p2, &in2).unwrap();
                std::fs::rename(&in2, &dest2).unwrap();
            });
            presenter
                .flush_checkpoint()
                .expect("the reversed excursion overlaps no mutation; the commit lands");
            super::pre_commit_hook::disarm();
            assert!(
                super::tripwire_probe::take() >= 1,
                "{tag}: the excursion was DETECTED by the tripwire"
            );
            // The producer tree is byte-for-byte the same
            // population as before (no writer entry persisted
            // inside at any observable point after the write).
            let out_after: Vec<String> = std::fs::read_dir(&out)
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            assert_eq!(
                out_after, out_before,
                "{tag}: no writer mutation persisted beneath the producer"
            );
            // The commit landed through the fd at its outside
            // destination with the bumped sequence.
            let landed = dest.join("ckpt.json");
            let v: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&landed).unwrap()).unwrap();
            assert_eq!(
                v["checkpoint_seq"],
                serde_json::json!(seq_before + 1),
                "{tag}: the new commit settled outside"
            );
            Presenter::open_with_checkpoint(&out, &landed, 1, "export")
                .expect("the landed checkpoint reloads");
            assert!(
                staging_residue(&dest).is_empty(),
                "{tag}: no residue after a settled commit"
            );
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    #[test]
    fn new75_stage_residue_never_adopted_on_reopen() {
        // P2fix13 NEW-75 (process-stop shape): a stage left
        // by a stopped/aborted write — even one carrying a
        // valid body with a HIGHER sequence than the
        // committed target — is never adopted on reopen:
        // authority is the target name only. With NO target,
        // a lone stage reopens FRESH (the unpublished
        // checkpoint does not exist as far as reopen is
        // concerned).
        let base = unique_dir("stage-never-adopted");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        let committed_seq = presenter.checkpoint_seq;
        drop(presenter);
        // Forge a "newer" stage beside the target (valid
        // body, bumped sequence, rehashed).
        let mut forged: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
        forged["checkpoint_seq"] = serde_json::json!(committed_seq + 41);
        rehash_checkpoint(&mut forged);
        let stage = p.join(format!(
            "ckpt.json.staging-{}-{}.0.tmp",
            999,
            committed_seq + 41
        ));
        std::fs::write(&stage, serde_json::to_vec(&forged).unwrap()).unwrap();
        let q = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
            .expect("reopen on the committed target");
        assert_eq!(
            q.checkpoint_seq, committed_seq,
            "the committed target is authoritative, never the newer stage"
        );
        drop(q);
        // Lone-stage shape: no target at all.
        std::fs::remove_file(&ckpt).unwrap();
        let q = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
            .expect("a lone stage reopens fresh");
        assert_eq!(q.checkpoint_seq, 0, "no sequence adopted from a stage");
        assert_eq!(q.watermark, None, "no watermark adopted from a stage");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Re-hash a mutated checkpoint body (P2fix12 NEW-72
    /// negative controls): the sha covers the bare body, so
    /// removing + re-adding it last keeps a crafted body
    /// hash-valid.
    fn rehash_checkpoint(v: &mut serde_json::Value) {
        v.as_object_mut().unwrap().remove("sha256");
        let bytes = serde_json::to_vec(&v).unwrap();
        let hex = sha256_hex(&bytes);
        v.as_object_mut()
            .unwrap()
            .insert("sha256".to_string(), serde_json::json!(hex));
    }

    /// Void the settlement record beside a checkpoint
    /// (P2fix15 NEW-88 — out-of-band craft support): the
    /// record binds WRITER productions only, so a test that
    /// mutates the target out-of-band removes the stale
    /// record alongside the craft (the craft then exercises
    /// the legacy content-validation path, whose rules are
    /// identical on the marker path).
    fn void_settlement(ckpt: &Path) {
        let _ = std::fs::remove_file(super::settled_path(ckpt));
    }

    /// Traced window envelope (P2fix12 NEW-73): a
    /// producer-shaped document carrying a REAL valid
    /// summarized trace plane, so the fold counts as MEASURED
    /// (folded-but-null windows merge into the unmeasured span
    /// instead of breaking it into separate ranges).
    fn traced_envelope(
        seq: u64,
        generation: u64,
        run: serde_json::Value,
        calls: u64,
    ) -> serde_json::Value {
        use crate::provider_observation::trace as t;
        let mut p = t::TraceProducer::new();
        p.set_mode(t::TRACE_MODE_LATENCY);
        let k = t::PairKey {
            pid: 1,
            tid: 2,
            generation: 1,
            cookie: 9000,
            invocation: 1,
        };
        p.attempt(t::AttemptEdge {
            key: k,
            api: 20,
            monotonic_ns: 1000,
            start_time_ns: 1,
            seed: 1,
        });
        p.result(t::ResultEdge {
            key: k,
            api: 20,
            monotonic_ns: 1050,
            outcome: 1,
            start_time_ns: 1,
            seed: 1,
        });
        let window = p.close_window(0, 9000, [0; 8]);
        let totals = p.totals();
        let summary = t::summarize(&window, &totals, "latency", None);
        summary.validate().expect("test trace validates");
        let mut doc = test_document(calls, "complete");
        doc["schema"] = serde_json::json!("observed-crypto-v2.9");
        doc["trace_summary"] = serde_json::to_value(&summary).unwrap();
        test_envelope_with_doc(seq, generation, run, doc)
    }

    /// Scenario checkpoint carrying a VALID preserved record
    /// (P2fix12 NEW-72 controls): publish gen 0, fail a gen-1
    /// prefix after a hole, recover into gen 2. Returns the
    /// out-DIR, the checkpoint path, and the live record.
    fn scenario_checkpoint_with_record(tag: &str) -> (PathBuf, PathBuf, PreservedEpoch) {
        let base = unique_dir(tag);
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run.clone(), 10)).unwrap(),
        )
        .unwrap();
        let ckpt = base.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("gen 0 publishes");
        std::fs::write(
            out.join("window-0000000002.json"),
            serde_json::to_string(&test_envelope(2, 1, run.clone(), 10)).unwrap(),
        )
        .unwrap();
        let mut bad = test_envelope(3, 1, run.clone(), 10);
        bad["schema"] = serde_json::json!("service-window-v9");
        std::fs::write(
            out.join("window-0000000003.json"),
            serde_json::to_string(&bad).unwrap(),
        )
        .unwrap();
        presenter
            .build_service_staged()
            .expect_err("the rejected tail fails the scan");
        std::fs::remove_file(out.join("window-0000000003.json")).unwrap();
        std::fs::write(
            out.join("window-0000000004.json"),
            serde_json::to_string(&test_envelope(4, 2, run.clone(), 10)).unwrap(),
        )
        .unwrap();
        presenter.build_service().expect("recovery builds");
        let prev = presenter
            .previous_epoch()
            .expect("the gen-2 reset preserves gen 1");
        // Forget the base path (the caller owns teardown via
        // the out-DIR's parent).
        let _ = base;
        (out, ckpt, prev)
    }

    #[test]
    fn new72_hash_valid_previous_epoch_binds_to_preceding_epoch() {
        // P2fix12 NEW-72 (+ NEW-67-OPEN): a HASH-VALID
        // checkpoint's `previous_epoch` binds to a DISTINCT
        // preceding epoch with an EARLIER tip and canonical
        // flags + ranges — no-watermark, tip-at-or-after-
        // current, same-generation, reversed/unsorted/
        // overlapping/adjacent ranges, and unsorted/dup/
        // foreign flags all refuse loudly (never applied as
        // earlier evidence). Pre-fix: every crafted body
        // opens fine (RED).
        let (out, ckpt, prev) = scenario_checkpoint_with_record("restore-binding");
        assert_eq!(prev.generation, 1, "premise: the record is gen 1");
        let live: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
        let watermark = live["watermark_seq"].as_u64().expect("premise: watermark");
        let generation = live["generation"].as_u64().expect("premise: generation");
        assert_eq!((generation, watermark), (2, 4), "premise: gen 2 @ tip 4");
        assert_eq!(prev.window_seq, 2, "premise: the record tip is 2");
        // Premise: the untouched body round-trips hash-valid
        // (parse + re-hash without mutation still opens).
        let mut roundtrip = live.clone();
        rehash_checkpoint(&mut roundtrip);
        std::fs::write(&ckpt, serde_json::to_vec(&roundtrip).unwrap()).unwrap();
        drop(
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
                .expect("premise: the rehashed body opens"),
        );
        let cases: Vec<(&str, Box<dyn Fn(&mut serde_json::Value)>)> = vec![
            (
                "no-watermark",
                Box::new(|v: &mut serde_json::Value| {
                    v["generation"] = serde_json::Value::Null;
                    v["watermark_seq"] = serde_json::Value::Null;
                    v["accumulators"]["latest"] = serde_json::Value::Null;
                }),
            ),
            (
                "tip-at-current",
                Box::new(move |v: &mut serde_json::Value| {
                    v["accumulators"]["previous_epoch"]["window_seq"] =
                        serde_json::json!(watermark);
                }),
            ),
            (
                "tip-after-current",
                Box::new(move |v: &mut serde_json::Value| {
                    v["accumulators"]["previous_epoch"]["window_seq"] =
                        serde_json::json!(watermark + 7);
                }),
            ),
            (
                "same-generation",
                Box::new(move |v: &mut serde_json::Value| {
                    v["accumulators"]["previous_epoch"]["generation"] =
                        serde_json::json!(generation);
                }),
            ),
            (
                "reversed-range",
                Box::new(|v: &mut serde_json::Value| {
                    v["accumulators"]["previous_epoch"]["unmeasured"] = serde_json::json!([[5, 2]]);
                }),
            ),
            (
                "unsorted-ranges",
                Box::new(|v: &mut serde_json::Value| {
                    v["accumulators"]["previous_epoch"]["unmeasured"] =
                        serde_json::json!([[5, 6], [1, 2]]);
                }),
            ),
            (
                "overlapping-ranges",
                Box::new(|v: &mut serde_json::Value| {
                    v["accumulators"]["previous_epoch"]["unmeasured"] =
                        serde_json::json!([[1, 3], [2, 4]]);
                }),
            ),
            (
                "adjacent-ranges",
                Box::new(|v: &mut serde_json::Value| {
                    v["accumulators"]["previous_epoch"]["unmeasured"] =
                        serde_json::json!([[1, 2], [3, 4]]);
                }),
            ),
            (
                "unsorted-flags",
                Box::new(|v: &mut serde_json::Value| {
                    let flags = v["accumulators"]["previous_epoch"]["unstable"]
                        .as_array()
                        .unwrap()
                        .clone();
                    assert!(flags.len() > 1, "premise: several flags to reorder");
                    let mut rev = flags;
                    rev.reverse();
                    v["accumulators"]["previous_epoch"]["unstable"] = serde_json::Value::Array(rev);
                }),
            ),
            (
                "dup-flag",
                Box::new(|v: &mut serde_json::Value| {
                    let first = v["accumulators"]["previous_epoch"]["unstable"][0].clone();
                    v["accumulators"]["previous_epoch"]["unstable"]
                        .as_array_mut()
                        .unwrap()
                        .push(first);
                }),
            ),
            (
                "foreign-flag",
                Box::new(|v: &mut serde_json::Value| {
                    v["accumulators"]["previous_epoch"]["unstable"]
                        .as_array_mut()
                        .unwrap()
                        .push(serde_json::json!("bogus.flag"));
                }),
            ),
        ];
        for (name, mutate) in cases {
            let mut crafted = live.clone();
            mutate(&mut crafted);
            rehash_checkpoint(&mut crafted);
            std::fs::write(&ckpt, serde_json::to_vec(&crafted).unwrap()).unwrap();
            void_settlement(&ckpt);
            let err = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
                .expect_err(&format!("{name}: a misbound record must refuse"));
            assert!(
                format!("{err:?}").contains("previous_epoch"),
                "{name}: the refusal names the record: {err:?}"
            );
        }
        let _ = std::fs::remove_dir_all(out.parent().unwrap());
    }

    #[test]
    fn new72_legacy_checkpoint_without_previous_epoch_restores() {
        // P2fix12 NEW-72 (legacy-absence control): a hash-valid
        // checkpoint WITHOUT the record (old writer) restores
        // with no preservation (absence keeps its meaning).
        // Guard (holds pre/post).
        let (out, ckpt, _) = scenario_checkpoint_with_record("restore-legacy");
        let live: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
        let mut stripped = live.clone();
        stripped["accumulators"]
            .as_object_mut()
            .unwrap()
            .remove("previous_epoch");
        rehash_checkpoint(&mut stripped);
        std::fs::write(&ckpt, serde_json::to_vec(&stripped).unwrap()).unwrap();
        void_settlement(&ckpt);
        let q = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
            .expect("a legacy checkpoint without the record opens");
        assert_eq!(
            q.previous_epoch(),
            None,
            "absence restores to no preservation"
        );
        assert_eq!(q.watermark, Some(4), "the watermark restores");
        let _ = std::fs::remove_dir_all(out.parent().unwrap());
    }

    #[test]
    fn new72_valid_previous_epoch_reopens_exact() {
        // P2fix12 NEW-72 (valid-reopen control): a hash-valid
        // checkpoint WITH a well-bound record reopens with the
        // record intact (gen, tip, counts, lanes, flags,
        // ranges — exactly). Guard (holds pre/post).
        let (out, ckpt, prev) = scenario_checkpoint_with_record("restore-valid");
        let q = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
            .expect("a well-bound checkpoint opens");
        assert_eq!(q.previous_epoch(), Some(prev), "the record reopens exactly");
        let _ = std::fs::remove_dir_all(out.parent().unwrap());
    }

    /// Open a presenter on a thread with a hard bound
    /// (P2fix13 NEW-76 pins): a blocked open (the pre-fix
    /// FIFO stall) fails the pin in bounded time instead of
    /// wedging the harness. Returns the open's error text, or
    /// `None` when the open succeeded.
    fn open_bounded(out: &Path, ckpt: &Path, secs: u64) -> Option<String> {
        let (out, ckpt) = (out.to_path_buf(), ckpt.to_path_buf());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(
                match Presenter::open_with_checkpoint(&out, &ckpt, 1, "export") {
                    Ok(_) => None,
                    Err(e) => Some(format!("{e:?}")),
                },
            );
        });
        rx.recv_timeout(std::time::Duration::from_secs(secs))
            .expect("the open returns within the bound (no intake stall)")
    }

    fn mkfifo_at(path: &Path) {
        // SAFETY: mkfifo on a fresh private path.
        assert_eq!(
            unsafe {
                libc::mkfifo(
                    std::ffi::CString::new(path.to_str().unwrap())
                        .unwrap()
                        .as_ptr(),
                    0o600,
                )
            },
            0,
            "mkfifo succeeds"
        );
    }

    #[test]
    fn new76_nonregular_checkpoint_refuses_at_startup() {
        // P2fix13 NEW-76 (startup arm): checkpoint intake is a
        // BOUNDED regular-file read — a FIFO at the checkpoint
        // path refuses promptly (pre-fix: the blocking
        // `fs::read` open stalls forever — the bounded-open
        // harness convicts), a directory or symlink refuses,
        // and an oversize regular file refuses past the intake
        // bound. A valid checkpoint still opens (guard).
        // Healthy control first: a real checkpoint opens.
        let (out, ckpt, _) = scenario_checkpoint_with_record("intake-control");
        assert_eq!(
            open_bounded(&out, &ckpt, 10),
            None,
            "a valid checkpoint opens"
        );
        let valid_bytes = std::fs::read(&ckpt).unwrap();
        // FIFO at the target path.
        std::fs::remove_file(&ckpt).unwrap();
        mkfifo_at(&ckpt);
        let err = open_bounded(&out, &ckpt, 10).expect("the FIFO refuses promptly");
        assert!(
            err.contains("regular file"),
            "the FIFO refusal names regularity: {err}"
        );
        // Directory at the target path.
        std::fs::remove_file(&ckpt).unwrap();
        std::fs::create_dir_all(&ckpt).unwrap();
        let err = open_bounded(&out, &ckpt, 10).expect("a directory refuses");
        assert!(
            err.contains("regular file"),
            "the directory refusal names regularity: {err}"
        );
        std::fs::remove_dir_all(&ckpt).unwrap();
        // Symlink to a VALID checkpoint (substitution class —
        // the write side never follows target links either).
        let real = out.parent().unwrap().join("real-ckpt.json");
        std::fs::write(&real, &valid_bytes).unwrap();
        std::os::unix::fs::symlink(&real, &ckpt).unwrap();
        let err = open_bounded(&out, &ckpt, 10).expect("a symlink refuses");
        assert!(
            err.contains("checkpoint"),
            "the symlink refusal names the checkpoint: {err}"
        );
        std::fs::remove_file(&ckpt).unwrap();
        // Oversize regular file (past the intake bound).
        let big = std::fs::File::create(&ckpt).unwrap();
        big.set_len(super::CHECKPOINT_MAX_BYTES + 1).unwrap();
        drop(big);
        let err = open_bounded(&out, &ckpt, 10).expect("an oversize target refuses");
        assert!(
            err.contains("intake bound"),
            "the oversize refusal names the bound: {err}"
        );
        let _ = std::fs::remove_dir_all(out.parent().unwrap());
    }

    #[test]
    fn new76_fifo_substituted_target_refuses_at_refresh() {
        // P2fix13 NEW-76 (refresh arm): a FIFO substituted at
        // the checkpoint target after a healthy start refuses
        // the next flush PROMPTLY (pre-fix: the preservation
        // read blocks on the FIFO open — the bounded-flush
        // harness convicts) without touching the FIFO; once
        // the substitution is removed the flush recovers.
        let base = unique_dir("intake-refresh");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let p_dir = base.join("p");
        std::fs::create_dir_all(&p_dir).unwrap();
        let ckpt = p_dir.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("healthy commit");
        // Substitute the FIFO.
        std::fs::remove_file(&ckpt).unwrap();
        mkfifo_at(&ckpt);
        // Flush on a thread with a hard bound.
        let (tx, rx) = std::sync::mpsc::channel();
        let mut moved = presenter;
        let handle = std::thread::spawn(move || {
            let result = moved.flush_checkpoint().map_err(|e| format!("{e:?}"));
            let _ = tx.send((moved, result));
        });
        let (mut presenter, result) = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the flush returns within the bound (no refresh stall)");
        handle.join().unwrap();
        let err = result.expect_err("the FIFO target refuses the flush");
        assert!(
            err.contains("regular file"),
            "the refresh refusal names regularity: {err}"
        );
        // The FIFO is untouched (still a FIFO) and no stage
        // residue persists (placement held — cleanup ran).
        use std::os::unix::fs::FileTypeExt as _;
        assert!(
            std::fs::metadata(&ckpt).unwrap().file_type().is_fifo(),
            "the substituted FIFO is never replaced by the refused flush"
        );
        assert!(
            staging_residue(&p_dir).is_empty(),
            "zero stage residue: {:?}",
            staging_residue(&p_dir)
        );
        // Recovery: remove the substitution; the flush commits.
        std::fs::remove_file(&ckpt).unwrap();
        presenter
            .flush_checkpoint()
            .expect("post-substitution flush");
        Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
            .expect("the recovered checkpoint reloads");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new79_hash_valid_previous_epoch_lane_sum_binds() {
        // P2fix13 NEW-79: a HASH-VALID restored `previous_epoch`
        // must satisfy the writer's saturated lane-sum invariant
        // (`calls_total` == saturated sum of the four lanes) —
        // a hash-valid disagreement refuses loudly (never
        // reaches the terminal/JSON previous-epoch payloads).
        // Pre-fix: the reader type-checks both and the gate
        // accepts the contradiction (RED).
        let (out, ckpt, prev) = scenario_checkpoint_with_record("restore-lane-sum");
        let live: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
        let lane_sum: u64 = prev.lanes.iter().fold(0u64, |a, &l| a.saturating_add(l));
        assert_eq!(
            prev.calls_total, lane_sum,
            "premise: the writer record satisfies the invariant"
        );
        assert!(lane_sum > 0, "premise: nonzero lanes to disagree with");
        // Negative controls: every disagreement refuses naming
        // the record.
        let mismatches: Vec<(&str, [u64; 4], u64)> = vec![
            ("sum-minus-one", prev.lanes, lane_sum - 1),
            ("sum-plus-one", prev.lanes, lane_sum + 1),
            ("zero-calls", prev.lanes, 0),
            // The WRAPPING sum of saturated lanes is not the
            // saturated sum (MAX + MAX wraps to MAX-1; the
            // writer saturates to MAX).
            ("wrapped-sum", [u64::MAX, u64::MAX, 0, 0], u64::MAX - 1),
            ("saturated-lanes-low-calls", [u64::MAX, 1, 0, 0], 7),
        ];
        for (name, lanes, calls) in mismatches {
            let mut crafted = live.clone();
            crafted["accumulators"]["previous_epoch"]["lanes"] = serde_json::json!(lanes);
            crafted["accumulators"]["previous_epoch"]["calls_total"] = serde_json::json!(calls);
            rehash_checkpoint(&mut crafted);
            std::fs::write(&ckpt, serde_json::to_vec(&crafted).unwrap()).unwrap();
            void_settlement(&ckpt);
            let err = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
                .expect_err(&format!("{name}: a lane-sum mismatch must refuse"));
            assert!(
                format!("{err:?}").contains("previous_epoch"),
                "{name}: the refusal names the record: {err:?}"
            );
        }
        // Positive guards: the untouched writer record reopens
        // (the new72 guard covers it too), and an exactly
        // SATURATED sum opens (the writer saturates — MAX with
        // lanes summing past MAX is writer-legit).
        let mut saturated = live.clone();
        saturated["accumulators"]["previous_epoch"]["lanes"] =
            serde_json::json!([u64::MAX, 1, 0, 0]);
        saturated["accumulators"]["previous_epoch"]["calls_total"] = serde_json::json!(u64::MAX);
        rehash_checkpoint(&mut saturated);
        std::fs::write(&ckpt, serde_json::to_vec(&saturated).unwrap()).unwrap();
        void_settlement(&ckpt);
        let q = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
            .expect("an exactly saturated lane sum opens");
        assert_eq!(
            q.previous_epoch().map(|p| p.calls_total),
            Some(u64::MAX),
            "the saturated record restores verbatim"
        );
        let _ = std::fs::remove_dir_all(out.parent().unwrap());
    }

    #[test]
    fn new71_published_prefix_and_uncertainty_survive_reset() {
        // P2fix12 NEW-71 (+ NEW-P2c/NEW-67-OPEN): publish an
        // epoch, then accept MORE windows in that same epoch
        // before a rejected tail — recovery into the next
        // generation preserves the FINAL accepted prefix +
        // uncertainty (not the stale published tip). Two
        // schedules: (A) the tip advances past publication;
        // (B) the tip holds but the failed scan accrues hole
        // uncertainty. Both observe the EXACT failed prefix
        // BEFORE advancing. Pre-fix: the published shortcut
        // clears the newer prefix (None) (RED).
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        // Schedule A: tip advances past publication.
        {
            let base = unique_dir("published-prefix-advanced");
            let out = base.join("out");
            std::fs::create_dir_all(&out).unwrap();
            std::fs::write(
                out.join("window-0000000000.json"),
                serde_json::to_string(&test_envelope(0, 0, run.clone(), 10)).unwrap(),
            )
            .unwrap();
            let ckpt = base.join("ckpt.json");
            let mut presenter =
                Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
            presenter.build_service().expect("gen 0 publishes at tip 0");
            assert_eq!(presenter.published_generation, Some(0));
            assert_eq!(presenter.watermark, Some(0));
            for (seq, calls) in [(1u64, 20u64), (2, 30)] {
                std::fs::write(
                    out.join(format!("window-{seq:010}.json")),
                    serde_json::to_string(&test_envelope(seq, 0, run.clone(), calls)).unwrap(),
                )
                .unwrap();
            }
            let mut bad = test_envelope(3, 0, run.clone(), 10);
            bad["schema"] = serde_json::json!("service-window-v9");
            std::fs::write(
                out.join("window-0000000003.json"),
                serde_json::to_string(&bad).unwrap(),
            )
            .unwrap();
            presenter
                .build_service()
                .expect_err("the rejected tail fails the scan");
            // The EXACT failed prefix, observed BEFORE advancing.
            assert_eq!(presenter.generation, Some(0), "still gen 0");
            assert_eq!(presenter.watermark, Some(2), "the prefix tip is 2");
            assert_eq!(presenter.calls_total, 60, "10 + 20 + 30 accepted");
            assert_eq!(presenter.lanes, [60, 0, 0, 0]);
            assert_eq!(
                presenter.trace_unmeasured,
                vec![[0u64, 2u64]],
                "the folded-but-null span survives"
            );
            assert!(
                presenter.unstable.is_empty(),
                "no hole flags on a contiguous prefix: {:?}",
                presenter.unstable
            );
            assert_eq!(presenter.failed_generation, Some(0), "the tenure failed");
            // Recovery into gen 1 after retention removes the tail.
            std::fs::remove_file(out.join("window-0000000003.json")).unwrap();
            std::fs::write(
                out.join("window-0000000004.json"),
                serde_json::to_string(&test_envelope(4, 1, run.clone(), 7)).unwrap(),
            )
            .unwrap();
            let snap = presenter.build_service().expect("recovery builds");
            assert_eq!(snap.source.generation, Some(1));
            let prev = presenter
                .previous_epoch()
                .expect("the reset preserves the newer prefix");
            assert_eq!(prev.generation, 0);
            assert_eq!(
                prev.window_seq, 2,
                "the preserved tip is 2, not the stale 0"
            );
            assert_eq!(
                prev.calls_total, 60,
                "the preserved counts are final, not stale"
            );
            assert_eq!(prev.lanes, [60, 0, 0, 0]);
            assert_eq!(prev.unmeasured, vec![[0u64, 2u64]]);
            // Persist + reopen.
            let ckpt_json: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&ckpt).unwrap()).unwrap();
            assert_eq!(
                ckpt_json["accumulators"]["previous_epoch"]["calls_total"],
                serde_json::json!(60),
                "the checkpoint persists the final prefix"
            );
            drop(presenter);
            let q = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
                .expect("the recovery checkpoint reloads");
            assert_eq!(
                q.previous_epoch(),
                Some(prev),
                "the newer prefix survives the reopen"
            );
            let _ = std::fs::remove_dir_all(&base);
        }
        // Schedule B: the tip holds at publication but the
        // failed scan accrues hole uncertainty.
        {
            let base = unique_dir("published-prefix-failed");
            let out = base.join("out");
            std::fs::create_dir_all(&out).unwrap();
            std::fs::write(
                out.join("window-0000000000.json"),
                serde_json::to_string(&test_envelope(0, 0, run.clone(), 10)).unwrap(),
            )
            .unwrap();
            let ckpt = base.join("ckpt.json");
            let mut presenter =
                Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
            presenter.build_service().expect("gen 0 publishes at tip 0");
            let mut bad = test_envelope(2, 0, run.clone(), 10);
            bad["schema"] = serde_json::json!("service-window-v9");
            std::fs::write(
                out.join("window-0000000002.json"),
                serde_json::to_string(&bad).unwrap(),
            )
            .unwrap();
            presenter
                .build_service()
                .expect_err("the rejected tail fails the scan");
            // The EXACT failed prefix, observed BEFORE advancing.
            assert_eq!(presenter.watermark, Some(0), "no new tip folded");
            assert_eq!(presenter.calls_total, 10, "only the published window");
            assert_eq!(
                presenter.trace_unmeasured,
                vec![[0u64, 1u64]],
                "the published span + the hole"
            );
            assert_eq!(presenter.unstable.len(), 8, "the hole flags accrue");
            assert_eq!(presenter.failed_generation, Some(0), "the tenure failed");
            // Recovery into gen 1 after retention removes the tail.
            std::fs::remove_file(out.join("window-0000000002.json")).unwrap();
            std::fs::write(
                out.join("window-0000000003.json"),
                serde_json::to_string(&test_envelope(3, 1, run.clone(), 7)).unwrap(),
            )
            .unwrap();
            let snap = presenter.build_service().expect("recovery builds");
            assert_eq!(snap.source.generation, Some(1));
            let prev = presenter
                .previous_epoch()
                .expect("the reset preserves the failed prefix");
            assert_eq!(prev.generation, 0);
            assert_eq!(prev.window_seq, 0, "the tip holds at publication");
            assert_eq!(prev.calls_total, 10);
            assert_eq!(prev.unstable.len(), 8, "the accrued flags survive");
            assert_eq!(
                prev.unmeasured,
                vec![[0u64, 1u64]],
                "the hole span survives"
            );
            drop(presenter);
            let q = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
                .expect("the recovery checkpoint reloads");
            assert_eq!(
                q.previous_epoch(),
                Some(prev),
                "the failed prefix survives the reopen"
            );
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    #[test]
    fn new77_coalesced_resets_keep_accepted_predecessor() {
        // P2fix13 NEW-77 (+ NEW-P2c/NEW-67-OPEN): gen 0
        // published, a gen-1 prefix accepted before a rejected
        // tail, then gen 2 AND gen 3 folded in ONE recovery
        // scan — the preserved predecessor is gen 1 (with its
        // uncertainty), never stale gen 0 and never dropped.
        // Pre-fix: the second reset (clean unpublished gen 2)
        // clears the record (RED). Schedule B guards the
        // published-clean clear (an outgoing epoch that
        // published cleanly still supersedes an older record
        // exactly).
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        // Schedule A: two generation changes in one recovery scan.
        {
            let base = unique_dir("coalesced-resets");
            let out = base.join("out");
            std::fs::create_dir_all(&out).unwrap();
            std::fs::write(
                out.join("window-0000000000.json"),
                serde_json::to_string(&test_envelope(0, 0, run.clone(), 10)).unwrap(),
            )
            .unwrap();
            let ckpt = base.join("ckpt.json");
            let mut presenter =
                Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
            presenter.build_service().expect("gen 0 publishes");
            // Gen-1 prefix after a hole, then a rejected tail.
            std::fs::write(
                out.join("window-0000000002.json"),
                serde_json::to_string(&test_envelope(2, 1, run.clone(), 10)).unwrap(),
            )
            .unwrap();
            let mut bad = test_envelope(3, 1, run.clone(), 10);
            bad["schema"] = serde_json::json!("service-window-v9");
            std::fs::write(
                out.join("window-0000000003.json"),
                serde_json::to_string(&bad).unwrap(),
            )
            .unwrap();
            presenter
                .build_service()
                .expect_err("the rejected gen-1 tail fails the scan");
            // The EXACT failed gen-1 prefix, observed BEFORE
            // advancing (the record the reset must keep).
            assert_eq!(presenter.generation, Some(1));
            assert_eq!(presenter.watermark, Some(2));
            assert_eq!(presenter.calls_total, 10);
            assert_eq!(presenter.lanes, [10, 0, 0, 0]);
            assert_eq!(presenter.failed_generation, Some(1));
            // Recovery: gen 2 and gen 3 in ONE scan.
            std::fs::remove_file(out.join("window-0000000003.json")).unwrap();
            std::fs::write(
                out.join("window-0000000004.json"),
                serde_json::to_string(&test_envelope(4, 2, run.clone(), 20)).unwrap(),
            )
            .unwrap();
            std::fs::write(
                out.join("window-0000000005.json"),
                serde_json::to_string(&test_envelope(5, 3, run.clone(), 30)).unwrap(),
            )
            .unwrap();
            let snap = presenter.build_service().expect("recovery builds");
            assert_eq!(snap.source.generation, Some(3), "gen 3 is current");
            let prev = presenter
                .previous_epoch()
                .expect("the coalesced resets keep the gen-1 predecessor");
            assert_eq!(prev.generation, 1, "predecessor is gen 1, never gen 0");
            assert_eq!(prev.window_seq, 2);
            assert_eq!(prev.calls_total, 10);
            assert_eq!(prev.lanes, [10, 0, 0, 0]);
            assert_eq!(prev.unstable.len(), 8, "gen 1 uncertainty survives");
            assert_eq!(prev.unmeasured, vec![[1u64, 2u64]]);
            // Persist + reopen (two generation changes in one
            // recovery scan survive the checkpoint round trip).
            let ckpt_json: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&ckpt).unwrap()).unwrap();
            assert_eq!(
                ckpt_json["accumulators"]["previous_epoch"]["generation"],
                serde_json::json!(1),
                "the checkpoint persists gen 1"
            );
            drop(presenter);
            let q = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
                .expect("the recovery checkpoint reloads");
            assert_eq!(q.previous_epoch(), Some(prev), "gen 1 survives reopen");
            let _ = std::fs::remove_dir_all(&base);
        }
        // Schedule B (guard): gen 2 PUBLISHES cleanly between
        // the scans — the later gen-3 reset clears the older
        // record (last-good covers the clean published epoch
        // exactly; the keep must not resurrect gen 1 past it).
        {
            let base = unique_dir("coalesced-published-clear");
            let out = base.join("out");
            std::fs::create_dir_all(&out).unwrap();
            std::fs::write(
                out.join("window-0000000000.json"),
                serde_json::to_string(&test_envelope(0, 0, run.clone(), 10)).unwrap(),
            )
            .unwrap();
            let ckpt = base.join("ckpt.json");
            let mut presenter =
                Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
            presenter.build_service().expect("gen 0 publishes");
            std::fs::write(
                out.join("window-0000000002.json"),
                serde_json::to_string(&test_envelope(2, 1, run.clone(), 10)).unwrap(),
            )
            .unwrap();
            let mut bad = test_envelope(3, 1, run.clone(), 10);
            bad["schema"] = serde_json::json!("service-window-v9");
            std::fs::write(
                out.join("window-0000000003.json"),
                serde_json::to_string(&bad).unwrap(),
            )
            .unwrap();
            presenter
                .build_service()
                .expect_err("the rejected gen-1 tail fails the scan");
            std::fs::remove_file(out.join("window-0000000003.json")).unwrap();
            std::fs::write(
                out.join("window-0000000004.json"),
                serde_json::to_string(&test_envelope(4, 2, run.clone(), 20)).unwrap(),
            )
            .unwrap();
            presenter.build_service().expect("gen 2 publishes");
            assert_eq!(
                presenter.previous_epoch().map(|p| p.generation),
                Some(1),
                "premise: gen 1 preserved under published gen 2"
            );
            std::fs::write(
                out.join("window-0000000005.json"),
                serde_json::to_string(&test_envelope(5, 3, run.clone(), 30)).unwrap(),
            )
            .unwrap();
            presenter.build_service().expect("gen 3 builds");
            assert_eq!(
                presenter.previous_epoch(),
                None,
                "a clean published epoch supersedes the older record"
            );
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    #[test]
    fn new65_same_generation_failed_prefix_exact_before_repair() {
        // P2fix12 NEW-65 (+ NEW-67 scope): the same-generation
        // failed prefix is EXACT before repair — a retention
        // hole + a valid prefix + a rejected tail, observed
        // field-for-field (watermark, counts, lanes, ranges,
        // flags, failure mark), THEN repaired in the same
        // generation. Recovery publishes WITH the missing
        // span. Guard (the behavior holds; the exactness is
        // the new coverage).
        let base = unique_dir("samegen-exact-prefix");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run.clone(), 10)).unwrap(),
        )
        .unwrap();
        let ckpt = base.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("gen 0 publishes");
        std::fs::write(
            out.join("window-0000000002.json"),
            serde_json::to_string(&test_envelope(2, 1, run.clone(), 5)).unwrap(),
        )
        .unwrap();
        let mut bad = test_envelope(3, 1, run.clone(), 10);
        bad["schema"] = serde_json::json!("service-window-v9");
        std::fs::write(
            out.join("window-0000000003.json"),
            serde_json::to_string(&bad).unwrap(),
        )
        .unwrap();
        presenter
            .build_service()
            .expect_err("the rejected tail fails the scan");
        // The EXACT failed prefix, observed BEFORE repair.
        assert_eq!(presenter.generation, Some(1), "gen 1 adopted");
        assert_eq!(presenter.watermark, Some(2), "the prefix tip is 2");
        assert_eq!(presenter.calls_total, 5, "the prefix counts only");
        assert_eq!(presenter.lanes, [5, 0, 0, 0]);
        assert_eq!(
            presenter.trace_unmeasured,
            vec![[1u64, 2u64]],
            "the hole + the folded-but-null span"
        );
        assert_eq!(presenter.unstable.len(), 8, "the hole flags");
        assert_eq!(presenter.failed_generation, Some(1), "the tenure failed");
        assert!(presenter.epoch_folded, "the tenure folded");
        // Same-generation repair: the tail heals in place.
        std::fs::write(
            out.join("window-0000000003.json"),
            serde_json::to_string(&test_envelope(3, 1, run.clone(), 7)).unwrap(),
        )
        .unwrap();
        let snap = presenter.build_service().expect("recovery builds");
        assert_eq!(snap.source.generation, Some(1), "same generation");
        assert_eq!(snap.source.window_seq, Some(3), "the repaired tip");
        assert_eq!(presenter.watermark, Some(3));
        assert_eq!(presenter.calls_total, 12, "5 + 7 across the repair");
        assert_eq!(
            presenter.trace_unmeasured,
            vec![[1u64, 3u64]],
            "recovery publishes WITH the missing span"
        );
        assert_eq!(presenter.unstable.len(), 8, "the flags survive repair");
        assert_eq!(
            presenter.previous_epoch(),
            None,
            "same-generation recovery preserves nothing (last-good supersedes)"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new73_bounded_ranges_render_complete_with_exact_omitted_count() {
        // P2fix12 NEW-73 (+ NEW-67-OPEN): a preserved epoch
        // with a 36-range payload through the REAL pipeline
        // (fold 37 windows with 36 retention gaps, fail, reset
        // into the next generation) — the human tail renders
        // COMPLETE bounded entries with an EXACT omitted-range
        // count (never a mid-list cut), the checkpoint persists
        // the full record, and the reopen restores it. Pre-fix:
        // the 200-char cap cuts the line mid-list (RED).
        let base = unique_dir("bounded-ranges");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        for k in 0..37u64 {
            let seq = k * 3;
            std::fs::write(
                out.join(format!("window-{seq:010}.json")),
                serde_json::to_string(&traced_envelope(seq, 0, run.clone(), 1)).unwrap(),
            )
            .unwrap();
        }
        let ckpt = base.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        // Staged (no publication marking — gen 0 stays
        // unpublished, so the NEW-67 arm preserves it
        // pre-fix too and this pin's RED is purely the
        // rendering cut, not the NEW-71 shortcut).
        presenter.build_service_staged().expect("gen 0 folds");
        assert_eq!(
            presenter.trace_unmeasured.len(),
            36,
            "36 retention gaps: {:?}",
            presenter.trace_unmeasured
        );
        let mut bad = test_envelope(109, 0, run.clone(), 1);
        bad["schema"] = serde_json::json!("service-window-v9");
        std::fs::write(
            out.join("window-0000000109.json"),
            serde_json::to_string(&bad).unwrap(),
        )
        .unwrap();
        presenter
            .build_service()
            .expect_err("the rejected tail fails the scan");
        std::fs::remove_file(out.join("window-0000000109.json")).unwrap();
        std::fs::write(
            out.join("window-0000000110.json"),
            serde_json::to_string(&test_envelope(110, 1, run.clone(), 1)).unwrap(),
        )
        .unwrap();
        let snap = presenter.build_service().expect("recovery builds");
        let prev = presenter
            .previous_epoch()
            .expect("the reset preserves gen 0");
        assert_eq!(prev.unmeasured.len(), 36, "the 36 ranges survive");
        // The human tail: bounded, complete entries, exact count.
        let frame = crate::presentation::watch::render_frame_with_prev(
            &snap,
            Some(crate::presentation::watch::PrevEpoch::Preserved(&prev)),
            0,
            &snap.markers,
        );
        let line = frame
            .lines()
            .find(|l| l.starts_with("  prev-unmeasured="))
            .expect("the tail carries the ranges")
            .to_string();
        assert!(
            line.len() <= 200,
            "the line respects the 200-char bound ({}): {line:?}",
            line.len()
        );
        assert!(!line.contains('…'), "no mid-list cut marker: {line:?}");
        // Every shown entry is complete: count `[<digits>,` entry
        // openings; the omitted count is exact.
        let shown = line
            .as_bytes()
            .windows(2)
            .filter(|w| w[0] == b'[' && w[1].is_ascii_digit())
            .count();
        assert!(shown > 0 && shown < 36, "bounded but nonempty: {line:?}");
        assert!(
            line.contains(&format!("+{} more", 36 - shown)),
            "the exact omitted-range count: {line:?}"
        );
        assert!(
            line.starts_with("  prev-unmeasured=[[1, 2], [4, 5]"),
            "complete entries from the front: {line:?}"
        );
        // Persist + reopen: the full record survives.
        drop(presenter);
        let q = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
            .expect("the recovery checkpoint reloads");
        assert_eq!(
            q.previous_epoch().as_ref().map(|p| p.unmeasured.len()),
            Some(36),
            "the 36 ranges survive the reopen"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new80_substitution_between_gate_and_publish_preserved() {
        // P2fix14 NEW-80 (+ NEW-76-OPEN target-identity half):
        // an object substituted at the checkpoint target AFTER
        // the fused publish-gate stat succeeds and before the
        // publish syscall must be DETECTED and PRESERVED —
        // never replaced — and the publish must refuse with
        // the prior bytes authoritative. Three arms: a FIFO, a
        // symlink, and a foreign regular file. Pre-fix: the
        // plain rename replaces the substitute and reports
        // success (RED).
        use std::os::unix::fs::FileTypeExt as _;
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        for arm in ["fifo", "symlink", "regular"] {
            let base = unique_dir(&format!("gate-substitute-{arm}"));
            let out = base.join("out");
            std::fs::create_dir_all(&out).unwrap();
            std::fs::write(
                out.join("window-0000000000.json"),
                serde_json::to_string(&test_envelope(0, 0, run.clone(), 10)).unwrap(),
            )
            .unwrap();
            let p = base.join("p");
            std::fs::create_dir_all(&p).unwrap();
            let ckpt = p.join("ckpt.json");
            let mut presenter =
                Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
            presenter.build_service().expect("first fold commits");
            let before = std::fs::read(&ckpt).unwrap();
            let before_seq = presenter.checkpoint_seq;
            // The substitute, planted by the gate→publish hook
            // (the hook moves the prior target aside first so
            // preservation of BOTH objects is observable).
            let holding = p.join("holding.json");
            let referent = p.join("referent.bin");
            std::fs::write(&referent, b"referent-bytes").unwrap();
            let (ckpt2, holding2, referent2) = (ckpt.clone(), holding.clone(), referent.clone());
            let arm2 = arm.to_string();
            let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let ran2 = ran.clone();
            super::pre_exchange_hook::arm(move || {
                std::fs::rename(&ckpt2, &holding2).unwrap();
                match arm2.as_str() {
                    "fifo" => {
                        // SAFETY: mkfifo on a fresh private path.
                        assert_eq!(
                            unsafe {
                                libc::mkfifo(
                                    std::ffi::CString::new(ckpt2.to_str().unwrap())
                                        .unwrap()
                                        .as_ptr(),
                                    0o600,
                                )
                            },
                            0
                        );
                    }
                    "symlink" => {
                        std::os::unix::fs::symlink(&referent2, &ckpt2).unwrap();
                    }
                    _ => {
                        std::fs::write(&ckpt2, b"foreign-regular-bytes").unwrap();
                    }
                }
                ran2.store(true, std::sync::atomic::Ordering::Relaxed);
            });
            let err = presenter
                .flush_checkpoint()
                .expect_err("a gate→publish substitution must refuse");
            super::pre_exchange_hook::disarm();
            assert!(
                ran.load(std::sync::atomic::Ordering::Relaxed),
                "{arm}: the substitution hook ran between the gate and the publish"
            );
            assert!(
                format!("{err:?}").contains("substituted after the gate"),
                "{arm}: the refusal names the substitution: {err:?}"
            );
            // The substituted object is preserved AT the target
            // (never opened, never replaced — only relinked).
            match arm {
                "fifo" => {
                    assert!(
                        std::fs::symlink_metadata(&ckpt)
                            .unwrap()
                            .file_type()
                            .is_fifo(),
                        "{arm}: the target is still a FIFO"
                    );
                }
                "symlink" => {
                    assert!(
                        std::fs::symlink_metadata(&ckpt)
                            .unwrap()
                            .file_type()
                            .is_symlink(),
                        "{arm}: the symlink still stands at the target"
                    );
                    assert_eq!(
                        std::fs::read_link(&ckpt).unwrap(),
                        referent,
                        "{arm}: the link still names its referent"
                    );
                    assert_eq!(
                        std::fs::read(&referent).unwrap(),
                        b"referent-bytes",
                        "{arm}: the referent is untouched"
                    );
                }
                _ => {
                    assert_eq!(
                        std::fs::read(&ckpt).unwrap(),
                        b"foreign-regular-bytes",
                        "{arm}: the foreign regular file still stands at the target"
                    );
                }
            }
            // The prior committed bytes sit aside untouched,
            // and no stage residue remains.
            assert_eq!(
                std::fs::read(&holding).unwrap(),
                before,
                "{arm}: the prior bytes were never touched"
            );
            assert!(
                staging_residue(&p).is_empty(),
                "{arm}: no stage residue: {:?}",
                staging_residue(&p)
            );
            // Restore + reopen: the prior transaction stands.
            std::fs::remove_file(&ckpt).unwrap();
            std::fs::rename(&holding, &ckpt).unwrap();
            let q = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
                .expect("reopen on the prior committed checkpoint");
            assert_eq!(
                q.checkpoint_seq, before_seq,
                "{arm}: reopen adopts the prior sequence"
            );
            assert_eq!(q.watermark, Some(0), "{arm}: the prior watermark stands");
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    #[test]
    fn new80_move_between_proof_and_publish_left_standing() {
        // P2fix14 NEW-80 (+ NEW-13/NEW-34/NEW-50/NEW-56/
        // NEW-61/NEW-66-OPEN; leave arm P2fix15 NEW-87 —
        // supersedes the P2fix14 inside swapback: withdrawal
        // is placement-bound): a move AFTER the final publish
        // proof returns and before/during the publish syscall
        // must not COMPLETE publication beneath the producer:
        // the post-publish verification detects the interval
        // move and leaves the unsettled publish STANDING
        // declared (no swapback beneath the producer — prior
        // authority via the settlement record), reporting
        // failure — never success. Pre-fix: no post-publish
        // check exists, so the commit lands inside and
        // reports success (RED).
        let base = unique_dir("proof-publish-move");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        let before = std::fs::read(&ckpt).unwrap();
        let before_seq = presenter.checkpoint_seq;
        let inside = out.join("p-inside");
        let (p2, in2) = (p.clone(), inside.clone());
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran2 = ran.clone();
        let _ = super::tripwire_probe::take();
        super::post_exchange_hook::arm(move || {
            std::fs::rename(&p2, &in2).unwrap();
            ran2.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        let err = presenter
            .flush_checkpoint()
            .expect_err("an interval move must withdraw the publish");
        super::post_exchange_hook::disarm();
        assert!(
            ran.load(std::sync::atomic::Ordering::Relaxed),
            "the relocation hook ran in the proof→publish interval"
        );
        assert!(
            super::tripwire_probe::take() >= 1,
            "the interval move was DETECTED by the tripwire"
        );
        assert!(
            format!("{err:?}").contains("moved during write"),
            "the refusal names the interval move: {err:?}"
        );
        assert!(
            format!("{err:?}").contains("left standing"),
            "the refusal declares the standing publish (no inside swapback): {err:?}"
        );
        assert!(
            !format!("{err:?}").contains("prior checkpoint restored"),
            "no swapback ran beneath the producer: {err:?}"
        );
        // Standing declared inside: the unsettled replacement
        // at the target (the exchange ran pre-move), the
        // prior under the stage name — both byte-exact, plus
        // the untouched settlement record.
        let target_now: serde_json::Value =
            serde_json::from_slice(&std::fs::read(inside.join("ckpt.json")).unwrap()).unwrap();
        assert_eq!(
            target_now["checkpoint_seq"],
            serde_json::json!(before_seq + 1),
            "the target carries the unsettled replacement (exchange ran pre-move)"
        );
        let (stage_name, _, _) = single_left_stage(&inside);
        assert_eq!(
            std::fs::read(inside.join(&stage_name)).unwrap(),
            before,
            "the aside bytes are the prior checkpoint byte-identical"
        );
        let mut entries: Vec<String> = std::fs::read_dir(&inside)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        entries.sort();
        assert_eq!(
            entries,
            vec![
                "ckpt.json".to_string(),
                "ckpt.json.settled".to_string(),
                stage_name,
            ],
            "only the standing publish + the record stand inside: {entries:?}"
        );
        // Return outside + reopen: the prior transaction stands
        // via the settlement record.
        let back = base.join("p-back");
        std::fs::rename(&inside, &back).unwrap();
        let q = Presenter::open_with_checkpoint(&out, &back.join("ckpt.json"), 1, "export")
            .expect("reopen adopts the marker-bound prior");
        assert_eq!(
            q.checkpoint_seq, before_seq,
            "reopen adopts the prior committed sequence"
        );
        assert_eq!(q.watermark, Some(0), "the prior watermark stands");
        assert!(
            q.recovered_unsettled_prior(),
            "the reopen reports the prior-settlement recovery"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new80_reversed_move_between_proof_and_publish_withdrawn() {
        // P2fix14 NEW-80 (reversal schedule): a move that
        // reverses BEFORE the next check (inside and back
        // outside within the proof→publish interval —
        // ancestry indistinguishable at the ends) must still
        // be DETECTED (tripwire) and the unsettled publish
        // WITHDRAWN (prior bytes authoritative, zero net
        // effect) — never completed. Pre-fix: success is
        // reported with no post-publish check at all (RED).
        let base = unique_dir("proof-publish-reverse");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        let before = std::fs::read(&ckpt).unwrap();
        let before_seq = presenter.checkpoint_seq;
        let inside = out.join("p-inside");
        let (p2, in2, p3) = (p.clone(), inside.clone(), p.clone());
        let _ = super::tripwire_probe::take();
        super::post_exchange_hook::arm(move || {
            std::fs::rename(&p2, &in2).unwrap();
            std::fs::rename(&in2, &p3).unwrap();
        });
        let err = presenter
            .flush_checkpoint()
            .expect_err("a reversed interval move must withdraw the publish");
        super::post_exchange_hook::disarm();
        assert!(
            super::tripwire_probe::take() >= 1,
            "the reversed excursion was DETECTED by the tripwire"
        );
        assert!(
            format!("{err:?}").contains("moved during write"),
            "the refusal names the interval move: {err:?}"
        );
        assert_eq!(
            std::fs::read(&ckpt).unwrap(),
            before,
            "the prior bytes were restored (nothing published)"
        );
        assert!(
            staging_residue(&p).is_empty(),
            "no stage residue: {:?}",
            staging_residue(&p)
        );
        // The producer tree holds nothing of the writer's.
        let out_entries: Vec<String> = std::fs::read_dir(&out)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            out_entries,
            vec!["window-0000000000.json".to_string()],
            "no writer entry persisted beneath the producer: {out_entries:?}"
        );
        let q = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
            .expect("reopen on the prior committed checkpoint");
        assert_eq!(
            q.checkpoint_seq, before_seq,
            "reopen adopts the prior committed sequence"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new80_staging_race_leaves_own_bytes_declared() {
        // P2fix14 NEW-80 (+ NEW-26/NEW-66-OPEN — leave arm
        // P2fix15 NEW-87, supersedes the P2fix14 withdrawal:
        // withdrawal is placement-bound): a move racing the
        // staging write refuses BEFORE the sync, and the
        // staged bytes stand DECLARED (never unlinked
        // beneath the possibly-inside directory). Pre-fix:
        // the bytes sit inside through the sync (RED).
        let base = unique_dir("staging-race-withdraw");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        let before = std::fs::read(&ckpt).unwrap();
        let inside = out.join("p-inside");
        let (p2, in2) = (p.clone(), inside.clone());
        super::mid_write_hook::arm(move || {
            std::fs::rename(&p2, &in2).unwrap();
        });
        let err = presenter
            .flush_checkpoint()
            .expect_err("a mid-write move must refuse before the sync");
        super::mid_write_hook::disarm();
        assert!(
            format!("{err:?}").contains("moved during write"),
            "the refusal names the race: {err:?}"
        );
        assert!(
            format!("{err:?}").contains("stage left in place"),
            "the refusal declares the left stage: {err:?}"
        );
        // The moved dir holds the prior checkpoint + its
        // settlement record + the declared stage (never
        // unlinked beneath the producer).
        let (stage_name, stage_len, _) = single_left_stage(&inside);
        assert!(stage_len > 0, "the declared stage carries the staged bytes");
        let mut entries: Vec<String> = std::fs::read_dir(&inside)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        entries.sort();
        assert_eq!(
            entries,
            vec![
                "ckpt.json".to_string(),
                "ckpt.json.settled".to_string(),
                stage_name,
            ],
            "the staged bytes stand declared inside: {entries:?}"
        );
        assert_eq!(
            std::fs::read(inside.join("ckpt.json")).unwrap(),
            before,
            "the prior bytes stand untouched"
        );
        let back = base.join("p-back");
        std::fs::rename(&inside, &back).unwrap();
        Presenter::open_with_checkpoint(&out, &back.join("ckpt.json"), 1, "export")
            .expect("reopen on the prior committed checkpoint");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new80_early_target_gate_refuses_before_staging() {
        // P2fix14 NEW-80 (refuse-before-writing): a nonregular
        // target standing BEFORE the write refuses at an early
        // gate with ZERO staging (no stage is ever created —
        // the publish-boundary gate below stays as the fused
        // freshness check for racing substitutions). Pre-fix:
        // the write stages fully before the late gate refuses
        // (RED — the creation-boundary hook observes staging).
        use std::os::unix::fs::FileTypeExt as _;
        let base = unique_dir("early-target-gate");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        std::fs::remove_file(&ckpt).unwrap();
        // SAFETY: mkfifo on a fresh private path.
        assert_eq!(
            unsafe {
                libc::mkfifo(
                    std::ffi::CString::new(ckpt.to_str().unwrap())
                        .unwrap()
                        .as_ptr(),
                    0o600,
                )
            },
            0
        );
        let staged = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let staged2 = staged.clone();
        super::post_create_check_hook::arm(move || {
            staged2.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        let err = presenter
            .flush_checkpoint()
            .expect_err("a pre-standing FIFO target must refuse");
        super::post_create_check_hook::disarm();
        assert!(
            format!("{err:?}").contains("regular file"),
            "the refusal names target regularity: {err:?}"
        );
        assert!(
            !staged.load(std::sync::atomic::Ordering::Relaxed),
            "zero staging ran before the refusal"
        );
        assert!(
            staging_residue(&p).is_empty(),
            "no stage was ever created: {:?}",
            staging_residue(&p)
        );
        assert!(
            std::fs::symlink_metadata(&ckpt)
                .unwrap()
                .file_type()
                .is_fifo(),
            "the FIFO survives (never opened)"
        );
        // Remove the substitution: recovery commits.
        std::fs::remove_file(&ckpt).unwrap();
        presenter.flush_checkpoint().expect("recovery commits");
        Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("recovery reloads");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new80_unverifiable_stage_declared_not_removed() {
        // P2fix14 NEW-80 (publish identity): a pre-publish
        // freshness check verifies the stage name still
        // refers to OUR OWN stage inode — a foreign object
        // planted at the stage name (here: the owned stage
        // renamed aside + foreign bytes planted at its name)
        // refuses BEFORE the publish, is PRESERVED, and the
        // residue is DECLARED (never unlinked — withdrawal
        // verifies identity too). Pre-fix: no check exists,
        // so the publish renames the planted foreign file
        // onto the target and reports success (RED).
        let base = unique_dir("unverifiable-stage");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        let before = std::fs::read(&ckpt).unwrap();
        let p2 = p.clone();
        super::pre_first_write_hook::arm(move || {
            // The owned stage exists (EMPTY) here: move it
            // aside and plant foreign bytes at its name.
            let residue: Vec<String> = std::fs::read_dir(&p2)
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.contains(".staging-"))
                .collect();
            assert_eq!(residue.len(), 1, "premise: one owned stage stands");
            std::fs::rename(p2.join(&residue[0]), p2.join("aside.bin")).unwrap();
            std::fs::write(p2.join(&residue[0]), b"foreign-stage-name-bytes").unwrap();
        });
        let err = presenter
            .flush_checkpoint()
            .expect_err("the rebound stage name must refuse");
        super::pre_first_write_hook::disarm();
        assert!(
            format!("{err:?}").contains("stage identity changed"),
            "the refusal names the rebound stage: {err:?}"
        );
        assert!(
            format!("{err:?}").contains("stage left in place"),
            "the refusal declares the unverifiable residue: {err:?}"
        );
        // Both objects stand untouched: the renamed-aside own
        // stage (with bytes the fd wrote post-rebind) and the
        // planted foreign file (never unlinked).
        let aside = std::fs::read(p.join("aside.bin")).unwrap();
        assert!(!aside.is_empty(), "the aside stage keeps its written bytes");
        let residue = staging_residue(&p);
        assert_eq!(
            residue.len(),
            1,
            "the planted name still stands: {residue:?}"
        );
        assert_eq!(
            std::fs::read(p.join(&residue[0])).unwrap(),
            b"foreign-stage-name-bytes",
            "the foreign object is preserved (never unlinked)"
        );
        assert_eq!(
            std::fs::read(&ckpt).unwrap(),
            before,
            "the prior checkpoint stands untouched"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new80_noreplace_race_at_first_commit() {
        // P2fix14 NEW-80 (absent-target arm): a first commit
        // (no target at the gate) publishes with NOREPLACE —
        // an object planted at the target between the gate
        // and the publish refuses (EEXIST) with the planted
        // object preserved and NO checkpoint published.
        // Pre-fix: the plain rename replaces the planted
        // object and reports success (RED).
        let base = unique_dir("noreplace-race");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        let ckpt2 = ckpt.clone();
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran2 = ran.clone();
        super::pre_exchange_hook::arm(move || {
            std::fs::write(&ckpt2, b"planted-between-gate-and-publish").unwrap();
            ran2.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        let err = presenter
            .flush_checkpoint()
            .expect_err("a raced-in target must refuse the first commit");
        super::pre_exchange_hook::disarm();
        assert!(
            ran.load(std::sync::atomic::Ordering::Relaxed),
            "the plant hook ran between the gate and the publish"
        );
        assert!(
            format!("{err:?}").contains("after the gate"),
            "the refusal names the race: {err:?}"
        );
        assert_eq!(
            std::fs::read(&ckpt).unwrap(),
            b"planted-between-gate-and-publish",
            "the planted object is preserved (never replaced)"
        );
        assert!(
            staging_residue(&p).is_empty(),
            "no stage residue: {:?}",
            staging_residue(&p)
        );
        // Nothing of ours published: reopen finds no
        // adoptable checkpoint (the planted noise discards).
        let q = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
            .expect("reopen reads past the planted noise");
        assert_eq!(q.watermark, None, "no watermark published");
        // Remove the plant: the first commit lands.
        std::fs::remove_file(&ckpt).unwrap();
        presenter.build_service().expect("the first commit lands");
        let q = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("reloads");
        assert_eq!(q.watermark, Some(0), "the commit settled");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new80_publish_failure_names_target_truthfully() {
        // P2fix14 NEW-80 (publish-failure arms — the
        // conditional publish itself can refuse): when the
        // target explains the failure, the refusal names THAT
        // (never a bare errno); NOTHING publishes (the prior
        // bytes stand), our stage is withdrawn, and the
        // foreign object is preserved. Three arms: an empty
        // DIRECTORY substituted after the gate (exchange
        // relinks it — the substitution detector swaps it
        // back and refuses), a target VANISHED after the gate
        // (exchange fails ENOENT → vanished wording), and a
        // genuine publish error with the target unchanged
        // (read-only dir → the raw error leads).
        use std::os::unix::fs::PermissionsExt as _;
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        for arm in ["dir-substitute", "vanished", "denied"] {
            let base = unique_dir(&format!("publish-failure-{arm}"));
            let out = base.join("out");
            std::fs::create_dir_all(&out).unwrap();
            std::fs::write(
                out.join("window-0000000000.json"),
                serde_json::to_string(&test_envelope(0, 0, run.clone(), 10)).unwrap(),
            )
            .unwrap();
            let p = base.join("p");
            std::fs::create_dir_all(&p).unwrap();
            let ckpt = p.join("ckpt.json");
            let mut presenter =
                Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
            presenter.build_service().expect("first fold commits");
            let before = std::fs::read(&ckpt).unwrap();
            let before_seq = presenter.checkpoint_seq;
            let holding = p.join("holding.json");
            let (ckpt2, holding2, p2) = (ckpt.clone(), holding.clone(), p.clone());
            let arm2 = arm.to_string();
            super::pre_exchange_hook::arm(move || match arm2.as_str() {
                "dir-substitute" => {
                    std::fs::rename(&ckpt2, &holding2).unwrap();
                    std::fs::create_dir(&ckpt2).unwrap();
                }
                "vanished" => {
                    std::fs::rename(&ckpt2, &holding2).unwrap();
                }
                _ => {
                    std::fs::set_permissions(&p2, std::fs::Permissions::from_mode(0o555)).unwrap();
                }
            });
            let err = presenter
                .flush_checkpoint()
                .expect_err("the publish failure must refuse");
            super::pre_exchange_hook::disarm();
            if arm == "denied" {
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            match arm {
                "dir-substitute" => {
                    assert!(
                        format!("{err:?}").contains("substituted after the gate"),
                        "{arm}: the refusal names the substitution: {err:?}"
                    );
                    assert!(
                        std::fs::symlink_metadata(&ckpt)
                            .unwrap()
                            .file_type()
                            .is_dir(),
                        "{arm}: the substituted directory stands (never swapped)"
                    );
                    assert_eq!(
                        std::fs::read(&holding).unwrap(),
                        before,
                        "{arm}: the prior bytes were never touched"
                    );
                    // Restore + reopen: the prior stands.
                    std::fs::remove_dir(&ckpt).unwrap();
                    std::fs::rename(&holding, &ckpt).unwrap();
                }
                "vanished" => {
                    assert!(
                        format!("{err:?}").contains("vanished after the gate"),
                        "{arm}: the refusal names the vanished target: {err:?}"
                    );
                    assert!(
                        !ckpt.exists(),
                        "{arm}: no target stands (nothing published)"
                    );
                    std::fs::rename(&holding, &ckpt).unwrap();
                }
                _ => {
                    assert!(
                        format!("{err:?}").contains("Permission denied")
                            || format!("{err:?}").contains("EACCES")
                            || err.raw_os_error() == Some(libc::EACCES),
                        "{arm}: the raw error leads when the target is unchanged: {err:?}"
                    );
                    assert!(
                        format!("{err:?}").contains("stage cleanup failed"),
                        "{arm}: the failed withdrawal is declared: {err:?}"
                    );
                    assert_eq!(
                        staging_residue(&p).len(),
                        1,
                        "{arm}: the stage stands declared (unlink denied too)"
                    );
                    assert_eq!(
                        std::fs::read(&ckpt).unwrap(),
                        before,
                        "{arm}: the prior bytes stand untouched"
                    );
                    // Permissions restored above: the operator
                    // removes the declared residue.
                    std::fs::remove_file(p.join(&staging_residue(&p)[0])).unwrap();
                }
            }
            assert!(
                staging_residue(&p).is_empty(),
                "{arm}: no stage residue: {:?}",
                staging_residue(&p)
            );
            let q = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
                .expect("reopen on the prior committed checkpoint");
            assert_eq!(
                q.checkpoint_seq, before_seq,
                "{arm}: reopen adopts the prior sequence"
            );
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    #[test]
    fn new81_dir_sync_failure_restores_prior() {
        // P2fix14 NEW-81 (+ NEW-2/NEW-9/NEW-16/NEW-70/
        // NEW-75-OPEN): commit acknowledgment reflects DURABLE
        // settlement — a directory-sync failure after the
        // conditional publish reports FAILURE (never success)
        // and the unsettled publish is WITHDRAWN (the prior
        // committed bytes authoritative again: swap the
        // exchange back, remove our own stage). Restart
        // authority stays unambiguous: reopen adopts the
        // prior transaction, never the unsettled replacement.
        // Pre-fix: the sync result is discarded (`let _`) and
        // success is reported over unsettled bytes (RED).
        let base = unique_dir("dirsync-restores-prior");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run.clone(), 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        let before = std::fs::read(&ckpt).unwrap();
        let before_seq = presenter.checkpoint_seq;
        // A second window folds (the commit under test would
        // advance the watermark) — then the settle sync fails.
        std::fs::write(
            out.join("window-0000000001.json"),
            serde_json::to_string(&test_envelope(1, 0, run, 10)).unwrap(),
        )
        .unwrap();
        presenter
            .build_service_staged()
            .expect("staged fold advances");
        super::dir_sync_fault::arm(1);
        let err = presenter
            .flush_checkpoint()
            .expect_err("a directory-sync failure must fail the commit");
        assert!(
            format!("{err:?}").contains("directory sync failed"),
            "the failure names the unsettled sync: {err:?}"
        );
        assert!(
            format!("{err:?}").contains("prior checkpoint restored"),
            "the failure declares the restored authority: {err:?}"
        );
        assert_eq!(
            std::fs::read(&ckpt).unwrap(),
            before,
            "the prior bytes were restored byte-identical (nothing published)"
        );
        assert!(
            staging_residue(&p).is_empty(),
            "no stage residue: {:?}",
            staging_residue(&p)
        );
        // Restart authority: reopen adopts the PRIOR
        // transaction (watermark 0), never the unsettled
        // replacement (watermark 1).
        drop(presenter);
        let q = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
            .expect("reopen on the restored prior checkpoint");
        assert_eq!(
            q.checkpoint_seq, before_seq,
            "reopen adopts the prior committed sequence"
        );
        assert_eq!(q.watermark, Some(0), "the prior watermark stands");
        // Unarmed retry commits the advance exactly once.
        let mut r = q;
        r.build_service().expect("retry folds window 1");
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
        assert_eq!(v["watermark_seq"], serde_json::json!(1));
        assert_eq!(
            v["accumulators"]["calls_total"],
            serde_json::json!(20),
            "exactly one fold of each window past the withdrawn commit"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new81_dir_sync_failure_first_commit_restores_absence() {
        // P2fix14 NEW-81 (absent-target arm): a directory-sync
        // failure on the FIRST commit (NOREPLACE publish)
        // reports FAILURE and withdraws the unsettled publish
        // (our own target entry removed — absence, the prior
        // authority, restored). Reopen finds no adoptable
        // checkpoint. Pre-fix: success is reported over
        // unsettled bytes (RED).
        let base = unique_dir("dirsync-restores-absence");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        super::dir_sync_fault::arm(1);
        let err = presenter
            .flush_checkpoint()
            .expect_err("a directory-sync failure must fail the first commit");
        assert!(
            format!("{err:?}").contains("directory sync failed"),
            "the failure names the unsettled sync: {err:?}"
        );
        assert!(
            format!("{err:?}").contains("no checkpoint published"),
            "the failure declares the restored absence: {err:?}"
        );
        assert!(!ckpt.exists(), "no target entry stands (absence restored)");
        assert!(
            staging_residue(&p).is_empty(),
            "no stage residue: {:?}",
            staging_residue(&p)
        );
        drop(presenter);
        let q = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
            .expect("reopen past the withdrawn first commit");
        assert_eq!(q.watermark, None, "no watermark published");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new83_restart_with_newer_generation_preserves_outgoing() {
        // P2fix14 NEW-83 (+ NEW-P2c/NEW-67-OPEN): after a
        // checkpoint carrying the recovery record (here: gen
        // 3 carrying the gen-1 record), restart with a NEWER
        // generation already available — the first-scan reset
        // preserves the generation ACTUALLY being left (gen 3
        // with its restored finals), not the stale retained
        // record (gen 1), and the committed checkpoint carries
        // gen 3 (restore-valid). Pre-fix: the reset keeps the
        // stale gen-1 record (RED).
        let base = unique_dir("restart-newer-gen");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run.clone(), 10)).unwrap(),
        )
        .unwrap();
        let ckpt = base.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("gen 0 publishes");
        std::fs::write(
            out.join("window-0000000002.json"),
            serde_json::to_string(&test_envelope(2, 1, run.clone(), 10)).unwrap(),
        )
        .unwrap();
        let mut bad = test_envelope(3, 1, run.clone(), 10);
        bad["schema"] = serde_json::json!("service-window-v9");
        std::fs::write(
            out.join("window-0000000003.json"),
            serde_json::to_string(&bad).unwrap(),
        )
        .unwrap();
        presenter
            .build_service()
            .expect_err("the rejected gen-1 tail fails the scan");
        std::fs::remove_file(out.join("window-0000000003.json")).unwrap();
        std::fs::write(
            out.join("window-0000000004.json"),
            serde_json::to_string(&test_envelope(4, 2, run.clone(), 20)).unwrap(),
        )
        .unwrap();
        std::fs::write(
            out.join("window-0000000005.json"),
            serde_json::to_string(&test_envelope(5, 3, run.clone(), 30)).unwrap(),
        )
        .unwrap();
        presenter.build_service().expect("recovery builds");
        assert_eq!(
            presenter.previous_epoch().map(|p| p.generation),
            Some(1),
            "premise: gen 3 carries the gen-1 recovery record"
        );
        // Restart with gen 4 already available.
        std::fs::write(
            out.join("window-0000000006.json"),
            serde_json::to_string(&test_envelope(6, 4, run.clone(), 40)).unwrap(),
        )
        .unwrap();
        drop(presenter);
        let mut q = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
            .expect("restart restores the gen-3 checkpoint");
        assert_eq!(
            q.previous_epoch().map(|p| p.generation),
            Some(1),
            "premise: the stale gen-1 record restores"
        );
        q.build_service()
            .expect("the first post-restart scan folds gen 4");
        let prev = q
            .previous_epoch()
            .expect("the first-scan reset preserves a predecessor");
        assert_eq!(
            prev.generation, 3,
            "the predecessor is the generation actually left (gen 3), never the stale gen 1"
        );
        assert_eq!(prev.window_seq, 5, "gen 3's restored tip");
        assert_eq!(prev.calls_total, 30, "gen 3's restored calls");
        assert_eq!(prev.lanes, [30, 0, 0, 0], "gen 3's restored lanes");
        assert_eq!(
            prev.unmeasured,
            vec![[3u64, 5u64]],
            "gen 3's restored span (gap [3,3] + folded-but-null tips [4,4],[5,5], merged)"
        );
        assert!(!prev.unstable.is_empty(), "gen 3's restored uncertainty");
        // The committed checkpoint carries gen 3, restore-valid.
        let ckpt_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&ckpt).unwrap()).unwrap();
        assert_eq!(
            ckpt_json["accumulators"]["previous_epoch"]["generation"],
            serde_json::json!(3),
            "the committed checkpoint preserves gen 3"
        );
        drop(q);
        let r = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
            .expect("the gen-3-carrying checkpoint reloads");
        assert_eq!(
            r.previous_epoch().map(|p| p.generation),
            Some(3),
            "gen 3 survives the reopen (restore-valid record)"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// One sealed-gross entry for the NEW-82 envelope pins
    /// (valid shape — restores through the typed map).
    fn seal_entry() -> SealedGross {
        SealedGross {
            records: 1,
            bytes: 2,
            queue_full: ReasonTotals {
                records: 1,
                bytes: 2,
            },
            epipe: ReasonTotals {
                records: 0,
                bytes: 0,
            },
            stream_abandoned: ReasonTotals {
                records: 0,
                bytes: 0,
            },
            source: "close".to_string(),
            tail_note: None,
            idempotent: true,
        }
    }

    #[test]
    fn new82_writer_output_at_cap_reopens() {
        // P2fix14 NEW-82 (at-cap arm): writer output of EXACTLY
        // the 64 MiB intake bound COMMITS (the writer enforces
        // `>`, symmetric with the intake) and REOPENS with
        // state equal. Sizing runs through the REAL finalizer
        // (`checkpoint_bytes` — the exact bytes the commit
        // stages), with one length-tuned key landing the
        // boundary precisely. (Boundary guard: green on old
        // code too — the overflow arm below carries the RED.)
        let base = unique_dir("writer-at-cap");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        for seq in 0..2u64 {
            std::fs::write(
                out.join(format!("window-{seq:010}.json")),
                serde_json::to_string(&test_envelope(seq, 0, run.clone(), 10)).unwrap(),
            )
            .unwrap();
        }
        let ckpt = base.join("ckpt.json");
        let mut p = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").unwrap();
        p.build_service().expect("folds commit");
        // Marginal sealed-entry size (fixed-width keys keep
        // the delta constant).
        let key = |i: usize| format!("seal-key-{i:08}-{}", "k".repeat(1000));
        p.checkpoint_seq = 42;
        let len0 = p
            .checkpoint_bytes_raw()
            .expect("premise: small finalizes")
            .len() as u64;
        for i in 0..11usize {
            p.sealed.insert(key(i), seal_entry());
        }
        let len11 = p.checkpoint_bytes_raw().expect("premise: grows").len() as u64;
        p.sealed.remove(&key(10));
        let len10 = p.checkpoint_bytes_raw().expect("premise: shrinks").len() as u64;
        let delta = len11 - len10;
        assert!(
            delta > 1000 && delta < 2000,
            "premise: sane entry size ({delta})"
        );
        // Bulk-fill to just under the cap, then land exactly
        // with one length-tuned key.
        let cap = 64 * 1024 * 1024u64;
        let n = (cap - len0 - 4000) / delta;
        for i in 11..(n as usize) {
            p.sealed.insert(key(i), seal_entry());
        }
        let mut len = p.checkpoint_bytes_raw().expect("premise: near cap").len() as u64;
        assert!(len < cap, "premise: bulk fill stays under the cap ({len})");
        assert!(
            cap - len < 100_000,
            "premise: tunable remainder ({})",
            cap - len
        );
        // Land exactly: insert a short LAST key, measure the
        // entry overhead, then extend the key by the exact
        // remainder (extending a key grows output byte-for-byte
        // — no escaping).
        let last_short = format!("seal-key-LAST-{}", "k".repeat(100));
        p.sealed.insert(last_short.clone(), seal_entry());
        len = p
            .checkpoint_bytes_raw()
            .expect("premise: last overhead")
            .len() as u64;
        assert!(len < cap, "premise: short LAST key stays under ({len})");
        let r = cap - len;
        p.sealed.remove(&last_short);
        p.sealed.insert(
            format!("seal-key-LAST-{}", "k".repeat(100 + r as usize)),
            seal_entry(),
        );
        len = p.checkpoint_bytes_raw().expect("premise: tuned").len() as u64;
        assert_eq!(len, cap, "the tuned writer output lands exactly on the cap");
        let sealed_len = p.sealed.len();
        // The commit publishes the at-cap bytes; reopen is exact.
        p.checkpoint_seq = 41;
        p.flush_checkpoint().expect("at-cap output commits");
        assert_eq!(
            std::fs::metadata(&ckpt).unwrap().len(),
            cap,
            "the committed file is exactly the cap"
        );
        drop(p);
        let q = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
            .expect("at-cap writer output reopens");
        assert_eq!(q.checkpoint_seq, 42);
        assert_eq!(q.watermark, Some(1));
        assert_eq!(q.calls_total, 20);
        assert_eq!(q.lanes, [20, 0, 0, 0]);
        assert_eq!(q.sealed.len(), sealed_len, "the grown maps round-trip");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new82_writer_overflow_preserves_prior() {
        // P2fix14 NEW-82 (+ NEW-76-OPEN writer half): writer
        // output ABOVE the 64 MiB intake bound REFUSES before
        // staging (the same envelope the intake enforces) —
        // the prior readable checkpoint stands byte-identical
        // (no stage, no touch) and reopens exactly. Pre-fix:
        // the oversize bytes COMMIT (and then refuse at
        // intake on reopen — writer/intake mismatch) (RED).
        let base = unique_dir("writer-overflow");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        for seq in 0..2u64 {
            std::fs::write(
                out.join(format!("window-{seq:010}.json")),
                serde_json::to_string(&test_envelope(seq, 0, run.clone(), 10)).unwrap(),
            )
            .unwrap();
        }
        let ckpt = base.join("ckpt.json");
        let mut p = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").unwrap();
        p.build_service().expect("folds commit");
        let before = std::fs::read(&ckpt).unwrap();
        let before_seq = p.checkpoint_seq;
        // Grow past the cap (bulk + confirm).
        let key = |i: usize| format!("seal-key-{i:08}-{}", "k".repeat(1000));
        p.checkpoint_seq = 42;
        let len0 = p
            .checkpoint_bytes_raw()
            .expect("premise: small finalizes")
            .len() as u64;
        for i in 0..11usize {
            p.sealed.insert(key(i), seal_entry());
        }
        let len11 = p.checkpoint_bytes_raw().expect("premise: grows").len() as u64;
        p.sealed.remove(&key(10));
        let len10 = p.checkpoint_bytes_raw().expect("premise: shrinks").len() as u64;
        let delta = len11 - len10;
        let cap = 64 * 1024 * 1024u64;
        let n = (cap - len0 + 4096) / delta + 2;
        for i in 11..(n as usize) {
            p.sealed.insert(key(i), seal_entry());
        }
        let len = p.checkpoint_bytes_raw().expect("premise: probe").len() as u64;
        assert!(
            len > cap,
            "premise: the fold genuinely overflows ({len} > {cap})"
        );
        // The commit refuses BEFORE staging; the prior stands.
        p.checkpoint_seq = 41;
        let err = p
            .flush_checkpoint()
            .expect_err("oversize writer output must refuse");
        assert!(
            format!("{err:?}").contains("exceeds the intake bound"),
            "the refusal names the envelope: {err:?}"
        );
        assert_eq!(
            std::fs::read(&ckpt).unwrap(),
            before,
            "the prior checkpoint stands byte-identical"
        );
        assert!(
            staging_residue(&base).is_empty(),
            "zero staging ran: {:?}",
            staging_residue(&base)
        );
        drop(p);
        let q = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
            .expect("the preserved prior checkpoint reloads");
        assert_eq!(
            q.checkpoint_seq, before_seq,
            "reopen adopts the prior sequence"
        );
        assert_eq!(q.watermark, Some(1), "the prior watermark stands");
        assert_eq!(q.calls_total, 20, "the prior totals stand");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new87_move_before_exchange_refuses_before_publish() {
        // P2fix15 NEW-87 (+ NEW-13/NEW-34/NEW-50/NEW-56/
        // NEW-61/NEW-66/NEW-69/NEW-74-OPEN): a move AFTER
        // the publish gate and BEFORE the exchange syscall
        // must refuse BEFORE the publish runs — never an
        // inside exchange withdrawn after. The pin proves
        // the syscall never ran (publish-syscall count
        // covers the capability probe only) and the owned
        // stage is left declared (withdrawal is
        // placement-bound — no unlink beneath the producer).
        // Pre-fix: the exchange runs inside and the error
        // reports a post-hoc withdrawal (RED).
        let base = unique_dir("move-before-exchange");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run.clone(), 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        let before = std::fs::read(&ckpt).unwrap();
        let before_seq = presenter.checkpoint_seq;
        std::fs::write(
            out.join("window-0000000001.json"),
            serde_json::to_string(&test_envelope(1, 0, run, 10)).unwrap(),
        )
        .unwrap();
        presenter
            .build_service_staged()
            .expect("staged fold advances");
        let target = out.join("p-moved");
        let (p2, target2) = (p.clone(), target.clone());
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran2 = ran.clone();
        super::pre_exchange_hook::arm(move || {
            std::fs::rename(&p2, &target2).unwrap();
            ran2.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        super::publish_probe::take();
        let err = presenter
            .flush_checkpoint()
            .expect_err("a move before exchange must refuse before the publish");
        super::pre_exchange_hook::disarm();
        assert!(
            ran.load(std::sync::atomic::Ordering::Relaxed),
            "the move hook ran between the gate and the publish"
        );
        assert!(
            format!("{err:?}").contains("no longer outside"),
            "the refusal names placement: {err:?}"
        );
        assert!(
            !format!("{err:?}").contains("unsettled publish withdrawn"),
            "nothing published, so nothing withdraws (refused BEFORE the syscall): {err:?}"
        );
        assert_eq!(
            super::publish_probe::take(),
            2,
            "the publish syscall never ran (capability probe only)"
        );
        assert_eq!(
            std::fs::read(target.join("ckpt.json")).unwrap(),
            before,
            "the prior target bytes are untouched"
        );
        // Placement-bound withdrawal: the owned stage stands
        // declared (never unlinked beneath the producer).
        let residue = staging_residue(&target);
        assert_eq!(
            residue.len(),
            1,
            "the owned stage stands declared: {residue:?}"
        );
        assert!(
            format!("{err:?}").contains("stage left in place"),
            "the refusal declares the left stage: {err:?}"
        );
        // Return outside + reopen: the prior transaction stands.
        drop(presenter);
        let back = base.join("p-back");
        std::fs::rename(&target, &back).unwrap();
        let q = Presenter::open_with_checkpoint(&out, &back.join("ckpt.json"), 1, "export")
            .expect("reopen on the prior committed checkpoint");
        assert_eq!(
            q.checkpoint_seq, before_seq,
            "reopen adopts the prior sequence"
        );
        assert_eq!(q.watermark, Some(0), "the prior watermark stands");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new87_move_after_final_position_check_skips_sync_and_swapback() {
        // P2fix15 NEW-87 (+ NEW-61/NEW-66/NEW-69/NEW-74-OPEN):
        // a move AFTER the final post-publish position proof
        // must refuse BEFORE the directory sync runs — with
        // no swapback beneath the producer (withdrawal is
        // placement-bound) and prior authority preserved via
        // the settlement record (the unsettled publish stands
        // declared; reopen adopts the marker-bound prior).
        // Pre-fix: nothing detects the move — the sync and
        // the settled cleanup run inside and report success
        // (RED).
        let base = unique_dir("move-after-position");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run.clone(), 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        let before = std::fs::read(&ckpt).unwrap();
        let before_seq = presenter.checkpoint_seq;
        std::fs::write(
            out.join("window-0000000001.json"),
            serde_json::to_string(&test_envelope(1, 0, run, 10)).unwrap(),
        )
        .unwrap();
        presenter
            .build_service_staged()
            .expect("staged fold advances");
        let target = out.join("p-moved");
        let (p2, target2) = (p.clone(), target.clone());
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran2 = ran.clone();
        super::post_position_hook::arm(move || {
            std::fs::rename(&p2, &target2).unwrap();
            ran2.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        super::publish_probe::take();
        super::dir_sync_probe::take();
        let err = presenter
            .flush_checkpoint()
            .expect_err("a move after the final position check must refuse settlement");
        super::post_position_hook::disarm();
        assert!(
            ran.load(std::sync::atomic::Ordering::Relaxed),
            "the move hook ran after the final position check"
        );
        assert!(
            format!("{err:?}").contains("no longer outside"),
            "the refusal names placement: {err:?}"
        );
        assert_eq!(
            super::dir_sync_probe::take(),
            0,
            "the directory sync never ran beneath the producer"
        );
        assert_eq!(
            super::publish_probe::take(),
            3,
            "the publish ran (before the move) but no swapback did (capability probe ×2 + publish)"
        );
        // Nothing touched after the move: the unsettled
        // replacement stands at the target, the prior under
        // the stage name — both byte-exact.
        let target_now: serde_json::Value =
            serde_json::from_slice(&std::fs::read(target.join("ckpt.json")).unwrap()).unwrap();
        assert_eq!(
            target_now["watermark_seq"],
            serde_json::json!(1),
            "the target carries the unsettled replacement (exchange ran pre-move)"
        );
        let residue = staging_residue(&target);
        assert_eq!(
            residue.len(),
            1,
            "the prior stands aside declared: {residue:?}"
        );
        assert_eq!(
            std::fs::read(target.join(&residue[0])).unwrap(),
            before,
            "the aside bytes are the prior checkpoint byte-identical"
        );
        // Return outside + reopen: prior authority via the
        // settlement record — reopen adopts the marker-bound
        // prior, never the standing unconfirmed replacement.
        drop(presenter);
        let back = base.join("p-back");
        std::fs::rename(&target, &back).unwrap();
        let moved_ckpt = back.join("ckpt.json");
        let q = Presenter::open_with_checkpoint(&out, &moved_ckpt, 1, "export")
            .expect("reopen adopts the marker-bound prior");
        assert_eq!(
            q.checkpoint_seq, before_seq,
            "reopen adopts the prior sequence"
        );
        assert_eq!(q.watermark, Some(0), "the prior watermark stands");
        assert_eq!(q.calls_total, 10, "the prior totals stand");
        assert!(
            q.recovered_unsettled_prior(),
            "the reopen reports the prior-settlement recovery"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new87_rebound_unlink_detected_not_silent() {
        // P2fix15 NEW-87 (+ NEW-26/NEW-69-OPEN): the
        // verify→unlink interval is CONFIRMED, not trusted —
        // a name rebound between identity verification and
        // the `unlinkat` must be DETECTED by the post-unlink
        // confirmation (our inode's link count intact while
        // the name went away) and declared loudly — never
        // silent success. Pre-fix: verification-then-unlink
        // trusts the interval, so the foreign object is
        // unlinked and the withdrawal reports clean (RED).
        let base = unique_dir("rebound-unlink");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        let p2 = p.clone();
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran2 = ran.clone();
        super::unlink_hook::arm(move || {
            // Rebind the verified stage name to a sacrificial
            // foreign file between verify and use.
            let residue: Vec<String> = std::fs::read_dir(&p2)
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.contains(".staging-"))
                .collect();
            assert_eq!(residue.len(), 1, "premise: one owned stage stands");
            std::fs::rename(p2.join(&residue[0]), p2.join("aside.bin")).unwrap();
            std::fs::write(p2.join(&residue[0]), b"sacrificial-foreign-bytes").unwrap();
            ran2.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        // The injected stage-write EIO drives the withdrawal
        // (the withdrawal's unlink is the interval under test).
        super::stage_fault::arm(1);
        let err = presenter
            .flush_checkpoint()
            .expect_err("the injected EIO must fail the flush");
        super::unlink_hook::disarm();
        assert!(
            ran.load(std::sync::atomic::Ordering::Relaxed),
            "the rebind hook ran inside the verify→unlink interval"
        );
        assert!(
            format!("{err:?}").contains("rebound"),
            "the failure declares the detected rebound (never silent): {err:?}"
        );
        // The damage is exactly what the confirmation
        // describes: our own stage still stands (moved
        // aside by the hook, never unlinked) while the
        // rebound name went away.
        assert!(
            p.join("aside.bin").exists(),
            "our own stage was never unlinked"
        );
        assert!(
            staging_residue(&p).is_empty(),
            "the rebound name went away (declared damage): {:?}",
            staging_residue(&p)
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new87_foreign_settled_name_refuses_before_staging() {
        // P2fix15 NEW-87 (refuse unsafe destinations before
        // staging): a foreign object standing at the
        // settlement-record name — a FIFO or foreign bytes —
        // refuses the write with ZERO staging (the record
        // slot is never replaced blindly) and the prior
        // checkpoint stands untouched. Pre-fix: no gate
        // exists, so the write succeeds past the foreign
        // object (RED).
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        for arm in ["fifo", "regular"] {
            let base = unique_dir(&format!("foreign-settled-{arm}"));
            let out = base.join("out");
            std::fs::create_dir_all(&out).unwrap();
            std::fs::write(
                out.join("window-0000000000.json"),
                serde_json::to_string(&test_envelope(0, 0, run.clone(), 10)).unwrap(),
            )
            .unwrap();
            let p = base.join("p");
            std::fs::create_dir_all(&p).unwrap();
            let ckpt = p.join("ckpt.json");
            let mut presenter =
                Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
            presenter.build_service().expect("first fold commits");
            let before = std::fs::read(&ckpt).unwrap();
            let settled = super::settled_path(&ckpt);
            // A foreign object stands at the record name (the
            // first commit's own record, if any, is replaced
            // by the plant — the gate must refuse it either
            // way).
            let _ = std::fs::remove_file(&settled);
            if arm == "fifo" {
                // SAFETY: mkfifo on a fresh private path.
                assert_eq!(
                    unsafe {
                        libc::mkfifo(
                            std::ffi::CString::new(settled.to_str().unwrap())
                                .unwrap()
                                .as_ptr(),
                            0o600,
                        )
                    },
                    0
                );
            } else {
                std::fs::write(&settled, b"foreign-settled-bytes").unwrap();
            }
            let err = presenter
                .flush_checkpoint()
                .expect_err("a foreign settlement name must refuse before staging");
            assert!(
                format!("{err:?}").contains("settlement"),
                "{arm}: the refusal names the settlement record: {err:?}"
            );
            assert!(
                staging_residue(&p).is_empty(),
                "{arm}: zero staging ran: {:?}",
                staging_residue(&p)
            );
            assert_eq!(
                std::fs::read(&ckpt).unwrap(),
                before,
                "{arm}: the prior checkpoint stands untouched"
            );
            use std::os::unix::fs::FileTypeExt as _;
            if arm == "fifo" {
                assert!(
                    std::fs::symlink_metadata(&settled)
                        .unwrap()
                        .file_type()
                        .is_fifo(),
                    "{arm}: the planted FIFO survives (never opened)"
                );
            } else {
                assert_eq!(
                    std::fs::read(&settled).unwrap(),
                    b"foreign-settled-bytes",
                    "{arm}: the foreign bytes survive (never replaced)"
                );
            }
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    /// Marker for the actual-interruption pin (P2fix15 NEW-88):
    /// when the `P2FIX15_NEW88_CHILD` env spec is present this
    /// test runs as the CHILD (open, fold, publish, then park
    /// inside the post-exchange hook until the parent kills
    /// it); without the spec it is a no-op pass (never run
    /// directly — only re-executed by its parent pin).
    #[test]
    fn new88_interrupted_publish_child() {
        let spec = match std::env::var("P2FIX15_NEW88_CHILD") {
            Ok(s) => s,
            Err(_) => return,
        };
        let parts: Vec<&str> = spec.split('|').collect();
        assert_eq!(parts.len(), 3, "child spec is out|ckpt|ready: {spec:?}");
        let (out, ckpt, ready) = (
            std::path::PathBuf::from(parts[0]),
            std::path::PathBuf::from(parts[1]),
            std::path::PathBuf::from(parts[2]),
        );
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("child opens");
        presenter
            .build_service_staged()
            .expect("child folds the staged window");
        let ready2 = ready.clone();
        super::post_exchange_hook::arm(move || {
            // The exchange RAN (this hook runs post-publish):
            // signal the parent, then park until killed.
            std::fs::write(&ready2, b"exchanged").unwrap();
            loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
            }
        });
        let _ = presenter.flush_checkpoint();
        unreachable!("the child parks in the post-exchange hook until killed");
    }

    #[test]
    fn new88_interrupted_publish_reopen_adopts_prior() {
        // P2fix15 NEW-88 (+ NEW-2/NEW-56/NEW-66/NEW-70/
        // NEW-75/NEW-81-OPEN): restart authority distinguishes
        // settled from unsettled writes DURABLY — a process
        // interrupted (SIGKILLed) after the exchange syscall
        // and before settlement leaves the replacement
        // standing UNCONFIRMED, and reopen adopts the
        // marker-bound prior — never the unconfirmed
        // replacement, never a silent reset. The interruption
        // is REAL (a re-executed test-binary child killed
        // mid-write), not a simulated fault. Pre-fix: reopen
        // reads the authoritative name directly and adopts the
        // unconfirmed replacement (RED).
        let base = unique_dir("interrupted-publish");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        for seq in 0..2u64 {
            std::fs::write(
                out.join(format!("window-{seq:010}.json")),
                serde_json::to_string(&test_envelope(seq, 0, run.clone(), 10)).unwrap(),
            )
            .unwrap();
        }
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        drop(presenter);
        // The prior writer is GONE (its owner pid reaped —
        // the realistic pre-state for crash recovery: the
        // child opens a checkpoint whose owner is dead, and
        // the harness's own live pid never leases it). The
        // volatile owner field is fixed out-of-band and the
        // settlement record is kept consistent with the
        // fixed bytes (same content, dead owner) — the
        // recovery mechanics below are unaffected by the
        // owner value.
        let mut reaped = std::process::Command::new("true")
            .spawn()
            .expect("reaped-pid probe spawns");
        let dead_pid = reaped.id();
        reaped.wait().expect("reaped-pid probe reaps");
        assert!(
            !super::pid_alive(dead_pid),
            "premise: the probe pid is dead"
        );
        let mut forged: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
        forged["owner"]["pid"] = serde_json::json!(dead_pid);
        rehash_checkpoint(&mut forged);
        let forged_sha = forged["sha256"]
            .as_str()
            .expect("premise: rehashed")
            .to_string();
        let forged_seq = forged["checkpoint_seq"]
            .as_u64()
            .expect("premise: sequence");
        std::fs::write(&ckpt, serde_json::to_vec(&forged).unwrap()).unwrap();
        std::fs::write(
            super::settled_path(&ckpt),
            super::render_settlement_record(&super::SettledRecord {
                target_sha256: forged_sha,
                checkpoint_seq: forged_seq,
            }),
        )
        .unwrap();
        let before = std::fs::read(&ckpt).unwrap();
        let before_seq = forged_seq;
        // The child folds window 2 (staged before spawn).
        std::fs::write(
            out.join("window-0000000002.json"),
            serde_json::to_string(&test_envelope(2, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let ready = base.join("child-ready");
        let spec = format!("{}|{}|{}", out.display(), ckpt.display(), ready.display());
        let exe = std::env::current_exe().expect("the test binary re-executes");
        struct KillOnDrop(std::process::Child);
        impl Drop for KillOnDrop {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut guard = KillOnDrop(
            std::process::Command::new(&exe)
                .args([
                    "--exact",
                    "presentation::snapshot::tests::new88_interrupted_publish_child",
                    "--nocapture",
                ])
                .env("P2FIX15_NEW88_CHILD", &spec)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("the child spawns"),
        );
        // Wait for the post-exchange signal (the child dies
        // early only on a bug — surface its output then).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            if ready.exists() {
                break;
            }
            if let Some(status) = guard.0.try_wait().expect("child wait") {
                let mut err_text = String::new();
                if let Some(mut stderr) = guard.0.stderr.take() {
                    use std::io::Read as _;
                    let _ = stderr.read_to_string(&mut err_text);
                }
                panic!("the child died before exchanging ({status:?}): {err_text}");
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the child must exchange within the bound"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        // The exchange RAN in the child: the standing target
        // is the unconfirmed replacement (watermark 2).
        let standing_bytes = std::fs::read(&ckpt).unwrap();
        let standing: serde_json::Value = serde_json::from_slice(&standing_bytes).unwrap();
        assert_eq!(
            standing["watermark_seq"],
            serde_json::json!(2),
            "premise: the child exchanged the replacement before parking"
        );
        // ACTUAL INTERRUPTION: SIGKILL mid-write.
        guard.0.kill().expect("the parent kills the child");
        let status = guard.0.wait().expect("the parent reaps the child");
        assert!(!status.success(), "the child died by signal, never exited");
        assert_eq!(
            status.code(),
            None,
            "the child was killed (no exit code): {status:?}"
        );
        std::mem::forget(guard);
        // Reopen adopts the marker-bound PRIOR (watermark 1,
        // exact totals) — never the standing replacement.
        let q = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
            .expect("reopen adopts the marker-bound prior");
        assert_eq!(
            q.checkpoint_seq, before_seq,
            "reopen adopts the prior sequence"
        );
        assert_eq!(q.watermark, Some(1), "the prior watermark stands");
        assert_eq!(q.calls_total, 20, "the prior totals stand");
        assert!(
            q.recovered_unsettled_prior(),
            "the reopen reports the prior-settlement recovery"
        );
        assert_eq!(
            std::fs::read(&ckpt).unwrap(),
            standing_bytes,
            "the standing replacement is untouched by the recovery-side reopen"
        );
        // The marker-bound prior stands under the stage name.
        let residue = staging_residue(&p);
        assert_eq!(residue.len(), 1, "the prior stands aside: {residue:?}");
        assert_eq!(
            std::fs::read(p.join(&residue[0])).unwrap(),
            before,
            "the aside bytes are the prior checkpoint byte-identical"
        );
        drop(q);
        // Forward repair: the recovered state folds onward
        // and settles (the interruption leaves no wedge).
        let mut r =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("reopen for repair");
        r.build_service().expect("post-recovery build settles");
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
        assert_eq!(v["watermark_seq"], serde_json::json!(2), "the tip advances");
        assert_eq!(
            v["accumulators"]["calls_total"],
            serde_json::json!(30),
            "exactly one fold of each window past the interruption"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new87_outside_move_at_exchange_proof_still_commits() {
        // P2fix15 NEW-87 (Tier-1 adjacent edge — NEW-50
        // stabilization at the NEW pre-exchange proof): an
        // outside→outside move between the gate and the
        // publish still COMMITS through the validated fd
        // (the drain discards the move, the position holds)
        // — the new fused proof refuses only inside moves,
        // never stabilization.
        let base = unique_dir("exchange-proof-stabilizes");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        let moved = base.join("p-moved-outside");
        let (p2, moved2) = (p.clone(), moved.clone());
        super::pre_exchange_hook::arm(move || {
            std::fs::rename(&p2, &moved2).unwrap();
        });
        presenter
            .flush_checkpoint()
            .expect("an outside move at the exchange proof still commits");
        super::pre_exchange_hook::disarm();
        let moved_ckpt = moved.join("ckpt.json");
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&moved_ckpt).unwrap()).unwrap();
        assert_eq!(v["watermark_seq"], 0, "the commit landed through the move");
        let q = Presenter::open_with_checkpoint(&out, &moved_ckpt, 1, "export")
            .expect("the committed bytes reload");
        assert_eq!(q.watermark, Some(0), "reopen adopts the commit");
        assert!(
            !q.recovered_unsettled_prior(),
            "a clean commit reopens directly (no recovery)"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new87_settled_slot_race_refuses_at_commit() {
        // P2fix15 NEW-87 (Tier-1 adjacent edge — commit-time
        // enforcement behind the early settled gate): an
        // object raced into the settlement-record slot after
        // the early gate refuses AT COMMIT (freshness
        // mismatch — never replaced blindly), the publish
        // remediates (swapback outside — the race touched no
        // ancestry), and the prior stands.
        let base = unique_dir("settled-slot-race");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        let before = std::fs::read(&ckpt).unwrap();
        let before_seq = presenter.checkpoint_seq;
        let settled = super::settled_path(&ckpt);
        let settled2 = settled.clone();
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran2 = ran.clone();
        super::pre_exchange_hook::arm(move || {
            std::fs::write(&settled2, b"raced-into-settled-slot").unwrap();
            ran2.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        let err = presenter
            .flush_checkpoint()
            .expect_err("a settled-slot race must refuse at commit");
        super::pre_exchange_hook::disarm();
        assert!(
            ran.load(std::sync::atomic::Ordering::Relaxed),
            "the race hook ran between the gate and the publish"
        );
        assert!(
            format!("{err:?}").contains("settlement record slot changed after the gate"),
            "the refusal names the slot race: {err:?}"
        );
        assert!(
            format!("{err:?}").contains("prior checkpoint restored"),
            "the publish remediates outside: {err:?}"
        );
        assert_eq!(
            std::fs::read(&settled).unwrap(),
            b"raced-into-settled-slot",
            "the raced-in object is preserved (never replaced)"
        );
        assert_eq!(
            std::fs::read(&ckpt).unwrap(),
            before,
            "the prior checkpoint stands untouched"
        );
        // Operator clears the slot; the retry settles (the
        // refused write consumed a sequence — gaps are
        // harmless, no contiguity assumed).
        std::fs::remove_file(&settled).unwrap();
        presenter
            .build_service()
            .expect("retry settles after slot cleared");
        let q = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("reloads");
        assert_eq!(q.checkpoint_seq, before_seq + 2, "the retry committed once");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new88_torn_target_discards_despite_marker() {
        // P2fix15 NEW-88 (Tier-1 adjacent edge — torn
        // handling preserved): a TORN target with a
        // settlement record on file takes the EXISTING
        // discard-and-replay path (fresh + unstable — never
        // adopted, never a refusal): torn bytes are never
        // authoritative under any rule, and the next flush
        // re-settles over them (self-healing).
        let base = unique_dir("torn-target-with-marker");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        assert!(
            super::settled_path(&ckpt).exists(),
            "premise: a record stands"
        );
        std::fs::write(&ckpt, b"{torn-json").unwrap();
        let q = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
            .expect("a torn target discards (never refuses)");
        assert_eq!(q.watermark, None, "discard replays fresh");
        assert!(
            !q.recovered_unsettled_prior(),
            "discard is not recovery (no flag)"
        );
        // Self-healing: the next flush settles over the torn
        // bytes and the record confirms them.
        let mut r = q;
        r.build_service().expect("post-discard build settles");
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&ckpt).unwrap()).unwrap();
        assert_eq!(v["watermark_seq"], 0, "the tip rebuilds");
        let s = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("reloads");
        assert_eq!(
            s.watermark,
            Some(0),
            "the re-settled commit adopts directly"
        );
        assert!(
            !s.recovered_unsettled_prior(),
            "the re-settled commit reopens directly (no recovery)"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new89_stale_stage_declared_on_clean_commit() {
        // P2fix15 NEW-89 (Tier-1 adjacent edge — crash
        // residue declared, commit stands): a stale stage
        // from an interrupted write (junk standing under a
        // stage name) does not fail the next clean commit —
        // the commit settles (`Ok`) and the residue scan
        // declares the leftover on the outcome (operator
        // intervenes; nothing silent, nothing failed).
        let base = unique_dir("stale-stage-declared");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        std::fs::write(p.join("ckpt.json.staging-crashed.tmp"), b"crash-junk").unwrap();
        let outcome = presenter
            .flush_checkpoint()
            .expect("a stale stage must not fail a clean commit");
        assert!(
            !outcome.residue.is_empty()
                && outcome
                    .residue
                    .join(" ")
                    .contains("ckpt.json.staging-crashed.tmp"),
            "the outcome declares the stale stage: {:?}",
            outcome.residue
        );
        assert_eq!(
            std::fs::read(p.join("ckpt.json.staging-crashed.tmp")).unwrap(),
            b"crash-junk",
            "the stale stage is preserved (declared, never adopted, never removed)"
        );
        let q = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("reloads");
        assert_eq!(q.watermark, Some(0), "the clean commit adopts directly");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new91_rejected_window_clears_per_scan() {
        // P2fix15 NEW-91 (Tier-1 adjacent edge — no stale
        // windows): the rejected-window marker is per-scan —
        // a failed scan records its break sequence, and the
        // next scan clears it before running (a later
        // success reports none; the outage note never names
        // a stale window).
        let base = unique_dir("rejected-clears-per-scan");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        std::fs::write(
            out.join("window-0000000000.json"),
            serde_json::to_string(&test_envelope(0, 0, run.clone(), 10)).unwrap(),
        )
        .unwrap();
        let mut bad = test_envelope(1, 0, run.clone(), 10);
        bad["schema"] = serde_json::json!("service-window-v9");
        std::fs::write(
            out.join("window-0000000001.json"),
            serde_json::to_string(&bad).unwrap(),
        )
        .unwrap();
        let ckpt = base.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter
            .build_service_staged()
            .expect_err("the bad tail fails the scan");
        assert_eq!(
            presenter.rejected_window(),
            Some(1),
            "the failed scan records its break sequence"
        );
        std::fs::remove_file(out.join("window-0000000001.json")).unwrap();
        presenter.build_service().expect("recovery builds");
        assert_eq!(
            presenter.rejected_window(),
            None,
            "the next scan clears the marker (no stale window)"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn new88_unsettled_replacement_without_prior_refuses() {
        // P2fix15 NEW-88 (+ NEW-2/NEW-70/NEW-75-OPEN): a
        // hash-valid target that the settlement record does
        // NOT confirm is an unconfirmed replacement — reopen
        // REFUSES it loudly when no marker-bound prior stage
        // stands (never adopts it, never silently resets);
        // when the prior stage DOES stand, reopen adopts the
        // prior and reports the recovery. Pre-fix: reopen
        // reads the name directly and adopts the replacement
        // (RED).
        let base = unique_dir("unsettled-without-prior");
        let out = base.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let run = serde_json::json!({"pid": 1, "starttime": 2, "boot_id": "12345678-9abc-def0-1234-56789abcdef0"});
        for seq in 0..2u64 {
            std::fs::write(
                out.join(format!("window-{seq:010}.json")),
                serde_json::to_string(&test_envelope(seq, 0, run.clone(), 10)).unwrap(),
            )
            .unwrap();
        }
        let p = base.join("p");
        std::fs::create_dir_all(&p).unwrap();
        let ckpt = p.join("ckpt.json");
        let mut presenter =
            Presenter::open_with_checkpoint(&out, &ckpt, 1, "export").expect("open succeeds");
        presenter.build_service().expect("first fold commits");
        let prior = std::fs::read(&ckpt).unwrap();
        let before_seq = presenter.checkpoint_seq;
        drop(presenter);
        // A VALID twin transaction (same out-DIR, further
        // tip) stands at the target unconfirmed (as if left
        // by an interrupted publish that also lost its
        // stage): crafted through the REAL writer on a twin
        // path, then copied over.
        std::fs::write(
            out.join("window-0000000002.json"),
            serde_json::to_string(&test_envelope(2, 0, run, 10)).unwrap(),
        )
        .unwrap();
        let twin = p.join("twin.json");
        let mut twin_p =
            Presenter::open_with_checkpoint(&out, &twin, 1, "export").expect("twin opens");
        twin_p.build_service().expect("twin folds further");
        let replacement = std::fs::read(&twin).unwrap();
        drop(twin_p);
        assert_ne!(
            replacement, prior,
            "premise: the twin advanced past the prior"
        );
        std::fs::write(&ckpt, &replacement).unwrap();
        // No marker-bound prior stage stands: reopen REFUSES
        // the unconfirmed replacement loudly.
        let err = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
            .expect_err("an unconfirmed replacement without a prior stage must refuse");
        assert!(
            format!("{err:?}").contains("unconfirmed"),
            "the refusal names the unconfirmed replacement: {err:?}"
        );
        assert_eq!(
            std::fs::read(&ckpt).unwrap(),
            replacement,
            "the refusal mutates nothing"
        );
        // The prior stage stands: reopen adopts the
        // marker-bound prior and reports the recovery.
        std::fs::write(p.join("ckpt.json.staging-manual.tmp"), &prior).unwrap();
        let q = Presenter::open_with_checkpoint(&out, &ckpt, 1, "export")
            .expect("reopen adopts the marker-bound prior stage");
        assert_eq!(
            q.checkpoint_seq, before_seq,
            "reopen adopts the prior sequence"
        );
        assert_eq!(q.watermark, Some(1), "the prior watermark stands");
        assert_eq!(q.calls_total, 20, "the prior totals stand");
        assert!(
            q.recovered_unsettled_prior(),
            "the reopen reports the prior-settlement recovery"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
