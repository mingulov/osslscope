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
        };
        p.load_checkpoint()?;
        Ok(p)
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
    pub fn flush_checkpoint(&mut self) -> std::io::Result<()> {
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
        self.write_checkpoint().map_err(|e| e.to_string())?;
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
        if !self.out_dir.is_dir() {
            return Err(format!(
                "osslscope: unreadable out-DIR: {}",
                self.out_dir.display()
            ));
        }
        self.read_sidecars();
        // Scan window files (seq order).
        let mut seqs: Vec<u64> = vec![];
        let entries = std::fs::read_dir(&self.out_dir)
            .map_err(|e| format!("osslscope: unreadable out-DIR: {e}"))?;
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
            expect = seq.saturating_add(1);
        }
        // Re-union scan-added recovery flags (a mid-scan generation
        // reset above may have cleared them — the hole/prefix they
        // describe belongs to this build's adopted state).
        self.unstable.extend(scan_added);
        // Re-union scan-added unmeasured ranges (same rule — the
        // missing ranges detected during this scan survive the
        // reset with their flags).
        for range in scan_added_ranges {
            push_range(&mut self.trace_unmeasured, range);
        }
        self.adopt_summary();
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
            Ok(snap) => Ok(snap),
            Err(e) => {
                self.snapshot_seq = seq_before;
                self.pending_markers = markers_before;
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
        serde_json::json!({
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
        })
    }

    /// Load the checkpoint (absent ⇒ fresh; torn ⇒ discard + replay
    /// with unstable-all; owner-busy ⇒ usage error).
    fn load_checkpoint(&mut self) -> std::io::Result<()> {
        let Ok(body) = std::fs::read(&self.checkpoint_path) else {
            return Ok(());
        };
        let v: serde_json::Value = match serde_json::from_slice(&body) {
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
                    if !matches!(
                        flag,
                        "counts.calls_total"
                            | "counts.lanes"
                            | "members.retired_epoch"
                            | "counts.by_outcome"
                            | "loss.epoch_by_cause"
                            | "completeness.epoch_partial_by_class"
                            | "histograms"
                            | "stream.drops"
                    ) {
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
        Ok(())
    }

    /// Atomic checkpoint write (tmp + fsync + rename + fsync dir).
    fn write_checkpoint(&mut self) -> std::io::Result<()> {
        // Placement at every write (P2fix4 NEW-13/NEW-18): an
        // initially absent directory that became available after
        // open still holds the outside-producer condition — the
        // write refuses loudly instead of landing inside.
        check_checkpoint_placement(&self.out_dir, &self.checkpoint_path).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("osslscope: {e}"))
        })?;
        // Validated staging/rename directory (P2fix5 NEW-26,
        // P2fix7 NEW-44): OPEN the checkpoint parent first, then
        // prove containment + identity on the SAME opened
        // directory — no pathname-check-then-reopen gap (a path
        // that vanished, moved inside, or was substituted between
        // open and validation fails closed). Every step below is
        // dirfd-relative (openat/renameat), never a path string.
        let parent = self
            .checkpoint_path
            .parent()
            .unwrap_or_else(|| Path::new(""));
        let parent = if parent.as_os_str().is_empty() {
            std::env::current_dir()?
        } else {
            parent.to_path_buf()
        };
        let (dir_fd, parent_id) =
            open_validated_checkpoint_parent(&parent, &self.out_dir, &self.checkpoint_path)?;
        // Directory binding (P2fix6 NEW-34): compare against the
        // open-time binding — a replaced parent fails closed
        // (loudly), and a first resolution binds (the NEW-18
        // absent-dir deferral).
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
        // Fault injection (P2fix8 NEW-50, test-only): run the
        // armed relocation after validation, before the first
        // staging write (placement must stabilize through the
        // validated fd — inert at zero).
        #[cfg(test)]
        post_validation_hook::take_and_run();
        // Outside placement THROUGH staging (P2fix9 NEW-56):
        // the opened dir itself may have been reparented after
        // validation — re-prove fd-anchored ancestry on the SAME
        // fd immediately before the first staging write.
        // Occupancy is NOT re-checked (the NEW-50 outside-rename
        // control requires proceeding when only the PATH moved).
        // Refusal precedes ANY write (zero bytes land inside).
        if !opened_dir_is_outside(&dir_fd, &self.out_dir, &self.checkpoint_path)? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "osslscope: checkpoint dir no longer outside the producer out-DIR at staging (reparented during write; not {})",
                    self.checkpoint_path.display()
                ),
            ));
        }
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
        self.checkpoint_seq = self.checkpoint_seq.saturating_add(1);
        let mut body = self.checkpoint_body();
        // Refresh the sequence fields post-increment.
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
        let bytes = serde_json::to_vec(&body)?;
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
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::io::AsRawFd as _;
        let raw_target = target_name.as_bytes();
        let target_c = std::ffi::CString::new(raw_target).map_err(|_| bad_name("path"))?;
        let pid = std::process::id();
        let seq = self.checkpoint_seq;
        let mut attempt = 0u32;
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
        {
            use std::io::Write as _;
            // Fault injection (P2fix7 NEW-45, test-only): fail the
            // stage write with EIO AFTER the owned stage is
            // created (inert at zero — production always writes).
            #[cfg(test)]
            let injected = stage_fault::take();
            #[cfg(not(test))]
            let injected = false;
            let staged = (|| -> std::io::Result<()> {
                if injected {
                    return Err(std::io::Error::from_raw_os_error(libc::EIO));
                }
                stage_file.write_all(&bytes)?;
                stage_file.sync_all()
            })();
            // Owned-stage cleanup on EVERY pre-commit failure
            // (P2fix7 NEW-45 — write/sync, not just rename): the
            // stage is exclusively ours (O_EXCL created it this
            // call), so a failed write/sync unlinks it instead of
            // leaking it — staged retries reuse the same
            // committed sequence, and leaked names would exhaust
            // the 16-attempt bound and wedge export offline after
            // storage recovers.
            if let Err(e) = staged {
                unsafe {
                    libc::unlinkat(dir_fd.as_raw_fd(), stage_c.as_ptr(), 0);
                }
                return Err(e);
            }
        }
        // Fault injection (P2fix9 NEW-56, test-only): run the
        // armed pre-commit relocation after the stage write,
        // before the commit rename (placement must hold THROUGH
        // the commit — inert at zero).
        #[cfg(test)]
        pre_commit_hook::take_and_run();
        // Outside placement THROUGH the commit (P2fix9 NEW-56):
        // re-prove fd-anchored ancestry on the SAME fd
        // immediately before the rename — a dir reparented
        // under the producer tree after staging must not
        // commit there. The owned stage is unlinked on
        // refusal (NEW-45 cleanup covers EVERY pre-commit
        // failure, placement included).
        match opened_dir_is_outside(&dir_fd, &self.out_dir, &self.checkpoint_path) {
            Ok(true) => {}
            Ok(false) => {
                unsafe {
                    libc::unlinkat(dir_fd.as_raw_fd(), stage_c.as_ptr(), 0);
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "osslscope: checkpoint dir no longer outside the producer out-DIR at commit (reparented during write; not {})",
                        self.checkpoint_path.display()
                    ),
                ));
            }
            Err(e) => {
                unsafe {
                    libc::unlinkat(dir_fd.as_raw_fd(), stage_c.as_ptr(), 0);
                }
                return Err(e);
            }
        }
        // SAFETY: dir_fd is live; both names are NUL-free file
        // names in it (the target extends no path).
        if unsafe {
            libc::renameat(
                dir_fd.as_raw_fd(),
                stage_c.as_ptr(),
                dir_fd.as_raw_fd(),
                target_c.as_ptr(),
            )
        } != 0
        {
            let e = std::io::Error::last_os_error();
            // Best-effort cleanup of OUR stage (exclusively owned
            // — created this call, never shared, never another
            // writer's).
            unsafe {
                libc::unlinkat(dir_fd.as_raw_fd(), stage_c.as_ptr(), 0);
            }
            return Err(e);
        }
        // Directory fsync stays best-effort (parity with the
        // pre-NEW-34 write — the stage file itself is fsynced
        // above; a dir-sync failure must not fail the commit).
        let _ = dir_fd.sync_all();
        Ok(())
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
    fn new50_destination_relocation_before_first_write_stays_stable() {
        // P2fix8 NEW-50: placement stabilizes through staging —
        // a destination relocation AFTER validation and BEFORE
        // the first staging write cannot redirect the bytes: the
        // write lands in the VALIDATED fd (dirfd-relative), never
        // by re-resolving the path. The armed hook renames the
        // validated parent away and replants the path as a
        // symlink over the inside dir; the flush still commits
        // into the moved directory and the inside dir stays
        // empty. (Guard pin — pre-fix staging is already
        // dirfd-relative, so this holds pre/post; it proves the
        // stabilization half of NEW-50.)
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
        super::post_validation_hook::arm(move || {
            std::fs::rename(&p2, &moved2).unwrap();
            std::os::unix::fs::symlink(&inner2, &p2).unwrap();
        });
        presenter
            .flush_checkpoint()
            .expect("post-validation relocation still commits");
        super::post_validation_hook::disarm();
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
        // P2fix9 NEW-56: outside placement holds THROUGH the
        // commit — a dir reparented under the producer tree
        // AFTER the stage write refuses the rename (the target
        // name never appears there) and the owned stage is
        // cleaned. Pre-fix: the rename commits inside (RED).
        // Post-fix: the pre-commit ancestry re-check refuses
        // (GREEN).
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
        assert!(
            staging_residue(&target).is_empty(),
            "the owned stage is cleaned on refusal: {:?}",
            staging_residue(&target)
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
                    Ok(()) => {
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
}
