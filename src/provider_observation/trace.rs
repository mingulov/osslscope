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
    /// Fetch carve-out (10..=15 plus the P1-A1 73..=80 extension).
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

/// Slots in the per-API edge arrays: IDs 1..=80 addressable, slot 0
/// unused (P1-A1: grown from 73 with the fetch extension).
pub const TRACE_API_SLOTS: usize = 81;

/// Family demux BEFORE unknown-ID rejection (§6D-1). `None` ⟺ {0} ∪ {81+}.
pub fn demux(api: u32) -> Option<TraceFamily> {
    match api {
        1..=9 | 16..=19 => Some(TraceFamily::Lifecycle),
        10..=15 | 73..=80 => Some(TraceFamily::Fetch),
        20..=72 => Some(TraceFamily::PublicApi),
        _ => None,
    }
}

/// §6D-6 fallback pairing family (P2fix4 NEW-17): the wire-valid
/// fetch/lifecycle IDs — lifecycle 1..=6 plus the contract fetch
/// carve-out (10..=15, 73..=80). ONE classifier shared by
/// production pairing ([`TraceProducer::pairs`]), intake
/// validation ([`TraceSummary::validate`]), and the stored
/// fallback-family check ([`fallback_family_clean`]): the
/// producer pairs exactly this set under fallback, so intake
/// accepts exactly this set (expanded-fetch orphans validate;
/// operational IDs reject).
pub fn fallback_pairing_family(api: u32) -> bool {
    matches!(api, 1..=6) || c::fetch_api(api)
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
    /// BPF-stamped task incarnation (`Record.start_time_ns`,
    /// decode-gated nonzero). Part of the pairing identity.
    pub start_time_ns: u64,
    /// BPF-stamped creation seed (`Record.seed`, bytes 104..112 —
    /// NOT decode-gated: 0 is the legitimate first creation).
    /// Part of the pairing identity.
    pub seed: u64,
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
    /// BPF-stamped task incarnation (`Record.start_time_ns`,
    /// decode-gated nonzero). Part of the pairing identity.
    pub start_time_ns: u64,
    /// BPF-stamped creation seed (`Record.seed`, bytes 104..112 —
    /// NOT decode-gated: 0 is the legitimate first creation).
    /// Part of the pairing identity.
    pub seed: u64,
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
/// structure (pending ATTEMPTs, pending RESULTs, scopes, retire
/// epochs). FIFO eviction (oldest first): every evicted
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
    /// Window cap-sacrificed ATTEMPTs (fix3: the documented
    /// visible exception to the detail-caps guarantee — a subset
    /// of `unpaired_entries`, counted at every cap-driven
    /// sacrifice: FIFO pending eviction + coupled
    /// incarnation-evict expiry).
    pub pending_evicted_entries: u64,
    /// Window cap-sacrificed RESULTs (subset of
    /// `unpaired_results`, same increment sites).
    pub pending_evicted_results: u64,
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
    /// D0-6 aggregate-only fallback active for this window.
    pub fallback: bool,
    /// Window per-API distributions (§6D-3 opt-in; `None` unless
    /// `--trace-histogram-by-api`).
    pub api_histograms: Option<ApiHistograms>,
    /// Window ATTEMPT edges by API ID (§6D-10 multiset/fetch
    /// inputs; slot 0 unused).
    pub api_attempts: [u64; TRACE_API_SLOTS],
    /// Window RESULT edges by API ID (slot 0 unused).
    pub api_results: [u64; TRACE_API_SLOTS],
    /// Exemplars (≤8 per direction).
    pub exemplars: Vec<TraceExemplar>,
    /// Pairing-uncertainty for this window (item 3): pairing-state
    /// corruption was observed (fresh signals below, or taint
    /// carried across the close). Interpreted distributions
    /// withhold while set; raw counters/detail/exemplars stay.
    pub pairing_uncertain: bool,
    /// Uncertainty reasons (`pending-eviction`, `depth-overflow`,
    /// `decode-reject`, `late-cut`, `terminal-boundary-failed`,
    /// `carried`).
    pub pairing_uncertainty: Vec<String>,
    /// Late cut (P2fix3 NEW-P2e): the feed cut armed below already-
    /// consumed timestamps — the fold holds out-of-interval pairs
    /// it cannot exclude, so the window projection is UNBOUND
    /// (withheld as window-scoped evidence; diagnostics retain
    /// with the scope marked).
    pub late_cut: bool,
}

/// Per-API latency distributions: `[api - 20][class]` over
/// operational IDs 20..=72 (§6D-3 opt-in keying).
pub type ApiHistograms = [[TraceHistogram; 5]; 53];

/// Frozen histogram edge-set marker (§6D-3).
pub const TRACE_EDGES_MARKER: &str = "6d-frozen-18";

/// Per-class pair counts, §6D-7 presentation order.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceClassCounts {
    pub success: u64,
    pub failure: u64,
    pub empty: u64,
    pub retry: u64,
    pub unknown: u64,
}

impl TraceClassCounts {
    /// From by-class-ID counts (`[unknown, success, failure, empty,
    /// retry]` slot order).
    pub fn from_slots(counts: [u64; 5]) -> Self {
        Self {
            success: counts[1],
            failure: counts[2],
            empty: counts[3],
            retry: counts[4],
            unknown: counts[0],
        }
    }

    /// Exact class total (P2fix4 NEW-P2f): widened to u128 so
    /// an overfull vector can never saturate into a false
    /// conservation equality at u64::MAX.
    pub fn sum(self) -> u128 {
        u128::from(self.success)
            + u128::from(self.failure)
            + u128::from(self.empty)
            + u128::from(self.retry)
            + u128::from(self.unknown)
    }
}

/// One serializable latency distribution (§6D-3 form).
#[derive(Clone, PartialEq, Eq, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceDistribution {
    pub buckets: [u64; 19],
    pub sum: u64,
    pub count: u64,
}

impl From<&TraceHistogram> for TraceDistribution {
    fn from(h: &TraceHistogram) -> Self {
        Self {
            buckets: h.buckets,
            sum: h.sum,
            count: h.count,
        }
    }
}

/// Default-keyed distributions (§6D-3).
#[derive(Clone, PartialEq, Eq, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceHistograms {
    pub edges: String,
    pub success: TraceDistribution,
    pub failure: TraceDistribution,
    pub empty: TraceDistribution,
    pub retry: TraceDistribution,
    pub unknown: TraceDistribution,
}

/// Per-API distributions for one covered API (dense 5 leaves).
#[derive(Clone, PartialEq, Eq, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceByApiEntry {
    pub success: TraceDistribution,
    pub failure: TraceDistribution,
    pub empty: TraceDistribution,
    pub retry: TraceDistribution,
    pub unknown: TraceDistribution,
}

/// Serde skip predicate for default-false scope marks.
pub(crate) fn is_false(b: &bool) -> bool {
    !b
}

/// Document schema minor (`observed-crypto-v2.N`) from either
/// document shape (producer `schema`, doc_json/raw
/// `schema_version`). Unparseable/absent reads `None` (the
/// contract fails closed where a version is required).
pub(crate) fn doc_minor(doc: &serde_json::Value) -> Option<u64> {
    let v = doc
        .get("schema_version")
        .and_then(|x| x.as_str())
        .or_else(|| doc.get("schema").and_then(|x| x.as_str()))?;
    v.strip_prefix("observed-crypto-v2.")?.parse().ok()
}

/// Required-nullable presence + non-nullable null rules (P2fix4
/// NEW-19/GATE29): enforced on the RAW section BEFORE serde
/// normalization collapses absent-vs-null. The raw schema
/// requires explicit `class_epoch` + `window.class_window`
/// (present, null allowed — withheld shapes stay explicit);
/// the non-nullable optionals (`histograms`, `by_api`,
/// `by_api_availability`) reject explicit null. Same rules at
/// every typed reader (both presenter inputs via
/// [`parse_trace_section`], restored checkpoints via the restore
/// path) — identical to the raw schema gate. Field-naming
/// errors only (never rejected input text — P2fix4 NEW-4).
pub(crate) fn check_trace_shape_presence(section: &serde_json::Value) -> Result<(), String> {
    let obj = section
        .as_object()
        .ok_or_else(|| "trace_summary: not an object".to_string())?;
    if !obj.contains_key("class_epoch") {
        return Err("trace_summary.class_epoch: required field absent".to_string());
    }
    let window = obj
        .get("window")
        .and_then(|w| w.as_object())
        .ok_or_else(|| "trace_summary.window: not an object".to_string())?;
    if !window.contains_key("class_window") {
        return Err("trace_summary.window.class_window: required field absent".to_string());
    }
    for key in ["histograms", "by_api", "by_api_availability"] {
        if obj.get(key).is_some_and(|v| v.is_null()) {
            return Err(format!("trace_summary.{key}: explicit null rejected"));
        }
    }
    Ok(())
}

/// Strict trace-section read: object shape + [`TraceSummary::validate`]
/// (version, closed mode word, fallback/mode coherence,
/// withholding biconditionals, uncertainty vocabulary + scope
/// coherence, class/paired conservation, cumulative buckets,
/// L1 combined conservation, edge marker, by-api/availability
/// agreement, GAP/exemplar/range rules). Closed shape at every
/// level (P2fix5 NEW-27 — extra properties reject, never
/// discard, matching the raw schema gate).
pub(crate) fn parse_trace_section(section: &serde_json::Value) -> Result<TraceSummary, String> {
    check_trace_shape_presence(section)?;
    let ts: TraceSummary = serde_json::from_value(section.clone())
        .map_err(|_| "strict read rejected it".to_string())?;
    ts.validate()?;
    Ok(ts)
}

/// ONE document-level trace contract (P2fix3 GATE29) across raw
/// intake, both presenter inputs, and restored checkpoints —
/// the section/version triggers, required-vs-withheld
/// (via [`TraceSummary::validate`]), inner/outer mode +
/// uncertainty coherence (ditto), class/histogram conservation
/// (ditto), and coverage-vs-`api_activity` reconciliation here:
/// EVERY availability word binds to the producer's worst-wins
/// rule (P2fix4 GATE29 — the stamp rule in
/// [`super::cli::trace_availability_from_rows`]: per API the
/// worst row wins — any `not_attached` row, else any
/// attachment/finality row, else `covered` over ≥1 clean row;
/// missing rows read `not_attached`). A claimed word that
/// differs from its row-derived word rejects, as does any
/// malformed row (P2fix5 NEW-27 + P2fix6 NEW-37 + P2fix7 NEW-42 —
/// complete row validation: a present collection must be an
/// array, and EVERY row carries the complete raw-schema shape
/// with its api in 20..=72 and no duplicate apis, validated
/// before ranking — no skips, no short-circuit — whenever the
/// section is present, EVEN with the by-api opt-in disabled:
/// supplied rows never bypass shape validation for want of an
/// availability map). Only the word reconciliation itself is
/// vacuous without an availability map (no invented requirement
/// — current producers report none).
/// Returns the validated section (`None` when legitimately
/// absent).
pub(crate) fn check_trace_contract(
    minor: Option<u64>,
    section: Option<&TraceSummary>,
    activity: Option<&serde_json::Value>,
) -> Result<Option<TraceSummary>, String> {
    // Section/version triggers (both directions).
    match (minor, section.is_some()) {
        (Some(9), false) => {
            return Err("minor == 9 needs its trace_summary section".to_string());
        }
        (_, true) if minor.is_none_or(|m| m < 9) => {
            return Err("trace_summary needs a schema minor >= 9".to_string());
        }
        _ => {}
    }
    let Some(ts) = section else {
        return Ok(None);
    };
    // Complete row validation (P2fix5 NEW-27, P2fix6 NEW-37,
    // P2fix7 NEW-42): applies to SUPPLIED activity whenever the
    // section is present — EVEN with the by-api opt-in disabled
    // (no availability-absent skip: a present-but-malformed
    // collection rejects, never reads-as-absent — only ABSENT
    // reads rowless, the conservative direction claiming nothing
    // covered). A PRESENT collection must be an array, and EVERY
    // row carries the COMPLETE activity-row shape BEFORE ranking
    // — the raw schema's required keys with exact types (API +
    // flags alone is insufficient), no unknown keys (the raw
    // `additionalProperties: false`), each api in 20..=72 like
    // every other reader, and each api at most ONCE (duplicate
    // coverage inputs reject on every reader —
    // availability-driving rows are never silently normalized).
    // No skips, no short-circuit.
    let rows: &[serde_json::Value] = match activity {
        None => &[],
        Some(collection) => collection
            .as_array()
            .map(Vec::as_slice)
            .ok_or_else(|| "api_activity: present collection must be an array".to_string())?,
    };
    let mut seen: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    let mut ranked: Vec<(u64, u8)> = Vec::with_capacity(rows.len());
    for row in rows.iter() {
        let obj = row
            .as_object()
            .ok_or_else(|| "api_activity row: want object".to_string())?;
        for key in obj.keys() {
            if !matches!(
                key.as_str(),
                "api"
                    | "entries"
                    | "observed_success"
                    | "observed_failure"
                    | "verification_mismatch"
                    | "unsupported"
                    | "gaps"
            ) {
                return Err("api_activity row: unknown field".to_string());
            }
        }
        let api = obj
            .get("api")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| "api_activity row api: want u64".to_string())?;
        if !(20..=72).contains(&api) {
            return Err("api_activity row api: out of range".to_string());
        }
        if !seen.insert(api) {
            return Err("api_activity: duplicate api row".to_string());
        }
        for key in [
            "entries",
            "observed_success",
            "observed_failure",
            "verification_mismatch",
            "unsupported",
        ] {
            obj.get(key)
                .and_then(|x| x.as_u64())
                .ok_or_else(|| format!("api_activity row {key}: want u64"))?;
        }
        let gaps = obj
            .get("gaps")
            .and_then(|g| g.as_object())
            .ok_or_else(|| "api_activity row without gaps".to_string())?;
        for key in gaps.keys() {
            if !matches!(
                key.as_str(),
                "map"
                    | "depth"
                    | "unpaired"
                    | "tail"
                    | "unsupported_return"
                    | "attachment"
                    | "finality"
                    | "not_attached"
                    | "read_receipt"
                    | "saturated"
            ) {
                return Err("api_activity row gaps: unknown field".to_string());
            }
        }
        for key in ["map", "depth", "unpaired", "tail", "unsupported_return"] {
            gaps.get(key)
                .and_then(|x| x.as_u64())
                .ok_or_else(|| format!("api_activity row gaps.{key}: want u64"))?;
        }
        let flag = |key: &str| {
            gaps.get(key)
                .and_then(|v| v.as_bool())
                .ok_or_else(|| format!("api_activity row gaps.{key}: want bool"))
        };
        // All flags validate before branching (no
        // short-circuit — a malformed sibling flag never
        // hides behind not_attached). Ranks (the producer's
        // per-row rule): 0 = not_attached, 1 = partial, 2 =
        // covered.
        let (not_attached, attachment, finality) = (
            flag("not_attached")?,
            flag("attachment")?,
            flag("finality")?,
        );
        flag("saturated")?;
        if let Some(receipt) = gaps.get("read_receipt") {
            receipt
                .as_bool()
                .ok_or_else(|| "api_activity row gaps.read_receipt: want bool".to_string())?;
        }
        let rank = if not_attached {
            0
        } else if attachment || finality {
            1
        } else {
            2
        };
        ranked.push((api, rank));
    }
    // Coverage reconciliation (availability-gated): every
    // availability word binds to the producer worst-wins rule
    // over the validated rows above. Vacuous without a map —
    // but the row validation above is NOT.
    if let Some(avail) = ts.by_api_availability.as_ref() {
        for id in 20..=72u32 {
            let claimed = avail.get(&id.to_string()).map(String::as_str);
            let mut worst: Option<u8> = None;
            for (api, rank) in ranked.iter() {
                if *api != u64::from(id) {
                    continue;
                }
                worst = Some(worst.map_or(*rank, |w| w.min(*rank)));
            }
            let expected = match worst {
                Some(2) => "covered",
                Some(1) => "partial_coverage",
                _ => "not_attached",
            };
            if claimed != Some(expected) {
                return Err(format!(
                    "by_api_availability[{id}]: claimed {claimed:?} disagrees with worst-wins {expected:?} over api_activity rows"
                ));
            }
        }
    }
    Ok(Some(ts.clone()))
}

/// Stored fallback-family check (P2fix3 NEW-3): a
/// fallback-shaped stored summary carries ONLY fallback-family
/// content — fetch/lifecycle classes (class-0 only) and §6D-6
/// family exemplars (the shared [`fallback_pairing_family`]
/// classifier — P2fix4 NEW-17). Operational classes or exemplar
/// IDs fail (the presenter withholds on failure, never trusting
/// intake alone). Non-fallback summaries always pass.
pub(crate) fn fallback_family_clean(ts: &TraceSummary) -> bool {
    if !ts.fallback {
        return true;
    }
    for c in [ts.window.class_window.as_ref(), ts.class_epoch.as_ref()]
        .into_iter()
        .flatten()
    {
        if c.success > 0 || c.failure > 0 || c.empty > 0 || c.retry > 0 {
            return false;
        }
    }
    ts.window
        .exemplars
        .iter()
        .all(|e| fallback_pairing_family(e.api))
}

/// §6D-7 window record, typed (JSON shape matches the frozen
/// record; the additive `fallback` key marks D0-6 state).
#[derive(Clone, PartialEq, Eq, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceWindowRecord {
    pub window_seq: u64,
    pub mode: String,
    pub fallback: bool,
    pub paired: u64,
    pub trace_unpaired_entries: u64,
    pub trace_unpaired_results: u64,
    pub trace_depth_exceeded: u64,
    pub trace_dropped: u64,
    pub trace_capped: bool,
    pub trace_nonmonotonic_pairs: u64,
    pub trace_rejected_unknown_api: u64,
    pub ring_loss: [u64; 8],
    /// Window pairs by class (withheld — `None` — while the window
    /// is pairing-uncertain; a present block always sums to
    /// `paired`).
    pub class_window: Option<TraceClassCounts>,
    /// Pairing-uncertainty for this window (withholding marker).
    #[serde(default)]
    pub pairing_uncertain: bool,
    /// Uncertainty reasons (empty unless uncertain).
    #[serde(default)]
    pub pairing_uncertainty: Vec<String>,
    /// Unbound window scope (P2fix3 NEW-P2e): the fold holds
    /// out-of-interval pairs past a late cut — the window
    /// projection withholds as window-scoped evidence while
    /// diagnostics retain with this mark. Serializes only when
    /// set (clean-run bytes stable).
    #[serde(default, skip_serializing_if = "is_false")]
    pub cut_unbound: bool,
    /// Folded-but-null seq ranges (epoch scope; always empty on a
    /// single-window summary — the presenter owns the epoch fold).
    #[serde(default)]
    pub unmeasured_seqs: Vec<[u64; 2]>,
    #[serde(default)]
    pub gaps: Vec<serde_json::Value>,
    #[serde(default)]
    pub gap_overflow: u64,
    #[serde(default)]
    pub exemplars: Vec<TraceExemplarJson>,
}

/// Exemplar JSON (§6D-7: hashes, never raw cookies).
#[derive(Clone, PartialEq, Eq, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceExemplarJson {
    pub dir: String,
    pub key_hash16: String,
    pub api: u32,
    pub age_ns: u64,
}

/// Document-level trace projection (v2.9 `trace_summary`): the
/// sealed window record + epoch folds. Histograms ride latency-
/// bearing modes only; by-api rides the opt-in only.
/// Closed shape (P2fix5 NEW-27 — every level denies unknown
/// fields, matching the raw schema's `additionalProperties:
/// false`): the typed readers enforce the same
/// pre-normalization shape as the raw gate (extra properties
/// reject, never discard).
#[derive(Clone, PartialEq, Eq, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceSummary {
    /// Summary version (1).
    pub version: u32,
    /// Effective mode word.
    pub mode: String,
    /// D0-6 aggregate-only fallback active.
    pub fallback: bool,
    /// Sealed §6D-7 window record.
    pub window: TraceWindowRecord,
    /// Epoch pairing-uncertainty (sticky withholding marker).
    #[serde(default)]
    pub pairing_uncertain: bool,
    /// Epoch pairs by class (withheld — `None` — while the epoch
    /// is pairing-uncertain).
    pub class_epoch: Option<TraceClassCounts>,
    /// Epoch default-keyed distributions (None in status mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub histograms: Option<TraceHistograms>,
    /// Sparse per-API distributions (None unless the opt-in
    /// produced them; L1 keys are decimal API-ID strings of
    /// covered APIs only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by_api: Option<std::collections::BTreeMap<String, TraceByApiEntry>>,
    /// Dense per-API availability (present iff `by_api` is
    /// non-null; all 53 IDs, closed `covered`/`not_attached`/
    /// `partial_coverage` vocabulary).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by_api_availability: Option<std::collections::BTreeMap<String, String>>,
}

impl TraceSummary {
    /// Strict self-validation — the SAME rules raw intake and both
    /// presenter paths enforce (items 4/23): version, closed mode
    /// word, mode/fallback coherence (fallback rides metadata only
    /// with fetch-only classes and no distributions; off/metadata
    /// without fallback pair nothing; status carries no
    /// histograms), withholding biconditionals (classes present
    /// iff certain), uncertainty vocabulary + coherence
    /// (uncertain iff reasons nonempty; unbound mark iff
    /// late-cut reason), class/paired conservation,
    /// histogram-count coherence (folded counts never exceed
    /// their class; no positive sum without pairs),
    /// cumulative-bucket invariants (default AND by-api),
    /// combined L1 conservation (counts/buckets/sums never
    /// exceed the default fold), edge marker,
    /// by-api/availability agreement (both directions — entries
    /// need covered AND covered needs entries), empty GAP inputs
    /// (DELTA-3: nonempty rejected until a typed producer
    /// exists), exemplar identities (fallback family only under
    /// fallback), and well-formed ranges.
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 {
            return Err(format!(
                "trace_summary.version: want 1, got {}",
                self.version
            ));
        }
        if !matches!(
            self.mode.as_str(),
            "off" | "metadata" | "latency" | "status" | "all"
        ) {
            // Field-only (P2fix4 NEW-4 — the rejected word never
            // echoes).
            return Err("trace_summary.mode: bad word".to_string());
        }
        let latency_bearing = matches!(self.mode.as_str(), "latency" | "all");
        let edge_bearing = trace_mode_edge_bearing(match self.mode.as_str() {
            "off" => TRACE_MODE_OFF,
            "metadata" => TRACE_MODE_METADATA,
            "latency" => TRACE_MODE_LATENCY,
            "status" => TRACE_MODE_STATUS,
            _ => TRACE_MODE_ALL,
        });
        // Withholding biconditionals (classes present iff certain).
        if self.window.class_window.is_none() != self.window.pairing_uncertain {
            return Err(
                "trace_summary.window: class_window withheld iff pairing_uncertain".to_string(),
            );
        }
        if self.class_epoch.is_none() != self.pairing_uncertain {
            return Err("trace_summary: class_epoch withheld iff pairing_uncertain".to_string());
        }
        // Uncertain summaries carry no interpreted distributions.
        if self.pairing_uncertain && (self.histograms.is_some() || self.by_api.is_some()) {
            return Err(
                "trace_summary: uncertain epoch must withhold histograms/by_api".to_string(),
            );
        }
        // Inner/outer coherence (P2fix2 item 13): an uncertain
        // window taints its epoch — inner-uncertain under
        // outer-certain is incoherent (the sticky direction is
        // inner-certain + outer-uncertain). Mode + fallback words
        // agree (one resolution stamps both — a mismatch is a
        // forged section).
        if self.window.pairing_uncertain && !self.pairing_uncertain {
            return Err("trace_summary: uncertain window under certain epoch".to_string());
        }
        if self.window.mode != self.mode {
            return Err("trace_summary: window/outer mode mismatch".to_string());
        }
        if self.window.fallback != self.fallback {
            return Err("trace_summary: window/outer fallback mismatch".to_string());
        }
        // Uncertainty reasons (P2fix3 DELTA-8): closed vocabulary
        // (the six seal reasons — P2fix6 NEW-32 adds the explicit
        // terminal-boundary failure) + uncertain-iff-nonempty —
        // every renderer (JSON, frames, terminal) reads validated
        // reasons only, never free strings.
        for reason in self.window.pairing_uncertainty.iter() {
            if !matches!(
                reason.as_str(),
                "pending-eviction"
                    | "depth-overflow"
                    | "decode-reject"
                    | "late-cut"
                    | "terminal-boundary-failed"
                    | "carried"
            ) {
                // Field-only (P2fix4 NEW-4 — the rejected reason
                // never echoes).
                return Err("trace_summary.window: bad uncertainty reason".to_string());
            }
        }
        if self.window.pairing_uncertain == self.window.pairing_uncertainty.is_empty() {
            return Err(
                "trace_summary.window: pairing_uncertain iff pairing_uncertainty nonempty"
                    .to_string(),
            );
        }
        // Unbound scope (P2fix3 NEW-P2e): the mark rides the
        // late-cut reason exactly (mark ⟺ reason present), and a
        // marked window is always pairing-uncertain (the seal
        // latches both together).
        let late_cut_reason = self
            .window
            .pairing_uncertainty
            .iter()
            .any(|r| r == "late-cut");
        if self.window.cut_unbound != late_cut_reason {
            return Err("trace_summary.window: cut_unbound iff late-cut reason".to_string());
        }
        if self.window.cut_unbound && !self.window.pairing_uncertain {
            return Err(
                "trace_summary.window: unbound window must be pairing-uncertain".to_string(),
            );
        }
        // Fallback rides metadata only, with fetch-only classes and
        // no distributions.
        if self.fallback {
            if self.mode != "metadata" {
                return Err("trace_summary: fallback rides metadata only".to_string());
            }
            if self.histograms.is_some() || self.by_api.is_some() {
                return Err("trace_summary: fallback carries no histograms/by_api".to_string());
            }
            for (scope, classes) in [
                ("class_window", self.window.class_window.as_ref()),
                ("class_epoch", self.class_epoch.as_ref()),
            ] {
                if let Some(c) = classes {
                    if c.success > 0 || c.failure > 0 || c.empty > 0 || c.retry > 0 {
                        return Err(format!(
                            "trace_summary.{scope}: operational classes under fallback"
                        ));
                    }
                }
            }
        }
        // Off/metadata without fallback never seal (the producer
        // gates seals on pairing modes + fallback) — reject
        // outright, same as raw intake ("ride fallback only").
        if !self.fallback && !edge_bearing {
            return Err("trace_summary: non-pairing mode without fallback".to_string());
        }
        // Status carries classes but no histograms (default or
        // by-API — P2fix2 item 13 closes the by-API hole).
        if !self.fallback && self.mode == "status" && self.histograms.is_some() {
            return Err("trace_summary: status mode must not carry histograms".to_string());
        }
        if !self.fallback && self.mode == "status" && self.by_api.is_some() {
            return Err("trace_summary: status mode must not carry by_api".to_string());
        }
        // Latency-bearing certain summaries carry histograms.
        if !self.fallback && latency_bearing && !self.pairing_uncertain && self.histograms.is_none()
        {
            return Err("trace_summary: latency-bearing mode without histograms".to_string());
        }
        if let Some(cw) = self.window.class_window.as_ref() {
            if cw.sum() != u128::from(self.window.paired) {
                return Err("trace_summary.window: class_window does not sum to paired".to_string());
            }
        }
        if let Some(h) = self.histograms.as_ref() {
            if h.edges != TRACE_EDGES_MARKER {
                return Err(format!(
                    "trace_summary.histograms.edges: want {TRACE_EDGES_MARKER:?}"
                ));
            }
            for (name, dist) in [
                ("success", &h.success),
                ("failure", &h.failure),
                ("empty", &h.empty),
                ("retry", &h.retry),
                ("unknown", &h.unknown),
            ] {
                if dist.buckets[18] != dist.count {
                    return Err(format!(
                        "trace_summary.histograms.{name}: buckets[18] != count"
                    ));
                }
                // Impossible sum (P2fix3 NEW-P2f): no pairs folded
                // a positive total — same rule as the adapters.
                if dist.count == 0 && dist.sum > 0 {
                    return Err(format!(
                        "trace_summary.histograms.{name}: count=0 with sum>0"
                    ));
                }
                let mut prev = 0u64;
                for (i, b) in dist.buckets.iter().enumerate() {
                    if *b < prev {
                        return Err(format!(
                            "trace_summary.histograms.{name}: buckets not cumulative at {i}"
                        ));
                    }
                    prev = *b;
                }
            }
            // Folded durations never exceed their class (nonmonotonic
            // pairs are excluded from exactly their class).
            if let Some(ce) = self.class_epoch.as_ref() {
                for (name, dist, class) in [
                    ("success", &h.success, ce.success),
                    ("failure", &h.failure, ce.failure),
                    ("empty", &h.empty, ce.empty),
                    ("retry", &h.retry, ce.retry),
                    ("unknown", &h.unknown, ce.unknown),
                ] {
                    if dist.count > class {
                        return Err(format!(
                            "trace_summary.histograms.{name}: count above class"
                        ));
                    }
                }
            }
        }
        match (&self.by_api, &self.by_api_availability) {
            (None, None) => {}
            (Some(by_api), Some(avail)) => {
                // L1 sub-folds ride the default fold (P2fix2 item
                // 13): by_api without histograms is impossible (the
                // mode rules above already exclude every such case;
                // this states it mode-independently).
                if self.histograms.is_none() {
                    return Err("trace_summary: by_api without histograms".to_string());
                }
                if avail.len() != 53 {
                    return Err(format!(
                        "trace_summary.by_api_availability: want 53 entries, got {}",
                        avail.len()
                    ));
                }
                for id in 20..=72u32 {
                    match avail.get(&id.to_string()).map(String::as_str) {
                        Some("covered" | "not_attached" | "partial_coverage") => {}
                        // Field-only (P2fix4 NEW-4 — the rejected
                        // word never echoes; the [id] is the loop
                        // index, not input).
                        _ => {
                            return Err(format!(
                                "trace_summary.by_api_availability[{id}]: bad word"
                            ));
                        }
                    }
                }
                for (id, entry) in by_api.iter() {
                    // Field-only (P2fix4 NEW-4 — the rejected key
                    // never echoes).
                    let parsed: u32 = id
                        .parse()
                        .map_err(|_| "trace_summary.by_api: bad key".to_string())?;
                    if !(20..=72).contains(&parsed) || *id != parsed.to_string() {
                        return Err("trace_summary.by_api: bad key".to_string());
                    }
                    if avail.get(id).map(String::as_str) != Some("covered") {
                        return Err(format!(
                            "trace_summary.by_api[{id}]: L1 entry without covered availability"
                        ));
                    }
                    for (name, dist) in [
                        ("success", &entry.success),
                        ("failure", &entry.failure),
                        ("empty", &entry.empty),
                        ("retry", &entry.retry),
                        ("unknown", &entry.unknown),
                    ] {
                        if dist.buckets[18] != dist.count {
                            return Err(format!(
                                "trace_summary.by_api[{id}].{name}: buckets[18] != count"
                            ));
                        }
                        // Impossible sum (P2fix3 NEW-P2f — same
                        // rule as the default fold above).
                        if dist.count == 0 && dist.sum > 0 {
                            return Err(format!(
                                "trace_summary.by_api[{id}].{name}: count=0 with sum>0"
                            ));
                        }
                        let mut prev = 0u64;
                        for (i, b) in dist.buckets.iter().enumerate() {
                            if *b < prev {
                                return Err(format!(
                                    "trace_summary.by_api[{id}].{name}: buckets not cumulative at {i}"
                                ));
                            }
                            prev = *b;
                        }
                    }
                    // Impossible distributions (P2fix2 item 13): an
                    // L1 sub-fold never exceeds its default fold —
                    // the covered API's pairs are a subset of all
                    // pairs (per class).
                    if let Some(h) = self.histograms.as_ref() {
                        for (name, l1, base) in [
                            ("success", &entry.success, &h.success),
                            ("failure", &entry.failure, &h.failure),
                            ("empty", &entry.empty, &h.empty),
                            ("retry", &entry.retry, &h.retry),
                            ("unknown", &entry.unknown, &h.unknown),
                        ] {
                            if l1.count > base.count {
                                return Err(format!(
                                    "trace_summary.by_api[{id}].{name}: L1 count above default"
                                ));
                            }
                        }
                    }
                }
                // Exact class conservation (P2fix3 NEW-P2f): the L1
                // sub-folds conserve into their default fold per
                // class — the COMBINED L1 counts, bucket masses,
                // and sums never exceed the parent (each entry
                // alone may fit while their sum overflows; summed
                // in u128 — no saturation masks a surplus).
                if let Some(h) = self.histograms.as_ref() {
                    fn l1_success(e: &TraceByApiEntry) -> &TraceDistribution {
                        &e.success
                    }
                    fn l1_failure(e: &TraceByApiEntry) -> &TraceDistribution {
                        &e.failure
                    }
                    fn l1_empty(e: &TraceByApiEntry) -> &TraceDistribution {
                        &e.empty
                    }
                    fn l1_retry(e: &TraceByApiEntry) -> &TraceDistribution {
                        &e.retry
                    }
                    fn l1_unknown(e: &TraceByApiEntry) -> &TraceDistribution {
                        &e.unknown
                    }
                    for (name, base, l1_of) in [
                        (
                            "success",
                            &h.success,
                            l1_success as fn(&TraceByApiEntry) -> &TraceDistribution,
                        ),
                        (
                            "failure",
                            &h.failure,
                            l1_failure as fn(&TraceByApiEntry) -> &TraceDistribution,
                        ),
                        (
                            "empty",
                            &h.empty,
                            l1_empty as fn(&TraceByApiEntry) -> &TraceDistribution,
                        ),
                        (
                            "retry",
                            &h.retry,
                            l1_retry as fn(&TraceByApiEntry) -> &TraceDistribution,
                        ),
                        (
                            "unknown",
                            &h.unknown,
                            l1_unknown as fn(&TraceByApiEntry) -> &TraceDistribution,
                        ),
                    ] {
                        let count_sum: u128 = by_api.values().map(|e| l1_of(e).count as u128).sum();
                        if count_sum > base.count as u128 {
                            return Err(format!(
                                "trace_summary.by_api.{name}: combined L1 count above default"
                            ));
                        }
                        let sum_sum: u128 = by_api.values().map(|e| l1_of(e).sum as u128).sum();
                        if sum_sum > base.sum as u128 {
                            return Err(format!(
                                "trace_summary.by_api.{name}: combined L1 sum above default"
                            ));
                        }
                        for i in 0..19 {
                            let bucket_sum: u128 =
                                by_api.values().map(|e| l1_of(e).buckets[i] as u128).sum();
                            if bucket_sum > base.buckets[i] as u128 {
                                return Err(format!(
                                    "trace_summary.by_api.{name}: combined L1 bucket {i} above default"
                                ));
                            }
                        }
                    }
                }
                // Complete coverage binding: every covered API needs
                // its L1 entry (a covered-but-absent API is an
                // incomplete projection, never a silent zero).
                for id in 20..=72u32 {
                    if avail.get(&id.to_string()).map(String::as_str) == Some("covered")
                        && !by_api.contains_key(&id.to_string())
                    {
                        return Err(format!(
                            "trace_summary.by_api: covered API {id} without entry"
                        ));
                    }
                }
            }
            _ => {
                return Err(
                    "trace_summary: by_api and by_api_availability must be jointly present or absent"
                        .to_string(),
                );
            }
        }
        // GAP inputs (DELTA-3): empty + zero until a typed producer
        // and read-set are reviewed — nonempty inputs reject.
        if !self.window.gaps.is_empty() {
            return Err("trace_summary.window: nonempty gaps[]".to_string());
        }
        if self.window.gap_overflow > 0 {
            return Err("trace_summary.window: nonzero gap_overflow".to_string());
        }
        // Exemplar identities: closed direction, 16-hex hash (never
        // a raw cookie), wire-valid API — and under fallback the
        // §6D-6 pairing family only (P2fix3 NEW-10 as corrected by
        // P2fix4 NEW-17: the shared `fallback_pairing_family`
        // classifier — a fallback producer pairs fetch/lifecycle
        // IDs 1..=6/10..=15/73..=80, so an operational exemplar
        // under fallback is forged or corrupt, never
        // projectable).
        for e in self.window.exemplars.iter() {
            if e.dir != "entry" && e.dir != "result" {
                // Field-only (P2fix4 NEW-4 — the rejected dir
                // never echoes).
                return Err("trace_summary.window.exemplars: bad dir".to_string());
            }
            // Canonical lowercase spelling (P2fix6 NEW-37 — the
            // raw schema's `^[0-9a-f]{16}$`; uppercase hex that
            // the raw gate excludes must not pass the typed
            // reader).
            if e.key_hash16.len() != 16
                || !e
                    .key_hash16
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err("trace_summary.window.exemplars: bad key_hash16".to_string());
            }
            if !matches!(e.api, 1..=6 | 10..=15 | 20..=72 | 73..=80) {
                return Err(format!("trace_summary.window.exemplars: bad api {}", e.api));
            }
            if self.fallback && !fallback_pairing_family(e.api) {
                return Err(format!(
                    "trace_summary.window.exemplars: non-family api {} under fallback",
                    e.api
                ));
            }
        }
        // Unmeasured ranges: ascending, non-overlapping, well-formed.
        let mut prev_end: Option<u64> = None;
        for range in self.window.unmeasured_seqs.iter() {
            if range[0] > range[1] {
                return Err("trace_summary.window: malformed unmeasured range".to_string());
            }
            if let Some(end) = prev_end {
                if end >= range[0] {
                    return Err("trace_summary.window: overlapping unmeasured ranges".to_string());
                }
            }
            prev_end = Some(range[1]);
        }
        Ok(())
    }
}

impl TraceSummary {
    /// Human section (PUBLIC-API plane, never physical entries):
    /// mode, pairs, classes, unpaired visibility, histogram counts.
    pub fn human_section(&self) -> String {
        let mut s = String::from(
            "trace (public-API pairs/classes/durations; never physical callback entries, never observer overhead):\n",
        );
        let w = &self.window;
        // Unbound window projection (P2fix4 NEW-P2e — the focused
        // twin of the standalone rule): a late cut withholds
        // paired as window-scoped evidence with the cause named;
        // the scope mark rides only when set (clean lines
        // byte-stable). The retained count stays in the
        // explicitly unbound document JSON (paired + mark).
        let paired = if w.cut_unbound {
            "withheld (late-cut)".to_string()
        } else {
            w.paired.to_string()
        };
        s.push_str(&format!(
            "  mode={} fallback={} paired={} unpaired_e={} unpaired_r={}{}\n",
            self.mode,
            self.fallback,
            paired,
            w.trace_unpaired_entries,
            w.trace_unpaired_results,
            if w.cut_unbound {
                " cut_unbound=true"
            } else {
                ""
            },
        ));
        match w.class_window.as_ref() {
            Some(c) => s.push_str(&format!(
                "  class success={} failure={} empty={} retry={} unknown={}\n",
                c.success, c.failure, c.empty, c.retry, c.unknown
            )),
            None => s.push_str("  class: withheld (pairing uncertainty)\n"),
        }
        match self.class_epoch.as_ref() {
            Some(c) => s.push_str(&format!(
                "  epoch success={} failure={} empty={} retry={} unknown={}\n",
                c.success, c.failure, c.empty, c.retry, c.unknown
            )),
            None => s.push_str("  epoch: withheld (pairing uncertainty)\n"),
        }
        match self.histograms.as_ref() {
            Some(h) => s.push_str(&format!(
                "  histograms({}) success={} failure={} empty={} retry={} unknown={}\n",
                h.edges,
                h.success.count,
                h.failure.count,
                h.empty.count,
                h.retry.count,
                h.unknown.count
            )),
            // Withholding governs this renderer too (P2fix2 item
            // 10): an uncertain epoch withholds (never the status
            // mislabel); a certain epoch without histograms is
            // honestly a non-latency mode.
            None if self.pairing_uncertain => {
                s.push_str("  histograms: withheld (pairing uncertainty)\n")
            }
            None => s.push_str("  histograms: none (status mode)\n"),
        }
        match self.by_api.as_ref() {
            Some(by_api) => s.push_str(&format!("  by_api: {} covered APIs\n", by_api.len())),
            // Same withholding rule (never silent while uncertain;
            // silent when the certain mode produces none).
            None if self.pairing_uncertain => {
                s.push_str("  by_api: withheld (pairing uncertainty)\n")
            }
            None => {}
        }
        s
    }
}

/// Per-call metadata trace (JSON): retained detail rows with the
/// full pairing identity MINUS the raw cookie (§6D-6:
/// `{pid, tid, generation, key_hash16, invocation, api}` plus
/// kind/timestamp/outcome — a strict subset of the §6D-1
/// allowlist). Raw cookies, parameter values, `rv` scalars, and
/// strings never appear here (§6D-11).
pub fn detail_json(window: &ClosedTraceWindow) -> serde_json::Value {
    serde_json::Value::Array(
        window
            .detail
            .iter()
            .map(|row| {
                serde_json::json!({
                    "kind": row.kind,
                    "api": row.api,
                    "pid": row.key.pid,
                    "tid": row.key.tid,
                    "generation": row.key.generation,
                    "key_hash16": row.key.key_hash16,
                    "invocation": row.key.invocation,
                    "monotonic_ns": row.monotonic_ns,
                    "outcome": row.outcome,
                })
            })
            .collect(),
    )
}

/// Project a sealed window + totals into a document summary.
/// `availability` maps operational API IDs to the frozen
/// availability words (computed from `ApiActivityRow` gaps at the
/// stamp site); the L1 block keeps covered APIs only.
pub fn summarize(
    window: &ClosedTraceWindow,
    totals: &TraceTotals,
    mode_word: &str,
    availability: Option<&std::collections::BTreeMap<u32, String>>,
) -> TraceSummary {
    // Withholding (items 3/14): interpreted duration/status
    // distributions withhold while uncertain (epoch scope for
    // cumulative folds, window scope for the window block); raw
    // counters/lanes/unpaired/exemplars always flow.
    let epoch_uncertain = totals.pairing_uncertain;
    let window_uncertain = window.pairing_uncertain;
    let class_epoch = if epoch_uncertain {
        None
    } else {
        Some(TraceClassCounts::from_slots(totals.class_counts))
    };
    let latency_bearing = matches!(mode_word, "latency" | "all");
    let histograms = if latency_bearing && !epoch_uncertain {
        Some(TraceHistograms {
            edges: TRACE_EDGES_MARKER.to_string(),
            success: TraceDistribution::from(&totals.histograms[1]),
            failure: TraceDistribution::from(&totals.histograms[2]),
            empty: TraceDistribution::from(&totals.histograms[3]),
            retry: TraceDistribution::from(&totals.histograms[4]),
            unknown: TraceDistribution::from(&totals.histograms[0]),
        })
    } else {
        None
    };
    let (by_api, by_api_availability) = match (
        latency_bearing && !epoch_uncertain,
        availability,
        totals.api_histograms,
    ) {
        (true, Some(avail), Some(hists)) => {
            let mut map = std::collections::BTreeMap::new();
            let mut dense = std::collections::BTreeMap::new();
            for id in 20..=72u32 {
                let word = avail
                    .get(&id)
                    .cloned()
                    .unwrap_or_else(|| "not_attached".to_string());
                dense.insert(id.to_string(), word.clone());
                if word == "covered" {
                    let cell = &hists[(id - 20) as usize];
                    map.insert(
                        id.to_string(),
                        TraceByApiEntry {
                            success: TraceDistribution::from(&cell[1]),
                            failure: TraceDistribution::from(&cell[2]),
                            empty: TraceDistribution::from(&cell[3]),
                            retry: TraceDistribution::from(&cell[4]),
                            unknown: TraceDistribution::from(&cell[0]),
                        },
                    );
                }
            }
            (Some(map), Some(dense))
        }
        _ => (None, None),
    };
    TraceSummary {
        version: 1,
        mode: mode_word.to_string(),
        fallback: window.fallback,
        pairing_uncertain: epoch_uncertain,
        window: TraceWindowRecord {
            window_seq: window.window_seq,
            mode: mode_word.to_string(),
            fallback: window.fallback,
            paired: window.paired,
            trace_unpaired_entries: window.unpaired_entries,
            trace_unpaired_results: window.unpaired_results,
            trace_depth_exceeded: window.depth_exceeded,
            trace_dropped: window.dropped,
            trace_capped: window.capped,
            trace_nonmonotonic_pairs: window.nonmonotonic_pairs,
            trace_rejected_unknown_api: window.rejected_unknown_api,
            ring_loss: window.ring_loss,
            class_window: if window_uncertain {
                None
            } else {
                Some(TraceClassCounts::from_slots(window.class_counts))
            },
            pairing_uncertain: window_uncertain,
            pairing_uncertainty: window.pairing_uncertainty.clone(),
            cut_unbound: window.late_cut,
            unmeasured_seqs: vec![],
            gaps: vec![],
            gap_overflow: 0,
            exemplars: window
                .exemplars
                .iter()
                .take(16)
                .map(|e| TraceExemplarJson {
                    dir: match e.dir {
                        ExemplarDir::Entry => "entry".to_string(),
                        ExemplarDir::Result => "result".to_string(),
                    },
                    key_hash16: e.key_hash16.clone(),
                    api: e.api,
                    age_ns: e.age_ns,
                })
                .collect(),
        },
        class_epoch,
        histograms,
        by_api,
        by_api_availability,
    }
}

/// Cumulative session totals.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TraceTotals {
    /// Cumulative pairs by class ID (2c's `class_epoch` input).
    pub class_counts: [u64; 5],
    /// Cumulative latency distributions by class ID.
    pub histograms: [TraceHistogram; 5],
    /// Cumulative per-API distributions (§6D-3 opt-in; `None`
    /// unless `--trace-histogram-by-api`).
    pub api_histograms: Option<ApiHistograms>,
    /// Cumulative pairs.
    pub paired: u64,
    /// Cumulative unpaired ATTEMPTs.
    pub unpaired_entries: u64,
    /// Cumulative unpaired RESULTs.
    pub unpaired_results: u64,
    /// Cumulative cap-sacrificed ATTEMPTs (fix3: subset of
    /// `unpaired_entries` — see the window field).
    pub pending_evicted_entries: u64,
    /// Cumulative cap-sacrificed RESULTs (subset of
    /// `unpaired_results`, same increment sites).
    pub pending_evicted_results: u64,
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
    /// Epoch pairing-uncertainty (sticky: latched by any uncertain
    /// window, never cleared within the run — cumulative folds
    /// cannot un-mix suspect pairs, so epoch interpreted
    /// distributions stay withheld once tainted).
    pub pairing_uncertain: bool,
}

/// Trace data-plane producer: demux + pairing + caps + counters.
pub struct TraceProducer {
    /// Active mode word.
    mode: u32,
    /// Row budget.
    max_rows: usize,
    /// Byte budget.
    max_bytes: usize,
    /// Pending ATTEMPTs by epoch-tagged key (G1: ≤ cap, FIFO-evicted).
    pending_attempts: HashMap<EpochKey, PendingEdge>,
    /// FIFO index: (insert window, sequence) → key. Bounded by
    /// the cap (exactly one entry per pending).
    pending_attempt_order: BTreeMap<(u64, u64), EpochKey>,
    /// Pending RESULTs by epoch-tagged key (G1: ≤ cap, FIFO-evicted).
    pending_results: HashMap<EpochKey, PendingEdge>,
    /// FIFO index for pending RESULTs (bounded by the cap).
    pending_result_order: BTreeMap<(u64, u64), EpochKey>,
    /// Per-scope invocation high-water (F3: consumed keys never re-pair).
    inv_hw: HashMap<ScopeKey, ScopeHw>,
    /// FIFO index for scopes (bounded by the cap).
    scope_order: BTreeMap<(u64, u64), ScopeKey>,
    /// Retire epochs (fix3, replaces the G3 retire markers): (pid,tid) →
    /// retire record (≤ cap, FIFO-evicted; bumped in off-mode
    /// too). Absent ⟺ epoch 0 (never retired — feeds never
    /// insert here, so the map holds retired tids only).
    epochs: BTreeMap<(u32, u32), RetireEpoch>,
    /// FIFO index for retire epochs (bounded by the cap).
    epoch_order: BTreeMap<(u64, u64), (u32, u32)>,
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
    /// D0-6 aggregate-only fallback: fetch/lifecycle pair
    /// (class-0); operational edges never pair.
    fallback: bool,
    /// §6D-3 by-api opt-in enabled.
    histogram_by_api: bool,
    /// Window per-API distributions (`Some` iff opt-in on).
    api_hists: Option<ApiHistograms>,
    /// Window ATTEMPT edges by API ID.
    api_attempts: [u64; TRACE_API_SLOTS],
    /// Window RESULT edges by API ID.
    api_results: [u64; TRACE_API_SLOTS],
    /// Window exemplars.
    exemplars: Vec<TraceExemplar>,
    /// Window paired count.
    paired: u64,
    /// Window unpaired ATTEMPTs.
    unpaired_entries: u64,
    /// Window unpaired RESULTs.
    unpaired_results: u64,
    /// Window cap-sacrificed ATTEMPTs (fix3).
    pending_evicted_entries: u64,
    /// Window cap-sacrificed RESULTs (fix3).
    pending_evicted_results: u64,
    /// Window received.
    received: ReceivedCounts,
    /// Window nonmonotonic pairs.
    nonmonotonic_pairs: u64,
    /// Window rejected records.
    rejected_unknown_api: u64,
    /// Window decode-domain rejections, ALL causes (P2fix2 item 5:
    /// the session funnel routes every generic wire rejection here;
    /// unknown-ID records ALSO count under
    /// `rejected_unknown_api`, so this is the superset — same
    /// `decode-reject` taint, exact per-cause counts). Window scope
    /// (resets at close); unpublished (the taint + session gaps
    /// carry the signal).
    wire_rejected: u64,
    /// Window late-cut taint (P2fix2 item 13): set when a cut
    /// (6A fence edge or feed-cut claim end) is noted at or below
    /// an already-folded timestamp — the irreversible fold cannot
    /// exclude those pairs, so the window seals `late-cut`
    /// uncertain.
    late_cut: bool,
    /// Terminal settlement proof (P2fix2 item 5): set by
    /// `finalize` (every held edge terminally accounted), cleared
    /// by any later pairing-state mutation (feeds, rejections) and
    /// by any uncertain close. A close proves a fresh boundary
    /// only when settled AND clean — empty host pending maps alone
    /// never clear taint.
    settled: bool,
    /// Failed terminal boundary latch (P2fix3 PAIRING): set by
    /// [`Self::note_boundary_failure`] when the terminal cut
    /// fails — sticky (a failed boundary is terminal, so nothing
    /// after it can prove freshness). A close proves fresh only
    /// when this latch is clear: taint clears ONLY on a
    /// successful producer boundary.
    boundary_failed: bool,
    /// Positive terminal-drain receipt (P2fix5 NEW-23): set ONLY
    /// by [`Self::note_terminal_drain`] on a quiescence-confirmed
    /// clean terminal drain (affirmative writer quiescence + ring
    /// exhaustion — a bare `None` is NOT clean). The fresh-
    /// boundary proof requires it: host finalization alone
    /// (settled + clean, no drainage evidence) carries taint,
    /// never clears it. Consumed by the next close; voided by any
    /// later pairing-state mutation (like `settled`).
    terminal_drain_proved: bool,
    /// Per-pid maximum folded monotonic timestamp, this window
    /// (P2fix2 item 13: the 6A fence is per-pid, so the overrun
    /// check scopes to the fenced pid). Capped (kernel-mirrored
    /// bound); past the cap the global max below answers (sound
    /// direction — over-taint, never a miss).
    fed_max: HashMap<u32, u64>,
    /// Global maximum folded monotonic timestamp, this window
    /// (claim-end binding + per-pid-map fallback).
    fed_max_global: u64,
    /// Live pairing-uncertainty taint (item 3): set when pairing-
    /// state corruption is observed (pending eviction, depth
    /// overflow, decode rejection — never plain ring loss), carried
    /// across closes until a proved fresh boundary (terminal
    /// settlement via `finalize` plus a clean close — P2fix2 item
    /// 5) clears it. Epoch totals latch it sticky (cumulative folds
    /// cannot un-mix suspect pairs).
    pairing_uncertain: bool,
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

/// Epoch-tagged pairing key (fix3 + fix4 incarnation + fix6
/// seed): the retire epoch AND the BPF-stamped task incarnation
/// AND the BPF-stamped creation seed are part of the pairing
/// identity, so cross-incarnation edges never pair in EITHER
/// recycle order (after-retire late edges land in their own
/// incarnation namespace; before-retire recycled edges never
/// shared a namespace to begin with), and cross-creation edges
/// never pair even when invocations overlap (R6-1: rows restart
/// at 1 BY DESIGN — the seed scopes them). Wire keys are
/// UNCHANGED (outputs still bind the bare `PairKey` —
/// `HashedKey::of`, exemplars, `key_hash16`).
///
/// fix6 (R6-1) joint invariant: a mispair needs the FULL key
/// equal (epoch + stamp + seed + key + invocation); safety =
/// stamps-differ OR seeds-differ OR invocations-differ — three
/// strands, each sufficient with its precondition (stamps
/// immutable-ish, seeds CAS-unique, invocations
/// per-row-monotonic). (The fix5 two-strand invariant claimed
/// non-reusing invocations — R6-1 refuted it: unique seeds with
/// overlapping ranges mispair. The answer is identity — the seed
/// IN the key — not more arithmetic.)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct EpochKey {
    /// The tid's retire epoch at feed time (`epoch_of`).
    epoch: u64,
    /// BPF-stamped task incarnation at feed time.
    start_time_ns: u64,
    /// BPF-stamped creation seed at feed time.
    seed: u64,
    /// Full wire pairing key.
    key: PairKey,
}

/// Pairing scope: the THREADS-row scope (contract `ThreadKey` —
/// `pid`, `tid`, `generation` — the key `invocation` counts
/// under), qualified by the retire epoch (HW is per-epoch,
/// dropped at bump — fix3), the task incarnation (HW is
/// per-incarnation — fix4: a recycled tid's invocation counter
/// never aliases the old one) AND the creation seed (HW is
/// per-seed — fix6: invocations restart at 1 per row BY DESIGN,
/// so an unscoped HW would false-dup across seeds — the same
/// reasoning as per-incarnation).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct ScopeKey {
    /// Executing pid.
    pid: u32,
    /// Executing tid.
    tid: u32,
    /// Scope/authority generation.
    generation: u64,
    /// Retire epoch (high-water namespace).
    epoch: u64,
    /// Task incarnation (high-water namespace).
    start_time_ns: u64,
    /// Creation seed (high-water namespace).
    seed: u64,
}

impl ScopeKey {
    /// Project an epoch-tagged pairing key to its scope.
    fn of(key: &EpochKey) -> Self {
        Self {
            pid: key.key.pid,
            tid: key.key.tid,
            generation: key.key.generation,
            epoch: key.epoch,
            start_time_ns: key.start_time_ns,
            seed: key.seed,
        }
    }
}

/// Retire epoch record (fix3, replaces the G3 retire marker): a
/// retired (pid,tid)'s incarnation counter (covers EVERY
/// generation for the tid). The boundary is PERMANENT — no
/// window-counted expiry can be outrun by a late edge (codex
/// R3-2). fix4: the epoch is best-effort cleanup + ordering —
/// cross-incarnation soundness comes from the BPF-stamped
/// incarnation in `EpochKey`, not from the drain-then-bump (the
/// drain cannot prove the ring empty).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct RetireEpoch {
    /// Current retire epoch (1 after the first bump; absent ⟺ 0).
    epoch: u64,
    /// Producer window of the insert (FIFO order key with `seq`).
    insert_window: u64,
    /// Insertion sequence.
    seq: u64,
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
            epochs: BTreeMap::new(),
            epoch_order: BTreeMap::new(),
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
            fallback: false,
            histogram_by_api: false,
            api_hists: None,
            api_attempts: [0; TRACE_API_SLOTS],
            api_results: [0; TRACE_API_SLOTS],
            exemplars: Vec::new(),
            paired: 0,
            unpaired_entries: 0,
            unpaired_results: 0,
            pending_evicted_entries: 0,
            pending_evicted_results: 0,
            received: ReceivedCounts::default(),
            nonmonotonic_pairs: 0,
            rejected_unknown_api: 0,
            wire_rejected: 0,
            late_cut: false,
            settled: false,
            boundary_failed: false,
            terminal_drain_proved: false,
            fed_max: HashMap::new(),
            fed_max_global: 0,
            pairing_uncertain: false,
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

    /// Engage the D0-6 aggregate-only fallback (fetch/lifecycle
    /// pair; operational edges never pair). The session pairs this
    /// with BPF `TRACE_MODE_METADATA` (no operational emission).
    pub fn set_fallback(&mut self, fallback: bool) {
        self.fallback = fallback;
    }

    /// Fallback active?
    pub fn fallback(&self) -> bool {
        self.fallback
    }

    /// Enable the §6D-3 by-api histogram opt-in (default off).
    pub fn set_histogram_by_api(&mut self, on: bool) {
        self.histogram_by_api = on;
        if on {
            if self.api_hists.is_none() {
                self.api_hists = Some([[TraceHistogram::default(); 5]; 53]);
            }
            if self.totals.api_histograms.is_none() {
                self.totals.api_histograms = Some([[TraceHistogram::default(); 5]; 53]);
            }
        } else {
            self.api_hists = None;
            self.totals.api_histograms = None;
        }
    }

    /// By-api opt-in active?
    pub fn histogram_by_api(&self) -> bool {
        self.histogram_by_api
    }

    /// Pairing predicate: operational pairs only on the
    /// edge-bearing path without fallback; fetch/lifecycle pair on
    /// the edge-bearing path OR — under fallback — exactly the
    /// shared §6D-6 family (P2fix4 NEW-17: the fallback arm calls
    /// the same [`fallback_pairing_family`] classifier intake
    /// enforces, so production and intake agree on every ID; the
    /// wire decoder already rejects non-wire-valid IDs before
    /// they reach here).
    fn pairs(&self, api: u32) -> bool {
        match demux(api) {
            Some(TraceFamily::PublicApi) => !self.fallback && trace_mode_edge_bearing(self.mode),
            Some(_) => {
                trace_mode_edge_bearing(self.mode)
                    || (self.fallback && fallback_pairing_family(api))
            }
            None => false,
        }
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
        if !self.pairs(edge.api) {
            return;
        }
        self.note_fed(edge.key.pid, edge.monotonic_ns);
        self.retain(RetainedEdge {
            kind: 1,
            key: HashedKey::of(&edge.key),
            api: edge.api,
            monotonic_ns: edge.monotonic_ns,
            outcome: 0,
        });
        // fix3: tag with the tid's current retire epoch — the epoch
        // is part of the pairing identity, so a pre-bump hold never
        // pairs with a post-bump edge (no window-counted rejection:
        // the new incarnation pairs immediately — its restarted
        // invocations are scoped by the new seed).
        // fix4: tag with the BPF-stamped incarnation too — soundness
        // against recycled tids (both orders) comes from the stamp,
        // not from the drain barrier (which is best-effort ordering).
        // fix6: tag with the BPF-stamped creation seed too —
        // soundness against delete/recreate invocation overlap
        // (R6-1) comes from the seed: rows restart at 1 BY DESIGN.
        let ekey = EpochKey {
            epoch: self.epoch_of(edge.key.pid, edge.key.tid),
            start_time_ns: edge.start_time_ns,
            seed: edge.seed,
            key: edge.key,
        };
        // F4: a held RESULT pairs only in its arrival window
        // (frozen §6D-6 is forward-only: the RESULT lands in the
        // ATTEMPT's SAME or NEXT window — same-window inversion
        // still pairs, cross-window reverse carry never does).
        let held_same_window = self
            .pending_results
            .get(&ekey)
            .is_some_and(|held| held.window == self.window);
        if held_same_window {
            let held = self
                .pending_result_remove(&ekey)
                .expect("held RESULT just observed");
            self.pair(
                ekey,
                edge.api,
                edge.monotonic_ns,
                held.monotonic_ns,
                held.outcome,
            );
        } else if self.pending_results.contains_key(&ekey) {
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
            if let Some(held) = self.pending_result_remove(&ekey) {
                self.unpaired_results = self.unpaired_results.saturating_add(1);
                self.totals.unpaired_results = self.totals.unpaired_results.saturating_add(1);
                self.push_live_exemplar(ExemplarDir::Result, ekey.key, held.api);
            }
            if self.is_hw_dup(&ekey) {
                self.unpaired_entries = self.unpaired_entries.saturating_add(1);
                self.totals.unpaired_entries = self.totals.unpaired_entries.saturating_add(1);
            } else if self.pending_attempts.contains_key(&ekey) {
                // The anomaly when an ATTEMPT is already live
                // (same bucket as the HW-dup above — both
                // conserve the newcomer as unpaired immediately).
                self.unpaired_entries = self.unpaired_entries.saturating_add(1);
                self.totals.unpaired_entries = self.totals.unpaired_entries.saturating_add(1);
            } else {
                // Fresh key: pending-then-correct as before.
                self.pending_attempt_insert(ekey, edge.api, edge.monotonic_ns);
            }
        } else if self.pending_attempts.contains_key(&ekey) {
            // Duplicate ATTEMPT on a live key (BPF never emits this):
            // the newcomer is the anomaly — conserve it as unpaired
            // immediately and keep the pairable original pending.
            self.unpaired_entries = self.unpaired_entries.saturating_add(1);
            self.totals.unpaired_entries = self.totals.unpaired_entries.saturating_add(1);
        } else if self.is_hw_dup(&ekey) {
            // F3: consumed-or-older invocation with no live state —
            // a replay, never a re-pair (frozen §6D-6).
            self.unpaired_entries = self.unpaired_entries.saturating_add(1);
            self.totals.unpaired_entries = self.totals.unpaired_entries.saturating_add(1);
        } else {
            self.pending_attempt_insert(ekey, edge.api, edge.monotonic_ns);
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
        if !self.pairs(edge.api) {
            return;
        }
        self.note_fed(edge.key.pid, edge.monotonic_ns);
        self.retain(RetainedEdge {
            kind: 2,
            key: HashedKey::of(&edge.key),
            api: edge.api,
            monotonic_ns: edge.monotonic_ns,
            outcome: edge.outcome,
        });
        // fix3: epoch tag (see `attempt` — same boundary).
        // fix4: incarnation tag (see `attempt` — same boundary).
        // fix6: seed tag (see `attempt` — same boundary).
        let ekey = EpochKey {
            epoch: self.epoch_of(edge.key.pid, edge.key.tid),
            start_time_ns: edge.start_time_ns,
            seed: edge.seed,
            key: edge.key,
        };
        if let Some(held) = self.pending_attempt_remove(&ekey) {
            self.pair(
                ekey,
                held.api,
                held.monotonic_ns,
                edge.monotonic_ns,
                edge.outcome,
            );
        } else if self.pending_results.contains_key(&ekey) {
            // Duplicate RESULT on a live key: conserve the newcomer
            // as unpaired immediately, keep the original pending.
            self.unpaired_results = self.unpaired_results.saturating_add(1);
            self.totals.unpaired_results = self.totals.unpaired_results.saturating_add(1);
        } else if self.is_hw_dup(&ekey) {
            // F3: consumed-or-older invocation with no live state —
            // a replay, never a re-pair (frozen §6D-6).
            self.unpaired_results = self.unpaired_results.saturating_add(1);
            self.totals.unpaired_results = self.totals.unpaired_results.saturating_add(1);
        } else {
            self.pending_result_insert(ekey, edge.api, edge.monotonic_ns, edge.outcome);
        }
    }

    /// Count one decode-domain unknown-ID record.
    pub fn reject_unknown(&mut self) {
        self.rejected_unknown_api = self.rejected_unknown_api.saturating_add(1);
        self.totals.rejected_unknown_api = self.totals.rejected_unknown_api.saturating_add(1);
        self.settled = false;
        self.terminal_drain_proved = false;
    }

    /// Count one generic wire rejection (P2fix2 item 5): any
    /// decode-domain refusal the session funnel observes (malformed
    /// record, zero stamp, ...). Unknown-ID records count here too
    /// (this is the superset — same `decode-reject` taint, exact
    /// per-cause counts).
    pub fn note_wire_rejection(&mut self) {
        self.wire_rejected = self.wire_rejected.saturating_add(1);
        self.settled = false;
        self.terminal_drain_proved = false;
    }

    /// Note a failed terminal producer boundary (P2fix3
    /// PAIRING): the terminal cut failed, so the seal cannot
    /// certify freshness — latch the failure (sticky) and drop
    /// any settlement. A later `finalize` still lands held edges
    /// unpaired, but the proof stays poisoned: taint carries,
    /// never clears.
    pub fn note_boundary_failure(&mut self) {
        self.boundary_failed = true;
        self.settled = false;
    }

    /// Note the TERMINAL drain's completion (P2fix4 NEW-20,
    /// P2fix5 NEW-23): the affirmative drain-completion result
    /// enters trace settlement like the gate-close result — a
    /// dirty terminal drain drops its remainder (the missing edge
    /// may be in it), so the producer boundary failed exactly
    /// like a failed gate close (latch + unsettle: prior taint
    /// carries through the terminal seal, never clears on it). A
    /// QUIESCENCE-CONFIRMED clean terminal drain stores the
    /// positive drain receipt (the session passes true ONLY after
    /// affirmative writer quiescence + ring exhaustion — a bare
    /// ring `None` is busy-or-empty, never clean by itself). The
    /// fresh-boundary proof requires the receipt: without it the
    /// seal carries, never clears. Called by the session exactly
    /// once, on the terminal drain only (live overruns merely
    /// delay — the kernel ring holds the backlog for the next
    /// drain).
    pub fn note_terminal_drain(&mut self, clean: bool) {
        if clean {
            self.terminal_drain_proved = true;
        } else {
            self.note_boundary_failure();
        }
    }

    /// Record one folded edge's timestamp for cut-overrun checks
    /// (P2fix2 item 13): per-pid max (capped — past the cap the
    /// global max answers) + global max. Any feed unsettles the
    /// terminal-settlement proof.
    fn note_fed(&mut self, pid: u32, monotonic_ns: u64) {
        self.settled = false;
        self.terminal_drain_proved = false;
        self.fed_max_global = self.fed_max_global.max(monotonic_ns);
        if self.fed_max.len() < TRACE_PAIRING_CAP || self.fed_max.contains_key(&pid) {
            self.fed_max
                .entry(pid)
                .and_modify(|m| *m = (*m).max(monotonic_ns))
                .or_insert(monotonic_ns);
        }
    }

    /// Note a per-pid cut (P2fix2 item 13 — the 6A fence edge): when
    /// this pid already folded a timestamp at/above the cut, the
    /// irreversible fold holds out-of-interval pairs it cannot
    /// exclude — latch `late-cut` taint (fail closed; the affected
    /// interpretations withhold at every renderer). A cut above all
    /// folded timestamps taints nothing, and a pid that folded
    /// nothing is clean. A capped-out pid (map full, entry absent)
    /// falls back to the global max (sound direction — over-taint,
    /// never a miss).
    pub fn note_cut_edge(&mut self, pid: u32, edge_ns: u64) {
        match self.fed_max.get(&pid) {
            Some(fed) => {
                if *fed >= edge_ns {
                    self.late_cut = true;
                }
            }
            None if self.fed_max.len() >= TRACE_PAIRING_CAP => {
                if self.fed_max_global >= edge_ns {
                    self.late_cut = true;
                }
            }
            None => {}
        }
    }

    /// Note a global cut (P2fix2 item 13 — the feed-cut claim end):
    /// same rule as [`Self::note_cut_edge`] over every folded pid
    /// (an empty fold is clean at any cut).
    pub fn note_global_cut(&mut self, cut_ns: u64) {
        let fed_any = !self.fed_max.is_empty() || self.fed_max_global > 0;
        if fed_any && self.fed_max_global >= cut_ns {
            self.late_cut = true;
        }
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
        let stale_attempts: Vec<EpochKey> = self
            .pending_attempts
            .iter()
            .filter(|(_, held)| held.window < current)
            .map(|(key, _)| *key)
            .collect();
        for key in stale_attempts {
            if let Some(held) = self.pending_attempt_remove(&key) {
                self.unpaired_entries = self.unpaired_entries.saturating_add(1);
                self.totals.unpaired_entries = self.totals.unpaired_entries.saturating_add(1);
                self.push_exemplar(ExemplarDir::Entry, key.key, held, now_ns);
                // fix3: a stale-epoch hold's HW namespace is dead
                // (feeds tag the current epoch, which never recurs
                // backward) — advancing it would write an unreadable
                // scope, so only current-epoch expiry advances.
                if key.epoch == self.epoch_of(key.key.pid, key.key.tid) {
                    self.advance_hw(&key);
                }
            }
        }
        let stale_results: Vec<EpochKey> = self
            .pending_results
            .iter()
            .filter(|(_, held)| held.window < current)
            .map(|(key, _)| *key)
            .collect();
        for key in stale_results {
            if let Some(held) = self.pending_result_remove(&key) {
                self.unpaired_results = self.unpaired_results.saturating_add(1);
                self.totals.unpaired_results = self.totals.unpaired_results.saturating_add(1);
                self.push_exemplar(ExemplarDir::Result, key.key, held, now_ns);
                // fix3: stale-epoch HW is dead (see above).
                if key.epoch == self.epoch_of(key.key.pid, key.key.tid) {
                    self.advance_hw(&key);
                }
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
        // fix3: epochs NEVER expire by clock (the boundary is
        // permanent — entries leave only via FIFO cap eviction,
        // with coupled expiry of the victim's pending).
        let mut ring_loss = [0u64; 8];
        for index in 0..8 {
            ring_loss[index] = loss_abs[index].saturating_sub(self.last_loss[index]);
            self.last_loss[index] = loss_abs[index];
        }
        // Pairing-uncertainty (item 3): fresh corruption signals for
        // this window, plus taint carried across the close. Plain
        // ring loss on other lanes is detectable loss (PARTIAL-
        // flagged, never withheld) and sets nothing here.
        let mut uncertainty = Vec::new();
        if self.pending_evicted_entries > 0 || self.pending_evicted_results > 0 {
            uncertainty.push("pending-eviction".to_string());
        }
        if ring_loss[2] > 0 {
            uncertainty.push("depth-overflow".to_string());
        }
        if self.rejected_unknown_api > 0 || self.wire_rejected > 0 {
            uncertainty.push("decode-reject".to_string());
        }
        if self.late_cut {
            uncertainty.push("late-cut".to_string());
        }
        // Explicit terminal-boundary failure (P2fix6 NEW-32): a
        // failed gate cut or a dirty/unproved terminal drain is
        // itself an uncertainty signal — the seal withholds
        // interpretations even with clean history (a clean close
        // can no longer launder a failed producer boundary). The
        // latch is sticky: later windows keep naming it beside
        // `carried`.
        if self.boundary_failed {
            uncertainty.push("terminal-boundary-failed".to_string());
        }
        if self.pairing_uncertain {
            uncertainty.push("carried".to_string());
        }
        let uncertain = !uncertainty.is_empty();
        // Proved fresh boundary (P2fix2 item 5, P2fix3 PAIRING,
        // P2fix5 NEW-23): taint clears ONLY on terminal
        // settlement (`finalize` ran — every held edge terminally
        // accounted) plus a clean close (empty pending, no fresh
        // corruption of any kind) on a SUCCESSFUL producer
        // boundary (no terminal-cut failure latched) WITH a
        // positive terminal-drain receipt (the session proved
        // writer quiescence + ring exhaustion — host finalization
        // alone withholds interpreted data on the unproved
        // terminal boundary). Empty host pending maps alone NEVER
        // clear taint (an idle close after a tainted one stays
        // carried): mid-run closes carry; only a settled clean
        // close proves the next window fresh. Epoch totals latch
        // sticky regardless (cumulative folds cannot un-mix
        // suspect pairs).
        let proved = self.settled
            && self.terminal_drain_proved
            && !self.boundary_failed
            && self.pending_attempts.is_empty()
            && self.pending_results.is_empty()
            && self.pending_evicted_entries == 0
            && self.pending_evicted_results == 0
            && ring_loss[2] == 0
            && self.rejected_unknown_api == 0
            && self.wire_rejected == 0
            && !self.late_cut;
        // The receipt is single-seal (consumed here — every
        // terminal settlement needs its own drainage proof).
        self.terminal_drain_proved = false;
        self.pairing_uncertain = uncertain && !proved;
        if uncertain {
            self.totals.pairing_uncertain = true;
            // Any uncertain close unsettles the proof (taint needs a
            // NEW terminal settlement to clear — an ancient finalize
            // never washes fresh corruption).
            self.settled = false;
        }
        let api_histograms = self.api_hists.take();
        if self.histogram_by_api {
            self.api_hists = Some([[TraceHistogram::default(); 5]; 53]);
        }
        let sealed = ClosedTraceWindow {
            window_seq,
            mode: self.mode,
            paired: self.paired,
            unpaired_entries: self.unpaired_entries,
            unpaired_results: self.unpaired_results,
            pending_evicted_entries: self.pending_evicted_entries,
            pending_evicted_results: self.pending_evicted_results,
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
            fallback: self.fallback,
            api_histograms,
            api_attempts: std::mem::replace(&mut self.api_attempts, [0; TRACE_API_SLOTS]),
            api_results: std::mem::replace(&mut self.api_results, [0; TRACE_API_SLOTS]),
            exemplars: std::mem::take(&mut self.exemplars),
            pairing_uncertain: uncertain,
            pairing_uncertainty: uncertainty,
            late_cut: self.late_cut,
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
        self.pending_evicted_entries = 0;
        self.pending_evicted_results = 0;
        self.received = ReceivedCounts::default();
        self.nonmonotonic_pairs = 0;
        self.rejected_unknown_api = 0;
        self.wire_rejected = 0;
        self.late_cut = false;
        self.fed_max.clear();
        self.fed_max_global = 0;
        self.window = self.window.saturating_add(1);
        sealed
    }

    /// The currently open window index (the label the next
    /// `close_window` must bind — callers never hardcode 0).
    pub fn current_window(&self) -> u64 {
        self.window
    }

    /// Terminal finalize: every held edge lands unpaired.
    /// Settles the fresh-boundary proof (P2fix2 item 5): after this
    /// call every held edge is terminally accounted, so a following
    /// clean close proves the next window fresh (until any new
    /// pairing-state mutation unsettles it).
    pub fn finalize(&mut self, now_ns: u64) {
        self.settled = true;
        for (key, held) in std::mem::take(&mut self.pending_attempts) {
            self.unpaired_entries = self.unpaired_entries.saturating_add(1);
            self.totals.unpaired_entries = self.totals.unpaired_entries.saturating_add(1);
            self.push_exemplar(ExemplarDir::Entry, key.key, held, now_ns);
            // fix3: stale-epoch HW is dead (see close-time expiry).
            if key.epoch == self.epoch_of(key.key.pid, key.key.tid) {
                self.advance_hw(&key);
            }
        }
        self.pending_attempt_order.clear();
        for (key, held) in std::mem::take(&mut self.pending_results) {
            self.unpaired_results = self.unpaired_results.saturating_add(1);
            self.totals.unpaired_results = self.totals.unpaired_results.saturating_add(1);
            self.push_exemplar(ExemplarDir::Result, key.key, held, now_ns);
            if key.epoch == self.epoch_of(key.key.pid, key.key.tid) {
                self.advance_hw(&key);
            }
        }
        self.pending_result_order.clear();
    }

    /// Cumulative totals.
    pub fn totals(&self) -> TraceTotals {
        self.totals
    }

    /// The tid's current retire epoch (absent ⟺ 0 — never
    /// retired). Feeds tag edges with this; it never recurs
    /// backward except via epoch-cap eviction (whose coupled
    /// expiry keeps the fallback sound — see `retire_scope`).
    fn epoch_of(&self, pid: u32, tid: u32) -> u64 {
        self.epochs.get(&(pid, tid)).map_or(0, |r| r.epoch)
    }

    /// fix3: retire a CONFIRMED-DEAD tid's pairing scopes. Called
    /// from `remove_thread_rows` (the sole cleanup funnel) AFTER
    /// a best-effort retire-drain (drain-then-bump — fix4: the
    /// drain is best-effort ORDERING, never a proven barrier; a
    /// busy ring head reads empty while committed records wait
    /// behind it, so cross-incarnation soundness comes from the
    /// BPF-stamped incarnation in the pairing key, not from this
    /// bump); covering EVERY generation for the tid; fires in
    /// off-mode too (no edges flow, but the bump is recorded for
    /// the next edge-bearing feed). The HW scopes are dropped (HW
    /// is per-epoch) and the epoch bumps: pre-bump holds (old
    /// epoch) never pair with post-bump edges (new epoch), and
    /// the new incarnation pairs immediately — fix6: its restarted
    /// invocations (rows restart at 1 BY DESIGN) are scoped by the
    /// new row's seed, so they never alias the old holds.
    /// Epoch storage is FIXED-CAPPED (FIFO, same
    /// kernel-mirrored bound); evicting an epoch expires the
    /// victim's pending WITH it (coupled expiry — protection
    /// loss retires the protected state, codex R3-3).
    pub(crate) fn retire_scope(&mut self, pid: u32, tid: u32) {
        self.drop_tid_scopes(pid, tid);
        let who = (pid, tid);
        let next = self
            .epochs
            .get(&who)
            .map_or(1, |r| r.epoch.saturating_add(1));
        if let Some(old) = self.epochs.get(&who) {
            let order = (old.insert_window, old.seq);
            self.epoch_order.remove(&order);
        } else if self.epochs.len() >= TRACE_PAIRING_CAP {
            // New entry past the cap: evict the oldest epoch with
            // COUPLED EXPIRY (finding-3 analog — never silent,
            // never mispairing). Cap-driven like the FIFO pending
            // evictions, so the victims count evicted too.
            if let Some((&order, &victim)) = self.epoch_order.iter().next() {
                self.epoch_order.remove(&order);
                self.epochs.remove(&victim);
                let (attempts, results) = self.expire_tid_pending(victim.0, victim.1);
                self.pending_evicted_entries = self
                    .pending_evicted_entries
                    .saturating_add(attempts.len() as u64);
                self.totals.pending_evicted_entries = self
                    .totals
                    .pending_evicted_entries
                    .saturating_add(attempts.len() as u64);
                self.pending_evicted_results = self
                    .pending_evicted_results
                    .saturating_add(results.len() as u64);
                self.totals.pending_evicted_results = self
                    .totals
                    .pending_evicted_results
                    .saturating_add(results.len() as u64);
                self.drop_tid_scopes(victim.0, victim.1);
            }
        }
        let window = self.window;
        let seq = self.next_seq();
        self.epoch_order.insert((window, seq), who);
        self.epochs.insert(
            who,
            RetireEpoch {
                epoch: next,
                insert_window: window,
                seq,
            },
        );
    }

    /// fix3: the retire-drain budget-exceeded path — the bump is
    /// SKIPPED (the tid stays unretired: same epoch, HW intact).
    /// The tid's pending expires immediately (unpaired + exemplar,
    /// never silently — a live old hold plus a recycled same-key
    /// edge would otherwise mispair through live-state
    /// precedence), and the HW shield extends past the expired
    /// holds (current epoch only — stale-epoch HW is dead), so
    /// late old edges (invocations at or below the old HW) land
    /// visible dup-unpaired — fix6: recycled tids mint a fresh
    /// seed, so their restarted edges land in a fresh seed scope
    /// beside the shield and pair normally.
    /// Conservation exact; the session records the visible skip
    /// signal (`DrainOverrun`).
    pub(crate) fn retire_scope_skipped(&mut self, pid: u32, tid: u32) {
        let (attempts, results) = self.expire_tid_pending(pid, tid);
        // Bounded by 2× the pairing cap (one entry per expired hold).
        for key in attempts.into_iter().chain(results) {
            // fix3: shield only the live namespace (see close-time expiry).
            if key.epoch == self.epoch_of(pid, tid) {
                self.advance_hw(&key);
            }
        }
    }

    /// Expire EVERY pending hold of a (pid,tid) (all epochs, all
    /// generations) as unpaired + exemplar. Returns the expired
    /// keys per direction (bounded by the pairing cap each) so
    /// callers can advance or drop HW per path.
    fn expire_tid_pending(&mut self, pid: u32, tid: u32) -> (Vec<EpochKey>, Vec<EpochKey>) {
        // Bounded by the pairing cap per direction (one stale key
        // per held edge, like the close-time sweeps).
        let stale_attempts: Vec<EpochKey> = self
            .pending_attempts
            .keys()
            .filter(|key| key.key.pid == pid && key.key.tid == tid)
            .copied()
            .collect();
        for key in &stale_attempts {
            if let Some(held) = self.pending_attempt_remove(key) {
                self.unpaired_entries = self.unpaired_entries.saturating_add(1);
                self.totals.unpaired_entries = self.totals.unpaired_entries.saturating_add(1);
                self.push_live_exemplar(ExemplarDir::Entry, key.key, held.api);
            }
        }
        let stale_results: Vec<EpochKey> = self
            .pending_results
            .keys()
            .filter(|key| key.key.pid == pid && key.key.tid == tid)
            .copied()
            .collect();
        for key in &stale_results {
            if let Some(held) = self.pending_result_remove(key) {
                self.unpaired_results = self.unpaired_results.saturating_add(1);
                self.totals.unpaired_results = self.totals.unpaired_results.saturating_add(1);
                self.push_live_exemplar(ExemplarDir::Result, key.key, held.api);
            }
        }
        (stale_attempts, stale_results)
    }

    /// Drop EVERY HW scope of a (pid,tid) (all epochs, all
    /// generations) with index cleanup.
    fn drop_tid_scopes(&mut self, pid: u32, tid: u32) {
        let dead: Vec<ScopeKey> = self
            .inv_hw
            .keys()
            .filter(|scope| scope.pid == pid && scope.tid == tid)
            .copied()
            .collect();
        // Bounded by the scope cap (one entry per scope).
        for scope in dead {
            if let Some(hw) = self.inv_hw.remove(&scope) {
                self.scope_order.remove(&(hw.insert_window, hw.seq));
            }
        }
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
    fn pending_attempt_insert(&mut self, key: EpochKey, api: u32, monotonic_ns: u64) {
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
        // G3: accept-path stamp (the hold accepts the newcomer).
        self.touch_scope(&key);
    }

    /// Index-maintaining removal of a held ATTEMPT.
    fn pending_attempt_remove(&mut self, key: &EpochKey) -> Option<PendingEdge> {
        let held = self.pending_attempts.remove(key)?;
        self.pending_attempt_order.remove(&(held.window, held.seq));
        Some(held)
    }

    /// Insert a held RESULT (G1: cap-enforced FIFO).
    fn pending_result_insert(&mut self, key: EpochKey, api: u32, monotonic_ns: u64, outcome: u32) {
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
        // G3: accept-path stamp (the hold accepts the newcomer).
        self.touch_scope(&key);
    }

    /// Index-maintaining removal of a held RESULT.
    fn pending_result_remove(&mut self, key: &EpochKey) -> Option<PendingEdge> {
        let held = self.pending_results.remove(key)?;
        self.pending_result_order.remove(&(held.window, held.seq));
        Some(held)
    }

    /// Evict the oldest pending ATTEMPT (FIFO cap enforcement):
    /// visible unpaired count + exemplar + evicted count, NEVER
    /// an HW advance (eviction ≠ consumption — the counterpart
    /// may still arrive; terminal buckets stay correct).
    fn evict_oldest_attempt(&mut self) {
        let Some((&order, &key)) = self.pending_attempt_order.iter().next() else {
            return;
        };
        self.pending_attempt_order.remove(&order);
        if let Some(held) = self.pending_attempts.remove(&key) {
            self.unpaired_entries = self.unpaired_entries.saturating_add(1);
            self.totals.unpaired_entries = self.totals.unpaired_entries.saturating_add(1);
            self.pending_evicted_entries = self.pending_evicted_entries.saturating_add(1);
            self.totals.pending_evicted_entries =
                self.totals.pending_evicted_entries.saturating_add(1);
            self.push_live_exemplar(ExemplarDir::Entry, key.key, held.api);
        }
    }

    /// Evict the oldest pending RESULT (FIFO cap enforcement):
    /// visible unpaired count + exemplar + evicted count, never
    /// an HW advance.
    fn evict_oldest_result(&mut self) {
        let Some((&order, &key)) = self.pending_result_order.iter().next() else {
            return;
        };
        self.pending_result_order.remove(&order);
        if let Some(held) = self.pending_results.remove(&key) {
            self.unpaired_results = self.unpaired_results.saturating_add(1);
            self.totals.unpaired_results = self.totals.unpaired_results.saturating_add(1);
            self.pending_evicted_results = self.pending_evicted_results.saturating_add(1);
            self.totals.pending_evicted_results =
                self.totals.pending_evicted_results.saturating_add(1);
            self.push_live_exemplar(ExemplarDir::Result, key.key, held.api);
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

    /// Mark scope activity on ACCEPT paths only (pending-insert
    /// and pair — G3): an immediate-unpaired edge must NEVER
    /// stamp the scope clock, or rejections self-perpetuate
    /// stale HW (the recycled-tid feedback loop). Idle-drop keys
    /// on accepted arrivals only.
    fn touch_scope(&mut self, key: &EpochKey) {
        let window = self.window;
        self.scope_or_insert(ScopeKey::of(key)).last_window = window;
    }

    /// F3 replay check: a consumed-or-older invocation with NO live
    /// state is a dup. Call only when no pending entry holds `key`
    /// in either direction — live state means unconsumed (nested
    /// per-thread invocations interleave, so a live counterpart
    /// always pairs and the high-water never overrides it).
    fn is_hw_dup(&self, key: &EpochKey) -> bool {
        self.inv_hw
            .get(&ScopeKey::of(key))
            .is_some_and(|scope| scope.hw.is_some_and(|hw| key.key.invocation <= hw))
    }

    /// Advance the scope high-water past a consumed invocation
    /// (pair/expiry/finalize). Deliberately not activity: the
    /// idle-drop clock runs on arrivals, not bookkeeping.
    fn advance_hw(&mut self, key: &EpochKey) {
        let entry = self.scope_or_insert(ScopeKey::of(key));
        entry.hw = Some(
            entry
                .hw
                .map_or(key.key.invocation, |hw| hw.max(key.key.invocation)),
        );
    }

    fn pair(&mut self, key: EpochKey, api: u32, attempt_ns: u64, result_ns: u64, outcome: u32) {
        // G3: accept-path stamp (the pair accepts the newcomer).
        self.touch_scope(&key);
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
            // §6D-3 opt-in: per-(api, class) distributions over
            // operational IDs 20..=72 only.
            if self.histogram_by_api && (20..=72).contains(&api) {
                let cell = (api - 20) as usize;
                if let Some(h) = self.api_hists.as_mut() {
                    h[cell][slot].fold(duration_ns);
                }
                if let Some(h) = self.totals.api_histograms.as_mut() {
                    h[cell][slot].fold(duration_ns);
                }
            }
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
        assert_eq!(self.epochs.len(), self.epoch_order.len(), "epoch index");
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
        for ((window, seq), who) in &self.epoch_order {
            let r = self.epochs.get(who).expect("epoch order resolves");
            assert_eq!((r.insert_window, r.seq), (*window, *seq));
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

    /// Default test incarnation (nonzero, like the wire gate).
    const STAMP: u64 = 0x5A44;
    /// A second test incarnation (recycled tid).
    const STAMP_NEW: u64 = 0x5A45;
    /// Default test seed (0 — the legitimate first creation; every
    /// default-helper test below pins the decoder's NO-nonzero-gate
    /// rule implicitly).
    const SEED: u64 = 0;
    /// A second test seed (recreated row).
    const SEED_NEW: u64 = 1;

    fn attempt(key: PairKey, api: u32, ns: u64) -> AttemptEdge {
        AttemptEdge {
            key,
            api,
            monotonic_ns: ns,
            start_time_ns: STAMP,
            seed: SEED,
        }
    }

    fn result(key: PairKey, api: u32, ns: u64, outcome: u32) -> ResultEdge {
        ResultEdge {
            key,
            api,
            monotonic_ns: ns,
            outcome,
            start_time_ns: STAMP,
            seed: SEED,
        }
    }

    fn attempt_stamped(key: PairKey, api: u32, ns: u64, stamp: u64) -> AttemptEdge {
        AttemptEdge {
            key,
            api,
            monotonic_ns: ns,
            start_time_ns: stamp,
            seed: SEED,
        }
    }

    fn result_stamped(key: PairKey, api: u32, ns: u64, outcome: u32, stamp: u64) -> ResultEdge {
        ResultEdge {
            key,
            api,
            monotonic_ns: ns,
            outcome,
            start_time_ns: stamp,
            seed: SEED,
        }
    }

    fn attempt_seeded(key: PairKey, api: u32, ns: u64, seed: u64) -> AttemptEdge {
        AttemptEdge {
            key,
            api,
            monotonic_ns: ns,
            start_time_ns: STAMP,
            seed,
        }
    }

    fn result_seeded(key: PairKey, api: u32, ns: u64, outcome: u32, seed: u64) -> ResultEdge {
        ResultEdge {
            key,
            api,
            monotonic_ns: ns,
            outcome,
            start_time_ns: STAMP,
            seed,
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
    fn demux_fetch_extension_is_fetch() {
        // Phase 1 amendment P1-A1: 73..=80 demux Fetch; the
        // unknown boundary moves from 73 to 81.
        for api in 73..=80 {
            assert_eq!(demux(api), Some(TraceFamily::Fetch), "api {api}");
        }
        for api in [0, 81, 82, 100, 1000, u32::MAX] {
            assert_eq!(demux(api), None, "api {api}");
        }
        assert_eq!(TRACE_API_SLOTS, 81);
    }

    #[test]
    fn demux_families_are_exact() {
        for api in (1..=9).chain(16..=19) {
            assert_eq!(demux(api), Some(TraceFamily::Lifecycle), "api {api}");
        }
        for api in (10..=15).chain(73..=80) {
            assert_eq!(demux(api), Some(TraceFamily::Fetch), "api {api}");
        }
        for api in 20..=72 {
            assert_eq!(demux(api), Some(TraceFamily::PublicApi), "api {api}");
        }
        for api in [0, 81, 82, 100, 1000, u32::MAX] {
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
    fn reject_storm_does_not_refresh_scope() {
        // G3 (codex R2-3): immediate-unpaired rejections must NOT
        // refresh the scope clock — a reject storm still expires
        // (breaks the reject-refresh feedback loop that kept a
        // recycled tid's stale HW alive forever).
        let mut p = edge_bearing();
        let k = key(10, 11, 1, 100, 50);
        p.attempt(attempt(k, 20, 1000));
        p.result(result(k, 20, 1500, 1));
        p.close_window(0, 2000, [0; 8]);
        for w in 0..2u64 {
            for inv in 1..=50u64 {
                let d = key(10, 11, 1, 200 + inv, inv);
                p.attempt(attempt(d, 20, 3000 + w * 1000 + inv));
                p.result(result(d, 20, 3050 + w * 1000 + inv, 1));
            }
            p.close_window(1 + w, 4000 + w * 1000, [0; 8]);
        }
        // Scope expired despite the storm → the ancient key
        // re-pairs (disclosed F3 residual: replay after expiry
        // pairs; BPF never emits dups).
        p.attempt(attempt(k, 20, 9000));
        p.result(result(k, 20, 9500, 1));
        p.finalize(9999);
        let t = p.totals();
        assert_eq!(t.paired, 2);
        assert_eq!((t.unpaired_entries, t.unpaired_results), (100, 100));
        let ra: u64 = t.received.attempts.iter().sum();
        let rr: u64 = t.received.results.iter().sum();
        assert_eq!(ra, t.paired + t.unpaired_entries);
        assert_eq!(rr, t.paired + t.unpaired_results);
    }

    #[test]
    fn incarnation_same_epoch_never_pairs_either_order() {
        // fix4: same-key edges with different BPF stamps never pair
        // even in the SAME epoch (recycle-before-retire: the epoch
        // cannot separate them — only the stamp can). Both arrival
        // orders; conservation exact.
        for swap in [false, true] {
            let mut p = edge_bearing();
            let k = key(10, 11, 1, 100, 7);
            if swap {
                p.result(result_stamped(k, 20, 1500, 1, STAMP_NEW));
                p.attempt(attempt_stamped(k, 20, 1000, STAMP));
            } else {
                p.attempt(attempt_stamped(k, 20, 1000, STAMP));
                p.result(result_stamped(k, 20, 1500, 1, STAMP_NEW));
            }
            p.finalize(2000);
            let t = p.totals();
            assert_eq!(t.paired, 0, "swap={swap}: no cross-incarnation pair");
            assert_eq!(
                (t.unpaired_entries, t.unpaired_results),
                (1, 1),
                "swap={swap}"
            );
            let ra: u64 = t.received.attempts.iter().sum();
            let rr: u64 = t.received.results.iter().sum();
            assert_eq!(ra, t.paired + t.unpaired_entries, "swap={swap}");
            assert_eq!(rr, t.paired + t.unpaired_results, "swap={swap}");
        }
    }

    #[test]
    fn incarnation_same_stamp_pairs_and_hw_is_per_incarnation() {
        // fix4: same-stamp edges pair (legitimate — it really
        // happened), and the high-water is per-incarnation: a
        // consumed invocation in the old incarnation never
        // suppresses the recycled same-invocation call (fix6:
        // BPF rows restart invocations at 1 BY DESIGN, scoped by
        // the seed — the forged reuse below pins the
        // stamp-namespace isolation as one sufficient strand).
        let mut p = edge_bearing();
        let k = key(10, 11, 1, 100, 7);
        p.attempt(attempt_stamped(k, 20, 1000, STAMP));
        p.result(result_stamped(k, 20, 1500, 1, STAMP));
        assert_eq!(p.totals().paired, 1, "same-stamp pair forms");
        // Forged recycled-tid reuse of invocation 7 under a new
        // stamp: not an HW dup (the old scope's HW is namespaced
        // away).
        p.attempt(attempt_stamped(k, 20, 2000, STAMP_NEW));
        p.result(result_stamped(k, 20, 2500, 1, STAMP_NEW));
        p.finalize(3000);
        let t = p.totals();
        assert_eq!(
            (t.paired, t.unpaired_entries, t.unpaired_results),
            (2, 0, 0)
        );
    }

    #[test]
    fn same_stamp_different_invocations_never_pair() {
        // fix5 (R5-3 dissolution proof): same stamp + DIFFERENT
        // invocations (+ same epoch/key) NEVER pair, both feed
        // orders. A same-stamp mispair WITHOUT invocation reuse
        // would force the clocksource-restriction path — this
        // proves the pairing key separates on invocation alone
        // (the joint invariant's second sufficient strand).
        for swap in [false, true] {
            let mut p = edge_bearing();
            let ka = key(10, 11, 1, 100, 7);
            let kb = key(10, 11, 1, 100, 8);
            if swap {
                p.result(result_stamped(kb, 20, 1500, 1, STAMP));
                p.attempt(attempt_stamped(ka, 20, 1000, STAMP));
            } else {
                p.attempt(attempt_stamped(ka, 20, 1000, STAMP));
                p.result(result_stamped(kb, 20, 1500, 1, STAMP));
            }
            p.finalize(3000);
            let t = p.totals();
            assert_eq!(
                (t.paired, t.unpaired_entries, t.unpaired_results),
                (0, 1, 1),
                "swap={swap}"
            );
        }
    }

    #[test]
    fn seed_scoped_cross_creation_reuse_never_pairs() {
        // fix6 F1/F3e GREEN (RED was the R6-1 mispair on seedless
        // code — same schedule paired (1,0,0)): row A (seed 0)
        // emits invocation 2, is deleted by numeric cleanup; row B
        // (seed 1) restarts and re-emits invocation 2 BY DESIGN.
        // Late RESULT(A) + ATTEMPT(B) share stamp+epoch+key+
        // invocation (same task — a live-row delete never
        // re-stamps) but carry DIFFERENT seeds: no pair, both
        // orders. Conservation exact.
        for swap in [false, true] {
            let mut p = edge_bearing();
            let k = key(10, 11, 1, 100, 2);
            if swap {
                p.result(result_seeded(k, 20, 1500, 1, SEED));
                p.attempt(attempt_seeded(k, 20, 1000, SEED_NEW));
            } else {
                p.attempt(attempt_seeded(k, 20, 1000, SEED_NEW));
                p.result(result_seeded(k, 20, 1500, 1, SEED));
            }
            p.finalize(2000);
            let t = p.totals();
            assert_eq!(
                (t.paired, t.unpaired_entries, t.unpaired_results),
                (0, 1, 1),
                "swap={swap}: cross-seed reuse must not pair"
            );
            let ra: u64 = t.received.attempts.iter().sum();
            let rr: u64 = t.received.results.iter().sum();
            assert_eq!(ra, t.paired + t.unpaired_entries, "swap={swap}");
            assert_eq!(rr, t.paired + t.unpaired_results, "swap={swap}");
        }
    }

    #[test]
    fn seed_scoped_same_seed_restart_pairs_and_hw_is_per_seed() {
        // fix6 F1 availability + HW-per-seed: same-seed edges pair
        // (legitimate — it really happened), and the high-water is
        // per-seed: a consumed invocation under the old seed never
        // suppresses the recreated same-invocation call (rows
        // restart at 1 BY DESIGN — an unscoped HW would false-dup
        // every recreated row's first calls).
        let mut p = edge_bearing();
        let k = key(10, 11, 1, 100, 1);
        p.attempt(attempt_seeded(k, 20, 1000, SEED));
        p.result(result_seeded(k, 20, 1500, 1, SEED));
        assert_eq!(p.totals().paired, 1, "same-seed pair forms");
        // Recreated row restarts invocation 1 under a new seed:
        // not an HW dup (the old scope's HW is namespaced away).
        p.attempt(attempt_seeded(k, 20, 2000, SEED_NEW));
        p.result(result_seeded(k, 20, 2500, 1, SEED_NEW));
        p.finalize(3000);
        let t = p.totals();
        assert_eq!(
            (t.paired, t.unpaired_entries, t.unpaired_results),
            (2, 0, 0)
        );
        // ... while a same-seed replay stays HW-blocked.
        p.attempt(attempt_seeded(k, 20, 4000, SEED_NEW));
        p.result(result_seeded(k, 20, 4500, 1, SEED_NEW));
        p.finalize(5000);
        let t = p.totals();
        assert_eq!(
            (t.paired, t.unpaired_entries, t.unpaired_results),
            (2, 1, 1),
            "same-seed replay stays dup-unpaired"
        );
    }

    #[test]
    fn same_stamp_different_seeds_never_pair() {
        // fix6 F1: same stamp + SAME invocation + different seeds
        // NEVER pair, both feed orders — extends the R5-3 proof to
        // the three-strand invariant (the seed strand separates on
        // its own, like the stamp and invocation strands).
        for swap in [false, true] {
            let mut p = edge_bearing();
            let k = key(10, 11, 1, 100, 7);
            if swap {
                p.result(result_seeded(k, 20, 1500, 1, SEED_NEW));
                p.attempt(attempt_seeded(k, 20, 1000, SEED));
            } else {
                p.attempt(attempt_seeded(k, 20, 1000, SEED));
                p.result(result_seeded(k, 20, 1500, 1, SEED_NEW));
            }
            p.finalize(3000);
            let t = p.totals();
            assert_eq!(
                (t.paired, t.unpaired_entries, t.unpaired_results),
                (0, 1, 1),
                "swap={swap}"
            );
        }
    }

    #[test]
    fn seed_scoped_restart_pairs_across_retire() {
        // fix6 availability (replaces the fix5 high-seed pin — the
        // old `b > a`-on-`next` assert is VOID: it measured the
        // wrong thing): rows restart invocations at 1 BY DESIGN,
        // scoped by the seed. Old incarnation pairs (seed 0), retire
        // (bump), then the recycled row RESTARTS at invocation 1
        // under a new seed (same stamp — a delete/recreate without
        // tid death never re-stamps; the seed separates alone) and
        // pairs; same-seed continuation also pairs (no HW block).
        let mut p = edge_bearing();
        let k1 = key(10, 11, 1, 100, 5);
        p.attempt(attempt_seeded(k1, 20, 1000, SEED));
        p.result(result_seeded(k1, 20, 1500, 1, SEED));
        assert_eq!(p.totals().paired, 1, "old pair forms");
        p.retire_scope(10, 11);
        let k2 = key(10, 11, 1, 100, 1);
        p.attempt(attempt_seeded(k2, 20, 2000, SEED_NEW));
        p.result(result_seeded(k2, 20, 2500, 1, SEED_NEW));
        let k3 = key(10, 11, 1, 100, 2);
        p.attempt(attempt_seeded(k3, 20, 2600, SEED_NEW));
        p.result(result_seeded(k3, 20, 2700, 1, SEED_NEW));
        p.finalize(3000);
        let t = p.totals();
        assert_eq!(
            (t.paired, t.unpaired_entries, t.unpaired_results),
            (3, 0, 0)
        );
    }

    #[test]
    fn retire_epoch_queued_old_record_never_pairs() {
        // fix3: an old-incarnation ATTEMPT held at bump time must
        // never pair with a late same-key RESULT (different epoch):
        // the hold expires unpaired, the late edge pends under the
        // new epoch and expires unpaired. No cross-incarnation
        // mispair; conservation exact.
        let mut p = edge_bearing();
        let k = key(10, 11, 1, 100, 7);
        p.attempt(attempt(k, 20, 1000));
        p.retire_scope(10, 11);
        p.result(result(k, 20, 1500, 1));
        assert_eq!(p.totals().paired, 0);
        assert_eq!(
            p.totals().unpaired_results,
            0,
            "late edge pends, then expires"
        );
        let w0 = p.close_window(0, 2000, [0; 8]);
        assert_eq!(
            (w0.paired, w0.unpaired_entries, w0.unpaired_results),
            (0, 0, 0)
        );
        let w1 = p.close_window(1, 3000, [0; 8]);
        assert_eq!((w1.unpaired_entries, w1.unpaired_results), (1, 1));
        assert_eq!(w1.exemplars.len(), 2);
        p.finalize(4000);
        let t = p.totals();
        assert_eq!(
            (t.paired, t.unpaired_entries, t.unpaired_results),
            (0, 1, 1)
        );
        let ra: u64 = t.received.attempts.iter().sum();
        let rr: u64 = t.received.results.iter().sum();
        assert_eq!(ra, t.paired + t.unpaired_entries);
        assert_eq!(rr, t.paired + t.unpaired_results);
    }

    #[test]
    fn retire_epoch_bounded_and_off_mode() {
        // fix3: epoch storage is FIXED-CAPPED (FIFO), and the bump
        // fires in off-mode too (no edges, no panic — the epoch is
        // recorded for the next edge-bearing feed, which pairs
        // immediately in the fresh epoch).
        let mut p = TraceProducer::new();
        p.retire_scope(10, 11);
        assert_eq!(p.epochs.len(), 1);
        assert_eq!(p.epoch_of(10, 11), 1);
        for i in 0..5000u32 {
            p.retire_scope(100 + (i % 7), 2000 + i);
        }
        assert!(p.epochs.len() <= TRACE_PAIRING_CAP);
        p.check_indexes();
        p.retire_scope(7, 7);
        p.set_mode(TRACE_MODE_LATENCY);
        let k = key(7, 7, 1, 100, 1);
        p.attempt(attempt(k, 20, 1000));
        p.result(result(k, 20, 1500, 1));
        p.finalize(2000);
        let t = p.totals();
        assert_eq!(
            (t.paired, t.unpaired_entries, t.unpaired_results),
            (1, 0, 0)
        );
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
        // fix3: the G2 stale-orphan eviction is correctness-driven
        // (F4 forward-only), not cap-driven — no evicted counts.
        assert_eq!(
            (t.pending_evicted_entries, t.pending_evicted_results),
            (0, 0)
        );
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
    fn fix7_dropped_attempt_leaves_result_unpaired_and_later_pair_valid() {
        // fix7 F1 (R7-1 verdict (i) pin, pairing plane): a lost
        // ATTEMPT never lets its RESULT pair with anything else
        // (different invocation = different EpochKey) — the orphan
        // expires unpaired-visible — and a post-loss complete pair
        // on another invocation pairs valid.
        let mut p = edge_bearing();
        let lost = key(10, 11, 1, 100, 7);
        let later = key(10, 11, 1, 100, 8);
        p.result(result(lost, 20, 1000, 1));
        p.close_window(0, 1500, [0; 8]);
        let w1 = p.close_window(1, 2500, [0; 8]);
        assert_eq!((w1.paired, w1.unpaired_results), (0, 1));
        p.attempt(attempt(later, 20, 3000));
        p.result(result(later, 20, 3500, 1));
        p.close_window(2, 4000, [0; 8]);
        p.finalize(4500);
        let t = p.totals();
        assert_eq!(t.paired, 1);
        assert_eq!((t.unpaired_entries, t.unpaired_results), (0, 1));
        let rr: u64 = t.received.results.iter().sum();
        assert_eq!(rr, t.paired + t.unpaired_results);
    }
    #[test]
    fn fix7_dropped_result_leaves_attempt_unpaired_and_later_pair_valid() {
        // fix7 F1 (R7-1 verdict (i) pin, pairing plane): a lost
        // RESULT never lets its ATTEMPT pair with anything else —
        // the orphan expires unpaired-visible (+ exemplar) — and a
        // post-loss complete pair on another invocation pairs
        // valid. No cross-invocation mispair exists.
        let mut p = edge_bearing();
        let lost = key(10, 11, 1, 100, 7);
        let later = key(10, 11, 1, 100, 8);
        p.attempt(attempt(lost, 20, 1000));
        p.close_window(0, 1500, [0; 8]);
        let w1 = p.close_window(1, 2500, [0; 8]);
        assert_eq!((w1.paired, w1.unpaired_entries), (0, 1));
        assert_eq!(w1.exemplars.len(), 1);
        assert_eq!(w1.exemplars[0].dir, ExemplarDir::Entry);
        p.attempt(attempt(later, 20, 3000));
        p.result(result(later, 20, 3500, 1));
        p.close_window(2, 4000, [0; 8]);
        p.finalize(4500);
        let t = p.totals();
        assert_eq!(t.paired, 1);
        assert_eq!((t.unpaired_entries, t.unpaired_results), (1, 0));
        let ra: u64 = t.received.attempts.iter().sum();
        assert_eq!(ra, t.paired + t.unpaired_entries);
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
        for api in (1..=9).chain(10..=15).chain(16..=19).chain(73..=80) {
            for outcome in 0..=4 {
                assert_eq!(pair_class(api, outcome), 0, "api {api}");
            }
        }
        for api in 20..=72 {
            for outcome in 0..=4 {
                assert_eq!(pair_class(api, outcome), outcome, "api {api}");
            }
        }
        for api in [0, 81, 100, u32::MAX] {
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
        // fix3: every FIFO sacrifice is counted (2×cap evicted per
        // direction; the cap still held at `finalize` expires
        // uncounted — evicted ⊆ unpaired).
        assert_eq!(t.pending_evicted_entries, 2 * cap as u64);
        assert_eq!(t.pending_evicted_results, 2 * cap as u64);
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
        // fix3: scope eviction drops HW only (pending self-sufficient)
        // — no pending sacrificed, no evicted counts.
        assert_eq!(
            (t.pending_evicted_entries, t.pending_evicted_results),
            (0, 0)
        );
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

    #[test]
    fn three_window_late_mixed_colliding_keys_never_pair() {
        // fix3 (codex R3-2): drain-then-bump shape — the old-incarnation
        // edge was externally queued at retire time, so the session's
        // retire-drain fed it PRE-bump (epoch 0); the recycled same-key
        // counterpart arrives 3 windows post-bump (epoch 1). Cross-epoch
        // → NEVER pair, both unpaired, no fabricated duration — across
        // an ARBITRARY gap (the epoch boundary is permanent; no
        // window-counted expiry can be outrun).
        let mut p = edge_bearing();
        // k1: colliding — old A drained pre-bump, recycled R 3 windows later.
        let k1 = key(10, 11, 1, 100, 7);
        p.attempt(attempt(k1, 20, 1000));
        // k2: complete old pair drained pre-bump (preserved).
        let k2 = key(10, 11, 1, 101, 8);
        p.attempt(attempt(k2, 20, 1100));
        p.result(result(k2, 20, 1500, 1));
        p.retire_scope(10, 11);
        // The boundary is a permanent epoch, not a window-counted marker.
        assert_eq!(p.epoch_of(10, 11), 1);
        assert_eq!(p.epoch_of(10, 12), 0, "untouched tid stays epoch 0");
        p.close_window(0, 2000, [0; 8]);
        p.close_window(1, 3000, [0; 8]);
        p.close_window(2, 4000, [0; 8]);
        assert_eq!(p.epoch_of(10, 11), 1, "no window-counted expiry");
        p.result(result(k1, 20, 9000, 1));
        // k3: clean recycled pair post-bump (new incarnation unaffected).
        let k3 = key(10, 11, 1, 102, 1);
        p.attempt(attempt(k3, 20, 9100));
        p.result(result(k3, 20, 9500, 1));
        p.close_window(3, 9999, [0; 8]);
        p.finalize(10_000);
        let t = p.totals();
        assert_eq!(t.paired, 2, "k2 old + k3 new pair; k1 never");
        assert_eq!((t.unpaired_entries, t.unpaired_results), (1, 1));
        assert_eq!(t.nonmonotonic_pairs, 0);
        assert_eq!(t.class_counts.iter().sum::<u64>(), t.paired);
        let hist_total: u64 = t.histograms.iter().map(|h| h.count).sum();
        assert_eq!(hist_total, 2, "only real pairs histogrammed");
        let ra: u64 = t.received.attempts.iter().sum();
        let rr: u64 = t.received.results.iter().sum();
        assert_eq!(ra, t.paired + t.unpaired_entries);
        assert_eq!(rr, t.paired + t.unpaired_results);
    }

    #[test]
    fn feed_after_epoch_eviction_never_mispairs() {
        // fix3 (codex R3-3): retire, 4096 other retires (cap evicts the
        // first protection), then the recycled same-key RESULT. The
        // evicted hold surfaces unpaired (+ evicted count) and the
        // recycled edge NEVER pairs with it: 0+1+1, conservation exact.
        let mut p = edge_bearing();
        let k = key(10, 11, 1, 100, 7);
        p.attempt(attempt(k, 20, 1000));
        p.retire_scope(10, 11);
        for i in 0..4096u32 {
            p.retire_scope(100 + (i % 7), 2000 + i);
        }
        p.result(result(k, 20, 1500, 1));
        assert_eq!(p.totals().paired, 0, "evicted hold must never pair");
        // Coupled incarnation-evict expiry: the hold's sacrifice is counted.
        assert_eq!(p.totals().pending_evicted_entries, 1);
        assert_eq!(p.totals().pending_evicted_results, 0);
        let w0 = p.close_window(0, 2000, [0; 8]);
        assert_eq!(w0.pending_evicted_entries, 1, "window carries the count");
        assert_eq!(w0.pending_evicted_results, 0);
        p.close_window(1, 3000, [0; 8]);
        p.finalize(4000);
        let t = p.totals();
        assert_eq!(
            (t.paired, t.unpaired_entries, t.unpaired_results),
            (0, 1, 1)
        );
        assert_eq!(
            (t.pending_evicted_entries, t.pending_evicted_results),
            (1, 0),
            "evicted counts are cumulative"
        );
        let ra: u64 = t.received.attempts.iter().sum();
        let rr: u64 = t.received.results.iter().sum();
        assert_eq!(ra, t.paired + t.unpaired_entries);
        assert_eq!(rr, t.paired + t.unpaired_results);
    }

    #[test]
    fn retire_epoch_recycle_matrix() {
        // fix3: epochs replace window-counted markers — old-old pairs preserved iff
        // drained pre-bump; the new incarnation pairs clean IMMEDIATELY
        // (no 2-window rejection); cross-bump same-key halves never
        // pair. (fix6: the forged post-bump invocations 1..=10 below
        // exercise the epoch namespace — and real recycled tids DO
        // restart at 1 now, scoped by their fresh seed.)
        let mut p = edge_bearing();
        // Old incarnation: complete pairs (both gens) + one dangling hold.
        for generation in [1u64, 2] {
            for inv in 1..=10u64 {
                let k = key(10, 11, generation, 100 + inv, inv);
                p.attempt(attempt(k, 20, 1000 + inv));
                p.result(result(k, 20, 2000 + inv, 1));
            }
        }
        let dangling = key(10, 11, 1, 500, 11);
        p.attempt(attempt(dangling, 20, 1500));
        assert_eq!(p.totals().paired, 20);
        p.retire_scope(10, 11);
        // Immediately post-bump: recycled SAME keys pair clean (inv ≤ old HW;
        // forged reuse — the dropped epoch HW is what this pins).
        for generation in [1u64, 2] {
            for inv in 1..=10u64 {
                let k = key(10, 11, generation, 100 + inv, inv);
                p.attempt(attempt(k, 20, 3000 + inv));
                p.result(result(k, 20, 4000 + inv, 1));
            }
        }
        assert_eq!(p.totals().paired, 40, "new incarnation pairs immediately");
        // Cross-bump: dangling old hold's late counterpart never pairs.
        p.result(result(dangling, 20, 5000, 1));
        assert_eq!(p.totals().paired, 40);
        // Untouched scope pairs throughout (isolation).
        let other = key(10, 12, 1, 600, 1);
        p.attempt(attempt(other, 20, 5100));
        p.result(result(other, 20, 5200, 1));
        p.close_window(0, 6000, [0; 8]);
        p.close_window(1, 7000, [0; 8]);
        p.finalize(8000);
        let t = p.totals();
        assert_eq!(t.paired, 41);
        assert_eq!((t.unpaired_entries, t.unpaired_results), (1, 1));
        let ra: u64 = t.received.attempts.iter().sum();
        let rr: u64 = t.received.results.iter().sum();
        assert_eq!(ra, t.paired + t.unpaired_entries);
        assert_eq!(rr, t.paired + t.unpaired_results);
    }

    #[test]
    fn counterpart_after_evict_reports_evicted_counts() {
        // fix3 (codex R3-1 counters): hold A(k), flood 4096 other-tid
        // ATTEMPTs (FIFO evicts A(k) — the documented visible exception),
        // then R(k) arrives within horizon. The sacrifice is counted
        // (window + cumulative), the counterpart never pairs with the
        // sacrificed hold (unpaired), conservation stays exact.
        let mut p = edge_bearing();
        let k = key(10, 11, 1, 100, 7);
        p.attempt(attempt(k, 20, 1000));
        for i in 0..4096u64 {
            let f = key(20, 3000 + i as u32, 1, 5000 + i, 1);
            p.attempt(attempt(f, 20, 2000 + i));
        }
        // A(k) was the oldest: exactly one FIFO sacrifice so far.
        assert_eq!(p.totals().pending_evicted_entries, 1);
        assert_eq!(p.totals().unpaired_entries, 1);
        p.result(result(k, 20, 9000, 1));
        assert_eq!(p.totals().paired, 0, "sacrificed hold never pairs");
        let w0 = p.close_window(0, 9500, [0; 8]);
        assert_eq!(w0.pending_evicted_entries, 1);
        assert_eq!(w0.pending_evicted_results, 0);
        p.close_window(1, 9999, [0; 8]);
        p.finalize(10_000);
        let t = p.totals();
        assert_eq!(t.paired, 0);
        assert_eq!(t.unpaired_entries, 4097);
        assert_eq!(t.unpaired_results, 1);
        assert_eq!(
            (t.pending_evicted_entries, t.pending_evicted_results),
            (1, 0),
            "one sacrifice, cumulative"
        );
        let ra: u64 = t.received.attempts.iter().sum();
        let rr: u64 = t.received.results.iter().sum();
        assert_eq!(ra, t.paired + t.unpaired_entries);
        assert_eq!(rr, t.paired + t.unpaired_results);
    }

    #[test]
    fn retire_skip_expires_pending_and_shields() {
        // fix3: the retire-drain budget-exceeded path (the session skips
        // the bump — stays unretired). The tid's pending expires
        // immediately (unpaired + exemplar, never silently) and the HW
        // shield extends past the expired holds, so recycled low
        // invocations AND late old edges land visible-unpaired instead
        // of mispairing. No pair, no corruption, conservation exact.
        let mut p = edge_bearing();
        // Old incarnation: pairs (HW 10) + two dangling holds (one per dir).
        for inv in 1..=10u64 {
            let k = key(10, 11, 1, 100 + inv, inv);
            p.attempt(attempt(k, 20, 1000 + inv));
            p.result(result(k, 20, 2000 + inv, 1));
        }
        let held_a = key(10, 11, 1, 500, 11);
        p.attempt(attempt(held_a, 20, 1500));
        let held_r = key(10, 11, 1, 501, 12);
        p.result(result(held_r, 20, 1600, 1));
        assert_eq!(p.totals().paired, 10);
        // Budget exceeded → skip the bump (epoch stays 0), expire + shield.
        p.retire_scope_skipped(10, 11);
        assert_eq!(p.epoch_of(10, 11), 0, "skipped bump stays unretired");
        assert_eq!(p.totals().paired, 10);
        assert_eq!(
            (p.totals().unpaired_entries, p.totals().unpaired_results),
            (1, 1)
        );
        // Forged low invocation (≤ old HW): visible dup-unpaired,
        // never pairs (fix6: real recycled tids mint a fresh seed
        // and pair in the new scope — this same-seed forging
        // exercises the shield mechanism).
        let r1 = key(10, 11, 1, 600, 1);
        p.attempt(attempt(r1, 20, 3000));
        p.result(result(r1, 20, 3100, 1));
        assert_eq!(p.totals().paired, 10);
        // Expired-hold invocations (11, 12 — shield extended): dup-unpaired too.
        let r2 = key(10, 11, 1, 601, 11);
        p.attempt(attempt(r2, 20, 3200));
        let r3 = key(10, 11, 1, 602, 12);
        p.result(result(r3, 20, 3300, 1));
        assert_eq!(p.totals().paired, 10);
        // Skip-expiry is budget-driven, NOT cap-driven: no evicted counts.
        assert_eq!(
            (
                p.totals().pending_evicted_entries,
                p.totals().pending_evicted_results
            ),
            (0, 0)
        );
        let w0 = p.close_window(0, 4000, [0; 8]);
        assert!(
            w0.exemplars.iter().any(|e| e.dir == ExemplarDir::Entry),
            "skipped hold leaves an Entry exemplar: {:?}",
            w0.exemplars
        );
        assert!(
            w0.exemplars.iter().any(|e| e.dir == ExemplarDir::Result),
            "skipped hold leaves a Result exemplar: {:?}",
            w0.exemplars
        );
        p.finalize(5000);
        let t = p.totals();
        assert_eq!(t.paired, 10);
        assert_eq!((t.unpaired_entries, t.unpaired_results), (3, 3));
        let ra: u64 = t.received.attempts.iter().sum();
        let rr: u64 = t.received.results.iter().sum();
        assert_eq!(ra, t.paired + t.unpaired_entries);
        assert_eq!(rr, t.paired + t.unpaired_results);
    }

    #[test]
    fn fallback_pairs_fetch_lifecycle_only() {
        // D0-6 aggregate-only fallback: fetch/lifecycle pair
        // (class-0); operational edges count received but never
        // pair, never histogram, never go unpaired.
        let mut p = TraceProducer::new();
        p.set_mode(TRACE_MODE_METADATA);
        p.set_fallback(true);
        let fetch = key(1, 1, 1, 100, 1);
        p.attempt(attempt(fetch, 10, 1000));
        p.result(result(fetch, 10, 1500, 1));
        let ext = key(1, 1, 1, 101, 2);
        p.attempt(attempt(ext, 73, 2000));
        p.result(result(ext, 73, 2500, 1));
        let life = key(1, 1, 1, 102, 3);
        p.attempt(attempt(life, 1, 3000));
        p.result(result(life, 1, 3500, 1));
        let op = key(1, 1, 1, 103, 4);
        p.attempt(attempt(op, 20, 4000));
        p.result(result(op, 20, 4500, 1));
        let w = p.close_window(0, 9000, [0; 8]);
        assert!(w.fallback);
        assert_eq!(w.paired, 3);
        assert_eq!(w.class_counts, [3, 0, 0, 0, 0]);
        for (c, h) in w.histograms.iter().enumerate() {
            assert_eq!((h.count, h.sum), (0, 0), "class {c}");
        }
        // Operational edges counted (F2) but never pending.
        assert_eq!(w.api_attempts[20], 1);
        assert_eq!(w.api_results[20], 1);
        let w1 = p.close_window(1, 9000, [0; 8]);
        assert_eq!(w1.unpaired_entries, 0);
        assert_eq!(w1.unpaired_results, 0);
        assert!(w1.fallback);
    }

    #[test]
    fn fallback_off_is_edge_bearing_only() {
        // Without fallback, metadata mode pairs nothing (BASE twin).
        let mut p = TraceProducer::new();
        p.set_mode(TRACE_MODE_METADATA);
        assert!(!p.fallback());
        let fetch = key(1, 1, 1, 100, 1);
        p.attempt(attempt(fetch, 10, 1000));
        p.result(result(fetch, 10, 1500, 1));
        let w = p.close_window(0, 9000, [0; 8]);
        assert!(!w.fallback);
        assert_eq!(w.paired, 0);
    }

    #[test]
    fn by_api_opt_in_folds_per_api_distributions() {
        // §6D-3 opt-in: per-(api, class) distributions over
        // operational IDs only; fetch never takes distributions.
        let mut p = edge_bearing();
        p.set_histogram_by_api(true);
        let a = key(1, 1, 1, 100, 1);
        p.attempt(attempt(a, 20, 1000));
        p.result(result(a, 20, 1500, 1));
        let b = key(1, 1, 1, 101, 2);
        p.attempt(attempt(b, 64, 2000));
        p.result(result(b, 64, 2600, 2));
        let f = key(1, 1, 1, 102, 3);
        p.attempt(attempt(f, 10, 3000));
        p.result(result(f, 10, 3600, 1));
        let w = p.close_window(0, 9000, [0; 8]);
        assert_eq!(w.paired, 3);
        let by_api = w.api_histograms.expect("opt-in folds per-API");
        // API 20 success: one 500ns observation.
        assert_eq!((by_api[0][1].count, by_api[0][1].sum), (1, 500));
        assert_eq!(by_api[0][1].buckets[18], 1);
        // API 64 failure: one 600ns observation.
        assert_eq!((by_api[44][2].count, by_api[44][2].sum), (1, 600));
        // Every other (api, class) cell is empty.
        for (i, classes) in by_api.iter().enumerate() {
            for (c, h) in classes.iter().enumerate() {
                if (i, c) != (0, 1) && (i, c) != (44, 2) {
                    assert_eq!((h.count, h.sum), (0, 0), "cell {i}/{c}");
                }
            }
        }
        // Totals fold cumulatively.
        let t = p.totals();
        let th = t.api_histograms.expect("totals fold per-API");
        assert_eq!((th[0][1].count, th[0][1].sum), (1, 500));
        assert_eq!((th[44][2].count, th[44][2].sum), (1, 600));
    }

    #[test]
    fn by_api_opt_out_folds_nothing() {
        // Default OFF: no per-API state, no rows.
        let mut p = edge_bearing();
        assert!(!p.histogram_by_api());
        let a = key(1, 1, 1, 100, 1);
        p.attempt(attempt(a, 20, 1000));
        p.result(result(a, 20, 1500, 1));
        let w = p.close_window(0, 9000, [0; 8]);
        assert_eq!(w.paired, 1);
        assert!(w.api_histograms.is_none());
        assert!(p.totals().api_histograms.is_none());
    }

    #[test]
    fn pairing_uncertainty_triggers_and_fresh_boundary_clears() {
        // P2fix1 item 3 (codex PAIRING) as corrected by P2fix2 item
        // 5 (codex PAIRING-OPEN): pairing-state corruption (pending
        // eviction, depth overflow, decode rejection) marks the
        // window uncertain; plain ring loss does not (detectable
        // loss rides PARTIAL, not withholding); taint carries until
        // a PROVED fresh boundary (terminal settlement via finalize
        // plus a clean close — empty host pending maps alone never
        // clear it) while epoch totals stay sticky-suspect.
        // Clean window: certain.
        let mut p = edge_bearing();
        let a = key(1, 1, 1, 100, 1);
        p.attempt(attempt(a, 20, 1000));
        p.result(result(a, 20, 1500, 1));
        let w = p.close_window(0, 9000, [0; 8]);
        assert!(!w.pairing_uncertain);
        assert!(w.pairing_uncertainty.is_empty());
        assert!(!p.totals().pairing_uncertain);
        // Decode rejection corrupts pairing trust.
        let mut p = edge_bearing();
        p.reject_unknown();
        let w = p.close_window(0, 9000, [0; 8]);
        assert!(w.pairing_uncertain);
        assert_eq!(w.pairing_uncertainty, vec!["decode-reject".to_string()]);
        // Depth overflow (the overflow schedule) corrupts trust.
        let mut p = edge_bearing();
        let w = p.close_window(0, 9000, [0, 0, 2, 0, 0, 0, 0, 0]);
        assert!(w.pairing_uncertain);
        assert_eq!(w.pairing_uncertainty, vec!["depth-overflow".to_string()]);
        // Plain ring loss on other lanes does NOT (detectable loss
        // is PARTIAL-flagged, never withheld).
        let mut p = edge_bearing();
        let w = p.close_window(0, 9000, [5, 4, 0, 0, 0, 0, 0, 0]);
        assert!(!w.pairing_uncertain);
        // Pending-cap eviction corrupts trust.
        let mut p = edge_bearing();
        for i in 0..(TRACE_PAIRING_CAP as u64 + 1) {
            p.attempt(attempt(key(1, 1, 1, 1000 + i, i + 1), 20, 1000 + i));
        }
        let w = p.close_window(0, 9000, [0; 8]);
        assert!(w.pending_evicted_entries > 0);
        assert!(w.pairing_uncertain);
        assert!(
            w.pairing_uncertainty
                .contains(&"pending-eviction".to_string())
        );
        // Taint carries across unsettled closes (P2fix2: a clean
        // close with empty pending is NOT a proved boundary — the
        // old auto-clear is rejected); only terminal settlement
        // plus a clean close proves the next window fresh.
        let mut p = edge_bearing();
        p.reject_unknown();
        let w0 = p.close_window(0, 9000, [0; 8]);
        assert!(w0.pairing_uncertain);
        let b = key(1, 1, 1, 200, 1);
        p.attempt(attempt(b, 20, 9500));
        p.result(result(b, 20, 9600, 1));
        let w1 = p.close_window(1, 9900, [0; 8]);
        assert!(w1.pairing_uncertain, "taint carries one window");
        assert!(w1.pairing_uncertainty.contains(&"carried".to_string()));
        let c = key(1, 1, 1, 201, 2);
        p.attempt(attempt(c, 20, 9950));
        p.result(result(c, 20, 9960, 1));
        let w2 = p.close_window(2, 9990, [0; 8]);
        assert!(w2.pairing_uncertain, "unsettled clean closes keep carrying");
        assert!(w2.pairing_uncertainty.contains(&"carried".to_string()));
        // Proved boundary: settle terminally, seal the boundary
        // close (still carried — pre-proof data), then fresh.
        // [p2fix5 NEW-23: the proof includes the positive
        // terminal-drain receipt — finalize alone withholds.]
        p.note_terminal_drain(true);
        p.finalize(9995);
        let w3 = p.close_window(3, 9999, [0; 8]);
        assert!(w3.pairing_uncertain, "boundary close seals carried");
        let w4 = p.close_window(4, 9999, [0; 8]);
        assert!(
            !w4.pairing_uncertain,
            "post-proof windows seal fresh: {:?}",
            w4.pairing_uncertainty
        );
        // ...but epoch totals stay sticky-suspect (cumulative folds
        // cannot un-mix suspect pairs).
        assert!(p.totals().pairing_uncertain);
        // Non-empty pending blocks the fresh boundary (suspect live
        // holds may persist).
        let mut p = edge_bearing();
        p.reject_unknown();
        let _ = p.close_window(0, 9000, [0; 8]);
        p.attempt(attempt(key(1, 1, 1, 300, 1), 20, 9500));
        let w = p.close_window(1, 9900, [0; 8]);
        assert!(w.pairing_uncertain);
    }

    #[test]
    fn withheld_summary_hides_interpreted_keeps_raw() {
        // P2fix1 items 3/14 (codex PAIRING/DELTA-8): while uncertain,
        // interpreted duration/status distributions withhold (None)
        // and raw loss/detail evidence stays; the withheld shape
        // still validates.
        let mut p = edge_bearing();
        let a = key(1, 1, 1, 100, 1);
        p.attempt(attempt(a, 20, 1000));
        p.result(result(a, 20, 1500, 1));
        p.reject_unknown();
        let w = p.close_window(0, 9000, [0; 8]);
        let t = p.totals();
        assert!(w.pairing_uncertain && t.pairing_uncertain);
        let s = summarize(&w, &t, "latency", None);
        assert!(s.window.class_window.is_none());
        assert!(s.class_epoch.is_none());
        assert!(s.histograms.is_none());
        assert!(s.by_api.is_none());
        // Raw evidence kept.
        assert_eq!(s.window.paired, 1);
        assert_eq!(s.window.trace_rejected_unknown_api, 1);
        assert!(s.window.pairing_uncertain);
        s.validate().expect("withheld shape validates");
        // Certain window: everything flows.
        let mut q = edge_bearing();
        let b = key(1, 1, 1, 100, 1);
        q.attempt(attempt(b, 20, 1000));
        q.result(result(b, 20, 1500, 1));
        let wq = q.close_window(0, 9000, [0; 8]);
        let tq = q.totals();
        let sq = summarize(&wq, &tq, "latency", None);
        assert_eq!(sq.window.class_window.unwrap().success, 1);
        assert_eq!(sq.class_epoch.unwrap().success, 1);
        assert_eq!(sq.histograms.as_ref().unwrap().success.count, 1);
        sq.validate().expect("certain shape validates");
    }

    #[test]
    fn trace_summary_validation_rejects_incoherence() {
        // P2fix1 items 4/23 (codex GATE29/NEW-P2f): raw intake +
        // both presenter paths enforce the same strict rules —
        // inconsistent mode/fallback state, impossible
        // class/histogram counts, decreasing by-API buckets,
        // incomplete coverage binding, non-empty GAP inputs,
        // malformed exemplars/ranges, and withholding mismatches.
        fn baseline() -> TraceSummary {
            let mut p = edge_bearing();
            p.set_histogram_by_api(true);
            let a = key(1, 1, 1, 100, 1);
            p.attempt(attempt(a, 20, 1000));
            p.result(result(a, 20, 1500, 1));
            let w = p.close_window(0, 9000, [0; 8]);
            let t = p.totals();
            let mut avail = std::collections::BTreeMap::new();
            for id in 20..=72u32 {
                avail.insert(
                    id,
                    if id == 20 { "covered" } else { "not_attached" }.to_string(),
                );
            }
            summarize(&w, &t, "latency", Some(&avail))
        }
        let good = baseline();
        good.validate().expect("baseline validates");
        assert!(good.by_api.as_ref().unwrap().contains_key("20"));
        // Decreasing by-API buckets.
        let mut bad = baseline();
        bad.by_api
            .as_mut()
            .unwrap()
            .get_mut("20")
            .unwrap()
            .success
            .buckets[1] = 0;
        bad.by_api
            .as_mut()
            .unwrap()
            .get_mut("20")
            .unwrap()
            .success
            .buckets[0] = 1;
        assert!(bad.validate().is_err(), "decreasing by-api buckets");
        // Fallback with operational classes / histograms.
        let mut bad = baseline();
        bad.mode = "metadata".to_string();
        bad.fallback = true;
        assert!(bad.validate().is_err(), "fallback with histograms");
        let mut bad = baseline();
        bad.mode = "metadata".to_string();
        bad.fallback = true;
        bad.histograms = None;
        bad.by_api = None;
        bad.by_api_availability = None;
        assert!(bad.validate().is_err(), "fallback with operational class");
        // Off/metadata without fallback never seal (rejected
        // outright, same as raw intake — even all-zeros).
        let mut bad = baseline();
        bad.mode = "off".to_string();
        assert!(bad.validate().is_err(), "off with pairs");
        let mut bad = baseline();
        bad.mode = "metadata".to_string();
        bad.window.paired = 0;
        bad.window.class_window = Some(TraceClassCounts::default());
        bad.class_epoch = Some(TraceClassCounts::default());
        bad.histograms = None;
        bad.by_api = None;
        bad.by_api_availability = None;
        assert!(bad.validate().is_err(), "zeros metadata without fallback");
        // Histogram count above its class count.
        let mut bad = baseline();
        let h = &mut bad.histograms.as_mut().unwrap().success;
        h.buckets = [2; 19];
        h.count = 2;
        assert!(bad.validate().is_err(), "count above class");
        // Covered API without a by_api entry (incomplete binding).
        let mut bad = baseline();
        bad.by_api.as_mut().unwrap().clear();
        assert!(bad.validate().is_err(), "covered without entry");
        // Non-empty GAP inputs (DELTA-3: rejected until a typed
        // producer exists).
        let mut bad = baseline();
        bad.window.gaps = vec![serde_json::json!({"kind": "gap"})];
        assert!(bad.validate().is_err(), "nonempty gaps");
        let mut bad = baseline();
        bad.window.gap_overflow = 1;
        assert!(bad.validate().is_err(), "nonzero gap_overflow");
        // Malformed exemplars.
        let mut bad = baseline();
        bad.window.exemplars = vec![TraceExemplarJson {
            dir: "sideways".to_string(),
            key_hash16: "814dd7b9784d57c1".to_string(),
            api: 20,
            age_ns: 5,
        }];
        assert!(bad.validate().is_err(), "bad exemplar dir");
        bad.window.exemplars[0].dir = "entry".to_string();
        bad.window.exemplars[0].key_hash16 = "XYZ".to_string();
        assert!(bad.validate().is_err(), "bad exemplar hash");
        bad.window.exemplars[0].key_hash16 = "814dd7b9784d57c1".to_string();
        bad.window.exemplars[0].api = 999;
        assert!(bad.validate().is_err(), "bad exemplar api");
        // Malformed unmeasured ranges.
        for ranges in [
            vec![[5u64, 3u64]],
            vec![[1u64, 2u64], [2u64, 3u64]],
            vec![[3u64, 4u64], [1u64, 2u64]],
        ] {
            let mut bad = baseline();
            bad.window.unmeasured_seqs = ranges;
            assert!(bad.validate().is_err(), "malformed range");
        }
        // Withholding mismatches (both directions).
        let mut bad = baseline();
        bad.class_epoch = None;
        assert!(bad.validate().is_err(), "certain without class_epoch");
        let mut bad = baseline();
        bad.window.class_window = None;
        assert!(bad.validate().is_err(), "certain without class_window");
        let mut bad = baseline();
        bad.pairing_uncertain = true;
        assert!(bad.validate().is_err(), "uncertain with class_epoch");
        let mut bad = baseline();
        bad.window.pairing_uncertain = true;
        assert!(bad.validate().is_err(), "uncertain with class_window");
        // P2fix2 item 13 (codex NEW-P2f): status carries classes but
        // NO distributions — by-API histograms reject like default
        // histograms.
        let mut bad = baseline();
        bad.mode = "status".to_string();
        bad.window.mode = "status".to_string();
        bad.histograms = None;
        assert!(bad.by_api.is_some(), "premise: by_api rides status");
        assert!(bad.validate().is_err(), "status with by_api");
        // Inner/outer state coherence: an uncertain window taints
        // its epoch (inner-certain + outer-uncertain is the sticky
        // direction; the reverse is incoherent).
        let mut bad = baseline();
        bad.window.pairing_uncertain = true;
        bad.window.class_window = None;
        assert!(
            bad.validate().is_err(),
            "uncertain window under certain epoch"
        );
        // Inner/outer mode + fallback words agree (the projection
        // stamps both from one resolution — a mismatch is a forged
        // section).
        let mut bad = baseline();
        bad.window.mode = "all".to_string();
        assert!(bad.validate().is_err(), "window/outer mode mismatch");
        let mut bad = baseline();
        bad.window.fallback = true;
        assert!(bad.validate().is_err(), "window/outer fallback mismatch");
        // Impossible distributions: an L1 sub-fold never exceeds its
        // default fold (per class — the covered API's pairs are a
        // subset of all pairs).
        let mut bad = baseline();
        let l1 = bad
            .by_api
            .as_mut()
            .unwrap()
            .get_mut("20")
            .unwrap()
            .success
            .clone();
        assert_eq!(
            (l1.count, bad.histograms.as_ref().unwrap().success.count),
            (1, 1)
        );
        let e = bad.by_api.as_mut().unwrap().get_mut("20").unwrap();
        e.success.buckets = [2; 19];
        e.success.count = 2;
        assert!(bad.validate().is_err(), "L1 count above its default count");
    }

    fn bearing_latency() -> TraceProducer {
        let mut p = TraceProducer::new();
        p.set_mode(TRACE_MODE_LATENCY);
        p
    }

    fn pair_at(p: &mut TraceProducer, pid: u32, invocation: u64, t0: u64, t1: u64) {
        let k = key(pid, pid, 1, 500 + invocation, invocation);
        p.attempt(attempt(k, 20, t0));
        p.result(result(k, 20, t1, 1));
    }

    #[test]
    fn p2fix2_wire_rejection_taints_decode_reject() {
        // P2fix2 item 5 (codex PAIRING-OPEN): a generic wire
        // rejection (any decode-domain refusal, not just
        // unknown-ID) taints pairing as `decode-reject` — the
        // session funnel routes it here. The unknown-ID count
        // stays exact (no misattribution).
        let mut p = bearing_latency();
        pair_at(&mut p, 7, 1, 100, 200);
        p.note_wire_rejection();
        let w = p.close_window(0, 9000, [0; 8]);
        assert_eq!(w.paired, 1);
        assert!(w.pairing_uncertain, "wire rejection must taint");
        assert!(
            w.pairing_uncertainty.contains(&"decode-reject".to_string()),
            "{:?}",
            w.pairing_uncertainty
        );
        assert_eq!(w.rejected_unknown_api, 0, "not an unknown-ID record");
    }

    #[test]
    fn p2fix2_taint_carries_until_proved_boundary() {
        // P2fix2 item 5 (codex PAIRING-OPEN): taint carries across
        // closes until a PROVED fresh boundary — terminal
        // settlement (finalize) plus a clean close. Empty host
        // pending maps alone never clear it (an idle close after a
        // tainted one stays carried).
        let mut p = bearing_latency();
        pair_at(&mut p, 7, 1, 100, 200);
        p.reject_unknown();
        let w0 = p.close_window(0, 9000, [0; 8]);
        assert!(w0.pairing_uncertain, "rejection taints window 0");
        // Idle window 1 (no feeds, empty pending): taint CARRIES
        // (no proved boundary — finalize never ran).
        let w1 = p.close_window(1, 9900, [0; 8]);
        assert!(
            w1.pairing_uncertain,
            "taint must carry past an unsettled close"
        );
        assert!(
            w1.pairing_uncertainty.contains(&"carried".to_string()),
            "{:?}",
            w1.pairing_uncertainty
        );
        // Proved boundary: terminal settlement + clean close. The
        // boundary close itself still seals pre-proof data as
        // carried (fail closed — its window predates the proof);
        // the NEXT window seals fresh (the proof clears live taint).
        // [p2fix5 NEW-23: the proof includes the positive
        // terminal-drain receipt — finalize alone withholds.]
        p.note_terminal_drain(true);
        p.finalize(9950);
        let w2 = p.close_window(2, 9990, [0; 8]);
        assert!(
            w2.pairing_uncertain,
            "the boundary close seals pre-proof data as carried"
        );
        assert_eq!(w2.pairing_uncertainty, vec!["carried".to_string()]);
        let w3 = p.close_window(3, 9999, [0; 8]);
        assert!(
            !w3.pairing_uncertain,
            "post-proof windows seal fresh: {:?}",
            w3.pairing_uncertainty
        );
    }

    #[test]
    fn p2fix2_late_cut_note_taints_overrun_only() {
        // P2fix2 item 13 (codex NEW-P2e): the irreversible fold
        // cannot exclude pairs consumed past a late-discovered cut
        // — noting a cut below already-consumed timestamps taints
        // (`late-cut`); noting above stays clean.
        let mut p = bearing_latency();
        pair_at(&mut p, 7, 1, 100, 200);
        p.note_cut_edge(7, 50);
        let w = p.close_window(0, 9000, [0; 8]);
        assert_eq!(w.paired, 1);
        assert!(w.pairing_uncertain, "cut below consumed must taint");
        assert!(
            w.pairing_uncertainty.contains(&"late-cut".to_string()),
            "{:?}",
            w.pairing_uncertainty
        );
        let mut p = bearing_latency();
        pair_at(&mut p, 7, 1, 100, 200);
        p.note_cut_edge(7, 10_000);
        let w = p.close_window(0, 9000, [0; 8]);
        assert!(
            !w.pairing_uncertain,
            "cut above consumed stays clean: {:?}",
            w.pairing_uncertainty
        );
    }

    #[test]
    fn p2fix2_cut_note_is_per_pid() {
        // Another pid's fence edge never taints this pid's fold
        // (the 6A fence is per-pid; the overrun check scopes to
        // the fenced pid).
        let mut p = bearing_latency();
        pair_at(&mut p, 7, 1, 100, 200);
        p.note_cut_edge(9, 50);
        let w = p.close_window(0, 9000, [0; 8]);
        assert!(
            !w.pairing_uncertain,
            "foreign-pid cut must not taint: {:?}",
            w.pairing_uncertainty
        );
    }

    /// Forge one wire edge image (full key params — the R13
    /// schedule needs distinct cookies/invocations/timestamps).
    fn wire_edge(
        kind: u32,
        api: u32,
        cookie: u64,
        invocation: u64,
        mono_ns: u64,
        outcome: u32,
    ) -> Vec<u8> {
        use super::super::wire::contract as c;
        let mut b = vec![0u8; c::EVENT_SIZE];
        for (at, v) in [
            (0, c::VERSION),
            (4, kind),
            (8, c::EVENT_SIZE as u32),
            (12, api),
            (16, 7u32),
            (20, 8u32),
        ] {
            b[at..at + 4].copy_from_slice(&v.to_le_bytes());
        }
        for (at, v) in [(24, cookie), (32, 1u64), (40, mono_ns), (48, invocation)] {
            b[at..at + 8].copy_from_slice(&v.to_le_bytes());
        }
        b[56..60].copy_from_slice(&outcome.to_le_bytes());
        b[96..104].copy_from_slice(&1u64.to_le_bytes());
        b
    }

    /// Feed forged wire bytes through the REAL decode into the
    /// producer (the pairing key comes FROM the decoded record —
    /// producer-side key correctness, never hand-built structs).
    fn feed_wire(p: &mut TraceProducer, bytes: &[u8]) {
        use super::super::wire::contract as c;
        let event = super::super::wire::decode_transport(bytes).expect("r13 bytes decode");
        let r = event.record();
        let key = PairKey {
            pid: r.pid,
            tid: r.tid,
            generation: r.generation,
            cookie: r.cookie,
            invocation: r.invocation,
        };
        if r.kind == c::ATTEMPT {
            p.attempt(AttemptEdge {
                key,
                api: r.api,
                monotonic_ns: r.monotonic_ns,
                start_time_ns: r.start_time_ns,
                seed: r.seed,
            });
        } else {
            p.result(ResultEdge {
                key,
                api: r.api,
                monotonic_ns: r.monotonic_ns,
                outcome: r.outcome,
                start_time_ns: r.start_time_ns,
                seed: r.seed,
            });
        }
    }

    #[test]
    fn p2fix2_human_section_withholds_like_json() {
        // P2fix2 item 10 (codex DELTA-8): EVERY renderer withholds
        // the affected interpretations — the document human section
        // must mark withheld histograms/by_api as
        // `withheld (pairing uncertainty)`, never the `(status
        // mode)` mislabel and never silent.
        let mut p = bearing_latency();
        p.set_histogram_by_api(true);
        for i in 0..(TRACE_PAIRING_CAP as u64 + 1) {
            let k = key(1, 1, 1, 1000 + i, i + 1);
            p.attempt(attempt(k, 20, 1000 + i));
        }
        let w = p.close_window(0, 20000, [0; 8]);
        assert!(w.pairing_uncertain);
        let t = p.totals();
        let s = summarize(&w, &t, "latency", None);
        assert!(s.histograms.is_none() && s.by_api.is_none());
        let human = s.human_section();
        assert!(
            human.contains("histograms: withheld (pairing uncertainty)"),
            "{human:?}"
        );
        assert!(
            human.contains("by_api: withheld (pairing uncertainty)"),
            "{human:?}"
        );
        assert!(!human.contains("status mode"), "{human:?}");
        // Status-certain keeps its honest `none` (nothing withheld —
        // the mode produces no distributions).
        let mut p = bearing_latency();
        let k = key(1, 1, 1, 100, 1);
        p.attempt(attempt(k, 20, 1000));
        p.result(result(k, 20, 1500, 1));
        let w = p.close_window(0, 9000, [0; 8]);
        let t = p.totals();
        let s = summarize(&w, &t, "status", None);
        let human = s.human_section();
        assert!(
            human.contains("histograms: none (status mode)"),
            "{human:?}"
        );
    }

    #[test]
    fn newp2e_human_section_withholds_unbound_paired() {
        // P2fix4 NEW-P2e: the focused human summary withholds
        // scoped pairs like every other late-cut output — a
        // cut-unbound window prints `paired=withheld (late-cut)`
        // with the `cut_unbound=true` mark (pre-fix: the
        // contaminated count prints as ordinary `paired=N`
        // without the mark), while the retained count stays in
        // the explicitly unbound document JSON (paired + mark).
        // Clean summaries keep byte-stable lines.
        let mut p = bearing_latency();
        pair_at(&mut p, 7, 1, 100, 200);
        p.note_global_cut(50);
        let w = p.close_window(0, 9000, [0; 8]);
        assert!(w.late_cut && w.pairing_uncertain);
        let t = p.totals();
        let s = summarize(&w, &t, "latency", None);
        s.validate().expect("marked summary validates");
        let human = s.human_section();
        assert!(
            human.contains("paired=withheld (late-cut)"),
            "unbound paired withholds: {human:?}"
        );
        assert!(
            human.contains("cut_unbound=true"),
            "unbound mark rides: {human:?}"
        );
        assert!(
            !human.contains(&format!("paired={}", w.paired)),
            "contaminated count never prints ordinary: {human:?}"
        );
        // Retained count stays in the explicitly unbound
        // document JSON (paired + mark together).
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["window"]["paired"], w.paired);
        assert_eq!(v["window"]["cut_unbound"], true);
        // Clean summary: ordinary count, no mark, stable bytes.
        let mut q = bearing_latency();
        pair_at(&mut q, 7, 1, 100, 200);
        q.note_global_cut(10_000);
        let wq = q.close_window(0, 9000, [0; 8]);
        let tq = q.totals();
        let sq = summarize(&wq, &tq, "latency", None);
        let clean = sq.human_section();
        assert!(
            clean.contains(&format!("paired={}", wq.paired)),
            "clean count prints: {clean:?}"
        );
        assert!(!clean.contains("cut_unbound"), "{clean:?}");
        assert!(!clean.contains("withheld (late-cut)"), "{clean:?}");
    }

    #[test]
    fn new10_fallback_rejects_nonfamily_exemplar_ids() {
        // P2fix3 NEW-10 as corrected by P2fix4 NEW-17/DELTA-7:
        // under fallback, exemplar APIs must be the §6D-6
        // fetch/lifecycle family (1..=6, 10..=15, 73..=80) — the
        // only pairs a fallback producer emits. Operational IDs
        // (20..=72) reject (a fallback record carrying them is
        // forged or corrupt, never projectable); the extended
        // fetch IDs (73..=80) are legitimate fallback output and
        // validate.
        fn fallback_baseline() -> TraceSummary {
            let mut p = TraceProducer::new();
            p.set_mode(TRACE_MODE_METADATA);
            p.set_fallback(true);
            let a = key(1, 1, 1, 100, 1);
            p.attempt(attempt(a, 10, 1000));
            p.result(result(a, 10, 1500, 1));
            let w = p.close_window(0, 9000, [0; 8]);
            let t = p.totals();
            summarize(&w, &t, "metadata", None)
        }
        let good = fallback_baseline();
        good.validate().expect("fallback baseline validates");
        for api in [1u32, 6, 10, 15, 73, 80] {
            let mut ok = fallback_baseline();
            ok.window.exemplars = vec![TraceExemplarJson {
                dir: "entry".to_string(),
                key_hash16: "814dd7b9784d57c1".to_string(),
                api,
                age_ns: 5,
            }];
            assert!(ok.validate().is_ok(), "family api {api} validates");
        }
        for api in [20u32, 64, 72] {
            let mut bad = fallback_baseline();
            bad.window.exemplars = vec![TraceExemplarJson {
                dir: "entry".to_string(),
                key_hash16: "814dd7b9784d57c1".to_string(),
                api,
                age_ns: 5,
            }];
            assert!(
                bad.validate().is_err(),
                "non-family api {api} must reject under fallback"
            );
        }
        // Non-fallback keeps the wire-valid rule (an operational
        // exemplar on a latency summary still validates).
        let mut p = edge_bearing();
        let a = key(1, 1, 1, 100, 1);
        p.attempt(attempt(a, 20, 1000));
        p.result(result(a, 20, 1500, 1));
        let w = p.close_window(0, 9000, [0; 8]);
        let t = p.totals();
        let mut ok = summarize(&w, &t, "latency", None);
        ok.window.exemplars = vec![TraceExemplarJson {
            dir: "entry".to_string(),
            key_hash16: "814dd7b9784d57c1".to_string(),
            api: 20,
            age_ns: 5,
        }];
        ok.validate()
            .expect("operational exemplar validates off-fallback");
    }

    #[test]
    fn new17_fallback_family_matches_producer_pairing() {
        // P2fix4 NEW-17: ONE fetch/lifecycle classifier shared by
        // production pairing and intake validation. The producer
        // pairs 73..=80 as fetch under fallback, so their
        // exemplars validate at intake (pre-fix: rejected);
        // operational IDs (20..=72) never pair under fallback, so
        // they still reject. Exhaustive agreement: every api in
        // 0..=100 pairs under a fallback producer iff the shared
        // classifier admits it.
        fn fallback_baseline() -> TraceSummary {
            let mut p = TraceProducer::new();
            p.set_mode(TRACE_MODE_METADATA);
            p.set_fallback(true);
            let a = key(1, 1, 1, 100, 1);
            p.attempt(attempt(a, 10, 1000));
            p.result(result(a, 10, 1500, 1));
            let w = p.close_window(0, 9000, [0; 8]);
            let t = p.totals();
            summarize(&w, &t, "metadata", None)
        }
        // Expanded-fetch orphan positive (intake).
        for api in [73u32, 76, 80] {
            let mut ok = fallback_baseline();
            ok.window.exemplars = vec![TraceExemplarJson {
                dir: "entry".to_string(),
                key_hash16: "814dd7b9784d57c1".to_string(),
                api,
                age_ns: 5,
            }];
            assert!(
                ok.validate().is_ok(),
                "expanded-fetch api {api} must validate under fallback: {:?}",
                ok.validate().err()
            );
            assert!(
                super::fallback_family_clean(&ok),
                "expanded-fetch api {api} must read family-clean"
            );
        }
        // Operational-ID negative (intake, kept).
        for api in [20u32, 45, 72] {
            let mut bad = fallback_baseline();
            bad.window.exemplars = vec![TraceExemplarJson {
                dir: "entry".to_string(),
                key_hash16: "814dd7b9784d57c1".to_string(),
                api,
                age_ns: 5,
            }];
            assert!(
                bad.validate().is_err(),
                "operational api {api} must reject under fallback"
            );
            assert!(
                !super::fallback_family_clean(&bad),
                "operational api {api} must read family-broken"
            );
        }
        // Production/intake agreement over the whole ID space.
        for api in 0..=100u32 {
            let mut p = TraceProducer::new();
            p.set_mode(TRACE_MODE_METADATA);
            p.set_fallback(true);
            let a = key(1, 1, 1, 100, 1);
            p.attempt(attempt(a, api, 1000));
            p.result(result(a, api, 1500, 1));
            let w = p.close_window(0, 9000, [0; 8]);
            let paired = w.paired == 1;
            assert_eq!(
                paired,
                super::fallback_pairing_family(api),
                "api {api}: production pairing must agree with the shared classifier"
            );
        }
    }

    #[test]
    fn newp2f_l1_combined_never_exceeds_parent() {
        // P2fix3 NEW-P2f: exact class conservation — the L1
        // sub-folds conserve into their default fold per class:
        // the COMBINED L1 counts/buckets/sums never exceed the
        // parent (each entry alone may fit while their sum
        // overflows — that sum is the conserved quantity).
        fn two_api_baseline() -> TraceSummary {
            let mut p = TraceProducer::new();
            p.set_mode(TRACE_MODE_LATENCY);
            p.set_histogram_by_api(true);
            for (api, inv) in [(20u32, 1u64), (21u32, 2u64)] {
                let k = key(1, 1, 1, 100 + inv, inv);
                p.attempt(attempt(k, api, 1000));
                p.result(result(k, api, 1500, 1));
            }
            let w = p.close_window(0, 9000, [0; 8]);
            let t = p.totals();
            let mut avail = std::collections::BTreeMap::new();
            for id in 20..=72u32 {
                avail.insert(
                    id,
                    if id == 20 || id == 21 {
                        "covered"
                    } else {
                        "not_attached"
                    }
                    .to_string(),
                );
            }
            summarize(&w, &t, "latency", Some(&avail))
        }
        let good = two_api_baseline();
        good.validate().expect("two-api baseline validates");
        // Parent success: count 2, sum 1000 (two 500ns pairs); each
        // L1 entry holds its own pair (count 1, sum 500).
        assert_eq!(good.histograms.as_ref().unwrap().success.count, 2);
        assert_eq!(good.histograms.as_ref().unwrap().success.sum, 1000);
        // Case A — combined counts above the parent (each entry
        // alone fits its count: 2 ≤ 2 — with fitting sums).
        let mut bad = two_api_baseline();
        for id in ["20", "21"] {
            let d = &mut bad.by_api.as_mut().unwrap().get_mut(id).unwrap().success;
            d.buckets = [2; 19];
            d.count = 2;
            d.sum = 500;
        }
        assert!(
            bad.validate().is_err(),
            "combined L1 counts above parent must reject"
        );
        // Case B — combined buckets above the parent with fitting
        // counts (each L1 entry claims full low-edge mass: the
        // 500ns pairs sit above edge 0, so edge 0 overflows).
        let mut bad = two_api_baseline();
        assert_eq!(
            bad.histograms.as_ref().unwrap().success.buckets[0],
            0,
            "premise: 500ns pairs sit above edge 0"
        );
        for id in ["20", "21"] {
            let d = &mut bad.by_api.as_mut().unwrap().get_mut(id).unwrap().success;
            d.buckets = [1; 19];
            d.count = 1;
            d.sum = 500;
        }
        assert!(
            bad.validate().is_err(),
            "combined L1 buckets above parent must reject"
        );
        // Case C — combined sums above the parent with fitting
        // counts + buckets (each L1 entry carries the parent's
        // full sum; folded shapes untouched).
        let mut bad = two_api_baseline();
        for id in ["20", "21"] {
            let d = &mut bad.by_api.as_mut().unwrap().get_mut(id).unwrap().success;
            d.sum = 1000;
        }
        assert!(
            bad.validate().is_err(),
            "combined L1 sums above parent must reject"
        );
    }

    #[test]
    fn newp2f_class_conservation_is_exact_at_u64_max() {
        // P2fix4 NEW-P2f: class conservation uses widened exact
        // arithmetic — a saturating sum must never equal u64::MAX
        // into acceptance. [MAX, 1, 0, 0, 0] with paired=MAX
        // saturates to MAX (pre-fix: validates); the exact sum
        // (MAX+1) exceeds paired and must reject. An exact-MAX
        // vector still validates (control).
        let baseline = || {
            let mut p = edge_bearing();
            let a = key(1, 1, 1, 100, 1);
            p.attempt(attempt(a, 20, 1000));
            p.result(result(a, 20, 1500, 1));
            let w = p.close_window(0, 9000, [0; 8]);
            let t = p.totals();
            summarize(&w, &t, "latency", None)
        };
        baseline().validate().expect("baseline validates");
        let mut bad = baseline();
        bad.window.class_window = Some(TraceClassCounts {
            success: u64::MAX,
            failure: 1,
            empty: 0,
            retry: 0,
            unknown: 0,
        });
        bad.window.paired = u64::MAX;
        assert!(
            bad.validate().is_err(),
            "overfull class vector (exact sum MAX+1) must reject at paired=MAX"
        );
        let mut ok = baseline();
        ok.window.class_window = Some(TraceClassCounts {
            success: u64::MAX,
            failure: 0,
            empty: 0,
            retry: 0,
            unknown: 0,
        });
        ok.window.paired = u64::MAX;
        assert!(
            ok.validate().is_ok(),
            "exact-MAX class vector must validate: {:?}",
            ok.validate().err()
        );
    }

    #[test]
    fn newp2f_gate_rejects_zero_count_positive_sum() {
        // P2fix3 NEW-P2f: `count=0, sum>0` is impossible (no pairs
        // folded a positive total) — the trace gate rejects it in
        // default AND L1 distributions, like the adapters omit it.
        let bad = {
            let mut p = edge_bearing();
            p.set_histogram_by_api(true);
            let a = key(1, 1, 1, 100, 1);
            p.attempt(attempt(a, 20, 1000));
            p.result(result(a, 20, 1500, 1));
            let w = p.close_window(0, 9000, [0; 8]);
            let t = p.totals();
            let mut avail = std::collections::BTreeMap::new();
            for id in 20..=72u32 {
                avail.insert(
                    id,
                    if id == 20 { "covered" } else { "not_attached" }.to_string(),
                );
            }
            summarize(&w, &t, "latency", Some(&avail))
        };
        bad.validate().expect("baseline validates");
        // Default distribution.
        let mut one = bad.clone();
        one.histograms.as_mut().unwrap().failure.buckets = [0; 19];
        one.histograms.as_mut().unwrap().failure.count = 0;
        one.histograms.as_mut().unwrap().failure.sum = 7;
        assert!(one.validate().is_err(), "default count=0/sum>0 must reject");
        // L1 distribution (covered API 20, empty class).
        let mut two = bad.clone();
        {
            let d = &mut two.by_api.as_mut().unwrap().get_mut("20").unwrap().empty;
            d.buckets = [0; 19];
            d.count = 0;
            d.sum = 7;
        }
        assert!(two.validate().is_err(), "L1 count=0/sum>0 must reject");
    }

    #[test]
    fn delta8_uncertainty_reasons_validate_before_renderers() {
        // P2fix3 DELTA-8: uncertainty reasons validate (closed
        // vocabulary + uncertain-iff-nonempty) BEFORE any renderer
        // trusts them — every downstream emission (JSON, frames,
        // terminal) reads validated reasons only.
        fn certain_baseline() -> TraceSummary {
            let mut p = edge_bearing();
            let a = key(1, 1, 1, 100, 1);
            p.attempt(attempt(a, 20, 1000));
            p.result(result(a, 20, 1500, 1));
            let w = p.close_window(0, 9000, [0; 8]);
            assert!(w.pairing_uncertainty.is_empty());
            let t = p.totals();
            summarize(&w, &t, "latency", None)
        }
        let good = certain_baseline();
        good.validate().expect("certain baseline validates");
        // Closed vocabulary (the five seal reasons).
        for reason in [
            "pending-eviction",
            "depth-overflow",
            "decode-reject",
            "late-cut",
            "carried",
        ] {
            let mut ok = certain_baseline();
            ok.window.pairing_uncertain = true;
            ok.window.pairing_uncertainty = vec![reason.to_string()];
            // Scope coherence (P2fix3 NEW-P2e): the mark rides the
            // late-cut reason exactly.
            ok.window.cut_unbound = reason == "late-cut";
            ok.window.class_window = None;
            ok.pairing_uncertain = true;
            ok.class_epoch = None;
            ok.histograms = None;
            assert!(
                ok.validate().is_ok(),
                "vocabulary reason {reason} validates"
            );
        }
        for reason in ["bogus", "decode_reject", "CARRIED", "", "late-cut "] {
            let mut bad = certain_baseline();
            bad.window.pairing_uncertain = true;
            bad.window.pairing_uncertainty = vec![reason.to_string()];
            bad.window.class_window = None;
            bad.pairing_uncertain = true;
            bad.class_epoch = None;
            bad.histograms = None;
            assert!(
                bad.validate().is_err(),
                "non-vocabulary reason {reason:?} must reject"
            );
        }
        // Uncertain-iff-nonempty (both directions).
        let mut bad = certain_baseline();
        bad.window.pairing_uncertain = true;
        bad.window.class_window = None;
        bad.pairing_uncertain = true;
        bad.class_epoch = None;
        bad.histograms = None;
        assert!(
            bad.window.pairing_uncertainty.is_empty(),
            "premise: producer-empty reasons"
        );
        assert!(
            bad.validate().is_err(),
            "uncertain with empty reasons must reject"
        );
        let mut bad = certain_baseline();
        bad.window.pairing_uncertainty = vec!["carried".to_string()];
        assert!(bad.validate().is_err(), "certain with reasons must reject");
    }

    #[test]
    fn newp2e_late_cut_seal_marks_window_unbound() {
        // P2fix3 NEW-P2e: a late cut marks the sealed window
        // unbound — the seal carries `late_cut`, the summary
        // carries the `cut_unbound` scope mark with the taint, and
        // the gate binds mark ⟺ late-cut reason (clean seals stay
        // bound with stable bytes).
        let mut p = bearing_latency();
        pair_at(&mut p, 7, 1, 100, 200);
        p.note_global_cut(50);
        let w = p.close_window(0, 9000, [0; 8]);
        assert!(w.late_cut, "seal marks the late cut");
        assert!(w.pairing_uncertain);
        let t = p.totals();
        let s = summarize(&w, &t, "latency", None);
        assert!(s.window.cut_unbound, "summary marks unbound scope");
        assert!(
            s.window
                .pairing_uncertainty
                .contains(&"late-cut".to_string()),
            "taint rides the mark"
        );
        s.validate().expect("marked unbound summary validates");
        // Gate coherence (both directions).
        let mut bad = s.clone();
        bad.window.pairing_uncertainty = vec!["carried".to_string()];
        assert!(
            bad.validate().is_err(),
            "mark without late-cut reason rejects"
        );
        let mut bad = s.clone();
        bad.window.cut_unbound = false;
        assert!(
            bad.validate().is_err(),
            "late-cut reason without mark rejects"
        );
        // Clean seals stay bound (no mark, validates, stable
        // bytes — the mark serializes only when set).
        let mut q = bearing_latency();
        pair_at(&mut q, 7, 1, 100, 200);
        q.note_global_cut(10_000);
        let wq = q.close_window(0, 9000, [0; 8]);
        assert!(!wq.late_cut);
        let tq = q.totals();
        let sq = summarize(&wq, &tq, "latency", None);
        assert!(!sq.window.cut_unbound);
        sq.validate().expect("clean summary validates");
        let v = serde_json::to_value(&sq).unwrap();
        assert!(v["window"].get("cut_unbound").is_none());
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["window"]["cut_unbound"], true);
    }

    #[test]
    fn pairing_taint_clears_only_on_successful_boundary() {
        // P2fix3 PAIRING: taint clears ONLY on a SUCCESSFUL
        // producer boundary — a failed terminal boundary (cut
        // failure) carries taint through finalize+close instead
        // of proving fresh, while a successful one clears.
        let mut p = bearing_latency();
        pair_at(&mut p, 7, 1, 100, 200);
        p.reject_unknown();
        let w0 = p.close_window(0, 9000, [0; 8]);
        assert!(w0.pairing_uncertain, "decode-reject taints");
        // Failed terminal boundary: the seal carries (and the
        // NEXT window still carries — never cleared).
        p.note_boundary_failure();
        p.finalize(10_000);
        let w1 = p.close_window(1, 11_000, [0; 8]);
        assert!(w1.pairing_uncertain, "failed boundary carries taint");
        assert!(
            w1.pairing_uncertainty.contains(&"carried".to_string()),
            "{:?}",
            w1.pairing_uncertainty
        );
        let w2 = p.close_window(2, 12_000, [0; 8]);
        assert!(
            w2.pairing_uncertain,
            "failed boundary never clears: {:?}",
            w2.pairing_uncertainty
        );
        // Successful terminal boundary (same taint): the seal
        // carries once, then the proved boundary clears.
        // [p2fix5 NEW-23: success includes the positive
        // terminal-drain receipt — finalize alone withholds.]
        let mut q = bearing_latency();
        pair_at(&mut q, 7, 1, 100, 200);
        q.reject_unknown();
        let _ = q.close_window(0, 9000, [0; 8]);
        q.note_terminal_drain(true);
        q.finalize(10_000);
        let wq = q.close_window(1, 11_000, [0; 8]);
        assert!(wq.pairing_uncertain, "seal shows carried taint");
        let wq2 = q.close_window(2, 12_000, [0; 8]);
        assert!(
            !wq2.pairing_uncertain,
            "proved boundary clears: {:?}",
            wq2.pairing_uncertainty
        );
    }

    #[test]
    fn new20_terminal_drain_overrun_latches_like_gate_close() {
        // P2fix4 NEW-20/PAIRING: the affirmative terminal-drain
        // result enters settlement like the gate-close result — a
        // dirty terminal drain (remainder dropped) latches the
        // producer-boundary failure: prior taint carries through
        // finalize+close AND the next window (never clears). A
        // clean terminal drain latches nothing: the seal carries
        // once, then the proved boundary clears (pinned
        // separately from the fully-successful boundary).
        let mut p = bearing_latency();
        pair_at(&mut p, 7, 1, 100, 200);
        p.reject_unknown();
        let w0 = p.close_window(0, 9000, [0; 8]);
        assert!(w0.pairing_uncertain, "decode-reject taints");
        // Successful close, FAILED drain: taint carries, never
        // clears.
        p.note_terminal_drain(false);
        p.finalize(10_000);
        let w1 = p.close_window(1, 11_000, [0; 8]);
        assert!(
            w1.pairing_uncertain,
            "failed drain carries prior taint: {:?}",
            w1.pairing_uncertainty
        );
        assert!(
            w1.pairing_uncertainty.contains(&"carried".to_string()),
            "{:?}",
            w1.pairing_uncertainty
        );
        let w2 = p.close_window(2, 12_000, [0; 8]);
        assert!(
            w2.pairing_uncertain,
            "failed drain never clears: {:?}",
            w2.pairing_uncertainty
        );
        // Fully successful boundary (same taint): the seal
        // carries once, then clears.
        let mut q = bearing_latency();
        pair_at(&mut q, 7, 1, 100, 200);
        q.reject_unknown();
        let _ = q.close_window(0, 9000, [0; 8]);
        q.note_terminal_drain(true);
        q.finalize(10_000);
        let wq = q.close_window(1, 11_000, [0; 8]);
        assert!(wq.pairing_uncertain, "seal shows carried taint");
        let wq2 = q.close_window(2, 12_000, [0; 8]);
        assert!(
            !wq2.pairing_uncertain,
            "clean drain + close proves fresh: {:?}",
            wq2.pairing_uncertainty
        );
    }

    #[test]
    fn new23_unproved_terminal_boundary_withholds() {
        // P2fix5 NEW-23: host finalization alone proves NOTHING —
        // without a positive terminal-drain receipt the taint
        // carries through finalize+close AND the next window
        // (pre-fix: the clear predicate passes on settled+clean
        // alone, clearing without drainage evidence).
        let mut q = bearing_latency();
        pair_at(&mut q, 7, 1, 100, 200);
        q.reject_unknown();
        let w0 = q.close_window(0, 9000, [0; 8]);
        assert!(w0.pairing_uncertain, "decode-reject taints");
        q.finalize(10_000);
        let w1 = q.close_window(1, 11_000, [0; 8]);
        assert!(w1.pairing_uncertain, "seal shows carried taint");
        assert!(
            w1.pairing_uncertainty.contains(&"carried".to_string()),
            "{:?}",
            w1.pairing_uncertainty
        );
        let w2 = q.close_window(2, 12_000, [0; 8]);
        assert!(
            w2.pairing_uncertain,
            "an unproved terminal boundary never clears: {:?}",
            w2.pairing_uncertainty
        );
    }

    #[test]
    fn new32_failed_clean_history_seal_withholds() {
        // P2fix6 NEW-32: an EXPLICIT failed terminal boundary
        // withholds interpretations EVEN with clean history (a
        // clean close can no longer launder a failed producer
        // boundary — pre-fix: no uncertainty signal fires, so the
        // seal publishes). Both failure funnels (failed gate cut
        // via `note_boundary_failure`, failed/unproved drain via
        // `note_terminal_drain(false)`) seal uncertain with the
        // `terminal-boundary-failed` reason, and the projection
        // withholds interpreted classes/distributions while raw
        // counters stay.
        for (what, fail) in [("cut", true), ("drain", false)] {
            let mut p = bearing_latency();
            pair_at(&mut p, 7, 1, 100, 200);
            if fail {
                p.note_boundary_failure();
            } else {
                p.note_terminal_drain(false);
            }
            p.finalize(10_000);
            let w = p.close_window(1, 11_000, [0; 8]);
            assert_eq!(w.paired, 1, "{what}: raw pairs still flow");
            assert!(
                w.pairing_uncertain,
                "{what}: a failed terminal boundary withholds on clean history: {:?}",
                w.pairing_uncertainty
            );
            assert!(
                w.pairing_uncertainty
                    .contains(&"terminal-boundary-failed".to_string()),
                "{what}: the failure names itself: {:?}",
                w.pairing_uncertainty
            );
            let summary = summarize(&w, &p.totals(), "latency", None);
            summary
                .validate()
                .expect("{what}: the withholding seal validates");
            assert!(
                summary.class_epoch.is_none(),
                "{what}: interpreted classes withhold"
            );
            assert!(
                summary.histograms.is_none(),
                "{what}: interpreted distributions withhold"
            );
            // The failure never clears on a later window either.
            let w2 = p.close_window(2, 12_000, [0; 8]);
            assert!(
                w2.pairing_uncertain,
                "{what}: a failed boundary never clears: {:?}",
                w2.pairing_uncertainty
            );
        }
    }

    #[test]
    fn new32_proved_clean_history_seal_publishes() {
        // P2fix6 NEW-32 positively-settled control: a clean
        // history WITH the positive terminal-drain receipt seals
        // certain and publishes interpretations (the receipt is
        // the difference from the withhold pin above).
        let mut p = bearing_latency();
        pair_at(&mut p, 7, 1, 100, 200);
        p.note_terminal_drain(true);
        p.finalize(10_000);
        let w = p.close_window(1, 11_000, [0; 8]);
        assert_eq!(w.paired, 1);
        assert!(
            !w.pairing_uncertain,
            "a proved clean-history seal publishes: {:?}",
            w.pairing_uncertainty
        );
        let summary = summarize(&w, &p.totals(), "latency", None);
        summary.validate().expect("the publishing seal validates");
        assert!(
            summary.class_epoch.is_some(),
            "interpreted classes publish on the proved boundary"
        );
        assert!(
            summary.histograms.is_some(),
            "interpreted distributions publish on the proved boundary"
        );
    }

    #[test]
    fn new23_proved_terminal_boundary_clears() {
        // P2fix5 NEW-23 control: WITH the positive terminal-drain
        // receipt the settled clean close carries once, then the
        // proved boundary clears (green before and after — the
        // receipt is the difference from the withhold pin above).
        let mut q = bearing_latency();
        pair_at(&mut q, 7, 1, 100, 200);
        q.reject_unknown();
        let w0 = q.close_window(0, 9000, [0; 8]);
        assert!(w0.pairing_uncertain, "decode-reject taints");
        q.note_terminal_drain(true);
        q.finalize(10_000);
        let w1 = q.close_window(1, 11_000, [0; 8]);
        assert!(w1.pairing_uncertain, "seal shows carried taint");
        let w2 = q.close_window(2, 12_000, [0; 8]);
        assert!(
            !w2.pairing_uncertain,
            "proved boundary clears: {:?}",
            w2.pairing_uncertainty
        );
    }

    #[test]
    fn new4_trace_diagnostics_name_fields_not_values() {
        // P2fix4 NEW-4: trace-validation rejections name the FIELD,
        // never the rejected input text (canary words in mode,
        // reasons, exemplar dirs, by_api keys, or availability
        // words must not echo into diagnostics).
        let mut p = edge_bearing();
        p.set_histogram_by_api(true);
        let a = key(1, 1, 1, 100, 1);
        p.attempt(attempt(a, 20, 1000));
        p.result(result(a, 20, 1500, 1));
        let w = p.close_window(0, 9000, [0; 8]);
        let t = p.totals();
        let mut avail = std::collections::BTreeMap::new();
        for id in 20..=72u32 {
            avail.insert(
                id,
                if id == 20 { "covered" } else { "not_attached" }.to_string(),
            );
        }
        let good = summarize(&w, &t, "latency", Some(&avail));
        good.validate().expect("baseline validates");
        // Bad mode word.
        let mut bad = good.clone();
        bad.mode = "EVIL_MODE_N0ECHO".to_string();
        bad.window.mode = "EVIL_MODE_N0ECHO".to_string();
        let err = bad.validate().expect_err("bad mode must reject");
        assert!(
            !err.contains("EVIL_MODE_N0ECHO"),
            "mode must not echo: {err}"
        );
        // Bad uncertainty reason.
        let mut bad = good.clone();
        bad.pairing_uncertain = true;
        bad.class_epoch = None;
        bad.histograms = None;
        bad.by_api = None;
        bad.by_api_availability = None;
        bad.window.pairing_uncertain = true;
        bad.window.class_window = None;
        bad.window.pairing_uncertainty = vec!["EVIL_REASON_N0ECHO".to_string()];
        let err = bad.validate().expect_err("bad reason must reject");
        assert!(
            !err.contains("EVIL_REASON_N0ECHO"),
            "reason must not echo: {err}"
        );
        // Bad exemplar dir.
        let mut bad = good.clone();
        bad.window.exemplars = vec![TraceExemplarJson {
            dir: "EVIL_DIR_N0ECHO".to_string(),
            key_hash16: "814dd7b9784d57c1".to_string(),
            api: 20,
            age_ns: 5,
        }];
        let err = bad.validate().expect_err("bad dir must reject");
        assert!(!err.contains("EVIL_DIR_N0ECHO"), "dir must not echo: {err}");
        // Bad by_api key + bad availability word (via JSON so the
        // map keys/words ride the typed read).
        let mut v = serde_json::to_value(&good).unwrap();
        v["by_api"]["EVIL_KEY_N0ECHO"] = v["by_api"]["20"].clone();
        v["by_api"].as_object_mut().unwrap().remove("20");
        let err = super::parse_trace_section(&v).expect_err("bad key must reject");
        assert!(!err.contains("EVIL_KEY_N0ECHO"), "key must not echo: {err}");
        let mut v = serde_json::to_value(&good).unwrap();
        v["by_api_availability"]["20"] = serde_json::json!("EVIL_WORD_N0ECHO");
        let err = super::parse_trace_section(&v).expect_err("bad word must reject");
        assert!(
            !err.contains("EVIL_WORD_N0ECHO"),
            "word must not echo: {err}"
        );
    }

    #[test]
    fn new3_fallback_family_invariant_detects_operational_content() {
        // P2fix3 NEW-3: a fallback-shaped stored summary carries
        // ONLY fallback-family content (fetch/lifecycle classes +
        // family exemplars) — operational classes or exemplar IDs
        // fail the invariant (the presenter withholds on failure,
        // never trusting intake alone).
        fn fallback_seal() -> TraceSummary {
            let mut p = TraceProducer::new();
            p.set_mode(TRACE_MODE_METADATA);
            p.set_fallback(true);
            let a = key(1, 1, 1, 100, 1);
            p.attempt(attempt(a, 10, 1000));
            p.result(result(a, 10, 1500, 1));
            let w = p.close_window(0, 9000, [0; 8]);
            let t = p.totals();
            summarize(&w, &t, "metadata", None)
        }
        let good = fallback_seal();
        assert!(super::fallback_family_clean(&good));
        // Operational class under fallback.
        let mut bad = fallback_seal();
        bad.window.class_window.as_mut().unwrap().success = 1;
        assert!(
            !super::fallback_family_clean(&bad),
            "operational class under fallback fails"
        );
        // Operational exemplar under fallback.
        let mut bad = fallback_seal();
        bad.window.exemplars = vec![TraceExemplarJson {
            dir: "entry".to_string(),
            key_hash16: "814dd7b9784d57c1".to_string(),
            api: 20,
            age_ns: 5,
        }];
        assert!(
            !super::fallback_family_clean(&bad),
            "operational exemplar under fallback fails"
        );
        // Family exemplar under fallback passes.
        let mut ok = fallback_seal();
        ok.window.exemplars = vec![TraceExemplarJson {
            dir: "entry".to_string(),
            key_hash16: "814dd7b9784d57c1".to_string(),
            api: 10,
            age_ns: 5,
        }];
        assert!(super::fallback_family_clean(&ok));
        // Non-fallback summaries always pass (operational content
        // is legitimate off-fallback).
        let mut p = edge_bearing();
        let a = key(1, 1, 1, 100, 1);
        p.attempt(attempt(a, 20, 1000));
        p.result(result(a, 20, 1500, 1));
        let w = p.close_window(0, 9000, [0; 8]);
        let t = p.totals();
        let lat = summarize(&w, &t, "latency", None);
        assert!(super::fallback_family_clean(&lat));
    }

    #[test]
    fn r13_emitted_schedule_carries_through_publication() {
        // P2fix3 item 5 (codex PAIRING-OPEN): the ACTUAL R13 emitted
        // schedule (`r13_mixed_rejected_steal` — seven framed Y
        // calls + operational X1, quota units A(Y) + B(X), window
        // close mid-flight, B's rejected return stealing X1's
        // frame, A's accept emitting (7,900) against Y7's frame,
        // X1's genuine return consuming B's orphaned unit) driven
        // as REAL wire bytes through decode into the producer,
        // then through summarize → validate → JSON → presenter →
        // adapters/frame. The quota units + rejected return are
        // BPF-side mechanics (no wire records — the frozen model
        // asserts suppr/disc/evicted all 0, so loss_abs stays
        // zero); the producer sees their EMISSION consequences:
        // seven Y-keyed RESULTs ([(7,900),(6,6)..(1,1)] — Y7
        // FIRST with X1's 900ns, then Y6..Y1 in LIFO order; the
        // model's small durations map to post-close ns deltas, the
        // 900 mislabel exactly) and NO X1 RESULT. Key-exact
        // matching pairs all 7 Y frames (Y7 carries the 900 into
        // fetch class-0, never histogrammed) and orphans X1's
        // attempt visibly — paired 7 with the orphan + exemplar,
        // never a silent 8.
        use super::super::wire::contract as c;
        let mut p = bearing_latency();
        // Frames: Y1..Y7 (cookie 1, fetch api 10) + X1 (cookie 2,
        // operational api 20), invocations 1..=8.
        for i in 1..=7u64 {
            feed_wire(&mut p, &wire_edge(c::ATTEMPT, 10, 1, i, 1000 + 10 * i, 0));
        }
        feed_wire(&mut p, &wire_edge(c::ATTEMPT, 20, 2, 8, 1100, 0));
        // The window closes mid-flight (the R13 close — holds carry,
        // nothing expires: pre-expiry, unlike the retired analog).
        let w0 = p.close_window(0, 1900, [0; 8]);
        assert_eq!(
            (w0.paired, w0.unpaired_entries, w0.unpaired_results),
            (0, 0, 0)
        );
        assert!(!w0.pairing_uncertain);
        // Emitted RESULTs: (7,900) FIRST, then Y6..Y1 LIFO; X1
        // emits nothing (consumed by the rejected arm).
        feed_wire(&mut p, &wire_edge(c::RESULT, 10, 1, 7, 1970, 1));
        for i in (1..=6u64).rev() {
            feed_wire(&mut p, &wire_edge(c::RESULT, 10, 1, i, 2080 - 10 * i, 1));
        }
        let w1 = p.close_window(1, 9900, [0; 8]);
        assert_eq!(w1.paired, 7, "seven Y frames pair; X1 orphans");
        assert_eq!((w1.unpaired_entries, w1.unpaired_results), (1, 0));
        assert!(!w1.pairing_uncertain, "orphan expiry stays certain");
        // Classes: 7 fetch class-0, ZERO operational success (X1
        // never paired — its frame holds no RESULT).
        assert_eq!(w1.class_counts, [7, 0, 0, 0, 0]);
        // The mislabeled 900 rides Y7's fetch pair (class-0,
        // never histogrammed): NO operational duration folds —
        // verdict distributions stay uncontaminated.
        for (slot, name) in [(0, "unknown"), (1, "success")] {
            assert_eq!(w1.histograms[slot].count, 0, "{name} histogram empty");
            assert_eq!(w1.histograms[slot].sum, 0, "{name} sum empty");
        }
        // X1's orphan is visible (entry exemplar, operational api).
        assert!(
            w1.exemplars.iter().any(|e| e.api == 20),
            "X1 orphan exemplified: {:?}",
            w1.exemplars.iter().map(|e| e.api).collect::<Vec<_>>()
        );
        let t = p.totals();
        assert_eq!(
            (t.paired, t.unpaired_entries, t.unpaired_results),
            (7, 1, 0)
        );
        assert!(!t.pairing_uncertain);
        // Through publication: the certain shape projects with
        // the orphan visible (paired 7, class-0 7, operational 0).
        let s = summarize(&w1, &t, "latency", None);
        s.validate().expect("r13 summary validates");
        let json = serde_json::to_value(&s).unwrap();
        let back: TraceSummary = serde_json::from_value(json).unwrap();
        back.validate().expect("round-tripped summary validates");
        let mut doc = crate::presentation::snapshot::test_document(3, "complete");
        doc["schema"] = serde_json::json!("observed-crypto-v2.9");
        doc["trace_summary"] = serde_json::to_value(&back).unwrap();
        let snap = crate::presentation::snapshot::Presenter::oneshot(&doc).unwrap();
        snap.check_unknown_invariant().unwrap();
        let trace = snap.trace.as_ref().expect("trace block projects");
        assert_eq!(trace.paired, 7);
        assert_eq!(trace.trace_unpaired_entries, 1);
        let cw = trace.class_window.as_ref().expect("certain classes show");
        assert_eq!((cw.success, cw.unknown), (0, 7));
        assert!(snap.histograms.is_some(), "certain histograms show");
        assert!(snap.counts.by_outcome.is_some(), "certain fold shows");
        let prom = crate::presentation::prometheus::render(&snap);
        assert!(prom.contains("osslscope_trace_calls_total"), "{prom:?}");
        assert!(
            prom.contains("osslscope_dispatch_duration_nanoseconds_bucket"),
            "{prom:?}"
        );
        let otel = crate::presentation::otel::render(&snap);
        assert!(otel.contains("osslscope.trace.calls"), "{otel:?}");
        let frame = crate::presentation::watch::render_frame(&snap);
        assert!(frame.contains("class success=0"), "{frame:?}");
        assert!(frame.contains("unpaired_e=1"), "{frame:?}");
        assert!(!frame.contains("class withheld"), "{frame:?}");
    }

    #[test]
    fn p2fix2_global_cut_note_taints_any_overrun() {
        // The feed-cut arm (claim-end binding): any already-consumed
        // timestamp at/above the cut taints (`late-cut`).
        let mut p = bearing_latency();
        pair_at(&mut p, 7, 1, 100, 200);
        p.note_global_cut(50);
        let w = p.close_window(0, 9000, [0; 8]);
        assert!(w.pairing_uncertain, "global cut below consumed must taint");
        assert!(
            w.pairing_uncertainty.contains(&"late-cut".to_string()),
            "{:?}",
            w.pairing_uncertainty
        );
        let mut p = bearing_latency();
        pair_at(&mut p, 7, 1, 100, 200);
        p.note_global_cut(10_000);
        let w = p.close_window(0, 9000, [0; 8]);
        assert!(
            !w.pairing_uncertain,
            "global cut above consumed stays clean: {:?}",
            w.pairing_uncertainty
        );
    }
}
