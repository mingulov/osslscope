// SPDX-License-Identifier: GPL-3.0-or-later
//! Sampled scope coordinator. Each segment owns one exact foreign incarnation;
//! documents are streamed after link retirement, without cross-process totals.
//! 6A: event membership, lifetime and fair admission per
//! `docs/2026-11-03-t7-6a-d-record.md` (frozen): descendant following,
//! exec image epochs, deterministic deferral, per-incarnation loss ledgers
//! and the §7 additive `crypto-watch-v1` shapes.
use crate::{
    capture::{ClockPort as _, LifecycleKind, LifecyclePort as _, LiveClock, LiveLifecycle},
    focused_capture::{FocusedConfig, FocusedObjects, FocusedSession, SessionProgress},
    inventory::{
        self, GapReason, NamespaceId, ProcessRecord, Snapshot,
        scope::{ScopedScanner, Selection},
    },
    observation_memory::{MemoryLease, MemoryPool},
    provider_observation::{cli::Signals, objects::read_triple},
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet, VecDeque},
    io::{self, IsTerminal as _, Write},
    process::ExitCode,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const GLOBAL_BYTES: usize = 256 << 20;
// Four active slots, identity envelopes, serde's streaming stack, IO buffer,
// scalar records and a spare limit gap. Document storage stays in its session.
const COORDINATOR_BYTES: usize = 256 << 10;
// 6A run-lifetime leases (§3.1 byte account): the deferred queue
// (1024 × `DEFERRED_ENTRY_BYTES`) and the session-loss carrier (64 ×
// 24 B + fold count) hold SEPARATE additive leases beside the
// coordinator lease. R3-5: the per-entry flat is 768 B, not 256 —
// the REAL entry costs 248 B inline + 64 B key + 96 B marks heap
// (measured on this toolchain, pinned by
// `staging_charges_cover_worst_case_entries`), so 256 undercharges
// by ≥152 KiB at cap. NOTE for R4: the D-record §3.1 byte account
// still says 1024 × 256 B — this charge needs a ratification
// amendment (no D-record edits allowed in the fix round that set
// it). The pool fit below is re-pinned, not assumed.
const DEFERRED_ENTRY_BYTES: usize = 768;
const DEFERRED_BYTES: usize = DEFERRED_CAP * DEFERRED_ENTRY_BYTES;
const SESSION_LOSS_BYTES: usize = 2 << 10;
// 6A queue/ledger caps (§3.1/§4.1, frozen).
const DEFERRED_CAP: usize = 1024;
const WINDOW_CAP: usize = 64;
const DEFERRED_MARKS: usize = 4;
// 6A staging caps (bounded state): followed-but-unclassified births,
// pending exec-readmit contexts and cross-tick deferred drop
// records are each capped; refusals stay visible (gap record,
// ledger-carried seal, or deferred classification — never silent).
const FOLLOW_CAP: usize = 1024;
const PENDING_EPOCH_CAP: usize = 1024;
const PENDING_DROPS_CAP: usize = 4096;
// N8d staging byte account (implementation charges, pinned by
// `staging_charges_cover_worst_case_entries`): every staging
// store holds a run-lifetime pool lease computed from its cap ×
// flat worst-case entry —
// follow_pending: u32 key + (triple ≤64 B + parent + tick) +
// map-node slack ≤ 256 B/entry → 256 KiB;
// pending_epoch: key + (epoch + FULL 64-window MemberLedger
// ≤1576 B inline+heap + readmit ctx) + slack ≤ 2 KiB/entry → 2
// MiB (a full stash otherwise retains >1.5 MiB past its session
// leases with no charge);
// pending_drops: one owned LimitRec ≤ 256 B/entry → 1 MiB.
// Per-active flags (exec/exit/retire/unsteady/ignored, ≤
// max_active entries each) ride the coordinator lease's scalar
// spare. Coordinator plane total = 256 KiB coordinator + args +
// 768 KiB deferred + 2 KiB session-loss + staging, all inside
// the 256 MiB global pool.
const FOLLOW_ENTRY_BYTES: usize = 256;
const FOLLOW_BYTES: usize = FOLLOW_CAP * FOLLOW_ENTRY_BYTES;
const PENDING_EPOCH_ENTRY_BYTES: usize = 2 << 10;
const PENDING_EPOCH_BYTES: usize = PENDING_EPOCH_CAP * PENDING_EPOCH_ENTRY_BYTES;
const PENDING_DROP_ENTRY_BYTES: usize = 256;
const PENDING_DROPS_BYTES: usize = PENDING_DROPS_CAP * PENDING_DROP_ENTRY_BYTES;
// R3-4b: demoted-context table (same value shape and cap as the
// primary stash) plus the epoch-tombstone table (R4-3: key +
// bounded conservative summary, below). Both ride the staging
// lease and the layout pin below. The tombstone flat doubles to
// 512 B to carry the summary while the cap halves to 512 — the
// table total stays 256 KiB, so the staging account (5.5 MiB)
// and the §3.1 amendment are unchanged.
const EVICTED_EPOCH_CAP: usize = PENDING_EPOCH_CAP;
const EVICTED_EPOCH_ENTRY_BYTES: usize = PENDING_EPOCH_ENTRY_BYTES;
const EVICTED_EPOCH_BYTES: usize = EVICTED_EPOCH_CAP * EVICTED_EPOCH_ENTRY_BYTES;
const EPOCH_TOMBSTONE_CAP: usize = 512;
const EPOCH_TOMBSTONE_ENTRY_BYTES: usize = 512;
const EPOCH_TOMBSTONE_BYTES: usize = EPOCH_TOMBSTONE_CAP * EPOCH_TOMBSTONE_ENTRY_BYTES;
const STAGING_BYTES: usize = FOLLOW_BYTES
    + PENDING_EPOCH_BYTES
    + PENDING_DROPS_BYTES
    + EVICTED_EPOCH_BYTES
    + EPOCH_TOMBSTONE_BYTES;
// 6A per-tick machine-path bound (§3.3): at most 1024 Limit
// envelopes per tick, retained entries first (their per-tick
// record is frozen), then oldest-first queued drop records.
const LIMIT_TICK_BUDGET: usize = 1024;
#[derive(Clone, Debug)]
pub struct CryptoWatchConfig {
    pub selection: Selection,
    pub max_active: usize,
    pub max_state_bytes: usize,
    pub duration: Duration,
    pub interval: Duration,
    /// T5 `--resolve-paths` RENDER intent (raw flag; acquisition is
    /// gated separately via `selection.resolve_paths`). Human
    /// Object rows render `path=` fragments iff this is on AND
    /// `terminal` is on (external F4).
    pub resolve_paths: bool,
    /// Stdout is a terminal (caller-observed). Render-only.
    pub terminal: bool,
}
impl Default for CryptoWatchConfig {
    fn default() -> Self {
        Self {
            selection: Selection::default(),
            max_active: 4,
            max_state_bytes: GLOBAL_BYTES,
            duration: Duration::from_secs(30),
            interval: Duration::from_secs(1),
            resolve_paths: false,
            terminal: false,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Incarnation {
    pid: u32,
    starttime: u64,
    namespaces: inventory::NamespaceIds,
}
impl From<&ProcessRecord> for Incarnation {
    fn from(p: &ProcessRecord) -> Self {
        Self {
            pid: p.pid,
            starttime: p.starttime,
            namespaces: p.namespaces.clone(),
        }
    }
}
/// 6A compact loss-cause IDs (§4.1, frozen). In-memory intervals store
/// the discriminant; the wire keeps the `&'static str` word. IDs
/// 12..=255 are RESERVED, never emitted by 6A.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LossCause {
    CorpseWait = 0,
    CgroupMove = 1,
    MembershipUnknown = 2,
    RingLoss = 3,
    ConnectorDrops = 4,
    ConnectorEnobufs = 5,
    ScanLoss = 6,
    SignalPrefixUnwitnessed = 7,
    DrainPending = 8,
    ExecSpanningAggregate = 9,
    CoalescedLoss = 10,
    SkippedTick = 11,
}
impl LossCause {
    fn word(self) -> &'static str {
        match self {
            LossCause::CorpseWait => "corpse_wait",
            LossCause::CgroupMove => "cgroup_move",
            LossCause::MembershipUnknown => "membership_unknown",
            LossCause::RingLoss => "ring_loss",
            LossCause::ConnectorDrops => "connector_drops",
            LossCause::ConnectorEnobufs => "connector_enobufs",
            LossCause::ScanLoss => "scan_loss",
            LossCause::SignalPrefixUnwitnessed => "signal_prefix_unwitnessed",
            LossCause::DrainPending => "drain_pending",
            LossCause::ExecSpanningAggregate => "exec_spanning_aggregate",
            LossCause::CoalescedLoss => "coalesced_loss",
            LossCause::SkippedTick => "skipped_tick",
        }
    }
}
/// 6A compact lost-window layout (§3.1/§4.1, frozen): 8 + 8 + 1 + 7
/// pad = 24 B at align 8 (pinned by `compact_window_layout_is_24_bytes`).
/// Half-open tick interval `[start_tick, end_tick)`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct CompactWindow {
    start_tick: u64,
    end_tick: u64,
    cause: LossCause,
}
/// 6A bounded interval store with the frozen coalescing rule (§3.1):
/// an appended window first merges with any overlapping or adjacent
/// same-cause interval; when the cap is full, the newcomer folds into
/// a single `coalesced_loss` interval spanning the min/max bounds and
/// bumps `coalesced` — always visible, never silent.
#[derive(Clone)]
struct WindowStore {
    windows: Vec<CompactWindow>,
    coalesced: u64,
    cap: usize,
}
impl WindowStore {
    fn new(cap: usize) -> Self {
        Self {
            windows: Vec::new(),
            coalesced: 0,
            cap,
        }
    }
    fn append(&mut self, start: u64, end: u64, cause: LossCause) {
        if end <= start {
            return;
        }
        let before = self.windows.len();
        let mut span = (start, end);
        self.windows.retain(|w| {
            if w.cause != cause {
                return true;
            }
            // Half-open overlap or adjacency: [s1,e1) touches [s2,e2).
            if w.start_tick <= span.1 && span.0 <= w.end_tick {
                span.0 = span.0.min(w.start_tick);
                span.1 = span.1.max(w.end_tick);
                false
            } else {
                true
            }
        });
        if self.windows.len() < before {
            self.windows.push(CompactWindow {
                start_tick: span.0,
                end_tick: span.1,
                cause,
            });
            return;
        }
        if self.windows.len() < self.cap {
            self.windows.push(CompactWindow {
                start_tick: span.0,
                end_tick: span.1,
                cause,
            });
            return;
        }
        // Full: fold into the single coalesced-loss interval. The
        // first fold evicts the oldest normal interval (min start)
        // to hold the cap; later folds only widen the span.
        self.coalesced = self.coalesced.saturating_add(1);
        if let Some(slot) = self
            .windows
            .iter_mut()
            .find(|w| w.cause == LossCause::CoalescedLoss)
        {
            slot.start_tick = slot.start_tick.min(span.0);
            slot.end_tick = slot.end_tick.max(span.1);
            return;
        }
        if let Some(oldest) = self
            .windows
            .iter()
            .enumerate()
            .min_by_key(|(_, w)| (w.start_tick, w.end_tick))
            .map(|(i, _)| i)
        {
            let evicted = self.windows.remove(oldest);
            span.0 = span.0.min(evicted.start_tick);
            span.1 = span.1.max(evicted.end_tick);
        }
        self.windows.push(CompactWindow {
            start_tick: span.0,
            end_tick: span.1,
            cause: LossCause::CoalescedLoss,
        });
    }
    fn wire(&self) -> Vec<LostWindow> {
        self.windows
            .iter()
            .map(|w| LostWindow {
                start_tick: w.start_tick,
                end_tick: w.end_tick,
                cause: w.cause.word(),
            })
            .collect()
    }
}
/// 6A wire lost-window (§7): half-open `[start_tick, end_tick)`.
#[derive(Clone, Copy, Debug, Serialize)]
struct LostWindow {
    start_tick: u64,
    end_tick: u64,
    cause: &'static str,
}
/// 6A sealed deferred span (§7): ticks spent eligible-but-unadmitted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
struct DeferredSpan {
    ticks: u64,
    first_tick: u64,
    last_tick: u64,
}
/// 6A incarnation-wide deferral history (§4.1): a carried prior span
/// unions with the current span (ticks add; bounds widen). Empty
/// spans (zero ticks) contribute nothing — not even their bounds.
fn merge_deferred_spans(a: DeferredSpan, b: DeferredSpan) -> DeferredSpan {
    if a.ticks == 0 {
        return b;
    }
    if b.ticks == 0 {
        return a;
    }
    DeferredSpan {
        ticks: a.ticks.saturating_add(b.ticks),
        first_tick: a.first_tick.min(b.first_tick),
        last_tick: a.last_tick.max(b.last_tick),
    }
}
/// 6A one-transition detail (§7). `tid` is `None` on every 6A record
/// (no frozen read-set supplies thread-origin evidence, §1.8).
#[derive(Clone, Copy, Serialize)]
struct TransitionDetail {
    kind: &'static str,
    at_tick: u64,
    edge_ns: Option<u64>,
    tid: Option<u32>,
}
/// 6A incarnation-scope loss summary (§4.1, §7).
#[derive(Serialize)]
struct LossSummary {
    loss: u64,
    deferred: DeferredSpan,
    lost_windows: Vec<LostWindow>,
    coalesced: u64,
}
impl LossSummary {
    fn empty() -> Self {
        Self {
            loss: 0,
            deferred: DeferredSpan::default(),
            lost_windows: Vec::new(),
            coalesced: 0,
        }
    }
    fn from_ledger(ledger: &MemberLedger) -> Self {
        Self {
            loss: ledger.loss,
            deferred: ledger.deferred,
            lost_windows: ledger.windows.wire(),
            coalesced: ledger.windows.coalesced,
        }
    }
    fn from_entry(entry: &DeferredEntry, tick: u64) -> Self {
        let ticks = entry
            .ticks
            .saturating_add(tick.saturating_sub(entry.last_tick));
        let own = DeferredSpan {
            ticks,
            first_tick: entry.first_tick,
            last_tick: tick,
        };
        Self {
            loss: entry.carried_loss,
            deferred: merge_deferred_spans(entry.carried_deferred, own),
            lost_windows: entry.marks.wire(),
            coalesced: entry.marks.coalesced,
        }
    }
}
/// 6A session-scope cumulative loss (§7).
#[derive(Serialize)]
struct SessionLoss {
    ring: [u64; 8],
    connector_drops: u64,
    connector_enobufs: u64,
    scan_loss: u64,
    signal_dropped: u64,
    signal_prefix_unwitnessed: u64,
    drain_pending: u64,
    polling_fallback: bool,
    unattributed_events: u64,
    /// R3-9: EXIT events quarantined as live-member artifacts —
    /// the subject pid had an ADMITTED member whose triple matched
    /// the fresh probe (delivery proven post-admission; the EXIT
    /// belongs to a previous incarnation or a dead thread, never
    /// to the live member). This counter proves the control-5
    /// held-leg binding scenario; `unattributed_events` alone
    /// cannot (it also counts pre-admission quarantines).
    admitted_exit_artifacts: u64,
    lost_intervals: Vec<LostWindow>,
    coalesced: u64,
}
/// 6A per-incarnation loss ledger (§4.1, incarnation scope: spans
/// image epochs — an exec seals counts while the ledger carries
/// forward by reference into the new epoch).
#[derive(Clone)]
struct MemberLedger {
    loss: u64,
    deferred: DeferredSpan,
    windows: WindowStore,
}
impl MemberLedger {
    fn empty() -> Self {
        Self {
            loss: 0,
            deferred: DeferredSpan::default(),
            windows: WindowStore::new(WINDOW_CAP),
        }
    }
}
/// 6A deferred-queue key (§3.2): total order by `(starttime, pid)`,
/// namespaces disambiguating setns siblings. Starttimes are
/// immutable so the order is stable across ticks.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DeferredKey {
    starttime: u64,
    pid: u32,
    namespaces: inventory::NamespaceIds,
}
impl From<&Incarnation> for DeferredKey {
    fn from(i: &Incarnation) -> Self {
        Self {
            starttime: i.starttime,
            pid: i.pid,
            namespaces: i.namespaces.clone(),
        }
    }
}
/// 6A deferred-queue entry (§3.2.5, ≤768 B accounted): the triple,
/// image epoch, deferral accumulator, binding reason, up to 4 loss
/// marks and the fold count, plus the exe identity for lossless
/// deferred-exec detection (re-proof, not attribution) and the
/// readmit context for queued exec-readmits (window ordering).
/// A queued exec-readmit also carries its incarnation ledger
/// forward: the localized-loss count, the prior deferred span and
/// the sealed windows FOLDED through the frozen coalescing rule
/// (visible `coalesced_loss`, never silent truncation) — the full
/// monotone history survives deferral and resumes on readmission.
struct DeferredEntry {
    identity: Incarnation,
    image_epoch: u64,
    first_tick: u64,
    last_tick: u64,
    ticks: u64,
    reason: &'static str,
    marks: WindowStore,
    exe: Option<(u64, u64)>,
    readmit: Option<ReadmitCtx>,
    carried_loss: u64,
    carried_deferred: DeferredSpan,
    /// N6 exact lifetime window (§1.8): the observer's producer-clock
    /// read at deferral. A timestamped event binds to this entry
    /// only inside `[admit_ns, now]` (trust-gated) — a delayed
    /// previous-occupant event can never advance it.
    admit_ns: u64,
    /// R4-3: this entry carries a tombstone summary (consumed at
    /// queue time) — its admission announces the compression
    /// with one visible gap (the announcement rides the
    /// admission, never the queueing).
    tombstoned: bool,
}
/// 6A admission-attempt context (shared borrows only; admitted pids
/// return via `admitted` for the caller's port bookkeeping).
struct AdmitCtx<'a> {
    pool: &'a MemoryPool,
    objects: &'a FocusedObjects,
    reservation: usize,
    deadline: Instant,
    cancel: &'a AtomicBool,
    tracing: bool,
    trust_reviewed: bool,
    selection: &'a Selection,
    max_active: usize,
}
/// 6A one admission: owned identity + borrowed sample record.
/// `admit_floor_ns` enforces strict window ordering for readmits
/// (0 for fresh admissions).
struct AdmitSpec<'a> {
    identity: Incarnation,
    record: &'a ProcessRecord,
    epoch: u64,
    detail: Option<TransitionDetail>,
    ledger: MemberLedger,
    cgroup: Option<NamespaceId>,
    admit_floor_ns: u64,
}
struct Active {
    identity: Incarnation,
    segment: u64,
    /// 6A image epoch (§1.4): 0 at initial admission, +1 per exec
    /// re-admission under the same incarnation key.
    image_epoch: u64,
    session: FocusedSession,
    /// 6A incarnation loss ledger (§4.1).
    ledger: MemberLedger,
    /// 6A exact lifetime window (§1.8): producer-clock admission
    /// instant. A same-tick replacement opens strictly after the
    /// old window closes.
    admit_ns: u64,
    /// 6A retained-unknown (§2.4): excluded by `stable_members`
    /// with the sample otherwise succeeding — not retired, not
    /// counted, polls skipped until recovery or a proven terminal
    /// fact.
    suspended: bool,
    /// 6A last stable cgroup directory identity (when scoped).
    cgroup: Option<NamespaceId>,
    /// 6A foreign-corpse grace (§1.3): tick maps-empty was first
    /// observed (retire at the next tick if still empty).
    grace_noted: Option<u64>,
    /// 6A successful-read receipts (§4.1 `[S,T+1)` rule): per-lane
    /// LOSS read sequences consumed at the last baseline advance.
    /// A lane's baseline tick advances only when every live
    /// member's sequence moved (its session read that lane since).
    loss_seen: [u64; 8],
}
#[derive(Serialize)]
struct Envelope<T: Serialize> {
    schema_version: &'static str,
    sequence: u64,
    #[serde(flatten)]
    record: T,
}
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Record<'a> {
    Start {
        max_active: usize,
        max_state_bytes: usize,
        poll_interval: Duration,
        duration: Duration,
        membership: &'static str,
        /// 6A tick-clock anchor (§7): the `LiveClock`
        /// `CLOCK_MONOTONIC` reading taken when tick 0 opens.
        /// Nominal tick T spans
        /// `[run_origin_ns + T·tick_ns, run_origin_ns + (T+1)·tick_ns)`
        /// with `tick_ns = poll_interval.as_nanos()`.
        run_origin_ns: u64,
    },
    Discovery {
        process: &'a ProcessRecord,
        /// Source snapshot's resolve sidecar (human rows only;
        /// never serialized). The writer is built per-record in
        /// `human()` from `Output`'s render flags.
        #[serde(skip)]
        sidecar: Option<&'a crate::inventory::resolve::ResolveSidecar>,
    },
    TracingGap {
        reason: &'static str,
    },
    Membership {
        incarnation: &'a Incarnation,
        segment: u64,
        state: &'static str,
        reason: &'static str,
        /// 6A image-epoch scope (§1.4, §7): 0 at initial admission,
        /// +1 per exec re-admission.
        image_epoch: u64,
        /// 6A this-transition-only detail (§7).
        detail: Option<TransitionDetail>,
        /// 6A incarnation-scope loss (§4.1, §7): present on EVERY
        /// `Membership` record (admission, admission-after-deferral,
        /// `retired`, `deferred_removed`).
        loss: Option<LossSummary>,
    },
    Limit {
        incarnation: &'a Incarnation,
        reason: &'static str,
        /// 6A emitting tick (§7): the envelope `sequence` counts
        /// records, not ticks, so per-tick deferral reconstructs
        /// exactly by `(incarnation, at_tick)`.
        at_tick: u64,
        /// 6A sealed deferred span (§3.2.4, §7): present on
        /// overflow-drop records (the drop record is the dropped
        /// history's output path).
        deferred: Option<DeferredSpan>,
    },
    Gap {
        gap: &'a inventory::Gap,
    },
    SessionGap {
        incarnation: &'a Incarnation,
        reason: &'static str,
    },
    ProcessObservation {
        incarnation: &'a Incarnation,
        segment: u64,
        retirement: &'static str,
        document: &'a serde_json::Value,
        /// 6A image epoch (§1.4, §7) of the sealed segment.
        image_epoch: u64,
        /// 6A incarnation-scope loss (§4.1, §7).
        loss: LossSummary,
    },
    End {
        reason: &'static str,
        segments: u64,
        peak_accounted_bytes: usize,
        coverage: &'static str,
        /// 6A fair-admission tallies (§3.3, §7).
        peak_deferred_depth: u64,
        deferred_drops: u64,
        deferred_removed: DeferredRemoved,
        /// 6A session-scope cumulative loss (§7).
        session_loss: SessionLoss,
    },
}
/// 6A `deferred_removed` cause tallies (§3.2.5, §7): `closed`
/// covers `cancelled` + `end_of_observation`.
#[derive(Default, Serialize)]
struct DeferredRemoved {
    exited: u64,
    reused: u64,
    ineligible: u64,
    closed: u64,
}
struct Output<'a, W> {
    writer: &'a mut W,
    sequence: u64,
    json: bool,
    /// Human-only gap buffer: discovery gaps coalesce until the next
    /// record flushes one grouped block. Bounded by one sample's gaps
    /// (flushed by the records that follow); the JSON path never
    /// buffers, so NDJSON stays one envelope per gap.
    pending_gaps: Vec<(GapReason, Option<u64>, Option<u32>)>,
    /// T5 `--resolve-paths` render flags (external F4): fragments
    /// render iff `resolve_paths && terminal && !json`.
    resolve_paths: bool,
    terminal: bool,
}
/// 6A one deferral record (owned: scan borrows don't outlive the
/// tick). Retained-entry records are computed at flush time from
/// the live queue; overflow-drop records wait in the run's
/// bounded cross-tick queue (`pending_drops`).
struct LimitRec {
    incarnation: Incarnation,
    reason: &'static str,
    at_tick: u64,
    deferred: Option<DeferredSpan>,
}
/// N9: a row's count is failed when a BPF/read-side failure
/// invalidates it — `map` failures (including failed final reads,
/// which carry `entries: 0` placeholders, never counts) or
/// counter saturation. Pairing/in-flight nuances
/// (`depth`/`unpaired`/`tail`/`unsupported_return`) leave the
/// entry-probe count exact and are not failures.
fn api_row_failed(row: &serde_json::Value) -> bool {
    row["gaps"]["map"].as_u64().unwrap_or(0) > 0
        || row["gaps"]["saturated"].as_bool().unwrap_or(false)
}
/// N9: the row is inside the proven domain — attached (observed)
/// and failure-free. Gapless legacy shapes count as attached.
fn api_row_available(row: &serde_json::Value) -> bool {
    if row.get("gaps").is_none() {
        return true;
    }
    !row["gaps"]["not_attached"].as_bool().unwrap_or(false) && !api_row_failed(row)
}
impl<W: Write> Output<'_, W> {
    fn emit(&mut self, record: Record<'_>) -> io::Result<()> {
        if !self.json {
            if let Record::Gap { gap } = &record {
                self.pending_gaps.push((gap.reason, gap.device, gap.pid));
            } else {
                self.flush_gaps()?;
                self.human(&record)?;
            }
            self.writer.flush()?;
            self.sequence += 1;
            return Ok(());
        }
        serde_json::to_writer(
            &mut *self.writer,
            &Envelope {
                schema_version: "crypto-watch-v1",
                sequence: self.sequence,
                record,
            },
        )
        .map_err(io::Error::other)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        self.sequence += 1;
        Ok(())
    }
    /// Membership record plus the optional human blindness boundary.
    /// The record reason is the frozen machine vocabulary; `blind` is
    /// the caller's stricter human-only decision (full visibility).
    /// JSON output is exactly one membership envelope either way.
    /// 6A: every membership carries its image epoch, an optional
    /// this-transition detail and its incarnation loss summary.
    #[allow(clippy::too_many_arguments, reason = "one coherent record shape")]
    fn emit_membership(
        &mut self,
        incarnation: &Incarnation,
        segment: u64,
        state: &'static str,
        reason: &'static str,
        image_epoch: u64,
        detail: Option<TransitionDetail>,
        loss: LossSummary,
        blind: bool,
    ) -> io::Result<()> {
        self.emit(Record::Membership {
            incarnation,
            segment,
            state,
            reason,
            image_epoch,
            detail,
            loss: Some(loss),
        })?;
        if blind && !self.json && reason == "no_candidate_interfaces_in_sample" {
            self.writer
                .write_all(inventory::blindness_line().as_bytes())?;
        }
        Ok(())
    }
    /// N7 middle-image seal (§1.4 amendment): an image that never
    /// had a session emits ONLY this retired record — segment 0,
    /// the carried incarnation ledger, no admission claim, no
    /// counts claim. Shared by the sample path and the close path.
    fn emit_middle_seal(
        &mut self,
        identity: &Incarnation,
        middle_epoch: u64,
        ledger: &MemberLedger,
    ) -> io::Result<()> {
        self.emit_membership(
            identity,
            0,
            "retired",
            "unobserved_transition",
            middle_epoch,
            None,
            LossSummary::from_ledger(ledger),
            false,
        )
    }
    /// 6A: emit one batch of deferral records — human groups
    /// past 8 rows, JSON emits one envelope each, in batch order
    /// (retained entries by key, then oldest-first drop records).
    fn emit_limit_batch(&mut self, recs: Vec<LimitRec>) -> io::Result<()> {
        const ROWS: usize = 8;
        if recs.is_empty() {
            return Ok(());
        }
        if !self.json && recs.len() > ROWS {
            for rec in recs.iter().take(ROWS) {
                self.human(&Record::Limit {
                    incarnation: &rec.incarnation,
                    reason: rec.reason,
                    at_tick: rec.at_tick,
                    deferred: rec.deferred,
                })?;
                self.sequence += 1;
            }
            writeln!(self.writer, "Deferred omitted={}", recs.len() - ROWS)?;
            self.sequence += 1;
            self.writer.flush()?;
            return Ok(());
        }
        for rec in recs {
            self.emit(Record::Limit {
                incarnation: &rec.incarnation,
                reason: rec.reason,
                at_tick: rec.at_tick,
                deferred: rec.deferred,
            })?;
        }
        Ok(())
    }
    /// 6A per-root ignored-descendant volume (§1.7): human-only,
    /// conditional (the coordinator calls it only when nonzero),
    /// bounded to 8 roots + omitted count.
    fn emit_ignored_line(&mut self, ignored: &BTreeMap<u32, u64>) -> io::Result<()> {
        const ROWS: usize = 8;
        if self.json || ignored.is_empty() {
            return Ok(());
        }
        write!(self.writer, "Lifecycle ignored:")?;
        for (root, count) in ignored.iter().take(ROWS) {
            write!(self.writer, " root={root} forks={count}")?;
        }
        if ignored.len() > ROWS {
            write!(self.writer, " roots omitted={}", ignored.len() - ROWS)?;
        }
        writeln!(self.writer)?;
        self.sequence += 1;
        self.writer.flush()?;
        Ok(())
    }
    /// Flush buffered human gaps as one grouped block (no-op when empty).
    fn flush_gaps(&mut self) -> io::Result<()> {
        if self.pending_gaps.is_empty() {
            return Ok(());
        }
        let block = inventory::gap_groups_block(
            self.pending_gaps
                .iter()
                .map(|(reason, device, pid)| (reason.word(), *device, *pid)),
            "",
        );
        self.pending_gaps.clear();
        self.writer.write_all(block.as_bytes())
    }
    /// Fixed-size summaries per record. Never dump a document, raw path, symbol
    /// or target string; large object/gap populations get explicit omitted counts.
    fn human(&mut self, record: &Record<'_>) -> io::Result<()> {
        const ROWS: usize = 8;
        let w = &mut self.writer;
        match record {
            Record::Start {
                max_active,
                max_state_bytes,
                poll_interval,
                duration,
                run_origin_ns,
                ..
            } => writeln!(
                w,
                "Crypto watch: membership=sampled coverage=unknown max_active={max_active} accounted_limit_bytes={max_state_bytes} interval_s={} duration_s={} run_origin_ns={run_origin_ns}",
                poll_interval.as_secs_f64(),
                duration.as_secs_f64()
            ),
            Record::Discovery {
                process: p,
                sidecar,
            } => {
                writeln!(
                    w,
                    "Process {} start={} objects={} execution=not_observed coverage=unknown (passive inventory)",
                    p.pid,
                    p.starttime,
                    p.modules.len()
                )?;
                let mut verified = 0usize;
                let mut locator = 0usize;
                for m in &p.modules {
                    match m.identity_status {
                        inventory::IdentityStatus::Verified => verified += 1,
                        inventory::IdentityStatus::LocatorCandidate => locator += 1,
                    }
                }
                write!(
                    w,
                    "  {}",
                    inventory::identity_totals_line(verified, locator)
                )?;
                // T5 `--resolve-paths` (external F4): per-record
                // writer over the source snapshot's sidecar
                // (construction is I/O-free; fragments render only
                // when flag + terminal + human all hold).
                let writer = sidecar.map(|sidecar| {
                    crate::inventory::resolve::TerminalPathWriter::new(
                        self.resolve_paths && !self.json,
                        self.terminal,
                        sidecar,
                    )
                });
                for m in p.modules.iter().take(ROWS) {
                    write!(
                        w,
                        "  Object sha256={} kind={:?} identity={:?} interfaces={}",
                        m.info.sha256.get(..12).unwrap_or("unknown"),
                        m.info.kind,
                        m.identity_status,
                        m.info.exports.len()
                    )?;
                    if let Some(fragment) = writer.as_ref().and_then(|writer| {
                        writer.fragment(m.identity_status, (m.info.device, m.info.inode))
                    }) {
                        write!(w, " path={fragment}")?;
                    }
                    writeln!(w)?;
                }
                if p.modules.len() > ROWS {
                    writeln!(w, "  Objects omitted={}", p.modules.len() - ROWS)?;
                }
                Ok(())
            }
            Record::TracingGap { reason } => {
                writeln!(w, "Tracing unavailable: {reason}; coverage=unknown")
            }
            Record::Membership {
                incarnation: i,
                segment,
                state,
                reason,
                image_epoch,
                detail,
                loss,
            } => {
                write!(
                    w,
                    "Membership pid={} start={} segment={segment} state={state} reason={reason} image_epoch={image_epoch}",
                    i.pid, i.starttime
                )?;
                if let Some(d) = detail {
                    write!(w, " detail={}@tick{}", d.kind, d.at_tick)?;
                    if let Some(edge) = d.edge_ns {
                        write!(w, " edge_ns={edge}")?;
                    }
                }
                if let Some(l) = loss {
                    write!(
                        w,
                        " loss_events={} loss_windows={} loss_coalesced={} deferred_ticks={}",
                        l.loss,
                        l.lost_windows.len(),
                        l.coalesced,
                        l.deferred.ticks
                    )?;
                }
                writeln!(w, "; sampled")
            }
            Record::Limit {
                incarnation: i,
                reason,
                at_tick,
                deferred,
            } => {
                write!(
                    w,
                    "Limit pid={} start={} at_tick={at_tick}: {reason}; activity=unknown",
                    i.pid, i.starttime
                )?;
                if let Some(d) = deferred {
                    write!(
                        w,
                        " deferred=[{},{}]ticks={}",
                        d.first_tick, d.last_tick, d.ticks
                    )?;
                }
                writeln!(w)
            }
            // Buffered at emit(): human gaps coalesce into one grouped
            // block flushed by the next record. This arm is unreachable
            // via emit but keeps the match exhaustive.
            Record::Gap { .. } => Ok(()),
            Record::SessionGap {
                incarnation: i,
                reason,
            } => writeln!(
                w,
                "Process {} start={} unavailable: {reason}; coverage=unknown",
                i.pid, i.starttime
            ),
            Record::ProcessObservation {
                incarnation: i,
                segment,
                retirement,
                document: d,
                image_epoch,
                loss,
            } => {
                let rows = |name: &str| d[name].as_array().map(Vec::as_slice).unwrap_or(&[]);
                // 6A unknown rendering (§4.3): every consumer-facing
                // total renders `unknown` when any contributing
                // interval is lost, deferred or unobserved — the
                // loss ledger is consulted, never bypassed. An
                // `attribution=unknown` trailer does not make a
                // numeric total unknown.
                let affected = loss.loss > 0
                    || !loss.lost_windows.is_empty()
                    || loss.coalesced > 0
                    || loss.deferred.ticks > 0;
                let physical = (!affected)
                    .then(|| {
                        rows("sites")
                            .iter()
                            .chain(rows("fenced").iter().flat_map(|epoch| {
                                epoch["sites"].as_array().map(Vec::as_slice).unwrap_or(&[])
                            }))
                            .try_fold(0u64, |n, r| n.checked_add(r["calls"].as_u64()?))
                    })
                    .flatten();
                // N9: the api total sums the PROVEN domain only —
                // attached, failure-free rows. Any failed row, any
                // unparseable attached row, or an empty proven
                // domain renders the total unknown (a zero over
                // gap-marked rows would assert unobserved counts).
                let api = if affected {
                    None
                } else if let Some(rows) = d["api_activity"].as_array() {
                    let mut sum = Some(0u64);
                    let mut any_attached = false;
                    for row in rows {
                        if api_row_failed(row) {
                            sum = None;
                        }
                        if !api_row_available(row) {
                            continue;
                        }
                        any_attached = true;
                        sum = match (sum, row["entries"].as_u64()) {
                            (Some(acc), Some(entries)) => acc.checked_add(entries),
                            _ => None,
                        };
                    }
                    if any_attached { sum } else { None }
                } else {
                    None
                };
                let total =
                    |v: Option<u64>| v.map(|n| n.to_string()).unwrap_or_else(|| "unknown".into());
                writeln!(
                    w,
                    "Process {} start={} segment={segment} retirement={retirement} image_epoch={image_epoch} objects={} physical_entries={} api_entries={} loss_events={} loss_windows={} loss_coalesced={} deferred_ticks={} coverage=partial attribution=unknown",
                    i.pid,
                    i.starttime,
                    rows("objects").len(),
                    total(physical),
                    total(api),
                    loss.loss,
                    loss.lost_windows.len(),
                    loss.coalesced,
                    loss.deferred.ticks
                )?;
                // Distinct op names across current + fenced sites: names only,
                // never call attribution (a site's calls are never split
                // across its candidates). Rows without ids are omitted.
                let mut ops: Vec<u32> = rows("sites")
                    .iter()
                    .chain(rows("fenced").iter().flat_map(|epoch| {
                        epoch["sites"].as_array().map(Vec::as_slice).unwrap_or(&[])
                    }))
                    .flat_map(|r| r["candidates"].as_array().map(Vec::as_slice).unwrap_or(&[]))
                    .filter_map(|c| c["op"].as_u64().and_then(|v| u32::try_from(v).ok()))
                    .collect();
                ops.sort_unstable();
                ops.dedup();
                for op in ops.iter().take(ROWS) {
                    writeln!(w, "  op={}", crate::report::op_display(*op))?;
                }
                if ops.len() > ROWS {
                    writeln!(w, "  Ops omitted={}", ops.len() - ROWS)?;
                }
                for row in rows("api_activity").iter().take(ROWS) {
                    let Some(api) = row["api"]
                        .as_u64()
                        .and_then(|v| u32::try_from(v).ok())
                        .and_then(|v| crate::api_activity::ApiId::try_from(v).ok())
                    else {
                        continue;
                    };
                    // 6A unknown rendering (§4.3): unavailable
                    // entries are unknown, never zero. N9: a row is
                    // unavailable when the segment is affected or
                    // the row itself is outside the proven domain
                    // (never attached, or failed) — row gaps are
                    // consulted, never bypassed.
                    let entries = if affected || !api_row_available(row) {
                        "unknown".to_string()
                    } else {
                        row["entries"]
                            .as_u64()
                            .map(|n| n.to_string())
                            .unwrap_or_else(|| "unknown".into())
                    };
                    writeln!(w, "  api={} entries={entries}", api.export_name())?;
                }
                if rows("api_activity").len() > ROWS {
                    writeln!(w, "  Apis omitted={}", rows("api_activity").len() - ROWS)?;
                }
                let counters = d["completeness"]["counters"]
                    .as_array()
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                // Counter names are observer-owned finite vocabulary; limit text
                // width even if a future producer extends that vocabulary.
                for c in counters.iter().take(ROWS) {
                    let name = c["name"].as_str().unwrap_or("unknown");
                    let label: String = name
                        .chars()
                        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_'))
                        .take(80)
                        .collect();
                    writeln!(
                        w,
                        "  Gap {label} value={}",
                        c["value"].as_u64().unwrap_or(0)
                    )?;
                }
                if counters.len() > ROWS {
                    writeln!(w, "  Gaps omitted={}", counters.len() - ROWS)?;
                }
                // P1c diagnostic channels: the same shaped cause the NDJSON
                // envelope carries in full, bounded here by the ROWS
                // discipline with explicit omitted counts.
                for (name, label) in [
                    ("attach_diagnostics", "Attach diagnostic"),
                    ("refusal_diagnostics", "Refusal diagnostic"),
                ] {
                    let diags = d[name].as_array().map(Vec::as_slice).unwrap_or(&[]);
                    for diag in diags.iter().take(ROWS) {
                        if let Some(text) = diag.as_str() {
                            writeln!(w, "  {label}: {}", crate::report::safe_display(text))?;
                        }
                    }
                    if diags.len() > ROWS {
                        writeln!(w, "  {label}s omitted={}", diags.len() - ROWS)?;
                    }
                }
                Ok(())
            }
            Record::End {
                reason,
                segments,
                peak_accounted_bytes,
                coverage,
                peak_deferred_depth,
                deferred_drops,
                deferred_removed,
                session_loss,
            } => {
                let ring: u64 = session_loss
                    .ring
                    .iter()
                    .fold(0, |a, b| a.saturating_add(*b));
                writeln!(
                    w,
                    "Crypto watch end: reason={reason} segments={segments} peak_accounted_bytes={peak_accounted_bytes} peak_deferred_depth={peak_deferred_depth} deferred_drops={deferred_drops} deferred_removed={}/{}/{}/{} signal_dropped={} scan_loss={} prefix_unwitnessed={} drain_pending={} unattributed={} admitted_exit_artifacts={} ring_loss={} lost_intervals={} polling_fallback={} coverage={coverage}; unsampled membership and unobserved activity remain unknown",
                    deferred_removed.exited,
                    deferred_removed.reused,
                    deferred_removed.ineligible,
                    deferred_removed.closed,
                    session_loss.signal_dropped,
                    session_loss.scan_loss,
                    session_loss.signal_prefix_unwitnessed,
                    session_loss.drain_pending,
                    session_loss.unattributed_events,
                    session_loss.admitted_exit_artifacts,
                    ring,
                    session_loss.lost_intervals.len(),
                    session_loss.polling_fallback
                )
            }
        }
    }
    /// 6A seal: exactly one `ProcessObservation` (or
    /// `SessionGap{finalization_failed}`) plus one `Membership{retired}`
    /// (§1.3 retirement protocol). `fenced` selects the fenced close
    /// drain (transition seals) vs the plain close drain (live
    /// members at close). Returns the sealed session's final LOSS
    /// deltas for the cumulative ring fold.
    fn finish(
        &mut self,
        active: Active,
        reason: &'static str,
        fenced: bool,
    ) -> io::Result<SealOutcome> {
        let Active {
            identity,
            segment,
            image_epoch,
            session,
            mut ledger,
            ..
        } = active;
        // finish closes all links before projection and releases foreign pins.
        // The result keeps the lease until the borrowed document is delivered.
        let result = if fenced {
            session.finish_with_edge(Instant::now() + Duration::from_millis(100), None)
        } else {
            session.finish(Instant::now() + Duration::from_millis(100))
        };
        match result {
            Ok(result) => {
                ledger.loss = ledger.loss.saturating_add(result.fence_withheld);
                let outcome = SealOutcome {
                    loss_totals: result.loss_totals,
                };
                self.emit(Record::ProcessObservation {
                    incarnation: &identity,
                    segment,
                    retirement: reason,
                    document: &crate::report::doc_json(&result.document),
                    image_epoch,
                    loss: LossSummary::from_ledger(&ledger),
                })?;
                self.emit_membership(
                    &identity,
                    segment,
                    "retired",
                    reason,
                    image_epoch,
                    None,
                    LossSummary::from_ledger(&ledger),
                    false,
                )?;
                Ok(outcome)
            }
            Err(_) => {
                // The failed finalization itself is one localized
                // proven-missed final read on the retirement record.
                ledger.loss = ledger.loss.saturating_add(1);
                self.emit(Record::SessionGap {
                    incarnation: &identity,
                    reason: "finalization_failed",
                })?;
                self.emit_membership(
                    &identity,
                    segment,
                    "retired",
                    reason,
                    image_epoch,
                    None,
                    LossSummary::from_ledger(&ledger),
                    false,
                )?;
                Ok(SealOutcome {
                    loss_totals: [0; 8],
                })
            }
        }
    }
    /// 6A exec image seal (§1.4): the old image epoch retires
    /// EXACTLY like a member departure — sealed segment (or
    /// `SessionGap{finalization_failed}`) PLUS `Membership{retired}`
    /// (§1.3 retirement protocol) — then the incarnation continues
    /// (its next record is the new epoch's admission carrying
    /// `image_readmission`). Returns the sealed finals plus the
    /// carried ledger and retire instant for the readmit.
    fn finish_exec_seal(&mut self, active: Active) -> io::Result<ExecSealOutcome> {
        let Active {
            identity,
            segment,
            image_epoch,
            session,
            mut ledger,
            ..
        } = active;
        // Underdetermined D-record point (reported): no frozen
        // retirement word names an image seal (all eight name
        // endings of observation). `duration` is the least false:
        // the only frozen word denoting a planned, non-failure
        // segment end; the readmit membership (same incarnation,
        // epoch + 1, `image_readmission`) disambiguates it from
        // run expiry. A future `image_sealed` word would need a
        // D-record amendment.
        let retirement = "duration";
        let retire_ns = LiveClock.monotonic_ns();
        match session.finish_with_edge(Instant::now() + Duration::from_millis(100), None) {
            Ok(result) => {
                ledger.loss = ledger.loss.saturating_add(result.fence_withheld);
                let outcome = ExecSealOutcome {
                    loss_totals: result.loss_totals,
                    ledger,
                    retire_ns,
                };
                self.emit(Record::ProcessObservation {
                    incarnation: &identity,
                    segment,
                    retirement,
                    document: &crate::report::doc_json(&result.document),
                    image_epoch,
                    loss: LossSummary::from_ledger(&outcome.ledger),
                })?;
                self.emit_membership(
                    &identity,
                    segment,
                    "retired",
                    retirement,
                    image_epoch,
                    None,
                    LossSummary::from_ledger(&outcome.ledger),
                    false,
                )?;
                Ok(outcome)
            }
            Err(_) => {
                ledger.loss = ledger.loss.saturating_add(1);
                let outcome = ExecSealOutcome {
                    loss_totals: [0; 8],
                    ledger,
                    retire_ns,
                };
                self.emit(Record::SessionGap {
                    incarnation: &identity,
                    reason: "finalization_failed",
                })?;
                self.emit_membership(
                    &identity,
                    segment,
                    "retired",
                    retirement,
                    image_epoch,
                    None,
                    LossSummary::from_ledger(&outcome.ledger),
                    false,
                )?;
                Ok(outcome)
            }
        }
    }
}
/// 6A sealed session finals folded by the caller into the cumulative ring.
struct SealOutcome {
    loss_totals: [u64; 8],
}
/// 6A exec-seal finals: sealed LOSS plus the carried incarnation
/// ledger and retire instant for the readmit window/ledger.
struct ExecSealOutcome {
    loss_totals: [u64; 8],
    ledger: MemberLedger,
    retire_ns: u64,
}
/// 6A probe liveness: really-dead (ESRCH/ENOENT) vs alive vs
/// unreadable-but-present (unknown — never treated as death).
enum Liveness {
    Dead,
    Alive(Incarnation),
    Unknown,
}
/// 6A fresh-triple probe: `None` when the pid currently proves no triple.
fn verify_triple(pid: u32) -> Option<Incarnation> {
    read_triple(pid)
        .ok()
        .map(|(starttime, namespaces)| Incarnation {
            pid,
            starttime,
            namespaces,
        })
}
/// 6A liveness probe: full triple read, falling back to an
/// existence check that separates really-dead from unknown.
fn probe_liveness(pid: u32) -> Liveness {
    if let Some(identity) = verify_triple(pid) {
        return Liveness::Alive(identity);
    }
    match std::fs::metadata(format!("/proc/{pid}")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Liveness::Dead,
        Err(_) | Ok(_) => Liveness::Unknown,
    }
}
/// 6A thread liveness: task-dir existence for one tid under a
/// live TGID — really-dead (entry gone) vs alive (entry present;
/// covers recycled numbers — a live entry belongs to the current
/// holder, never to the exit's subject) vs unknown (unreadable —
/// never treated as death).
#[derive(Clone, Copy, PartialEq, Eq)]
enum TidLiveness {
    Dead,
    Alive,
    Unknown,
}
/// 6A thread liveness probe (§1.2 cleanup): see `TidLiveness`.
fn probe_tid_liveness(tgid: u32, tid: u32) -> TidLiveness {
    match std::fs::metadata(format!("/proc/{tgid}/task/{tid}")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => TidLiveness::Dead,
        Err(_) => TidLiveness::Unknown,
        Ok(_) => TidLiveness::Alive,
    }
}
/// 6A exe device+inode identity for lossless deferred-exec detection.
fn exe_identity(pid: u32) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(format!("/proc/{pid}/exe"))
        .ok()
        .map(|m| (m.dev(), m.ino()))
}
/// 6A elapsed-derived nominal tick (§7 `Start` rule): the nominal
/// tick containing `ns` — NEVER a sample-loop counter. Instants
/// before the origin saturate to tick 0.
fn tick_of(ns: u64, origin: u64, tick_ns: u64) -> u64 {
    ns.saturating_sub(origin) / tick_ns.max(1)
}
/// N4 pure receipt advance (§4.1 `[S,T+1)` rule): `None` when any
/// live session's lane sequence is unmoved (a stalled session
/// blocks the advance); otherwise the tick the baseline may
/// advance to — the OLDEST certified (accounted) read tick across
/// receipts (never the evaluation tick: loss after the read but
/// still in its tick stays covered; fix6/R6-2: peeks certify the
/// last ACCOUNTED tick, so unaccounted reads never advance the
/// baseline past the totals). Vacuous (no live sessions, or none
/// contributing) advances to the evaluation tick, preserving
/// quiet-tick progress.
fn lane_advance(
    eval_tick: u64,
    lane: usize,
    seen: &[[u64; 8]],
    receipts: &[Option<[(u64, u64); 8]>],
) -> Option<u64> {
    let mut advance = eval_tick;
    let mut any = false;
    for (consumed, receipt) in seen.iter().zip(receipts.iter()) {
        match receipt {
            None => {}
            Some(receipt) if receipt[lane].0 > consumed[lane] => {
                advance = if any {
                    advance.min(receipt[lane].1)
                } else {
                    receipt[lane].1
                };
                any = true;
            }
            Some(_) => return None,
        }
    }
    Some(advance)
}
/// 6A whole-sample failure (§2.4): a global deadline/read/cgroup
/// limit fails the tick for every member (unknown, not removed).
fn whole_sample_failed(snapshot: &Snapshot) -> bool {
    snapshot.gaps.iter().any(|g| {
        g.pid.is_none()
            && matches!(
                g.reason,
                GapReason::Deadline | GapReason::ReadLimit | GapReason::CgroupLimit
            )
    })
}
/// Sampled-record reason: any non-identity gap touching the process
/// (or the whole sample) renders the candidacy unknown rather than
/// conclusively interface-less.
fn sampled_uncertain(snapshot: &Snapshot, pid: u32) -> bool {
    snapshot.gaps.iter().any(|g| {
        (g.pid.is_none() || g.pid == Some(pid)) && g.reason != GapReason::IdentityUnverified
    })
}
/// Conservative human blindness boundary: any gap touching this
/// process (identity uncertainty included) or any module-selector
/// filtering vetoes the claim.
fn sampled_blind(selection: &Selection, snapshot: &Snapshot, pid: u32) -> bool {
    selection.modules.is_empty()
        && !snapshot
            .gaps
            .iter()
            .any(|g| g.pid.is_none() || g.pid == Some(pid))
}
/// 6A `stable_members` exclusion evidence (§2.4 exception 2): a
/// between-pass move or ambiguity gaps the sample globally.
fn exclusion_gap_present(snapshot: &Snapshot) -> bool {
    snapshot
        .gaps
        .iter()
        .any(|g| matches!(g.reason, GapReason::Changed | GapReason::MembershipUnknown))
}
/// 6A watched set: user selection ∪ live members ∪ deferred queue ∪
/// followed-but-unclassified (sorted, deterministic).
fn watched_pids(run: &RunState) -> Vec<u32> {
    let mut pids = run.user_pids.clone();
    for a in &run.active {
        pids.insert(a.identity.pid);
    }
    for key in run.deferred.keys() {
        pids.insert(key.pid);
    }
    for pid in run.follow_pending.keys() {
        pids.insert(*pid);
    }
    pids.into_iter().collect()
}
/// 6A scanner following: the next sample classifies followed
/// incarnations through the reviewed inventory machinery (their
/// eligibility is sample-established, never event-established).
/// The scanner unions these with its preserved discovery scope —
/// user-selected pids ride the original scope, so only the
/// genuinely followed pids are synced here.
fn sync_selection(scanner: &mut ScopedScanner, run: &RunState) {
    scanner.set_pids(
        watched_pids(run)
            .into_iter()
            .filter(|pid| !run.user_pids.contains(pid))
            .collect(),
    );
    // F8d restoration: re-share the run's parsed-object cache
    // every tick (cheap handle clone; also re-wires after a
    // failed-tick scan-state reset).
    scanner.set_parsed_cache(run.parsed_cache.clone());
}
/// 6A port roots: the watched TGIDs (the port additionally
/// fail-closes on every admitted pid it has ever seen).
fn sync_roots(port: &mut LiveLifecycle, run: &RunState) {
    port.set_roots(&watched_pids(run).into_iter().collect());
}
/// 6A event drain (§1.8): fold the loss lanes, latch the fallback,
/// then bind every event before applying any — in drain order
/// (producer timestamp, unknown last, then `(cpu, seq)`; no
/// sequence arithmetic: SMP reordering never fabricates order).
fn drain_port<W: Write>(
    port: &mut LiveLifecycle,
    run: &mut RunState,
    out: &mut Output<'_, W>,
    trust_reviewed: bool,
) -> io::Result<()> {
    let delta = port.poll();
    run.scan_loss = run.scan_loss.saturating_add(delta.loss);
    run.signal_dropped = run.signal_dropped.saturating_add(delta.dropped);
    run.signal_prefix_unwitnessed = run
        .signal_prefix_unwitnessed
        .saturating_add(delta.prefix_unwitnessed);
    run.drain_pending = run.drain_pending.saturating_add(delta.pending);
    run.connector_drops = run.connector_drops.saturating_add(delta.connector_drops);
    run.connector_enobufs = run
        .connector_enobufs
        .saturating_add(delta.connector_enobufs);
    // `filtered` stays a port diagnostic: system noise outside the
    // watched set has no §7 carrier.
    if port.fallback_partial() {
        run.polling = true;
    }
    let mut events = delta.events;
    events.sort_by_key(|e| (e.timestamp_ns.unwrap_or(u64::MAX), e.cpu, e.seq));
    for event in events {
        bind_event(run, out, &event, trust_reviewed)?;
    }
    Ok(())
}
/// R3-4b: a stash key is sweep-dead when its triple is provably
/// dead or reused (the ledger already rode the sealed segment).
/// Unknown liveness retains (an unreadable `/proc` entry is not
/// death) — same rule for all three stash tables.
fn stash_key_dead(key: &DeferredKey) -> bool {
    match probe_liveness(key.pid) {
        Liveness::Alive(now)
            if now.starttime == key.starttime && now.namespaces == key.namespaces =>
        {
            false
        }
        Liveness::Unknown => false,
        Liveness::Dead | Liveness::Alive(_) => true,
    }
}
/// R3-4b: one visible `MembershipUnknown` gap naming `pid`
/// (epoch-history demotion/drop/restart accounting — never silent).
fn emit_membership_unknown_gap<W: Write>(out: &mut Output<'_, W>, pid: u32) -> io::Result<()> {
    let gap = inventory::Gap {
        pid: Some(pid),
        device: None,
        inode: None,
        reason: GapReason::MembershipUnknown,
        errno: None,
        actor_euid: None,
    };
    out.emit(Record::Gap { gap: &gap })
}
/// 6A event binding (§1.8): presence binds by fresh triple, window
/// and tgid; exit only confirms revalidation-observed absence; a
/// birth event never self-identifies (verification carries); an
/// event matching no entry quarantines once as session-level
/// unattributed evidence.
fn bind_event<W: Write>(
    run: &mut RunState,
    out: &mut Output<'_, W>,
    event: &crate::capture::LifecycleEvent,
    trust_reviewed: bool,
) -> io::Result<()> {
    let quarantine = |run: &mut RunState| {
        run.unattributed = run.unattributed.saturating_add(1);
    };
    // 6A lifetime coverage (§1.8): a trusted timestamp from the
    // future binds to nothing — the event is recorded once as
    // unattributed evidence, never applied.
    if trust_reviewed {
        if let Some(ts) = event.timestamp_ns {
            if ts > LiveClock.monotonic_ns() {
                quarantine(run);
                return Ok(());
            }
        }
    }
    match event.kind {
        LifecycleKind::Fork => {
            let child = event.pid;
            // 6A presence-binding (§1.8): an existing numeric pid is
            // NEVER silently ignored — the fresh triple decides.
            // Same triple: the birth is already known (window
            // rules below); different triple: the number was reused
            // and this is the NEW incarnation's birth (a stranger
            // candidate — the old entry retires through the sample
            // rules, never through this event).
            let recorded = run
                .active
                .iter()
                .find(|a| a.identity.pid == child)
                .map(|a| (a.identity.clone(), Some(a.admit_ns)))
                .or_else(|| {
                    run.deferred
                        .values()
                        .find(|e| e.identity.pid == child)
                        .map(|e| (e.identity.clone(), None))
                })
                .or_else(|| {
                    run.follow_pending
                        .get(&child)
                        .map(|(identity, _, _)| (identity.clone(), None))
                });
            let fresh = verify_triple(child);
            match (recorded, fresh) {
                (Some((known, admit)), Some(now)) if now == known => {
                    // Already-known birth: exact-window coverage for
                    // admitted entries (a trusted timestamped event
                    // binds iff it falls inside `[admit_ns, now]`);
                    // deferred/pending entries predate admission, so
                    // only the future check above applies. A bound
                    // duplicate is a no-op (the candidate exists).
                    if let (Some(admit_ns), true) = (admit, trust_reviewed) {
                        if let Some(ts) = event.timestamp_ns {
                            let now_ns = LiveClock.monotonic_ns();
                            if ts < admit_ns || ts > now_ns {
                                quarantine(run);
                                return Ok(());
                            }
                        }
                    }
                    return Ok(());
                }
                (_, Some(now)) => {
                    // Stranger birth (or a reused number's new
                    // incarnation): verify carried, then follow. A
                    // pending entry for a DIFFERENT triple is dead —
                    // its birth gaps now (it can never classify),
                    // billed to its witnessing root.
                    if let Some((old, parent, _)) = run.follow_pending.get(&child).cloned() {
                        if old != now {
                            run.follow_pending.remove(&child);
                            if let Some(root) = parent {
                                run.count_ignored(root);
                            }
                            let gap = inventory::Gap {
                                pid: Some(child),
                                device: None,
                                inode: None,
                                reason: GapReason::MembershipUnknown,
                                errno: None,
                                actor_euid: None,
                            };
                            out.emit(Record::Gap { gap: &gap })?;
                        }
                    }
                    run.follow_insert(out, child, now, Some(event.parent_tgid))?;
                }
                (_, None) => {
                    run.count_ignored(event.parent_tgid);
                    let gap = inventory::Gap {
                        pid: Some(child),
                        device: None,
                        inode: None,
                        reason: GapReason::MembershipUnknown,
                        errno: None,
                        actor_euid: None,
                    };
                    out.emit(Record::Gap { gap: &gap })?;
                }
            }
        }
        LifecycleKind::Exec => {
            let subject = event.pid;
            // 6A deferred exec (§3.2.5): presence-bind (triple +
            // tgid); a witnessed exec advances the entry's image
            // epoch even when the exe identity is unchanged
            // (same-binary re-exec — the sweep's exe-flip check
            // cannot see it). The exe stamp refreshes here so the
            // sweep never double-advances; eligibility is re-proved
            // at the next sweep. Mismatches quarantine.
            if let Some(key) = run.deferred.keys().find(|k| k.pid == subject).cloned() {
                let bound = run
                    .deferred
                    .get(&key)
                    .map(|e| (e.identity.clone(), e.admit_ns));
                match (bound, verify_triple(subject)) {
                    (Some((known, admit_ns)), Some(now))
                        if now == known && event.tgid == subject =>
                    {
                        // N6 exact lifetime window (§1.8): a trusted
                        // timestamp binds only inside `[admit_ns,
                        // now]` — a delayed previous-occupant exec
                        // quarantines instead of advancing the
                        // replacement's epoch.
                        if trust_reviewed {
                            if let Some(ts) = event.timestamp_ns {
                                let now_ns = LiveClock.monotonic_ns();
                                if ts < admit_ns || ts > now_ns {
                                    quarantine(run);
                                    return Ok(());
                                }
                            }
                        }
                        let entry = run.deferred.get_mut(&key).expect("bound entry");
                        entry.image_epoch = entry.image_epoch.saturating_add(1);
                        entry.exe = exe_identity(subject);
                    }
                    _ => quarantine(run),
                }
                return Ok(());
            }
            let Some(pos) = run.active.iter().position(|a| a.identity.pid == subject) else {
                // Stranger exec: re-follow verified pids
                // (exec-into-eligibility after a prune) — with the
                // post-exec group cross-check (the payload word
                // EQUALS the surviving tgid, §1.8) and lifetime
                // coverage; unverifiable subjects quarantine.
                // R3-4a: a stashed incarnation advances first (the
                // second exec seals the stashed image as an
                // unobserved middle and moves the stash on).
                match verify_triple(subject) {
                    Some(identity) if event.tgid == subject => {
                        match run.advance_stash_for_exec(
                            out,
                            &identity,
                            event.timestamp_ns,
                            trust_reviewed,
                        )? {
                            StashAdvance::Stale => return Ok(()),
                            StashAdvance::None | StashAdvance::Advanced => {}
                        }
                        run.follow_insert(out, subject, identity, None)?;
                    }
                    _ => quarantine(run),
                }
                return Ok(());
            };
            let identity = run.active[pos].identity.clone();
            let admit_ns = run.active[pos].admit_ns;
            match verify_triple(subject) {
                Some(now) if now == identity && event.tgid == identity.pid => {
                    if trust_reviewed {
                        if let Some(ts) = event.timestamp_ns {
                            let now_ns = LiveClock.monotonic_ns();
                            if ts < admit_ns || ts > now_ns {
                                quarantine(run);
                                return Ok(());
                            }
                        }
                    }
                    // Fence at the witness instant (exact under sane
                    // clocks; the conservative drain-instant edge
                    // would under-withhold) + flag the seal. The
                    // flag counts distinct execs (epoch advances by
                    // the count when several execs precede a seal),
                    // NOT signals: a session exe-flip and its kernel
                    // EXEC event are one exec. Flip-first order is
                    // systematic (the sample scan separates the
                    // session poll from the next event bind), so an
                    // event arriving atop a single timestamp-less
                    // same-tick flag adopts it (keeping count 1 with
                    // the better timestamp) instead of counting a
                    // second exec. Distinct execs still count: a
                    // second event finds a timestamped flag.
                    run.active[pos].session.note_kernel_edge(event.timestamp_ns);
                    let tick = run.current_tick;
                    let adopted = matches!(
                        run.exec_flags.get(&subject),
                        Some((ftick, None, 1)) if *ftick == tick
                    );
                    if adopted {
                        run.exec_flags
                            .insert(subject, (tick, event.timestamp_ns, 1));
                    } else {
                        run.exec_flags
                            .entry(subject)
                            .and_modify(|f| f.2 = f.2.saturating_add(1))
                            .or_insert((tick, event.timestamp_ns, 1));
                    }
                }
                _ => quarantine(run),
            }
        }
        LifecycleKind::Exit => {
            let subject = event.pid;
            if let Some(pos) = run.active.iter().position(|a| a.identity.pid == subject) {
                let identity = run.active[pos].identity.clone();
                let admit_ns = run.active[pos].admit_ns;
                match probe_liveness(subject) {
                    Liveness::Dead => {
                        if trust_reviewed {
                            if let Some(ts) = event.timestamp_ns {
                                let reval_ns = LiveClock.monotonic_ns();
                                if ts < admit_ns || ts > reval_ns {
                                    quarantine(run);
                                    return Ok(());
                                }
                            }
                        }
                        run.active[pos].session.note_kernel_edge(event.timestamp_ns);
                        run.exit_flags.insert(subject, ExitDisposition::EventExit);
                    }
                    Liveness::Alive(now) if now == identity => {
                        // Thread-exit artifact (frozen rationale):
                        // member untouched, counted once. R3-9: this
                        // arm PROVES post-admission delivery — the
                        // EXIT met a live admitted member — so it
                        // also counts the binding proof (the Reused
                        // and unmatched arms do not: delivery there
                        // precedes admission).
                        quarantine(run);
                        run.admitted_exit_artifacts = run.admitted_exit_artifacts.saturating_add(1);
                    }
                    Liveness::Alive(_) => {
                        // Reuse: the old incarnation retires
                        // `incarnation_changed`; the Exit binds to
                        // NEITHER (quarantine) — the new triple
                        // enters as a stranger.
                        run.active[pos].session.note_kernel_edge(event.timestamp_ns);
                        run.exit_flags.insert(subject, ExitDisposition::Reused);
                        quarantine(run);
                    }
                    Liveness::Unknown => quarantine(run),
                }
                return Ok(());
            }
            // 6A thread exit (§1.2): an Exit naming a non-leader tid
            // under a LIVE member removes the tid row only — the
            // TGID member and its counts survive. Absence-confirming
            // and binding-safe: the TGID's fresh triple must equal
            // the member's, the tid must be freshly observed ABSENT
            // from the task dir (a live entry — including a recycled
            // number — belongs to its current holder, so cleanup is
            // skipped), and a trusted timestamp must fall inside
            // `[admit_ns, revalidation_ns]`. Anything else
            // quarantines; cleanup carries no record (tid rows come
            // and go silently under a continuous TGID segment).
            if subject != event.tgid {
                if let Some(pos) = run.active.iter().position(|a| a.identity.pid == event.tgid) {
                    let identity = run.active[pos].identity.clone();
                    let admit_ns = run.active[pos].admit_ns;
                    let bound = verify_triple(event.tgid).is_some_and(|now| now == identity)
                        && matches!(probe_tid_liveness(event.tgid, subject), TidLiveness::Dead)
                        && (!trust_reviewed
                            || event.timestamp_ns.is_none_or(|ts| {
                                let reval_ns = LiveClock.monotonic_ns();
                                ts >= admit_ns && ts <= reval_ns
                            }));
                    if bound {
                        run.active[pos].session.remove_thread_rows(subject);
                    } else {
                        quarantine(run);
                    }
                    return Ok(());
                }
            }
            if run.deferred.keys().any(|k| k.pid == subject) {
                // Deferred exits: Dead matches silently (the sweep
                // removes with `sampled_removal`); any LIVE subject
                // mismatches — a validated triple is a thread
                // artifact, a different triple binds to NEITHER
                // incarnation (the sweep retires the old entry
                // `incarnation_changed`; the new triple joins only
                // as a stranger) — both quarantine. Unknown retains
                // silently (no confirmation either way).
                if matches!(probe_liveness(subject), Liveness::Alive(_)) {
                    quarantine(run);
                }
                return Ok(());
            }
            if run.follow_pending.contains_key(&subject) {
                // Matched: resolution handles the death.
                return Ok(());
            }
            quarantine(run);
        }
        LifecycleKind::ThreadBirth => {
            // 6A presence-binding (§1.8): a birth binds iff the
            // TGID's fresh triple EQUALS the live member's triple
            // and a trusted timestamp falls inside the member's
            // exact window. A bound birth is a BPF-side hint (the
            // tid row learns through the PENDING/THREADS path; no
            // record, TGID identity untouched); anything else
            // quarantines. A verified-but-unwatched TGID is
            // followed as a stranger candidate (its threads will
            // then bind); an unverifiable TGID quarantines.
            let tgid = event.tgid;
            let Some(pos) = run.active.iter().position(|a| a.identity.pid == tgid) else {
                match verify_triple(tgid) {
                    Some(identity) => {
                        run.follow_insert(out, tgid, identity, None)?;
                    }
                    None => quarantine(run),
                }
                return Ok(());
            };
            let identity = run.active[pos].identity.clone();
            let admit_ns = run.active[pos].admit_ns;
            match verify_triple(tgid) {
                Some(now) if now == identity => {
                    if trust_reviewed {
                        if let Some(ts) = event.timestamp_ns {
                            let now_ns = LiveClock.monotonic_ns();
                            if ts < admit_ns || ts > now_ns {
                                quarantine(run);
                                return Ok(());
                            }
                        }
                    }
                }
                _ => quarantine(run),
            }
        }
    }
    Ok(())
}
fn eligible(record: &ProcessRecord) -> bool {
    record.modules.iter().any(|m| {
        matches!(
            m.info.kind,
            inventory::ObjectKind::OpenSslCompatible
                | inventory::ObjectKind::ProviderModule
                | inventory::ObjectKind::OpenSslConsumer
        )
    })
}
/// 6A exit-flag disposition: confirmed death (revalidation-observed
/// absence) vs detected reuse (same pid, different triple).
#[derive(Clone, Copy)]
enum ExitDisposition {
    EventExit,
    Reused,
}
/// 6A per-lane loss baseline (§4.1): cumulative value + tick of the
/// last successful read (`None` until the first evaluation).
#[derive(Clone, Copy)]
struct LaneBase {
    value: u64,
    tick: Option<u64>,
}
/// 6A readmit context for exec-sealed incarnations awaiting
/// re-admission: retire instant (strict window ordering), seal tick
/// (transition-window extension) and kernel-witness instant (gated
/// transition edge).
#[derive(Clone, Copy)]
struct ReadmitCtx {
    retire_ns: u64,
    seal_tick: u64,
    witness_ts: Option<u64>,
}
/// R3-4a: outcome of advancing a stashed readmit context for a
/// witnessed second exec.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StashAdvance {
    /// No stash for this incarnation (plain stranger follow).
    None,
    /// Stash advanced + middle image sealed (caller still follows).
    Advanced,
    /// Stale trusted timestamp: quarantined, stash untouched, no
    /// follow (the event binds to nothing — never applied).
    Stale,
}
/// R4-3: bounded conservative summary of a twice-evicted readmit
/// context — the known epoch, the exact loss/deferred totals,
/// the readmit context, and the ledger windows folded through
/// the frozen coalescing rule into a single `coalesced_loss`
/// cover span (+ the fold count). Readmission resumes from the
/// summary (epoch/loss continue, never reset to 0/0); the
/// admission announces the compression with one visible gap.
/// Fixed size (no heap): key + summary + node slack fit the
/// 512 B flat (see the staging layout pin).
#[derive(Clone)]
struct TombstoneSummary {
    epoch: u64,
    loss: u64,
    deferred: DeferredSpan,
    retire_ns: u64,
    seal_tick: u64,
    witness_ts: Option<u64>,
    /// Folded cover span `[start, end)` over the dropped windows
    /// (`None` when the ledger held no windows).
    span: Option<(u64, u64)>,
    coalesced: u64,
}
impl TombstoneSummary {
    fn summarize(epoch: u64, ledger: &MemberLedger, ctx: ReadmitCtx) -> Self {
        let mut span: Option<(u64, u64)> = None;
        for w in ledger.windows.windows.iter() {
            span = Some(match span {
                None => (w.start_tick, w.end_tick),
                Some((s, e)) => (s.min(w.start_tick), e.max(w.end_tick)),
            });
        }
        Self {
            epoch,
            loss: ledger.loss,
            deferred: ledger.deferred,
            retire_ns: ctx.retire_ns,
            seal_tick: ctx.seal_tick,
            witness_ts: ctx.witness_ts,
            span,
            coalesced: ledger
                .windows
                .coalesced
                .saturating_add(ledger.windows.windows.len() as u64),
        }
    }
    fn materialize(&self) -> (u64, MemberLedger, ReadmitCtx) {
        let mut windows = WindowStore::new(WINDOW_CAP);
        if let Some((s, e)) = self.span {
            windows.append(s, e, LossCause::CoalescedLoss);
        }
        windows.coalesced = self.coalesced;
        (
            self.epoch,
            MemberLedger {
                loss: self.loss,
                deferred: self.deferred,
                windows,
            },
            ReadmitCtx {
                retire_ns: self.retire_ns,
                seal_tick: self.seal_tick,
                witness_ts: self.witness_ts,
            },
        )
    }
}
/// R4-3: stashed readmit context with its provenance — a
/// tombstone summary consumes only on actual admission success
/// (its announcement rides the admission, never a pre-admission
/// sample), and a pending/evicted hit drops any same-key
/// tombstone as stale (same-key stash entries are always
/// fresher — every exec advances the epoch).
struct StashedCtx {
    ctx: (u64, MemberLedger, ReadmitCtx),
    tombstoned: bool,
}
/// 6A coordinator run state: observed set, deferred queue, loss
/// baselines, per-tick flags and end tallies.
struct RunState {
    active: Vec<Active>,
    /// Run-shared ELF parse cache (F8d RESTORATION): handed to
    /// every admitted session so same-file parses happen once.
    parsed_cache: std::rc::Rc<std::cell::RefCell<crate::provider_observation::objects::ParseCache>>,
    deferred: BTreeMap<DeferredKey, DeferredEntry>,
    /// Followed-but-unclassified pids (event births + stranger
    /// execs): pid → (recorded triple, parent tgid if any, first tick).
    follow_pending: BTreeMap<u32, (Incarnation, Option<u32>, u64)>,
    /// Exec-sealed incarnations awaiting readmit: key → (next
    /// epoch, carried ledger, readmit context).
    pending_epoch: BTreeMap<DeferredKey, (u64, MemberLedger, ReadmitCtx)>,
    /// R3-4b: demoted readmit contexts — `pending_epoch` overflow
    /// victims keep their incarnation-wide history HERE (same
    /// value shape, same cap) instead of being deleted. No silent
    /// epoch-0 rebirth: readmission consults this table when the
    /// primary stash misses.
    evicted_epoch: BTreeMap<DeferredKey, (u64, MemberLedger, ReadmitCtx)>,
    /// R4-3: twice-evicted readmit contexts as bounded
    /// conservative summaries (key → known epoch + loss
    /// history, never a bare key). Readmission resumes from
    /// the summary; the admission announces the compression
    /// with one visible gap. Swept on death/reuse like the
    /// stash tables.
    epoch_tombstones: BTreeMap<DeferredKey, TombstoneSummary>,
    /// R4-3: triple-churn amnesia — set once a tombstone
    /// summary itself is forgotten (tombstone-table overflow).
    /// Monotonic: the forgotten incarnation may reappear at any
    /// later tick. R5-2b: while latched, every ambiguous fresh
    /// stranger is REFUSED (`SessionGap{history_ambiguous}`) —
    /// no mark can distinguish the forgotten incarnation from a
    /// genuinely new one, so no fresh 0/0 is manufactured at
    /// all. Queued-fresh heads (known-fresh before the latch)
    /// still admit with the unknown-history marker.
    epoch_amnesia: bool,
    segments: u64,
    current_tick: u64,
    prev_tick: Option<u64>,
    /// Cumulative sealed ring + per-reason read ticks
    /// (`last_loss_tick[8]`, §4.1) + per-reason propagation
    /// high-water (sealed finals plus live sessions; live sessions
    /// are folded into `consumed_ring` exactly once at seal).
    consumed_ring: [u64; 8],
    consumed_tick: [u64; 8],
    ring_hw: [u64; 8],
    lane_drops: LaneBase,
    lane_enobufs: LaneBase,
    lane_scan: LaneBase,
    lane_prefix: LaneBase,
    lane_signal: LaneBase,
    /// Cumulative session lanes (§7 `SessionLoss`).
    connector_drops: u64,
    connector_enobufs: u64,
    scan_loss: u64,
    signal_dropped: u64,
    signal_prefix_unwitnessed: u64,
    drain_pending: u64,
    carrier: WindowStore,
    unattributed: u64,
    /// R3-9: live-member EXIT artifacts (see `SessionLoss`).
    admitted_exit_artifacts: u64,
    /// R3-2: run-lifetime worker-backlog guard — topped up from
    /// the live backlog before every admission so queued link
    /// batches (kernel retention past their sessions) stay
    /// charged in the global pool.
    backlog_guard: Option<MemoryLease>,
    polling: bool,
    /// `drain_pending` at the last sample (per-tick residue gauge).
    pending_mark: u64,
    /// 6A cross-tick overflow-drop queue (oldest-first): drop
    /// records that miss the per-tick `LIMIT_TICK_BUDGET` wait here
    /// (cap `PENDING_DROPS_CAP`; newcomer classification applies
    /// backpressure when full — Discovery covers unclassified
    /// newcomers, classification resumes as the queue drains).
    /// Close flushes the remainder (close is not a tick).
    pending_drops: VecDeque<LimitRec>,
    /// Per-tick staging (flushed/consumed at the sample block).
    ignored: BTreeMap<u32, u64>,
    /// pid → (first-fence tick, first-witness ts, witness count).
    /// Multiple execs before a seal retire each image in drain
    /// order (middle images admit + retire with the carried
    /// ledger; their lifetimes sit inside the transition
    /// window, never silently skipped).
    exec_flags: BTreeMap<u32, (u64, Option<u64>, u64)>,
    exit_flags: BTreeMap<u32, ExitDisposition>,
    retire_flags: BTreeMap<u32, (&'static str, bool)>,
    unsteady: BTreeSet<u32>,
    pending_details: Vec<u32>,
    /// End tallies (§3.3, §7).
    peak_depth: u64,
    drops: u64,
    removed: DeferredRemoved,
    user_pids: BTreeSet<u32>,
    last_probe_ns: u64,
    /// 6A tick clock (§7 `Start` rule): the producer-clock anchor +
    /// nominal tick length, for tick↔ns mapping (deferred windows,
    /// uncertainty edges).
    origin_ns: u64,
    tick_ns: u64,
}
impl RunState {
    fn new(user_pids: BTreeSet<u32>, origin_ns: u64, tick_ns: u64) -> Self {
        Self {
            active: Vec::new(),
            parsed_cache: std::rc::Rc::new(std::cell::RefCell::new(
                crate::provider_observation::objects::ParseCache::new(),
            )),
            deferred: BTreeMap::new(),
            follow_pending: BTreeMap::new(),
            pending_epoch: BTreeMap::new(),
            evicted_epoch: BTreeMap::new(),
            epoch_tombstones: BTreeMap::new(),
            epoch_amnesia: false,
            segments: 0,
            current_tick: 0,
            prev_tick: None,
            consumed_ring: [0; 8],
            consumed_tick: [0; 8],
            ring_hw: [0; 8],
            lane_drops: LaneBase {
                value: 0,
                tick: None,
            },
            lane_enobufs: LaneBase {
                value: 0,
                tick: None,
            },
            lane_scan: LaneBase {
                value: 0,
                tick: None,
            },
            lane_prefix: LaneBase {
                value: 0,
                tick: None,
            },
            lane_signal: LaneBase {
                value: 0,
                tick: None,
            },
            connector_drops: 0,
            connector_enobufs: 0,
            scan_loss: 0,
            signal_dropped: 0,
            signal_prefix_unwitnessed: 0,
            drain_pending: 0,
            carrier: WindowStore::new(WINDOW_CAP),
            unattributed: 0,
            admitted_exit_artifacts: 0,
            backlog_guard: None,
            polling: false,
            pending_mark: 0,
            pending_drops: VecDeque::new(),
            ignored: BTreeMap::new(),
            exec_flags: BTreeMap::new(),
            exit_flags: BTreeMap::new(),
            retire_flags: BTreeMap::new(),
            unsteady: BTreeSet::new(),
            pending_details: Vec::new(),
            peak_depth: 0,
            drops: 0,
            removed: DeferredRemoved::default(),
            user_pids,
            last_probe_ns: origin_ns,
            origin_ns,
            tick_ns: tick_ns.max(1),
        }
    }
    /// 6A tick↔ns mapping (§7 `Start` rule): nominal tick T starts at
    /// `origin + T·tick_ns` (saturating).
    fn tick_start_ns(&self, tick: u64) -> u64 {
        self.origin_ns
            .saturating_add(tick.saturating_mul(self.tick_ns))
    }
    /// N5 closing tick: `current_tick` is assigned at sample open,
    /// so close-time detection (close drain, final sealing) needs
    /// its own elapsed-derived tick — otherwise a closing delta
    /// lands in the last sample's tick and excludes the affected
    /// tail. Never moves backward.
    fn refresh_close_tick(&mut self, now_ns: u64) {
        let close_tick = tick_of(now_ns, self.origin_ns, self.tick_ns);
        self.current_tick = self.current_tick.max(close_tick);
    }
    /// 6A loss propagation (§4.1): every open ledger (live member or
    /// deferred entry) gets the baseline-to-detection window, and
    /// the session carrier keeps it (sealed ledgers ride the
    /// carrier; they are never revised).
    fn propagate(&mut self, start: u64, end: u64, cause: LossCause) {
        self.carrier.append(start, end, cause);
        for a in &mut self.active {
            a.ledger.windows.append(start, end, cause);
        }
        for (_, e) in self.deferred.iter_mut() {
            e.marks.append(start, end, cause);
        }
    }
    /// 6A seal fold: sealed finals join the cumulative ring exactly once.
    fn seal_fold(&mut self, totals: [u64; 8]) {
        for (i, v) in totals.iter().enumerate() {
            self.consumed_ring[i] = self.consumed_ring[i].saturating_add(*v);
        }
    }
    /// 6A live ring: cumulative sealed plus current live sessions.
    fn live_ring(&self) -> [u64; 8] {
        let mut ring = self.consumed_ring;
        for a in &self.active {
            let totals = a.session.session_loss_totals();
            for (i, v) in totals.iter().enumerate() {
                ring[i] = ring[i].saturating_add(*v);
            }
        }
        ring
    }
    /// 6A per-tick ring evaluation (§4.1): per-reason deltas over
    /// the high-water propagate baseline-to-detection windows
    /// `[S, T+1)` (`S` = tick of the last accounted read, widening
    /// across skipped ticks); drain residue marks the current tick
    /// while backpressured. Baseline ticks advance ONLY to the
    /// oldest ACCOUNTED read's containing tick across live
    /// sessions (per-session/lane receipts; fix6/R6-2: peeks
    /// certify the last accounted tick, never their own read tick
    /// — receipts certify accounted coverage): failed reads retain
    /// the last successful baseline so the next detection starts
    /// at the frozen `[S, T+1)`, never after the failure — and a
    /// read evaluated a tick late never skips its own tick.
    /// Detection itself runs every tick over the best-known
    /// cumulative totals.
    fn update_loss_baselines(&mut self, tick_pending: u64) {
        let tick = self.current_tick;
        let first = self.prev_tick.is_none();
        let ring = self.live_ring();
        // N4: receipts carry (sequence, certified tick); the
        // baseline advances to the oldest CERTIFIED (accounted)
        // tick, never to the evaluation tick (fix6/R6-2).
        let seen: Vec<[u64; 8]> = self.active.iter().map(|a| a.loss_seen).collect();
        let receipts: Vec<Option<[(u64, u64); 8]>> = self
            .active
            .iter()
            .map(|a| a.session.session_loss_read_receipts())
            .collect();
        for (i, live) in ring.iter().enumerate() {
            let s = if first { tick } else { self.consumed_tick[i] };
            if *live > self.ring_hw[i] {
                self.propagate(s, tick + 1, LossCause::RingLoss);
                self.ring_hw[i] = *live;
            }
            if let Some(advance) = lane_advance(tick, i, &seen, &receipts) {
                for (a, receipt) in self.active.iter_mut().zip(receipts.iter()) {
                    if let Some(receipt) = receipt {
                        a.loss_seen[i] = receipt[i].0;
                    }
                }
                // Baselines are monotone (D-record §4.1): the clamp
                // enforces it even against a stale read tick.
                self.consumed_tick[i] = self.consumed_tick[i].max(advance);
            }
        }
        if tick_pending > 0 {
            self.propagate(tick, tick + 1, LossCause::DrainPending);
        }
    }
    /// 6A per-tick connector-lane evaluation (counter lanes only;
    /// drain residue is gauged in `update_loss_baselines`). The
    /// authoritative `signal_dropped` total is evaluated alongside
    /// its diagnostic components: sequence-hole-only loss moves the
    /// total without moving any component lane, so the total gets
    /// its own baseline and covering window (cause
    /// `connector_drops`: proven connector-channel drops — seq
    /// holes are drops the socket counter never saw — merging with
    /// the Drops-delta lane's same-cause windows by the frozen
    /// coalescing rule).
    fn update_lane_baselines(&mut self) {
        let tick = self.current_tick;
        let lanes = [
            (self.connector_drops, LossCause::ConnectorDrops, 0),
            (self.connector_enobufs, LossCause::ConnectorEnobufs, 1),
            (self.scan_loss, LossCause::ScanLoss, 2),
            (
                self.signal_prefix_unwitnessed,
                LossCause::SignalPrefixUnwitnessed,
                3,
            ),
            (self.signal_dropped, LossCause::ConnectorDrops, 4),
        ];
        for (value, cause, lane) in lanes {
            let (s, fire) = match lane {
                0 => (
                    self.lane_drops.tick.unwrap_or(tick),
                    value > self.lane_drops.value,
                ),
                1 => (
                    self.lane_enobufs.tick.unwrap_or(tick),
                    value > self.lane_enobufs.value,
                ),
                2 => (
                    self.lane_scan.tick.unwrap_or(tick),
                    value > self.lane_scan.value,
                ),
                3 => (
                    self.lane_prefix.tick.unwrap_or(tick),
                    value > self.lane_prefix.value,
                ),
                _ => (
                    self.lane_signal.tick.unwrap_or(tick),
                    value > self.lane_signal.value,
                ),
            };
            if fire {
                self.propagate(s, tick + 1, cause);
            }
            let base = match lane {
                0 => &mut self.lane_drops,
                1 => &mut self.lane_enobufs,
                2 => &mut self.lane_scan,
                3 => &mut self.lane_prefix,
                _ => &mut self.lane_signal,
            };
            if fire {
                base.value = value;
            }
            base.tick = Some(tick);
        }
    }
    /// 6A exit-flag seals (sample block + close): re-probed
    /// deaths retire `event_exit`, re-probed reuses retire
    /// `incarnation_changed`; anything else drops the flag for the
    /// sample rules (close: the seal-all covers stragglers).
    fn seal_exit_flags<W: Write>(&mut self, out: &mut Output<'_, W>) -> io::Result<()> {
        let flagged: Vec<u32> = self.exit_flags.keys().copied().collect();
        for pid in flagged {
            let Some(disp) = self.exit_flags.get(&pid).copied() else {
                continue;
            };
            let Some(pos) = self.active.iter().position(|a| a.identity.pid == pid) else {
                self.exit_flags.remove(&pid);
                continue;
            };
            let identity = self.active[pos].identity.clone();
            let seal: Option<&'static str> = match (probe_liveness(pid), disp) {
                (Liveness::Dead, ExitDisposition::EventExit) => Some("event_exit"),
                (Liveness::Alive(now), ExitDisposition::Reused) if now != identity => {
                    Some("incarnation_changed")
                }
                _ => None,
            };
            self.exit_flags.remove(&pid);
            if let Some(reason) = seal {
                let pos = self
                    .active
                    .iter()
                    .position(|a| a.identity.pid == pid)
                    .expect("flagged member");
                self.seal_active(out, pos, reason, true)?;
            }
        }
        Ok(())
    }
    /// Clear every per-member flag when the member leaves the set.
    fn drop_flags_for(&mut self, pid: u32) {
        self.exec_flags.remove(&pid);
        self.exit_flags.remove(&pid);
        self.retire_flags.remove(&pid);
        self.unsteady.remove(&pid);
        self.pending_details.retain(|p| *p != pid);
    }
    /// 6A deferred sweep (§3.2.5): revalidate every entry against the
    /// current snapshot + `eligible()` BEFORE the admission scan, so
    /// a dead head can never block the queue. Deferred execs advance
    /// the epoch in place (exe re-proof, no session to seal).
    fn sweep_deferred<W: Write>(
        &mut self,
        out: &mut Output<'_, W>,
        snapshot: &Snapshot,
    ) -> io::Result<()> {
        let tick = self.current_tick;
        let keys: Vec<DeferredKey> = self.deferred.keys().cloned().collect();
        for key in keys {
            let Some((identity, image_epoch, exe)) = self
                .deferred
                .get(&key)
                .map(|e| (e.identity.clone(), e.image_epoch, e.exe))
            else {
                continue;
            };
            let pid = identity.pid;
            match snapshot.processes.iter().find(|p| p.pid == pid) {
                Some(record) if Incarnation::from(record) == identity => {
                    // Present, same triple: exec re-proof first (the
                    // epoch tracks image identity even when the entry
                    // then leaves as ineligible), then eligibility.
                    let exe_now = exe_identity(pid);
                    let mut epoch = image_epoch;
                    if let (Some(was), Some(now)) = (exe, exe_now) {
                        if was != now {
                            epoch = epoch.saturating_add(1);
                        }
                    }
                    if !eligible(record) {
                        let entry = self.deferred.remove(&key).expect("swept entry");
                        self.emit_removal(out, &entry, epoch, "ineligible")?;
                        self.removed.ineligible = self.removed.ineligible.saturating_add(1);
                        // R6-2a: the SAME live incarnation leaves the
                        // queue but stays alive — its exec
                        // continuation (if any) re-stashes for the
                        // eligibility return (updated epoch + sealed
                        // span + loss + readmit context, like the
                        // R5-2a overflow path). Without this the
                        // return manufactures 0/0. An entry with no
                        // continuation leaves only its removal
                        // record (its 0/0 is honest).
                        if let Some(rctx) = entry.readmit {
                            if self.peek_exec_ctx(&key).is_none() {
                                let own = DeferredSpan {
                                    ticks: entry
                                        .ticks
                                        .saturating_add(tick.saturating_sub(entry.last_tick)),
                                    first_tick: entry.first_tick,
                                    last_tick: tick,
                                };
                                let mut windows = WindowStore::new(WINDOW_CAP);
                                for w in entry.marks.windows.iter() {
                                    windows.append(w.start_tick, w.end_tick, w.cause);
                                }
                                windows.coalesced =
                                    windows.coalesced.saturating_add(entry.marks.coalesced);
                                let ledger = MemberLedger {
                                    loss: entry.carried_loss,
                                    deferred: merge_deferred_spans(entry.carried_deferred, own),
                                    windows,
                                };
                                if entry.tombstoned {
                                    // The tombstone flag's
                                    // announcement promise rides the
                                    // re-stash (the admission it was
                                    // saved for never comes).
                                    emit_membership_unknown_gap(out, entry.identity.pid)?;
                                }
                                self.stash_pending_epoch(out, key, (epoch, ledger, rctx))?;
                            } else {
                                // Defensive-unreachable (same proof
                                // as the overflow path): a queued
                                // incarnation's stash was consumed
                                // at queue time; the live stash is
                                // fresher and wins, gapped.
                                debug_assert!(false, "swept victim key already stashed");
                                emit_membership_unknown_gap(out, entry.identity.pid)?;
                            }
                        }
                        continue;
                    }
                    let entry = self.deferred.get_mut(&key).expect("swept entry");
                    entry.image_epoch = epoch;
                    entry.exe = exe_now;
                    entry.ticks = entry
                        .ticks
                        .saturating_add(tick.saturating_sub(entry.last_tick));
                    entry.last_tick = tick;
                }
                Some(_) => {
                    // R6-2a: reuse DISCARDS the continuation (the
                    // incarnation is gone — the number now names a
                    // stranger; resuming the old history under it
                    // would corrupt the new incarnation).
                    let entry = self.deferred.remove(&key).expect("swept entry");
                    self.emit_removal(out, &entry, image_epoch, "incarnation_changed")?;
                    self.removed.reused = self.removed.reused.saturating_add(1);
                }
                None => match probe_liveness(pid) {
                    Liveness::Dead => {
                        // R6-2a: death DISCARDS the continuation
                        // (the incarnation is gone — nothing
                        // returns to resume it).
                        let entry = self.deferred.remove(&key).expect("swept entry");
                        self.emit_removal(out, &entry, image_epoch, "sampled_removal")?;
                        self.removed.exited = self.removed.exited.saturating_add(1);
                    }
                    Liveness::Alive(now) if now == identity => {
                        // Unscanned but alive (scanner caps/cursor):
                        // retain — eligibility is unproven, kept.
                        let entry = self.deferred.get_mut(&key).expect("swept entry");
                        entry.ticks = entry
                            .ticks
                            .saturating_add(tick.saturating_sub(entry.last_tick));
                        entry.last_tick = tick;
                    }
                    Liveness::Alive(_) => {
                        // R6-2a: reuse DISCARDS (same as above —
                        // the incarnation is gone).
                        let entry = self.deferred.remove(&key).expect("swept entry");
                        self.emit_removal(out, &entry, image_epoch, "incarnation_changed")?;
                        self.removed.reused = self.removed.reused.saturating_add(1);
                    }
                    Liveness::Unknown => {
                        // Covering unknown: retain with recovery.
                        let entry = self.deferred.get_mut(&key).expect("swept entry");
                        entry.ticks = entry
                            .ticks
                            .saturating_add(tick.saturating_sub(entry.last_tick));
                        entry.last_tick = tick;
                    }
                },
            }
        }
        self.peak_depth = self.peak_depth.max(self.deferred.len() as u64);
        Ok(())
    }
    /// 6A deferred-removal record: the sealed `[first_tick,
    /// last_tick]` span rides `loss.deferred` (§3.2.5). Segment-less
    /// states (`deferred_removed`, `sampled`) carry segment 0 (the
    /// pre-6A convention — the running counter would collide with a
    /// real segment number).
    fn emit_removal<W: Write>(
        &mut self,
        out: &mut Output<'_, W>,
        entry: &DeferredEntry,
        image_epoch: u64,
        reason: &'static str,
    ) -> io::Result<()> {
        let loss = LossSummary::from_entry(entry, self.current_tick);
        out.emit_membership(
            &entry.identity,
            0,
            "deferred_removed",
            reason,
            image_epoch,
            None,
            loss,
            false,
        )
    }
    /// 6A readmit-context sweep: drop entries whose triple is
    /// provably dead or reused (their ledger already rode the
    /// sealed segment; nothing further is owed). Unknown liveness
    /// RETAINS the context (recovery retries next tick — an
    /// unreadable `/proc` entry is not death). R3-4b: covers the
    /// primary stash, the demoted table and the tombstones — no
    /// table keeps residue for a dead incarnation.
    fn sweep_pending_epoch(&mut self) {
        let keys: Vec<DeferredKey> = self.pending_epoch.keys().cloned().collect();
        for key in keys {
            if stash_key_dead(&key) {
                self.pending_epoch.remove(&key);
            }
        }
        let keys: Vec<DeferredKey> = self.evicted_epoch.keys().cloned().collect();
        for key in keys {
            if stash_key_dead(&key) {
                self.evicted_epoch.remove(&key);
            }
        }
        let keys: Vec<DeferredKey> = self.epoch_tombstones.keys().cloned().collect();
        for key in keys {
            if stash_key_dead(&key) {
                self.epoch_tombstones.remove(&key);
            }
        }
    }
    /// 6A followed-birth resolution: sample-present births leave
    /// pending (the discovery/scan pipeline classifies the record);
    /// births dead before classification become `MembershipUnknown`
    /// gaps (never silent members); unscanned-but-alive births stay
    /// pending with recovery.
    fn resolve_follow_pending<W: Write>(
        &mut self,
        out: &mut Output<'_, W>,
        snapshot: &Snapshot,
    ) -> io::Result<()> {
        let pids: Vec<u32> = self.follow_pending.keys().copied().collect();
        for pid in pids {
            let Some((recorded, parent, _)) = self.follow_pending.get(&pid).cloned() else {
                continue;
            };
            match snapshot.processes.iter().find(|p| p.pid == pid) {
                Some(record) if Incarnation::from(record) == recorded => {
                    self.follow_pending.remove(&pid);
                }
                Some(_) => {
                    self.follow_pending.remove(&pid);
                    if let Some(root) = parent {
                        self.count_ignored(root);
                    }
                    let gap = inventory::Gap {
                        pid: Some(pid),
                        device: None,
                        inode: None,
                        reason: GapReason::MembershipUnknown,
                        errno: None,
                        actor_euid: None,
                    };
                    out.emit(Record::Gap { gap: &gap })?;
                }
                None => match probe_liveness(pid) {
                    Liveness::Dead => {
                        self.follow_pending.remove(&pid);
                        if let Some(root) = parent {
                            self.count_ignored(root);
                        }
                        let gap = inventory::Gap {
                            pid: Some(pid),
                            device: None,
                            inode: None,
                            reason: GapReason::MembershipUnknown,
                            errno: None,
                            actor_euid: None,
                        };
                        out.emit(Record::Gap { gap: &gap })?;
                    }
                    Liveness::Alive(now) if now == recorded => {}
                    Liveness::Alive(_) => {
                        self.follow_pending.remove(&pid);
                        if let Some(root) = parent {
                            self.count_ignored(root);
                        }
                        let gap = inventory::Gap {
                            pid: Some(pid),
                            device: None,
                            inode: None,
                            reason: GapReason::MembershipUnknown,
                            errno: None,
                            actor_euid: None,
                        };
                        out.emit(Record::Gap { gap: &gap })?;
                    }
                    Liveness::Unknown => {}
                },
            }
        }
        Ok(())
    }
    /// 6A capacity-bounded follow insert: followed-but-unclassified
    /// births are staging state (cap `FOLLOW_CAP`, same family as
    /// the deferred queue). A refused birth emits a visible
    /// `MembershipUnknown` gap — the birth is real (verified
    /// triple) but unfollowed; it is never a silent member and
    /// never retried silently (rediscovery re-follows when room
    /// frees).
    fn follow_insert<W: Write>(
        &mut self,
        out: &mut Output<'_, W>,
        pid: u32,
        identity: Incarnation,
        parent: Option<u32>,
    ) -> io::Result<()> {
        if self.follow_pending.len() >= FOLLOW_CAP && !self.follow_pending.contains_key(&pid) {
            let gap = inventory::Gap {
                pid: Some(pid),
                device: None,
                inode: None,
                reason: GapReason::MembershipUnknown,
                errno: None,
                actor_euid: None,
            };
            out.emit(Record::Gap { gap: &gap })?;
            return Ok(());
        }
        self.follow_pending
            .insert(pid, (identity, parent, self.current_tick));
        Ok(())
    }
    /// 6A capacity-bounded readmit-context stash: pending
    /// exec-readmit contexts are staging state (cap
    /// `PENDING_EPOCH_CAP`). Overflow drops the OLDEST context —
    /// its incarnation re-enters as a fresh candidate (the seal
    /// already carried its ledger). N8a: the eviction is VISIBLE —
    /// each dropped context emits a `MembershipUnknown` gap naming
    /// its pid (the epoch continuity is lost, explicitly, under
    /// documented pathological churn) — never a silent eviction.
    fn stash_pending_epoch<W: Write>(
        &mut self,
        out: &mut Output<'_, W>,
        key: DeferredKey,
        ctx: (u64, MemberLedger, ReadmitCtx),
    ) -> io::Result<()> {
        // R4-3: the new stash supersedes any same-key tombstone
        // (the stashed exec is newer, so its epoch is higher —
        // the summary is stale and must not resurrect later).
        self.epoch_tombstones.remove(&key);
        self.pending_epoch.insert(key, ctx);
        while self.pending_epoch.len() > PENDING_EPOCH_CAP {
            let Some(oldest) = self.pending_epoch.keys().next().cloned() else {
                break;
            };
            let Some(victim) = self.pending_epoch.remove(&oldest) else {
                break;
            };
            let gap = inventory::Gap {
                pid: Some(oldest.pid),
                device: None,
                inode: None,
                reason: GapReason::MembershipUnknown,
                errno: None,
                actor_euid: None,
            };
            out.emit(Record::Gap { gap: &gap })?;
            // R3-4b: the victim's history demotes (preserved), it
            // is not deleted — a PID-only gap never authorizes
            // epoch reuse.
            self.demote_evicted(out, oldest, victim)?;
        }
        Ok(())
    }
    /// R4-3: read the stashed exec-readmit context for `key`
    /// (primary stash, else the demoted table, else the
    /// tombstone summary — materialized). Cloned: the caller
    /// consumes on admission success and retries on failure. A
    /// pending/evicted hit wins over any same-key tombstone
    /// (always fresher — every exec advances the epoch).
    fn peek_exec_ctx(&self, key: &DeferredKey) -> Option<StashedCtx> {
        if let Some(ctx) = self.pending_epoch.get(key) {
            return Some(StashedCtx {
                ctx: ctx.clone(),
                tombstoned: false,
            });
        }
        if let Some(ctx) = self.evicted_epoch.get(key) {
            return Some(StashedCtx {
                ctx: ctx.clone(),
                tombstoned: false,
            });
        }
        self.epoch_tombstones.get(key).map(|summary| StashedCtx {
            ctx: summary.materialize(),
            tombstoned: true,
        })
    }
    /// R4-3: consume the stashed exec-readmit context for `key`
    /// from whichever table holds it. A same-key tombstone is
    /// always dropped too — either it was just consumed live
    /// (tombstone admission, announced by the caller) or it is
    /// stale (a pending/evicted hit is fresher) — either way it
    /// must not resurrect later.
    fn consume_exec_ctx(&mut self, key: &DeferredKey) {
        self.pending_epoch.remove(key);
        self.evicted_epoch.remove(key);
        self.epoch_tombstones.remove(key);
    }
    /// R4-3: admission-success bookkeeping — consume the stashed
    /// context and announce a tombstone-summary admission (the
    /// windows folded through the lossy summary) or an amnesiac
    /// QUEUED-fresh admission (history possibly forgotten) with
    /// one visible gap. Called ONLY on actual admission success —
    /// never on a pre-admission sample, never on a failed open.
    /// R5-2b: stranger-fresh newcomers are refused before any
    /// admission, so only queued-fresh heads take the amnesiac
    /// arm.
    fn note_admitted<W: Write>(
        &mut self,
        out: &mut Output<'_, W>,
        identity: &Incarnation,
        tombstoned: bool,
        fresh: bool,
    ) -> io::Result<()> {
        self.consume_exec_ctx(&DeferredKey::from(identity));
        if tombstoned || (fresh && self.epoch_amnesia) {
            emit_membership_unknown_gap(out, identity.pid)?;
        }
        Ok(())
    }
    /// R4-3: triple-churn amnesia marker — a QUEUED-fresh
    /// head (known-fresh before the latch) admitted after
    /// forgotten history carries an unknown-history window over
    /// the run so far. R5-2b: stranger-fresh newcomers are
    /// refused outright and never reach this marker.
    fn apply_amnesia(amnesia: bool, ledger: &mut MemberLedger, tick: u64) {
        if amnesia {
            ledger
                .windows
                .append(0, tick.saturating_add(1), LossCause::MembershipUnknown);
        }
    }
    /// R3-4a: advance a stashed readmit context for a witnessed
    /// second exec (stranger path): the stashed image was never
    /// observed, so it seals as an unobserved middle (§1.4
    /// amendment — drain order holds: first seal < this middle <
    /// the future readmission) and the stash moves to the next
    /// epoch with the newest witness. Consults the primary stash
    /// first, then the demoted table, then the tombstone summary
    /// (R4-3: advanced in place like the rest — a tombstoned
    /// incarnation's second exec still seals its middle and
    /// advances; no promotion cascade under pressure). A trusted
    /// timestamp predating the stashed seal is a stale
    /// previous-occupant event (N6 exact window): quarantine,
    /// never apply.
    fn advance_stash_for_exec<W: Write>(
        &mut self,
        out: &mut Output<'_, W>,
        identity: &Incarnation,
        ts: Option<u64>,
        trust_reviewed: bool,
    ) -> io::Result<StashAdvance> {
        let key = DeferredKey::from(identity);
        let in_pending = self.pending_epoch.contains_key(&key);
        let in_evicted = !in_pending && self.evicted_epoch.contains_key(&key);
        let in_tomb = !in_pending && !in_evicted && self.epoch_tombstones.contains_key(&key);
        if !in_pending && !in_evicted && !in_tomb {
            return Ok(StashAdvance::None);
        }
        let (epoch, ledger, ctx) = if in_pending {
            self.pending_epoch.get(&key).expect("probed stash").clone()
        } else if in_evicted {
            self.evicted_epoch.get(&key).expect("probed stash").clone()
        } else {
            self.epoch_tombstones
                .get(&key)
                .expect("probed stash")
                .materialize()
        };
        if trust_reviewed && ts.is_some_and(|ts| ts < ctx.retire_ns) {
            self.unattributed = self.unattributed.saturating_add(1);
            return Ok(StashAdvance::Stale);
        }
        out.emit_middle_seal(identity, epoch, &ledger)?;
        if in_pending {
            let slot = self.pending_epoch.get_mut(&key).expect("probed stash");
            slot.0 = epoch.saturating_add(1);
            slot.2.witness_ts = ts;
        } else if in_evicted {
            let slot = self.evicted_epoch.get_mut(&key).expect("probed stash");
            slot.0 = epoch.saturating_add(1);
            slot.2.witness_ts = ts;
        } else {
            let summary = self.epoch_tombstones.get_mut(&key).expect("probed stash");
            summary.epoch = epoch.saturating_add(1);
            summary.witness_ts = ts;
        }
        Ok(StashAdvance::Advanced)
    }
    /// R4-3: demote a stash-overflow victim into the evicted
    /// table (history preserved, not deleted). A full evicted
    /// table compacts ITS oldest into a tombstone summary (known
    /// epoch + loss history, visible gap now, compression
    /// announced at admission); a full tombstone table forgets
    /// its oldest summary with a visible gap AND latches the
    /// triple-churn amnesia flag (R5-2b: every later ambiguous
    /// fresh stranger is refused — forgotten history never
    /// re-authorizes a manufactured epoch-0 rebirth).
    fn demote_evicted<W: Write>(
        &mut self,
        out: &mut Output<'_, W>,
        key: DeferredKey,
        ctx: (u64, MemberLedger, ReadmitCtx),
    ) -> io::Result<()> {
        self.evicted_epoch.insert(key, ctx);
        while self.evicted_epoch.len() > EVICTED_EPOCH_CAP {
            let Some(oldest) = self.evicted_epoch.keys().next().cloned() else {
                break;
            };
            let Some(victim) = self.evicted_epoch.remove(&oldest) else {
                break;
            };
            let summary = TombstoneSummary::summarize(victim.0, &victim.1, victim.2);
            self.epoch_tombstones.insert(oldest.clone(), summary);
            while self.epoch_tombstones.len() > EPOCH_TOMBSTONE_CAP {
                let Some(ancient) = self.epoch_tombstones.keys().next().cloned() else {
                    break;
                };
                self.epoch_tombstones.remove(&ancient);
                self.epoch_amnesia = true;
                emit_membership_unknown_gap(out, ancient.pid)?;
            }
            emit_membership_unknown_gap(out, oldest.pid)?;
        }
        Ok(())
    }
    /// R3-2: reserve one session's pool lease with the live
    /// worker backlog charged first (guard top-up): `backlog` is
    /// the caller-observed `worker_backlog_charged` (a parameter,
    /// not a global read, so tests stay deterministic). `None`
    /// refuses the admission — pool too tight to even account the
    /// backlog (honest backpressure, never a hole).
    ///
    /// T7.4-fix4: admission proves the session's working
    /// envelope before reserving, in two tiers. Cold tier (no
    /// live member attached yet): prove lease plus one stock
    /// parse transient — the first member can always complete
    /// its parses, so symmetric starvation (leases held, no
    /// parse room, cache never filling) is impossible. Warm
    /// tier (some live member attached): prove the lease only —
    /// attachment implies that member's parses completed into
    /// the run cache, so a new member most likely clones (this
    /// keeps cache-covered followers admitted). The signal is
    /// deliberately attachment, not cache non-emptiness: the
    /// scanner prefills small files pre-admission, so a
    /// warm-but-irrelevant cache must not admit lease-only
    /// (that re-admits the starvation). The working set is
    /// proven, not held (parse transients are short-lived; the
    /// held lease is unchanged). A warm-tier member needing
    /// DISTINCT uncached files still refuses its parses honestly
    /// with named gaps and retries (contained self-degrade,
    /// never symmetric deadlock: the cold-proven first member
    /// always progresses). Overflow refuses here and queues with
    /// the specific `global_state_limit` gap.
    fn reserve_session(
        &mut self,
        pool: &MemoryPool,
        reservation: usize,
        backlog: usize,
    ) -> Option<MemoryLease> {
        // Free the stale guard BEFORE topping up (a new-guard
        // reserve against the old guard's spend would spuriously
        // fail on tight pools). A failed top-up refuses the
        // admission with the backlog transiently uncharged — safe:
        // nothing new is retained, and the next admission retries.
        self.backlog_guard = None;
        let guard = pool.reserve(backlog)?;
        self.backlog_guard = Some(guard);
        let warm = self.active.iter().any(|a| a.session.has_attached());
        if !warm {
            let working = crate::provider_observation::objects::session_working_bytes();
            let envelope = reservation.checked_add(working)?;
            if !pool.fits(envelope) {
                return None;
            }
        }
        pool.reserve(reservation)
    }
    /// 6A per-root ignored-descendant volume (§1.7): delivered
    /// births that resolve to death gaps (never followed).
    fn count_ignored(&mut self, parent: u32) {
        self.ignored
            .entry(parent)
            .and_modify(|n| *n = n.saturating_add(1))
            .or_insert(1);
    }
    /// 6A seal one member by position: remove, close, fold finals,
    /// clear flags. Positions must be freshly computed (no
    /// intervening mutation).
    fn seal_active<W: Write>(
        &mut self,
        out: &mut Output<'_, W>,
        pos: usize,
        reason: &'static str,
        fenced: bool,
    ) -> io::Result<()> {
        let active = self.active.remove(pos);
        let pid = active.identity.pid;
        let outcome = out.finish(active, reason, fenced)?;
        self.seal_fold(outcome.loss_totals);
        self.drop_flags_for(pid);
        Ok(())
    }
    /// 6A session open + admission record. On success the member
    /// joins with its epoch/detail/ledger; on failure a `SessionGap`
    /// names the cause (the caller decides queue/stash/forget).
    fn try_admit<W: Write>(
        &mut self,
        out: &mut Output<'_, W>,
        spec: AdmitSpec<'_>,
        lease: crate::observation_memory::MemoryLease,
        ctx: &AdmitCtx<'_>,
        admitted: &mut Vec<u32>,
    ) -> io::Result<bool> {
        // F8a: the engine deadline is a decade out (the service
        // runs until canceled) but session durations validate at ≤
        // `MAX_DURATION_SECS` — the uncapped engine life failed
        // EVERY service admission (the vacuous 24h). Cap the session
        // at the validation bound (a session observes within the
        // bound; renewal past it is future work — session windows
        // already span any dry qual).
        let duration = ctx
            .deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(crate::args::MAX_DURATION_SECS as u64));
        let config = FocusedConfig {
            duration,
            // F8d RESTORATION: the run's shared parse cache — the
            // second session clones same-file parses instead of
            // re-reserving the 22 MiB transient that no longer
            // fits beside two held session leases.
            parsed_cache: Some(self.parsed_cache.clone()),
            ..Default::default()
        };
        match FocusedSession::open_scanned_reserved(
            config,
            ctx.objects.clone(),
            (
                ctx.deadline.min(Instant::now() + Duration::from_secs(60)),
                ctx.deadline,
            ),
            ctx.cancel,
            spec.record,
            lease,
        ) {
            Ok(mut session) => {
                self.segments += 1;
                let segment = self.segments;
                out.emit_membership(
                    &spec.identity,
                    segment,
                    "observing",
                    "sampled_admission",
                    spec.epoch,
                    spec.detail,
                    LossSummary::from_ledger(&spec.ledger),
                    false,
                )?;
                admitted.push(spec.identity.pid);
                // N4: stamp receipts with this run's tick clock so
                // baselines advance to certified (accounted) read
                // ticks, not eval ticks (fix6/R6-2).
                session.set_loss_tick_clock(self.origin_ns, self.tick_ns);
                let loss_seen = session
                    .session_loss_read_receipts()
                    .map(|receipts| receipts.map(|(seq, _)| seq))
                    .unwrap_or([0; 8]);
                self.active.push(Active {
                    identity: spec.identity,
                    segment,
                    image_epoch: spec.epoch,
                    session,
                    ledger: spec.ledger,
                    admit_ns: LiveClock.monotonic_ns().max(spec.admit_floor_ns),
                    suspended: false,
                    cgroup: spec.cgroup,
                    grace_noted: None,
                    loss_seen,
                });
                Ok(true)
            }
            Err(_) => {
                out.emit(Record::SessionGap {
                    incarnation: &spec.identity,
                    reason: if ctx.cancel.load(Ordering::Relaxed) {
                        "setup_cancelled"
                    } else if Instant::now() >= ctx.deadline {
                        "setup_deadline"
                    } else {
                        "acquisition_unavailable"
                    },
                })?;
                Ok(false)
            }
        }
    }
    /// 6A deferred insert by key (§3.2.3) with deterministic
    /// drop-youngest overflow (§3.2.4): the drop record carries the
    /// dropped history's sealed span. Exec-readmit context moves
    /// into the entry — the FULL incarnation ledger carried
    /// forward (localized loss + prior deferred span exact; sealed
    /// windows folded through the frozen coalescing rule into the
    /// 4-mark store, visible via `coalesced_loss`, never silently
    /// truncated). R5-2a: an overflow victim carrying an exec
    /// continuation re-stashes into the readmit stash (epoch +
    /// loss + spans forward for the incarnation's return — its
    /// own span unions into the carried ledger like a retained
    /// head's, and a tombstoned victim's announcement promise
    /// rides the re-stash, exactly once); only a victim with no
    /// continuation (readmit `None`) leaves nothing but its drop
    /// record. Retained entries emit their per-tick `Limit` at
    /// flush time from the live queue; drop records queue
    /// oldest-first in `pending_drops` (the per-tick budget may
    /// defer them — the caller applies backpressure when the
    /// queue is full).
    fn queue_insert<W: Write>(
        &mut self,
        out: &mut Output<'_, W>,
        identity: Incarnation,
        stashed: Option<StashedCtx>,
        reason: &'static str,
    ) -> io::Result<()> {
        let tick = self.current_tick;
        let key = DeferredKey::from(&identity);
        if self.deferred.contains_key(&key) {
            if let Some(entry) = self.deferred.get_mut(&key) {
                entry.reason = reason;
            }
            return Ok(());
        }
        let (epoch, marks, readmit, carried_loss, carried_deferred, tombstoned) = match stashed {
            Some(stashed) => {
                let (epoch, ledger, rctx) = stashed.ctx;
                let mut marks = WindowStore::new(DEFERRED_MARKS);
                let mut carried = ledger.windows.windows.clone();
                carried.sort_by_key(|w| (w.start_tick, w.end_tick));
                for w in carried.iter() {
                    marks.append(w.start_tick, w.end_tick, w.cause);
                }
                marks.coalesced = marks.coalesced.saturating_add(ledger.windows.coalesced);
                (
                    epoch,
                    marks,
                    Some(rctx),
                    ledger.loss,
                    ledger.deferred,
                    stashed.tombstoned,
                )
            }
            None => (
                0,
                WindowStore::new(DEFERRED_MARKS),
                None,
                0,
                DeferredSpan::default(),
                false,
            ),
        };
        self.consume_exec_ctx(&key);
        self.deferred.insert(
            key.clone(),
            DeferredEntry {
                identity: identity.clone(),
                image_epoch: epoch,
                first_tick: tick,
                last_tick: tick,
                ticks: 1,
                reason,
                marks,
                exe: exe_identity(identity.pid),
                readmit,
                carried_loss,
                carried_deferred,
                admit_ns: LiveClock.monotonic_ns(),
                tombstoned,
            },
        );
        while self.deferred.len() > DEFERRED_CAP {
            let (vkey, dropped) = self.deferred.pop_last().expect("overflow entry");
            let own = DeferredSpan {
                ticks: dropped
                    .ticks
                    .saturating_add(tick.saturating_sub(dropped.last_tick)),
                first_tick: dropped.first_tick,
                last_tick: tick,
            };
            self.pending_drops.push_back(LimitRec {
                incarnation: dropped.identity.clone(),
                reason: "deferred_limit",
                at_tick: tick,
                deferred: Some(merge_deferred_spans(dropped.carried_deferred, own)),
            });
            self.drops = self.drops.saturating_add(1);
            // R5-2a: the victim's exec continuation (if any)
            // re-stashes for the incarnation's return — epoch +
            // loss + spans forward (the own span unions into the
            // carried ledger like a retained head's). A victim
            // with no continuation leaves only its drop record
            // (its 0/0 is honest — it never held history).
            if let Some(rctx) = dropped.readmit {
                if self.peek_exec_ctx(&vkey).is_none() {
                    let mut windows = WindowStore::new(WINDOW_CAP);
                    for w in dropped.marks.windows.iter() {
                        windows.append(w.start_tick, w.end_tick, w.cause);
                    }
                    windows.coalesced = windows.coalesced.saturating_add(dropped.marks.coalesced);
                    let ledger = MemberLedger {
                        loss: dropped.carried_loss,
                        deferred: merge_deferred_spans(dropped.carried_deferred, own),
                        windows,
                    };
                    if dropped.tombstoned {
                        // The tombstone flag's announcement
                        // promise rides the re-stash: the
                        // admission it was saved for will never
                        // come, so the queue-time fold is
                        // announced here — exactly once, never
                        // silent, never twice.
                        emit_membership_unknown_gap(out, dropped.identity.pid)?;
                    }
                    self.stash_pending_epoch(out, vkey, (dropped.image_epoch, ledger, rctx))?;
                } else {
                    // Defensive-unreachable: a queued
                    // incarnation's stash was consumed at queue
                    // time, and no seal path re-stashes under a
                    // queued key. The live stash is fresher
                    // (every exec advances the epoch) and wins;
                    // the victim's older history is gapped, never
                    // silent.
                    debug_assert!(false, "queue-drop victim key already stashed");
                    emit_membership_unknown_gap(out, dropped.identity.pid)?;
                }
            }
        }
        self.peak_depth = self.peak_depth.max(self.deferred.len() as u64);
        Ok(())
    }
    /// 6A per-tick deferral emission (§3.3): one `Limit` per RETAINED
    /// deferred incarnation (by key, with its current binding
    /// reason — recordless heads keep their last evaluated
    /// binding), then oldest-first queued drop records to fill
    /// `LIMIT_TICK_BUDGET` (1024). The budget is hard: retained
    /// entries (≤1024 by the queue cap) always fit; drops wait
    /// their turn (close flushes the remainder). This resolves
    /// the retained/drop output conflict WITHOUT touching frozen
    /// text: §3.2.4 requires every drop record (queued, never
    /// silent) and §3.3 requires every retained record per tick —
    /// both hold, with drops possibly emitting on a later tick
    /// (their sealed spans ride along, so no information is lost;
    /// `at_tick` is the emitting tick per §7).
    fn emit_limit_tick<W: Write>(&mut self, out: &mut Output<'_, W>) -> io::Result<()> {
        let tick = self.current_tick;
        let mut recs: Vec<LimitRec> = self
            .deferred
            .values()
            .map(|e| LimitRec {
                incarnation: e.identity.clone(),
                reason: e.reason,
                at_tick: tick,
                deferred: None,
            })
            .collect();
        while recs.len() < LIMIT_TICK_BUDGET {
            let Some(mut drop) = self.pending_drops.pop_front() else {
                break;
            };
            drop.at_tick = tick;
            recs.push(drop);
        }
        out.emit_limit_batch(recs)
    }
    /// 6A close flush: every still-queued drop record emits (close
    /// is not a tick, so no per-tick budget applies — the batch is
    /// bounded by `PENDING_DROPS_CAP`). `at_tick` is the emitting
    /// (close) tick per §7; sealed spans ride `deferred`.
    fn emit_pending_drops_all<W: Write>(&mut self, out: &mut Output<'_, W>) -> io::Result<()> {
        let tick = self.current_tick;
        let recs: Vec<LimitRec> = self
            .pending_drops
            .drain(..)
            .map(|mut r| {
                r.at_tick = tick;
                r
            })
            .collect();
        out.emit_limit_batch(recs)
    }
    /// 6A admission scan (§3): freed slots admit from the deferred
    /// head (smallest key) first, then newcomers by `(starttime,
    /// pid)`. Binding order per candidate: active slots, then pool
    /// (sub-limits bind mid-run as site gaps inside fresh sessions,
    /// never at admission); refusals queue by key with
    /// drop-youngest overflow. Recordless heads evaluate capacity
    /// only (a session never opens without a sample record).
    fn scan_admit<W: Write>(
        &mut self,
        out: &mut Output<'_, W>,
        snapshot: &Snapshot,
        ctx: &AdmitCtx<'_>,
        admitted: &mut Vec<u32>,
    ) -> io::Result<()> {
        let tick = self.current_tick;
        let heads: Vec<DeferredKey> = self.deferred.keys().cloned().collect();
        for key in heads {
            let Some(entry) = self.deferred.get(&key) else {
                continue;
            };
            let identity = entry.identity.clone();
            let record = snapshot.processes.iter().find(|p| p.pid == identity.pid);
            // Retained heads record their binding on the entry (the
            // per-tick `Limit` emits at flush time from the live
            // queue); recordless heads keep their last binding.
            if self.active.len() >= ctx.max_active {
                if let Some(entry) = self.deferred.get_mut(&key) {
                    entry.reason = "active_limit";
                }
                continue;
            }
            // R3-2: the session lease reserves behind the live
            // worker-backlog charge (queued batches stay pooled).
            let backlog = crate::provider_observation::session::worker_backlog_charged();
            let Some(lease) = self.reserve_session(ctx.pool, ctx.reservation, backlog) else {
                if let Some(entry) = self.deferred.get_mut(&key) {
                    entry.reason = "global_state_limit";
                }
                continue;
            };
            let Some(record) = record else {
                // Unscanned but alive: capacity is free but no
                // record exists to open against — stay queued
                // without a refusal (the span accumulator preserves
                // the tick; classification resumes next sample).
                drop(lease);
                continue;
            };
            if Incarnation::from(record) != identity {
                // Swept-swapped under us (reuse landed between sweep
                // and scan): leave for next tick's sweep.
                drop(lease);
                continue;
            }
            let entry = self.deferred.remove(&key).expect("scanned head");
            // 6A incarnation-wide ledger (§4.1): readmission resumes
            // the FULL carried history (localized loss exact, prior
            // deferred span unioned, folded marks reseeded into the
            // 64-window store) — never a zeroed ledger.
            let own = DeferredSpan {
                ticks: entry
                    .ticks
                    .saturating_add(tick.saturating_sub(entry.last_tick)),
                first_tick: entry.first_tick,
                last_tick: tick,
            };
            let mut marks = WindowStore::new(WINDOW_CAP);
            for w in entry.marks.windows.iter() {
                marks.append(w.start_tick, w.end_tick, w.cause);
            }
            marks.coalesced = marks.coalesced.saturating_add(entry.marks.coalesced);
            let mut ledger = MemberLedger {
                loss: entry.carried_loss,
                deferred: merge_deferred_spans(entry.carried_deferred, own),
                windows: marks,
            };
            // R4-3: a fully-fresh entry admitted after forgotten
            // history carries the amnesia marker (a queued
            // exec-readmit — readmit `Some`, tombstoned or not —
            // has known history and needs none).
            let fresh_head = entry.readmit.is_none();
            if fresh_head {
                Self::apply_amnesia(self.epoch_amnesia, &mut ledger, tick);
            }
            let flagged_head = entry.tombstoned;
            let (detail, floor) = match entry.readmit {
                // Queued exec-readmit: the image transition defines
                // the admission (the deferral span still rides
                // `loss.deferred`); the transition window extends
                // over the stuck span.
                Some(rctx) => {
                    if rctx.seal_tick < tick {
                        ledger.windows.append(
                            rctx.seal_tick.saturating_add(1),
                            tick.saturating_add(1),
                            LossCause::ExecSpanningAggregate,
                        );
                    }
                    (
                        Some(TransitionDetail {
                            kind: "image_readmission",
                            at_tick: tick,
                            edge_ns: if ctx.trust_reviewed {
                                rctx.witness_ts
                            } else {
                                None
                            },
                            tid: None,
                        }),
                        rctx.retire_ns.saturating_add(1),
                    )
                }
                None => (
                    Some(TransitionDetail {
                        kind: "deferred_admission",
                        at_tick: tick,
                        edge_ns: None,
                        tid: None,
                    }),
                    0,
                ),
            };
            let admitted_now = self.try_admit(
                out,
                AdmitSpec {
                    identity: identity.clone(),
                    record,
                    epoch: entry.image_epoch,
                    detail,
                    ledger,
                    cgroup: snapshot.cgroup_identity.get(&identity.pid).copied(),
                    admit_floor_ns: floor,
                },
                lease,
                ctx,
                admitted,
            )?;
            if !admitted_now {
                // Open failed: back to the queue head with its
                // history (retry next tick; the SessionGap is this
                // tick's record, not a Limit). The tombstone flag
                // rides along — the announcement waits for the
                // admission that eventually succeeds.
                let mut back = entry;
                back.last_tick = tick;
                let rekey = DeferredKey::from(&identity);
                self.deferred.insert(rekey, back);
            } else {
                // R4-3: the announcement rides the admission
                // (tombstone compression or amnesiac fresh).
                self.note_admitted(out, &identity, flagged_head, fresh_head)?;
            }
        }
        let mut newcomers: Vec<&ProcessRecord> = snapshot
            .processes
            .iter()
            .filter(|p| {
                let id = Incarnation::from(*p);
                !self.active.iter().any(|a| a.identity == id)
                    && !self.deferred.contains_key(&DeferredKey::from(&id))
            })
            .collect();
        newcomers.sort_by_key(|p| (p.starttime, p.pid));
        for record in newcomers {
            // 6A drop-queue backpressure: classification that could
            // overflow the queue pauses while the cross-tick drop
            // queue is full (a drop record must never go silent for
            // lack of room). Unclassified newcomers stay covered by
            // this tick's Discovery records and classify next tick.
            // N8b: the pause itself is VISIBLE — a session-carrier
            // `membership_unknown` window covers the unclassified
            // newcomers (otherwise-unrecorded activity, §4.1).
            // Carrier-only: open members' observation is unaffected
            // by the classification pause.
            if self.pending_drops.len() >= PENDING_DROPS_CAP && self.deferred.len() >= DEFERRED_CAP
            {
                self.carrier
                    .append(tick, tick.saturating_add(1), LossCause::MembershipUnknown);
                break;
            }
            let identity = Incarnation::from(record);
            let stash_key = DeferredKey::from(&identity);
            // R4-3: peek only — a tombstone summary consumes on
            // actual admission success (or into a queued entry),
            // never on a pre-admission sample: an ineligible (or
            // untracing, or capped) sample must neither announce
            // nor consume it.
            let stashed = self.peek_exec_ctx(&stash_key);
            // R6-2b (extends R5-2b): the ambiguity refusal precedes
            // EVERY path emitting an empty sampled ledger — a
            // forgotten ineligible (or untracing) incarnation is
            // refused with a visible record, never a fabricated
            // 0/0 `sampled` row. Remembered carriers (stashed)
            // sample their history below; genuinely-new (no
            // amnesia) sample honest 0/0.
            if stashed.is_none() && self.epoch_amnesia {
                out.emit(Record::SessionGap {
                    incarnation: &identity,
                    reason: "history_ambiguous",
                })?;
                continue;
            }
            if !eligible(record) {
                let (epoch, loss) = match &stashed {
                    Some(stashed) => (stashed.ctx.0, LossSummary::from_ledger(&stashed.ctx.1)),
                    None => (0, LossSummary::empty()),
                };
                // Machine-record reason (base logic, frozen): only
                // non-identity gaps keep visibility unknown here.
                // The human blindness decision is stricter and
                // computed separately below — the JSON reason never
                // changes for display purposes.
                let reason = if sampled_uncertain(snapshot, identity.pid) {
                    "candidate_visibility_unknown"
                } else {
                    "no_candidate_interfaces_in_sample"
                };
                out.emit_membership(
                    &identity,
                    0,
                    "sampled",
                    reason,
                    epoch,
                    None,
                    loss,
                    sampled_blind(ctx.selection, snapshot, identity.pid),
                )?;
                continue;
            }
            if !ctx.tracing {
                let epoch = stashed.as_ref().map(|s| s.ctx.0).unwrap_or(0);
                out.emit_membership(
                    &identity,
                    0,
                    "sampled",
                    "tracing_unavailable",
                    epoch,
                    None,
                    LossSummary::empty(),
                    false,
                )?;
                continue;
            }
            // R5-2b refusal hoisted above (R6-2b): a fresh
            // stranger under amnesia never reaches here (refused
            // before the sampled branches); reaching here unstashed
            // means genuinely-new (no amnesia — the empty ledger
            // below is honest).
            if self.active.len() >= ctx.max_active {
                self.queue_insert(out, identity, stashed, "active_limit")?;
                continue;
            }
            // R3-2: the session lease reserves behind the live
            // worker-backlog charge (queued batches stay pooled).
            let backlog = crate::provider_observation::session::worker_backlog_charged();
            let Some(lease) = self.reserve_session(ctx.pool, ctx.reservation, backlog) else {
                self.queue_insert(out, identity, stashed, "global_state_limit")?;
                continue;
            };
            let was_tombstoned = stashed.as_ref().is_some_and(|s| s.tombstoned);
            let was_fresh = stashed.is_none();
            let (epoch, detail, ledger, floor) = match stashed {
                Some(stashed) => {
                    let (epoch, mut ledger, rctx) = stashed.ctx;
                    if rctx.seal_tick < tick {
                        ledger.windows.append(
                            rctx.seal_tick.saturating_add(1),
                            tick.saturating_add(1),
                            LossCause::ExecSpanningAggregate,
                        );
                    }
                    (
                        epoch,
                        Some(TransitionDetail {
                            kind: "image_readmission",
                            at_tick: tick,
                            edge_ns: if ctx.trust_reviewed {
                                rctx.witness_ts
                            } else {
                                None
                            },
                            tid: None,
                        }),
                        ledger,
                        rctx.retire_ns.saturating_add(1),
                    )
                }
                None => {
                    // R5-2b: reachable only WITHOUT amnesia (a
                    // fresh stranger under amnesia is refused
                    // above) — a genuinely-new incarnation, so
                    // the empty ledger is honest and the marker
                    // below is a no-op.
                    let mut ledger = MemberLedger::empty();
                    Self::apply_amnesia(self.epoch_amnesia, &mut ledger, tick);
                    (0, None, ledger, 0)
                }
            };
            let admitted_now = self.try_admit(
                out,
                AdmitSpec {
                    identity: identity.clone(),
                    record,
                    epoch,
                    detail,
                    ledger,
                    cgroup: snapshot.cgroup_identity.get(&identity.pid).copied(),
                    admit_floor_ns: floor,
                },
                lease,
                ctx,
                admitted,
            )?;
            if admitted_now {
                // R4-3: the consume + announcement ride the
                // admission. Failed exec-readmits keep theirs
                // (retry next tick); fresh candidates are
                // forgotten (rediscovery retries).
                self.note_admitted(out, &identity, was_tombstoned, was_fresh)?;
            }
        }
        self.peak_depth = self.peak_depth.max(self.deferred.len() as u64);
        Ok(())
    }
    /// 6A inline exec readmit (§1.4): the seal freed the incarnation's
    /// own slot and session lease, which the readmit reclaims (an
    /// incumbent keeps its slot — the incarnation never left, only
    /// its image rotated). The seal site pre-stashes the readmit
    /// context and clears it on success, so every fallback path
    /// below simply returns (the context retries next tick; it
    /// never queues inline).
    #[allow(clippy::too_many_arguments, reason = "one coherent admission spec")]
    fn readmit<W: Write>(
        &mut self,
        out: &mut Output<'_, W>,
        identity: Incarnation,
        record: &ProcessRecord,
        ledger: MemberLedger,
        retire_ns: u64,
        epoch: u64,
        witness_ts: Option<u64>,
        snapshot: &Snapshot,
        ctx: &AdmitCtx<'_>,
        admitted: &mut Vec<u32>,
    ) -> io::Result<()> {
        let tick = self.current_tick;
        if self.active.len() >= ctx.max_active {
            return Ok(());
        }
        // R3-2: the session lease reserves behind the live
        // worker-backlog charge (queued batches stay pooled).
        let backlog = crate::provider_observation::session::worker_backlog_charged();
        let Some(lease) = self.reserve_session(ctx.pool, ctx.reservation, backlog) else {
            return Ok(());
        };
        self.try_admit(
            out,
            AdmitSpec {
                identity,
                record,
                epoch,
                detail: Some(TransitionDetail {
                    kind: "image_readmission",
                    at_tick: tick,
                    edge_ns: if ctx.trust_reviewed { witness_ts } else { None },
                    tid: None,
                }),
                ledger,
                cgroup: snapshot.cgroup_identity.get(&record.pid).copied(),
                admit_floor_ns: retire_ns.saturating_add(1),
            },
            lease,
            ctx,
            admitted,
        )?;
        Ok(())
    }
    /// 6A per-member sample pass (§1.3-§1.6, §2): exit/exec flags
    /// seal first (re-probed), then poll flags, then sample-driven
    /// stay/resume/retire/suspend per member, with cgroup-move
    /// details and corpse-grace accounting inline.
    fn sample_members<W: Write>(
        &mut self,
        out: &mut Output<'_, W>,
        snapshot: &Snapshot,
        ctx: &AdmitCtx<'_>,
        admitted: &mut Vec<u32>,
    ) -> io::Result<()> {
        let tick = self.current_tick;
        let failed = whole_sample_failed(snapshot);
        let excluded = exclusion_gap_present(snapshot);
        // (a) Exit flags: re-probe at seal (a resurrection, however
        // impossible, drops the flag instead of sealing a live member).
        self.seal_exit_flags(out)?;
        // (b) Exec flags: seal each witnessed image epoch IN DRAIN
        // ORDER, then readmit inline (fresh record), stash readmit
        // context (alive but unscanned/ineligible), or drop it
        // (dead/reused). The first seal consumes the live session
        // (sealed segment + `Membership{retired}`); every further
        // witnessed exec seals its middle image with ONLY
        // `Membership{retired, unobserved_transition}` (§1.4
        // amendment: no session ever observed a middle image, so
        // no admission claim, no `ProcessObservation`, no counts
        // claim — segment 0 with the carried incarnation ledger;
        // lifetimes sit inside the transition window).
        let flagged: Vec<u32> = self.exec_flags.keys().copied().collect();
        for pid in flagged {
            let Some((fence_tick, witness_ts, count)) = self.exec_flags.get(&pid).copied() else {
                continue;
            };
            let Some(pos) = self.active.iter().position(|a| a.identity.pid == pid) else {
                self.exec_flags.remove(&pid);
                continue;
            };
            let identity = self.active[pos].identity.clone();
            let epoch = self.active[pos].image_epoch;
            let next_epoch = epoch.saturating_add(count.max(1));
            self.active[pos].ledger.windows.append(
                fence_tick,
                tick.saturating_add(1),
                LossCause::ExecSpanningAggregate,
            );
            let active = self.active.remove(pos);
            self.drop_flags_for(pid);
            let outcome = out.finish_exec_seal(active)?;
            self.seal_fold(outcome.loss_totals);
            for middle in 1..count.max(1) {
                let middle_epoch = epoch.saturating_add(middle);
                out.emit_middle_seal(&identity, middle_epoch, &outcome.ledger)?;
            }
            let stash = ReadmitCtx {
                retire_ns: outcome.retire_ns,
                seal_tick: tick,
                witness_ts,
            };
            // 6A whole-sample failure (§2.4): the seal above is
            // witness-proven (kept), but the sample is
            // untrustworthy — stash the context for retry and emit
            // NO sample-derived records (no inline readmit, no
            // `sampled` membership, no liveness-stash split).
            if failed {
                self.stash_pending_epoch(
                    out,
                    DeferredKey::from(&identity),
                    (next_epoch, outcome.ledger, stash),
                )?;
                continue;
            }
            match snapshot.processes.iter().find(|p| p.pid == pid) {
                Some(record) if Incarnation::from(record) == identity => {
                    if eligible(record) && ctx.tracing {
                        // Pre-stash: try_admit consumes the spec, so
                        // the context lives here first and the
                        // readmit clears it on success.
                        self.stash_pending_epoch(
                            out,
                            DeferredKey::from(&identity),
                            (next_epoch, outcome.ledger.clone(), stash),
                        )?;
                        self.readmit(
                            out,
                            identity.clone(),
                            record,
                            outcome.ledger,
                            outcome.retire_ns,
                            next_epoch,
                            witness_ts,
                            snapshot,
                            ctx,
                            admitted,
                        )?;
                        // readmit succeeding means the member is
                        // back; clear the pre-stash then.
                        if self.active.iter().any(|a| a.identity == identity) {
                            self.consume_exec_ctx(&DeferredKey::from(&identity));
                        }
                    } else {
                        let reason = if !ctx.tracing {
                            "tracing_unavailable"
                        } else if sampled_uncertain(snapshot, identity.pid) {
                            "candidate_visibility_unknown"
                        } else {
                            "no_candidate_interfaces_in_sample"
                        };
                        out.emit_membership(
                            &identity,
                            0,
                            "sampled",
                            reason,
                            next_epoch,
                            None,
                            LossSummary::from_ledger(&outcome.ledger),
                            sampled_blind(ctx.selection, snapshot, identity.pid),
                        )?;
                        self.stash_pending_epoch(
                            out,
                            DeferredKey::from(&identity),
                            (next_epoch, outcome.ledger, stash),
                        )?;
                    }
                }
                _ => match probe_liveness(pid) {
                    Liveness::Alive(now) if now == identity => {
                        self.stash_pending_epoch(
                            out,
                            DeferredKey::from(&identity),
                            (next_epoch, outcome.ledger, stash),
                        )?;
                    }
                    Liveness::Unknown => {
                        self.stash_pending_epoch(
                            out,
                            DeferredKey::from(&identity),
                            (next_epoch, outcome.ledger, stash),
                        )?;
                    }
                    _ => {}
                },
            }
        }
        // 6A whole-sample failure (§2.4): the failure applies
        // BEFORE ordinary retention/readmission, uniformly — members
        // already encountered keep nothing. Only independently
        // proven terminal handling survives: exit flags (sealed
        // above via re-probe), exec seals (sealed above via
        // witness) and session-observed owned exits below. Every
        // other member suspends unknown with the tick-start
        // uncertainty edge (inter-tick aggregates withhold; no
        // window — the global Gap record covers the tick).
        // Retire/unsteady flags stay queued for the next
        // successful tick (nothing retires on unproven evidence).
        if failed {
            let owned: Vec<u32> = self
                .retire_flags
                .iter()
                .filter(|(_, r)| r.0 == "owned_exit")
                .map(|(pid, _)| *pid)
                .collect();
            for pid in owned {
                self.retire_flags.remove(&pid);
                if let Some(pos) = self.active.iter().position(|a| a.identity.pid == pid) {
                    self.seal_active(out, pos, "owned_exit", true)?;
                }
            }
            let edge_ns = self.tick_start_ns(tick);
            for a in self.active.iter_mut() {
                if !a.suspended {
                    a.session.suspend_retained_with_edge(edge_ns);
                    a.suspended = true;
                }
            }
            return Ok(());
        }
        // (c) Poll retire flags.
        let flagged: Vec<u32> = self.retire_flags.keys().copied().collect();
        for pid in flagged {
            let Some((reason, fenced)) = self.retire_flags.get(&pid).copied() else {
                continue;
            };
            self.retire_flags.remove(&pid);
            if let Some(pos) = self.active.iter().position(|a| a.identity.pid == pid) {
                self.seal_active(out, pos, reason, fenced)?;
            }
        }
        // (d) Unsteady (session-Unverifiable): present-and-same
        // recovers via the refresh handoff (the session's counter
        // retired spuriously; the next reconcile re-adds); anything
        // else falls through to the sample rules below.
        let flagged: Vec<u32> = self.unsteady.iter().copied().collect();
        for pid in flagged {
            self.unsteady.remove(&pid);
            let Some(pos) = self.active.iter().position(|a| a.identity.pid == pid) else {
                continue;
            };
            let identity = self.active[pos].identity.clone();
            let present_same = snapshot
                .processes
                .iter()
                .any(|p| p.pid == pid && Incarnation::from(p) == identity);
            if present_same {
                self.active[pos].session.suspend_retained();
            }
        }
        // (e) Sample-driven stay/resume/retire/suspend per member.
        let mut i = 0;
        while i < self.active.len() {
            let identity = self.active[i].identity.clone();
            let suspended = self.active[i].suspended;
            let record = snapshot.processes.iter().find(|p| p.pid == identity.pid);
            match record {
                Some(record) if Incarnation::from(record) == identity => {
                    if suspended {
                        self.active[i].suspended = false;
                    }
                    // Cgroup move: different directory identity in
                    // two consecutive stable sets (scoped only; the
                    // sidecar is empty otherwise).
                    let moved = matches!(
                        (
                            self.active[i].cgroup,
                            snapshot.cgroup_identity.get(&identity.pid).copied(),
                        ),
                        (Some(was), Some(now)) if was != now
                    );
                    self.active[i].cgroup = snapshot.cgroup_identity.get(&identity.pid).copied();
                    if moved {
                        let detail = TransitionDetail {
                            kind: "cgroup_move",
                            at_tick: tick,
                            edge_ns: None,
                            tid: None,
                        };
                        // Inter-tick window: the move landed between
                        // the previous tick and this one (spanning
                        // skipped ticks conservatively).
                        let from = self.prev_tick.unwrap_or(tick).min(tick);
                        self.active[i].ledger.windows.append(
                            from,
                            tick.saturating_add(1),
                            LossCause::CgroupMove,
                        );
                        // 6A cgroup uncertainty (§1.6): the window
                        // annotation alone never suffices — the
                        // member stays, but its inter-tick
                        // aggregates fence/withhold at the window
                        // start (latest sound tick-granular edge)
                        // and both planes refresh through the
                        // handoff (recovery re-adds; the provider
                        // fence clears after the first clean
                        // post-recovery drain).
                        let edge_ns = self.tick_start_ns(from);
                        self.active[i].session.suspend_retained_with_edge(edge_ns);
                        let loss = LossSummary::from_ledger(&self.active[i].ledger);
                        let segment = self.active[i].segment;
                        let epoch = self.active[i].image_epoch;
                        out.emit_membership(
                            &identity,
                            segment,
                            "observing",
                            "candidate_visibility_unknown",
                            epoch,
                            Some(detail),
                            loss,
                            false,
                        )?;
                    }
                    // Maps-empty grace (§1.3 foreign corpses).
                    if record.modules.is_empty() {
                        if self.active[i].grace_noted.is_none() {
                            self.active[i].grace_noted = Some(tick);
                            i += 1;
                        } else {
                            let noted = self.active[i].grace_noted.expect("noted grace");
                            self.active[i].ledger.windows.append(
                                noted,
                                tick.saturating_add(1),
                                LossCause::CorpseWait,
                            );
                            self.seal_active(out, i, "visibility_lost", true)?;
                        }
                    } else {
                        self.active[i].grace_noted = None;
                        i += 1;
                    }
                }
                _ => {
                    if record.is_some() {
                        // Present but different triple: reuse.
                        self.seal_active(out, i, "incarnation_changed", true)?;
                        continue;
                    }
                    if excluded {
                        // Partial-sample exclusion: retain unknown
                        // with a per-tick window, fenced at the
                        // tick start (inter-tick aggregates
                        // withhold — retention never projects
                        // uncertain counts).
                        if !self.active[i].suspended {
                            let edge_ns = self.tick_start_ns(tick);
                            self.active[i].session.suspend_retained_with_edge(edge_ns);
                            self.active[i].suspended = true;
                        }
                        self.active[i].ledger.windows.append(
                            tick,
                            tick.saturating_add(1),
                            LossCause::MembershipUnknown,
                        );
                        i += 1;
                        continue;
                    }
                    match departure(&identity, snapshot) {
                        Some(reason) => {
                            self.seal_active(out, i, reason, true)?;
                        }
                        None => {
                            i += 1;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
fn departure(identity: &Incarnation, snapshot: &Snapshot) -> Option<&'static str> {
    if snapshot
        .processes
        .iter()
        .any(|p| Incarnation::from(p) == *identity)
    {
        return None;
    }
    if snapshot.processes.iter().any(|p| p.pid == identity.pid) {
        return Some("incarnation_changed");
    }
    if snapshot.gaps.iter().any(|g| {
        (g.pid.is_none() || g.pid == Some(identity.pid))
            && g.reason != GapReason::IdentityUnverified
    }) {
        Some("visibility_lost")
    } else {
        Some("sampled_removal")
    }
}
/// Stderr reason for the crypto end record (always exit 3/4: coverage
/// is partial by construction), derived from the same segment count
/// the exit code derives from.
fn crypto_end_reason(segments: u64, reason: &str) -> String {
    if segments == 0 {
        format!("osslscope crypto watch: no segments observed ({reason}; see records above)")
    } else {
        format!(
            "osslscope crypto watch: {segments} segments ({reason}); coverage partial (see records above)"
        )
    }
}

/// Stderr reason for pool-reserve failures (exit 4 before any session
/// or parser exists).
fn pool_exhausted_reason() -> &'static str {
    "osslscope crypto watch: memory pool exhausted (admission blocked; no observation attempted)"
}

/// Help requested in flag position only: value-taking options consume
/// the next token (from the parser's own VALUE_OPTIONS list), so
/// flag-shaped values like `--module -h` never trigger help.
fn help_requested(args: &[String]) -> bool {
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if inventory::cli::VALUE_OPTIONS.contains(&arg.as_str()) {
            it.next();
        } else if arg == "--help" || arg == "-h" {
            return true;
        }
    }
    false
}

/// 6B steppable 6A engine (D-record §11.1): the `observe()` loop
/// restructured into open/pump/close withOUT behavior change.
/// `observe()` below drives these same methods (the 6A gates prove
/// preservation); the 6B service coordinator drives one engine per
/// run (W4 — windows never restart it) and calls `snapshot`
/// (below) at window boundaries.
pub(crate) struct ServiceEngine {
    config: CryptoWatchConfig,
    objects: FocusedObjects,
    pool: MemoryPool,
    scanner: ScopedScanner,
    port: LiveLifecycle,
    run: RunState,
    sequence: u64,
    json: bool,
    pending_gaps: Vec<(GapReason, Option<u64>, Option<u32>)>,
    resolve_paths: bool,
    terminal: bool,
    tracing: bool,
    reservation: usize,
    trust_reviewed: bool,
    run_origin_ns: u64,
    tick_ns: u64,
    deadline: Instant,
    next_scan: Instant,
    admitted: Vec<u32>,
}

/// `ServiceEngine::open` outcome: the setup record bytes always
/// flow (scope gaps / `TracingGap` / `Start`); `engine` is `None`
/// with `early_code` set when setup ends the run before the loop
/// (scope unavailable).
pub(crate) struct OpenOut {
    pub engine: Option<ServiceEngine>,
    pub setup_bytes: Vec<u8>,
    pub early_code: u8,
}

/// One pump iteration: the emitted record bytes + whether a sample
/// fired (the coordinator's admission-tick edge).
pub(crate) struct IterationOut {
    pub bytes: Vec<u8>,
    pub sample_fired: bool,
}

/// Close drain: the emitted record bytes + the 6A exit code.
pub(crate) struct CloseOut {
    pub bytes: Vec<u8>,
    pub code: u8,
}

impl ServiceEngine {
    /// Engine setup (moved verbatim from `observe()`): scanner,
    /// tracing reservation, `Start`, the lifecycle port, and the
    /// initial run state. Admission contexts are rebuilt per pump
    /// from the owned parts below.
    pub(crate) fn open(
        config: &CryptoWatchConfig,
        objects: FocusedObjects,
        pool: &MemoryPool,
        json: bool,
        producer: Option<&crate::lifecycle_producer::ProducerHandle>,
    ) -> io::Result<OpenOut> {
        let mut setup_bytes = Vec::new();
        let mut out = Output {
            writer: &mut setup_bytes,
            sequence: 0,
            json,
            pending_gaps: Vec::new(),
            resolve_paths: config.resolve_paths,
            terminal: config.terminal,
        };
        let mut scanner = match ScopedScanner::new_budgeted(
            config.selection.clone(),
            inventory::Limits::default(),
            Some(pool.clone()),
        ) {
            Ok(s) => s,
            Err(reason) => {
                out.emit(Record::Gap {
                    gap: &inventory::Gap {
                        pid: None,
                        device: None,
                        inode: None,
                        reason,
                        errno: None,
                        actor_euid: None,
                    },
                })?;
                out.emit(Record::End {
                    reason: "scope_unavailable",
                    segments: 0,
                    peak_accounted_bytes: pool.peak(),
                    coverage: "unknown",
                    peak_deferred_depth: 0,
                    deferred_drops: 0,
                    deferred_removed: DeferredRemoved::default(),
                    session_loss: SessionLoss {
                        ring: [0; 8],
                        connector_drops: 0,
                        connector_enobufs: 0,
                        scan_loss: 0,
                        signal_dropped: 0,
                        signal_prefix_unwitnessed: 0,
                        drain_pending: 0,
                        polling_fallback: false,
                        unattributed_events: 0,
                        admitted_exit_artifacts: 0,
                        lost_intervals: Vec::new(),
                        coalesced: 0,
                    },
                })?;
                crate::report::err_line(&format!(
                    "osslscope crypto watch: scope unavailable ({}; see records above)",
                    reason.word()
                ));
                drop(out);
                return Ok(OpenOut {
                    engine: None,
                    setup_bytes,
                    early_code: 4,
                });
            }
        };
        let tracing = !objects.observation.is_empty() && !objects.count.is_empty();
        if !tracing {
            out.emit(Record::TracingGap {
                reason: "companions_unavailable",
            })?;
        }
        let (tracing, reservation) = if tracing {
            match FocusedSession::reservation_bytes(&objects) {
                Ok(bytes) => (true, bytes),
                Err(_) => {
                    out.emit(Record::TracingGap {
                        reason: "session_capacity_unavailable",
                    })?;
                    (false, 0)
                }
            }
        } else {
            (false, 0)
        };
        // 6A tick clock (§7 `Start` rule): the producer-clock anchor is
        // read immediately before emitting `Start` (tick 0 opens with
        // the first sample that follows).
        let run_origin_ns = LiveClock.monotonic_ns();
        let tick_ns = config.interval.as_nanos().min(u64::MAX as u128) as u64;
        out.emit(Record::Start {
            max_active: config.max_active,
            max_state_bytes: config.max_state_bytes,
            poll_interval: config.interval,
            duration: config.duration,
            membership: "sampled; unsampled intervals and unseen members remain unknown",
            run_origin_ns,
        })?;
        // Setup emission ends here: release the setup-bytes borrow and
        // keep the sequence state for the engine.
        let Output {
            sequence,
            pending_gaps,
            ..
        } = out;
        // 6A event feed (§1.8): one port for the run, subscribed on the
        // observer itself (always live — a dead selection must not force
        // polling fallback) with the watched roots replaced every tick.
        // Subscribe failure anywhere here degrades to polling (PARTIAL),
        // never to silence.
        let barrier = crate::count_owner::CountForkBarrier::new();
        let mut port = match barrier.prefix_permit(Instant::now() + Duration::from_secs(5)) {
            Ok(permit) => match producer {
                // Installed producer: a real connector subscription
                // (trusted birth/exec/exit timestamps, Drops oracle).
                Some(producer) => {
                    LiveLifecycle::select_with_producer(std::process::id(), true, &permit, producer)
                }
                None => LiveLifecycle::select(std::process::id(), true, &permit),
            },
            Err(_) => {
                LiveLifecycle::Polling(crate::capture::PollingLifecycle::new(std::process::id()))
            }
        };
        let trust_reviewed =
            port.timing_trust() == crate::capture::LifecycleTimingTrust::ReviewedMonotonic;
        let user_pids: BTreeSet<u32> = config.selection.pids.iter().copied().collect();
        let run = RunState::new(user_pids, run_origin_ns, tick_ns);
        sync_selection(&mut scanner, &run);
        sync_roots(&mut port, &run);
        // Pack the engine (admission contexts rebuild per pump from
        // these owned parts; `cancel` arrives per call).
        let engine = ServiceEngine {
            config: config.clone(),
            objects,
            pool: pool.clone(),
            scanner,
            port,
            run,
            sequence,
            json,
            pending_gaps,
            resolve_paths: config.resolve_paths,
            terminal: config.terminal,
            tracing,
            reservation,
            trust_reviewed,
            run_origin_ns,
            tick_ns,
            deadline: Instant::now() + config.duration,
            next_scan: Instant::now(),
            admitted: Vec::new(),
        };
        Ok(OpenOut {
            engine: Some(engine),
            setup_bytes,
            early_code: 0,
        })
    }

    /// One loop iteration (moved verbatim from `observe()`): event
    /// drain, triple probes, the sample arm (when due), deferral
    /// flush, baselines, polls. Deadline/cancel/sleep stay with the
    /// caller (the coordinator's cadence). `sample_fired` marks the
    /// coordinator's admission-tick edge.
    pub(crate) fn pump_iteration(&mut self, cancel: &AtomicBool) -> io::Result<IterationOut> {
        let mut buf = Vec::new();
        let mut out = Output {
            writer: &mut buf,
            sequence: self.sequence,
            json: self.json,
            pending_gaps: std::mem::take(&mut self.pending_gaps),
            resolve_paths: self.resolve_paths,
            terminal: self.terminal,
        };
        let ctx = AdmitCtx {
            pool: &self.pool,
            objects: &self.objects,
            reservation: self.reservation,
            deadline: self.deadline,
            cancel,
            tracing: self.tracing,
            trust_reviewed: self.trust_reviewed,
            selection: &self.config.selection,
            max_active: self.config.max_active,
        };
        // Local views over owned engine state (field-disjoint from
        // the `ctx` borrows above; scalars copied out/in).
        let run = &mut self.run;
        let port = &mut self.port;
        let scanner = &mut self.scanner;
        let admitted = &mut self.admitted;
        let mut next_scan = self.next_scan;
        let deadline = self.deadline;
        let trust_reviewed = self.trust_reviewed;
        let run_origin_ns = self.run_origin_ns;
        let tick_ns = self.tick_ns;
        let interval = self.config.interval;
        let mut sample_fired = false;
        let now = Instant::now();
        // R7-3: reset the per-tick global cleanup allowance FIRST
        // (before any admission/poll arms links): live links
        // across members plus global deferred closes must leave
        // room for every new arm, so a live-path close never hits
        // the cap-hit sync arm (arms past the allowance refuse
        // with LinkLimit instead).
        crate::provider_observation::session::reset_cleanup_allowance(
            run.active
                .iter()
                .map(|a| a.session.provider_live_links())
                .sum(),
        );
        // (1) 6A event drain, every iteration: loss lanes fold and
        // events bind (fences/flags/candidates/gaps/quarantine).
        // Revalidation runs between event application (here) and
        // count projection (the polls below).
        drain_port(port, run, &mut out, trust_reviewed)?;
        // (2) 6A per-iteration triple probes (live, unflagged
        // members only): BPF rows are pid-number-keyed, so reuse
        // fences within one cadence bound instead of aliasing up to
        // a tick. The edge is the previous probe instant (the reuse
        // landed after it — conservative-early).
        let probe_edge = run.last_probe_ns;
        run.last_probe_ns = LiveClock.monotonic_ns();
        let flagged: HashSet<u32> = run
            .exec_flags
            .keys()
            .chain(run.exit_flags.keys())
            .chain(run.retire_flags.keys())
            .copied()
            .collect();
        for a in &mut run.active {
            if a.suspended || flagged.contains(&a.identity.pid) {
                continue;
            }
            match probe_liveness(a.identity.pid) {
                Liveness::Alive(now) if now == a.identity => {}
                Liveness::Unknown => {}
                _ => {
                    a.session.note_kernel_edge(Some(probe_edge));
                }
            }
        }
        // Drop each snapshot before acquiring the next; only the scanner cache
        // and active sessions retain metadata between samples.
        let sampled = if now >= next_scan {
            sample_fired = true;
            let sample_open_ns = LiveClock.monotonic_ns();
            let snapshot = scanner
                .observation_snapshot_for(interval.min(deadline.saturating_duration_since(now)));
            next_scan = Instant::now() + interval;
            // 6A elapsed-derived tick (§7 Start rule) + skipped spans
            // (nominal ticks with no sample render unknown, §4.1).
            let tick = tick_of(sample_open_ns, run_origin_ns, tick_ns);
            match run.prev_tick {
                Some(prev) if tick > prev + 1 => {
                    run.propagate(prev + 1, tick, LossCause::SkippedTick);
                }
                None if tick > 0 => {
                    run.propagate(0, tick, LossCause::SkippedTick);
                }
                _ => {}
            }
            run.current_tick = tick;
            for gap in &snapshot.snapshot.gaps {
                out.emit(Record::Gap { gap })?;
            }
            // Flush each sample's gap batch immediately (human-only;
            // JSON never buffers): without this, gap-only samples
            // accumulate silently until the end record. The buffer
            // holds one sample's (limits-bounded) gap triples at most.
            out.flush_gaps()?;
            // 6A per-member pass: flags seal first (re-probed),
            // then sample-driven stay/resume/retire/suspend.
            run.sample_members(&mut out, &snapshot.snapshot, &ctx, admitted)?;
            for p in &snapshot.snapshot.processes {
                out.emit(Record::Discovery {
                    process: p,
                    sidecar: Some(&snapshot.snapshot.resolve),
                })?;
                if cancel.load(Ordering::Relaxed) || Instant::now() >= deadline {
                    break;
                }
            }
            if !whole_sample_failed(&snapshot.snapshot) {
                run.sweep_deferred(&mut out, &snapshot.snapshot)?;
                run.sweep_pending_epoch();
                run.resolve_follow_pending(&mut out, &snapshot.snapshot)?;
                run.scan_admit(&mut out, &snapshot.snapshot, &ctx, admitted)?;
            }
            // R6-3: drain live-path deferred closes when capacity
            // frees (covers all-suspended ticks with no session
            // reconcile; live sessions also drain in reconcile).
            crate::provider_observation::session::drain_deferred_offpath();
            // 6A stashed refresh details: same-state records carrying
            // the transition (tick-quantized for determinism).
            for pid in std::mem::take(&mut run.pending_details) {
                if let Some(a) = run.active.iter().find(|a| a.identity.pid == pid) {
                    let detail = TransitionDetail {
                        kind: "additive_module_refresh",
                        at_tick: tick,
                        edge_ns: None,
                        tid: None,
                    };
                    out.emit_membership(
                        &a.identity,
                        a.segment,
                        "observing",
                        "candidate_visibility_unknown",
                        a.image_epoch,
                        Some(detail),
                        LossSummary::from_ledger(&a.ledger),
                        false,
                    )?;
                }
            }
            // Per-tick deferral flush (retained entries by key,
            // then oldest-first drops to the 1024 budget; grouped
            // past 8 rows on human).
            run.emit_limit_tick(&mut out)?;
            // 6A per-root ignored volume (human only, conditional).
            out.emit_ignored_line(&run.ignored)?;
            run.ignored.clear();
            // 6A loss baselines (ring + connector lanes).
            let tick_pending = run.drain_pending.saturating_sub(run.pending_mark);
            run.pending_mark = run.drain_pending;
            run.update_loss_baselines(tick_pending);
            run.update_lane_baselines();
            // Port bookkeeping for the tick's admissions.
            for pid in admitted.drain(..) {
                port.add_known(pid);
            }
            // Following + roots for the next sample.
            sync_selection(scanner, run);
            sync_roots(port, run);
            run.prev_tick = Some(tick);
            Some(snapshot)
        } else {
            None
        };
        let mut i = 0;
        while i < run.active.len() {
            if run.active[i].suspended {
                i += 1;
                continue;
            }
            let pid = run.active[i].identity.pid;
            let identity = run.active[i].identity.clone();
            let records = sampled.as_ref().map(|s| {
                s.snapshot
                    .processes
                    .iter()
                    .find(|p| p.pid == pid && Incarnation::from(*p) == identity)
                    .map_or(&[][..], std::slice::from_ref)
            });
            let partial = sampled
                .as_ref()
                .is_some_and(|s| !s.snapshot.gaps.is_empty());
            let tick_deadline = deadline.min(Instant::now() + Duration::from_secs(1));
            let result = run.active[i].session.poll_scanned(
                Instant::now(),
                tick_deadline,
                cancel,
                records,
                partial,
            );
            // 6A session signals (taken on every outcome — never lost).
            // A session flip only confirms (fence above): it inserts
            // when no flag exists (polling: the authoritative
            // signal) and never increments — the kernel EXEC event
            // counts, and flip-first order is systematic (see the
            // adopt rule at the event bind).
            for witness in run.active[i].session.take_exec_witnesses() {
                run.active[i].session.note_kernel_edge(None);
                let tick_now = run.current_tick;
                run.exec_flags.entry(witness).or_insert((tick_now, None, 1));
            }
            for _at in run.active[i].session.take_module_refreshes() {
                run.pending_details.push(pid);
            }
            // 6A retirement quantization: finishes seal at the sample
            // block (tick-stamped); the close path covers stragglers.
            match result {
                Ok(SessionProgress::Running) => {
                    i += 1;
                }
                Ok(SessionProgress::Exited) => {
                    run.retire_flags.insert(pid, ("owned_exit", true));
                    i += 1;
                }
                Ok(SessionProgress::Unverifiable) => {
                    run.unsteady.insert(pid);
                    i += 1;
                }
                Ok(SessionProgress::StopRequested) => {
                    let reason = if cancel.load(Ordering::Relaxed) {
                        "cancelled"
                    } else {
                        "duration"
                    };
                    run.retire_flags.insert(pid, (reason, false));
                    i += 1;
                }
                Err(_) => {
                    run.retire_flags.insert(pid, ("session_unavailable", true));
                    i += 1;
                }
            }
        }
        drop(sampled);
        self.next_scan = next_scan;
        self.sequence = out.sequence;
        self.pending_gaps = out.pending_gaps;
        Ok(IterationOut {
            bytes: buf,
            sample_fired,
        })
    }

    /// 6A close drain (moved verbatim from `observe()`): the final
    /// poll (lanes fold, events bind), retirement seals without
    /// readmit, deferred close-out, and the terminal `End`. The
    /// caller's `cancel` decides the reason word (`cancelled` vs
    /// `duration`); service stops always cancel first (the engine
    /// run IS cancelled — the window-level reason rides the
    /// envelope/summary, never the 6A vocabulary).
    pub(crate) fn close_drain(&mut self, cancel: &AtomicBool) -> io::Result<CloseOut> {
        self.close_drain_capped(cancel, None)
    }

    /// 6A close drain with an external shutdown deadline (S3/WS-A):
    /// the service passes its minted `--grace` deadline so the
    /// transport drain honors the shutdown remainder instead of
    /// only its internal bound; `None` keeps the plain drain (6A).
    pub(crate) fn close_drain_capped(
        &mut self,
        cancel: &AtomicBool,
        deadline: Option<Instant>,
    ) -> io::Result<CloseOut> {
        let mut buf = Vec::new();
        let mut out = Output {
            writer: &mut buf,
            sequence: self.sequence,
            json: self.json,
            pending_gaps: std::mem::take(&mut self.pending_gaps),
            resolve_paths: self.resolve_paths,
            terminal: self.terminal,
        };
        let run = &mut self.run;
        let port = &mut self.port;
        let run_origin_ns = self.run_origin_ns;
        let trust_reviewed = self.trust_reviewed;
        let reason = if cancel.load(Ordering::Relaxed) {
            "cancelled"
        } else {
            "duration"
        };
        // 6A close drain: a final poll — its lanes fold and its events
        // bind (births may gap; exits may confirm; execs seal without
        // readmit). No suffix witness exists on the §7 boundary, so the
        // close witness is not recorded.
        {
            let edge = crate::capture::LifecycleEdge {
                start_ns: run_origin_ns,
                end_ns: LiveClock.monotonic_ns(),
            };
            let close = match deadline {
                Some(d) => port.close_drain_capped(edge, None, d),
                None => port.close_drain(edge, None),
            };
            if let Some(delta) = close.delta {
                run.scan_loss = run.scan_loss.saturating_add(delta.loss);
                run.signal_dropped = run.signal_dropped.saturating_add(delta.dropped);
                run.signal_prefix_unwitnessed = run
                    .signal_prefix_unwitnessed
                    .saturating_add(delta.prefix_unwitnessed);
                run.drain_pending = run.drain_pending.saturating_add(delta.pending);
                run.connector_drops = run.connector_drops.saturating_add(delta.connector_drops);
                run.connector_enobufs = run
                    .connector_enobufs
                    .saturating_add(delta.connector_enobufs);
                if port.fallback_partial() {
                    run.polling = true;
                }
                let mut events = delta.events;
                events.sort_by_key(|e| (e.timestamp_ns.unwrap_or(u64::MAX), e.cpu, e.seq));
                for event in events {
                    bind_event(run, &mut out, &event, trust_reviewed)?;
                }
            }
            // 6A close-drain evaluation (§4.1): newly folded closing loss
            // needs the same covering intervals as per-tick loss — the
            // session carrier plus every still-open ledger — before the
            // seals below close those ledgers. N5: detection runs at
            // the elapsed-derived close tick, not the last sample's.
            let tick_pending = run.drain_pending.saturating_sub(run.pending_mark);
            run.pending_mark = run.drain_pending;
            run.refresh_close_tick(LiveClock.monotonic_ns());
            run.update_loss_baselines(tick_pending);
            run.update_lane_baselines();
        }
        // Stop every member before potentially slow final projection/output. This
        // also propagates cancellation arriving between poll passes into documents.
        for a in &mut run.active {
            a.session.stop_admission(cancel);
        }
        // Flagged seals first (proven deaths/reuses/execs keep their
        // exact reasons at close).
        run.seal_exit_flags(&mut out)?;
        let flagged: Vec<u32> = run.exec_flags.keys().copied().collect();
        for pid in flagged {
            let Some((fence_tick, _ts, count)) = run.exec_flags.get(&pid).copied() else {
                continue;
            };
            let Some(pos) = run.active.iter().position(|a| a.identity.pid == pid) else {
                run.exec_flags.remove(&pid);
                continue;
            };
            let epoch = run.active[pos].image_epoch;
            let identity = run.active[pos].identity.clone();
            let tick = run.current_tick;
            run.active[pos].ledger.windows.append(
                fence_tick,
                tick.saturating_add(1),
                LossCause::ExecSpanningAggregate,
            );
            let active = run.active.remove(pos);
            run.drop_flags_for(pid);
            let outcome = out.finish_exec_seal(active)?;
            run.seal_fold(outcome.loss_totals);
            // Middle images seal in drain order (no readmit at close —
            // the run ends inside the transition window).
            for middle in 1..count.max(1) {
                let middle_epoch = epoch.saturating_add(middle);
                out.emit_middle_seal(&identity, middle_epoch, &outcome.ledger)?;
            }
        }
        let flagged: Vec<u32> = run.retire_flags.keys().copied().collect();
        for pid in flagged {
            let Some((flag_reason, fenced)) = run.retire_flags.get(&pid).copied() else {
                continue;
            };
            run.retire_flags.remove(&pid);
            if let Some(pos) = run.active.iter().position(|a| a.identity.pid == pid) {
                run.seal_active(&mut out, pos, flag_reason, fenced)?;
            }
        }
        let flagged: Vec<u32> = run.unsteady.iter().copied().collect();
        for pid in flagged {
            run.unsteady.remove(&pid);
            if let Some(pos) = run.active.iter().position(|a| a.identity.pid == pid) {
                run.seal_active(&mut out, pos, "visibility_lost", true)?;
            }
        }
        // Seal-all: the run ended (death unproven either way — stopping
        // observation, never inventing exits).
        while let Some(active) = run.active.pop() {
            let pid = active.identity.pid;
            let outcome = out.finish(active, reason, false)?;
            run.seal_fold(outcome.loss_totals);
            run.drop_flags_for(pid);
        }
        // Deferred close: every entry still deferred emits
        // `deferred_removed` (cancel/timeout path vs natural expiry).
        // R6-2a: run-end DISCARDS continuations (the run ends — no
        // readmission follows, so nothing resumes them).
        let close_reason = if cancel.load(Ordering::Relaxed) {
            "cancelled"
        } else {
            "end_of_observation"
        };
        let keys: Vec<DeferredKey> = run.deferred.keys().cloned().collect();
        for key in keys {
            if let Some(entry) = run.deferred.remove(&key) {
                run.emit_removal(&mut out, &entry, entry.image_epoch, close_reason)?;
                run.removed.closed = run.removed.closed.saturating_add(1);
            }
        }
        // Follow-pending at close: dead births gap (counted per root);
        // live-but-never-classified births gap as unknown (no root bill).
        let pids: Vec<u32> = run.follow_pending.keys().copied().collect();
        for pid in pids {
            let Some((_recorded, parent, _)) = run.follow_pending.remove(&pid) else {
                continue;
            };
            let gap = inventory::Gap {
                pid: Some(pid),
                device: None,
                inode: None,
                reason: GapReason::MembershipUnknown,
                errno: None,
                actor_euid: None,
            };
            if matches!(probe_liveness(pid), Liveness::Dead) {
                if let Some(root) = parent {
                    run.count_ignored(root);
                }
            }
            out.emit(Record::Gap { gap: &gap })?;
        }
        run.pending_epoch.clear();
        // R3-4b: the run ends — no readmission follows, so demoted
        // contexts and tombstones retire with the primary stash (their
        // ledgers already rode the seals; nothing is reborn).
        run.evicted_epoch.clear();
        run.epoch_tombstones.clear();
        // R6-3: run-end flush of live-path deferred closes (terminal —
        // no more polling, so bounded synchronous close is allowed).
        crate::provider_observation::session::flush_deferred_offpath_sync();
        // 6A seal-fold evaluation (§4.1): final ring reads folded during
        // sealing join the cumulative ring here, so the evaluators run
        // once more — seal-folded loss reaches the session carrier
        // (sealed ledgers ride the carrier; they are never revised).
        // N5: same elapsed-derived close tick as the close drain.
        run.refresh_close_tick(LiveClock.monotonic_ns());
        run.update_loss_baselines(0);
        run.update_lane_baselines();
        out.flush_gaps()?;
        run.emit_pending_drops_all(&mut out)?;
        out.emit_ignored_line(&run.ignored)?;
        run.ignored.clear();
        let session_loss = SessionLoss {
            ring: run.live_ring(),
            connector_drops: run.connector_drops,
            connector_enobufs: run.connector_enobufs,
            scan_loss: run.scan_loss,
            signal_dropped: run.signal_dropped,
            signal_prefix_unwitnessed: run.signal_prefix_unwitnessed,
            drain_pending: run.drain_pending,
            polling_fallback: run.polling,
            unattributed_events: run.unattributed,
            admitted_exit_artifacts: run.admitted_exit_artifacts,
            lost_intervals: run.carrier.wire(),
            coalesced: run.carrier.coalesced,
        };
        out.emit(Record::End {
            reason,
            segments: run.segments,
            peak_accounted_bytes: self.pool.peak(),
            coverage: "partial",
            peak_deferred_depth: run.peak_depth,
            deferred_drops: run.drops,
            deferred_removed: std::mem::take(&mut run.removed),
            session_loss,
        })?;
        crate::report::err_line(&crypto_end_reason(run.segments, reason));
        let code = if run.segments == 0 { 4 } else { 3 };
        self.sequence = out.sequence;
        self.pending_gaps = out.pending_gaps;
        Ok(CloseOut { bytes: buf, code })
    }
}

impl ServiceEngine {
    /// The 6A tick-clock anchor (`Start.run_origin_ns`) for the
    /// coordinator's effective-ns → tick mapping (§11.1).
    pub(crate) fn run_origin_ns(&self) -> u64 {
        self.run_origin_ns
    }

    /// The 6A tick length in ns (the engine interval).
    pub(crate) fn tick_ns(&self) -> u64 {
        self.tick_ns
    }

    /// The §11.1 non-destructive snapshot query (additive API): deep
    /// copies of cumulative per-site counts, count-generation
    /// markers, incarnation ledgers, session tallies, and sealed
    /// in-window hit bounds — reads WITHOUT consuming anything
    /// (no re-poll, no re-read; deltas derive from the stored
    /// open/close pair only).
    ///
    /// `flip_to`: flip every member's bound-epoch to the NEXT
    /// window's seq before reading (close seal — the sealed pairs
    /// read are generation `flip_to − 1`), or `None` for the
    /// run-open acquisition read (no flip; sealed bounds unset —
    /// opens carry counts + ledgers only).
    ///
    /// Map-read failures degrade, never trap: the member's missing
    /// reads count as absent (the L3 clamp absorbs the difference
    /// and the residual formula still holds exactly) and the
    /// snapshot marks unstable (PARTIAL via the existing
    /// `forces_partial` mechanism).
    pub(crate) fn snapshot(&self, flip_to: Option<u64>) -> crate::service::snapshot::Snapshot {
        self.snapshot_impl(flip_to, flip_to.map(|g| g.saturating_sub(1)))
    }

    /// Terminal-window close (`N == u64::MAX`, §4.2): read the sealed
    /// generation WITHOUT flipping — MAX+1 is unrepresentable, so no
    /// flip target exists. Unreachable in practice; frozen for
    /// MAXGATE fidelity.
    // Test builds serve snapshots from `FakeCloseEngine`
    // (`Run.engine` is the fake under `cfg(test)`), so the real
    // sealed snapshot has no test-build caller.
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn snapshot_sealed(&self, sealed_gen: u64) -> crate::service::snapshot::Snapshot {
        self.snapshot_impl(None, Some(sealed_gen))
    }

    fn snapshot_impl(
        &self,
        flip_to: Option<u64>,
        sealed_gen: Option<u64>,
    ) -> crate::service::snapshot::Snapshot {
        use crate::service::snapshot::{
            LossView, LostView, MemberView, RunTallies, SiteBinding, SiteCounts, Snapshot,
        };
        let mut flip_failed = false;
        if let Some(g) = flip_to {
            debug_assert!(g >= 1, "first close flips 0 → 1");
            for a in &self.run.active {
                if let Some(counter) = a.session.counter() {
                    // A failed flip leaves this member's epoch
                    // behind: its sealed reads then tag-mismatch to
                    // EMPTY (L1 lazy reinit) — bounds unknown,
                    // counts exact. Tag mismatch reads
                    // stable-empty, so the failure marks unstable
                    // explicitly here (PARTIAL via `forces_partial`).
                    if counter.flip_bound_epoch(g).is_err() {
                        flip_failed = true;
                    }
                }
            }
        }
        // Close: the first monotonic read after the last flip.
        // Open: the acquisition read instant.
        let at_ns = crate::service::state::monotonic_ns();
        let mut stable = !flip_failed;
        let mut members = Vec::new();
        for a in &self.run.active {
            let mut sites = Vec::new();
            let mut bindings = Vec::new();
            let mut gen_marker = 1u32;
            let mut gaps = Vec::new();
            let mut gauges = (0u64, 0u64);
            if let Some(counter) = a.session.counter() {
                let (marker, rows, fold_gaps) = counter.snapshot_fold();
                gen_marker = marker;
                gaps = fold_gaps;
                let mut attached = 0u64;
                let mut fenced = 0u64;
                for (cookie, row, active) in &rows {
                    if *active {
                        attached += 1;
                    } else {
                        fenced += 1;
                    }
                    bindings.push(SiteBinding {
                        cookie: *cookie,
                        site: row.site.clone(),
                        candidates: row.candidates.clone(),
                        coverage: row.candidates_coverage,
                        installed_at: row.installed_at,
                    });
                }
                gauges = (attached.saturating_add(fenced), attached);
                match counter.counts_keys() {
                    Ok(keys) => {
                        for key in keys {
                            let (cookie, generation) = osslscope_ebpf_common::split_key(key);
                            let calls = counter.read_key_counts(key).unwrap_or_else(|_| {
                                stable = false;
                                0
                            });
                            let sealed_bounds = match sealed_gen {
                                Some(g) => match counter.read_sealed_bounds(key, g) {
                                    Ok((bounds, ok)) => {
                                        stable = stable && ok;
                                        bounds
                                    }
                                    Err(_) => {
                                        stable = false;
                                        None
                                    }
                                },
                                None => None,
                            };
                            // ENGINE-plane keys share the COUNTS map:
                            // site rows only. Still-open ENGINE rows
                            // are honestly EMPTY (R1 finding 4
                            // adjudication, evidence both ways):
                            // the cookie→meaning join lives in the
                            // session collector and certifies ONLY
                            // at the closed cut (`collector.build`
                            // at `FocusedSession::finish`, with
                            // finish-constructed objects +
                            // closed-tail custody proof —
                            // `capture.rs` collector, "would
                            // misattribute replacement bytes to
                            // stale meanings"; emission proven
                            // live by
                            // `native_session_routes_engine_calls_to_observations`).
                            // No certified mid-run ENGINE read API
                            // exists (a 6A engine addition — the
                            // engine is frozen), so the snapshot
                            // path projects no ENGINE rows rather
                            // than joining uncertified meanings.
                            // No ENGINE evidence is lost: retired
                            // members' sealed `engine_observations`
                            // ride `crypto_watch[]` verbatim AND
                            // merge into the window document
                            // (`snapshot::produce` sealed ENGINE
                            // merge); still-open counts accumulate
                            // in the fold + collector and certify
                            // at seal.
                            if crate::focused_count::is_engine_cookie(cookie) {
                                continue;
                            }
                            sites.push(SiteCounts {
                                cookie,
                                generation,
                                calls,
                                sealed_bounds,
                            });
                        }
                    }
                    Err(_) => {
                        stable = false;
                    }
                }
            }
            let ledger = LossSummary::from_ledger(&a.ledger);
            members.push(MemberView {
                pid: a.identity.pid,
                starttime: a.identity.starttime,
                segment: a.segment,
                image_epoch: a.image_epoch,
                sites,
                gen_marker,
                bindings,
                loss: LossView {
                    loss: ledger.loss,
                    deferred_ticks: ledger.deferred.ticks,
                    deferred_first: ledger.deferred.first_tick,
                    deferred_last: ledger.deferred.last_tick,
                    lost: ledger
                        .lost_windows
                        .iter()
                        .map(|w| LostView {
                            start_tick: w.start_tick,
                            end_tick: w.end_tick,
                            cause: w.cause,
                        })
                        .collect(),
                    coalesced: ledger.coalesced,
                },
                ring: a.session.session_loss_totals(),
                gaps,
                // Honestly empty: still-open ENGINE rows have no
                // certified mid-run projection (adjudication at the
                // engine-cookie skip above; sealed rows merge in
                // `snapshot::produce`).
                engine: Vec::new(),
                gauges,
                target: crate::evidence::TargetRecord::new(
                    a.identity.pid,
                    "unknown".to_string(),
                    String::new(),
                    String::new(),
                ),
            });
        }
        Snapshot {
            at_ns,
            stable,
            members,
            run: RunTallies {
                scan_loss: self.run.scan_loss,
                signal_dropped: self.run.signal_dropped,
                prefix_unwitnessed: self.run.signal_prefix_unwitnessed,
                drain_pending: self.run.drain_pending,
            },
            polling: self.run.polling,
        }
    }
}

/// One-shot 6A observation: the original `observe()` loop, now a
/// thin driver over the steppable engine (identical record bytes,
/// cadence, and exit codes — the 6A gates prove it).
fn observe(
    config: &CryptoWatchConfig,
    objects: FocusedObjects,
    pool: &MemoryPool,
    output: &mut impl Write,
    json: bool,
    cancel: &AtomicBool,
    producer: Option<&crate::lifecycle_producer::ProducerHandle>,
) -> io::Result<u8> {
    let opened = ServiceEngine::open(config, objects, pool, json, producer)?;
    output.write_all(&opened.setup_bytes)?;
    let mut engine = match opened.engine {
        Some(engine) => engine,
        None => return Ok(opened.early_code),
    };
    while Instant::now() < engine.deadline && !cancel.load(Ordering::Relaxed) {
        let it = engine.pump_iteration(cancel)?;
        output.write_all(&it.bytes)?;
        let remaining = engine.deadline.saturating_duration_since(Instant::now());
        if !cancel.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(25).min(remaining));
        }
    }
    let closed = engine.close_drain(cancel)?;
    output.write_all(&closed.bytes)?;
    Ok(closed.code)
}
/// Complete grammar admission precedes selectors, companion reads and signals.
pub fn run(args: &[String]) -> ExitCode {
    let invalid = || {
        crate::report::err_line(
            "osslscope crypto watch: invalid arguments (requires scan --watch --observe-crypto)",
        );
        ExitCode::from(2)
    };
    if args.first().is_none_or(|s| s != "scan")
        || args.iter().filter(|s| *s == "--observe-crypto").count() != 1
    {
        return invalid();
    }
    if help_requested(args) {
        println!(
            "usage: osslscope scan --watch --observe-crypto [--pid PID ...] [--cgroup PATH] [--module PATH ...] [--interval S] [--duration S] [--json] [--resolve-paths]"
        );
        println!(
            "Automatic per-process crypto observations; passive inventory when tracing is unavailable."
        );
        for line in crate::cli::exit_code_help_observation() {
            println!("{line}");
        }
        println!("{}", crate::cli::blocked_pointer_sub());
        return ExitCode::SUCCESS;
    }
    // 6A kernel feed (§1.8): the connector subscription needs an
    // explicitly installed lifecycle producer, and nothing
    // bootstraps one on the watch path (all production paths poll
    // today). Best effort, placed before any acquisition while the
    // process is single-threaded with a pristine descriptor table;
    // any failure keeps polling fallback (status quo, PARTIAL).
    // SAFETY: no threads exist yet, no target/native/Count state is
    // acquired, only stdio descriptors are open, SIGCHLD is default,
    // and the main thread outlives the runtime below (dropped at the
    // end of this function); the bootstrap audits the rest
    // fail-closed.
    let _producer = unsafe {
        crate::lifecycle_producer::LifecycleRuntime::bootstrap_early(
            std::time::Instant::now() + std::time::Duration::from_secs(5),
            None,
        )
    }
    .ok()
    .and_then(|runtime| {
        runtime
            .install()
            .ok()
            .map(|guard| (runtime.handle(), runtime, guard))
    });
    let producer = _producer.as_ref().map(|(handle, _, _)| handle);
    let pool = MemoryPool::new(GLOBAL_BYTES);
    let argument_bytes = args.iter().try_fold(COORDINATOR_BYTES, |n, a| {
        n.checked_add(a.len().saturating_mul(4).saturating_add(1024))
    });
    let Some(_coordinator) = argument_bytes.and_then(|n| pool.reserve(n)) else {
        return invalid();
    };
    // 6A run-lifetime leases (§3.1): the deferred queue and the
    // session-loss carrier hold separate additive leases beside the
    // coordinator lease. Per-member ledgers charge against the
    // session lease's reservation space (no separate lease).
    let Some(_deferred) = pool.reserve(DEFERRED_BYTES) else {
        crate::report::err_line("osslscope crypto watch: pool exhausted (deferred queue)");
        return ExitCode::from(4);
    };
    let Some(_session_loss) = pool.reserve(SESSION_LOSS_BYTES) else {
        crate::report::err_line("osslscope crypto watch: pool exhausted (session loss)");
        return ExitCode::from(4);
    };
    // N8d: the staging plane (followed births, pending epoch
    // ledgers, queued drop records) holds a run-lifetime lease —
    // staging past session ceilings can no longer escape the pool.
    let Some(_staging) = pool.reserve(STAGING_BYTES) else {
        crate::report::err_line("osslscope crypto watch: pool exhausted (staging stores)");
        return ExitCode::from(4);
    };
    let options = match inventory::cli::parse_crypto_watch(&args[1..]) {
        Ok(o) if o.watch => o,
        _ => return invalid(),
    };
    // F2 gate: locator acquisition runs only for human output
    // on a terminal; machine modes bypass resolution entirely.
    // Render intent travels separately (F4).
    let terminal = io::stdout().is_terminal();
    let config = CryptoWatchConfig {
        selection: Selection {
            pids: options.pids,
            cgroup: options.cgroup,
            modules: options.modules,
            resolve_paths: crate::inventory::cli::acquire_paths(
                options.resolve_paths,
                options.json,
                terminal,
            ),
        },
        duration: options.duration.unwrap_or(Duration::from_secs(30)),
        interval: options.interval.unwrap_or(Duration::from_secs(1)),
        resolve_paths: options.resolve_paths,
        terminal,
        ..Default::default()
    };
    // Resolver admits at most two 16MiB objects, with bounded verification/read
    // copies. This phase ends before any session or parser is allocated.
    let Some(resolving) = pool.reserve(64 << 20) else {
        crate::report::err_line(pool_exhausted_reason());
        return ExitCode::from(4);
    };
    let objects = match crate::package::commands::resolve_focused_objects(None, None) {
        Ok(o) => o,
        Err(_) => {
            use sha2::{Digest, Sha256};
            FocusedObjects {
                observation: std::sync::Arc::from([]),
                count: std::sync::Arc::from([]),
                count_sha256: Sha256::digest([]).into(),
            }
        }
    };
    let object_bytes = objects.observation.len() + objects.count.len();
    drop(resolving);
    let Some(_objects) = pool.reserve(object_bytes) else {
        crate::report::err_line(pool_exhausted_reason());
        return ExitCode::from(4);
    };
    let _signals = match Signals::install() {
        Ok(s) => s,
        Err(_) => return ExitCode::from(1),
    };
    match observe(
        &config,
        objects,
        &pool,
        &mut io::stdout().lock(),
        options.json,
        _signals.cancel(),
        producer,
    ) {
        Ok(code) => ExitCode::from(code),
        Err(_) => {
            crate::report::err_line("osslscope crypto watch: observation/output failed");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    fn objects() -> FocusedObjects {
        use sha2::{Digest, Sha256};
        // Session-like companions (non-empty observation): the reservation
        // under test covers a session whose counter borrows maps.
        FocusedObjects {
            observation: Arc::from([0u8; 1024]),
            count: Arc::from([0u8; 1024]),
            count_sha256: Sha256::digest([0u8; 1024]).into(),
        }
    }
    #[test]
    fn human_summary_conserves_fenced_counts_and_bounds_gaps() {
        let identity = Incarnation {
            pid: 42,
            starttime: 123,
            namespaces: inventory::NamespaceIds {
                pid: None,
                mount: None,
            },
        };
        let document = serde_json::json!({
            "sites": [{"calls": 2}], "fenced": [{"sites": [{"calls": 3}]}],
            "api_activity": [{"entries": 7}], "objects": [{}, {}],
            "completeness": {"counters": (0..12).map(|_| serde_json::json!({"name": "focused.test", "value": 1})).collect::<Vec<_>>()}
        });
        let mut bytes = Vec::new();
        let mut out = Output {
            writer: &mut bytes,
            sequence: 0,
            json: false,
            pending_gaps: Vec::new(),
            resolve_paths: false,
            terminal: false,
        };
        out.emit(Record::ProcessObservation {
            incarnation: &identity,
            segment: 4,
            retirement: "duration",
            document: &document,
            image_epoch: 0,
            loss: LossSummary::empty(),
        })
        .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("physical_entries=5 api_entries=7"));
        assert!(text.contains("start=123 segment=4") && text.contains("objects=2"));
        assert_eq!(text.lines().count(), 10);
        assert!(text.contains("Gaps omitted=4"));
        assert!(text.contains("coverage=partial attribution=unknown"));
    }
    #[test]
    fn human_totals_render_unknown_on_any_loss() {
        // §4.3: totals render unknown when any contributing
        // interval is lost, deferred or unobserved; unavailable
        // per-API entries are unknown, never zero.
        let identity = Incarnation {
            pid: 42,
            starttime: 123,
            namespaces: inventory::NamespaceIds {
                pid: None,
                mount: None,
            },
        };
        let document = serde_json::json!({
            "sites": [{"calls": 2}], "fenced": [],
            "api_activity": [{"api": 20, "entries": 3}, {"api": 21, "entries": 5}],
            "objects": [{}],
            "completeness": {"counters": []}
        });
        let sparse = serde_json::json!({
            "sites": [{"calls": 2}], "fenced": [],
            "api_activity": [{"api": 20}],
            "objects": [{}],
            "completeness": {"counters": []}
        });
        let render = |document: &serde_json::Value, loss: LossSummary| {
            let mut bytes = Vec::new();
            let mut out = Output {
                writer: &mut bytes,
                sequence: 0,
                json: false,
                pending_gaps: Vec::new(),
                resolve_paths: false,
                terminal: false,
            };
            out.emit(Record::ProcessObservation {
                incarnation: &identity,
                segment: 4,
                retirement: "duration",
                document,
                image_epoch: 0,
                loss,
            })
            .unwrap();
            drop(out);
            String::from_utf8(bytes).unwrap()
        };
        let clean = render(&document, LossSummary::empty());
        assert!(
            clean.contains("physical_entries=2 api_entries=8"),
            "{clean}"
        );
        let sparse_text = render(&sparse, LossSummary::empty());
        assert!(
            sparse_text.contains("entries=unknown"),
            "unavailable api entries are unknown, never zero: {sparse_text}"
        );
        let mut windows = WindowStore::new(WINDOW_CAP);
        windows.append(2, 3, LossCause::RingLoss);
        let affected = render(
            &document,
            LossSummary {
                loss: 0,
                deferred: DeferredSpan::default(),
                lost_windows: windows.wire(),
                coalesced: 0,
            },
        );
        assert!(
            affected.contains("physical_entries=unknown api_entries=unknown"),
            "affected totals are unknown, not numeric: {affected}"
        );
        let deferred = render(
            &document,
            LossSummary {
                loss: 0,
                deferred: DeferredSpan {
                    ticks: 2,
                    first_tick: 0,
                    last_tick: 1,
                },
                lost_windows: Vec::new(),
                coalesced: 0,
            },
        );
        assert!(
            deferred.contains("physical_entries=unknown api_entries=unknown"),
            "deferred totals are unknown: {deferred}"
        );
    }
    #[test]
    fn human_api_rows_honor_unavailable_shape() {
        // N9: production unavailable rows (entries 0 +
        // not_attached) and failed final reads (entries 0 +
        // gaps.map=1) render entries=unknown — and poison the api
        // total — even with an otherwise empty ledger. The shapes
        // below mirror `ApiActivityRow::unavailable` and the
        // failed-final-read row byte for byte.
        let identity = Incarnation {
            pid: 42,
            starttime: 123,
            namespaces: inventory::NamespaceIds {
                pid: None,
                mount: None,
            },
        };
        let unavailable = serde_json::json!({
            "api": 20, "entries": 0,
            "observed_success": 0, "observed_failure": 0,
            "verification_mismatch": 0, "unsupported": 0,
            "gaps": {"map": 0, "depth": 0, "unpaired": 0, "tail": 0,
                     "unsupported_return": 0, "saturated": false,
                     "not_attached": true, "attachment": true, "finality": true}
        });
        let failed_read = serde_json::json!({
            "api": 21, "entries": 0,
            "observed_success": 0, "observed_failure": 0,
            "verification_mismatch": 0, "unsupported": 0,
            "gaps": {"map": 1, "depth": 0, "unpaired": 0, "tail": 0,
                     "unsupported_return": 0, "saturated": false,
                     "not_attached": false, "attachment": true, "finality": true}
        });
        let clean_row = serde_json::json!({
            "api": 22, "entries": 3,
            "observed_success": 3, "observed_failure": 0,
            "verification_mismatch": 0, "unsupported": 0,
            "gaps": {"map": 0, "depth": 0, "unpaired": 0, "tail": 0,
                     "unsupported_return": 0, "saturated": false,
                     "not_attached": false, "attachment": true, "finality": true}
        });
        let render = |rows: Vec<serde_json::Value>| {
            let document = serde_json::json!({
                "sites": [], "fenced": [],
                "api_activity": rows,
                "objects": [{}],
                "completeness": {"counters": []}
            });
            let mut bytes = Vec::new();
            let mut out = Output {
                writer: &mut bytes,
                sequence: 0,
                json: false,
                pending_gaps: Vec::new(),
                resolve_paths: false,
                terminal: false,
            };
            out.emit(Record::ProcessObservation {
                incarnation: &identity,
                segment: 4,
                retirement: "duration",
                document: &document,
                image_epoch: 0,
                loss: LossSummary::empty(),
            })
            .unwrap();
            drop(out);
            String::from_utf8(bytes).unwrap()
        };
        let text = render(vec![unavailable, failed_read]);
        let api_lines: Vec<&str> = text
            .lines()
            .filter(|l| l.trim_start().starts_with("api="))
            .collect();
        assert_eq!(api_lines.len(), 2, "both rows render: {text}");
        for line in &api_lines {
            assert!(
                line.contains("entries=unknown"),
                "unavailable row must not print zero: {line}"
            );
        }
        assert!(
            text.contains("api_entries=unknown"),
            "gap-marked rows poison the api total: {text}"
        );
        let clean = render(vec![clean_row]);
        assert!(
            clean.contains("entries=3"),
            "proven rows stay numeric: {clean}"
        );
        assert!(
            clean.contains("api_entries=3"),
            "proven total stays numeric: {clean}"
        );
    }
    #[test]
    fn human_and_json_modes_carry_the_same_diagnostics() {
        let identity = Incarnation {
            pid: 42,
            starttime: 123,
            namespaces: inventory::NamespaceIds {
                pid: None,
                mount: None,
            },
        };
        let attach: Vec<_> = (0..10)
            .map(|i| serde_json::json!(format!("attach:link probe@0x{i:x} failed (kind=Denied)")))
            .collect();
        let document = serde_json::json!({
            "sites": [], "objects": [],
            "attach_diagnostics": attach,
            "refusal_diagnostics": ["budget:keyed-alloc limit: 3 entries"],
        });
        // Human: bounded summaries with omitted counts, same ROWS discipline
        // as ops/apis/gaps.
        let mut bytes = Vec::new();
        let mut out = Output {
            writer: &mut bytes,
            sequence: 0,
            json: false,
            pending_gaps: Vec::new(),
            resolve_paths: false,
            terminal: false,
        };
        out.emit(Record::ProcessObservation {
            incarnation: &identity,
            segment: 4,
            retirement: "duration",
            document: &document,
            image_epoch: 0,
            loss: LossSummary::empty(),
        })
        .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            text.contains("attach:link probe@0x0 failed (kind=Denied)"),
            "{text}"
        );
        assert!(text.contains("Attach diagnostics omitted=2"), "{text}");
        assert!(
            text.contains("budget:keyed-alloc limit: 3 entries"),
            "{text}"
        );
        // JSON: the same document carries both channels in full.
        let mut bytes = Vec::new();
        let mut out = Output {
            writer: &mut bytes,
            sequence: 0,
            json: true,
            pending_gaps: Vec::new(),
            resolve_paths: false,
            terminal: false,
        };
        out.emit(Record::ProcessObservation {
            incarnation: &identity,
            segment: 4,
            retirement: "duration",
            document: &document,
            image_epoch: 0,
            loss: LossSummary::empty(),
        })
        .unwrap();
        let envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let doc = &envelope["document"];
        assert_eq!(doc["attach_diagnostics"].as_array().unwrap().len(), 10);
        assert_eq!(doc["refusal_diagnostics"].as_array().unwrap().len(), 1);
    }
    #[test]
    fn parser_refused_honestly_with_two_sessions_live_recovers_after() {
        // F8d (R1 finding 8) — pool-arithmetic pin (STILL TRUE):
        // the pre-6A envelope (stock parser + TWO max sessions on
        // one 256 MiB pool) no longer fits — the 6A sealed-bound
        // maps cost ~1.39 MiB per session and the pool size is
        // D-bound frozen. This pins the HONEST behavior of the
        // SYNTHETIC contended state: refusal (never silent
        // corruption), partial availability (small modules still
        // parse), and recovery (the parse fits again once a
        // session ends). The stock size IS libcrypto.so.3
        // (6,386,528 B on the qual host): with two max sessions
        // ~21.8 MiB is free, so modules ≤ ~4.7 MiB parse and
        // larger ones refuse.
        //
        // T7.4-fix4: the RESTORATION premise above proved false
        // in live 2-pid runs — both leases land before either
        // parse, so the cache never fills and BOTH sessions
        // refuse the first same-file parse (symmetric
        // silent-zero). Admission now proves the working
        // envelope in two tiers (`reserve_session`): cold (no
        // live member attached yet) proves lease + one stock
        // transient, so the first member always keeps parse
        // room and the cache fills; warm (some member
        // attached) proves the lease only, so cache-covered
        // followers still admit. Overflow queues with the
        // specific `global_state_limit` gap. This test's
        // synthetic exhaustion still refuses (the pool
        // arithmetic is unchanged). BPF map right-sizing stays
        // round-2 work.
        //
        // CI-fix: the free-space premise above holds only on
        // many-CPU hosts (per-CPU map growth); 4-CPU CI runners
        // left slack a stock parse fit (check.yml runs
        // 42861210551 + 42974059023). The clamp below takes that
        // host-dependent slack, leaving exactly one small-module
        // scratch free, so the refuse/fit/recover legs hold on
        // any CPU count. Already-contended hosts take no filler.
        let pool = MemoryPool::new(GLOBAL_BYTES);
        let _coordinator = pool.reserve(COORDINATOR_BYTES + 32_768).unwrap();
        let _scanner = pool.reserve(4096 * 160 + 100 * 4096).unwrap();
        let cost = FocusedSession::reservation_bytes(&objects()).unwrap() + 29_480;
        let _a = pool.reserve(cost).unwrap();
        let _b = pool.reserve(cost).unwrap();
        let small = inventory::elf::parser_scratch_bytes(1 << 20).unwrap();
        let _pressure = pool.clamp_free_to(small);
        // Contended: the stock parse refuses (loud `None` — the
        // scan records a `ReadLimit` gap, never a silent skip).
        assert!(
            pool.reserve(inventory::elf::parser_scratch_bytes(6_386_528).unwrap())
                .is_none(),
            "stock libcrypto parse refuses under two max sessions"
        );
        // Partial availability: small modules still parse (a
        // 1 MiB module needs ~17.9 MiB, exactly the clamped free).
        {
            let _fit = pool
                .reserve(small)
                .expect("small-module parse fits under two sessions");
        }
        // Recovery: the stock parse fits again once a session ends.
        drop(_b);
        let _parser = pool
            .reserve(inventory::elf::parser_scratch_bytes(6_386_528).unwrap())
            .expect("stock parse recovers after a session ends");
        assert!(pool.peak() <= GLOBAL_BYTES);
    }
    #[test]
    fn two_normal_reservations_fit_parser_coexists_with_one() {
        // 6B capacity note (D-record §11.1, mandated): the
        // sealed-bound maps (BOUNDS/EPOCH/EPOCH_CUR, 2048-entry
        // bound per the loader capacity comment) grow each session
        // reservation (~2.5 MiB at 16 CPUs), so the stock parser
        // scratch no longer fits alongside TWO max sessions. This
        // test proves the pool arithmetic: two leases +
        // coordinator + scanner fit (a third lease refused), and
        // the stock parser still coexists with ONE session.
        // T7.4-fix4: cold admission no longer reaches the
        // two-lease state for maximal sessions — the second
        // envelope refuses at `reserve_session` (lease + working
        // must fit) and queues `global_state_limit` until a
        // member attaches and warms admission. The admitted
        // member keeps the one-session-plus-parser coexistence
        // below.
        let pool = MemoryPool::new(GLOBAL_BYTES);
        let _coordinator = pool.reserve(COORDINATOR_BYTES + 32_768).unwrap();
        let _scanner = pool.reserve(4096 * 160 + 100 * 4096).unwrap();
        let cost = FocusedSession::reservation_bytes(&objects()).unwrap() + 29_480;
        let _a = pool.reserve(cost).unwrap();
        let _b = pool.reserve(cost).unwrap();
        assert!(pool.peak() <= GLOBAL_BYTES);
        assert!(pool.reserve(cost).is_none());
        // Parser coexistence with one session (fresh pool).
        let pool2 = MemoryPool::new(GLOBAL_BYTES);
        let _coordinator2 = pool2.reserve(COORDINATOR_BYTES + 32_768).unwrap();
        let _scanner2 = pool2.reserve(4096 * 160 + 100 * 4096).unwrap();
        let _a2 = pool2.reserve(cost).unwrap();
        let _parser = pool2
            .reserve(inventory::elf::parser_scratch_bytes(6_386_528).unwrap())
            .unwrap();
        assert!(pool2.peak() <= GLOBAL_BYTES);
    }
    #[test]
    fn second_session_envelope_refused_while_first_holds() {
        // T7.4-fix4 cold tier (fresh run, nothing attached):
        // admission proves lease + one stock parse transient per
        // session.
        // A pool fitting two leases but one byte short of the
        // second working set admits the first session and refuses
        // the second — the pre-fix over-admit held both leases
        // with room for neither parse, starving BOTH sessions
        // silent-zero.
        let working = crate::provider_observation::objects::session_working_bytes();
        let reservation = 1 << 20;
        let pool = MemoryPool::new(2 * reservation + working - 1);
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        let first = run.reserve_session(&pool, reservation, 0);
        assert!(first.is_some(), "first envelope must admit");
        let second = run.reserve_session(&pool, reservation, 0);
        assert!(
            second.is_none(),
            "second envelope must refuse: pool cannot fund its working set"
        );
        drop(first);
        let retry = run.reserve_session(&pool, reservation, 0);
        assert!(
            retry.is_some(),
            "refused envelope recovers after a session ends"
        );
    }
    #[test]
    fn refused_newcomer_queues_global_state_limit_naming_member() {
        // T7.4-fix4: the refused envelope queues with the specific
        // named gap — which limit (`global_state_limit`) plus
        // which member (incarnation) — and the per-tick Limit
        // record carries all three fields.
        fn eligible_snapshot(pid: u32, starttime: u64) -> inventory::Snapshot {
            let module = inventory::ModuleRecord {
                info: inventory::ModuleInfo {
                    sha256: String::new(),
                    device: 0,
                    inode: 0,
                    size_bytes: 0,
                    architecture: inventory::Architecture::X86_64,
                    kind: inventory::ObjectKind::OpenSslConsumer,
                    exports: Vec::new(),
                    depends_on_libcrypto: false,
                    depends_on_libssl: false,
                },
                identity_status: inventory::IdentityStatus::Verified,
            };
            let record = inventory::ProcessRecord {
                interval: inventory::CaptureInterval {
                    started_unix_ms: None,
                    finished_unix_ms: None,
                    elapsed_ns: 0,
                },
                namespaces: inventory::NamespaceIds {
                    pid: None,
                    mount: None,
                },
                pid,
                starttime,
                modules: vec![module],
                provider_activation: inventory::ObservationState::Unknown,
                provider_interfaces: inventory::ObservationState::Unknown,
                execution: inventory::ObservationState::Unknown,
            };
            inventory::Snapshot {
                interval: inventory::CaptureInterval {
                    started_unix_ms: None,
                    finished_unix_ms: None,
                    elapsed_ns: 0,
                },
                scope_record: inventory::ScopeRecord::default(),
                schema_version: "crypto-watch-test".to_owned(),
                mode: inventory::SnapshotMode::Snapshot,
                scope: inventory::Scope::Pids,
                selected_pids: vec![pid],
                processes: vec![record],
                gaps: Vec::new(),
                totals: inventory::WorkTotals {
                    processes_attempted: 1,
                    objects_attempted: 0,
                    objects_inspected: 0,
                    read_bytes: 0,
                },
                limits: inventory::Limits::default(),
                capabilities: inventory::Capabilities {
                    inventory: inventory::InventoryState::Complete,
                    provider_activation: inventory::ObservationState::Unknown,
                    provider_interfaces: inventory::ObservationState::Unknown,
                    execution: inventory::ObservationState::Unknown,
                },
                resolve: Default::default(),
                cgroup_identity: std::collections::BTreeMap::new(),
            }
        }
        let working = crate::provider_observation::objects::session_working_bytes();
        let reservation = 1 << 20;
        let pool = MemoryPool::new(2 * reservation + working - 1);
        // Simulate the admitted first session's held lease.
        let _held = pool.reserve(reservation).unwrap();
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        let snapshot = eligible_snapshot(4242, 1);
        assert!(
            eligible(&snapshot.processes[0]),
            "synthetic record must be eligible (premise)"
        );
        let objects = FocusedObjects {
            observation: Arc::from([0u8; 8]),
            count: Arc::from([0u8; 8]),
            count_sha256: [0; 32],
        };
        let selection = Selection::default();
        let cancel = AtomicBool::new(false);
        let ctx = AdmitCtx {
            pool: &pool,
            objects: &objects,
            reservation,
            deadline: Instant::now() + Duration::from_secs(60),
            cancel: &cancel,
            tracing: true,
            trust_reviewed: false,
            selection: &selection,
            max_active: 4,
        };
        let mut bytes = Vec::new();
        let mut sink = Output {
            writer: &mut bytes,
            sequence: 0,
            json: true,
            pending_gaps: Vec::new(),
            resolve_paths: false,
            terminal: false,
        };
        let mut admitted = Vec::new();
        run.scan_admit(&mut sink, &snapshot, &ctx, &mut admitted)
            .unwrap();
        assert!(admitted.is_empty(), "tight pool must not admit");
        let identity = Incarnation::from(&snapshot.processes[0]);
        let entry = run
            .deferred
            .get(&DeferredKey::from(&identity))
            .expect("refused newcomer must queue with the specific gap");
        assert_eq!(entry.reason, "global_state_limit");
        run.emit_limit_tick(&mut sink).unwrap();
        drop(sink);
        let rows: Vec<serde_json::Value> = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let limit = rows
            .iter()
            .find(|r| r["kind"] == "limit" && r["incarnation"]["pid"] == 4242 && r["at_tick"] == 0)
            .expect("per-tick Limit must name the refused member");
        assert_eq!(limit["reason"], "global_state_limit");
    }
    #[test]
    fn cache_warmth_without_attach_keeps_cold_tier() {
        // T7.4-fix4: cache non-emptiness is NOT the warm signal —
        // the scanner prefills small files pre-admission, so a
        // warm-but-irrelevant cache must not admit lease-only
        // (that re-admits the starvation). Only an attached
        // member warms admission (see below).
        let working = crate::provider_observation::objects::session_working_bytes();
        let reservation = 1 << 20;
        let pool = MemoryPool::new(2 * reservation + working - 1);
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        let first = run
            .reserve_session(&pool, reservation, 0)
            .expect("first admits cold");
        // Warm the run cache with a real parse (roomy side pool).
        let path = std::env::temp_dir().join(format!("osslscope-fix4-warm-{}", std::process::id()));
        std::fs::copy("/bin/true", &path).unwrap();
        {
            let side = MemoryPool::new(64 << 20);
            let mut budget = crate::provider_observation::ObservationBudget::default();
            budget.memory = Some(side);
            budget.parsed_cache = Some(run.parsed_cache.clone());
            let mut file = std::fs::File::open(&path).unwrap();
            crate::provider_observation::objects::parse_object(&mut file, None, &budget)
                .expect("warm parse fills");
        }
        std::fs::remove_file(&path).unwrap();
        let second = run.reserve_session(&pool, reservation, 0);
        assert!(
            second.is_none(),
            "warmed cache without an attached member must not admit lease-only"
        );
        drop(first);
    }
    #[test]
    fn attached_member_warms_admission_lease_only() {
        // T7.4-fix4 warm tier: a live attached member's parses
        // completed into the run cache, so a new member most
        // likely clones — the lease alone admits (this keeps
        // cache-covered followers, e.g. six_a survivors,
        // admitted). Pins the readiness wiring; production
        // readiness implies completed parses (argued at
        // `reserve_session`, proven live by six_a + 2-pid runs).
        let working = crate::provider_observation::objects::session_working_bytes();
        let reservation = 1 << 20;
        let pool = MemoryPool::new(2 * reservation + working - 1);
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        let first = run
            .reserve_session(&pool, reservation, 0)
            .expect("first admits cold");
        let mut session = FocusedSession::hollow_for_coordinator_tests(
            4242,
            1,
            crate::inventory::NamespaceIds {
                pid: None,
                mount: None,
            },
            &pool,
        );
        session.set_attached_for_test();
        run.active.push(Active {
            identity: Incarnation {
                pid: 4242,
                starttime: 1,
                namespaces: crate::inventory::NamespaceIds {
                    pid: None,
                    mount: None,
                },
            },
            segment: 1,
            image_epoch: 0,
            session,
            ledger: MemberLedger::empty(),
            admit_ns: 0,
            suspended: false,
            cgroup: None,
            grace_noted: None,
            loss_seen: [0; 8],
        });
        let second = run.reserve_session(&pool, reservation, 0);
        assert!(
            second.is_some(),
            "attached member warms admission to lease-only"
        );
        drop(first);
        drop(second);
    }
    #[test]
    fn reincarnation_and_visibility_are_not_inferred_exits() {
        let mut snapshot = inventory::snapshot(&inventory::SnapshotOptions {
            pids: vec![std::process::id()],
            resolve_paths: false,
            limits: inventory::Limits {
                max_objects_per_process: 0,
                ..Default::default()
            },
        });
        let identity = Incarnation::from(&snapshot.processes[0]);
        assert_eq!(departure(&identity, &snapshot), None);
        snapshot.processes[0].starttime += 1;
        assert_eq!(departure(&identity, &snapshot), Some("incarnation_changed"));
        snapshot.processes.clear();
        assert_eq!(departure(&identity, &snapshot), Some("visibility_lost"));
        snapshot.gaps.clear();
        assert_eq!(departure(&identity, &snapshot), Some("sampled_removal"));
        snapshot.gaps.push(inventory::Gap {
            pid: None,
            device: None,
            inode: None,
            reason: GapReason::Deadline,
            errno: None,
            actor_euid: None,
        });
        assert_eq!(departure(&identity, &snapshot), Some("visibility_lost"));
    }
    #[test]
    #[ignore = "requires explicit privileged observation/count companions"]
    fn focused_active_slot_limit_names_the_uncovered_member() {
        let mut children: Vec<_> = (0..2)
            .map(|_| {
                std::process::Command::new("openssl")
                    .args([
                        "speed", "-elapsed", "-seconds", "20", "-evp", "SHA512", "-bytes", "64",
                    ])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .unwrap()
            })
            .collect();
        std::thread::sleep(Duration::from_millis(100));
        let config = CryptoWatchConfig {
            selection: Selection {
                pids: children.iter().map(|p| p.id()).collect(),
                ..Default::default()
            },
            max_active: 1,
            duration: Duration::from_secs(4),
            ..Default::default()
        };
        let pool = MemoryPool::new(GLOBAL_BYTES);
        let _coordinator = pool.reserve(COORDINATOR_BYTES).unwrap();
        let mut output = Vec::new();
        use sha2::{Digest, Sha256};
        let observation = std::fs::read(
            std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").expect("observation companion"),
        )
        .unwrap();
        let count = std::fs::read(
            std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT").expect("count companion"),
        )
        .unwrap();
        let objects = FocusedObjects {
            observation: observation.into(),
            count_sha256: Sha256::digest(&count).into(),
            count: count.into(),
        };
        let result = observe(
            &config,
            objects,
            &pool,
            &mut output,
            true,
            &AtomicBool::new(false),
            // In-process unit test: no producer installation (the
            // bootstrap history is process-global); polling applies.
            None,
        );
        for child in &mut children {
            child.kill().unwrap();
            child.wait().unwrap();
        }
        result.unwrap();
        let rows: Vec<serde_json::Value> = output
            .split(|b| *b == b'\n')
            .filter(|s| !s.is_empty())
            .map(|s| serde_json::from_slice(s).unwrap())
            .collect();
        assert!(rows.iter().any(|r| {
            r["kind"] == "limit"
                && r["reason"] == "active_limit"
                && config
                    .selection
                    .pids
                    .contains(&(r["incarnation"]["pid"].as_u64().unwrap() as u32))
        }));
    }

    #[test]
    fn human_discovery_prints_identity_totals() {
        let process: inventory::ProcessRecord = serde_json::from_value(serde_json::json!({
            "interval": {"started_unix_ms": null, "finished_unix_ms": null, "elapsed_ns": 0},
            "namespaces": {"pid": null, "mount": null},
            "pid": 42, "starttime": 123,
            "modules": [
                {"info": {"sha256": "aa", "device": 1, "inode": 2, "size_bytes": 3, "architecture": "x86_64", "kind": "other", "exports": [], "depends_on_libcrypto": false, "depends_on_libssl": false}, "identity_status": "verified"},
                {"info": {"sha256": "bb", "device": 1, "inode": 3, "size_bytes": 3, "architecture": "x86_64", "kind": "other", "exports": [], "depends_on_libcrypto": false, "depends_on_libssl": false}, "identity_status": "locator_candidate"}
            ],
            "provider_activation": "unknown", "provider_interfaces": "unknown", "execution": "not_observed"
        })).unwrap();
        let mut bytes = Vec::new();
        let mut out = Output {
            writer: &mut bytes,
            sequence: 0,
            json: false,
            pending_gaps: Vec::new(),
            resolve_paths: false,
            terminal: false,
        };
        out.emit(Record::Discovery {
            process: &process,
            sidecar: None,
        })
        .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            text.contains("identity: 1 verified, 1 locator-candidate of 2 modules (50% verified)"),
            "got: {text}"
        );
    }

    #[test]
    fn human_discovery_renders_path_fragments_by_flag_and_terminal() {
        // External F4: crypto Object rows carry `path=` fragments
        // under the same gates as discovery/watch (flag + terminal
        // + human); the empty sidecar joins nothing, so the
        // verified row reports `(unavailable)` without I/O.
        let process: inventory::ProcessRecord = serde_json::from_value(serde_json::json!({
            "interval": {"started_unix_ms": null, "finished_unix_ms": null, "elapsed_ns": 0},
            "namespaces": {"pid": null, "mount": null},
            "pid": 42, "starttime": 123,
            "modules": [
                {"info": {"sha256": "aa", "device": 1, "inode": 2, "size_bytes": 3, "architecture": "x86_64", "kind": "other", "exports": [], "depends_on_libcrypto": false, "depends_on_libssl": false}, "identity_status": "verified"},
                {"info": {"sha256": "bb", "device": 1, "inode": 3, "size_bytes": 3, "architecture": "x86_64", "kind": "other", "exports": [], "depends_on_libcrypto": false, "depends_on_libssl": false}, "identity_status": "locator_candidate"}
            ],
            "provider_activation": "unknown", "provider_interfaces": "unknown", "execution": "not_observed"
        })).unwrap();
        let sidecar = crate::inventory::resolve::ResolveSidecar::default();
        let render = |resolve_paths: bool, terminal: bool, json: bool| {
            let mut bytes = Vec::new();
            let mut out = Output {
                writer: &mut bytes,
                sequence: 0,
                json,
                pending_gaps: Vec::new(),
                resolve_paths,
                terminal,
            };
            out.emit(Record::Discovery {
                process: &process,
                sidecar: Some(&sidecar),
            })
            .unwrap();
            String::from_utf8(bytes).unwrap()
        };
        // Flag off: byte-identical rows, no fragments.
        assert!(!render(false, true, false).contains("path="));
        // Flag on, terminal: verified joins nothing (unavailable),
        // candidate never resolves (unverified).
        let text = render(true, true, false);
        assert!(text.contains("path=(unavailable)"), "got: {text}");
        assert!(text.contains("path=(unverified)"), "got: {text}");
        // Flag on, redirected: not-a-terminal on both rows.
        let text = render(true, false, false);
        assert_eq!(
            text.matches("path=(not-a-terminal)").count(),
            2,
            "got: {text}"
        );
        // JSON: machine envelope, no fragments.
        assert!(!render(true, true, true).contains("path="));
    }

    #[test]
    fn human_observation_names_top_ops_and_apis() {
        // Op ids resolve via op_display, api ids via ApiId export names;
        // rows without ids are omitted, never invented.
        let identity = Incarnation {
            pid: 42,
            starttime: 123,
            namespaces: inventory::NamespaceIds {
                pid: None,
                mount: None,
            },
        };
        let document = serde_json::json!({
            "sites": [{"calls": 2, "candidates": [{"op": 1}]}],
            "fenced": [],
            "api_activity": [{"api": 20, "entries": 5}, {"entries": 3}],
            "objects": [{}],
            "completeness": {"counters": []}
        });
        let mut bytes = Vec::new();
        let mut out = Output {
            writer: &mut bytes,
            sequence: 0,
            json: false,
            pending_gaps: Vec::new(),
            resolve_paths: false,
            terminal: false,
        };
        out.emit(Record::ProcessObservation {
            incarnation: &identity,
            segment: 4,
            retirement: "duration",
            document: &document,
            image_epoch: 0,
            loss: LossSummary::empty(),
        })
        .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("op=DIGEST"), "op name rendered, got: {text}");
        assert!(
            text.contains("api=EVP_DigestInit_ex entries=5"),
            "api name with exact entries, got: {text}"
        );
        assert_eq!(
            text.matches("api=").count(),
            1,
            "id-less api row omitted, not guessed, got: {text}"
        );
        assert_eq!(
            text.matches("op=").count(),
            1,
            "one op row for one id-bearing candidate, got: {text}"
        );
    }

    #[test]
    fn membership_blindness_follows_caller_decision_not_reason() {
        // The blindness line follows the caller's stricter `blind`
        // decision — never the record reason alone: the same
        // no-candidates reason prints the boundary when blind and
        // stays silent when not, while the record line is identical.
        let identity = Incarnation {
            pid: 42,
            starttime: 123,
            namespaces: inventory::NamespaceIds {
                pid: None,
                mount: None,
            },
        };
        for (blind, expect) in [(true, true), (false, false)] {
            let mut bytes = Vec::new();
            let mut out = Output {
                writer: &mut bytes,
                sequence: 0,
                json: false,
                pending_gaps: Vec::new(),
                resolve_paths: false,
                terminal: false,
            };
            out.emit_membership(
                &identity,
                0,
                "sampled",
                "no_candidate_interfaces_in_sample",
                0,
                None,
                LossSummary::empty(),
                blind,
            )
            .unwrap();
            drop(out);
            let text = String::from_utf8(bytes).unwrap();
            assert!(
                text.contains("reason=no_candidate_interfaces_in_sample"),
                "record line identical, got: {text}"
            );
            assert_eq!(
                text.contains("blindness: no-mapped-openssl"),
                expect,
                "blind={blind} decides, got: {text}"
            );
        }
    }

    #[test]
    fn human_gaps_coalesce_until_next_record() {
        // Three identical + one different gap buffer in human mode and
        // flush as one grouped block when the next record arrives.
        let gap = |reason| inventory::Gap {
            pid: Some(11),
            device: Some(7),
            inode: None,
            reason,
            errno: None,
            actor_euid: None,
        };
        let gaps = [
            gap(inventory::GapReason::BackingUnavailable),
            gap(inventory::GapReason::BackingUnavailable),
            gap(inventory::GapReason::BackingUnavailable),
            gap(inventory::GapReason::Deadline),
        ];
        let mut bytes = Vec::new();
        let mut out = Output {
            writer: &mut bytes,
            sequence: 0,
            json: false,
            pending_gaps: Vec::new(),
            resolve_paths: false,
            terminal: false,
        };
        for g in &gaps {
            out.emit(Record::Gap { gap: g }).unwrap();
        }
        assert_eq!(out.pending_gaps.len(), 4, "gaps buffer instead of printing");
        out.emit(Record::TracingGap {
            reason: "companions_unavailable",
        })
        .unwrap();
        assert!(out.pending_gaps.is_empty(), "flush drains the buffer");
        drop(out);
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            text.contains("gaps (4 total in 2 groups):"),
            "coalesced header, got: {text}"
        );
        assert!(
            text.contains("backing_unavailable device=7 pid=11: 3"),
            "group of three, got: {text}"
        );
        assert!(
            text.find("gaps (").unwrap() < text.find("Tracing unavailable:").unwrap(),
            "block flushes before the next record, got: {text}"
        );
    }

    #[test]
    fn human_gap_batches_flush_per_sample() {
        // Consecutive gap-only samples: each batch flushes its own
        // block (no cross-sample accumulation).
        let gap = inventory::Gap {
            pid: Some(11),
            device: Some(7),
            inode: None,
            reason: inventory::GapReason::Deadline,
            errno: None,
            actor_euid: None,
        };
        let mut bytes = Vec::new();
        let mut out = Output {
            writer: &mut bytes,
            sequence: 0,
            json: false,
            pending_gaps: Vec::new(),
            resolve_paths: false,
            terminal: false,
        };
        for _ in 0..2 {
            out.emit(Record::Gap { gap: &gap }).unwrap();
            out.emit(Record::Gap { gap: &gap }).unwrap();
            out.flush_gaps().unwrap();
        }
        drop(out);
        let text = String::from_utf8(bytes).unwrap();
        assert_eq!(
            text.matches("gaps (2 total in 1 group):").count(),
            2,
            "one block per sample batch, got: {text}"
        );
    }

    #[test]
    fn json_gaps_stay_per_record_ndjson() {
        // The JSON twin of the same stream: one envelope per gap, exact
        // bytes (buffering is human-only).
        let gap = |reason| inventory::Gap {
            pid: Some(11),
            device: Some(7),
            inode: None,
            reason,
            errno: None,
            actor_euid: None,
        };
        let mut bytes = Vec::new();
        let mut out = Output {
            writer: &mut bytes,
            sequence: 0,
            json: true,
            pending_gaps: Vec::new(),
            resolve_paths: false,
            terminal: false,
        };
        out.emit(Record::Gap {
            gap: &gap(inventory::GapReason::Deadline),
        })
        .unwrap();
        out.emit(Record::TracingGap {
            reason: "companions_unavailable",
        })
        .unwrap();
        drop(out);
        let text = String::from_utf8(bytes).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "one envelope per record, got: {text}");
        assert!(
            lines[0].contains("\"sequence\":0") && lines[0].contains("\"reason\":\"deadline\""),
            "gap envelope exact, got: {}",
            lines[0]
        );
        assert!(
            lines[1].contains("\"sequence\":1") && lines[1].contains("companions_unavailable"),
            "second envelope exact, got: {}",
            lines[1]
        );
    }

    #[test]
    fn compact_window_layout_is_24_bytes() {
        // Frozen §3.1/§4.1 layout: 8 + 8 + 1 + 7 pad = 24 B at align
        // 8 — the LEDGER_BYTES/DEFERRED_BYTES/SESSION_LOSS_BYTES
        // charges are computed from it.
        assert_eq!(std::mem::size_of::<CompactWindow>(), 24);
        assert_eq!(std::mem::align_of::<CompactWindow>(), 8);
        assert_eq!(std::mem::size_of::<LossCause>(), 1);
    }
    #[test]
    fn signal_dropped_delta_gets_covering_window() {
        // §4.1: sequence-hole-only loss moves the authoritative
        // signal_dropped total without moving any diagnostic lane —
        // the total's own baseline still produces a covering window.
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        run.current_tick = 3;
        run.prev_tick = Some(2);
        run.signal_dropped = 5;
        run.update_lane_baselines();
        let wire = run.carrier.wire();
        assert_eq!(wire.len(), 1, "one covering window, got {wire:?}");
        assert_eq!(wire[0].start_tick, 3);
        assert_eq!(wire[0].end_tick, 4);
        assert_eq!(wire[0].cause, "connector_drops");
        // Idempotent: no new window without a new delta.
        run.update_lane_baselines();
        assert_eq!(run.carrier.wire().len(), 1);
        // A later delta widens baseline-to-detection from the last
        // evaluation tick.
        run.current_tick = 6;
        run.signal_dropped = 9;
        run.update_lane_baselines();
        let wire = run.carrier.wire();
        assert_eq!(wire.len(), 1, "same-cause merge, got {wire:?}");
        assert_eq!((wire[0].start_tick, wire[0].end_tick), (3, 7));
    }
    #[test]
    fn ring_baselines_advance_past_quiet_ticks() {
        // §4.1 `[S,T+1)`: with no live members (vacuous freshness)
        // quiet ticks advance the baseline; a later seal-folded
        // delta propagates from the last advanced tick.
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        run.current_tick = 2;
        run.prev_tick = Some(1);
        run.update_loss_baselines(0);
        assert_eq!(run.consumed_tick, [2; 8]);
        assert!(run.carrier.wire().is_empty());
        run.current_tick = 5;
        run.seal_fold([0, 0, 0, 1, 0, 0, 0, 0]);
        run.update_loss_baselines(0);
        let wire = run.carrier.wire();
        assert_eq!(wire.len(), 1, "got {wire:?}");
        assert_eq!((wire[0].start_tick, wire[0].end_tick), (2, 6));
        assert_eq!(wire[0].cause, "ring_loss");
    }
    #[test]
    fn receipt_advance_uses_read_tick_not_eval_tick() {
        // N4: a read in tick 0 evaluated in tick 1 advances the
        // baseline to 0 (the read's containing tick), never to 1 —
        // loss after the read but still in tick 0 stays covered
        // ([0,4), not [1,4)).
        let seen = [[0u64; 8]];
        let receipts = [Some([(1u64, 0u64); 8])];
        assert_eq!(super::lane_advance(1, 3, &seen, &receipts), Some(0));
    }
    #[test]
    fn receipt_advance_vacuous_min_and_stall() {
        // N4: no sessions advances to the evaluation tick
        // (quiet-tick progress, as before); several sessions take
        // the OLDEST read tick; a stalled session blocks.
        let empty: [[u64; 8]; 0] = [];
        let no_receipts: [Option<[(u64, u64); 8]>; 0] = [];
        assert_eq!(super::lane_advance(5, 0, &empty, &no_receipts), Some(5));
        let none = [None, None];
        assert_eq!(super::lane_advance(5, 0, &empty[..0], &none), Some(5));
        let seen = [[0u64; 8], [0u64; 8]];
        let receipts = [Some([(1u64, 4u64); 8]), Some([(1u64, 2u64); 8])];
        assert_eq!(super::lane_advance(5, 0, &seen, &receipts), Some(2));
        let stalled = [Some([(1u64, 4u64); 8]), Some([(0u64, 2u64); 8])];
        assert_eq!(super::lane_advance(5, 0, &seen, &stalled), None);
    }
    #[test]
    #[ignore = "fix6 R6-2 schedule: requires BPF map privileges (sudo M4 run)"]
    fn peek_receipts_must_not_certify_unaccounted_coverage() {
        // fix6 (R6-2) coordinator-schedule test — nothing mocked
        // about the property: a REAL session (real peek/drain,
        // real receipts, real totals over real maps) inside a REAL
        // coordinator (real `lane_advance`, real baselines, real
        // propagation). The R6-2 schedule: loss late tick 2 →
        // reconcile peeks tick 3 → drain skipped through next eval
        // → eval tick 4 → drain accounts → eval tick 5. The
        // propagated window must COVER tick 2, and `lane_advance`
        // must not stall for the peek-only phase.
        let Some(session) =
            crate::provider_observation::session::ProviderSession::minimal_for_coordinator_tests()
        else {
            eprintln!("SKIP R6-2 schedule: BPF map creation failed (no caps)");
            return;
        };
        const TICK_NS: u64 = 1_000_000_000;
        let pool = MemoryPool::new(GLOBAL_BYTES);
        let namespaces = crate::inventory::NamespaceIds {
            pid: None,
            mount: None,
        };
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        run.prev_tick = Some(1);
        run.active.push(Active {
            identity: Incarnation {
                pid: 4242,
                starttime: 1,
                namespaces: namespaces.clone(),
            },
            segment: 1,
            image_epoch: 0,
            session: FocusedSession::with_session_for_coordinator_tests(
                4242, 1, namespaces, &pool, session,
            ),
            ledger: MemberLedger::empty(),
            admit_ns: 0,
            suspended: false,
            cgroup: None,
            grace_noted: None,
            loss_seen: [0; 8],
        });
        // Phase 1: clean drain in tick 2 (sees zero, accounts
        // nothing) + eval tick 2 (baseline advances to 2).
        run.active[0].session.set_loss_tick_for_test(2, TICK_NS);
        run.active[0].session.drain_for_test();
        run.current_tick = 2;
        run.update_loss_baselines(0);
        assert_eq!(
            run.consumed_tick, [2; 8],
            "premise: tick-2 baseline, got {:?}",
            run.consumed_tick
        );
        // Loss LATE tick 2 (after the drain's read) + reconcile
        // peeks tick 3 (receipt moves, totals stay 0) + drain
        // skipped through the next eval (the `pending.is_some()`
        // early return — modeled by simply not draining).
        run.active[0].session.set_loss_lane_for_test(0, 5);
        run.active[0].session.set_loss_tick_for_test(3, TICK_NS);
        let peeked = run.active[0].session.peek_for_test();
        assert!(
            peeked.gaps.is_empty(),
            "premise: empty peek emits no signal: {:?}",
            peeked.gaps
        );
        run.current_tick = 4;
        run.update_loss_baselines(0);
        // No-stall: the peek-only receipts moved the lane (seq 2
        // observed — `lane_advance` returned `Some`).
        assert_eq!(
            run.active[0].loss_seen[0], 2,
            "lane_advance must not stall on peek-only receipts"
        );
        // ... but the peek must NOT certify its own tick ahead of
        // the accounted totals: the baseline stays at the last
        // ACCOUNTED tick (2), never the peek tick (3).
        assert_eq!(
            run.consumed_tick[0], 2,
            "peek must not advance past accounted coverage, got {:?}",
            run.consumed_tick
        );
        // Drain accounts the delta (read tick 3) + eval tick 5:
        // the propagated window must COVER the tick-2 loss.
        run.active[0].session.set_loss_tick_for_test(3, TICK_NS);
        run.active[0].session.drain_for_test();
        run.current_tick = 5;
        run.update_loss_baselines(0);
        let wire = run.carrier.wire();
        assert!(
            wire.iter()
                .any(|w| w.cause == "ring_loss" && w.start_tick <= 2 && w.end_tick > 2),
            "propagated window must cover tick 2, got {wire:?}"
        );
    }
    #[test]
    fn deferred_exec_checks_entry_lifetime_lower_bound() {
        // N6: a delayed exec for a previous occupant (trusted
        // timestamp before the deferred entry's lifetime) must
        // quarantine — never advance the replacement's epoch. A
        // timestamp inside the lifetime still advances.
        let pid = std::process::id();
        let identity = super::verify_triple(pid).expect("own triple");
        let key = DeferredKey::from(&identity);
        let entry = || DeferredEntry {
            identity: identity.clone(),
            image_epoch: 0,
            first_tick: 0,
            last_tick: 0,
            ticks: 1,
            reason: "active_limit",
            marks: WindowStore::new(DEFERRED_MARKS),
            exe: None,
            readmit: None,
            carried_loss: 0,
            carried_deferred: DeferredSpan::default(),
            admit_ns: LiveClock.monotonic_ns(),
            tombstoned: false,
        };
        let exec = |ts: Option<u64>| crate::capture::LifecycleEvent {
            kind: LifecycleKind::Exec,
            pid,
            timestamp_ns: ts,
            tgid: pid,
            parent_tgid: 0,
            cpu: 0,
            seq: 0,
        };
        // Stale: timestamp predates the entry — quarantine, no advance.
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        run.deferred.insert(key.clone(), entry());
        let admit = run.deferred.get(&key).expect("entry").admit_ns;
        let mut bytes = Vec::new();
        let mut sink = Output {
            writer: &mut bytes,
            sequence: 0,
            json: true,
            pending_gaps: Vec::new(),
            resolve_paths: false,
            terminal: false,
        };
        super::bind_event(&mut run, &mut sink, &exec(Some(admit - 1)), true).unwrap();
        assert_eq!(
            run.deferred.get(&key).expect("entry").image_epoch,
            0,
            "stale exec advanced the replacement epoch"
        );
        assert_eq!(run.unattributed, 1, "stale exec not quarantined");
        // Inside the lifetime: advances exactly once.
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        run.deferred.insert(key.clone(), entry());
        let admit = run.deferred.get(&key).expect("entry").admit_ns;
        let mut bytes = Vec::new();
        let mut sink = Output {
            writer: &mut bytes,
            sequence: 0,
            json: true,
            pending_gaps: Vec::new(),
            resolve_paths: false,
            terminal: false,
        };
        super::bind_event(&mut run, &mut sink, &exec(Some(admit)), true).unwrap();
        assert_eq!(
            run.deferred.get(&key).expect("entry").image_epoch,
            1,
            "in-lifetime exec did not advance"
        );
        assert_eq!(run.unattributed, 0);
    }
    #[test]
    fn closing_loss_uses_close_tick_not_last_sample_tick() {
        // N5: closing loss detected after the last sample opened
        // anchors to the elapsed-derived close tick, not the stale
        // sample tick — the affected tail stays covered.
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        run.current_tick = 7;
        run.prev_tick = Some(7);
        run.update_lane_baselines();
        assert!(run.carrier.wire().is_empty());
        run.signal_dropped = 3;
        run.refresh_close_tick(10);
        run.update_lane_baselines();
        let wire = run.carrier.wire();
        assert_eq!(wire.len(), 1, "one covering window, got {wire:?}");
        assert_eq!((wire[0].start_tick, wire[0].end_tick), (7, 11));
        assert_eq!(wire[0].cause, "connector_drops");
    }
    /// Hollow member for coordinator unit tests (N7/N8b/N13):
    /// fabricated identity + hollow session (no BPF, no custody).
    fn hollow_active(
        pool: &MemoryPool,
        pid: u32,
        starttime: u64,
        namespaces: inventory::NamespaceIds,
    ) -> Active {
        Active {
            identity: Incarnation {
                pid,
                starttime,
                namespaces: namespaces.clone(),
            },
            segment: 1,
            image_epoch: 0,
            session: FocusedSession::hollow_for_coordinator_tests(pid, starttime, namespaces, pool),
            ledger: MemberLedger::empty(),
            admit_ns: 0,
            suspended: false,
            cgroup: None,
            grace_noted: None,
            loss_seen: [0; 8],
        }
    }
    #[test]
    fn middle_image_seals_retired_only_without_admission() {
        // N7 (§1.4 amendment): with two execs before any readmission,
        // the middle image (never observed — no session, no
        // eligibility proof) emits ONLY `Membership{retired,
        // unobserved_transition}` — no `observing` admission claim,
        // no `ProcessObservation`, no `SessionGap`.
        let pool = MemoryPool::new(GLOBAL_BYTES);
        let pid = std::process::id();
        let snapshot = inventory::snapshot(&inventory::SnapshotOptions {
            pids: vec![pid],
            resolve_paths: false,
            limits: inventory::Limits::default(),
        });
        let record = snapshot
            .processes
            .iter()
            .find(|p| p.pid == pid)
            .expect("own record")
            .clone();
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        run.current_tick = 5;
        run.prev_tick = Some(4);
        run.active.push(hollow_active(
            &pool,
            pid,
            record.starttime,
            record.namespaces.clone(),
        ));
        run.exec_flags.insert(pid, (5, None, 2));
        let objects = FocusedObjects {
            observation: Arc::from([]),
            count: Arc::from([]),
            count_sha256: [0; 32],
        };
        let selection = Selection::default();
        let cancel = AtomicBool::new(false);
        let ctx = AdmitCtx {
            pool: &pool,
            objects: &objects,
            reservation: 0,
            deadline: Instant::now() + Duration::from_secs(60),
            cancel: &cancel,
            tracing: false,
            trust_reviewed: false,
            selection: &selection,
            max_active: 4,
        };
        let mut bytes = Vec::new();
        let mut sink = Output {
            writer: &mut bytes,
            sequence: 0,
            json: true,
            pending_gaps: Vec::new(),
            resolve_paths: false,
            terminal: false,
        };
        let mut admitted = Vec::new();
        run.sample_members(&mut sink, &snapshot, &ctx, &mut admitted)
            .unwrap();
        drop(sink);
        let rows: Vec<serde_json::Value> = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let middle: Vec<&serde_json::Value> = rows
            .iter()
            .filter(|r| r["incarnation"]["pid"] == pid as u64 && r["image_epoch"] == 1)
            .collect();
        assert_eq!(
            middle.len(),
            1,
            "middle image emits exactly one record: {middle:?}"
        );
        assert_eq!(middle[0]["kind"], "membership");
        assert_eq!(middle[0]["state"], "retired");
        assert_eq!(middle[0]["reason"], "unobserved_transition");
        assert_eq!(middle[0]["segment"], 0);
        assert!(middle[0]["detail"].is_null());
        assert!(middle[0]["loss"].is_object(), "carried ledger present");
    }
    #[test]
    fn pending_epoch_overflow_eviction_is_visible() {
        // N8a: the pending-epoch stash never silently evicts — the
        // dropped oldest context emits a `MembershipUnknown` gap
        // naming its pid (its incarnation re-enters as a fresh
        // candidate; the epoch discontinuity is explicit).
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        let namespaces = inventory::NamespaceIds {
            pid: None,
            mount: None,
        };
        for i in 0..PENDING_EPOCH_CAP {
            let identity = Incarnation {
                pid: 1000 + i as u32,
                starttime: 1,
                namespaces: namespaces.clone(),
            };
            run.pending_epoch.insert(
                DeferredKey::from(&identity),
                (
                    1,
                    MemberLedger::empty(),
                    ReadmitCtx {
                        retire_ns: 0,
                        seal_tick: 0,
                        witness_ts: None,
                    },
                ),
            );
        }
        assert_eq!(run.pending_epoch.len(), PENDING_EPOCH_CAP);
        let mut bytes = Vec::new();
        let mut sink = Output {
            writer: &mut bytes,
            sequence: 0,
            json: true,
            pending_gaps: Vec::new(),
            resolve_paths: false,
            terminal: false,
        };
        let fresh = Incarnation {
            pid: 999_999,
            starttime: 1,
            namespaces: namespaces.clone(),
        };
        run.stash_pending_epoch(
            &mut sink,
            DeferredKey::from(&fresh),
            (
                2,
                MemberLedger::empty(),
                ReadmitCtx {
                    retire_ns: 0,
                    seal_tick: 0,
                    witness_ts: None,
                },
            ),
        )
        .unwrap();
        drop(sink);
        assert_eq!(run.pending_epoch.len(), PENDING_EPOCH_CAP);
        assert!(run.pending_epoch.contains_key(&DeferredKey::from(&fresh)));
        let rows: Vec<serde_json::Value> = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows.len(), 1, "one visible eviction, got {rows:?}");
        assert_eq!(rows[0]["kind"], "gap");
        assert_eq!(rows[0]["gap"]["reason"], "membership_unknown");
        assert_eq!(rows[0]["gap"]["pid"], 1000, "oldest evicted");
    }
    #[test]
    fn stranger_exec_advances_pending_stash_with_middle_seal() {
        // R3-4a: epoch 0 execs into an ineligible image (stash 1);
        // a second exec into an eligible image arrives before
        // readmission. The stranger path must advance the stash to
        // 2 AND seal image 1 as an unobserved middle — readmission
        // reporting 1 with no middle seal invents continuity.
        let pid = std::process::id();
        let identity = super::verify_triple(pid).expect("own triple");
        let key = DeferredKey::from(&identity);
        let mut ledger = MemberLedger::empty();
        ledger.loss = 7;
        let retire = LiveClock.monotonic_ns();
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        run.pending_epoch.insert(
            key.clone(),
            (
                1,
                ledger,
                ReadmitCtx {
                    retire_ns: retire,
                    seal_tick: 3,
                    witness_ts: Some(retire),
                },
            ),
        );
        let mut bytes = Vec::new();
        let mut sink = Output {
            writer: &mut bytes,
            sequence: 0,
            json: true,
            pending_gaps: Vec::new(),
            resolve_paths: false,
            terminal: false,
        };
        let event = crate::capture::LifecycleEvent {
            kind: LifecycleKind::Exec,
            pid,
            timestamp_ns: Some(LiveClock.monotonic_ns()),
            tgid: pid,
            parent_tgid: 0,
            cpu: 0,
            seq: 0,
        };
        super::bind_event(&mut run, &mut sink, &event, true).unwrap();
        drop(sink);
        assert_eq!(
            run.pending_epoch.get(&key).map(|c| c.0),
            Some(2),
            "second exec must advance the stash"
        );
        let rows: Vec<serde_json::Value> = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let middle: Vec<&serde_json::Value> = rows
            .iter()
            .filter(|r| r["kind"] == "membership" && r["image_epoch"] == 1)
            .collect();
        assert_eq!(middle.len(), 1, "one middle seal, got {rows:?}");
        assert_eq!(middle[0]["state"], "retired");
        assert_eq!(middle[0]["reason"], "unobserved_transition");
        assert_eq!(
            middle[0]["loss"]["loss"], 7,
            "middle seal carries the stash ledger"
        );
    }
    #[test]
    fn stranger_exec_with_stale_trusted_ts_quarantines() {
        // R3-4a/N6: a stranger exec with a trusted timestamp
        // predating the stashed seal (delayed previous-occupant
        // event) quarantines — it must not advance the stash or
        // seal a middle image.
        let pid = std::process::id();
        let identity = super::verify_triple(pid).expect("own triple");
        let key = DeferredKey::from(&identity);
        let retire = LiveClock.monotonic_ns();
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        run.pending_epoch.insert(
            key.clone(),
            (
                1,
                MemberLedger::empty(),
                ReadmitCtx {
                    retire_ns: retire,
                    seal_tick: 3,
                    witness_ts: Some(retire),
                },
            ),
        );
        let mut bytes = Vec::new();
        let mut sink = Output {
            writer: &mut bytes,
            sequence: 0,
            json: true,
            pending_gaps: Vec::new(),
            resolve_paths: false,
            terminal: false,
        };
        let event = crate::capture::LifecycleEvent {
            kind: LifecycleKind::Exec,
            pid,
            timestamp_ns: Some(retire - 1),
            tgid: pid,
            parent_tgid: 0,
            cpu: 0,
            seq: 0,
        };
        super::bind_event(&mut run, &mut sink, &event, true).unwrap();
        drop(sink);
        assert_eq!(run.unattributed, 1, "stale exec not quarantined");
        assert_eq!(
            run.pending_epoch.get(&key).map(|c| c.0),
            Some(1),
            "stale exec advanced the stash"
        );
        assert!(bytes.is_empty(), "stale exec emitted records");
    }
    #[test]
    fn r32_reserve_session_charges_backlog_first() {
        // R3-2: the admission reserve tops up the backlog guard
        // BEFORE the session lease — a backlog that crowds the
        // pool refuses the admission (honest backpressure); a
        // fitting backlog coexists with the lease; a drained
        // backlog shrinks the guard on the next admission.
        // T7.4-fix4 contract change (the ordering above is
        // preserved): admission now also proves one stock parse
        // transient per session, so the pool carries the working
        // set past guard + lease instead of exhausting at the
        // lease.
        let working = crate::provider_observation::objects::session_working_bytes();
        let pool = MemoryPool::new(100 + working);
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        // Backlog alone exceeds the pool: refused (the guard
        // top-up fails first).
        assert!(run.reserve_session(&pool, 60, 101 + working).is_none());
        // 60 + 40 + working == pool: admitted; guard + lease +
        // proven working exhaust it.
        let lease = run.reserve_session(&pool, 60, 40).expect("fits");
        assert!(
            pool.reserve(working + 1).is_none(),
            "only the proven working set remains"
        );
        assert!(
            pool.reserve(working).is_some(),
            "proven working set fits beside guard + lease"
        );
        drop(lease);
        // Backlog drained: the guard shrinks (60 + 0) and room
        // returns.
        let lease = run.reserve_session(&pool, 60, 0).expect("fits after drain");
        assert!(pool.reserve(40).is_some(), "drained guard frees room");
        drop(lease);
    }

    #[test]
    fn f8a_service_deadline_admits_with_capped_session() {
        // F8a REGRESSION (R1 finding 8 — the vacuous 24h): the
        // service engine lives a decade (ENGINE_DURATION) and
        // try_admit fed the FULL remaining engine life as the
        // session duration — but FocusedConfig::validate caps
        // duration at 3600 s, so EVERY admission failed
        // (acquisition_unavailable × 85k; zero members/sites/calls
        // in all 2880 windows). The session duration must be
        // capped at the validation bound. Self-targeted, no BPF
        // (empty companions degrade — the failure under test is
        // the pre-BPF validation, which is what rejected every
        // qual admission before any BPF syscall ran).
        use sha2::{Digest, Sha256};
        let pool = MemoryPool::new(GLOBAL_BYTES);
        let pid = std::process::id();
        let snapshot = inventory::snapshot(&inventory::SnapshotOptions {
            pids: vec![pid],
            resolve_paths: false,
            limits: inventory::Limits::default(),
        });
        let record = snapshot
            .processes
            .iter()
            .find(|p| p.pid == pid)
            .expect("own record")
            .clone();
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        let objects = FocusedObjects {
            observation: Arc::from([]),
            count: Arc::from([]),
            count_sha256: Sha256::digest([]).into(),
        };
        let selection = Selection::default();
        let cancel = AtomicBool::new(false);
        let ctx = AdmitCtx {
            pool: &pool,
            objects: &objects,
            reservation: 0,
            // The service engine deadline (a decade out).
            deadline: Instant::now() + Duration::from_secs(10 * 365 * 24 * 3600),
            cancel: &cancel,
            tracing: true,
            trust_reviewed: false,
            selection: &selection,
            max_active: 4,
        };
        let need = FocusedSession::reservation_bytes(&objects).expect("session cost");
        let lease = pool.reserve(need).expect("session lease");
        let mut bytes = Vec::new();
        let mut sink = Output {
            writer: &mut bytes,
            sequence: 0,
            json: true,
            pending_gaps: Vec::new(),
            resolve_paths: false,
            terminal: false,
        };
        let mut admitted = Vec::new();
        let admitted_now = run
            .try_admit(
                &mut sink,
                AdmitSpec {
                    identity: Incarnation {
                        pid,
                        starttime: record.starttime,
                        namespaces: record.namespaces.clone(),
                    },
                    record: &record,
                    epoch: 0,
                    detail: None,
                    ledger: MemberLedger::empty(),
                    cgroup: None,
                    admit_floor_ns: 0,
                },
                lease,
                &ctx,
                &mut admitted,
            )
            .unwrap();
        assert!(
            admitted_now,
            "a decade-out engine deadline must still admit (capped session)"
        );
        assert_eq!(admitted, vec![pid]);
    }
    #[test]
    fn exit_against_live_admitted_member_counts_artifact() {
        // R3-9: an EXIT naming an ADMITTED member whose triple
        // matches the fresh probe (the control-5 held-leg binding:
        // EXIT delivered after the replacement admitted)
        // quarantines as a live-member artifact — counted
        // separately from unmatched quarantines so the binding
        // scenario is PROVEN, not assumed from queue depth.
        let pool = MemoryPool::new(GLOBAL_BYTES);
        let pid = std::process::id();
        let identity = super::verify_triple(pid).expect("own triple");
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        run.active.push(hollow_active(
            &pool,
            identity.pid,
            identity.starttime,
            identity.namespaces.clone(),
        ));
        let mut bytes = Vec::new();
        let mut sink = Output {
            writer: &mut bytes,
            sequence: 0,
            json: true,
            pending_gaps: Vec::new(),
            resolve_paths: false,
            terminal: false,
        };
        let event = crate::capture::LifecycleEvent {
            kind: LifecycleKind::Exit,
            pid,
            timestamp_ns: None,
            tgid: pid,
            parent_tgid: 0,
            cpu: 0,
            seq: 0,
        };
        super::bind_event(&mut run, &mut sink, &event, true).unwrap();
        drop(sink);
        assert_eq!(run.unattributed, 1, "artifact not quarantined");
        assert_eq!(
            run.admitted_exit_artifacts, 1,
            "EXIT-against-admitted-member not proven"
        );
        assert!(
            !run.exit_flags.contains_key(&pid),
            "artifact must not flag the live member"
        );
        // The unmatched twin: no admitted member — quarantines
        // WITHOUT the artifact proof.
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        let mut bytes = Vec::new();
        let mut sink = Output {
            writer: &mut bytes,
            sequence: 0,
            json: true,
            pending_gaps: Vec::new(),
            resolve_paths: false,
            terminal: false,
        };
        super::bind_event(&mut run, &mut sink, &event, true).unwrap();
        drop(sink);
        assert_eq!(run.unattributed, 1);
        assert_eq!(
            run.admitted_exit_artifacts, 0,
            "pre-admission quarantine must not prove binding"
        );
    }
    #[test]
    fn pending_epoch_eviction_preserves_history_for_readmit() {
        // R3-4b: stash overflow demotes (not deletes) the oldest
        // context — readmission still finds its epoch + ledger, so
        // no silent epoch-0 rebirth. The N8a eviction gap stays.
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        let namespaces = inventory::NamespaceIds {
            pid: None,
            mount: None,
        };
        for i in 0..PENDING_EPOCH_CAP {
            let identity = Incarnation {
                pid: 1000 + i as u32,
                starttime: 1,
                namespaces: namespaces.clone(),
            };
            let mut ledger = MemberLedger::empty();
            ledger.loss = 40 + i as u64;
            run.pending_epoch.insert(
                DeferredKey::from(&identity),
                (
                    41,
                    ledger,
                    ReadmitCtx {
                        retire_ns: 5,
                        seal_tick: 2,
                        witness_ts: Some(6),
                    },
                ),
            );
        }
        let mut bytes = Vec::new();
        let mut sink = Output {
            writer: &mut bytes,
            sequence: 0,
            json: true,
            pending_gaps: Vec::new(),
            resolve_paths: false,
            terminal: false,
        };
        let fresh = Incarnation {
            pid: 999_999,
            starttime: 1,
            namespaces: namespaces.clone(),
        };
        run.stash_pending_epoch(
            &mut sink,
            DeferredKey::from(&fresh),
            (
                2,
                MemberLedger::empty(),
                ReadmitCtx {
                    retire_ns: 0,
                    seal_tick: 0,
                    witness_ts: None,
                },
            ),
        )
        .unwrap();
        drop(sink);
        let oldest = Incarnation {
            pid: 1000,
            starttime: 1,
            namespaces: namespaces.clone(),
        };
        let stashed = run
            .peek_exec_ctx(&DeferredKey::from(&oldest))
            .expect("evicted history preserved");
        assert!(!stashed.tombstoned, "demoted hit mislabeled tombstoned");
        let (epoch, ledger, ctx) = stashed.ctx;
        assert_eq!(epoch, 41, "epoch lost across eviction");
        assert_eq!(ledger.loss, 40, "ledger lost across eviction");
        assert_eq!((ctx.seal_tick, ctx.witness_ts), (2, Some(6)));
        run.consume_exec_ctx(&DeferredKey::from(&oldest));
        assert!(
            run.peek_exec_ctx(&DeferredKey::from(&oldest)).is_none(),
            "consumed context lingers"
        );
        let rows: Vec<serde_json::Value> = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows.len(), 1, "N8a gap stays, got {rows:?}");
        assert_eq!(rows[0]["gap"]["reason"], "membership_unknown");
    }
    #[test]
    fn double_eviction_announces_epoch_restart() {
        // R4-3: when BOTH stash tables overflow, the victim's
        // known epoch + loss history survive in a bounded
        // tombstone summary (never reset to 0/0) — and its next
        // admission announces the compression with a visible gap
        // (once), riding the admission itself.
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        let namespaces = inventory::NamespaceIds {
            pid: None,
            mount: None,
        };
        for i in 0..PENDING_EPOCH_CAP {
            let identity = Incarnation {
                pid: 1000 + i as u32,
                starttime: 1,
                namespaces: namespaces.clone(),
            };
            // The demotion victim (pid 1000, key-smallest) carries
            // known epoch 41 / loss 40 — the history R4-3 must
            // preserve across the double eviction.
            let (epoch, mut ledger) = if i == 0 {
                let mut ledger = MemberLedger::empty();
                ledger.loss = 40;
                ledger.windows.append(3, 5, LossCause::RingLoss);
                ledger.windows.append(9, 12, LossCause::ScanLoss);
                (41, ledger)
            } else {
                (1, MemberLedger::empty())
            };
            run.pending_epoch.insert(
                DeferredKey::from(&identity),
                (
                    epoch,
                    ledger,
                    ReadmitCtx {
                        retire_ns: 5,
                        seal_tick: 2,
                        witness_ts: Some(6),
                    },
                ),
            );
        }
        for i in 0..EVICTED_EPOCH_CAP {
            let identity = Incarnation {
                pid: 5000 + i as u32,
                starttime: 1,
                namespaces: namespaces.clone(),
            };
            run.evicted_epoch.insert(
                DeferredKey::from(&identity),
                (
                    3,
                    MemberLedger::empty(),
                    ReadmitCtx {
                        retire_ns: 0,
                        seal_tick: 0,
                        witness_ts: None,
                    },
                ),
            );
        }
        let mut bytes = Vec::new();
        let mut sink = Output {
            writer: &mut bytes,
            sequence: 0,
            json: true,
            pending_gaps: Vec::new(),
            resolve_paths: false,
            terminal: false,
        };
        let fresh = Incarnation {
            pid: 999_999,
            starttime: 1,
            namespaces: namespaces.clone(),
        };
        run.stash_pending_epoch(
            &mut sink,
            DeferredKey::from(&fresh),
            (
                2,
                MemberLedger::empty(),
                ReadmitCtx {
                    retire_ns: 0,
                    seal_tick: 0,
                    witness_ts: None,
                },
            ),
        )
        .unwrap();
        // The demoted stash victim (pid 1000) cascades: the full
        // demoted table drops its key-smallest entry — the
        // just-demoted pid 1000 itself (key order, like N8a: all
        // share starttime 1, so the smallest pid drops) — into a
        // tombstone summary. Preserved, not reset.
        let dropped = Incarnation {
            pid: 1000,
            starttime: 1,
            namespaces: namespaces.clone(),
        };
        let stashed = run
            .peek_exec_ctx(&DeferredKey::from(&dropped))
            .expect("tombstoned history must survive (not epoch 0/loss 0)");
        assert!(stashed.tombstoned, "double-evicted hit must be tombstoned");
        let (epoch, ledger, ctx) = stashed.ctx;
        assert_eq!(epoch, 41, "epoch reset across double eviction");
        assert_eq!(ledger.loss, 40, "loss reset across double eviction");
        assert_eq!((ctx.seal_tick, ctx.witness_ts), (2, Some(6)));
        // The two windows folded into one coalesced cover span.
        assert_eq!(ledger.windows.windows.len(), 1);
        assert_eq!(
            ledger.windows.windows[0].cause,
            LossCause::CoalescedLoss,
            "folded span must speak the coalescing vocabulary"
        );
        assert_eq!(
            (
                ledger.windows.windows[0].start_tick,
                ledger.windows.windows[0].end_tick,
                ledger.windows.coalesced,
            ),
            (3, 12, 2),
            "cover span must span the folded windows"
        );
        let kept = Incarnation {
            pid: 5000,
            starttime: 1,
            namespaces: namespaces.clone(),
        };
        assert_eq!(
            run.peek_exec_ctx(&DeferredKey::from(&kept))
                .map(|s| s.ctx.0),
            Some(3),
            "demoted history must survive the cascade"
        );
        // The announcement rides the admission: consuming the
        // tombstone for pid 1000's admission emits the third
        // gap; a later fresh admission announces nothing more.
        run.note_admitted(&mut sink, &dropped, true, false).unwrap();
        assert!(
            run.peek_exec_ctx(&DeferredKey::from(&dropped)).is_none(),
            "consumed tombstone lingers"
        );
        run.note_admitted(&mut sink, &dropped, false, true).unwrap();
        drop(sink);
        let rows: Vec<serde_json::Value> = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        // Three visible gaps name pid 1000: the N8a stash
        // eviction, the demoted-table drop, and the restart
        // announcement — every history loss is on the record.
        let pid_gaps = rows
            .iter()
            .filter(|r| {
                r["kind"] == "gap"
                    && r["gap"]["reason"] == "membership_unknown"
                    && r["gap"]["pid"] == 1000
            })
            .count();
        assert_eq!(pid_gaps, 3, "restart gap missing, got {rows:?}");
    }
    #[test]
    fn tombstone_summary_roundtrip() {
        // R4-3: the bounded summary keeps the known epoch, the
        // exact loss/deferred totals and the readmit context,
        // and folds the windows into one coalesced cover span (+
        // the fold count) through the frozen vocabulary.
        let mut windows = WindowStore::new(WINDOW_CAP);
        windows.append(3, 5, LossCause::RingLoss);
        windows.append(9, 12, LossCause::ScanLoss);
        windows.coalesced = 4;
        let ledger = MemberLedger {
            loss: 40,
            deferred: DeferredSpan {
                ticks: 2,
                first_tick: 1,
                last_tick: 7,
            },
            windows,
        };
        let summary = TombstoneSummary::summarize(
            41,
            &ledger,
            ReadmitCtx {
                retire_ns: 5,
                seal_tick: 2,
                witness_ts: Some(6),
            },
        );
        assert_eq!((summary.epoch, summary.loss), (41, 40));
        assert_eq!(summary.deferred, ledger.deferred);
        assert_eq!(summary.span, Some((3, 12)));
        assert_eq!(summary.coalesced, 6);
        let (epoch, resumed, ctx) = summary.materialize();
        assert_eq!(epoch, 41);
        assert_eq!(resumed.loss, 40);
        assert_eq!(resumed.deferred, ledger.deferred);
        assert_eq!(
            (ctx.retire_ns, ctx.seal_tick, ctx.witness_ts),
            (5, 2, Some(6))
        );
        assert_eq!(resumed.windows.windows.len(), 1);
        assert_eq!(resumed.windows.windows[0].cause, LossCause::CoalescedLoss);
        assert_eq!(resumed.windows.coalesced, 6);
        // Empty ledger: no span, count preserved.
        let summary = TombstoneSummary::summarize(
            3,
            &MemberLedger::empty(),
            ReadmitCtx {
                retire_ns: 0,
                seal_tick: 0,
                witness_ts: None,
            },
        );
        assert_eq!(summary.span, None);
        let (_, resumed, _) = summary.materialize();
        assert!(resumed.windows.windows.is_empty());
        assert_eq!(resumed.windows.coalesced, 0);
    }
    #[test]
    fn tombstone_survives_ineligible_sample() {
        // R4-3: an ineligible sample for a tombstoned incarnation
        // displays the summary's epoch/loss (not 0/0) and
        // NEITHER announces NOR consumes the tombstone — the
        // announcement rides the admission, never a pre-admission
        // sample.
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        let snapshot = inventory::snapshot(&inventory::SnapshotOptions {
            pids: vec![pid],
            resolve_paths: false,
            limits: inventory::Limits::default(),
        });
        let record = snapshot
            .processes
            .iter()
            .find(|p| p.pid == pid)
            .expect("sleep record")
            .clone();
        assert!(!eligible(&record), "sleep must be ineligible (premise)");
        let identity = Incarnation::from(&record);
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        run.current_tick = 6;
        let mut ledger = MemberLedger::empty();
        ledger.loss = 40;
        run.epoch_tombstones.insert(
            DeferredKey::from(&identity),
            TombstoneSummary::summarize(
                41,
                &ledger,
                ReadmitCtx {
                    retire_ns: 5,
                    seal_tick: 2,
                    witness_ts: Some(6),
                },
            ),
        );
        let pool = MemoryPool::new(GLOBAL_BYTES);
        let objects = FocusedObjects {
            observation: Arc::from([0u8; 8]),
            count: Arc::from([0u8; 8]),
            count_sha256: [0; 32],
        };
        let selection = Selection::default();
        let cancel = AtomicBool::new(false);
        let ctx = AdmitCtx {
            pool: &pool,
            objects: &objects,
            reservation: 0,
            deadline: Instant::now() + Duration::from_secs(60),
            cancel: &cancel,
            tracing: true,
            trust_reviewed: false,
            selection: &selection,
            max_active: 4,
        };
        let mut bytes = Vec::new();
        let mut sink = Output {
            writer: &mut bytes,
            sequence: 0,
            json: true,
            pending_gaps: Vec::new(),
            resolve_paths: false,
            terminal: false,
        };
        let mut admitted = Vec::new();
        run.scan_admit(&mut sink, &snapshot, &ctx, &mut admitted)
            .unwrap();
        assert!(
            run.epoch_tombstones
                .contains_key(&DeferredKey::from(&identity)),
            "ineligible sample consumed the tombstone"
        );
        assert!(admitted.is_empty(), "ineligible sample admitted");
        drop(sink);
        let rows: Vec<serde_json::Value> = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let sampled: Vec<&serde_json::Value> = rows
            .iter()
            .filter(|r| r["kind"] == "membership" && r["state"] == "sampled")
            .collect();
        assert_eq!(sampled.len(), 1, "one sampled row, got {rows:?}");
        assert_eq!(sampled[0]["image_epoch"], 41, "epoch reset, got {rows:?}");
        assert_eq!(sampled[0]["loss"]["loss"], 40, "loss reset, got {rows:?}");
        assert!(
            rows.iter().all(|r| r["kind"] != "gap"),
            "pre-admission sample announced, got {rows:?}"
        );
        child.kill().ok();
        child.wait().ok();
    }
    #[test]
    fn amnesia_refuses_forgotten_ineligible_sample() {
        // R6-2b: ambiguity refusal precedes the sampled-membership
        // emission — a forgotten ineligible incarnation (amnesia,
        // no stash) is REFUSED with `history_ambiguous`, never a
        // fabricated 0/0 `sampled` row. Remembered carriers still
        // sample their history (41/40); genuinely-new (no amnesia)
        // still sample honest 0/0.
        fn ineligible_snapshot(pids: &[(u32, u64)]) -> inventory::Snapshot {
            let processes: Vec<inventory::ProcessRecord> = pids
                .iter()
                .map(|(pid, starttime)| inventory::ProcessRecord {
                    interval: inventory::CaptureInterval {
                        started_unix_ms: None,
                        finished_unix_ms: None,
                        elapsed_ns: 0,
                    },
                    namespaces: inventory::NamespaceIds {
                        pid: None,
                        mount: None,
                    },
                    pid: *pid,
                    starttime: *starttime,
                    modules: Vec::new(),
                    provider_activation: inventory::ObservationState::Unknown,
                    provider_interfaces: inventory::ObservationState::Unknown,
                    execution: inventory::ObservationState::Unknown,
                })
                .collect();
            for record in &processes {
                assert!(!eligible(record), "synthetic must be ineligible (premise)");
            }
            inventory::Snapshot {
                interval: inventory::CaptureInterval {
                    started_unix_ms: None,
                    finished_unix_ms: None,
                    elapsed_ns: 0,
                },
                scope_record: inventory::ScopeRecord::default(),
                schema_version: "crypto-watch-test".to_owned(),
                mode: inventory::SnapshotMode::Snapshot,
                scope: inventory::Scope::Pids,
                selected_pids: pids.iter().map(|(pid, _)| *pid).collect(),
                processes,
                gaps: Vec::new(),
                totals: inventory::WorkTotals {
                    processes_attempted: pids.len(),
                    objects_attempted: 0,
                    objects_inspected: 0,
                    read_bytes: 0,
                },
                limits: inventory::Limits::default(),
                capabilities: inventory::Capabilities {
                    inventory: inventory::InventoryState::Complete,
                    provider_activation: inventory::ObservationState::Unknown,
                    provider_interfaces: inventory::ObservationState::Unknown,
                    execution: inventory::ObservationState::Unknown,
                },
                resolve: Default::default(),
                cgroup_identity: std::collections::BTreeMap::new(),
            }
        }
        let namespaces = inventory::NamespaceIds {
            pid: None,
            mount: None,
        };
        let pool = MemoryPool::new(GLOBAL_BYTES);
        let objects = FocusedObjects {
            observation: Arc::from([0u8; 8]),
            count: Arc::from([0u8; 8]),
            count_sha256: [0; 32],
        };
        let selection = Selection::default();
        let cancel = AtomicBool::new(false);
        // Amnesiac run: forgotten 4242 (no stash) + remembered
        // 4343 (stashed 41/40), both ineligible.
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        run.current_tick = 6;
        run.epoch_amnesia = true;
        let remembered = Incarnation {
            pid: 4343,
            starttime: 1,
            namespaces: namespaces.clone(),
        };
        let mut ledger = MemberLedger::empty();
        ledger.loss = 40;
        run.pending_epoch.insert(
            DeferredKey::from(&remembered),
            (
                41,
                ledger,
                ReadmitCtx {
                    retire_ns: 5,
                    seal_tick: 2,
                    witness_ts: Some(6),
                },
            ),
        );
        let ctx = AdmitCtx {
            pool: &pool,
            objects: &objects,
            reservation: 0,
            deadline: Instant::now() + Duration::from_secs(60),
            cancel: &cancel,
            tracing: true,
            trust_reviewed: false,
            selection: &selection,
            max_active: 4,
        };
        let snapshot = ineligible_snapshot(&[(4242, 1), (4343, 1)]);
        let mut bytes = Vec::new();
        let mut sink = sink_into(&mut bytes);
        let mut admitted = Vec::new();
        run.scan_admit(&mut sink, &snapshot, &ctx, &mut admitted)
            .unwrap();
        drop(sink);
        let rows: Vec<serde_json::Value> = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let refused: Vec<&serde_json::Value> = rows
            .iter()
            .filter(|r| {
                r["kind"] == "session_gap"
                    && r["incarnation"]["pid"] == 4242
                    && r["reason"] == "history_ambiguous"
            })
            .collect();
        assert_eq!(
            refused.len(),
            1,
            "forgotten ineligible owes exactly one refusal, got {rows:?}"
        );
        assert!(
            rows.iter().all(|r| r["kind"] != "membership"
                || r["incarnation"]["pid"] != 4242
                || r["state"] != "sampled"),
            "forgotten ineligible must never sample (not even 0/0), got {rows:?}"
        );
        let sampled: Vec<&serde_json::Value> = rows
            .iter()
            .filter(|r| {
                r["kind"] == "membership"
                    && r["incarnation"]["pid"] == 4343
                    && r["state"] == "sampled"
            })
            .collect();
        assert_eq!(sampled.len(), 1, "remembered must sample, got {rows:?}");
        assert_eq!(sampled[0]["image_epoch"], 41, "epoch reset, got {rows:?}");
        assert_eq!(sampled[0]["loss"]["loss"], 40, "loss reset, got {rows:?}");
        // Genuinely-new run (no amnesia): ineligible 4444 samples
        // honest 0/0 (no refusal — nothing forgotten).
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        run.current_tick = 6;
        assert!(!run.epoch_amnesia, "fresh run has no amnesia (premise)");
        let snapshot = ineligible_snapshot(&[(4444, 1)]);
        let mut bytes = Vec::new();
        let mut sink = sink_into(&mut bytes);
        let mut admitted = Vec::new();
        run.scan_admit(&mut sink, &snapshot, &ctx, &mut admitted)
            .unwrap();
        drop(sink);
        let rows: Vec<serde_json::Value> = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let sampled: Vec<&serde_json::Value> = rows
            .iter()
            .filter(|r| {
                r["kind"] == "membership"
                    && r["incarnation"]["pid"] == 4444
                    && r["state"] == "sampled"
            })
            .collect();
        assert_eq!(
            sampled.len(),
            1,
            "genuinely-new ineligible must sample honest 0/0, got {rows:?}"
        );
        assert_eq!(sampled[0]["image_epoch"], 0, "honest 0/0, got {rows:?}");
        assert_eq!(sampled[0]["loss"]["loss"], 0, "honest 0/0, got {rows:?}");
        assert!(
            rows.iter().all(|r| r["kind"] != "session_gap"),
            "genuinely-new must not refuse, got {rows:?}"
        );
    }
    #[test]
    fn failed_admission_keeps_tombstone() {
        // R4-3: the consume rides ADMISSION SUCCESS — a failed
        // open (SessionGap) keeps the tombstone for retry (an
        // eligible record + broken objects force the failure
        // deterministically).
        let mut child = std::process::Command::new("python3")
            .args(["-c", "import ssl, time; time.sleep(30)"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn ssl sleeper");
        let pid = child.id();
        // Bounded wait for the `import ssl` (libssl mapping) —
        // the snapshot must observe the eligible modules, and
        // the import lands in ms (the cap only bounds breakage).
        let until = Instant::now() + Duration::from_secs(10);
        let snapshot = loop {
            let snapshot = inventory::snapshot(&inventory::SnapshotOptions {
                pids: vec![pid],
                resolve_paths: false,
                limits: inventory::Limits::default(),
            });
            let eligible_now = snapshot
                .processes
                .iter()
                .find(|p| p.pid == pid)
                .is_some_and(eligible);
            if eligible_now || Instant::now() >= until {
                break snapshot;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let record = snapshot
            .processes
            .iter()
            .find(|p| p.pid == pid)
            .expect("ssl record")
            .clone();
        assert!(eligible(&record), "ssl child must be eligible (premise)");
        let identity = Incarnation::from(&record);
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        run.current_tick = 6;
        let mut ledger = MemberLedger::empty();
        ledger.loss = 40;
        run.epoch_tombstones.insert(
            DeferredKey::from(&identity),
            TombstoneSummary::summarize(
                41,
                &ledger,
                ReadmitCtx {
                    retire_ns: 5,
                    seal_tick: 2,
                    witness_ts: Some(6),
                },
            ),
        );
        let pool = MemoryPool::new(GLOBAL_BYTES);
        let objects = FocusedObjects {
            observation: Arc::from([0u8; 8]),
            count: Arc::from([0u8; 8]),
            count_sha256: [0; 32],
        };
        let selection = Selection::default();
        let cancel = AtomicBool::new(false);
        let ctx = AdmitCtx {
            pool: &pool,
            objects: &objects,
            reservation: 0,
            deadline: Instant::now() + Duration::from_secs(60),
            cancel: &cancel,
            tracing: true,
            trust_reviewed: false,
            selection: &selection,
            max_active: 4,
        };
        let mut bytes = Vec::new();
        let mut sink = Output {
            writer: &mut bytes,
            sequence: 0,
            json: true,
            pending_gaps: Vec::new(),
            resolve_paths: false,
            terminal: false,
        };
        let mut admitted = Vec::new();
        run.scan_admit(&mut sink, &snapshot, &ctx, &mut admitted)
            .unwrap();
        assert!(
            run.epoch_tombstones
                .contains_key(&DeferredKey::from(&identity)),
            "failed admission consumed the tombstone"
        );
        assert!(admitted.is_empty(), "broken objects admitted");
        assert!(run.active.is_empty(), "broken objects admitted");
        drop(sink);
        let rows: Vec<serde_json::Value> = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert!(
            rows.iter().any(|r| r["kind"] == "session_gap"),
            "failed open owes a SessionGap, got {rows:?}"
        );
        assert!(
            rows.iter().all(|r| r["kind"] != "gap"),
            "failed admission announced, got {rows:?}"
        );
        child.kill().ok();
        child.wait().ok();
    }
    #[test]
    fn queue_drop_restashes_continuation_for_return() {
        // R5-2a: a queue-overflow victim carrying an exec
        // continuation (epoch/loss/spans) re-stashes into the
        // readmit stash instead of vanishing with only a
        // span-carrying drop record — the incarnation's return
        // resumes its history (never 0/0, never silent,
        // amnesia unlatched: nothing was forgotten). The
        // tombstoned victim's announcement promise rides the
        // re-stash (exactly one gap — the admission it was
        // saved for will never come).
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        run.current_tick = 6;
        let namespaces = inventory::NamespaceIds {
            pid: None,
            mount: None,
        };
        let mut bytes = Vec::new();
        let mut sink = sink_into(&mut bytes);
        for i in 0..DEFERRED_CAP {
            let identity = Incarnation {
                pid: 1 + i as u32,
                starttime: 1,
                namespaces: namespaces.clone(),
            };
            run.queue_insert(&mut sink, identity, None, "active_limit")
                .unwrap();
        }
        assert_eq!(run.deferred.len(), DEFERRED_CAP);
        let mut ledger = MemberLedger::empty();
        ledger.loss = 40;
        ledger.windows.append(3, 5, LossCause::RingLoss);
        ledger.windows.append(9, 12, LossCause::ScanLoss);
        let summary = TombstoneSummary::summarize(
            41,
            &ledger,
            ReadmitCtx {
                retire_ns: 5,
                seal_tick: 2,
                witness_ts: Some(6),
            },
        );
        let dropped = Incarnation {
            pid: 99_999,
            starttime: 1,
            namespaces: namespaces.clone(),
        };
        run.queue_insert(
            &mut sink,
            dropped.clone(),
            Some(StashedCtx {
                ctx: summary.materialize(),
                tombstoned: true,
            }),
            "active_limit",
        )
        .unwrap();
        assert_eq!(run.deferred.len(), DEFERRED_CAP);
        assert_eq!(run.pending_drops.len(), 1, "drop record queued");
        assert_eq!(run.pending_drops[0].incarnation.pid, 99_999);
        let back = run
            .peek_exec_ctx(&DeferredKey::from(&dropped))
            .expect("queue drop must preserve the continuation (not epoch 0/loss 0)");
        assert_eq!(back.ctx.0, 41, "epoch reset across queue drop");
        assert_eq!(back.ctx.1.loss, 40, "loss reset across queue drop");
        assert_eq!(back.ctx.2.seal_tick, 2, "readmit context must ride along");
        assert!(
            !back.tombstoned,
            "re-stash promotes to the lossless primary stash (the fold stays data-visible)"
        );
        assert!(
            !run.epoch_amnesia,
            "queue drop preserves — nothing forgotten"
        );
        drop(sink);
        let rows: Vec<serde_json::Value> = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let announced = rows
            .iter()
            .filter(|r| {
                r["kind"] == "gap"
                    && r["gap"]["reason"] == "membership_unknown"
                    && r["gap"]["pid"] == 99_999
            })
            .count();
        assert_eq!(
            announced, 1,
            "tombstoned drop owes exactly one announcement, got {rows:?}"
        );
    }
    #[test]
    fn live_ineligible_removal_preserves_continuation() {
        // R6-2a: a LIVE ineligible removal (same incarnation, triple
        // matches, record ineligible) carrying an exec-readmission
        // context must re-stash the continuation — updated epoch
        // (the sweep's exe re-proof already bumped it) + sealed
        // deferred span + loss + readmit context — so the return
        // resumes history (never 0/0). Death/reuse/run-end removal
        // may discard (the incarnation is gone — see the sweep).
        let pid = std::process::id();
        let identity = super::verify_triple(pid).expect("own triple");
        let live_exe = super::exe_identity(pid).expect("own exe");
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        run.current_tick = 6;
        let mut marks = WindowStore::new(DEFERRED_MARKS);
        marks.append(2, 4, LossCause::RingLoss);
        let key = DeferredKey::from(&identity);
        run.deferred.insert(
            key.clone(),
            DeferredEntry {
                identity: identity.clone(),
                image_epoch: 41,
                first_tick: 4,
                last_tick: 5,
                ticks: 2,
                reason: "active_limit",
                marks,
                // Bogus exe forces the re-proof bump (41 -> 42):
                // the live exe differs, so the sweep advances.
                exe: Some((0, 0)),
                readmit: Some(ReadmitCtx {
                    retire_ns: 5,
                    seal_tick: 2,
                    witness_ts: Some(6),
                }),
                carried_loss: 40,
                carried_deferred: DeferredSpan {
                    ticks: 10,
                    first_tick: 1,
                    last_tick: 3,
                },
                admit_ns: 0,
                tombstoned: false,
            },
        );
        assert_ne!(Some((0, 0)), Some(live_exe), "bump premise");
        // Ineligible record under the exact live triple (no
        // candidate interfaces — modules empty).
        let record = ProcessRecord {
            interval: inventory::CaptureInterval {
                started_unix_ms: None,
                finished_unix_ms: None,
                elapsed_ns: 0,
            },
            namespaces: identity.namespaces.clone(),
            pid,
            starttime: identity.starttime,
            modules: Vec::new(),
            provider_activation: inventory::ObservationState::Unknown,
            provider_interfaces: inventory::ObservationState::Unknown,
            execution: inventory::ObservationState::Unknown,
        };
        assert!(
            Incarnation::from(&record) == identity,
            "synthetic record must match the live triple (premise)"
        );
        assert!(!eligible(&record), "record must be ineligible (premise)");
        let snapshot = Snapshot {
            interval: inventory::CaptureInterval {
                started_unix_ms: None,
                finished_unix_ms: None,
                elapsed_ns: 0,
            },
            scope_record: inventory::ScopeRecord::default(),
            schema_version: "crypto-watch-test".to_owned(),
            mode: inventory::SnapshotMode::Snapshot,
            scope: inventory::Scope::Pids,
            selected_pids: vec![pid],
            processes: vec![record],
            gaps: Vec::new(),
            totals: inventory::WorkTotals {
                processes_attempted: 1,
                objects_attempted: 0,
                objects_inspected: 0,
                read_bytes: 0,
            },
            limits: inventory::Limits::default(),
            capabilities: inventory::Capabilities {
                inventory: inventory::InventoryState::Complete,
                provider_activation: inventory::ObservationState::Unknown,
                provider_interfaces: inventory::ObservationState::Unknown,
                execution: inventory::ObservationState::Unknown,
            },
            resolve: Default::default(),
            cgroup_identity: std::collections::BTreeMap::new(),
        };
        let mut bytes = Vec::new();
        let mut sink = sink_into(&mut bytes);
        run.sweep_deferred(&mut sink, &snapshot).unwrap();
        assert!(
            !run.deferred.contains_key(&key),
            "ineligible live entry must leave the queue"
        );
        let back = run.peek_exec_ctx(&key).expect(
            "live ineligibility removal must preserve the continuation (not epoch 0/loss 0)",
        );
        assert_eq!(back.ctx.0, 42, "updated epoch must ride the re-stash");
        assert_eq!(back.ctx.1.loss, 40, "loss reset across live removal");
        assert_eq!(back.ctx.2.seal_tick, 2, "readmit context must ride along");
        assert!(!back.tombstoned, "lossless entry stays lossless");
        assert!(
            !run.epoch_amnesia,
            "live removal preserves — nothing forgotten"
        );
        // Sealed span: carried (10/[1,3]) unions own (3/[4,6]) —
        // own ticks = 2 + (6 - 5), last = sweep tick.
        assert_eq!(
            back.ctx.1.deferred,
            DeferredSpan {
                ticks: 13,
                first_tick: 1,
                last_tick: 6,
            },
            "sealed deferred span must ride the re-stash"
        );
        drop(sink);
        let rows: Vec<serde_json::Value> = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let removed: Vec<&serde_json::Value> = rows
            .iter()
            .filter(|r| {
                r["kind"] == "membership"
                    && r["incarnation"]["pid"] == pid
                    && r["state"] == "deferred_removed"
            })
            .collect();
        assert_eq!(
            removed.len(),
            1,
            "removal owes exactly one record, got {rows:?}"
        );
        assert_eq!(
            removed[0]["image_epoch"], 42,
            "removal carries the updated epoch, got {rows:?}"
        );
    }
    #[test]
    fn tombstone_overflow_fails_conservative() {
        // R5-2b (rewritten — the R4-3 marker tail checked the
        // wrong thing): tombstone-table overflow forgets a
        // summary with a visible gap AND latches amnesia — and
        // every later ambiguous fresh readmission is REFUSED
        // with a visible `SessionGap{history_ambiguous}` (never
        // a manufactured 0/0, marked or not). The latch is
        // monotonic (the forgotten incarnation may reappear at
        // any later tick). Both capacity variants refuse: with
        // room (no open attempted) and under pressure (not
        // queued).
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        run.current_tick = 6;
        let namespaces = inventory::NamespaceIds {
            pid: None,
            mount: None,
        };
        // The forgotten incarnation K: known epoch 41 / loss 40,
        // key-smallest so the cascade forgets exactly it.
        let forgotten = Incarnation {
            pid: 4242,
            starttime: 1,
            namespaces: namespaces.clone(),
        };
        let mut ledger = MemberLedger::empty();
        ledger.loss = 40;
        run.epoch_tombstones.insert(
            DeferredKey::from(&forgotten),
            TombstoneSummary::summarize(
                41,
                &ledger,
                ReadmitCtx {
                    retire_ns: 5,
                    seal_tick: 2,
                    witness_ts: Some(6),
                },
            ),
        );
        for i in 0..(EPOCH_TOMBSTONE_CAP - 1) {
            let identity = Incarnation {
                pid: 5000 + i as u32,
                starttime: 1,
                namespaces: namespaces.clone(),
            };
            run.epoch_tombstones.insert(
                DeferredKey::from(&identity),
                TombstoneSummary::summarize(
                    1,
                    &MemberLedger::empty(),
                    ReadmitCtx {
                        retire_ns: 0,
                        seal_tick: 0,
                        witness_ts: None,
                    },
                ),
            );
        }
        for i in 0..EVICTED_EPOCH_CAP {
            let identity = Incarnation {
                pid: 6000 + i as u32,
                starttime: 1,
                namespaces: namespaces.clone(),
            };
            run.evicted_epoch.insert(
                DeferredKey::from(&identity),
                (
                    3,
                    MemberLedger::empty(),
                    ReadmitCtx {
                        retire_ns: 0,
                        seal_tick: 0,
                        witness_ts: None,
                    },
                ),
            );
        }
        assert!(!run.epoch_amnesia, "amnesia latches only on overflow");
        let mut bytes = Vec::new();
        let mut sink = Output {
            writer: &mut bytes,
            sequence: 0,
            json: true,
            pending_gaps: Vec::new(),
            resolve_paths: false,
            terminal: false,
        };
        let fresh = Incarnation {
            pid: 99_999,
            starttime: 1,
            namespaces: namespaces.clone(),
        };
        run.demote_evicted(
            &mut sink,
            DeferredKey::from(&fresh),
            (
                2,
                MemberLedger::empty(),
                ReadmitCtx {
                    retire_ns: 0,
                    seal_tick: 0,
                    witness_ts: None,
                },
            ),
        )
        .unwrap();
        // The cascade forgets the key-smallest summary (K, pid
        // 4242 — its 41/40 is unretainable): forgotten, flagged,
        // gapped.
        assert!(
            run.peek_exec_ctx(&DeferredKey::from(&forgotten)).is_none(),
            "forgotten summary reads back"
        );
        assert!(run.epoch_amnesia, "overflow must latch amnesia");
        assert_eq!(
            run.epoch_tombstones.len(),
            EPOCH_TOMBSTONE_CAP,
            "tombstone table must stay capped"
        );
        drop(sink);
        let demote_rows: Vec<serde_json::Value> = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        // One gap names the demote-drop (pid 6000), one the
        // overflow-forget (K, pid 4242).
        for (pid, want) in [(6000, 1), (4242, 1)] {
            let n = demote_rows
                .iter()
                .filter(|r| {
                    r["kind"] == "gap"
                        && r["gap"]["reason"] == "membership_unknown"
                        && r["gap"]["pid"] == pid
                })
                .count();
            assert_eq!(n, want, "gap census wrong for {pid}, got {demote_rows:?}");
        }
        // K returns (synthetic eligible record under its exact
        // key): readmission is REFUSED with a visible record —
        // never a silent (or marked) 0/0. Both capacities.
        fn synthetic_snapshot(pid: u32, starttime: u64) -> inventory::Snapshot {
            let module = inventory::ModuleRecord {
                info: inventory::ModuleInfo {
                    sha256: String::new(),
                    device: 0,
                    inode: 0,
                    size_bytes: 0,
                    architecture: inventory::Architecture::X86_64,
                    kind: inventory::ObjectKind::OpenSslConsumer,
                    exports: Vec::new(),
                    depends_on_libcrypto: false,
                    depends_on_libssl: false,
                },
                identity_status: inventory::IdentityStatus::Verified,
            };
            let record = inventory::ProcessRecord {
                interval: inventory::CaptureInterval {
                    started_unix_ms: None,
                    finished_unix_ms: None,
                    elapsed_ns: 0,
                },
                namespaces: inventory::NamespaceIds {
                    pid: None,
                    mount: None,
                },
                pid,
                starttime,
                modules: vec![module],
                provider_activation: inventory::ObservationState::Unknown,
                provider_interfaces: inventory::ObservationState::Unknown,
                execution: inventory::ObservationState::Unknown,
            };
            inventory::Snapshot {
                interval: inventory::CaptureInterval {
                    started_unix_ms: None,
                    finished_unix_ms: None,
                    elapsed_ns: 0,
                },
                scope_record: inventory::ScopeRecord::default(),
                schema_version: "crypto-watch-test".to_owned(),
                mode: inventory::SnapshotMode::Snapshot,
                scope: inventory::Scope::Pids,
                selected_pids: vec![pid],
                processes: vec![record],
                gaps: Vec::new(),
                totals: inventory::WorkTotals {
                    processes_attempted: 1,
                    objects_attempted: 0,
                    objects_inspected: 0,
                    read_bytes: 0,
                },
                limits: inventory::Limits::default(),
                capabilities: inventory::Capabilities {
                    inventory: inventory::InventoryState::Complete,
                    provider_activation: inventory::ObservationState::Unknown,
                    provider_interfaces: inventory::ObservationState::Unknown,
                    execution: inventory::ObservationState::Unknown,
                },
                resolve: Default::default(),
                cgroup_identity: std::collections::BTreeMap::new(),
            }
        }
        let snapshot = synthetic_snapshot(4242, 1);
        assert!(
            eligible(&snapshot.processes[0]),
            "synthetic K record must be eligible (premise)"
        );
        assert!(
            DeferredKey::from(&Incarnation::from(&snapshot.processes[0]))
                == DeferredKey::from(&forgotten),
            "synthetic K record must match the forgotten key (premise)"
        );
        let pool = MemoryPool::new(GLOBAL_BYTES);
        let objects = FocusedObjects {
            observation: Arc::from([0u8; 8]),
            count: Arc::from([0u8; 8]),
            count_sha256: [0; 32],
        };
        let selection = Selection::default();
        let cancel = AtomicBool::new(false);
        for (case, max_active) in [("room", 4), ("full", 0)] {
            let ctx = AdmitCtx {
                pool: &pool,
                objects: &objects,
                reservation: 0,
                deadline: Instant::now() + Duration::from_secs(60),
                cancel: &cancel,
                tracing: true,
                trust_reviewed: false,
                selection: &selection,
                max_active,
            };
            let mut bytes = Vec::new();
            let mut sink = Output {
                writer: &mut bytes,
                sequence: 0,
                json: true,
                pending_gaps: Vec::new(),
                resolve_paths: false,
                terminal: false,
            };
            let mut admitted = Vec::new();
            run.scan_admit(&mut sink, &snapshot, &ctx, &mut admitted)
                .unwrap();
            assert!(admitted.is_empty(), "{case}: forgotten K must not admit");
            assert!(run.active.is_empty(), "{case}: forgotten K must not admit");
            assert!(
                !run.deferred.contains_key(&DeferredKey::from(&forgotten)),
                "{case}: forgotten K must not queue (a queued 0/0 is a delayed manufacture)"
            );
            assert!(run.epoch_amnesia, "{case}: amnesia must be monotonic");
            drop(sink);
            let rows: Vec<serde_json::Value> = String::from_utf8(bytes)
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect();
            let refused: Vec<&serde_json::Value> = rows
                .iter()
                .filter(|r| {
                    r["kind"] == "session_gap"
                        && r["incarnation"]["pid"] == 4242
                        && r["reason"] == "history_ambiguous"
                })
                .collect();
            assert_eq!(
                refused.len(),
                1,
                "{case}: K owes exactly one visible refusal, got {rows:?}"
            );
            assert!(
                rows.iter().all(|r| r["kind"] != "membership"
                    || r["incarnation"]["pid"] != 4242
                    || r["state"] != "observing"),
                "{case}: K must never observe, got {rows:?}"
            );
            assert!(
                rows.iter().all(|r| r["kind"] != "session_gap"
                    || r["incarnation"]["pid"] != 4242
                    || r["reason"] != "acquisition_unavailable"),
                "{case}: refusal precedes any open attempt, got {rows:?}"
            );
        }
    }
    #[test]
    fn stale_tombstone_dies_with_fresher_ctx() {
        // R4-3: a same-key stash entry is always fresher than a
        // tombstone (every exec advances the epoch) — peek
        // prefers it, and consume/stash drop the stale summary
        // (no resurrection of regressed history).
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        let namespaces = inventory::NamespaceIds {
            pid: None,
            mount: None,
        };
        let identity = Incarnation {
            pid: 4242,
            starttime: 7,
            namespaces: namespaces.clone(),
        };
        let key = DeferredKey::from(&identity);
        run.epoch_tombstones.insert(
            key.clone(),
            TombstoneSummary::summarize(
                5,
                &MemberLedger::empty(),
                ReadmitCtx {
                    retire_ns: 0,
                    seal_tick: 0,
                    witness_ts: None,
                },
            ),
        );
        run.pending_epoch.insert(
            key.clone(),
            (
                9,
                MemberLedger::empty(),
                ReadmitCtx {
                    retire_ns: 0,
                    seal_tick: 0,
                    witness_ts: None,
                },
            ),
        );
        let stashed = run.peek_exec_ctx(&key).expect("stashed ctx");
        assert!(!stashed.tombstoned, "fresher stash must win");
        assert_eq!(stashed.ctx.0, 9);
        run.consume_exec_ctx(&key);
        assert!(
            run.peek_exec_ctx(&key).is_none(),
            "stale tombstone resurrected after consume"
        );
        // A new stash supersedes a same-key tombstone outright.
        run.epoch_tombstones.insert(
            key.clone(),
            TombstoneSummary::summarize(
                5,
                &MemberLedger::empty(),
                ReadmitCtx {
                    retire_ns: 0,
                    seal_tick: 0,
                    witness_ts: None,
                },
            ),
        );
        let mut bytes = Vec::new();
        let mut sink = Output {
            writer: &mut bytes,
            sequence: 0,
            json: true,
            pending_gaps: Vec::new(),
            resolve_paths: false,
            terminal: false,
        };
        run.stash_pending_epoch(
            &mut sink,
            key.clone(),
            (
                11,
                MemberLedger::empty(),
                ReadmitCtx {
                    retire_ns: 0,
                    seal_tick: 0,
                    witness_ts: None,
                },
            ),
        )
        .unwrap();
        assert!(
            !run.epoch_tombstones.contains_key(&key),
            "stash must supersede the stale tombstone"
        );
        assert_eq!(run.peek_exec_ctx(&key).map(|s| s.ctx.0), Some(11));
    }
    #[test]
    fn stranger_exec_advances_tombstoned_stash_with_middle_seal() {
        // R4-3: a tombstoned incarnation's second exec (stranger
        // path) seals the unobserved middle from the summary
        // ledger and advances the summary in place — like the
        // primary and demoted stashes, no promotion cascade.
        let pid = std::process::id();
        let identity = super::verify_triple(pid).expect("own triple");
        let key = DeferredKey::from(&identity);
        let mut ledger = MemberLedger::empty();
        ledger.loss = 7;
        let retire = LiveClock.monotonic_ns();
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        run.epoch_tombstones.insert(
            key.clone(),
            TombstoneSummary::summarize(
                1,
                &ledger,
                ReadmitCtx {
                    retire_ns: retire,
                    seal_tick: 3,
                    witness_ts: Some(retire),
                },
            ),
        );
        let mut bytes = Vec::new();
        let mut sink = Output {
            writer: &mut bytes,
            sequence: 0,
            json: true,
            pending_gaps: Vec::new(),
            resolve_paths: false,
            terminal: false,
        };
        let event = crate::capture::LifecycleEvent {
            kind: LifecycleKind::Exec,
            pid,
            timestamp_ns: Some(LiveClock.monotonic_ns()),
            tgid: pid,
            parent_tgid: 0,
            cpu: 0,
            seq: 0,
        };
        super::bind_event(&mut run, &mut sink, &event, true).unwrap();
        drop(sink);
        assert_eq!(
            run.epoch_tombstones.get(&key).map(|s| s.epoch),
            Some(2),
            "second exec must advance the tombstone"
        );
        assert!(run.pending_epoch.is_empty(), "no promotion cascade");
        assert!(run.evicted_epoch.is_empty(), "no promotion cascade");
        let rows: Vec<serde_json::Value> = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let middle: Vec<&serde_json::Value> = rows
            .iter()
            .filter(|r| r["kind"] == "membership" && r["image_epoch"] == 1)
            .collect();
        assert_eq!(middle.len(), 1, "one middle seal, got {rows:?}");
        assert_eq!(middle[0]["state"], "retired");
        assert_eq!(middle[0]["reason"], "unobserved_transition");
        assert_eq!(
            middle[0]["loss"]["loss"], 7,
            "middle seal carries the summary ledger"
        );
    }
    #[test]
    fn epoch_sweep_drops_dead_evicted_and_tombstones() {
        // R3-4b: the readmit-context sweep covers all three
        // tables — dead/reused incarnations leave no residue;
        // live ones (and unreadable ones) are retained.
        let mut child = std::process::Command::new("/bin/true")
            .spawn()
            .expect("spawn true");
        let dead_pid = child.id();
        child.wait().expect("reap true");
        assert!(matches!(
            super::probe_liveness(dead_pid),
            super::Liveness::Dead
        ));
        let namespaces = inventory::NamespaceIds {
            pid: None,
            mount: None,
        };
        let dead = Incarnation {
            pid: dead_pid,
            starttime: 1,
            namespaces: namespaces.clone(),
        };
        let pid = std::process::id();
        let live = super::verify_triple(pid).expect("own triple");
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        for table in [&mut run.pending_epoch, &mut run.evicted_epoch] {
            table.insert(
                DeferredKey::from(&dead),
                (
                    1,
                    MemberLedger::empty(),
                    ReadmitCtx {
                        retire_ns: 0,
                        seal_tick: 0,
                        witness_ts: None,
                    },
                ),
            );
            table.insert(
                DeferredKey::from(&live),
                (
                    1,
                    MemberLedger::empty(),
                    ReadmitCtx {
                        retire_ns: 0,
                        seal_tick: 0,
                        witness_ts: None,
                    },
                ),
            );
        }
        for key in [DeferredKey::from(&dead), DeferredKey::from(&live)] {
            run.epoch_tombstones.insert(
                key,
                TombstoneSummary::summarize(
                    1,
                    &MemberLedger::empty(),
                    ReadmitCtx {
                        retire_ns: 0,
                        seal_tick: 0,
                        witness_ts: None,
                    },
                ),
            );
        }
        run.sweep_pending_epoch();
        assert!(!run.pending_epoch.contains_key(&DeferredKey::from(&dead)));
        assert!(!run.evicted_epoch.contains_key(&DeferredKey::from(&dead)));
        assert!(!run.epoch_tombstones.contains_key(&DeferredKey::from(&dead)));
        assert!(run.pending_epoch.contains_key(&DeferredKey::from(&live)));
        assert!(run.evicted_epoch.contains_key(&DeferredKey::from(&live)));
        assert!(run.epoch_tombstones.contains_key(&DeferredKey::from(&live)));
    }
    #[test]
    fn backpressure_pause_carries_named_window() {
        // N8b: when a full drop queue pauses newcomer
        // classification, the pause is VISIBLE — a session-carrier
        // `membership_unknown` window covers the unclassified
        // newcomers (otherwise-unrecorded activity, §4.1).
        // Carrier-only: open members are unaffected.
        let pool = MemoryPool::new(GLOBAL_BYTES);
        let namespaces = inventory::NamespaceIds {
            pid: None,
            mount: None,
        };
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        run.current_tick = 6;
        run.prev_tick = Some(5);
        for i in 0..DEFERRED_CAP {
            let identity = Incarnation {
                pid: 200_000 + i as u32,
                starttime: 1,
                namespaces: namespaces.clone(),
            };
            run.deferred.insert(
                DeferredKey::from(&identity),
                DeferredEntry {
                    identity,
                    image_epoch: 0,
                    first_tick: 6,
                    last_tick: 6,
                    ticks: 1,
                    reason: "active_limit",
                    marks: WindowStore::new(DEFERRED_MARKS),
                    exe: None,
                    readmit: None,
                    carried_loss: 0,
                    carried_deferred: DeferredSpan::default(),
                    admit_ns: 0,
                    tombstoned: false,
                },
            );
        }
        for i in 0..PENDING_DROPS_CAP {
            run.pending_drops.push_back(LimitRec {
                incarnation: Incarnation {
                    pid: 300_000 + i as u32,
                    starttime: 1,
                    namespaces: namespaces.clone(),
                },
                reason: "deferred_limit",
                at_tick: 6,
                deferred: None,
            });
        }
        assert_eq!(run.deferred.len(), DEFERRED_CAP);
        assert_eq!(run.pending_drops.len(), PENDING_DROPS_CAP);
        let pid = std::process::id();
        let snapshot = inventory::snapshot(&inventory::SnapshotOptions {
            pids: vec![pid],
            resolve_paths: false,
            limits: inventory::Limits::default(),
        });
        assert!(snapshot.processes.iter().any(|p| p.pid == pid));
        let objects = FocusedObjects {
            observation: Arc::from([0u8; 8]),
            count: Arc::from([0u8; 8]),
            count_sha256: [0; 32],
        };
        let selection = Selection::default();
        let cancel = AtomicBool::new(false);
        let ctx = AdmitCtx {
            pool: &pool,
            objects: &objects,
            reservation: 0,
            deadline: Instant::now() + Duration::from_secs(60),
            cancel: &cancel,
            tracing: true,
            trust_reviewed: false,
            selection: &selection,
            max_active: 4,
        };
        let mut bytes = Vec::new();
        let mut sink = Output {
            writer: &mut bytes,
            sequence: 0,
            json: true,
            pending_gaps: Vec::new(),
            resolve_paths: false,
            terminal: false,
        };
        let mut admitted = Vec::new();
        run.scan_admit(&mut sink, &snapshot, &ctx, &mut admitted)
            .unwrap();
        assert!(run.active.is_empty(), "nothing admitted under backpressure");
        assert_eq!(run.deferred.len(), DEFERRED_CAP, "nothing queued");
        let wire = run.carrier.wire();
        assert!(
            wire.iter().any(|w| {
                w.cause == "membership_unknown" && w.start_tick == 6 && w.end_tick == 7
            }),
            "backpressure pause has no named window: {wire:?}"
        );
    }
    #[test]
    fn deferred_spans_merge_by_union() {
        let full = DeferredSpan {
            ticks: 3,
            first_tick: 1,
            last_tick: 2,
        };
        let own = DeferredSpan {
            ticks: 1,
            first_tick: 5,
            last_tick: 5,
        };
        assert_eq!(
            merge_deferred_spans(full, own),
            DeferredSpan {
                ticks: 4,
                first_tick: 1,
                last_tick: 5,
            }
        );
        assert_eq!(merge_deferred_spans(DeferredSpan::default(), own), own);
        assert_eq!(merge_deferred_spans(full, DeferredSpan::default()), full);
    }
    /// R5-2: throwaway JSON sink for `queue_insert` callers
    /// whose drops emit nothing (fresh victims / no overflow).
    fn sink_into(bytes: &mut Vec<u8>) -> Output<'_, Vec<u8>> {
        Output {
            writer: bytes,
            sequence: 0,
            json: true,
            pending_gaps: Vec::new(),
            resolve_paths: false,
            terminal: false,
        }
    }
    #[test]
    fn queued_exec_readmit_carries_full_ledger() {
        // §4.1 incarnation-wide ledger: queueing an exec-readmit
        // preserves localized loss + the prior deferred span
        // exactly and folds sealed windows through the visible
        // coalescing rule (never silent truncation).
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        run.current_tick = 5;
        let identity = Incarnation {
            pid: 4242,
            starttime: 7,
            namespaces: inventory::NamespaceIds {
                pid: None,
                mount: None,
            },
        };
        let mut windows = WindowStore::new(WINDOW_CAP);
        for (i, cause) in [
            LossCause::RingLoss,
            LossCause::ConnectorDrops,
            LossCause::ScanLoss,
            LossCause::CorpseWait,
            LossCause::CgroupMove,
            LossCause::DrainPending,
        ]
        .iter()
        .enumerate()
        {
            windows.append(i as u64, i as u64 + 1, *cause);
        }
        windows.coalesced = 2;
        let ledger = MemberLedger {
            loss: 7,
            deferred: DeferredSpan {
                ticks: 3,
                first_tick: 1,
                last_tick: 2,
            },
            windows,
        };
        let rctx = ReadmitCtx {
            retire_ns: 100,
            seal_tick: 4,
            witness_ts: None,
        };
        let mut bytes = Vec::new();
        let mut sink = sink_into(&mut bytes);
        run.queue_insert(
            &mut sink,
            identity.clone(),
            Some(StashedCtx {
                ctx: (1, ledger, rctx),
                tombstoned: false,
            }),
            "active_limit",
        )
        .unwrap();
        let key = DeferredKey::from(&identity);
        let entry = run.deferred.get(&key).expect("queued entry");
        assert_eq!(entry.carried_loss, 7);
        assert_eq!(
            entry.carried_deferred,
            DeferredSpan {
                ticks: 3,
                first_tick: 1,
                last_tick: 2,
            }
        );
        assert!(entry.marks.windows.len() <= DEFERRED_MARKS);
        assert!(
            entry.marks.coalesced >= 4,
            "6 windows into 4 marks folds visibly + carried 2: {}",
            entry.marks.coalesced
        );
        assert!(
            entry
                .marks
                .windows
                .iter()
                .any(|w| w.cause == LossCause::CoalescedLoss),
            "fold is visible, not silent"
        );
        let summary = LossSummary::from_entry(entry, 5);
        assert_eq!(summary.loss, 7);
        assert_eq!(summary.deferred.ticks, 4);
        assert_eq!(summary.deferred.first_tick, 1);
        assert_eq!(summary.deferred.last_tick, 5);
    }
    #[test]
    fn limit_tick_budget_holds_with_queued_drops() {
        // §3.3: at most 1024 Limit envelopes per tick — retained
        // entries first, then oldest-first drops to fill; the rest
        // wait (close flushes them; close is not a tick).
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        run.current_tick = 9;
        let namespaces = inventory::NamespaceIds {
            pid: None,
            mount: None,
        };
        let mut bytes = Vec::new();
        let mut out = sink_into(&mut bytes);
        for pid in 0..(DEFERRED_CAP as u32 + 3) {
            run.queue_insert(
                &mut out,
                Incarnation {
                    pid: 100_000 + pid,
                    starttime: 1,
                    namespaces: namespaces.clone(),
                },
                None,
                "active_limit",
            )
            .unwrap();
        }
        assert_eq!(run.deferred.len(), DEFERRED_CAP);
        assert_eq!(run.pending_drops.len(), 3);
        assert_eq!(run.drops, 3);
        drop(out);
        assert!(
            bytes.is_empty(),
            "fresh-victim drops emit no gaps, got {:?}",
            String::from_utf8_lossy(&bytes)
        );
        let mut out = sink_into(&mut bytes);
        run.emit_limit_tick(&mut out).unwrap();
        drop(out);
        let text = String::from_utf8(bytes).unwrap();
        assert_eq!(text.lines().count(), LIMIT_TICK_BUDGET, "hard budget");
        assert_eq!(run.pending_drops.len(), 3, "drops wait their turn");
        // Close flushes every queued drop with the emitting tick.
        let mut bytes = Vec::new();
        let mut out = Output {
            writer: &mut bytes,
            sequence: 0,
            json: true,
            pending_gaps: Vec::new(),
            resolve_paths: false,
            terminal: false,
        };
        run.emit_pending_drops_all(&mut out).unwrap();
        drop(out);
        let text = String::from_utf8(bytes).unwrap();
        let rows: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows.len(), 3);
        for row in &rows {
            assert_eq!(row["kind"], "limit");
            assert_eq!(row["reason"], "deferred_limit");
            assert_eq!(row["at_tick"], 9);
            assert!(row["deferred"].is_object());
        }
        assert!(run.pending_drops.is_empty());
    }
    #[test]
    fn close_flush_exceeds_per_tick_budget_by_amendment() {
        // N8c (§3.3 amendment): close is not a tick — the close
        // flush emits every still-queued drop in one batch (here
        // past the 1024/tick bound), oldest-first, each stamped
        // with the emitting close tick and its sealed span.
        let mut run = RunState::new(BTreeSet::new(), 0, 1);
        run.current_tick = 9;
        let namespaces = inventory::NamespaceIds {
            pid: None,
            mount: None,
        };
        let mut bytes = Vec::new();
        let mut out = sink_into(&mut bytes);
        for pid in 0..(DEFERRED_CAP as u32 + LIMIT_TICK_BUDGET as u32 + 7) {
            run.queue_insert(
                &mut out,
                Incarnation {
                    pid: 100_000 + pid,
                    starttime: 1,
                    namespaces: namespaces.clone(),
                },
                None,
                "active_limit",
            )
            .unwrap();
        }
        assert_eq!(run.deferred.len(), DEFERRED_CAP);
        assert_eq!(run.pending_drops.len(), LIMIT_TICK_BUDGET + 7);
        drop(out);
        assert!(
            bytes.is_empty(),
            "fresh-victim drops emit no gaps, got {:?}",
            String::from_utf8_lossy(&bytes)
        );
        let mut out = sink_into(&mut bytes);
        run.emit_pending_drops_all(&mut out).unwrap();
        drop(out);
        let text = String::from_utf8(bytes).unwrap();
        let rows: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows.len(), LIMIT_TICK_BUDGET + 7, "complete flush");
        for row in &rows {
            assert_eq!(row["kind"], "limit");
            assert_eq!(row["reason"], "deferred_limit");
            assert_eq!(row["at_tick"], 9, "emitting close tick");
            assert!(row["deferred"].is_object(), "sealed span rides along");
        }
        // Same-starttime pids queue ascending, so each insert past
        // the cap evicts itself — oldest-first drain replays pids
        // ascending from the first evicted.
        let first = 100_000 + DEFERRED_CAP as u64;
        assert_eq!(rows[0]["incarnation"]["pid"], first);
        assert_eq!(
            rows[rows.len() - 1]["incarnation"]["pid"],
            first + LIMIT_TICK_BUDGET as u64 + 6
        );
        assert!(run.pending_drops.is_empty());
    }
    #[test]
    fn staging_charges_cover_worst_case_entries() {
        // N8d: every staging store is charged against the pool with
        // a computed byte bound — the flat per-entry charges must
        // cover the worst-case entry (inline + heap + map-node
        // slack). BTreeMap node slack is generous: nodes hold ~11
        // entries, so amortized overhead is a few bytes.
        const BTREE_SLACK: usize = 128;
        let incarnation = std::mem::size_of::<Incarnation>();
        // follow_pending: u32 key + (triple, parent, tick).
        let follow_entry = 4 + incarnation + 8 + 8 + BTREE_SLACK;
        assert!(
            follow_entry <= FOLLOW_ENTRY_BYTES,
            "follow entry {follow_entry} exceeds flat {FOLLOW_ENTRY_BYTES}"
        );
        assert_eq!(FOLLOW_BYTES, FOLLOW_CAP * FOLLOW_ENTRY_BYTES);
        // pending_epoch: key + (epoch, full 64-window ledger, ctx).
        let epoch_entry = std::mem::size_of::<DeferredKey>()
            + 8
            + std::mem::size_of::<MemberLedger>()
            + std::mem::size_of::<ReadmitCtx>()
            + WINDOW_CAP * std::mem::size_of::<CompactWindow>()
            + BTREE_SLACK;
        assert!(
            epoch_entry <= PENDING_EPOCH_ENTRY_BYTES,
            "epoch entry {epoch_entry} exceeds flat {PENDING_EPOCH_ENTRY_BYTES}"
        );
        assert_eq!(
            PENDING_EPOCH_BYTES,
            PENDING_EPOCH_CAP * PENDING_EPOCH_ENTRY_BYTES
        );
        // pending_drops: one owned LimitRec per queued drop.
        let drop_entry = std::mem::size_of::<LimitRec>() + 64;
        assert!(
            drop_entry <= PENDING_DROP_ENTRY_BYTES,
            "drop entry {drop_entry} exceeds flat {PENDING_DROP_ENTRY_BYTES}"
        );
        assert_eq!(
            PENDING_DROPS_BYTES,
            PENDING_DROPS_CAP * PENDING_DROP_ENTRY_BYTES
        );
        // R3-4b demoted table: same value shape as the primary
        // stash, same flat.
        let evicted_entry = std::mem::size_of::<DeferredKey>()
            + 8
            + std::mem::size_of::<MemberLedger>()
            + std::mem::size_of::<ReadmitCtx>()
            + WINDOW_CAP * std::mem::size_of::<CompactWindow>()
            + BTREE_SLACK;
        assert!(
            evicted_entry <= EVICTED_EPOCH_ENTRY_BYTES,
            "evicted entry {evicted_entry} exceeds flat {EVICTED_EPOCH_ENTRY_BYTES}"
        );
        assert_eq!(
            EVICTED_EPOCH_BYTES,
            EVICTED_EPOCH_CAP * EVICTED_EPOCH_ENTRY_BYTES
        );
        // R4-3 tombstones: key + bounded summary (fixed
        // size, no heap) + node slack. The flat doubles to 512
        // B while the cap halves to 512 — the table total is
        // unchanged (asserted below with the staging sum).
        let tombstone_entry = std::mem::size_of::<DeferredKey>()
            + std::mem::size_of::<TombstoneSummary>()
            + BTREE_SLACK;
        assert!(
            tombstone_entry <= EPOCH_TOMBSTONE_ENTRY_BYTES,
            "tombstone entry {tombstone_entry} exceeds flat {EPOCH_TOMBSTONE_ENTRY_BYTES}"
        );
        assert_eq!(
            EPOCH_TOMBSTONE_BYTES,
            EPOCH_TOMBSTONE_CAP * EPOCH_TOMBSTONE_ENTRY_BYTES
        );
        assert_eq!(
            STAGING_BYTES,
            FOLLOW_BYTES
                + PENDING_EPOCH_BYTES
                + PENDING_DROPS_BYTES
                + EVICTED_EPOCH_BYTES
                + EPOCH_TOMBSTONE_BYTES
        );
        // R3-5: the deferred store is pinned here too — no store
        // escapes the layout pin. The REAL entry cost is inline
        // struct + map key + marks heap (up to DEFERRED_MARKS
        // compact windows; the Vec never holds more than the cap,
        // so capacity stays within the bound) + node slack.
        let deferred_entry = std::mem::size_of::<DeferredEntry>()
            + std::mem::size_of::<DeferredKey>()
            + DEFERRED_MARKS * std::mem::size_of::<CompactWindow>()
            + BTREE_SLACK;
        assert!(
            deferred_entry <= DEFERRED_ENTRY_BYTES,
            "deferred entry {deferred_entry} exceeds flat {DEFERRED_ENTRY_BYTES}"
        );
        assert_eq!(DEFERRED_BYTES, DEFERRED_CAP * DEFERRED_ENTRY_BYTES);
        // The staging plane fits the global pool beside the frozen
        // coordinator + deferred + session-loss leases.
        assert!(
            COORDINATOR_BYTES + DEFERRED_BYTES + SESSION_LOSS_BYTES + STAGING_BYTES < GLOBAL_BYTES
        );
    }
    #[test]
    fn crypto_end_reason_names_segment_outcome() {
        let none = super::crypto_end_reason(0, "duration");
        assert!(
            none.contains("no segments") && none.contains("duration"),
            "got: {none}"
        );
        let some = super::crypto_end_reason(7, "cancelled");
        assert!(
            some.contains("7 segments") && some.contains("cancelled") && some.contains("partial"),
            "got: {some}"
        );
        assert!(
            super::pool_exhausted_reason().contains("pool exhausted"),
            "pool reason pinned"
        );
    }
}
