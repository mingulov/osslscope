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
    observation_memory::MemoryPool,
    provider_observation::{cli::Signals, objects::read_triple},
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    io::{self, IsTerminal as _, Write},
    process::ExitCode,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const GLOBAL_BYTES: usize = 256 << 20;
// Four active slots, identity envelopes, serde's streaming stack, IO buffer,
// scalar records and a spare limit gap. Document storage stays in its session.
const COORDINATOR_BYTES: usize = 256 << 10;
// 6A run-lifetime leases (§3.1, frozen byte account): the deferred queue
// (1024 × 256 B) and the session-loss carrier (64 × 24 B + fold count)
// hold SEPARATE additive leases beside the coordinator lease.
const DEFERRED_BYTES: usize = 256 << 10;
const SESSION_LOSS_BYTES: usize = 2 << 10;
// 6A queue/ledger caps (§3.1/§4.1, frozen).
const DEFERRED_CAP: usize = 1024;
const WINDOW_CAP: usize = 64;
const DEFERRED_MARKS: usize = 4;
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
#[derive(Clone, Copy, Serialize)]
struct LostWindow {
    start_tick: u64,
    end_tick: u64,
    cause: &'static str,
}
/// 6A sealed deferred span (§7): ticks spent eligible-but-unadmitted.
#[derive(Clone, Copy, Default, Serialize)]
struct DeferredSpan {
    ticks: u64,
    first_tick: u64,
    last_tick: u64,
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
        Self {
            loss: 0,
            deferred: DeferredSpan {
                ticks,
                first_tick: entry.first_tick,
                last_tick: tick,
            },
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
/// 6A deferred-queue entry (§3.2.5, ≤256 B accounted): the triple,
/// image epoch, deferral accumulator, binding reason, up to 4 loss
/// marks and the fold count, plus the exe identity for lossless
/// deferred-exec detection (re-proof, not attribution) and the
/// readmit context for queued exec-readmits (window ordering).
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
    /// 6A per-tick Limit buffer (BOTH modes): the tick's deferral
    /// records flush once at tick end — human groups past 8 rows
    /// (first 8 + `Deferred omitted=N`, §3.3), JSON emits one
    /// envelope per deferred incarnation (≤1024/tick by the
    /// deferred-queue cap).
    pending_limits: Vec<LimitRec>,
    /// T5 `--resolve-paths` render flags (external F4): fragments
    /// render iff `resolve_paths && terminal && !json`.
    resolve_paths: bool,
    terminal: bool,
}
/// 6A one buffered per-tick deferral record (owned: the scan's
/// borrows don't outlive the tick).
struct LimitRec {
    incarnation: Incarnation,
    reason: &'static str,
    at_tick: u64,
    deferred: Option<DeferredSpan>,
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
    /// 6A: buffer one per-tick deferral record (flushed at tick end).
    fn buffer_limit(
        &mut self,
        incarnation: &Incarnation,
        reason: &'static str,
        at_tick: u64,
        deferred: Option<DeferredSpan>,
    ) {
        self.pending_limits.push(LimitRec {
            incarnation: incarnation.clone(),
            reason,
            at_tick,
            deferred,
        });
    }
    /// 6A: flush the tick's buffered deferral records — human groups
    /// past 8 rows, JSON emits one envelope each, in buffer order
    /// (queue-head-first, then newcomers, both by key).
    fn flush_limits(&mut self) -> io::Result<()> {
        const ROWS: usize = 8;
        if self.pending_limits.is_empty() {
            return Ok(());
        }
        let recs = std::mem::take(&mut self.pending_limits);
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
                let physical = rows("sites")
                    .iter()
                    .chain(rows("fenced").iter().flat_map(|epoch| {
                        epoch["sites"].as_array().map(Vec::as_slice).unwrap_or(&[])
                    }))
                    .try_fold(0u64, |n, r| n.checked_add(r["calls"].as_u64()?));
                let api = d["api_activity"].as_array().and_then(|rows| {
                    rows.iter()
                        .try_fold(0u64, |n, r| n.checked_add(r["entries"].as_u64()?))
                });
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
                    writeln!(
                        w,
                        "  api={} entries={}",
                        api.export_name(),
                        row["entries"].as_u64().unwrap_or(0)
                    )?;
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
                    "Crypto watch end: reason={reason} segments={segments} peak_accounted_bytes={peak_accounted_bytes} peak_deferred_depth={peak_deferred_depth} deferred_drops={deferred_drops} deferred_removed={}/{}/{}/{} signal_dropped={} scan_loss={} prefix_unwitnessed={} drain_pending={} unattributed={} ring_loss={} lost_intervals={} polling_fallback={} coverage={coverage}; unsampled membership and unobserved activity remain unknown",
                    deferred_removed.exited,
                    deferred_removed.reused,
                    deferred_removed.ineligible,
                    deferred_removed.closed,
                    session_loss.signal_dropped,
                    session_loss.scan_loss,
                    session_loss.signal_prefix_unwitnessed,
                    session_loss.drain_pending,
                    session_loss.unattributed_events,
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
    /// 6A exec image seal (§1.4): the old image epoch retires like a
    /// member departure (sealed segment, conserved counts) WITHOUT a
    /// `Membership{retired}` — the incarnation continues (its next
    /// record is the new epoch's admission carrying
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
fn sync_selection(scanner: &mut ScopedScanner, run: &RunState) {
    scanner.set_pids(watched_pids(run));
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
    match event.kind {
        LifecycleKind::Fork => {
            let child = event.pid;
            if run.active.iter().any(|a| a.identity.pid == child)
                || run.deferred.keys().any(|k| k.pid == child)
                || run.follow_pending.contains_key(&child)
            {
                return Ok(());
            }
            match verify_triple(child) {
                Some(identity) => {
                    run.follow_pending
                        .insert(child, (identity, Some(event.parent_tgid), run.current_tick));
                }
                None => {
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
            let Some(pos) = run.active.iter().position(|a| a.identity.pid == subject) else {
                // Stranger exec: re-follow verified pids
                // (exec-into-eligibility after a prune);
                // unverifiable subjects quarantine.
                match verify_triple(subject) {
                    Some(identity) => {
                        run.follow_pending
                            .insert(subject, (identity, None, run.current_tick));
                    }
                    None => quarantine(run),
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
                        // member untouched, counted once.
                        quarantine(run);
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
            if let Some(key) = run.deferred.keys().find(|k| k.pid == subject).cloned() {
                let identity = run.deferred[&key].identity.clone();
                // Deferred exits match silently (the sweep removes);
                // validated-triple exits are thread artifacts.
                if matches!(probe_liveness(subject), Liveness::Alive(now) if now == identity) {
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
        // Thread births are BPF-side hints (tid rows learn through
        // the PENDING/THREADS path); they carry no record and never
        // quarantine (delivered births always name a watched TGID).
        LifecycleKind::ThreadBirth => {}
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
/// 6A coordinator run state: observed set, deferred queue, loss
/// baselines, per-tick flags and end tallies.
struct RunState {
    active: Vec<Active>,
    deferred: BTreeMap<DeferredKey, DeferredEntry>,
    /// Followed-but-unclassified pids (event births + stranger
    /// execs): pid → (recorded triple, parent tgid if any, first tick).
    follow_pending: BTreeMap<u32, (Incarnation, Option<u32>, u64)>,
    /// Exec-sealed incarnations awaiting readmit: key → (next
    /// epoch, carried ledger, readmit context).
    pending_epoch: BTreeMap<DeferredKey, (u64, MemberLedger, ReadmitCtx)>,
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
    /// Cumulative session lanes (§7 `SessionLoss`).
    connector_drops: u64,
    connector_enobufs: u64,
    scan_loss: u64,
    signal_dropped: u64,
    signal_prefix_unwitnessed: u64,
    drain_pending: u64,
    carrier: WindowStore,
    unattributed: u64,
    polling: bool,
    /// `drain_pending` at the last sample (per-tick residue gauge).
    pending_mark: u64,
    /// Per-tick staging (flushed/consumed at the sample block).
    ignored: BTreeMap<u32, u64>,
    /// pid → (first-fence tick, first-witness ts, witness count).
    /// Multiple execs before a seal advance the epoch by the count
    /// (the middle images are covered-unknown by the transition
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
}
impl RunState {
    fn new(user_pids: BTreeSet<u32>, origin_ns: u64) -> Self {
        Self {
            active: Vec::new(),
            deferred: BTreeMap::new(),
            follow_pending: BTreeMap::new(),
            pending_epoch: BTreeMap::new(),
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
            connector_drops: 0,
            connector_enobufs: 0,
            scan_loss: 0,
            signal_dropped: 0,
            signal_prefix_unwitnessed: 0,
            drain_pending: 0,
            carrier: WindowStore::new(WINDOW_CAP),
            unattributed: 0,
            polling: false,
            pending_mark: 0,
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
        }
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
    /// `[S, T+1)` (`S` = tick of the last successful read, widening
    /// across skipped ticks); drain residue marks the current tick
    /// while backpressured. Read ticks always advance.
    fn update_loss_baselines(&mut self, tick_pending: u64) {
        let tick = self.current_tick;
        let first = self.prev_tick.is_none();
        let ring = self.live_ring();
        for (i, live) in ring.iter().enumerate() {
            let s = if first { tick } else { self.consumed_tick[i] };
            if *live > self.ring_hw[i] {
                self.propagate(s, tick + 1, LossCause::RingLoss);
                self.ring_hw[i] = *live;
            }
            self.consumed_tick[i] = tick;
        }
        if tick_pending > 0 {
            self.propagate(tick, tick + 1, LossCause::DrainPending);
        }
    }
    /// 6A per-tick connector-lane evaluation (counter lanes only;
    /// drain residue is gauged in `update_loss_baselines`).
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
                _ => (
                    self.lane_prefix.tick.unwrap_or(tick),
                    value > self.lane_prefix.value,
                ),
            };
            if fire {
                self.propagate(s, tick + 1, cause);
            }
            let base = match lane {
                0 => &mut self.lane_drops,
                1 => &mut self.lane_enobufs,
                2 => &mut self.lane_scan,
                _ => &mut self.lane_prefix,
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
                    let entry = self.deferred.remove(&key).expect("swept entry");
                    self.emit_removal(out, &entry, image_epoch, "incarnation_changed")?;
                    self.removed.reused = self.removed.reused.saturating_add(1);
                }
                None => match probe_liveness(pid) {
                    Liveness::Dead => {
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
    /// last_tick]` span rides `loss.deferred` (§3.2.5).
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
            self.segments,
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
    /// sealed segment; nothing further is owed).
    fn sweep_pending_epoch(&mut self) {
        let keys: Vec<DeferredKey> = self.pending_epoch.keys().cloned().collect();
        for key in keys {
            let alive_same = matches!(probe_liveness(key.pid), Liveness::Alive(now)
                if now.starttime == key.starttime && now.namespaces == key.namespaces);
            if !alive_same {
                self.pending_epoch.remove(&key);
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
        let config = FocusedConfig {
            duration: ctx.deadline.saturating_duration_since(Instant::now()),
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
            Ok(session) => {
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
    /// into the entry (latest 4 marks; the sealed segment carried
    /// the full ledger) or is forgotten with the drop. The
    /// newcomer's own per-tick `Limit` buffers unless it dropped.
    fn queue_insert<W: Write>(
        &mut self,
        out: &mut Output<'_, W>,
        identity: Incarnation,
        exec_ctx: Option<(u64, MemberLedger, ReadmitCtx)>,
        reason: &'static str,
    ) -> io::Result<()> {
        let tick = self.current_tick;
        let key = DeferredKey::from(&identity);
        if self.deferred.contains_key(&key) {
            if let Some(entry) = self.deferred.get_mut(&key) {
                entry.reason = reason;
            }
            out.buffer_limit(&identity, reason, tick, None);
            return Ok(());
        }
        let (epoch, marks, readmit) = match exec_ctx {
            Some((epoch, ledger, rctx)) => {
                let mut marks = WindowStore::new(DEFERRED_MARKS);
                let mut carried = ledger.windows.windows.clone();
                carried.sort_by_key(|w| (w.start_tick, w.end_tick));
                for w in carried.iter().rev().take(DEFERRED_MARKS).rev() {
                    marks.windows.push(*w);
                }
                marks.coalesced = ledger.windows.coalesced;
                (epoch, marks, Some(rctx))
            }
            None => (0, WindowStore::new(DEFERRED_MARKS), None),
        };
        self.pending_epoch.remove(&key);
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
            },
        );
        while self.deferred.len() > DEFERRED_CAP {
            let (_, dropped) = self.deferred.pop_last().expect("overflow entry");
            let span = DeferredSpan {
                ticks: dropped
                    .ticks
                    .saturating_add(tick.saturating_sub(dropped.last_tick)),
                first_tick: dropped.first_tick,
                last_tick: tick,
            };
            out.buffer_limit(&dropped.identity, "deferred_limit", tick, Some(span));
            self.drops = self.drops.saturating_add(1);
        }
        if self.deferred.contains_key(&key) {
            out.buffer_limit(&identity, reason, tick, None);
        }
        self.peak_depth = self.peak_depth.max(self.deferred.len() as u64);
        Ok(())
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
            if self.active.len() >= ctx.max_active {
                if let Some(entry) = self.deferred.get_mut(&key) {
                    entry.reason = "active_limit";
                }
                out.buffer_limit(&identity, "active_limit", tick, None);
                continue;
            }
            let Some(lease) = ctx.pool.reserve(ctx.reservation) else {
                if let Some(entry) = self.deferred.get_mut(&key) {
                    entry.reason = "global_state_limit";
                }
                out.buffer_limit(&identity, "global_state_limit", tick, None);
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
            let mut ledger = MemberLedger {
                loss: 0,
                deferred: DeferredSpan {
                    ticks: entry
                        .ticks
                        .saturating_add(tick.saturating_sub(entry.last_tick)),
                    first_tick: entry.first_tick,
                    last_tick: tick,
                },
                windows: entry.marks.clone(),
            };
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
                // tick's record, not a Limit).
                let mut back = entry;
                back.last_tick = tick;
                let rekey = DeferredKey::from(&identity);
                self.deferred.insert(rekey, back);
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
            let identity = Incarnation::from(record);
            let exec_ctx = self
                .pending_epoch
                .get(&DeferredKey::from(&identity))
                .cloned();
            if !eligible(record) {
                let (epoch, loss) = match &exec_ctx {
                    Some((epoch, ledger, _)) => (*epoch, LossSummary::from_ledger(ledger)),
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
                    self.segments,
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
                let epoch = exec_ctx.as_ref().map(|c| c.0).unwrap_or(0);
                out.emit_membership(
                    &identity,
                    self.segments,
                    "sampled",
                    "tracing_unavailable",
                    epoch,
                    None,
                    LossSummary::empty(),
                    false,
                )?;
                continue;
            }
            if self.active.len() >= ctx.max_active {
                self.queue_insert(out, identity, exec_ctx, "active_limit")?;
                continue;
            }
            let Some(lease) = ctx.pool.reserve(ctx.reservation) else {
                self.queue_insert(out, identity, exec_ctx, "global_state_limit")?;
                continue;
            };
            let (epoch, detail, ledger, floor) = match exec_ctx {
                Some((epoch, mut ledger, rctx)) => {
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
                None => (0, None, MemberLedger::empty(), 0),
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
                // Readmit consumed its context. Failed
                // exec-readmits keep theirs (retry next tick);
                // fresh candidates are forgotten (rediscovery
                // retries).
                self.pending_epoch.remove(&DeferredKey::from(&identity));
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
        let Some(lease) = ctx.pool.reserve(ctx.reservation) else {
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
        // (b) Exec flags: seal the image epoch, then readmit inline
        // (fresh record), stash readmit context (alive but
        // unscanned/ineligible), or drop it (dead/reused). The next
        // epoch advances by the witness count (middle images are
        // covered-unknown by the transition window).
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
            let stash = ReadmitCtx {
                retire_ns: outcome.retire_ns,
                seal_tick: tick,
                witness_ts,
            };
            match snapshot.processes.iter().find(|p| p.pid == pid) {
                Some(record) if Incarnation::from(record) == identity => {
                    if eligible(record) && ctx.tracing {
                        // Pre-stash: try_admit consumes the spec, so
                        // the context lives here first and the
                        // readmit clears it on success.
                        self.pending_epoch.insert(
                            DeferredKey::from(&identity),
                            (next_epoch, outcome.ledger.clone(), stash),
                        );
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
                            self.pending_epoch.remove(&DeferredKey::from(&identity));
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
                            self.segments,
                            "sampled",
                            reason,
                            next_epoch,
                            None,
                            LossSummary::from_ledger(&outcome.ledger),
                            sampled_blind(ctx.selection, snapshot, identity.pid),
                        )?;
                        self.pending_epoch.insert(
                            DeferredKey::from(&identity),
                            (next_epoch, outcome.ledger, stash),
                        );
                    }
                }
                _ => match probe_liveness(pid) {
                    Liveness::Alive(now) if now == identity => {
                        self.pending_epoch.insert(
                            DeferredKey::from(&identity),
                            (next_epoch, outcome.ledger, stash),
                        );
                    }
                    Liveness::Unknown => {
                        self.pending_epoch.insert(
                            DeferredKey::from(&identity),
                            (next_epoch, outcome.ledger, stash),
                        );
                    }
                    _ => {}
                },
            }
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
                    if moved && !failed {
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
                    if failed {
                        // Whole-sample failure: unknown, not
                        // removed (no window — the global Gap
                        // record covers the tick).
                        if !self.active[i].suspended {
                            self.active[i].session.suspend_retained();
                            self.active[i].suspended = true;
                        }
                        i += 1;
                        continue;
                    }
                    if record.is_some() {
                        // Present but different triple: reuse.
                        self.seal_active(out, i, "incarnation_changed", true)?;
                        continue;
                    }
                    if excluded {
                        // Partial-sample exclusion: retain unknown
                        // with a per-tick window.
                        if !self.active[i].suspended {
                            self.active[i].session.suspend_retained();
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

fn observe(
    config: &CryptoWatchConfig,
    objects: FocusedObjects,
    pool: &MemoryPool,
    output: &mut impl Write,
    json: bool,
    cancel: &AtomicBool,
    producer: Option<&crate::lifecycle_producer::ProducerHandle>,
) -> io::Result<u8> {
    let mut out = Output {
        writer: output,
        sequence: 0,
        json,
        pending_gaps: Vec::new(),
        pending_limits: Vec::new(),
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
                    lost_intervals: Vec::new(),
                    coalesced: 0,
                },
            })?;
            crate::report::err_line(&format!(
                "osslscope crypto watch: scope unavailable ({}; see records above)",
                reason.word()
            ));
            return Ok(4);
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
        Err(_) => LiveLifecycle::Polling(crate::capture::PollingLifecycle::new(std::process::id())),
    };
    let trust_reviewed =
        port.timing_trust() == crate::capture::LifecycleTimingTrust::ReviewedMonotonic;
    let user_pids: BTreeSet<u32> = config.selection.pids.iter().copied().collect();
    let mut run = RunState::new(user_pids, run_origin_ns);
    sync_selection(&mut scanner, &run);
    sync_roots(&mut port, &run);
    let ctx = AdmitCtx {
        pool,
        objects: &objects,
        reservation,
        deadline: Instant::now() + config.duration,
        cancel,
        tracing,
        trust_reviewed,
        selection: &config.selection,
        max_active: config.max_active,
    };
    let deadline = ctx.deadline;
    let mut next_scan = Instant::now();
    let mut admitted: Vec<u32> = Vec::new();
    while Instant::now() < deadline && !cancel.load(Ordering::Relaxed) {
        let now = Instant::now();
        // (1) 6A event drain, every iteration: loss lanes fold and
        // events bind (fences/flags/candidates/gaps/quarantine).
        // Revalidation runs between event application (here) and
        // count projection (the polls below).
        drain_port(&mut port, &mut run, &mut out, trust_reviewed)?;
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
            let sample_open_ns = LiveClock.monotonic_ns();
            let snapshot = scanner.observation_snapshot_for(
                config.interval.min(deadline.saturating_duration_since(now)),
            );
            next_scan = Instant::now() + config.interval;
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
            run.sample_members(&mut out, &snapshot.snapshot, &ctx, &mut admitted)?;
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
                run.scan_admit(&mut out, &snapshot.snapshot, &ctx, &mut admitted)?;
            }
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
            // Per-tick deferral flush (grouped past 8 rows on human).
            out.flush_limits()?;
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
            sync_selection(&mut scanner, &run);
            sync_roots(&mut port, &run);
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
        let remaining = deadline.saturating_duration_since(Instant::now());
        if !cancel.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(25).min(remaining));
        }
    }
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
        let close = port.close_drain(edge, None);
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
                bind_event(&mut run, &mut out, &event, trust_reviewed)?;
            }
        }
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
        let Some((fence_tick, _ts, _count)) = run.exec_flags.get(&pid).copied() else {
            continue;
        };
        let Some(pos) = run.active.iter().position(|a| a.identity.pid == pid) else {
            run.exec_flags.remove(&pid);
            continue;
        };
        run.active[pos].ledger.windows.append(
            fence_tick,
            run.current_tick.saturating_add(1),
            LossCause::ExecSpanningAggregate,
        );
        let active = run.active.remove(pos);
        run.drop_flags_for(pid);
        let outcome = out.finish_exec_seal(active)?;
        run.seal_fold(outcome.loss_totals);
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
    out.flush_gaps()?;
    out.flush_limits()?;
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
        lost_intervals: run.carrier.wire(),
        coalesced: run.carrier.coalesced,
    };
    out.emit(Record::End {
        reason,
        segments: run.segments,
        peak_accounted_bytes: pool.peak(),
        coverage: "partial",
        peak_deferred_depth: run.peak_depth,
        deferred_drops: run.drops,
        deferred_removed: std::mem::take(&mut run.removed),
        session_loss,
    })?;
    crate::report::err_line(&crypto_end_reason(run.segments, reason));
    Ok(if run.segments == 0 { 4 } else { 3 })
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
        for line in crate::cli::exit_code_help() {
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
            pending_limits: Vec::new(),
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
            pending_limits: Vec::new(),
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
            pending_limits: Vec::new(),
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
    fn two_normal_reservations_include_coordinator_scanner_and_stock_parser() {
        let pool = MemoryPool::new(GLOBAL_BYTES);
        let _coordinator = pool.reserve(COORDINATOR_BYTES + 32_768).unwrap();
        let _scanner = pool.reserve(4096 * 160 + 100 * 4096).unwrap();
        let cost = FocusedSession::reservation_bytes(&objects()).unwrap() + 29_480;
        let _a = pool.reserve(cost).unwrap();
        let _b = pool.reserve(cost).unwrap();
        let _parser = pool
            .reserve(inventory::elf::parser_scratch_bytes(6_386_528).unwrap())
            .unwrap();
        assert!(pool.peak() <= GLOBAL_BYTES);
        assert!(pool.reserve(cost).is_none());
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
            pending_limits: Vec::new(),
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
                pending_limits: Vec::new(),
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
            pending_limits: Vec::new(),
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
                pending_limits: Vec::new(),
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
            pending_limits: Vec::new(),
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
            pending_limits: Vec::new(),
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
            pending_limits: Vec::new(),
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
