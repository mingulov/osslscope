//! SPDX-License-Identifier: GPL-3.0-or-later
//! T08 session-driven capture controller (spec R04/R05).
//!
//! One requested observation holds BOTH sessions for its complete
//! lifetime: a [`DiscoverySession`](crate::discovery::session::DiscoverySession)
//! for the dispatch/legacy planes and a
//! [`CountSession`](crate::count_session::CountSession) for keyed
//! callback counts. Discovery deltas apply incrementally through the
//! [`adapt_delta`] adapter; legacy tripwire counters baseline at the
//! declared window boundary; counting closes before the final
//! discovery drain; and the window finalizes through
//! [`evidence::finalize`] only after every counter is known.
//!
//! Window order for `run` (R05: requested begins at child release):
//! spawn stopped → attach discovery → open the kernel count window →
//! baseline discovery poll → release the child (requested start) →
//! poll loop → close counting → final discovery drain → reap/detach.
//! Opening before release keeps the happy-path startup gap at zero;
//! `--pid` (requested begins at acquisition, necessarily before the
//! window opens) stays explicitly PARTIAL, as before.
//!
//! The `Capture`/`Counters`/`Outcome` surface below is the T10/T11
//! seam: reports and policy still consume it, now mapped from the
//! finalized [`evidence::CaptureDocument`] (carried in
//! [`Capture::document`]) instead of the retired Engine. Reason
//! strings stay inside the `REASON_TAXONOMY` vocabulary in
//! `report.rs` (extended by review for the session-driven gaps).
//!
//! Lifecycle (R05): short fork/exec detection uses the EXPLICIT
//! PARTIAL polling fallback ([`PollingLifecycle`]); polling alone
//! cannot prove no such activity, so every live capture carries the
//! `lifecycle.polling_fallback` loss until the bounded kernel signal
//! path lands (recorded gap, see the T08 handoff). No multi-target
//! capture: one TGID throughout.
//!
//! The controller is generic over [`DiscoveryPort`], [`TargetPort`],
//! [`LifecyclePort`], [`ClockPort`] and [`ProcPort`] so the
//! `tests/capture_controller.rs` suite drives the real [`observe`]
//! loop with scripted sessions, an injected clock and failing I/O —
//! no timing sleeps, no privileges.
use crate::count_session::{
    CountBackend, CountDelta, CountDrain, CountSession, DiscoveredSite, FenceReason as CountFence,
};
use crate::discovery::provider::ProviderTable;
use crate::discovery::session::{
    CoverageState, DiscoveredCandidate, DiscoveryDelta, DiscoverySession, DiscoverySnapshot,
    PollBudget, Recycled, TripwireDelta,
};
use crate::discovery::{coverage, elf, legacy, maps, onboard};
use crate::evidence::{
    self, CandidateCoverage, CandidateIdentity, CaptureContext, CaptureDocument, CaptureWindow,
    Completeness, CounterKind, CounterSource, CounterUnits, DispositionRecord, EngineObservation,
    EngineWindow, ExpectedScope, FencedGeneration, FinalizeInput, GapCounter, GapReason,
    LegacyCallPartition, ObjectId, ObjectRecord, OpensslVersion, ScopeCoverage, SiteExecution,
    SiteKey, TargetRecord,
};
use crate::scan::backend::{BackendAction as ScanAction, ScanBackend};
use crate::scan::oracle::{Finding, Outcome as ScanOutcome, WalkDone};
use crate::scan::registry::TidSource as _;
use crate::{args, kinds, pin, plan, target};
use anyhow::Context as _;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime};

/// Maps-fence poll cadence (frozen §5).
pub const POLL_INTERVAL: Duration = Duration::from_millis(250);
/// Per-poll wall budget; overruns skip the round (§5).
pub const POLL_BUDGET: Duration = Duration::from_millis(50);
/// Signal-drain grace (P2 default; P3 sets final).
pub const DEFAULT_GRACE: Duration = Duration::from_secs(5);
/// Extra discovery polls per round while `budget_exhausted` persists.
/// Backpressure, not loss — but the round stays bounded so a busy
/// ring cannot starve the deadline.
const MAX_CATCHUP_POLLS: u32 = 8;
/// Bounded corpse-close wait: covers the `exit_mm`-to-zombie window
/// (maps already empty, waitpid still blind) through custody.
const CORPSE_WAIT: Duration = Duration::from_millis(100);

/// Capture run configuration.
///
/// `harvest_object`/`count_object`/`provider` are `None` for normal
/// automatic discovery (trusted installed objects; the live target's
/// libcrypto in builtin mode) and `Some` for explicit operator
/// overrides. `table`/`force_offset`/`provider_enrollment` are
/// explicit-only local enrollment (never implicit).
#[derive(Clone)]
pub struct Config {
    pub harvest_object: Option<PathBuf>,
    pub count_object: Option<PathBuf>,
    /// Explicit members object (`--members-object`): the operator
    /// asked for traversal — the triple must resolve (fail-closed,
    /// no harvest-only fallback). `None` attempts the automatic
    /// triple (receipt-verified); pair-only installs stay
    /// harvest-only; broken triples refuse.
    pub members_object: Option<PathBuf>,
    pub provider: Option<PathBuf>,
    pub builtin: bool,
    /// Explicit local offset table (`--table`), or None for the
    /// shipped frozen table.
    pub table: Option<PathBuf>,
    /// Forced query-fn file offset (forensics escape hatch).
    pub force_offset: Option<u64>,
    /// Explicit provider-class enrollment (parsed at CLI time, so a
    /// malformed file is a usage error before any side effect).
    pub provider_enrollment: Option<ProviderTable>,
    /// Provider pinned at target resolution (enrollment hit or
    /// builtin assertion, bound to one verified object id);
    /// consumed by evidence synthesis. `None` until `run`
    /// resolves the target.
    pub resolved_provider: Option<PinnedProvider>,
    pub duration: Duration,
    pub settle: Duration,
    pub harvest_timeout: Duration,
    pub grace: Duration,
    /// CI-supplied container image digest for the check
    /// actionability tuple ("" when unknown — bare metal).
    pub image_digest: String,
}

/// Capture target: spawned child (`run --`) or live pid (staging).
pub enum Target {
    Spawn {
        argv: Vec<String>,
        workload: target::WorkloadDest,
    },
    Pid(u32),
}

/// Fatal outcomes; the CLI maps these per report.rs precedence
/// (H7: `Runtime` — a salvaged post-observation tool failure — is
/// exit 1; the rest are exit 4, or 1 when the child itself failed).
#[derive(Debug, Clone)]
pub enum FatalKind {
    /// Target recycled mid-window: all observations discarded.
    Recycled,
    /// Zero count probes attached (all planned offsets missed or
    /// kernel-rejected).
    AttachZero,
    /// Environment failure: BPF load, fork/exec, maps reads, ... —
    /// anything that is neither evidence nor a usage error.
    Env(String),
    /// Post-observation tool failure (H7): the close flow broke
    /// mid-run; the capture is salvaged (collected state kept,
    /// failure folded in as fatal loss + reason).
    Runtime(String),
}

/// Window outcome.
#[derive(Debug, Clone)]
pub enum Outcome {
    Complete,
    Partial,
    Fatal(FatalKind),
}

/// Traversal selection for [`run_traversal`] (opt-in per run —
/// [`run`] stays harvest-only). `None` members means automatic
/// triple discovery from the trusted object dirs; `Some` is an
/// explicit operator override for the members role.
#[derive(Debug, Clone, Default)]
pub struct TraversalRequest {
    pub members_object: Option<PathBuf>,
}

/// Provenance of one resolved BPF object (matched-set identity:
/// the path that was loaded plus the sha256 of the bytes read).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectProvenance {
    pub path: PathBuf,
    pub sha256: String,
}

/// Resolved triple provenance (recorded on the capture when
/// traversal runs — the exact selected objects, so doctor and the
/// capture agree; report/check CLI selection is follow-up work).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TripleProvenance {
    pub harvest: ObjectProvenance,
    pub count: ObjectProvenance,
    pub members: ObjectProvenance,
}

// NOTE (round 3, F1): traversal records are NOT adapted into
// count-session executions. Callback execution is unobservable
// in v1, so any `SiteExecution` assembled from query visibility
// would fabricate execution (fetch/query visibility is not
// execution evidence). Traversal reports natively:
// `TraversalCapture` retains full records (per-slot identities
// with generations + TRUE-T + outcomes + provenance + admitted
// census); the report `traversal` section carries the triple,
// the census, and per-record summaries (full slot arrays stay
// in-capture like raw ring events). The inventory carries only
// count-observed executions.

/// Summarize a traversal outcome into the document's traversal
/// record (the exact selected triple + counts — `None` when the
/// run never resolved provenance, i.e. harvest-only or a stub
/// without one, so the document key stays absent there).
fn traversal_record(t: &TraversalCapture) -> Option<evidence::TraversalRecord> {
    let p = t.provenance.as_ref()?;
    let obj = |o: &ObjectProvenance| evidence::TraversalObject {
        path: o.path.display().to_string(),
        sha256: o.sha256.clone(),
    };
    Some(evidence::TraversalRecord {
        harvest: obj(&p.harvest),
        count: obj(&p.count),
        members: obj(&p.members),
        records: t.done.len() as u64,
        findings: t.findings.len() as u64,
        polls: t.polls,
        admitted: t.admitted_by_op.clone(),
        admitted_unknown: t.admitted_unknown_by_op.iter().copied().collect(),
        census_loss: t.census_loss,
        entries: t
            .done
            .iter()
            .map(|w| evidence::TraversalRecordEntry {
                tid: w.tid,
                seq: w.seq,
                op: w.op,
                outcome: w.outcome.clone(),
                true_t: w.true_t,
                alg_count: w.alg_count,
                row_count: w.row_count,
                generation: w.generation(),
            })
            .collect(),
    })
}

/// One traversal poll's outputs (port → Runner): completed
/// invocation records, join findings, and the PARTIAL reasons
/// this poll earned (storm cut observation, throttle skipped
/// queries, invocations incomplete/unjoined).
#[derive(Debug, Default)]
pub struct TraversalDelta {
    pub done: Vec<WalkDone>,
    pub findings: Vec<Finding>,
    pub partial_reasons: Vec<String>,
    /// In-window backend polls this delta covers (1 per round
    /// poll; the baseline poll contributes 0).
    pub polls: u64,
    /// Post-drain verdict corrections (the Runner applies them
    /// to its held verdicts by (tid, seq) — a consumed verdict
    /// never stands on mixed evidence).
    pub corrections: Vec<crate::scan::oracle::Correction>,
    /// Admitted-query census snapshot (per op, cumulative since
    /// attach): honest observation metadata (loss-independent —
    /// record count is not a census).
    pub admitted: BTreeMap<u32, u64>,
    /// Ops with records in this delta but no census entry while
    /// the census lost increments: UNKNOWN, never zero.
    pub admitted_unknown: BTreeSet<u32>,
    /// Cumulative admitted-increment loss (CALLS map pressure).
    pub census_loss: u64,
    /// A storm detach cut observation this poll (typed form of
    /// the `traversal-storm` reason — feeds the finalizer).
    pub storm: bool,
    /// The tier-2 throttle skipped queries this poll (typed form
    /// of the `traversal-throttled` reason — feeds the finalizer).
    pub throttled: bool,
}

/// Retained traversal outcome (on [`Capture`] when traversal ran;
/// `None` on harvest-only runs — no behavior change there).
#[derive(Debug, Clone, Default)]
pub struct TraversalCapture {
    pub provenance: Option<TripleProvenance>,
    pub done: Vec<WalkDone>,
    pub findings: Vec<Finding>,
    pub polls: u64,
    /// Cumulative storm-cut observations, rounds plus the close
    /// drain (P1: feeds the `traversal.storm` typed gap).
    pub storm_polls: u64,
    /// Cumulative throttle observations, rounds plus the close
    /// drain (P1: feeds the `traversal.throttled` typed gap).
    pub throttled_polls: u64,
    /// Backend throttled (SKIP_ALL) at the final drain.
    pub throttled: bool,
    /// Backend detached (tier-3 storm) at the final drain.
    pub detached: bool,
    /// The final tail drain failed (records kept are the
    /// drained-so-far prefix — proved facts, H7).
    pub finish_error: Option<String>,
    /// Pending post-drain corrections (rewrites for already-held
    /// verdicts — applied by [`TraversalCapture::merge`], never
    /// left standing).
    pub corrections: Vec<crate::scan::oracle::Correction>,
    /// Latest admitted-query census snapshot (per op): honest
    /// observation metadata (loss-independent — record count
    /// is not a census; never billed into executions).
    pub admitted_by_op: BTreeMap<u32, u64>,
    /// Ops observed (records retained) but missing from the
    /// census while increments were lost: UNKNOWN, never zero
    /// (unioned across polls — keys never un-observe).
    pub admitted_unknown_by_op: BTreeSet<u32>,
    /// Cumulative admitted-increment loss (CALLS map pressure).
    pub census_loss: u64,
}

impl TraversalCapture {
    /// Merge a later drain (finish tail) into the accumulated
    /// outcome: records append, end-state flags refresh,
    /// provenance/finish-error fill once, then pending
    /// corrections rewrite held verdicts by key.
    fn merge(&mut self, tail: TraversalCapture) {
        self.done.extend(tail.done);
        self.findings.extend(tail.findings);
        apply_corrections(&mut self.done, &tail.corrections);
        // Census snapshots are cumulative (never shrink): the
        // latest non-empty snapshot wins; an empty tail (no poll)
        // keeps the accumulated one. Unknown-flags union and
        // census loss keeps its high-water (same monotonicity).
        if !tail.admitted_by_op.is_empty() {
            self.admitted_by_op = tail.admitted_by_op;
        }
        self.admitted_unknown_by_op
            .extend(tail.admitted_unknown_by_op);
        self.census_loss = self.census_loss.max(tail.census_loss);
        self.polls += tail.polls;
        // P1: typed gate observations union (cumulative, never
        // shrink — same monotonicity as the census); end-state
        // gates still in force at the close drain count as
        // observations (the close drain is a poll).
        self.storm_polls += tail.storm_polls + u64::from(tail.detached);
        self.throttled_polls += tail.throttled_polls + u64::from(tail.throttled);
        self.throttled = tail.throttled;
        self.detached = tail.detached;
        if self.provenance.is_none() {
            self.provenance = tail.provenance;
        }
        if self.finish_error.is_none() {
            self.finish_error = tail.finish_error;
        }
    }
}

/// §4 gap counters (PRD key = TOTAL; `_bpf`/`_userspace` the split).
#[derive(Debug, Clone, Default)]
pub struct Counters {
    pub dropped_bpf: u64,
    pub dropped_userspace: u64,
    pub missed_attaches: u64,
    pub unresolved_offsets: u64,
    pub table_staleness_events: u64,
    pub cold_gap_calls: u64,
    pub provider_changed: u64,
    pub scan_budget_exhaustions: u64,
    pub engine_fallback_uninstrumented: u64,
    pub drain_shortfall: u64,
    pub uninstrumented_ops: u64,
    pub fork_exec_ignored: u64,
    /// Windows expired while the target lived (0/1): post-window
    /// executions unobserved — over-budget PARTIAL (P2 exit-3).
    pub over_budget: u64,
}

/// One counted identity (current generation, all CPUs folded).
#[derive(Debug, Clone)]
pub struct Execution {
    pub cookie: u32,
    pub id: plan::Identity,
    pub aliases: Vec<plan::Identity>,
    pub count: u64,
    pub first_ns: u64,
    pub last_ns: u64,
}

/// One fenced key's conserved counts (§3 extension: per-key detail
/// rides WITH the aggregate so exit-2 conservation joins per
/// identity instead of trusting bare totals).
#[derive(Debug, Clone)]
pub struct StaleDetail {
    pub cookie: u32,
    pub id: plan::Identity,
    pub count: u64,
    pub first_ns: u64,
    pub last_ns: u64,
}

/// Fenced generation's counts (aggregate with the generation label, §3).
#[derive(Debug, Clone)]
pub struct StaleBucket {
    pub generation: u32,
    pub events: u64,
    pub keys: u64,
    pub detail: Vec<StaleDetail>,
}

/// Finished capture window.
#[derive(Debug, Clone)]
pub struct Capture {
    pub target_pid: u32,
    pub target_comm: String,
    pub window_planned: Duration,
    pub window_actual: Duration,
    pub outcome: Outcome,
    /// Compatibility reason strings (v0.2 R22 seam 2 — RETAINED):
    /// write-only diagnostics; production report/check consume
    /// the typed `document` gaps, and no decision reads these
    /// strings — so removal would churn test pins without
    /// removing any duplicate decision. The P1 typed gaps map
    /// back onto the same vocabulary (deduped, never
    /// double-reported).
    pub reasons: Vec<String>,
    pub executions: Vec<Execution>,
    pub stale: Vec<StaleBucket>,
    pub counters: Counters,
    /// Legacy child-exit carrier (v0.2 R22 seam 3 — RETAINED):
    /// live consumers in report/check (`workload_hint`,
    /// exit mapping) require it; removal fails the plan R22
    /// checkbox-1 gate (parity + zero consumers unproven).
    pub child_exit: Option<i32>,
    pub drain_wall_us: u64,
    pub harvest_doc: serde_json::Value,
    pub legacy: serde_json::Value,
    /// Window wall-clock edges (PRD §5 window-only claims): the
    /// ONE consistently captured pair (R12), shared verbatim with
    /// `document.context`. The start is the wall counterpart of the
    /// monotonic requested start (release for owned spawns,
    /// acquisition for `--pid`); the end is the single close sample
    /// taken alongside the effective-end stamp. Context only — the
    /// monotonic window fields stay authoritative. Pre-window FATAL
    /// captures carry the acquisition instant in both
    /// (window_actual == 0 marks "no window opened").
    pub window_start_wall: SystemTime,
    pub window_end_wall: SystemTime,
    pub kernel_release: String,
    pub target_cmdline: String,
    pub target_container_id: String,
    pub provider_build_id: String,
    pub provider_path: String,
    pub image_digest: String,
    /// Finalized v2 evidence document (T08 produces it; T10/T11
    /// rewire reports/policy onto it).
    pub document: CaptureDocument,
    /// End-of-observation target disposition (T04 custody): exit
    /// status preserved, or the detached pid that was left running.
    /// `None` for foreign `--pid` targets that recycled mid-window.
    pub disposition: Option<target::TargetDisposition>,
    /// Traversal outcome (opt-in [`run_traversal`] runs only):
    /// resolved-triple provenance plus the drained per-invocation
    /// records. `None` on harvest-only runs.
    pub traversal: Option<TraversalCapture>,
}

/// Minimal document for test constructors outside this module (real
/// captures always carry the finalized document).
pub fn empty_document() -> CaptureDocument {
    evidence::finalize(FinalizeInput {
        window: CaptureWindow {
            requested_start_ns: 0,
            requested_end_ns: 0,
            effective_start_ns: 0,
            effective_end_ns: 0,
            signal_cut: false,
        },
        sites: Vec::new(),
        fenced: Vec::new(),
        objects: Vec::new(),
        coverage: Vec::new(),
        counters: Vec::new(),
        fatal: None,
        target: TargetRecord::unknown(),
        openssl: OpensslVersion::unknown(),
        disposition: None,
        policy: None,
        legacy_partition: LegacyCallPartition::default(),
        engine_observations: Vec::new(),
        traversal: None,
    })
}

/// v2 document target context: mirrors the legacy `Capture` target
/// fields exactly (settled comm plus container/image provenance;
/// never raw argv/cmdline).
fn doc_target(pid: u32, comm: &str, container_id: &str, image_digest: &str) -> TargetRecord {
    TargetRecord::new(
        pid,
        comm.to_string(),
        container_id.to_string(),
        image_digest.to_string(),
    )
}

/// Custody disposition → v2 document value. Foreign `--pid` finish
/// reports `Detached` ("left running, never signaled — documented,
/// not custody"), which the document records distinctly from an
/// owned detach (explicit ownership transfer). `None` (never
/// recorded, e.g. mid-window recycle) stays `None`.
fn doc_disposition(
    owned: bool,
    disposition: Option<&target::TargetDisposition>,
) -> Option<DispositionRecord> {
    match (owned, disposition) {
        (_, Some(target::TargetDisposition::Exited { code })) => {
            Some(DispositionRecord::exited(*code))
        }
        (true, Some(target::TargetDisposition::Detached { pid })) => {
            Some(DispositionRecord::detached_running(*pid))
        }
        (false, Some(target::TargetDisposition::Detached { pid })) => {
            Some(DispositionRecord::foreign_observed(*pid))
        }
        (_, None) => None,
    }
}

/// Wall-clock instant → unix nanoseconds for the v2 document
/// context (R12). Pre-epoch and unrepresentable instants are
/// explicit `None` (rendered JSON `null`), never a fabricated
/// zero; a backward-adjusted pair stays visible as-is, never
/// rewritten.
fn unix_ns(t: SystemTime) -> Option<u64> {
    u64::try_from(t.duration_since(SystemTime::UNIX_EPOCH).ok()?.as_nanos()).ok()
}

/// Execution context for the finalized document (R12): the
/// already-captured kernel release plus the ONE consistently
/// captured wall pair (requested-start counterpart + single close
/// sample — the same pair the enclosing Capture carries).
/// Monotonic window fields stay authoritative; this context never
/// feeds durations or deadlines.
fn doc_context(kernel_release: &str, start: SystemTime, end: SystemTime) -> CaptureContext {
    CaptureContext {
        kernel_release: kernel_release.to_string(),
        wall_start_unix_ns: unix_ns(start),
        wall_end_unix_ns: unix_ns(end),
    }
}

/// Legacy provider file identities for the H8 call partition: the
/// (device, inode) pairs of advertised objects whose id matches the
/// run's pinned provider, and only when the pin's class is legacy.
/// Empty in every other run (nothing partitions legacy) — notably
/// when no provider is pinned at all. Pure identity join (H5 stat
/// domain both sides); pathnames never consulted.
fn legacy_files_for(
    pinned: Option<&PinnedProvider>,
    objects: &[ObjectRecord],
) -> HashSet<(u64, u64)> {
    let Some(pin) = pinned else {
        return HashSet::new();
    };
    if pin.class != legacy::LEGACY_PROVIDER_CLASS {
        return HashSet::new();
    }
    objects
        .iter()
        .filter(|o| o.id.0 == pin.object)
        .map(|o| (o.device, o.inode))
        .collect()
}

/// Legacy call partition (H8/A-8) over current plus fenced sites: a
/// site counts legacy-exclusive iff ALL its candidates are
/// legacy-class AND its backing (device, inode) is in
/// `legacy_files`; any legacy candidate short of that (mixed
/// classes, or all-legacy backed by a foreign file such as shared
/// libcrypto) lands shared-ambiguous; sites with no legacy
/// candidate land non-legacy-exclusive; sites with no candidates at
/// all land unfenced-tails (no partition key exists). Conserves
/// exactly: the four buckets sum to every counted call.
fn partition_calls(
    current: &[SiteExecution],
    fenced: &[FencedGeneration],
    legacy_files: &HashSet<(u64, u64)>,
) -> legacy::CallPartition {
    let mut out = legacy::CallPartition::default();
    let mut one = |site: &SiteExecution| {
        if site.candidates.is_empty() {
            out.unfenced_tails = out.unfenced_tails.saturating_add(site.calls);
        } else if site
            .candidates
            .iter()
            .all(|c| c.provider_class == legacy::LEGACY_PROVIDER_CLASS)
            && legacy_files.contains(&(site.site.device, site.site.inode))
        {
            out.legacy_exclusive = out.legacy_exclusive.saturating_add(site.calls);
        } else if site
            .candidates
            .iter()
            .any(|c| c.provider_class == legacy::LEGACY_PROVIDER_CLASS)
        {
            out.shared_ambiguous = out.shared_ambiguous.saturating_add(site.calls);
        } else {
            out.non_legacy_exclusive = out.non_legacy_exclusive.saturating_add(site.calls);
        }
    };
    for site in current {
        one(site);
    }
    for generation in fenced {
        for site in &generation.sites {
            one(site);
        }
    }
    out
}

/// Map the discovery-side partition onto the evidence document
/// shape (same four buckets, same conservation).
fn evidence_partition(p: legacy::CallPartition) -> LegacyCallPartition {
    LegacyCallPartition {
        legacy_exclusive: p.legacy_exclusive,
        non_legacy_exclusive: p.non_legacy_exclusive,
        shared_ambiguous: p.shared_ambiguous,
        unfenced_tails: p.unfenced_tails,
    }
}

// ---------------------------------------------------------------- signals

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: libc::c_int) {
    INTERRUPTED.store(true, Ordering::Relaxed);
}

fn arm_signals() {
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as libc::sighandler_t);
    }
}

fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------- ports
//
// The controller drives sessions, target custody, lifecycle, time
// and /proc reads through these ports. Live wiring sits beside each
// trait; `tests/capture_controller.rs` scripts fakes behind the same
// contracts (injected clock, failing I/O, no sleeps).

/// Persistent discovery engine, held for the complete observation.
pub trait DiscoveryPort {
    fn poll(&mut self, budget: PollBudget) -> anyhow::Result<DiscoveryDelta>;
    fn snapshot(&self) -> DiscoverySnapshot;
    /// Quiesce-then-PROCESS teardown: exact tail accounting for the
    /// final drain. Called once, at close.
    fn finish(&mut self) -> anyhow::Result<DiscoverySnapshot>;
    /// Traversal backend poll (same cadence as [`DiscoveryPort::poll`];
    /// `baseline` drains the setup slice and fences pre-window opens —
    /// same seed-then-discard discipline as the discovery baseline).
    /// Harvest-only ports keep the default (inactive, empty delta).
    fn poll_traversal(&mut self, _baseline: bool) -> anyhow::Result<TraversalDelta> {
        Ok(TraversalDelta::default())
    }
    /// Traversal tail drain at close (infallible: a failed tail
    /// drain rides inside as `finish_error`, never fails teardown).
    fn finish_traversal(&mut self) -> TraversalCapture {
        TraversalCapture::default()
    }
    /// Whether this port carries a live traversal backend (the
    /// Runner retains a [`TraversalCapture`] only then).
    fn traversal_active(&self) -> bool {
        false
    }
    /// Provider turnover fence (the backend retires its GEN/cache
    /// epoch with the discovery generation; harvest-only ports
    /// no-op).
    fn note_provider_turnover(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Live discovery engine behind the port: `DiscoverySession::close`
/// consumes, so the wrapper holds it by option and takes it at
/// finish (RAII detaches on the drop paths).
pub struct LiveDiscovery(Option<DiscoverySession>);

impl LiveDiscovery {
    pub fn new(session: DiscoverySession) -> Self {
        Self(Some(session))
    }
}

impl DiscoveryPort for LiveDiscovery {
    fn poll(&mut self, budget: PollBudget) -> anyhow::Result<DiscoveryDelta> {
        match self.0.as_mut() {
            Some(session) => session.poll(budget),
            None => anyhow::bail!("discovery session already finished"),
        }
    }

    fn snapshot(&self) -> DiscoverySnapshot {
        match self.0.as_ref() {
            Some(session) => session.snapshot(),
            None => DiscoverySnapshot::default(),
        }
    }

    fn finish(&mut self) -> anyhow::Result<DiscoverySnapshot> {
        match self.0.take() {
            Some(session) => session.close(),
            None => anyhow::bail!("discovery session already finished"),
        }
    }
}

/// Storm/throttle gate flags one traversal poll earned: the typed
/// form of the `traversal-storm` / `traversal-throttled` reasons
/// (P1 — feeds the finalizer). Matches the same backend actions
/// as [`traversal_reasons`] by construction; the agreement test
/// below pins them together.
fn traversal_gate_flags(actions: &[ScanAction]) -> (bool, bool) {
    (
        actions.iter().any(|a| matches!(a, ScanAction::Detached)),
        actions
            .iter()
            .any(|a| matches!(a, ScanAction::SkipAllEngaged)),
    )
}

/// PARTIAL reasons one traversal poll earned: a storm detach cut
/// observation (`traversal-storm`), the tier-2 throttle skipped
/// queries (`traversal-throttled`), an invocation closed
/// incomplete (`traversal-incomplete`), a record never joined
/// (`traversal-unjoined`). Reattach/release/warm actions are
/// recovery, never loss.
fn traversal_reasons(
    actions: &[ScanAction],
    done: &[WalkDone],
    findings: &[Finding],
) -> Vec<String> {
    let mut reasons = Vec::new();
    if actions.iter().any(|a| matches!(a, ScanAction::Detached)) {
        reasons.push("traversal-storm".to_string());
    }
    if actions
        .iter()
        .any(|a| matches!(a, ScanAction::SkipAllEngaged))
    {
        reasons.push("traversal-throttled".to_string());
    }
    if done
        .iter()
        .any(|w| !matches!(w.outcome, ScanOutcome::Complete { .. }))
    {
        reasons.push("traversal-incomplete".to_string());
    }
    if !findings.is_empty() {
        reasons.push("traversal-unjoined".to_string());
    }
    reasons
}

/// Live discovery engine with an attached traversal backend
/// (opt-in [`run_traversal`] runs): harvest polling delegates to
/// the inner session; traversal polls register the target's live
/// tids (a vanished `/proc/<pid>/task` drains the tail against an
/// empty set — a dead target grows no tids) and drain the members
/// ring through the production backend.
pub struct LiveTraversalDiscovery {
    inner: LiveDiscovery,
    backend: ScanBackend,
    tasks: crate::scan::registry::ProcTaskSource,
    provenance: TripleProvenance,
}

impl LiveTraversalDiscovery {
    pub fn new(
        session: DiscoverySession,
        backend: ScanBackend,
        pid: u32,
        provenance: TripleProvenance,
    ) -> Self {
        Self {
            inner: LiveDiscovery::new(session),
            backend,
            tasks: crate::scan::registry::ProcTaskSource::new(pid),
            provenance,
        }
    }
}

impl DiscoveryPort for LiveTraversalDiscovery {
    fn poll(&mut self, budget: PollBudget) -> anyhow::Result<DiscoveryDelta> {
        self.inner.poll(budget)
    }

    fn snapshot(&self) -> DiscoverySnapshot {
        self.inner.snapshot()
    }

    fn finish(&mut self) -> anyhow::Result<DiscoverySnapshot> {
        self.inner.finish()
    }

    fn poll_traversal(&mut self, baseline: bool) -> anyhow::Result<TraversalDelta> {
        use std::io::ErrorKind;
        let tids = match self.tasks.tids() {
            Ok(tids) => tids,
            Err(e) if e.kind() == ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e).context("enumerate target tasks"),
        };
        // BIRTH registration failure is a HARD error (the run
        // fails loud, never silently unregistered).
        self.backend.register(&tids)?;
        if baseline {
            // Seed-then-discard (fence order lives in the
            // backend — pre-window news never becomes
            // in-window evidence).
            self.backend.baseline()?;
            return Ok(TraversalDelta::default());
        }
        let delta = self.backend.poll()?;
        let reasons = traversal_reasons(&delta.actions, &delta.done, &delta.findings);
        let (storm, throttled) = traversal_gate_flags(&delta.actions);
        Ok(TraversalDelta {
            done: delta.done,
            findings: delta.findings,
            partial_reasons: reasons,
            polls: 1,
            corrections: delta.corrections,
            admitted: delta.admitted,
            admitted_unknown: delta.admitted_unknown,
            census_loss: delta.census_loss,
            storm,
            throttled,
        })
    }

    fn finish_traversal(&mut self) -> TraversalCapture {
        let mut out = TraversalCapture {
            provenance: Some(self.provenance.clone()),
            polls: 1,
            ..TraversalCapture::default()
        };
        // Settle + backstop (trailing queries close here —
        // RET-joined evaluate, RET-less dangle — never dropped).
        match self.backend.finish() {
            Ok(delta) => {
                out.done = delta.done;
                out.findings = delta.findings;
                out.corrections = delta.corrections;
                out.admitted_by_op = delta.admitted;
                out.admitted_unknown_by_op = delta.admitted_unknown;
                out.census_loss = delta.census_loss;
            }
            Err(e) => {
                out.finish_error = Some(format!("{e:#}"));
                let (done, findings) = self.backend.take_completed();
                out.done = done;
                out.findings = findings;
                // Salvage corrections too (pending rewrites for
                // already-held verdicts — the merge below
                // applies them; dropping them would strand a
                // false verdict while saving everything else).
                out.corrections = self.backend.take_corrections();
                // R34/I1: the census does not default on the
                // failure path — propagate the backend's loss
                // high-water + unknown set over the salvaged
                // records, so uncounted ops render with their
                // known loss.
                let (admitted, unknown, loss) = self.backend.salvage_census(&out.done);
                out.admitted_by_op = admitted;
                out.admitted_unknown_by_op = unknown;
                out.census_loss = loss;
            }
        }
        let snap = self.backend.snapshot();
        out.throttled = snap.throttled;
        out.detached = snap.detached;
        out
    }

    fn traversal_active(&self) -> bool {
        true
    }

    fn note_provider_turnover(&mut self) -> anyhow::Result<()> {
        self.backend.note_provider_turnover()
    }
}

/// Discovery engine behind the port: harvest-only by default,
/// traversal-carrying on opt-in runs. One concrete type keeps
/// [`SessionSet`] and [`observe`] unchanged for every caller.
pub enum CaptureDiscovery {
    HarvestOnly(Box<LiveDiscovery>),
    Traversal(Box<LiveTraversalDiscovery>),
}

impl DiscoveryPort for CaptureDiscovery {
    fn poll(&mut self, budget: PollBudget) -> anyhow::Result<DiscoveryDelta> {
        match self {
            CaptureDiscovery::HarvestOnly(d) => d.poll(budget),
            CaptureDiscovery::Traversal(d) => d.poll(budget),
        }
    }

    fn snapshot(&self) -> DiscoverySnapshot {
        match self {
            CaptureDiscovery::HarvestOnly(d) => d.snapshot(),
            CaptureDiscovery::Traversal(d) => d.snapshot(),
        }
    }

    fn finish(&mut self) -> anyhow::Result<DiscoverySnapshot> {
        match self {
            CaptureDiscovery::HarvestOnly(d) => d.finish(),
            CaptureDiscovery::Traversal(d) => d.finish(),
        }
    }

    fn poll_traversal(&mut self, baseline: bool) -> anyhow::Result<TraversalDelta> {
        match self {
            CaptureDiscovery::HarvestOnly(d) => d.poll_traversal(baseline),
            CaptureDiscovery::Traversal(d) => d.poll_traversal(baseline),
        }
    }

    fn finish_traversal(&mut self) -> TraversalCapture {
        match self {
            CaptureDiscovery::HarvestOnly(d) => d.finish_traversal(),
            CaptureDiscovery::Traversal(d) => d.finish_traversal(),
        }
    }

    fn traversal_active(&self) -> bool {
        match self {
            CaptureDiscovery::HarvestOnly(d) => d.traversal_active(),
            CaptureDiscovery::Traversal(d) => d.traversal_active(),
        }
    }

    fn note_provider_turnover(&mut self) -> anyhow::Result<()> {
        match self {
            CaptureDiscovery::HarvestOnly(d) => d.note_provider_turnover(),
            CaptureDiscovery::Traversal(d) => d.note_provider_turnover(),
        }
    }
}

/// Observed target custody (T04). Owned children move through
/// stopped → released → reaped/detached; foreign `--pid` targets are
/// pinned and never signaled or waited on.
pub trait TargetPort {
    fn pid(&self) -> u32;
    fn is_owned(&self) -> bool;
    /// Release a stopped owned child (strictly once); a foreign
    /// target ignores this (never signaled).
    fn release(&mut self) -> anyhow::Result<()>;
    /// Non-blocking exit poll: `Ok(None)` = alive. Foreign targets
    /// are never waited on and always answer `None`.
    fn poll_exit(&mut self) -> anyhow::Result<Option<i32>>;
    /// Resolve custody after a setup failure (never leaves a stopped
    /// child; never kills a running application).
    fn resolve_setup_failure(&mut self) -> anyhow::Result<()>;
    /// End-of-observation disposition: reaped status or detached pid.
    fn finish_observation(&mut self) -> anyhow::Result<target::TargetDisposition>;
    /// Identity intact (foreign pin check; owned targets are
    /// waitpid-owned and always answer `Ok`).
    fn verify(&self) -> anyhow::Result<()>;
}

impl TargetPort for target::OwnedTarget {
    fn pid(&self) -> u32 {
        target::OwnedTarget::pid(self)
    }

    fn is_owned(&self) -> bool {
        true
    }

    fn release(&mut self) -> anyhow::Result<()> {
        target::OwnedTarget::release(self)
    }

    fn poll_exit(&mut self) -> anyhow::Result<Option<i32>> {
        target::OwnedTarget::poll_exit(self)
    }

    fn resolve_setup_failure(&mut self) -> anyhow::Result<()> {
        target::OwnedTarget::resolve_setup_failure(self)
    }

    fn finish_observation(&mut self) -> anyhow::Result<target::TargetDisposition> {
        target::OwnedTarget::finish_observation(self)
    }

    fn verify(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

/// A foreign `--pid` target: pinned identity, no custody. Every
/// signal/wait path is a deliberate no-op; liveness is the pin.
pub struct PinnedTarget {
    pid: u32,
    pin: pin::TargetPin,
}

impl PinnedTarget {
    pub fn new(pid: u32, pin: pin::TargetPin) -> Self {
        Self { pid, pin }
    }
}

impl TargetPort for PinnedTarget {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn is_owned(&self) -> bool {
        false
    }

    fn release(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    fn poll_exit(&mut self) -> anyhow::Result<Option<i32>> {
        Ok(None)
    }

    fn resolve_setup_failure(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    fn finish_observation(&mut self) -> anyhow::Result<target::TargetDisposition> {
        // Never owned: "detached" here means left running and never
        // signaled (documented, not custody).
        Ok(target::TargetDisposition::Detached { pid: self.pid })
    }

    fn verify(&self) -> anyhow::Result<()> {
        self.pin.verify().map_err(|e| anyhow::anyhow!("{e}"))
    }
}

/// One ignored fork/exec event: detected and explained, never
/// captured (no multi-target capture).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleKind {
    Fork,
    Exec,
}

/// One ignored child/sibling lifecycle event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleEvent {
    pub kind: LifecycleKind,
    pub pid: u32,
}

/// One lifecycle poll: new events plus scan loss (failed /proc
/// reads that may have missed activity) plus kernel-side signal
/// drops (the kernel producer's own overflow count between drains,
/// as reported through the port — distinct from host scan loss so
/// the two sources stay attributable) plus the bounded-drain
/// residual (records still queued when the drain stopped).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LifecycleDelta {
    pub events: Vec<LifecycleEvent>,
    pub loss: u64,
    /// Kernel-side signals known-dropped (proven seq holes plus the
    /// socket Drops delta; the ENOBUFS-unmoved at-least-one at the
    /// drain also lands here and stays documented there). Zero for
    /// ports with no kernel producer (polling). Conservative
    /// first-sighting prefix gaps are NOT counted here — see
    /// `prefix_unwitnessed`.
    pub dropped: u64,
    /// Kernel-side signals conservatively unwitnessed (prefix gaps
    /// on post-activity first sightings): at-least-one per CPU with
    /// an ungapped prefix — NEVER read as a proven transport-drop
    /// count. Rendered as `lifecycle.signal_prefix_unwitnessed`
    /// Loss; blocks COMPLETE exactly like proven drops.
    pub prefix_unwitnessed: u64,
    /// Bounded-drain residual: nonzero when this drain stopped
    /// with records still queued (1 = tail remains; the exact
    /// queued depth is transport-specific, so presence — not a
    /// count — is the contract). Round sweeps carry the residual
    /// losslessly (the next round continues the same queue); at
    /// close it is an uncovered tail and the controller records
    /// `lifecycle.drain_pending` loss. Always zero for polling
    /// ports (their close drain is `None` — absence, not a
    /// truncated drain).
    pub pending: u64,
}

/// Short fork/exec + lifecycle-loss observer. The T08 selection is
/// the EXPLICIT PARTIAL polling fallback: `fallback_partial()` is
/// true, and the controller records the `lifecycle.polling_fallback`
/// loss on every observation using it, because polling alone cannot
/// prove no short-lived activity occurred between scans.
pub trait LifecyclePort {
    fn poll(&mut self) -> LifecycleDelta;
    fn fallback_partial(&self) -> bool;
    /// Close-time signal-ring drain for kernel-signal ports: consume
    /// the ring through the current tail at window close, even when
    /// the target already exited (a ring drain needs no /proc scan,
    /// so it is safe on corpses). Polling ports return `None`: their
    /// close-time sweep stays skipped once the child is reaped (there
    /// is nothing to scan but the sweep's own unreadable-exe loss).
    fn close_drain(&mut self) -> Option<LifecycleDelta> {
        None
    }
    /// Mark the owned target released (R20-fix round 3, F2): from
    /// here on the target can emit, so per-CPU first sightings gap
    /// their unwitnessed prefix instead of baselining silently.
    /// The runner calls this once, right after a successful owned
    /// release; live targets (`--pid`) subscribe already released.
    /// No-op except for kernel-signal ports.
    fn mark_released(&mut self) {}
}

/// Parse (pid, ppid) from a `/proc/<pid>/stat` line; comm may hold
/// spaces and ')' — ppid is post-comm token 1 (after the LAST ')').
fn parse_stat_ppid(stat: &str) -> Option<(u32, u32)> {
    let (pid_s, rest) = stat.split_once(' ')?;
    let pid = pid_s.parse().ok()?;
    let after = rest.rsplit_once(')')?.1;
    let mut it = after.split_whitespace();
    it.next()?; // state
    let ppid = it.next()?.parse().ok()?;
    Some((pid, ppid))
}

/// Live pids whose parent is `target` (fork/exec detection, §7).
/// Poll-granularity residual: children living entirely between two
/// scans are missed — the polling fallback is explicitly PARTIAL.
pub fn children_of(target: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return out;
    };
    for e in rd.flatten() {
        let s = e.file_name().to_string_lossy().into_owned();
        if s.parse::<u32>().is_err() {
            continue;
        }
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{s}/stat")) else {
            continue;
        };
        if let Some((pid, ppid)) = parse_stat_ppid(&stat) {
            if ppid == target {
                out.push(pid);
            }
        }
    }
    out.sort_unstable();
    out
}

/// Process-group id of `pid` from `/proc/<pid>/status` (`Tgid:`):
/// a same-TGID clone is thread creation, not an ignored process.
fn tgid_of(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Tgid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Polling lifecycle fallback (explicit PARTIAL): ppid scans for
/// forked children plus an exe-link watch for same-TGID exec of the
/// target itself. Every NEW child counts once (a double-fork that
/// reparents away stays counted); same-TGID clones never count.
pub struct PollingLifecycle {
    target: u32,
    seen: HashSet<u32>,
    exe: Option<PathBuf>,
}

impl PollingLifecycle {
    pub fn new(target: u32) -> Self {
        let exe = std::fs::read_link(format!("/proc/{target}/exe")).ok();
        Self {
            target,
            seen: HashSet::new(),
            exe,
        }
    }
}

impl LifecyclePort for PollingLifecycle {
    fn poll(&mut self) -> LifecycleDelta {
        let mut delta = LifecycleDelta::default();
        if std::fs::read_dir("/proc").is_err() {
            // The scan itself failed: activity may have been missed.
            delta.loss += 1;
            return delta;
        }
        for kid in children_of(self.target) {
            if !self.seen.insert(kid) {
                continue;
            }
            // Same-TGID clone (thread creation) is not an ignored
            // process. Unreadable Tgid fails closed to Fork: a child
            // that vanished mid-scan is still ignored activity.
            let is_thread = tgid_of(kid).is_some_and(|tg| tg == self.target);
            if !is_thread {
                delta.events.push(LifecycleEvent {
                    kind: LifecycleKind::Fork,
                    pid: kid,
                });
            }
        }
        match std::fs::read_link(format!("/proc/{}/exe", self.target)) {
            Ok(exe) => {
                if self.exe.as_ref() != Some(&exe) {
                    self.exe = Some(exe);
                    delta.events.push(LifecycleEvent {
                        kind: LifecycleKind::Exec,
                        pid: self.target,
                    });
                }
            }
            Err(_) => {
                // The target may be exiting (its exe link is gone);
                // the controller's custody check owns that verdict —
                // here it is only scan loss when unreadable.
                delta.loss += 1;
            }
        }
        delta
    }

    fn fallback_partial(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Kernel-observed lifecycle (proc connector, R20-fix finding 1).
//
// The kernel pushes fork/exec/exit (plus uids/gids/sids/ptrace/comm/
// coredump, which carry no execution information and are ignored)
// over a dedicated NETLINK_CONNECTOR socket: sub-poll activity that
// no /proc snapshot can catch is queued by the kernel and drained
// here. Identity is (pid, tgid) per event filtered to the target
// subtree; loss accounting is exact (socket Drops delta — every
// overrun the kernel counted) with an in-band ENOBUFS tripwire.
//
// COMPLETE-capable when: subscribed before first activity (owned
// children are stopped pre-exec at subscribe time, so this holds
// structurally), drops-delta zero, and the close drain reaches an
// empty tail. Anything else degrades loud (scan loss, signal
// drops, no-witness, drain-pending) — never silent, never polling.
//

/// Proc-connector group: process events.
const CN_IDX_PROC: u32 = 1;
/// Proc-connector commands: subscribe / unsubscribe (uapi
/// `proc_cn_mcast_op` — IGNORE is 2, not 0; 0 hits `default: EINVAL`
/// and unsubscribes nothing).
const PROC_CN_MCAST_LISTEN: u32 = 1;
const PROC_CN_MCAST_IGNORE: u32 = 2;
/// Proc-connector event value (numerically 1, like the listen
/// command above — a distinct constant for readability).
const CN_VAL_PROC: u32 = 1;
/// `proc_event.what` values we consume (fork/exec/exit create or
/// replace executing code; every other value is ignored — see
/// [`KernelLifecycle::ingest_cn`]).
const PROC_EVENT_FORK: u32 = 1;
const PROC_EVENT_EXEC: u32 = 2;
const PROC_EVENT_EXIT: u32 = 0x8000_0000;
/// Connector acknowledgement marker (uapi `proc_cn_event`): the
/// kernel answers (un)subscribe with a `PROC_EVENT_NONE` message
/// whose `event_data.ack.err` (first union u32, positive errno,
/// 0 = accepted) is the registration verdict. Namespaces the kernel
/// ignores answer with NOTHING (silence, not an error ack).
const PROC_EVENT_NONE: u32 = 0;
/// Netlink message header length + ACK/error type. Note the
/// connector marks event datagrams `NLMSG_DONE` (3, verified live)
/// — every non-error message on this dedicated socket is a
/// connector payload (the `cn_msg` idx/val check inside is the
/// real gatekeeper).
const NLMSG_HDRLEN: usize = 16;
const NLMSG_ERROR: u16 = 2;
/// Connector message header length (`cn_msg` without payload).
const CN_HDRLEN: usize = 20;
/// `cn_msg` field offsets (uapi `struct cn_msg`: idx, val, seq, ack,
/// len, flags): seq carries the kernel's per-CPU continuity counter,
/// ack the (un)subscribe correlation echo.
const CN_SEQ_OFF: usize = 8;
const CN_ACK_OFF: usize = 12;
/// `proc_event` fixed prefix (`what`, `cpu`, `timestamp_ns`) length.
const PROC_EVENT_HDRLEN: usize = 16;
/// `proc_event.cpu` offset (the seq counter's per-CPU lane).
const PROC_EVENT_CPU_OFF: usize = 4;
/// Bounded drain: datagrams consumed per `poll` / per close round.
/// Fork/exec/exit are rare (a quiet window drains in one call);
/// the cap bounds poll latency under system-wide fork storms, and
/// the residual reports via `pending` (carried across rounds,
/// loud at close).
const MAX_LIFECYCLE_DRAIN: usize = 256;
/// Close-drain loop rounds (4 × 256): a quiet tail empties on the
/// first round; only sustained arrivals past 1024 datagrams leave
/// a `pending` residual (explicit drain-pending loss).
const CLOSE_DRAIN_ROUNDS: u32 = 4;
/// Socket receive buffer target (best-effort: uncapped kernels
/// clamp it; drops stay exactly accounted either way).
const CONNECTOR_RCVBUF: libc::c_int = 1 << 20;
/// Bounded subscription-acceptance wait: the kernel acks LISTEN via
/// workqueue multicast (millisecond-scale); silence past this bound
/// (ignored namespace, lost ack) fails the subscribe — never an
/// assumed-clean witness.
const SUBSCRIBE_ACK_TIMEOUT: Duration = Duration::from_secs(2);
/// Subscribe-wait stash caps (datagrams arriving before the ack are
/// witnesses, never dropped — ingested in arrival order by the
/// subscribe drain): a storm past either cap bails to loud fallback
/// instead of an unwitnessable prefix.
const SUBSCRIBE_STASH_MAX_MSGS: usize = 256;
const SUBSCRIBE_STASH_MAX_BYTES: usize = 4 << 20;
/// Bounded wait for per-CPU watermark successors (R20-fix round 3,
/// F2): fork/exit delivery is local and millisecond-scale; silence
/// past this bound is an unwitnessed watermark (explicit loss),
/// never an assumed-clean baseline or suffix.
const SYNC_WATERMARK_TIMEOUT: Duration = Duration::from_secs(2);

fn le_u32_at(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .and_then(|w| w.try_into().ok())
        .map(u32::from_le_bytes)
}

fn le_i32_at(b: &[u8], off: usize) -> Option<i32> {
    b.get(off..off + 4)
        .and_then(|w| w.try_into().ok())
        .map(i32::from_le_bytes)
}

/// Exact kernel-side drops for one netlink socket, via its
/// `/proc/net/netlink` row (matched by socket inode): the Drops
/// column counts every overrun the kernel took on that socket
/// (verified live: a 400-fork flood against a 4KiB buffer reports
/// exactly 812). `None` when the table is unreadable or the socket
/// is absent — the caller fails closed (loss, never assumed zero).
fn socket_drops(sock_inode: u64) -> Option<u64> {
    let text = std::fs::read_to_string("/proc/net/netlink").ok()?;
    parse_netlink_drops(&text, sock_inode)
}

fn parse_netlink_drops(text: &str, sock_inode: u64) -> Option<u64> {
    // Columns: sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode.
    let want = sock_inode.to_string();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() > 9 && f[9] == want {
            return f[8].parse().ok();
        }
    }
    None
}

/// True when `fd` has queued input bytes (nonempty tail).
/// ioctl failure fails closed to true.
fn socket_has_pending(fd: &OwnedFd) -> bool {
    let mut pending: libc::c_int = 0;
    let r = unsafe { libc::ioctl(fd.as_raw_fd(), libc::FIONREAD, &mut pending) };
    r != 0 || pending > 0
}

/// Distinct operation token per connector subscription
/// (R20-fix round 3, NEW-ACK): one shared process-ID token lets a
/// cooperating same-process socket's success satisfy another
/// subscription's acceptance wait (acks multicast to the whole
/// group). Tokens are process-unique by counter; the counter
/// starts from a pid/time mix so distinct processes don't share a
/// sequence either (a stale or foreign ack echoing another
/// token scans `Absent`, never satisfying our wait).
static ACK_TOKEN_COUNTER: LazyLock<AtomicU32> = LazyLock::new(|| {
    let seed =
        std::process::id().wrapping_mul(0x9E37_79B9) ^ (ClockPort::monotonic_ns(&LiveClock) as u32);
    AtomicU32::new(seed)
});

fn next_ack_token() -> u32 {
    ACK_TOKEN_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// One (un)subscribe request: nlmsghdr + cn_msg + bare u32 op (a
/// 4-byte payload makes the kernel treat the data as a bare
/// `proc_cn_mcast_op` with `ev_type = ALL` — unfiltered delivery).
/// `ack` is our correlation nonce (the kernel echoes ack+1 on its
/// NONE acknowledgement, distinguishing ours from other
/// subscribers' acks on the shared multicast group).
fn mcast_msg(op: u32, ack: u32) -> Vec<u8> {
    let mut msg = Vec::with_capacity(NLMSG_HDRLEN + CN_HDRLEN + 4);
    let total = (NLMSG_HDRLEN + CN_HDRLEN + 4) as u32;
    msg.extend_from_slice(&total.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());
    msg.extend_from_slice(&std::process::id().to_le_bytes());
    msg.extend_from_slice(&CN_IDX_PROC.to_le_bytes());
    msg.extend_from_slice(&CN_VAL_PROC.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());
    msg.extend_from_slice(&ack.to_le_bytes());
    msg.extend_from_slice(&4u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&op.to_le_bytes());
    msg
}

fn send_connector(fd: &OwnedFd, msg: &[u8]) -> anyhow::Result<()> {
    let sent = unsafe {
        libc::send(
            fd.as_raw_fd(),
            msg.as_ptr() as *const libc::c_void,
            msg.len(),
            0,
        )
    };
    if sent < 0 {
        anyhow::bail!("connector send: {}", std::io::Error::last_os_error());
    }
    if (sent as usize) != msg.len() {
        anyhow::bail!("connector short send ({sent} of {})", msg.len());
    }
    Ok(())
}

/// Per-CPU kernel sequence continuity: the kernel numbers every proc
/// message per sending CPU (`send_msg`, strictly +1 — including
/// ignored `what` values and NONE acks, which also consume a seq).
/// A hole is signals never received — pre-delivery allocation
/// failure (`GFP_NOWAIT` in `cn_netlink_send`) or socket overrun —
/// counted exact into `dropped` (kernel-side missing signals, the
/// same witness class as the socket Drops delta; one loss event may
/// appear in both counters — an upper bound, fail-closed, never an
/// under-count). A repeated or backward seq is a corrupt stream
/// (scan loss, no advance). First sightings baseline SILENTLY only
/// while the target provably cannot emit (`post_release == false` —
/// a stopped owned child at subscribe, where every predecessor is
/// a non-target signal); once activity is possible the unwitnessed
/// prefix gaps explicit (`dropped` at-least-one, fail-closed — a
/// fork lost before the first message leaves no Drops trace).
#[derive(Debug, Default)]
struct SeqState {
    last: HashMap<u32, u32>,
}

impl SeqState {
    fn observe(&mut self, cpu: u32, seq: u32, delta: &mut LifecycleDelta, post_release: bool) {
        let Some(prev) = self.last.get(&cpu).copied() else {
            self.last.insert(cpu, seq);
            if post_release {
                delta.prefix_unwitnessed = delta.prefix_unwitnessed.saturating_add(1);
            }
            return;
        };
        let step = seq.wrapping_sub(prev);
        if step == 1 {
            self.last.insert(cpu, seq);
        } else if step == 0 {
            delta.loss += 1;
        } else if step <= u32::MAX / 2 {
            delta.dropped = delta.dropped.saturating_add(u64::from(step) - 1);
            self.last.insert(cpu, seq);
        } else {
            delta.loss += 1;
        }
    }
}

/// Subscription-acceptance scan of one received datagram: our ack is
/// the NONE message echoing our correlation ack+1 (its err field is
/// the registration verdict); a nonzero NLMSG_ERROR is a transport
/// rejection. A transport error wins over a co-bundled ack
/// (fail-closed: the request path reported failure).
enum AckScan {
    Absent,
    Ours(u32),
    TransportError(i32),
}

fn scan_ack(buf: &[u8], our_ack: u32) -> AckScan {
    let mut off = 0usize;
    let mut ours = None;
    while off + NLMSG_HDRLEN <= buf.len() {
        let (Some(len), Some(typ)) = (
            le_u32_at(buf, off).map(|l| l as usize),
            le_u32_at(buf, off + 4).map(|t| t as u16),
        ) else {
            return AckScan::Absent;
        };
        if len < NLMSG_HDRLEN || off + len > buf.len() {
            return AckScan::Absent;
        }
        let body = &buf[off + NLMSG_HDRLEN..off + len];
        if typ == NLMSG_ERROR {
            match le_i32_at(body, 0) {
                Some(0) | None => {}
                Some(e) => return AckScan::TransportError(e),
            }
        } else if body.len() >= CN_HDRLEN + PROC_EVENT_HDRLEN
            && le_u32_at(body, 0) == Some(CN_IDX_PROC)
            && le_u32_at(body, 4) == Some(CN_VAL_PROC)
            && le_u32_at(body, CN_ACK_OFF) == Some(our_ack)
        {
            let ev = &body[CN_HDRLEN..];
            if le_u32_at(ev, 0) == Some(PROC_EVENT_NONE) {
                match le_u32_at(ev, PROC_EVENT_HDRLEN) {
                    // Malformed ack: unproven, keep waiting — the
                    // bound bails (a corrupt single ack must not
                    // manufacture acceptance).
                    None => {}
                    Some(err) => ours = Some(err),
                }
            }
        }
        off += (len + 3) & !3;
    }
    match ours {
        Some(err) => AckScan::Ours(err),
        None => AckScan::Absent,
    }
}

/// Drops-table fold: `(new_baseline, fresh_drops, blind)`. An
/// unreadable table is accounting blindness (loss, never assumed
/// zero); a first read after subscribe-time blindness re-anchors
/// WITHOUT backfilling (the blind interval's drops are unknowable —
/// the blindness loss already withholds COMPLETE).
fn drops_delta(baseline: Option<u64>, cur: Option<u64>) -> (Option<u64>, u64, bool) {
    match (baseline, cur) {
        (_, None) => (baseline, 0, true),
        (Some(b), Some(c)) => (Some(c), c.saturating_sub(b), false),
        (None, Some(c)) => (Some(c), 0, true),
    }
}

/// Per-CPU watermark watch (R20-fix round 3, F2; received-CPU
/// validation round 4): the burst forks one short-lived child per
/// online CPU (pinned, so its FORK lands on that CPU); each CPU
/// needs ≥1 sync message (its child's FORK or EXIT — either proves
/// the stream alive past the burst). Children stay unreaped until
/// after the await (a zombie pins its pid — no reuse race in
/// matching). A message marks the RECEIVED event's CPU — never the
/// helper's intended CPU: the kernel migrates tasks off a CPU
/// going offline, so a migrated helper's EXIT must not complete
/// another lane (its intended lane stays unwitnessed and gaps
/// honestly, while the arrival lane genuinely advanced past the
/// burst — either way the per-lane proof is exact).
struct SyncWatch {
    sought: HashMap<u32, u32>,
    lanes: HashSet<u32>,
    seen: HashSet<u32>,
}

impl SyncWatch {
    fn new(pids: &[(u32, u32)]) -> Self {
        Self {
            sought: pids.iter().copied().collect(),
            lanes: pids.iter().map(|(_, cpu)| *cpu).collect(),
            seen: HashSet::new(),
        }
    }

    fn note(&mut self, pid: u32, cpu: u32) {
        if self.sought.contains_key(&pid) && self.lanes.contains(&cpu) {
            self.seen.insert(cpu);
        }
    }

    fn complete(&self) -> bool {
        self.lanes.iter().all(|c| self.seen.contains(c))
    }

    fn sought_count(&self) -> u32 {
        self.sought.len() as u32
    }

    fn seen_count(&self) -> u32 {
        self.seen.len() as u32
    }
}

/// Online CPUs to watermark (0..n). Falls back to CPU 0 when the
/// count is unreadable (the burst still runs; unwatermarked CPUs
/// gap honestly — fail-closed).
fn online_cpus() -> Vec<u32> {
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if n <= 0 {
        return vec![0];
    }
    (0..n as u32).collect()
}

/// Close-time per-CPU watermark plan (R20-fix round 4, F2a): the
/// required lane set is preserved across the window (subscribe-time
/// ∪ close-time online), never rebuilt from the current online
/// count — a previously active CPU that went offline keeps its
/// required lane (gapped explicitly, never silently dropped).
/// `burst` covers the closable lanes (required ∩ current online —
/// newly-online CPUs join, so their suffix proves too); `offlined`
/// names required lanes no burst can close (topology gap).
#[derive(Debug, PartialEq, Eq)]
struct CloseCpuPlan {
    required: Vec<u32>,
    burst: Vec<u32>,
    offlined: Vec<u32>,
}

fn plan_close_cpus(subscribed: &[u32], current: &[u32]) -> CloseCpuPlan {
    let mut required: Vec<u32> = subscribed.to_vec();
    for c in current {
        if !required.contains(c) {
            required.push(*c);
        }
    }
    required.sort_unstable();
    let burst: Vec<u32> = required
        .iter()
        .copied()
        .filter(|c| current.contains(c))
        .collect();
    let offlined: Vec<u32> = required
        .iter()
        .copied()
        .filter(|c| !current.contains(c))
        .collect();
    CloseCpuPlan {
        required,
        burst,
        offlined,
    }
}

/// Fork one immediate-exit child per CPU, pinned in turn (R20-fix
/// round 3, F2): each CPU then delivers a watermark message on its
/// own lane. Returns the (pid, cpu) pairs plus a shortfall flag
/// (pin/fork/range failure — that CPU stays unwatermarked and its
/// prefix/suffix gaps honestly later). The caller's affinity mask
/// is restored before returning (every iteration and at the end).
/// Children must stay unreaped until their messages are awaited
/// (see [`SyncWatch`); reap with `reap_sync_children` after).
fn watermark_burst(cpus: &[u32]) -> (Vec<(u32, u32)>, bool) {
    let mut out = Vec::new();
    let mut shortfall = false;
    let mut saved: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut saved) != 0
    } {
        // No saved mask — pinning would be irreversible (the
        // thread could stick on one CPU). Fail closed: no burst,
        // honest gaps cover the unwatermarked CPUs.
        return (Vec::new(), true);
    }
    let restore = |saved: &libc::cpu_set_t| unsafe {
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), saved);
    };
    for &cpu in cpus {
        if cpu >= libc::CPU_SETSIZE as u32 {
            shortfall = true;
            continue;
        }
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::CPU_ZERO(&mut set);
            libc::CPU_SET(cpu as usize, &mut set);
        }
        if unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) } != 0
        {
            // Disallowed (container affinity) or offline CPU: no
            // watermark attainable from here.
            shortfall = true;
            continue;
        }
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            shortfall = true;
        } else if pid == 0 {
            unsafe { libc::_exit(0) };
        } else {
            out.push((pid as u32, cpu));
        }
        restore(&saved);
    }
    restore(&saved);
    (out, shortfall)
}

/// Graceful reap window for watermark children (R20-fix round
/// 4, NEW-1): helpers exit immediately, so this bound is generous
/// (normal reaps land on the first pass); a helper stopped before
/// `_exit` exhausts it and escalates to SIGKILL below instead of
/// blocking subscription or close indefinitely.
const SYNC_REAP_GRACE: Duration = Duration::from_secs(2);
/// Post-SIGKILL reap window: a SIGKILLed helper is already dead —
/// this only bounds the zombie's collection (essentially instant;
/// the bound is belt-and-braces against pid-namespace pathologies).
const SYNC_KILL_REAP_GRACE: Duration = Duration::from_secs(1);
/// Reap-poll nap between WNOHANG sweeps (bounded loops only —
/// every path below terminates at its deadline).
const SYNC_REAP_NAP: Duration = Duration::from_millis(5);

/// Reap watermark children — the bounded cleanup owner (after
/// their messages are awaited: EXIT is generated at exit, delivery
/// never waits for the reap). Grace window first (WNOHANG sweeps),
/// then SIGKILL escalation with its own bounded reap window for
/// leftovers (a helper stopped before `_exit` dies on SIGKILL —
/// stopped processes are killable). EINTR retries everywhere;
/// ECHILD means gone (reaped — done); any other wait error or a
/// survivor past both windows reports LOUD on stderr and gives up
/// (a stuck zombie is transient hygiene until process exit, never
/// an observation gap — and never an unbounded block). Worst-case
/// added latency per burst: grace + kill window (normal: instant).
fn reap_sync_children(pids: &[(u32, u32)]) {
    reap_sync_children_grace(pids, SYNC_REAP_GRACE, SYNC_KILL_REAP_GRACE)
}

/// Bounded reap with explicit windows (the production path above
/// delegates; tests drive short windows directly).
fn reap_sync_children_grace(pids: &[(u32, u32)], grace: Duration, kill_grace: Duration) {
    let mut pending: Vec<u32> = pids.iter().map(|(pid, _)| *pid).collect();
    reap_sweep(&mut pending, Instant::now() + grace);
    if pending.is_empty() {
        return;
    }
    for pid in &pending {
        // Best-effort: the child may have exited between the last
        // sweep and now (its reap lands in the window below, or
        // ECHILD there means another sweeper's wait won — but this
        // owner holds the only handle, so that is just the race).
        unsafe {
            libc::kill(*pid as libc::pid_t, libc::SIGKILL);
        }
    }
    reap_sweep(&mut pending, Instant::now() + kill_grace);
    if !pending.is_empty() {
        eprintln!(
            "lifecycle: watermark helper(s) survived SIGKILL+reap, giving up bounded: {pending:?}"
        );
    }
}

/// WNOHANG reap sweeps until `pending` empties or `deadline`
/// passes. EINTR retries; ECHILD counts as reaped; other errors
/// drop the pid loud (unreapable is hygiene, never a block).
fn reap_sweep(pending: &mut Vec<u32>, deadline: Instant) {
    while !pending.is_empty() && Instant::now() < deadline {
        pending.retain(|pid| {
            let mut status = 0;
            let r = unsafe { libc::waitpid(*pid as libc::pid_t, &mut status, libc::WNOHANG) };
            if r > 0 {
                return false;
            }
            if r == 0 {
                return true;
            }
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e == libc::EINTR {
                return true;
            }
            if e != libc::ECHILD {
                eprintln!("lifecycle: watermark reap of {pid} failed ({e}); giving up on it");
            }
            false
        });
        if !pending.is_empty() && Instant::now() < deadline {
            std::thread::sleep(SYNC_REAP_NAP);
        }
    }
}

/// Kernel-observed lifecycle port: fork/exec/exit pushed by the
/// kernel over NETLINK_CONNECTOR, filtered to the target subtree
/// (target tgid + fork-observed descendants; grandchildren join by
/// parentage, double-forks stay counted after reparenting).
/// Same-tgid clones are thread creation (non-events, like polling);
/// exits are non-events (never pruned — an EXIT never proves its
/// group dead); the target's own exit is custody's verdict.
/// Registration is balanced (Drop unsubscribes) and validated (the
/// kernel's NONE ack must accept before any witness is trusted).
/// Per-CPU sequence baselines establish pre-activity (a stopped
/// owned target cannot emit, so predecessors are provably
/// non-target) and every close carries a terminal per-CPU
/// watermark — prefix/suffix gaps are explicit, never silent.
pub struct KernelLifecycle {
    fd: OwnedFd,
    sock_inode: u64,
    target_pid: u32,
    target_tgid: u32,
    known: HashSet<u32>,
    seqs: SeqState,
    drops_baseline: Option<u64>,
    mcast_ack: u32,
    wait_enobufs: bool,
    subscribed_ns: u64,
    dead: bool,
    /// Target activity is possible (R20-fix round 3, F2): set at
    /// subscribe for live targets (`--pid`, probes) and by
    /// [`LifecyclePort::mark_released`] at owned release. While
    /// false the target is stopped pre-activity, so per-CPU first
    /// sightings baseline silently (predecessors provably
    /// non-target); once true they gap their prefix explicitly.
    released: bool,
    /// Subscribe-drain outcome (initial watermark + pre-ack stash):
    /// prepended to the first `poll`/`close_drain` so no witness
    /// is lost between subscribe and the first drain.
    pending_delta: LifecycleDelta,
    /// Last watermark coverage as (CPUs sought, CPUs seen) — the
    /// subscribe burst's, until a close replaces it with the
    /// terminal burst's. Test-visible via
    /// [`KernelLifecycle::watermark_status`].
    last_watermark: Option<(u32, u32)>,
    /// Subscribe-time required lane set (R20-fix round 4, F2a):
    /// the CPUs the initial burst covered. Close preserves this
    /// set (union with close-time online) instead of rebuilding
    /// from the current online count — an offlined CPU keeps its
    /// required lane and gaps explicitly rather than vanishing.
    watermark_cpus: Vec<u32>,
    /// The subscribe-time watermark burst shortfell (R20-fix
    /// round 4, MINOR): some CPU could not be pinned/forked
    /// (restricted affinity, offline CPU) — its lane gaps
    /// honestly by design, so the environment is supported
    /// PARTIAL, never zero-loss. Feeds the facility probe
    /// ([`ConnectorFacility::watermark_clean`]) so zero-loss
    /// tests skip there instead of failing.
    subscribe_shortfall: bool,
}

impl KernelLifecycle {
    /// Subscribe to process events for `target`'s thread group.
    /// `activity_started` tells whether the target can already
    /// emit: `false` for an owned child stopped pre-activity
    /// (per-CPU first sightings baseline silently — predecessors
    /// provably non-target), `true` for live targets (`--pid`,
    /// probes — first sightings gap their prefix explicitly).
    /// Fails (caller falls back to polling, explicit PARTIAL) when
    /// the target has no readable tgid, the socket/bind/send fails,
    /// the fd cannot go nonblocking, or the kernel does not ACCEPT
    /// the subscription (see [`Self::await_acceptance`]): a sent
    /// LISTEN alone proves nothing (ignored namespaces answer with
    /// silence, failed registrations with a nonzero NONE ack).
    /// On acceptance, runs the initial per-CPU watermark burst and
    /// ingests the pre-ack stash in arrival order (witnesses,
    /// never dropped) — both ride the first drain via
    /// `pending_delta`, so continuity observes the unbroken
    /// stream from the very first poll.
    pub fn subscribe(target: u32, activity_started: bool) -> anyhow::Result<Self> {
        let tgid = tgid_of(target)
            .ok_or_else(|| anyhow::anyhow!("target {target} has no readable Tgid"))?;
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                libc::NETLINK_CONNECTOR,
            )
        };
        if raw < 0 {
            anyhow::bail!("connector socket: {}", std::io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
        {
            anyhow::bail!("connector nonblock: {}", std::io::Error::last_os_error());
        }
        // Best-effort sizing (clamped by rmem_max on tight kernels;
        // drops stay exactly accounted regardless).
        let rcv = CONNECTOR_RCVBUF;
        let _ = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &rcv as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        // Autobind (nl_pid 0): several observer sockets may coexist
        // in one process (probe + holder + session) — a fixed pid
        // would collide with EADDRINUSE. Nothing keys on the portid
        // (Drops rows match by socket inode; acks return by
        // multicast, not unicast).
        addr.nl_pid = 0;
        addr.nl_groups = CN_IDX_PROC;
        let bound = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if bound < 0 {
            anyhow::bail!("connector bind: {}", std::io::Error::last_os_error());
        }
        let sock_inode = {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } < 0 {
                anyhow::bail!("connector fstat: {}", std::io::Error::last_os_error());
            }
            st.st_ino
        };
        // Baseline BEFORE the LISTEN send: drops during the
        // acceptance wait are already our loss (the subscription may
        // activate mid-wait), and must not hide inside the baseline.
        let drops_baseline = socket_drops(sock_inode);
        let mcast_ack = next_ack_token();
        send_connector(&fd, &mcast_msg(PROC_CN_MCAST_LISTEN, mcast_ack))
            .map_err(|e| e.context("connector listen"))?;
        // Acceptance wait (bounded): a sent LISTEN is not coverage.
        // Any wait failure cleans up best-effort (the LISTEN may
        // have registered before its ack was lost — balance it)
        // before bailing to loud fallback.
        let (stash, wait_enobufs) = match Self::await_acceptance(&fd, mcast_ack.wrapping_add(1)) {
            Ok(prefix) => prefix,
            Err(e) => {
                let _ = send_connector(&fd, &mcast_msg(PROC_CN_MCAST_IGNORE, mcast_ack));
                return Err(e);
            }
        };
        let mut known = HashSet::new();
        known.insert(tgid);
        let mut this = Self {
            fd,
            sock_inode,
            target_pid: target,
            target_tgid: tgid,
            known,
            seqs: SeqState::default(),
            drops_baseline,
            mcast_ack,
            wait_enobufs,
            subscribed_ns: ClockPort::monotonic_ns(&LiveClock),
            dead: false,
            released: activity_started,
            pending_delta: LifecycleDelta::default(),
            last_watermark: None,
            watermark_cpus: Vec::new(),
            subscribe_shortfall: false,
        };
        // Subscribe drain: the pre-ack stash first (arrival order —
        // pre-ack traffic precedes everything after, so ingesting
        // it later would read the per-CPU streams backward), then
        // the initial per-CPU watermark burst. Owned-stopped
        // targets baseline every CPU silently here (pre-activity);
        // live targets gap each first sighting honestly. The
        // outcome rides the first drain (witnesses preserved).
        let mut delta0 = LifecycleDelta::default();
        for bytes in &stash {
            this.ingest_datagram(bytes, &mut delta0, None);
        }
        let cpus = online_cpus();
        this.watermark_cpus = cpus.clone();
        let (sync_pids, shortfall) = watermark_burst(&cpus);
        let mut watch = SyncWatch::new(&sync_pids);
        this.drain_await_sync(
            &mut delta0,
            &mut watch,
            Instant::now() + SYNC_WATERMARK_TIMEOUT,
        );
        reap_sync_children(&sync_pids);
        this.last_watermark = Some((watch.sought_count(), watch.seen_count()));
        this.subscribe_shortfall = shortfall;
        if shortfall {
            // Diagnostic, fail-closed: the burst could not cover
            // every CPU (affinity/fork) — unwatermarked CPUs gap
            // honestly on first sighting and at the terminal.
            delta0.loss += 1;
        }
        if this.dead {
            // A socket dead at birth proves nothing — loud
            // fallback, like any other subscribe failure.
            let _ = send_connector(&this.fd, &mcast_msg(PROC_CN_MCAST_IGNORE, mcast_ack));
            anyhow::bail!("connector died during subscribe drain");
        }
        this.pending_delta = delta0;
        Ok(this)
    }

    /// Await the kernel's acceptance of our LISTEN: the NONE ack
    /// echoing our correlation ack with err == 0. Namespaces the
    /// kernel ignores answer with silence (timeout → bail);
    /// registration failures answer with err != 0 (bail); transport
    /// errors bail. Datagrams arriving before the ack are STASHED
    /// (ingested in arrival order by the subscribe drain — the
    /// subscription may already be live, so they are witnesses, and
    /// the ack itself stays stashed so per-CPU continuity observes
    /// the unbroken stream). A storm past the stash caps bails (an
    /// unwitnessable prefix must not become a clean baseline).
    fn await_acceptance(fd: &OwnedFd, our_ack: u32) -> anyhow::Result<(VecDeque<Vec<u8>>, bool)> {
        Self::await_acceptance_timeout(fd, our_ack, SUBSCRIBE_ACK_TIMEOUT)
    }

    /// Bounded acceptance wait with an explicit timeout (the
    /// timeout is a parameter so the wait path itself — poll loop
    /// plus timeout accounting, not just ack parsing — carries a
    /// true timeout control).
    fn await_acceptance_timeout(
        fd: &OwnedFd,
        our_ack: u32,
        timeout: Duration,
    ) -> anyhow::Result<(VecDeque<Vec<u8>>, bool)> {
        let mut stash: VecDeque<Vec<u8>> = VecDeque::new();
        let mut stashed_bytes = 0usize;
        let mut wait_enobufs = false;
        let mut buf = vec![0u8; 65536];
        let t0 = Instant::now();
        'wait: loop {
            if t0.elapsed() > timeout {
                anyhow::bail!(
                    "connector subscribe not acknowledged within {timeout:?} \
                     (unsupported namespace answers with silence)"
                );
            }
            let mut pfd = libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let pr = unsafe { libc::poll(&mut pfd, 1, 50) };
            if pr < 0 {
                let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if e == libc::EINTR {
                    continue;
                }
                anyhow::bail!("connector accept poll: {}", std::io::Error::last_os_error());
            }
            if pr == 0 {
                continue;
            }
            loop {
                let r = unsafe {
                    libc::recv(
                        fd.as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                        libc::MSG_DONTWAIT,
                    )
                };
                if r < 0 {
                    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                    if e == libc::EAGAIN || e == libc::EWOULDBLOCK {
                        break;
                    }
                    if e == libc::ENOBUFS {
                        wait_enobufs = true;
                        continue;
                    }
                    anyhow::bail!("connector accept recv: {}", std::io::Error::last_os_error());
                }
                if r == 0 {
                    break;
                }
                let bytes = buf[..r as usize].to_vec();
                match scan_ack(&bytes, our_ack) {
                    AckScan::Ours(0) => {
                        stash.push_back(bytes);
                        break 'wait;
                    }
                    AckScan::Ours(err) => {
                        anyhow::bail!("connector rejected subscribe (err={err})");
                    }
                    AckScan::TransportError(e) => {
                        anyhow::bail!("connector subscribe transport error ({e})");
                    }
                    AckScan::Absent => {
                        stashed_bytes += bytes.len();
                        stash.push_back(bytes);
                        if stash.len() > SUBSCRIBE_STASH_MAX_MSGS
                            || stashed_bytes > SUBSCRIBE_STASH_MAX_BYTES
                        {
                            anyhow::bail!("connector subscribe storm during acceptance wait");
                        }
                    }
                }
            }
        }
        Ok((stash, wait_enobufs))
    }

    /// Unsubscribe (IGNORE): balances the LISTEN registration count
    /// so proc-event generation stops when the observer leaves. The
    /// kernel guards repeats (IGNORE-after-IGNORE is a no-op), so
    /// this is safe ahead of Drop.
    pub fn unsubscribe(&mut self) -> anyhow::Result<()> {
        send_connector(&self.fd, &mcast_msg(PROC_CN_MCAST_IGNORE, self.mcast_ack))
            .map_err(|e| e.context("connector unsubscribe"))
    }

    /// Monotonic subscription instant (ordering evidence: production
    /// subscribes before the window opens — structurally earlier
    /// than any owned activity, which starts at release).
    pub fn subscribed_ns(&self) -> u64 {
        self.subscribed_ns
    }

    /// This subscription's operation token (NEW-ACK): distinct per
    /// subscription — the kernel echoes `token + 1` on this
    /// subscription's NONE acks, so concurrent same-process
    /// subscriptions cannot satisfy each other's waits.
    pub fn ack_token(&self) -> u32 {
        self.mcast_ack
    }

    /// Last per-CPU watermark coverage as (CPUs sought, CPUs
    /// seen): the subscribe burst's until a close replaces it
    /// with the terminal burst's. `None` before any burst ran
    /// (unreachable via [`Self::subscribe`], which always bursts).
    pub fn watermark_status(&self) -> Option<(u32, u32)> {
        self.last_watermark
    }

    /// Close-time watermark plan (R20-fix round 4, F2a): the
    /// subscribe-time required lane set unioned with the current
    /// online set — never a fresh set from the current count
    /// alone (an offlined CPU would silently lose its lane).
    fn close_cpu_plan(&self) -> CloseCpuPlan {
        plan_close_cpus(&self.watermark_cpus, &online_cpus())
    }

    /// Ingest one connector payload (`cn_msg` body): filter to the
    /// target subtree, map fork/exec to events, ignore exits (never
    /// pruned — see the EXIT arm). Malformed records are host-side
    /// observation uncertainty (scan loss), never silent skips.
    /// EVERY valid proc message feeds per-CPU sequence continuity
    /// (ignored `what` values and NONE acks consume kernel seqs too —
    /// skipping them would manufacture false gaps). NONE messages
    /// echoing our correlation ack carry OUR registration verdict
    /// (err != 0 fails closed); other subscribers' acks ride the
    /// shared group — continuity-tracked, verdict ignored. All other
    /// non-fork/exec/exit `what` values (uid/gid/sid/ptrace/comm/
    /// coredump) create no processes and replace no images, so no
    /// uncaptured execution can hide behind them: ignored.
    /// `sync` (watermark awaits only) notes FORK/EXIT messages of
    /// the burst children — either marks the RECEIVED event's CPU
    /// witnessed (a migrated helper never completes another lane).
    fn ingest_cn(&mut self, body: &[u8], delta: &mut LifecycleDelta, sync: Option<&mut SyncWatch>) {
        if body.len() < CN_HDRLEN + PROC_EVENT_HDRLEN {
            delta.loss += 1;
            return;
        }
        let (Some(idx), Some(val)) = (le_u32_at(body, 0), le_u32_at(body, 4)) else {
            delta.loss += 1;
            return;
        };
        if idx != CN_IDX_PROC || val != CN_VAL_PROC {
            return;
        }
        let ev = &body[CN_HDRLEN..];
        let (Some(what), Some(cpu), Some(seq), Some(ack)) = (
            le_u32_at(ev, 0),
            le_u32_at(ev, PROC_EVENT_CPU_OFF),
            le_u32_at(body, CN_SEQ_OFF),
            le_u32_at(body, CN_ACK_OFF),
        ) else {
            delta.loss += 1;
            return;
        };
        let our_ack = self.mcast_ack.wrapping_add(1);
        let post_release = self.released;
        self.seqs.observe(cpu, seq, delta, post_release);
        match what {
            PROC_EVENT_NONE => {
                if ack == our_ack {
                    match le_u32_at(ev, PROC_EVENT_HDRLEN) {
                        Some(0) => {}
                        _ => delta.loss += 1,
                    }
                }
            }
            PROC_EVENT_FORK => {
                // parent_pid, parent_tgid, child_pid, child_tgid.
                let (Some(parent_tgid), Some(child_pid), Some(child_tgid)) = (
                    le_u32_at(ev, PROC_EVENT_HDRLEN + 4),
                    le_u32_at(ev, PROC_EVENT_HDRLEN + 8),
                    le_u32_at(ev, PROC_EVENT_HDRLEN + 12),
                ) else {
                    delta.loss += 1;
                    return;
                };
                if let Some(w) = sync {
                    w.note(child_pid, cpu);
                }
                if parent_tgid == self.target_tgid || self.known.contains(&parent_tgid) {
                    if child_tgid == parent_tgid {
                        // Same-tgid clone: thread creation, not an
                        // ignored process (polling parity).
                    } else {
                        self.known.insert(child_tgid);
                        delta.events.push(LifecycleEvent {
                            kind: LifecycleKind::Fork,
                            pid: child_pid,
                        });
                    }
                }
            }
            PROC_EVENT_EXEC => {
                let Some(process_tgid) = le_u32_at(ev, PROC_EVENT_HDRLEN + 4) else {
                    delta.loss += 1;
                    return;
                };
                if process_tgid == self.target_tgid {
                    delta.events.push(LifecycleEvent {
                        kind: LifecycleKind::Exec,
                        pid: self.target_pid,
                    });
                }
            }
            PROC_EVENT_EXIT => {
                // Length-validated, then ignored: the payload must
                // still parse (else scan loss), but no exit proves
                // its group dead — verified live, thread exits emit
                // EXIT with the surviving group as tgid, so pruning
                // on EXIT would untrack live children and silently
                // miss their later forks. The set is never pruned
                // (polling `seen` parity — stale entries from tgid
                // reuse can only spuriously count, never silently
                // miss: fail-closed). Target death is custody's
                // verdict regardless.
                if le_u32_at(ev, PROC_EVENT_HDRLEN + 4).is_none() {
                    delta.loss += 1;
                    return;
                }
                if let (Some(pid), Some(w)) = (le_u32_at(ev, PROC_EVENT_HDRLEN), sync) {
                    w.note(pid, cpu);
                }
            }
            _ => {}
        }
    }

    /// Ingest one socket datagram (one or more netlink messages):
    /// ACKs and ENOBUFS reports pass (drops count authoritatively
    /// via the Drops delta), other errors and truncations are scan
    /// loss, and every other message is a connector payload for
    /// [`Self::ingest_cn`] (the socket is dedicated to the proc
    /// group; the `cn_msg` idx/val check rejects strays).
    /// `sync` (watermark awaits only) threads through to
    /// [`Self::ingest_cn`].
    fn ingest_datagram(
        &mut self,
        buf: &[u8],
        delta: &mut LifecycleDelta,
        sync: Option<&mut SyncWatch>,
    ) {
        // A multi-message datagram shares one watch across its
        // messages (reborrowed per message).
        let mut sync = sync;
        let mut off = 0usize;
        let mut consumed_any = false;
        while off + NLMSG_HDRLEN <= buf.len() {
            let (Some(len), Some(typ)) = (
                le_u32_at(buf, off).map(|l| l as usize),
                le_u32_at(buf, off + 4).map(|t| t as u16),
            ) else {
                delta.loss += 1;
                return;
            };
            if len < NLMSG_HDRLEN || off + len > buf.len() {
                delta.loss += 1;
                return;
            }
            let body = &buf[off + NLMSG_HDRLEN..off + len];
            if typ == NLMSG_ERROR {
                match le_i32_at(body, 0) {
                    Some(0) => {}
                    Some(e) if e == -libc::ENOBUFS => {}
                    _ => delta.loss += 1,
                }
            } else {
                self.ingest_cn(body, delta, sync.as_deref_mut());
            }
            consumed_any = true;
            off += (len + 3) & !3;
        }
        if !consumed_any && !buf.is_empty() {
            delta.loss += 1;
        }
    }

    /// Bounded drain into `delta` (at most `max_records`
    /// datagrams): the subscribe drain already ingested the
    /// pre-ack stash in arrival order (nothing replays here), so
    /// this reads the live socket only. Events filter to the
    /// subtree, kernel drops ride exact via the Drops delta
    /// (ENOBUFS backstops a same-poll counter race with an
    /// at-least-one), an unreadable Drops table fails closed to
    /// scan loss, and a nonempty tail after the bound reports
    /// `pending`. `sync` (watermark awaits only) threads through
    /// to [`Self::ingest_cn`].
    fn drain_into(
        &mut self,
        delta: &mut LifecycleDelta,
        max_records: usize,
        sync: Option<&mut SyncWatch>,
    ) {
        if self.dead {
            delta.loss += 1;
            return;
        }
        let mut sync = sync;
        let mut records = 0usize;
        let mut buf = vec![0u8; 65536];
        let mut enobufs = false;
        loop {
            if records >= max_records {
                break;
            }
            let r = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if r < 0 {
                let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if e == libc::EAGAIN || e == libc::EWOULDBLOCK {
                    break;
                }
                if e == libc::ENOBUFS {
                    // In-band overrun tripwire: the Drops delta
                    // below counts it; keep draining.
                    enobufs = true;
                    continue;
                }
                self.dead = true;
                delta.loss += 1;
                break;
            }
            if r == 0 {
                break;
            }
            self.ingest_datagram(&buf[..r as usize], delta, sync.as_deref_mut());
            records += 1;
        }
        let (baseline, fresh, blind) =
            drops_delta(self.drops_baseline, socket_drops(self.sock_inode));
        self.drops_baseline = baseline;
        delta.dropped = delta.dropped.saturating_add(fresh);
        if blind {
            // Accounting blind: cannot prove no-loss.
            delta.loss += 1;
        }
        if (enobufs || std::mem::replace(&mut self.wait_enobufs, false)) && fresh == 0 {
            // Overrun proven, counter unmoved (same-poll read race
            // or a wait-period overrun): at-least-one.
            delta.dropped = delta.dropped.saturating_add(1);
        }
        if records >= max_records && socket_has_pending(&self.fd) {
            delta.pending = 1;
        }
    }

    /// Drain until the watermark `watch` completes or `deadline`
    /// passes (R20-fix round 3, F2): bounded poll-sleep between
    /// bounded drains. An incomplete watch at the deadline is an
    /// unwitnessed watermark — explicit loss (fail-closed), never
    /// an assumed baseline or suffix. A dead socket breaks early
    /// (its loss already recorded; close reports no-witness).
    fn drain_await_sync(
        &mut self,
        delta: &mut LifecycleDelta,
        watch: &mut SyncWatch,
        deadline: Instant,
    ) {
        loop {
            if self.dead || watch.complete() {
                break;
            }
            self.drain_into(delta, MAX_LIFECYCLE_DRAIN, Some(&mut *watch));
            if watch.complete() || Instant::now() >= deadline {
                break;
            }
            let mut pfd = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let pr = unsafe { libc::poll(&mut pfd, 1, 50) };
            if pr < 0 {
                let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if e == libc::EINTR {
                    continue;
                }
                self.dead = true;
                delta.loss += 1;
                break;
            }
        }
        if !watch.complete() && !self.dead {
            delta.loss += 1;
            eprintln!(
                "lifecycle: sync watermark incomplete ({}/{} CPUs witnessed)",
                watch.seen_count(),
                watch.sought_count(),
            );
        }
    }
}

impl Drop for KernelLifecycle {
    /// Balance the LISTEN registration (socket release alone does
    /// not decrement the kernel's listener count — generation would
    /// stay enabled after the observer exits). Best-effort: a failed
    /// send is loud on stderr, never a panic.
    fn drop(&mut self) {
        if let Err(e) = self.unsubscribe() {
            eprintln!("lifecycle: connector unsubscribe failed ({e:#})");
        }
    }
}

impl LifecyclePort for KernelLifecycle {
    fn poll(&mut self) -> LifecycleDelta {
        // The subscribe drain rides first (initial watermark +
        // pre-ack stash witnesses, preserved in arrival order).
        let mut delta = std::mem::take(&mut self.pending_delta);
        self.drain_into(&mut delta, MAX_LIFECYCLE_DRAIN, None);
        delta
    }

    fn fallback_partial(&self) -> bool {
        false
    }

    fn mark_released(&mut self) {
        self.released = true;
    }

    fn close_drain(&mut self) -> Option<LifecycleDelta> {
        if self.dead {
            // Missing evidence: the controller records no-witness
            // loss (a dead stream proves nothing about the tail).
            return None;
        }
        // The subscribe drain rides first when no poll ever ran
        // (a window that closed before its first round still
        // reports its initial watermark outcome).
        let mut delta = std::mem::take(&mut self.pending_delta);
        // Terminal per-CPU watermark (R20-fix round 3, F2):
        // successors on every online CPU prove the suffix — any
        // pre-close loss surfaces as an interior hole when its
        // successor ingests, and a lost final message without a
        // successor is impossible once every lane advanced past
        // the close. An incomplete watermark gaps explicit. The
        // required lane set is preserved across the window (round
        // 4, F2a): required-but-offlined lanes gap explicitly as
        // topology changes that prevent closure — never vanish.
        let plan = self.close_cpu_plan();
        if !plan.offlined.is_empty() {
            eprintln!(
                "lifecycle: watermark lane(s) offlined mid-window, gap explicit: {:?}",
                plan.offlined
            );
            delta.loss += 1;
        }
        let (sync_pids, shortfall) = watermark_burst(&plan.burst);
        let mut watch = SyncWatch::new(&sync_pids);
        self.drain_await_sync(
            &mut delta,
            &mut watch,
            Instant::now() + SYNC_WATERMARK_TIMEOUT,
        );
        reap_sync_children(&sync_pids);
        self.last_watermark = Some((watch.sought_count(), watch.seen_count()));
        if shortfall {
            delta.loss += 1;
        }
        for _ in 0..CLOSE_DRAIN_ROUNDS {
            if self.dead {
                // Drained prefix survives (events preserved, loss
                // loud); only the unwitnessed remainder is missing.
                break;
            }
            delta.pending = 0;
            self.drain_into(&mut delta, MAX_LIFECYCLE_DRAIN, None);
            if delta.pending == 0 {
                break;
            }
        }
        Some(delta)
    }
}

/// Production lifecycle selection: kernel-observed signals when
/// the connector subscribes, the explicit PARTIAL polling fallback
/// otherwise (never silent — the fallback announces on stderr and
/// the polling-fallback loss withholds COMPLETE downstream).
pub enum LiveLifecycle {
    Kernel(KernelLifecycle),
    Polling(PollingLifecycle),
}

/// Connector facility probe outcome (R20-fix round 3, MINOR-A;
/// watermark-clean round 4, MINOR): whether a subscription
/// succeeds, whether its socket Drops row is readable, and
/// whether the subscribe-time watermark burst covered every
/// online CPU with no shortfall. COMPLETE/zero-loss tests need
/// ALL THREE — an unreadable Drops table fails closed to loss,
/// and restricted-affinity pinning records loss by design, so
/// drops-blind or pin-limited environments are supported
/// PARTIAL, never COMPLETE. Test gates cache one probe per
/// process (subscribing runs the initial watermark burst, so
/// probing per test would spam).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectorFacility {
    pub subscribes: bool,
    pub drops_readable: bool,
    pub watermark_clean: bool,
}

/// Probe the connector facility once (balanced: the probe
/// subscription unsubscribes on drop).
pub fn connector_facility() -> ConnectorFacility {
    match KernelLifecycle::subscribe(std::process::id(), true) {
        Ok(lc) => {
            let drops_readable = socket_drops(lc.sock_inode).is_some();
            let online = online_cpus().len() as u32;
            let watermark_clean = !lc.subscribe_shortfall
                && matches!(lc.last_watermark, Some((s, v)) if s == v && s == online && s >= 1);
            ConnectorFacility {
                subscribes: true,
                drops_readable,
                watermark_clean,
            }
        }
        Err(_) => ConnectorFacility {
            subscribes: false,
            drops_readable: false,
            watermark_clean: false,
        },
    }
}

impl LiveLifecycle {
    /// `activity_started` threads through to
    /// [`KernelLifecycle::subscribe`]: `false` for owned children
    /// stopped pre-activity, `true` for live targets.
    pub fn select(target: u32, activity_started: bool) -> Self {
        match KernelLifecycle::subscribe(target, activity_started) {
            Ok(kernel) => LiveLifecycle::Kernel(kernel),
            Err(e) => {
                eprintln!(
                    "lifecycle: kernel signals unavailable ({e:#}); explicit polling fallback (PARTIAL)"
                );
                LiveLifecycle::Polling(PollingLifecycle::new(target))
            }
        }
    }
}

impl LifecyclePort for LiveLifecycle {
    fn poll(&mut self) -> LifecycleDelta {
        match self {
            LiveLifecycle::Kernel(k) => k.poll(),
            LiveLifecycle::Polling(p) => p.poll(),
        }
    }

    fn fallback_partial(&self) -> bool {
        match self {
            LiveLifecycle::Kernel(k) => k.fallback_partial(),
            LiveLifecycle::Polling(p) => p.fallback_partial(),
        }
    }

    fn close_drain(&mut self) -> Option<LifecycleDelta> {
        match self {
            LiveLifecycle::Kernel(k) => k.close_drain(),
            LiveLifecycle::Polling(p) => p.close_drain(),
        }
    }

    fn mark_released(&mut self) {
        match self {
            LiveLifecycle::Kernel(k) => k.mark_released(),
            LiveLifecycle::Polling(p) => p.mark_released(),
        }
    }
}

/// Time: monotonic nanoseconds for the kernel window program plus
/// the requested/effective boundaries, `Instant` for loop control.
pub trait ClockPort {
    fn monotonic_ns(&self) -> u64;
    fn now(&self) -> Instant;
    fn wall_now(&self) -> SystemTime;
    fn sleep(&self, d: Duration);
}

/// Live clock: `CLOCK_MONOTONIC` for the kernel-adjacent stamps.
pub struct LiveClock;

impl ClockPort for LiveClock {
    fn monotonic_ns(&self) -> u64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe {
            libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
        }
        (ts.tv_sec.max(0) as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(ts.tv_nsec.max(0) as u64)
    }

    fn now(&self) -> Instant {
        Instant::now()
    }

    fn wall_now(&self) -> SystemTime {
        SystemTime::now()
    }

    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// Target /proc + file reads: live mappings for planning, file bytes
/// for ELF validation and object fingerprints, the exe link and file
/// sizes for fence comparison, and the comm for post-exec identity.
pub trait ProcPort {
    fn read_maps(&mut self, pid: u32) -> anyhow::Result<Vec<maps::Mapping>>;
    fn read_file(&mut self, path: &str) -> anyhow::Result<Vec<u8>>;
    /// Identity-bound read (F-A/A3), budgeted (R14): bytes plus
    /// the read-time (encoded dev, ino) they were read as. Reads
    /// past `max_bytes` refuse with `ErrorKind::FileTooLarge`
    /// BEFORE allocating (callers skip the path and count loud
    /// loss). Implementations pin the file across the read (open
    /// once, fstat/read/fstat) so the bytes cannot tear across a
    /// replacement. The payload is shared immutable (R14 fix):
    /// cache and output clones never copy the bytes.
    #[allow(clippy::type_complexity, reason = "R14 budgeted-read triple")]
    fn read_file_bound(
        &mut self,
        path: &str,
        max_bytes: usize,
    ) -> std::io::Result<(Arc<[u8]>, (u64, u64))>;
    /// Per-poll byte budget for relevant-file reads (R14): the
    /// total allowance one `read_relevant_files` pass may newly
    /// read; production allows [`MAX_CACHED_BYTES`]. Tests inject
    /// small budgets to prove cumulative overflow without huge
    /// allocations.
    fn read_budget(&self) -> usize {
        MAX_CACHED_BYTES
    }
    /// Identity stat (F-D/A13, freshness per R20): the CURRENT
    /// [`FileStat`] of `path` without reading bytes — same (dev,
    /// ino) encoding domain as
    /// [`read_file_bound`](Self::read_file_bound) so callers can
    /// validate a cached entry. `None` when unstatable (the caller
    /// treats that as a cache miss, never as a hit).
    fn stat_file(&mut self, path: &str) -> Option<FileStat>;
    fn read_exe(&mut self, pid: u32) -> Option<PathBuf>;
    fn file_len(&mut self, path: &str) -> Option<u64>;
    /// Current comm (`None` when unreadable — the caller keeps its
    /// snapshot). Owned children are acquired stopped pre-exec, so
    /// this settles the application identity after release.
    fn read_comm(&mut self, pid: u32) -> Option<String>;
}

/// Identity + freshness of one filesystem path (R20): (dev, ino)
/// is the file identity (same encoding domain as
/// [`plan::read_file_bound`]), (size, mtime_ns) its freshness. The
/// file cache validates all four: an in-place content change keeps
/// (dev, ino) but moves size and/or mtime, so (dev, ino)-only
/// validation would serve stale bytes under a stale fingerprint
/// indefinitely (P6 implementation-only replacement).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileStat {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    /// Nanoseconds since the Unix epoch, saturating (pre-epoch
    /// mtimes read 0 — a constant, never a tear).
    pub mtime_ns: u64,
}

/// Live /proc + filesystem reads.
pub struct LiveProc;

impl ProcPort for LiveProc {
    fn read_maps(&mut self, pid: u32) -> anyhow::Result<Vec<maps::Mapping>> {
        maps::read_maps(pid)
    }

    fn read_file(&mut self, path: &str) -> anyhow::Result<Vec<u8>> {
        Ok(std::fs::read(path)?)
    }

    fn read_file_bound(
        &mut self,
        path: &str,
        max_bytes: usize,
    ) -> std::io::Result<(Arc<[u8]>, (u64, u64))> {
        plan::read_file_bounded(path, max_bytes).map(|f| (f.bytes, (f.dev, f.ino)))
    }

    fn stat_file(&mut self, path: &str) -> Option<FileStat> {
        use std::os::unix::fs::MetadataExt as _;
        // Same encoding as plan::read_file_bound (major/minor via
        // libc, never the raw dev_t word) so cache validation
        // compares in one domain.
        std::fs::metadata(path)
            .map(|m| FileStat {
                dev: plan::encode_device(libc::major(m.dev()), libc::minor(m.dev())),
                ino: m.ino(),
                size: m.len(),
                mtime_ns: m
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_nanos().min(u128::from(u64::MAX)) as u64)
                    .unwrap_or(0),
            })
            .ok()
    }

    fn read_exe(&mut self, pid: u32) -> Option<PathBuf> {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
    }

    fn file_len(&mut self, path: &str) -> Option<u64> {
        std::fs::metadata(path).map(|m| m.len()).ok()
    }

    fn read_comm(&mut self, pid: u32) -> Option<String> {
        std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|s| s.trim().to_string())
            .ok()
    }
}

// ---------------------------------------------------------------- fence snapshots

/// Fence kind (every fence is recorded; §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceKind {
    /// Mapping add/remove (dev:ino/offset set changed; base shifts
    /// are NOT fences — file-offset attach is base-independent).
    MappingsChanged,
    /// A planned provider path's (dev, ino, size) identity changed.
    ProviderChanged,
    /// Target exec'd (`/proc/<pid>/exe` link changed).
    Exec,
}

/// Window snapshot for fence comparison.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Snapshot {
    exe: Option<PathBuf>,
    /// (path, dev, ino, file-offset, x) — start/end deliberately
    /// excluded (pure base shifts never fence).
    mapset: BTreeSet<(String, String, u64, u64, bool)>,
    /// Planned path → (dev, ino, size?). Size None = unreadable
    /// (never a fence by itself — attached probes hold the inode).
    planned: BTreeMap<String, (String, u64, Option<u64>)>,
}

fn snapshot(
    exe: Option<PathBuf>,
    live: &[maps::Mapping],
    planned_paths: &[String],
    sizes: &HashMap<String, Option<u64>>,
) -> Snapshot {
    let mapset = live
        .iter()
        .map(|m| (m.path.clone(), m.dev.clone(), m.ino, m.offset, m.x))
        .collect();
    let mut planned = BTreeMap::new();
    for p in planned_paths {
        // First sorted mapping wins (same file ⇒ same identity; a
        // deviant bind-mount alias still fences via the mapset).
        let ident = live
            .iter()
            .filter(|m| &m.path == p)
            .map(|m| (m.dev.clone(), m.ino))
            .min();
        if let Some((dev, ino)) = ident {
            let size = sizes.get(p).copied().flatten();
            planned.insert(p.clone(), (dev, ino, size));
        }
    }
    Snapshot {
        exe,
        mapset,
        planned,
    }
}

fn detect_fence(prev: &Snapshot, next: &Snapshot) -> Vec<FenceKind> {
    let mut out = Vec::new();
    if prev.mapset != next.mapset {
        out.push(FenceKind::MappingsChanged);
    }
    for (path, (dev, ino, size)) in &next.planned {
        // Planned path unmapped mid-window: the mapset already
        // fenced; no double count.
        if let Some((pdev, pino, psize)) = prev.planned.get(path) {
            if (pdev, pino) != (dev, ino) {
                out.push(FenceKind::ProviderChanged);
                break;
            }
            if let (Some(a), Some(b)) = (psize, size) {
                if a != b {
                    out.push(FenceKind::ProviderChanged);
                    break;
                }
            }
        }
    }
    if prev.exe != next.exe {
        out.push(FenceKind::Exec);
    }
    out
}

// ---------------------------------------------------------------- target identity

fn comm_of(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Container id from `/proc/<pid>/cgroup` content: the first
/// 64-hex path segment or runtime scope name (docker/crio/libpod),
/// else "" (bare metal). Best-effort identity for the check
/// actionability tuple — never a security boundary.
fn parse_container_id(cgroup: &str) -> String {
    for line in cgroup.lines() {
        let path = line.rsplit(':').next().unwrap_or("");
        for mut seg in path.split('/') {
            seg = seg.strip_suffix(".scope").unwrap_or(seg);
            for prefix in ["docker-", "crio-", "libpod-"] {
                seg = seg.strip_prefix(prefix).unwrap_or(seg);
            }
            if seg.len() == 64 && seg.bytes().all(|b| b.is_ascii_hexdigit()) {
                return seg.to_string();
            }
        }
    }
    String::new()
}

fn container_id_of(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map(|s| parse_container_id(&s))
        .unwrap_or_default()
}

/// PRD §6 byte-stability: identity order, not cookie order
/// (cookies are attach-sequence numbers).
fn sort_executions(executions: &mut [Execution]) {
    executions.sort_by(|a, b| {
        (a.id.op, &a.id.provider, &a.id.alg_class, a.id.funcid).cmp(&(
            b.id.op,
            &b.id.provider,
            &b.id.alg_class,
            b.id.funcid,
        ))
    });
}

// ---------------------------------------------------------------- adapter
//
// `DiscoveryDelta` (T06 producer) → `CountDelta` (T07 consumer) plus
// the auxiliary evidence the count session never sees. Stage-2
// review decisions, frozen here:
//
// D1 — Incremental vs complete. Discovery emits each candidate once
// (plus identity refreshes); the count session REPLACES a site's
// candidate set on every emit. The adapter therefore accumulates the
// full per-site set in [`AdapterState`] and re-emits the complete
// set for every touched site on every poll. Two sites sharing one
// backing triple union; coverage only ever degrades (see D3).
//
// D2 — The nine producer fields without a `CountDelta` counterpart:
// `events_consumed`/`queries_delta`/`attaches`(ok)/`budget_exhausted`
// become Activity counters; `objects` become [`ObjectRecord`]s;
// `tables` feed per-op [`ScopeCoverage`], tracked per table epoch
// (sibling epochs never collapse); `retirements` tombstone the
// retired epoch (dirty until the rebirth proves — an unload keeps
// the tombstone) and re-emit affected sites as Unknown;
// table-only changes that un-close an op (new unproven epochs,
// fresh TRUNC bits, lost termination) re-emit the same way;
// `tripwire` feeds the separate legacy evidence with window
// baselining (controller-owned); `trigger_observed` drives the
// no-query verdict. Retirement gap losses are NOT re-counted here
// (the session emits them through `losses`); close-time snapshot
// residuals reconcile once.
//
// D3 — Identity/metadata synthesis. Backing and advertising object
// ids are the mapped file's build-id fingerprint when its bytes
// yield one, else an opaque `unverified-…` id — pathnames never
// become identity. `provider_class` resolves per verified
// advertising object (F-A/A6): the run's pin (enrollment hit, else
// `default` in operator-asserted builtin mode) labels only the
// pinned object id — every other object stays `unknown`, never
// guessed from `fips.so`, a rename, or a run-wide default. A missing
// backing or an unparsable maps device makes the site unplannable:
// explicit loss, never a fabricated device zero. Per-site coverage
// is `Unknown` when any candidate read badly (`status != ok`), any
// of the op's table epochs is unterminated/dirty/retired-unproven,
// the op carries sticky TRUNC bits, new candidates arrive for an
// epoch after it terminated (the set proved non-closed), or
// candidates arrive for an epoch with zero table proof (an op
// closed on sibling epochs never vouches for unobserved ones).
// Session-global losses do NOT flip per-site coverage: they PARTIAL
// the window via Loss counters while unrelated positive evidence
// survives (R06).
//
// D4 — Loss classification. Every [`DiscoveryLoss`](crate::discovery::session::DiscoveryLoss)
// stays `Loss`: wire ring ids → `KernelRing`, wire map ids →
// `KernelMap`, pending/init-scan ids → `Discovery`, orphan rows →
// `TableRows`, everything else → `Events` (`HOST_DRAIN_SHORTFALL`
// sources `Drain`). Unknown ids (newer BPF than userspace) fail
// closed as `discovery.unknown_<id>` with the count preserved.

fn typed_counter(
    name: &str,
    kind: CounterKind,
    units: CounterUnits,
    source: CounterSource,
    value: u64,
) -> GapCounter {
    GapCounter {
        name: name.to_string(),
        kind,
        units,
        source,
        value,
    }
}

/// Classify one discovery loss source (D4). Unknown ids fail closed:
/// the count is preserved under `discovery.unknown_<id>`, never
/// dropped.
fn classify_loss(source: u32, count: u64) -> GapCounter {
    use osslscope_ebpf_common as wire;
    let name = coverage::loss_source_name(source)
        .map(str::to_string)
        .unwrap_or_else(|| format!("unknown_{source}"));
    let (units, origin) = match source {
        wire::LOSS_RING_ALG | wire::LOSS_RING_ROW | wire::LOSS_RING_TRIP | wire::LOSS_RING_INIT => {
            (CounterUnits::Events, CounterSource::KernelRing)
        }
        wire::LOSS_MAP_QUERY_NEXT
        | wire::LOSS_MAP_TRUNC
        | wire::LOSS_MAP_CALLS
        | wire::LOSS_MAP_TRIP
        | wire::LOSS_MAP_LGCALLS
        | wire::LOSS_MAP_TERMD => (CounterUnits::Events, CounterSource::KernelMap),
        wire::LOSS_PENDING_INIT_FULL
        | wire::LOSS_PENDING_QUERY_FULL
        | wire::LOSS_PENDING_INIT_MISS
        | wire::LOSS_PENDING_QUERY_MISS
        | wire::LOSS_INIT_SCAN => (CounterUnits::Events, CounterSource::Discovery),
        coverage::HOST_ORPHAN_ROW => (CounterUnits::TableRows, CounterSource::Discovery),
        coverage::HOST_DRAIN_SHORTFALL => (CounterUnits::Events, CounterSource::Drain),
        coverage::HOST_BAD_EVENT
        | coverage::HOST_SHORT_EVENT
        | coverage::HOST_UNKNOWN_KIND
        | coverage::HOST_MAP_SNAPSHOT
        | coverage::HOST_MAPS_READ
        | coverage::HOST_EVICT_FAILED => (CounterUnits::Events, CounterSource::Discovery),
        _ => (CounterUnits::Events, CounterSource::Discovery),
    };
    typed_counter(
        &format!("discovery.{name}"),
        CounterKind::Loss,
        units,
        origin,
        count,
    )
}

/// Verified object identity for one mapped backing: the file's
/// build-id when its bytes yield one, else an opaque unverified id
/// (D3). Bytes bind to the mapping's inode (F-A/A3): a same-path
/// replacement between the maps read and the files read lends the
/// new file's fingerprint to nothing. A vanished mapping never
/// yields build-id — without the VMA pinning its inode, the bytes
/// are unprovable (the display locator survives on the record as a
/// hint, never as identity).
/// Memoized build-id reads (P6): one ELF parse per bound file per
/// adapt call. The parse closure runs at most once per (path, dev,
/// ino) identity (absence caches too); a same-path replacement
/// carries a new inode, so it re-parses. The cache is call-local
/// (fresh per adapt_delta) and adds no persistence beyond the byte
/// cache: it inherits `files`-map freshness — an in-place rewrite
/// that keeps (dev, ino) keeps serving the previously read bytes
/// (read_relevant_files reuses cache hits across polls), so its
/// ids stay exactly as stale as those bytes. Within one immutable
/// `files` map, every result is exact.
type BuildIdCache = HashMap<(String, u64, u64), Option<String>>;

fn cached_build_id(
    cache: &mut BuildIdCache,
    path: &str,
    dev: u64,
    ino: u64,
    parse: impl FnOnce() -> Option<String>,
) -> Option<String> {
    if let Some(hit) = cache.get(&(path.to_owned(), dev, ino)) {
        return hit.clone();
    }
    let id = parse();
    cache.insert((path.to_owned(), dev, ino), id.clone());
    id
}

fn object_id_for_mapping(
    dev: &str,
    ino: u64,
    live: &[maps::Mapping],
    files: &HashMap<String, plan::FileBytes>,
    build_ids: &mut BuildIdCache,
) -> ObjectId {
    // H5: `dev` is stat-domain (BackingRef via H5-T1) — maps
    // text never joins identity. Ino-prefilter, then bind each
    // same-ino mapping's bytes against the full identity; the
    // first bound mapping wins (live order, deterministic).
    let bid = plan::device_id_of_dev_str(dev).and_then(|want| {
        let (path, bytes) = live
            .iter()
            .filter(|m| m.ino != 0 && m.ino == ino)
            .find_map(|m| {
                plan::bound_bytes(files, &m.path, want, ino).map(|b| (m.path.clone(), b))
            })?;
        cached_build_id(build_ids, &path, want, ino, || elf::read_build_id(bytes))
    });
    match bid {
        Some(id) => ObjectId(format!("build:{id}")),
        None => ObjectId(format!("unverified:{dev}:{ino}")),
    }
}

/// Advertising provider object id (D3): fingerprinted from the
/// array owner's mapped bytes when available, else opaque.
fn advertising_object_id(
    candidate: &DiscoveredCandidate,
    live: &[maps::Mapping],
    files: &HashMap<String, plan::FileBytes>,
    build_ids: &mut BuildIdCache,
) -> ObjectId {
    if candidate.advertising.is_empty() {
        return ObjectId("unverified-advertising:anonymous".to_string());
    }
    // Exact-VMA join by array address — never first-pathname-match
    // (F-A/A3), which conflates simultaneously live old/new objects
    // under one path.
    let owner = live
        .iter()
        .find(|m| m.start <= candidate.arr && candidate.arr < m.end && m.ino != 0);
    let Some(m) = owner else {
        return ObjectId("unverified-advertising:anonymous".to_string());
    };
    // Turnover check (H5): the array's current owner must
    // still be the discovery-time owner — stat-vs-stat
    // (backing_dev), never maps text (x-subvol/x-mount twins
    // share maps-dev + ino). Unstatable owners fall back to
    // maps-identity on both sides (dual-facet:
    // unlinked-but-mapped files keep working). Interim: a file
    // statable at discovery but unstatable now degrades to
    // anonymous (Slice B adds the maps-facet fallback
    // compare). The class was decoded from the old file's
    // array, so a changed owner degrades rather than borrowing
    // the new file's fingerprint.
    let Some(want) = plan::device_id_of_dev_str(&candidate.advertising_dev) else {
        return ObjectId("unverified-advertising:anonymous".to_string());
    };
    if crate::discovery::session::backing_dev(m) != candidate.advertising_dev
        || m.ino != candidate.advertising_ino
    {
        return ObjectId("unverified-advertising:anonymous".to_string());
    }
    let bid = match plan::bound_bytes(files, &m.path, want, candidate.advertising_ino) {
        Some(bytes) => cached_build_id(build_ids, &m.path, want, candidate.advertising_ino, || {
            elf::read_build_id(bytes)
        }),
        None => None,
    };
    match bid {
        Some(id) => ObjectId(format!("build:{id}")),
        // Mapping-bound opaque identity (D3/H5/B-5): binds the
        // ADVERTISED (stat-domain) triple — x-fs twins
        // separate even when the fingerprint is unavailable. A
        // same-path replacement changes identity instead of
        // conflating two objects. The pathname itself never
        // becomes identity. The located form is UNIFIED with
        // object ids (`unverified:` — same file, same record,
        // so candidates[].provider joins objects[]); only the
        // ownerless form keeps the role infix
        // (`unverified-advertising:anonymous` — D2 never emits
        // ownerless records, so no unification applies).
        None => ObjectId(format!(
            "unverified:{}:{}",
            candidate.advertising_dev, candidate.advertising_ino
        )),
    }
}

/// Run-pinned provider (F-A/A6): the enrollment pins a class to
/// ONE verified object id (`build:<hex>`), never to the run — a
/// mixed window's other objects stay `unknown`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedProvider {
    pub object: String,
    pub class: String,
}

/// Run-pin synthesis (D3): a pinned enrollment for this run's
/// provider file wins; else builtin mode observes the
/// in-libcrypto provider by operator assertion and OpenSSL
/// architecture (not a filename guess); file-provider mode pins
/// nothing. An unknown build-id pins nothing — without an object
/// id there is nothing to scope the pin to.
fn pin_provider_class(
    builtin: bool,
    build_id: &str,
    enrolled: Option<&str>,
) -> Option<PinnedProvider> {
    if build_id == "unknown" {
        return None;
    }
    let class = enrolled
        .map(str::to_string)
        .or_else(|| builtin.then(|| "default".to_string()))?;
    Some(PinnedProvider {
        object: format!("build:{build_id}"),
        class,
    })
}

/// Legacy display partitioning: classes of candidates advertised
/// from a legacy-shaped locator. A DISPLAY hint only (R02 permits
/// filenames as locator/display hints) — never provider-class
/// authority, which stays `unknown` above.
fn is_legacy_locator(locator: &str) -> bool {
    let stem = Path::new(locator)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let stem = stem.strip_suffix(".so").unwrap_or(stem);
    stem == "legacy"
}

/// Per-(op, epoch) table view: termination proof plus retirement
/// dirt. Sibling epochs never collapse: each array incarnation
/// proves separately, and a retired epoch's completion never carries
/// over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OpTable {
    terminated: bool,
    /// Poll sequence when termination was first observed (a new
    /// candidate for this epoch in a LATER poll proves the set
    /// non-closed).
    term_poll: Option<u64>,
    /// Retired without new-epoch proof yet.
    dirty: bool,
}

/// Adapter accumulation state (D1): full per-site candidate sets,
/// per-op backing census, table views, objects and loss sums.
#[derive(Debug, Default)]
pub struct AdapterState {
    poll_seq: u64,
    emitted: HashMap<(u64, u64, u64), DiscoveredSite>,
    triple_ops: HashMap<(u64, u64, u64), HashSet<u32>>,
    op_triples: HashMap<u32, HashSet<(u64, u64, u64)>>,
    op_tables: HashMap<(u32, u64), OpTable>,
    /// Sites with a permanent read gap (F-A/A4): once a candidate
    /// arrives unreadable, the site never claims Complete. Same
    /// stickiness as the old coverage latch — per-identity healing
    /// (a re-read row clearing its own gap) is future work.
    sites_bad_read: HashSet<(u64, u64, u64)>,
    /// Sites that ever arrived mixed (H3): same stickiness —
    /// in-window ambiguity poisons the site's window claim, so a
    /// same-triple single re-walk never flips back to Complete.
    /// Separate from bad_read (ambiguity, not lost identity).
    sites_mixed: HashSet<(u64, u64, u64)>,
    /// Sites that ever arrived with an `ok` verdict (R01): with
    /// `sites_mixed` this distinguishes pure-mixed triples (every
    /// row ambiguous — bounded ambiguity when the tables prove no
    /// rows missing) from mixed/`ok` blends (H3 withhold — a
    /// re-walked row never unmixes its triple).
    sites_ok: HashSet<(u64, u64, u64)>,
    /// Sticky per-op walk-shape bits (mirrors the producer: never
    /// retired — any nonzero bit keeps the op unclosed).
    op_trunc: HashMap<u32, u64>,
    legacy_classes: BTreeSet<String>,
    objects: Vec<ObjectRecord>,
    /// Object registry (H5/B-5): every id a ref can name is
    /// registered at construction (D2 object records AND
    /// advertising records) — keyed by normalized identity
    /// (dev-string, ino, id), so a file observed under two ids
    /// (`build:` + `unverified:`) registers both and every ref
    /// resolves.
    seen_objects: HashSet<(String, u64, String)>,
    loss_sums: HashMap<u32, u64>,
    /// Ops carrying op-localized loss (orphan ROWs): their
    /// candidate sets and denominators are tainted (F-B/A7).
    tainted_ops: HashSet<u32>,
    /// Unlocalizable loss seen (undecodable records, drain tails,
    /// snapshot failures, kernel counters): taints every op.
    taint_global: bool,
    queries_observed: u64,
    /// Pre-window tripwire totals (baselining poll): anchor the
    /// close-tail residual reconcile at assembly time.
    baseline_trip: HashMap<u64, u64>,
    baseline_lgcalls: u64,
    /// Failed-attach diagnostic texts (R06): retained sorted +
    /// deduped for the document path (the systematic attach
    /// failure must identify itself in JSON, not just count).
    /// Producer literals only (no paths/pointers) — capped at
    /// assembly ([`ATTACH_DIAGNOSTICS_CAP]).
    attach_diagnostics: BTreeSet<String>,
}

/// Cap on retained attach diagnostics (R06): sorted take — the
/// first N distinct texts (deterministic; counts stay exact in
/// the counters regardless).
pub const ATTACH_DIAGNOSTICS_CAP: usize = 16;

impl AdapterState {
    /// Distinct backing triples seen per op (coverage census).
    pub fn op_discovered(&self, op: u32) -> u64 {
        self.op_triples
            .get(&op)
            .map(|s| s.len() as u64)
            .unwrap_or(0)
    }

    /// Ops touched so far, sorted.
    pub fn ops(&self) -> Vec<u32> {
        let mut ops: Vec<u32> = self
            .op_triples
            .keys()
            .chain(self.op_tables.keys().map(|(op, _)| op))
            .copied()
            .collect();
        ops.sort_unstable();
        ops.dedup();
        ops
    }

    /// Op closure: at least one tracked epoch, every epoch
    /// terminated and clean, and no sticky walk-shape bits. A
    /// retired-awaiting-rebirth epoch (dirty tombstone) or an op
    /// with no table yet never closes.
    /// Loss taint for an op's completeness claims (F-B/A7):
    /// op-localized orphan loss or unlocalizable global loss. Pure
    /// table proof stays in `op_closed`; taint applies at the claim
    /// sites (candidate coverage, denominator).
    fn loss_tainted(&self, op: u32) -> bool {
        self.taint_global || self.tainted_ops.contains(&op)
    }

    fn op_closed(&self, op: u32) -> bool {
        if self.op_trunc.get(&op).copied().unwrap_or(0) != 0 {
            return false;
        }
        let mut any = false;
        for ((o, _), t) in &self.op_tables {
            if *o != op {
                continue;
            }
            any = true;
            if !t.terminated || t.dirty {
                return false;
            }
        }
        any
    }
}

/// Re-emit an op's emitted sites as Unknown (retirements and
/// closed-transitions share this): the op's completion dropped, so
/// every site touching it degrades.
fn degrade_op_sites(
    state: &mut AdapterState,
    touched: &mut HashMap<(u64, u64, u64), DiscoveredSite>,
    op: u32,
) {
    if let Some(triples) = state.op_triples.get(&op).cloned() {
        for triple in triples {
            if let Some(site) = state.emitted.get_mut(&triple) {
                if site.candidates_coverage != CandidateCoverage::Unknown {
                    site.candidates_coverage = CandidateCoverage::Unknown;
                }
                touched.insert(triple, site.clone());
            }
        }
    }
}

/// Re-emit every emitted site as Unknown: unlocalizable loss taints
/// all ops (F-B/A7 — the missing evidence could be anyone's).
fn degrade_all_sites(
    state: &mut AdapterState,
    touched: &mut HashMap<(u64, u64, u64), DiscoveredSite>,
) {
    let triples: Vec<(u64, u64, u64)> = state.emitted.keys().copied().collect();
    for triple in triples {
        if let Some(site) = state.emitted.get_mut(&triple) {
            if site.candidates_coverage != CandidateCoverage::Unknown {
                site.candidates_coverage = CandidateCoverage::Unknown;
            }
            touched.insert(triple, site.clone());
        }
    }
}

/// Per-poll adapter context: the live planning inputs plus the
/// round's classification inputs.
pub struct AdapterCtx<'a> {
    pub live: &'a [maps::Mapping],
    pub files: &'a HashMap<String, plan::FileBytes>,
    /// Run-pinned provider (F-A/A6): labels only the candidate
    /// whose verified advertising object id matches the pin.
    pub pinned_provider: Option<PinnedProvider>,
    /// Backings first seen this round (fresh dlopen vs long-present).
    pub fresh: &'a HashSet<(String, u64)>,
    /// Past the settle grace: newly emitted long-present sites are
    /// late-attach loss (the settle phase is the accepted
    /// query→attach residual, documented like the drain residual).
    pub post_settle: bool,
    /// Owned target released (R20-fix round 2, F7): a post-release
    /// first-attach of a LONG-PRESENT site (mapped at release) is a
    /// readiness gap — the [release, attach] sub-window executed
    /// without a probe — even inside the settle grace (which now
    /// covers only genuinely fresh mappings). The baseline poll
    /// runs pre-release and always sets false; --pid rounds set
    /// false (acquire-then-attach is unavoidable there, and the
    /// pid-prewindow-blind reason already withholds COMPLETE).
    pub post_release: bool,
    /// Baselining poll: tripwire news is pre-window and dropped;
    /// queries are pre-window (cold gap), never in-window arrivals.
    pub baseline: bool,
}

/// One adapted poll: the count delta plus auxiliary evidence.
pub struct AdaptedDelta {
    pub delta: CountDelta,
    pub activity: Vec<GapCounter>,
    pub objects: Vec<ObjectRecord>,
    pub pre_window_queries: u64,
    /// In-window tripwire news (`None` on the baselining poll).
    pub tripwire: Option<TripwireDelta>,
    /// Tripwire binding generation live this poll (R05): in-window
    /// tripwire counts key per (generation, cookie) so a mid-window
    /// replacement can never join two bindings' probes into one
    /// observation row.
    pub trip_generation: u64,
    /// Retired-binding tripwire news fenced before replacement
    /// (R05/F-R05-3): (generation, cookie, count) already keyed to
    /// the retired generation. Empty on non-replacement polls and
    /// on the baselining poll.
    pub retired_trip: Vec<crate::discovery::session::RetiredTripDelta>,
    pub trigger_observed: bool,
}

/// Adapt one discovery delta (D1–D4).
pub fn adapt_delta(
    state: &mut AdapterState,
    delta: &DiscoveryDelta,
    ctx: &AdapterCtx,
) -> AdaptedDelta {
    state.poll_seq += 1;
    let seq = state.poll_seq;
    let mut count_losses = Vec::new();
    let mut activity = Vec::new();
    // P6: call-local build-id memoization (one ELF parse per bound
    // file per delta — see BuildIdCache).
    let mut build_ids: BuildIdCache = HashMap::new();

    // D4: every discovery loss stays Loss, forwarded exactly once.
    // A7: loss also taints completeness claims — op-localized
    // orphans taint their op's sets/denominators, unlocalizable
    // loss taints every op. Newly tainted scopes degrade below.
    let mut taint_global_new = false;
    let mut taint_ops_new = Vec::new();
    for loss in &delta.losses {
        if loss.count == 0 {
            continue;
        }
        let sum = state.loss_sums.entry(loss.source).or_default();
        *sum = sum.saturating_add(loss.count);
        count_losses.push(classify_loss(loss.source, loss.count));
        match loss.op {
            Some(op) => {
                if state.tainted_ops.insert(op) {
                    taint_ops_new.push(op);
                }
            }
            None => {
                if !state.taint_global {
                    state.taint_global = true;
                    taint_global_new = true;
                }
            }
        }
    }

    // D2 retirements FIRST: the retired epoch's completion drops
    // (rows survive) into a dirty tombstone. A newer epoch's table
    // prunes older dirt (sibling isolation: an unload must not veto
    // a live array's proof); pruned-epoch arrivals fail closed via
    // the untracked-epoch arm. An unload with no newer table leaves
    // the tombstone standing — proof dropped forever. Retirement
    // gap losses are NOT re-counted (D2).
    let mut touched: HashMap<(u64, u64, u64), DiscoveredSite> = HashMap::new();
    let was_closed: HashSet<u32> = state
        .ops()
        .into_iter()
        .filter(|op| state.op_closed(*op))
        .collect();
    for retirement in &delta.retirements {
        activity.push(typed_counter(
            "discovery.table_retired",
            CounterKind::Activity,
            CounterUnits::Events,
            CounterSource::Discovery,
            1,
        ));
        state.op_tables.insert(
            (retirement.op, retirement.epoch),
            OpTable {
                terminated: false,
                term_poll: None,
                dirty: true,
            },
        );
        degrade_op_sites(state, &mut touched, retirement.op);
    }

    // D2 tables: track each live epoch's proof per (op, epoch) —
    // sibling arrays at distinct epochs never collapse, and a
    // terminated table cannot overwrite an unfinished sibling. A
    // rebirth (newer epoch) supersedes its retired tombstone;
    // epochs are globally monotonic, so the comparison is exact.
    for table in &delta.tables {
        let key = (table.op, table.epoch);
        let entry = state.op_tables.entry(key).or_insert(OpTable {
            terminated: false,
            term_poll: None,
            dirty: false,
        });
        if entry.dirty {
            // Stale re-emit of a retired epoch: the tombstone stands
            // (only a newer epoch's rebirth clears it).
            continue;
        }
        if matches!(table.state, CoverageState::Terminated { .. }) {
            entry.terminated = true;
            if entry.term_poll.is_none() {
                entry.term_poll = Some(seq);
            }
        } else {
            entry.terminated = false;
        }
        state
            .op_tables
            .retain(|(op, epoch), t| *op != table.op || *epoch >= table.epoch || !t.dirty);
        if table.trunc_bits != 0 {
            *state.op_trunc.entry(table.op).or_default() |= table.trunc_bits;
        }
    }

    // Closed-transition degrade: table-only changes that un-close an
    // op (new unproven epochs, fresh TRUNC bits, lost termination)
    // degrade already-emitted sites exactly like retirements do.
    for op in state.ops() {
        if was_closed.contains(&op) && !state.op_closed(op) {
            degrade_op_sites(state, &mut touched, op);
        }
    }

    // A7 loss-taint degrade: newly tainted scopes re-emit as
    // Unknown (transition-only — already-tainted scopes stay
    // quiet, and the emit-time check below covers first emits).
    for op in taint_ops_new {
        degrade_op_sites(state, &mut touched, op);
    }
    if taint_global_new {
        degrade_all_sites(state, &mut touched);
    }

    // D1/D3 candidates: group by backing triple, union with the
    // accumulated set, degrade coverage, classify late attaches.
    // The class resolves per verified advertising object (F-A/A6).
    let mut unbacked = 0u64;
    let mut unparsed_dev = 0u64;
    let mut late_attach = 0u64;
    let mut fresh_mapped = 0u64;
    let mut identity_refreshed = 0u64;
    // B-5: poll-new object records (advertising registrations
    // below join D2 records — one registry, one vec).
    let mut objects = Vec::new();
    // triple → (dev string, new candidates, (op, epoch) arrivals,
    // any bad read).
    // (device string, fresh identities, every arrival's epoch,
    // novel arrivals' epochs, bad-read flag, mixed flag,
    // all-fresh-mixed flag). The two epoch sets split per-arrival
    // validation (F-H/H1): membership/proof-voidness covers all
    // arrivals, the post-proof trip novel only. The trailing
    // conjunct (R01) starts true and folds `&= mixed` per arrival.
    type Group = (
        String,
        Vec<CandidateIdentity>,
        HashSet<(u32, u64)>,
        HashSet<(u32, u64)>,
        bool,
        bool,
        bool,
    );
    let mut groups: HashMap<(u64, u64, u64), Group> = HashMap::new();
    // Novelty index for the non-closed guard (F-A/A4): duplicate
    // arrivals (re-walked rows, multi-libctx re-queries) carry no
    // new information and must not trip "new candidate after
    // termination" — only novel identities feed the guard's epoch
    // set. Prior emitted identities plus this poll's arrivals.
    let mut seen_ids: HashMap<(u64, u64, u64), HashSet<CandidateIdentity>> = HashMap::new();
    for candidate in &delta.candidates {
        if is_legacy_locator(&candidate.advertising) {
            state.legacy_classes.insert(candidate.class.clone());
        }
        let Some(backing) = candidate.backing.as_ref() else {
            // No file mapping: unplannable (fenced, count-only at
            // render) — explicit loss, never silent.
            unbacked += 1;
            continue;
        };
        let Some(device) = plan::device_id_of_dev_str(&backing.dev) else {
            // Unparsable device: unplannable, never device zero.
            unparsed_dev += 1;
            continue;
        };
        let triple = (device, backing.ino, backing.offset);
        state
            .op_triples
            .entry(candidate.op)
            .or_default()
            .insert(triple);
        state
            .triple_ops
            .entry(triple)
            .or_default()
            .insert(candidate.op);
        let class = if candidate.class.is_empty() {
            "other".to_string()
        } else {
            candidate.class.clone()
        };
        let advertising = advertising_object_id(candidate, ctx.live, ctx.files, &mut build_ids);
        // B-5 registry: the advertising id is a nameable ref
        // (candidates[].provider), so it registers HERE at
        // construction — an advertising-only provider (no D2
        // object) still resolves. The record carries the
        // owner's triple (device 0 / locator "" when ownerless
        // — `...:anonymous` still resolves).
        if state.seen_objects.insert((
            candidate.advertising_dev.clone(),
            candidate.advertising_ino,
            advertising.0.clone(),
        )) {
            let record = ObjectRecord {
                id: advertising.clone(),
                device: plan::device_id_of_dev_str(&candidate.advertising_dev).unwrap_or(0),
                inode: candidate.advertising_ino,
                display_locator: candidate.advertising.clone(),
            };
            state.objects.push(record.clone());
            objects.push(record);
        }
        let provider_class = match &ctx.pinned_provider {
            Some(pinned) if pinned.object == advertising.0 => pinned.class.clone(),
            _ => "unknown".to_string(),
        };
        let identity = CandidateIdentity::new(
            advertising,
            provider_class,
            candidate.op,
            candidate.funcid,
            vec![class],
            candidate.weak,
        );
        // H3: mixed is ambiguity, not lost identity — it rides
        // its own sticky set, never bad_read.
        let mixed = candidate.status == "mixed";
        let bad_read = candidate.status != "ok" && !mixed;
        let slot = groups.entry(triple).or_insert_with(|| {
            (
                backing.dev.clone(),
                Vec::new(),
                HashSet::new(),
                HashSet::new(),
                false,
                false,
                true,
            )
        });
        let novel = seen_ids
            .entry(triple)
            .or_insert_with(|| {
                state
                    .emitted
                    .get(&triple)
                    .map(|s| s.candidates.iter().cloned().collect())
                    .unwrap_or_default()
            })
            .insert(identity.clone());
        slot.1.push(identity);
        // Per-arrival validation (F-H/H1): EVERY arrival's epoch
        // joins the membership set — a duplicate carrying a retired
        // epoch is still evidence about that epoch, and skipping
        // it let retired stamps re-close a site (A-2). The
        // post-proof arm below stays novel-only (a re-walked
        // identity proves nothing new), tracked in the second set.
        slot.2.insert((candidate.op, candidate.epoch));
        if novel {
            slot.3.insert((candidate.op, candidate.epoch));
        }
        slot.4 |= bad_read;
        if bad_read {
            state.sites_bad_read.insert(triple);
        }
        slot.5 |= mixed;
        if mixed {
            state.sites_mixed.insert(triple);
        }
        if !mixed && !bad_read {
            state.sites_ok.insert(triple);
        }
        slot.6 &= mixed;
    }
    // Deterministic group order (arrival order must not leak).
    let mut group_keys: Vec<(u64, u64, u64)> = groups.keys().copied().collect();
    group_keys.sort_unstable();
    for triple in group_keys {
        let (dev_str, mut fresh_identities, group_epochs, novel_epochs, bad_read, mixed, all_mixed) =
            groups.remove(&triple).unwrap_or_default();
        let (device, ino, offset) = triple;
        let first_emit = !state.emitted.contains_key(&triple);
        // D3 coverage: degrade on bad reads, an unclosed op (any
        // epoch unterminated/dirty/retired, or sticky TRUNC bits), a
        // NEW arrival for an epoch after it terminated (the set
        // proved non-closed), or an arrival for an epoch with zero
        // table proof (an op closed on sibling epochs never vouches
        // for an epoch it never observed — arrivals for sibling
        // epochs or ops on a shared site do not taint a closed
        // epoch, but an unproven epoch taints its own site).
        // Membership/proof-voidness covers every arrival, duplicate
        // or novel (F-H/H1); only the post-proof trip stays
        // novel-only.
        // A7: relevant loss taints the set (op-localized orphans
        // via tainted_ops; unlocalizable loss via the global flag).
        //
        // R01 bounded ambiguity: a group whose fresh arrivals are
        // ALL mixed-status, on a triple that NEVER arrived `ok`
        // (pure-mixed — no blend history), carries ambiguity the
        // terminated tables bound: no rows are missing, so the upper
        // is finite. Candidate COUNT proves nothing here — the wire
        // retains only the minimum class per row, so distinct
        // identities (e.g. weak differing) can name one class while
        // hiding every alternative (re-reviewer round 2). Bounds
        // and assets treat AmbiguousComplete as unattributable but
        // finite. Everything else keeps H3 withhold: ok/mixed
        // blends (sticky — a re-walk never unmixes its triple),
        // duplicates (no new information, F-A/A4), bad reads,
        // unclosed ops and taint.
        let pure_mixed = all_mixed && !state.sites_ok.contains(&triple);
        let mut unknown = bad_read
            || (mixed && !pure_mixed)
            || state.taint_global
            || state.sites_bad_read.contains(&triple)
            || (state.sites_mixed.contains(&triple) && !pure_mixed);
        if let Some(ops) = state.triple_ops.get(&triple) {
            for op in ops {
                if !state.op_closed(*op) {
                    unknown = true;
                }
                if state.tainted_ops.contains(op) {
                    unknown = true;
                }
                for (gop, gepoch) in &group_epochs {
                    if *gop != *op {
                        continue;
                    }
                    match state.op_tables.get(&(*op, *gepoch)) {
                        // Untracked epoch: fail closed (a missing
                        // entry is not proof of completion). Covers
                        // every arrival, duplicate or novel (F-H/H1).
                        None => unknown = true,
                        Some(t) => {
                            // Retired tombstone: the epoch's proof
                            // is void, so any arrival for it —
                            // duplicate or novel — taints its own
                            // site. (Also subsumed by the unclosed-op
                            // arm above while the tombstone stands;
                            // explicit here so a pruned-then-reseen
                            // tombstone can never slip through.)
                            if t.dirty {
                                unknown = true;
                            }
                            // Transient trip (F-A/A4): a NOVEL
                            // arrival after this epoch's proof
                            // degrades this emit only — a re-walked
                            // duplicate proves nothing new, so live
                            // re-walks still recover closure. True
                            // non-closure (beyond-proof rows) is
                            // the session's call — it re-opens the
                            // table (len-aware) until re-proof —
                            // while drain-delayed in-range rows
                            // must not dirt the epoch forever.
                            if novel_epochs.contains(&(*op, *gepoch))
                                && t.term_poll.is_some_and(|p| p < seq)
                            {
                                unknown = true;
                            }
                        }
                    }
                }
            }
        }
        let coverage = if unknown {
            CandidateCoverage::Unknown
        } else if pure_mixed {
            CandidateCoverage::AmbiguousComplete
        } else {
            CandidateCoverage::Complete
        };
        let site_key = SiteKey {
            object: object_id_for_mapping(&dev_str, ino, ctx.live, ctx.files, &mut build_ids),
            device,
            inode: ino,
            offset,
        };
        match state.emitted.get_mut(&triple) {
            Some(prior) => {
                prior.candidates.append(&mut fresh_identities);
                prior.candidates.sort();
                prior.candidates.dedup();
                // Recomputed every emit (F-A/A4): retirement dirt
                // clears when a newer table prunes it and the
                // rebirth proves, while permanent gaps (read
                // failures via `sites_bad_read`, loss taint)
                // persist in their own sticky state.
                prior.candidates_coverage = coverage;
                if prior.site != site_key {
                    // Refreshed backing fingerprint (same triple, new
                    // bytes): forward it so the count session versions
                    // the meaning at the next fence — the fenced
                    // generation keeps the old fingerprint, the new
                    // one carries the new — instead of silently
                    // reusing the stale identity.
                    prior.site = site_key;
                    identity_refreshed += 1;
                }
                touched.insert(triple, prior.clone());
            }
            None => {
                fresh_identities.sort();
                fresh_identities.dedup();
                let site = DiscoveredSite {
                    site: site_key,
                    candidates: fresh_identities,
                    candidates_coverage: coverage,
                };
                state.emitted.insert(triple, site.clone());
                touched.insert(triple, site);
            }
        }
        // Late-attach classification for first emits past settle
        // — or past the release boundary (R20-fix round 2, F7): an
        // owned post-release attach of a long-present site missed
        // the [release, attach] sub-window (a boundary call then is
        // uncaptured), so the settle no longer suppresses it; only
        // genuinely fresh mappings (nothing to miss before they
        // existed) stay Activity.
        if first_emit && (ctx.post_settle || ctx.post_release) {
            if ctx.fresh.contains(&(dev_str, ino)) {
                fresh_mapped += 1;
            } else {
                late_attach += 1;
            }
        }
    }
    if unbacked > 0 {
        count_losses.push(typed_counter(
            "discovery.unbacked_candidate",
            CounterKind::Loss,
            CounterUnits::Sites,
            CounterSource::Discovery,
            unbacked,
        ));
    }
    if unparsed_dev > 0 {
        count_losses.push(typed_counter(
            "discovery.unparsed_device",
            CounterKind::Loss,
            CounterUnits::Sites,
            CounterSource::Discovery,
            unparsed_dev,
        ));
    }
    if late_attach > 0 {
        count_losses.push(typed_counter(
            "discovery.late_attach_sites",
            CounterKind::Loss,
            CounterUnits::Sites,
            CounterSource::Discovery,
            late_attach,
        ));
    }
    if fresh_mapped > 0 {
        activity.push(typed_counter(
            "discovery.new_mapping_sites",
            CounterKind::Activity,
            CounterUnits::Sites,
            CounterSource::Discovery,
            fresh_mapped,
        ));
    }
    if identity_refreshed > 0 {
        activity.push(typed_counter(
            "discovery.site_identity_refreshed",
            CounterKind::Activity,
            CounterUnits::Sites,
            CounterSource::Discovery,
            identity_refreshed,
        ));
    }

    // D2 objects: fingerprinted records; unparsable devices skip loud.
    let mut unparsed_object_dev = 0u64;
    for object in &delta.objects {
        let Some(device) = plan::device_id_of_dev_str(&object.dev) else {
            unparsed_object_dev += 1;
            continue;
        };
        // B-5: the id computes BEFORE the registry check — one
        // file under two ids (`build:` + `unverified:`)
        // registers both records, never just the first.
        let id =
            object_id_for_mapping(&object.dev, object.ino, ctx.live, ctx.files, &mut build_ids);
        if !state
            .seen_objects
            .insert((object.dev.clone(), object.ino, id.0.clone()))
        {
            continue;
        }
        let record = ObjectRecord {
            id,
            device,
            inode: object.ino,
            display_locator: object.display_locator.clone(),
        };
        state.objects.push(record.clone());
        objects.push(record);
    }
    if unparsed_object_dev > 0 {
        count_losses.push(typed_counter(
            "discovery.unparsed_object_dev",
            CounterKind::Loss,
            CounterUnits::Events,
            CounterSource::Discovery,
            unparsed_object_dev,
        ));
    }

    // D2 auxiliary fields.
    if delta.events_consumed > 0 {
        activity.push(typed_counter(
            "discovery.events_consumed",
            CounterKind::Activity,
            CounterUnits::Events,
            CounterSource::Discovery,
            delta.events_consumed,
        ));
    }
    let mut pre_window_queries = 0u64;
    if delta.queries_delta > 0 {
        state.queries_observed = state.queries_observed.saturating_add(delta.queries_delta);
        if ctx.baseline {
            pre_window_queries = delta.queries_delta;
        } else {
            activity.push(typed_counter(
                "discovery.queries_observed",
                CounterKind::Activity,
                CounterUnits::Events,
                CounterSource::Discovery,
                delta.queries_delta,
            ));
        }
    }
    let mut attaches_ok = 0u64;
    let mut attaches_failed = 0u64;
    for attach in &delta.attaches {
        if let Some(failed) = attach.failed.as_ref() {
            attaches_failed += 1;
            // R06: retain the diagnostic text (sorted + deduped
            // in the set) for the document path — the failure
            // identifies itself, not just counts.
            state.attach_diagnostics.insert(failed.clone());
        } else {
            attaches_ok += 1;
        }
    }
    if attaches_ok > 0 {
        activity.push(typed_counter(
            "discovery.attaches",
            CounterKind::Activity,
            CounterUnits::Events,
            CounterSource::Discovery,
            attaches_ok,
        ));
    }
    if attaches_failed > 0 {
        count_losses.push(typed_counter(
            "discovery.attach_failed",
            CounterKind::Loss,
            CounterUnits::Probes,
            CounterSource::Discovery,
            attaches_failed,
        ));
    }
    if delta.budget_exhausted {
        activity.push(typed_counter(
            "discovery.budget_exhausted",
            CounterKind::Activity,
            CounterUnits::Events,
            CounterSource::Discovery,
            1,
        ));
    }

    if ctx.baseline {
        // Retain the pre-window tripwire totals (dropped as evidence
        // below): they anchor the close-tail residual reconcile —
        // snapshot minus baseline minus in-window.
        state.baseline_trip.clear();
        for (cookie, n) in &delta.tripwire.counter_deltas {
            state.baseline_trip.insert(*cookie, *n);
        }
        state.baseline_lgcalls = delta.tripwire.executed_legacy_queries_delta;
    }
    let mut discovered: Vec<DiscoveredSite> = touched.into_values().collect();
    discovered.sort_by(|a, b| a.site.cmp(&b.site));
    AdaptedDelta {
        delta: CountDelta {
            discovered,
            losses: count_losses,
        },
        activity,
        objects,
        pre_window_queries,
        tripwire: if ctx.baseline {
            None
        } else {
            Some(delta.tripwire.clone())
        },
        trip_generation: delta.trip_generation,
        retired_trip: if ctx.baseline {
            Vec::new()
        } else {
            delta.retired_trip_deltas.clone()
        },
        trigger_observed: delta.trigger_observed,
    }
}

/// Typed ENGINE observation collector (R05): the production
/// accumulation path shared by the capture controller and
/// acceptance tests. Per-poll, the caller snapshots the live
/// binding's probe meanings + module pins once per generation
/// ([`snapshot_binding`](Self::snapshot_binding)), then accumulates
/// that poll's in-window counter news under its generation
/// ([`accumulate`](Self::accumulate)). At assembly,
/// [`build`](Self::build) joins counts to meanings + pins +
/// fingerprinted objects. Baseline/straddle gating stays with the
/// caller (only in-window news reaches `accumulate`).
/// Pinned attach identity per (module, program) group for one
/// binding generation: (device id, inode).
type TripGroupPins = HashMap<(String, String), (u64, u64)>;

#[derive(Debug, Default)]
pub struct EngineCollector {
    counts: HashMap<(u64, u64), u64>,
    probes: HashMap<u64, legacy::ProbeSet>,
    pins: HashMap<u64, TripGroupPins>,
    probed_generation: Option<u64>,
}

impl EngineCollector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot a bound generation's probe meanings + group pins
    /// (once per generation). An absent binding consumes nothing.
    /// Pins key per (module, program) attach group (fix-round-2
    /// F1): one pathname bound through two programs keeps both
    /// bindings.
    pub fn snapshot_binding(
        &mut self,
        generation: u64,
        probe_set: Option<legacy::ProbeSet>,
        module_pins: &[crate::discovery::session::TripModulePin],
    ) {
        if self.probed_generation != Some(generation) {
            if let Some(set) = probe_set {
                self.probed_generation = Some(generation);
                let mut pins: TripGroupPins = HashMap::new();
                for p in module_pins {
                    if let Some(device) = plan::device_id_of_dev_str(&p.dev) {
                        pins.insert((p.module.clone(), p.program.clone()), (device, p.ino));
                    }
                }
                self.pins.insert(generation, pins);
                self.probes.insert(generation, set);
            }
        }
    }

    /// Accumulate one in-window poll's counter news under its
    /// generation, plus any retired-binding news already keyed to
    /// the retired generation.
    pub fn accumulate(
        &mut self,
        generation: u64,
        counter_deltas: &[(u64, u64)],
        retired: &[crate::discovery::session::RetiredTripDelta],
    ) {
        for (cookie, n) in counter_deltas {
            let slot = self.counts.entry((generation, *cookie)).or_default();
            *slot = slot.saturating_add(*n);
        }
        for r in retired {
            let slot = self.counts.entry((r.generation, r.cookie)).or_default();
            *slot = slot.saturating_add(r.count);
        }
    }

    /// Join accumulated counts to probe meanings + pinned module
    /// identities + fingerprinted objects. Returns the observations
    /// plus the ENGINE increments with no joinable provenance.
    pub fn build(&self, objects: &[ObjectRecord]) -> (Vec<EngineObservation>, u64) {
        let mut out = Vec::new();
        let mut unkeyed = 0u64;
        for ((generation, cookie), n) in &self.counts {
            if *n == 0 {
                continue;
            }
            let mut reject = || {
                unkeyed = unkeyed.saturating_add(*n);
            };
            let Some(set) = self.probes.get(generation) else {
                reject();
                continue;
            };
            let Some(probe) = set.probes.iter().find(|p| p.cookie == *cookie) else {
                reject();
                continue;
            };
            if probe.family.is_some() || set.load_cookies.contains(cookie) {
                continue;
            }
            let Some(entrypoint) = evidence::engine_index(&probe.symbol) else {
                continue;
            };
            let Some(pins) = self.pins.get(generation) else {
                reject();
                continue;
            };
            let group = (probe.module.clone(), probe.program.to_string());
            let Some((device, ino)) = pins.get(&group) else {
                reject();
                continue;
            };
            let mut matches: Vec<&ObjectRecord> = objects
                .iter()
                .filter(|o| o.device == *device && o.inode == *ino)
                .collect();
            matches.sort_by(|a, b| {
                (!a.id.0.starts_with("build:"), &a.id.0)
                    .cmp(&(!b.id.0.starts_with("build:"), &b.id.0))
            });
            let Some(record) = matches.first() else {
                reject();
                continue;
            };
            out.push(EngineObservation {
                key: SiteKey {
                    object: record.id.clone(),
                    device: *device,
                    inode: *ino,
                    offset: probe.offset,
                },
                generation: *generation,
                entrypoint,
                calls: *n,
                window: EngineWindow::InWindow,
            });
        }
        out.sort();
        (out, unkeyed)
    }
}

// ---------------------------------------------------------------- controller

/// Sessions held for the complete observation (moved into
/// [`observe`], which owns setup, the poll loop and teardown).
pub struct SessionSet<D, B: CountBackend, T, L> {
    pub discovery: D,
    pub count: CountSession<B>,
    pub target: T,
    pub lifecycle: L,
}

/// Safe target identity snapshotted at acquisition (before exit).
#[derive(Debug, Clone)]
pub struct TargetInfo {
    pub pid: u32,
    pub owned: bool,
    pub comm: String,
    pub cmdline: String,
    pub container_id: String,
    pub kernel_release: String,
    pub provider_build_id: String,
    pub provider_path: String,
    pub image_digest: String,
    /// Monotonic nanoseconds at acquisition (requested start for
    /// `--pid`; `run` re-stamps at release).
    pub acquired_ns: u64,
    pub acquired_instant: Instant,
    pub acquired_wall: SystemTime,
}

/// One poll round's control outcome.
enum RoundAction {
    Continue,
    Expired,
    Closed,
    Recycled,
}

/// Pieces a salvage caller already collected (H7/B-6): `Some` = use
/// as-is (that close is never retried — no double-close, single
/// fatal); `None` = attempt best-effort inside salvage now.
struct SalvageSeed {
    drain: Option<CountDrain>,
    snapshot: Option<DiscoverySnapshot>,
    disposition: Option<target::TargetDisposition>,
    effective_end_ns: u64,
}

/// What assembly must know about a salvage (H7): the dominating
/// fatal plus whether counts were lost. Only a lost drain feeds
/// H2's close-evidence taint — intact counts stay T3-reachable even
/// when another close call failed (blanket taint would make
/// violation-in-salvaged-sites unreachable, contradicting T3).
struct SalvageContext {
    fatal: evidence::FatalKind,
    taint_evidence: bool,
}

/// One cached file: the identity-bound bytes plus the freshness
/// (size, mtime) they were read under. Kept in one entry so prune
/// and validation can never disagree about what a path holds.
#[derive(Debug, Clone)]
struct CachedFile {
    file: plan::FileBytes,
    size: u64,
    mtime_ns: u64,
}

/// The session-driven observation: owns both sessions, target
/// custody, lifecycle, accumulation and finalization for one
/// requested window.
struct Runner<'x, D, B: CountBackend, T, L, C: ClockPort, P: ProcPort> {
    cfg: &'x Config,
    info: &'x TargetInfo,
    discovery: D,
    count: CountSession<B>,
    target: T,
    lifecycle: L,
    clock: &'x C,
    proc: &'x mut P,
    cancelled: &'x dyn Fn() -> bool,
    reasons: HashSet<String>,
    adapter: AdapterState,
    activity: Vec<GapCounter>,
    /// Close/salvage-path counters beyond the standard set (Loss
    /// forces PARTIAL; Activity rides as audit trail — e.g. the
    /// reaped-owned-child skipped join).
    extra_counters: Vec<GapCounter>,
    in_window_trip: HashMap<u64, u64>,
    in_window_hits: Vec<legacy::TripHit>,
    in_window_lgcalls: u64,
    /// Typed ENGINE observation collector (R05): the shared
    /// production accumulation path (see [`EngineCollector`]). The
    /// cookie-keyed `in_window_trip` above is untouched (legacy
    /// block + fallback parity).
    engine_collector: EngineCollector,
    /// Window-straddling poll deltas (F-D/A10): a discovery poll
    /// that completes at/after the loop deadline contributes
    /// window-ambiguous tripwire/query counts — explicit loss, never
    /// in-window evidence. Subtracted from the close-tail residual
    /// alongside the in-window accumulators (counted exactly once).
    straddling_trip: HashMap<u64, u64>,
    straddling_lgcalls: u64,
    trigger_observed: bool,
    attached_total: u64,
    cold_gap_queries: u64,
    fork_exec_ignored: u64,
    lifecycle_loss: u64,
    /// Kernel-side lifecycle signals known-dropped (ring overflow
    /// reported through the port).
    lifecycle_dropped: u64,
    /// Conservative prefix gaps accumulated from
    /// `LifecycleDelta.prefix_unwitnessed` (at-least-one; Loss).
    lifecycle_prefix_unwitnessed: u64,
    /// Close drains with missing evidence (non-fallback port,
    /// `close_drain` None): the observer never proved it covered
    /// the tail.
    lifecycle_no_witness: u64,
    /// Close-drain bounded residual (records still queued when the
    /// close drain stopped): an uncovered tail.
    lifecycle_pending: u64,
    /// Exec witnesses past the last fence opportunity (final sweep
    /// and close drain): the tail may mix pre/post-exec identity.
    lifecycle_exec_gap: u64,
    /// Outstanding exec obligation (R20-fix round 2, F3): exec
    /// witnesses a round consumed but did not fence (the round
    /// returned on cancellation or deadline before applying its
    /// kinds). Persisted on the runner — never in round-locals —
    /// so the consumed witness survives to the close drain, which
    /// converts it to an exec gap. Cleared when a fence applies.
    pending_exec_obligation: u64,
    maps_read_failed: u64,
    scan_budget_exhaustions: u64,
    provider_changed_fences: u64,
    planned_paths: HashSet<String>,
    site_cookies: HashMap<SiteKey, u32>,
    /// Backing identities observed in any round (H5:
    /// stat-or-fallback strings — the `fresh` set derived from
    /// this joins group device strings, which are stat-domain).
    seen_backings: HashSet<(String, u64)>,
    snapshot: Snapshot,
    last_live: Vec<maps::Mapping>,
    /// Settled application comm: starts at the acquisition snapshot
    /// (pre-exec for owned children) and refreshes post-release
    /// until it differs (foreign targets never refresh).
    comm: String,
    child_exit: Option<i32>,
    /// Post-reap provenance (round 3, residual D): the owned
    /// child was already reaped when the discovery close ran
    /// (`child_exit` known at finish entry — a mid-window reap),
    /// so the close-phase maps read is reaped-then-read. Gates
    /// the benign close-single Activity treatment together with
    /// the snapshot's close-phase tag and the Exited
    /// disposition; a mere eventual exit never exempts.
    reaped_before_close: bool,
    signal_cut: bool,
    expired: bool,
    fallback_partial: bool,
    window_start_ns: u64,
    requested_start_ns: u64,
    kernel_deadline_ns: u64,
    open_instant: Instant,
    /// Wall counterpart of `requested_start_ns` (R12): re-stamped at
    /// every requested-start assignment (release for owned spawns,
    /// acquisition for `--pid`), so the wall pair always brackets
    /// the requested window the monotonic fields describe — never
    /// the pre-setup open instant. Monotonic stays authoritative.
    wall_start: SystemTime,
    /// Wall counterpart of the effective-end stamp (R12): sampled
    /// ONCE at window close, alongside the monotonic effective-end
    /// stamp (before count/discovery teardown on the clean path —
    /// drain time is not coverage), then reused verbatim by both
    /// `document.context` and the enclosing Capture's wall edges.
    /// Tentatively equals `wall_start` until the close stamp lands.
    wall_end: SystemTime,
    drain_wall_us: u64,
    /// Verified-identity file cache (F-D/A13, freshness per R20):
    /// path → identity-bound bytes plus the freshness they were
    /// read under. Entries are validated per poll by
    /// [`ProcPort::stat_file`] against the CURRENT on-disk
    /// [`FileStat`] and re-read on any mismatch; unmapped entries
    /// never survive a round (a vanished mapping's bytes are
    /// unprovable). Bounded by [`MAX_CACHED_FILES`] /
    /// [`MAX_CACHED_BYTES`].
    file_cache: HashMap<String, CachedFile>,
    /// Relevant paths dropped by the per-poll relevance/bytes
    /// caps (loud loss at finalize).
    relevance_capped: u64,
    /// File reads discarded by the freshness-race guard
    /// (pre/post metadata disagreed): served to nobody, loud loss
    /// at finalize, evidence-tainting (the rows miss).
    unverified_reads: u64,
    /// Setup-vs-runtime classifier (H7/B-6): false until the
    /// observation loop starts (the baseline poll and count fence
    /// are setup machinery — attach phase, exit 4 on failure).
    /// Once set, failures salvage into fatal-Runtime captures
    /// (exit 1) instead of returning Err.
    observation_started: bool,
    /// Traversal accumulator (`Some` once an active port's
    /// baseline poll ran; deepened every round, merged with the
    /// finish tail at close; discarded on recycle/no-window).
    traversal: Option<TraversalCapture>,
}

/// Maximum distinct file paths read per discovery poll
/// (F-D/A13). Typical polls reference a handful of backings;
/// 256 is 10x headroom — beyond it the poll keeps the
/// lexicographically first 256 (deterministic under pathology)
/// and reports the remainder as `discovery.relevance_capped`
/// loss. Counts distinct PATHS (aliases of one file each
/// count): the bound that matters is read calls + resident
/// clones, both path-keyed.
const MAX_RELEVANT_FILES_PER_POLL: usize = 256;

/// Maximum cached file entries across polls (F-D/A13). Overflow
/// (mapping churn across polls) retains only the current poll's
/// relevant set — eviction is a silent perf event (the next poll
/// re-reads fresh bytes), never a loss.
const MAX_CACHED_FILES: usize = 256;

/// Maximum accumulated file bytes per poll's read set (F-D/A13).
/// The read loop stops past this (remaining paths join
/// `discovery.relevance_capped`); the cache evicts largest-first
/// past this. It bounds the per-poll out-map accumulation —
/// total transient resident is ~2x (out-map clones + cache) plus
/// retained entries, all path-bounded above. Sized at ~8x a
/// legitimate multi-provider set (~15MB: provider + libcrypto +
/// siblings) so small sets always read fully; only pathological
/// counts (100s of distinct backings) stop here instead of
/// growing into the gigabytes the old read-all round map
/// routinely held.
const MAX_CACHED_BYTES: usize = 128 * 1024 * 1024;

/// File paths a discovery poll's consumers can touch (F-D/A13):
/// candidate backing identities + array-owner identities (a
/// superset of the advertising exact-VMA join — ALL mappings
/// containing the array, so VMA overlap can never strand a
/// read) + new object identities, expanded to ALL mapped-path
/// aliases (any x-bit — dispatch arrays live in data mappings;
/// anonymous mappings have no bytes and are excluded). Every
/// round-map consumer (plan_rows, object_id_for_mapping,
/// advertising_object_id) resolves within these (dev, ino)
/// identities, so scoping reads to this set changes no outcome
/// — only I/O. Returns the sorted path set plus the
/// over-cap dropped count (0 on the common path).
fn relevant_paths(delta: &DiscoveryDelta, live: &[maps::Mapping]) -> (BTreeSet<String>, u64) {
    // H5 single-domain relevance (dual-facet, mirroring
    // `bindings_alive`): backings/objects carry stat identity
    // and array owners resolve to stat-or-fallback here
    // (their mapping is in hand). A mapping is relevant when
    // its ino matches an ident AND the device binds in one
    // domain — stat-vs-stat when statable, else maps-vs-maps
    // (the read then fails into a cache miss, as before).
    // Maps text never joins against a stat ident: on
    // btrfs/overlay the old join excluded every backing path
    // from the round's reads (all sites missed).
    let mut idents: HashSet<(String, u64)> = HashSet::new();
    for c in &delta.candidates {
        if let Some(b) = &c.backing {
            idents.insert((b.dev.clone(), b.ino));
        }
        if c.arr != 0 {
            for m in live
                .iter()
                .filter(|m| m.start <= c.arr && c.arr < m.end && m.ino != 0)
            {
                idents.insert((crate::discovery::session::backing_dev(m), m.ino));
            }
        }
    }
    for o in &delta.objects {
        idents.insert((o.dev.clone(), o.ino));
    }
    // One stat-facet pass over the live mappings.
    let facets: Vec<(u64, &str, Option<String>, &str)> = live
        .iter()
        .map(|m| {
            (
                m.ino,
                m.dev.as_str(),
                crate::discovery::session::stat_dev_of(&m.path),
                m.path.as_str(),
            )
        })
        .collect();
    let mut paths: BTreeSet<String> = facets
        .iter()
        .filter(|(ino, maps_dev, stat, _)| {
            *ino != 0
                && idents.iter().any(|(d, i)| {
                    *i == *ino
                        && match stat {
                            Some(cur) => cur == d,
                            None => maps_dev == d,
                        }
                })
        })
        .map(|(_, _, _, path)| path.to_string())
        .collect();
    let dropped = paths.len().saturating_sub(MAX_RELEVANT_FILES_PER_POLL) as u64;
    if dropped > 0 {
        paths = paths
            .into_iter()
            .take(MAX_RELEVANT_FILES_PER_POLL)
            .collect();
    }
    (paths, dropped)
}

/// Post-read stat check with race signal (R20-fix finding 6):
/// true when the file still stats `cur` (verified); false with
/// `raced` set when it moved (proven mutation during the read —
/// the caller discards the bytes). Called only when the read
/// identity matched pre-stat (guard short-circuit at the call
/// site), preserving stat-call alignment; read drift (pre-stat
/// raced, consistent bytes) keeps the legacy serve-uncached
/// shape and is NOT a race.
fn post_stat_matches<P: ProcPort>(proc: &mut P, p: &str, cur: FileStat, raced: &mut bool) -> bool {
    if proc.stat_file(p) == Some(cur) {
        true
    } else {
        *raced = true;
        false
    }
}

impl<D, B, T, L, C, P> Runner<'_, D, B, T, L, C, P>
where
    D: DiscoveryPort,
    B: CountBackend,
    T: TargetPort,
    L: LifecyclePort,
    C: ClockPort,
    P: ProcPort,
{
    fn reason(&mut self, r: &str) {
        self.reasons.insert(r.to_string());
    }

    /// Merge the traversal finish tail into the accumulator and
    /// raise the PARTIAL reasons its end state earns (a storm or
    /// throttle still in force at close, a failed tail drain,
    /// incomplete/unjoined tail records). No-op when traversal
    /// never ran.
    fn absorb_traversal_tail(&mut self) {
        if self.traversal.is_none() {
            return;
        }
        let tail = self.discovery.finish_traversal();
        if tail.detached {
            self.reason("traversal-storm");
        }
        if tail.throttled {
            self.reason("traversal-throttled");
        }
        if tail.finish_error.is_some() {
            self.reason("traversal-finish-error");
        }
        if tail
            .done
            .iter()
            .any(|w| !matches!(w.outcome, ScanOutcome::Complete { .. }))
        {
            self.reason("traversal-incomplete");
        }
        if !tail.findings.is_empty() {
            self.reason("traversal-unjoined");
        }
        if let Some(t) = self.traversal.as_mut() {
            t.merge(tail);
        }
    }

    /// Post-exec comm settle (owned only): refresh until the
    /// snapshot differs from the pre-exec acquisition value, then
    /// freeze — later setproctitle changes do not rewrite identity.
    /// Call BEFORE any custody reap (never after: a reused pid
    /// could supply another process's comm, and a reaped child
    /// keeps no post-hoc read). No-op once settled, after a known
    /// exit, on foreign targets, or when /proc is unreadable.
    fn settle_comm(&mut self) {
        if !self.info.owned || self.child_exit.is_some() || self.comm != self.info.comm {
            return;
        }
        if let Some(comm) = self.proc.read_comm(self.info.pid) {
            self.comm = comm;
        }
    }

    /// Pre-read every distinct mapped path once per round, bound
    /// to its read-time identity (F-A/A3). Failures skip (the
    /// planner misses those rows loud as unreadable).
    /// Relevance-scoped file bytes for one discovery poll
    /// (F-D/A13): only [`relevant_paths`] are read, through the
    /// verified-identity cache (stat-validated per poll, re-read
    /// on any mismatch or stat failure). Unreadable paths are
    /// skipped exactly like the old read-all round map (their
    /// rows miss with "unreadable" + the cap counter stays the
    /// loud path for cap drops). Callers pass the returned map to
    /// [`adapt_delta`](adapt_delta) and attach; the cache retains
    /// across polls within its bounds.
    fn read_relevant_files(
        &mut self,
        delta: &DiscoveryDelta,
        live: &[maps::Mapping],
    ) -> HashMap<String, plan::FileBytes> {
        let (relevant, mut dropped) = relevant_paths(delta, live);
        // R14: the round's byte budget binds BEFORE any read —
        // every read carries the remaining allowance (capped per
        // object), so even the first object cannot bypass the cap
        // (F17: the old loop always read at least one path
        // unbounded). Refusals skip the path — its rows miss
        // "unreadable" — and join the dropped count, so skipped
        // evidence always lands as `discovery.relevance_capped`
        // loss (PARTIAL, never a completeness claim).
        let round = self.proc.read_budget();
        let mut out = HashMap::new();
        let mut out_bytes: usize = 0;
        let mut remaining = relevant.len() as u64;
        for p in &relevant {
            remaining -= 1;
            // Bytes cap: stop past the round budget. Skipped paths
            // join the dropped count: their rows miss "unreadable"
            // and the loss counter says so.
            if out_bytes > round && !out.is_empty() {
                dropped = dropped.saturating_add(remaining + 1);
                break;
            }
            // Per-read allowance: the remaining round budget,
            // capped per object; checked arithmetic (an
            // over-consumed accumulator yields zero, never wraps).
            let allowance = round
                .checked_sub(out_bytes)
                .unwrap_or_default()
                .min(plan::MAX_OBJECT_BYTES);
            let current = self.proc.stat_file(p);
            // Identity + freshness (R20): an in-place content change
            // keeps (dev, ino) but moves size and/or mtime, so
            // identity-only validation would serve stale bytes under
            // a stale fingerprint indefinitely (P6 implementation-only
            // replacement). Any mismatch re-reads.
            let hit = matches!(
                (&current, self.file_cache.get(p)),
                (Some(cur), Some(cached))
                    if cached.file.dev == cur.dev
                        && cached.file.ino == cur.ino
                        && cached.size == cur.size
                        && cached.mtime_ns == cur.mtime_ns
            );
            if !hit {
                match self.proc.read_file_bound(p, allowance) {
                    Ok((bytes, (dev, ino))) => {
                        let read = plan::FileBytes { bytes, dev, ino };
                        // Torn-read guard: the file may have changed
                        // between the pre-stat and the read (stat old
                        // / read new, or the fd pinning the old inode
                        // under a new stat). Cache only when the read
                        // identity matches the pre-stat AND a
                        // post-read stat still matches it; otherwise
                        // serve these bytes this round uncached and
                        // re-read next poll. An unstatable path never
                        // caches (freshness unprovable).
                        let mut raced = false;
                        let verified = match current {
                            Some(cur)
                                if (dev, ino) == (cur.dev, cur.ino)
                                    && post_stat_matches(&mut *self.proc, p, cur, &mut raced) =>
                            {
                                Some(cur)
                            }
                            _ => None,
                        };
                        // Proven mid-read mutation (R20-fix finding
                        // 6): the read identity matched pre-stat
                        // but the post-read stat moved — the bytes
                        // may be torn across a same-size edit.
                        // DISCARD: never cached, never forwarded
                        // for fingerprinting (the rows miss exactly
                        // like an unreadable file, and the next
                        // poll re-reads). Loud via
                        // `discovery.unverified_read` + evidence
                        // taint. Read drift (pre-stat raced, the
                        // bound read is a consistent-inode
                        // snapshot) and unstatable paths keep the
                        // legacy serve-uncached shape — no mutation
                        // of the read bytes was proven there.
                        if raced {
                            self.unverified_reads = self.unverified_reads.saturating_add(1);
                            self.file_cache.remove(p);
                            continue;
                        }
                        if let Some(cur) = verified {
                            self.file_cache.insert(
                                p.clone(),
                                CachedFile {
                                    file: read.clone(),
                                    size: cur.size,
                                    mtime_ns: cur.mtime_ns,
                                },
                            );
                        }
                        // Fresh reads always fit the allowance (the
                        // reader refuses past it first), so admit
                        // directly — never fall through to the hit
                        // admission below (that would count the bytes
                        // twice AND serve a stale entry over bytes
                        // deliberately served uncached).
                        out_bytes = out_bytes.saturating_add(read.bytes.len());
                        out.insert(p.clone(), read);
                        continue;
                    }
                    // Budget refusal: loud, like any other cap drop
                    // (rows miss "unreadable"; the loss counter
                    // says why).
                    Err(e) if e.kind() == std::io::ErrorKind::FileTooLarge => {
                        self.file_cache.remove(p);
                        dropped = dropped.saturating_add(1);
                        continue;
                    }
                    Err(_) => {
                        self.file_cache.remove(p);
                        continue;
                    }
                }
            }
            // R14 fix: cached payloads are output-admitted only
            // within the remaining allowance — a hit past it skips
            // loud like a fresh-read refusal (a fresh read always
            // fits: the reader refuses past `allowance` first).
            if let Some(cached) = self.file_cache.get(p) {
                if cached.file.bytes.len() > allowance {
                    dropped = dropped.saturating_add(1);
                    continue;
                }
                out_bytes = out_bytes.saturating_add(cached.file.bytes.len());
                out.insert(p.clone(), cached.file.clone());
            }
        }
        self.relevance_capped = self.relevance_capped.saturating_add(dropped);
        self.prune_file_cache(live, &relevant);
        out
    }

    /// Cache bounds enforcement (F-D/A13): unmapped entries never
    /// survive a round; count/bytes overflow retains only the
    /// current poll's relevant set, then evicts largest-first
    /// past the bytes cap. Eviction is silent (the next poll
    /// re-reads fresh bytes — a perf event, never a loss).
    fn prune_file_cache(&mut self, live: &[maps::Mapping], relevant: &BTreeSet<String>) {
        let mapped: HashSet<&str> = live.iter().map(|m| m.path.as_str()).collect();
        self.file_cache.retain(|p, _| mapped.contains(p.as_str()));
        let cached_bytes: usize = self.file_cache.values().map(|f| f.file.bytes.len()).sum();
        if self.file_cache.len() <= MAX_CACHED_FILES && cached_bytes <= MAX_CACHED_BYTES {
            return;
        }
        self.file_cache.retain(|p, _| relevant.contains(p));
        let mut survivors: Vec<(String, usize)> = self
            .file_cache
            .iter()
            .map(|(p, f)| (p.clone(), f.file.bytes.len()))
            .collect();
        survivors.sort_by(|a, b| b.1.cmp(&a.1));
        let mut bytes: usize = survivors.iter().map(|(_, s)| s).sum();
        for (p, s) in &survivors {
            if bytes <= MAX_CACHED_BYTES {
                break;
            }
            if self.file_cache.remove(p).is_some() {
                bytes = bytes.saturating_sub(*s);
            }
        }
    }

    /// One discovery poll plus its completion stamp (F-D/A13):
    /// the stamp is taken at poll return so the straddle verdict
    /// measures the POLL, never the file reads + adapt work after
    /// it (A10's "poll completing at/after the edge").
    fn poll_discovery(&mut self) -> anyhow::Result<(DiscoveryDelta, Instant)> {
        let delta = self.discovery.poll(PollBudget::default())?;
        let poll_end = self.clock.now();
        Ok((delta, poll_end))
    }

    /// Apply one discovery poll's delta: adapt, attach, and
    /// accumulate. Returns (budget_exhausted, candidates_changed).
    /// `poll_end` is the poll-completion stamp from
    /// [`poll_discovery`](Self::poll_discovery); `deadline` (loop
    /// rounds only, never the setup baseline poll) is the window
    /// edge the poll must complete before: rounds only poll
    /// pre-deadline, so a poll completing at/after it straddled
    /// the edge and its tripwire deltas route to the
    /// straddling-loss accumulators instead of the in-window
    /// evidence (F-D/A10).
    fn apply_delta(
        &mut self,
        delta: &DiscoveryDelta,
        poll_end: Instant,
        ctx: &AdapterCtx,
        deadline: Option<Instant>,
    ) -> anyhow::Result<(bool, bool)> {
        let exhausted = delta.budget_exhausted;
        let adapted = adapt_delta(&mut self.adapter, delta, ctx);
        // R05: snapshot the live binding's probe meanings + pins
        // through the shared collector (absent bindings consume
        // nothing — see `EngineCollector`).
        self.engine_collector.snapshot_binding(
            delta.trip_generation,
            self.discovery.snapshot().legacy.set,
            &delta.trip_module_pins,
        );
        self.activity.extend(adapted.activity);
        self.cold_gap_queries = self
            .cold_gap_queries
            .saturating_add(adapted.pre_window_queries);
        if let Some(trip) = adapted.tripwire {
            // Window-ambiguous poll: the counter values were read
            // after the window closed — the delta mixes pre- and
            // post-deadline increments inseparably (hits carry no
            // timestamps), so all of it is loss. Anything else is
            // in-window evidence (the round checked pre-deadline).
            let straddled = deadline.is_some_and(|d| poll_end >= d);
            if straddled {
                for (cookie, n) in trip.counter_deltas {
                    let slot = self.straddling_trip.entry(cookie).or_default();
                    *slot = slot.saturating_add(n);
                }
                self.straddling_lgcalls = self
                    .straddling_lgcalls
                    .saturating_add(trip.executed_legacy_queries_delta);
            } else {
                for (cookie, n) in &trip.counter_deltas {
                    let slot = self.in_window_trip.entry(*cookie).or_default();
                    *slot = slot.saturating_add(*n);
                }
                // R05: the same evidence through the shared
                // collector for the typed ENGINE plane.
                self.engine_collector.accumulate(
                    adapted.trip_generation,
                    &trip.counter_deltas,
                    &[],
                );
                self.in_window_hits.extend(trip.hits.iter());
                self.in_window_lgcalls = self
                    .in_window_lgcalls
                    .saturating_add(trip.executed_legacy_queries_delta);
            }
        }
        // R05/F-R05-3: retired-binding news already carries its
        // generation. In-window polls accumulate it under the
        // retired generation (plus the cookie-keyed legacy
        // ledger for parity); straddled polls shed it as
        // window-ambiguous loss, never evidence.
        if !adapted.retired_trip.is_empty() {
            let straddled = deadline.is_some_and(|d| poll_end >= d);
            if straddled {
                for r in &adapted.retired_trip {
                    let slot = self.straddling_trip.entry(r.cookie).or_default();
                    *slot = slot.saturating_add(r.count);
                }
            } else {
                for r in &adapted.retired_trip {
                    let slot = self.in_window_trip.entry(r.cookie).or_default();
                    *slot = slot.saturating_add(r.count);
                }
                self.engine_collector.accumulate(
                    adapted.trip_generation,
                    &[],
                    &adapted.retired_trip,
                );
            }
        }
        self.trigger_observed |= adapted.trigger_observed;
        let report = self.count.attach_delta(
            &adapted.delta,
            ctx.live,
            ctx.files,
            self.clock.monotonic_ns(),
        )?;
        self.attached_total = self.attached_total.saturating_add(report.attached);
        for site in &adapted.delta.discovered {
            if let Some(cookie) =
                self.count
                    .cookie_for(site.site.device, site.site.inode, site.site.offset)
            {
                self.site_cookies.insert(site.site.clone(), cookie);
                if let Some(prov) = self.count.provenance(cookie) {
                    if !prov.link_path.is_empty() {
                        self.planned_paths.insert(prov.link_path.clone());
                    }
                }
            }
        }
        Ok((exhausted, report.candidates_changed))
    }

    /// Build typed ENGINE observations (R05) through the shared
    /// collector over the adapter's fingerprinted objects.
    fn build_engine_observations(&self) -> (Vec<EngineObservation>, u64) {
        self.engine_collector.build(&self.adapter.objects)
    }

    /// Exec witnesses in one lifecycle delta: the target's own
    /// execs are fence-tracked (round sweeps) or continuity-gapped
    /// (final sweep and close drain — no generation left to version
    /// into), never ignored-counted.
    fn exec_witnesses(delta: &LifecycleDelta) -> u64 {
        delta
            .events
            .iter()
            .filter(|e| e.kind == LifecycleKind::Exec)
            .count() as u64
    }

    /// Fold one lifecycle delta (round sweep, final sweep, or
    /// close-time ring drain) into the accumulators. Only Fork events
    /// count as ignored: the target's own execs are fence-tracked by
    /// the snapshot generation (counting them here would double-book
    /// the observed spawn-exec as ignored). Kernel-side drops ride
    /// separately from host scan loss so the two sources stay
    /// attributable.
    fn fold_lifecycle(&mut self, delta: &LifecycleDelta) {
        self.fork_exec_ignored = self.fork_exec_ignored.saturating_add(
            delta
                .events
                .iter()
                .filter(|e| e.kind == LifecycleKind::Fork)
                .count() as u64,
        );
        self.lifecycle_loss = self.lifecycle_loss.saturating_add(delta.loss);
        self.lifecycle_dropped = self.lifecycle_dropped.saturating_add(delta.dropped);
        self.lifecycle_prefix_unwitnessed = self
            .lifecycle_prefix_unwitnessed
            .saturating_add(delta.prefix_unwitnessed);
    }

    /// One bounded poll round: maps, corpse check, fence compare,
    /// lifecycle sweep, discovery catch-up polls, single fence.
    fn round(&mut self, deadline: Instant, settle_end: Instant) -> anyhow::Result<RoundAction> {
        let pid = self.info.pid;
        let owned = self.info.owned;
        let t0 = self.clock.now();
        let live = match self.proc.read_maps(pid) {
            Ok(live) => live,
            Err(_) => {
                // Target gone, or /proc flakiness: custody decides.
                if owned {
                    // Last-gasp settle before the reap below.
                    self.settle_comm();
                    if let Ok(Some(code)) = self.target.poll_exit() {
                        self.child_exit = Some(code);
                        return Ok(RoundAction::Closed);
                    }
                } else if self.target.verify().is_err() {
                    return Ok(RoundAction::Recycled);
                }
                self.maps_read_failed += 1;
                return Ok(RoundAction::Continue);
            }
        };
        if self.clock.now().saturating_duration_since(t0) > POLL_BUDGET {
            // Overruns skip the round (§5): the deadline still binds.
            self.scan_budget_exhaustions += 1;
            return Ok(RoundAction::Continue);
        }
        if self.clock.now() >= deadline {
            // Metadata I/O ran past the deadline: no post-deadline
            // discovery poll (its tripwire would pollute in-window
            // evidence) — the loop closes instead.
            return Ok(RoundAction::Expired);
        }
        // Pre-reap comm settle: the corpse path below reaps, after
        // which no post-hoc comm read exists — a fast exit would
        // otherwise keep the pre-exec observer comm. Settles until
        // the snapshot differs, then freezes.
        self.settle_comm();
        // Post-read liveness: close corpses, never fence them. The
        // bounded wait covers the `exit_mm`-to-zombie window (maps
        // already empty, waitpid still blind) through custody — never
        // a raw waitpid outside OwnedTarget.
        if live.is_empty() && owned {
            if let Ok(Some(code)) = self.target.poll_exit() {
                self.child_exit = Some(code);
                return Ok(RoundAction::Closed);
            }
            let waited_from = self.clock.now();
            while self.clock.now().saturating_duration_since(waited_from) < CORPSE_WAIT {
                self.clock.sleep(Duration::from_millis(1));
                // Settle before each wait poll: the exit may land
                // on this poll, ending post-hoc comm reads.
                self.settle_comm();
                if let Ok(Some(code)) = self.target.poll_exit() {
                    self.child_exit = Some(code);
                    return Ok(RoundAction::Closed);
                }
            }
        }
        let mut fresh = HashSet::new();
        for m in &live {
            // H5: stat-or-fallback (joins stat-domain group
            // strings; a same-ino x-device swap reads fresh,
            // correctly — it IS a new file).
            let ident = (crate::discovery::session::backing_dev(m), m.ino);
            if self.seen_backings.insert(ident.clone()) {
                fresh.insert(ident);
            }
        }
        let exe = self.proc.read_exe(pid);
        let mut sizes = HashMap::new();
        for p in &self.planned_paths {
            sizes.insert(p.clone(), self.proc.file_len(p));
        }
        let planned: Vec<String> = self.planned_paths.iter().cloned().collect();
        let next = snapshot(exe, &live, &planned, &sizes);
        let mut kinds = detect_fence(&self.snapshot, &next);
        self.snapshot = next;
        self.last_live = live.clone();
        // Fork/exec detection: every NEW child counted once. Only
        // Fork events count as ignored: the target's own execs are
        // fence-tracked by the snapshot generation (counting them
        // here double-books the observed spawn-exec as ignored).
        let sweep = self.lifecycle.poll();
        self.fold_lifecycle(&sweep);
        // Witness-driven exec fence (R20-fix): a kernel Exec witness
        // fences even when the exe snapshot cannot see it (same-path
        // exec with unchanged mappings). The snapshot arm above
        // already flagged genuine exe-link flips, so this OR-ing
        // never double-fences — one fence per round either way.
        if Self::exec_witnesses(&sweep) > 0 && !kinds.contains(&FenceKind::Exec) {
            kinds.push(FenceKind::Exec);
        }
        // Persist the exec obligation BEFORE the early returns
        // below (R20-fix round 2, F3): a witness consumed here must
        // survive a cancellation/deadline return to the close
        // drain (which converts it to an exec gap) — a round-local
        // would evaporate with `kinds`.
        self.pending_exec_obligation = self
            .pending_exec_obligation
            .saturating_add(Self::exec_witnesses(&sweep));
        // Slow metadata work above (fence snapshots, lifecycle
        // scan — file reads moved per-poll below, F-D/A13) may have
        // crossed the deadline — or a signal may have landed —
        // since the pre-read check: no post-deadline discovery poll
        // (its tripwire would pollute in-window evidence). The loop
        // owns the signal cut.
        if (self.cancelled)() {
            return Ok(RoundAction::Continue);
        }
        if self.clock.now() >= deadline {
            return Ok(RoundAction::Expired);
        }
        // Discovery catch-up: backpressure re-polls, bounded, with
        // the deadline enforced even while discovery is busy.
        let post_settle = self.clock.now() >= settle_end;
        let mut fence_candidates = false;
        let mut catches = 0u32;
        loop {
            // Poll → read-relevant → apply (F-D/A13): the file
            // reads follow the poll so only this delta's paths
            // are touched (verified-identity cache across polls).
            let (delta, poll_end) = self.poll_discovery()?;
            let files = self.read_relevant_files(&delta, &live);
            let pinned = self.cfg.resolved_provider.clone();
            let ctx = AdapterCtx {
                live: &live,
                files: &files,
                pinned_provider: pinned,
                fresh: &fresh,
                post_settle,
                // Rounds run post-release; --pid has no release
                // boundary (its pre-acquire blindness already
                // withholds COMPLETE).
                post_release: self.info.owned,
                baseline: false,
            };
            let (exhausted, fence) = self.apply_delta(&delta, poll_end, &ctx, Some(deadline))?;
            fence_candidates |= fence;
            if !exhausted {
                break;
            }
            catches += 1;
            if catches >= MAX_CATCHUP_POLLS {
                self.scan_budget_exhaustions += 1;
                break;
            }
            if (self.cancelled)() || self.clock.now() >= deadline {
                break;
            }
        }
        // Traversal poll (same cadence, active ports only — the
        // harvest-only default no-ops): fold records/findings and
        // the PARTIAL reasons this round earned. Errors propagate
        // to salvage like any mid-window infrastructure failure.
        if self.discovery.traversal_active() {
            let tdelta = self.discovery.poll_traversal(false)?;
            if let Some(t) = self.traversal.as_mut() {
                for r in tdelta.partial_reasons {
                    self.reasons.insert(r);
                }
                t.done.extend(tdelta.done);
                t.findings.extend(tdelta.findings);
                t.polls += tdelta.polls;
                // P1: typed gate observations accumulate with the
                // compat reasons above (a mid-window storm that
                // recovered still cut observation).
                t.storm_polls += u64::from(tdelta.storm);
                t.throttled_polls += u64::from(tdelta.throttled);
                apply_corrections(&mut t.done, &tdelta.corrections);
                if !tdelta.admitted.is_empty() {
                    t.admitted_by_op = tdelta.admitted;
                }
                // Unknown-flags union (keys never un-observe);
                // census loss keeps its high-water (cumulative,
                // never shrinks).
                t.admitted_unknown_by_op.extend(tdelta.admitted_unknown);
                t.census_loss = t.census_loss.max(tdelta.census_loss);
            }
        }
        // One fence per round (Exec > ProviderChanged >
        // MappingsChanged > CandidatesChanged).
        let fence_reason = if kinds.contains(&FenceKind::Exec) {
            Some(CountFence::Exec)
        } else if kinds.contains(&FenceKind::ProviderChanged) {
            Some(CountFence::ProviderChanged)
        } else if kinds.contains(&FenceKind::MappingsChanged) {
            Some(CountFence::MappingsChanged)
        } else if fence_candidates {
            Some(CountFence::CandidatesChanged)
        } else {
            None
        };
        if let Some(reason) = fence_reason {
            self.count.fence(reason)?;
            // The fence consumed this round's witness (F3): one
            // fence per round covers the round's exec-ness (local
            // or snapshot-sourced — either versions the
            // generation), so the persisted obligation clears.
            if kinds.contains(&FenceKind::Exec) {
                self.pending_exec_obligation = 0;
            }
        }
        if kinds.contains(&FenceKind::ProviderChanged) {
            self.provider_changed_fences += 1;
            // The discovery generation turned over: the traversal
            // backend retires its GEN/cache epoch with it
            // (in-flight opens abandon as Churned — their arrays
            // may be freed/reused by the new provider).
            self.discovery.note_provider_turnover()?;
        }
        Ok(RoundAction::Continue)
    }

    /// Mid-window infrastructure failure (H7/B-6): before the
    /// observation loop this keeps the setup shape (best-effort
    /// cleanup, cleanup failures chained onto the original error);
    /// once observing, it salvages into a fatal-Runtime capture.
    fn fail(mut self, err: anyhow::Error) -> anyhow::Result<Capture> {
        // Outstanding exec obligation (F3): a consumed-but-unfenced
        // witness rides into salvage as a gap (the fatal verdict
        // dominates, but the lost transition stays exact).
        self.lifecycle_exec_gap = self
            .lifecycle_exec_gap
            .saturating_add(std::mem::replace(&mut self.pending_exec_obligation, 0));
        if self.observation_started {
            let effective_end_ns = self.clock.monotonic_ns().min(self.kernel_deadline_ns);
            // R12: the single close sample, alongside the monotonic
            // end stamp — reused by the document and the Capture.
            self.wall_end = self.clock.wall_now();
            return Ok(self.salvage(
                SalvageSeed {
                    drain: None,
                    snapshot: None,
                    disposition: None,
                    effective_end_ns,
                },
                err,
            ));
        }
        let mut err = err;
        if let Err(e) = self.count.close_and_drain(self.cfg.grace) {
            err = err.context(format!("setup abandon also failed to close counts: {e:#}"));
        }
        if let Err(e) = self.discovery.finish() {
            err = err.context(format!(
                "setup abandon also failed to finish discovery: {e:#}"
            ));
        }
        if let Err(e) = self.target.finish_observation() {
            err = err.context(format!(
                "setup abandon also failed to finish observation: {e:#}"
            ));
        }
        Err(err)
    }

    /// Post-observation salvage (H7/B-6): every remaining close is
    /// attempted best-effort, every failure recorded as a typed loss
    /// counter, and the doc assembles from collected state with a
    /// fatal-Runtime verdict. Never fails; never retries a close the
    /// caller already attempted (a `Some` seed piece is used as-is).
    fn salvage(mut self, seed: SalvageSeed, err: anyhow::Error) -> Capture {
        self.reason("close-failure");
        // Traversal best-effort tail (drained-so-far survives:
        // proved facts — H7; the finish error rides inside, never
        // fails salvage).
        self.absorb_traversal_tail();
        let mut failures = vec![format!("{err:#}")];
        let drain_failed: bool;
        let drain = match seed.drain {
            Some(drained) => {
                drain_failed = false;
                Some(drained)
            }
            None => match self.count.close_and_drain(self.cfg.grace) {
                Ok(drained) => {
                    drain_failed = false;
                    Some(drained)
                }
                Err(e) => {
                    self.extra_counters.push(typed_counter(
                        "count.close_failed",
                        CounterKind::Loss,
                        CounterUnits::Events,
                        CounterSource::Drain,
                        1,
                    ));
                    failures.push(format!("close_and_drain: {e:#}"));
                    drain_failed = true;
                    None
                }
            },
        };
        let snapshot = match seed.snapshot {
            Some(snapshot) => snapshot,
            None => {
                // Snapshot BEFORE attempting finish: on failure the
                // live session is taken and only this pre-state
                // survives for assembly.
                // Round 3, residual D: post-reap provenance for the
                // maps-loss exemption — captured at finish entry (a
                // later reap during finish_observation must not
                // backdate the close read as reaped-then-read).
                self.reaped_before_close = self.info.owned && self.child_exit.is_some();
                let pre = self.discovery.snapshot();
                match self.discovery.finish() {
                    Ok(snapshot) => snapshot,
                    Err(e) => {
                        self.extra_counters.push(typed_counter(
                            "discovery.finish_failed",
                            CounterKind::Loss,
                            CounterUnits::Events,
                            CounterSource::Discovery,
                            1,
                        ));
                        failures.push(format!("discovery finish: {e:#}"));
                        pre
                    }
                }
            }
        };
        let disposition = match seed.disposition {
            Some(disposition) => Some(disposition),
            None => match self.target.finish_observation() {
                Ok(disposition) => Some(disposition),
                Err(e) => {
                    self.extra_counters.push(typed_counter(
                        "target.finish_failed",
                        CounterKind::Loss,
                        CounterUnits::Events,
                        CounterSource::Lifecycle,
                        1,
                    ));
                    failures.push(format!("finish_observation: {e:#}"));
                    None
                }
            },
        };
        if let Some(target::TargetDisposition::Exited { code }) = &disposition {
            self.child_exit = Some(*code);
        }
        // A lost drain means lost counts (sites gone, not zero) —
        // assemble over an explicitly empty drain, never a forged one.
        let drain = drain.unwrap_or(CountDrain {
            current: Vec::new(),
            fenced: Vec::new(),
            counters: Vec::new(),
        });
        let fatal = evidence::FatalKind::Runtime(crate::report::bound_line(&failures.join("; ")));
        self.assemble(
            snapshot,
            drain,
            disposition,
            seed.effective_end_ns,
            Some(SalvageContext {
                fatal,
                taint_evidence: drain_failed,
            }),
        )
    }

    /// Setup-phase result with no window opened (fast exit, setup
    /// cut): the whole requested window is startup gap, the exit
    /// status rides along, and nothing claims COMPLETE.
    fn no_window_result(mut self) -> Capture {
        // R12: the single close sample (no window was observed, but
        // the pair still closes here) — reused below.
        self.wall_end = self.clock.wall_now();
        // No window opened: nothing retained, traversal included.
        self.traversal = None;
        let requested_end = self
            .requested_start_ns
            .saturating_add(duration_ns(self.cfg.duration));
        let window = CaptureWindow {
            requested_start_ns: self.requested_start_ns,
            requested_end_ns: requested_end,
            effective_start_ns: requested_end,
            effective_end_ns: requested_end,
            signal_cut: self.signal_cut,
        };
        let mut document = evidence::finalize(FinalizeInput {
            window,
            sites: Vec::new(),
            fenced: Vec::new(),
            objects: Vec::new(),
            coverage: Vec::new(),
            counters: Vec::new(),
            fatal: None,
            target: doc_target(
                self.info.pid,
                &self.comm,
                &self.info.container_id,
                &self.info.image_digest,
            ),
            openssl: OpensslVersion::unknown(),
            disposition: self.child_exit.map(DispositionRecord::exited),
            policy: None,
            legacy_partition: LegacyCallPartition::default(),
            engine_observations: Vec::new(),
            traversal: None,
        });
        // R12: retain the one consistently captured pair (no window
        // was observed, but the host context is still honest context).
        document.context = Some(doc_context(
            &self.info.kernel_release,
            self.wall_start,
            self.wall_end,
        ));
        self.emit_gap_reasons(document.reasons());
        if !self.trigger_observed {
            self.reason("no-query");
        }
        if self.signal_cut {
            self.reason("interrupted");
        }
        if !self.info.owned {
            self.reason("pid-prewindow-blind");
        }
        let disposition = self
            .child_exit
            .map(|code| target::TargetDisposition::Exited { code });
        self.finish_capture(
            document,
            FinishParts {
                outcome: Outcome::Partial,
                executions: Vec::new(),
                stale: Vec::new(),
                counters: Counters::default(),
                legacy: serde_json::Value::Null,
                harvest_doc: serde_json::json!({}),
                disposition,
                window_actual: Duration::ZERO,
            },
        )
    }

    /// Mid-window recycle: best-effort close, every observation
    /// discarded (pid-scoped evidence is tainted), fatal verdict.
    fn recycled(mut self) -> Capture {
        // H7: post-observation close — errors recorded as loss, not
        // swallowed (the recycle verdict dominates, but close
        // failures stay visible as typed counters + reason).
        // Pid-scoped traversal evidence is tainted like the rest:
        // discarded, never retained.
        self.traversal = None;
        let mut close_failed = false;
        if self.count.close_and_drain(self.cfg.grace).is_err() {
            self.extra_counters.push(typed_counter(
                "count.close_failed",
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Drain,
                1,
            ));
            close_failed = true;
        }
        if self.discovery.finish().is_err() {
            self.extra_counters.push(typed_counter(
                "discovery.finish_failed",
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Discovery,
                1,
            ));
            close_failed = true;
        }
        let requested_end = self
            .requested_start_ns
            .saturating_add(duration_ns(self.cfg.duration));
        let now_ns = self.clock.monotonic_ns();
        // R12: the single close sample, alongside the monotonic end
        // stamp — reused by the document and the Capture.
        self.wall_end = self.clock.wall_now();
        // R21-F4 (round 2, residual E): same setup-overrun collapse
        // as the assembly path (a close sample predating the
        // clamped start would invert the window — collapse to the
        // empty window at the effective start instead).
        let recycled_start = effective_start_ns(self.window_start_ns, self.requested_start_ns);
        let mut document = evidence::finalize(FinalizeInput {
            window: CaptureWindow {
                requested_start_ns: self.requested_start_ns,
                requested_end_ns: requested_end,
                effective_start_ns: recycled_start,
                effective_end_ns: now_ns.min(requested_end).max(recycled_start),
                signal_cut: false,
            },
            sites: Vec::new(),
            fenced: Vec::new(),
            objects: Vec::new(),
            coverage: Vec::new(),
            counters: self.extra_counters.clone(),
            fatal: Some(evidence::FatalKind::Recycled),
            target: doc_target(
                self.info.pid,
                &self.comm,
                &self.info.container_id,
                &self.info.image_digest,
            ),
            openssl: OpensslVersion::unknown(),
            disposition: None,
            policy: None,
            legacy_partition: LegacyCallPartition::default(),
            engine_observations: Vec::new(),
            traversal: None,
        });
        // R12: retain the one consistently captured pair (the
        // observations are discarded, but the host context stands).
        document.context = Some(doc_context(
            &self.info.kernel_release,
            self.wall_start,
            self.wall_end,
        ));
        self.reasons.clear();
        self.reason("pid-recycled");
        if close_failed {
            self.reason("close-failure");
        }
        let window_actual = self
            .clock
            .now()
            .saturating_duration_since(self.open_instant);
        self.finish_capture(
            document,
            FinishParts {
                outcome: Outcome::Fatal(FatalKind::Recycled),
                executions: Vec::new(),
                stale: Vec::new(),
                counters: Counters::default(),
                legacy: serde_json::Value::Null,
                harvest_doc: serde_json::json!({}),
                disposition: None,
                window_actual,
            },
        )
    }
}

/// Saturating `Duration` → nanoseconds (config bounds keep this far
/// below overflow; saturation fails closed, never wraps).
fn duration_ns(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

/// Effective observation start (R21-F4): the kernel window opens
/// pre-release (probes armed while the child is stopped), but
/// observation coverage starts at release — clamp the kernel-open
/// instant up to the requested start so effective ⊆ requested
/// (the semantic validator's containment rule). `--pid` runs are
/// unaffected (acquisition predates the open, so the open wins).
fn effective_start_ns(window_start_ns: u64, requested_start_ns: u64) -> u64 {
    window_start_ns.max(requested_start_ns)
}

/// Run one requested observation over already-attached sessions.
/// Setup (open → baseline poll → release), the poll loop, teardown
/// (counting closes before the final discovery drain) and
/// finalization (status after counters) all live here; `run` wires
/// the live sessions around it.
pub fn observe<D, B, T, L, C, P>(
    cfg: &Config,
    info: &TargetInfo,
    sessions: SessionSet<D, B, T, L>,
    clock: &C,
    proc: &mut P,
    cancelled: &dyn Fn() -> bool,
) -> anyhow::Result<Capture>
where
    D: DiscoveryPort,
    B: CountBackend,
    T: TargetPort,
    L: LifecyclePort,
    C: ClockPort,
    P: ProcPort,
{
    let SessionSet {
        discovery,
        mut count,
        mut target,
        lifecycle,
    } = sessions;
    if cfg.duration.is_zero() {
        let _ = target.resolve_setup_failure();
        anyhow::bail!("--duration must be > 0");
    }
    // Open the kernel window BEFORE release: probes arm while the
    // child is still stopped, so the happy-path startup gap is zero
    // (release instant ≥ programmed start saturates the gap). The
    // setup slice this steals from the requested window reports as
    // tail gap: the loop clamps to the kernel deadline and the
    // effective end caps there (never hidden, never drained).
    // F-D/A10: the kernel admission deadline measures from the
    // DECLARED window start — window open for owned spawns (the
    // child is stopped, so the setup slice counts nothing and the
    // clamped loop ends at this same edge), acquisition for --pid
    // (setup already consumed part of the requested window, so
    // open + duration would admit post-requested-end executions as
    // in-window).
    let start_ns = clock.monotonic_ns();
    let duration = duration_ns(cfg.duration);
    let declared_start_ns = if info.owned {
        start_ns
    } else {
        info.acquired_ns
    };
    let Some(kernel_deadline_ns) = declared_start_ns.checked_add(duration) else {
        let _ = target.resolve_setup_failure();
        anyhow::bail!("window deadline overflow");
    };
    if start_ns >= kernel_deadline_ns {
        let _ = target.resolve_setup_failure();
        if info.owned {
            anyhow::bail!("empty count window");
        }
        // Setup outlasted the requested window (or acquisition is
        // unstamped): nothing of the declared interval is countable.
        // Fail closed — programming open + duration would launder
        // post-window executions as in-window evidence.
        anyhow::bail!("requested window elapsed before window open");
    }
    if let Err(e) = count.open_window(start_ns, kernel_deadline_ns) {
        let _ = count.close_and_drain(cfg.grace);
        let _ = target.resolve_setup_failure();
        return Err(e.context("count open_window"));
    }
    // R12: the wall pair is sampled once per edge and reused —
    // this open instant is tentative (release/acquisition re-stamps
    // the start; window close stamps the end).
    let wall_open = clock.wall_now();
    let mut runner = Runner {
        cfg,
        info,
        discovery,
        count,
        target,
        lifecycle,
        clock,
        proc,
        cancelled,
        reasons: HashSet::new(),
        adapter: AdapterState::default(),
        activity: Vec::new(),
        extra_counters: Vec::new(),
        in_window_trip: HashMap::new(),
        in_window_hits: Vec::new(),
        in_window_lgcalls: 0,
        engine_collector: EngineCollector::new(),
        straddling_trip: HashMap::new(),
        straddling_lgcalls: 0,
        trigger_observed: false,
        attached_total: 0,
        cold_gap_queries: 0,
        fork_exec_ignored: 0,
        lifecycle_loss: 0,
        lifecycle_dropped: 0,
        lifecycle_prefix_unwitnessed: 0,
        lifecycle_no_witness: 0,
        lifecycle_pending: 0,
        lifecycle_exec_gap: 0,
        pending_exec_obligation: 0,
        maps_read_failed: 0,
        scan_budget_exhaustions: 0,
        provider_changed_fences: 0,
        planned_paths: HashSet::new(),
        site_cookies: HashMap::new(),
        seen_backings: HashSet::new(),
        snapshot: Snapshot::default(),
        last_live: Vec::new(),
        comm: info.comm.clone(),
        child_exit: None,
        reaped_before_close: false,
        signal_cut: false,
        expired: false,
        fallback_partial: false,
        window_start_ns: start_ns,
        requested_start_ns: start_ns,
        kernel_deadline_ns,
        open_instant: clock.now(),
        wall_start: wall_open,
        wall_end: wall_open,
        drain_wall_us: 0,
        file_cache: HashMap::new(),
        relevance_capped: 0,
        unverified_reads: 0,
        observation_started: false,
        traversal: None,
    };
    runner.fallback_partial = runner.lifecycle.fallback_partial();
    runner.setup_and_run()
}

impl<D, B, T, L, C, P> Runner<'_, D, B, T, L, C, P>
where
    D: DiscoveryPort,
    B: CountBackend,
    T: TargetPort,
    L: LifecyclePort,
    C: ClockPort,
    P: ProcPort,
{
    fn setup_and_run(mut self) -> anyhow::Result<Capture> {
        let pid = self.info.pid;
        let owned = self.info.owned;
        let setup_deadline = args::deadline_at(self.clock.now(), self.cfg.harvest_timeout);
        // Baseline poll: seed maps/snapshot, attach the first delta,
        // and baseline tripwire counters at the declared window
        // boundary (pre-window tripwire/query news never becomes
        // in-window evidence).
        let live = match self.proc.read_maps(pid) {
            Ok(live) => live,
            Err(e) => {
                if !owned && self.target.verify().is_err() {
                    return Ok(self.recycled());
                }
                let _ = self.count.close_and_drain(self.cfg.grace);
                let _ = self.target.resolve_setup_failure();
                return Err(e.context("setup maps read"));
            }
        };
        for m in &live {
            self.seen_backings
                .insert((crate::discovery::session::backing_dev(m), m.ino));
        }
        let exe = self.proc.read_exe(pid);
        self.snapshot = snapshot(exe, &live, &[], &HashMap::new());
        self.last_live = live.clone();
        let fresh = HashSet::new();
        // Poll → read-relevant → apply (F-D/A13), like the round
        // loop: the baseline poll reads only its delta's paths.
        let baseline_outcome: anyhow::Result<(bool, bool)> = (|| {
            let (delta, poll_end) = self.poll_discovery()?;
            let files = self.read_relevant_files(&delta, &live);
            let pinned = self.cfg.resolved_provider.clone();
            let ctx = AdapterCtx {
                live: &live,
                files: &files,
                pinned_provider: pinned,
                fresh: &fresh,
                post_settle: false,
                // The baseline poll runs pre-release (the child is
                // still stopped): attaches here ARE the ready
                // boundary, never late.
                post_release: false,
                baseline: true,
            };
            self.apply_delta(&delta, poll_end, &ctx, None)
        })();
        match baseline_outcome {
            Ok((_, fence_candidates)) => {
                if fence_candidates {
                    if let Err(e) = self.count.fence(CountFence::CandidatesChanged) {
                        let _ = self.count.close_and_drain(self.cfg.grace);
                        let _ = self.target.resolve_setup_failure();
                        return Err(e.context("setup fence"));
                    }
                }
            }
            Err(e) => {
                let _ = self.count.close_and_drain(self.cfg.grace);
                let _ = self.target.resolve_setup_failure();
                return Err(e.context("setup discovery poll"));
            }
        }
        // Traversal baseline (active ports only): drain the setup
        // slice and fence pre-window opens — pre-window traversal
        // news never becomes in-window evidence (same
        // seed-then-discard discipline as the discovery baseline).
        if self.discovery.traversal_active() {
            if let Err(e) = self.discovery.poll_traversal(true) {
                let _ = self.count.close_and_drain(self.cfg.grace);
                let _ = self.target.resolve_setup_failure();
                return Err(e.context("setup traversal poll"));
            }
            self.traversal = Some(TraversalCapture::default());
        }
        if (self.cancelled)() {
            self.signal_cut = true;
            let _ = self.count.close_and_drain(self.cfg.grace);
            let _ = self.target.resolve_setup_failure();
            // A never-released owned child was just terminated and
            // reaped above: preserve its status (foreign targets
            // answer None — no disposition for a target never owned).
            if let Ok(Some(code)) = self.target.poll_exit() {
                self.child_exit = Some(code);
            }
            self.requested_start_ns = self.clock.monotonic_ns();
            // R12: the wall start is the counterpart of the requested
            // start — re-stamped together, never the pre-setup open.
            self.wall_start = self.clock.wall_now();
            return Ok(self.no_window_result());
        }
        if setup_deadline.is_some_and(|d| self.clock.now() >= d) {
            let _ = self.count.close_and_drain(self.cfg.grace);
            let _ = self.target.resolve_setup_failure();
            anyhow::bail!("setup timeout");
        }
        // Release (owned): the requested window begins here.
        if owned {
            if let Err(e) = self.target.release() {
                // A child that died before release keeps its exit
                // status (never-released custody resolves around the
                // preserved code, never by killing).
                if let Ok(Some(code)) = self.target.poll_exit() {
                    self.child_exit = Some(code);
                    let _ = self.count.close_and_drain(self.cfg.grace);
                    let _ = self.target.resolve_setup_failure();
                    self.requested_start_ns = self.clock.monotonic_ns();
                    // R12: wall/requested starts re-stamp together.
                    self.wall_start = self.clock.wall_now();
                    return Ok(self.no_window_result());
                }
                let _ = self.count.close_and_drain(self.cfg.grace);
                let _ = self.target.resolve_setup_failure();
                return Err(e.context("release"));
            }
            // Release performed: the target can emit from here on —
            // per-CPU first sightings gap their prefix from now.
            self.lifecycle.mark_released();
            // Post-release comm settle: acquisition read comm while
            // the child was stopped pre-exec (the observer's inherited
            // comm); refresh now, and again before every reap until
            // it differs (a slow exec settles late).
            self.settle_comm();
            self.requested_start_ns = self.clock.monotonic_ns();
            self.wall_start = self.clock.wall_now();
            self.open_instant = self.clock.now();
        } else {
            self.requested_start_ns = self.info.acquired_ns;
            self.wall_start = self.info.acquired_wall;
        }
        let requested_instant = if owned {
            self.open_instant
        } else {
            self.info.acquired_instant
        };
        let Some(loop_deadline) = args::deadline_at(requested_instant, self.cfg.duration) else {
            let _ = self.count.close_and_drain(self.cfg.grace);
            let _ = self.target.resolve_setup_failure();
            anyhow::bail!("window deadline overflow");
        };
        // Clamp the loop to the kernel deadline: the kernel window
        // opened pre-setup while the requested window starts at
        // release, so an unclamped loop runs one setup past the
        // kernel deadline — uncounted time with no gap (spec: any
        // unobserved interval in the requested window is a gap). The
        // setup slice then reports as tail gap via the capped
        // effective end below. (--pid requested starts predate the
        // kernel open, so the clamp is a no-op there.)
        let setup_ns = self.requested_start_ns.saturating_sub(self.window_start_ns);
        let setup = Duration::from_nanos(setup_ns.min(duration_ns(self.cfg.duration)));
        let loop_deadline = loop_deadline.checked_sub(setup).unwrap_or(loop_deadline);
        let settle_end =
            args::deadline_at(requested_instant, self.cfg.settle).unwrap_or(loop_deadline);

        // H7/B-6: observation starts here — everything above is
        // setup (baseline poll included: it seeds pre-window state,
        // never evidence). From this point failures salvage.
        self.observation_started = true;
        // Poll loop: expiry / signal / death / fence.
        loop {
            let now = self.clock.now();
            if now >= loop_deadline {
                self.expired = true;
                break;
            }
            if (self.cancelled)() {
                self.signal_cut = true;
                break;
            }
            // Pre-reap settle: this poll may reap, ending post-hoc
            // comm reads (a fast exit keeps no second chance).
            self.settle_comm();
            if owned {
                match self.target.poll_exit() {
                    Ok(Some(code)) => {
                        self.child_exit = Some(code);
                        break;
                    }
                    Ok(None) => {}
                    Err(e) => return self.fail(e.context("poll_exit")),
                }
            } else if self.target.verify().is_err() {
                return Ok(self.recycled());
            }
            let wait = POLL_INTERVAL.min(loop_deadline.saturating_duration_since(now));
            if !wait.is_zero() {
                self.clock.sleep(wait);
            }
            // Post-sleep liveness: a child that died during the
            // sleep closes the window, never fences on its corpse.
            // Pre-reap settle again: the exec may have settled
            // during the sleep, just before the death below.
            self.settle_comm();
            if owned {
                match self.target.poll_exit() {
                    Ok(Some(code)) => {
                        self.child_exit = Some(code);
                        break;
                    }
                    Ok(None) => {}
                    Err(e) => return self.fail(e.context("poll_exit")),
                }
            } else if self.target.verify().is_err() {
                return Ok(self.recycled());
            }
            match self.round(loop_deadline, settle_end) {
                Ok(RoundAction::Continue) => {}
                Ok(RoundAction::Expired) => {
                    self.expired = true;
                    break;
                }
                Ok(RoundAction::Closed) => break,
                Ok(RoundAction::Recycled) => return Ok(self.recycled()),
                Err(e) => return self.fail(e),
            }
        }
        self.close_and_finalize()
    }

    fn close_and_finalize(mut self) -> anyhow::Result<Capture> {
        // Last pre-reap settle: the expiry poll and the final
        // disposition below can reap, ending post-hoc comm reads.
        self.settle_comm();
        // Over-budget: the window expired while the target lived
        // (docs/partial-runbook.md alive-at-expiry contract). A
        // reaped-here spawn is STILL over-budget: reaping after
        // expiry does not establish death before expiry (the loop
        // broke on the deadline, never observing death — the exit
        // may postdate it), so the reap is kept for custody/status
        // but never negates the loss (fail-closed).
        if self.expired {
            if self.info.owned {
                if let Ok(Some(code)) = self.target.poll_exit() {
                    self.child_exit = Some(code);
                }
            }
            self.extra_counters.push(typed_counter(
                "capture.over_budget",
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Lifecycle,
                1,
            ));
        }
        // One last lifecycle sweep at window end — skipped once
        // the owned child has exited: it is reaped by then (its
        // children reparented, its exe link gone), so a sweep can
        // only find its own unreadable-exe loss, never activity.
        // (Fork events only, as in the round sweep above: execs are
        // fence-tracked, never ignored. Post-round Exec witnesses
        // cannot fence — no generation left to version into — so
        // they gap instead: the tail may mix pre/post-exec identity
        // under one fingerprint.)
        if self.child_exit.is_none() {
            let sweep = self.lifecycle.poll();
            self.fold_lifecycle(&sweep);
            self.lifecycle_exec_gap = self
                .lifecycle_exec_gap
                .saturating_add(Self::exec_witnesses(&sweep));
        }
        // Kernel-signal close drain (R20, witness-completeness per
        // R20-fix): consume the signal ring through the current tail
        // even when the target already exited — a ring drain needs
        // no /proc scan, so it is safe on corpses. A non-fallback
        // port MUST witness the tail: `None` is missing evidence
        // (explicit no-witness loss — absence never passes silent),
        // and a nonzero `pending` residual is an uncovered tail
        // (explicit drain-pending loss). Polling ports return `None`
        // (their close sweep above stays skipped once reaped, and
        // the standing polling-fallback loss already withholds
        // COMPLETE).
        let drained = self.lifecycle.close_drain();
        if !self.fallback_partial && drained.is_none() {
            self.lifecycle_no_witness = self.lifecycle_no_witness.saturating_add(1);
        }
        if let Some(drained) = drained {
            self.fold_lifecycle(&drained);
            if drained.pending > 0 {
                self.lifecycle_pending = self.lifecycle_pending.saturating_add(drained.pending);
            }
            self.lifecycle_exec_gap = self
                .lifecycle_exec_gap
                .saturating_add(Self::exec_witnesses(&drained));
        }
        // Outstanding exec obligation (R20-fix round 2, F3): a
        // round consumed this witness but returned on
        // cancellation/deadline before fencing — no generation
        // left to version into, so it gaps (the reaped-at-expiry
        // path included: over-budget records fail-closed above,
        // and the lost transition still records here).
        self.lifecycle_exec_gap = self
            .lifecycle_exec_gap
            .saturating_add(std::mem::replace(&mut self.pending_exec_obligation, 0));
        // TEST HOOK (exit-3 kernel-proof): hold the final drain past
        // close so a still-counting kernel would advance last_ns
        // beyond the window edge. Production behavior unchanged when
        // unset.
        if let Ok(ms) = std::env::var("OSSLSCOPE_DRAIN_DELAY_MS") {
            if let Ok(ms) = ms.parse::<u64>() {
                self.clock.sleep(Duration::from_millis(ms));
            }
        }
        // Effective coverage ends when counting stops (close_window
        // inside): stamp before the userspace drain, capped at the
        // programmed kernel deadline — drain time is not coverage,
        // and the loop can overshoot the clamped deadline by up to
        // one round.
        let effective_end_ns = self.clock.monotonic_ns().min(self.kernel_deadline_ns);
        // R12: the single close sample, alongside the monotonic end
        // stamp (drain time is not coverage) — every consumer below
        // reuses this pair, never re-samples.
        self.wall_end = self.clock.wall_now();
        // Counting closes BEFORE the final discovery drain
        // (in-kernel TARGET=0 inside: no userspace delay can extend
        // counting past this point).
        let drain_t0 = self.clock.now();
        // H7: pre-finish discovery snapshot — on any close failure
        // below, salvage assembles from this pre-state (no polls run
        // between here and finish, so it stays valid; a failed
        // finish takes the live session).
        let pre_finish = self.discovery.snapshot();
        let drain = match self.count.close_and_drain(self.cfg.grace) {
            Ok(drain) => drain,
            Err(e) => {
                // Discovery finish is still attempted inside salvage
                // (None seed) — only an already-failed finish takes
                // the pre-finish fallback.
                return Ok(self.salvage(
                    SalvageSeed {
                        drain: None,
                        snapshot: None,
                        disposition: None,
                        effective_end_ns,
                    },
                    e.context("close_and_drain"),
                ));
            }
        };
        self.drain_wall_us = self
            .clock
            .now()
            .checked_duration_since(drain_t0)
            .map(|d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        // An owned child that already exited was reaped mid-window,
        // so its /proc entry is gone and the discovery close misreads
        // that as a pid recycle. Snapshot first: on a spurious
        // recycle the pre-close state (plus an explicit skipped-join
        // Activity counter — audit trail, not a gap: the reaped
        // child cannot execute past its death) survives instead of
        // losing the whole capture. Foreign targets keep the loud
        // recycle verdict — their pids really can be reused.
        let pre_close =
            (self.info.owned && self.child_exit.is_some()).then(|| self.discovery.snapshot());
        // Round 3, residual D: post-reap provenance for the
        // maps-loss exemption — captured at finish entry (the
        // same mid-window-reap fact arming the pre-close arm
        // above; a later reap during finish_observation must not
        // backdate the close read as reaped-then-read).
        self.reaped_before_close = self.info.owned && self.child_exit.is_some();
        let snapshot = match self.discovery.finish() {
            Ok(snapshot) => snapshot,
            Err(e) => {
                let recycled = e.downcast_ref::<Recycled>();
                match (pre_close, recycled) {
                    (Some(pre), Some(r)) => {
                        // R21-F1: a reaped owned child cannot execute
                        // past its death, so the skipped final join
                        // is inapplicable, not missed — an Activity
                        // counter (audit trail), never a Loss (the
                        // window is fulfilled through the exit; the
                        // pre-close arm only exists with a known
                        // child exit).
                        self.extra_counters.push(typed_counter(
                            "discovery.close_join_skipped",
                            CounterKind::Activity,
                            CounterUnits::Events,
                            CounterSource::Discovery,
                            1,
                        ));
                        // Prefer the close-time final (a superset of
                        // the pre-close snapshot: the same polls plus
                        // the close-time joins and tail count); fall
                        // back to the pre-close state when the backend
                        // stages no final.
                        r.final_snapshot.clone().unwrap_or(pre)
                    }
                    _ => {
                        return Ok(self.salvage(
                            SalvageSeed {
                                drain: Some(drain),
                                snapshot: Some(pre_finish),
                                disposition: None,
                                effective_end_ns,
                            },
                            e.context("discovery finish"),
                        ));
                    }
                }
            }
        };
        let disposition = match self.target.finish_observation() {
            Ok(disposition) => disposition,
            Err(e) => {
                return Ok(self.salvage(
                    SalvageSeed {
                        drain: Some(drain),
                        snapshot: Some(snapshot),
                        disposition: None,
                        effective_end_ns,
                    },
                    e.context("finish_observation"),
                ));
            }
        };
        if let target::TargetDisposition::Exited { code } = disposition {
            self.child_exit = Some(code);
        }
        // Traversal tail (last drain before assembly: the quiesce
        // slice lands here too — same class as the harvest tail
        // join; salvage-seed paths absorb inside salvage instead,
        // so every close absorbs exactly once).
        self.absorb_traversal_tail();
        Ok(self.assemble(snapshot, drain, Some(disposition), effective_end_ns, None))
    }

    /// Sites of one op with live probes (coverage attach census).
    fn op_attached(&self, op: u32) -> u64 {
        let mut attached = 0u64;
        if let Some(triples) = self.adapter.op_triples.get(&op) {
            for triple in triples {
                if let Some(cookie) = self.count.cookie_for(triple.0, triple.1, triple.2) {
                    if self
                        .count
                        .provenance(cookie)
                        .is_some_and(|p| !p.link_path.is_empty())
                    {
                        attached += 1;
                    }
                }
            }
        }
        attached
    }

    /// Finalize status AFTER counters: merge every loss/activity
    /// source, reconcile close residuals once, build coverage, and
    /// finalize through the sole finalizer.
    fn assemble(
        mut self,
        snapshot: DiscoverySnapshot,
        mut drain: CountDrain,
        disposition: Option<target::TargetDisposition>,
        effective_end_ns: u64,
        salvage: Option<SalvageContext>,
    ) -> Capture {
        if self.cold_gap_queries > 0 {
            self.extra_counters.push(typed_counter(
                "discovery.pre_window_queries",
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Discovery,
                self.cold_gap_queries,
            ));
        }
        if self.fork_exec_ignored > 0 {
            self.extra_counters.push(typed_counter(
                "lifecycle.fork_exec_ignored",
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Lifecycle,
                self.fork_exec_ignored,
            ));
        }
        if self.lifecycle_loss > 0 {
            self.extra_counters.push(typed_counter(
                "lifecycle.scan_loss",
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Lifecycle,
                self.lifecycle_loss,
            ));
        }
        if self.lifecycle_dropped > 0 {
            self.extra_counters.push(typed_counter(
                "lifecycle.signal_dropped",
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Lifecycle,
                self.lifecycle_dropped,
            ));
        }
        if self.lifecycle_prefix_unwitnessed > 0 {
            self.extra_counters.push(typed_counter(
                "lifecycle.signal_prefix_unwitnessed",
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Lifecycle,
                self.lifecycle_prefix_unwitnessed,
            ));
        }
        if self.lifecycle_no_witness > 0 {
            self.extra_counters.push(typed_counter(
                "lifecycle.no_witness",
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Lifecycle,
                self.lifecycle_no_witness,
            ));
        }
        if self.lifecycle_pending > 0 {
            self.extra_counters.push(typed_counter(
                "lifecycle.drain_pending",
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Lifecycle,
                self.lifecycle_pending,
            ));
        }
        if self.lifecycle_exec_gap > 0 {
            self.extra_counters.push(typed_counter(
                "lifecycle.exec_gap",
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Lifecycle,
                self.lifecycle_exec_gap,
            ));
        }
        // H3: mixed-withheld sites are ambiguity, not loss —
        // Activity (the observation is complete; the verdict is
        // withheld). Distinct triples ever marked mixed; absent
        // (zero) on clean runs. Deliberately NOT a taint input:
        // mixed hides no sites and misses no evidence.
        let mixed_sites = self.adapter.sites_mixed.len() as u64;
        if mixed_sites > 0 {
            self.activity.push(typed_counter(
                "discovery.mixed_classes",
                CounterKind::Activity,
                CounterUnits::Sites,
                CounterSource::Discovery,
                mixed_sites,
            ));
        }
        if self.fallback_partial {
            self.extra_counters.push(typed_counter(
                "lifecycle.polling_fallback",
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Lifecycle,
                1,
            ));
        }
        if self.maps_read_failed > 0 {
            self.extra_counters.push(typed_counter(
                "discovery.maps_read_failed",
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Discovery,
                self.maps_read_failed,
            ));
        }
        if self.relevance_capped > 0 {
            self.extra_counters.push(typed_counter(
                "discovery.relevance_capped",
                CounterKind::Loss,
                CounterUnits::Sites,
                CounterSource::Discovery,
                self.relevance_capped,
            ));
        }
        if self.unverified_reads > 0 {
            self.extra_counters.push(typed_counter(
                "discovery.unverified_read",
                CounterKind::Loss,
                CounterUnits::Sites,
                CounterSource::Discovery,
                self.unverified_reads,
            ));
        }
        // Post-exit maps reads miss nothing (the target is reaped,
        // its /proc entry gone — the expected close single); live
        // targets have no benign maps failure. Needed before the
        // residual loop: the maps-source residual is exempt below.
        // H7: unknown custody (salvaged finish_observation failure)
        // is not an exit — the maps-source residual stays suspect.
        let target_exited = matches!(disposition, Some(target::TargetDisposition::Exited { .. }));
        // Close reconcile (D2/D4): increments rode the deltas; only
        // the close-tail residual lands here, exactly once.
        let mut loss_residual_any = false;
        for (source, total) in &snapshot.losses {
            let adapted = self.adapter.loss_sums.get(source).copied().unwrap_or(0);
            if let Some(residual) = total.checked_sub(adapted) {
                if residual > 0 {
                    // R21-F1 (round 2) + round-3 D provenance: only
                    // the close-phase maps portion under a
                    // reaped-before-close Exited target is the
                    // benign close-only read (reaped child, /proc
                    // gone, nothing missable — the H2/T5
                    // exemption's counter half): an Activity
                    // counter (audit trail, same name), never a
                    // Loss — the same treatment as the skipped
                    // close join. Every other source, maps under
                    // a live target, maps without reaped-before-
                    // close provenance, and any poll-phase maps
                    // remainder stay Loss. A poll that recorded
                    // live maps loss then failed pre-delta leaves
                    // a poll-phase residual — the eventual Exited
                    // disposition never relabels it.
                    let mut close_part = 0;
                    if target_exited
                        && self.reaped_before_close
                        && *source == coverage::HOST_MAPS_READ
                    {
                        close_part = snapshot.maps_loss_close.min(residual);
                    }
                    if close_part > 0 {
                        let mut benign = classify_loss(*source, close_part);
                        benign.kind = CounterKind::Activity;
                        self.extra_counters.push(benign);
                    }
                    let loss_part = residual - close_part;
                    if loss_part > 0 {
                        self.extra_counters.push(classify_loss(*source, loss_part));
                        // H2/T5: mid-run maps failures rode the
                        // deltas (op None → poll-global taint
                        // already fired); only the proven
                        // post-reap close portion above is exempt
                        // — every other residual taints. Round
                        // errors are fatal (fail, never a silent
                        // delta drop), so residuals are real.
                        loss_residual_any = true;
                    }
                }
            }
        }
        if snapshot.lossy_slots > 0 {
            self.extra_counters.push(typed_counter(
                "discovery.lossy_slots",
                CounterKind::Loss,
                CounterUnits::TableRows,
                CounterSource::Discovery,
                snapshot.lossy_slots,
            ));
        }
        if !snapshot.truncated_ops.is_empty() {
            self.extra_counters.push(typed_counter(
                "discovery.truncated_walk",
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Discovery,
                snapshot.truncated_ops.len() as u64,
            ));
        }
        if !snapshot.dispatch.attach_failures.is_empty() {
            self.extra_counters.push(typed_counter(
                "discovery.unresolved_stage2",
                CounterKind::Loss,
                CounterUnits::Probes,
                CounterSource::Discovery,
                snapshot.dispatch.attach_failures.len() as u64,
            ));
            // R06: close-time failure texts join the retained
            // diagnostics (same set, same dedup — the close drain
            // identifies itself too).
            for failure in &snapshot.dispatch.attach_failures {
                self.adapter
                    .attach_diagnostics
                    .insert(failure.error.clone());
            }
        }
        // Retained epoch gaps stay PARTIAL even when every live table
        // terminates (rows survive; completion does not).
        for reason in &snapshot.retained_reasons {
            self.extra_counters.push(typed_counter(
                &format!("discovery.retained_{}", reason.replace('-', "_")),
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Discovery,
                1,
            ));
        }
        let reloads = snapshot
            .dispatch
            .reloads
            .iter()
            .fold(0u64, |acc, (_, n)| acc.saturating_add(*n));
        if reloads > 0 {
            self.activity.push(typed_counter(
                "discovery.provider_reloads",
                CounterKind::Activity,
                CounterUnits::Events,
                CounterSource::Discovery,
                reloads,
            ));
        }
        if let Some(tail) = snapshot
            .queries_observed
            .checked_sub(self.adapter.queries_observed)
        {
            if tail > 0 {
                // Post-count-close arrivals: activity, never cold gap.
                self.activity.push(typed_counter(
                    "discovery.queries_observed",
                    CounterKind::Activity,
                    CounterUnits::Events,
                    CounterSource::Discovery,
                    tail,
                ));
            }
        }
        // Straddling-poll legacy reconcile (F-D/A10): polls that
        // completed at/after the loop deadline contributed
        // window-ambiguous deltas — explicit loss here, and
        // subtracted from the close-tail residual below so each
        // increment counts exactly once.
        let straddling_trip: u64 = self
            .straddling_trip
            .values()
            .fold(0u64, |a, &b| a.saturating_add(b));
        if straddling_trip > 0 {
            self.extra_counters.push(typed_counter(
                "legacy.straddling_poll_trip",
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Discovery,
                straddling_trip,
            ));
        }
        if self.straddling_lgcalls > 0 {
            self.extra_counters.push(typed_counter(
                "legacy.straddling_poll_lgcalls",
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Discovery,
                self.straddling_lgcalls,
            ));
        }
        // Close-tail legacy reconcile: the final join covers TRIP
        // and LGCALLS increments past the last poll (a probe with no
        // ring event, e.g. an in-window ENGINE_init, lands only
        // here). Counting already closed, so window membership is
        // unknowable — explicit loss, never silent execution and
        // never a silent drop.
        let mut tail_trip = 0u64;
        for (cookie, total) in &snapshot.legacy.trip {
            let base = self.adapter.baseline_trip.get(cookie).copied().unwrap_or(0);
            let in_window = self.in_window_trip.get(cookie).copied().unwrap_or(0);
            let straddling = self.straddling_trip.get(cookie).copied().unwrap_or(0);
            if let Some(after_base) = total.checked_sub(base)
                && let Some(after_window) = after_base.checked_sub(in_window)
                && let Some(tail) = after_window.checked_sub(straddling)
            {
                tail_trip = tail_trip.saturating_add(tail);
            }
        }
        if tail_trip > 0 {
            self.extra_counters.push(typed_counter(
                "legacy.close_tail_trip",
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Discovery,
                tail_trip,
            ));
        }
        if let Some(after_base) = snapshot
            .legacy
            .executed_queries
            .checked_sub(self.adapter.baseline_lgcalls)
            && let Some(after_window) = after_base.checked_sub(self.in_window_lgcalls)
            && let Some(tail_lgcalls) = after_window.checked_sub(self.straddling_lgcalls)
            && tail_lgcalls > 0
        {
            self.extra_counters.push(typed_counter(
                "legacy.close_tail_lgcalls",
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Discovery,
                tail_lgcalls,
            ));
        }
        let (engine_un, meth_un, low_un) = snapshot
            .legacy
            .set
            .as_ref()
            .map(|set| {
                (
                    set.engine_uninstrumented,
                    set.meth_uninstrumented,
                    set.lowlevel_uninstrumented,
                )
            })
            .unwrap_or((0, 0, 0));
        if engine_un > 0 {
            self.extra_counters.push(typed_counter(
                "legacy.engine_uninstrumented",
                CounterKind::Loss,
                CounterUnits::Sites,
                CounterSource::Discovery,
                engine_un,
            ));
        }
        if meth_un > 0 {
            self.extra_counters.push(typed_counter(
                "legacy.meth_uninstrumented",
                CounterKind::Loss,
                CounterUnits::Sites,
                CounterSource::Discovery,
                meth_un,
            ));
        }
        if low_un > 0 {
            self.extra_counters.push(typed_counter(
                "legacy.lowlevel_uninstrumented",
                CounterKind::Loss,
                CounterUnits::Sites,
                CounterSource::Discovery,
                low_un,
            ));
        }

        // Coverage: per-op rows from discovery census + attach truth,
        // legacy + dispatch planes, then the sole finalizer. An op
        // terminates only when EVERY live epoch proves and no sticky
        // walk-shape bits haunt it — sibling epochs never collapse.
        let snap_trunc: HashMap<u32, u64> = snapshot.truncated_ops.iter().copied().collect();
        let mut snap_term: HashMap<u32, bool> = HashMap::new();
        for table in &snapshot.tables {
            let term = matches!(table.state, CoverageState::Terminated { .. })
                && snap_trunc.get(&table.op).copied().unwrap_or(0) == 0;
            snap_term
                .entry(table.op)
                .and_modify(|t| *t &= term)
                .or_insert(term);
        }
        // H2 close-taint computation (A-6): close residuals that
        // never rode a poll delta taint here, before coverage.
        // EXTENSIBLE: H7 adds close-error inputs to this set —
        // keep the evidence/census split (sites vs denominators).
        let drain_shortfall = drain
            .counters
            .iter()
            .find(|c| c.name == "count.drain_shortfall")
            .map(|c| c.value)
            .unwrap_or(0);
        // Evidence taint (sites + denominators Unknown): the
        // snapshot collapses per-source totals, so residuals
        // taint globally — op info exists only in poll-time
        // deltas (already tainted then).
        // `maps_read_failed` always taints (H2/T5b): the counter
        // increments only on the live-round path (round()
        // reaps-or-continues first — no post-exit site exists),
        // so every count is mid-window turnover blindness. The
        // benign post-exit single lives on the discovery side
        // (HOST_MAPS_READ residual, exempt above).
        // H7-T4: a lost drain feeds the close-evidence taint (a
        // failed close may hide tails) — surviving denominators go
        // Unknown. Salvages with intact counts do not taint.
        let mut close_evidence_global = loss_residual_any
            || snapshot.lossy_slots > 0
            || !snapshot.dispatch.attach_failures.is_empty()
            || !snapshot.retained_reasons.is_empty()
            || self.relevance_capped > 0
            || self.unverified_reads > 0
            || drain_shortfall > 0
            || self.maps_read_failed > 0
            || salvage.as_ref().is_some_and(|s| s.taint_evidence);
        // Close-candidate reconcile (P6 §6ii sol blocker 2):
        // candidates first joined (or refreshed) by close's tail
        // ingest never rode a poll delta, so the adapter never saw
        // them — yet the final table proof may be complete. Every
        // close-joined candidate is a genuine adapter-visible
        // change (unchanged duplicates never reach the close
        // list), so each one taints: its op joins the
        // evidence-tainted set (denominator Unknown — the window
        // census is short or its sets incomplete; blanket per op
        // like the orphan doctrine, not gated on novelty) and its
        // (ino, offset) joins the site-revision set below (covers
        // cross-op aliases, whose op never appears in the site's
        // adapted identities). The adapter is the POLL record and
        // stays write-free here: `discovered` keeps its
        // operational meaning (the attachable window census —
        // every counted triple was attachable, so
        // attached==discovered still pins attach completeness),
        // while post-window discoveries ride the gap counter, not
        // the census. A close-only op (no poll triples) keeps no
        // coverage row — its sites surface in the gap volume, and
        // the discovery snapshot retains the full inventory.
        //
        // Device is deliberately IGNORED (sol round 2): the
        // backing dev string flips facets across unlink
        // (`backing_dev` falls back to maps text when unstatable),
        // so a device match misses same-file aliases. (ino,
        // offset) are flip-proof (maps ino is stable across
        // unlink — the dual-facet doctrine of `bindings_alive`),
        // and kernel-grounded u64s need no parsing (there is no
        // unparsed path here — even a garbage dev string rides
        // its (ino, offset)). A candidate with NO backing at all
        // cannot be localized to any site — its alias could
        // belong anywhere — so it taints GLOBALLY (F-B/A7: the
        // missing evidence could be anyone's), plus the explicit
        // volume counter. (Poll-time unbacked stays counter-only:
        // a later poll may still resolve it; at close there is
        // no later.)
        let mut close_backings: HashSet<(u64, u64)> = HashSet::new();
        let mut close_joined = 0u64;
        let mut close_unbacked = 0u64;
        let mut close_evidence_ops: HashSet<u32> =
            snapshot.truncated_ops.iter().map(|(op, _)| *op).collect();
        for candidate in &snapshot.close_candidates {
            let Some(backing) = candidate.backing.as_ref() else {
                close_unbacked += 1;
                // Unlocalizable: taint everything (see above).
                close_evidence_global = true;
                continue;
            };
            close_joined += 1;
            close_evidence_ops.insert(candidate.op);
            close_backings.insert((backing.ino, backing.offset));
        }
        // Remap-evidence merge (sol round 3): M4-remembered old
        // backings for close-joined impls join the SAME revision
        // set — a silent first-cell adoption may have outrun an
        // impl remap, so the old sites' sets may miss the alias.
        // Site revision ONLY (no op taint): no triple is missing
        // for the old ops, so their denominators stay exact —
        // the precise Applicable-census/Unknown-set split.
        for (ino, offset) in &snapshot.close_remembered {
            close_backings.insert((*ino, *offset));
        }
        if !snapshot.close_remembered.is_empty() {
            self.extra_counters.push(typed_counter(
                "discovery.close_remembered",
                CounterKind::Loss,
                CounterUnits::Sites,
                CounterSource::Discovery,
                snapshot.close_remembered.len() as u64,
            ));
        }
        if close_joined > 0 {
            self.extra_counters.push(typed_counter(
                "discovery.close_candidates",
                CounterKind::Loss,
                CounterUnits::Sites,
                CounterSource::Discovery,
                close_joined,
            ));
        }
        if close_unbacked > 0 {
            self.extra_counters.push(typed_counter(
                "discovery.unbacked_candidate",
                CounterKind::Loss,
                CounterUnits::Sites,
                CounterSource::Discovery,
                close_unbacked,
            ));
        }
        // Census taint (denominators Unknown, emitted+proven sites
        // stand — all site evidence is in-window by construction).
        let close_census_global = self.cold_gap_queries > 0
            || self.lifecycle_loss > 0
            || self.lifecycle_dropped > 0
            || self.lifecycle_prefix_unwitnessed > 0
            || self.lifecycle_no_witness > 0
            || self.lifecycle_pending > 0
            || self.lifecycle_exec_gap > 0
            || self.fallback_partial;
        let mut coverage = Vec::new();
        for op in self.adapter.ops() {
            let terminated = snap_term
                .get(&op)
                .copied()
                .unwrap_or_else(|| self.adapter.op_closed(op));
            let discovered = self.adapter.op_discovered(op);
            let attached = self.op_attached(op);
            // A7: a tainted op's discovered count is no denominator
            // (a lost ROW may hide a site or an identity).
            // H2: final taint (poll ∪ close, evidence ∪ census).
            let known = terminated
                && !self.adapter.loss_tainted(op)
                && !close_evidence_global
                && !close_evidence_ops.contains(&op)
                && !close_census_global;
            coverage.push(ScopeCoverage {
                scope: format!("op:{op}"),
                expected: if known {
                    ExpectedScope::Applicable { sites: discovered }
                } else {
                    ExpectedScope::Unknown
                },
                discovered,
                attached,
            });
        }
        if let Some(set) = snapshot.legacy.set.as_ref() {
            let n = set.probes.len() as u64;
            if snapshot.legacy.planned {
                coverage.push(ScopeCoverage {
                    scope: "legacy".to_string(),
                    expected: ExpectedScope::Applicable { sites: n },
                    discovered: n,
                    attached: n,
                });
            } else {
                // F-D/A11: anchors superseded mid-window — the
                // last-good set still renders history, but nothing
                // further is observable: Unknown, never
                // stale-Applicable.
                coverage.push(ScopeCoverage {
                    scope: "legacy".to_string(),
                    expected: ExpectedScope::Unknown,
                    discovered: n,
                    attached: 0,
                });
            }
        } else if legacy::find_libcrypto(&self.last_live).is_some() {
            coverage.push(ScopeCoverage {
                scope: "legacy".to_string(),
                expected: ExpectedScope::Unknown,
                discovered: 0,
                attached: 0,
            });
        } else {
            // No libcrypto mapping ever observed: the legacy surface
            // is not applicable (differs from unknown).
            coverage.push(ScopeCoverage {
                scope: "legacy".to_string(),
                expected: ExpectedScope::NotApplicable,
                discovered: 0,
                attached: 0,
            });
        }
        // H2: the dispatch surface is a denominator too (B-3b) —
        // global evidence taint (poll ∪ close) means it was not
        // fully observed. Op-localized truncation leaves the
        // dispatch anchor claim standing.
        let dispatch_known = !self.adapter.taint_global && !close_evidence_global;
        if snapshot.dispatch.attached {
            coverage.push(ScopeCoverage {
                scope: "dispatch".to_string(),
                expected: if dispatch_known {
                    ExpectedScope::Applicable { sites: 1 }
                } else {
                    ExpectedScope::Unknown
                },
                discovered: 1,
                attached: 1,
            });
        } else {
            coverage.push(ScopeCoverage {
                scope: "dispatch".to_string(),
                expected: ExpectedScope::Unknown,
                discovered: 0,
                attached: 0,
            });
        }

        let mut requested_end = self
            .requested_start_ns
            .saturating_add(duration_ns(self.cfg.duration));
        if self.child_exit.is_some() {
            // Fulfilled by exit: the dead target cannot execute past
            // its death, so no tail gap accrues past the close.
            requested_end = requested_end
                .min(effective_end_ns)
                .max(self.requested_start_ns);
        }
        // R21-F4 (round 2, residual E): setup can outlast the
        // requested window (accepted tiny --duration) — the kernel
        // deadline then predates the requested start, and the
        // capped effective end would invert the window (the
        // semantic validator rejects inversion). Collapse honestly
        // to the empty window at the effective start (the deadline
        // passed during setup, so the whole requested window is
        // tail gap; the loop also records over-budget, so COMPLETE
        // is unreachable here). Never widens: the clamp only fires
        // when the capped end predates the start.
        let effective_start = effective_start_ns(self.window_start_ns, self.requested_start_ns);
        let effective_end_ns = effective_end_ns.max(effective_start);
        // H7: a salvage fatal dominates the attach-zero
        // computation (the close failure is the verdict; zero
        // attaches stay visible in the coverage rows).
        let fatal = salvage.as_ref().map(|s| s.fatal.clone()).or(
            if self.attached_total == 0 && !self.adapter.emitted.is_empty() {
                Some(evidence::FatalKind::AttachZero)
            } else {
                None
            },
        );
        // H2 retrospective revision (A-6/B-3b): final evidence
        // taint (poll ∪ close) revises every claimed site —
        // current AND fenced — before the doc is built. Census
        // taint never touches sites (emitted+proven sites are
        // in-window by construction). (adapter.emitted needs no
        // revision: Capture carries no adapter — the doc's sites
        // come from this drain alone.)
        {
            let poll_global = self.adapter.taint_global;
            let site_tainted = |site: &SiteExecution| {
                close_evidence_global
                    || poll_global
                    || close_backings.contains(&(site.site.inode, site.site.offset))
                    || site.candidates.iter().any(|c| {
                        close_evidence_ops.contains(&c.op)
                            || self.adapter.tainted_ops.contains(&c.op)
                    })
            };
            for site in drain
                .current
                .iter_mut()
                .chain(drain.fenced.iter_mut().flat_map(|g| g.sites.iter_mut()))
            {
                // R01: taint voids AmbiguousComplete exactly like
                // Complete — possibly-missing evidence unproves the
                // no-rows-missing finiteness claim.
                if matches!(
                    site.candidates_coverage,
                    CandidateCoverage::Complete | CandidateCoverage::AmbiguousComplete
                ) && site_tainted(site)
                {
                    site.candidates_coverage = CandidateCoverage::Unknown;
                }
            }
        }
        // Traversal evidence is NOT adapted into count-session
        // sites (round 3, F1): manufacturing executions from
        // query visibility fabricates execution. The traversal
        // outcome (records + identities + TRUE-T + provenance)
        // reports natively; the inventory below carries only
        // count-observed executions.
        let mut counters = drain.counters.clone();
        counters.extend(self.activity.iter().cloned());
        counters.extend(self.extra_counters.iter().cloned());
        // R05: typed ENGINE observations join the finalized
        // document once, from the same in-window tripwire evidence
        // the legacy block below renders. Unjoinable increments
        // are loud loss (never silent evidence loss).
        let (engine_observations, engine_unkeyed) = self.build_engine_observations();
        if engine_unkeyed > 0 {
            counters.push(typed_counter(
                "engine.observation_unkeyed",
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Discovery,
                engine_unkeyed,
            ));
        }
        // P1: traversal losses feed the sole finalizer as typed
        // gaps (a compat Capture reason alone does not restore
        // document completeness — storm/throttle/incomplete/
        // unjoined/finish-error windows must partial the document
        // with named reasons). Observed records are preserved
        // untouched (done/findings flow to the traversal section
        // as before — only the gaps are newly typed).
        if let Some(t) = self.traversal.as_ref() {
            if t.storm_polls > 0 {
                counters.push(typed_counter(
                    "traversal.storm",
                    CounterKind::Loss,
                    CounterUnits::Events,
                    CounterSource::Discovery,
                    t.storm_polls,
                ));
            }
            if t.throttled_polls > 0 {
                counters.push(typed_counter(
                    "traversal.throttled",
                    CounterKind::Loss,
                    CounterUnits::Events,
                    CounterSource::Discovery,
                    t.throttled_polls,
                ));
            }
            if t.finish_error.is_some() {
                counters.push(typed_counter(
                    "traversal.finish_error",
                    CounterKind::Loss,
                    CounterUnits::Events,
                    CounterSource::Discovery,
                    1,
                ));
            }
            let incomplete = t
                .done
                .iter()
                .filter(|w| !matches!(w.outcome, ScanOutcome::Complete { .. }))
                .count() as u64;
            if incomplete > 0 {
                counters.push(typed_counter(
                    "traversal.incomplete",
                    CounterKind::Loss,
                    CounterUnits::Events,
                    CounterSource::Discovery,
                    incomplete,
                ));
            }
            if !t.findings.is_empty() {
                counters.push(typed_counter(
                    "traversal.unjoined",
                    CounterKind::Loss,
                    CounterUnits::Events,
                    CounterSource::Discovery,
                    t.findings.len() as u64,
                ));
            }
        }
        // H8: legacy call partition over the claimed sites (taint
        // revisions applied above; finalize only sorts/dedups
        // candidates, never calls, so pre-finalize values equal the
        // document's). One computation feeds both the v2 document
        // field and the v1 legacy section below.
        let legacy_files =
            legacy_files_for(self.cfg.resolved_provider.as_ref(), &self.adapter.objects);
        let call_partition = partition_calls(&drain.current, &drain.fenced, &legacy_files);
        let mut document = evidence::finalize(FinalizeInput {
            window: CaptureWindow {
                requested_start_ns: self.requested_start_ns,
                requested_end_ns: requested_end,
                effective_start_ns: effective_start,
                effective_end_ns,
                signal_cut: self.signal_cut,
            },
            sites: drain.current.clone(),
            fenced: drain.fenced.clone(),
            objects: self.adapter.objects.clone(),
            coverage,
            counters,
            fatal,
            target: doc_target(
                self.info.pid,
                &self.comm,
                &self.info.container_id,
                &self.info.image_digest,
            ),
            openssl: OpensslVersion::unknown(),
            disposition: doc_disposition(self.info.owned, disposition.as_ref()),
            policy: None,
            legacy_partition: evidence_partition(call_partition),
            engine_observations,
            traversal: self.traversal.as_ref().and_then(traversal_record),
        });
        // R12: retain the one consistently captured pair
        // (monotonic fields stay authoritative).
        document.context = Some(doc_context(
            &self.info.kernel_release,
            self.wall_start,
            self.wall_end,
        ));
        // R06: failed-attach diagnostics ride the document (sorted
        // set take, capped — deterministic; the counters stay the
        // exact counts regardless).
        document.attach_diagnostics = self
            .adapter
            .attach_diagnostics
            .iter()
            .take(ATTACH_DIAGNOSTICS_CAP)
            .cloned()
            .collect();

        // Legacy `legacy` block from IN-WINDOW tripwire evidence only
        // (baselined at the declared boundary; the post-count-close
        // tail never becomes execution).
        let blind = legacy::blind_probe_set();
        let set = snapshot.legacy.set.as_ref().unwrap_or(&blind);
        let extra: Vec<&str> = snapshot
            .legacy
            .extra_findings
            .iter()
            .map(String::as_str)
            .collect();
        let legacy_doc = legacy::section(&legacy::SectionInputs {
            set,
            trip: &self.in_window_trip,
            trip_hits: &self.in_window_hits,
            legacy_queries: self.in_window_lgcalls,
            legacy_classes: self.adapter.legacy_classes.iter().cloned().collect(),
            extra_findings: &extra,
            call_partition,
        });

        self.emit_gap_reasons(document.reasons());
        if !self.trigger_observed {
            self.reason("no-query");
        } else if document.sites.is_empty() && document.fenced.iter().all(|g| g.sites.is_empty()) {
            self.reason("empty-inventory");
        }
        if !self.info.owned {
            self.reason("pid-prewindow-blind");
        }
        if self.cfg.provider.as_deref().is_some_and(fips_configured) && document.total_calls() > 0 {
            self.reason("fips-unlabeled");
        }
        if engine_un > 0 {
            self.reason("engine-fallback-uninstrumented");
        }
        if meth_un > 0 {
            self.reason("meth-fallback-uninstrumented");
        }
        if low_un > 0 {
            self.reason("lowlevel-fallback-uninstrumented");
        }
        if snapshot.dispatch.preset_reason.is_some() {
            self.reason("harvest-anchor-unresolved");
        }

        let outcome = match &document.status {
            Completeness::Complete if self.reasons.is_empty() => Outcome::Complete,
            Completeness::Fatal { kind, .. } => Outcome::Fatal(match kind {
                evidence::FatalKind::Recycled => FatalKind::Recycled,
                evidence::FatalKind::AttachZero => FatalKind::AttachZero,
                evidence::FatalKind::Environment(msg) => FatalKind::Env(msg.clone()),
                evidence::FatalKind::Runtime(msg) => FatalKind::Runtime(msg.clone()),
            }),
            _ => Outcome::Partial,
        };
        let mut executions = Vec::new();
        for site in &document.sites {
            if site.calls == 0 {
                continue;
            }
            let (id, aliases) = render_candidates(&site.candidates, site.site.offset);
            executions.push(Execution {
                cookie: self.cookie_for_site(site),
                id,
                aliases,
                count: site.calls,
                first_ns: site.first_ns,
                last_ns: site.last_ns,
            });
        }
        sort_executions(&mut executions);
        let mut stale = Vec::new();
        for generation in &document.fenced {
            let mut detail: Vec<StaleDetail> = Vec::new();
            for site in &generation.sites {
                if site.calls == 0 {
                    continue;
                }
                let (id, _) = render_candidates(&site.candidates, site.site.offset);
                detail.push(StaleDetail {
                    cookie: self.cookie_for_site(site),
                    id,
                    count: site.calls,
                    first_ns: site.first_ns,
                    last_ns: site.last_ns,
                });
            }
            detail.sort_by_key(|d| d.cookie);
            let events = detail.iter().map(|d| d.count).sum();
            stale.push(StaleBucket {
                generation: generation.generation,
                events,
                keys: detail.len() as u64,
                detail,
            });
        }
        let counter_value = |name: &str| {
            document
                .counters
                .iter()
                .find(|c| c.name == name)
                .map(|c| c.value)
                .unwrap_or(0)
        };
        let mut covered: HashSet<u32> = executions.iter().map(|e| e.id.op).collect();
        for bucket in &stale {
            for row in &bucket.detail {
                covered.insert(row.id.op);
            }
        }
        let uninstrumented = kinds::OPS
            .iter()
            .filter(|op| !covered.contains(&op.id))
            .count() as u64;
        let counters = Counters {
            dropped_bpf: counter_value("count.map_insert_dropped"),
            dropped_userspace: counter_value("count.unattributed"),
            missed_attaches: counter_value("count.missed_attaches"),
            unresolved_offsets: counter_value("count.unresolved_offsets"),
            table_staleness_events: counter_value("count.stale_events"),
            cold_gap_calls: self.cold_gap_queries,
            provider_changed: self.provider_changed_fences,
            scan_budget_exhaustions: self.scan_budget_exhaustions,
            engine_fallback_uninstrumented: engine_un,
            drain_shortfall: counter_value("count.drain_shortfall"),
            uninstrumented_ops: uninstrumented,
            fork_exec_ignored: self.fork_exec_ignored,
            over_budget: counter_value("capture.over_budget"),
        };
        let status = match &outcome {
            Outcome::Complete => "COMPLETE",
            Outcome::Partial => "PARTIAL",
            Outcome::Fatal(_) => "FATAL",
        };
        let harvest_doc = serde_json::json!({
            "status": status,
            "trigger_observed": self.trigger_observed,
            "rows": [],
        });
        let window_actual = self
            .clock
            .now()
            .saturating_duration_since(self.open_instant);
        self.finish_capture(
            document,
            FinishParts {
                outcome,
                executions,
                stale,
                counters,
                legacy: legacy_doc,
                harvest_doc,
                disposition,
                window_actual,
            },
        )
    }

    /// Cookie minted for a drained site (recorded at attach);
    /// defensive sentinel on miss — evidence is preserved, never
    /// dropped for a bookkeeping gap.
    fn cookie_for_site(&self, site: &SiteExecution) -> u32 {
        self.site_cookies
            .get(&site.site)
            .copied()
            .unwrap_or_else(|| {
                eprintln!("CAPTURE cookie miss for drained site (defensive sentinel)");
                u32::MAX
            })
    }

    /// Map finalized gaps onto the legacy reason vocabulary. Every
    /// arm uses an explicit literal: the taxonomy test scans these
    /// call sites, and the auditor vocabulary mirrors them.
    fn emit_gap_reasons(&mut self, gaps: &[GapReason]) {
        for gap in gaps {
            match gap {
                GapReason::UnknownDenominator { .. }
                | GapReason::UndiscoveredSites { .. }
                | GapReason::UnattachedSites { .. } => self.reason("discovery-loss"),
                GapReason::Loss { counter, .. } => self.emit_loss_reason(counter),
                GapReason::UnattributedCalls { .. } => self.reason("unattributed"),
                GapReason::StartupGap { .. } => self.reason("startup-gap"),
                GapReason::TailGap { .. } => self.reason("tail-gap"),
                GapReason::SignalCut => self.reason("interrupted"),
            }
        }
    }

    /// Map one loss counter onto the legacy reason vocabulary (same
    /// explicit-literal rule as above). Unmapped names fail closed
    /// to blind PARTIAL, never to silence.
    fn emit_loss_reason(&mut self, counter: &str) {
        match counter {
            "count.map_insert_dropped" => self.reason("dropped-events"),
            "count.unattributed" => self.reason("unattributed"),
            "count.drain_shortfall" => self.reason("drain-shortfall"),
            "count.missed_attaches" => self.reason("missed-attaches"),
            "count.unresolved_offsets" => self.reason("unresolved-offsets"),
            "capture.over_budget" => self.reason("over-budget"),
            "lifecycle.fork_exec_ignored"
            | "lifecycle.scan_loss"
            | "lifecycle.signal_dropped"
            | "lifecycle.signal_prefix_unwitnessed"
            | "lifecycle.no_witness"
            | "lifecycle.drain_pending"
            | "lifecycle.exec_gap" => self.reason("fork-exec-ignored"),
            "lifecycle.polling_fallback" => self.reason("lifecycle-polling-partial"),
            "discovery.pre_window_queries" => self.reason("cold-gap"),
            "discovery.late_attach_sites" => self.reason("late-attach"),
            "discovery.unverified_read" => self.reason("discovery-loss"),
            "legacy.engine_uninstrumented" => self.reason("engine-fallback-uninstrumented"),
            "legacy.meth_uninstrumented" => self.reason("meth-fallback-uninstrumented"),
            "legacy.lowlevel_uninstrumented" => self.reason("lowlevel-fallback-uninstrumented"),
            // P1: typed traversal gaps map back onto their compat
            // reasons (same strings the round/tail folds insert —
            // the set dedups, so typed + compat never double-report).
            "traversal.storm" => self.reason("traversal-storm"),
            "traversal.throttled" => self.reason("traversal-throttled"),
            "traversal.finish_error" => self.reason("traversal-finish-error"),
            "traversal.incomplete" => self.reason("traversal-incomplete"),
            "traversal.unjoined" => self.reason("traversal-unjoined"),
            _ => self.reason("discovery-loss"),
        }
    }

    fn finish_capture(self, document: CaptureDocument, parts: FinishParts) -> Capture {
        let mut reasons: Vec<String> = self.reasons.into_iter().collect();
        reasons.sort();
        Capture {
            target_pid: self.info.pid,
            target_comm: self.comm.clone(),
            window_planned: self.cfg.duration,
            window_actual: parts.window_actual,
            outcome: parts.outcome,
            reasons,
            executions: parts.executions,
            stale: parts.stale,
            counters: parts.counters,
            child_exit: self.child_exit,
            drain_wall_us: self.drain_wall_us,
            harvest_doc: parts.harvest_doc,
            legacy: parts.legacy,
            window_start_wall: self.wall_start,
            window_end_wall: self.wall_end,
            kernel_release: self.info.kernel_release.clone(),
            target_cmdline: self.info.cmdline.clone(),
            target_container_id: self.info.container_id.clone(),
            provider_build_id: self.info.provider_build_id.clone(),
            provider_path: self.info.provider_path.clone(),
            image_digest: self.info.image_digest.clone(),
            document,
            disposition: parts.disposition,
            traversal: self.traversal,
        }
    }
}

/// Assembled window parts (kept out of the 7-argument lint).
struct FinishParts {
    outcome: Outcome,
    executions: Vec<Execution>,
    stale: Vec<StaleBucket>,
    counters: Counters,
    legacy: serde_json::Value,
    harvest_doc: serde_json::Value,
    disposition: Option<target::TargetDisposition>,
    window_actual: Duration,
}

/// Render count candidates into the legacy identity shape (T10/T11
/// seam): the first candidate rides as the primary identity with the
/// rest as aliases. Provider label is the candidate class, never a
/// filename guess.
fn render_candidates(
    candidates: &[CandidateIdentity],
    offset: u64,
) -> (plan::Identity, Vec<plan::Identity>) {
    let render = |c: &CandidateIdentity| plan::Identity {
        provider: c.provider_class.clone(),
        op: c.op,
        funcid: c.funcid,
        alg_class: c
            .algorithm_classes
            .first()
            .cloned()
            .unwrap_or_else(|| "other".to_string()),
        offset,
    };
    let mut iter = candidates.iter();
    match iter.next() {
        Some(first) => (render(first), iter.map(render).collect()),
        None => (
            plan::Identity {
                provider: "unknown".to_string(),
                op: 0,
                funcid: 0,
                alg_class: "other".to_string(),
                offset,
            },
            Vec::new(),
        ),
    }
}

/// FIPS KAT caveat trigger (display-level, operator-configured): the
/// CONFIGURED provider path is fips-shaped and provider-plane calls
/// executed. Not a filename guess about target identity — the
/// operator told us which module to watch.
fn fips_configured(provider: &Path) -> bool {
    let stem = provider.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let stem = stem.strip_suffix(".so").unwrap_or(stem);
    stem == "fips"
}

// ---------------------------------------------------------------- run

/// Pre-attach recycle capture (`--pid` only): the pin failed during
/// discovery attach, so no session was ever held.
fn recycled_capture(cfg: &Config, info: &TargetInfo) -> Capture {
    let requested_end = info.acquired_ns.saturating_add(duration_ns(cfg.duration));
    let mut document = evidence::finalize(FinalizeInput {
        window: CaptureWindow {
            requested_start_ns: info.acquired_ns,
            requested_end_ns: requested_end,
            effective_start_ns: requested_end,
            effective_end_ns: requested_end,
            signal_cut: false,
        },
        sites: Vec::new(),
        fenced: Vec::new(),
        objects: Vec::new(),
        coverage: Vec::new(),
        counters: Vec::new(),
        fatal: Some(evidence::FatalKind::Recycled),
        target: doc_target(info.pid, &info.comm, &info.container_id, &info.image_digest),
        openssl: OpensslVersion::unknown(),
        disposition: None,
        policy: None,
        legacy_partition: LegacyCallPartition::default(),
        engine_observations: Vec::new(),
        traversal: None,
    });
    // R12: the pre-attach recycle carries the acquisition instant in
    // both wall edges, mirroring the legacy Capture wall fields.
    document.context = Some(doc_context(
        &info.kernel_release,
        info.acquired_wall,
        info.acquired_wall,
    ));
    Capture {
        target_pid: info.pid,
        target_comm: info.comm.clone(),
        window_planned: cfg.duration,
        window_actual: Duration::ZERO,
        outcome: Outcome::Fatal(FatalKind::Recycled),
        reasons: vec!["pid-recycled".to_string()],
        executions: Vec::new(),
        stale: Vec::new(),
        counters: Counters::default(),
        child_exit: None,
        drain_wall_us: 0,
        harvest_doc: serde_json::json!({}),
        legacy: serde_json::Value::Null,
        window_start_wall: info.acquired_wall,
        window_end_wall: info.acquired_wall,
        kernel_release: info.kernel_release.clone(),
        target_cmdline: info.cmdline.clone(),
        target_container_id: info.container_id.clone(),
        provider_build_id: info.provider_build_id.clone(),
        provider_path: info.provider_path.clone(),
        image_digest: info.image_digest.clone(),
        document,
        disposition: None,
        traversal: None,
    }
}

/// Provider selection after onboarding resolution.
struct ResolvedProvider {
    path: PathBuf,
    builtin: bool,
    build_id: String,
    provider_class: Option<String>,
}

/// Effective run config: onboarding `None`s replaced by resolved
/// values, so the controller below sees concrete paths + the
/// effective observation mode.
fn effective_config(
    cfg: &Config,
    objects: &onboard::ObjectPaths,
    resolved: &ResolvedProvider,
) -> Config {
    let mut out = cfg.clone();
    out.harvest_object = Some(objects.harvest.clone());
    out.count_object = Some(objects.count.clone());
    out.provider = Some(resolved.path.clone());
    out.builtin = resolved.builtin;
    out.resolved_provider = pin_provider_class(
        resolved.builtin,
        &resolved.build_id,
        resolved.provider_class.as_deref(),
    );
    out
}

/// Automatic-discovery target: a live pid's maps, or pre-exec
/// spawn prediction (a stopped child's maps still show the
/// pre-exec image, so `run --` predicts from the exe instead).
enum AutoTarget<'a> {
    Pid(u32),
    Spawn(&'a [String]),
}

/// Resolve + qualify the capture provider: explicit `--provider`
/// (builtin or file mode) or automatic discovery (live maps for
/// `--pid`, exe prediction for `run --`; builtin mode).
/// Unsupported/Unknown targets fail closed with enrollment
/// remediation — offsets are never guessed.
fn resolve_capture_provider(
    auto: AutoTarget,
    cfg: &Config,
    offset_table: &crate::discovery::builtin::Table,
    enrollment: &ProviderTable,
) -> anyhow::Result<ResolvedProvider> {
    let builtin = cfg.builtin || cfg.provider.is_none();
    let opts = onboard::QualifyOpts {
        offset_table,
        offset_table_explicit: cfg.table.is_some(),
        force_offset: cfg.force_offset,
        enrollment,
        builtin_asserted: builtin,
    };
    let qual = match &cfg.provider {
        Some(p) => {
            let bytes = onboard::read_bounded(p, onboard::MAX_OBJECT_SCAN_BYTES)
                .map_err(|e| anyhow::anyhow!("provider {} unreadable: {e}", p.display()))?;
            if builtin {
                onboard::qualify_libcrypto_bytes(&bytes, p, false, &opts)
            } else {
                onboard::qualify_file_provider_bytes(&bytes, p, &opts)
            }
        }
        None => {
            // The child inherits our environment, so current
            // `PATH`/`LD_LIBRARY_PATH` predict its resolution.
            let path_var = std::env::var("PATH").unwrap_or_else(|_| "/bin:/usr/bin".to_string());
            let ld_var = std::env::var("LD_LIBRARY_PATH").ok();
            let spenv = onboard::SpawnEnv {
                path: &path_var,
                ld_library_path: ld_var.as_deref(),
            };
            let qual = match auto {
                AutoTarget::Pid(p) => onboard::discover_pid(p, &opts),
                AutoTarget::Spawn(argv) => onboard::discover_spawn(argv, &opts, &spenv),
            };
            qual.map_err(|e| anyhow::anyhow!("target discovery: {}", e.full()))?
        }
    };
    match qual {
        onboard::TargetQualification::Supported(t) => {
            if cfg.provider.is_none() {
                eprintln!(
                    "osslscope: auto discovery: provider={} class={} via={}",
                    t.provider_path.display(),
                    t.provider_class.map(|c| c.as_str()).unwrap_or("unknown"),
                    t.resolution.map(|r| r.as_str()).unwrap_or("init-anchor"),
                );
            }
            Ok(ResolvedProvider {
                path: t.provider_path,
                builtin: t.builtin,
                build_id: t.build_id.unwrap_or_else(|| "unknown".to_string()),
                provider_class: t.provider_class.map(|c| c.as_str().to_string()),
            })
        }
        onboard::TargetQualification::Unsupported {
            reason,
            remediation,
        } => Err(anyhow::anyhow!(
            "unsupported target: {reason}; fix: {remediation}"
        )),
        onboard::TargetQualification::Unknown {
            reason,
            remediation,
        } => Err(anyhow::anyhow!(
            "unqualified target: {reason}; fix: {remediation}"
        )),
    }
}

/// Run a full capture window against `target` (harvest-only:
/// the qualified default — pair resolution, unchanged behavior).
pub fn run(cfg: &Config, target: Target) -> anyhow::Result<Capture> {
    if cfg.duration.is_zero() {
        anyhow::bail!("--duration must be > 0 (no --forever in v1)");
    }
    // Full coexistence with automatic selection (Decision 8R) over
    // the production search set (see `run_with_dirs`).
    run_with_dirs(
        cfg,
        target,
        &onboard::default_object_dirs(),
        &onboard::TrustPolicy::production(),
    )
}

/// Ordinary run over an explicit object search set: an explicit
/// members object demands the triple (fail-closed); otherwise the
/// shared run-set decision runs — complete compatible sets
/// traverse, pair-only prefixes stay harvest-only (unchanged),
/// and mixed/stale/broken sets refuse exactly like doctor (never
/// a silent harvest-only fallback where doctor rejects). `run` is
/// this with the production default dirs + trust; lanes and
/// custom prefixes pass their own.
pub fn run_with_dirs(
    cfg: &Config,
    target: Target,
    dirs: &[PathBuf],
    trust: &onboard::TrustPolicy,
) -> anyhow::Result<Capture> {
    if cfg.duration.is_zero() {
        anyhow::bail!("--duration must be > 0 (no --forever in v1)");
    }
    if cfg.members_object.is_some() {
        return run_with_traversal_in(cfg, target, cfg.members_object.as_deref(), dirs, trust);
    }
    match onboard::resolve_run_set(
        cfg.harvest_object.as_deref(),
        cfg.count_object.as_deref(),
        None,
        dirs,
        trust,
    ) {
        Ok((onboard::RunSet::Triple(set), _)) => run_inner(
            cfg,
            target,
            onboard::ObjectPaths {
                harvest: set.harvest.clone(),
                count: set.count.clone(),
            },
            Some(traversal_attach(&set, true)?),
        ),
        Ok((onboard::RunSet::PairOnly(objects), _)) => {
            // Pair-only install (no members file anywhere): the
            // ordinary harvest-only run, exactly as before.
            run_inner(cfg, target, objects, None)
        }
        Ok((onboard::RunSet::NoObjects(pair_e), _)) => {
            Err(anyhow::anyhow!("BPF objects: {}", pair_e.full()))
        }
        Err(e) => Err(anyhow::anyhow!("BPF objects: {}", e.full())),
    }
}

/// Ordinary run with an explicitly requested triple (shared by
/// `run` with `--members-object` and `run_traversal`): the triple
/// resolves first — missing/mixed/stale sets refuse before any
/// side effect — then the ordinary window runs with the members
/// backend draining alongside discovery.
fn run_with_traversal(
    cfg: &Config,
    target: Target,
    members: Option<&Path>,
) -> anyhow::Result<Capture> {
    run_with_traversal_in(
        cfg,
        target,
        members,
        &onboard::default_object_dirs(),
        &onboard::TrustPolicy::production(),
    )
}

/// `run_with_traversal` over an explicit search set (see
/// `run_with_dirs`).
fn run_with_traversal_in(
    cfg: &Config,
    target: Target,
    members: Option<&Path>,
    dirs: &[PathBuf],
    trust: &onboard::TrustPolicy,
) -> anyhow::Result<Capture> {
    let (set, _) = onboard::resolve_set(
        cfg.harvest_object.as_deref(),
        cfg.count_object.as_deref(),
        members,
        dirs,
        trust,
    )
    .map_err(|e| anyhow::anyhow!("BPF objects: {}", e.full()))?;
    run_inner(
        cfg,
        target,
        onboard::ObjectPaths {
            harvest: set.harvest.clone(),
            count: set.count.clone(),
        },
        Some(traversal_attach(&set, false)?),
    )
}

/// Build the traversal attach from a resolved triple: snapshot
/// every role's bytes (implicit roles re-verified against their
/// receipt — a swap between resolve and snapshot fails loud —
/// explicit roles bounded-read, never receipt-checked) and retain
/// all three snapshots so no loader re-reads a path (no reread
/// drift between identity and loading). `auto` marks automatic
/// selection (init-mode targets degrade to harvest-only —
/// round-0 behavior preserved); explicit requests refuse loud on
/// a missing anchor instead.
fn traversal_attach(set: &onboard::ObjectSet, auto: bool) -> anyhow::Result<TraversalAttach> {
    let (provenance, bytes) = triple_snapshot(set)?;
    Ok(TraversalAttach {
        members: set.members.clone(),
        members_bytes: bytes.members,
        harvest_bytes: bytes.harvest,
        count_bytes: bytes.count,
        provenance,
        auto,
    })
}

/// Run a full capture window with the traversal backend attached
/// (explicit per-run request — the same triple `run` selects
/// automatically when available): the harvest/count/members triple
/// resolves first — missing/mixed/stale sets refuse before any
/// side effect, never a silent harvest-only fallback — then the
/// ordinary window runs with the members backend draining
/// alongside discovery.
pub fn run_traversal(
    cfg: &Config,
    target: Target,
    req: &TraversalRequest,
) -> anyhow::Result<Capture> {
    if cfg.duration.is_zero() {
        anyhow::bail!("--duration must be > 0 (no --forever in v1)");
    }
    run_with_traversal(cfg, target, req.members_object.as_deref())
}

/// Traversal attach request (resolved members object + every
/// role's verified byte snapshot + the matched-set provenance the
/// capture retains). Identity and loading share these bytes — no
/// loader re-opens a path, so no swap can interpose between the
/// hash and any load.
struct TraversalAttach {
    members: PathBuf,
    members_bytes: Vec<u8>,
    harvest_bytes: Vec<u8>,
    count_bytes: Vec<u8>,
    provenance: TripleProvenance,
    auto: bool,
}

/// Verified byte snapshots for a resolved triple (one bounded
/// read per role — the same bytes the provenance hashes, the
/// backend loads, and the harvest/count loaders consume).
#[derive(Debug)]
struct TripleBytes {
    harvest: Vec<u8>,
    count: Vec<u8>,
    members: Vec<u8>,
}

/// Mint matched-set provenance for a resolved triple and retain
/// every role's byte snapshot. Implicit roles re-verify against
/// their receipt HERE (a swap between resolve and snapshot fails
/// loud — identity binds to THESE bytes); explicit roles are
/// bounded-read only (operator-trusted, never receipt-checked).
fn triple_snapshot(set: &onboard::ObjectSet) -> anyhow::Result<(TripleProvenance, TripleBytes)> {
    use sha2::Digest as _;
    let snap = |role: onboard::ObjectRole,
                path: &Path,
                explicit: bool|
     -> anyhow::Result<(ObjectProvenance, Vec<u8>)> {
        let bytes = if explicit {
            onboard::read_bounded(path, onboard::MAX_OBJECT_SCAN_BYTES).map_err(|e| {
                anyhow::anyhow!("{} object {}: {e}", role.describe(), path.display())
            })?
        } else {
            onboard::verify_role_receipt_bytes(role, path)
                .map_err(|e| anyhow::anyhow!("BPF objects: {}", e.full()))?
        };
        Ok((
            ObjectProvenance {
                path: path.to_path_buf(),
                sha256: sha2::Sha256::digest(&bytes)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
            },
            bytes,
        ))
    };
    let (harvest, harvest_bytes) =
        snap(onboard::ObjectRole::Harvest, &set.harvest, set.explicit[0])?;
    let (count, count_bytes) = snap(onboard::ObjectRole::Count, &set.count, set.explicit[1])?;
    let (members, members_bytes) =
        snap(onboard::ObjectRole::Members, &set.members, set.explicit[2])?;
    Ok((
        TripleProvenance {
            harvest,
            count,
            members,
        },
        TripleBytes {
            harvest: harvest_bytes,
            count: count_bytes,
            members: members_bytes,
        },
    ))
}

/// Apply post-drain corrections to held verdicts (pure):
/// rewrite outcome + op by (tid, seq) key. Unknown keys are
/// ignored (defensive — holders extend monotonically, so a
/// correction always names a held verdict; a missing key means
/// the holder never saw the verdict, and there is nothing
/// false standing to fix).
fn apply_corrections(done: &mut [WalkDone], corrections: &[crate::scan::oracle::Correction]) {
    for c in corrections {
        if let Some(w) = done.iter_mut().find(|w| w.tid == c.tid && w.seq == c.seq) {
            w.outcome = c.outcome.clone();
            w.op = c.op;
        }
    }
}

/// Anchor-or-degrade decision (pure): an explicit traversal
/// request without an anchor refuses (the operator demanded the
/// impossible); automatic selection without an anchor degrades
/// to harvest-only (init-mode and dispatch-blind runs keep
/// working exactly as before — the operator never asked for
/// traversal). Traversal never guesses an offset either way.
fn anchor_or_degrade(
    anchor: Option<(PathBuf, u64)>,
    auto: bool,
) -> anyhow::Result<Option<(PathBuf, u64)>> {
    match (anchor, auto) {
        (Some(a), _) => Ok(Some(a)),
        (None, true) => Ok(None),
        (None, false) => anyhow::bail!(
            "traversal requires the builtin query anchor (init-mode and dispatch-blind targets cannot traverse)"
        ),
    }
}

/// Wrap an attached discovery session for the run: harvest-only
/// by default; traversal runs pin the builtin query anchor and
/// attach the members backend (full 512, production CTRL).
/// Explicit traversal without an anchor (init mode /
/// dispatch-blind — traversal never guesses an offset) refuses
/// BEFORE the window opens (no release yet — the caller resolves
/// custody exactly like a discovery-attach failure); automatic
/// selection without an anchor degrades to harvest-only instead
/// (existing init-mode runs keep working exactly as before —
/// the operator never asked for traversal).
fn wrap_discovery(
    session: DiscoverySession,
    traversal: Option<&TraversalAttach>,
    pid: u32,
) -> anyhow::Result<CaptureDiscovery> {
    let Some(t) = traversal else {
        return Ok(CaptureDiscovery::HarvestOnly(Box::new(LiveDiscovery::new(
            session,
        ))));
    };
    let Some((exe_path, off)) = anchor_or_degrade(session.query_anchor(), t.auto)? else {
        return Ok(CaptureDiscovery::HarvestOnly(Box::new(LiveDiscovery::new(
            session,
        ))));
    };
    let exe_str = exe_path.to_str().ok_or_else(|| {
        anyhow::anyhow!("traversal anchor path is not UTF-8: {}", exe_path.display())
    })?;
    let exe = std::ffi::CString::new(exe_str)?;
    let ctrl = crate::loader::default_ctrl(512, crate::loader::MEMBER_RING_BYTES)?;
    // The backend loads the verified snapshot (never re-opens the
    // path) on the capture clock (WALK-DONE instants are
    // capture-ns, joining the evidence document honestly).
    let backend = ScanBackend::attach_bytes(
        &t.members_bytes,
        &t.members,
        &exe,
        off,
        pid,
        &ctrl,
        None,
        LiveClock.monotonic_ns(),
    )
    .map_err(|e| anyhow::anyhow!("members backend attach: {e:#}"))?;
    Ok(CaptureDiscovery::Traversal(Box::new(
        LiveTraversalDiscovery::new(session, backend, pid, t.provenance.clone()),
    )))
}

/// Shared window setup over resolved objects (both entries funnel
/// here after their own resolution; `traversal` selects the
/// backend attach after discovery attaches, before release).
fn run_inner(
    cfg: &Config,
    target: Target,
    objects: onboard::ObjectPaths,
    traversal: Option<TraversalAttach>,
) -> anyhow::Result<Capture> {
    arm_signals();
    // Triple runs load the retained count snapshot (no re-read —
    // identity and loading share these bytes); harvest-only runs
    // bounded-read the resolved path (a swap between resolve and
    // load fails loud, never huge).
    let obj_bytes = match traversal.as_ref() {
        Some(t) => t.count_bytes.clone(),
        None => onboard::read_bounded(&objects.count, onboard::MAX_OBJECT_SCAN_BYTES)
            .map_err(|e| anyhow::anyhow!("count object {}: {e}", objects.count.display()))?,
    };
    let prep = crate::loader::prepare(
        &obj_bytes,
        &crate::loader::COUNT_MAPS,
        &crate::loader::COUNT_PROGS,
    )?;
    let loaded = crate::loader::load(&prep).map_err(|e| anyhow::anyhow!("count load: {e:#}"))?;
    // Target-identity snapshot at acquisition (the target may be
    // dead by report time — /proc reads then would miss).
    let acq_clock = LiveClock;
    let acq_ns = acq_clock.monotonic_ns();
    let acq_instant = Instant::now();
    let acq_wall = SystemTime::now();
    // Offset table for target qualification (explicit file or
    // shipped; the CLI pre-validated an explicit file, so a failure
    // here is a mid-run environment change, not a usage error).
    let offset_table = match &cfg.table {
        Some(p) => onboard::load_offset_table_file(p)
            .map_err(|e| anyhow::anyhow!("offset table: {}", e.full()))?,
        None => crate::discovery::builtin::shipped_table(),
    };
    let empty_enrollment = ProviderTable::empty();
    let enrollment = cfg
        .provider_enrollment
        .as_ref()
        .unwrap_or(&empty_enrollment);
    match target {
        Target::Spawn { argv, workload } => {
            let cmdline = args::redact_spawn_argv(&argv);
            // R06/F07: pre-stop setup runs under the checked
            // harvest-timeout deadline and the live SIGINT/SIGTERM
            // flag — a blocking workload destination or a lost stop
            // can neither hang setup nor orphan a child: every
            // failure kills + reaps only this never-released owned
            // child. (observe() bounds its own post-spawn setup
            // slice separately with the same timeout.)
            let setup_deadline = match args::deadline_at(Instant::now(), cfg.harvest_timeout) {
                Some(d) => d,
                None => anyhow::bail!("spawn: setup deadline overflow"),
            };
            let mut owned = target::OwnedTarget::spawn_stopped_with_control(
                &argv,
                workload,
                setup_deadline,
                &INTERRUPTED,
            )
            .map_err(|e| anyhow::anyhow!("spawn: {e:#}"))?;
            let pid = owned.pid();
            let resolved = match resolve_capture_provider(
                AutoTarget::Spawn(&argv),
                cfg,
                &offset_table,
                enrollment,
            ) {
                Ok(r) => r,
                Err(e) => {
                    // Same custody rule as a discovery-attach
                    // failure: preserve status, resolve, fail loud.
                    let exit_note = owned
                        .poll_exit()
                        .ok()
                        .flatten()
                        .map(|code| format!(" (child status {code})"))
                        .unwrap_or_default();
                    let _ = owned.resolve_setup_failure();
                    return Err(e.context(format!("target resolution{exit_note}")));
                }
            };
            let effective = effective_config(cfg, &objects, &resolved);
            let info = TargetInfo {
                pid,
                owned: true,
                comm: comm_of(pid),
                cmdline,
                container_id: container_id_of(pid),
                kernel_release: crate::doctor::uname_release(),
                provider_build_id: resolved.build_id,
                provider_path: resolved.path.to_string_lossy().into_owned(),
                image_digest: cfg.image_digest.clone(),
                acquired_ns: acq_ns,
                acquired_instant: acq_instant,
                acquired_wall: acq_wall,
            };
            let backend = crate::count_session::LiveBackend::new(loaded, pid);
            let count = CountSession::new(pid, backend);
            let discovery = match DiscoverySession::attach(
                &crate::discovery::session::DiscoveryConfig {
                    provider: resolved.path,
                    object: objects.harvest,
                    object_bytes: traversal.as_ref().map(|t| t.harvest_bytes.clone()),
                    builtin: resolved.builtin,
                    legacy: true,
                    table: cfg.table.clone(),
                    force_offset: cfg.force_offset,
                    explicit_offsets: cfg.table.is_some() || cfg.force_offset.is_some(),
                    cmdline_marker: None,
                },
                pid,
            ) {
                Ok(discovery) => discovery,
                Err(e) => {
                    // A stopped child can only die by an outside
                    // kill; preserve whatever status exists, resolve
                    // custody, and fail loud (no zombie, no silence).
                    let exit_note = owned
                        .poll_exit()
                        .ok()
                        .flatten()
                        .map(|code| format!(" (child status {code})"))
                        .unwrap_or_default();
                    let _ = owned.resolve_setup_failure();
                    return Err(e.context(format!("discovery attach{exit_note}")));
                }
            };
            // Traversal opt-in: the backend attaches before release
            // (probes arm while the child is still stopped, like
            // every other plane); refusal custody mirrors discovery.
            let discovery = match wrap_discovery(discovery, traversal.as_ref(), pid) {
                Ok(discovery) => discovery,
                Err(e) => {
                    let exit_note = owned
                        .poll_exit()
                        .ok()
                        .flatten()
                        .map(|code| format!(" (child status {code})"))
                        .unwrap_or_default();
                    let _ = owned.resolve_setup_failure();
                    return Err(e.context(format!("traversal attach{exit_note}")));
                }
            };
            observe(
                &effective,
                &info,
                SessionSet {
                    discovery,
                    count,
                    target: owned,
                    lifecycle: LiveLifecycle::select(pid, false),
                },
                &LiveClock,
                &mut LiveProc,
                &interrupted,
            )
        }
        Target::Pid(p) => {
            let pin_guard = pin::pin(p).map_err(|e| anyhow::anyhow!("pin: {e:#}"))?;
            let resolved =
                resolve_capture_provider(AutoTarget::Pid(p), cfg, &offset_table, enrollment)
                    .map_err(|e| e.context("target resolution"))?;
            let effective = effective_config(cfg, &objects, &resolved);
            let raw = std::fs::read(format!("/proc/{p}/cmdline")).unwrap_or_default();
            let info = TargetInfo {
                pid: p,
                owned: false,
                comm: comm_of(p),
                cmdline: args::redact_proc_cmdline(&raw),
                container_id: container_id_of(p),
                kernel_release: crate::doctor::uname_release(),
                provider_build_id: resolved.build_id,
                provider_path: resolved.path.to_string_lossy().into_owned(),
                image_digest: cfg.image_digest.clone(),
                acquired_ns: acq_ns,
                acquired_instant: acq_instant,
                acquired_wall: acq_wall,
            };
            let backend = crate::count_session::LiveBackend::new(loaded, p);
            let count = CountSession::new(p, backend);
            let discovery = match DiscoverySession::attach(
                &crate::discovery::session::DiscoveryConfig {
                    provider: resolved.path,
                    object: objects.harvest,
                    object_bytes: traversal.as_ref().map(|t| t.harvest_bytes.clone()),
                    builtin: resolved.builtin,
                    legacy: true,
                    table: cfg.table.clone(),
                    force_offset: cfg.force_offset,
                    explicit_offsets: cfg.table.is_some() || cfg.force_offset.is_some(),
                    cmdline_marker: None,
                },
                p,
            ) {
                Ok(discovery) => discovery,
                Err(e) => {
                    // Mid-attach recycle: fatal verdict, no sessions
                    // held (the count object drops unused).
                    if e.downcast_ref::<Recycled>().is_some() {
                        return Ok(recycled_capture(&effective, &info));
                    }
                    return Err(e.context("discovery attach"));
                }
            };
            // Traversal opt-in (same pre-window attach; a refusal
            // here is an anchor/attach failure, never a recycle).
            let discovery = match wrap_discovery(discovery, traversal.as_ref(), p) {
                Ok(discovery) => discovery,
                Err(e) => return Err(e.context("traversal attach")),
            };
            observe(
                &effective,
                &info,
                SessionSet {
                    discovery,
                    count,
                    target: PinnedTarget::new(p, pin_guard),
                    lifecycle: LiveLifecycle::select(p, true),
                },
                &LiveClock,
                &mut LiveProc,
                &interrupted,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::session::{
        AttachEvent, AttachKind, BackingRef, DiscoveredCandidate, DiscoveredObject, TableCoverage,
        TableRetirement,
    };

    #[test]
    fn fix2_anchor_or_degrade_decision_table() {
        // Anchor present: both modes proceed (decision carries it).
        let a = Some((PathBuf::from("/lib/libcrypto.so.3"), 0x26e4a0u64));
        assert_eq!(anchor_or_degrade(a.clone(), true).unwrap(), a);
        assert_eq!(anchor_or_degrade(a.clone(), false).unwrap(), a);
        // Anchor missing: automatic selection degrades (init-mode
        // and dispatch-blind runs keep working harvest-only)...
        assert_eq!(anchor_or_degrade(None, true).unwrap(), None);
        // ...while an explicit traversal request refuses loud (the
        // operator demanded the impossible).
        let err = anchor_or_degrade(None, false).unwrap_err();
        assert!(
            err.to_string().contains("builtin query anchor"),
            "refusal names the anchor: {err:#}"
        );
    }

    static F11_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    /// A receipt-backed fixture prefix: copies the three built BPF
    /// objects under `<prefix>/lib/osslscope/` and writes an honest
    /// install manifest, returning the object dir. Mirrors what
    /// `scripts/install-dev.sh` lays down.
    fn f11_prefix(test: &str) -> Option<PathBuf> {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("crates/ebpf/target/bpfel-unknown-none/release");
        let h = dir.join("osslscope-harvest");
        let c = dir.join("osslscope-count");
        let m = dir.join("osslscope-members");
        if !(h.exists() && c.exists() && m.exists()) {
            return None;
        }
        let n = F11_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let prefix = std::env::temp_dir().join(format!(
            "osslscope-f11-{}-{}-{}",
            std::process::id(),
            test,
            n
        ));
        let objdir = prefix.join("lib").join("osslscope");
        std::fs::create_dir_all(&objdir).unwrap();
        let dsts = [
            (objdir.join("osslscope-harvest"), &h),
            (objdir.join("osslscope-count"), &c),
            (objdir.join("osslscope-members"), &m),
        ];
        let mut arts = Vec::new();
        for (dst, src) in &dsts {
            std::fs::copy(src, dst).unwrap();
            let sha = onboard::file_sha256_hex(dst).unwrap();
            arts.push(serde_json::json!({
                "role": "bpf-object",
                "dest": dst.to_string_lossy(),
                "sha256": sha,
            }));
        }
        let rdir = prefix.join("share").join("osslscope");
        std::fs::create_dir_all(&rdir).unwrap();
        let manifest = serde_json::json!({
            "schema": "osslscope-install-manifest-v1",
            "artifacts": arts,
        });
        std::fs::write(
            rdir.join(onboard::INSTALL_RECEIPT_NAME),
            serde_json::to_string(&manifest).unwrap(),
        )
        .unwrap();
        Some(objdir)
    }

    fn f11_trust() -> onboard::TrustPolicy {
        onboard::TrustPolicy {
            // SAFETY: getuid takes no arguments and always succeeds.
            trusted_uids: vec![unsafe { libc::getuid() }],
            check_ancestry: false,
        }
    }

    #[test]
    fn fix2_triple_snapshot_binds_one_read() {
        // F11: the snapshot binds ONE read per role to identity —
        // provenance hashes equal the loaded bytes' hashes, so the
        // reported identity IS the loaded bytes (no reread drift).
        let Some(objdir) = f11_prefix("bind") else {
            return;
        };
        let trust = f11_trust();
        let run = onboard::resolve_run_set(None, None, None, std::slice::from_ref(&objdir), &trust)
            .expect("fixture triple resolves");
        let onboard::RunSet::Triple(set) = run.0 else {
            panic!("receipt-backed prefix must resolve a triple");
        };
        let (prov, bytes) = triple_snapshot(&set).expect("snapshot binds");
        use sha2::Digest as _;
        for (p, b) in [
            (&prov.harvest, &bytes.harvest),
            (&prov.count, &bytes.count),
            (&prov.members, &bytes.members),
        ] {
            let hex: String = sha2::Sha256::digest(b)
                .iter()
                .map(|x| format!("{x:02x}"))
                .collect();
            assert_eq!(p.sha256, hex, "provenance must hash the loaded bytes");
            assert!(!b.is_empty(), "snapshot must carry every role's bytes");
        }
    }

    #[test]
    fn fix2_triple_snapshot_stale_swap_refuses() {
        // F11: a role file swapped after resolve (stale bytes under
        // a live identity) refuses at snapshot time — the snapshot
        // re-verifies implicit roles against the receipt instead of
        // trusting the resolve-time read.
        let Some(objdir) = f11_prefix("stale") else {
            return;
        };
        let trust = f11_trust();
        let run = onboard::resolve_run_set(None, None, None, std::slice::from_ref(&objdir), &trust)
            .expect("fixture triple resolves");
        let onboard::RunSet::Triple(set) = run.0 else {
            panic!("receipt-backed prefix must resolve a triple");
        };
        triple_snapshot(&set).expect("honest snapshot binds");
        // Swap the members file (same length, hostile bytes).
        let mpath = objdir.join("osslscope-members");
        let len = std::fs::metadata(&mpath).unwrap().len() as usize;
        std::fs::write(&mpath, vec![0x7Fu8; len]).unwrap();
        let err = triple_snapshot(&set).expect_err("swapped role must refuse");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("does not match") || msg.contains("receipt"),
            "stale swap must name the receipt binding: {msg}"
        );
    }

    #[test]
    fn build_id_cache_parses_once_per_identity() {
        // P6: one goblin parse per bound file per adapt call — the
        // uncached helpers re-parsed multi-MB files per candidate
        // AND per group (1658 parses ≈ 10s stalled one apply_delta,
        // landing count attach after the child exited). The parse
        // closure runs once per (path, dev, ino); absence (None)
        // caches too; distinct identities re-parse.
        use std::cell::Cell;
        let calls = Cell::new(0u32);
        let mut cache: BuildIdCache = HashMap::new();
        let r1 = cached_build_id(&mut cache, "/lib/x.so", 8, 100, || {
            calls.set(calls.get() + 1);
            Some("aa".to_string())
        });
        let r2 = cached_build_id(&mut cache, "/lib/x.so", 8, 100, || {
            calls.set(calls.get() + 1);
            Some("bb".to_string())
        });
        assert_eq!(r1, Some("aa".to_string()));
        assert_eq!(
            r2,
            Some("aa".to_string()),
            "second resolve must hit the cache"
        );
        assert_eq!(calls.get(), 1, "same identity parses once");
        let r3 = cached_build_id(&mut cache, "/lib/y.so", 8, 101, || {
            calls.set(calls.get() + 1);
            Some("cc".to_string())
        });
        assert_eq!(r3, Some("cc".to_string()));
        assert_eq!(calls.get(), 2, "distinct identity re-parses");
        let r4: Option<String> = cached_build_id(&mut cache, "/lib/z.so", 8, 102, || {
            calls.set(calls.get() + 1);
            None
        });
        let r5: Option<String> = cached_build_id(&mut cache, "/lib/z.so", 8, 102, || {
            calls.set(calls.get() + 1);
            Some("zz".to_string())
        });
        assert_eq!((r4, r5), (None, None), "absence caches too");
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn ppid_parse_tricky_comm() {
        // comm with spaces + parens: fields start after LAST ')'.
        assert_eq!(
            parse_stat_ppid("4242 (my (weird) proc) R 777 0 0"),
            Some((4242, 777))
        );
        assert_eq!(parse_stat_ppid("1 (systemd) S 0 0"), Some((1, 0)));
        assert!(parse_stat_ppid("garbage").is_none());
        assert!(parse_stat_ppid("9 (x) S").is_none());
    }

    // ------------------------------------------------------------------
    // R20-fix finding 1: kernel-lifecycle ingest mapping (synthetic
    // datagrams — deterministic, no kernel needed).
    // ------------------------------------------------------------------

    /// One connector datagram: nlmsghdr (type 3, like the kernel
    /// marks event datagrams) + cn_msg + `payload`.
    fn cn_datagram(payload: &[u8]) -> Vec<u8> {
        cn_datagram_seq(payload, 0, 0)
    }

    /// One connector datagram with explicit cn_msg seq/ack (R20-fix
    /// round 2, F2: per-CPU sequence continuity + ack correlation).
    fn cn_datagram_seq(payload: &[u8], seq: u32, ack: u32) -> Vec<u8> {
        let mut b = Vec::new();
        let total = (NLMSG_HDRLEN + CN_HDRLEN + payload.len()) as u32;
        b.extend_from_slice(&total.to_le_bytes());
        b.extend_from_slice(&3u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&CN_IDX_PROC.to_le_bytes());
        b.extend_from_slice(&CN_VAL_PROC.to_le_bytes());
        b.extend_from_slice(&seq.to_le_bytes());
        b.extend_from_slice(&ack.to_le_bytes());
        b.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(payload);
        b
    }

    /// One `proc_event`: what/cpu/timestamp + u32 union fields.
    fn proc_event(what: u32, fields: &[u32]) -> Vec<u8> {
        proc_event_cpu(what, 0, fields)
    }

    /// One `proc_event` on an explicit CPU (F2 continuity).
    fn proc_event_cpu(what: u32, cpu: u32, fields: &[u32]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&what.to_le_bytes());
        b.extend_from_slice(&cpu.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        for f in fields {
            b.extend_from_slice(&f.to_le_bytes());
        }
        b
    }

    /// Concatenate single-message datagrams into one multi-message
    /// datagram (netlink alignment: every part length is a multiple
    /// of 4 for even field counts — enforced here).
    fn multi_datagram(parts: &[Vec<u8>]) -> Vec<u8> {
        for p in parts {
            assert_eq!(p.len() % 4, 0, "part must be nlmsg-aligned");
        }
        parts.concat()
    }

    /// Ingest fixture: a `KernelLifecycle` with scripted identity
    /// state and a stand-in fd (ingest never touches the socket).
    /// `released` selects the continuity regime under test:
    /// pre-release first sightings baseline silently (stopped
    /// target — predecessors provably non-target), post-release
    /// they gap their prefix explicitly.
    fn ingest_fixture(known: HashSet<u32>, seqs: SeqState, released: bool) -> KernelLifecycle {
        use std::os::fd::FromRawFd as _;
        let fd = unsafe { OwnedFd::from_raw_fd(libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY)) };
        assert!(fd.as_raw_fd() >= 0, "/dev/null must open");
        KernelLifecycle {
            fd,
            sock_inode: 0,
            target_pid: 100,
            target_tgid: 100,
            known,
            seqs,
            drops_baseline: None,
            mcast_ack: TEST_OUR_ACK.wrapping_sub(1),
            wait_enobufs: false,
            subscribed_ns: 0,
            dead: false,
            released,
            pending_delta: LifecycleDelta::default(),
            last_watermark: None,
            watermark_cpus: Vec::new(),
            subscribe_shortfall: false,
        }
    }

    fn fresh_ingest(known: &mut HashSet<u32>, buf: &[u8]) -> LifecycleDelta {
        // Fresh continuity state per call (each crafted datagram is
        // its own first sighting — continuity ACROSS datagrams is
        // production state, covered by multi-message datagrams here).
        fresh_ingest_as(known, buf, false)
    }

    fn fresh_ingest_as(known: &mut HashSet<u32>, buf: &[u8], released: bool) -> LifecycleDelta {
        // ManuallyDrop: the fixture never subscribed, so Drop's
        // balancing IGNORE must not run (its send would fail loud
        // on the stand-in fd); the fd closes explicitly instead.
        let mut lc = std::mem::ManuallyDrop::new(ingest_fixture(
            std::mem::take(known),
            SeqState::default(),
            released,
        ));
        let mut delta = LifecycleDelta::default();
        lc.ingest_datagram(buf, &mut delta, None);
        *known = std::mem::take(&mut lc.known);
        unsafe { libc::close(lc.fd.as_raw_fd()) };
        delta
    }

    #[test]
    fn kernel_ingest_maps_subtree_fork_exec_exit() {
        let mut known = HashSet::from([100u32]);
        // Target forks a process child: event + tracked.
        let d = fresh_ingest(
            &mut known,
            &cn_datagram(&proc_event(PROC_EVENT_FORK, &[100, 100, 200, 200])),
        );
        assert_eq!(
            d.events,
            vec![LifecycleEvent {
                kind: LifecycleKind::Fork,
                pid: 200
            }]
        );
        assert!(known.contains(&200));
        // Same-tgid clone: thread creation, non-event.
        let d = fresh_ingest(
            &mut known,
            &cn_datagram(&proc_event(PROC_EVENT_FORK, &[100, 100, 101, 100])),
        );
        assert!(d.events.is_empty() && d.loss == 0);
        // Grandchild by parentage (parent = known child).
        let d = fresh_ingest(
            &mut known,
            &cn_datagram(&proc_event(PROC_EVENT_FORK, &[200, 200, 300, 300])),
        );
        assert_eq!(d.events.len(), 1);
        assert_eq!(d.events[0].pid, 300);
        // Foreign fork: ignored.
        let d = fresh_ingest(
            &mut known,
            &cn_datagram(&proc_event(PROC_EVENT_FORK, &[900, 900, 901, 901])),
        );
        assert!(d.events.is_empty() && d.loss == 0);
        // Target exec: event under the target pid.
        let d = fresh_ingest(
            &mut known,
            &cn_datagram(&proc_event(PROC_EVENT_EXEC, &[100, 100])),
        );
        assert_eq!(
            d.events,
            vec![LifecycleEvent {
                kind: LifecycleKind::Exec,
                pid: 100
            }]
        );
        // Known-child exec: already ignored, non-event.
        let d = fresh_ingest(
            &mut known,
            &cn_datagram(&proc_event(PROC_EVENT_EXEC, &[200, 200])),
        );
        assert!(d.events.is_empty() && d.loss == 0);
        // Target exit: custody's verdict, non-event.
        let d = fresh_ingest(
            &mut known,
            &cn_datagram(&proc_event(PROC_EVENT_EXIT, &[100, 100, 0, 0, 1, 1])),
        );
        assert!(d.events.is_empty() && d.loss == 0);
        assert!(known.contains(&100));
        // Exits never prune: a thread exit (pid != tgid) must not
        // untrack the live group — the next grandchild fork still
        // witnesses.
        let d = fresh_ingest(
            &mut known,
            &cn_datagram(&proc_event(PROC_EVENT_EXIT, &[201, 200, 0, 0, 100, 100])),
        );
        assert!(d.events.is_empty() && d.loss == 0);
        assert!(known.contains(&200));
        let d = fresh_ingest(
            &mut known,
            &cn_datagram(&proc_event(PROC_EVENT_FORK, &[200, 200, 400, 400])),
        );
        assert_eq!(d.events.len(), 1);
        assert_eq!(d.events[0].pid, 400);
        // Whole-process exit: still no prune (an EXIT never proves
        // its group dead — polling `seen` parity).
        let d = fresh_ingest(
            &mut known,
            &cn_datagram(&proc_event(PROC_EVENT_EXIT, &[200, 200, 0, 0, 100, 100])),
        );
        assert!(d.events.is_empty() && d.loss == 0);
        assert!(known.contains(&200));
        // Unknown `what` (incl. the zero registration artifact):
        // creates no process, replaces no image — ignored.
        let d = fresh_ingest(
            &mut known,
            &cn_datagram(&proc_event(0, &[0, 0, 0, 0, 0, 0])),
        );
        assert!(d.events.is_empty() && d.loss == 0);
        let d = fresh_ingest(
            &mut known,
            &cn_datagram(&proc_event(0x200, &[100, 100, 0, 0, 0, 0])),
        );
        assert!(d.events.is_empty() && d.loss == 0);
    }

    #[test]
    fn kernel_ingest_truncation_is_loss_not_silence() {
        let mut known = HashSet::from([100u32]);
        // Truncated datagram (no full header).
        let d = fresh_ingest(&mut known, &[1u8; 7]);
        assert_eq!(d.loss, 1);
        // Declared length overruns the buffer.
        let mut bad = cn_datagram(&proc_event(PROC_EVENT_FORK, &[100, 100, 200, 200]));
        bad.truncate(bad.len() - 5);
        let d = fresh_ingest(&mut known, &bad);
        assert_eq!(d.loss, 1);
        // Truncated fork payload.
        let d = fresh_ingest(
            &mut known,
            &cn_datagram(&proc_event(PROC_EVENT_FORK, &[100])),
        );
        assert_eq!(d.loss, 1);
        assert!(d.events.is_empty());
        // Foreign cn index: stray, ignored (loss would misattribute
        // another subsystem's traffic on a shared socket).
        let mut stray = cn_datagram(&proc_event(PROC_EVENT_FORK, &[100, 100, 200, 200]));
        stray[NLMSG_HDRLEN..NLMSG_HDRLEN + 4].copy_from_slice(&7u32.to_le_bytes());
        let d = fresh_ingest(&mut known, &stray);
        assert!(d.events.is_empty() && d.loss == 0);
    }

    // ------------------------------------------------------------------
    // R20-fix round 2, F2: subscription acceptance + (seq, cpu)
    // continuity. RED tests (fail on FIX_BASE behavior — the decoder
    // ignores NONE acks and per-CPU sequence entirely).
    // ------------------------------------------------------------------

    /// Correlated ack for crafted NONE messages (unit-test stand-in
    /// for the pid+1 the kernel echoes back to our LISTEN).
    const TEST_OUR_ACK: u32 = 4243;

    #[test]
    fn kernel_none_ack_error_is_loss_not_silence() {
        // A connector acknowledgement carrying a nonzero error is a
        // kernel-reported registration/operation failure — failing
        // closed (scan loss), never silently ignored.
        let mut known = HashSet::from([100u32]);
        let d = fresh_ingest(
            &mut known,
            &cn_datagram_seq(&proc_event_cpu(0, 0, &[12, 0, 0, 0]), 9, TEST_OUR_ACK),
        );
        assert!(d.events.is_empty());
        assert_eq!(d.loss, 1, "NONE ack err=12 must taint observation");
    }

    #[test]
    fn kernel_percpu_seq_gap_counts_dropped() {
        // Per-CPU cn_msg seq is gapless per sender (kernel send_msg);
        // a hole is signals never received (pre-delivery allocation
        // failure or socket overrun) — kernel-side drops, exact count.
        let mut known = HashSet::from([100u32]);
        let buf = multi_datagram(&[
            cn_datagram_seq(
                &proc_event_cpu(PROC_EVENT_FORK, 0, &[100, 100, 200, 200]),
                5,
                0,
            ),
            cn_datagram_seq(
                &proc_event_cpu(PROC_EVENT_FORK, 0, &[100, 100, 201, 201]),
                7,
                0,
            ),
        ]);
        let d = fresh_ingest(&mut known, &buf);
        assert_eq!(d.events.len(), 2);
        assert_eq!(d.loss, 0);
        assert_eq!(d.dropped, 1, "seq 5→7 on cpu0 misses exactly one signal");
        assert_eq!(d.prefix_unwitnessed, 0);
    }

    #[test]
    fn kernel_percpu_seq_duplicate_and_backward_are_loss() {
        // A repeated or backward per-CPU seq is a corrupt stream
        // (the kernel counter strictly increases) — fail closed.
        let mut known = HashSet::from([100u32]);
        let dupe = multi_datagram(&[
            cn_datagram_seq(
                &proc_event_cpu(PROC_EVENT_FORK, 0, &[100, 100, 200, 200]),
                5,
                0,
            ),
            cn_datagram_seq(
                &proc_event_cpu(PROC_EVENT_FORK, 0, &[100, 100, 201, 201]),
                5,
                0,
            ),
        ]);
        assert_eq!(fresh_ingest(&mut known, &dupe).loss, 1);
        let back = multi_datagram(&[
            cn_datagram_seq(
                &proc_event_cpu(PROC_EVENT_FORK, 0, &[100, 100, 200, 200]),
                7,
                0,
            ),
            cn_datagram_seq(
                &proc_event_cpu(PROC_EVENT_FORK, 0, &[100, 100, 201, 201]),
                5,
                0,
            ),
        ]);
        assert_eq!(fresh_ingest(&mut known, &back).loss, 1);
    }

    #[test]
    fn kernel_percpu_seq_first_seen_baselines_silently() {
        // GUARD (pins no-false-positive for the PRE-RELEASE regime):
        // first sightings per CPU baseline silently while the
        // target provably cannot emit (stopped at subscribe —
        // predecessors are non-target signals, never a lost fork).
        // Post-release first sightings gap instead (see
        // `kernel_seq_first_seen_post_release_gaps_prefix`).
        let mut known = HashSet::from([100u32]);
        let buf = multi_datagram(&[
            cn_datagram_seq(
                &proc_event_cpu(PROC_EVENT_FORK, 0, &[100, 100, 200, 200]),
                900,
                0,
            ),
            cn_datagram_seq(
                &proc_event_cpu(PROC_EVENT_FORK, 1, &[100, 100, 201, 201]),
                5,
                0,
            ),
        ]);
        let d = fresh_ingest(&mut known, &buf);
        assert_eq!(d.events.len(), 2);
        assert_eq!(d.dropped, 0);
        assert_eq!(d.prefix_unwitnessed, 0);
        assert_eq!(d.loss, 0);
    }

    #[test]
    fn kernel_seq_first_seen_post_release_gaps_prefix() {
        // F2: a CPU's first received sequence must not silently
        // establish its baseline once activity is possible — a
        // fork lost before that first message (pre-delivery
        // allocation failure leaves no Drops trace) would stay
        // invisible. Post-release first sightings record an
        // explicit prefix gap (kernel-side-missing, at-least-one).
        // (RED shape: `observe` took no release flag and the
        // baseline was always silent — dropped stayed 0.)
        let mut seqs = SeqState::default();
        let mut delta = LifecycleDelta::default();
        seqs.observe(0, 900, &mut delta, true);
        assert_eq!(delta.dropped, 0);
        assert_eq!(
            delta.prefix_unwitnessed, 1,
            "post-activity first sighting must gap its unwitnessed prefix"
        );
        // ...and the stream still baselines (no compounding: the
        // next in-order message is clean).
        let mut delta2 = LifecycleDelta::default();
        seqs.observe(0, 901, &mut delta2, true);
        assert_eq!(delta2.dropped, 0);
        assert_eq!(delta2.prefix_unwitnessed, 0);
        assert_eq!(delta2.loss, 0);
        // Pre-release first sightings stay silent (stopped target:
        // predecessors provably non-target).
        let mut seqs_pre = SeqState::default();
        let mut delta_pre = LifecycleDelta::default();
        seqs_pre.observe(0, 900, &mut delta_pre, false);
        assert_eq!(delta_pre.dropped, 0);
        assert_eq!(delta_pre.prefix_unwitnessed, 0);
        assert_eq!(delta_pre.loss, 0);
    }

    #[test]
    fn kernel_seq_first_seen_prefix_is_conservative_not_proven() {
        // v0.2 gap-accept 2/14: post-activity first sightings gap
        // the unwitnessed prefix WITHOUT claiming a proven
        // transport drop.
        let mut seqs = SeqState::default();
        let mut delta = LifecycleDelta::default();
        seqs.observe(0, 900, &mut delta, true);
        assert_eq!(delta.dropped, 0, "prefix gap is not a proven drop");
        assert_eq!(
            delta.prefix_unwitnessed, 1,
            "prefix gap records conservatively"
        );
    }

    #[test]
    fn kernel_ingest_post_release_first_seen_gaps() {
        // F2 ingest level: the release flag threads from the
        // lifecycle (`mark_released`) into continuity — a crafted
        // first-sighting datagram gaps post-release, baselines
        // pre-release.
        let mut known = HashSet::from([100u32]);
        let buf = cn_datagram_seq(
            &proc_event_cpu(PROC_EVENT_FORK, 0, &[100, 100, 200, 200]),
            900,
            0,
        );
        let d = fresh_ingest_as(&mut known, &buf, true);
        assert_eq!(d.events.len(), 1, "witness still maps to its event");
        assert_eq!(d.dropped, 0, "post-release first sighting must gap");
        assert_eq!(
            d.prefix_unwitnessed, 1,
            "post-release first sighting must gap"
        );
        let mut known_pre = HashSet::from([100u32]);
        let d_pre = fresh_ingest_as(&mut known_pre, &buf, false);
        assert_eq!(d_pre.events.len(), 1);
        assert_eq!(d_pre.dropped, 0, "pre-release baseline stays silent");
        assert_eq!(d_pre.prefix_unwitnessed, 0);
    }

    #[test]
    fn kernel_acceptance_wait_times_out_without_ack() {
        // MINOR-B: a TRUE acceptance-wait timeout control — the
        // wait path itself (poll loop plus timeout accounting),
        // not just ack parsing. A connected socket that never
        // delivers our ack must fail the wait at the bound.
        // (New-surface control: the timeout parameter is new; the
        // base 2s wait already timed out correctly — the gap was
        // coverage, so GREEN-on-base behavior is expected.)
        use std::os::fd::FromRawFd as _;
        let mut fds = [0 as libc::c_int; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) },
            0,
            "socketpair must succeed"
        );
        let fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let peer = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        let t0 = Instant::now();
        let err =
            KernelLifecycle::await_acceptance_timeout(&fd, 0xA11CE, Duration::from_millis(100))
                .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not acknowledged"),
            "timeout must name itself: {msg}"
        );
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "the wait must be bounded"
        );
        drop(peer);
        drop(fd);
    }

    #[test]
    fn kernel_sync_watch_marks_fork_or_exit() {
        // F2: either watermark message (its child's FORK or EXIT)
        // marks the RECEIVED event's CPU witnessed (round 4: the
        // helper's intended CPU is never credited — migration
        // matrix below); foreign pids never mark.
        let mut w = SyncWatch::new(&[(11, 0), (22, 1)]);
        assert!(!w.complete());
        w.note(999, 0);
        assert!(!w.complete());
        assert_eq!(w.seen_count(), 0);
        // Migrated FORK: pid 11's message arrives on lane 1 — lane
        // 1 (genuinely advanced) marks, lane 0 stays unwitnessed.
        w.note(11, 1);
        assert_eq!(w.seen_count(), 1);
        assert!(!w.complete());
        // A message on a non-required lane marks nothing.
        w.note(11, 7);
        assert_eq!(w.seen_count(), 1);
        assert!(!w.complete());
        // Home-lane message completes the remaining lane.
        w.note(11, 0);
        assert!(w.complete());
        assert_eq!((w.sought_count(), w.seen_count()), (2, 2));
    }

    #[test]
    fn kernel_migrated_sync_exit_must_not_complete_intended_lane() {
        // R20-fix round 4, F2b RED (fails on FIX_BASE — the watch
        // credits the helper's intended CPU from its pid without
        // checking the received event's CPU): a sync helper pinned
        // for CPU 0 whose EXIT arrives on CPU 1 (migrated — the
        // kernel migrates tasks off a CPU going offline) must NOT
        // complete lane 0's watermark. Forged EXIT ingested through
        // the production `ingest_datagram` + watch path.
        let mut lc = std::mem::ManuallyDrop::new(ingest_fixture(
            HashSet::from([100u32]),
            SeqState::default(),
            false,
        ));
        let mut watch = SyncWatch::new(&[(11, 0)]);
        let mut delta = LifecycleDelta::default();
        // EXIT of CPU-0's helper (pid 11) arriving on CPU 1.
        let migrated = cn_datagram_seq(
            &proc_event_cpu(PROC_EVENT_EXIT, 1, &[11, 11, 0, 0, 0, 0]),
            7,
            0,
        );
        lc.ingest_datagram(&migrated, &mut delta, Some(&mut watch));
        assert_eq!(delta.loss, 0, "well-formed EXIT is not scan loss");
        assert!(
            !watch.complete(),
            "a migrated helper EXIT must not complete its intended lane"
        );
        assert_eq!(
            watch.seen_count(),
            0,
            "no required lane witnessed yet: sought={} seen={}",
            watch.sought_count(),
            watch.seen_count()
        );
        // Positive control (passes pre+post): the same EXIT arriving
        // on its intended lane completes the watermark.
        let home = cn_datagram_seq(
            &proc_event_cpu(PROC_EVENT_EXIT, 0, &[11, 11, 0, 0, 0, 0]),
            8,
            0,
        );
        lc.ingest_datagram(&home, &mut delta, Some(&mut watch));
        assert!(watch.complete(), "home-lane EXIT must mark its lane");
        unsafe { libc::close(lc.fd.as_raw_fd()) };
    }

    #[test]
    fn kernel_close_cpu_plan_preserves_offlined_lanes() {
        // R20-fix round 4, F2a RED (new-surface — `plan_close_cpus`
        // does not exist on FIX_BASE): close must preserve the
        // subscribe-time required lane set, not rebuild it from the
        // current online count — a previously active CPU that went
        // offline keeps its required lane (gapped explicitly, never
        // silently dropped), and newly-online CPUs join the burst.
        let stable = plan_close_cpus(&[0, 1, 2, 3], &[0, 1, 2, 3]);
        assert_eq!(stable.required, vec![0, 1, 2, 3]);
        assert!(stable.offlined.is_empty());
        assert_eq!(stable.burst, vec![0, 1, 2, 3]);
        let offlined = plan_close_cpus(&[0, 1, 2, 3], &[0, 1, 2]);
        assert_eq!(
            offlined.required,
            vec![0, 1, 2, 3],
            "the required lane set survives the offlining"
        );
        assert_eq!(offlined.offlined, vec![3]);
        assert_eq!(
            offlined.burst,
            vec![0, 1, 2],
            "the burst covers closable lanes; the offlined lane gaps explicitly"
        );
        let grown = plan_close_cpus(&[0, 1], &[0, 1, 2]);
        assert_eq!(grown.required, vec![0, 1, 2]);
        assert!(grown.offlined.is_empty());
        assert_eq!(grown.burst, vec![0, 1, 2]);
    }

    #[test]
    fn kernel_close_cpu_plan_reads_subscribe_time_set() {
        // F2a wiring: the plan is built from the subscription's
        // stored lane set (`watermark_cpus`), not from a fresh
        // online count — a forged offlined lane (present at
        // subscribe, absent now) must surface in the plan.
        let mut lc = std::mem::ManuallyDrop::new(ingest_fixture(
            HashSet::from([100u32]),
            SeqState::default(),
            false,
        ));
        let mut stored = online_cpus();
        stored.push(u32::MAX);
        stored.sort_unstable();
        lc.watermark_cpus = stored.clone();
        let plan = lc.close_cpu_plan();
        assert!(
            plan.required.contains(&u32::MAX),
            "required set must preserve the subscribe-time lane: {:?}",
            plan.required
        );
        assert_eq!(plan.offlined, vec![u32::MAX]);
        assert!(
            !plan.burst.contains(&u32::MAX),
            "an offlined lane is gapped, not burst: {:?}",
            plan.burst
        );
        unsafe { libc::close(lc.fd.as_raw_fd()) };
    }

    #[test]
    fn kernel_stopped_sync_helper_must_not_block_reap() {
        // R20-fix round 4, NEW-1: a watermark helper stopped before
        // `_exit` (SIGSTOP — its FORK receipt may already have been
        // awaited) must not block reaping indefinitely — the
        // bounded owner escalates to SIGKILL and reaps. (RED ran
        // against the BASE reaper on a thread with a bounded join:
        // `reap of a stopped helper must be bounded (blocked >3s)`
        // — the unbounded `waitpid(pid, …, 0)` never returned.
        // Same property, new API — the old fn is deleted.)
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork for stopped helper");
        if pid == 0 {
            unsafe {
                libc::raise(libc::SIGSTOP);
                libc::pause();
                libc::_exit(0);
            }
        }
        let pid_u = pid as u32;
        // Prove the fixture: the child is STOPPED (not exited).
        let stop_end = Instant::now() + Duration::from_secs(5);
        let stopped = loop {
            let mut status = 0;
            let r = unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED | libc::WNOHANG) };
            if r == pid && libc::WIFSTOPPED(status) {
                break true;
            }
            if Instant::now() >= stop_end {
                break false;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        assert!(stopped, "fixture child must reach the stopped state");
        // Short windows: grace must exhaust (the helper never
        // exits on its own) and SIGKILL escalation must collect
        // it — all promptly and with no zombie left behind.
        let t0 = Instant::now();
        reap_sync_children_grace(
            &[(pid_u, 0)],
            Duration::from_millis(100),
            Duration::from_millis(200),
        );
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "the reap must be bounded"
        );
        let mut status = 0;
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert!(
            r < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD),
            "the stopped helper must be killed and reaped (no zombie): r={r}"
        );
        assert!(
            std::fs::read_to_string(format!("/proc/{pid}/stat")).is_err(),
            "no /proc residue for the reaped helper"
        );
    }

    #[test]
    fn kernel_reap_collects_exited_helpers_promptly() {
        // NEW-1 positive control (passes pre+post by design — the
        // ordinary path): immediate-exit helpers reap on the first
        // sweep with no escalation and no residue.
        let mut pids = Vec::new();
        for _ in 0..4 {
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork for exited helper");
            if pid == 0 {
                unsafe { libc::_exit(0) };
            }
            pids.push((pid as u32, 0u32));
        }
        let t0 = Instant::now();
        reap_sync_children_grace(&pids, Duration::from_secs(2), Duration::from_secs(1));
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "exited helpers must reap promptly"
        );
        for (pid, _) in &pids {
            let mut status = 0;
            let r = unsafe { libc::waitpid(*pid as libc::pid_t, &mut status, libc::WNOHANG) };
            assert!(
                r < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD),
                "helper {pid} must be reaped: r={r}"
            );
        }
    }

    #[test]
    fn kernel_none_ack_success_stays_silent() {
        // GUARD (passes pre+post): a zero-error ack is the expected
        // subscription receipt — evidence, not loss.
        let mut known = HashSet::from([100u32]);
        let d = fresh_ingest(
            &mut known,
            &cn_datagram_seq(&proc_event_cpu(0, 0, &[0, 0, 0, 0]), 9, TEST_OUR_ACK),
        );
        assert!(d.events.is_empty());
        assert_eq!(d.dropped, 0);
        assert_eq!(d.prefix_unwitnessed, 0);
        assert_eq!(d.loss, 0);
    }

    /// Ingest sharing one continuity state across datagrams (the
    /// production shape — `fresh_ingest` baselines per call).
    fn seq_ingest(known: &mut HashSet<u32>, seqs: &mut SeqState, buf: &[u8]) -> LifecycleDelta {
        seq_ingest_as(known, seqs, buf, false)
    }

    fn seq_ingest_as(
        known: &mut HashSet<u32>,
        seqs: &mut SeqState,
        buf: &[u8],
        released: bool,
    ) -> LifecycleDelta {
        let mut lc = std::mem::ManuallyDrop::new(ingest_fixture(
            std::mem::take(known),
            std::mem::take(seqs),
            released,
        ));
        let mut delta = LifecycleDelta::default();
        lc.ingest_datagram(buf, &mut delta, None);
        *known = std::mem::take(&mut lc.known);
        *seqs = std::mem::take(&mut lc.seqs);
        unsafe { libc::close(lc.fd.as_raw_fd()) };
        delta
    }

    #[test]
    fn kernel_foreign_none_ack_err_is_not_ours() {
        // Another subscriber's failed LISTEN rides our shared group
        // (continuity-tracked — it consumed a kernel seq) but its
        // verdict must not taint OUR window.
        let mut known = HashSet::from([100u32]);
        let buf = multi_datagram(&[
            cn_datagram_seq(&proc_event_cpu(0, 0, &[12, 0, 0, 0]), 9, 7),
            cn_datagram_seq(
                &proc_event_cpu(PROC_EVENT_FORK, 0, &[100, 100, 200, 200]),
                10,
                0,
            ),
        ]);
        let d = fresh_ingest(&mut known, &buf);
        assert_eq!(d.events.len(), 1);
        assert_eq!(d.dropped, 0, "foreign ack consumes seq 9 — no gap");
        assert_eq!(d.prefix_unwitnessed, 0);
        assert_eq!(d.loss, 0, "foreign verdict is not our loss");
    }

    #[test]
    fn kernel_seq_continuity_spans_datagrams() {
        // Production drains several datagrams per poll through one
        // persistent state — a hole across the boundary counts.
        let mut known = HashSet::from([100u32]);
        let mut seqs = SeqState::default();
        let d1 = seq_ingest(
            &mut known,
            &mut seqs,
            &cn_datagram_seq(
                &proc_event_cpu(PROC_EVENT_FORK, 0, &[100, 100, 200, 200]),
                5,
                0,
            ),
        );
        assert_eq!(d1.dropped, 0);
        assert_eq!(d1.prefix_unwitnessed, 0);
        assert_eq!(d1.loss, 0);
        let d2 = seq_ingest(
            &mut known,
            &mut seqs,
            &cn_datagram_seq(
                &proc_event_cpu(PROC_EVENT_FORK, 0, &[100, 100, 201, 201]),
                7,
                0,
            ),
        );
        assert_eq!(d2.dropped, 1);
        assert_eq!(d2.prefix_unwitnessed, 0);
        assert_eq!(d2.loss, 0);
        // And the stream resyncs (no compounding).
        let d3 = seq_ingest(
            &mut known,
            &mut seqs,
            &cn_datagram_seq(
                &proc_event_cpu(PROC_EVENT_FORK, 0, &[100, 100, 202, 202]),
                8,
                0,
            ),
        );
        assert_eq!(d3.dropped, 0);
        assert_eq!(d3.prefix_unwitnessed, 0);
        assert_eq!(d3.loss, 0);
    }

    #[test]
    fn kernel_mcast_msg_bytes_are_exact() {
        // LISTEN / IGNORE wire shape: nlmsghdr + cn_msg + bare op.
        let pid = std::process::id();
        let listen = mcast_msg(PROC_CN_MCAST_LISTEN, pid);
        assert_eq!(listen.len(), NLMSG_HDRLEN + CN_HDRLEN + 4);
        assert_eq!(u32::from_le_bytes(listen[0..4].try_into().unwrap()), 40);
        assert_eq!(u32::from_le_bytes(listen[12..16].try_into().unwrap()), pid);
        assert_eq!(
            u32::from_le_bytes(listen[16..20].try_into().unwrap()),
            CN_IDX_PROC
        );
        assert_eq!(
            u32::from_le_bytes(listen[20..24].try_into().unwrap()),
            CN_VAL_PROC
        );
        assert_eq!(u32::from_le_bytes(listen[24..28].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(listen[28..32].try_into().unwrap()), pid);
        assert_eq!(u16::from_le_bytes(listen[32..34].try_into().unwrap()), 4);
        assert_eq!(
            u32::from_le_bytes(listen[36..40].try_into().unwrap()),
            PROC_CN_MCAST_LISTEN
        );
        let ignore = mcast_msg(PROC_CN_MCAST_IGNORE, pid);
        assert_eq!(
            u32::from_le_bytes(ignore[36..40].try_into().unwrap()),
            PROC_CN_MCAST_IGNORE
        );
        assert_eq!(PROC_CN_MCAST_IGNORE, 2, "uapi op (0 would be EINVAL)");
    }

    #[test]
    fn kernel_scan_ack_finds_ours_and_rejects() {
        let ours_ok = cn_datagram_seq(&proc_event_cpu(0, 0, &[0, 0, 0, 0]), 9, TEST_OUR_ACK);
        assert!(matches!(scan_ack(&ours_ok, TEST_OUR_ACK), AckScan::Ours(0)));
        let ours_err = cn_datagram_seq(&proc_event_cpu(0, 0, &[12, 0, 0, 0]), 9, TEST_OUR_ACK);
        assert!(matches!(
            scan_ack(&ours_err, TEST_OUR_ACK),
            AckScan::Ours(12)
        ));
        // Foreign ack (another subscriber): not ours.
        let foreign = cn_datagram_seq(&proc_event_cpu(0, 0, &[0, 0, 0, 0]), 9, 7);
        assert!(matches!(scan_ack(&foreign, TEST_OUR_ACK), AckScan::Absent));
        // Plain event: not an ack.
        let ev = cn_datagram(&proc_event(PROC_EVENT_FORK, &[100, 100, 200, 200]));
        assert!(matches!(scan_ack(&ev, TEST_OUR_ACK), AckScan::Absent));
        // Bundled with an event: still found.
        let bundled = multi_datagram(&[ev, ours_ok]);
        assert!(matches!(scan_ack(&bundled, TEST_OUR_ACK), AckScan::Ours(0)));
        // Transport rejection wins.
        let mut err = Vec::new();
        err.extend_from_slice(&20u32.to_le_bytes());
        err.extend_from_slice(&NLMSG_ERROR.to_le_bytes());
        err.extend_from_slice(&0u16.to_le_bytes());
        err.extend_from_slice(&0u32.to_le_bytes());
        err.extend_from_slice(&0u32.to_le_bytes());
        err.extend_from_slice(&(-5i32).to_le_bytes());
        assert!(matches!(
            scan_ack(&err, TEST_OUR_ACK),
            AckScan::TransportError(-5)
        ));
        // Truncated input: unproven, never accepted.
        assert!(matches!(scan_ack(&[1u8; 7], TEST_OUR_ACK), AckScan::Absent));
    }

    #[test]
    fn kernel_same_process_ack_must_not_cross_satisfy() {
        // NEW-ACK: distinct operation tokens per subscription, so a
        // cooperating socket's success ack cannot satisfy another
        // subscription's acceptance wait. B's wait scans for its
        // own token; A's ack bytes must NOT match it. (`scan_ack`
        // is the exact predicate `await_acceptance` loops on, so
        // this is the wait's cross-talk control. RED shape: both
        // tokens were the shared process-ID token, and the scan
        // found `Ours` — cross-satisfied.)
        let token_a = next_ack_token().wrapping_add(1);
        let token_b = next_ack_token().wrapping_add(1);
        assert_ne!(token_a, token_b, "tokens must be distinct");
        let ack_a = cn_datagram_seq(&proc_event_cpu(0, 0, &[0, 0, 0, 0]), 9, token_a);
        assert!(
            matches!(scan_ack(&ack_a, token_b), AckScan::Absent),
            "B's wait must ignore A's ack (same-process cross-talk)"
        );
        assert!(
            matches!(scan_ack(&ack_a, token_a), AckScan::Ours(0)),
            "A's own wait still matches A's ack"
        );
    }

    #[test]
    fn kernel_concurrent_subscribes_use_distinct_tokens() {
        // NEW-ACK RED (live): two concurrent same-process
        // subscriptions must hold distinct operation tokens (one
        // shared process-ID token lets either wait consume the
        // other's ack).
        if std::env::var("OSSLSCOPE_CONNECTOR_TEST").as_deref() == Ok("force-absent") {
            eprintln!("SKIP ack-token half: forced-absent facility gate");
            return;
        }
        let require = std::env::var("OSSLSCOPE_REQUIRE_CONNECTOR").as_deref() == Ok("1");
        let a = match KernelLifecycle::subscribe(std::process::id(), true) {
            Ok(a) => a,
            Err(_) if !require => {
                eprintln!("SKIP ack-token half: connector unavailable");
                return;
            }
            Err(e) => panic!("subscribe A failed when required: {e:#}"),
        };
        let b = match KernelLifecycle::subscribe(std::process::id(), true) {
            Ok(b) => b,
            Err(_) if !require => {
                eprintln!("SKIP ack-token half: connector unavailable");
                return;
            }
            Err(e) => panic!("subscribe B failed when required: {e:#}"),
        };
        assert_ne!(
            a.mcast_ack, b.mcast_ack,
            "concurrent same-process subscriptions must not share one ACK token"
        );
    }

    #[test]
    fn kernel_drops_delta_folds_blindness() {
        assert_eq!(drops_delta(Some(10), Some(13)), (Some(13), 3, false));
        assert_eq!(drops_delta(Some(10), Some(10)), (Some(10), 0, false));
        assert_eq!(drops_delta(Some(10), None), (Some(10), 0, true));
        // Blind-then-readable re-anchors WITHOUT backfilling (the
        // blind interval is unknowable — its loss already fired).
        assert_eq!(drops_delta(None, Some(13)), (Some(13), 0, true));
        assert_eq!(drops_delta(None, None), (None, 0, true));
    }

    #[test]
    fn kernel_drops_parser_reads_own_row() {
        let text = "sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode\n\
             0000000000000000 0 111 00000440 0 0 0 2 0 100724\n\
             0000000000000000 11 222 00000001 0 0 0 2 812 673319\n";
        assert_eq!(parse_netlink_drops(text, 673319), Some(812));
        assert_eq!(parse_netlink_drops(text, 100724), Some(0));
        assert_eq!(parse_netlink_drops(text, 1), None);
        assert_eq!(parse_netlink_drops("sk Eth Pid Groups\n", 673319), None);
    }

    #[test]
    fn kernel_select_uses_signals_or_falls_back_loud() {
        // No such pid: tgid unreadable → explicit polling fallback
        // (deterministic contract — unconditional).
        let polled = LiveLifecycle::select(u32::MAX, true);
        assert!(matches!(polled, LiveLifecycle::Polling(_)));
        assert!(polled.fallback_partial());
        // Live self: kernel signals where the facility subscribes
        // (facility-gated — default suites pass where only the
        // fallback/PARTIAL shape is supported; REQUIRE forces the
        // live half in proving environments).
        if std::env::var("OSSLSCOPE_CONNECTOR_TEST").as_deref() == Ok("force-absent") {
            eprintln!("SKIP kernel half: forced-absent facility gate");
            return;
        }
        match LiveLifecycle::select(std::process::id(), true) {
            LiveLifecycle::Kernel(_) => {}
            LiveLifecycle::Polling(_) => {
                assert!(
                    std::env::var("OSSLSCOPE_REQUIRE_CONNECTOR").as_deref() != Ok("1"),
                    "select must use kernel signals when required"
                );
                eprintln!("SKIP kernel half: connector unavailable");
            }
        }
    }

    #[test]
    fn self_has_no_unexpected_parent_gap() {
        // Smoke: our own pid parses out of the live scan path.
        let me = std::process::id();
        let stat = std::fs::read_to_string(format!("/proc/{me}/stat")).unwrap();
        let (pid, _) = parse_stat_ppid(&stat).unwrap();
        assert_eq!(pid, me);
    }

    fn snap(
        exe: &str,
        maps: Vec<(&str, &str, u64, u64, bool)>,
        planned: Vec<(&str, &str, u64, Option<u64>)>,
    ) -> Snapshot {
        Snapshot {
            exe: Some(PathBuf::from(exe)),
            mapset: maps
                .into_iter()
                .map(|(p, d, i, o, x)| (p.to_string(), d.to_string(), i, o, x))
                .collect(),
            planned: planned
                .into_iter()
                .map(|(p, d, i, s)| (p.to_string(), (d.to_string(), i, s)))
                .collect(),
        }
    }

    #[test]
    fn fence_matrix() {
        let base = snap(
            "/bin/app",
            vec![("/lib/x.so", "08:01", 7, 0, true)],
            vec![("/lib/x.so", "08:01", 7, Some(99))],
        );
        // Identical: no fence.
        assert!(detect_fence(&base, &base).is_empty());
        // Mapping add: fence (dlopen).
        let added = snap(
            "/bin/app",
            vec![
                ("/lib/x.so", "08:01", 7, 0, true),
                ("/lib/y.so", "08:01", 8, 0, true),
            ],
            vec![("/lib/x.so", "08:01", 7, Some(99))],
        );
        assert_eq!(
            detect_fence(&base, &added),
            vec![FenceKind::MappingsChanged]
        );
        // Provider identity flip: fence + provider counter kind.
        let flipped = snap(
            "/bin/app",
            vec![("/lib/x.so", "08:01", 9, 0, true)],
            vec![("/lib/x.so", "08:01", 9, Some(99))],
        );
        let k = detect_fence(&base, &flipped);
        assert!(k.contains(&FenceKind::MappingsChanged));
        assert!(k.contains(&FenceKind::ProviderChanged));
        // Size-only change, same file: provider fence, no maps fence.
        let grown = snap(
            "/bin/app",
            vec![("/lib/x.so", "08:01", 7, 0, true)],
            vec![("/lib/x.so", "08:01", 7, Some(100))],
        );
        assert_eq!(
            detect_fence(&base, &grown),
            vec![FenceKind::ProviderChanged]
        );
        // Unreadable size: never a fence by itself.
        let unread = snap(
            "/bin/app",
            vec![("/lib/x.so", "08:01", 7, 0, true)],
            vec![("/lib/x.so", "08:01", 7, None)],
        );
        assert!(detect_fence(&base, &unread).is_empty());
        // Exec: fence.
        let execd = snap(
            "/bin/other",
            vec![("/lib/x.so", "08:01", 7, 0, true)],
            vec![("/lib/x.so", "08:01", 7, Some(99))],
        );
        assert_eq!(detect_fence(&base, &execd), vec![FenceKind::Exec]);
    }

    #[test]
    fn fips_caveat_triggers_on_configured_path_only() {
        // Operator-configured fips-shaped module (never a target
        // filename guess): stem match with .so/version tolerance.
        assert!(fips_configured(Path::new("/usr/lib/ossl-modules/fips.so")));
        assert!(fips_configured(Path::new("fips.so.3")));
        assert!(fips_configured(Path::new("/p/fips")));
        assert!(!fips_configured(Path::new("/usr/lib/libcrypto.so.3")));
        assert!(!fips_configured(Path::new("/p/default.so")));
        assert!(!fips_configured(Path::new("/p/FIPS.so")));
        assert!(!fips_configured(Path::new("/p/myfips.so")));
    }

    #[test]
    fn executions_sort_by_identity() {
        // PRD §6 byte-stability: (op, provider, alg, funcid) —
        // input order must not leak into output order.
        let mut v = vec![
            Execution {
                cookie: 1,
                id: plan::Identity {
                    provider: "default".into(),
                    op: 12,
                    funcid: 1,
                    alg_class: "RSA".into(),
                    offset: 0,
                },
                aliases: Vec::new(),
                count: 1,
                first_ns: 0,
                last_ns: 0,
            },
            Execution {
                cookie: 0,
                id: plan::Identity {
                    provider: "default".into(),
                    op: 1,
                    funcid: 1,
                    alg_class: "SHA256".into(),
                    offset: 0,
                },
                aliases: Vec::new(),
                count: 2,
                first_ns: 0,
                last_ns: 0,
            },
        ];
        sort_executions(&mut v);
        assert_eq!(v[0].id.op, 1);
        assert_eq!(v[1].id.op, 12);
        assert_eq!(v[0].cookie, 0);
    }

    #[test]
    fn container_id_parses_runtimes() {
        let id = "9".repeat(64);
        // Docker cgroupfs path segment.
        assert_eq!(
            parse_container_id(&format!("12:pids:/docker/{id}\n11:memory:/docker/{id}\n")),
            id
        );
        // K8s systemd scope (docker + crio runtimes).
        assert_eq!(
            parse_container_id(&format!(
                "0::/kubepods/burstable/podabc123/docker-{id}.scope\n"
            )),
            id
        );
        assert_eq!(
            parse_container_id(&format!(
                "0::/kubepods-besteffort.slice/kubepods-besteffort-poddef.slice/crio-{id}.scope\n"
            )),
            id
        );
        // Bare metal / user slice: no id.
        assert_eq!(parse_container_id("0::/user.slice/user-1000.slice\n"), "");
        assert_eq!(parse_container_id(""), "");
        // Short hex is not an id (64 required).
        assert_eq!(parse_container_id("0::/docker/abc123\n"), "");
    }

    #[test]
    fn kernel_release_nonempty() {
        assert!(!crate::doctor::uname_release().is_empty());
    }

    #[test]
    fn r12_unix_ns_converts_or_stays_unknown() {
        // R12: representable wall instants convert exactly;
        // pre-epoch instants are explicit unknown, never zero.
        let epoch = SystemTime::UNIX_EPOCH;
        assert_eq!(unix_ns(epoch), Some(0));
        let t = epoch + Duration::from_nanos(1_700_000_000_000_000_000);
        assert_eq!(unix_ns(t), Some(1_700_000_000_000_000_000));
        let pre = epoch - Duration::from_nanos(1);
        assert_eq!(unix_ns(pre), None);
    }

    #[test]
    fn r12_doc_context_carries_kernel_and_wall_pair() {
        // R12: the document context mirrors the already-captured
        // kernel release and wall edges verbatim — including a
        // backward-adjusted pair, which is legal context.
        let epoch = SystemTime::UNIX_EPOCH;
        let ctx = doc_context(
            "6.9.0-test",
            epoch + Duration::from_nanos(2_000),
            epoch + Duration::from_nanos(1_000),
        );
        assert_eq!(ctx.kernel_release, "6.9.0-test");
        assert_eq!(ctx.wall_start_unix_ns, Some(2_000));
        assert_eq!(ctx.wall_end_unix_ns, Some(1_000));
    }

    // ---------------------------------------------------------------- adapter

    fn backing(dev: &str, ino: u64, offset: u64) -> Option<BackingRef> {
        Some(BackingRef {
            dev: dev.to_string(),
            ino,
            offset,
        })
    }

    fn candidate(
        advertising: &str,
        backing: Option<BackingRef>,
        op: u32,
        funcid: u32,
        class: &str,
        weak: bool,
        status: &str,
    ) -> DiscoveredCandidate {
        DiscoveredCandidate {
            advertising: advertising.to_string(),
            advertising_dev: String::new(),
            advertising_ino: 0,
            backing,
            op,
            funcid,
            class: class.to_string(),
            weak,
            status: status.to_string(),
            epoch: 0,
            impl_addr: 0,
            arr: 0,
        }
    }

    fn terminated(op: u32, epoch: u64) -> TableCoverage {
        TableCoverage {
            op,
            epoch,
            state: CoverageState::Terminated { len: 4 },
            trunc_bits: 0,
        }
    }

    fn in_progress(op: u32, epoch: u64) -> TableCoverage {
        TableCoverage {
            op,
            epoch,
            state: CoverageState::InProgress { walked: 2 },
            trunc_bits: 0,
        }
    }

    fn ctx_for<'a>(
        live: &'a [maps::Mapping],
        files: &'a HashMap<String, plan::FileBytes>,
        fresh: &'a HashSet<(String, u64)>,
    ) -> AdapterCtx<'a> {
        AdapterCtx {
            live,
            files,
            pinned_provider: None,
            fresh,
            post_settle: false,
            post_release: false,
            baseline: false,
        }
    }

    fn adapt_fresh(delta: &DiscoveryDelta, live: &[maps::Mapping]) -> (AdapterState, AdaptedDelta) {
        let mut state = AdapterState::default();
        let files = HashMap::new();
        let fresh = HashSet::new();
        let adapted = adapt_delta(
            &mut state,
            delta,
            &AdapterCtx {
                live,
                files: &files,
                pinned_provider: None,
                fresh: &fresh,
                post_settle: false,
                post_release: false,
                baseline: false,
            },
        );
        (state, adapted)
    }

    #[test]
    fn adapt_accumulates_shared_site_sets() {
        // D1: two candidates sharing one backing triple (across two
        // polls) union into one complete replacement set — the later
        // poll must not clobber the earlier candidate.
        let live: Vec<maps::Mapping> = Vec::new();
        let files = HashMap::new();
        let fresh = HashSet::new();
        let mut state = AdapterState::default();
        let first = DiscoveryDelta {
            candidates: vec![candidate(
                "/p/provider.so",
                backing("08:01", 7, 0x100),
                1,
                11,
                "SHA-256",
                false,
                "ok",
            )],
            tables: vec![terminated(1, 0)],
            ..DiscoveryDelta::default()
        };
        let out = adapt_delta(&mut state, &first, &ctx_for(&live, &files, &fresh));
        assert_eq!(out.delta.discovered.len(), 1);
        assert_eq!(out.delta.discovered[0].candidates.len(), 1);
        assert_eq!(
            out.delta.discovered[0].candidates_coverage,
            CandidateCoverage::Complete
        );
        // Same triple, second op, later poll: union (2 candidates),
        // and the op-2 prefix keeps this emit Unknown.
        let second = DiscoveryDelta {
            candidates: vec![candidate(
                "/p/provider.so",
                backing("08:01", 7, 0x100),
                2,
                21,
                "SHA-512",
                true,
                "ok",
            )],
            tables: vec![in_progress(2, 0)],
            ..DiscoveryDelta::default()
        };
        let out = adapt_delta(&mut state, &second, &ctx_for(&live, &files, &fresh));
        assert_eq!(out.delta.discovered.len(), 1);
        let site = &out.delta.discovered[0];
        assert_eq!(site.candidates.len(), 2);
        assert!(site.candidates.iter().any(|c| c.weak_alias));
        assert_eq!(site.candidates_coverage, CandidateCoverage::Unknown);
        // Physical identity is the backing triple (never the path).
        let device = plan::device_id_of_dev_str("08:01").unwrap();
        assert_eq!(site.site.device, device);
        assert_eq!(site.site.inode, 7);
        assert_eq!(site.site.offset, 0x100);
    }

    #[test]
    fn adapt_late_arrival_after_termination_is_unknown() {
        // D3: an op that already terminated, then grows a new
        // candidate in a later poll, proves its set non-closed.
        let live: Vec<maps::Mapping> = Vec::new();
        let files = HashMap::new();
        let fresh = HashSet::new();
        let mut state = AdapterState::default();
        let proof = DiscoveryDelta {
            tables: vec![terminated(1, 0)],
            ..DiscoveryDelta::default()
        };
        let out = adapt_delta(&mut state, &proof, &ctx_for(&live, &files, &fresh));
        assert!(out.delta.discovered.is_empty());
        let late = DiscoveryDelta {
            candidates: vec![candidate(
                "/p/provider.so",
                backing("08:01", 7, 0x100),
                1,
                11,
                "SHA-256",
                false,
                "ok",
            )],
            ..DiscoveryDelta::default()
        };
        let out = adapt_delta(&mut state, &late, &ctx_for(&live, &files, &fresh));
        assert_eq!(
            out.delta.discovered[0].candidates_coverage,
            CandidateCoverage::Unknown
        );
    }

    #[test]
    fn adapt_retirement_reemits_unknown_without_recounting_loss() {
        // D2: retirement dirties the op and re-emits affected sites
        // as Unknown; the carried gap losses are NOT re-counted.
        let live: Vec<maps::Mapping> = Vec::new();
        let files = HashMap::new();
        let fresh = HashSet::new();
        let mut state = AdapterState::default();
        let first = DiscoveryDelta {
            candidates: vec![candidate(
                "/p/provider.so",
                backing("08:01", 7, 0x100),
                1,
                11,
                "SHA-256",
                false,
                "ok",
            )],
            tables: vec![terminated(1, 0)],
            ..DiscoveryDelta::default()
        };
        let out = adapt_delta(&mut state, &first, &ctx_for(&live, &files, &fresh));
        assert_eq!(
            out.delta.discovered[0].candidates_coverage,
            CandidateCoverage::Complete
        );
        let retire = DiscoveryDelta {
            retirements: vec![TableRetirement {
                op: 1,
                epoch: 0,
                gap: coverage::CoverageDelta {
                    reasons: vec!["prefix-walk".to_string()],
                    losses: vec![(1, 9)],
                },
            }],
            ..DiscoveryDelta::default()
        };
        let out = adapt_delta(&mut state, &retire, &ctx_for(&live, &files, &fresh));
        assert_eq!(out.delta.discovered.len(), 1);
        assert_eq!(
            out.delta.discovered[0].candidates_coverage,
            CandidateCoverage::Unknown
        );
        // No loss counters from the carried gap (the session emits
        // those through `losses`); one retirement activity row.
        assert!(out.delta.losses.is_empty());
        assert_eq!(out.activity.len(), 1);
        assert_eq!(out.activity[0].name, "discovery.table_retired");
    }

    #[test]
    fn adapt_orphan_loss_taints_same_op_site_set() {
        use crate::discovery::session::DiscoveryLoss;
        // A7: both ALG records arrive (table terminates) but one ROW
        // is lost — the orphan localizes to op 1, so the surviving
        // site's set degrades to Unknown (the missing identity could
        // be hers), exactly like a retirement re-emit.
        let live: Vec<maps::Mapping> = Vec::new();
        let files = HashMap::new();
        let fresh = HashSet::new();
        let mut state = AdapterState::default();
        let first = DiscoveryDelta {
            candidates: vec![candidate(
                "/p/provider.so",
                backing("08:01", 7, 0x100),
                1,
                11,
                "SHA-256",
                false,
                "ok",
            )],
            tables: vec![terminated(1, 0)],
            ..DiscoveryDelta::default()
        };
        let out = adapt_delta(&mut state, &first, &ctx_for(&live, &files, &fresh));
        assert_eq!(
            out.delta.discovered[0].candidates_coverage,
            CandidateCoverage::Complete
        );
        let orphan = DiscoveryDelta {
            losses: vec![DiscoveryLoss {
                source: coverage::HOST_ORPHAN_ROW,
                count: 1,
                op: Some(1),
            }],
            ..DiscoveryDelta::default()
        };
        let out = adapt_delta(&mut state, &orphan, &ctx_for(&live, &files, &fresh));
        assert_eq!(out.delta.discovered.len(), 1);
        assert_eq!(
            out.delta.discovered[0].candidates_coverage,
            CandidateCoverage::Unknown
        );
    }

    #[test]
    fn adapt_orphan_loss_same_delta_taints_emit() {
        use crate::discovery::session::DiscoveryLoss;
        // A7: loss in the SAME delta as the first emit taints it —
        // the site is never Complete even for one poll.
        let delta = DiscoveryDelta {
            candidates: vec![candidate(
                "/p/provider.so",
                backing("08:01", 7, 0x100),
                1,
                11,
                "SHA-256",
                false,
                "ok",
            )],
            tables: vec![terminated(1, 0)],
            losses: vec![DiscoveryLoss {
                source: coverage::HOST_ORPHAN_ROW,
                count: 1,
                op: Some(1),
            }],
            ..DiscoveryDelta::default()
        };
        let (_, out) = adapt_fresh(&delta, &[]);
        assert_eq!(out.delta.discovered.len(), 1);
        assert_eq!(
            out.delta.discovered[0].candidates_coverage,
            CandidateCoverage::Unknown
        );
    }

    #[test]
    fn adapt_unlocalizable_loss_taints_all_ops() {
        use crate::discovery::session::DiscoveryLoss;
        // A7: an undecodable record localizes to no op — every
        // previously Complete site degrades, and later emits stay
        // Unknown (the missing evidence could be anyone's).
        let live: Vec<maps::Mapping> = Vec::new();
        let files = HashMap::new();
        let fresh = HashSet::new();
        let mut state = AdapterState::default();
        let first = DiscoveryDelta {
            candidates: vec![
                candidate(
                    "/p/provider.so",
                    backing("08:01", 7, 0x100),
                    1,
                    11,
                    "SHA-256",
                    false,
                    "ok",
                ),
                candidate(
                    "/p/provider.so",
                    backing("08:01", 9, 0x200),
                    2,
                    21,
                    "SHA-512",
                    false,
                    "ok",
                ),
            ],
            tables: vec![terminated(1, 0), terminated(2, 0)],
            ..DiscoveryDelta::default()
        };
        let out = adapt_delta(&mut state, &first, &ctx_for(&live, &files, &fresh));
        assert_eq!(out.delta.discovered.len(), 2);
        for site in &out.delta.discovered {
            assert_eq!(site.candidates_coverage, CandidateCoverage::Complete);
        }
        let bad = DiscoveryDelta {
            losses: vec![DiscoveryLoss {
                source: coverage::HOST_BAD_EVENT,
                count: 1,
                op: None,
            }],
            ..DiscoveryDelta::default()
        };
        let out = adapt_delta(&mut state, &bad, &ctx_for(&live, &files, &fresh));
        assert_eq!(out.delta.discovered.len(), 2);
        for site in &out.delta.discovered {
            assert_eq!(site.candidates_coverage, CandidateCoverage::Unknown);
        }
    }

    #[test]
    fn adapt_unplannable_sites_are_loud_loss() {
        // D3: missing backing / unparsable device → explicit loss,
        // never a fabricated site.
        let delta = DiscoveryDelta {
            candidates: vec![
                candidate("/p/x.so", None, 1, 11, "SHA-256", false, "ok"),
                candidate(
                    "/p/x.so",
                    backing("bogus", 7, 0x100),
                    1,
                    11,
                    "SHA-256",
                    false,
                    "ok",
                ),
            ],
            ..DiscoveryDelta::default()
        };
        let (_, out) = adapt_fresh(&delta, &[]);
        assert!(out.delta.discovered.is_empty());
        let names: Vec<&str> = out.delta.losses.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"discovery.unbacked_candidate"));
        assert!(names.contains(&"discovery.unparsed_device"));
        for loss in &out.delta.losses {
            assert_eq!(loss.kind, CounterKind::Loss);
            assert!(loss.forces_partial());
        }
    }

    #[test]
    fn adapt_classifies_losses_and_keeps_unknown_ids() {
        // D4: ring → KernelRing, map → KernelMap, orphan rows →
        // TableRows, unknown ids fail closed with counts kept.
        use crate::discovery::session::DiscoveryLoss;
        let delta = DiscoveryDelta {
            losses: vec![
                DiscoveryLoss {
                    source: osslscope_ebpf_common::LOSS_RING_ROW,
                    count: 2,
                    op: None,
                },
                DiscoveryLoss {
                    source: osslscope_ebpf_common::LOSS_MAP_TRIP,
                    count: 3,
                    op: None,
                },
                DiscoveryLoss {
                    source: coverage::HOST_ORPHAN_ROW,
                    count: 4,
                    op: None,
                },
                DiscoveryLoss {
                    source: 4242,
                    count: 5,
                    op: None,
                },
                DiscoveryLoss {
                    source: osslscope_ebpf_common::LOSS_RING_ROW,
                    count: 0,
                    op: None,
                },
            ],
            ..DiscoveryDelta::default()
        };
        let (state, out) = adapt_fresh(&delta, &[]);
        assert_eq!(out.delta.losses.len(), 4);
        let by_name = |n: &str| {
            out.delta
                .losses
                .iter()
                .find(|c| c.name == n)
                .unwrap()
                .clone()
        };
        let ring = by_name("discovery.ring_row");
        assert_eq!(ring.source, CounterSource::KernelRing);
        assert_eq!(ring.units, CounterUnits::Events);
        assert_eq!(ring.value, 2);
        let map = by_name("discovery.map_trip");
        assert_eq!(map.source, CounterSource::KernelMap);
        assert_eq!(map.value, 3);
        let orphan = by_name("discovery.orphan_row");
        assert_eq!(orphan.units, CounterUnits::TableRows);
        assert_eq!(orphan.value, 4);
        let unknown = by_name("discovery.unknown_4242");
        assert_eq!(unknown.kind, CounterKind::Loss);
        assert_eq!(unknown.value, 5);
        // Loss sums accumulate for the close reconcile.
        assert_eq!(
            state.loss_sums.get(&osslscope_ebpf_common::LOSS_RING_ROW),
            Some(&2)
        );
    }

    #[test]
    fn pin_provider_class_precedence() {
        // D3/F-A/A6: a pinned enrollment wins; else builtin mode
        // asserts `default`; file mode pins nothing; an unknown
        // build-id pins nothing (no object to scope the pin to).
        assert_eq!(
            pin_provider_class(false, "ab12", Some("fips")),
            Some(PinnedProvider {
                object: "build:ab12".to_string(),
                class: "fips".to_string(),
            })
        );
        assert_eq!(
            pin_provider_class(true, "ab12", Some("fips")),
            Some(PinnedProvider {
                object: "build:ab12".to_string(),
                class: "fips".to_string(),
            })
        );
        assert_eq!(
            pin_provider_class(true, "ab12", None),
            Some(PinnedProvider {
                object: "build:ab12".to_string(),
                class: "default".to_string(),
            })
        );
        assert_eq!(pin_provider_class(false, "ab12", None), None);
        assert_eq!(pin_provider_class(true, "unknown", Some("fips")), None);
        assert_eq!(pin_provider_class(true, "unknown", None), None);
    }

    #[test]
    fn adapt_provider_class_resolves_per_object() {
        // D3/F-A/A6: the pin labels only the matching verified
        // object — an unverified advertising id never matches, and
        // an unpinned run labels nothing.
        let delta = DiscoveryDelta {
            candidates: vec![candidate(
                "/p/provider.so",
                backing("08:01", 7, 0x100),
                1,
                11,
                "SHA-256",
                false,
                "ok",
            )],
            tables: vec![terminated(1, 0)],
            ..DiscoveryDelta::default()
        };
        // Unpinned: unknown.
        let (_, out) = adapt_fresh(&delta, &[]);
        assert_eq!(
            out.delta.discovered[0].candidates[0].provider_class,
            "unknown"
        );
        // Pinned, but no live mapping resolves the advertising —
        // the anonymous id is not the pinned object: unknown.
        let mut state = AdapterState::default();
        let files = HashMap::new();
        let fresh = HashSet::new();
        let out = adapt_delta(
            &mut state,
            &delta,
            &AdapterCtx {
                live: &[],
                files: &files,
                pinned_provider: Some(PinnedProvider {
                    object: "build:ab12".to_string(),
                    class: "fips".to_string(),
                }),
                fresh: &fresh,
                post_settle: false,
                post_release: false,
                baseline: false,
            },
        );
        assert_eq!(
            out.delta.discovered[0].candidates[0].provider_class,
            "unknown"
        );
    }

    #[test]
    fn adapt_late_attach_splits_fresh_loads() {
        // Past settle, a first emit for a long-present backing is
        // late-attach loss; a fresh-dlopen backing is activity.
        let delta = DiscoveryDelta {
            candidates: vec![
                candidate(
                    "/p/old.so",
                    backing("08:01", 7, 0x100),
                    1,
                    11,
                    "SHA-256",
                    false,
                    "ok",
                ),
                candidate(
                    "/p/new.so",
                    backing("08:01", 8, 0x200),
                    1,
                    12,
                    "SHA-512",
                    false,
                    "ok",
                ),
            ],
            tables: vec![in_progress(1, 0)],
            ..DiscoveryDelta::default()
        };
        let mut state = AdapterState::default();
        let files = HashMap::new();
        let fresh: HashSet<(String, u64)> = HashSet::from([("08:01".to_string(), 8)]);
        let out = adapt_delta(
            &mut state,
            &delta,
            &AdapterCtx {
                live: &[],
                files: &files,
                pinned_provider: None,
                fresh: &fresh,
                post_settle: true,
                post_release: false,
                baseline: false,
            },
        );
        assert_eq!(out.delta.discovered.len(), 2);
        let loss = out
            .delta
            .losses
            .iter()
            .find(|c| c.name == "discovery.late_attach_sites")
            .unwrap();
        assert_eq!(loss.value, 1);
        let fresh_row = out
            .activity
            .iter()
            .find(|c| c.name == "discovery.new_mapping_sites")
            .unwrap();
        assert_eq!(fresh_row.value, 1);
    }

    #[test]
    fn adapt_post_release_first_emit_gaps_long_present() {
        // R20-fix round 2, F7 (adapter level): a first-attach past
        // the release boundary gaps for long-present sites even
        // pre-settle; fresh mappings stay Activity.
        let delta = DiscoveryDelta {
            candidates: vec![
                candidate(
                    "/p/provider.so",
                    backing("08:01", 7, 0x100),
                    1,
                    11,
                    "SHA-256",
                    false,
                    "ok",
                ),
                candidate(
                    "/p/new.so",
                    backing("08:01", 8, 0x200),
                    1,
                    12,
                    "SHA-512",
                    false,
                    "ok",
                ),
            ],
            tables: vec![in_progress(1, 0)],
            ..DiscoveryDelta::default()
        };
        let mut state = AdapterState::default();
        let files = HashMap::new();
        let fresh: HashSet<(String, u64)> = HashSet::from([("08:01".to_string(), 8)]);
        let out = adapt_delta(
            &mut state,
            &delta,
            &AdapterCtx {
                live: &[],
                files: &files,
                pinned_provider: None,
                fresh: &fresh,
                post_settle: false,
                post_release: true,
                baseline: false,
            },
        );
        assert_eq!(out.delta.discovered.len(), 2);
        let loss = out
            .delta
            .losses
            .iter()
            .find(|c| c.name == "discovery.late_attach_sites")
            .unwrap();
        assert_eq!(loss.value, 1);
        let fresh_row = out
            .activity
            .iter()
            .find(|c| c.name == "discovery.new_mapping_sites")
            .unwrap();
        assert_eq!(fresh_row.value, 1);
    }

    #[test]
    fn adapt_baseline_drops_tripwire_and_cold_queries() {
        // D2 tripwire/queries: the baselining poll drops tripwire
        // news and reports queries as pre-window (cold gap).
        let delta = DiscoveryDelta {
            queries_delta: 6,
            tripwire: crate::discovery::session::TripwireDelta {
                hits: vec![legacy::TripHit {
                    cookie: 7,
                    class: 1,
                    status: 0,
                }],
                counter_deltas: vec![(7, 3)],
                executed_legacy_queries_delta: 2,
            },
            ..DiscoveryDelta::default()
        };
        let mut state = AdapterState::default();
        let files = HashMap::new();
        let fresh = HashSet::new();
        let out = adapt_delta(
            &mut state,
            &delta,
            &AdapterCtx {
                live: &[],
                files: &files,
                pinned_provider: None,
                fresh: &fresh,
                post_settle: false,
                post_release: false,
                baseline: true,
            },
        );
        assert!(out.tripwire.is_none());
        assert_eq!(out.pre_window_queries, 6);
        assert!(
            out.activity
                .iter()
                .all(|c| c.name != "discovery.queries_observed")
        );
    }

    #[test]
    fn adapt_failed_attach_diagnostic_retained() {
        // R06 (attach diagnostics): a failed attach's diagnostic
        // text is retained (sorted, deduped) for the document
        // path — the systematic attach failure must identify
        // itself in JSON, not just count.
        let delta = DiscoveryDelta {
            attaches: vec![
                AttachEvent {
                    kind: AttachKind::Stage2 { cookie: 7 },
                    failed: Some("EBUSY".to_string()),
                },
                AttachEvent {
                    kind: AttachKind::Tripwires { count: 3 },
                    failed: Some("EBUSY".to_string()),
                },
                AttachEvent {
                    kind: AttachKind::Stage2 { cookie: 9 },
                    failed: None,
                },
            ],
            ..DiscoveryDelta::default()
        };
        let (state, _) = adapt_fresh(&delta, &[]);
        assert_eq!(
            state.attach_diagnostics.into_iter().collect::<Vec<_>>(),
            vec!["EBUSY".to_string()],
            "failed-attach text retained once (deduped)"
        );
    }

    #[test]
    fn adapt_auxiliary_fields_become_counters() {
        // D2: events/attaches/budget dispositions stay visible.
        let delta = DiscoveryDelta {
            events_consumed: 10,
            queries_delta: 4,
            attaches: vec![
                AttachEvent {
                    kind: AttachKind::Stage2 { cookie: 1 },
                    failed: None,
                },
                AttachEvent {
                    kind: AttachKind::Tripwires { count: 3 },
                    failed: Some("EBUSY".to_string()),
                },
            ],
            budget_exhausted: true,
            trigger_observed: true,
            ..DiscoveryDelta::default()
        };
        let (_, out) = adapt_fresh(&delta, &[]);
        assert!(out.trigger_observed);
        let names: Vec<&str> = out.activity.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"discovery.events_consumed"));
        assert!(names.contains(&"discovery.queries_observed"));
        assert!(names.contains(&"discovery.attaches"));
        assert!(names.contains(&"discovery.budget_exhausted"));
        let failed = out
            .delta
            .losses
            .iter()
            .find(|c| c.name == "discovery.attach_failed")
            .unwrap();
        assert_eq!(failed.value, 1);
        assert_eq!(failed.units, CounterUnits::Probes);
    }

    #[test]
    fn adapt_objects_skip_unparsed_devices() {
        // D2 objects: fingerprinted-or-opaque records; unparsable
        // devices skip loud (never device zero).
        use crate::discovery::session::DiscoveredObject;
        let delta = DiscoveryDelta {
            objects: vec![
                DiscoveredObject {
                    dev: "08:01".to_string(),
                    ino: 7,
                    display_locator: "/p/provider.so".to_string(),
                },
                DiscoveredObject {
                    dev: "bogus".to_string(),
                    ino: 8,
                    display_locator: "/p/other.so".to_string(),
                },
            ],
            ..DiscoveryDelta::default()
        };
        let (state, out) = adapt_fresh(&delta, &[]);
        assert_eq!(out.objects.len(), 1);
        assert_eq!(out.objects[0].inode, 7);
        assert_eq!(out.objects[0].display_locator, "/p/provider.so");
        assert!(
            out.delta
                .losses
                .iter()
                .any(|c| c.name == "discovery.unparsed_object_dev")
        );
        assert_eq!(state.objects.len(), 1);
    }

    fn unit_mapping(path: &str, dev: &str, ino: u64, start: u64, x: bool) -> maps::Mapping {
        maps::Mapping {
            start,
            end: start + 0x1000,
            x,
            offset: 0,
            dev: dev.to_string(),
            ino,
            path: path.to_string(),
        }
    }

    fn unit_candidate(backing: Option<BackingRef>, arr: u64) -> DiscoveredCandidate {
        DiscoveredCandidate {
            advertising: "/p/data.so".to_string(),
            advertising_dev: "08:01".to_string(),
            advertising_ino: 12,
            backing,
            op: 1,
            funcid: 11,
            class: "SHA-256".to_string(),
            weak: false,
            status: "ok".to_string(),
            epoch: 0,
            impl_addr: 0,
            arr,
        }
    }

    #[test]
    fn relevant_paths_covers_backings_owners_and_objects() {
        // F-D/A13 T-u1: relevance = candidate backings + array
        // owners (any x-bit — dispatch arrays live in data
        // mappings) + new objects. Unreferenced and anonymous
        // mappings are never relevant.
        let live = vec![
            unit_mapping("/p/prov.so", "08:01", 11, 0x1000, true),
            unit_mapping("/p/data.so", "08:01", 12, 0x2000, false),
            unit_mapping("/p/obj.so", "08:01", 13, 0x3000, true),
            unit_mapping("/p/other.so", "08:02", 14, 0x4000, true),
            unit_mapping("[anon]", "00:00", 0, 0x5000, true),
        ];
        let delta = DiscoveryDelta {
            candidates: vec![unit_candidate(
                Some(BackingRef {
                    dev: "08:01".to_string(),
                    ino: 11,
                    offset: 8,
                }),
                0x2400,
            )],
            objects: vec![DiscoveredObject {
                dev: "08:01".to_string(),
                ino: 13,
                display_locator: "/p/obj.so".to_string(),
            }],
            ..DiscoveryDelta::default()
        };
        let (paths, dropped) = relevant_paths(&delta, &live);
        assert_eq!(dropped, 0);
        assert_eq!(
            paths.into_iter().collect::<Vec<_>>(),
            vec!["/p/data.so", "/p/obj.so", "/p/prov.so"]
        );
    }

    #[test]
    fn h5_t4a_advertising_ids_register_at_construction() {
        // H5 (B-5): every id a ref can name is registered at
        // construction — an advertising-only provider (no D2
        // object in the delta) still lands an ObjectRecord, so
        // candidates[].provider always resolves. The located
        // opaque form is unified (`unverified:`, like object
        // ids — same file, same record). RED pre-B-5
        // (advertising records never registered).
        let live = vec![
            unit_mapping("/p/prov.so", "08:01", 11, 0x1000, true),
            unit_mapping("/p/data.so", "08:01", 12, 0x2000, false),
        ];
        let files = HashMap::new();
        let fresh = HashSet::new();
        let mut state = AdapterState::default();
        let delta = DiscoveryDelta {
            candidates: vec![unit_candidate(
                Some(BackingRef {
                    dev: "08:01".to_string(),
                    ino: 11,
                    offset: 8,
                }),
                0x2400,
            )],
            tables: vec![terminated(1, 0)],
            ..DiscoveryDelta::default()
        };
        let out = adapt_delta(&mut state, &delta, &ctx_for(&live, &files, &fresh));
        assert_eq!(out.delta.discovered.len(), 1);
        let provider = &out.delta.discovered[0].candidates[0].provider.0;
        assert_eq!(provider, "unverified:08:01:12");
        // No D2 objects in this delta — the objects set carries
        // ONLY the advertising record, and the ref resolves.
        assert_eq!(out.objects.len(), 1);
        assert_eq!(out.objects[0].id.0, *provider);
        assert_eq!(out.objects[0].inode, 12);
        assert_eq!(out.objects[0].display_locator, "/p/data.so");
        assert_eq!(state.objects.len(), 1);
    }

    #[test]
    fn relevant_paths_caps_pathological_sets_deterministically() {
        // F-D/A13 T-u2: a pathological delta (300 distinct
        // backings) keeps the lexicographically first 256 paths
        // and reports the dropped remainder.
        let mut live = Vec::new();
        let mut candidates = Vec::new();
        for i in 0..300u64 {
            live.push(unit_mapping(
                &format!("/x/mod{i:03}.so"),
                "08:01",
                1_000_000 + i,
                0x1000,
                true,
            ));
            candidates.push(unit_candidate(
                Some(BackingRef {
                    dev: "08:01".to_string(),
                    ino: 1_000_000 + i,
                    offset: 8,
                }),
                0,
            ));
        }
        let delta = DiscoveryDelta {
            candidates,
            ..DiscoveryDelta::default()
        };
        let (paths, dropped) = relevant_paths(&delta, &live);
        assert_eq!(dropped, 44);
        assert_eq!(paths.len(), MAX_RELEVANT_FILES_PER_POLL);
        assert_eq!(paths.iter().next().unwrap(), "/x/mod000.so");
        assert!(paths.contains("/x/mod255.so"));
        assert!(!paths.contains("/x/mod256.so"));
    }

    #[test]
    fn relevant_paths_empty_delta_reads_nothing() {
        // F-D/A13 T-u3: an empty poll reads no files (the common
        // steady-state round is maps + stats only).
        let live = vec![unit_mapping("/p/prov.so", "08:01", 11, 0x1000, true)];
        let (paths, dropped) = relevant_paths(&DiscoveryDelta::default(), &live);
        assert_eq!(dropped, 0);
        assert!(paths.is_empty());
    }

    /// Stub-port Runner harness (born in H7-T1/T5): stub ports
    /// drive the Runner's close paths directly. H7 salvages close
    /// errors into fatal-Runtime captures (exit 1) that keep every
    /// observation collected so far; H8 reuses the harness for the
    /// legacy call partition end-to-end.
    mod stub_runner {
        use super::*;
        use crate::count_session::{CountDelta, FakeCountBackend};
        use crate::evidence::FencedGeneration;
        use std::cell::Cell;

        const TPID: u32 = 424242;

        // Incidental attach stamp for seeds that predate
        // installed-at: none of them assert on it.
        const ATTACH_AT: u64 = 900;

        /// First X-segment file offset of an ELF image (attach plans
        /// probes at X offsets only — an arbitrary offset filters out
        /// and no cookie is ever issued).
        fn x_offset(bytes: &[u8]) -> u64 {
            use goblin::elf::program_header::{PF_X, PT_LOAD};
            let elf = goblin::elf::Elf::parse(bytes).unwrap();
            let ph = elf
                .program_headers
                .iter()
                .find(|ph| ph.p_type == PT_LOAD && ph.p_flags & PF_X != 0)
                .unwrap();
            ph.p_offset + 8
        }

        static SEED_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

        /// Real temp file backing the seeded site: attach pins the
        /// path on disk (`resolve_pinned`), so a fake path never
        /// binds and its rows drain as unattributed. Removed on drop.
        struct SeedFile {
            path: String,
        }

        impl SeedFile {
            fn fresh(bytes: &[u8]) -> Self {
                use std::sync::atomic::Ordering;
                let seq = SEED_SEQ.fetch_add(1, Ordering::SeqCst);
                let dir = std::env::temp_dir().join(format!(
                    "osslscope-h7-{}-{}-{:?}",
                    std::process::id(),
                    seq,
                    std::thread::current().id()
                ));
                std::fs::create_dir_all(&dir).unwrap();
                let path = dir.join("prov.so");
                std::fs::write(&path, bytes).unwrap();
                Self {
                    path: path.to_str().unwrap().to_string(),
                }
            }

            fn identity(&self) -> (u64, u64) {
                use std::os::unix::fs::MetadataExt as _;
                let meta = std::fs::metadata(&self.path).unwrap();
                (
                    crate::plan::encode_device(libc::major(meta.dev()), libc::minor(meta.dev())),
                    meta.ino(),
                )
            }
        }

        impl Drop for SeedFile {
            fn drop(&mut self) {
                if let Some(dir) = std::path::Path::new(&self.path).parent() {
                    let _ = std::fs::remove_dir_all(dir);
                }
            }
        }

        struct DiscoveryStub {
            finish_err: bool,
            poll_err: bool,
            dispatch_attached: bool,
            trip_set: Option<legacy::ProbeSet>,
        }
        impl DiscoveryStub {
            fn snapshot_value(&self) -> DiscoverySnapshot {
                let mut snapshot = DiscoverySnapshot::default();
                snapshot.dispatch.attached = self.dispatch_attached;
                snapshot.legacy.set = self.trip_set.clone();
                snapshot.legacy.planned = self.trip_set.is_some();
                snapshot
            }
        }
        impl DiscoveryPort for DiscoveryStub {
            fn poll(&mut self, _budget: PollBudget) -> anyhow::Result<DiscoveryDelta> {
                if self.poll_err {
                    anyhow::bail!("injected poll failure");
                }
                Ok(DiscoveryDelta::default())
            }
            fn snapshot(&self) -> DiscoverySnapshot {
                self.snapshot_value()
            }
            fn finish(&mut self) -> anyhow::Result<DiscoverySnapshot> {
                if self.finish_err {
                    anyhow::bail!("injected finish failure");
                }
                Ok(self.snapshot_value())
            }
        }

        /// Scripted traversal port: harvest behavior delegates to
        /// the inner stub; traversal serves canned round deltas +
        /// a finish tail (the baseline poll drops, like the live
        /// port — it never consumes a canned round).
        struct TraversalStub {
            inner: DiscoveryStub,
            rounds: std::collections::VecDeque<TraversalDelta>,
            tail: TraversalCapture,
            baseline_calls: Vec<bool>,
        }
        impl TraversalStub {
            fn scripted(rounds: Vec<TraversalDelta>, tail: TraversalCapture) -> Self {
                Self {
                    inner: DiscoveryStub {
                        finish_err: false,
                        poll_err: false,
                        dispatch_attached: false,
                        trip_set: None,
                    },
                    rounds: rounds.into(),
                    tail,
                    baseline_calls: Vec::new(),
                }
            }
        }
        impl DiscoveryPort for TraversalStub {
            fn poll(&mut self, budget: PollBudget) -> anyhow::Result<DiscoveryDelta> {
                self.inner.poll(budget)
            }
            fn snapshot(&self) -> DiscoverySnapshot {
                self.inner.snapshot()
            }
            fn finish(&mut self) -> anyhow::Result<DiscoverySnapshot> {
                self.inner.finish()
            }
            fn poll_traversal(&mut self, baseline: bool) -> anyhow::Result<TraversalDelta> {
                self.baseline_calls.push(baseline);
                if baseline {
                    return Ok(TraversalDelta::default());
                }
                Ok(self.rounds.pop_front().unwrap_or_default())
            }
            fn finish_traversal(&mut self) -> TraversalCapture {
                std::mem::take(&mut self.tail)
            }
            fn traversal_active(&self) -> bool {
                true
            }
        }

        fn walk(seq: u64, outcome: crate::scan::oracle::Outcome) -> WalkDone {
            WalkDone {
                tid: TPID,
                seq,
                op: 1,
                arr: 0xa000,
                outcome,
                true_t: crate::scan::oracle::TrueT::Proven(6),
                alg_count: 6,
                row_count: 6,
                guard: None,
                algs: Vec::new(),
                event_ns: 100,
                rows: Vec::new(),
            }
        }

        fn walk_full(
            seq: u64,
            op: u32,
            outcome: crate::scan::oracle::Outcome,
            algs: Vec<crate::scan::oracle::AlgIdentity>,
            rows: Vec<osslscope_ebpf_common::ScanRowEvent>,
            event_ns: u64,
        ) -> WalkDone {
            WalkDone {
                tid: TPID,
                seq,
                op,
                arr: 0xa000,
                outcome,
                true_t: crate::scan::oracle::TrueT::Proven(6),
                alg_count: algs.len(),
                row_count: rows.len(),
                guard: None,
                algs,
                event_ns,
                rows,
            }
        }

        fn row_ev(idx: u64, funcid: u32) -> osslscope_ebpf_common::ScanRowEvent {
            osslscope_ebpf_common::ScanRowEvent {
                kind: osslscope_ebpf_common::KIND_SCAN_ROW,
                op: 0,
                funcid,
                _pad: 0,
                addr: 0x4400 + funcid as u64,
                aux: 0xa000,
                idx,
                generation: 0,
                tid: TPID,
                _pad2: 0,
                seq: 0,
            }
        }

        fn ident(idx: u64, class: u16, status: u8, weak: u8) -> crate::scan::oracle::AlgIdentity {
            crate::scan::oracle::AlgIdentity {
                idx,
                class,
                status,
                weak,
                generation: 0,
            }
        }
        fn triple_prov() -> TripleProvenance {
            let obj = |n: &str| ObjectProvenance {
                path: PathBuf::from(format!("/prefix/lib/osslscope/{n}")),
                sha256: format!("hash-{n}"),
            };
            TripleProvenance {
                harvest: obj("osslscope-harvest"),
                count: obj("osslscope-count"),
                members: obj("osslscope-members"),
            }
        }

        #[test]
        fn traversal_off_by_default_never_polls() {
            // Harvest-only ports (the default methods) are never
            // polled for traversal and retain no outcome.
            let cfg = stub_config();
            let info = stub_info();
            let clock = ClockStub::at(5_000_000_000);
            let mut proc = ProcStub;
            let cancelled = || false;
            let count = CountSession::new(TPID, FakeCountBackend::new());
            let mut runner = stub_runner(
                &cfg,
                &info,
                DiscoveryStub {
                    finish_err: false,
                    poll_err: false,
                    dispatch_attached: false,
                    trip_set: None,
                },
                count,
                &clock,
                &mut proc,
                &cancelled,
            );
            let deadline = clock.now() + Duration::from_secs(10);
            let action = runner
                .round(deadline, clock.now())
                .expect("stub round runs");
            assert!(matches!(action, RoundAction::Continue));
            assert!(runner.traversal.is_none());
            let cap = runner.close_and_finalize().expect("stub close finalizes");
            assert!(cap.traversal.is_none());
        }

        #[test]
        fn traversal_baseline_rounds_and_close_fold() {
            // RED: an active port's baseline fences (first call,
            // contributes nothing), rounds fold records/reasons,
            // and the finish tail merges with provenance.
            use crate::scan::oracle::{Finding as OFinding, Outcome, PartialReason};
            let d1 = TraversalDelta {
                done: vec![walk(
                    1,
                    Outcome::Complete {
                        true_t: 6,
                        cached: false,
                    },
                )],
                findings: vec![],
                partial_reasons: vec!["traversal-storm".to_string()],
                polls: 1,
                corrections: vec![],
                admitted: std::collections::BTreeMap::new(),
                admitted_unknown: std::collections::BTreeSet::new(),
                census_loss: 0,
                storm: true,
                throttled: false,
            };
            let d2 = TraversalDelta {
                done: vec![walk(
                    2,
                    Outcome::Partial {
                        reasons: vec![PartialReason::DrainLoss],
                    },
                )],
                findings: vec![OFinding::OrphanRet { tid: TPID, seq: 9 }],
                partial_reasons: vec!["traversal-incomplete".to_string()],
                polls: 1,
                corrections: vec![],
                admitted: std::collections::BTreeMap::new(),
                admitted_unknown: std::collections::BTreeSet::new(),
                census_loss: 0,
                storm: false,
                throttled: false,
            };
            let tail = TraversalCapture {
                provenance: Some(triple_prov()),
                done: vec![walk(
                    3,
                    Outcome::Complete {
                        true_t: 6,
                        cached: true,
                    },
                )],
                findings: vec![],
                polls: 1,
                corrections: vec![],
                admitted_by_op: std::collections::BTreeMap::new(),
                admitted_unknown_by_op: std::collections::BTreeSet::new(),
                census_loss: 0,
                throttled: true,
                detached: false,
                finish_error: None,
                storm_polls: 0,
                throttled_polls: 0,
            };
            let cfg = stub_config();
            let info = stub_info();
            let clock = ClockStub::at(5_000_000_000);
            let mut proc = ProcStub;
            let cancelled = || false;
            let count = CountSession::new(TPID, FakeCountBackend::new());
            let runner = stub_runner(
                &cfg,
                &info,
                TraversalStub::scripted(vec![d1, d2], tail),
                count,
                &clock,
                &mut proc,
                &cancelled,
            );
            let cap = runner.setup_and_run().expect("stub run completes");
            let t = cap.traversal.expect("active traversal retained");
            assert_eq!(
                t.done.iter().map(|w| w.seq).collect::<Vec<_>>(),
                vec![1, 2, 3]
            );
            assert_eq!(t.findings.len(), 1);
            assert!(t.polls >= 2, "rounds + finish tail, got {}", t.polls);
            assert_eq!(t.provenance, Some(triple_prov()));
            assert!(t.throttled);
            assert!(t.finish_error.is_none());
            assert!(cap.reasons.iter().any(|r| r == "traversal-storm"));
            assert!(cap.reasons.iter().any(|r| r == "traversal-incomplete"));
        }

        #[test]
        fn fix3_apply_corrections_rewrites_by_key() {
            use crate::scan::oracle::{Correction, Outcome};
            // Post-drain corrections rewrite the holder's copy by
            // (tid, seq) (outcome + op); unknown keys are ignored
            // (defensive — the holder extends monotonically, so a
            // correction always names a held verdict).
            let mut done = vec![
                walk_full(
                    1,
                    1,
                    Outcome::Complete {
                        true_t: 6,
                        cached: false,
                    },
                    vec![],
                    vec![],
                    100,
                ),
                walk_full(
                    2,
                    1,
                    Outcome::Complete {
                        true_t: 6,
                        cached: false,
                    },
                    vec![],
                    vec![],
                    200,
                ),
            ];
            let op0 = done[0].op;
            apply_corrections(
                &mut done,
                &[Correction {
                    tid: TPID + 1,
                    seq: 1,
                    outcome: Outcome::Tainted { by_seq: 2 },
                    op: crate::scan::oracle::UNKNOWN_OP,
                }],
            );
            // Wrong-tid correction ignored; right-tid rewrites.
            assert_eq!(done[0].op, op0);
            apply_corrections(
                &mut done,
                &[Correction {
                    tid: TPID,
                    seq: 1,
                    outcome: Outcome::Tainted { by_seq: 2 },
                    op: crate::scan::oracle::UNKNOWN_OP,
                }],
            );
            assert!(
                matches!(done[0].outcome, Outcome::Tainted { by_seq: 2 }),
                "held verdict corrected: {:?}",
                done[0].outcome
            );
            assert_eq!(done[0].op, crate::scan::oracle::UNKNOWN_OP);
            assert!(
                matches!(done[1].outcome, Outcome::Complete { .. }),
                "uncorrected verdict untouched"
            );
        }

        #[test]
        fn traversal_close_produces_no_synthetic_sites() {
            // Traversal evidence reports NATIVELY (records +
            // per-slot identities + TRUE-T + outcomes + provenance)
            // — never as manufactured count-session executions:
            // callback execution is unobservable in v1, and
            // fetch/query visibility is not execution evidence
            // (Global Constraints). Close with a Complete record:
            // document sites carry NO anchor-offset synthetic
            // site, executions carry nothing synthetic, and the
            // traversal outcome retains the record.
            use crate::scan::oracle::Outcome;
            use osslscope_ebpf_common as wire;
            let round = TraversalDelta {
                done: vec![walk_full(
                    1,
                    1,
                    Outcome::Complete {
                        true_t: 6,
                        cached: false,
                    },
                    vec![
                        ident(0, 0, wire::ALG_OK, 0),
                        ident(1, wire::OTHER_CLASS, wire::ALG_EMPTY, 0),
                    ],
                    vec![row_ev(0, 300)],
                    5_000_000_000,
                )],
                findings: vec![],
                partial_reasons: vec![],
                polls: 1,
                corrections: vec![],
                admitted: std::collections::BTreeMap::new(),
                admitted_unknown: std::collections::BTreeSet::new(),
                census_loss: 0,
                storm: false,
                throttled: false,
            };
            let tail = TraversalCapture {
                provenance: Some(triple_prov()),
                done: vec![],
                findings: vec![],
                polls: 1,
                corrections: vec![],
                admitted_by_op: std::collections::BTreeMap::new(),
                admitted_unknown_by_op: std::collections::BTreeSet::new(),
                census_loss: 0,
                throttled: false,
                detached: false,
                finish_error: None,
                storm_polls: 0,
                throttled_polls: 0,
            };
            let cfg = stub_config();
            let info = stub_info();
            let clock = ClockStub::at(5_000_000_000);
            let mut proc = ProcStub;
            let cancelled = || false;
            let count = CountSession::new(TPID, FakeCountBackend::new());
            let runner = stub_runner(
                &cfg,
                &info,
                TraversalStub::scripted(vec![round], tail),
                count,
                &clock,
                &mut proc,
                &cancelled,
            );
            let cap = runner.setup_and_run().expect("stub run completes");
            // The stub count backend observes nothing, and
            // traversal manufactures nothing: the inventory is
            // empty while the traversal outcome retains the
            // record natively.
            assert!(
                cap.document.sites.is_empty(),
                "no synthetic sites are manufactured"
            );
            assert!(
                cap.executions.is_empty(),
                "no synthetic executions are manufactured"
            );
            assert_eq!(cap.traversal.as_ref().unwrap().done.len(), 1);
        }

        #[test]
        fn fix4_admitted_census_retained_and_rendered() {
            // The admitted-query census (per-op CALLS) is honest
            // observation metadata (loss-independent — record
            // count is not a census): deltas carry it, the
            // capture retains the latest snapshot, and the
            // rendered traversal section reports it (additive
            // `admitted` map — old readers ignore unknown keys).
            use crate::scan::oracle::Outcome;
            use osslscope_ebpf_common as wire;
            let admitted: std::collections::BTreeMap<u32, u64> =
                [(1u32, 3u64)].into_iter().collect();
            let round = TraversalDelta {
                done: vec![walk_full(
                    1,
                    1,
                    Outcome::Complete {
                        true_t: 6,
                        cached: false,
                    },
                    vec![
                        ident(0, 0, wire::ALG_OK, 0),
                        ident(1, wire::OTHER_CLASS, wire::ALG_EMPTY, 0),
                    ],
                    vec![row_ev(0, 300)],
                    5_000_000_000,
                )],
                findings: vec![],
                partial_reasons: vec![],
                polls: 1,
                corrections: vec![],
                admitted: admitted.clone(),
                admitted_unknown: std::collections::BTreeSet::new(),
                census_loss: 0,
                storm: false,
                throttled: false,
            };
            let tail = TraversalCapture {
                provenance: Some(triple_prov()),
                done: vec![],
                findings: vec![],
                polls: 1,
                corrections: vec![],
                admitted_by_op: std::collections::BTreeMap::new(),
                admitted_unknown_by_op: std::collections::BTreeSet::new(),
                census_loss: 0,
                throttled: false,
                detached: false,
                finish_error: None,
                storm_polls: 0,
                throttled_polls: 0,
            };
            let cfg = stub_config();
            let info = stub_info();
            let clock = ClockStub::at(5_000_000_000);
            let mut proc = ProcStub;
            let cancelled = || false;
            let count = CountSession::new(TPID, FakeCountBackend::new());
            let runner = stub_runner(
                &cfg,
                &info,
                TraversalStub::scripted(vec![round], tail),
                count,
                &clock,
                &mut proc,
                &cancelled,
            );
            let cap = runner.setup_and_run().expect("stub run completes");
            assert_eq!(
                cap.traversal.as_ref().unwrap().admitted_by_op,
                admitted,
                "capture retains the admitted census"
            );
            let json = crate::report::render_json(&cap.document).expect("render");
            let v: serde_json::Value = serde_json::from_slice(&json).expect("parse");
            assert_eq!(
                v["traversal"]["admitted"]["1"], 3,
                "rendered census reports per-op admissions"
            );
            // Per-record native facts (one entry per close, close
            // order — verdict-relevant facts, not slot arrays).
            let entries = v["traversal"]["entries"]
                .as_array()
                .expect("entries render");
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0]["seq"], 1);
            assert_eq!(entries[0]["op"], 1);
            assert_eq!(entries[0]["outcome"]["Complete"]["true_t"], 6);
            assert_eq!(entries[0]["true_t"], serde_json::json!({"Proven": 6}));
            assert_eq!(entries[0]["alg_count"], 2);
            assert_eq!(entries[0]["row_count"], 1);
            assert_eq!(entries[0]["generation"], 0);
            // Old-reader compatibility: a reader that knows only
            // the round-3 shape parses the new document fine.
            #[derive(serde::Deserialize)]
            struct OldTraversal {
                records: u64,
            }
            let old: OldTraversal =
                serde_json::from_value(v["traversal"].clone()).expect("old reader parses");
            assert_eq!(old.records, 1);
        }
        #[test]
        fn fix5_admitted_unknown_retained_and_rendered() {
            // An op past CALLS map pressure has records but no
            // census entry: its count is UNKNOWN, never silently
            // zero. Deltas carry the unknown set + cumulative
            // loss, the capture unions them across rounds, and
            // the rendered traversal section reports both
            // (additive keys — old readers ignore them).
            use crate::scan::oracle::Outcome;
            use osslscope_ebpf_common as wire;
            let round = |seq: u64, op: u32, unknown: u32, loss: u64| TraversalDelta {
                done: vec![walk_full(
                    seq,
                    op,
                    Outcome::Complete {
                        true_t: 6,
                        cached: false,
                    },
                    vec![
                        ident(0, 0, wire::ALG_OK, 0),
                        ident(1, wire::OTHER_CLASS, wire::ALG_EMPTY, 0),
                    ],
                    vec![row_ev(0, 300)],
                    5_000_000_000,
                )],
                findings: vec![],
                partial_reasons: vec![],
                polls: 1,
                corrections: vec![],
                admitted: [(1u32, 3u64)].into_iter().collect(),
                admitted_unknown: [unknown].into_iter().collect(),
                census_loss: loss,
                storm: false,
                throttled: false,
            };
            let tail = TraversalCapture {
                provenance: Some(triple_prov()),
                done: vec![],
                findings: vec![],
                polls: 1,
                corrections: vec![],
                admitted_by_op: std::collections::BTreeMap::new(),
                admitted_unknown_by_op: std::collections::BTreeSet::new(),
                census_loss: 0,
                throttled: false,
                detached: false,
                finish_error: None,
                storm_polls: 0,
                throttled_polls: 0,
            };
            let cfg = stub_config();
            let info = stub_info();
            let clock = ClockStub::at(5_000_000_000);
            let mut proc = ProcStub;
            let cancelled = || false;
            let count = CountSession::new(TPID, FakeCountBackend::new());
            let runner = stub_runner(
                &cfg,
                &info,
                TraversalStub::scripted(vec![round(1, 99, 99, 2), round(2, 100, 100, 3)], tail),
                count,
                &clock,
                &mut proc,
                &cancelled,
            );
            let cap = runner.setup_and_run().expect("stub run completes");
            let t = cap.traversal.as_ref().unwrap();
            assert_eq!(
                t.admitted_unknown_by_op,
                [99u32, 100].into_iter().collect(),
                "capture unions unknown ops across rounds"
            );
            assert_eq!(t.census_loss, 3, "capture keeps the loss high-water");
            let json = crate::report::render_json(&cap.document).expect("render");
            let v: serde_json::Value = serde_json::from_slice(&json).expect("parse");
            assert_eq!(
                v["traversal"]["admitted_unknown"],
                serde_json::json!([99, 100]),
                "rendered unknown set names the uncounted ops"
            );
            assert_eq!(
                v["traversal"]["census_loss"], 3,
                "rendered census loss marks the snapshot incomplete"
            );
            // Old-reader compatibility: a reader that knows only
            // the round-3 shape parses the new document fine.
            #[derive(serde::Deserialize)]
            struct OldTraversal {
                records: u64,
            }
            let old: OldTraversal =
                serde_json::from_value(v["traversal"].clone()).expect("old reader parses");
            assert_eq!(old.records, 2);
        }

        #[test]
        fn traversal_salvage_keeps_drained() {
            // RED: a close failure salvages the drained-so-far
            // traversal records (proved facts, H7) with the tail.
            use crate::scan::oracle::Outcome;
            let d1 = TraversalDelta {
                done: vec![walk(
                    1,
                    Outcome::Complete {
                        true_t: 6,
                        cached: false,
                    },
                )],
                findings: vec![],
                partial_reasons: vec!["traversal-storm".to_string()],
                polls: 1,
                corrections: vec![],
                admitted: std::collections::BTreeMap::new(),
                admitted_unknown: std::collections::BTreeSet::new(),
                census_loss: 0,
                storm: true,
                throttled: false,
            };
            let tail = TraversalCapture {
                provenance: Some(triple_prov()),
                done: vec![walk(
                    2,
                    Outcome::Complete {
                        true_t: 6,
                        cached: true,
                    },
                )],
                findings: vec![],
                polls: 1,
                corrections: vec![],
                admitted_by_op: std::collections::BTreeMap::new(),
                admitted_unknown_by_op: std::collections::BTreeSet::new(),
                census_loss: 0,
                throttled: false,
                detached: true,
                finish_error: None,
                storm_polls: 0,
                throttled_polls: 0,
            };
            let cfg = stub_config();
            let info = stub_info();
            let clock = ClockStub::at(5_000_000_000);
            let mut proc = ProcStub;
            let cancelled = || false;
            let count = CountSession::new(TPID, FakeCountBackend::new());
            let mut stub = TraversalStub::scripted(vec![d1], tail);
            stub.inner.finish_err = true;
            let runner = stub_runner(&cfg, &info, stub, count, &clock, &mut proc, &cancelled);
            let cap = runner
                .setup_and_run()
                .expect("close failure must salvage, not Err");
            let t = cap.traversal.expect("salvage keeps traversal");
            assert_eq!(t.done.iter().map(|w| w.seq).collect::<Vec<_>>(), vec![1, 2]);
            assert!(t.detached);
            assert!(cap.reasons.iter().any(|r| r == "close-failure"));
            assert!(cap.reasons.iter().any(|r| r == "traversal-storm"));
        }

        #[test]
        fn traversal_losses_yield_typed_document_gaps() {
            // P1: traversal failures (storm in force at close,
            // throttled round, finish error, incomplete records,
            // unjoined findings) must surface as TYPED document
            // gaps (Loss counters → Partial reasons feeding the
            // sole finalizer) — a compat Capture reason alone does
            // not restore document completeness, and observed
            // records must survive untouched.
            use crate::scan::oracle::Outcome;
            let d1 = TraversalDelta {
                done: vec![walk(1, Outcome::Skipped { cause: 1 })],
                findings: vec![crate::scan::oracle::Finding::OrphanRet { tid: TPID, seq: 9 }],
                partial_reasons: vec![
                    "traversal-throttled".to_string(),
                    "traversal-incomplete".to_string(),
                    "traversal-unjoined".to_string(),
                ],
                polls: 1,
                corrections: vec![],
                admitted: std::collections::BTreeMap::new(),
                admitted_unknown: std::collections::BTreeSet::new(),
                census_loss: 0,
                storm: false,
                throttled: true,
            };
            let tail = TraversalCapture {
                provenance: Some(triple_prov()),
                done: vec![],
                findings: vec![],
                polls: 1,
                corrections: vec![],
                admitted_by_op: std::collections::BTreeMap::new(),
                admitted_unknown_by_op: std::collections::BTreeSet::new(),
                census_loss: 0,
                throttled: false,
                detached: true,
                finish_error: Some("tail drain failed".to_string()),
                storm_polls: 0,
                throttled_polls: 0,
            };
            let cfg = stub_config();
            let info = stub_info();
            let clock = ClockStub::at(5_000_000_000);
            let mut proc = ProcStub;
            let cancelled = || false;
            let count = CountSession::new(TPID, FakeCountBackend::new());
            let stub = TraversalStub::scripted(vec![d1], tail);
            let runner = stub_runner(&cfg, &info, stub, count, &clock, &mut proc, &cancelled);
            let cap = runner.setup_and_run().expect("stub run");
            // Observed records preserved (skipped record + finding
            // survive into the retained traversal outcome).
            let t = cap.traversal.as_ref().expect("traversal retained");
            assert_eq!(t.done.len(), 1);
            assert_eq!(t.findings.len(), 1);
            // Typed gaps present in the finalized document.
            for name in [
                "traversal.storm",
                "traversal.throttled",
                "traversal.finish_error",
                "traversal.incomplete",
                "traversal.unjoined",
            ] {
                let c = cap
                    .document
                    .counters
                    .iter()
                    .find(|c| c.name == name)
                    .unwrap_or_else(|| {
                        panic!(
                            "typed gap counter {name} missing: {:?}",
                            cap.document.counters
                        )
                    });
                assert_eq!(c.kind, CounterKind::Loss, "{name} forces PARTIAL");
                assert!(c.value > 0, "{name} is positive");
                assert!(
                    cap.document.reasons().iter().any(|r| matches!(
                        r,
                        GapReason::Loss { counter, .. } if counter == name
                    )),
                    "typed gap reason {name} missing: {:?}",
                    cap.document.reasons()
                );
            }
            assert!(
                matches!(cap.document.status, Completeness::Partial { .. }),
                "traversal losses partial the document: {:?}",
                cap.document.status
            );
        }

        #[test]
        fn owned_setup_skew_clamps_effective_start() {
            // R21-F4: owned setup does real work between the
            // kernel-window open and release (1.17–2.05 ms on
            // every live owned-run doc) — the document's
            // effective start must never predate the requested
            // start (the semantic validator's containment rule:
            // effective ⊆ requested). The ticking clock
            // reproduces the production skew deterministically.
            let cfg = stub_config();
            let mut info = stub_info();
            info.owned = true;
            let clock = TickClock {
                ns: Cell::new(5_000_000_000),
                step: 1_000_000,
                now: Cell::new(Instant::now()),
                wall: SystemTime::now(),
            };
            let mut proc = ProcStub;
            let cancelled = || false;
            let count = CountSession::new(TPID, FakeCountBackend::new());
            let runner = stub_runner(
                &cfg,
                &info,
                DiscoveryStub {
                    finish_err: false,
                    poll_err: false,
                    dispatch_attached: false,
                    trip_set: None,
                },
                count,
                &clock,
                &mut proc,
                &cancelled,
            );
            let cap = runner.setup_and_run().expect("stub run");
            let w = &cap.document.window;
            assert!(
                w.requested_start_ns > 5_000_000_000,
                "setup must consume ticks (skew premise): {w:?}"
            );
            assert!(
                w.effective_start_ns >= w.requested_start_ns,
                "effective start escapes the requested window: {w:?}"
            );
        }

        #[test]
        fn tiny_duration_setup_overrun_collapses_window_without_inversion() {
            // R21-F4 (round 2, residual E): an accepted tiny
            // --duration (1ns) with ordinary setup: setup consumes
            // the whole window (the kernel deadline predates the
            // requested start), so the capped effective end would
            // invert the window (schema rejects effective
            // inversion). The window must collapse honestly to the
            // empty window at the effective start (tail gap +
            // over-budget PARTIAL) and validate end to end.
            let mut cfg = stub_config();
            cfg.duration = Duration::from_nanos(1);
            let mut info = stub_info();
            info.owned = true;
            let clock = TickClock {
                ns: Cell::new(5_000_000_000),
                step: 1_000_000,
                now: Cell::new(Instant::now()),
                wall: SystemTime::now(),
            };
            let mut proc = ProcStub;
            let cancelled = || false;
            let count = CountSession::new(TPID, FakeCountBackend::new());
            let mut runner = stub_runner(
                &cfg,
                &info,
                DiscoveryStub {
                    finish_err: false,
                    poll_err: false,
                    dispatch_attached: false,
                    trip_set: None,
                },
                count,
                &clock,
                &mut proc,
                &cancelled,
            );
            // Production-faithful kernel deadline (run_observation
            // derives declared-start + duration; the stub default
            // would mask the overrun).
            runner.kernel_deadline_ns = 5_000_000_001;
            let cap = runner.setup_and_run().expect("stub run");
            let w = &cap.document.window;
            assert!(
                w.requested_start_ns > 5_000_000_001,
                "setup must outlast the 1ns window (overrun premise): {w:?}"
            );
            assert!(
                w.effective_start_ns <= w.effective_end_ns,
                "effective window inverted by setup overrun: {w:?}"
            );
            assert!(
                w.effective_start_ns >= w.requested_start_ns
                    && w.effective_end_ns <= w.requested_end_ns,
                "effective window escapes the requested window: {w:?}"
            );
            assert!(
                matches!(cap.document.status, Completeness::Partial { .. }),
                "overrun is an honest PARTIAL (tail gap + over-budget): {:?}",
                cap.document.status
            );
            // End-to-end: the collapsed document validates.
            let bytes = crate::report::render_json(&cap.document).unwrap();
            let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            crate::schema::validate_v2(&val).unwrap();
            crate::schema::check_v2_semantics(&val).unwrap();
        }

        #[test]
        fn traversal_gate_flags_agree_with_reasons() {
            // P1: the typed storm/throttle flags match exactly the
            // actions that earn the compat reasons (both derive
            // from the same backend actions — drift here would
            // split typed gaps from compat reasons).
            use crate::scan::oracle::Outcome;
            let clean = walk(
                1,
                Outcome::Complete {
                    true_t: 6,
                    cached: false,
                },
            );
            for actions in [
                vec![],
                vec![ScanAction::Detached],
                vec![ScanAction::SkipAllEngaged],
                vec![
                    ScanAction::Detached,
                    ScanAction::SkipAllEngaged,
                    ScanAction::Reattached,
                    ScanAction::SkipAllReleased,
                    ScanAction::CacheWarmed { arr: 1, t: 6 },
                ],
            ] {
                let (storm, throttled) = traversal_gate_flags(&actions);
                let reasons = traversal_reasons(&actions, &[clean.clone()], &[]);
                assert_eq!(
                    storm,
                    reasons.iter().any(|r| r == "traversal-storm"),
                    "storm flag ⟺ reason for {actions:?}"
                );
                assert_eq!(
                    throttled,
                    reasons.iter().any(|r| r == "traversal-throttled"),
                    "throttle flag ⟺ reason for {actions:?}"
                );
            }
        }

        #[test]
        fn traversal_reasons_map_loss_not_recovery() {
            // Storm/throttle/incomplete/unjoined earn PARTIAL
            // reasons; reattach/release/warm are recovery, never
            // loss; a clean complete poll earns nothing.
            use crate::scan::oracle::{Finding as OFinding, Outcome};
            let clean = walk(
                1,
                Outcome::Complete {
                    true_t: 6,
                    cached: false,
                },
            );
            assert!(traversal_reasons(&[], &[clean], &[]).is_empty());
            let stormy = traversal_reasons(
                &[
                    ScanAction::Detached,
                    ScanAction::Reattached,
                    ScanAction::CacheWarmed { arr: 1, t: 6 },
                ],
                &[walk(
                    2,
                    Outcome::Complete {
                        true_t: 6,
                        cached: true,
                    },
                )],
                &[],
            );
            assert_eq!(stormy, vec!["traversal-storm".to_string()]);
            let rough = traversal_reasons(
                &[ScanAction::SkipAllEngaged, ScanAction::SkipAllReleased],
                &[walk(3, Outcome::Skipped { cause: 1 })],
                &[OFinding::OrphanRet { tid: TPID, seq: 9 }],
            );
            assert_eq!(
                rough,
                vec![
                    "traversal-throttled".to_string(),
                    "traversal-incomplete".to_string(),
                    "traversal-unjoined".to_string(),
                ]
            );
        }

        #[test]
        fn run_traversal_refuses_roles_before_effects() {
            // Role-set refusal lands before any target side effect:
            // a bogus spawn that would fail at exec still reports
            // the role error (object resolution first — never a
            // silent harvest-only fallback, never the spawn error).
            let cfg = stub_config();
            let spawn = || Target::Spawn {
                argv: vec!["/nonexistent-target-xyz".to_string()],
                workload: target::WorkloadDest::Null,
            };
            let req = TraversalRequest {
                members_object: Some(PathBuf::from("/nonexistent/members.o")),
            };
            let err = run_traversal(&cfg, spawn(), &req).expect_err("bogus members must refuse");
            let msg = format!("{err:#}");
            assert!(msg.contains("explicit members object"), "unexpected: {msg}");
            let mut pair_cfg = stub_config();
            pair_cfg.harvest_object = Some(PathBuf::from("/nonexistent/harvest.o"));
            let err = run_traversal(&pair_cfg, spawn(), &TraversalRequest::default())
                .expect_err("bogus harvest must refuse");
            let msg = format!("{err:#}");
            assert!(msg.contains("explicit harvest object"), "unexpected: {msg}");
        }

        #[test]
        fn traversal_recycled_discards() {
            // Recycle discards pid-scoped traversal evidence like
            // the rest (tainted, never retained).
            let cfg = stub_config();
            let info = stub_info();
            let clock = ClockStub::at(5_000_000_000);
            let mut proc = ProcStub;
            let cancelled = || false;
            let count = CountSession::new(TPID, FakeCountBackend::new());
            let runner = stub_runner(
                &cfg,
                &info,
                TraversalStub::scripted(vec![], TraversalCapture::default()),
                count,
                &clock,
                &mut proc,
                &cancelled,
            );
            let cap = runner.recycled();
            assert!(cap.traversal.is_none());
            assert!(cap.reasons.iter().any(|r| r == "pid-recycled"));
        }

        #[test]
        fn traversal_capture_merge() {
            // Records append, end-state flags refresh, provenance
            // and finish-error fill once (first wins).
            use crate::scan::oracle::Outcome;
            let mut acc = TraversalCapture::default();
            acc.done.push(walk(
                1,
                Outcome::Complete {
                    true_t: 6,
                    cached: false,
                },
            ));
            acc.polls = 2;
            acc.throttled = true;
            let tail = TraversalCapture {
                provenance: Some(triple_prov()),
                done: vec![walk(
                    2,
                    Outcome::Complete {
                        true_t: 6,
                        cached: true,
                    },
                )],
                findings: vec![],
                polls: 1,
                corrections: vec![],
                admitted_by_op: std::collections::BTreeMap::new(),
                admitted_unknown_by_op: std::collections::BTreeSet::new(),
                census_loss: 0,
                throttled: false,
                detached: true,
                finish_error: Some("tail drained late".to_string()),
                storm_polls: 0,
                throttled_polls: 0,
            };
            acc.merge(tail);
            assert_eq!(
                acc.done.iter().map(|w| w.seq).collect::<Vec<_>>(),
                vec![1, 2]
            );
            assert_eq!(acc.polls, 3);
            assert!(!acc.throttled);
            assert!(acc.detached);
            assert_eq!(acc.provenance, Some(triple_prov()));
            assert_eq!(acc.finish_error.as_deref(), Some("tail drained late"));
            // Fill-once: a second tail does not overwrite.
            let tail2 = TraversalCapture {
                provenance: Some(TripleProvenance {
                    harvest: ObjectProvenance {
                        path: PathBuf::from("/other"),
                        sha256: "x".to_string(),
                    },
                    count: ObjectProvenance {
                        path: PathBuf::from("/other"),
                        sha256: "x".to_string(),
                    },
                    members: ObjectProvenance {
                        path: PathBuf::from("/other"),
                        sha256: "x".to_string(),
                    },
                }),
                finish_error: Some("second".to_string()),
                ..TraversalCapture::default()
            };
            acc.merge(tail2);
            assert_eq!(acc.provenance, Some(triple_prov()));
            assert_eq!(acc.finish_error.as_deref(), Some("tail drained late"));
        }

        #[test]
        fn traversal_capture_merge_applies_corrections() {
            // A tail carrying pending corrections rewrites the
            // accumulated held verdicts by key (salvage and
            // finish tails never strand a false verdict).
            use crate::scan::oracle::{Correction, Outcome};
            let mut acc = TraversalCapture::default();
            acc.done.push(walk(
                1,
                Outcome::Complete {
                    true_t: 6,
                    cached: false,
                },
            ));
            let tail = TraversalCapture {
                corrections: vec![Correction {
                    tid: TPID,
                    seq: 1,
                    outcome: Outcome::Tainted { by_seq: 2 },
                    op: crate::scan::oracle::UNKNOWN_OP,
                }],
                ..TraversalCapture::default()
            };
            acc.merge(tail);
            assert!(
                matches!(acc.done[0].outcome, Outcome::Tainted { by_seq: 2 }),
                "merged tail corrects the held verdict: {:?}",
                acc.done[0].outcome
            );
            assert_eq!(acc.done[0].op, crate::scan::oracle::UNKNOWN_OP);
        }

        struct TargetStub;
        impl TargetPort for TargetStub {
            fn pid(&self) -> u32 {
                TPID
            }
            fn is_owned(&self) -> bool {
                false
            }
            fn release(&mut self) -> anyhow::Result<()> {
                Ok(())
            }
            fn poll_exit(&mut self) -> anyhow::Result<Option<i32>> {
                Ok(None)
            }
            fn resolve_setup_failure(&mut self) -> anyhow::Result<()> {
                Ok(())
            }
            fn finish_observation(&mut self) -> anyhow::Result<target::TargetDisposition> {
                Ok(target::TargetDisposition::Detached { pid: TPID })
            }
            fn verify(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }

        struct LifecycleStub;
        impl LifecyclePort for LifecycleStub {
            fn poll(&mut self) -> LifecycleDelta {
                LifecycleDelta {
                    events: Vec::new(),
                    loss: 0,
                    dropped: 0,
                    prefix_unwitnessed: 0,
                    pending: 0,
                }
            }
            fn fallback_partial(&self) -> bool {
                false
            }
        }

        struct ClockStub {
            ns: Cell<u64>,
            now: Cell<Instant>,
            wall: SystemTime,
        }
        impl ClockStub {
            fn at(ns: u64) -> Self {
                Self {
                    ns: Cell::new(ns),
                    now: Cell::new(Instant::now()),
                    wall: SystemTime::now(),
                }
            }
        }
        /// Ticking test clock (R21-F4): every monotonic read
        /// advances time by `step` — production setup does real
        /// work between the kernel-window open and release (1–2 ms
        /// live), which the fixed ClockStub cannot reproduce.
        struct TickClock {
            ns: Cell<u64>,
            step: u64,
            now: Cell<Instant>,
            wall: SystemTime,
        }
        impl ClockPort for TickClock {
            fn monotonic_ns(&self) -> u64 {
                let v = self.ns.get();
                self.ns.set(v.saturating_add(self.step));
                v
            }
            fn now(&self) -> Instant {
                self.now.get()
            }
            fn wall_now(&self) -> SystemTime {
                self.wall
            }
            fn sleep(&self, d: Duration) {
                self.ns.set(
                    self.ns
                        .get()
                        .saturating_add(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)),
                );
                self.now.set(self.now.get() + d);
            }
        }

        impl ClockPort for ClockStub {
            fn monotonic_ns(&self) -> u64 {
                self.ns.get()
            }
            fn now(&self) -> Instant {
                self.now.get()
            }
            fn wall_now(&self) -> SystemTime {
                self.wall
            }
            fn sleep(&self, d: Duration) {
                self.ns.set(
                    self.ns
                        .get()
                        .saturating_add(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)),
                );
                self.now.set(self.now.get() + d);
            }
        }

        struct ProcStub;
        impl ProcPort for ProcStub {
            fn read_maps(&mut self, _pid: u32) -> anyhow::Result<Vec<maps::Mapping>> {
                Ok(Vec::new())
            }
            fn read_file(&mut self, _path: &str) -> anyhow::Result<Vec<u8>> {
                anyhow::bail!("unstubbed")
            }
            fn read_file_bound(
                &mut self,
                _path: &str,
                _max_bytes: usize,
            ) -> std::io::Result<(Arc<[u8]>, (u64, u64))> {
                Err(std::io::Error::new(std::io::ErrorKind::Other, "unstubbed"))
            }
            fn stat_file(&mut self, _path: &str) -> Option<FileStat> {
                None
            }
            fn read_exe(&mut self, _pid: u32) -> Option<PathBuf> {
                None
            }
            fn file_len(&mut self, _path: &str) -> Option<u64> {
                None
            }
            fn read_comm(&mut self, _pid: u32) -> Option<String> {
                None
            }
        }

        fn stub_config() -> Config {
            Config {
                harvest_object: None,
                count_object: None,
                members_object: None,
                provider: None,
                builtin: false,
                table: None,
                force_offset: None,
                provider_enrollment: None,
                resolved_provider: None,
                duration: Duration::from_secs(1),
                settle: Duration::ZERO,
                harvest_timeout: Duration::from_secs(5),
                grace: Duration::from_secs(1),
                image_digest: String::new(),
            }
        }

        fn stub_info() -> TargetInfo {
            TargetInfo {
                pid: TPID,
                owned: false,
                comm: "stub".to_string(),
                cmdline: String::new(),
                container_id: String::new(),
                kernel_release: String::new(),
                provider_build_id: String::new(),
                provider_path: String::new(),
                image_digest: String::new(),
                acquired_ns: 5_000_000_000,
                acquired_instant: Instant::now(),
                acquired_wall: SystemTime::now(),
            }
        }

        #[allow(clippy::too_many_arguments)]
        type StubRunner<'x> = Runner<
            'x,
            DiscoveryStub,
            FakeCountBackend,
            TargetStub,
            LifecycleStub,
            ClockStub,
            ProcStub,
        >;

        fn stub_runner<'x, D: DiscoveryPort, C: ClockPort>(
            cfg: &'x Config,
            info: &'x TargetInfo,
            discovery: D,
            count: CountSession<FakeCountBackend>,
            clock: &'x C,
            proc: &'x mut ProcStub,
            cancelled: &'x dyn Fn() -> bool,
        ) -> Runner<'x, D, FakeCountBackend, TargetStub, LifecycleStub, C, ProcStub> {
            let wall = clock.wall_now();
            Runner {
                cfg,
                info,
                discovery,
                count,
                target: TargetStub,
                lifecycle: LifecycleStub,
                clock,
                proc,
                cancelled,
                reasons: HashSet::new(),
                adapter: AdapterState::default(),
                activity: Vec::new(),
                extra_counters: Vec::new(),
                in_window_trip: HashMap::new(),
                in_window_hits: Vec::new(),
                in_window_lgcalls: 0,
                engine_collector: EngineCollector::new(),
                straddling_trip: HashMap::new(),
                straddling_lgcalls: 0,
                trigger_observed: false,
                attached_total: 0,
                cold_gap_queries: 0,
                fork_exec_ignored: 0,
                lifecycle_loss: 0,
                lifecycle_dropped: 0,
                lifecycle_prefix_unwitnessed: 0,
                lifecycle_no_witness: 0,
                lifecycle_pending: 0,
                lifecycle_exec_gap: 0,
                pending_exec_obligation: 0,
                maps_read_failed: 0,
                scan_budget_exhaustions: 0,
                provider_changed_fences: 0,
                planned_paths: HashSet::new(),
                site_cookies: HashMap::new(),
                seen_backings: HashSet::new(),
                snapshot: Snapshot::default(),
                last_live: Vec::new(),
                comm: info.comm.clone(),
                child_exit: None,
                reaped_before_close: false,
                signal_cut: false,
                expired: false,
                fallback_partial: false,
                window_start_ns: 5_000_000_000,
                requested_start_ns: 5_000_000_000,
                kernel_deadline_ns: 7_000_000_000,
                open_instant: clock.now(),
                wall_start: wall,
                wall_end: wall,
                drain_wall_us: 0,
                file_cache: HashMap::new(),
                relevance_capped: 0,
                unverified_reads: 0,
                observation_started: false,
                traversal: None,
            }
        }

        /// One attached site with 7 in-window calls: a real temp
        /// file carries the test binary's own ELF bytes (attach
        /// planning parses ELF and pins the path — zeros and fake
        /// paths never bind). The caller holds the file until the
        /// drain completes. Returns the file plus its (device, ino)
        /// identity for object/backing joins.
        fn seed_site(count: &mut CountSession<FakeCountBackend>) -> SeedFile {
            seed_site_as(count, "default").0
        }

        fn seed_site_as(
            count: &mut CountSession<FakeCountBackend>,
            class: &str,
        ) -> (SeedFile, (u64, u64)) {
            seed_site_candidates(
                count,
                vec![CandidateIdentity::new(
                    ObjectId("prov".to_string()),
                    class.to_string(),
                    1,
                    7,
                    vec!["digest".to_string()],
                    false,
                )],
            )
        }

        /// Seeded site with caller-chosen candidates (R02: MD5/weak
        /// and mixed-ambiguity seeds share the attach/drain path).
        fn seed_site_candidates(
            count: &mut CountSession<FakeCountBackend>,
            candidates: Vec<CandidateIdentity>,
        ) -> (SeedFile, (u64, u64)) {
            let bytes = std::fs::read(std::env::current_exe().unwrap()).unwrap();
            let off = x_offset(&bytes);
            let seed = SeedFile::fresh(&bytes);
            let (dev, ino) = seed.identity();
            let site = DiscoveredSite {
                site: SiteKey {
                    object: ObjectId("fp-A".to_string()),
                    device: dev,
                    inode: ino,
                    offset: off,
                },
                candidates,
                candidates_coverage: CandidateCoverage::Complete,
            };
            let live = vec![unit_mapping(
                &seed.path,
                &crate::plan::render_device(dev),
                ino,
                0x7f00_0000_0000,
                true,
            )];
            let files = HashMap::from([(
                seed.path.clone(),
                crate::plan::FileBytes {
                    bytes: bytes.into(),
                    dev,
                    ino,
                },
            )]);
            let delta = CountDelta {
                discovered: vec![site],
                losses: Vec::new(),
            };
            count
                .attach_delta(&delta, &live, &files, ATTACH_AT)
                .unwrap();
            let cookie = count.cookie_for(dev, ino, off).unwrap();
            count.open_window(1000, 2000).unwrap();
            count.backend_mut().fire(TPID, cookie, 1500, 7);
            (seed, (dev, ino))
        }

        fn counter(doc: &CaptureDocument, name: &str) -> u64 {
            doc.counters
                .iter()
                .find(|c| c.name == name)
                .map(|c| c.value)
                .unwrap_or(0)
        }

        #[test]
        fn engine_observations_join_binding_and_registry() {
            // R05: per-(generation, cookie) counts join their
            // generation's probe meanings plus each probe module's
            // own pinned identity; other planes skip silently,
            // unjoinable ENGINE counts go loud via the unkeyed
            // tally. F-R05-1: the caller's stub never resolves to
            // libcrypto even when libcrypto is the only other
            // registered object.
            let cfg = stub_config();
            let info = stub_info();
            let clock = ClockStub::at(1_500);
            let mut proc = ProcStub;
            let cancelled = || false;
            let count = CountSession::new(TPID, FakeCountBackend::new());
            let mut runner = stub_runner(
                &cfg,
                &info,
                DiscoveryStub {
                    finish_err: false,
                    poll_err: false,
                    dispatch_attached: false,
                    trip_set: None,
                },
                count,
                &clock,
                &mut proc,
                &cancelled,
            );
            let device = plan::device_id_of_dev_str("08:01").unwrap();
            runner.adapter.objects.push(ObjectRecord {
                id: ObjectId("build:caller".to_string()),
                device,
                inode: 200,
                display_locator: "/app/caller.so".to_string(),
            });
            // B-5 double: the same file under an unverified id
            // must lose to the verified one.
            runner.adapter.objects.push(ObjectRecord {
                id: ObjectId("unverified:08:01:200".to_string()),
                device,
                inode: 200,
                display_locator: "/app/caller.so".to_string(),
            });
            // libcrypto registered but never the caller stub's home.
            runner.adapter.objects.push(ObjectRecord {
                id: ObjectId("build:lc".to_string()),
                device,
                inode: 100,
                display_locator: "/lib/libcrypto.so.3".to_string(),
            });
            let probe = |cookie: u64, symbol: &str, offset: u64| legacy::Probe {
                cookie,
                symbol: symbol.to_string(),
                offset,
                module: "/app/caller.so".to_string(),
                family: None,
                str_arg: None,
                program: "trip_count",
            };
            let mut set = legacy::ProbeSet::default();
            set.probes = vec![
                probe(7, "ENGINE_init", 0x100),
                probe(8, "ENGINE_init", 0x200),
                probe(9, "RSA_meth_new", 0x300),
            ];
            set.libcrypto = Some(("/lib/libcrypto.so.3".to_string(), "08:01".to_string(), 100));
            runner.engine_collector.snapshot_binding(
                0,
                Some(set),
                &[crate::discovery::session::TripModulePin {
                    module: "/app/caller.so".to_string(),
                    program: "trip_count".to_string(),
                    dev: "08:01".to_string(),
                    ino: 200,
                }],
            );
            runner
                .engine_collector
                .accumulate(0, &[(7, 3), (8, 5), (9, 11), (77, 13)], &[]);
            runner.engine_collector.accumulate(1, &[(7, 17)], &[]);
            let (obs, unkeyed) = runner.build_engine_observations();
            // Meth plane skips silently; unknown cookie (13) and
            // unknown generation (17) go loud.
            assert_eq!(unkeyed, 30);
            assert_eq!(obs.len(), 2);
            assert_eq!(obs[0].calls, 3);
            assert_eq!(obs[0].key.offset, 0x100);
            assert_eq!(obs[1].calls, 5);
            assert_eq!(obs[1].key.offset, 0x200);
            for o in &obs {
                assert_eq!(o.key.object.0, "build:caller");
                assert_eq!(o.key.device, device);
                assert_eq!(o.key.inode, 200);
                assert_eq!(o.generation, 0);
                assert_eq!(o.entrypoint, evidence::engine_index("ENGINE_init").unwrap());
                assert_eq!(o.window, EngineWindow::InWindow);
            }
        }

        #[test]
        fn engine_observations_keep_caller_identities_distinct() {
            // F-R05-1: two callers with the same entrypoint and stub
            // offset keep distinct observation keys (their own
            // pinned modules) instead of collapsing onto libcrypto.
            let cfg = stub_config();
            let info = stub_info();
            let clock = ClockStub::at(1_500);
            let mut proc = ProcStub;
            let cancelled = || false;
            let count = CountSession::new(TPID, FakeCountBackend::new());
            let mut runner = stub_runner(
                &cfg,
                &info,
                DiscoveryStub {
                    finish_err: false,
                    poll_err: false,
                    dispatch_attached: false,
                    trip_set: None,
                },
                count,
                &clock,
                &mut proc,
                &cancelled,
            );
            let device = plan::device_id_of_dev_str("08:01").unwrap();
            for (id, ino, path) in [
                ("build:a", 201, "/app/a.so"),
                ("build:b", 202, "/app/b.so"),
                ("build:lc", 100, "/lib/libcrypto.so.3"),
            ] {
                runner.adapter.objects.push(ObjectRecord {
                    id: ObjectId(id.to_string()),
                    device,
                    inode: ino,
                    display_locator: path.to_string(),
                });
            }
            let mut set = legacy::ProbeSet::default();
            set.probes = vec![
                legacy::Probe {
                    cookie: 7,
                    symbol: "ENGINE_init".to_string(),
                    offset: 0x100,
                    module: "/app/a.so".to_string(),
                    family: None,
                    str_arg: None,
                    program: "trip_count",
                },
                legacy::Probe {
                    cookie: 8,
                    symbol: "ENGINE_init".to_string(),
                    offset: 0x100,
                    module: "/app/b.so".to_string(),
                    family: None,
                    str_arg: None,
                    program: "trip_count",
                },
            ];
            set.libcrypto = Some(("/lib/libcrypto.so.3".to_string(), "08:01".to_string(), 100));
            runner.engine_collector.snapshot_binding(
                0,
                Some(set),
                &[
                    crate::discovery::session::TripModulePin {
                        module: "/app/a.so".to_string(),
                        program: "trip_count".to_string(),
                        dev: "08:01".to_string(),
                        ino: 201,
                    },
                    crate::discovery::session::TripModulePin {
                        module: "/app/b.so".to_string(),
                        program: "trip_count".to_string(),
                        dev: "08:01".to_string(),
                        ino: 202,
                    },
                ],
            );
            runner
                .engine_collector
                .accumulate(0, &[(7, 3), (8, 5)], &[]);
            let (obs, unkeyed) = runner.build_engine_observations();
            assert_eq!(unkeyed, 0);
            assert_eq!(obs.len(), 2);
            assert_ne!(obs[0].key, obs[1].key);
            for o in &obs {
                assert_ne!(o.key.inode, 100, "must not collapse onto libcrypto");
            }
            let inos: Vec<u64> = obs.iter().map(|o| o.key.inode).collect();
            assert!(inos.contains(&201) && inos.contains(&202));
        }

        #[test]
        fn engine_observations_attribute_per_program_binding() {
            // Fix-round-2 F1 RED: the pin-collapse schedule — one
            // pathname bound through two (module, program) groups
            // (`trip_count` through inode A, `trip_str0` through
            // inode B after a pathname replacement). Each cookie
            // must attribute to its own group's inode; attributing
            // both to one collapses distinct bindings.
            let cfg = stub_config();
            let info = stub_info();
            let clock = ClockStub::at(1_500);
            let mut proc = ProcStub;
            let cancelled = || false;
            let count = CountSession::new(TPID, FakeCountBackend::new());
            let mut runner = stub_runner(
                &cfg,
                &info,
                DiscoveryStub {
                    finish_err: false,
                    poll_err: false,
                    dispatch_attached: false,
                    trip_set: None,
                },
                count,
                &clock,
                &mut proc,
                &cancelled,
            );
            let device = plan::device_id_of_dev_str("08:01").unwrap();
            for (id, ino) in [("build:a", 300), ("build:b", 301)] {
                runner.adapter.objects.push(ObjectRecord {
                    id: ObjectId(id.to_string()),
                    device,
                    inode: ino,
                    display_locator: "/app/target".to_string(),
                });
            }
            let mut set = legacy::ProbeSet::default();
            set.probes = vec![
                legacy::Probe {
                    cookie: 7,
                    symbol: "ENGINE_init".to_string(),
                    offset: 0x100,
                    module: "/app/target".to_string(),
                    family: None,
                    str_arg: None,
                    program: "trip_count",
                },
                legacy::Probe {
                    cookie: 8,
                    symbol: "ENGINE_by_id".to_string(),
                    offset: 0x200,
                    module: "/app/target".to_string(),
                    family: None,
                    str_arg: Some(0),
                    program: "trip_str0",
                },
            ];
            set.libcrypto = Some(("/lib/libcrypto.so.3".to_string(), "08:01".to_string(), 100));
            runner.engine_collector.snapshot_binding(
                0,
                Some(set),
                &[
                    crate::discovery::session::TripModulePin {
                        module: "/app/target".to_string(),
                        program: "trip_count".to_string(),
                        dev: "08:01".to_string(),
                        ino: 300,
                    },
                    crate::discovery::session::TripModulePin {
                        module: "/app/target".to_string(),
                        program: "trip_str0".to_string(),
                        dev: "08:01".to_string(),
                        ino: 301,
                    },
                ],
            );
            runner
                .engine_collector
                .accumulate(0, &[(7, 3), (8, 5)], &[]);
            let (obs, unkeyed) = runner.build_engine_observations();
            assert_eq!(unkeyed, 0);
            assert_eq!(obs.len(), 2);
            let by_offset = |off: u64| {
                obs.iter()
                    .find(|o| o.key.offset == off)
                    .unwrap_or_else(|| panic!("missing observation at {off:#x}: {obs:?}"))
                    .key
                    .inode
            };
            assert_eq!(by_offset(0x100), 300, "trip_count cookie joins inode A");
            assert_eq!(by_offset(0x200), 301, "trip_str0 cookie joins inode B");
        }

        #[test]
        fn engine_deferred_first_install_snapshots_meanings() {
            // F-R05-2 RED: deferred first install stays generation 0.
            // A gen-0 poll with no probe set must not consume the
            // generation; the deferred gen-0 bind must still snapshot
            // its meanings so its counts become observations.
            let cfg = stub_config();
            let info = stub_info();
            let clock = ClockStub::at(1_500);
            let mut proc = ProcStub;
            let cancelled = || false;
            let count = CountSession::new(TPID, FakeCountBackend::new());
            let mut runner = stub_runner(
                &cfg,
                &info,
                DiscoveryStub {
                    finish_err: false,
                    poll_err: false,
                    dispatch_attached: false,
                    trip_set: None,
                },
                count,
                &clock,
                &mut proc,
                &cancelled,
            );
            let device = plan::device_id_of_dev_str("08:01").unwrap();
            runner.adapter.objects.push(ObjectRecord {
                id: ObjectId("build:caller".to_string()),
                device,
                inode: 200,
                display_locator: "/app/caller.so".to_string(),
            });
            let live: Vec<maps::Mapping> = Vec::new();
            let files: HashMap<String, plan::FileBytes> = HashMap::new();
            let fresh: HashSet<(String, u64)> = HashSet::new();
            // Poll 1: generation 0, no probe set yet (deferred).
            let d1 = DiscoveryDelta {
                trip_generation: 0,
                ..DiscoveryDelta::default()
            };
            let ctx = AdapterCtx {
                live: &live,
                files: &files,
                pinned_provider: None,
                fresh: &fresh,
                post_settle: false,
                baseline: false,
                post_release: false,
            };
            runner
                .apply_delta(&d1, clock.now(), &ctx, None)
                .expect("poll 1 applies");
            // Poll 2: deferred bind arrives, still generation 0, with
            // five in-window hits on cookie 7.
            let mut set = legacy::ProbeSet::default();
            set.probes = vec![legacy::Probe {
                cookie: 7,
                symbol: "ENGINE_init".to_string(),
                offset: 0x100,
                module: "/app/caller.so".to_string(),
                family: None,
                str_arg: None,
                program: "trip_count",
            }];
            set.libcrypto = Some(("/lib/libcrypto.so.3".to_string(), "08:01".to_string(), 100));
            runner.discovery.trip_set = Some(set);
            let d2 = DiscoveryDelta {
                trip_generation: 0,
                trip_module_pins: vec![crate::discovery::session::TripModulePin {
                    module: "/app/caller.so".to_string(),
                    program: "trip_count".to_string(),
                    dev: "08:01".to_string(),
                    ino: 200,
                }],
                tripwire: crate::discovery::session::TripwireDelta {
                    hits: Vec::new(),
                    counter_deltas: vec![(7, 5)],
                    executed_legacy_queries_delta: 0,
                },
                ..DiscoveryDelta::default()
            };
            let ctx2 = AdapterCtx {
                live: &live,
                files: &files,
                pinned_provider: None,
                fresh: &fresh,
                post_settle: false,
                baseline: false,
                post_release: false,
            };
            runner
                .apply_delta(&d2, clock.now(), &ctx2, None)
                .expect("poll 2 applies");
            let (obs, unkeyed) = runner.build_engine_observations();
            assert_eq!(unkeyed, 0, "deferred counts must key, not go unkeyed");
            assert_eq!(obs.len(), 1);
            assert_eq!(obs[0].calls, 5);
            assert_eq!(obs[0].generation, 0);
        }

        #[test]
        fn engine_replacement_keeps_retired_counts_on_old_generation() {
            // F-R05-3: replacement poll carries retired gen-0 news
            // plus the live gen-1 binding. Retired counts join gen
            // 0's probe meanings; nothing joins gen 1 without new
            // hits. Drives real `apply_delta` transitions (snapshot
            // + accumulate), not direct map inserts.
            let cfg = stub_config();
            let info = stub_info();
            let clock = ClockStub::at(1_500);
            let mut proc = ProcStub;
            let cancelled = || false;
            let count = CountSession::new(TPID, FakeCountBackend::new());
            let mut runner = stub_runner(
                &cfg,
                &info,
                DiscoveryStub {
                    finish_err: false,
                    poll_err: false,
                    dispatch_attached: false,
                    trip_set: None,
                },
                count,
                &clock,
                &mut proc,
                &cancelled,
            );
            let device = plan::device_id_of_dev_str("08:01").unwrap();
            runner.adapter.objects.push(ObjectRecord {
                id: ObjectId("build:caller".to_string()),
                device,
                inode: 200,
                display_locator: "/app/caller.so".to_string(),
            });
            let live: Vec<maps::Mapping> = Vec::new();
            let files: HashMap<String, plan::FileBytes> = HashMap::new();
            let fresh: HashSet<(String, u64)> = HashSet::new();
            let ctx_for = || AdapterCtx {
                live: &live,
                files: &files,
                pinned_provider: None,
                fresh: &fresh,
                post_settle: false,
                baseline: false,
                post_release: false,
            };
            let pins = || {
                vec![crate::discovery::session::TripModulePin {
                    module: "/app/caller.so".to_string(),
                    program: "trip_count".to_string(),
                    dev: "08:01".to_string(),
                    ino: 200,
                }]
            };
            let set_at = |off: u64| {
                let mut set = legacy::ProbeSet::default();
                set.probes = vec![legacy::Probe {
                    cookie: 7,
                    symbol: "ENGINE_init".to_string(),
                    offset: off,
                    module: "/app/caller.so".to_string(),
                    family: None,
                    str_arg: None,
                    program: "trip_count",
                }];
                set.libcrypto = Some(("/lib/libcrypto.so.3".to_string(), "08:01".to_string(), 100));
                set
            };
            // Poll 1: gen 0 binds (snapshot meanings + pins).
            runner.discovery.trip_set = Some(set_at(0x100));
            let d1 = DiscoveryDelta {
                trip_generation: 0,
                trip_module_pins: pins(),
                ..DiscoveryDelta::default()
            };
            runner
                .apply_delta(&d1, clock.now(), &ctx_for(), None)
                .expect("poll 1 applies");
            // Poll 2: replacement to gen 1; five unread gen-0 hits
            // fence as retired; zero new hits under gen 1.
            runner.discovery.trip_set = Some(set_at(0x110));
            let d2 = DiscoveryDelta {
                trip_generation: 1,
                trip_module_pins: pins(),
                retired_trip_deltas: vec![crate::discovery::session::RetiredTripDelta {
                    generation: 0,
                    cookie: 7,
                    count: 5,
                }],
                ..DiscoveryDelta::default()
            };
            runner
                .apply_delta(&d2, clock.now(), &ctx_for(), None)
                .expect("poll 2 applies");
            let (obs, unkeyed) = runner.build_engine_observations();
            assert_eq!(unkeyed, 0);
            assert_eq!(obs.len(), 1);
            assert_eq!(obs[0].generation, 0);
            assert_eq!(obs[0].key.offset, 0x100);
            assert_eq!(obs[0].calls, 5);
            // Legacy parity: the retired hits still count cookie-wise.
            assert_eq!(runner.in_window_trip.get(&7), Some(&5));
        }

        #[test]
        fn engine_runtime_salvage_keeps_real_observations() {
            // F-R05-5: real controller salvage. Real `apply_delta`
            // transitions collect ENGINE observations, then a real
            // close failure salvages them into a fatal-Runtime
            // capture (not a hand-built doc). Policy still proves
            // the violation from the salvaged observations.
            let cfg = stub_config();
            let info = stub_info();
            let clock = ClockStub::at(1_500);
            let mut proc = ProcStub;
            let cancelled = || false;
            let count = CountSession::new(TPID, FakeCountBackend::new());
            let mut runner = stub_runner(
                &cfg,
                &info,
                DiscoveryStub {
                    finish_err: true,
                    poll_err: false,
                    dispatch_attached: false,
                    trip_set: None,
                },
                count,
                &clock,
                &mut proc,
                &cancelled,
            );
            let device = plan::device_id_of_dev_str("08:01").unwrap();
            runner.adapter.objects.push(ObjectRecord {
                id: ObjectId("build:caller".to_string()),
                device,
                inode: 200,
                display_locator: "/app/caller.so".to_string(),
            });
            let mut set = legacy::ProbeSet::default();
            set.probes = vec![legacy::Probe {
                cookie: 7,
                symbol: "ENGINE_init".to_string(),
                offset: 0x100,
                module: "/app/caller.so".to_string(),
                family: None,
                str_arg: None,
                program: "trip_count",
            }];
            set.libcrypto = Some(("/lib/libcrypto.so.3".to_string(), "08:01".to_string(), 100));
            runner.discovery.trip_set = Some(set);
            let live: Vec<maps::Mapping> = Vec::new();
            let files: HashMap<String, plan::FileBytes> = HashMap::new();
            let fresh: HashSet<(String, u64)> = HashSet::new();
            let delta = DiscoveryDelta {
                trip_generation: 0,
                trip_module_pins: vec![crate::discovery::session::TripModulePin {
                    module: "/app/caller.so".to_string(),
                    program: "trip_count".to_string(),
                    dev: "08:01".to_string(),
                    ino: 200,
                }],
                tripwire: crate::discovery::session::TripwireDelta {
                    hits: Vec::new(),
                    counter_deltas: vec![(7, 7)],
                    executed_legacy_queries_delta: 0,
                },
                ..DiscoveryDelta::default()
            };
            let ctx = AdapterCtx {
                live: &live,
                files: &files,
                pinned_provider: None,
                fresh: &fresh,
                post_settle: false,
                baseline: false,
                post_release: false,
            };
            runner
                .apply_delta(&delta, clock.now(), &ctx, None)
                .expect("collect applies");
            let cap = runner
                .close_and_finalize()
                .expect("close failure must salvage, not Err");
            assert!(
                matches!(
                    cap.document.status,
                    Completeness::Fatal {
                        kind: evidence::FatalKind::Runtime(_),
                        ..
                    }
                ),
                "want salvaged Runtime, got {:?}",
                cap.document.status
            );
            assert_eq!(cap.document.engine_observations.len(), 1);
            assert_eq!(cap.document.engine_observations[0].calls, 7);
            let v = crate::policy::evaluate_document(
                std::slice::from_ref(&crate::policy::PolicyRule::deny_engine()),
                &cap.document,
            );
            assert_eq!(v.overall(), crate::policy::PolicyOutcome::Violation);
            assert_eq!(v.rules[0].bounds.definite, 7);
            assert_eq!(v.rules[0].engine_hits.len(), 1);
        }

        #[test]
        fn h7_close_finish_error_salvages_sites() {
            // T1a (RED): discovery.finish fails AFTER the drain
            // succeeded — the observed sites must survive in a
            // salvaged capture, not vanish into an Err.
            let cfg = stub_config();
            let info = stub_info();
            let clock = ClockStub::at(1_500);
            let mut proc = ProcStub;
            let cancelled = || false;
            let mut count = CountSession::new(TPID, FakeCountBackend::new());
            let _seed = seed_site(&mut count);
            let runner = stub_runner(
                &cfg,
                &info,
                DiscoveryStub {
                    finish_err: true,
                    poll_err: false,
                    dispatch_attached: false,
                    trip_set: None,
                },
                count,
                &clock,
                &mut proc,
                &cancelled,
            );
            let cap = runner
                .close_and_finalize()
                .expect("H7: finish error must salvage, not Err");
            assert_eq!(cap.document.sites.len(), 1);
            assert_eq!(cap.document.sites[0].calls, 7);
            assert!(cap.reasons.iter().any(|r| r == "close-failure"));
            // Fatal kind + message (RED: no Runtime variant yet).
            let detail = match &cap.document.status {
                Completeness::Fatal {
                    kind: evidence::FatalKind::Runtime(detail),
                    ..
                } => detail.clone(),
                other => panic!("want Fatal(Runtime), got {other:?}"),
            };
            assert!(
                detail.contains("discovery finish"),
                "unexpected detail: {detail}"
            );
            // Counts are intact on this path (the drain succeeded),
            // so surviving sites stay Complete — T3-reachable.
            assert_eq!(
                cap.document.sites[0].candidates_coverage,
                CandidateCoverage::Complete
            );
        }

        #[test]
        fn h7_close_drain_error_salvages_without_sites() {
            // T1b (RED): close_and_drain fails (here: the session was
            // already drained — the same Err arm a real close I/O
            // error takes) — salvage keeps the loss explicit, with
            // no sites (the drain is gone) and a typed loss counter.
            let cfg = stub_config();
            let info = stub_info();
            let clock = ClockStub::at(1_500);
            let mut proc = ProcStub;
            let cancelled = || false;
            let mut count = CountSession::new(TPID, FakeCountBackend::new());
            let _seed = seed_site(&mut count);
            count.close_and_drain(Duration::from_secs(1)).unwrap();
            let runner = stub_runner(
                &cfg,
                &info,
                DiscoveryStub {
                    finish_err: false,
                    poll_err: false,
                    dispatch_attached: false,
                    trip_set: None,
                },
                count,
                &clock,
                &mut proc,
                &cancelled,
            );
            let cap = runner
                .close_and_finalize()
                .expect("H7: drain error must salvage, not Err");
            assert!(cap.document.sites.is_empty());
            assert_eq!(counter(&cap.document, "count.close_failed"), 1);
            assert!(cap.reasons.iter().any(|r| r == "close-failure"));
        }

        #[test]
        fn h7_double_close_failure_salvages_once() {
            // T5 (RED): drain AND finish both fail — one salvaged
            // capture, both losses recorded, no double-close cascade.
            let cfg = stub_config();
            let info = stub_info();
            let clock = ClockStub::at(1_500);
            let mut proc = ProcStub;
            let cancelled = || false;
            let mut count = CountSession::new(TPID, FakeCountBackend::new());
            let _seed = seed_site(&mut count);
            count.close_and_drain(Duration::from_secs(1)).unwrap();
            let runner = stub_runner(
                &cfg,
                &info,
                DiscoveryStub {
                    finish_err: true,
                    poll_err: false,
                    dispatch_attached: false,
                    trip_set: None,
                },
                count,
                &clock,
                &mut proc,
                &cancelled,
            );
            let cap = runner
                .close_and_finalize()
                .expect("H7: double close error must salvage once, not Err");
            assert!(cap.document.sites.is_empty());
            assert_eq!(counter(&cap.document, "count.close_failed"), 1);
            assert_eq!(counter(&cap.document, "discovery.finish_failed"), 1);
            assert!(cap.reasons.iter().any(|r| r == "close-failure"));
        }

        #[test]
        fn h7_setup_poll_error_stays_err() {
            // T1f (PIN, green now): pre-observation failures keep the
            // setup shape — Err out of setup_and_run, exit 4 at the
            // CLI — even after H7.
            let cfg = stub_config();
            let info = stub_info();
            let clock = ClockStub::at(5_000_000_000);
            let mut proc = ProcStub;
            let cancelled = || false;
            let count = CountSession::new(TPID, FakeCountBackend::new());
            let runner = stub_runner(
                &cfg,
                &info,
                DiscoveryStub {
                    finish_err: false,
                    poll_err: true,
                    dispatch_attached: false,
                    trip_set: None,
                },
                count,
                &clock,
                &mut proc,
                &cancelled,
            );
            let err = runner
                .setup_and_run()
                .expect_err("setup poll must stay Err");
            assert!(
                format!("{err:#}").contains("setup discovery poll"),
                "unexpected: {err:#}"
            );
        }

        #[test]
        fn h7_setup_and_run_finish_error_salvages() {
            // T1e (RED): end-to-end bit wiring — a full setup_and_run
            // whose discovery.finish fails must salvage (proving the
            // observation bit was set by the loop, not by hand).
            let cfg = stub_config();
            let info = stub_info();
            let clock = ClockStub::at(5_000_000_000);
            let mut proc = ProcStub;
            let cancelled = || false;
            let count = CountSession::new(TPID, FakeCountBackend::new());
            let runner = stub_runner(
                &cfg,
                &info,
                DiscoveryStub {
                    finish_err: true,
                    poll_err: false,
                    dispatch_attached: false,
                    trip_set: None,
                },
                count,
                &clock,
                &mut proc,
                &cancelled,
            );
            let cap = runner
                .setup_and_run()
                .expect("H7: mid-run finish error must salvage, not Err");
            assert!(cap.reasons.iter().any(|r| r == "close-failure"));
        }

        fn dispatch_expected(doc: &CaptureDocument) -> ExpectedScope {
            doc.coverage
                .iter()
                .find(|c| c.scope == "dispatch")
                .unwrap_or_else(|| panic!("want a dispatch row: {:?}", doc.coverage))
                .expected
        }

        #[test]
        fn h7_clean_close_keeps_dispatch_applicable() {
            // T4 control (green now): an attached dispatch anchor
            // with a clean close claims Applicable — the baseline
            // the taint test below inverts.
            let cfg = stub_config();
            let info = stub_info();
            let clock = ClockStub::at(1_500);
            let mut proc = ProcStub;
            let cancelled = || false;
            let mut count = CountSession::new(TPID, FakeCountBackend::new());
            let _seed = seed_site(&mut count);
            let runner = stub_runner(
                &cfg,
                &info,
                DiscoveryStub {
                    finish_err: false,
                    poll_err: false,
                    dispatch_attached: true,
                    trip_set: None,
                },
                count,
                &clock,
                &mut proc,
                &cancelled,
            );
            let cap = runner.close_and_finalize().expect("clean close");
            assert_eq!(
                dispatch_expected(&cap.document),
                ExpectedScope::Applicable { sites: 1 }
            );
        }

        #[test]
        fn h7_drain_error_taints_coverage_unknown() {
            // T4 (RED): a close_and_drain error feeds H2's
            // close-evidence taint — surviving coverage denominators
            // go Unknown (a failed close may hide tails).
            let cfg = stub_config();
            let info = stub_info();
            let clock = ClockStub::at(1_500);
            let mut proc = ProcStub;
            let cancelled = || false;
            let mut count = CountSession::new(TPID, FakeCountBackend::new());
            let _seed = seed_site(&mut count);
            count.close_and_drain(Duration::from_secs(1)).unwrap();
            let runner = stub_runner(
                &cfg,
                &info,
                DiscoveryStub {
                    finish_err: false,
                    poll_err: false,
                    dispatch_attached: true,
                    trip_set: None,
                },
                count,
                &clock,
                &mut proc,
                &cancelled,
            );
            let cap = runner
                .close_and_finalize()
                .expect("H7: drain error must salvage, not Err");
            assert_eq!(dispatch_expected(&cap.document), ExpectedScope::Unknown);
        }

        #[test]
        fn h7_fail_before_observation_stays_err() {
            // PIN: fail() with the observation bit clear keeps the
            // setup shape — Err with cleanup failures chained, never
            // a salvaged doc.
            let cfg = stub_config();
            let info = stub_info();
            let clock = ClockStub::at(1_500);
            let mut proc = ProcStub;
            let cancelled = || false;
            let count = CountSession::new(TPID, FakeCountBackend::new());
            let runner = stub_runner(
                &cfg,
                &info,
                DiscoveryStub {
                    finish_err: false,
                    poll_err: false,
                    dispatch_attached: false,
                    trip_set: None,
                },
                count,
                &clock,
                &mut proc,
                &cancelled,
            );
            let err = runner
                .fail(anyhow::anyhow!("poll_exit: boom"))
                .expect_err("pre-observation fail must stay Err");
            assert!(
                format!("{err:#}").contains("poll_exit: boom"),
                "unexpected: {err:#}"
            );
        }

        #[test]
        fn h7_fail_after_observation_salvages() {
            // RED (compile: no bit yet): fail() with the observation
            // bit set salvages into a fatal-Runtime capture.
            let cfg = stub_config();
            let info = stub_info();
            let clock = ClockStub::at(1_500);
            let mut proc = ProcStub;
            let cancelled = || false;
            let count = CountSession::new(TPID, FakeCountBackend::new());
            let mut runner = stub_runner(
                &cfg,
                &info,
                DiscoveryStub {
                    finish_err: false,
                    poll_err: false,
                    dispatch_attached: false,
                    trip_set: None,
                },
                count,
                &clock,
                &mut proc,
                &cancelled,
            );
            runner.observation_started = true;
            let cap = runner
                .fail(anyhow::anyhow!("poll_exit: boom"))
                .expect("H7: post-observation fail must salvage, not Err");
            assert!(
                matches!(
                    cap.document.status,
                    Completeness::Fatal {
                        kind: evidence::FatalKind::Runtime(_),
                        ..
                    }
                ),
                "unexpected: {:?}",
                cap.document.status
            );
            assert!(cap.reasons.iter().any(|r| r == "close-failure"));
        }

        const LEG_DEV: u64 = (8 << 32) | 1;
        const LEG_INO: u64 = 101;
        const LIB_INO: u64 = 202;

        fn h8_cand(class: &str) -> CandidateIdentity {
            CandidateIdentity::new(
                ObjectId("prov".to_string()),
                class.to_string(),
                1,
                7,
                vec!["digest".to_string()],
                false,
            )
        }

        fn h8_site(dev: u64, ino: u64, off: u64, calls: u64, classes: &[&str]) -> SiteExecution {
            SiteExecution {
                site: SiteKey {
                    object: ObjectId("fp".to_string()),
                    device: dev,
                    inode: ino,
                    offset: off,
                },
                generation: 0,
                candidates: classes.iter().map(|c| h8_cand(c)).collect(),
                candidates_coverage: CandidateCoverage::Complete,
                calls,
                first_ns: 100,
                last_ns: 200,
                installed_at: None,
            }
        }

        fn h8_legacy_files() -> HashSet<(u64, u64)> {
            HashSet::from([(LEG_DEV, LEG_INO)])
        }

        #[test]
        fn h8_partition_three_buckets() {
            // T1 (RED): exclusive (all-legacy + legacy-backed),
            // shared by mixed classes, shared by libcrypto backing
            // despite all-legacy candidates, non-legacy (no legacy).
            let sites = vec![
                h8_site(LEG_DEV, LEG_INO, 0x100, 7, &["legacy"]),
                h8_site(LEG_DEV, LEG_INO, 0x200, 3, &["legacy", "default"]),
                h8_site(LEG_DEV, LIB_INO, 0x300, 5, &["legacy"]),
                h8_site(LEG_DEV, LIB_INO, 0x400, 11, &["default"]),
            ];
            let p = partition_calls(&sites, &[], &h8_legacy_files());
            assert_eq!(p.legacy_exclusive, 7);
            assert_eq!(p.shared_ambiguous, 8);
            assert_eq!(p.non_legacy_exclusive, 11);
            assert_eq!(p.unfenced_tails, 0);
        }

        #[test]
        fn h8_partition_conserves_fenced_pair() {
            // T2a (RED): conservation across a current + fenced pair;
            // zero-candidate sites land unfenced-tails (no key).
            let current = vec![h8_site(LEG_DEV, LEG_INO, 0x100, 7, &["legacy"])];
            let fenced = vec![FencedGeneration {
                generation: 0,
                sites: vec![
                    h8_site(LEG_DEV, LEG_INO, 0x100, 4, &["legacy"]),
                    h8_site(LEG_DEV, LIB_INO, 0x300, 6, &[]),
                ],
            }];
            let p = partition_calls(&current, &fenced, &h8_legacy_files());
            assert_eq!(p.legacy_exclusive, 11);
            assert_eq!(p.unfenced_tails, 6);
            assert_eq!(
                p.legacy_exclusive + p.non_legacy_exclusive + p.shared_ambiguous + p.unfenced_tails,
                17
            );
        }

        #[test]
        fn h8_partition_default_heavy_is_zero() {
            // T4a (RED): no legacy candidates and no legacy files.
            let sites = vec![h8_site(LEG_DEV, LIB_INO, 0x100, 9, &["default"])];
            let p = partition_calls(&sites, &[], &HashSet::new());
            assert_eq!(p.legacy_exclusive, 0);
            assert_eq!(p.shared_ambiguous, 0);
            assert_eq!(p.non_legacy_exclusive, 9);
        }

        #[test]
        fn h8_close_computes_legacy_partition() {
            // T2b (RED): end-to-end through close_and_finalize — a
            // legacy-backed, legacy-class seeded site lands in
            // executed_calls, and the four buckets conserve the
            // doc's total calls exactly.
            let mut cfg = stub_config();
            cfg.resolved_provider = Some(PinnedProvider {
                object: "fp-A".to_string(),
                class: "legacy".to_string(),
            });
            let info = stub_info();
            let clock = ClockStub::at(1_500);
            let mut proc = ProcStub;
            let cancelled = || false;
            let mut count = CountSession::new(TPID, FakeCountBackend::new());
            let (_seed, (dev, ino)) = seed_site_as(&mut count, "legacy");
            let mut runner = stub_runner(
                &cfg,
                &info,
                DiscoveryStub {
                    finish_err: false,
                    poll_err: false,
                    dispatch_attached: false,
                    trip_set: None,
                },
                count,
                &clock,
                &mut proc,
                &cancelled,
            );
            runner.adapter.objects.push(ObjectRecord {
                id: ObjectId("fp-A".to_string()),
                device: dev,
                inode: ino,
                display_locator: "seed".to_string(),
            });
            let cap = runner.close_and_finalize().expect("clean close");
            // H8b (RED): the partition also lands on the v2
            // document (the only live-rendered surface).
            let part = &cap.document.legacy_partition;
            assert_eq!(part.legacy_exclusive, 7);
            assert_eq!(part.non_legacy_exclusive, 0);
            assert_eq!(part.shared_ambiguous, 0);
            assert_eq!(part.unfenced_tails, 0);
            assert_eq!(part.total(), cap.document.total_calls());
            let lp = &cap.legacy["legacy_provider"];
            assert_eq!(lp["executed_calls"], 7);
            assert_eq!(lp["shared_ambiguous_calls"], 0);
            assert_eq!(lp["non_legacy_exclusive_calls"], 0);
            assert_eq!(lp["unfenced_tail_calls"], 0);
            assert_eq!(
                lp["executed_calls"].as_u64().unwrap()
                    + lp["shared_ambiguous_calls"].as_u64().unwrap()
                    + lp["non_legacy_exclusive_calls"].as_u64().unwrap()
                    + lp["unfenced_tail_calls"].as_u64().unwrap(),
                cap.document.total_calls()
            );
        }

        #[test]
        fn h8_close_default_pin_partitions_nothing_legacy() {
            // T4b (RED): a default-class pin leaves the legacy file
            // set empty — nothing partitions legacy, everything
            // lands non-legacy-exclusive.
            let mut cfg = stub_config();
            cfg.resolved_provider = Some(PinnedProvider {
                object: "fp-A".to_string(),
                class: "default".to_string(),
            });
            let info = stub_info();
            let clock = ClockStub::at(1_500);
            let mut proc = ProcStub;
            let cancelled = || false;
            let mut count = CountSession::new(TPID, FakeCountBackend::new());
            let (_seed, (dev, ino)) = seed_site_as(&mut count, "default");
            let mut runner = stub_runner(
                &cfg,
                &info,
                DiscoveryStub {
                    finish_err: false,
                    poll_err: false,
                    dispatch_attached: false,
                    trip_set: None,
                },
                count,
                &clock,
                &mut proc,
                &cancelled,
            );
            runner.adapter.objects.push(ObjectRecord {
                id: ObjectId("fp-A".to_string()),
                device: dev,
                inode: ino,
                display_locator: "seed".to_string(),
            });
            let cap = runner.close_and_finalize().expect("clean close");
            let lp = &cap.legacy["legacy_provider"];
            assert_eq!(lp["executed_calls"], 0);
            assert_eq!(lp["shared_ambiguous_calls"], 0);
            assert_eq!(lp["non_legacy_exclusive_calls"], 7);
        }

        /// Index a CBOM properties array by name.
        fn cbom_props(props: &serde_json::Value) -> std::collections::BTreeMap<String, String> {
            props
                .as_array()
                .unwrap()
                .iter()
                .map(|p| {
                    (
                        p["name"].as_str().unwrap().to_string(),
                        p["value"].as_str().unwrap().to_string(),
                    )
                })
                .collect()
        }

        /// Unique temp artifact path for delivery readback
        /// (parallel-safe: pid + sequence + thread id, the same
        /// scheme as [`SeedFile`]).
        fn artifact_path(name: &str) -> std::path::PathBuf {
            use std::sync::atomic::Ordering;
            static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let seq = SEQ.fetch_add(1, Ordering::SeqCst);
            std::env::temp_dir().join(format!(
                "osslscope-r02-{}-{}-{:?}-{name}",
                std::process::id(),
                seq,
                std::thread::current().id()
            ))
        }

        fn remove_quiet(path: &std::path::Path) {
            let _ = std::fs::remove_file(path);
        }

        /// Align the harness window with the count window so the
        /// salvaged doc is window-consistent for schema/semantic
        /// validation (the harness default 5e9 window predates
        /// semantic validation of stub docs).
        fn align_window(runner: &mut StubRunner<'_>) {
            runner.window_start_ns = 1000;
            runner.requested_start_ns = 1000;
            runner.kernel_deadline_ns = 2000;
        }

        /// Complete the stubbed discovery with the object records a
        /// real snapshot would carry for the seeded site (H8
        /// precedent: the DiscoveryStub provides no objects).
        fn push_seed_objects(runner: &mut StubRunner<'_>, dev: u64, ino: u64) {
            runner.adapter.objects.push(ObjectRecord {
                id: ObjectId("fp-A".to_string()),
                device: dev,
                inode: ino,
                display_locator: "seed".to_string(),
            });
            runner.adapter.objects.push(ObjectRecord {
                id: ObjectId("prov".to_string()),
                device: dev,
                inode: ino,
                display_locator: "seed".to_string(),
            });
        }

        #[test]
        fn runtime_finish_failure_preserves_policy_and_assets() {
            // R02: an actual controller close failure (discovery
            // finish fails AFTER a good drain) salvages the observed
            // MD5 site; check assembly and every renderer must agree
            // on the retained evidence — JSON validates, semantics
            // accepts the evaluated verdict, deny_weak convicts (exit
            // 10), seven calls survive, and the CBOM carries the
            // asset with an accurate disclaimer.
            let cfg = stub_config();
            let info = stub_info();
            let clock = ClockStub::at(1_500);
            let mut proc = ProcStub;
            let cancelled = || false;
            let mut count = CountSession::new(TPID, FakeCountBackend::new());
            let (_seed, (dev, ino)) = seed_site_candidates(
                &mut count,
                vec![CandidateIdentity::new(
                    ObjectId("prov".to_string()),
                    "default".to_string(),
                    1,
                    7,
                    vec!["MD5".to_string()],
                    true,
                )],
            );
            let mut runner = stub_runner(
                &cfg,
                &info,
                DiscoveryStub {
                    finish_err: true,
                    poll_err: false,
                    dispatch_attached: false,
                    trip_set: None,
                },
                count,
                &clock,
                &mut proc,
                &cancelled,
            );
            align_window(&mut runner);
            push_seed_objects(&mut runner, dev, ino);
            let cap = runner
                .close_and_finalize()
                .expect("finish error must salvage, not Err");
            // Controller facts: Runtime fatal naming discovery
            // finish, seven intact calls, Complete coverage.
            let detail = match &cap.document.status {
                Completeness::Fatal {
                    kind: evidence::FatalKind::Runtime(detail),
                    ..
                } => detail.clone(),
                other => panic!("want Fatal(Runtime), got {other:?}"),
            };
            assert!(
                detail.contains("discovery finish"),
                "unexpected detail: {detail}"
            );
            assert!(cap.reasons.iter().any(|r| r == "close-failure"));
            assert_eq!(cap.document.sites.len(), 1);
            assert_eq!(cap.document.sites[0].calls, 7);
            assert_eq!(
                cap.document.sites[0].candidates_coverage,
                CandidateCoverage::Complete
            );
            assert!(cap.document.has_usable_evidence());
            // Check assembly flows through the production seam:
            // evaluate, fold the legacy tripwire, attach the policy
            // section.
            let (verdict, document) = crate::check::assemble_checked_document(
                std::slice::from_ref(&crate::policy::PolicyRule::deny_weak()),
                cap.document.clone(),
                &cap.legacy,
            );
            assert_eq!(verdict.overall(), crate::policy::PolicyOutcome::Violation);
            assert!(!verdict.rules.is_empty());
            // Delivered artifacts are independently validated:
            // both destinations are written, read back, and checked
            // — the exit below derives from the actual delivery
            // result, never a fabricated outcome.
            let primary_path = artifact_path("runtime.report.json");
            let cbom_path = artifact_path("runtime.report.cdx.json");
            let req = crate::report::OutputRequest {
                format: crate::report::OutputFormat::Json,
                primary: crate::report::OutputDest::File(primary_path.clone()),
                cbom: Some(crate::report::OutputDest::File(cbom_path.clone())),
            };
            let delivery = crate::report::write_artifacts(&document, &req);
            assert!(delivery.delivered_all(), "{delivery:?}");
            assert!(
                delivery.diagnostics.is_empty(),
                "{:?}",
                delivery.diagnostics
            );
            let primary = std::fs::read(&primary_path).unwrap();
            let cbom_bytes = std::fs::read(&cbom_path).unwrap();
            assert_eq!(
                primary,
                crate::report::render_json(&document).unwrap(),
                "delivered primary drifted from the direct render"
            );
            assert_eq!(
                cbom_bytes,
                crate::report::render_cbom(&document).unwrap(),
                "delivered CBOM drifted from the direct render"
            );
            // JSON validates and semantics accepts the evaluated
            // verdict on usable Runtime evidence.
            let v: serde_json::Value = serde_json::from_slice(&primary).unwrap();
            crate::schema::validate_v2(&v).unwrap();
            crate::schema::check_v2_semantics(&v).expect("usable Runtime verdict must validate");
            assert_eq!(v["policy"]["verdict"], "violation");
            assert_eq!(v["policy"]["rules"][0]["definite"], 7);
            assert_eq!(document.total_calls(), 7);
            // CBOM retains the definite MD5 asset with honest
            // omission accounting and an accurate disclaimer.
            let cbom: serde_json::Value = serde_json::from_slice(&cbom_bytes).unwrap();
            let comps = cbom["components"].as_array().unwrap();
            assert_eq!(comps.len(), 1);
            let asset = cbom_props(&comps[0]["properties"]);
            assert_eq!(asset["osslscope:algorithm"], "MD5");
            assert_eq!(asset["osslscope:calls"], "7");
            let meta = cbom_props(&cbom["metadata"]["properties"]);
            assert_eq!(meta["osslscope:omitted-ambiguous-sites"], "0");
            assert_eq!(meta["osslscope:omitted-unknown-coverage-sites"], "0");
            assert_eq!(meta["osslscope:policy-verdict"], "violation");
            let disclaimer = &meta["osslscope:completeness-disclaimer"];
            assert!(disclaimer.contains("FATAL"), "{disclaimer}");
            assert!(disclaimer.contains("salvaged"), "{disclaimer}");
            assert!(!disclaimer.contains("no usable evidence"), "{disclaimer}");
            // Human names the retained site and the violation.
            let text = crate::report::render_human(&document);
            assert!(text.contains("7 calls"), "{text}");
            assert!(text.contains("policy: violation"), "{text}");
            assert!(text.contains("fatal: runtime:"), "{text}");
            // A proved violation dominates the tool failure (driven
            // by the actual delivery result).
            assert_eq!(
                crate::report::exit_for(verdict.overall(), cap.child_exit, &document, &delivery),
                10
            );
            remove_quiet(&primary_path);
            remove_quiet(&cbom_path);
        }

        #[test]
        fn runtime_ambiguous_site_stays_possible_only() {
            // R02 control: ambiguous Runtime evidence is usable (it
            // evaluates) but never definite — mixed MD5/SHA2-256
            // candidates are possible-only, so deny_weak is
            // inconclusive, the CBOM omits the site with accounting,
            // and the nonviolating Runtime exits 1.
            let cfg = stub_config();
            let info = stub_info();
            let clock = ClockStub::at(1_500);
            let mut proc = ProcStub;
            let cancelled = || false;
            let mut count = CountSession::new(TPID, FakeCountBackend::new());
            let (_seed, (dev, ino)) = seed_site_candidates(
                &mut count,
                vec![
                    CandidateIdentity::new(
                        ObjectId("prov".to_string()),
                        "default".to_string(),
                        1,
                        7,
                        vec!["MD5".to_string()],
                        true,
                    ),
                    CandidateIdentity::new(
                        ObjectId("prov".to_string()),
                        "default".to_string(),
                        1,
                        7,
                        vec!["SHA2-256".to_string()],
                        false,
                    ),
                ],
            );
            let mut runner = stub_runner(
                &cfg,
                &info,
                DiscoveryStub {
                    finish_err: true,
                    poll_err: false,
                    dispatch_attached: false,
                    trip_set: None,
                },
                count,
                &clock,
                &mut proc,
                &cancelled,
            );
            align_window(&mut runner);
            push_seed_objects(&mut runner, dev, ino);
            let cap = runner
                .close_and_finalize()
                .expect("finish error must salvage, not Err");
            assert!(
                matches!(
                    &cap.document.status,
                    Completeness::Fatal {
                        kind: evidence::FatalKind::Runtime(_),
                        ..
                    }
                ),
                "want Fatal(Runtime), got {:?}",
                cap.document.status
            );
            assert_eq!(cap.document.sites.len(), 1);
            assert_eq!(cap.document.sites[0].calls, 7);
            assert!(cap.document.has_usable_evidence());
            // Same production seam as the violation case above.
            let (verdict, document) = crate::check::assemble_checked_document(
                std::slice::from_ref(&crate::policy::PolicyRule::deny_weak()),
                cap.document.clone(),
                &cap.legacy,
            );
            assert_eq!(
                verdict.overall(),
                crate::policy::PolicyOutcome::Inconclusive
            );
            assert!(!verdict.rules.is_empty());
            // Same independent delivery readback as the violation
            // case: both destinations written, read back, and checked.
            let primary_path = artifact_path("runtime.ambiguous.report.json");
            let cbom_path = artifact_path("runtime.ambiguous.report.cdx.json");
            let req = crate::report::OutputRequest {
                format: crate::report::OutputFormat::Json,
                primary: crate::report::OutputDest::File(primary_path.clone()),
                cbom: Some(crate::report::OutputDest::File(cbom_path.clone())),
            };
            let delivery = crate::report::write_artifacts(&document, &req);
            assert!(delivery.delivered_all(), "{delivery:?}");
            let primary = std::fs::read(&primary_path).unwrap();
            let cbom_bytes = std::fs::read(&cbom_path).unwrap();
            assert_eq!(
                primary,
                crate::report::render_json(&document).unwrap(),
                "delivered primary drifted from the direct render"
            );
            assert_eq!(
                cbom_bytes,
                crate::report::render_cbom(&document).unwrap(),
                "delivered CBOM drifted from the direct render"
            );
            let v: serde_json::Value = serde_json::from_slice(&primary).unwrap();
            crate::schema::validate_v2(&v).unwrap();
            crate::schema::check_v2_semantics(&v).expect("ambiguous Runtime must validate");
            assert_eq!(v["policy"]["verdict"], "inconclusive");
            let cbom: serde_json::Value = serde_json::from_slice(&cbom_bytes).unwrap();
            assert_eq!(cbom["components"].as_array().unwrap().len(), 0);
            let meta = cbom_props(&cbom["metadata"]["properties"]);
            assert_eq!(meta["osslscope:omitted-ambiguous-sites"], "1");
            assert_eq!(meta["osslscope:omitted-ambiguous-calls"], "7");
            assert!(
                meta["osslscope:omitted-evidence-refs"].contains("fp-A"),
                "refs: {}",
                meta["osslscope:omitted-evidence-refs"]
            );
            let disclaimer = &meta["osslscope:completeness-disclaimer"];
            assert!(disclaimer.contains("FATAL"), "{disclaimer}");
            assert!(disclaimer.contains("salvaged"), "{disclaimer}");
            assert!(!disclaimer.contains("no usable evidence"), "{disclaimer}");
            assert_eq!(
                crate::report::exit_for(verdict.overall(), cap.child_exit, &document, &delivery),
                1
            );
            remove_quiet(&primary_path);
            remove_quiet(&cbom_path);
        }

        #[test]
        fn runtime_lost_drain_evaluates_without_sites() {
            // R02 control: a lost drain (pre-drained session plus a
            // finish failure) salvages no sites; the Runtime doc still
            // evaluates (kind-eligible) to inconclusive — absence is
            // unprovable over a broken close — with an accurate empty
            // CBOM and exit 1.
            let cfg = stub_config();
            let info = stub_info();
            let clock = ClockStub::at(1_500);
            let mut proc = ProcStub;
            let cancelled = || false;
            let mut count = CountSession::new(TPID, FakeCountBackend::new());
            let _seed = seed_site(&mut count);
            count.close_and_drain(Duration::from_secs(1)).unwrap();
            let mut runner = stub_runner(
                &cfg,
                &info,
                DiscoveryStub {
                    finish_err: true,
                    poll_err: false,
                    dispatch_attached: false,
                    trip_set: None,
                },
                count,
                &clock,
                &mut proc,
                &cancelled,
            );
            align_window(&mut runner);
            let cap = runner
                .close_and_finalize()
                .expect("double close error must salvage once, not Err");
            assert!(
                matches!(
                    &cap.document.status,
                    Completeness::Fatal {
                        kind: evidence::FatalKind::Runtime(_),
                        ..
                    }
                ),
                "want Fatal(Runtime), got {:?}",
                cap.document.status
            );
            assert!(cap.document.sites.is_empty());
            assert_eq!(counter(&cap.document, "count.close_failed"), 1);
            assert_eq!(counter(&cap.document, "discovery.finish_failed"), 1);
            assert!(cap.reasons.iter().any(|r| r == "close-failure"));
            assert!(cap.document.has_usable_evidence());
            // Same production seam as the violation case above.
            let (verdict, document) = crate::check::assemble_checked_document(
                std::slice::from_ref(&crate::policy::PolicyRule::deny_weak()),
                cap.document.clone(),
                &cap.legacy,
            );
            assert_eq!(
                verdict.overall(),
                crate::policy::PolicyOutcome::Inconclusive
            );
            assert!(!verdict.rules.is_empty());
            // Same independent delivery readback as the violation
            // case: both destinations written, read back, and checked.
            let primary_path = artifact_path("runtime.lostdrain.report.json");
            let cbom_path = artifact_path("runtime.lostdrain.report.cdx.json");
            let req = crate::report::OutputRequest {
                format: crate::report::OutputFormat::Json,
                primary: crate::report::OutputDest::File(primary_path.clone()),
                cbom: Some(crate::report::OutputDest::File(cbom_path.clone())),
            };
            let delivery = crate::report::write_artifacts(&document, &req);
            assert!(delivery.delivered_all(), "{delivery:?}");
            let primary = std::fs::read(&primary_path).unwrap();
            let cbom_bytes = std::fs::read(&cbom_path).unwrap();
            assert_eq!(
                primary,
                crate::report::render_json(&document).unwrap(),
                "delivered primary drifted from the direct render"
            );
            assert_eq!(
                cbom_bytes,
                crate::report::render_cbom(&document).unwrap(),
                "delivered CBOM drifted from the direct render"
            );
            let v: serde_json::Value = serde_json::from_slice(&primary).unwrap();
            crate::schema::validate_v2(&v).unwrap();
            crate::schema::check_v2_semantics(&v).expect("lost-drain Runtime must validate");
            assert_eq!(v["policy"]["verdict"], "inconclusive");
            let cbom: serde_json::Value = serde_json::from_slice(&cbom_bytes).unwrap();
            assert_eq!(cbom["components"].as_array().unwrap().len(), 0);
            let meta = cbom_props(&cbom["metadata"]["properties"]);
            assert_eq!(meta["osslscope:omitted-ambiguous-sites"], "0");
            assert_eq!(meta["osslscope:omitted-unknown-coverage-sites"], "0");
            let disclaimer = &meta["osslscope:completeness-disclaimer"];
            assert!(disclaimer.contains("FATAL"), "{disclaimer}");
            assert!(disclaimer.contains("salvaged"), "{disclaimer}");
            assert!(!disclaimer.contains("no usable evidence"), "{disclaimer}");
            assert_eq!(
                crate::report::exit_for(verdict.overall(), cap.child_exit, &document, &delivery),
                1
            );
            remove_quiet(&primary_path);
            remove_quiet(&cbom_path);
        }

        /// Wall-script clock (R12 fix): wall advances by a full step
        /// on EVERY wall sample while monotonic advances only via
        /// sleep — the two clocks change independently, so any
        /// double-sampled edge or pre-setup start shows up as an
        /// exact-step skew the assertions below pin.
        struct WallScriptClock {
            ns: Cell<u64>,
            now: Cell<Instant>,
            wall_ns: Cell<u64>,
        }

        impl WallScriptClock {
            const WALL_BASE: u64 = 1_700_000_000_000_000_000;
            const WALL_STEP: u64 = 1_000_000_000;
            fn at(ns: u64) -> Self {
                Self {
                    ns: Cell::new(ns),
                    now: Cell::new(Instant::now()),
                    wall_ns: Cell::new(Self::WALL_BASE),
                }
            }
            fn wall_at(sample: u64) -> SystemTime {
                SystemTime::UNIX_EPOCH
                    + Duration::from_nanos(Self::WALL_BASE + sample * Self::WALL_STEP)
            }
        }

        impl ClockPort for WallScriptClock {
            fn monotonic_ns(&self) -> u64 {
                self.ns.get()
            }
            fn now(&self) -> Instant {
                self.now.get()
            }
            fn wall_now(&self) -> SystemTime {
                let w = self.wall_ns.get();
                self.wall_ns.set(w.saturating_add(Self::WALL_STEP));
                SystemTime::UNIX_EPOCH + Duration::from_nanos(w)
            }
            fn sleep(&self, d: Duration) {
                self.ns.set(
                    self.ns
                        .get()
                        .saturating_add(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)),
                );
                self.now.set(self.now.get() + d);
            }
        }

        fn wall_script_capture(owned: bool, acquired_wall: SystemTime) -> Capture {
            let cfg = stub_config();
            let mut info = stub_info();
            info.owned = owned;
            info.kernel_release = "6.9.0-test".to_string();
            info.acquired_wall = acquired_wall;
            let clock = WallScriptClock::at(5_000_000_000);
            let mut proc = ProcStub;
            let cancelled = || false;
            let count = CountSession::new(TPID, FakeCountBackend::new());
            observe(
                &cfg,
                &info,
                SessionSet {
                    discovery: DiscoveryStub {
                        finish_err: false,
                        poll_err: false,
                        dispatch_attached: false,
                        trip_set: None,
                    },
                    count,
                    target: TargetStub,
                    lifecycle: LifecycleStub,
                },
                &clock,
                &mut proc,
                &cancelled,
            )
            .expect("stubbed capture runs end to end")
        }

        #[test]
        fn r12_fix_wall_pair_is_single_release_to_close_pair_owned() {
            // R12 fix control (fails pre-fix): one consistently
            // captured wall pair through the real controller — the
            // document context and the enclosing Capture share both
            // edges; the start is the release-time wall (sample 1,
            // not the pre-setup open sample 0); the end is the single
            // close sample (sample 2), reused — not a fresh
            // post-teardown sample per consumer. Monotonic stays
            // authoritative: setup moved wall samples without moving
            // monotonic, and the 1s window is pure monotonic.
            let cap = wall_script_capture(true, WallScriptClock::wall_at(0));
            let ctx = cap.document.context.as_ref().expect("context retained");
            assert_eq!(ctx.kernel_release, "6.9.0-test");
            assert_eq!(
                ctx.wall_start_unix_ns,
                unix_ns(WallScriptClock::wall_at(1)),
                "start must be the release-time wall, not the pre-setup open"
            );
            assert_eq!(
                ctx.wall_end_unix_ns,
                unix_ns(WallScriptClock::wall_at(2)),
                "end must be the single close sample"
            );
            assert_eq!(
                cap.window_start_wall,
                WallScriptClock::wall_at(1),
                "Capture must reuse the one start edge"
            );
            assert_eq!(
                cap.window_end_wall,
                WallScriptClock::wall_at(2),
                "Capture must reuse the one end edge"
            );
            assert_eq!(cap.document.window.requested_start_ns, 5_000_000_000);
            assert_eq!(cap.document.window.requested_end_ns, 6_000_000_000);
            assert_eq!(cap.document.window.effective_start_ns, 5_000_000_000);
            assert_eq!(cap.document.window.effective_end_ns, 6_000_000_000);
        }

        #[test]
        fn r12_fix_wall_pair_is_single_acquire_to_close_pair_foreign() {
            // R12 fix control (fails pre-fix): foreign requested
            // start IS acquisition, so the wall start is the
            // acquisition wall — never the post-acquisition open
            // sample — and the close sample is reused by both
            // consumers.
            let acquired = SystemTime::UNIX_EPOCH + Duration::from_nanos(1_600_000_000_000_000_000);
            let cap = wall_script_capture(false, acquired);
            let ctx = cap.document.context.as_ref().expect("context retained");
            assert_eq!(
                ctx.wall_start_unix_ns,
                unix_ns(acquired),
                "foreign start must be the acquisition wall"
            );
            assert_eq!(
                ctx.wall_end_unix_ns,
                unix_ns(WallScriptClock::wall_at(1)),
                "end must be the single close sample"
            );
            assert_eq!(
                cap.window_start_wall, acquired,
                "Capture must reuse the one start edge"
            );
            assert_eq!(
                cap.window_end_wall,
                WallScriptClock::wall_at(1),
                "Capture must reuse the one end edge"
            );
            assert_eq!(cap.document.window.requested_start_ns, 5_000_000_000);
        }
    }
}
