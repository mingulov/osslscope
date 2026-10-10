//! SPDX-License-Identifier: GPL-3.0-or-later
//! Persistent discovery session (T06, spec R03/R04).
//!
//! [`DiscoverySession`] is the single discovery engine: it owns the
//! loaded BPF programs/maps, the attach links, the ring consumer,
//! the target pin, and all discovery state until the session drops.
//! Callers poll it in bounded batches and consume typed
//! [`DiscoveryDelta`]s — there is no blocking full harvest and no
//! JSON reparse in the (future T08) count loop. `inspect` and the
//! capture harvest path are thin run-policies over this session
//! (see `harvest::run_detailed`).
//!
//! The engine splits into two layers:
//!
//! * [`SessionCore`], the host-testable state machine: ring decode,
//!   table-epoch binding, monotonic map joins, retry state, and
//!   delta/snapshot accounting. It touches no BPF types directly;
//!   every privileged/file operation goes through [`SessionEnv`].
//! * [`LiveEnv`], the privileged environment behind
//!   [`DiscoverySession`]: the real ring, maps, links, pin, and
//!   `/proc` reads.
//!
//! Wire enums/records stay in `ebpf-common`; the frozen
//! `DiscoverySession`/`DiscoveryConfig`/`DiscoveryDelta`/
//! `DiscoverySnapshot`/`PollBudget`/`CoverageState`/`DiscoveryLoss`
//! surface below is the spec's task boundary (T08 consumes deltas).
//!
//! Epoch binding (T03 follow-up): every observed (op, array) table
//! is bound to its array mapping's incarnation fingerprint
//! `(device, inode, range, file offset)`, reconciled from `/proc`
//! maps on every poll. When the incarnation changes or vanishes,
//! the table retires: its walked set and termination proof drop,
//! the kernel's per-array walker state (`TERMD` proof and
//! `QUERY_NEXT` cursors) is evicted so stale state cannot satisfy
//! the next incarnation, its gap reasons are retained forever, and
//! its rows stay. This closes growth-ABA (a stale proof plus a
//! longer walk is still a prefix, per T03 exact coverage),
//! shrinkage-OOB (an old proof can never terminate a new
//! incarnation), and cursor staleness on reload (the next walk
//! restarts at slot 0). Two residuals remain explicit: a
//! same-address content swap inside an unchanged mapping is
//! indistinguishable from continued use (repeat inits bump the
//! reload witness and re-attach when the callback moved; exact
//! coverage is the backstop when the walk shape changes); and a
//! turnover that lands between the kernel's genuine re-proof and
//! the next poll evicts a fresh proof too — fail-safe to prefix,
//! never to false COMPLETE. Eviction failure is explicit loss
//! (`evict_failed`), and loss forces PARTIAL, which contains any
//! surviving stale proof.
//!
//! `no_store` lifetimes stay intact: uncacheable arrays are sampled,
//! never walked to proof, and no array pointer is ever retained
//! beyond its poll — candidates keep classified metadata plus
//! integer join keys only, exactly as before.
//!
//! Teardown is quiesce-then-PROCESS: [`SessionCore::close`] drops
//! the attach links first (quiesce: no new events can arrive),
//! then counts the ring tail exactly into drain shortfall, joins
//! the maps once more, and verifies the pin — so no post-stop
//! arrival escapes accounting. Prefer `close()` over `drop()`: the
//! `Drop` impl only releases file descriptors and cannot report
//! the tail.
//!
//! The session performs no ELF reads in the poll path: backing
//! triples come from `/proc` maps alone, and foreign-object ELF
//! checks stay at the (cached, per-emit) document-render layer, so
//! only relevant objects are ever read.

use crate::discovery::{builtin, coverage, elf, harvest, legacy, maps};
use crate::loader::Loaded;
use anyhow::{Context as _, anyhow, bail};
use aya::maps::{Map, MapData, RingBuf};
use osslscope_ebpf_common as wire;
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Frozen task-boundary types.
// ---------------------------------------------------------------------------

/// Discovery session configuration: what to attach, not how long to
/// run (durations are caller run-policy, e.g. `harvest::Config`).
#[derive(Clone, Debug)]
pub struct DiscoveryConfig {
    /// Provider `.so` (or libcrypto with `builtin`).
    pub provider: PathBuf,
    /// Harvest BPF object.
    pub object: PathBuf,
    /// Builtin mode: the in-libcrypto default provider.
    pub builtin: bool,
    /// Legacy tripwires (ENGINE/meth/load/low-level + legacy query).
    pub legacy: bool,
    /// Override build-id table (forensics/redacted-table gates).
    pub table: Option<PathBuf>,
    /// Forced query-fn file offset (forensics escape hatch).
    pub force_offset: Option<u64>,
    /// Required cmdline marker (fixture guard), or None for any target.
    pub cmdline_marker: Option<String>,
}

/// Per-poll resource bounds (spec R04: every poll/attachment batch
/// is bounded). The default drains a full 2 MiB ring of smallest
/// events per poll, matching the old full-drain rounds; tighter
/// budgets yield partial polls flagged via
/// [`DiscoveryDelta::budget_exhausted`].
#[derive(Clone, Debug)]
pub struct PollBudget {
    /// Ring items decoded per poll at most.
    pub max_events: u64,
    /// Stage-2/tripwire attaches per poll at most.
    pub max_attaches: u32,
}

impl PollBudget {
    pub fn new(max_events: u64, max_attaches: u32) -> Self {
        Self {
            max_events,
            max_attaches,
        }
    }
}

impl Default for PollBudget {
    fn default() -> Self {
        Self {
            max_events: 131072,
            max_attaches: 64,
        }
    }
}

/// One source-tagged discovery loss: `source` is a wire `LOSS_*` id
/// or a `coverage::HOST_*` id (see
/// [`coverage::loss_source_name`]); `count` is this delta's
/// increment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscoveryLoss {
    pub source: u32,
    pub count: u64,
}

/// Traversal state of one table incarnation. R03's aborted/truncated
/// shapes travel alongside as sticky `TRUNC` bits (frozen
/// vocabulary in `ebpf-common`) plus ranked gap reasons — see
/// [`TableCoverage`] — rather than as a second precedence order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoverageState {
    Unseen,
    InProgress { walked: u32 },
    Terminated { len: u32 },
}

/// One observed (op, array-epoch) table and its current state.
/// `epoch` is the mapping-incarnation generation (see the module
/// docs); `trunc_bits` carries the op's sticky walk-shape bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableCoverage {
    pub op: u32,
    pub epoch: u64,
    pub state: CoverageState,
    pub trunc_bits: u64,
}

/// Verified backing triple for one callback implementation: the
/// `(device, inode, file offset)` the address relocated to. The
/// mapping executable bit and ELF segment checks stay at the
/// document-render layer; this triple is the claimed relocation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BackingRef {
    pub dev: String,
    pub ino: u64,
    pub offset: u64,
}

/// One observed backing object (code provenance for operators).
/// Verified fingerprints are T07 work; this carries the
/// `(device, inode)` identity plus a display locator, never an
/// authority claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredObject {
    pub dev: String,
    pub ino: u64,
    pub display_locator: String,
}

/// One classified dispatch candidate, retained across polls. The
/// advertising identity (which provider's array offered it) and the
/// backing identity (which object's code implements it) are
/// separate fields and are never conflated: `backing` is `None`
/// exactly when the implementation sits in no file mapping (fenced,
/// count-only at render). `impl_addr`/`arr` are internal integer
/// join keys, never serialized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredCandidate {
    /// Array owner's mapped locator (`""` for anonymous/unmapped
    /// arrays).
    pub advertising: String,
    pub backing: Option<BackingRef>,
    pub op: u32,
    pub funcid: u32,
    /// Registry class label or `"other"` — never target bytes.
    pub class: String,
    pub weak: bool,
    /// Kernel read verdict (`ok`/`unknown`/`overlong`/`truncated`).
    pub status: String,
    /// Table-epoch this candidate was ingested under.
    pub epoch: u64,
    /// INTERNAL relocation input, never serialized.
    pub impl_addr: u64,
    /// INTERNAL array join key, never serialized.
    pub arr: u64,
}

/// This poll's tripwire news. Query/load counters and tripwire
/// counters stay separate: `executed_legacy_queries_delta` moves
/// only on the executed-query ledger, never on load hits.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TripwireDelta {
    /// Newly classified hits this poll.
    pub hits: Vec<legacy::TripHit>,
    /// Per-cookie counter increments (joined `TRIP` map).
    pub counter_deltas: Vec<(u64, u64)>,
    /// Executed-query ledger increment (joined `LGCALLS` map).
    pub executed_legacy_queries_delta: u64,
}

/// One link-installation outcome this poll.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachEvent {
    pub kind: AttachKind,
    /// Set on failure (retryable: the next trigger re-attempts).
    pub failed: Option<String>,
}

/// What was (or failed to be) installed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttachKind {
    /// Stage-2 query pair for one init cookie.
    Stage2 { cookie: u64 },
    /// Legacy tripwire batch.
    Tripwires { count: usize },
}

/// One table-incarnation retirement this poll: the epoch that
/// turned over plus the gap it carried (retained forever in the
/// snapshot; rows survive separately). Consumers must drop the
/// retired epoch's completion — only the new epoch's proof counts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableRetirement {
    pub op: u32,
    pub epoch: u64,
    pub gap: coverage::CoverageDelta,
}

/// One poll's worth of discovery news: new/changed classified
/// candidates + newly observed objects + touched table states +
/// retirements + tripwire deltas + source-tagged losses.
/// Cumulative state lives in [`DiscoverySnapshot`]; this delta
/// never requires JSON.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiscoveryDelta {
    /// Ring items consumed this poll.
    pub events_consumed: u64,
    /// Candidates first seen (or identity-refreshed after a
    /// same-address remap) this poll.
    pub candidates: Vec<DiscoveredCandidate>,
    /// Backing objects first seen this poll.
    pub objects: Vec<DiscoveredObject>,
    /// Tables touched this poll (ring events, map-join
    /// transitions, or rebirth), with current state.
    pub tables: Vec<TableCoverage>,
    /// Incarnations retired this poll, with their gaps.
    pub retirements: Vec<TableRetirement>,
    pub tripwire: TripwireDelta,
    /// Losses incurred this poll (host + kernel increments).
    pub losses: Vec<DiscoveryLoss>,
    /// Query/load counter increment — arrivals, NOT execution.
    pub queries_delta: u64,
    pub attaches: Vec<AttachEvent>,
    /// True when the budget stopped work with more pending (more
    /// events queued or attaches deferred): resume with another
    /// poll. This is backpressure, not loss.
    pub budget_exhausted: bool,
    /// Cumulative dispatch-trigger flag (loop-convenience copy;
    /// authoritative state lives in the snapshot).
    pub trigger_observed: bool,
}

/// Unresolved stage-2 attach failure (retryable state, not a
/// terminal verdict): the next init for `cookie` re-attempts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachFailure {
    pub cookie: u64,
    pub error: String,
}

/// Cumulative dispatch-plane state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DispatchSnapshot {
    /// A dispatch anchor is attached (init pair, builtin pair, or
    /// any stage-2 pair).
    pub attached: bool,
    /// Blind-dispatch PARTIAL reason (`anchor-unresolved`), if the
    /// anchor ladder failed.
    pub preset_reason: Option<String>,
    /// Non-default resolution label (`symtab`, `anchor+delta`, `force`).
    pub resolution: Option<String>,
    /// Currently unresolved stage-2 failures, by cookie.
    pub attach_failures: Vec<AttachFailure>,
    /// Repeat inits per cookie (reload witness; the content-swap
    /// backstop is exact coverage, see the module docs).
    pub reloads: Vec<(u64, u64)>,
    /// The target provider's init fired post-attach.
    pub primary_init_observed: bool,
    /// Any dispatch trigger (query/alg/row) was observed.
    pub trigger_observed: bool,
}

/// Cumulative legacy-plane state. Query counters
/// (`executed_queries`) and tripwire counters (`trip`/`hits`) are
/// separate fields; only the executed-query ledger feeds
/// `executed_calls` at render.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LegacySnapshot {
    /// A tripwire probe set is planned and installed.
    pub planned: bool,
    pub set: Option<legacy::ProbeSet>,
    /// Last-joined `TRIP` contents: cookie → hit count.
    pub trip: HashMap<u64, u64>,
    /// Retained classified hits.
    pub hits: Vec<legacy::TripHit>,
    /// Executed legacy queries (joined `LGCALLS` ledger only).
    pub executed_queries: u64,
    /// Extra findings (e.g. legacy attach notes).
    pub extra_findings: Vec<String>,
}

/// Live attach-link counts (resource-liveness witness for T08
/// lifecycle accounting).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkLiveness {
    pub dispatch: u64,
    pub tripwire: u64,
}

/// Cumulative discovery state: all retained candidates/objects,
/// live-epoch table states, retained ∪ live gap reasons, and
/// accumulated counters. Reasons only ever grow within a session.
///
/// `retained_reasons` carries the retired-epoch gaps alone (the
/// `reasons` union minus live state): renderers must honor them —
/// a retired prefix stays PARTIAL even when every live table
/// terminates.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiscoverySnapshot {
    pub candidates: Vec<DiscoveredCandidate>,
    pub objects: Vec<DiscoveredObject>,
    /// Live-epoch tables only; retired epochs survive in
    /// `candidates` (rows) and `reasons` (gaps).
    pub tables: Vec<TableCoverage>,
    /// Retained ∪ live gap reasons, in the frozen rank order.
    pub reasons: Vec<String>,
    /// Retired-epoch gaps alone (subset of `reasons`).
    pub retained_reasons: Vec<String>,
    /// Accumulated source-tagged losses, sorted by source.
    pub losses: Vec<(u32, u64)>,
    /// Sticky per-op walk-shape bits (never retired).
    pub truncated_ops: Vec<(u32, u64)>,
    /// Walked slots whose identity was lost.
    pub lossy_slots: u64,
    /// Query/load arrivals (CALLS-joined total, event-count
    /// fallback) — never execution.
    pub queries_observed: u64,
    /// Ops with at least one query hit.
    pub ops_hit: Vec<u32>,
    pub dispatch: DispatchSnapshot,
    pub legacy: LegacySnapshot,
    pub links_live: LinkLiveness,
    pub pid_recycled: u64,
}

// ---------------------------------------------------------------------------
// Environment: the seam between the state machine and the privileged world.
// ---------------------------------------------------------------------------

/// One round of BPF map reads. Kernel counters (`losses`, `calls`,
/// `trip`, `lgcalls`) are cumulative; the core joins them
/// monotonically and reports only increments. `TERMD`/`TRUNC` join
/// idempotently. A `*_failed` flag means that map's contents are
/// unknown and becomes explicit snapshot loss, never a silent
/// empty.
#[derive(Clone, Debug, Default)]
pub struct MapSnapshots {
    pub trunc: Vec<(u32, u64)>,
    pub trunc_failed: bool,
    pub termd: Vec<(u64, u64)>,
    pub termd_failed: bool,
    pub losses: Vec<(u32, u64)>,
    pub losses_failed: bool,
    /// `CALLS` sum (`None` when the map is absent).
    pub calls: Option<u64>,
    pub calls_failed: bool,
    /// `TRIP` contents.
    pub trip: Vec<(u64, u64)>,
    pub trip_failed: bool,
    /// `LGCALLS` sum.
    pub lgcalls: u64,
    pub lgcalls_failed: bool,
}

/// Privileged/file operations the [`SessionCore`] needs. The live
/// implementation ([`LiveEnv`]) performs real BPF and `/proc` work;
/// host tests stage synthetic rings, maps, snapshots, links, and
/// pins behind the same contract.
pub trait SessionEnv {
    /// Pop one raw ring item, or `None` when the ring is empty now.
    fn next_event(&mut self) -> Option<Vec<u8>>;
    /// Current target mappings (epoch reconcile + attribution).
    fn current_maps(&mut self) -> Vec<maps::Mapping>;
    /// One round of BPF map reads.
    fn join_maps(&mut self) -> MapSnapshots;
    /// Install one stage-2 query pair; the live impl reports the
    /// harness-gated `INSPECT stage=query` line itself.
    fn install_stage2(
        &mut self,
        cookie: u64,
        offset: u64,
        path: &Path,
        pid: u32,
    ) -> anyhow::Result<()>;
    /// Install one tripwire batch; returns an optional attach note
    /// (e.g. legacy-query attach failure, loud but non-fatal).
    fn install_trips(&mut self, set: &legacy::ProbeSet, pid: u32)
    -> anyhow::Result<Option<String>>;
    /// Plan legacy tripwires against `maps`: `None` when
    /// libcrypto is not mapped (blind — the core retries on later
    /// polls as mappings appear).
    fn plan_trips(&mut self, maps: &[maps::Mapping]) -> anyhow::Result<Option<legacy::ProbeSet>>;
    /// Best-effort page fault-in after a repeat init (cold reload
    /// pages make nofault BPF reads abort the walk).
    fn pretouch(&mut self, cookie: u64, addr: u64);
    /// Evict one array's kernel walker state (`TERMD` proof and
    /// `QUERY_NEXT` cursors) after its incarnation retired, so stale
    /// proofs and mid-array cursors cannot satisfy the next
    /// incarnation. Evicting an absent entry succeeds; other
    /// failures are explicit loss (the stale state may survive).
    fn evict_array_state(&mut self, arr: u64) -> anyhow::Result<()>;
    /// Re-verify the target pin; `Err` means the pid recycled and
    /// all retained evidence is tainted.
    fn verify_pin(&self) -> anyhow::Result<()>;
    /// Drop every attach link (quiesce: no new events can arrive).
    fn quiesce(&mut self);
    /// Live link counts as `(dispatch, tripwire)`.
    fn link_counts(&self) -> (u64, u64);
}

/// Pid recycle mid-observation: carries the discarded-state
/// snapshot (zero rows; blind legacy at most — trip data is
/// pid-scoped, hence tainted too). Callers render their
/// `PARTIAL(pid-recycled)` discard from it.
#[derive(Debug)]
pub struct Recycled {
    pub snapshot: DiscoverySnapshot,
}

impl std::fmt::Display for Recycled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "target recycled mid-run (evidence discarded; see PARTIAL snapshot)"
        )
    }
}

impl std::error::Error for Recycled {}

fn debug_session() -> bool {
    std::env::var("OSSL_DEBUG_HARVEST").is_ok()
}

/// Debug-only alg line over an already-classified record (logs are
/// artifacts: table labels, ids, and counters only — never target
/// strings, string lengths, or runtime addresses, even under the
/// debug flag).
fn debug_alg_line(op: u32, idx: u64, class: &str, weak: bool, status: u8) -> String {
    format!(
        "HARVESTDBG alg op={op} idx={idx} class={class} weak={} status={status}",
        u8::from(weak)
    )
}

// ---------------------------------------------------------------------------
// SessionCore: the host-testable discovery state machine.
// ---------------------------------------------------------------------------

/// One table incarnation: the epoch id plus the mapping
/// fingerprint the array was bound to (`None` for anonymous or
/// unmapped arrays, which carry no verifiable identity).
#[derive(Clone, Debug)]
struct TableEpoch {
    epoch: u64,
    fingerprint: Option<(String, u64, u64, u64, u64)>,
}

/// Candidate identity: `(op, class, weak, status, funcid,
/// impl_addr, array)`. Scaled tables cycle funcids, alias verdicts
/// must not collapse, and two providers sharing one implementation
/// stay distinct per offering array (R02 advertising identity).
/// Epoch is deliberately excluded: re-walked rows in a new epoch
/// refresh, never duplicate.
type CandidateKey = (u32, String, bool, String, u32, u64, u64);

/// One reconcile round: retirements (for the delta) and reborn
/// keys (fresh unproven epochs, always delta-visible).
#[derive(Default)]
struct ReconcileOutcome {
    retired: Vec<TableRetirement>,
    reborn: Vec<(u32, u64)>,
}

/// Fingerprint the mapping covering `arr`: `(dev, ino, start, end,
/// file offset)`. File mappings only — anonymous mappings have no
/// identity to bind.
fn incarnation_of(maps: &[maps::Mapping], arr: u64) -> Option<(String, u64, u64, u64, u64)> {
    maps.iter()
        .find(|m| m.start <= arr && arr < m.end && m.ino != 0)
        .map(|m| (m.dev.clone(), m.ino, m.start, m.end, m.offset))
}

/// The discovery state machine: ring decode, epoch binding,
/// monotonic joins, event-driven retry, and delta/snapshot
/// accounting, with no direct BPF dependency. Drive it with
/// [`SessionCore::poll`] through a [`SessionEnv`]; the live
/// [`DiscoverySession`] pairs it with [`LiveEnv`], host tests with
/// a staged fake.
///
/// There are no permanent harvested bits here: quiet tables wait,
/// failed attaches retry on the next trigger, and incarnation
/// turnover retires table state while retaining rows and reasons.
pub struct SessionCore {
    pid: u32,
    provider: PathBuf,
    canon: String,
    legacy_enabled: bool,
    class_count: u16,
    tracker: coverage::CoverageTracker,
    retained: coverage::CoverageDelta,
    table_epochs: HashMap<(u32, u64), TableEpoch>,
    next_epoch: u64,
    candidates: Vec<DiscoveredCandidate>,
    /// Dedupe index by [`CandidateKey`]. Value is the candidate index.
    seen: HashMap<CandidateKey, usize>,
    objects: Vec<DiscoveredObject>,
    seen_objects: HashSet<(String, u64)>,
    /// (Array, alg index) → kernel verdict: ROW events join here.
    alg_records: HashMap<(u64, u64), (String, bool, String)>,
    ops_hit: HashSet<u32>,
    queries_events: u64,
    /// Joined CALLS total (`None` until the map is first seen; the
    /// query source pins on first join — see `calls_pinned`).
    calls_joined: Option<u64>,
    calls_pinned: bool,
    emitted_queries: u64,
    emitted_losses: HashMap<u32, u64>,
    loss_seen: HashMap<u32, u64>,
    trip_joined: HashMap<u64, u64>,
    lgcalls_joined: u64,
    trip_hits: Vec<legacy::TripHit>,
    probe_set: Option<legacy::ProbeSet>,
    staged_trips: Option<legacy::ProbeSet>,
    legacy_note: Option<String>,
    attached_queries: HashSet<u64>,
    /// Installed stage-2 target per cookie: (file offset, attach
    /// path). A repeat init resolving elsewhere re-attaches instead
    /// of trusting a stale offset.
    attached_targets: HashMap<u64, (u64, String)>,
    attach_failures: HashMap<u64, String>,
    reloads: HashMap<u64, u64>,
    pending_stage2: std::collections::VecDeque<(u64, u64)>,
    primary_init_observed: bool,
    trigger_observed: bool,
    bootstrap_attached: bool,
    preset_reason: Option<String>,
    resolution: Option<String>,
    trunc_seen: HashMap<u32, u64>,
    stashed: Option<Vec<u8>>,
    last_links: (u64, u64),
    pid_recycled: u64,
    closed: bool,
    recycled: bool,
}

impl SessionCore {
    /// Bare core for staged/test driving: dispatch bootstrap state
    /// starts empty (waiting, retryable). The live session builds
    /// the same core through [`DiscoverySession::attach`], which
    /// then records its bootstrap outcome.
    pub fn new(provider: PathBuf, canon: String, legacy: bool, pid: u32) -> Self {
        Self {
            pid,
            provider,
            canon,
            legacy_enabled: legacy,
            class_count: crate::kinds::ALG_NAMES.len() as u16,
            tracker: coverage::CoverageTracker::new(),
            retained: coverage::CoverageDelta::default(),
            table_epochs: HashMap::new(),
            next_epoch: 0,
            candidates: Vec::new(),
            seen: HashMap::new(),
            objects: Vec::new(),
            seen_objects: HashSet::new(),
            alg_records: HashMap::new(),
            ops_hit: HashSet::new(),
            queries_events: 0,
            calls_joined: None,
            calls_pinned: false,
            emitted_queries: 0,
            emitted_losses: HashMap::new(),
            loss_seen: HashMap::new(),
            trip_joined: HashMap::new(),
            lgcalls_joined: 0,
            trip_hits: Vec::new(),
            probe_set: None,
            staged_trips: None,
            legacy_note: None,
            attached_queries: HashSet::new(),
            attached_targets: HashMap::new(),
            attach_failures: HashMap::new(),
            reloads: HashMap::new(),
            pending_stage2: std::collections::VecDeque::new(),
            primary_init_observed: false,
            trigger_observed: false,
            bootstrap_attached: false,
            preset_reason: None,
            resolution: None,
            trunc_seen: HashMap::new(),
            stashed: None,
            last_links: (0, 0),
            pid_recycled: 0,
            closed: false,
            recycled: false,
        }
    }

    /// Record the live bootstrap outcome (init/builtin anchor
    /// installed, or blind with a preset reason).
    pub(crate) fn set_bootstrap(
        &mut self,
        attached: bool,
        preset_reason: Option<String>,
        resolution: Option<String>,
    ) {
        self.bootstrap_attached = attached;
        self.preset_reason = preset_reason;
        self.resolution = resolution;
    }

    /// Record an attach-time stage-2 install (builtin mode
    /// pre-attaches its query pair): later inits for the cookie
    /// re-resolve against this target and re-attach only when the
    /// callback moved.
    pub(crate) fn mark_query_attached(&mut self, cookie: u64, offset: u64, path: String) {
        self.attached_queries.insert(cookie);
        self.attached_targets.insert(cookie, (offset, path));
    }

    /// Adopt an attach-time legacy plan (first poll planning goes
    /// through [`SessionCore::poll`] instead).
    pub(crate) fn adopt_legacy_plan(&mut self, set: legacy::ProbeSet, note: Option<String>) {
        if self.legacy_note.is_none() {
            self.legacy_note = note;
        }
        self.probe_set = Some(set);
    }

    /// Register (op, arr) under its current incarnation when first
    /// observed; every fresh key mints a new epoch id.
    fn ensure_epoch(&mut self, maps: &[maps::Mapping], op: u32, arr: u64) -> u64 {
        if let Some(t) = self.table_epochs.get(&(op, arr)) {
            return t.epoch;
        }
        let epoch = self.next_epoch;
        self.next_epoch += 1;
        self.table_epochs.insert(
            (op, arr),
            TableEpoch {
                epoch,
                fingerprint: incarnation_of(maps, arr),
            },
        );
        epoch
    }

    /// Reconcile tracked tables against current mappings: an
    /// incarnation change or unload retires the table (proof and
    /// walked set drop, gap retained, join records pruned, kernel
    /// walker state evicted) and a reborn array starts a fresh
    /// unproven epoch. Rows are never retired — only completion
    /// state is. Returns the retirements (for the delta) and the
    /// reborn keys (fresh unproven epochs, always delta-visible).
    fn reconcile_epochs<E: SessionEnv>(
        &mut self,
        env: &mut E,
        maps: &[maps::Mapping],
    ) -> ReconcileOutcome {
        let mut outcome = ReconcileOutcome::default();
        let keys: Vec<(u32, u64)> = self.table_epochs.keys().copied().collect();
        for (op, arr) in keys {
            let now = incarnation_of(maps, arr);
            let Some((epoch, fp)) = self
                .table_epochs
                .get(&(op, arr))
                .map(|t| (t.epoch, t.fingerprint.clone()))
            else {
                continue;
            };
            if fp == now {
                continue;
            }
            let gap = self.tracker.retire_table(op, arr);
            self.retained.accumulate(&gap);
            self.alg_records.retain(|(a, _), _| *a != arr);
            // Generation-bind the kernel walker: without eviction a
            // sticky proof (or a mid-array cursor) from the retired
            // incarnation could satisfy the next one. Eviction
            // failure is explicit loss — and loss forces PARTIAL,
            // which contains any surviving stale proof.
            if let Err(e) = env.evict_array_state(arr) {
                eprintln!("array evict failed: {e:#}");
                self.tracker.note_bad_event(coverage::HOST_EVICT_FAILED);
            }
            outcome.retired.push(TableRetirement { op, epoch, gap });
            match now {
                Some(fp) => {
                    let epoch = self.next_epoch;
                    self.next_epoch += 1;
                    self.table_epochs.insert(
                        (op, arr),
                        TableEpoch {
                            epoch,
                            fingerprint: Some(fp),
                        },
                    );
                    outcome.reborn.push((op, arr));
                }
                None => {
                    self.table_epochs.remove(&(op, arr));
                }
            }
        }
        outcome
            .retired
            .sort_by(|a, b| (a.op, a.epoch).cmp(&(b.op, b.epoch)));
        outcome
    }

    /// Discard all observation state after a pin failure: rows and
    /// trip data are pid-scoped, hence tainted.
    fn mark_recycled(&mut self) {
        self.tracker = coverage::CoverageTracker::new();
        self.retained = coverage::CoverageDelta::default();
        self.table_epochs.clear();
        self.candidates.clear();
        self.seen.clear();
        self.objects.clear();
        self.seen_objects.clear();
        self.alg_records.clear();
        self.ops_hit.clear();
        self.queries_events = 0;
        self.calls_joined = None;
        self.emitted_queries = 0;
        self.emitted_losses.clear();
        self.loss_seen.clear();
        self.trip_joined.clear();
        self.lgcalls_joined = 0;
        self.trip_hits.clear();
        self.probe_set = None;
        self.staged_trips = None;
        self.legacy_note = None;
        self.attached_queries.clear();
        self.attached_targets.clear();
        self.attach_failures.clear();
        self.reloads.clear();
        self.pending_stage2.clear();
        self.stashed = None;
        self.primary_init_observed = false;
        self.trigger_observed = false;
        self.trunc_seen.clear();
        self.pid_recycled = 1;
        self.recycled = true;
    }

    fn recycled_err(&self) -> anyhow::Error {
        anyhow::Error::new(Recycled {
            snapshot: self.snapshot(),
        })
    }

    fn pop_event<E: SessionEnv>(&mut self, env: &mut E) -> Option<Vec<u8>> {
        if let Some(ev) = self.stashed.take() {
            return Some(ev);
        }
        env.next_event()
    }

    fn queries_total(&self) -> u64 {
        self.calls_joined.unwrap_or(self.queries_events)
    }

    /// Current (state, sticky TRUNC bits) for one live table.
    fn live_table_state(&self, op: u32, arr: u64) -> (CoverageState, u64) {
        let state = match self.tracker.table_state(op, arr) {
            coverage::TableState::Unseen => CoverageState::Unseen,
            coverage::TableState::InProgress { walked } => CoverageState::InProgress { walked },
            coverage::TableState::Terminated { len } => CoverageState::Terminated { len },
        };
        (state, self.trunc_seen.get(&op).copied().unwrap_or(0))
    }

    /// One bounded poll: verify the pin, reconcile epochs, plan
    /// deferred tripwires, decode up to `budget.max_events` ring
    /// items, install up to `budget.max_attaches` pending links,
    /// and join one round of maps. Returns this poll's typed delta;
    /// cumulative state is available via [`SessionCore::snapshot`].
    pub fn poll<E: SessionEnv>(
        &mut self,
        env: &mut E,
        budget: PollBudget,
    ) -> anyhow::Result<DiscoveryDelta> {
        if self.closed {
            bail!("discovery session is closed");
        }
        if self.recycled {
            return Err(self.recycled_err());
        }
        // Pin FIRST: tainted events must not drive attaches.
        if env.verify_pin().is_err() {
            self.mark_recycled();
            return Err(self.recycled_err());
        }
        let mut maps = env.current_maps();
        let mut delta = DiscoveryDelta::default();
        let mut touched: HashSet<(u32, u64)> = HashSet::new();
        let rec = self.reconcile_epochs(env, &maps);
        delta.retirements = rec.retired;
        touched.extend(rec.reborn);

        let mut attaches_done = 0u32;
        // Deferred legacy planning: pre-exec images have no
        // libcrypto; plan at the first poll where it appears, and
        // install under the same attach budget as stage-2 pairs (a
        // zero budget stages the plan without installing).
        if self.legacy_enabled && self.probe_set.is_none() {
            if self.staged_trips.is_none() && legacy::find_libcrypto(&maps).is_some() {
                self.staged_trips = env.plan_trips(&maps)?;
            }
            if let Some(set) = self.staged_trips.clone()
                && attaches_done < budget.max_attaches
            {
                attaches_done += 1;
                let count = set.probes.len();
                let note = env.install_trips(&set, self.pid)?;
                if self.legacy_note.is_none() {
                    self.legacy_note = note;
                }
                self.probe_set = Some(set);
                self.staged_trips = None;
                delta.attaches.push(AttachEvent {
                    kind: AttachKind::Tripwires { count },
                    failed: None,
                });
            }
        }

        let mut consumed = 0u64;
        while consumed < budget.max_events {
            let Some(item) = self.pop_event(env) else {
                break;
            };
            consumed += 1;
            self.ingest_one(&maps, &item, &mut delta, &mut touched);
        }
        delta.events_consumed = consumed;
        // Exact exhaustion signal: probe one past the budget and
        // stash it for the next poll (backpressure, not loss).
        if consumed == budget.max_events
            && let Some(extra) = env.next_event()
        {
            self.stashed = Some(extra);
            delta.budget_exhausted = true;
        }

        // Resolve against fresh mappings: a provider that loaded
        // after the poll-start snapshot (file reads sit between the
        // snapshot and this drain) must still resolve.
        if !self.pending_stage2.is_empty() {
            maps = env.current_maps();
        }
        // Bounded pending stage-2 installs (FIFO across polls),
        // sharing the budget with the tripwire batch above.
        while attaches_done < budget.max_attaches {
            let Some((cookie, addr)) = self.pending_stage2.pop_front() else {
                break;
            };
            attaches_done += 1;
            // Tainted events must not drive stage-2 attaches.
            if env.verify_pin().is_err() {
                self.mark_recycled();
                return Err(self.recycled_err());
            }
            match harvest::resolve_query_target(&maps, &self.provider, &self.canon, addr, cookie) {
                Err(e) => self.record_attach_failure(
                    &mut delta,
                    cookie,
                    format!("resolve stage-2 for cookie {cookie}: {e:#}"),
                ),
                Ok((off, path)) => {
                    let target = (off, path.to_string_lossy().into_owned());
                    if self.attached_queries.contains(&cookie)
                        && self.attached_targets.get(&cookie) == Some(&target)
                    {
                        // Same callback: the install stands; fault
                        // the cold pages back in (best-effort).
                        env.pretouch(cookie, addr);
                        continue;
                    }
                    match env.install_stage2(cookie, off, &path, self.pid) {
                        Err(e) => {
                            self.record_attach_failure(&mut delta, cookie, format!("{e:#}"));
                        }
                        Ok(()) => {
                            self.attached_queries.insert(cookie);
                            self.attached_targets.insert(cookie, target);
                            self.attach_failures.remove(&cookie);
                            env.pretouch(cookie, addr);
                            delta.attaches.push(AttachEvent {
                                kind: AttachKind::Stage2 { cookie },
                                failed: None,
                            });
                        }
                    }
                }
            }
        }
        if self.staged_trips.is_some() || !self.pending_stage2.is_empty() {
            delta.budget_exhausted = true;
        }

        // Map-only transitions (a late proof, a fresh TRUNC bit)
        // are delta-visible too: compare every tracked table
        // across the join.
        let pre_join: HashMap<(u32, u64), (CoverageState, u64)> = self
            .table_epochs
            .keys()
            .map(|(op, arr)| ((*op, *arr), self.live_table_state(*op, *arr)))
            .collect();
        let snap = env.join_maps();
        self.join_snapshots(&snap, &mut delta);
        for (op, arr) in self.table_epochs.keys() {
            let cur = self.live_table_state(*op, *arr);
            if pre_join.get(&(*op, *arr)) != Some(&cur) {
                touched.insert((*op, *arr));
            }
        }

        let mut tables: Vec<TableCoverage> = Vec::with_capacity(touched.len());
        for (op, arr) in &touched {
            let Some(t) = self.table_epochs.get(&(*op, *arr)) else {
                continue;
            };
            let (state, trunc_bits) = self.live_table_state(*op, *arr);
            tables.push(TableCoverage {
                op: *op,
                epoch: t.epoch,
                state,
                trunc_bits,
            });
        }
        tables.sort_by(|a, b| (a.op, a.epoch).cmp(&(b.op, b.epoch)));
        delta.tables = tables;

        // Fresh losses: positive diffs of the cumulative tracker
        // against what earlier deltas already reported.
        for (src, n) in self.tracker.losses() {
            let last = self.emitted_losses.get(&src).copied().unwrap_or(0);
            if n > last {
                delta.losses.push(DiscoveryLoss {
                    source: src,
                    count: n - last,
                });
            }
            self.emitted_losses.insert(src, n);
        }
        let total = self.queries_total();
        delta.queries_delta = total.saturating_sub(self.emitted_queries);
        self.emitted_queries = total;
        delta.trigger_observed = self.trigger_observed;

        self.last_links = env.link_counts();
        Ok(delta)
    }

    fn record_attach_failure(&mut self, delta: &mut DiscoveryDelta, cookie: u64, msg: String) {
        // Retryable state, not a terminal verdict: the next init
        // for this cookie re-attempts the install.
        self.attach_failures.insert(cookie, msg.clone());
        delta.attaches.push(AttachEvent {
            kind: AttachKind::Stage2 { cookie },
            failed: Some(msg),
        });
    }

    /// Join one round of map snapshots: `TERMD`/`TRUNC`
    /// idempotently, cumulative counters monotonically (only
    /// increments reach the tracker and the delta). Every baseline
    /// is a high-water mark: a dipped or partial read (failed
    /// iteration, reset map) never moves a baseline backward, so
    /// `5→0→5` reports five once, not twice. Kernel counters are
    /// `u64` monotonic (a wrap needs 2⁶⁴ events); a dip always
    /// means a bad read, and bad reads are flagged below.
    fn join_snapshots(&mut self, snap: &MapSnapshots, delta: &mut DiscoveryDelta) {
        self.tracker.ingest_termd(&snap.termd);
        self.tracker.ingest_trunc(&snap.trunc);
        for (op, bits) in &snap.trunc {
            *self.trunc_seen.entry(*op).or_default() |= *bits;
        }
        for (src, n) in &snap.losses {
            let last = self.loss_seen.get(src).copied().unwrap_or(0);
            if *n > last {
                self.loss_seen.insert(*src, *n);
                self.tracker.ingest_losses(&[(*src, *n - last)]);
            }
        }
        for failed in [
            snap.trunc_failed,
            snap.termd_failed,
            snap.losses_failed,
            snap.trip_failed,
            snap.calls_failed,
            snap.lgcalls_failed,
        ] {
            if failed {
                self.tracker.note_map_snapshot();
            }
        }
        // The query source pins on first join: CALLS-joined when
        // the map exists (always, live), event-count otherwise. A
        // later missing read keeps the last total rather than
        // flapping sources mid-stream.
        if !self.calls_pinned {
            self.calls_pinned = true;
            self.calls_joined = snap.calls;
        } else if let (Some(cur), Some(c)) = (self.calls_joined, snap.calls) {
            self.calls_joined = Some(cur.max(c));
        }
        let joined: HashMap<u64, u64> = snap.trip.iter().copied().collect();
        for (cookie, n) in &joined {
            let last = self.trip_joined.get(cookie).copied().unwrap_or(0);
            if *n > last {
                delta.tripwire.counter_deltas.push((*cookie, *n - last));
                self.trip_joined.insert(*cookie, *n);
            }
        }
        delta.tripwire.counter_deltas.sort_unstable();
        if snap.lgcalls > self.lgcalls_joined {
            delta.tripwire.executed_legacy_queries_delta = snap.lgcalls - self.lgcalls_joined;
            self.lgcalls_joined = snap.lgcalls;
        }
    }

    /// Decode one raw ring item into core state. Payloads are small
    /// numerics-only structs (shared wire ABI v2): unknown kinds
    /// cannot be sized, so they are dropped before any field is
    /// read. Every drop path counts its loss at the drop site.
    #[allow(clippy::too_many_lines, reason = "one decode dispatch per wire kind")]
    fn ingest_one(
        &mut self,
        maps: &[maps::Mapping],
        b: &[u8],
        delta: &mut DiscoveryDelta,
        touched: &mut HashSet<(u32, u64)>,
    ) {
        if b.len() < 4 {
            eprintln!("short event: {} bytes", b.len());
            self.tracker.note_bad_event(coverage::HOST_SHORT_EVENT);
            return;
        }
        let kind = u32::from_le_bytes(b[0..4].try_into().unwrap());
        let want = match kind {
            wire::KIND_INIT_RET => size_of::<wire::InitRetEvent>(),
            wire::KIND_QUERY_RET | wire::KIND_ROW => size_of::<wire::RowEvent>(),
            wire::KIND_ALG => size_of::<wire::AlgEvent>(),
            wire::KIND_TRIP => size_of::<wire::TripEvent>(),
            k => {
                eprintln!("unknown event kind {k}");
                self.tracker.note_bad_event(coverage::HOST_UNKNOWN_KIND);
                return;
            }
        };
        if b.len() < want {
            eprintln!("short event: {} bytes", b.len());
            self.tracker.note_bad_event(coverage::HOST_SHORT_EVENT);
            return;
        }
        match kind {
            wire::KIND_INIT_RET => {
                let Ok(ev) = wire::parse_init_ret_event(b) else {
                    eprintln!("bad init-ret event");
                    self.tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                    return;
                };
                // aux carries the attach cookie: 0 = target
                // provider, 1 = legacy.
                let cookie = ev.aux;
                if self.attached_queries.contains(&cookie) {
                    // Repeat init (unload/reload cycles,
                    // multi-libctx): witness the reload and queue
                    // for the bounded drain, which re-resolves and
                    // re-attaches when the callback moved, else
                    // faults the cold pages back in.
                    *self.reloads.entry(cookie).or_default() += 1;
                    self.pending_stage2.push_back((cookie, ev.addr));
                    return;
                }
                if cookie == 0 {
                    self.primary_init_observed = true;
                }
                // Resolution + install happen in the bounded
                // pending drain below; failures are recorded for
                // event-driven retry on the next init.
                self.pending_stage2.push_back((cookie, ev.addr));
            }
            wire::KIND_QUERY_RET => {
                let Ok(ev) = wire::parse_row_event(b) else {
                    eprintln!("bad query-ret event");
                    self.tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                    return;
                };
                if ev.kind != wire::KIND_QUERY_RET || ev.funcid != 0 {
                    self.tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                    return;
                }
                self.trigger_observed = true;
                self.queries_events += 1;
                self.ops_hit.insert(ev.op);
                self.ensure_epoch(maps, ev.op, ev.addr);
                self.tracker.note_query_ret(ev.op, ev.addr);
                touched.insert((ev.op, ev.addr));
                if debug_session() {
                    eprintln!("HARVESTDBG query_ret op={} slot={}", ev.op, ev.aux);
                }
            }
            wire::KIND_ALG => {
                let Ok(ev) = wire::parse_alg_event(b, self.class_count) else {
                    eprintln!("bad alg event");
                    self.tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                    return;
                };
                self.trigger_observed = true;
                let Some(label) = crate::kinds::alg_class_label(ev.class) else {
                    eprintln!("alg event with out-of-range class {}", ev.class);
                    self.tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                    return;
                };
                let Some(status) = wire::alg_status_name(ev.status) else {
                    eprintln!("alg event with out-of-range status {}", ev.status);
                    self.tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                    return;
                };
                if debug_session() {
                    eprintln!(
                        "{}",
                        debug_alg_line(ev.op, ev.idx, label, ev.weak != 0, ev.status)
                    );
                }
                // Unreadable/overlong names lose the slot's
                // identity (no retained prefix); unknown names
                // are explicit `other` evidence, not loss.
                let lossy = ev.status == wire::ALG_UNREADABLE || ev.status == wire::ALG_OVERLONG;
                self.ensure_epoch(maps, ev.op, ev.arr);
                self.tracker.note_alg(ev.op, ev.arr, ev.idx, lossy);
                self.alg_records.insert(
                    (ev.arr, ev.idx),
                    (label.to_string(), ev.weak != 0, status.to_string()),
                );
                touched.insert((ev.op, ev.arr));
            }
            wire::KIND_ROW => {
                let Ok(ev) = wire::parse_row_event(b) else {
                    eprintln!("bad row event");
                    self.tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                    return;
                };
                if ev.kind != wire::KIND_ROW {
                    self.tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                    return;
                }
                self.trigger_observed = true;
                touched.insert((ev.op, ev.aux));
                let Some((label, weak, status)) = self.alg_records.get(&(ev.aux, ev.idx)).cloned()
                else {
                    eprintln!("orphan row: op={} idx={}", ev.op, ev.idx);
                    self.tracker.note_orphan_row();
                    return;
                };
                let key = (
                    ev.op,
                    label.clone(),
                    weak,
                    status.clone(),
                    ev.funcid,
                    ev.addr,
                    ev.aux,
                );
                let advertising = array_owner(maps, ev.aux);
                let (backing, locator) = attribute_impl(maps, &self.provider, &self.canon, ev.addr);
                if let Some(&i) = self.seen.get(&key) {
                    // Duplicate key (multi-libctx re-query): refresh
                    // identities when the current mappings attest a
                    // new owner or backing (same-address remap),
                    // else skip. A missing backing now (transient
                    // unmap) never overwrites an attested triple —
                    // the render re-derives from live maps.
                    let mut changed = false;
                    if self.candidates[i].advertising != advertising {
                        self.candidates[i].advertising = advertising;
                        changed = true;
                    }
                    if let Some(b) = &backing
                        && self.candidates[i].backing.as_ref() != Some(b)
                    {
                        if self.seen_objects.insert((b.dev.clone(), b.ino)) {
                            let obj = DiscoveredObject {
                                dev: b.dev.clone(),
                                ino: b.ino,
                                display_locator: locator,
                            };
                            self.objects.push(obj.clone());
                            delta.objects.push(obj);
                        }
                        self.candidates[i].backing = Some(b.clone());
                        changed = true;
                    }
                    if changed {
                        delta.candidates.push(self.candidates[i].clone());
                    }
                } else {
                    let epoch = self.ensure_epoch(maps, ev.op, ev.aux);
                    if let Some(b) = &backing
                        && self.seen_objects.insert((b.dev.clone(), b.ino))
                    {
                        let obj = DiscoveredObject {
                            dev: b.dev.clone(),
                            ino: b.ino,
                            display_locator: locator,
                        };
                        self.objects.push(obj.clone());
                        delta.objects.push(obj);
                    }
                    let candidate = DiscoveredCandidate {
                        advertising,
                        backing,
                        op: ev.op,
                        funcid: ev.funcid,
                        class: label,
                        weak,
                        status,
                        epoch,
                        impl_addr: ev.addr,
                        arr: ev.aux,
                    };
                    self.seen.insert(key, self.candidates.len());
                    self.candidates.push(candidate.clone());
                    delta.candidates.push(candidate);
                }
            }
            wire::KIND_TRIP => {
                // Deliberately NOT a dispatch trigger (doctrine:
                // tripwires observe independently of the dispatch
                // harvest).
                let Ok(ev) = wire::parse_trip_event(b) else {
                    eprintln!("bad trip event");
                    self.tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                    return;
                };
                // Trip events imply attached tripwires, which imply
                // a planned probe set; without one the cookie
                // cannot be validated, so the hit is dropped.
                if self.probe_set.is_none() {
                    eprintln!("trip hit before probe plan");
                    self.tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                    return;
                }
                let hit = {
                    let set = self.probe_set.as_ref().expect("checked above");
                    harvest::decode_trip_hit(ev.cookie as u64, ev.class, ev.status, set)
                };
                match hit {
                    Some(hit) => {
                        self.trip_hits.push(hit);
                        delta.tripwire.hits.push(hit);
                    }
                    None => {
                        eprintln!(
                            "trip hit outside taxonomy: cookie={} class={}",
                            ev.cookie, ev.class
                        );
                        self.tracker.note_bad_event(coverage::HOST_BAD_EVENT);
                    }
                }
            }
            // Unreachable: unknown kinds are dropped at the sizing
            // match above, before any field is read.
            _ => {}
        }
    }

    /// Cumulative discovery state. Candidates, objects, tables, and
    /// reasons all serialize deterministically (total orders,
    /// never arrival order).
    pub fn snapshot(&self) -> DiscoverySnapshot {
        let mut candidates = self.candidates.clone();
        candidates.sort_by(|a, b| {
            (
                a.op,
                &a.class,
                &a.status,
                a.funcid,
                a.epoch,
                a.backing.as_ref(),
            )
                .cmp(&(
                    b.op,
                    &b.class,
                    &b.status,
                    b.funcid,
                    b.epoch,
                    b.backing.as_ref(),
                ))
        });
        let mut objects = self.objects.clone();
        objects.sort_by(|a, b| (&a.dev, a.ino).cmp(&(&b.dev, b.ino)));
        let mut tables: Vec<TableCoverage> = self
            .table_epochs
            .iter()
            .map(|((op, arr), t)| {
                let (state, trunc_bits) = self.live_table_state(*op, *arr);
                TableCoverage {
                    op: *op,
                    epoch: t.epoch,
                    state,
                    trunc_bits,
                }
            })
            .collect();
        tables.sort_by(|a, b| (a.op, a.epoch).cmp(&(b.op, b.epoch)));
        let mut truncated_ops: Vec<(u32, u64)> =
            self.trunc_seen.iter().map(|(op, b)| (*op, *b)).collect();
        truncated_ops.sort_unstable();
        let mut ops_hit: Vec<u32> = self.ops_hit.iter().copied().collect();
        ops_hit.sort_unstable();
        let mut attach_failures: Vec<AttachFailure> = self
            .attach_failures
            .iter()
            .map(|(cookie, error)| AttachFailure {
                cookie: *cookie,
                error: error.clone(),
            })
            .collect();
        attach_failures.sort_by(|a, b| a.cookie.cmp(&b.cookie));
        let mut reloads: Vec<(u64, u64)> = self.reloads.iter().map(|(c, n)| (*c, *n)).collect();
        reloads.sort_unstable();
        DiscoverySnapshot {
            candidates,
            objects,
            tables,
            reasons: union_reasons(&self.retained.reasons, &self.tracker.reasons()),
            retained_reasons: self.retained.reasons.clone(),
            losses: self.tracker.losses(),
            truncated_ops,
            lossy_slots: self.tracker.lossy_slots(),
            queries_observed: self.queries_total(),
            ops_hit,
            dispatch: DispatchSnapshot {
                attached: self.bootstrap_attached || !self.attached_queries.is_empty(),
                preset_reason: self.preset_reason.clone(),
                resolution: self.resolution.clone(),
                attach_failures,
                reloads,
                primary_init_observed: self.primary_init_observed,
                trigger_observed: self.trigger_observed,
            },
            legacy: LegacySnapshot {
                planned: self.probe_set.is_some(),
                set: self.probe_set.clone(),
                trip: self.trip_joined.clone(),
                hits: self.trip_hits.clone(),
                executed_queries: self.lgcalls_joined,
                extra_findings: self.legacy_note.clone().into_iter().collect(),
            },
            links_live: LinkLiveness {
                dispatch: self.last_links.0,
                tripwire: self.last_links.1,
            },
            pid_recycled: self.pid_recycled,
        }
    }

    /// Quiesce-then-PROCESS teardown: drop the attach links first
    /// (no new events can arrive past this point), count the ring
    /// tail exactly into drain shortfall, join the maps once more,
    /// and verify the pin — so no post-stop arrival escapes
    /// accounting. Consumes nothing: the closed session keeps its
    /// final snapshot but rejects further polls.
    pub fn close<E: SessionEnv>(&mut self, env: &mut E) -> anyhow::Result<DiscoverySnapshot> {
        if self.closed {
            bail!("discovery session is already closed");
        }
        self.closed = true;
        // Final reconcile so the closing snapshot never carries a
        // stale-epoch table (retirements feed the retained gaps).
        let maps = env.current_maps();
        self.reconcile_epochs(env, &maps);
        env.quiesce();
        let mut shortfall: u64 = 0;
        while self.pop_event(env).is_some() {
            shortfall += 1;
        }
        if shortfall > 0 {
            eprintln!("drain shortfall: {shortfall} unprocessed ring items at stop");
        }
        self.tracker.note_drain_shortfall(shortfall);
        // Final join feeds cumulative state only (the close-time
        // delta is discarded — the snapshot below carries it).
        let snap = env.join_maps();
        let mut delta = DiscoveryDelta::default();
        self.join_snapshots(&snap, &mut delta);
        self.last_links = env.link_counts();
        if env.verify_pin().is_err() {
            self.mark_recycled();
            return Err(self.recycled_err());
        }
        Ok(self.snapshot())
    }
}

/// Advertising identity for one array: the mapped path of the
/// file owning the array, or `""` for anonymous/unmapped arrays
/// (which carry no attributable owner).
fn array_owner(maps: &[maps::Mapping], arr: u64) -> String {
    maps.iter()
        .find(|m| m.start <= arr && arr < m.end && m.ino != 0)
        .map(|m| m.path.clone())
        .unwrap_or_default()
}

/// Relocate one implementation address to its claimed backing
/// triple plus the owning locator: the provider mapping first,
/// then any file mapping (shared-code rows), else unbacked. This
/// mirrors the document render's mapping rule minus the
/// executable/ELF-segment verification, which stays render-side.
fn attribute_impl(
    maps: &[maps::Mapping],
    provider: &Path,
    canon: &str,
    addr: u64,
) -> (Option<BackingRef>, String) {
    if let Some(m) = maps::provider_mapping(maps, provider, canon, addr) {
        let backing = BackingRef {
            dev: m.dev.clone(),
            ino: m.ino,
            offset: addr - m.start + m.offset,
        };
        return (Some(backing), m.path.clone());
    }
    if let Some(m) = maps
        .iter()
        .find(|m| m.start <= addr && addr < m.end && m.ino != 0)
    {
        let backing = BackingRef {
            dev: m.dev.clone(),
            ino: m.ino,
            offset: addr - m.start + m.offset,
        };
        return (Some(backing), m.path.clone());
    }
    (None, String::new())
}

/// Ranked union of retained and live gap reasons: the frozen
/// ranking orders known reasons; unrecognized strings (newer
/// producer than consumer) append sorted rather than vanishing.
fn union_reasons(retained: &[String], live: &[String]) -> Vec<String> {
    use coverage::ReasonFlags;
    let has = |r: &str| retained.iter().any(|x| x == r) || live.iter().any(|x| x == r);
    let mut out: Vec<String> = coverage::ranked_reasons(&ReasonFlags {
        fenced: has(coverage::REASON_FENCED_ROWS),
        loss: has(coverage::REASON_DISCOVERY_LOSS),
        unreadable: has(coverage::REASON_UNREADABLE_ALG),
        truncated: has(coverage::REASON_TRUNCATED_WALK),
        prefix: has(coverage::REASON_PREFIX_WALK),
        zero_row: has(coverage::REASON_ZERO_ROW_OPS),
    })
    .into_iter()
    .map(str::to_string)
    .collect();
    let known = |r: &str| {
        [
            coverage::REASON_FENCED_ROWS,
            coverage::REASON_DISCOVERY_LOSS,
            coverage::REASON_UNREADABLE_ALG,
            coverage::REASON_TRUNCATED_WALK,
            coverage::REASON_PREFIX_WALK,
            coverage::REASON_ZERO_ROW_OPS,
        ]
        .contains(&r)
    };
    let mut extra: Vec<String> = retained
        .iter()
        .chain(live.iter())
        .filter(|r| !known(r))
        .cloned()
        .collect();
    extra.sort_unstable();
    extra.dedup();
    out.extend(extra);
    out
}

// ---------------------------------------------------------------------------
// Live environment: BPF resources owned until session drop.
// ---------------------------------------------------------------------------

/// Attach-link plane: dispatch anchors/pairs vs tripwires (the
/// liveness witness keeps the planes separate).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinkKind {
    Init,
    Query,
    Tripwire,
}

/// Owned multi links (drop = detach) with their plane records.
#[derive(Default)]
pub(crate) struct LinkSet {
    links: Vec<(OwnedFd, LinkKind)>,
}

impl LinkSet {
    fn push(&mut self, fd: OwnedFd, kind: LinkKind) {
        self.links.push((fd, kind));
    }

    fn clear(&mut self) {
        self.links.clear();
    }

    fn counts(&self) -> (u64, u64) {
        let mut dispatch = 0u64;
        let mut tripwire = 0u64;
        for (_, kind) in &self.links {
            match kind {
                LinkKind::Init | LinkKind::Query => dispatch += 1,
                LinkKind::Tripwire => tripwire += 1,
            }
        }
        (dispatch, tripwire)
    }
}

/// Path for a multi link: the kernel resolves it per mapping, so
/// the caller's (possibly relative) path is passed through as-is.
fn link_path(path: &Path) -> anyhow::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| anyhow!("attach path contains NUL: {}", path.display()))
}

fn prog_fd(loaded: &Loaded, name: &str) -> anyhow::Result<std::os::fd::RawFd> {
    loaded
        .progs
        .get(name)
        .map(AsRawFd::as_raw_fd)
        .ok_or_else(|| anyhow!("missing program {name}"))
}

#[allow(clippy::too_many_arguments, reason = "one coherent attach spec")]
fn attach_pair(
    loaded: &Loaded,
    links: &mut LinkSet,
    entry: &str,
    ret: &str,
    offset: u64,
    path: &Path,
    pid: u32,
    cookie: u64,
    kind: LinkKind,
) -> anyhow::Result<()> {
    let cpath = link_path(path)?;
    // Both links publish only after the pair succeeds: a failed
    // return-probe attach must not leave its entry link live (the
    // session retries, so a leak would accumulate double-firing
    // entry probes).
    let entry_link = ossl_bpf_sys::link_create_uprobe_multi(
        prog_fd(loaded, entry)?,
        &cpath,
        &[offset],
        &[cookie],
        pid,
    )
    .map_err(|e| anyhow!("attach {entry}@{offset:#x}: {e}"))?;
    let ret_link = ossl_bpf_sys::link_create_uretprobe_multi(
        prog_fd(loaded, ret)?,
        &cpath,
        &[offset],
        &[cookie],
        pid,
    )
    .map_err(|e| anyhow!("attach {ret}@{offset:#x}: {e}"))?;
    links.push(entry_link, kind);
    links.push(ret_link, kind);
    Ok(())
}

/// Attach legacy tripwires: one multi link per (module, program)
/// with the probes' offsets + cookies batched.
fn attach_trips(
    loaded: &Loaded,
    links: &mut LinkSet,
    set: &legacy::ProbeSet,
    pid: u32,
) -> anyhow::Result<()> {
    type OffsetsCookies = (Vec<u64>, Vec<u64>);
    let mut groups: HashMap<(&str, &str), OffsetsCookies> = HashMap::new();
    for p in &set.probes {
        let (offs, cookies) = groups.entry((p.module.as_str(), p.program)).or_default();
        offs.push(p.offset);
        cookies.push(p.cookie);
    }
    let mut keys: Vec<(&str, &str)> = groups.keys().copied().collect();
    keys.sort_unstable();
    for (module, prog_name) in keys {
        let (offsets, cookies) = &groups[&(module, prog_name)];
        let cpath = link_path(Path::new(module))?;
        let link = ossl_bpf_sys::link_create_uprobe_multi(
            prog_fd(loaded, prog_name)?,
            &cpath,
            offsets,
            cookies,
            pid,
        )
        .map_err(|e| anyhow!("attach {prog_name}@{module}+{}: {e}", offsets.len()))?;
        links.push(link, LinkKind::Tripwire);
    }
    Ok(())
}

/// Load the frozen harvest shape: `prepare` asserts dims vs the
/// object (fail-closed on drift), `load` creates maps + progs raw
/// with `expected_attach_type=UPROBE_MULTI`. Verifier failures
/// surface before any attach.
fn load_frozen(obj_bytes: &[u8]) -> anyhow::Result<Loaded> {
    let prep = crate::loader::prepare(
        obj_bytes,
        &crate::loader::HARVEST_MAPS,
        &crate::loader::HARVEST_PROGS,
    )?;
    crate::loader::load(&prep)
}

/// Populate the kernel classifier tables right after map creation,
/// before any attach can fire. Observer-owned registry bytes only;
/// no target memory is involved.
fn populate_classifier_maps(maps: &HashMap<String, OwnedFd>) -> anyhow::Result<()> {
    let put = |map: &str, key: &[u8], value: &[u8]| -> anyhow::Result<()> {
        let fd = maps
            .get(map)
            .ok_or_else(|| anyhow!("missing classifier map {map}"))?;
        ossl_bpf_sys::map_update_elem(fd.as_raw_fd(), key, value, 0)
            .with_context(|| format!("populate {map}"))?;
        Ok(())
    };
    for (h, v) in harvest::build_alg_entries()? {
        put("ALG_CLASS", &h.to_le_bytes(), &wire::alg_value_bytes(&v))?;
    }
    for (h, v) in harvest::build_trip_entries()? {
        put("TRIP_CLASS", &h.to_le_bytes(), &wire::trip_value_bytes(&v))?;
    }
    Ok(())
}

/// Fault in the provider file's mapped pages (best-effort, one byte
/// per page via process_vm_readv). BPF probe reads are nofault: a
/// query whose alg tables were never touched aborts the walk even
/// though the table is valid. Failures only degrade to abort-retry
/// + loud TRUNC, never to silence.
fn pretouch_mappings(pid: u32, live: &[maps::Mapping], path: &Path, canon: &str) {
    let arg = path.to_string_lossy();
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as u64;
    let mut pages: Vec<u64> = Vec::new();
    for m in live {
        if m.ino == 0
            || !(m.path == arg || m.path == canon || (!canon.is_empty() && m.path.ends_with(canon)))
        {
            continue;
        }
        let mut p = m.start & !(page - 1);
        while p < m.end {
            pages.push(p);
            p += page;
        }
    }
    if pages.is_empty() {
        return;
    }
    // One local byte per remote page; chunk under UIO_MAXIOV (1024).
    let mut sink = vec![0u8; pages.len().min(1000)];
    for chunk in pages.chunks(1000) {
        sink.resize(chunk.len(), 0);
        let local = libc::iovec {
            iov_base: sink.as_mut_ptr() as *mut libc::c_void,
            iov_len: chunk.len(),
        };
        let remote: Vec<libc::iovec> = chunk
            .iter()
            .map(|p| libc::iovec {
                iov_base: *p as *mut libc::c_void,
                iov_len: 1,
            })
            .collect();
        let n = unsafe {
            libc::process_vm_readv(
                pid as libc::pid_t,
                &local,
                1,
                remote.as_ptr(),
                remote.len() as libc::c_ulong,
                0,
            )
        };
        if n < 0 && debug_session() {
            eprintln!(
                "HARVESTDBG pretouch pid={pid} pages={} err={}",
                chunk.len(),
                std::io::Error::last_os_error()
            );
        }
    }
}

/// Candidate legacy.so paths for pre-mapping init attach: the
/// target's OPENSSL_MODULES dir plus libcrypto's ossl-modules dir
/// (existing files only; whichever loads fires the cookie-1 init).
fn legacy_candidates(pid: u32, libcrypto: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut consider = |p: PathBuf| {
        if p.is_file() && !out.contains(&p) {
            out.push(p);
        }
    };
    if let Ok(env) = std::fs::read(format!("/proc/{pid}/environ")) {
        for kv in env.split(|b| *b == 0) {
            if let Some(v) = kv
                .strip_prefix(b"OPENSSL_MODULES=")
                .and_then(|v| std::str::from_utf8(v).ok())
            {
                for dir in v.split(':') {
                    consider(PathBuf::from(dir).join("legacy.so"));
                }
            }
        }
    }
    if let Some(dir) = Path::new(libcrypto).parent() {
        consider(dir.join("ossl-modules").join("legacy.so"));
    }
    out
}

/// Typed hash-map handle over a dup'd raw fd (aya in its P2
/// role: typed access only — load/attach went raw).
fn open_hash<K, V>(
    maps: &HashMap<String, OwnedFd>,
    name: &str,
) -> anyhow::Result<aya::maps::HashMap<MapData, K, V>>
where
    K: aya::Pod + Eq + std::hash::Hash,
    V: aya::Pod,
{
    let fd = maps
        .get(name)
        .and_then(|f| f.try_clone().ok())
        .ok_or_else(|| anyhow!("missing map {name}"))?;
    let data = MapData::from_fd(fd).map_err(|e| anyhow!("{name} mapdata: {e}"))?;
    let map = Map::from_map_data(data).map_err(|e| anyhow!("{name} map: {e}"))?;
    aya::maps::HashMap::<_, K, V>::try_from(map).map_err(|e| anyhow!("{name} shape: {e}"))
}

/// Typed hash-map read: returns the rows plus whether the snapshot
/// failed (setup or iteration). Every map reads checked, so a
/// failed snapshot becomes explicit snapshot loss, never a silent
/// "no truncation / no loss" read.
fn read_kv_checked<K, V>(maps: &HashMap<String, OwnedFd>, name: &str) -> (Vec<(K, V)>, bool)
where
    K: aya::Pod + Eq + std::hash::Hash,
    V: aya::Pod,
{
    let Ok(map) = open_hash::<K, V>(maps, name) else {
        return (Vec::new(), true);
    };
    let mut out = Vec::new();
    let mut failed = false;
    for r in map.iter() {
        match r {
            Ok(kv) => out.push(kv),
            Err(_) => failed = true,
        }
    }
    (out, failed)
}

/// Delete one hash-map element; an absent key succeeds (already
/// evicted), anything else reports.
fn delete_elem<K, V>(map: &mut aya::maps::HashMap<MapData, K, V>, key: &K) -> anyhow::Result<()>
where
    K: aya::Pod + Eq + std::hash::Hash,
    V: aya::Pod,
{
    match map.remove(key) {
        Ok(()) => Ok(()),
        Err(aya::maps::MapError::SyscallError(e))
            if e.io_error.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(())
        }
        Err(e) => Err(anyhow!("{e}")),
    }
}

/// Evict one array's `TERMD` proof: a sticky proof from a retired
/// incarnation must never satisfy the next one.
fn evict_termd(maps: &HashMap<String, OwnedFd>, arr: u64) -> anyhow::Result<()> {
    let mut termd = open_hash::<u64, u64>(maps, "TERMD")?;
    delete_elem(&mut termd, &arr).context("evict TERMD")
}

/// Evict one array's `QUERY_NEXT` cursors across all threads (low
/// key half is the array base): the next incarnation's walk
/// restarts at slot 0 instead of resuming mid-array.
fn evict_cursors(maps: &HashMap<String, OwnedFd>, arr: u64) -> anyhow::Result<()> {
    let mut cursors = open_hash::<u128, u64>(maps, "QUERY_NEXT")?;
    // Collect first: deleting during iteration races concurrent
    // kernel inserts.
    let mut victims = Vec::new();
    for r in cursors.iter() {
        let (k, _) = r.map_err(|e| anyhow!("iterate QUERY_NEXT: {e}"))?;
        if k as u64 == arr {
            victims.push(k);
        }
    }
    for k in victims {
        delete_elem(&mut cursors, &k).context("evict QUERY_NEXT")?;
    }
    Ok(())
}

/// Load-mandated init anchor, present even in stripped modules.
const INIT_ANCHOR: &str = "OSSL_provider_init";

/// The privileged [`SessionEnv`]: real ring, maps, links, pin, and
/// `/proc` reads. Owned by [`DiscoverySession`] until session drop.
pub struct LiveEnv {
    pid: u32,
    provider: PathBuf,
    canon: String,
    loaded: Loaded,
    links: LinkSet,
    ring: RingBuf<MapData>,
    pin: crate::pin::TargetPin,
}

impl SessionEnv for LiveEnv {
    fn next_event(&mut self) -> Option<Vec<u8>> {
        self.ring.next().map(|item| item.to_vec())
    }

    fn current_maps(&mut self) -> Vec<maps::Mapping> {
        maps::read_maps(self.pid).unwrap_or_default()
    }

    fn join_maps(&mut self) -> MapSnapshots {
        let (trunc, trunc_failed) = read_kv_checked(&self.loaded.maps, "TRUNC");
        let (termd, termd_failed) = read_kv_checked(&self.loaded.maps, "TERMD");
        let (losses, losses_failed) = read_kv_checked(&self.loaded.maps, "LOSS");
        // Call volume from the CALLS map (`None` only when the map
        // itself is absent — the core falls back to the QUERY_RET
        // event count then). All counter maps read checked: a
        // failed iteration is explicit snapshot loss, never a
        // silent partial sum (the core's high-water baselines
        // additionally ignore the dip).
        let (call_rows, calls_failed): (Vec<(u32, u64)>, bool) =
            read_kv_checked(&self.loaded.maps, "CALLS");
        let calls = if call_rows.is_empty() && !self.loaded.maps.contains_key("CALLS") {
            None
        } else {
            Some(call_rows.iter().map(|(_, n)| n).sum())
        };
        let (trip, trip_failed): (Vec<(u64, u64)>, bool) =
            read_kv_checked(&self.loaded.maps, "TRIP");
        let (lg_rows, lgcalls_failed): (Vec<(u32, u64)>, bool) =
            read_kv_checked(&self.loaded.maps, "LGCALLS");
        let lgcalls: u64 = lg_rows.iter().map(|(_, n)| n).sum();
        MapSnapshots {
            trunc,
            trunc_failed,
            termd,
            termd_failed,
            losses,
            losses_failed,
            calls,
            calls_failed,
            trip,
            trip_failed,
            lgcalls,
            lgcalls_failed,
        }
    }

    fn install_stage2(
        &mut self,
        cookie: u64,
        offset: u64,
        path: &Path,
        pid: u32,
    ) -> anyhow::Result<()> {
        attach_pair(
            &self.loaded,
            &mut self.links,
            "query_entry",
            "query_return",
            offset,
            path,
            pid,
            cookie,
            LinkKind::Query,
        )?;
        eprintln!("INSPECT stage=query off={offset:#x} cookie={cookie}");
        Ok(())
    }

    fn install_trips(
        &mut self,
        set: &legacy::ProbeSet,
        pid: u32,
    ) -> anyhow::Result<Option<String>> {
        attach_trips(&self.loaded, &mut self.links, set, pid)?;
        eprintln!("INSPECT stage=legacy trips={}", set.probes.len());
        let mut note = None;
        if let Some(lc_path) = legacy::find_libcrypto(&self.current_maps()) {
            for cand in legacy_candidates(pid, &lc_path) {
                let off = std::fs::read(&cand)
                    .ok()
                    .and_then(|b| elf::dynsym_file_offset(&b, INIT_ANCHOR).ok());
                // No init anchor in the candidate: a pre-loaded
                // legacy stays unattributed (documented edge).
                if let Some(off) = off
                    && let Err(e) = attach_pair(
                        &self.loaded,
                        &mut self.links,
                        "init_entry",
                        "init_return",
                        off,
                        &cand,
                        pid,
                        harvest::LEGACY_COOKIE,
                        LinkKind::Init,
                    )
                {
                    // Loud in-doc (executed_calls would read a
                    // false 0); the run continues for tripwires.
                    note = Some(format!("legacy tripwire attach failed: {e:#}"));
                    eprintln!("INSPECT legacy attach failed: {e:#}");
                }
            }
        }
        Ok(note)
    }

    fn plan_trips(&mut self, maps: &[maps::Mapping]) -> anyhow::Result<Option<legacy::ProbeSet>> {
        let Some(lc_path) = legacy::find_libcrypto(maps) else {
            return Ok(None);
        };
        let lc_bytes =
            std::fs::read(&lc_path).with_context(|| format!("read target libcrypto {lc_path}"))?;
        // Caller modules for low-level PLT planning. Unreadable
        // files (deleted-but-mapped, permissions) are loud
        // findings: their imports stay unknown.
        let mut mod_bytes: Vec<(String, Vec<u8>)> = Vec::new();
        let mut unreadable: Vec<String> = Vec::new();
        for path in legacy::target_modules(maps, &lc_path) {
            match std::fs::read(&path) {
                Ok(bytes) => mod_bytes.push((path, bytes)),
                Err(_) => unreadable.push(path),
            }
        }
        let modules: Vec<legacy::Module> = mod_bytes
            .iter()
            .map(|(p, b)| legacy::Module { path: p, bytes: b })
            .collect();
        let mut set = legacy::probes_for(&lc_path, &lc_bytes, &modules)?;
        for path in &unreadable {
            set.findings
                .push(format!("unreadable module: {path} (imports unknown)"));
        }
        Ok(Some(set))
    }

    fn pretouch(&mut self, cookie: u64, addr: u64) {
        // Re-pretouch on repeat inits (unload/reload cycles): the
        // new mapping's pages are cold and nofault BPF reads fail
        // on them. Best-effort, never fatal.
        if let Ok(live) = maps::read_maps(self.pid) {
            let path = if cookie == harvest::LEGACY_COOKIE {
                live.iter()
                    .find(|m| m.start <= addr && addr < m.end && m.ino != 0)
                    .map(|m| PathBuf::from(&m.path))
            } else {
                Some(self.provider.clone())
            };
            if let Some(p) = path {
                pretouch_mappings(self.pid, &live, &p, &self.canon);
            }
        }
    }

    fn evict_array_state(&mut self, arr: u64) -> anyhow::Result<()> {
        evict_termd(&self.loaded.maps, arr)?;
        evict_cursors(&self.loaded.maps, arr)?;
        Ok(())
    }

    fn verify_pin(&self) -> anyhow::Result<()> {
        self.pin.verify().map_err(|e| anyhow!("{e}"))
    }

    fn quiesce(&mut self) {
        self.links.clear();
    }

    fn link_counts(&self) -> (u64, u64) {
        self.links.counts()
    }
}

// ---------------------------------------------------------------------------
// DiscoverySession: the live persistent engine.
// ---------------------------------------------------------------------------

/// Persistent discovery engine: owns loaded programs/maps, attach
/// links, the ring consumer, the target pin, and all discovery
/// state until the session drops. Poll in bounded batches;
/// [`DiscoverySession::close`] (quiesce-then-PROCESS) before drop
/// for exact tail accounting.
pub struct DiscoverySession {
    core: SessionCore,
    env: LiveEnv,
}

impl DiscoverySession {
    /// Attach a discovery session to `pid`: pin, load, populate
    /// classifiers, install dispatch anchors and (when configured)
    /// legacy tripwires. Dispatch-blind runs (unresolvable anchor)
    /// still attach when tripwires can observe — the preset reason
    /// travels in the snapshot.
    pub fn attach(cfg: &DiscoveryConfig, pid: u32) -> anyhow::Result<Self> {
        let nz = NonZeroU32::new(pid).ok_or_else(|| anyhow!("pid must be non-zero"))?;
        // Pin FIRST: every later /proc/<pid> read and every
        // pid-scoped attach is verified against this identity.
        let pin = crate::pin::pin(pid)?;
        if let Some(marker) = &cfg.cmdline_marker {
            let cmdline = std::fs::read(format!("/proc/{pid}/cmdline"))?;
            let m = marker.as_bytes();
            if !cmdline.windows(m.len()).any(|w| w == m) {
                bail!("pid {pid} cmdline lacks marker {marker}");
            }
        }
        let elf_bytes = std::fs::read(&cfg.provider)?;
        let canon = std::fs::canonicalize(&cfg.provider)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let obj_bytes = std::fs::read(&cfg.object)?;
        if pin.verify().is_err() {
            let mut core = SessionCore::new(cfg.provider.clone(), canon, cfg.legacy, pid);
            core.mark_recycled();
            return Err(core.recycled_err());
        }

        let loaded = load_frozen(&obj_bytes)?;
        // Classifier tables before any attach can fire: the kernel
        // classifies every string-bearing event against these.
        populate_classifier_maps(&loaded.maps)?;
        // Owns every multi link (drop = detach, all paths).
        let mut links = LinkSet::default();
        let mut builtin_query_attached = false;
        let mut builtin_query_offset = 0u64;
        let mut resolution: Option<String> = None;
        // Dispatch-blind runs preset their PARTIAL reason but still
        // drain for legacy tripwires (dispatch and legacy observe
        // independently).
        let mut preset_reason: Option<String> = None;
        if cfg.builtin {
            let table = match &cfg.table {
                Some(path) => {
                    let text = std::fs::read_to_string(path)?;
                    builtin::load_table_str(&text)?
                }
                None => builtin::shipped_table(),
            };
            match builtin::resolve_query_offset(&elf_bytes, &table, cfg.force_offset) {
                Ok((off, r)) => {
                    if r != builtin::Resolution::Table {
                        resolution = Some(r.as_str().to_string());
                    }
                    attach_pair(
                        &loaded,
                        &mut links,
                        "query_entry",
                        "query_return",
                        off,
                        &cfg.provider,
                        nz.get(),
                        0,
                        LinkKind::Query,
                    )?;
                    eprintln!("INSPECT stage=builtin off={off:#x} via={}", r.as_str());
                    builtin_query_attached = true;
                    builtin_query_offset = off;
                }
                Err(e) => {
                    eprintln!("INSPECT builtin unresolved: {e:#}");
                    preset_reason = Some("anchor-unresolved".to_string());
                }
            }
        } else {
            // Init ladder: load-mandated dynsym first, debug symtab second.
            let init_off = elf::dynsym_file_offset(&elf_bytes, INIT_ANCHOR)
                .map(|off| (off, None))
                .or_else(|_| {
                    elf::symtab_file_offset(&elf_bytes, INIT_ANCHOR)
                        .map(|off| (off, Some("symtab".to_string())))
                });
            match init_off {
                Ok((off, res)) => {
                    resolution = res;
                    attach_pair(
                        &loaded,
                        &mut links,
                        "init_entry",
                        "init_return",
                        off,
                        &cfg.provider,
                        nz.get(),
                        0,
                        LinkKind::Init,
                    )?;
                }
                Err(e) => {
                    eprintln!("INSPECT anchor unresolved: {e:#}");
                    preset_reason = Some("anchor-unresolved".to_string());
                }
            }
            // Machine-readable progress on stderr (stdout stays pure
            // JSON): harnesses gate fixture GO lines on these.
            eprintln!("INSPECT stage=init attached=2");
        }

        let ev_fd = loaded
            .maps
            .get("EVENTS")
            .context("no EVENTS map")?
            .try_clone()?;
        let ev_data = MapData::from_fd(ev_fd).map_err(|e| anyhow!("EVENTS mapdata: {e}"))?;
        let ev_map = Map::from_map_data(ev_data).map_err(|e| anyhow!("EVENTS map: {e}"))?;
        let ring = RingBuf::try_from(ev_map)?;

        let mut core = SessionCore::new(cfg.provider.clone(), canon.clone(), cfg.legacy, pid);
        if builtin_query_attached {
            core.mark_query_attached(
                0,
                builtin_query_offset,
                cfg.provider.to_string_lossy().into_owned(),
            );
        }
        let mut env = LiveEnv {
            pid,
            provider: cfg.provider.clone(),
            canon,
            loaded,
            links,
            ring,
            pin,
        };

        // Legacy tripwires (dispatch-independent: attach even when
        // the dispatch anchor failed — a blind dispatch can still
        // observe legacy calls; only a missing libcrypto mapping is
        // truly blind). Planned now when libcrypto is already mapped
        // and deferred to the first post-exec poll otherwise.
        if cfg.legacy {
            let maps0 = env.current_maps();
            if legacy::find_libcrypto(&maps0).is_some() {
                if let Some(set) = env.plan_trips(&maps0)? {
                    let note = env.install_trips(&set, pid)?;
                    core.adopt_legacy_plan(set, note);
                }
            } else {
                eprintln!("INSPECT stage=legacy blind=no-libcrypto-mapping");
            }
        }
        core.set_bootstrap(preset_reason.is_none(), preset_reason, resolution);

        // Post-attach verify: every maps read and attach above
        // resolved through /proc/<pid> — confirm the identity.
        if env.verify_pin().is_err() {
            core.mark_recycled();
            return Err(core.recycled_err());
        }
        Ok(Self { core, env })
    }

    /// One bounded poll; see [`SessionCore::poll`].
    pub fn poll(&mut self, budget: PollBudget) -> anyhow::Result<DiscoveryDelta> {
        self.core.poll(&mut self.env, budget)
    }

    /// Cumulative discovery state; see [`SessionCore::snapshot`].
    pub fn snapshot(&self) -> DiscoverySnapshot {
        self.core.snapshot()
    }

    /// Quiesce-then-PROCESS teardown; see [`SessionCore::close`].
    /// Prefer this over `drop()` for exact tail accounting.
    pub fn close(mut self) -> anyhow::Result<DiscoverySnapshot> {
        self.core.close(&mut self.env)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_maps() -> Vec<maps::Mapping> {
        vec![
            maps::Mapping {
                start: 0x1000,
                end: 0x2000,
                x: true,
                offset: 0x500,
                dev: "08:01".to_string(),
                ino: 7,
                path: "/prov.so".to_string(),
            },
            maps::Mapping {
                start: 0x3000,
                end: 0x4000,
                x: true,
                offset: 0,
                dev: "08:01".to_string(),
                ino: 9,
                path: "/lib/libcrypto.so".to_string(),
            },
            maps::Mapping {
                start: 0x5000,
                end: 0x6000,
                x: true,
                offset: 0,
                dev: "00:00".to_string(),
                ino: 0,
                path: String::new(),
            },
        ]
    }

    #[test]
    fn attribution_splits_advertising_and_backing() {
        let m = sample_maps();
        // Array owner is the file mapping covering the array.
        assert_eq!(array_owner(&m, 0x1400), "/prov.so");
        assert_eq!(array_owner(&m, 0x3500), "/lib/libcrypto.so");
        // Anonymous/unmapped arrays carry no attributable owner.
        assert_eq!(array_owner(&m, 0x5500), "");
        assert_eq!(array_owner(&m, 0x9000), "");
        // Backing prefers the provider mapping, then any file
        // mapping, else unbacked (render fences it). The canon is
        // a realistic non-empty path (live canonicalize only
        // yields "" when it fails outright).
        let (b, loc) = attribute_impl(&m, Path::new("/prov.so"), "/canon/prov.so", 0x1400);
        assert_eq!(
            b,
            Some(BackingRef {
                dev: "08:01".to_string(),
                ino: 7,
                offset: 0x900,
            })
        );
        assert_eq!(loc, "/prov.so");
        let (b, loc) = attribute_impl(&m, Path::new("/prov.so"), "/canon/prov.so", 0x3500);
        assert_eq!(b.as_ref().unwrap().ino, 9);
        assert_eq!(loc, "/lib/libcrypto.so");
        let (b, loc) = attribute_impl(&m, Path::new("/prov.so"), "/canon/prov.so", 0x5500);
        assert_eq!((b, loc.as_str()), (None, ""));
    }

    #[test]
    fn incarnation_ignores_anonymous_ranges() {
        let m = sample_maps();
        assert_eq!(
            incarnation_of(&m, 0x1400),
            Some(("08:01".to_string(), 7, 0x1000, 0x2000, 0x500))
        );
        // Anonymous and unmapped addresses carry no identity to
        // bind (same-address content swaps there are the documented
        // residual — exact coverage is the backstop).
        assert_eq!(incarnation_of(&m, 0x5500), None);
        assert_eq!(incarnation_of(&m, 0x9000), None);
    }

    #[test]
    fn reason_union_ranks_and_retains_unknowns() {
        let ranked = union_reasons(
            &["prefix-walk".to_string()],
            &["discovery-loss".to_string(), "prefix-walk".to_string()],
        );
        assert_eq!(ranked, vec!["discovery-loss", "prefix-walk"]);
        // Unrecognized reasons append sorted rather than vanishing.
        let ranked = union_reasons(&["zzz-next".to_string()], &["aaa-next".to_string()]);
        assert_eq!(ranked, vec!["aaa-next", "zzz-next"]);
        let ranked = union_reasons(&["prefix-walk".to_string(), "zzz-next".to_string()], &[]);
        assert_eq!(ranked, vec!["prefix-walk", "zzz-next"]);
    }

    #[test]
    fn debug_alg_line_prints_classified_fields_only() {
        let line = debug_alg_line(1, 0, "other", false, wire::ALG_UNKNOWN);
        assert_eq!(
            line,
            "HARVESTDBG alg op=1 idx=0 class=other weak=0 status=1"
        );
        assert!(!line.contains("0x"), "address leaked: {line}");
        assert!(!line.contains("len="), "length leaked: {line}");
    }
}
