//! SPDX-License-Identifier: GPL-3.0-or-later
//! T07 immutable count session (spec R01/R02/R05).
//!
//! [`CountSession`] consumes typed discovery deltas ([`CountDelta`]),
//! plans them through [`crate::plan`] (cookies identify verified
//! physical backing — device, inode, file offset — never the link
//! path), attaches count probes through a [`CountBackend`], and
//! drains per-generation conserved [`SiteExecution`](crate::evidence::SiteExecution)
//! records into a [`CountDrain`].
//!
//! Provenance is immutable: once a cookie is minted for a backing
//! triple, its site key never changes, and a changed candidate set
//! versions at a fence — the fenced generation keeps the old
//! meaning, the new generation carries the new one. Old links keep
//! their old meaning; drains and fences preserve every candidate,
//! weak metadata included.
//!
//! The spec's `DiscoveryDelta` producer lands in T06
//! (`src/discovery/session.rs`); [`CountDelta`] is this session's
//! consumer-side aggregation of it. The T08 adapter
//! (`crate::capture::adapt_delta`, decisions D1–D4) accumulates full
//! per-site candidate sets from the producer's incremental
//! candidates, synthesizes backing/advertising object identity and
//! per-site coverage, and classifies discovery losses; the
//! producer's auxiliary fields (tables, retirements, tripwire,
//! queries, attaches, budgets, triggers) feed separate coverage and
//! legacy evidence outside this session. The live-maps/file-bytes
//! context rides as explicit [`attach`](CountSession::attach_delta)
//! parameters so planning stays pure and host-testable; T08 passes
//! `read_maps(pid)` plus pre-read file bytes at each poll.
//!
//! Backends: [`LiveBackend`] drives the real BPF maps/links (needs
//! caps); [`FakeCountBackend`] is a deterministic host double that
//! models the kernel `TARGET`/window/`GEN` admission semantics
//! exactly, including map-full drops, so the identity, deadline and
//! conservation contracts pin without privileges.

use crate::count_owner::*;
pub use crate::count_owner::{
    AttachAck, AttachRefusal, AttachRefusalReason, AttachRequest, BackingIdentity, CleanupState,
    CleanupTicket, CommandAck, CommandCompletion, CommandFailure, CommandPublication,
    CommandResult, CommandSeq, Component, ComponentFailure, ControllerFrontier, CountForkBarrier,
    CountForkPermit, CountInput, CountMap, CountOperation, CountOwnerLimits, CountPrepareFailure,
    EnumerationStatus, EvidenceDomain, FailureClass, ForkBlocked, GenerationRequest,
    KernelApplicability, LinkId, LinkToken, OpenOutcome, OpenReceipt, OpenRequest,
    OpenWriteFrontier, OwnerFailure, PendingCommandId, ProgrammedAdmission, RawCheckpoint,
    RawSnapshot, RawTerminal, ReadRequest, ReadStatus, Ready, ResourceId, StopResult, TerminalId,
    TerminalRequest, WriterCompletion,
};
use crate::discovery::maps;
use crate::evidence::{
    CandidateCoverage, CandidateIdentity, CounterKind, CounterSource, CounterUnits,
    FencedGeneration, GapCounter, SiteExecution, SiteKey,
};
use crate::plan;
use osslscope_ebpf_common::{CountValue, make_key, split_key};
use std::collections::{HashMap, HashSet, hash_map::Entry};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

/// One discovered site: its physical key, the candidate identities
/// that could explain entry there, and whether that candidate set is
/// itself complete. The `(device, inode, offset)` triple is the
/// verified backing identity (R02); pathnames are locators only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredSite {
    pub site: SiteKey,
    pub candidates: Vec<CandidateIdentity>,
    pub candidates_coverage: CandidateCoverage,
}

impl DiscoveredSite {
    fn normalize(&mut self) {
        for c in &mut self.candidates {
            c.algorithm_classes.sort();
            c.algorithm_classes.dedup();
        }
        self.candidates.sort();
        self.candidates.dedup();
    }
}

fn normalize_sites(sites: &[DiscoveredSite]) -> anyhow::Result<Vec<DiscoveredSite>> {
    // Merge duplicate backing triples within one delta: their
    // candidate sets union (a site's aliases are simultaneous,
    // never competing updates) and coverage merges
    // conservatively — the weakest claim wins in either input
    // order (Unknown over AmbiguousComplete over Complete;
    // ambiguity is contagious). Conflicting object fingerprints
    // for one triple are a producer contradiction: fail closed
    // rather than silently keeping the first.
    let mut merged: HashMap<(u64, u64, u64), DiscoveredSite> = HashMap::new();
    for mut site in sites.iter().cloned() {
        site.normalize();
        let key = (site.site.device, site.site.inode, site.site.offset);
        match merged.get_mut(&key) {
            None => {
                merged.insert(key, site);
            }
            Some(prior) => {
                if prior.site.object != site.site.object {
                    anyhow::bail!("conflicting object identity for one backing triple");
                }
                prior.candidates.extend(site.candidates);
                prior.candidates_coverage =
                    match (prior.candidates_coverage, site.candidates_coverage) {
                        (CandidateCoverage::Unknown, _) | (_, CandidateCoverage::Unknown) => {
                            CandidateCoverage::Unknown
                        }
                        (CandidateCoverage::AmbiguousComplete, _)
                        | (_, CandidateCoverage::AmbiguousComplete) => {
                            CandidateCoverage::AmbiguousComplete
                        }
                        _ => CandidateCoverage::Complete,
                    };
            }
        }
    }
    let mut normalized: Vec<DiscoveredSite> = merged.into_values().collect();
    for site in &mut normalized {
        site.normalize();
    }
    normalized.sort_by(|a, b| a.site.cmp(&b.site));
    Ok(normalized)
}

/// Consumer-side discovery delta: full per-site replacement sets
/// for every touched site (capture accumulates these from the
/// producer's incremental candidates — a delta never partially
/// updates a site) plus classified discovery losses to carry into
/// the drain. See `crate::capture::adapt_delta` for the mapping.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CountDelta {
    pub discovered: Vec<DiscoveredSite>,
    pub losses: Vec<GapCounter>,
}

/// A link token carries identity only; the backend owner keeps every FD.
pub trait CountLink {
    fn id(&self) -> LinkId;
}
impl CountLink for LinkToken {
    fn id(&self) -> LinkId {
        self.id()
    }
}

/// Timed, data-only controller port. No count descriptor crosses this boundary.
pub trait CountBackend {
    type Link: CountLink;
    fn ready(&self) -> &Ready;
    fn attach(&mut self, request: AttachRequest) -> CommandResult<AttachAck<Self::Link>>;
    fn open_window(&mut self, request: OpenRequest) -> CommandResult<OpenReceipt>;
    fn set_generation(&mut self, request: GenerationRequest) -> CommandResult<()>;
    fn drain(&mut self, request: ReadRequest) -> CommandResult<Arc<RawSnapshot>>;
    fn terminal_request(
        &mut self,
        deadline: Instant,
        frontier: ControllerFrontier,
    ) -> TerminalRequest;
    fn terminal(&mut self, request: TerminalRequest) -> RawTerminal;
    fn progress(&self) -> Option<RawCheckpoint>;
    fn fork_permit(&self, deadline: Instant) -> Result<CountForkPermit<'_>, ForkBlocked>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    Expired,
    Interrupted,
    Failure,
    OwnedExit,
    SetupAbort,
    IdentityRecycle,
}
#[derive(Debug, Clone, Copy)]
pub struct CloseRequest {
    pub started_at: Instant,
    pub grace: Duration,
    pub reason: CloseReason,
}
#[derive(Debug, Clone)]
pub struct CountTerminal {
    pub retained_drain: CountDrain,
    pub receipt: RawTerminal,
    pub runtime_failure: Option<OwnerFailure>,
}

/// Checked command allocation. Terminal identities stay with the owner.
#[derive(Debug, Default)]
struct CountIds {
    command: u64,
}
impl CountIds {
    fn command(&mut self) -> Result<CommandSeq, OwnerFailure> {
        let next = self
            .command
            .checked_add(1)
            .ok_or_else(|| OwnerFailure::engine(CountOperation::Load, FailureClass::IdExhausted))?;
        self.command = next;
        CommandSeq::checked(next)
    }
}

#[derive(Debug, Clone)]
struct PendingAttach {
    seq: CommandSeq,
    backing: BackingIdentity,
    locator: String,
    positions: Vec<(u64, u32)>,
    installed_at: u64,
    deadline: Instant,
}
#[derive(Debug, Clone)]
enum PendingCountTxn {
    Attach(PendingAttach),
    Open(OpenRequest),
    Fence {
        request: GenerationRequest,
        reason: FenceReason,
        old_generation: u32,
        old_meanings: HashMap<u32, Provenance>,
        new_meanings: HashMap<u32, PendingMeaning>,
    },
    Read(ReadRequest),
}
impl PendingCountTxn {
    fn deadline(&self) -> Instant {
        match self {
            Self::Attach(a) => a.deadline,
            Self::Open(r) => r.deadline,
            Self::Fence { request, .. } => request.deadline,
            Self::Read(r) => r.deadline,
        }
    }
    fn id(&self) -> PendingCommandId {
        match self {
            Self::Attach(a) => PendingCommandId {
                seq: a.seq,
                operation: CountOperation::Attach,
            },
            Self::Open(r) => PendingCommandId {
                seq: r.seq,
                operation: CountOperation::Open,
            },
            Self::Fence { request, .. } => PendingCommandId {
                seq: request.seq,
                operation: CountOperation::Generation,
            },
            Self::Read(r) => PendingCommandId {
                seq: r.seq,
                operation: CountOperation::Read,
            },
        }
    }
}

/// Why a fence generation boundary was taken. Mapping/exec reasons
/// mirror the capture fence kinds; `CandidatesChanged` versions an
/// attribution-set change (R02: never relabel a live cookie).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceReason {
    MappingsChanged,
    ProviderChanged,
    Exec,
    CandidatesChanged,
}

/// Immutable meaning of one cookie: the physical site, the candidate
/// set explaining it, that set's coverage, the link path the probe
/// attached through (locator, not identity — recorded on successful
/// attach only, empty before that), and the monotonic install wall
/// (`None` until the first bind succeeds, never relabelled after —
/// minted is not installed, and installed is not yet counted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    pub site: SiteKey,
    pub candidates: Vec<CandidateIdentity>,
    pub candidates_coverage: CandidateCoverage,
    pub link_path: String,
    pub installed_at: Option<u64>,
}

/// Attribution update staged by [`CountSession::attach_delta`],
/// applied to the new generation by [`CountSession::fence`]. Carries
/// the full site key (not just candidates): a changed object
/// fingerprint for one backing triple — modified-in-place content or
/// inode reuse — versions the same way, so the fenced generation
/// keeps the old fingerprint and the new one carries the new.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingMeaning {
    site: SiteKey,
    candidates: Vec<CandidateIdentity>,
    coverage: CandidateCoverage,
}

/// Fence comparison view of candidate coverage (R01): a mixed
/// site's finiteness claim (`AmbiguousComplete`) and its loss claim
/// (`Unknown`) fence identically — drift between them updates
/// provenance without staging a fence (H3: mixed absorbs taint
/// silently). `Complete` stands apart: any drift to or from a
/// definite-capable claim still fences, as before.
fn fence_candidates_coverage(coverage: CandidateCoverage) -> CandidateCoverage {
    match coverage {
        CandidateCoverage::AmbiguousComplete => CandidateCoverage::Unknown,
        other => other,
    }
}

/// What one [`CountSession::attach_delta`] call did.
#[derive(Debug, Clone)]
pub struct AttachReport {
    /// Sites newly attached by this call.
    pub attached: u64,
    /// Planned sites skipped (probes already live).
    pub reused: u64,
    /// Plan-time and attach-time rejects (all counted loud).
    pub missed: Vec<plan::Missed>,
    /// Kernel-refused offsets this call (bisection survivors).
    pub unresolved: u64,
    /// A delta changed a live cookie's candidate set: the caller
    /// must [`fence`](CountSession::fence) with
    /// [`FenceReason::CandidatesChanged`] before the new meaning
    /// takes effect; until then the old meaning stands.
    pub candidates_changed: bool,
}

/// Final session output: current-generation executions, fenced
/// generations (each with the candidate meaning then current), and
/// typed loss/activity counters. T08 merges window, coverage and
/// object records around this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountDrain {
    pub current: Vec<SiteExecution>,
    pub fenced: Vec<FencedGeneration>,
    pub counters: Vec<GapCounter>,
}

impl CountDrain {
    /// Conserved total across current and fenced sites.
    pub fn total_calls(&self) -> u64 {
        let current = SiteExecution::sum_calls(&self.current);
        self.fenced.iter().fold(current, |acc, g| {
            acc.saturating_add(SiteExecution::sum_calls(&g.sites))
        })
    }
}

/// Merge one loss counter into the store: same (name, kind, units,
/// source) sums, zero values add nothing, and a clean delta never
/// erases an earlier gap.
fn merge_counter(store: &mut Vec<GapCounter>, next: GapCounter) {
    if next.value == 0 {
        return;
    }
    if let Some(slot) = store.iter_mut().find(|c| {
        c.name == next.name
            && c.kind == next.kind
            && c.units == next.units
            && c.source == next.source
    }) {
        slot.value = slot.value.saturating_add(next.value);
    } else {
        store.push(next);
    }
}

fn counter(
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

/// Plan-metadata identity for one candidate set. The planner's
/// single-`alg_class` [`plan::Identity`] cannot hold a set, so the
/// deterministic sort-first candidate rides as canonical with the
/// remaining set folded into a `+`-joined class list — a composite
/// rendering, never a canonical-algorithm claim. Real attribution
/// always comes from [`Provenance`], never from this row.
fn canonical_identity(candidates: &[CandidateIdentity], offset: u64) -> plan::Identity {
    let mut sorted = candidates.to_vec();
    sorted.sort();
    sorted.dedup();
    match sorted.first() {
        Some(c) => {
            let mut classes: Vec<&str> = sorted
                .iter()
                .flat_map(|c| c.algorithm_classes.iter().map(String::as_str))
                .collect();
            classes.sort_unstable();
            classes.dedup();
            plan::Identity {
                provider: c.provider.0.clone(),
                op: c.op,
                funcid: c.funcid,
                alg_class: if classes.is_empty() {
                    "other".to_string()
                } else {
                    classes.join("+")
                },
                offset,
            }
        }
        None => plan::Identity {
            provider: "unknown".to_string(),
            op: 0,
            funcid: 0,
            alg_class: "other".to_string(),
            offset,
        },
    }
}

/// Fold a drained delta into a site execution record.
fn fold_exec_calls(exec: &mut SiteExecution, delta: u64, first_ns: u64, last_ns: u64) {
    if exec.calls == 0 {
        exec.first_ns = first_ns;
        exec.last_ns = last_ns;
    } else {
        exec.first_ns = exec.first_ns.min(first_ns);
        exec.last_ns = exec.last_ns.max(last_ns);
    }
    exec.calls = exec.calls.saturating_add(delta);
}

/// Immutable planner identity + count window session, generic over
/// the [`CountBackend`]. Owns cookie provenance, generation epochs,
/// link identities and drain routing; T08 holds one for the whole
/// observation and feeds it deltas incrementally.
pub struct CountSession<B: CountBackend> {
    pid: u32,
    backend: B,
    links: Vec<B::Link>,
    ready: Ready,
    ids: CountIds,
    last_acked: Option<CommandSeq>,
    pending_txn: Option<PendingCountTxn>,
    programmed: Option<ProgrammedAdmission>,
    acknowledged_open: Option<OpenReceipt>,
    // Routing needs only the checked image identity after folding. Holding
    // the old rows here would pin a spare in the owner's three-image pool and
    // prevent a later ordinary read from publishing its positive prefixes.
    last_snapshot_seq: Option<SnapshotSeq>,
    terminal_view: Option<Arc<CountTerminal>>,
    canonical: Option<TerminalRequest>,
    runtime_failure: Option<OwnerFailure>,
    component_failures: [Option<ComponentFailure>; 18],
    terminal_reconciled: bool,
    terminal_complete: bool,
    terminal_inventory_unavailable: bool,
    lat_available: [bool; 16],
    lat_final_available: [bool; 16],
    admitted_available: bool,
    dropfail_available: bool,
    admitted_final_available: bool,
    dropfail_final_available: bool,
    read_duration_ns: Option<u64>,
    enumerated: bool,
    unread_unknown: bool,
    stable: plan::StableCookies,
    provenance: HashMap<u32, Provenance>,
    pending: HashMap<u32, PendingMeaning>,
    /// (device, inode, offset) triples with live probes. Re-plans
    /// skip survivors: inode probes persist across remaps, and
    /// re-attaching would double-fire every hit.
    attached: HashSet<(u64, u64, u64)>,
    /// Cookies with ≥1 live link (H4: attribution requires a
    /// bound link). Planned-but-never-bound cookies (rejected
    /// resolves, kernel refusals) stay OUT: their hits — backend
    /// anomalies only, no link could have produced them — route
    /// to unattributed loss at [`CountSession::route`], never
    /// silently dropped, never misattributed. Monotonic within
    /// the run (links never detach mid-run), so fenced
    /// stragglers keep routing under their retired meaning.
    bound: HashSet<u32>,
    known: HashSet<u32>,
    // H4 removed the `quarantined` set (F-A/A1 generation
    // quarantine): the fd pin binds the planned inode exactly,
    // so no link is ever bound wrong and there is nothing to
    // quarantine — a stale plan misses `replaced` per attempt,
    // having bound nothing (see H4-T4). Design:
    // docs/2026-10-11-h4-descriptor-custody-design.md §3.
    current: HashMap<u32, CountValue>,
    fenced: Vec<FencedGeneration>,
    /// (generation, cookie) → meaning then current, for exact
    /// straggler routing after a fence.
    retired: HashMap<(u32, u32), Provenance>,
    /// Last folded total per (cookie, generation): drains are
    /// delta-reads (map keys persist across fence drains — folding
    /// totals twice would double-count, and deleting keys mid-window
    /// would race in-flight increments).
    seen: HashMap<(u32, u32), u64>,
    last_dropfail: u64,
    /// Cumulative admitted hits across drains (delta-read like
    /// `dropfail`, from `DrainedCounts.admitted_total`).
    admitted: u64,
    last_admitted: u64,
    /// Cumulative callback-latency histogram (c8), folded across
    /// drains from `DrainedCounts.lat_buckets`.
    lat_cum: [u64; 16],
    /// Previous drain's histogram snapshot for delta-vs-last
    /// folding (V2-41: backends report cumulative histograms).
    last_lat: [u64; 16],
    generation: u32,
    window_open: bool,
    preplanned: bool,
    closed: bool,
    passthrough: Vec<GapCounter>,
    dropfail: u64,
    unattributed: u64,
    shortfall: u64,
    missed_attaches: u64,
    unresolved: u64,
    stale_events: u64,
    fences: u64,
    drained_keys: u64,
}

impl<B: CountBackend> CountSession<B> {
    pub fn new(pid: u32, backend: B) -> Self {
        Self {
            pid,
            ready: *backend.ready(),
            backend,
            links: Vec::new(),
            ids: CountIds::default(),
            last_acked: None,
            pending_txn: None,
            programmed: None,
            acknowledged_open: None,
            last_snapshot_seq: None,
            terminal_view: None,
            canonical: None,
            runtime_failure: None,
            component_failures: [None; 18],
            terminal_reconciled: false,
            terminal_complete: false,
            terminal_inventory_unavailable: false,
            lat_available: [false; 16],
            lat_final_available: [false; 16],
            admitted_available: false,
            dropfail_available: false,
            admitted_final_available: false,
            dropfail_final_available: false,
            read_duration_ns: None,
            enumerated: false,
            unread_unknown: false,
            stable: plan::StableCookies::default(),
            provenance: HashMap::new(),
            pending: HashMap::new(),
            attached: HashSet::new(),
            bound: HashSet::new(),
            known: HashSet::new(),
            current: HashMap::new(),
            fenced: Vec::new(),
            retired: HashMap::new(),
            seen: HashMap::new(),
            last_dropfail: 0,
            admitted: 0,
            last_admitted: 0,
            lat_cum: [0; 16],
            last_lat: [0; 16],
            generation: 0,
            window_open: false,
            preplanned: false,
            closed: false,
            passthrough: Vec::new(),
            dropfail: 0,
            unattributed: 0,
            shortfall: 0,
            missed_attaches: 0,
            unresolved: 0,
            stale_events: 0,
            fences: 0,
            drained_keys: 0,
        }
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn generation(&self) -> u32 {
        self.generation
    }

    pub fn window_open(&self) -> bool {
        self.window_open
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Cookies minted so far.
    pub fn cookie_count(&self) -> usize {
        self.stable.len()
    }

    /// The cookie minted for a backing triple, if any.
    pub fn cookie_for(&self, device: u64, inode: u64, offset: u64) -> Option<u32> {
        self.stable
            .lookup(&plan::render_device(device), inode, offset)
    }

    /// Immutable meaning of a cookie, if minted.
    pub fn provenance(&self, cookie: u32) -> Option<&Provenance> {
        self.provenance.get(&cookie)
    }

    /// Known cookies, sorted (coverage input for T08).
    pub fn cookies(&self) -> Vec<u32> {
        let mut out: Vec<u32> = self.known.iter().copied().collect();
        out.sort_unstable();
        out
    }

    /// Plan one discovery delta against live mappings and attach the
    /// not-yet-attached sites at the current generation. `live` is
    /// the target's current `/proc/pid/maps` view and `files` maps
    /// link-path → pre-read file bytes (T08 refreshes both per poll).
    ///
    /// New backing triples mint cookies and immutable provenance;
    /// surviving triples reuse both and skip re-attach. A changed
    /// candidate set for a live cookie stages a [`PendingMeaning`]
    /// and reports `candidates_changed` — the old meaning stands
    /// until [`fence`](Self::fence) versions it. The backend owner
    /// pins each group's locator and checks its planned backing
    /// before creating links; a pin missing the plan is
    /// skipped as `replaced`, loud, having bound nothing — and
    /// only bound cookies' hits attribute ([`CountSession::route`]
    /// gates on the bound set, so rejected plans' anomaly hits
    /// land in unattributed loss, never silently dropped).
    ///
    /// `installed_at_ns` is the caller's monotonic now: every
    /// cookie this call binds records it as its install wall
    /// (survivors and misses keep whatever they already carry).
    pub fn attach_delta(
        &mut self,
        delta: &CountDelta,
        live: &[maps::Mapping],
        files: &HashMap<String, plan::FileBytes>,
        installed_at_ns: u64,
        deadline: Instant,
    ) -> anyhow::Result<AttachReport> {
        if self.closed || self.preplanned {
            anyhow::bail!("count session is closed or has an immutable preplanned catalogue");
        }
        for loss in &delta.losses {
            merge_counter(&mut self.passthrough, loss.clone());
        }
        let normalized = normalize_sites(&delta.discovered)?;
        let rows: Vec<plan::PlanRow> = normalized
            .iter()
            .map(|s| plan::PlanRow {
                dev: plan::render_device(s.site.device),
                ino: s.site.inode,
                offset: s.site.offset,
                id: canonical_identity(&s.candidates, s.site.offset),
            })
            .collect();
        let planned = plan::plan_rows(&rows, live, files, self.generation, &mut self.stable)?;
        self.attach_planned(&normalized, &rows, planned, installed_at_ns, deadline)
    }

    /// Attach the admitted file catalogue before exec maps the library. The
    /// caller retains the reviewed backing; the owner verifies its dev/inode
    /// from this locator before binding the same nonzero original target.
    /// Exactly one immutable batch is allowed, before window programming.
    pub fn attach_preplanned(
        &mut self,
        sites: &[DiscoveredSite],
        locator: &std::path::Path,
        installed_at_ns: u64,
        deadline: Instant,
    ) -> anyhow::Result<AttachReport> {
        if self.pid == 0
            || self.closed
            || self.preplanned
            || self.window_open
            || !self.stable.is_empty()
        {
            anyhow::bail!("preplanned count requires a fresh session and nonzero original PID");
        }
        let locator = locator
            .to_str()
            .filter(|p| !p.is_empty() && p.len() <= 4095 && !p.as_bytes().contains(&0))
            .ok_or_else(|| anyhow::anyhow!("invalid pinned catalogue locator"))?;
        let normalized = normalize_sites(sites)?;
        let Some(first) = normalized.first() else {
            anyhow::bail!("preplanned catalogue is empty");
        };
        if normalized.len() > 64
            || normalized.iter().any(|s| {
                s.site.device != first.site.device
                    || s.site.inode != first.site.inode
                    || s.site.object != first.site.object
            })
        {
            anyhow::bail!("preplanned catalogue exceeds one bounded file backing");
        }
        let mut rows = Vec::with_capacity(normalized.len());
        let mut planned = plan::Plan {
            generation: self.generation,
            ..Default::default()
        };
        for site in &normalized {
            let dev = plan::render_device(site.site.device);
            let id = canonical_identity(&site.candidates, site.site.offset);
            let cookie = self
                .stable
                .cookie_for(&dev, site.site.inode, site.site.offset)?;
            rows.push(plan::PlanRow {
                dev,
                ino: site.site.inode,
                offset: site.site.offset,
                id: id.clone(),
            });
            planned.entries.push(plan::Entry {
                path: locator.to_owned(),
                offset: site.site.offset,
                cookie,
                id,
                aliases: Vec::new(),
            });
        }
        self.preplanned = true;
        self.attach_planned(&normalized, &rows, planned, installed_at_ns, deadline)
    }

    fn attach_planned(
        &mut self,
        normalized: &[DiscoveredSite],
        rows: &[plan::PlanRow],
        planned: plan::Plan,
        installed_at_ns: u64,
        deadline: Instant,
    ) -> anyhow::Result<AttachReport> {
        let mut report = AttachReport {
            attached: 0,
            reused: 0,
            missed: planned.missed.clone(),
            unresolved: 0,
            candidates_changed: false,
        };
        // Mint or version provenance, row by row. Cookie/site-key
        // bindings are append-only while the meaning is live; a
        // changed site key, candidate set or coverage stages a full
        // update for the fence, and a delta re-affirming the live
        // meaning cancels any staged update. Rows that miss now but
        // hold an old cookie (dormant sites) still version their
        // meaning — the inode probes are live and the fence applies
        // it. Link paths record on successful attach only.
        for (row, site) in rows.iter().zip(normalized.iter()) {
            let Some(cookie) = self.stable.lookup(&row.dev, row.ino, row.offset) else {
                continue;
            };
            self.known.insert(cookie);
            let same = self.provenance.get(&cookie).is_some_and(|current| {
                current.site == site.site
                    && current.candidates == site.candidates
                    && current.candidates_coverage == site.candidates_coverage
            });
            // R01: AmbiguousComplete and Unknown are the same
            // fence-wise — a mixed site absorbs taint, retirement
            // and re-proof silently (H3: mixed absorbs taint
            // silently; no second fence). Unlike `same`, the claim
            // DID change, so provenance still updates (newest
            // delta wins) — the relabel only ever weakens mixed
            // claims (finite↔unbounded, never toward definite), so
            // no fenced leg is owed.
            let same_fence_silent = !same
                && self.provenance.get(&cookie).is_some_and(|current| {
                    current.site == site.site
                        && current.candidates == site.candidates
                        && fence_candidates_coverage(current.candidates_coverage)
                            == fence_candidates_coverage(site.candidates_coverage)
                });
            match self.provenance.entry(cookie) {
                Entry::Vacant(vacant) => {
                    vacant.insert(Provenance {
                        site: site.site.clone(),
                        candidates: site.candidates.clone(),
                        candidates_coverage: site.candidates_coverage,
                        link_path: String::new(),
                        installed_at: None,
                    });
                }
                Entry::Occupied(_) if same => {
                    // Newest delta wins: the live meaning stands, so
                    // any staged update is stale and must not install
                    // later.
                    self.pending.remove(&cookie);
                }
                Entry::Occupied(mut occupied) if same_fence_silent => {
                    // Mixed-claim drift (AmbiguousComplete↔Unknown):
                    // adopt the newest claim without fencing — and
                    // cancel any staged update like `same` does.
                    occupied.get_mut().candidates_coverage = site.candidates_coverage;
                    self.pending.remove(&cookie);
                }
                Entry::Occupied(_) => {
                    // Attribution-set change: never relabel the live
                    // cookie — stage the new meaning for the fence.
                    self.pending.insert(
                        cookie,
                        PendingMeaning {
                            site: site.site.clone(),
                            candidates: site.candidates.clone(),
                            coverage: site.candidates_coverage,
                        },
                    );
                    report.candidates_changed = true;
                }
            }
        }
        // Single counting point for every miss pushed above
        // (planned); pushes below (resolve/attach failures) carry
        // their own increment instead.
        self.missed_attaches += report.missed.len() as u64;
        // The owner opens and verifies the locator. This session retains only
        // immutable planned membership and data-only acknowledged tokens.
        for group in plan::groups(&planned) {
            let mut survivors = Vec::new();
            for (offset, cookie) in group.offsets.iter().zip(&group.cookies) {
                let cookie = u32::try_from(*cookie)?;
                let Some(prov) = self.provenance.get(&cookie) else {
                    continue;
                };
                if self
                    .attached
                    .contains(&(prov.site.device, prov.site.inode, *offset))
                {
                    report.reused += 1;
                } else {
                    survivors.push((*offset, cookie));
                }
            }
            for positions in survivors.chunks(8192) {
                let Some((_, first)) = positions.first() else {
                    continue;
                };
                let prov = &self.provenance[first];
                let backing = BackingIdentity {
                    device: prov.site.device,
                    inode: prov.site.inode,
                };
                let seq = self.next_command(deadline)?;
                let pending = PendingAttach {
                    seq,
                    backing,
                    locator: group.path.clone(),
                    positions: positions.to_vec(),
                    installed_at: installed_at_ns,
                    deadline,
                };
                let request = AttachRequest {
                    seq,
                    deadline,
                    expected_backing: backing,
                    locator: group.path.clone(),
                    offsets: positions.iter().map(|p| p.0).collect(),
                    cookies: positions.iter().map(|p| u64::from(p.1)).collect(),
                };
                self.pending_txn = Some(PendingCountTxn::Attach(pending.clone()));
                let ack = match self.backend.attach(request) {
                    Ok(ack) if ack.seq == seq => ack.value,
                    Ok(_) => return self.invalid_command(CountOperation::Attach, deadline),
                    Err(failure) => return self.command_failed(failure),
                };
                let mut previous = None;
                for refusal in &ack.refused {
                    if refusal.position >= positions.len()
                        || previous.is_some_and(|p| p >= refusal.position)
                    {
                        return self.invalid_command(CountOperation::Attach, deadline);
                    }
                    previous = Some(refusal.position);
                }
                let ids: Vec<_> = ack.links.iter().map(CountLink::id).collect();
                if ids.iter().enumerate().any(|(i, id)| {
                    id.owner_epoch != self.ready.owner_epoch
                        || ids[..i].contains(id)
                        || self.links.iter().any(|l| l.id() == *id)
                }) || (ack.links.is_empty() && ack.refused.len() != positions.len())
                {
                    return self.invalid_command(CountOperation::Attach, deadline);
                }
                for (i, position) in positions.iter().enumerate() {
                    if let Some(refusal) = ack.refused.iter().find(|r| r.position == i) {
                        match refusal.reason {
                            AttachRefusalReason::Unreadable | AttachRefusalReason::Replaced => {
                                report.missed.push(plan::Missed {
                                    dev: plan::render_device(backing.device),
                                    ino: backing.inode,
                                    offset: position.0,
                                    reason: if refusal.reason == AttachRefusalReason::Unreadable {
                                        "unreadable"
                                    } else {
                                        "replaced"
                                    },
                                });
                                self.missed_attaches = self.missed_attaches.saturating_add(1);
                            }
                            AttachRefusalReason::KernelRefused | AttachRefusalReason::Capacity => {
                                report.unresolved += 1;
                                self.unresolved = self.unresolved.saturating_add(1);
                            }
                        }
                        if refusal.reason == AttachRefusalReason::Capacity {
                            self.record_loss("count.owner_capacity", CounterSource::Attach, 1);
                            self.runtime_failure.get_or_insert(OwnerFailure::engine(
                                CountOperation::Attach,
                                FailureClass::Capacity,
                            ));
                        }
                    } else {
                        self.bind_position(&pending, *position);
                        report.attached += 1;
                    }
                }
                self.links.extend(ack.links);
                self.last_acked = Some(seq);
                self.pending_txn = None;
                if ack
                    .refused
                    .iter()
                    .any(|r| r.reason == AttachRefusalReason::Capacity)
                {
                    self.closed = true;
                    self.canonical = Some(self.backend.terminal_request(deadline, self.frontier()));
                    return Err(OwnerFailure::engine(
                        CountOperation::Attach,
                        FailureClass::Capacity,
                    )
                    .into());
                }
            }
        }
        Ok(report)
    }

    /// Open the count window: arm the target TGID guard, the current
    /// generation and the monotonic `[start_ns, deadline_ns)`
    /// admission interval. Counts are admitted only inside the
    /// declared interval; an empty or inverted window is a
    /// fail-closed error. Called once per session, at target release
    /// (T08); attach deltas may precede or follow it.
    pub fn open_window(
        &mut self,
        start_ns: u64,
        deadline_ns: u64,
        deadline: Instant,
    ) -> anyhow::Result<()> {
        self.ensure_active()?;
        if self.window_open || start_ns >= deadline_ns {
            anyhow::bail!("invalid or already open count window");
        }
        let seq = self.next_command(deadline)?;
        let request = OpenRequest {
            seq,
            deadline,
            tgid: u64::from(self.pid),
            generation: self.generation,
            start_ns,
            deadline_ns,
        };
        self.pending_txn = Some(PendingCountTxn::Open(request));
        match self.backend.open_window(request) {
            Ok(ack) if ack.seq == seq => match ack
                .value
                .programmed_admission(self.ready.owner_epoch, &request)
            {
                Ok(admission) => {
                    self.acknowledged_open = Some(ack.value);
                    self.programmed = Some(admission);
                    self.window_open = true;
                    self.last_acked = Some(seq);
                    self.pending_txn = None;
                    Ok(())
                }
                Err(_) => self.invalid_command(CountOperation::Open, deadline),
            },
            Ok(_) => self.invalid_command(CountOperation::Open, deadline),
            Err(failure) => self.command_failed(failure),
        }
    }

    fn read(&mut self, deadline: Instant) -> anyhow::Result<()> {
        self.ensure_active()?;
        let seq = self.next_command(deadline)?;
        let read = ReadRequest { seq, deadline };
        self.pending_txn = Some(PendingCountTxn::Read(read));
        match self.backend.drain(read) {
            Ok(ack) if ack.seq == seq => {
                self.route_snapshot(ack.value);
                self.last_acked = Some(seq);
                self.pending_txn = None;
            }
            Ok(_) => return self.invalid_command(CountOperation::Read, deadline),
            Err(failure) => return self.command_failed(failure),
        }
        Ok(())
    }

    pub fn fence(&mut self, reason: FenceReason, deadline: Instant) -> anyhow::Result<()> {
        self.read(deadline)?;
        let Some(next) = self.generation.checked_add(1) else {
            return self.invalid_command(CountOperation::Generation, deadline);
        };
        let seq = self.next_command(deadline)?;
        let request = GenerationRequest {
            seq,
            deadline,
            generation: next,
        };
        self.pending_txn = Some(PendingCountTxn::Fence {
            request,
            reason,
            old_generation: self.generation,
            old_meanings: self.provenance.clone(),
            new_meanings: self.pending.clone(),
        });
        match self.backend.set_generation(request) {
            Ok(ack) if ack.seq == seq => {
                self.last_acked = Some(seq);
                self.commit_pending_fence();
                Ok(())
            }
            Ok(_) => self.invalid_command(CountOperation::Generation, deadline),
            Err(failure) => self.command_failed(failure),
        }
    }

    fn commit_pending_fence(&mut self) {
        let Some(PendingCountTxn::Fence {
            request,
            reason,
            old_generation,
            old_meanings,
            new_meanings,
        }) = self.pending_txn.take()
        else {
            return;
        };
        if self.generation != old_generation {
            self.record_loss("count.reference_inventory_invalid", CounterSource::Drain, 1);
            return;
        }
        let next = request.generation;
        self.provenance = old_meanings;
        self.pending = new_meanings;
        // Seal reads LIVE provenance (pending applies below, after
        // the seal): staged identity changes are the NEW
        // generation's meaning and must not relabel old counts.
        // Coverage-only staged downgrades therefore seal stale —
        // by design, not oversight: close-time revision (H2)
        // owns final truth (it revisits every fenced + current
        // site against final taint), and the seal-time value is
        // unobservable except through the revised doc. Do NOT
        // "fix" the order without splitting identity (post-seal)
        // from coverage (pre-seal) per staged entry.
        let mut sites: Vec<SiteExecution> = Vec::new();
        for (cookie, total) in &self.current {
            if total.count == 0 {
                continue;
            }
            let Some(prov) = self.provenance.get(cookie) else {
                continue;
            };
            sites.push(SiteExecution {
                site: prov.site.clone(),
                generation: self.generation,
                candidates: prov.candidates.clone(),
                candidates_coverage: prov.candidates_coverage,
                calls: total.count,
                first_ns: total.first_ns,
                last_ns: total.last_ns,
                installed_at: prov.installed_at,
            });
        }
        sites.sort();
        eprintln!(
            "COUNT fence reason={reason:?} generation={} keys={}",
            self.generation,
            sites.len(),
        );
        self.fenced.push(FencedGeneration {
            generation: self.generation,
            sites,
        });
        for cookie in self.known.iter() {
            if let Some(prov) = self.provenance.get(cookie) {
                self.retired
                    .insert((self.generation, *cookie), prov.clone());
            }
        }
        for (cookie, staged) in self.pending.drain() {
            if let Some(prov) = self.provenance.get_mut(&cookie) {
                prov.site = staged.site;
                prov.candidates = staged.candidates;
                prov.candidates_coverage = staged.coverage;
            }
        }
        self.current.clear();
        // H4: no quarantine set remains to lift (see the removed
        // field) — every generation re-resolves from the maps
        // plan, and stale plans miss `replaced` per attempt.
        self.generation = next;
        self.fences += 1;
    }

    pub fn programmed_admission(&self) -> Option<&ProgrammedAdmission> {
        self.programmed.as_ref()
    }
    pub fn terminal_id(&self) -> Option<TerminalId> {
        self.canonical.as_ref().map(|t| t.id)
    }
    pub fn fork_permit(&self, deadline: Instant) -> Result<CountForkPermit<'_>, ForkBlocked> {
        self.backend.fork_permit(deadline)
    }

    fn ensure_active(&self) -> anyhow::Result<()> {
        if self.closed || self.pending_txn.is_some() {
            anyhow::bail!("count session is sealed or has an unresolved operation");
        }
        Ok(())
    }
    fn next_command(&mut self, deadline: Instant) -> anyhow::Result<CommandSeq> {
        self.ensure_active()?;
        match self.ids.command() {
            Ok(seq) => Ok(seq),
            Err(failure) => {
                self.runtime_failure = Some(failure);
                self.terminal_shared(CloseRequest {
                    started_at: deadline,
                    grace: Duration::ZERO,
                    reason: CloseReason::Failure,
                });
                Err(failure.into())
            }
        }
    }
    fn invalid_command<T>(
        &mut self,
        operation: CountOperation,
        deadline: Instant,
    ) -> anyhow::Result<T> {
        let failure = OwnerFailure::engine(operation, FailureClass::Inventory);
        self.runtime_failure.get_or_insert(failure);
        self.closed = true;
        self.record_loss("count.reference_inventory_invalid", CounterSource::Drain, 1);
        self.canonical = Some(self.backend.terminal_request(deadline, self.frontier()));
        Err(failure.into())
    }
    fn command_failed<T>(&mut self, failure: CommandFailure) -> anyhow::Result<T> {
        self.closed = true;
        if let Some(loss) = failure.capacity_loss() {
            merge_counter(&mut self.passthrough, loss);
        }
        if !matches!(failure.failure.class, FailureClass::Deadline) {
            self.runtime_failure.get_or_insert(failure.failure);
        }
        let deadline = self
            .pending_txn
            .as_ref()
            .map(PendingCountTxn::deadline)
            .unwrap_or_else(Instant::now);
        if failure.publication == CommandPublication::Published
            && matches!(self.pending_txn, Some(PendingCountTxn::Read(read)) if read.seq == failure.seq)
            && failure.failure.operation == CountOperation::Read
        {
            if let Some(checkpoint) = self.backend.progress() {
                // Ordinary Read prefixes keep the actual Ready/Observing
                // phase. They retain positive facts under acknowledged link
                // meanings, without granting terminal completion authority.
                if checkpoint.published_at < deadline
                    && matches!(
                        checkpoint.phase,
                        OwnerPhase::Ready | OwnerPhase::Observing | OwnerPhase::Snapshotting
                    )
                {
                    self.route_snapshot(checkpoint.snapshot);
                }
            }
        }
        if failure.publication == CommandPublication::NotPublished {
            self.pending_txn = None;
        }
        let request = self.backend.terminal_request(deadline, self.frontier());
        self.canonical = Some(request);
        Err(failure.failure.into())
    }
    fn bind_position(&mut self, pending: &PendingAttach, (offset, cookie): (u64, u32)) {
        if let Some(prov) = self.provenance.get_mut(&cookie) {
            if prov.site.device != pending.backing.device
                || prov.site.inode != pending.backing.inode
                || prov.site.offset != offset
            {
                return;
            }
            self.attached
                .insert((prov.site.device, prov.site.inode, offset));
            self.bound.insert(cookie);
            if prov.installed_at.is_none() {
                prov.link_path = pending.locator.clone();
                prov.installed_at = Some(pending.installed_at);
            }
        }
    }
    fn record_loss(&mut self, name: &str, source: CounterSource, value: u64) {
        // Terminal classes are flags, never multiplied by salvage or repeated components.
        if let Some(old) = self
            .passthrough
            .iter_mut()
            .find(|c| c.name == name && c.source == source)
        {
            old.value = old.value.max(value);
        } else {
            self.passthrough.push(counter(
                name,
                CounterKind::Loss,
                CounterUnits::Events,
                source,
                value,
            ));
        }
    }
    fn frontier(&self) -> ControllerFrontier {
        ControllerFrontier {
            last_acked: self.last_acked,
            acknowledged_links: self.links.iter().map(CountLink::id).collect(),
            pending: self.pending_txn.as_ref().map(PendingCountTxn::id),
        }
    }

    /// Legacy owned-return adapter. New retained consumers share the selected
    /// canonical envelope via `terminal_shared` / `shared_terminal` instead.
    pub fn terminal(&mut self, request: CloseRequest) -> CountTerminal {
        self.terminal_shared(request).as_ref().clone()
    }

    /// Select exactly once, moving the routed converted drain into one shared
    /// immutable canonical envelope. Re-entry shares it without another image,
    /// close, clock sample or deadline.
    pub fn terminal_shared(&mut self, request: CloseRequest) -> Arc<CountTerminal> {
        if let Some(view) = &self.terminal_view {
            return view.clone();
        }
        self.closed = true;
        self.window_open = false;
        let frontier = self.frontier();
        // A failed ordinary command may already have reserved the sticky
        // terminal slot. Reuse that exact binding and original budget without
        // resubmission or another deadline calculation.
        let expected = if let Some(canonical) = &self.canonical {
            canonical.clone()
        } else {
            let deadline = request
                .started_at
                .checked_add(request.grace)
                .unwrap_or_else(|| {
                    self.runtime_failure.get_or_insert(OwnerFailure::engine(
                        CountOperation::Stop,
                        FailureClass::DeadlineOverflow,
                    ));
                    request.started_at
                });
            self.backend.terminal_request(deadline, frontier.clone())
        };
        self.canonical = Some(expected.clone());
        let receipt = self.backend.terminal(expected.clone());
        self.lat_final_available = [false; 16];
        self.admitted_final_available = false;
        self.dropfail_final_available = false;
        let binding_valid = expected.id.owner_epoch == self.ready.owner_epoch
            && expected.frontier == frontier
            && expected.evidence_domain == self.ready.evidence_domain
            && expected.writer_object_identity == self.ready.writer_object_identity
            && receipt.owner_epoch == self.ready.owner_epoch
            && receipt.terminal_id == expected.id
            && receipt.deadline == expected.deadline
            && receipt.evidence_domain == self.ready.evidence_domain
            && receipt.writer_object_identity == self.ready.writer_object_identity
            && receipt.writer_family == self.ready.dimensions
            && self
                .acknowledged_open
                .is_none_or(|open| receipt.resolved_open == Some(open))
            && receipt.cleanup_ticket
                == (CleanupTicket {
                    owner_epoch: expected.id.owner_epoch,
                    terminal_id: expected.id,
                });
        let validation = validate_terminal(&expected, &receipt);
        self.terminal_inventory_unavailable = binding_valid
            && validation == Err(ReceiptFailure::Inventory)
            && receipt.inventory.is_none()
            && matches!(
                receipt.writers,
                WriterCompletion::Unknown(QuiescenceReason::Deadline | QuiescenceReason::Owner)
            )
            && receipt
                .failures
                .operations
                .iter()
                .flatten()
                .all(|failure| failure.class == FailureClass::Deadline);
        let mut valid = validation.is_ok() && binding_valid;
        if valid {
            valid = self.resolve_pending(&receipt);
        }
        if valid {
            if let Some(checkpoint) = &receipt.checkpoint {
                if checkpoint.published_at < receipt.deadline {
                    self.route_snapshot(checkpoint.snapshot.clone());
                }
            }
            self.read_duration_ns = receipt
                .snapshot_binding
                .and_then(|b| b.completed_at.checked_duration_since(b.started_at))
                .map(|d| d.as_nanos().min(u128::from(u64::MAX)) as u64);
        } else {
            self.record_loss("count.reference_inventory_invalid", CounterSource::Drain, 1);
        }
        let known_empty = valid && matches!(receipt.writers, WriterCompletion::KnownEmpty(_));
        self.unread_unknown = !known_empty
            && matches!(
                receipt.read_status,
                ReadStatus::NotStarted
                    | ReadStatus::Incomplete {
                        enumeration: EnumerationStatus::Unfinished
                    }
            );
        let unresolved_meaning = matches!(
            self.pending_txn,
            Some(PendingCountTxn::Fence { .. } | PendingCountTxn::Open(_))
        );
        if unresolved_meaning {
            self.record_loss("count.reference_inventory_invalid", CounterSource::Drain, 1);
        }
        let finished = valid
            && !unresolved_meaning
            && matches!(receipt.writers, WriterCompletion::Finished(_));
        self.terminal_reconciled = finished
            && receipt.read_status == ReadStatus::Complete
            && receipt.checkpoint.as_ref().is_some_and(|c| {
                self.last_snapshot_seq == Some(c.snapshot.sequence)
                    && matches!(c.snapshot.admitted, Component::Available(_))
                    && matches!(c.snapshot.dropfail, Component::Available(_))
                    && c.snapshot
                        .latc
                        .iter()
                        .all(|v| matches!(v, Component::Available(_)))
                    && c.snapshot.enumeration == (EnumerationStatus::Complete { unread_keys: 0 })
            });
        self.terminal_complete = known_empty || self.terminal_reconciled;
        if !known_empty {
            if !finished {
                self.record_loss("count.quiescence_unknown", CounterSource::Drain, 1);
            }
            if !valid
                || matches!(
                    receipt.writers,
                    WriterCompletion::Unknown(
                        QuiescenceReason::Inventory
                            | QuiescenceReason::References
                            | QuiescenceReason::ObjectDrift
                    )
                )
            {
                self.record_loss("count.reference_inventory_invalid", CounterSource::Drain, 1);
            }
            if receipt.close_outcomes.iter().any(|c| c.errno.is_some())
                || receipt
                    .failures
                    .operations
                    .iter()
                    .flatten()
                    .any(|f| f.operation == CountOperation::Close)
            {
                self.record_loss("count.close_failed", CounterSource::Drain, 1);
            }
            if receipt.read_status != ReadStatus::Complete
                || receipt.failures.components.iter().any(Option::is_some)
            {
                self.record_loss("count.drain_read_failed", CounterSource::Drain, 1);
            }
            match receipt.read_status {
                ReadStatus::Incomplete {
                    enumeration: EnumerationStatus::Complete { .. },
                } => {}
                ReadStatus::NotStarted
                | ReadStatus::Incomplete {
                    enumeration: EnumerationStatus::Unfinished,
                } => self.record_loss("count.drain_unenumerated", CounterSource::Drain, 1),
                _ => {}
            }
            if !matches!(receipt.seal, SealBracket { before_ns: Some(before), after_ns: Some(after), result: StopResult::Stopped } if before <= after)
            {
                self.record_loss("count.close_time_uncertain", CounterSource::Drain, 1);
            }
        }
        for failure in receipt.failures.operations.iter().flatten() {
            if !matches!(failure.class, FailureClass::Deadline) {
                self.runtime_failure.get_or_insert(*failure);
            }
        }
        for failure in receipt
            .failures
            .components
            .iter()
            .chain(self.component_failures.iter())
            .flatten()
        {
            if let Some(class) = failure
                .class
                .filter(|class| *class != FailureClass::Deadline)
            {
                self.runtime_failure.get_or_insert(OwnerFailure {
                    operation: failure.operation,
                    resource: ResourceId::Map(failure.map),
                    class,
                    errno: failure.errno,
                });
            }
        }
        if let StopResult::Failed(failure) = receipt.seal.result
            && failure.class != FailureClass::Deadline
        {
            self.runtime_failure.get_or_insert(failure);
        }
        if !valid && !self.terminal_inventory_unavailable {
            self.runtime_failure.get_or_insert(OwnerFailure::engine(
                CountOperation::Stop,
                FailureClass::Inventory,
            ));
        }
        if self.runtime_failure.is_some() {
            self.record_loss("count.owner_failed", CounterSource::Drain, 1);
        }
        let view = Arc::new(CountTerminal {
            retained_drain: self.retained_drain(),
            receipt,
            runtime_failure: self.runtime_failure,
        });
        self.terminal_view = Some(Arc::clone(&view));
        view
    }

    fn resolve_pending(&mut self, receipt: &RawTerminal) -> bool {
        let Some(pending) = self.pending_txn.clone() else {
            return true;
        };
        let Some(inventory) = &receipt.inventory else {
            return true;
        };
        let mut valid = true;
        match pending {
            PendingCountTxn::Fence { request, .. } => {
                if inventory.last_completed
                    == Some(PendingCommandId {
                        seq: request.seq,
                        operation: CountOperation::Generation,
                    })
                    && receipt.last_command_seq == Some(request.seq)
                    && receipt.failures.operations[CountOperation::Generation as usize].is_none()
                    && !self
                        .runtime_failure
                        .is_some_and(|f| f.operation == CountOperation::Generation)
                {
                    self.commit_pending_fence();
                }
            }
            PendingCountTxn::Open(request) => {
                if let Some(open) = receipt.resolved_open {
                    if let Ok(admission) =
                        open.programmed_admission(self.ready.owner_epoch, &request)
                    {
                        self.acknowledged_open = Some(open);
                        self.programmed = Some(admission);
                        self.pending_txn = None;
                    }
                }
            }
            PendingCountTxn::Attach(attach) => {
                for record in &receipt.manifest {
                    if record.command != attach.seq {
                        continue;
                    }
                    if record.backing != attach.backing
                        || record.outcome != CreateOutcome::Succeeded
                    {
                        valid = false;
                        self.runtime_failure.get_or_insert(OwnerFailure::engine(
                            CountOperation::Attach,
                            FailureClass::Inventory,
                        ));
                        self.record_loss(
                            "count.reference_inventory_invalid",
                            CounterSource::Drain,
                            1,
                        );
                        continue;
                    }
                    for member in &inventory.memberships[record.memberships.clone()] {
                        if let Some(position) = attach.positions.iter().find(|(off, cookie)| {
                            *off == member.offset && u64::from(*cookie) == member.cookie
                        }) {
                            self.bind_position(&attach, *position);
                        } else {
                            valid = false;
                            self.runtime_failure.get_or_insert(OwnerFailure::engine(
                                CountOperation::Attach,
                                FailureClass::Inventory,
                            ));
                            self.record_loss(
                                "count.reference_inventory_invalid",
                                CounterSource::Drain,
                                1,
                            );
                        }
                    }
                }
            }
            PendingCountTxn::Read(_) => {}
        }
        valid
    }

    /// Pure shared replay of the selected envelope. No backend or clock access,
    /// and no converted row/candidate collection is copied.
    pub fn shared_terminal(&self, terminal_id: TerminalId) -> Arc<CountTerminal> {
        let view = self
            .terminal_view
            .as_ref()
            .expect("terminal must be selected before salvage");
        assert_eq!(
            Some(terminal_id),
            self.terminal_id(),
            "foreign terminal identity"
        );
        Arc::clone(view)
    }

    /// Legacy host-test replay; copies converted rows for older controls.
    /// Production retained state uses `shared_terminal` and shares allocations.
    pub fn salvage_view(&self, terminal_id: TerminalId) -> CountTerminal {
        self.shared_terminal(terminal_id).as_ref().clone()
    }

    /// Strict legacy host-test adapter. Production capture uses the canonical
    /// shared envelope, never this owned-copy view. This performs no alternate
    /// I/O or renewed wait; it refuses incomplete evidence and actual errors.
    pub fn close_and_drain(&mut self, grace: Duration) -> anyhow::Result<CountDrain> {
        let view = self.terminal(CloseRequest {
            started_at: Instant::now(),
            grace,
            reason: CloseReason::Expired,
        });
        if view.runtime_failure.is_some() || !self.terminal_complete {
            anyhow::bail!("count terminal is incomplete or unproven");
        }
        Ok(view.retained_drain)
    }

    fn retained_drain(&self) -> CountDrain {
        let mut current: Vec<SiteExecution> = Vec::new();
        for (cookie, total) in &self.current {
            if total.count == 0 {
                continue;
            }
            let Some(prov) = self.provenance.get(cookie) else {
                continue;
            };
            current.push(SiteExecution {
                site: prov.site.clone(),
                generation: self.generation,
                candidates: prov.candidates.clone(),
                candidates_coverage: prov.candidates_coverage,
                calls: total.count,
                first_ns: total.first_ns,
                last_ns: total.last_ns,
                installed_at: prov.installed_at,
            });
        }
        current.sort();
        // Own-process RSS at drain (Linux `/proc/self/statm`,
        // resident field x page size). Fail-loud: unreadable statm
        // yields 0 and the live leg gates rss > 0.
        let drain_rss_bytes = Self::drain_rss_sample().unwrap_or(0);
        let mut counters = vec![
            counter(
                "count.map_insert_dropped",
                CounterKind::Loss,
                CounterUnits::Calls,
                CounterSource::KernelMap,
                self.dropfail,
            ),
            counter(
                "count.unattributed",
                CounterKind::Loss,
                CounterUnits::Calls,
                CounterSource::Drain,
                self.unattributed,
            ),
            counter(
                "count.drain_shortfall",
                CounterKind::Loss,
                CounterUnits::Events,
                CounterSource::Drain,
                self.shortfall,
            ),
            counter(
                "count.ledger_admitted",
                CounterKind::Activity,
                CounterUnits::Calls,
                CounterSource::KernelMap,
                self.admitted,
            ),
            counter(
                "count.missed_attaches",
                CounterKind::Loss,
                CounterUnits::Sites,
                CounterSource::Attach,
                self.missed_attaches,
            ),
            counter(
                "count.unresolved_offsets",
                CounterKind::Loss,
                CounterUnits::Probes,
                CounterSource::Attach,
                self.unresolved,
            ),
            counter(
                "count.stale_events",
                CounterKind::Activity,
                CounterUnits::Calls,
                CounterSource::Drain,
                self.stale_events,
            ),
            counter(
                "count.fences",
                CounterKind::Activity,
                CounterUnits::Events,
                CounterSource::Lifecycle,
                self.fences,
            ),
            counter(
                "count.drained_keys",
                CounterKind::Activity,
                CounterUnits::Events,
                CounterSource::Drain,
                self.drained_keys,
            ),
            counter(
                "count.drain_passes",
                CounterKind::Activity,
                CounterUnits::Events,
                CounterSource::Drain,
                u64::from(self.last_snapshot_seq.is_some()),
            ),
            counter(
                "count.drain_pass_ns_total",
                CounterKind::Activity,
                CounterUnits::Events,
                CounterSource::Drain,
                self.read_duration_ns.unwrap_or(0),
            ),
            counter(
                "count.drain_pass_ns_max",
                CounterKind::Activity,
                CounterUnits::Events,
                CounterSource::Drain,
                self.read_duration_ns.unwrap_or(0),
            ),
            counter(
                "count.drain_rss_bytes",
                CounterKind::Activity,
                CounterUnits::Events,
                CounterSource::Drain,
                drain_rss_bytes,
            ),
        ];
        // c8 latency distribution: full histogram plus
        // upper-bucket-edge quantiles (conservative — bucket k
        // covers [2^k, 2^(k+1)), so the edge never under-reports;
        // the clamp bucket reports u64::MAX). Empty histogram
        // scores 0/0 with 0 samples (nothing measured, not "fast").
        for (k, n) in self.lat_cum.iter().enumerate() {
            if !self.lat_available[k] || (!self.lat_final_available[k] && *n == 0) {
                continue;
            }
            let bucket_name = format!("count.lat_bucket_{k:02}");
            counters.push(counter(
                bucket_name.as_str(),
                CounterKind::Activity,
                CounterUnits::Events,
                CounterSource::KernelMap,
                *n,
            ));
        }
        let lat_total: u64 = self.lat_cum.iter().fold(0u64, |a, n| a.saturating_add(*n));
        let (mut lat_median, mut lat_p99) = (0u64, 0u64);
        if lat_total > 0 {
            let mut acc = 0u64;
            let half = lat_total.div_ceil(2);
            let rank99 = ((u128::from(lat_total) * 99).div_ceil(100) as u64).max(1);
            for (k, n) in self.lat_cum.iter().enumerate() {
                acc = acc.saturating_add(*n);
                let edge = if k >= 15 { u64::MAX } else { 1u64 << (k + 1) };
                if lat_median == 0 && acc >= half {
                    lat_median = edge;
                }
                if lat_p99 == 0 && acc >= rank99 {
                    lat_p99 = edge;
                }
            }
        }
        for (name, value) in [
            ("count.lat_samples", lat_total),
            ("count.lat_median_ns", lat_median),
            ("count.lat_p99_ns", lat_p99),
        ] {
            if !self.terminal_reconciled || !self.lat_final_available.iter().all(|v| *v) {
                continue;
            }
            counters.push(counter(
                name,
                CounterKind::Activity,
                CounterUnits::Events,
                CounterSource::KernelMap,
                value,
            ));
        }
        // Independent-ledger reconciliation (c6): every admitted
        // hit must account into routed calls (current + fenced +
        // unattributed) or map-full drops. `stale_events` is a
        // memo, not additive (stragglers already fold into their
        // fenced bucket at route). Under drain shortfall the
        // unread keys' calls are unknowable — the gap stays open
        // as Activity, never forced to zero, never a silent Loss.
        let mut routed: u64 = self.unattributed;
        for exec in &current {
            routed = routed.saturating_add(exec.calls);
        }
        for fenced in &self.fenced {
            for exec in &fenced.sites {
                routed = routed.saturating_add(exec.calls);
            }
        }
        let accounted = routed.saturating_add(self.dropfail);
        if self.terminal_reconciled && self.shortfall == 0 {
            counters.push(counter(
                "count.ledger_delta",
                CounterKind::Loss,
                CounterUnits::Calls,
                CounterSource::Drain,
                self.admitted.abs_diff(accounted),
            ));
        } else {
            counters.push(counter(
                "count.ledger_unreconciled",
                CounterKind::Activity,
                CounterUnits::Calls,
                CounterSource::Drain,
                self.admitted.saturating_sub(accounted),
            ));
        }
        counters.extend(self.passthrough.iter().cloned());
        counters.sort();
        if !self.admitted_available || (!self.admitted_final_available && self.admitted == 0) {
            counters.retain(|c| {
                c.name != "count.ledger_admitted" && c.name != "count.ledger_unreconciled"
            });
        }
        if !self.dropfail_available || (!self.dropfail_final_available && self.dropfail == 0) {
            counters.retain(|c| c.name != "count.map_insert_dropped");
        }
        if !self.enumerated || (self.unread_unknown && self.shortfall == 0) {
            counters.retain(|c| c.name != "count.drain_shortfall");
        }
        if self.read_duration_ns.is_none() {
            counters.retain(|c| {
                c.name != "count.drain_pass_ns_total" && c.name != "count.drain_pass_ns_max"
            });
        }
        CountDrain {
            current,
            fenced: self.fenced.clone(),
            counters,
        }
    }

    /// Own-process RSS in bytes (Linux-only sampler for the c8
    /// drain/memory score). `None` when statm is unreadable.
    fn drain_rss_sample() -> Option<u64> {
        let text = std::fs::read_to_string("/proc/self/statm").ok()?;
        let resident_pages: u64 = text.split_whitespace().nth(1)?.parse().ok()?;
        // SAFETY: sysconf with a valid name is async-signal-safe
        // and has no preconditions on our state.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page <= 0 {
            return None;
        }
        resident_pages.checked_mul(page as u64)
    }

    /// Route one raw drain: delta-reads per (cookie, generation),
    /// current-generation hits fold per cookie, unknown cookies are
    /// loud unattributed loss, and old-generation stragglers route
    /// exactly into their fenced bucket under the retired meaning
    /// (with a staleness memo) instead of merging into the new
    /// meaning. A known cookie with a generation that was never
    /// fenced (or a future one — backend bug) is unattributed loss:
    /// folding it into `current` would stamp it with a generation
    /// and candidate meaning it never had. Every drained delta lands
    /// in exactly one bucket — current, fenced, or unattributed —
    /// so counts are conserved per generation. Returns whether any
    /// count delta routed. Snapshot identity and cumulative high-water marks
    /// make every replay data-only, without a repeat-until-equal close scan.
    /// New images refine existing timestamp bounds independently of call deltas.
    fn route_snapshot(&mut self, snapshot: Arc<RawSnapshot>) -> bool {
        if self
            .last_snapshot_seq
            .is_some_and(|last| snapshot.sequence <= last)
        {
            return false;
        }
        let mut keys = HashSet::new();
        if snapshot.rows.iter().any(|(key, value)| {
            !keys.insert(*key) || (value.count > 0 && value.first_ns > value.last_ns)
        }) {
            self.record_loss("count.drain_read_failed", CounterSource::Drain, 1);
            return false;
        }
        let drained = &snapshot;

        let mut progress = false;
        self.drained_keys = self.drained_keys.saturating_add(drained.rows.len() as u64);
        for (key, total) in &drained.rows {
            if total.count == 0 {
                continue;
            }
            let (cookie, generation) = split_key(*key);
            let prev = self.seen.entry((cookie, generation)).or_default();
            let delta = total.count.saturating_sub(*prev);
            *prev = (*prev).max(total.count);
            progress |= delta > 0;
            if !self.known.contains(&cookie) {
                // Unknown cookie (any generation): truly
                // unattributable — loud loss, never silent.
                self.unattributed = self.unattributed.saturating_add(delta);
                continue;
            }
            if !self.bound.contains(&cookie) {
                // H4: planned but never bound (rejected resolve,
                // kernel refusal) — no link exists, so these hits
                // are backend anomalies, not evidence. Loud
                // unattributed loss (replaces F-A/A1 quarantine's
                // eager retract, which died with the !bound path).
                self.unattributed = self.unattributed.saturating_add(delta);
                continue;
            }
            if generation == self.generation {
                if delta > 0 {
                    self.current.entry(cookie).or_default().fold(&CountValue {
                        count: delta,
                        first_ns: total.first_ns,
                        last_ns: total.last_ns,
                    });
                } else if let Some(current) = self.current.get_mut(&cookie) {
                    // The producer increments count before storing last_ns.
                    // A newer validated image can finish that timestamp store
                    // without contributing another call, including saturation.
                    current.first_ns = current.first_ns.min(total.first_ns);
                    current.last_ns = current.last_ns.max(total.last_ns);
                }
                continue;
            }
            // Straggler: a known cookie's old-generation events
            // landing after their fence drain. The count stays
            // attributed under its own generation's meaning while
            // the staleness memo records the fence crossing.
            let retired = self.retired.get(&(generation, cookie));
            let bucket = self.fenced.iter_mut().find(|b| b.generation == generation);
            match (retired, bucket) {
                (Some(old), Some(bucket)) => {
                    self.stale_events = self.stale_events.saturating_add(delta);
                    if let Some(exec) = bucket.sites.iter_mut().find(|s| s.site == old.site) {
                        fold_exec_calls(exec, delta, total.first_ns, total.last_ns);
                    } else if delta > 0 {
                        bucket.sites.push(SiteExecution {
                            site: old.site.clone(),
                            generation,
                            candidates: old.candidates.clone(),
                            candidates_coverage: old.candidates_coverage,
                            calls: delta,
                            first_ns: total.first_ns,
                            last_ns: total.last_ns,
                            installed_at: old.installed_at,
                        });
                        bucket.sites.sort();
                    }
                }
                _ => {
                    // Defensive: a generation we never fenced. The
                    // count is conserved as explicit unattributed
                    // loss rather than misattributed to the live
                    // meaning.
                    self.unattributed = self.unattributed.saturating_add(delta);
                }
            }
        }
        if let Component::Available(n) = drained.dropfail {
            self.dropfail = self
                .dropfail
                .saturating_add(n.saturating_sub(self.last_dropfail));
            self.last_dropfail = self.last_dropfail.max(n);
            self.dropfail_available = true;
            self.dropfail_final_available = true;
        } else if let Component::Unavailable(f) = drained.dropfail {
            self.component_failures[1] = Some(f);
        }
        if let Component::Available(n) = drained.admitted {
            self.admitted = self
                .admitted
                .saturating_add(n.saturating_sub(self.last_admitted));
            self.last_admitted = self.last_admitted.max(n);
            self.admitted_available = true;
            self.admitted_final_available = true;
        } else if let Component::Unavailable(f) = drained.admitted {
            self.component_failures[0] = Some(f);
        }
        for (k, component) in drained.latc.iter().enumerate() {
            match component {
                Component::Available(n) => {
                    self.lat_cum[k] =
                        self.lat_cum[k].saturating_add(n.saturating_sub(self.last_lat[k]));
                    self.last_lat[k] = self.last_lat[k].max(*n);
                    self.lat_available[k] = true;
                    self.lat_final_available[k] = true;
                }
                Component::Unavailable(f) => {
                    self.component_failures[k + 2] = Some(*f);
                    self.lat_final_available[k] = false;
                }
            }
        }
        if let EnumerationStatus::Complete { unread_keys } = drained.enumeration {
            self.enumerated = true;
            self.shortfall = self.shortfall.saturating_add(unread_keys);
        }
        self.last_snapshot_seq = Some(snapshot.sequence);
        progress
    }
}

/// Compatibility name; this identity token has no descriptor or destructor I/O.
pub type FakeLink = LinkToken;

/// Finite fault controls for the HostModel backend. They cannot produce Live
/// receipts, and do not qualify kernel writer completion.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FakeTerminalFaults {
    pub admitted_unavailable: bool,
    pub dropfail_unavailable: bool,
    pub latc_unavailable: [bool; 16],
    pub enumeration: Option<EnumerationStatus>,
    pub read_error: bool,
    pub quiescence_unknown: bool,
    pub forget_frontier: bool,
    pub inventory_unavailable: bool,
    pub omit_resolved_open: bool,
    pub close_errno: Option<i32>,
    /// HostModel resource hold after the count snapshot, never a live profile.
    pub cleanup_pending: bool,
}

/// Deterministic host double for the count kernel side. [`fire`](Self::fire)
/// models `count_entry` admission exactly: closed window or foreign
/// TGID drops silently, out-of-window timestamps drop, and inserts
/// past `capacity` fail loud into the drop counter (map-full model).
/// The per-(cookie, generation) ledger is the test oracle: each
/// provider mapping's executions land only under its own cookie.
pub struct FakeCountBackend {
    ready: Ready,
    barrier: Arc<CountForkBarrier>,
    pins: Vec<std::os::fd::OwnedFd>,
    records: Vec<CreationRecord>,
    memberships: Vec<AttachedMembership>,
    last_completed: Option<PendingCommandId>,
    resolved_open: Option<OpenReceipt>,
    snapshot_seq: u64,
    link_seq: u64,
    terminal_seq: u64,
    terminal_request: Option<TerminalRequest>,
    terminal_view: Option<RawTerminal>,
    checkpoint: Option<RawCheckpoint>,
    faults: FakeTerminalFaults,
    modeled_seal: Option<SealBracket>,
    initial_empty_at: Instant,
    images: [Arc<RawSnapshot>; 3],
    terminal_builder: Option<Arc<RawTerminalData>>,
    inventory_builder: Option<Arc<SealedInventory>>,
    tgid: u64,
    generation: u32,
    start_ns: u64,
    deadline_ns: u64,
    open: bool,
    attached: HashMap<u32, (String, u64)>,
    ledger: HashMap<(u32, u32), CountValue>,
    /// Per-CPU slots `(cpu, cookie, generation)`: the N-CPU
    /// fan-out model, folded per key at drain like the kernel
    /// per-CPU slots composed by the userspace fold.
    cpu_slots: HashMap<(u32, u32, u32), CountValue>,
    dropfail: u64,
    admitted: u64,
    capacity: usize,
    poison: HashSet<u64>,
    shortfall_hook: u64,
    programmed: Vec<(u64, u32, u64, u64)>,
    lat_samples: [u64; 16],
}

impl std::fmt::Debug for FakeCountBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeCountBackend")
            .field("ready", &self.ready)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}
impl FakeCountBackend {
    pub fn new() -> Self {
        static EPOCH: AtomicU64 = AtomicU64::new(0);
        let epoch = EPOCH
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .expect("fixture epoch space exhausted")
            + 1;
        let ready = Ready {
            owner_epoch: OwnerEpoch::checked(epoch).expect("nonzero epoch"),
            writer_object_identity: [0x48; 32],
            dimensions: CountDimensions::validated(),
            evidence_domain: EvidenceDomain::HostModel,
        };
        let writer = WriterIdentity {
            owner_epoch: ready.owner_epoch,
            object_sha256: ready.writer_object_identity,
            program: ResourceId::Program,
            maps: CountMap::ALL.map(ResourceId::Map),
        };
        let id = TerminalId {
            owner_epoch: ready.owner_epoch,
            sequence: TerminalSeq::checked(1).expect("builder placeholder"),
        };
        let now = Instant::now();
        let unavailable = |map, key| {
            Component::Unavailable(ComponentFailure {
                map,
                key,
                operation: CountOperation::Read,
                class: None,
                errno: None,
            })
        };
        let images = std::array::from_fn(|_| {
            Arc::new(RawSnapshot {
                sequence: SnapshotSeq::checked(1).expect("builder placeholder"),
                rows: Vec::with_capacity(8192),
                admitted: unavailable(CountMap::Admitted, 0),
                dropfail: unavailable(CountMap::Dropfail, 0),
                latc: std::array::from_fn(|k| unavailable(CountMap::Latc, k as u32)),
                enumeration: EnumerationStatus::Unfinished,
            })
        });
        let inventory_builder = Arc::new(SealedInventory {
            owner_epoch: ready.owner_epoch,
            writer,
            records: Vec::with_capacity(8192),
            memberships: Vec::with_capacity(8192),
            acknowledged_links: Vec::with_capacity(8192),
            unpublished_links: Vec::with_capacity(8192),
            last_acked: None,
            pending: None,
            last_completed: None,
            resolved_open: None,
        });
        let terminal_builder = Arc::new(RawTerminalData {
            owner_epoch: ready.owner_epoch,
            terminal_id: id,
            deadline: now,
            last_command_seq: None,
            resolved_open: None,
            evidence_domain: EvidenceDomain::HostModel,
            inventory: None,
            manifest: Vec::with_capacity(8192),
            close_outcomes: Vec::with_capacity(8192),
            kernel_profile: KernelApplicability::ModelFixture,
            writer_object_identity: ready.writer_object_identity,
            writer_family: ready.dimensions,
            host_writes_sealed: false,
            final_references: ReferenceFinality {
                file: true,
                bpf_link: true,
            },
            seal: SealBracket::default(),
            writers: WriterCompletion::Unknown(QuiescenceReason::Owner),
            checkpoint: None,
            snapshot_binding: None,
            read_status: ReadStatus::NotStarted,
            cleanup_ticket: CleanupTicket {
                owner_epoch: ready.owner_epoch,
                terminal_id: id,
            },
            cleanup_state: CleanupState::Complete,
            failures: TerminalFailures::default(),
        });
        Self {
            ready,
            images,
            terminal_builder: Some(terminal_builder),
            inventory_builder: Some(inventory_builder),
            barrier: Arc::new(CountForkBarrier::new()),
            pins: Vec::with_capacity(8192),
            records: Vec::with_capacity(8192),
            memberships: Vec::with_capacity(8192),
            last_completed: None,
            resolved_open: None,
            snapshot_seq: 0,
            link_seq: 0,
            terminal_seq: 0,
            terminal_request: None,
            terminal_view: None,
            checkpoint: None,
            faults: FakeTerminalFaults::default(),
            modeled_seal: None,
            initial_empty_at: Instant::now(),
            tgid: 0,
            generation: 0,
            start_ns: 0,
            deadline_ns: 0,
            open: false,
            attached: HashMap::new(),
            ledger: HashMap::new(),
            cpu_slots: HashMap::new(),
            dropfail: 0,
            admitted: 0,
            capacity: 8192,
            poison: HashSet::new(),
            shortfall_hook: 0,
            programmed: Vec::new(),
            lat_samples: [0; 16],
        }
    }

    /// HostModel stop-operation script, independent of receipt/cleanup time.
    /// A sticky selected terminal can never be restamped.
    pub fn set_modeled_seal(&mut self, before_ns: Option<u64>, after_ns: Option<u64>) -> bool {
        if self.terminal_view.is_some() {
            return false;
        }
        self.modeled_seal = Some(SealBracket {
            before_ns,
            after_ns,
            result: StopResult::Stopped,
        });
        true
    }

    pub fn terminal_faults(&mut self, faults: FakeTerminalFaults) {
        self.faults = faults;
    }

    fn failure(
        &self,
        seq: CommandSeq,
        operation: CountOperation,
        class: FailureClass,
    ) -> CommandFailure {
        CommandFailure {
            seq,
            failure: OwnerFailure::engine(operation, class),
            completion: CommandCompletion::NotEntered,
            publication: CommandPublication::NotPublished,
            cleanup_ticket: self.terminal_request.as_ref().map(|r| CleanupTicket {
                owner_epoch: r.id.owner_epoch,
                terminal_id: r.id,
            }),
        }
    }
    fn writer(&self) -> WriterIdentity {
        WriterIdentity {
            owner_epoch: self.ready.owner_epoch,
            object_sha256: self.ready.writer_object_identity,
            program: ResourceId::Program,
            maps: CountMap::ALL.map(ResourceId::Map),
        }
    }
    fn component(&self, map: CountMap, key: u32, n: u64, missing: bool) -> Component<u64> {
        if missing {
            Component::Unavailable(ComponentFailure {
                map,
                key,
                operation: CountOperation::Read,
                class: None,
                errno: None,
            })
        } else {
            Component::Available(n)
        }
    }
    /// Publish one cumulative model image; used by scripted host interleavings.
    pub fn publish_checkpoint(&mut self) -> Result<Arc<RawSnapshot>, OwnerFailure> {
        self.publish_checkpoint_in_phase(OwnerPhase::Observing)
    }
    fn publish_checkpoint_in_phase(
        &mut self,
        phase: OwnerPhase,
    ) -> Result<Arc<RawSnapshot>, OwnerFailure> {
        let fail = || OwnerFailure::engine(CountOperation::Read, FailureClass::Capacity);
        let index = self
            .images
            .iter_mut()
            .position(|image| Arc::get_mut(image).is_some())
            .ok_or_else(fail)?;
        let next = self
            .snapshot_seq
            .checked_add(1)
            .ok_or_else(|| OwnerFailure::engine(CountOperation::Read, FailureClass::IdExhausted))?;
        let admitted = self.component(
            CountMap::Admitted,
            0,
            self.admitted,
            self.faults.admitted_unavailable,
        );
        let dropfail = self.component(
            CountMap::Dropfail,
            0,
            self.dropfail,
            self.faults.dropfail_unavailable,
        );
        let latc = std::array::from_fn(|k| {
            self.component(
                CountMap::Latc,
                k as u32,
                self.lat_samples[k],
                self.faults.latc_unavailable[k],
            )
        });
        let image = Arc::get_mut(&mut self.images[index]).expect("unpublished model image");
        image.rows.clear();
        for ((cookie, generation), value) in &self.ledger {
            if value.count > 0 {
                if image.rows.len() == image.rows.capacity() {
                    return Err(fail());
                }
                image.rows.push((make_key(*cookie, *generation), *value));
            }
        }
        for ((_, cookie, generation), value) in &self.cpu_slots {
            if value.count == 0 {
                continue;
            }
            let key = make_key(*cookie, *generation);
            if let Some((_, total)) = image.rows.iter_mut().find(|(k, _)| *k == key) {
                total.fold(value);
            } else {
                if image.rows.len() == image.rows.capacity() {
                    return Err(fail());
                }
                image.rows.push((key, *value));
            }
        }
        image.rows.sort_unstable_by_key(|r| r.0);
        image.sequence = SnapshotSeq::checked(next)?;
        image.admitted = admitted;
        image.dropfail = dropfail;
        image.latc = latc;
        image.enumeration = self
            .faults
            .enumeration
            .unwrap_or(EnumerationStatus::Complete {
                unread_keys: std::mem::take(&mut self.shortfall_hook),
            });
        self.snapshot_seq = next;
        let image = Arc::clone(&self.images[index]);
        self.checkpoint = Some(RawCheckpoint {
            snapshot: image.clone(),
            phase,
            published_at: Instant::now(),
        });
        Ok(image)
    }

    /// Model a bounded `COUNTS` map: at most `cap` distinct keys;
    /// further inserts fail into the drop counter.
    pub fn with_capacity(cap: usize) -> Self {
        let mut out = Self::new();
        out.capacity = cap.min(8192);
        out
    }

    /// Refuse one offset at attach (kernel-EINVAL model).
    pub fn poison_offset(&mut self, offset: u64) {
        self.poison.insert(offset);
    }

    /// Script shortfall keys for the next drain (grace-expiry model).
    pub fn set_shortfall(&mut self, n: u64) {
        self.shortfall_hook = n;
    }

    /// Zero the programmed interval while leaving the target armed
    /// (isolates zeroed-WINDOW admission from the target guard).
    /// Test hook only.
    pub fn deprogram_window(&mut self) {
        self.start_ns = 0;
        self.deadline_ns = 0;
    }

    /// Model one batch of `count_entry` hits: `n` entries into
    /// `cookie` from `tgid` at monotonic `now_ns`. The window check
    /// runs independently of (and before) the target guard, exactly
    /// like the kernel: a zeroed interval admits nothing even while
    /// armed.
    pub fn fire(&mut self, tgid: u32, cookie: u32, now_ns: u64, n: u64) {
        if n == 0 {
            return;
        }
        if now_ns < self.start_ns || now_ns >= self.deadline_ns {
            return;
        }
        if !self.open || u64::from(tgid) != self.tgid {
            return;
        }
        // Independent ledger: every hit admitted past the window +
        // target guards, including map-full drops below.
        self.admitted = self.admitted.saturating_add(n);
        let key = (cookie, self.generation);
        if let Some(slot) = self.ledger.get_mut(&key) {
            slot.count = slot.count.saturating_add(n);
            // Min/max, not last-write-wins: the single-slot fake
            // emulates per-CPU kernel slots (each first<=last by
            // per-CPU time order) composed by the userspace fold —
            // out-of-order fires must not invert the bounds.
            slot.first_ns = slot.first_ns.min(now_ns);
            slot.last_ns = slot.last_ns.max(now_ns);
            return;
        }
        if self.ledger.len() >= self.capacity {
            self.dropfail = self.dropfail.saturating_add(n);
            return;
        }
        self.ledger.insert(
            key,
            CountValue {
                count: n,
                first_ns: now_ns,
                last_ns: now_ns,
            },
        );
    }

    /// Model a hit landing on one CPU's slot (N-CPU fan-out
    /// model): same admission guards as [`fire`](Self::fire),
    /// recorded per CPU and folded at drain. Capacity counts
    /// distinct (cookie, generation) keys across both stores.
    pub fn fire_cpu(&mut self, cpu: u32, tgid: u32, cookie: u32, now_ns: u64, n: u64) {
        if n == 0 {
            return;
        }
        if now_ns < self.start_ns || now_ns >= self.deadline_ns {
            return;
        }
        if !self.open || u64::from(tgid) != self.tgid {
            return;
        }
        self.admitted = self.admitted.saturating_add(n);
        let key = (cpu, cookie, self.generation);
        if let Some(slot) = self.cpu_slots.get_mut(&key) {
            slot.count = slot.count.saturating_add(n);
            slot.first_ns = slot.first_ns.min(now_ns);
            slot.last_ns = slot.last_ns.max(now_ns);
            return;
        }
        let mut keys: HashSet<(u32, u32)> = self.ledger.keys().copied().collect();
        keys.extend(self.cpu_slots.keys().map(|(_, c, g)| (*c, *g)));
        if keys.len() >= self.capacity {
            self.dropfail = self.dropfail.saturating_add(n);
            return;
        }
        self.cpu_slots.insert(
            key,
            CountValue {
                count: n,
                first_ns: now_ns,
                last_ns: now_ns,
            },
        );
    }

    /// Independent admitted-hits total (test oracle for the
    /// `count.ledger_*` reconciliation).
    pub fn admitted_ledger(&self) -> u64 {
        self.admitted
    }

    /// Script latency samples into one bucket (drain emits them
    /// verbatim). Panics on bucket >= 16 (fail loud, tests only).
    pub fn inject_latency(&mut self, bucket: usize, n: u64) {
        assert!(bucket < 16, "latency bucket {bucket} out of range");
        self.lat_samples[bucket] = self.lat_samples[bucket].saturating_add(n);
    }

    /// Independent ledger total for one (cookie, generation).
    pub fn ledger_total(&self, cookie: u32, generation: u32) -> u64 {
        let mut total = self
            .ledger
            .get(&(cookie, generation))
            .map(|v| v.count)
            .unwrap_or(0);
        for ((_, c, g), v) in self.cpu_slots.iter() {
            if (*c, *g) == (cookie, generation) {
                total = total.saturating_add(v.count);
            }
        }
        total
    }

    /// Inject a raw ledger row, bypassing admission (models a hit the
    /// kernel admitted pre-close, or a backend anomaly for the
    /// defensive-routing tests). Test hook only.
    pub fn inject_row(&mut self, cookie: u32, generation: u32, value: CountValue) {
        self.ledger
            .entry((cookie, generation))
            .or_default()
            .fold(&value);
    }

    /// Link path a cookie attached through, if any.
    pub fn attached_path(&self, cookie: u32) -> Option<&str> {
        self.attached.get(&cookie).map(|(p, _)| p.as_str())
    }

    /// `open_window` programming log: (tgid, generation, start, deadline).
    pub fn programmed(&self) -> &[(u64, u32, u64, u64)] {
        &self.programmed
    }
}

impl Default for FakeCountBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl CountBackend for FakeCountBackend {
    type Link = LinkToken;
    fn ready(&self) -> &Ready {
        &self.ready
    }
    fn attach(&mut self, request: AttachRequest) -> CommandResult<AttachAck<LinkToken>> {
        if self.terminal_request.is_some() {
            return Err(self.failure(
                request.seq,
                CountOperation::Attach,
                FailureClass::Disconnected,
            ));
        }
        if request.offsets.is_empty()
            || request.offsets.len() > 8192
            || request.offsets.len() != request.cookies.len()
        {
            return Err(self.failure(
                request.seq,
                CountOperation::Attach,
                FailureClass::InvalidInput,
            ));
        }
        let pin = plan::resolve_pinned(&request.locator);
        let reason = match &pin {
            Err(_) => Some(AttachRefusalReason::Unreadable),
            Ok(p)
                if p.device != request.expected_backing.device
                    || p.ino != request.expected_backing.inode =>
            {
                Some(AttachRefusalReason::Replaced)
            }
            Ok(_) => None,
        };
        let mut ack = AttachAck {
            links: Vec::new(),
            refused: Vec::new(),
        };
        let pin_slot = self.pins.len();
        let path = pin.as_ref().map(|p| p.link_path()).unwrap_or_default();
        for (position, (offset, cookie)) in request.offsets.iter().zip(&request.cookies).enumerate()
        {
            let refusal = reason
                .or_else(|| {
                    self.poison
                        .contains(offset)
                        .then_some(AttachRefusalReason::KernelRefused)
                })
                .or_else(|| {
                    (self.memberships.len() >= 8192).then_some(AttachRefusalReason::Capacity)
                });
            if let Some(reason) = refusal {
                ack.refused.push(AttachRefusal { position, reason });
                continue;
            }
            let Ok(cookie32) = u32::try_from(*cookie) else {
                return Err(self.failure(
                    request.seq,
                    CountOperation::Attach,
                    FailureClass::InvalidInput,
                ));
            };
            self.link_seq = self.link_seq.checked_add(1).ok_or_else(|| {
                self.failure(
                    request.seq,
                    CountOperation::Attach,
                    FailureClass::IdExhausted,
                )
            })?;
            let id = LinkId {
                owner_epoch: self.ready.owner_epoch,
                serial: LinkSerial::checked(self.link_seq).expect("nonzero link"),
            };
            let start = self.memberships.len();
            self.memberships.push(AttachedMembership {
                offset: *offset,
                cookie: *cookie,
            });
            self.records.push(CreationRecord {
                id,
                command: request.seq,
                writer: self.writer(),
                backing: request.expected_backing,
                pin_slot,
                memberships: start..start + 1,
                outcome: CreateOutcome::Succeeded,
                publication: PublicationState::Published,
                close_state: ResourceState::Held,
                close_errno: None,
            });
            self.attached.insert(cookie32, (path.clone(), *offset));
            ack.links.push(LinkToken::new(id));
        }
        if !ack.links.is_empty() {
            self.pins.push(pin.expect("successful pin").fd);
        }
        self.last_completed = Some(PendingCommandId {
            seq: request.seq,
            operation: CountOperation::Attach,
        });
        Ok(CommandAck {
            seq: request.seq,
            value: ack,
        })
    }
    fn open_window(&mut self, request: OpenRequest) -> CommandResult<OpenReceipt> {
        if self.terminal_request.is_some()
            || request.start_ns >= request.deadline_ns
            || request.tgid == 0
        {
            return Err(self.failure(
                request.seq,
                CountOperation::Open,
                FailureClass::InvalidInput,
            ));
        }
        self.tgid = request.tgid;
        self.generation = request.generation;
        self.start_ns = request.start_ns;
        self.deadline_ns = request.deadline_ns;
        self.open = true;
        self.programmed.push((
            request.tgid,
            request.generation,
            request.start_ns,
            request.deadline_ns,
        ));
        let receipt = OpenReceipt {
            owner_epoch: self.ready.owner_epoch,
            seq: request.seq,
            tgid: request.tgid,
            generation: request.generation,
            start_ns: request.start_ns,
            deadline_ns: request.deadline_ns,
            completed_writes: OpenWriteFrontier::Target,
            outcome: OpenOutcome::Completed,
        };
        self.resolved_open = Some(receipt);
        self.last_completed = Some(PendingCommandId {
            seq: request.seq,
            operation: CountOperation::Open,
        });
        Ok(CommandAck {
            seq: request.seq,
            value: receipt,
        })
    }
    fn set_generation(&mut self, request: GenerationRequest) -> CommandResult<()> {
        if self.terminal_request.is_some() {
            return Err(self.failure(
                request.seq,
                CountOperation::Generation,
                FailureClass::Disconnected,
            ));
        }
        self.generation = request.generation;
        self.last_completed = Some(PendingCommandId {
            seq: request.seq,
            operation: CountOperation::Generation,
        });
        Ok(CommandAck {
            seq: request.seq,
            value: (),
        })
    }
    fn drain(&mut self, request: ReadRequest) -> CommandResult<Arc<RawSnapshot>> {
        if self.terminal_request.is_some() {
            return Err(self.failure(
                request.seq,
                CountOperation::Read,
                FailureClass::Disconnected,
            ));
        }
        let image = self
            .publish_checkpoint()
            .map_err(|failure| CommandFailure {
                seq: request.seq,
                failure,
                completion: CommandCompletion::Completed,
                publication: CommandPublication::Published,
                cleanup_ticket: None,
            })?;
        self.last_completed = Some(PendingCommandId {
            seq: request.seq,
            operation: CountOperation::Read,
        });
        if self.faults.read_error {
            return Err(CommandFailure {
                completion: CommandCompletion::Completed,
                publication: CommandPublication::Published,
                ..self.failure(request.seq, CountOperation::Read, FailureClass::Io)
            });
        }
        Ok(CommandAck {
            seq: request.seq,
            value: image,
        })
    }
    fn terminal_request(
        &mut self,
        deadline: Instant,
        frontier: ControllerFrontier,
    ) -> TerminalRequest {
        if let Some(request) = &self.terminal_request {
            return request.clone();
        }
        self.terminal_seq = self
            .terminal_seq
            .checked_add(1)
            .expect("fixture terminal identity exhaustion");
        let request = TerminalRequest {
            id: TerminalId {
                owner_epoch: self.ready.owner_epoch,
                sequence: TerminalSeq::checked(self.terminal_seq).expect("nonzero terminal"),
            },
            deadline,
            evidence_domain: self.ready.evidence_domain,
            writer_object_identity: self.ready.writer_object_identity,
            frontier,
        };
        self.terminal_request = Some(request.clone());
        request
    }
    fn terminal(&mut self, request: TerminalRequest) -> RawTerminal {
        if let Some(view) = &self.terminal_view {
            return view.clone();
        }
        let now = Instant::now();
        self.open = false;
        let mut storage = self.terminal_builder.take().expect("one model envelope");
        let data = Arc::get_mut(&mut storage).expect("private model builder");
        data.terminal_id = request.id;
        data.deadline = request.deadline;
        data.host_writes_sealed = true;
        data.cleanup_ticket = CleanupTicket {
            owner_epoch: self.ready.owner_epoch,
            terminal_id: request.id,
        };
        if self.initial_empty_at < request.deadline
            && self.last_completed.is_none()
            && self.records.is_empty()
            && self.resolved_open.is_none()
            && self.checkpoint.is_none()
            && request.frontier == ControllerFrontier::default()
            && self.faults == FakeTerminalFaults::default()
        {
            data.kernel_profile = KernelApplicability::Unknown(ProfileFailure::UnboundBuild);
            data.writers = WriterCompletion::KnownEmpty(EmptyWitness {
                owner_epoch: self.ready.owner_epoch,
                terminal_id: request.id,
                writer_object_identity: self.ready.writer_object_identity,
                ready_published_at: self.initial_empty_at,
                sealed_at: now,
                deadline: request.deadline,
            });
            let view = RawTerminal::model(storage);
            self.terminal_view = Some(view.clone());
            return view;
        }
        let can_read = now < request.deadline;
        let finished =
            can_read && !self.faults.quiescence_unknown && self.faults.close_errno.is_none();
        let last_completed = if self.faults.forget_frontier {
            request.frontier.last_acked.map(|seq| PendingCommandId {
                seq,
                operation: CountOperation::Read,
            })
        } else {
            self.last_completed
        };
        let mut inventory = self.inventory_builder.take().expect("one model inventory");
        let journal = Arc::get_mut(&mut inventory).expect("private model inventory");
        journal.last_acked = request.frontier.last_acked;
        journal.pending = request.frontier.pending;
        journal.last_completed = last_completed;
        journal.resolved_open = if self.faults.omit_resolved_open {
            None
        } else {
            self.resolved_open
        };
        journal.memberships.extend_from_slice(&self.memberships);
        for record in &mut self.records {
            if request.frontier.acknowledged_links.contains(&record.id) {
                record.publication = PublicationState::Published;
                journal.acknowledged_links.push(record.id);
            } else {
                record.publication = PublicationState::Unpublished;
                journal.unpublished_links.push(record.id);
            }
            record.close_state = ResourceState::CloseReturned;
            record.close_errno = self.faults.close_errno;
            data.close_outcomes.push(LinkCloseOutcome {
                id: record.id,
                issued_at: Some(now),
                returned_at: Some(now),
                state: ResourceState::CloseReturned,
                errno: record.close_errno,
            });
            journal.records.push(record.clone());
            data.manifest.push(record.clone());
        }
        let resolved_open = journal.resolved_open;
        data.inventory = Some(inventory);
        data.last_command_seq = last_completed.map(|c| c.seq);
        data.resolved_open = resolved_open;
        data.seal = self.modeled_seal.unwrap_or(SealBracket {
            before_ns: Some(1),
            after_ns: Some(2),
            result: StopResult::Stopped,
        });
        data.writers = if finished {
            WriterCompletion::Finished(WriterWitness {
                owner_epoch: self.ready.owner_epoch,
                terminal_id: request.id,
                last_command_seq: data.last_command_seq,
                writer_object_identity: self.ready.writer_object_identity,
                established_at: now,
            })
        } else {
            WriterCompletion::Unknown(QuiescenceReason::Deadline)
        };
        let started = Instant::now();
        let mut fresh = false;
        if can_read {
            match self.publish_checkpoint_in_phase(OwnerPhase::Snapshotting) {
                Ok(_) => fresh = true,
                Err(failure) => {
                    data.failures.operations[CountOperation::Read as usize] = Some(failure);
                }
            }
        }
        data.checkpoint = self
            .checkpoint
            .clone()
            .filter(|c| c.published_at < request.deadline);
        data.read_status = match &data.checkpoint {
            Some(c)
                if fresh
                    && !self.faults.read_error
                    && c.snapshot.enumeration
                        == (EnumerationStatus::Complete { unread_keys: 0 })
                    && matches!(c.snapshot.admitted, Component::Available(_))
                    && matches!(c.snapshot.dropfail, Component::Available(_))
                    && c.snapshot
                        .latc
                        .iter()
                        .all(|v| matches!(v, Component::Available(_))) =>
            {
                ReadStatus::Complete
            }
            Some(c) => ReadStatus::Incomplete {
                enumeration: c.snapshot.enumeration,
            },
            None => ReadStatus::NotStarted,
        };
        if self.faults.read_error {
            data.failures.operations[CountOperation::Read as usize] =
                Some(OwnerFailure::engine(CountOperation::Read, FailureClass::Io));
        }
        if let Some(errno) = self.faults.close_errno {
            data.failures.operations[CountOperation::Close as usize] = Some(OwnerFailure {
                operation: CountOperation::Close,
                resource: ResourceId::Engine,
                class: FailureClass::Io,
                errno: Some(errno),
            });
        }
        if let Some(c) = &data.checkpoint {
            for (index, component) in std::iter::once(&c.snapshot.admitted)
                .chain(std::iter::once(&c.snapshot.dropfail))
                .chain(c.snapshot.latc.iter())
                .enumerate()
            {
                if let Component::Unavailable(f) = component {
                    data.failures.components[index] = Some(*f);
                }
            }
            data.snapshot_binding = Some(SnapshotBinding {
                sequence: c.snapshot.sequence,
                started_at: if fresh { started } else { c.published_at },
                completed_at: c.published_at,
                immutable: finished && fresh,
            });
        }
        // If no post-witness image could be built, the old ordinary image is
        // useful as positive evidence but cannot be an immutable final read.
        if finished && !fresh {
            data.checkpoint = None;
            data.snapshot_binding = None;
            data.read_status = ReadStatus::NotStarted;
        }
        if self.faults.inventory_unavailable {
            data.inventory = None;
            data.writers = WriterCompletion::Unknown(QuiescenceReason::Deadline);
            data.checkpoint = None;
            data.snapshot_binding = None;
            data.read_status = ReadStatus::NotStarted;
        }
        if self.faults.cleanup_pending {
            data.cleanup_state = CleanupState::Pending(ResourceSummary {
                resources: vec![ResourceRecord {
                    resource: ResourceId::Map(CountMap::Counts),
                    state: ResourceState::Held,
                    errno: None,
                }],
                sealed: true,
                cleanup_complete: false,
            });
        }
        self.pins.clear();
        let view = RawTerminal::model(storage);
        self.terminal_view = Some(view.clone());
        view
    }
    fn progress(&self) -> Option<RawCheckpoint> {
        self.checkpoint.clone()
    }
    fn fork_permit(&self, deadline: Instant) -> Result<CountForkPermit<'_>, ForkBlocked> {
        self.barrier.prefix_permit(deadline)
    }
}

/// Production adapter: the already-owning engine retains all count resources.
pub struct LiveBackend {
    engine: CountEngine,
}
impl LiveBackend {
    #[cfg(test)]
    pub(crate) fn from_setup_fixture(engine: CountEngine) -> Self {
        Self { engine }
    }

    pub(crate) fn prepare_controlled(
        input: CountInput,
        limits: CountOwnerLimits,
        deadline: Instant,
        admission: crate::count_owner::CountSetupAdmission,
        control: &crate::count_owner::CountPrepareControl,
        journal: &crate::count_owner::CountSetupJournal,
    ) -> Result<Self, CountPrepareFailure> {
        CountEngine::prepare_controlled(input, limits, deadline, admission, control, journal)
            .map(|engine| Self { engine })
    }
    pub fn prepare(
        input: CountInput,
        limits: CountOwnerLimits,
        setup_deadline: Instant,
    ) -> Result<Self, CountPrepareFailure> {
        CountEngine::prepare(input, limits, setup_deadline).map(|engine| Self { engine })
    }
}
impl CountBackend for LiveBackend {
    type Link = LinkToken;
    fn ready(&self) -> &Ready {
        self.engine.ready()
    }
    fn attach(&mut self, r: AttachRequest) -> CommandResult<AttachAck<LinkToken>> {
        self.engine.attach(r)
    }
    fn open_window(&mut self, r: OpenRequest) -> CommandResult<OpenReceipt> {
        self.engine.open_window(r)
    }
    fn set_generation(&mut self, r: GenerationRequest) -> CommandResult<()> {
        self.engine.set_generation(r)
    }
    fn drain(&mut self, r: ReadRequest) -> CommandResult<Arc<RawSnapshot>> {
        self.engine.drain(r)
    }
    fn terminal_request(
        &mut self,
        deadline: Instant,
        frontier: ControllerFrontier,
    ) -> TerminalRequest {
        let ready = self.engine.ready();
        self.engine.terminal_request(
            deadline,
            ready.evidence_domain,
            ready.writer_object_identity,
            frontier,
        )
    }
    fn terminal(&mut self, r: TerminalRequest) -> RawTerminal {
        self.engine.terminal(r)
    }
    fn progress(&self) -> Option<RawCheckpoint> {
        self.engine.progress()
    }
    fn fork_permit(&self, deadline: Instant) -> Result<CountForkPermit<'_>, ForkBlocked> {
        self.engine.fork_permit(deadline)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn preplanned_fixture() -> (std::fs::File, std::path::PathBuf, DiscoveredSite) {
        use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "osslscope-preplanned-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(path).unwrap();
        file.set_len(4096).unwrap();
        let m = file.metadata().unwrap();
        let locator = std::path::PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
        let object = crate::evidence::ObjectId("fixture-library".into());
        let site = DiscoveredSite {
            site: SiteKey {
                object: object.clone(),
                device: plan::encode_device(libc::major(m.dev()), libc::minor(m.dev())),
                inode: m.ino(),
                offset: 128,
            },
            candidates: vec![CandidateIdentity::new(
                object,
                "default".into(),
                1,
                1,
                vec!["SHA256".into()],
                false,
            )],
            candidates_coverage: CandidateCoverage::Complete,
        };
        (file, locator, site)
    }

    #[test]
    fn preplanned_attach_does_not_require_live_mapping() {
        let (_backing, locator, site) = preplanned_fixture();
        let mut session = CountSession::new(42, FakeCountBackend::new());
        let report = session
            .attach_preplanned(
                &[site.clone()],
                &locator,
                1,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
        assert_eq!(report.attached, 1);
        assert!(report.missed.is_empty());
        let cookie = session
            .cookie_for(site.site.device, site.site.inode, site.site.offset)
            .unwrap();
        assert_eq!(session.provenance(cookie).unwrap().site, site.site);
    }

    #[test]
    fn preplanned_aliases_count_once() {
        let (_backing, locator, site) = preplanned_fixture();
        let mut alias = site.clone();
        alias.candidates[0].algorithm_classes = vec!["AES-256-GCM".into()];
        alias.candidates_coverage = CandidateCoverage::Unknown;
        let mut session = CountSession::new(42, FakeCountBackend::new());
        let deadline = Instant::now() + Duration::from_secs(2);
        let report = session
            .attach_preplanned(&[site, alias], &locator, 1, deadline)
            .unwrap();
        assert_eq!(report.attached, 1);
        assert_eq!(session.cookie_count(), 1);
        let cookie = session.cookies()[0];
        let p = session.provenance(cookie).unwrap();
        assert_eq!(p.candidates.len(), 2);
        assert_eq!(p.candidates_coverage, CandidateCoverage::Unknown);
        session.open_window(10, 100, deadline).unwrap();
        session.backend_mut().fire(42, cookie, 20, 32);
        session.backend_mut().fire(43, cookie, 20, 100);
        let terminal = session.terminal(CloseRequest {
            started_at: Instant::now(),
            grace: Duration::from_secs(1),
            reason: CloseReason::Expired,
        });
        assert_eq!(terminal.retained_drain.total_calls(), 32);
        assert_eq!(terminal.retained_drain.current[0].candidates.len(), 2);
    }

    #[test]
    fn preplanned_attach_requires_nonzero_original_pid() {
        let (_backing, locator, site) = preplanned_fixture();
        let mut session = CountSession::new(0, FakeCountBackend::new());
        assert!(
            session
                .attach_preplanned(
                    &[site],
                    &locator,
                    1,
                    Instant::now() + Duration::from_secs(2)
                )
                .is_err()
        );
        assert_eq!(session.cookie_count(), 0);
    }

    #[test]
    fn preplanned_attach_closes_without_rebinding() {
        let (_backing, locator, site) = preplanned_fixture();
        let mut session = CountSession::new(42, FakeCountBackend::new());
        let deadline = Instant::now() + Duration::from_secs(2);
        session
            .attach_preplanned(&[site.clone()], &locator, 1, deadline)
            .unwrap();
        session.open_window(10, 100, deadline).unwrap();
        assert!(
            session
                .attach_preplanned(&[site.clone()], &locator, 2, deadline)
                .is_err()
        );
        assert!(
            session
                .attach_delta(&CountDelta::default(), &[], &HashMap::new(), 2, deadline)
                .is_err()
        );
        session.terminal(CloseRequest {
            started_at: Instant::now(),
            grace: Duration::from_secs(1),
            reason: CloseReason::Expired,
        });
        assert!(
            session
                .attach_preplanned(&[site], &locator, 2, deadline)
                .is_err()
        );
        assert_eq!(session.pid(), 42);
        assert_eq!(session.cookie_count(), 1);
    }

    #[test]
    fn preplanned_attach_refuses_replaced_backing() {
        let (_backing, locator, mut site) = preplanned_fixture();
        site.site.inode += 1;
        let mut session = CountSession::new(42, FakeCountBackend::new());
        let report = session
            .attach_preplanned(
                &[site],
                &locator,
                1,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
        assert_eq!(report.attached, 0);
        assert_eq!(report.missed.len(), 1);
        assert_eq!(report.missed[0].reason, "replaced");
    }

    pub(crate) fn read_for_fixture<B: CountBackend>(
        session: &mut CountSession<B>,
        deadline: Instant,
    ) -> CountDrain {
        session.read(deadline).unwrap();
        session.retained_drain()
    }

    /// Test-only identity of the actual selected allocations, including nested
    /// candidate buffers. No production accessors or allocation counters added.
    #[derive(Debug, PartialEq, Eq)]
    pub(crate) struct TerminalStorageIdentity {
        id: TerminalId,
        ticket: CleanupTicket,
        deadline: Instant,
        receipt: usize,
        calls: u64,
        allocations: Vec<usize>,
    }
    pub(crate) fn terminal_storage_identity(view: &CountTerminal) -> TerminalStorageIdentity {
        let drain = &view.retained_drain;
        let mut allocations = vec![
            drain.current.as_ptr() as usize,
            drain.fenced.as_ptr() as usize,
        ];
        for group in &drain.fenced {
            allocations.push(group.sites.as_ptr() as usize);
        }
        for row in drain
            .current
            .iter()
            .chain(drain.fenced.iter().flat_map(|group| &group.sites))
        {
            allocations.push(row.candidates.as_ptr() as usize);
            for candidate in &row.candidates {
                allocations.push(candidate.provider.0.as_ptr() as usize);
                allocations.push(candidate.provider_class.as_ptr() as usize);
                allocations.push(candidate.algorithm_classes.as_ptr() as usize);
                allocations.extend(
                    candidate
                        .algorithm_classes
                        .iter()
                        .map(|class| class.as_ptr() as usize),
                );
            }
        }
        TerminalStorageIdentity {
            id: view.receipt.terminal_id,
            ticket: view.receipt.cleanup_ticket,
            deadline: view.receipt.deadline,
            receipt: (&*view.receipt) as *const _ as usize,
            calls: drain.total_calls(),
            allocations,
        }
    }
    pub(crate) fn selected_storage_identity<B: CountBackend>(
        session: &CountSession<B>,
    ) -> TerminalStorageIdentity {
        terminal_storage_identity(session.terminal_view.as_ref().expect("selected terminal"))
    }

    #[test]
    fn fake_refuses_fourth_pinned_image() {
        let mut backend = FakeCountBackend::new();
        let a = backend.publish_checkpoint().unwrap();
        let b = backend.publish_checkpoint().unwrap();
        let c = backend.publish_checkpoint().unwrap();
        let read = backend.drain(ReadRequest {
            seq: CommandSeq::checked(1).unwrap(),
            deadline: Instant::now() + Duration::from_secs(1),
        });
        assert!(
            read.is_err(),
            "three pinned model images must refuse a fourth allocation"
        );
        drop((a, b, c));
    }

    #[test]
    fn command_ids_exhaust_without_reuse() {
        let mut ids = CountIds {
            command: u64::MAX - 1,
        };
        assert_eq!(ids.command().unwrap().value(), u64::MAX);
        assert_eq!(ids.command().unwrap_err().class, FailureClass::IdExhausted);
        assert_eq!(ids.command().unwrap_err().class, FailureClass::IdExhausted);
    }

    #[test]
    fn command_exhaustion_seals_session_once() {
        let mut session = CountSession::new(42, FakeCountBackend::new());
        session.ids.command = u64::MAX;
        assert!(
            session
                .open_window(10, 20, Instant::now() + Duration::from_secs(1))
                .is_err()
        );
        assert!(session.is_closed());
        let id = session.terminal_id().unwrap();
        let view = session.salvage_view(id);
        assert_eq!(
            view.runtime_failure.unwrap().class,
            FailureClass::IdExhausted
        );
        assert_eq!(
            session
                .terminal(CloseRequest {
                    started_at: Instant::now(),
                    grace: Duration::from_secs(20),
                    reason: CloseReason::Failure
                })
                .receipt
                .terminal_id,
            id
        );
    }

    #[test]
    fn admitted_spec_mirrors_dropfail_percpu_array() {
        // ADMITTED is drained exactly like DROPFAIL (per-CPU u64
        // array): the loader specs must agree on type and dims or
        // the live drain misreads the map. RED: ADMITTED unnamed.
        let spec = |name: &str| {
            crate::loader::COUNT_MAPS
                .iter()
                .find(|m| m.name == name)
                .unwrap_or_else(|| panic!("COUNT_MAPS names {name}"))
        };
        let drops = spec("DROPFAIL");
        let adm = spec("ADMITTED");
        assert_eq!(adm.map_type, drops.map_type);
        assert_eq!(adm.key_size, drops.key_size);
        assert_eq!(adm.value_size, drops.value_size);
        assert_eq!(adm.max_entries, 1);
    }

    #[test]
    fn lat_spec_is_percpu_array_16() {
        // LATC is drained like DROPFAIL (per-CPU u64 array) with
        // exactly LAT_BUCKETS cells. RED: LATC unnamed.
        let spec = crate::loader::COUNT_MAPS
            .iter()
            .find(|m| m.name == "LATC")
            .expect("COUNT_MAPS names LATC");
        let drops = crate::loader::COUNT_MAPS
            .iter()
            .find(|m| m.name == "DROPFAIL")
            .expect("COUNT_MAPS names DROPFAIL");
        assert_eq!(spec.map_type, drops.map_type);
        assert_eq!(spec.key_size, drops.key_size);
        assert_eq!(spec.value_size, drops.value_size);
        assert_eq!(spec.max_entries, 16);
    }

    #[test]
    fn loss_merge_sums_and_keeps_gaps() {
        let mut store = Vec::new();
        let loss = |v| {
            counter(
                "count.unattributed",
                CounterKind::Loss,
                CounterUnits::Calls,
                CounterSource::Drain,
                v,
            )
        };
        merge_counter(&mut store, loss(3));
        merge_counter(&mut store, loss(0));
        assert_eq!(store.len(), 1);
        assert_eq!(store[0].value, 3);
        // A clean delta never erases the earlier gap.
        merge_counter(&mut store, loss(4));
        assert_eq!(store[0].value, 7);
        // A different source is a different counter.
        merge_counter(
            &mut store,
            counter(
                "count.unattributed",
                CounterKind::Loss,
                CounterUnits::Calls,
                CounterSource::KernelMap,
                1,
            ),
        );
        assert_eq!(store.len(), 2);
    }
}
