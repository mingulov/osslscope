// SPDX-License-Identifier: GPL-3.0-or-later
//! Owned, synchronous public-ABI session. No legacy discovery/session graph.
use super::{
    wire::{self, contract as c},
    *,
};
use crate::{inventory, loader};
use aya::maps::{
    Array, HashMap as BpfMap, Map, MapData, PerCpuArray, PerCpuHashMap, PerCpuValues, RingBuf,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::File,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    time::{Duration, Instant},
};

// The shared integer-only C layouts have no implicit padding.
unsafe impl aya::Pod for c::Config {}
unsafe impl aya::Pod for c::Member {}
unsafe impl aya::Pod for c::Namespace {}
unsafe impl aya::Pod for c::Range {}
unsafe impl aya::Pod for c::RangeKey {}
unsafe impl aya::Pod for c::ApiAggregate {}
unsafe impl aya::Pod for c::ThreadKey {}
unsafe impl aya::Pod for c::Thread {}
unsafe impl aya::Pod for c::ApiThreadKey {}
#[derive(Default)]
pub struct ObservationBatch {
    pub facts: Vec<ObservationFact>,
    pub gaps: Vec<ObservationGap>,
    /// Shaped backing-refusal strings drained from the acquisition
    /// budget (R06 vocabulary, caller-rendered). The session merges
    /// these into its attach diagnostics at projection.
    pub refusals: Vec<String>,
    pub learned_sites: Vec<VerifiedSiteCandidate>,
    pub static_candidates: Vec<VerifiedStaticCandidate>,
    pub api_activity: Vec<ProcessApiActivity>,
    /// Internal provider reacquisition marker for stronger inventory authority.
    /// Count may bridge only after independently revalidating retained custody;
    /// this is not a claim that process or backing code changed identity.
    pub refreshed_processes: Vec<u32>,
    /// 6A exec witnesses (session-detected exe-stamp flips, §1.4): pids
    /// whose image epoch sealed this reconcile. The coordinator seals
    /// the segment and re-admits the post-exec image as a fresh
    /// candidate; the session never re-adds these pids itself
    /// (`exec_sealed`).
    pub exec_witnesses: Vec<u32>,
    /// 6A additive module refreshes (§1.2 late modules): pids whose
    /// binding refreshed over added-only rows this reconcile
    /// (distinct from `refreshed_processes`, which also covers
    /// authority upgrades). The coordinator emits the
    /// `additive_module_refresh` transition detail.
    pub additive_refreshes: Vec<u32>,
}
/// One cumulative final API ledger, scoped to an observed incarnation.
#[derive(Clone)]
pub struct ProcessApiActivity {
    pub pid: u32,
    pub starttime: u64,
    pub row: crate::api_activity::ApiActivityRow,
}
impl ObservationBatch {
    fn gap(&mut self, g: ObservationGap) {
        if !self.gaps.contains(&g) {
            self.gaps.push(g)
        }
    }
}
/// A verified historical advertisement, never an executed asset. No serde/Debug.
#[derive(Clone)]
pub struct VerifiedSiteCandidate {
    site: VerifiedSite,
    pid: u32,
    starttime: u64,
    generation: u64,
    advertisers: Vec<ObjectHash>,
    operation: Operation,
    numeric_operation: u32,
    dynamic_algorithm: super::static_tables::DynamicAlgorithmId,
    observed_ns: u64,
    algorithm: AlgorithmId,
    alias_quality: AliasQuality,
    function: FunctionIdentity,
}
impl VerifiedSiteCandidate {
    pub fn site(&self) -> &VerifiedSite {
        &self.site
    }
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn starttime(&self) -> u64 {
        self.starttime
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn advertiser_candidates(&self) -> &[ObjectHash] {
        &self.advertisers
    }
    pub fn operation(&self) -> Operation {
        self.operation
    }
    pub fn numeric_operation(&self) -> u32 {
        self.numeric_operation
    }
    pub fn dynamic_algorithm(&self) -> super::static_tables::DynamicAlgorithmId {
        self.dynamic_algorithm
    }
    pub fn observed_ns(&self) -> u64 {
        self.observed_ns
    }
    pub fn algorithm(&self) -> AlgorithmId {
        self.algorithm
    }
    pub fn alias_quality(&self) -> AliasQuality {
        self.alias_quality
    }
    pub fn function(&self) -> FunctionIdentity {
        self.function
    }
}
type RoleSite = [u64; 5];
#[derive(Default)]
struct Roles(BTreeMap<RoleSite, Option<u32>>);
impl Roles {
    fn observe(
        &mut self,
        site: RoleSite,
        api: u32,
        budget: &ObservationBudget,
    ) -> Result<bool, ObservationGap> {
        if let Some(role) = self.0.get_mut(&site) {
            if *role == Some(api) {
                return Ok(true);
            }
            *role = None;
            return Ok(false);
        }
        if self.0.len() >= budget.limits.max_learned_sites {
            return Err(ObservationGap::SiteLimit);
        }
        budget.state(96)?;
        self.0.insert(site, Some(api));
        Ok(true)
    }
    fn accepts(&self, site: RoleSite, api: u32) -> bool {
        self.0.get(&site) == Some(&Some(api))
    }
}
fn role_site(pid: u32, starttime: u64, site: &VerifiedSite) -> RoleSite {
    [
        pid as u64,
        starttime,
        site.native_device(),
        site.inode(),
        site.file_offset(),
    ]
}
fn validate_candidate_member(member: &c::Member, generation: u64) -> Result<(), ObservationGap> {
    // Epoch is the advertisement lease. Its invalidation does not invalidate
    // the verified process/code binding of a later current return.
    if member.generation != generation || !matches!(member.epoch, 0 | 1) {
        Err(ObservationGap::MembershipUnknown)
    } else {
        Ok(())
    }
}
fn mapped_member(
    previous: Option<c::Member>,
    generation: u64,
    ranges: usize,
) -> Result<c::Member, ObservationGap> {
    if let Some(member) = &previous {
        validate_candidate_member(member, generation)?;
    }
    Ok(c::Member {
        generation,
        epoch: previous.map_or(1, |member| member.epoch),
        range_count: ranges as u32,
        reserved: 0,
    })
}
fn reconcile_retirement_gap(
    current_starttime: Option<u64>,
    expected_starttime: u64,
    revalidate: impl FnOnce() -> Result<(), ObservationGap>,
) -> Option<ObservationGap> {
    match current_starttime {
        None => Some(ObservationGap::MembershipUnknown),
        Some(current) if current != expected_starttime => Some(ObservationGap::ProcessChanged),
        Some(_) => revalidate().err(),
    }
}
fn validate_then_arm(
    mut validate: impl FnMut() -> Result<(), ObservationGap>,
    arm: impl FnOnce() -> Result<(), ObservationGap>,
) -> Result<(), ObservationGap> {
    validate()?;
    arm()?;
    validate()
}
fn retain_and_arm(
    startup: &mut BTreeMap<u32, Vec<Attachment>>,
    pid: u32,
    attachment: Attachment,
    arm: impl FnOnce(&Attachment) -> Result<(), ObservationGap>,
) -> Result<(), ObservationGap> {
    let rows = startup.entry(pid).or_default();
    rows.push(attachment);
    arm(rows.last().unwrap())
}
fn retain_typed_startup(
    sites: Vec<super::objects::StartupTypedSite>,
    budget: &ObservationBudget,
    retained: &mut Vec<super::objects::TypedPublicSite>,
    deadline: Instant,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<(), ObservationGap> {
    let mut first_gap = None;
    for site in sites {
        if cancel.load(std::sync::atomic::Ordering::Relaxed) || Instant::now() >= deadline {
            return Err(ObservationGap::SnapshotLag);
        }
        if retained.len() >= budget.limits.max_learned_sites {
            return Err(ObservationGap::SiteLimit);
        }
        match site.prepare(budget) {
            Ok(prepared) => retained.push(prepared),
            Err(gap) => {
                first_gap.get_or_insert(gap);
            }
        }
    }
    first_gap.map_or(Ok(()), Err)
}
/// Pure object ABI admission, shared with ordinary command preflight.
pub(crate) fn prepare_object(object: &[u8]) -> Result<loader::Prepared, ObservationGap> {
    let programs: Vec<_> = [
        loader::ProgSpec::uprobe("observation_entry"),
        loader::ProgSpec::uretprobe("observation_return"),
        loader::ProgSpec::uprobe("typed_entry"),
        loader::ProgSpec::uretprobe("typed_return"),
    ]
    .into_iter()
    .chain(loader::SOURCE_REGISTRATION_PROGS)
    .chain(loader::LIFECYCLE_PROGS)
    .collect();
    let maps: Vec<_> = specs()
        .into_iter()
        .chain(super::source_owner::MAPS)
        .collect();
    loader::prepare(object, &maps, &programs).map_err(|_| ObservationGap::InvalidObject)
}
/// Preserve the sole mandatory legacy load while retaining the fully checked
/// source roots as unloaded input. Optional maps are acquired only after legacy
/// startup custody; no tracing root can reach the generic uprobe load adapter.
///
/// This is the single legacy/source partition rule: production session
/// startup and both native controls reach the gated-loadable legacy half
/// only through this split. No second copy of the predicate may exist.
pub(crate) fn split_source_preparation(
    prepared: loader::Prepared,
) -> (loader::Prepared, loader::Prepared) {
    let (legacy, source) = prepared
        .progs
        .into_iter()
        .partition(|p| matches!(p.name.as_str(), "observation_entry" | "observation_return"));
    let (source_maps, legacy_maps) = prepared.maps.into_iter().partition(|m| {
        super::source_owner::MAPS
            .iter()
            .any(|spec| spec.name == m.name)
    });
    (
        loader::Prepared {
            progs: legacy,
            maps: legacy_maps,
        },
        loader::Prepared {
            progs: source,
            maps: source_maps,
        },
    )
}
/// Shared legacy preparation for the native gated-load consumers: the
/// unsplit full preparation also carries source and lifecycle roots, which
/// `load_gated` refuses, so gated consumers load exactly this half.
/// Production startup reaches the same shared split directly because it
/// also retains the source half.
#[cfg(test)]
pub(crate) fn prepare_legacy_object(object: &[u8]) -> Result<loader::Prepared, ObservationGap> {
    Ok(split_source_preparation(prepare_object(object)?).0)
}
struct Attachment {
    links: Vec<OwnedFd>,
    site: VerifiedSite,
    cookie: u64,
    api: u32,
    advertisers: Vec<ObjectHash>,
    generation: u64,
    object: u64,
    original: Option<VerifiedSite>,
    historical: bool,
}
impl Attachment {
    fn adopt_site(&mut self, mapped: VerifiedSite) -> Result<(), ObservationGap> {
        if self.historical {
            return Err(ObservationGap::Invalidated);
        }
        self.site.revalidate_object()?;
        mapped.revalidate_object()?;
        if !mapped.matches_retained(&self.site)? {
            return Err(ObservationGap::ObjectChanged);
        }
        self.original = Some(std::mem::replace(&mut self.site, mapped));
        Ok(())
    }
}
/// Legacy prearm link plan. `Create` attaches the legacy producer links
/// immediately; `Reserve` mints the cookie and all configuration but creates
/// no links, leaving each attachment's required pair to the
/// source-acquisition path.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum PrearmLinks {
    Create,
    /// Native source qualification only: production never reserves.
    #[allow(dead_code)]
    Reserve,
}
#[cfg(test)]
thread_local! { static EXPIRE_STATIC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
/// First cookie of the typed range; see `next_typed_cookie`.
pub(crate) const TYPED_COOKIE_FIRST: u64 = 1 << 31;
/// One past the last typed cookie (u32 range end, exclusive).
pub(crate) const TYPED_COOKIE_END: u64 = 1 << 32;
/// Session record for one admitted typed site: the physical identity the
/// counter observes plus the attribution IDs the kernel emits. The
/// finalizer joins these records against strict SITE_BIND reads.
#[derive(Debug, Clone)]
pub(crate) struct TypedSiteRecord {
    pub site_id: u64,
    pub role_id: u32,
    #[allow(
        dead_code,
        reason = "record identity for the finalizer SITE_BIND join (native stage)"
    )]
    pub pid: u32,
    pub device: u64,
    pub inode: u64,
    pub offset: u64,
    pub object: crate::evidence::ObjectId,
    pub object_id: u64,
    pub source_epoch: u64,
    #[allow(
        dead_code,
        reason = "record identity for the finalizer SITE_BIND join (native stage)"
    )]
    pub process_incarnation: u64,
    #[allow(
        dead_code,
        reason = "record identity for the finalizer SITE_BIND join (native stage)"
    )]
    pub image_epoch: u64,
}
struct Target {
    process: VerifiedProcess,
    starttime: u64,
    generation: u64,
    attachments: Vec<Attachment>,
    ranges: usize,
    ready: bool,
}
pub struct ProviderSession {
    gate: crate::writer_gate::WriterGate,
    final_drain: bool,
    final_refusals: BTreeMap<u32, ObservationGap>,
    final_terminal: BTreeSet<u32>,
    loaded: loader::GatedLoaded,
    // A validated kernel layout is only a prerequisite. No source authority is
    // published without the separately owned anchor and actual registrations.
    _source_kernel: Result<loader::SourceKernel, ObservationGap>,
    // Unloaded roots retain symbolic map fixups and validated finite kernel
    // patches until the source owner adopts them during typed preparation.
    source_prepared: loader::Prepared,
    source_owner: Option<super::source_owner::SourceOwner>,
    // Prearmed source preparation is noncertifying until actual source links,
    // post-adoption readiness and target-domain guards are established.
    typed_startup: Vec<super::objects::TypedPublicSite>,
    events: RingBuf<MapData>,
    config: BpfMap<MapData, u64, c::Config>,
    members: BpfMap<MapData, u32, c::Member>,
    /// 6A thread-row cleanup handles (§1.2): host-side removal of a
    /// confirmed-dead tid's pairing rows (THREADS + API_THREADS).
    /// PENDING frames are left to the BPF bound (the rule removes
    /// the tid row only).
    threads: BpfMap<MapData, c::ThreadKey, c::Thread>,
    api_threads: BpfMap<MapData, c::ApiThreadKey, c::Thread>,
    ranges: BpfMap<MapData, c::RangeKey, c::Range>,
    loss: PerCpuArray<MapData, u64>,
    api_totals: PerCpuHashMap<MapData, u64, c::ApiAggregate>,
    api_window: Array<MapData, c::Range>,
    api_owners: BTreeMap<u64, (u32, u64, u32)>,
    startup: BTreeMap<u32, Vec<Attachment>>,
    targets: BTreeMap<u32, Target>,
    // Replaces (never adds to) an admitted target during metadata-only refresh.
    // The shared process lease still bounds this map and any Count site owners.
    refreshing: BTreeMap<u32, objects::ProcessIncarnation>,
    /// 6A exec-sealed pids (§1.4): image retired by an exe-stamp flip
    /// this session already reported via `exec_witnesses`. The
    /// coordinator owns the post-exec re-admission (new segment);
    /// the session never re-adds these pids itself. Never cleared:
    /// the session is dropped at segment seal.
    exec_sealed: BTreeSet<u32>,
    /// 6A kernel-edge fences (§1.8): pid → edge instant in the
    /// producer timestamp domain. Fenced records with
    /// `monotonic_ns >= edge` are dropped whole at `consume` and
    /// conserved in `fence_withheld` (never bound, never
    /// projected). One-way pre-seal state; earliest edge wins.
    fenced: BTreeMap<u32, u64>,
    /// 6A provider-plane fence conservation: ring records dropped
    /// whole by the `fenced` timestamp rule. Read once at segment
    /// seal into the member loss ledger.
    fence_withheld: u64,
    /// 6A bounded uncertainty windows (§§1.6, 2.4): pids whose
    /// provider fence clears after the next CLEAN backlog drain.
    /// A fenced-then-evicted target (cgroup move, exclusion,
    /// failed-tick suspend) re-adds through the refresh handoff;
    /// the re-add flags the pid here (the fence stays armed for
    /// the backlog: uncertain-span records withhold as conserved
    /// loss, certain pre-edge records bind), and the drain end
    /// clears the fence so post-recovery records flow again.
    /// Pre-seal fences (exec/exit/reuse) never flag: the member
    /// seals instead of resuming.
    unfence_after_drain: BTreeSet<u32>,
    roles: Roles,
    aliases: super::assembly::Sequences,
    budget: ObservationBudget,
    /// State spend at the end of session setup (object + maps + gate).
    /// Retire-time release returns here when no attachment remains live,
    /// so a retire/re-add cycle can re-acquire instead of starving on
    /// the first acquisition's permanent spend.
    setup_state_spent: usize,
    setup_reads_spent: u64,
    next_cookie: u64,
    /// First typed cookie. Cookies partition the (cookie, process, image)
    /// bind space across both programs: the counter mints u32
    /// `[1, 4096]`, typed sites mint `[2^31, 2^32)` (u32-fitting so the
    /// counter can pin the same cookie for the same site), legacy session
    /// cookies skip the typed range. Exhaustion refuses, never wraps.
    next_typed_cookie: u64,
    next_site_id: u64,
    next_object_id: u64,
    typed_sites: BTreeMap<u64, TypedSiteRecord>,
    typed_pins: BTreeMap<(u64, u64, u64), u64>,
    object_ids: BTreeMap<String, u64>,
    next_generation: u64,
    emitted: usize,
    learned: BTreeSet<(u32, u64, u64, u64, u64)>,
    last_loss: [u64; 8],
    /// 6A cumulative per-index loss deltas over the session lifetime.
    /// Same index order as the LOSS map poll below (QueueLoss,
    /// PendingLimit, DepthLimit, UnpairedReturn, TargetReadFailed,
    /// RelocationRefused, DispatchPartial, NamespaceChanged). The
    /// coordinator attributes these per incarnation; only deltas ever
    /// accumulate here (map counters are monotonic).
    loss_totals: [u64; 8],
    /// 6A successful-read receipts (§4.1 `[S,T+1)` rule): per-lane
    /// read sequence, bumped on every SUCCESSFUL per-lane LOSS map
    /// read (failed reads gap instead and leave the sequence — the
    /// coordinator retains the last successful baseline through
    /// failures rather than starting the next interval too late).
    loss_read_seq: [u64; 8],
    last_drain: Instant,
    closed: bool,
}
fn terminal_originals(
    startup: &[Attachment],
    target: Option<&Target>,
    record: Option<&inventory::ProcessRecord>,
) -> Result<bool, ObservationGap> {
    let mut found = false;
    let mut terminal = true;
    for a in startup
        .iter()
        .chain(target.into_iter().flat_map(|t| &t.attachments))
    {
        if let Some(original) = a
            .original
            .as_ref()
            .or_else(|| a.site.is_startup().then_some(&a.site))
        {
            found = true;
            terminal &= original.revalidate_queued_record(record)?;
        }
    }
    Ok(found && terminal)
}
fn rejects_history(gap: ObservationGap) -> bool {
    matches!(
        gap,
        ObservationGap::Invalidated
            | ObservationGap::AmbiguousSite
            | ObservationGap::ObjectChanged
            | ObservationGap::NamespaceChanged
            | ObservationGap::ProcessChanged
    )
}
fn recorded_refusal(process: &VerifiedProcess) -> Option<ObservationGap> {
    process.gaps().into_iter().find(|&gap| rejects_history(gap))
}
fn cold_attach_error(
    gap: ObservationGap,
    batch: &mut ObservationBatch,
) -> Result<(), ObservationGap> {
    batch.gap(gap);
    if rejects_history(gap) {
        Err(gap)
    } else {
        Ok(())
    }
}
fn process_retirement_gap(process: &VerifiedProcess) -> Option<ObservationGap> {
    recorded_refusal(process).or_else(|| process.revalidate().err())
}
/// Always-fresh variant for one-shot terminal decisions (final drain):
/// the hot-path memo must not carry a stale "alive" verdict into a
/// terminal-authority ruling.
fn process_retirement_gap_fresh(process: &VerifiedProcess) -> Option<ObservationGap> {
    recorded_refusal(process).or_else(|| process.revalidate_fresh().err())
}
fn candidate_validation_result(
    process: &VerifiedProcess,
    result: Result<(), ObservationGap>,
) -> Result<(), ObservationGap> {
    if let Err(gap) = result {
        if rejects_history(gap) {
            process.remember_refusal(gap);
        }
    }
    result
}
/// Shared retirement boundary for reconcile/acquisition failures and drain.
/// The descriptor/map operation is supplied by the session; source ownership
/// and pending assembler state have one production transition.
fn retire_source_owners(
    (startup, targets): (
        &mut BTreeMap<u32, Vec<Attachment>>,
        &mut BTreeMap<u32, Target>,
    ),
    aliases: &mut super::assembly::Sequences,
    pid: u32,
    record: Option<&inventory::ProcessRecord>,
    gap: ObservationGap,
    b: &mut ObservationBatch,
    disarm: impl FnOnce(&[Attachment], Option<&Target>) -> Result<(), ObservationGap>,
) -> bool {
    let rows: &[Attachment] = startup.get(&pid).map_or(&[], Vec::as_slice);
    // A resolver can record an earlier confirmed failure before a subsequent
    // call returns mere unavailability. Both forms retain refusal provenance.
    let recorded = targets
        .get(&pid)
        .and_then(|target| recorded_refusal(&target.process));
    if let Some(recorded) = recorded {
        b.gap(recorded);
    }
    let preserve = if rejects_history(gap) || recorded.is_some() {
        false
    } else {
        match terminal_originals(rows, targets.get(&pid), record) {
            Ok(terminal) => terminal,
            Err(gap) => {
                b.gap(gap);
                false
            }
        }
    };
    if let Err(gap) = disarm(rows, targets.get(&pid)) {
        b.gap(gap);
    }
    b.learned_sites.retain(|site| site.pid != pid);
    b.static_candidates.retain(|site| site.pid() != pid);
    if preserve {
        if let Some(target) = targets.remove(&pid) {
            for mut a in target.attachments {
                // Close links while both mapped and original file owners are
                // alive. Only original source identity survives the transition.
                a.links.clear();
                if let Some(original) = a.original.take() {
                    a.site = original;
                }
                if a.site.is_startup() {
                    startup.entry(pid).or_default().push(a);
                }
            }
        }
        for a in startup.get_mut(&pid).into_iter().flatten() {
            a.links.clear();
            a.historical = true;
        }
        b.gap(ObservationGap::ProcessUnavailable);
        b.gap(ObservationGap::IntervalUnknown);
        b.gap(ObservationGap::FirstQueryUnknown);
        b.gap(ObservationGap::SamplingPartial);
    } else {
        aliases.retire(pid);
        if let Some(rows) = startup.remove(&pid) {
            for a in rows {
                drop(a.links);
            }
        }
        if let Some(target) = targets.remove(&pid) {
            for a in target.attachments {
                drop(a.links);
            }
        }
    }
    preserve
}
fn final_source_refusals(
    targets: &BTreeMap<u32, Target>,
    startup: &BTreeMap<u32, Vec<Attachment>>,
    b: &mut ObservationBatch,
    deadline: Instant,
    terminal_pids: &mut BTreeSet<u32>,
) -> BTreeMap<u32, ObservationGap> {
    let mut refusals = BTreeMap::new();
    // Retain every immutable owner. A terminal original may authorize
    // queued records, but ordinary unavailability cannot become history.
    for (&pid, target) in targets {
        if Instant::now() >= deadline {
            refusals.insert(pid, ObservationGap::DrainOverrun);
            b.gap(ObservationGap::DrainOverrun);
            continue;
        }
        if let Some(gap) = process_retirement_gap_fresh(&target.process) {
            let rows = startup.get(&pid).map_or(&[][..], Vec::as_slice);
            let terminal = !rejects_history(gap)
                && recorded_refusal(&target.process).is_none()
                && terminal_originals(rows, Some(target), None) == Ok(true);
            if !terminal {
                refusals.insert(pid, gap);
            } else {
                terminal_pids.insert(pid);
            }
            b.gap(gap);
        }
    }
    for (&pid, rows) in startup {
        for attachment in rows {
            if Instant::now() >= deadline {
                refusals.insert(pid, ObservationGap::DrainOverrun);
                b.gap(ObservationGap::DrainOverrun);
                break;
            }
            if let Err(gap) = attachment.site.revalidate_queued() {
                refusals.insert(pid, gap);
                b.gap(gap);
            }
        }
    }
    refusals
}
struct RecordBinding<'a> {
    attachment: &'a Attachment,
    starttime: u64,
    process: Option<&'a VerifiedProcess>,
}
fn record_binding<'a>(
    targets: &'a BTreeMap<u32, Target>,
    startup: &'a BTreeMap<u32, Vec<Attachment>>,
    r: &c::Record,
) -> Result<Option<RecordBinding<'a>>, ObservationGap> {
    if let Some(target) = targets.get(&r.pid).filter(|t| t.generation == r.generation) {
        if let Some(attachment) = target
            .attachments
            .iter()
            .find(|a| a.cookie == r.cookie && a.api == r.api && a.generation == r.generation)
        {
            return Ok(Some(RecordBinding {
                attachment,
                starttime: target.starttime,
                process: (!attachment.historical).then_some(&target.process),
            }));
        }
    }
    // During partial first adoption some physical pairs are already mapped and
    // others are still retained startup authorities. Never hide either half.
    if let Some(rows) = startup.get(&r.pid) {
        if let Some(attachment) = rows.iter().find(|a| {
            a.cookie == r.cookie
                && a.api == r.api
                && a.generation == r.generation
                && a.site.pid() == r.pid
        }) {
            return Ok(Some(RecordBinding {
                attachment,
                starttime: attachment.site.starttime(),
                process: None,
            }));
        }
        if rows.iter().any(|a| a.generation == r.generation) {
            return Err(ObservationGap::InvalidWire);
        }
    }
    if targets
        .get(&r.pid)
        .is_some_and(|t| t.generation == r.generation)
    {
        return Err(ObservationGap::InvalidWire);
    }
    Ok(None)
}
fn final_record_binding<'a>(
    targets: &'a BTreeMap<u32, Target>,
    startup: &'a BTreeMap<u32, Vec<Attachment>>,
    refusals: &BTreeMap<u32, ObservationGap>,
    terminal_pids: &BTreeSet<u32>,
    r: &c::Record,
) -> Result<Option<RecordBinding<'a>>, ObservationGap> {
    if let Some(&gap) = refusals.get(&r.pid) {
        return Err(gap);
    }
    let Some(mut binding) = record_binding(targets, startup, r)? else {
        return Ok(None);
    };
    if terminal_pids.contains(&r.pid) {
        // Retention is not authority. Each queued cookie must carry its own
        // independently validated original; a sibling's original cannot help.
        let a = binding.attachment;
        let original = a
            .original
            .as_ref()
            .or_else(|| a.site.is_startup().then_some(&a.site))
            .ok_or(ObservationGap::ProcessUnavailable)?;
        if !original.revalidate_queued_record(None)? {
            return Err(ObservationGap::ProcessUnavailable);
        }
        binding.process = None;
    }
    Ok(Some(binding))
}
fn map_data(loaded: &loader::Loaded, name: &str) -> Result<MapData, ObservationGap> {
    MapData::from_fd(
        loaded
            .maps
            .get(name)
            .ok_or(ObservationGap::InvalidObject)?
            .try_clone()
            .map_err(|_| ObservationGap::BpfUnavailable)?,
    )
    .map_err(|_| ObservationGap::BpfUnavailable)
}
fn map(loaded: &loader::Loaded, name: &str) -> Result<Map, ObservationGap> {
    Map::from_map_data(map_data(loaded, name)?).map_err(|_| ObservationGap::InvalidObject)
}
pub(crate) fn specs() -> Vec<loader::MapSpec> {
    let shapes = [
        ("ADMIT", 12, 4, 4, 1),
        ("EVENTS", 27, 0, 0, 1 << 20),
        ("CONFIG", 1, 8, 24, 1024),
        ("MEMBERS", 1, 4, 24, 64),
        ("NAMESPACE", 2, 4, 16, 1),
        ("RANGES", 1, 8, 16, 8192),
        ("THREADS", 1, 16, 16, 4096),
        ("PENDING", 1, 24, 56, 4096),
        ("LOSS", 6, 4, 8, 8),
        ("API_TOTALS", 5, 8, 72, 1024),
        ("API_THREADS", 1, 24, 16, 4096),
        ("API_WINDOW", 2, 4, 16, 1),
        ("ALG_CLASS", 1, 8, 42, 1024),
        ("TRIP_CLASS", 1, 8, 22, 64),
    ];
    shapes
        .into_iter()
        .map(
            |(name, map_type, key_size, value_size, max_entries)| loader::MapSpec {
                name,
                map_type,
                key_size,
                value_size,
                max_entries,
                flags: 0,
            },
        )
        .chain(super::source_owner::CONTROL_MAPS)
        .collect()
}
fn reserve_map_capacity(
    budget: &ObservationBudget,
    maps: &[loader::MapSpecLite],
    possible_cpus: usize,
) -> Result<(), ObservationGap> {
    let map_capacity = maps
        .iter()
        // Shared ADMIT/inner-token owner has its own reservation; descriptors
        // are charged separately. This call does not allocate another gate.
        .filter(|m| m.name != "ADMIT")
        .try_fold(0usize, |bytes, m| {
            bytes.checked_add(m.reservation_bytes(possible_cpus)?)
        })
        .ok_or(ObservationGap::StateLimit)?;
    // This component ceiling is independent of the outer watch pool lease,
    // which already reserves these same map capacities before session setup.
    budget.state(map_capacity)
}

impl ProviderSession {
    /// Validate enclosing process and current membership, preserving the separate
    /// D3 membership epoch and mapped-object generation domains. This proves
    /// current process/code binding, not renewal of a borrowed table lease;
    /// the controller owns invalidation, batch discard and fresh-return rearm.
    pub fn revalidate_candidate(
        &self,
        candidate: &VerifiedSiteCandidate,
    ) -> Result<(), ObservationGap> {
        if self.closed {
            return Err(ObservationGap::Invalidated);
        }
        let target = self
            .targets
            .get(&candidate.pid)
            .ok_or(ObservationGap::MembershipUnknown)?;
        if target.starttime != candidate.starttime || target.generation != candidate.generation {
            return Err(ObservationGap::ProcessChanged);
        }
        if let Some(gap) = recorded_refusal(&target.process) {
            return Err(gap);
        }
        let member = self
            .members
            .get(&candidate.pid, 0)
            .map_err(|_| ObservationGap::MembershipUnknown)?;
        validate_candidate_member(&member, target.generation)?;
        candidate_validation_result(
            &target.process,
            target
                .process
                .revalidate()
                .and_then(|()| candidate.site.revalidate_object()),
        )
    }

    pub fn open(limits: ObservationLimits, object: &[u8]) -> Result<Self, ObservationGap> {
        Self::open_budgeted(ObservationBudget::new(limits), object)
    }
    pub(crate) fn open_budgeted(
        budget: ObservationBudget,
        object: &[u8],
    ) -> Result<Self, ObservationGap> {
        prepare_object(object)?;
        budget.state(crate::writer_gate::RESERVATION_BYTES)?;
        let pool = budget.memory.clone().unwrap_or_else(|| {
            crate::observation_memory::MemoryPool::new(budget.limits.max_state_bytes)
        });
        let gate = crate::writer_gate::WriterGate::create(&pool)
            .map_err(|_| ObservationGap::BpfUnavailable)?;
        let session = Self::open_gated(budget, object, gate.clone())?;
        gate.open().map_err(|_| ObservationGap::BpfUnavailable)?;
        Ok(session)
    }
    pub(crate) fn open_gated(
        budget: ObservationBudget,
        object: &[u8],
        gate: crate::writer_gate::WriterGate,
    ) -> Result<Self, ObservationGap> {
        budget.state(crate::writer_gate::INJECTION_BYTES)?;
        let limits = &budget.limits;
        let max = ObservationLimits::default();
        if object.len() > 16 << 20 {
            return Err(ObservationGap::ReadLimit);
        }
        // Hard producer capacities; smaller caller limits are honored before work.
        if limits.max_processes > max.max_processes
            || limits.max_objects > max.max_objects
            || limits.max_links > max.max_links
            || limits.max_pending_calls > max.max_pending_calls
            || limits.max_depth != 8
            || limits.max_learned_sites > max.max_learned_sites
            || limits.ring_bytes != max.ring_bytes
        {
            return Err(ObservationGap::StateLimit);
        }
        budget.state(
            object
                .len()
                .checked_mul(4)
                .ok_or(ObservationGap::StateLimit)?,
        )?;
        let (mut prepared, mut source_prepared) = split_source_preparation(prepare_object(object)?);
        // Retain hard bounds while honoring lower pending/process limits in actual maps.
        for m in &mut prepared.maps {
            if matches!(m.name.as_str(), "PENDING" | "THREADS" | "API_THREADS") {
                m.max_entries = budget.limits.max_pending_calls.max(1) as u32;
            }
            if m.name == "MEMBERS" {
                m.max_entries = budget.limits.max_processes.max(1) as u32;
            }
        }
        let possible_cpus = aya::util::nr_cpus().map_err(|_| ObservationGap::StateLimit)?;
        reserve_map_capacity(&budget, &prepared.maps, possible_cpus)?;
        let source_kernel = loader::SourceKernel::read(&budget).and_then(|kernel| {
            kernel.patch(&mut source_prepared)?;
            Ok(kernel)
        });
        budget.checkpoint()?;
        let loaded =
            loader::load_gated(&prepared, &gate).map_err(|_| ObservationGap::BpfUnavailable)?;
        super::source_owner::initialize_controls(&loaded, &gate, limits.max_pending_calls)?;
        crate::discovery::initialize_classifier_maps(
            &loaded.maps,
            crate::discovery::ClassifierRole::Harvest,
        )
        .map_err(|_| ObservationGap::ClassifierFailed)?;
        let ns = std::fs::File::open("/proc/self/ns/pid")
            .and_then(|f| f.metadata())
            .map_err(|_| ObservationGap::NamespaceChanged)?;
        let mut namespace = Array::<_, c::Namespace>::try_from(map(&loaded, "NAMESPACE")?)
            .map_err(|_| ObservationGap::InvalidObject)?;
        namespace
            .set(
                0,
                c::Namespace {
                    device: ns.dev(),
                    inode: ns.ino(),
                },
                0,
            )
            .map_err(|_| ObservationGap::NamespaceChanged)?;
        ossl_bpf_sys::map_freeze(loaded.maps["NAMESPACE"].as_raw_fd())
            .map_err(|_| ObservationGap::NamespaceChanged)?;
        let mut api_window = Array::try_from(map(&loaded, "API_WINDOW")?)
            .map_err(|_| ObservationGap::InvalidObject)?;
        api_window
            .set(
                0,
                c::Range {
                    start: 0,
                    end: u64::MAX,
                },
                0,
            )
            .map_err(|_| ObservationGap::BpfUnavailable)?;
        Ok(Self {
            gate,
            final_drain: false,
            final_refusals: BTreeMap::new(),
            final_terminal: BTreeSet::new(),
            api_totals: PerCpuHashMap::try_from(map(&loaded, "API_TOTALS")?)
                .map_err(|_| ObservationGap::InvalidObject)?,
            api_window,
            api_owners: BTreeMap::new(),
            startup: BTreeMap::new(),
            events: RingBuf::try_from(map(&loaded, "EVENTS")?)
                .map_err(|_| ObservationGap::BpfUnavailable)?,
            config: BpfMap::try_from(map(&loaded, "CONFIG")?)
                .map_err(|_| ObservationGap::InvalidObject)?,
            members: BpfMap::try_from(map(&loaded, "MEMBERS")?)
                .map_err(|_| ObservationGap::InvalidObject)?,
            threads: BpfMap::try_from(map(&loaded, "THREADS")?)
                .map_err(|_| ObservationGap::InvalidObject)?,
            api_threads: BpfMap::try_from(map(&loaded, "API_THREADS")?)
                .map_err(|_| ObservationGap::InvalidObject)?,
            ranges: BpfMap::try_from(map(&loaded, "RANGES")?)
                .map_err(|_| ObservationGap::InvalidObject)?,
            loss: PerCpuArray::try_from(map(&loaded, "LOSS")?)
                .map_err(|_| ObservationGap::InvalidObject)?,
            loaded,
            _source_kernel: source_kernel,
            source_prepared,
            source_owner: None,
            typed_startup: Vec::new(),
            targets: BTreeMap::new(),
            refreshing: BTreeMap::new(),
            exec_sealed: BTreeSet::new(),
            fenced: BTreeMap::new(),
            fence_withheld: 0,
            unfence_after_drain: BTreeSet::new(),
            roles: Roles::default(),
            aliases: super::assembly::Sequences::default(),
            setup_state_spent: budget.spent_state(),
            setup_reads_spent: budget.spent_reads(),
            budget,
            next_cookie: 1,
            next_typed_cookie: TYPED_COOKIE_FIRST,
            next_site_id: 1,
            next_object_id: 1,
            typed_sites: BTreeMap::new(),
            typed_pins: BTreeMap::new(),
            object_ids: BTreeMap::new(),
            next_generation: 1,
            emitted: 0,
            learned: BTreeSet::new(),
            last_loss: [0; 8],
            loss_totals: [0; 8],
            loss_read_seq: [0; 8],
            last_drain: Instant::now(),
            closed: false,
        })
    }
    fn link_count(&self) -> usize {
        // Live links only: legacy attachment links plus every link the
        // source owner adopted (the acquired legacy pair and all typed
        // pairs): the owner is the sole retainer of acquired links through
        // the final consumers. Reserve-only prearms carry no live links;
        // their planned pairs count via `link_pressure` below.
        self.targets
            .values()
            .map(|t| t.attachments.iter().map(|a| a.links.len()).sum::<usize>())
            .sum::<usize>()
            + self
                .startup
                .values()
                .flatten()
                .map(|a| a.links.len())
                .sum::<usize>()
            + self
                .source_owner
                .as_ref()
                .map(|owner| owner.adopted_link_count())
                .unwrap_or(0)
    }
    /// Planned-link pressure for prearm admission (ER-S2-I1): live links
    /// plus two planned links per reserve-only startup attachment. A
    /// reserve-only prearm mints no producer links yet, but its required
    /// pair is acquired after admission opens, so counting zero per
    /// reservation would let an unbounded order pass a finite `max_links`.
    /// Acquisition checks use live `link_count` plus the explicit planned
    /// order instead (the reserves being converted must not double-count).
    fn link_pressure(&self) -> usize {
        let reserved = self
            .startup
            .values()
            .flatten()
            .filter(|a| a.links.is_empty())
            .count()
            .saturating_mul(2);
        self.link_count().saturating_add(reserved)
    }
    #[allow(clippy::too_many_arguments, reason = "one coherent attach spec")]
    fn attach_pair(
        &mut self,
        pid: u32,
        api: u32,
        site: VerifiedSite,
        advertisers: Vec<ObjectHash>,
        existing: usize,
        generation: u64,
        create_links: bool,
    ) -> Result<Attachment, ObservationGap> {
        if self.final_drain || !self.gate.admitting() {
            return Err(ObservationGap::Invalidated);
        }
        if self
            .link_pressure()
            .saturating_add(existing)
            .saturating_add(2)
            > self.budget.limits.max_links
        {
            return Err(ObservationGap::LinkLimit);
        }
        self.budget.state(512 + advertisers.len() * 96)?;
        site.revalidate_object()?;
        let mut cookie = self.next_cookie;
        // Legacy cookies skip the typed range: both programs share one
        // (cookie, process, image) bind space, and a legacy/typed cookie
        // collision would misattribute counter hits to a typed site.
        if (TYPED_COOKIE_FIRST..TYPED_COOKIE_END).contains(&cookie) {
            cookie = TYPED_COOKIE_END;
        }
        self.next_cookie = cookie.checked_add(1).ok_or(ObservationGap::LinkLimit)?;
        let path = CString::new(format!(
            "/proc/self/fd/{}",
            site.attachment_fd().as_raw_fd()
        ))
        .map_err(|_| ObservationGap::AttachFailed)?;
        (|| {
            // Reserve-only prearm (Enabled source acquisition) mints the
            // cookie and all configuration below but creates no producer
            // links: each attachment's required pair is acquired after
            // admission opens, from its own retained site. The pressure
            // check above counts two planned links per such reservation,
            // so the pair's capacity is reserved at prearm time.
            let links = if create_links {
                paired_links(
                    || {
                        ossl_bpf_sys::link_create_uprobe_multi(
                            self.loaded.progs["observation_entry"].as_raw_fd(),
                            &path,
                            &[site.file_offset()],
                            &[cookie],
                            pid,
                        )
                        .map_err(|_| ObservationGap::AttachFailed)
                    },
                    || {
                        ossl_bpf_sys::link_create_uretprobe_multi(
                            self.loaded.progs["observation_return"].as_raw_fd(),
                            &path,
                            &[site.file_offset()],
                            &[cookie],
                            pid,
                        )
                        .map_err(|_| ObservationGap::AttachFailed)
                    },
                )?
            } else {
                Vec::new()
            };
            site.revalidate_object()?;
            if c::operational_api(api) {
                if self.api_owners.len() >= 1024 {
                    return Err(ObservationGap::LinkLimit);
                }
                self.budget.state(256)?;
                self.api_totals
                    .insert(
                        cookie,
                        PerCpuValues::try_from(vec![
                            c::ApiAggregate::default();
                            aya::util::nr_cpus().map_err(|_| {
                                ObservationGap::BpfUnavailable
                            })?
                        ])
                        .map_err(|_| ObservationGap::BpfUnavailable)?,
                        1,
                    )
                    .map_err(|_| ObservationGap::PendingLimit)?;
                self.api_owners.insert(cookie, (pid, site.starttime(), api));
            }
            Ok(Attachment {
                object: object_id(&site),
                generation,
                original: None,
                historical: false,
                links,
                site,
                cookie,
                api,
                advertisers,
            })
        })()
    }
    fn retire(&mut self, pid: u32, b: &mut ObservationBatch) {
        self.retire_for_gap(pid, None, ObservationGap::Invalidated, b);
    }
    fn retire_for_gap(
        &mut self,
        pid: u32,
        record: Option<&inventory::ProcessRecord>,
        gap: ObservationGap,
        b: &mut ObservationBatch,
    ) -> bool {
        if self.final_drain {
            self.final_refusals.insert(pid, gap);
            b.gap(gap);
            return false;
        }
        self.refreshing.remove(&pid);
        let preserve = retire_source_owners(
            (&mut self.startup, &mut self.targets),
            &mut self.aliases,
            pid,
            record,
            gap,
            b,
            |startup, target| {
                if target.is_none() && !startup.is_empty() && startup.iter().all(|a| a.historical) {
                    return Ok(());
                }
                let mut failed = self.members.remove(&pid).is_err();
                for a in startup
                    .iter()
                    .chain(target.into_iter().flat_map(|t| &t.attachments))
                {
                    failed |= self.config.remove(&a.cookie).is_err();
                }
                if let Some(target) = target {
                    for index in 0..target.ranges {
                        failed |= self
                            .ranges
                            .remove(&c::RangeKey {
                                pid,
                                index: index as u32,
                            })
                            .is_err();
                    }
                }
                if failed {
                    Err(ObservationGap::Invalidated)
                } else {
                    Ok(())
                }
            },
        );
        // Retire-time budget release: when no attachment remains live
        // anywhere, the retired acquisition's permanent spend is dead —
        // return to the setup watermark so a re-add can re-acquire.
        // Guarded to the fully-idle case: live attachments elsewhere
        // still own their spend, and per-target accounting would be
        // needed to release partially (all current CLI flows retire
        // the single live target here).
        if self.targets.is_empty() && self.startup.values().all(|rows| rows.is_empty()) {
            let floor = self.setup_state_spent;
            self.budget.release_state_to_floor(floor);
            let reads_floor = self.setup_reads_spent;
            self.budget.release_reads_to_floor(reads_floor);
        }
        preserve
    }
    pub(crate) fn set_deadline(&self, deadline: Instant) {
        self.budget.set_deadline(deadline);
    }
    pub fn reconcile(&mut self, snapshot: &inventory::Snapshot) -> ObservationBatch {
        self.reconcile_records(&snapshot.processes)
    }
    /// 6A cumulative per-index loss deltas since session setup; index
    /// order matches the LOSS map poll (see `loss_totals`).
    pub(crate) fn loss_totals(&self) -> [u64; 8] {
        self.loss_totals
    }
    /// 6A successful-read receipts (§4.1 `[S,T+1)` rule): per-lane
    /// read sequences, one bump per successful LOSS map read. The
    /// coordinator advances a lane's baseline tick only past ticks
    /// every live session read successfully.
    pub(crate) fn loss_read_seq(&self) -> [u64; 8] {
        self.loss_read_seq
    }
    /// 6A kernel-edge fence (§1.8): stop the BPF plane for `pid`
    /// (members/config/ranges rows removed, best-effort — the
    /// timestamp filter below is the real guard) and arm the
    /// `monotonic_ns >= edge_ns` drop rule at `consume`. The
    /// `Target` object is KEPT (unlike retirement) so the next
    /// reconcile still detects the exe-stamp flip / absence for
    /// the coordinator's seal decision. One-way; earliest edge wins.
    pub(crate) fn fence_target(&mut self, pid: u32, edge_ns: u64) {
        if self.fenced.get(&pid).is_some_and(|&e| e <= edge_ns) {
            return;
        }
        self.fenced.insert(pid, edge_ns);
        let _ = self.members.remove(&pid);
        if let Some(target) = self.targets.get(&pid) {
            for a in &target.attachments {
                let _ = self.config.remove(&a.cookie);
            }
            for index in 0..target.ranges {
                let _ = self.ranges.remove(&c::RangeKey {
                    pid,
                    index: index as u32,
                });
            }
        }
    }
    /// 6A provider-plane fence conservation, taken once at seal.
    pub(crate) fn take_fence_withheld(&mut self) -> u64 {
        std::mem::take(&mut self.fence_withheld)
    }
    /// 6A thread-exit row cleanup (§1.2): remove a
    /// CONFIRMED-DEAD tid's pairing rows (THREADS + API_THREADS,
    /// every generation — stale rows must never be adopted by a
    /// recycled tid number). The TGID member, its rows and its
    /// counts are untouched. Binding safety is the CALLER's
    /// contract: absence-confirming Exit (fresh triple + task-dir
    /// absence + window coverage) — removal itself is best-effort
    /// per key (a row re-created after our removal belongs to a
    /// live recycled tid and self-heals on its next hit; orphaned
    /// PENDING frames stay BPF-bounded and fail visible on cookie
    /// mismatch, never silently).
    pub(crate) fn remove_thread_rows(&mut self, pid: u32, tid: u32) {
        let dead: Vec<c::ThreadKey> = self
            .threads
            .keys()
            .flatten()
            .filter(|key| key.pid == pid && key.tid == tid)
            .collect();
        for key in dead {
            let _ = self.threads.remove(&key);
        }
        let dead_api: Vec<c::ApiThreadKey> = self
            .api_threads
            .keys()
            .flatten()
            .filter(|key| key.thread.pid == pid && key.thread.tid == tid)
            .collect();
        for key in dead_api {
            let _ = self.api_threads.remove(&key);
        }
    }
    /// 6A suspension for retained-unknown members (§2.4): evict the
    /// live target into the `refreshing` handoff WITHOUT gaps or
    /// refusals (this is not a failure — the incarnation is
    /// unchanged, only unwitnessed this tick). The next reconcile
    /// re-adds via the retained incarnation (lease-preserving,
    /// like the transient-budget path) and re-emits static
    /// candidates so the counter re-attaches. Aliases and learned
    /// sites are kept: the incarnation never died. The unknown
    /// window itself is recorded in the coordinator's loss ledger,
    /// never as a session gap.
    pub(crate) fn suspend_target(&mut self, pid: u32) {
        let Some(target) = self.targets.remove(&pid) else {
            return;
        };
        let retained = target.process.retained_incarnation();
        let _ = self.members.remove(&pid);
        for a in &target.attachments {
            let _ = self.config.remove(&a.cookie);
        }
        for index in 0..target.ranges {
            let _ = self.ranges.remove(&c::RangeKey {
                pid,
                index: index as u32,
            });
        }
        self.refreshing.insert(pid, retained);
    }
    pub(crate) fn reconcile_records(
        &mut self,
        records: &[inventory::ProcessRecord],
    ) -> ObservationBatch {
        let mut b = ObservationBatch::default();
        if self.closed || self.final_drain || !self.gate.admitting() {
            b.gap(ObservationGap::Invalidated);
            return b;
        }
        let invalid_refresh: Vec<_> = self
            .refreshing
            .iter()
            .filter_map(|(&pid, retained)| {
                let validation = records
                    .iter()
                    .find(|record| record.pid == pid)
                    .ok_or(ObservationGap::MembershipUnknown)
                    .and_then(|record| retained.validate_record(record));
                validation.err().map(|gap| (pid, gap))
            })
            .collect();
        for (pid, gap) in invalid_refresh {
            self.retire_for_gap(pid, records.iter().find(|r| r.pid == pid), gap, &mut b);
            b.gap(gap);
        }
        let retire: Vec<_> = self
            .targets
            .iter()
            .filter_map(|(&pid, t)| {
                reconcile_retirement_gap(
                    records.iter().find(|p| p.pid == pid).map(|p| p.starttime),
                    t.starttime,
                    || process_retirement_gap(&t.process).map_or(Ok(()), Err),
                )
                .map(|gap| (pid, gap))
            })
            .collect();
        // Pids retired on a transient budget gap keep their incarnation
        // for next tick's re-add, exactly like the authority-refresh path
        // below: the counter's learned sites keep the shared process lease
        // alive, so a fresh admission would starve on ProcessLimit under
        // a tight process budget.
        let mut readd_deferred = Vec::new();
        // 6A additive refresh: a `ProcessChanged` sourced from the
        // per-tick revalidation arm (record present, starttime matched,
        // no recorded refusal) may be a pure row-set addition (dlopen).
        // The additive verdict then diverts the target into the same
        // retained-incarnation refresh handoff as the authority path
        // below instead of a terminal retire; the fresh acquire that
        // follows re-proves backing. Any other gap — or any proof
        // failure inside the verdict — keeps the frozen `ProcessChanged`
        // retire. These pids skip the re-add loop like `refreshed`.
        let mut additive_refreshed = Vec::new();
        for (pid, gap) in retire {
            let record = records.iter().find(|r| r.pid == pid);
            let preserved = if transient_budget_gap(gap) {
                self.targets
                    .get(&pid)
                    .map(|t| t.process.retained_incarnation())
            } else {
                None
            };
            if gap == ObservationGap::ProcessChanged && preserved.is_none() {
                // 6A exec (exe-stamp flip, §1.4) precedes the additive
                // probe: an exec changes the exe AND the rows, so the
                // additive verdict would fail closed anyway. The
                // revalidation-arm isolation is the same as below
                // (record present, starttime matched, no recorded
                // refusal); `exec_witnessed` additionally requires a
                // live pidfd with identical starttime/namespaces, so
                // reuse and namespace change can never land here.
                let witnessed = matches!(
                    (record, self.targets.get(&pid)),
                    (Some(record), Some(target))
                        if record.starttime == target.starttime
                            && recorded_refusal(&target.process).is_none()
                            && target.process.exec_witnessed()
                );
                if witnessed {
                    self.retire_for_gap(pid, record, gap, &mut b);
                    self.exec_sealed.insert(pid);
                    b.exec_witnesses.push(pid);
                    b.gap(gap);
                    b.gap(ObservationGap::IntervalUnknown);
                    continue;
                }
                let additive = match (record, self.targets.get(&pid)) {
                    (Some(record), Some(target))
                        if record.starttime == target.starttime
                            && recorded_refusal(&target.process).is_none() =>
                    {
                        target.process.additive_verdict()
                    }
                    _ => Err(ObservationGap::ProcessChanged),
                };
                if additive == Ok(objects::AdditiveVerdict::AddedRowsOnly) {
                    let retained = self.targets[&pid].process.retained_incarnation();
                    self.retire(pid, &mut b);
                    self.refreshing.insert(pid, retained);
                    additive_refreshed.push(pid);
                    b.refreshed_processes.push(pid);
                    b.additive_refreshes.push(pid);
                    continue;
                }
            }
            self.retire_for_gap(pid, record, gap, &mut b);
            if let Some(retained) = preserved {
                self.refreshing.insert(pid, retained);
                readd_deferred.push(pid);
            }
            b.gap(gap);
            b.gap(ObservationGap::IntervalUnknown)
        }
        // A locator-only snapshot may have left useful partial custody while
        // excluding a library. Reacquire on stronger inventory authority; do not
        // promote the old locator or emit new sites in the retiring batch.
        let refreshed: Vec<_> = self
            .targets
            .iter()
            .filter_map(|(&pid, target)| {
                records
                    .iter()
                    .find(|record| record.pid == pid)
                    .filter(|record| target.process.inventory_authority_advanced(record))
                    .map(|_| pid)
            })
            .collect();
        for &pid in &refreshed {
            let record = records.iter().find(|r| r.pid == pid);
            match terminal_originals(
                self.startup.get(&pid).map_or(&[], Vec::as_slice),
                self.targets.get(&pid),
                record,
            ) {
                Ok(true) => {
                    self.retire_for_gap(pid, record, ObservationGap::ProcessUnavailable, &mut b);
                    continue;
                }
                Err(gap) => {
                    self.retire(pid, &mut b);
                    b.gap(gap);
                    continue;
                }
                Ok(false) => (),
            }
            let retained = self.targets[&pid].process.retained_incarnation();
            self.retire(pid, &mut b);
            self.refreshing.insert(pid, retained);
            b.refreshed_processes.push(pid);
        }
        for record in records {
            if refreshed.contains(&record.pid)
                || readd_deferred.contains(&record.pid)
                || additive_refreshed.contains(&record.pid)
                || self.exec_sealed.contains(&record.pid)
            {
                continue;
            }
            if self.targets.get(&record.pid).is_some_and(|t| t.ready) {
                continue;
            }
            match self.add_target(record, &mut b) {
                Ok(()) => {}
                Err(g) => {
                    if identity_failure(g) {
                        self.retire_for_gap(record.pid, Some(record), g, &mut b);
                    }
                    b.gap(g);
                }
            }
        }
        b.gap(ObservationGap::IntervalUnknown);
        b.refusals.extend(self.budget.take_refusals());
        b
    }
    fn add_target(
        &mut self,
        record: &inventory::ProcessRecord,
        b: &mut ObservationBatch,
    ) -> Result<(), ObservationGap> {
        if let Some(rows) = self
            .startup
            .get(&record.pid)
            .filter(|rows| rows.iter().any(|a| a.historical))
        {
            if terminal_originals(rows, None, Some(record))? {
                return Ok(());
            }
            return Err(ObservationGap::Invalidated);
        }
        let mut target = if let Some(target) = self.targets.remove(&record.pid) {
            target
        } else {
            let process = if let Some(retained) = self.refreshing.get(&record.pid) {
                objects::acquire_with_incarnation(record, &mut self.budget, Some(retained))?
            } else {
                let Some(process) = acquire_observable(record, &mut self.budget)? else {
                    return Ok(());
                };
                process
            };
            self.refreshing.remove(&record.pid);
            // Only the first mapped adoption of the original held incarnation
            // may retain its observation generation. Real retirement/remapping allocates a
            // fresh generation and fresh cookies as before.
            let generation = if let Some(startup) = self
                .startup
                .get(&record.pid)
                .filter(|rows| !rows.is_empty())
            {
                for a in startup {
                    a.site.revalidate_object()?;
                    if a.site.starttime() != record.starttime {
                        return Err(ObservationGap::ProcessChanged);
                    }
                }
                self.members
                    .get(&record.pid, 0)
                    .map_err(|_| ObservationGap::MembershipUnknown)?
                    .generation
            } else {
                let generation = self.next_generation;
                self.next_generation = self
                    .next_generation
                    .checked_add(1)
                    .ok_or(ObservationGap::ProcessLimit)?;
                generation
            };
            Target {
                process,
                starttime: record.starttime,
                generation,
                attachments: Vec::new(),
                ranges: 0,
                ready: false,
            }
        };
        let generation = target.generation;
        let pid = record.pid;
        let result = (|| {
            if let Some(gap) = recorded_refusal(&target.process) {
                return Err(gap);
            }
            let ranges = order_ranges(target.process.executable_ranges()?)?;
            target.ranges = ranges.len();
            for (index, (start, end)) in ranges.into_iter().enumerate() {
                self.ranges
                    .insert(
                        c::RangeKey {
                            pid,
                            index: index as u32,
                        },
                        c::Range { start, end },
                        0,
                    )
                    .map_err(|_| ObservationGap::AttachFailed)?;
            }
            // An adopted epoch is already active. Resolve every public role
            // before any cold reader is armed, so an alias conflict cannot
            // transiently grant a signature during this first transition.
            // Declare leases first so rows/buffer are dropped before their
            // accounting on every early return as well as the normal path.
            let mut staging = Vec::new();
            let mut public_sites = Vec::new();
            for id in (1..=16).chain(20..=72) {
                for resolved in target.process.resolve_api(wire::api(id)?) {
                    self.roles.observe(
                        role_site(pid, record.starttime, &resolved.site),
                        id,
                        &self.budget,
                    )?;
                    // This staging vector is temporary. Retrying a deferred
                    // object must reuse existing role/link ownership, not burn
                    // permanent state allowance for the same API staging rows.
                    staging.push(self.budget.reserve_state(
                        2 * (std::mem::size_of::<(u32, ApiSite)>()
                            + std::mem::size_of::<super::schema::StateReservation>()),
                    )?);
                    public_sites.push((id, resolved));
                }
            }
            if let Some(gap) = recorded_refusal(&target.process) {
                return Err(gap);
            }
            for (id, resolved) in public_sites {
                let key = role_site(pid, record.starttime, &resolved.site);
                if !self.roles.accepts(key, id) {
                    disarm_site(&mut target, &resolved.site, &mut self.config)?;
                    if let Some(rows) = self.startup.get_mut(&pid) {
                        while let Some(index) =
                            rows.iter().position(|a| same_site(&a.site, &resolved.site))
                        {
                            let a = rows.swap_remove(index);
                            let _ = self.config.remove(&a.cookie);
                            drop(a.links);
                        }
                    }
                    b.gap(ObservationGap::AmbiguousSite);
                    continue;
                }
                if target
                    .attachments
                    .iter()
                    .any(|a| same_site(&a.site, &resolved.site))
                {
                    continue;
                }
                if let Some(index) = self.startup.get(&pid).and_then(|rows| {
                    rows.iter()
                        .position(|a| a.api == id && same_site(&a.site, &resolved.site))
                }) {
                    let mut a = self.startup.get_mut(&pid).unwrap().swap_remove(index);
                    let adopt = (|| {
                        a.adopt_site(resolved.site)?;
                        arm_attachment(&mut self.config, &target.process, &a, pid, generation)
                    })();
                    target.attachments.push(a);
                    if let Err(gap) = adopt {
                        let _ = self
                            .config
                            .remove(&target.attachments.last().unwrap().cookie);
                        return Err(gap);
                    }
                    continue;
                }
                let advertisers = if id == c::PROVIDER_INIT {
                    vec![resolved.site.object_hash().clone()]
                } else {
                    Vec::new()
                };
                match self.attach_pair(
                    pid,
                    id,
                    resolved.site,
                    advertisers,
                    target.attachments.len() * 2,
                    generation,
                    true,
                ) {
                    Ok(a) => {
                        arm_attachment(&mut self.config, &target.process, &a, pid, generation)?;
                        target.attachments.push(a)
                    }
                    Err(g) => cold_attach_error(g, b)?,
                }
            }
            drop(staging);
            if target.process.api_discovery_deferred() {
                return Err(ObservationGap::SnapshotLag);
            }
            #[cfg(test)]
            EXPIRE_STATIC.with(|flag| {
                if flag.replace(false) {
                    self.budget.set_deadline(Instant::now());
                }
            });
            b.static_candidates
                .extend(target.process.static_candidates(&self.budget)?);
            target.process.revalidate_fresh()?;
            if target.attachments.is_empty() && b.static_candidates.is_empty() {
                return Err(ObservationGap::SymbolUnavailable);
            }
            let previous = match self.members.get(&pid, 0) {
                Ok(member) => Some(member),
                Err(aya::maps::MapError::KeyNotFound) => None,
                Err(_) => return Err(ObservationGap::MembershipUnknown),
            };
            self.members
                .insert(pid, mapped_member(previous, generation, target.ranges)?, 0)
                .map_err(|_| ObservationGap::AttachFailed)?;
            // The second check fences setup changes after all links and membership.
            target.process.revalidate_fresh()?;
            if let Some(gap) = recorded_refusal(&target.process) {
                return Err(gap);
            }
            if self.startup.get(&pid).is_some_and(Vec::is_empty) {
                self.startup.remove(&pid);
            }
            Ok(())
        })();
        target.ready = result.is_ok();
        // Preserve the finite resource gap even when this pass is deferred.
        for g in target.process.gaps() {
            b.gap(g);
        }
        self.targets.insert(pid, target);
        if let Err(g) = result {
            if g != ObservationGap::SnapshotLag {
                // A late-fence budget failure consumes the refreshing
                // entry above; preserve the fresh incarnation so the next
                // tick retries through the shared admission instead of
                // starving on a fresh one. Same rule as the retire paths,
                // not narrower: this pass may have emitted statics into
                // the batch before the fence failed (and a resumed
                // deferred target may have emitted on a prior pass), so
                // Count can already pin this admission — a StateLimit
                // retire here would strand the re-add on ProcessLimit.
                // Preservation is harmless when nothing is pinned: the
                // re-add simply refits deterministically. SnapshotLag
                // keeps the unready target in place for the next pass.
                let preserved = if transient_budget_gap(g) {
                    self.targets
                        .get(&pid)
                        .map(|t| t.process.retained_incarnation())
                } else {
                    None
                };
                self.retire_for_gap(pid, Some(record), g, b);
                if let Some(retained) = preserved {
                    self.refreshing.insert(pid, retained);
                }
            }
            return Err(g);
        }
        // 6A bounded uncertainty window: a fenced pid that re-adds
        // through the refresh handoff keeps its fence for exactly
        // one clean backlog drain (uncertain-span records withhold,
        // certain pre-edge records bind), then flows again.
        if self.fenced.contains_key(&pid) {
            self.unfence_after_drain.insert(pid);
        }
        b.gap(ObservationGap::FirstQueryUnknown);
        b.gap(ObservationGap::SamplingPartial);
        Ok(())
    }
    pub fn drain(&mut self, deadline: Instant) -> ObservationBatch {
        let mut b = ObservationBatch::default();
        if self.last_drain.elapsed() > Duration::from_millis(200) {
            b.gap(ObservationGap::SnapshotLag)
        }
        self.last_drain = Instant::now();
        if !self.startup.is_empty() {
            b.gap(ObservationGap::FirstQueryUnknown);
            b.gap(ObservationGap::SamplingPartial);
        }
        if self.final_drain {
            self.final_refusals.extend(final_source_refusals(
                &self.targets,
                &self.startup,
                &mut b,
                deadline,
                &mut self.final_terminal,
            ));
        }
        let mut terminal = Vec::new();
        if !self.final_drain {
            let retired: Vec<_> = self
                .targets
                .iter()
                .filter_map(|(&pid, t)| process_retirement_gap(&t.process).map(|g| (pid, g)))
                .collect();
            for (pid, gap) in retired {
                // Same transient-budget preservation as the reconcile
                // loop: without it a budget-gap retire here permanently
                // strands the re-add on ProcessLimit. No same-tick
                // deferral needed: drain runs after reconcile, so the
                // re-add lands on a later tick through the retained
                // incarnation.
                let preserved = if transient_budget_gap(gap) {
                    self.targets
                        .get(&pid)
                        .map(|t| t.process.retained_incarnation())
                } else {
                    None
                };
                // 6A exec/additive diversion (mirrors the reconcile
                // loop): the drain wins the race for maps changes
                // (25ms cadence vs tick cadence), so a drain-side
                // terminal retire would steal execs and dlopens from
                // the reconcile report — silently rehealing with a
                // fresh baseline and no image seal or refresh
                // detail. The live probes below fail closed on reuse
                // (no record exists on this path), exactly like the
                // revalidation-arm isolation in reconcile.
                if gap == ObservationGap::ProcessChanged && preserved.is_none() {
                    let witnessed = self.targets.get(&pid).is_some_and(|t| {
                        recorded_refusal(&t.process).is_none() && t.process.exec_witnessed()
                    });
                    if witnessed {
                        self.retire_for_gap(pid, None, gap, &mut b);
                        self.exec_sealed.insert(pid);
                        b.exec_witnesses.push(pid);
                        b.gap(gap);
                        b.gap(ObservationGap::IntervalUnknown);
                        continue;
                    }
                    let additive = self
                        .targets
                        .get(&pid)
                        .map(|t| {
                            if recorded_refusal(&t.process).is_none() {
                                t.process.additive_verdict()
                            } else {
                                Err(ObservationGap::ProcessChanged)
                            }
                        })
                        .unwrap_or(Err(ObservationGap::ProcessChanged));
                    if additive == Ok(objects::AdditiveVerdict::AddedRowsOnly) {
                        let retained = self.targets[&pid].process.retained_incarnation();
                        self.retire(pid, &mut b);
                        self.refreshing.insert(pid, retained);
                        b.refreshed_processes.push(pid);
                        b.additive_refreshes.push(pid);
                        continue;
                    }
                }
                self.retire_for_gap(pid, None, gap, &mut b);
                if let Some(retained) = preserved {
                    self.refreshing.insert(pid, retained);
                }
                b.gap(gap);
            }
            if !self.startup.is_empty() {
                b.gap(ObservationGap::FirstQueryUnknown);
                b.gap(ObservationGap::SamplingPartial);
            }
            let validation: Vec<_> = self
                .startup
                .iter()
                .map(|(&pid, rows)| {
                    let mut exited = false;
                    let result = rows.iter().try_for_each(|a| {
                        exited |= a.site.revalidate_queued()?;
                        Ok::<_, ObservationGap>(())
                    });
                    (pid, result.map(|()| exited))
                })
                .collect();
            for (pid, result) in validation {
                match result {
                    Err(gap) => {
                        self.retire_for_gap(pid, None, gap, &mut b);
                        b.gap(gap);
                    }
                    Ok(true) => {
                        if self.retire_for_gap(
                            pid,
                            None,
                            ObservationGap::ProcessUnavailable,
                            &mut b,
                        ) {
                            terminal.push(pid);
                        }
                    }
                    Ok(false) => (),
                }
            }
        }
        // 6A bounded uncertainty windows clear only after a CLEAN
        // backlog drain (ring exhausted): an overrun/limit break
        // leaves un-consumed backlog for the next drain, which must
        // still run under the fence.
        let mut drained_clean = true;
        loop {
            if Instant::now() >= deadline {
                b.gap(ObservationGap::DrainOverrun);
                drained_clean = false;
                break;
            }
            let event = match self.events.next() {
                Some(bytes) => wire::decode_transport(&bytes),
                None => break,
            };
            match event {
                Ok(e) => self.consume(e, &mut b),
                Err(g) => {
                    self.aliases.clear();
                    invalidate_algorithms(&mut b);
                    b.gap(g);
                }
            }
            if self.emitted >= self.budget.limits.max_facts {
                b.gap(ObservationGap::FactLimit);
                drained_clean = false;
                break;
            }
        }
        if drained_clean {
            for pid in std::mem::take(&mut self.unfence_after_drain) {
                self.fenced.remove(&pid);
            }
        }
        for index in 0..8 {
            match self.loss.get(&(index as u32), 0) {
                Ok(values) => {
                    self.loss_read_seq[index] = self.loss_read_seq[index].saturating_add(1);
                    let total = values.iter().fold(0u64, |sum, v| sum.saturating_add(*v));
                    if total > self.last_loss[index] {
                        self.loss_totals[index] =
                            self.loss_totals[index].saturating_add(total - self.last_loss[index]);
                        self.aliases.clear();
                        invalidate_algorithms(&mut b);
                        b.gap(match index {
                            0 => ObservationGap::QueueLoss,
                            1 => ObservationGap::PendingLimit,
                            2 => ObservationGap::DepthLimit,
                            3 => ObservationGap::UnpairedReturn,
                            4 => ObservationGap::TargetReadFailed,
                            5 => ObservationGap::RelocationRefused,
                            6 => ObservationGap::DispatchPartial,
                            _ => ObservationGap::NamespaceChanged,
                        });
                        self.last_loss[index] = total;
                    }
                }
                Err(_) => {
                    self.aliases.clear();
                    invalidate_algorithms(&mut b);
                    b.gap(ObservationGap::BpfUnavailable);
                }
            }
        }
        for pid in terminal {
            self.retire_startup(pid);
            self.aliases.retire(pid);
        }
        if self.aliases.incomplete() {
            b.gap(ObservationGap::IntervalUnknown);
        }
        b
    }
    fn consume(&mut self, event: wire::Transport, b: &mut ObservationBatch) {
        let r = event.record();
        // 6A fence: post-edge records never bind, never project —
        // dropped whole and conserved as withheld loss.
        if let Some(&edge) = self.fenced.get(&r.pid) {
            if r.monotonic_ns >= edge {
                self.fence_withheld = self.fence_withheld.saturating_add(1);
                return;
            }
        }
        let binding = if self.final_drain {
            final_record_binding(
                &self.targets,
                &self.startup,
                &self.final_refusals,
                &self.final_terminal,
                &r,
            )
        } else {
            record_binding(&self.targets, &self.startup, &r)
        };
        let binding = match binding {
            Ok(Some(binding)) => binding,
            Ok(None) => return,
            Err(gap) => {
                b.gap(gap);
                return;
            }
        };
        let attachment = binding.attachment;
        if !self
            .roles
            .accepts(role_site(r.pid, binding.starttime, &attachment.site), r.api)
        {
            b.gap(ObservationGap::AmbiguousSite);
            return;
        }
        let hash = attachment.site.object_hash().clone();
        let advertisers = attachment.advertisers.clone();
        let starttime = binding.starttime;
        let Some(mut payload) = assemble_payload(event, &mut self.aliases, &self.budget, b) else {
            return;
        };
        if self.final_drain && r.code != 0 {
            // Close-only decoding never relocates code or attaches a discovered
            // role. Keep finite metadata while marking its backing unavailable.
            b.gap(ObservationGap::RelocationRefused);
            if r.kind == c::INIT {
                b.gap(ObservationGap::FirstQueryUnknown);
                return;
            }
        }
        if r.code != 0 && !self.final_drain {
            let Some(process) = binding.process else {
                b.gap(ObservationGap::RelocationRefused);
                return;
            };
            let site = match process.relocate(TransientCodeAddress::from_kernel_event(r.code)) {
                Ok(s) => s,
                Err(g) => {
                    b.gap(g);
                    if identity_failure(g) {
                        self.retire_for_gap(r.pid, None, g, b);
                    }
                    return;
                }
            };
            if r.kind == c::INIT {
                let api = match r.function {
                    1 => c::PROVIDER_INIT,
                    1024 => c::TEARDOWN,
                    1027 => c::QUERY_CALLBACK,
                    1028 => c::UNQUERY_CALLBACK,
                    _ => {
                        b.gap(ObservationGap::InvalidWire);
                        return;
                    }
                };
                let mut candidates = advertisers;
                if r.function == 1 {
                    candidates.clear();
                    candidates.push(site.object_hash().clone());
                    b.gap(ObservationGap::RegistrationRace)
                }
                self.attach_learned(r.pid, api, site, candidates, b);
                b.gap(ObservationGap::FirstQueryUnknown);
                return;
            }
            if let ObservationPayload::Implementation {
                algorithm,
                alias_quality,
                function,
                advertiser_candidates,
                backing_sha256,
                ..
            } = &mut payload
            {
                *advertiser_candidates = advertisers.clone();
                *backing_sha256 = Some(site.object_hash().clone());
                let physical = (
                    r.pid,
                    r.generation,
                    site.native_device(),
                    site.inode(),
                    site.file_offset(),
                );
                if self.learned.contains(&physical)
                    || self.learned.len() < self.budget.limits.max_learned_sites
                {
                    if self.budget.state(512 + advertisers.len() * 96).is_ok() {
                        b.learned_sites.push(VerifiedSiteCandidate {
                            site,
                            pid: r.pid,
                            starttime,
                            generation: r.generation,
                            advertisers,
                            operation: Operation::from_id(r.operation).unwrap_or(Operation::Other),
                            numeric_operation: r.operation,
                            dynamic_algorithm: super::static_tables::DynamicAlgorithmId::observed(
                                &hash, starttime, &r,
                            ),
                            observed_ns: r.monotonic_ns,
                            algorithm: *algorithm,
                            alias_quality: *alias_quality,
                            function: *function,
                        });
                        self.learned.insert(physical);
                    } else {
                        b.gap(ObservationGap::StateLimit)
                    }
                } else {
                    b.gap(ObservationGap::SiteLimit)
                }
            }
        } else if let ObservationPayload::Implementation {
            advertiser_candidates,
            ..
        } = &mut payload
        {
            *advertiser_candidates = advertisers;
        }
        if self.emitted >= self.budget.limits.max_facts {
            b.gap(ObservationGap::FactLimit);
            return;
        }
        let state = 512
            + match &payload {
                ObservationPayload::Implementation {
                    advertiser_candidates,
                    ..
                } => advertiser_candidates.len() * 96,
                _ => 0,
            };
        if self.budget.state(state).is_err() {
            b.gap(ObservationGap::StateLimit);
            return;
        }
        let operation = Operation::from_id(r.operation).unwrap_or(Operation::Other);
        let class = match operation {
            Operation::Digest => AlgorithmClass::Digest,
            Operation::Cipher => AlgorithmClass::Cipher,
            Operation::Mac => AlgorithmClass::Mac,
            Operation::Kdf => AlgorithmClass::Kdf,
            Operation::Rand => AlgorithmClass::Rand,
            Operation::Keymgmt | Operation::Keyexch | Operation::AsymCipher => AlgorithmClass::Key,
            Operation::Signature => AlgorithmClass::Signature,
            Operation::Kem => AlgorithmClass::Kem,
            Operation::Encoder | Operation::Decoder => AlgorithmClass::Encoding,
            Operation::Store => AlgorithmClass::Store,
            Operation::Other => AlgorithmClass::Other,
        };
        b.facts.push(ObservationFact {
            pid: r.pid,
            starttime,
            object_sha256: hash,
            generation: r.generation,
            context: ContextIdentity::Unknown {},
            source: match r.kind {
                c::INIT => ObservationSource::ProviderInit,
                c::QUERY | c::ALGORITHM | c::ALIAS_END => ObservationSource::ProviderQuery,
                c::IMPLEMENTATION => ObservationSource::ProviderDispatch,
                _ => ObservationSource::PublicApi,
            },
            api: wire::api(r.api).unwrap_or(ObservationApi::ProviderQueryCallback),
            operation,
            class,
            monotonic_ns: r.monotonic_ns,
            confidence: ScopeConfidence::Observed,
            payload,
        });
        self.emitted += 1;
    }
    /// Consume the retained typed exports through the receipt-based
    /// source-acquisition protocol, one capability per site: revalidate
    /// freshness, mint cookie/site/artifact IDs, program the CONFIG row
    /// (the kernel resolves the cookie's TGID through it) and
    /// admission+bind, adopt the typed entry/return pair with ENTRY/RETURN
    /// receipts, and publish READY through the contracted kernel phase-4
    /// path — all under the shared LIVE anchor in `scope`. Runs after the
    /// legacy
    /// registration lists and before the terminal legacy READY publishes,
    /// while the child is still held: every capability lists before any
    /// READY completes the set, and no fetch can fire unadmitted. Any
    /// refusal aborts the whole acquisition: partially admitted sites
    /// would attribute under incomplete authority. The owner retains
    /// every adopted typed link through the final consumers.
    pub(crate) fn acquire_typed_sites(
        &mut self,
        scope: &super::source_owner::TypedAcquisitionScope,
        deadline: Instant,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<usize, ObservationGap> {
        use std::os::fd::AsRawFd as _;
        if self.final_drain || !self.gate.admitting() {
            return Err(ObservationGap::Invalidated);
        }
        if self.source_owner.is_none() {
            return Err(ObservationGap::Invalidated);
        }
        let (entry_prog, return_prog) = {
            let owner = self
                .source_owner
                .as_ref()
                .ok_or(ObservationGap::Invalidated)?;
            (
                owner.typed_program_fd("typed_entry")?.as_raw_fd(),
                owner.typed_program_fd("typed_return")?.as_raw_fd(),
            )
        };
        let mut admitted = 0usize;
        for index in 0..self.typed_startup.len() {
            if cancel.load(std::sync::atomic::Ordering::Relaxed) || Instant::now() >= deadline {
                return Err(ObservationGap::SnapshotLag);
            }
            // Clone the site handle (shares Rc anchor + descriptors); the
            // retained vector keeps custody for the session lifetime.
            let (role_id, site, object_hash) = {
                let staged = &self.typed_startup[index];
                staged.site().revalidate_object()?;
                (
                    staged.role().id(),
                    staged.site().clone(),
                    staged.site().object_hash().clone(),
                )
            };
            let pid = site.pid();
            // Evidence device (not native): pins and final joins must use
            // the same device encoding as the counter's SiteKey.
            let device = crate::focused_count::evidence_device(site.native_device());
            let inode = site.inode();
            let offset = site.file_offset();
            let hash = String::from(object_hash.clone());
            let (api, operation, function) =
                crate::attribution::wire::TypedAdmission::admission_parts(role_id)
                    .ok_or(ObservationGap::Invalidated)?;
            if self.next_typed_cookie >= TYPED_COOKIE_END {
                return Err(ObservationGap::LinkLimit);
            }
            if self
                .link_count()
                .checked_add(2)
                .ok_or(ObservationGap::LinkLimit)?
                > self.budget.limits.max_links
            {
                return Err(ObservationGap::LinkLimit);
            }
            self.budget.state(512 + 96)?;
            site.revalidate_object()?;
            let cookie = self.next_typed_cookie;
            self.next_typed_cookie += 1;
            let site_id = self.next_site_id;
            self.next_site_id = self
                .next_site_id
                .checked_add(1)
                .ok_or(ObservationGap::StateLimit)?;
            let object_id = match self.object_ids.get(&hash) {
                Some(id) => *id,
                None => {
                    let id = self.next_object_id;
                    self.next_object_id = self
                        .next_object_id
                        .checked_add(1)
                        .ok_or(ObservationGap::StateLimit)?;
                    self.object_ids.insert(hash.clone(), id);
                    id
                }
            };
            let object_sha256 = super::source_owner::decode_object_hash_hex(&object_hash)?;
            // The kernel's source_domain() resolves the TGID through
            // CONFIG[cookie]: program this cookie's row (same shape as the
            // legacy prearm rows) before the ENTRY request can arm. The
            // typed programs never read CONFIG — this row exists so the
            // registration receipts join the cookie to its domain.
            let startup_generation = self
                .startup
                .get(&pid)
                .and_then(|attachments| attachments.first())
                .map(|attachment| attachment.generation)
                .ok_or(ObservationGap::Invalidated)?;
            let config_result = validate_then_arm(
                || site.revalidate_object(),
                || {
                    self.config
                        .insert(
                            cookie,
                            c::Config {
                                generation: startup_generation,
                                object: object_id,
                                pid,
                                api,
                            },
                            0,
                        )
                        .map_err(|_| ObservationGap::AttachFailed)
                },
            );
            if config_result.is_err() {
                let _ = self.config.remove(&cookie);
            }
            config_result?;
            let owner = self
                .source_owner
                .as_mut()
                .ok_or(ObservationGap::Invalidated)?;
            let receipts = owner.admit_typed_site(&super::source_owner::TypedAdmissionRequest {
                cookie,
                site_id,
                role_id,
                public_api_id: api,
                operation,
                function,
                tgid: pid,
                object_id,
                object_sha256,
                source_epoch: scope.anchor.epoch,
            })?;
            // Registration custody is a dup of the retained site's own
            // descriptor (never a re-resolved path); the kernel joins the
            // registration to the shared anchor by inode, so a site from a
            // file the anchor does not cover refuses here, fail-closed.
            let target = File::from(
                site.attachment_fd()
                    .try_clone_to_owned()
                    .map_err(|_| ObservationGap::BackingUnavailable)?,
            );
            let registration_scope = super::source_owner::RequestScope {
                site_cookie: cookie,
                host_key: scope.host_key,
                incarnation: scope.incarnation,
                planned_image: scope.planned_image,
                link_offset: offset,
                target_pid: pid,
                target,
                expected_artifact: site.object_hash().clone(),
            };
            let registration = owner.register_entry_return(
                &registration_scope,
                entry_prog,
                return_prog,
                &scope.anchor,
            )?;
            owner.publish_capability_ready(&registration_scope, &scope.anchor, &registration)?;
            site.revalidate_object()?;
            self.typed_sites.insert(
                cookie,
                TypedSiteRecord {
                    site_id: receipts.site_id,
                    role_id,
                    pid,
                    device,
                    inode,
                    offset,
                    object: crate::evidence::ObjectId(hash.clone()),
                    object_id,
                    source_epoch: receipts.source_epoch,
                    process_incarnation: receipts.process_incarnation,
                    image_epoch: receipts.image_epoch,
                },
            );
            // The counter pins at most one cookie per physical site: first
            // operational role wins, later roles at the same offset keep
            // their own cookie (the discovery census already arbitrated
            // offset conflicts, so this is defense in depth).
            if matches!(role_id, 304..=308 | 312..=315 | 319..=323 | 327..=346 | 350..=355) {
                self.typed_pins
                    .entry((device, inode, offset))
                    .or_insert(cookie);
            }
            admitted += 1;
        }
        Ok(admitted)
    }
    /// Counter bridge: pinned cookie per physical site for same-cookie
    /// counter attach, so both programs resolve one SITE_BIND row.
    #[allow(
        dead_code,
        reason = "exercised by session native controls; production counter wiring is staged"
    )]
    pub(crate) fn typed_pins(&self) -> &BTreeMap<(u64, u64, u64), u64> {
        &self.typed_pins
    }
    /// Counter bridge: borrow every shared producer/source map FD the
    /// counter needs. `None` when no source owner exists (standalone
    /// counter opens private maps); a missing name refuses the borrow
    /// rather than mixing shared and private pools.
    pub(crate) fn borrowed_producer_maps(
        &self,
    ) -> Option<BTreeMap<String, std::os::fd::BorrowedFd<'_>>> {
        let owner = self.source_owner.as_ref()?;
        let mut maps = BTreeMap::new();
        for name in loader::BORROWED_COUNT_MAPS {
            maps.insert(name.to_string(), owner.owned_map(name).ok()?);
        }
        Some(maps)
    }
    /// Finalizer access to admitted typed-site records.
    pub(crate) fn typed_site_records(&self) -> &BTreeMap<u64, TypedSiteRecord> {
        &self.typed_sites
    }
    /// Finalizer maps: borrow the five producer maps for one strict
    /// final read. `None` without a source owner; a missing map refuses
    /// the whole read rather than a partial cut.
    pub(crate) fn attribution_maps(&self) -> Option<crate::attribution::ClosedAttributionMaps<'_>> {
        let owner = self.source_owner.as_ref()?;
        Some(crate::attribution::ClosedAttributionMaps {
            partition: owner.owned_map("PARTITION").ok()?,
            selector: owner.owned_map("SELECTOR_DICT").ok()?,
            loss: owner.owned_map("PRODUCER_LOSS").ok()?,
            bind: owner.owned_map("SITE_BIND").ok()?,
            control: owner.owned_map("ATTRIB_CONTROL").ok()?,
        })
    }
    /// Charge the session budget for the final attribution read's host
    /// buffers before the one-shot collect runs.
    pub(crate) fn charge_attribution_final(&mut self, bytes: usize) -> Result<(), ObservationGap> {
        self.budget.state(bytes)
    }
    fn attach_learned(
        &mut self,
        pid: u32,
        api: u32,
        site: VerifiedSite,
        advertisers: Vec<ObjectHash>,
        b: &mut ObservationBatch,
    ) {
        let Some(target) = self.targets.get(&pid) else {
            return;
        };
        let key = role_site(pid, target.starttime, &site);
        match self.roles.observe(key, api, &self.budget) {
            Ok(true) => {}
            Ok(false) => {
                let result =
                    disarm_site(self.targets.get_mut(&pid).unwrap(), &site, &mut self.config);
                // A conflict may be discovered after earlier queued records in this
                // batch. Do not return those facts/candidates as usable evidence.
                b.facts.retain(|fact| fact.pid != pid);
                b.learned_sites.retain(|candidate| candidate.pid != pid);
                self.aliases.retire(pid);
                b.gap(ObservationGap::AmbiguousSite);
                b.gap(ObservationGap::Invalidated);
                if let Err(g) = result {
                    b.gap(g);
                    self.retire(pid, b)
                }
                return;
            }
            Err(g) => {
                b.gap(g);
                return;
            }
        }
        {
            let target = self.targets.get_mut(&pid).unwrap();
            if let Some(existing) = target
                .attachments
                .iter_mut()
                .find(|a| same_site(&a.site, &site))
            {
                if let Err(g) =
                    merge_candidates(&mut existing.advertisers, advertisers, &self.budget)
                {
                    b.gap(g)
                }
                return;
            }
        }
        let gap = {
            let target = self.targets.get(&pid).unwrap();
            target.process.revalidate().err()
        };
        if let Some(g) = gap {
            b.gap(g);
            // Transient-budget preservation, as in the reconcile and
            // drain loops: a budget gap here must not strand the re-add
            // on ProcessLimit.
            let preserved = if transient_budget_gap(g) {
                self.targets
                    .get(&pid)
                    .map(|t| t.process.retained_incarnation())
            } else {
                None
            };
            self.retire_for_gap(pid, None, g, b);
            if let Some(retained) = preserved {
                self.refreshing.insert(pid, retained);
            }
            return;
        }
        let generation = self.targets.get(&pid).unwrap().generation;
        match self.attach_pair(pid, api, site, advertisers, 0, generation, true) {
            Ok(a) => {
                // Pair exists but CONFIG is absent: full process/maps/object
                // validation precedes the only arm operation, and runs again after it.
                let result = arm_attachment(
                    &mut self.config,
                    &self.targets[&pid].process,
                    &a,
                    pid,
                    generation,
                );
                if let Err(g) = result {
                    b.gap(g);
                    // The fresh arm proof can exhaust reads; preserve like
                    // any other live-target budget retire so the re-add
                    // retries through the shared admission.
                    let preserved = if transient_budget_gap(g) {
                        self.targets
                            .get(&pid)
                            .map(|t| t.process.retained_incarnation())
                    } else {
                        None
                    };
                    self.retire_for_gap(pid, None, g, b);
                    if let Some(retained) = preserved {
                        self.refreshing.insert(pid, retained);
                    }
                    return;
                }
                self.targets.get_mut(&pid).unwrap().attachments.push(a);
            }
            Err(g) => {
                b.gap(g);
                if identity_failure(g) {
                    self.retire_for_gap(pid, None, g, b);
                }
            }
        }
    }
    pub(crate) fn set_api_window(&mut self, start: u64, end: u64) -> Result<(), ObservationGap> {
        if self.final_drain || !self.gate.admitting() {
            return Err(ObservationGap::Invalidated);
        }
        self.api_window
            .set(0, c::Range { start, end }, 0)
            .map_err(|_| ObservationGap::BpfUnavailable)
    }
    fn retire_startup(&mut self, pid: u32) {
        if let Some(attachments) = self.startup.remove(&pid) {
            for a in attachments {
                let _ = self.config.remove(&a.cookie);
                drop(a.links);
            }
        }
    }
    /// Retain typed startup sources without arming an argument reader or
    /// reinterpreting any legacy API/event role. Source refusal is independent
    /// of the already acquired legacy startup facts. Under an enabled native
    /// lease the retained roots also load, attach and enable mode 1 here
    /// (pre-open); production passes a disabled lease and observes
    /// byte-identical behavior (mode stays 0, roots unloaded).
    pub(crate) fn prepare_typed_startup(
        &mut self,
        sites: Vec<super::objects::StartupTypedSite>,
        deadline: Instant,
        cancel: &std::sync::atomic::AtomicBool,
        lease: &super::source_owner::SourceAcquisitionLease,
    ) -> Result<(), ObservationGap> {
        if self.final_drain || !self.gate.admitting() {
            return Err(ObservationGap::Invalidated);
        }
        if sites.is_empty() {
            return Ok(());
        }
        let kernel = self._source_kernel.as_ref().map_err(|gap| *gap)?;
        if self.source_owner.is_none() {
            // The owner checks the retained half before acquiring anything and
            // moves it in on success; a refused half stays put for diagnosis.
            self.source_owner = Some(super::source_owner::SourceOwner::prepare(
                &self.budget,
                kernel,
                &self.gate,
                &self.loaded,
                &mut self.source_prepared,
                deadline,
                cancel,
            )?);
        }
        retain_typed_startup(
            sites,
            &self.budget,
            &mut self.typed_startup,
            deadline,
            cancel,
        )?;
        if matches!(
            lease,
            super::source_owner::SourceAcquisitionLease::Enabled(_)
        ) {
            self.source_owner
                .as_mut()
                .ok_or(ObservationGap::Invalidated)?
                .enable_roots_pre_open(&self.loaded)?;
        }
        Ok(())
    }

    /// Multi-attachment lease admission: every claim in the params must
    /// match one DISTINCT retained startup attachment of the single
    /// held process, by PID, file identity (claim-path device/inode vs
    /// the retained site) and file offset, with a legacy-range cookie
    /// and no legacy producer links. Exact count: an empty claim set,
    /// an over/under-claimed order, a recycled PID or a double-matched
    /// attachment refuses. Returns the admitted sites in claim order.
    fn admitted_source_sites(
        &self,
        params: &super::source_owner::NativeSourceParams,
    ) -> Result<Vec<super::source_owner::AdmittedSourceSite>, ObservationGap> {
        if self.startup.len() != 1 {
            return Err(ObservationGap::Invalidated);
        }
        let (tgid, attachments) = self
            .startup
            .iter()
            .next()
            .ok_or(ObservationGap::Invalidated)?;
        let (tgid, attachments) = (*tgid, attachments);
        let claims = params.claims();
        if claims.is_empty() || claims.len() != attachments.len() {
            return Err(ObservationGap::Invalidated);
        }
        // ER-S2-I2: reserve the bounded admission peak through the caller
        // budget before allocating the matching/admission buffers.
        self.budget.state(
            super::source_owner::multi_attachment_admission_charge(claims.len())
                .ok_or(ObservationGap::StateLimit)?,
        )?;
        let mut matched = vec![false; attachments.len()];
        let mut admitted = Vec::with_capacity(claims.len());
        for claim in claims {
            if claim.child_pid() != tgid {
                return Err(ObservationGap::Invalidated);
            }
            let claimed =
                std::fs::metadata(claim.target()).map_err(|_| ObservationGap::Invalidated)?;
            if !claimed.is_file() {
                return Err(ObservationGap::Invalidated);
            }
            let mut found = None;
            for (index, attachment) in attachments.iter().enumerate() {
                if matched[index]
                    || claim.link_offset() != attachment.site.file_offset()
                    || claimed.dev() != attachment.site.native_device()
                    || claimed.ino() != attachment.site.inode()
                {
                    continue;
                }
                found = Some(index);
                break;
            }
            let index = found.ok_or(ObservationGap::Invalidated)?;
            matched[index] = true;
            let attachment = &attachments[index];
            // Reserve-only prearm is mandatory: legacy producer links on
            // the site would duplicate the pair this acquisition creates.
            if !attachment.links.is_empty() {
                return Err(ObservationGap::Invalidated);
            }
            attachment.site.revalidate_object()?;
            let cookie = attachment.cookie;
            if !(1..=4096).contains(&cookie) {
                return Err(ObservationGap::Invalidated);
            }
            let target = File::from(
                attachment
                    .site
                    .attachment_fd()
                    .try_clone_to_owned()
                    .map_err(|_| ObservationGap::BackingUnavailable)?,
            );
            admitted.push(super::source_owner::AdmittedSourceSite {
                tgid,
                site_cookie: cookie,
                link_offset: attachment.site.file_offset(),
                target,
                expected_artifact: attachment.site.object_hash().clone(),
                device: attachment.site.native_device(),
                inode: attachment.site.inode(),
            });
        }
        Ok(admitted)
    }

    fn admitted_source_site(
        &self,
        params: &super::source_owner::NativeSourceParams,
    ) -> Result<super::source_owner::AdmittedSourceSite, ObservationGap> {
        let mut admitted = self.admitted_source_sites(params)?;
        if admitted.len() != 1 {
            return Err(ObservationGap::Invalidated);
        }
        admitted.pop().ok_or(ObservationGap::Invalidated)
    }

    /// Lease-gated post-open source acquisition. Disabled (production):
    /// inert empty receipts, zero effects. Enabled (owned native
    /// qualification): the serialized gate-open, domain-arm, enroll, anchor,
    /// entry/return and READY flow on this session's admitted pre-exec
    /// startup attachments (one order, one shared file anchor, one
    /// registration per attachment), before the held child is released.
    /// File custody, offset, cookie and identity derive from the retained
    /// admitted sites; the caller's params are verified against that truth
    /// first and never used as authority. Typed capabilities join the same
    /// order between the legacy registrations and the terminal legacy
    /// READY: every capability lists before any READY completes the set,
    /// so the held child releases only after post-adoption READY published
    /// for every legacy site and every typed cookie. Any phase failure
    /// refuses the order before returning.
    pub(crate) fn acquire_source_after_open(
        &mut self,
        lease: &super::source_owner::SourceAcquisitionLease,
        deadline: Instant,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<super::source_owner::SourceAcquisitionReceipts, ObservationGap> {
        use super::source_owner::SourceAcquisitionLease as Lease;
        let Lease::Enabled(params) = lease else {
            return Ok(super::source_owner::SourceAcquisitionReceipts {
                host_key: 0,
                site_cookie: 0,
                link_offset: 0,
                domain: super::source_owner::DomainArmed {
                    tgid: 0,
                    incarnation: 0,
                    original: 0,
                    planned: 0,
                },
                anchor: super::source_owner::AnchorEstablished {
                    anchor_id: 0,
                    epoch: 0,
                    object_id: 0,
                    sequence: 0,
                    hash: [0; 32],
                },
                registration: super::source_owner::RegistrationAdopted { registration_id: 0 },
                ready_sequence: 0,
                adopted_links: 0,
                attachments: Vec::new(),
                acquisition_buffers: None,
            });
        };
        if cancel.load(std::sync::atomic::Ordering::Relaxed) || Instant::now() >= deadline {
            return Err(ObservationGap::SnapshotLag);
        }
        self.budget.checkpoint()?;
        // Pre-exec startup truth (not post-exec targets): acquisition runs
        // while the child is still held, before release. The claim-vs-truth
        // check runs before any kernel effect: a substituted file, offset
        // or PID refuses here. The refusal is recorded so the close
        // receipts carry the diagnosis instead of silence.
        // Single-attachment leases clear through the singular guard;
        // multi-attachment orders through the exact-count plural guard.
        // Both refuse before any kernel effect.
        let admission = match params.claims().len() {
            1 => self.admitted_source_site(params).map(|site| vec![site]),
            _ => self.admitted_source_sites(params),
        };
        let admitted = match admission {
            Ok(admitted) => admitted,
            Err(error) => {
                if let Some(owner) = self.source_owner.as_mut() {
                    owner.note_refusal(format!(
                        "admission refused: {} claims against {} startup pid groups",
                        params.claims().len(),
                        self.startup.len(),
                    ));
                    owner.refuse_acquisition();
                }
                return Err(error);
            }
        };
        // ER-S2-I2: reserve the bounded acquisition peak (scope,
        // registration, sequence and returned-attachment vectors plus the
        // backing-identity scratch) before allocating any of them. The
        // reservation moves into the returned receipts, so the charge
        // survives session teardown and releases exactly when the
        // returned storage does; every failure path below drops it
        // (refunding a charge that backs no returned storage).
        let mut acquisition_reservation = match self.budget.reserve_state(
            super::source_owner::multi_attachment_acquisition_charge(admitted.len())
                .ok_or(ObservationGap::StateLimit)?,
        ) {
            Ok(reservation) => Some(reservation),
            Err(error) => {
                if let Some(owner) = self.source_owner.as_mut() {
                    owner.note_refusal(format!(
                        "acquisition buffers refused: {} attachments exceed the state budget",
                        admitted.len(),
                    ));
                    owner.refuse_acquisition();
                }
                return Err(error);
            }
        };
        // Single-file order: the adoption order carries one anchor, so
        // attachments spanning files refuse here, before any kernel
        // effect. (Real provider closures anchor one file; multi-file
        // orders need a multi-anchor order, which is future work.)
        let (device, inode) = (admitted[0].device, admitted[0].inode);
        if admitted
            .iter()
            .any(|a| (a.device, a.inode) != (device, inode))
        {
            if let Some(owner) = self.source_owner.as_mut() {
                let mut backings: Vec<(u64, u64)> =
                    admitted.iter().map(|a| (a.device, a.inode)).collect();
                backings.sort_unstable();
                backings.dedup();
                owner.note_refusal(format!(
                    "multi-file order refused: {} distinct backings",
                    backings.len(),
                ));
                owner.refuse_acquisition();
            }
            return Err(ObservationGap::Invalidated);
        }
        let entry_prog = self
            .loaded
            .progs
            .get("observation_entry")
            .ok_or(ObservationGap::InvalidObject)?;
        let return_prog = self
            .loaded
            .progs
            .get("observation_return")
            .ok_or(ObservationGap::InvalidObject)?;
        let (entry_prog, return_prog) = (
            std::os::fd::AsRawFd::as_raw_fd(entry_prog),
            std::os::fd::AsRawFd::as_raw_fd(return_prog),
        );
        // Shared staging anchor for the admitted file when staged: typed
        // staging already captured (and charged) this file's mapping, so
        // the source anchor reuses it instead of re-capturing. Selection
        // is by site identity only; the owner re-proves stamp and hash
        // inside and falls back to a fresh capture on any mismatch.
        let candidate = admitted[0].target.metadata().ok().and_then(|metadata| {
            let (device, inode) = (metadata.dev(), metadata.ino());
            self.typed_startup.iter().find_map(|staged| {
                let site = staged.site();
                (site.native_device() == device
                    && site.inode() == inode
                    && site.object_hash() == &admitted[0].expected_artifact)
                    .then(|| staged.anchor().clone())
            })
        });
        // ER-S2-I1: reserve the complete attachment order before any kernel
        // effect: live links plus every planned legacy pair plus every
        // planned typed pair must fit `max_links`. A tight limit refuses
        // here with zero adoptions instead of adopting legacy pairs and
        // failing later at the typed-site check.
        let max_links = self.budget.limits.max_links;
        let live_links = self.link_count();
        {
            let legacy_need = admitted
                .len()
                .checked_mul(2)
                .ok_or(ObservationGap::LinkLimit)?;
            let typed_need = self
                .typed_startup
                .len()
                .checked_mul(2)
                .ok_or(ObservationGap::LinkLimit)?;
            let planned = legacy_need
                .checked_add(typed_need)
                .ok_or(ObservationGap::LinkLimit)?;
            if live_links
                .checked_add(planned)
                .ok_or(ObservationGap::LinkLimit)?
                > max_links
            {
                if let Some(owner) = self.source_owner.as_mut() {
                    owner.note_refusal(format!(
                        "link budget refused: {live_links} live + {planned} planned exceeds {max_links}",
                    ));
                    owner.refuse_acquisition();
                }
                return Err(ObservationGap::LinkLimit);
            }
        }
        // Gate-open through the legacy registrations: every legacy
        // capability lists first, but READY publishes only after every
        // typed capability lists, so one terminal READY completes the
        // whole set. Any phase failure refuses the order before
        // returning; multi-attachment failures name their claim.
        let prepared = {
            let owner = self
                .source_owner
                .as_mut()
                .ok_or(ObservationGap::Invalidated)?;
            let budget = &self.budget;
            // Per-pair live accounting for the registration loop below:
            // the upfront order check passed, and each adopted pair grows
            // the live count by exactly two, so the loop re-checks before
            // creating each pair (defense in depth, no TOCTOU window).
            let mut live_links = live_links;
            (|| {
                owner.note_gate_open_observed()?;
                let domain = owner.arm_domain(admitted[0].tgid)?;
                let host_key = owner.enroll_observer()?;
                let mut scopes = Vec::with_capacity(admitted.len());
                for a in admitted {
                    if cancel.load(std::sync::atomic::Ordering::Relaxed)
                        || Instant::now() >= deadline
                    {
                        return Err(ObservationGap::SnapshotLag);
                    }
                    budget.checkpoint()?;
                    scopes.push(super::source_owner::RequestScope {
                        site_cookie: a.site_cookie,
                        host_key,
                        incarnation: domain.incarnation,
                        planned_image: domain.planned,
                        link_offset: a.link_offset,
                        target_pid: a.tgid,
                        target: a.target,
                        expected_artifact: a.expected_artifact,
                    });
                }
                let anchor = match owner.anchor_source(&scopes[0], budget, candidate) {
                    Ok(anchor) => anchor,
                    Err(error) => {
                        if scopes.len() > 1 {
                            owner.context_last_error(&format!(
                                "attachment 1/{} cookie {} offset {:#x} anchor",
                                scopes.len(),
                                scopes[0].site_cookie,
                                scopes[0].link_offset,
                            ));
                        }
                        return Err(error);
                    }
                };
                let mut registrations = Vec::with_capacity(scopes.len());
                for (index, scope) in scopes.iter().enumerate() {
                    if cancel.load(std::sync::atomic::Ordering::Relaxed)
                        || Instant::now() >= deadline
                    {
                        return Err(ObservationGap::SnapshotLag);
                    }
                    budget.checkpoint()?;
                    // ER-S2-I1: the legacy loop checks `max_links` before
                    // creating each pair; an over-limit order refuses here
                    // instead of adopting excess links.
                    if live_links.checked_add(2).ok_or(ObservationGap::LinkLimit)? > max_links {
                        owner.note_refusal(format!(
                            "link budget refused: attachment {}/{} needs 2 more within {max_links}",
                            index + 1,
                            scopes.len(),
                        ));
                        return Err(ObservationGap::LinkLimit);
                    }
                    match owner.register_entry_return(scope, entry_prog, return_prog, &anchor) {
                        Ok(registration) => {
                            registrations.push(registration);
                            live_links = live_links.saturating_add(2);
                        }
                        Err(error) => {
                            if scopes.len() > 1 {
                                owner.context_last_error(&format!(
                                    "attachment {}/{} cookie {} offset {:#x} register",
                                    index + 1,
                                    scopes.len(),
                                    scope.site_cookie,
                                    scope.link_offset,
                                ));
                            }
                            return Err(error);
                        }
                    }
                }
                let typed = super::source_owner::TypedAcquisitionScope {
                    anchor,
                    host_key,
                    incarnation: domain.incarnation,
                    planned_image: domain.planned,
                };
                Ok((scopes, domain, host_key, anchor, registrations, typed))
            })()
        };
        let (scopes, domain, host_key, anchor, registrations, typed) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                if let Some(owner) = self.source_owner.as_mut() {
                    owner.refuse_acquisition();
                }
                return Err(error);
            }
        };
        // Typed exports join the same order while the child is still held:
        // admit, register and READY every retained typed site before
        // release, so no fetch can fire unadmitted. A typed refusal fails
        // the whole acquisition (partial authority is worse than none).
        if self.acquire_typed_sites(&typed, deadline, cancel).is_err() {
            if let Some(owner) = self.source_owner.as_mut() {
                owner.refuse_acquisition();
            }
            return Err(ObservationGap::AttachFailed);
        }
        // Terminal legacy READY: the last legacy attachment completes the
        // full listed set (legacy + typed); earlier legacy attachments
        // publish per-capability READYs first. Only now may the held
        // child release.
        let owner = self
            .source_owner
            .as_mut()
            .ok_or(ObservationGap::Invalidated)?;
        let result = (|| {
            let mut sequences = Vec::with_capacity(scopes.len());
            for (index, (scope, registration)) in
                scopes.iter().zip(registrations.iter()).enumerate()
            {
                let last = index + 1 == scopes.len();
                let sequence = if last {
                    owner.publish_ready(scope, &anchor, registration)
                } else {
                    owner.publish_capability_ready(scope, &anchor, registration)
                };
                let sequence = match sequence {
                    Ok(sequence) => sequence,
                    Err(error) => {
                        if scopes.len() > 1 {
                            owner.context_last_error(&format!(
                                "attachment {}/{} cookie {} offset {:#x} ready",
                                index + 1,
                                scopes.len(),
                                scope.site_cookie,
                                scope.link_offset,
                            ));
                        }
                        return Err(error);
                    }
                };
                sequences.push(sequence);
            }
            if !owner.acquisition_ready() {
                return Err(ObservationGap::Invalidated);
            }
            let first = &scopes[0];
            Ok(super::source_owner::SourceAcquisitionReceipts {
                host_key,
                site_cookie: first.site_cookie,
                link_offset: first.link_offset,
                domain,
                anchor,
                registration: registrations[0],
                ready_sequence: sequences[0],
                adopted_links: owner.adopted_link_count(),
                attachments: scopes
                    .iter()
                    .zip(registrations.iter())
                    .zip(sequences.iter())
                    .map(|((scope, registration), sequence)| {
                        super::source_owner::AttachmentEstablished {
                            site_cookie: scope.site_cookie,
                            link_offset: scope.link_offset,
                            anchor,
                            registration: *registration,
                            ready_sequence: *sequence,
                        }
                    })
                    .collect(),
                acquisition_buffers: acquisition_reservation.take(),
            })
        })();
        if result.is_err() {
            owner.refuse_acquisition();
        }
        result
    }

    /// Lease-gated planned-exec mirror. Disabled: Ok(0), zero effects.
    /// Enabled: refuses unless the kernel row already shows the ACTIVE
    /// transition to the planned image; returns the mirrored state.
    pub(crate) fn note_source_exec(
        &mut self,
        lease: &super::source_owner::SourceAcquisitionLease,
        tgid: u32,
        planned_image: u64,
    ) -> Result<u64, ObservationGap> {
        match lease {
            super::source_owner::SourceAcquisitionLease::Disabled => Ok(0),
            super::source_owner::SourceAcquisitionLease::Enabled(_) => self
                .source_owner
                .as_mut()
                .ok_or(ObservationGap::Invalidated)?
                .note_exec_transition(tgid, planned_image),
        }
    }

    /// Native-qualification diagnostic passthrough. Test-called only:
    /// production close paths land with 5B activation.
    #[allow(dead_code)]
    pub(crate) fn source_error(&mut self) -> Option<String> {
        self.source_owner
            .as_mut()
            .and_then(|owner| owner.take_last_error())
    }
    /// Post-hoc pre-open enablement receipts. Test-called only.
    #[allow(dead_code)]
    pub(crate) fn roots_enabled_receipts(&self) -> Option<super::source_owner::RootsEnabled> {
        self.source_owner
            .as_ref()
            .and_then(|owner| owner.roots_enabled_receipts())
    }
    /// Explicit test-driven source close. Test-called only: production
    /// close paths land with 5B activation.
    #[allow(dead_code)]
    pub(crate) fn close_source_explicit(
        &mut self,
    ) -> Option<super::source_owner::SourceCloseReceipts> {
        self.source_owner.as_mut().map(|owner| owner.close_source())
    }

    /// Sealed public-export capability: static table shapes never grant an ABI.
    /// `Create` prearms the full legacy configuration with its producer
    /// links (production + legacy natives). `Reserve` mints the same
    /// configuration (cookie, config/member rows, API ownership) but creates
    /// no producer links: each attachment's required pair is acquired after
    /// admission opens by the source-acquisition path, from its own
    /// retained site.
    /// Enabled source acquisition refuses attachments that already carry
    /// legacy producer links, so the two plans cannot mix on one site.
    pub(crate) fn prearm_startup(
        &mut self,
        sites: Vec<super::objects::StartupApiSite>,
        deadline: Instant,
        cancel: &std::sync::atomic::AtomicBool,
        links: PrearmLinks,
    ) -> Result<(), ObservationGap> {
        if self.final_drain || !self.gate.admitting() {
            return Err(ObservationGap::Invalidated);
        }
        let mut resolved = Vec::new();
        for site in sites {
            let (api, site) = site.into_parts();
            let id = (1..=16)
                .chain(20..=72)
                .find(|&id| wire::api(id) == Ok(api))
                .ok_or(ObservationGap::InvalidWire)?;
            let key = role_site(site.pid(), site.starttime(), &site);
            self.roles.observe(key, id, &self.budget)?;
            resolved.push((id, site));
        }
        if let Some(pid) = resolved.iter().find_map(|(api, site)| {
            (!self
                .roles
                .accepts(role_site(site.pid(), site.starttime(), site), *api))
            .then_some(site.pid())
        }) {
            self.retire(pid, &mut ObservationBatch::default());
            return Err(ObservationGap::AmbiguousSite);
        }
        let generation = if let Some(a) = resolved
            .first()
            .and_then(|(_, s)| self.startup.get(&s.pid()))
            .and_then(|rows| rows.first())
        {
            a.generation
        } else {
            let generation = self.next_generation;
            self.next_generation = self
                .next_generation
                .checked_add(1)
                .ok_or(ObservationGap::ProcessLimit)?;
            generation
        };
        // Filter to the exact new attachments first, so the complete-order
        // link reservation below neither double-counts duplicates nor
        // leaves a partial prearm on refusal (ER-S2-I1).
        let mut to_add = Vec::with_capacity(resolved.len());
        for (api, site) in resolved {
            let pid = site.pid();
            if self
                .startup
                .get(&pid)
                .is_some_and(|rows| rows.iter().any(|a| a.historical))
            {
                return Err(ObservationGap::Invalidated);
            }
            if !self
                .roles
                .accepts(role_site(pid, site.starttime(), &site), api)
            {
                continue;
            }
            if self
                .startup
                .get(&pid)
                .is_some_and(|rows| rows.iter().any(|a| same_site(&a.site, &site)))
            {
                continue;
            }
            to_add.push((api, site));
        }
        // Reserve the complete prearm order before any effect: live links
        // plus planned reserve pairs plus this batch must fit `max_links`.
        let need = to_add
            .len()
            .checked_mul(2)
            .ok_or(ObservationGap::LinkLimit)?;
        if self
            .link_pressure()
            .checked_add(need)
            .ok_or(ObservationGap::LinkLimit)?
            > self.budget.limits.max_links
        {
            return Err(ObservationGap::LinkLimit);
        }
        for (api, site) in to_add {
            if cancel.load(std::sync::atomic::Ordering::Relaxed) || Instant::now() >= deadline {
                return Err(ObservationGap::SnapshotLag);
            }
            let pid = site.pid();
            let advertisers = if api == c::PROVIDER_INIT {
                vec![site.object_hash().clone()]
            } else {
                Vec::new()
            };
            let a = self.attach_pair(
                pid,
                api,
                site,
                advertisers,
                0,
                generation,
                matches!(links, PrearmLinks::Create),
            )?;
            retain_and_arm(&mut self.startup, pid, a, |a| {
                let result = validate_then_arm(
                    || a.site.revalidate_object(),
                    || {
                        self.config
                            .insert(
                                a.cookie,
                                c::Config {
                                    generation,
                                    object: a.object,
                                    pid,
                                    api,
                                },
                                0,
                            )
                            .map_err(|_| ObservationGap::AttachFailed)?;
                        self.members
                            .insert(
                                pid,
                                c::Member {
                                    generation,
                                    epoch: 1,
                                    range_count: 0,
                                    reserved: 0,
                                },
                                0,
                            )
                            .map_err(|_| ObservationGap::AttachFailed)
                    },
                );
                if result.is_err() {
                    let _ = self.config.remove(&a.cookie);
                }
                result
            })?;
        }
        Ok(())
    }
    pub fn close(self) -> ObservationBatch {
        self.close_until(Instant::now() + Duration::from_millis(100))
    }
    pub(crate) fn close_until(mut self, deadline: Instant) -> ObservationBatch {
        self.finalize_until(deadline)
    }
    // The combined physical/metadata owner keeps this session alive through
    // its physical snapshot; standalone close disposes only after this returns.
    pub(crate) fn finalize_until(&mut self, deadline: Instant) -> ObservationBatch {
        self.final_drain = true;
        if self.gate.close().is_err() {
            let mut b = ObservationBatch::default();
            b.gap(ObservationGap::BpfUnavailable);
            b.gap(ObservationGap::IntervalUnknown);
            return b;
        }
        // Store the receipt in the shared owner before fallible drain/read.
        // Final decoding uses its own bounded budget, not the expired live tick.
        self.budget.set_deadline(deadline);
        let mut b = self.drain(deadline);
        b.gap(ObservationGap::IntervalUnknown); // in-flight returns are not synthesized
        for (&cookie, &(pid, starttime, api)) in &self.api_owners {
            let values = if Instant::now() >= deadline {
                Err(ObservationGap::DrainOverrun)
            } else {
                self.api_totals
                    .get(&cookie, 0)
                    .map_err(|_| ObservationGap::InvalidWire)
            };
            match values.and_then(|values| {
                let mut total = c::ApiAggregate::default();
                for v in values.iter() {
                    macro_rules! sum {
                        ($field:ident) => {
                            total.$field = total
                                .$field
                                .checked_add(v.$field)
                                .ok_or(ObservationGap::InvalidWire)?;
                        };
                    }
                    sum!(entries);
                    sum!(success);
                    sum!(failure);
                    sum!(mismatch);
                    sum!(unsupported);
                    sum!(unsupported_return);
                    sum!(map);
                    sum!(depth);
                    sum!(unpaired);
                }
                wire::activity(api, total)
            }) {
                Ok(row) => b.api_activity.push(ProcessApiActivity {
                    pid,
                    starttime,
                    row,
                }),
                Err(gap) => {
                    b.gap(gap);
                    if let Ok(api) = crate::api_activity::ApiId::try_from(api) {
                        let mut row = crate::api_activity::ApiActivityRow::unavailable(api);
                        row.gaps.not_attached = false;
                        row.gaps.map = 1;
                        b.api_activity.push(ProcessApiActivity {
                            pid,
                            starttime,
                            row,
                        });
                    }
                }
            }
        }
        self.closed = true;
        b
    }
}
impl Drop for ProviderSession {
    fn drop(&mut self) {
        if self.final_drain || !self.gate.admitting() {
            for a in self
                .startup
                .values_mut()
                .flatten()
                .chain(self.targets.values_mut().flat_map(|t| &mut t.attachments))
            {
                a.links.clear();
            }
            return;
        }
        let pids: Vec<_> = self
            .targets
            .keys()
            .chain(self.startup.keys())
            .copied()
            .collect();
        let mut b = ObservationBatch::default();
        for pid in pids {
            self.retire(pid, &mut b)
        }
    }
}
fn acquire_observable(
    record: &inventory::ProcessRecord,
    budget: &mut ObservationBudget,
) -> Result<Option<VerifiedProcess>, ObservationGap> {
    // Inventory has already classified dynamic code exports. Names, build IDs,
    // dependencies and non-observable exports cannot authorize acquisition.
    // A later snapshot is evaluated afresh, so late module arrival can retry.
    if !record.modules.iter().any(|module| {
        module.info.exports.iter().any(|api| {
            api.operational_id().is_some()
                || (1..=16).any(|id| wire::api(id) == Ok(ObservationApi::Inventoried(*api)))
        })
    }) {
        return Ok(None);
    }
    acquire(record, budget).map(Some)
}

pub(crate) fn assemble_payload(
    event: wire::Transport,
    aliases: &mut super::assembly::Sequences,
    budget: &ObservationBudget,
    b: &mut ObservationBatch,
) -> Option<ObservationPayload> {
    let r = event.record();
    Some(match event {
        wire::Transport::Begin(r) => {
            if let Err(g) = aliases.begin(&r, budget) {
                invalidate_algorithms(b);
                b.gap(g);
            }
            return None;
        }
        wire::Transport::Alias(r) => {
            if let Err(g) = aliases.alias(&r) {
                invalidate_algorithms(b);
                b.gap(g);
            }
            return None;
        }
        wire::Transport::End(r) => {
            let (algorithm, alias_quality) = match aliases.end(&r) {
                Ok((algorithm, status, weak)) => {
                    match status {
                        2 | 3 => b.gap(ObservationGap::DispatchPartial),
                        4 => b.gap(ObservationGap::TargetReadFailed),
                        _ => (),
                    }
                    (algorithm, AliasQuality::from_fold(status, weak))
                }
                Err(g) => {
                    invalidate_algorithms(b);
                    b.gap(g);
                    (super::assembly::other(), AliasQuality::default())
                }
            };
            wire::algorithm_event(r, algorithm, alias_quality).into_payload()
        }
        wire::Transport::Event(event) => {
            if r.kind == c::INVALIDATION {
                aliases.retire(r.pid);
            }
            let mut payload = event.into_payload();
            if let ObservationPayload::Implementation {
                algorithm,
                alias_quality,
                ..
            } = &mut payload
            {
                (*algorithm, *alias_quality) = aliases.implementation(&r).unwrap_or_else(|g| {
                    b.gap(g);
                    (super::assembly::other(), AliasQuality::default())
                });
            }
            payload
        }
    })
}

fn invalidate_algorithms(batch: &mut ObservationBatch) {
    for fact in &mut batch.facts {
        match &mut fact.payload {
            ObservationPayload::Algorithm {
                algorithm,
                alias_quality,
                ..
            }
            | ObservationPayload::Implementation {
                algorithm,
                alias_quality,
                ..
            } => {
                *algorithm = super::assembly::other();
                alias_quality.status = AliasStatus::Unavailable
            }
            _ => (),
        }
    }
    for site in &mut batch.learned_sites {
        site.algorithm = super::assembly::other();
        site.alias_quality.status = AliasStatus::Unavailable;
    }
}
fn order_ranges(mut ranges: Vec<(u64, u64)>) -> Result<Vec<(u64, u64)>, ObservationGap> {
    if ranges.len() > c::MAX_RANGES as usize {
        return Err(ObservationGap::SiteLimit);
    }
    if ranges.iter().any(|&(start, end)| start >= end) {
        return Err(ObservationGap::MalformedMaps);
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(ObservationGap::AmbiguousSite);
    }
    Ok(ranges)
}
fn identity_failure(gap: ObservationGap) -> bool {
    matches!(
        gap,
        ObservationGap::ProcessUnavailable
            | ObservationGap::ProcessChanged
            | ObservationGap::NamespaceChanged
            | ObservationGap::ObjectChanged
            | ObservationGap::IdentityUnverified
            | ObservationGap::BackingUnavailable
    )
}
/// Budget gaps that can genuinely clear between ticks when retiring a
/// live target, so a preserved incarnation may retry next tick: reads
/// refill through the retire-time release and are consumed gradually,
/// deadlines refresh every tick, and fact/scratch pressure releases
/// with the target (a StateLimit re-add refits the same attach that fit
/// before). Everything else stays terminal for the incarnation:
/// identity changes no longer describe the pid, and deterministic faults
/// (symbols, attach, membership) would burn a full re-acquisition every
/// tick without ever clearing. Add-target failures use the same rule:
/// a failed add may already have emitted statics this pass (or resume a
/// deferred target that emitted earlier), so Count may pin the admission;
/// when nothing is pinned the preserved re-add refits deterministically.
fn transient_budget_gap(gap: ObservationGap) -> bool {
    matches!(
        gap,
        ObservationGap::ReadLimit | ObservationGap::SnapshotLag | ObservationGap::StateLimit
    )
}
fn arm_attachment(
    config: &mut BpfMap<MapData, u64, c::Config>,
    process: &VerifiedProcess,
    a: &Attachment,
    pid: u32,
    generation: u64,
) -> Result<(), ObservationGap> {
    let result = validate_then_arm(
        || {
            // Fence, not a hot check: both the pre- and post-arm proofs
            // must run full (a memoized pass would stamp the pre-arm
            // check and always skip the post-arm one).
            process.revalidate_fresh()?;
            a.site.revalidate_object()
        },
        || {
            config
                .insert(
                    a.cookie,
                    c::Config {
                        generation,
                        object: a.object,
                        pid,
                        api: a.api,
                    },
                    0,
                )
                .map_err(|_| ObservationGap::AttachFailed)
        },
    );
    if result.is_err() {
        let _ = config.remove(&a.cookie);
    }
    result
}
fn disarm_links(
    links: Vec<OwnedFd>,
    disarm: impl FnOnce() -> Result<(), ObservationGap>,
) -> Result<(), ObservationGap> {
    let result = disarm();
    drop(links);
    result
}
fn disarm_site(
    target: &mut Target,
    site: &VerifiedSite,
    config: &mut BpfMap<MapData, u64, c::Config>,
) -> Result<(), ObservationGap> {
    let mut failed = false;
    while let Some(index) = target
        .attachments
        .iter()
        .position(|a| same_site(&a.site, site))
    {
        let a = target.attachments.swap_remove(index);
        // Both links close after disarming even if map deletion fails; the
        // caller then retires process membership. Keep site custody until closure.
        if disarm_links(a.links, || {
            config
                .remove(&a.cookie)
                .map_err(|_| ObservationGap::AttachFailed)
        })
        .is_err()
        {
            failed = true
        }
    }
    if failed {
        Err(ObservationGap::AttachFailed)
    } else {
        Ok(())
    }
}
fn merge_candidates(
    existing: &mut Vec<ObjectHash>,
    incoming: Vec<ObjectHash>,
    budget: &ObservationBudget,
) -> Result<(), ObservationGap> {
    let additional = incoming
        .iter()
        .filter(|hash| !existing.contains(hash))
        .count();
    budget.state(
        additional
            .checked_mul(96)
            .ok_or(ObservationGap::StateLimit)?,
    )?;
    for hash in incoming {
        if !existing.contains(&hash) {
            existing.push(hash)
        }
    }
    Ok(())
}
fn paired_links(
    entry: impl FnOnce() -> Result<OwnedFd, ObservationGap>,
    ret: impl FnOnce() -> Result<OwnedFd, ObservationGap>,
) -> Result<Vec<OwnedFd>, ObservationGap> {
    let entry = entry()?;
    let ret = ret()?;
    Ok(vec![entry, ret])
}
fn same_site(a: &VerifiedSite, b: &VerifiedSite) -> bool {
    a.native_device() == b.native_device()
        && a.inode() == b.inode()
        && a.file_offset() == b.file_offset()
}
fn object_id(site: &VerifiedSite) -> u64 {
    // Observer-local identity, not a target opaque pointer. Same file object's fd
    // stays alive throughout attachments and is stable across its public APIs.
    site.attachment_fd().as_raw_fd() as u64
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore = "requires privileged BPF and fresh observation object"]
    fn native_final_cut_delete_failure_read_failure_and_expired_drain() {
        let object =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        for mode in ["delete", "read", "deadline"] {
            let mut session = ProviderSession::open_budgeted(
                ObservationBudget::new(ObservationLimits::default()),
                &object,
            )
            .unwrap();
            // Retain a real final consumer but deliberately omit its safe API
            // aggregate: this makes the actual post-cut map lookup return ENOENT.
            session.api_owners.insert(91, (std::process::id(), 1, 20));
            if mode == "delete" {
                session.gate.fail_next_delete();
            }
            let deadline = if mode == "deadline" {
                Instant::now()
            } else {
                Instant::now() + Duration::from_secs(2)
            };
            let result = session.finalize_until(deadline);
            assert_eq!(
                session.api_owners.len(),
                1,
                "final failure discarded its owner"
            );
            if mode == "delete" {
                assert!(session.gate.receipt().is_none());
                assert!(!session.closed);
                assert!(result.gaps.contains(&ObservationGap::BpfUnavailable));
                assert!(result.api_activity.is_empty());
                assert!(session.gate.close().is_err());
            } else {
                let receipt = session
                    .gate
                    .receipt()
                    .expect("successful native deletion survives read failure");
                assert!(session.closed);
                assert_eq!(session.gate.close().unwrap(), receipt);
                assert!(result.gaps.contains(&if mode == "read" {
                    ObservationGap::InvalidWire
                } else {
                    ObservationGap::DrainOverrun
                }));
                assert_eq!(result.api_activity.len(), 1);
                assert_eq!(result.api_activity[0].row.gaps.map, 1);
            }
            assert!(session.gate.open().is_err());
            eprintln!(
                "native_final_failure={mode} receipt={} owners_retained=1",
                session.gate.receipt().is_some()
            );
        }
    }
    #[test]
    fn live_algorithm_identity_separates_thread_local_invocations() {
        use super::super::static_tables::DynamicAlgorithmId;
        let object: ObjectHash = "a".repeat(64).try_into().unwrap();
        let first = c::Record {
            pid: 101,
            tid: 102,
            generation: 3,
            cookie: 4,
            invocation: 1,
            operation: 50001,
            algorithm_index: 0,
            algorithm: c::OTHER,
            function: 70001,
            ..Default::default()
        };
        let other_thread = c::Record { tid: 103, ..first };
        assert_ne!(
            DynamicAlgorithmId::observed(&object, 20, &first),
            DynamicAlgorithmId::observed(&object, 20, &other_thread),
            "different threads' first unknown rows must not collapse"
        );
    }

    #[test]
    fn live_algorithm_identity_unifies_functions_of_one_observed_row() {
        use super::super::static_tables::DynamicAlgorithmId;
        let object: ObjectHash = "a".repeat(64).try_into().unwrap();
        let first = c::Record {
            pid: 101,
            tid: 102,
            generation: 3,
            cookie: 4,
            invocation: 1,
            operation: 50001,
            algorithm_index: 0,
            algorithm: c::OTHER,
            function: 2,
            monotonic_ns: 30,
            code: 0x1000,
            ..Default::default()
        };
        let next_function = c::Record {
            function: 70001,
            monotonic_ns: 31,
            code: 0x2000,
            ..first
        };
        assert_eq!(
            DynamicAlgorithmId::observed(&object, 20, &first),
            DynamicAlgorithmId::observed(&object, 20, &next_function),
            "function, timestamp and callback address do not split one algorithm row"
        );
    }
    #[test]
    fn candidate_membership_accepts_current_return_after_lease_invalidation() {
        for epoch in [0, 1] {
            let member = c::Member {
                generation: 7,
                epoch,
                ..Default::default()
            };
            assert_eq!(
                validate_candidate_member(&member, 7),
                Ok(()),
                "epoch {epoch}"
            );
            assert_eq!(
                validate_candidate_member(&member, 8),
                Err(ObservationGap::MembershipUnknown)
            );
        }
        for epoch in [2, u64::MAX] {
            let member = c::Member {
                generation: 7,
                epoch,
                ..Default::default()
            };
            assert_eq!(
                validate_candidate_member(&member, 7),
                Err(ObservationGap::MembershipUnknown)
            );
        }
    }
    #[test]
    fn reconcile_preserves_membership_and_revalidation_retirement_causes() {
        assert_eq!(
            reconcile_retirement_gap(None, 4, || panic!("missing membership must not revalidate")),
            Some(ObservationGap::MembershipUnknown)
        );
        assert_eq!(
            reconcile_retirement_gap(Some(5), 4, || panic!(
                "recycled membership must not revalidate"
            )),
            Some(ObservationGap::ProcessChanged)
        );
        for gap in [
            ObservationGap::ProcessChanged,
            ObservationGap::NamespaceChanged,
            ObservationGap::ObjectChanged,
            ObservationGap::IdentityUnverified,
        ] {
            assert_eq!(reconcile_retirement_gap(Some(4), 4, || Err(gap)), Some(gap));
        }
        assert_eq!(reconcile_retirement_gap(Some(4), 4, || Ok(())), None);
    }

    use super::*;
    #[test]
    fn no_source_snapshots_preserve_admission_for_late_source() {
        let mut record: inventory::ProcessRecord = serde_json::from_value(serde_json::json!({
            "interval": {"started_unix_ms": null, "finished_unix_ms": null, "elapsed_ns": 1},
            "namespaces": {"pid": null, "mount": null}, "pid": 0, "starttime": 0,
            "modules": [], "provider_activation": "unknown", "provider_interfaces": "unknown",
            "execution": "not_observed"
        }))
        .unwrap();
        let mut budget = ObservationBudget::new(ObservationLimits {
            max_processes: 1,
            ..Default::default()
        });
        for pid in 0..80 {
            record.pid = pid;
            for _ in 0..30 {
                assert!(matches!(acquire_observable(&record, &mut budget), Ok(None)));
            }
        }
        record.pid = 0; // Observable exports now authorize exactly one attempted acquisition.
        record.modules = vec![inventory::ModuleRecord {
            info: inventory::ModuleInfo {
                sha256: "a".repeat(64),
                device: 0,
                inode: 0,
                size_bytes: 0,
                architecture: inventory::Architecture::X86_64,
                kind: inventory::ObjectKind::Other,
                exports: vec![
                    inventory::Api::OpenSslInitCrypto,
                    inventory::Api::OpenSslVersionMajor,
                ],
                depends_on_libcrypto: true,
                depends_on_libssl: false,
            },
            identity_status: inventory::IdentityStatus::Verified,
        }];
        assert!(matches!(acquire_observable(&record, &mut budget), Ok(None)));
        assert_eq!(budget.elf_read_bytes(), 0);
        budget.state(budget.limits.max_state_bytes).unwrap();
        // None of the no-source snapshots consumed state or process admission.
        record.modules[0]
            .info
            .exports
            .push(inventory::Api::OsslProviderGet0Dispatch);
        assert!(matches!(
            acquire_observable(&record, &mut budget),
            Err(ObservationGap::ProcessUnavailable)
        ));
        assert!(matches!(
            acquire_observable(&record, &mut budget),
            Err(ObservationGap::ProcessUnavailable)
        ));
    }

    #[test]
    fn queue_loss_downgrades_already_drained_algorithm_facts() {
        let known = AlgorithmId::try_from(0).unwrap();
        let mut batch = ObservationBatch::default();
        for payload in [
            ObservationPayload::Algorithm {
                algorithm: known,
                alias_quality: AliasQuality {
                    status: AliasStatus::Mixed,
                    weak: true,
                },
                cacheability: Cacheability::Cacheable,
            },
            ObservationPayload::Implementation {
                algorithm: known,
                alias_quality: AliasQuality {
                    status: AliasStatus::Mixed,
                    weak: true,
                },
                function: FunctionIdentity::new(Operation::Other, 0).unwrap(),
                cacheability: Cacheability::Cacheable,
                advertiser_candidates: Vec::new(),
                backing_sha256: None,
            },
        ] {
            batch.facts.push(ObservationFact {
                pid: 1,
                starttime: 2,
                object_sha256: "a".repeat(64).try_into().unwrap(),
                generation: 3,
                context: ContextIdentity::Unknown {},
                source: ObservationSource::ProviderQuery,
                api: ObservationApi::ProviderQueryCallback,
                operation: Operation::Other,
                class: AlgorithmClass::Other,
                monotonic_ns: 4,
                confidence: ScopeConfidence::Observed,
                payload,
            });
        }
        invalidate_algorithms(&mut batch);
        for fact in batch.facts {
            let (algorithm, quality) = match fact.payload {
                ObservationPayload::Algorithm {
                    algorithm,
                    alias_quality,
                    ..
                }
                | ObservationPayload::Implementation {
                    algorithm,
                    alias_quality,
                    ..
                } => (algorithm, alias_quality),
                _ => unreachable!(),
            };
            assert_eq!(algorithm, super::super::assembly::other());
            assert_eq!(quality.status, AliasStatus::Unavailable);
            assert!(quality.weak);
        }
    }

    #[test]
    fn role_conflicts_retire_both_discovery_orders_and_cannot_rearm() {
        for (first, second) in [
            (c::QUERY_CALLBACK, c::UNQUERY_CALLBACK),
            (c::UNQUERY_CALLBACK, c::QUERY_CALLBACK),
            (c::PUBLIC_QUERY, c::PUBLIC_UNQUERY),
            (c::PUBLIC_UNQUERY, c::PUBLIC_QUERY),
        ] {
            let mut roles = Roles::default();
            let key = [1, 2, 3, 4, 5];
            let budget = ObservationBudget::default();
            assert_eq!(roles.observe(key, first, &budget), Ok(true));
            assert!(roles.accepts(key, first));
            assert_eq!(roles.observe(key, second, &budget), Ok(false));
            assert!(
                !roles.accepts(key, first),
                "retired-cookie queued records must not be accepted"
            );
            assert!(!roles.accepts(key, second));
            assert_eq!(roles.observe(key, first, &budget), Ok(false));
            assert_eq!(roles.observe(key, second, &budget), Ok(false));
            assert_eq!(roles.0.len(), 1);
        }
    }
    #[test]
    fn conflict_disarm_closes_both_links_even_on_map_failure() {
        use std::{io::Read, os::unix::net::UnixStream};
        for fail in [false, true] {
            let mut peers = Vec::new();
            let mut links = Vec::new();
            for _ in 0..2 {
                let (link, peer) = UnixStream::pair().unwrap();
                peer.set_nonblocking(true).unwrap();
                peers.push(peer);
                links.push(OwnedFd::from(link));
            }
            let raw: Vec<_> = links.iter().map(AsRawFd::as_raw_fd).collect();
            let result = disarm_links(links, || {
                for &fd in &raw {
                    assert!(unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0);
                }
                if fail {
                    Err(ObservationGap::AttachFailed)
                } else {
                    Ok(())
                }
            });
            assert_eq!(result.is_err(), fail);
            // EOF proves these exact owned endpoints closed, even if another
            // parallel test has already reused their descriptor numbers.
            for mut peer in peers {
                assert_eq!(peer.read(&mut [0]).unwrap(), 0);
            }
        }
    }
    #[test]
    fn conflict_markers_are_bounded_and_survive_admission_exhaustion() {
        let budget = ObservationBudget::new(ObservationLimits {
            max_learned_sites: 1,
            ..Default::default()
        });
        let mut roles = Roles::default();
        let key = [1, 2, 3, 4, 5];
        assert_eq!(roles.observe(key, c::QUERY_CALLBACK, &budget), Ok(true));
        assert_eq!(
            roles.observe([2, 2, 3, 4, 5], c::QUERY_CALLBACK, &budget),
            Err(ObservationGap::SiteLimit)
        );
        assert_eq!(roles.observe(key, c::UNQUERY_CALLBACK, &budget), Ok(false));
        assert!(!roles.accepts(key, c::QUERY_CALLBACK));
        assert_eq!(roles.0.len(), 1);
    }
    #[test]
    fn post_arm_maps_change_fails_the_transaction() {
        let calls = std::cell::RefCell::new(Vec::new());
        let count = std::cell::Cell::new(0);
        let result = validate_then_arm(
            || {
                calls.borrow_mut().push("validate");
                count.set(count.get() + 1);
                if count.get() == 2 {
                    Err(ObservationGap::ProcessChanged)
                } else {
                    Ok(())
                }
            },
            || {
                calls.borrow_mut().push("arm");
                Ok(())
            },
        );
        assert_eq!(result, Err(ObservationGap::ProcessChanged));
        assert_eq!(*calls.borrow(), vec!["validate", "arm", "validate"]);
    }
    #[test]
    fn changed_maps_between_pair_and_arm_never_activate_config() {
        let armed = std::cell::Cell::new(false);
        assert_eq!(
            validate_then_arm(
                || Err(ObservationGap::ProcessChanged),
                || {
                    armed.set(true);
                    Ok(())
                }
            ),
            Err(ObservationGap::ProcessChanged)
        );
        assert!(
            !armed.get(),
            "CONFIG became live before full post-pair validation"
        );
    }
    #[test]
    fn successful_arm_has_pre_and_post_full_validation() {
        let calls = std::cell::RefCell::new(Vec::new());
        validate_then_arm(
            || {
                calls.borrow_mut().push("validate");
                Ok(())
            },
            || {
                calls.borrow_mut().push("arm");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(*calls.borrow(), vec!["validate", "arm", "validate"]);
    }
    #[test]
    fn range_search_matches_actual_executable_maps_and_eight_lookup_bound() {
        let text = std::fs::read_to_string("/proc/self/maps").unwrap();
        let mut ranges = Vec::new();
        for line in text.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields[1].as_bytes()[2] != b'x' || fields[4] == "0" {
                continue;
            }
            let (start, end) = fields[0].split_once('-').unwrap();
            ranges.push((
                u64::from_str_radix(start, 16).unwrap(),
                u64::from_str_radix(end, 16).unwrap(),
            ));
        }
        assert!(!ranges.is_empty());
        assert!(ranges.len() <= 128);
        let oracle = ranges.clone();
        ranges.reverse(); // Task1's priority passes need not preserve address order.
        let sorted = order_ranges(ranges).unwrap();
        assert!(
            sorted.windows(2).all(|pair| pair[0].1 <= pair[1].0),
            "admitted ranges must be sorted and disjoint"
        );
        let mut points = vec![
            0,
            4095,
            4096,
            0xffff_ffff_ffff,
            0x1_0000_0000_0000,
            u64::MAX,
        ];
        for &(start, end) in &oracle {
            points.extend([start - 1, start, start + (end - start) / 2, end - 1, end]);
        }
        for address in points {
            let expected = (4096..=0xffff_ffff_ffff).contains(&address)
                && oracle
                    .iter()
                    .any(|&(start, end)| start <= address && address < end);
            let mut lookups = 0;
            let found = c::code_in_ranges(address, sorted.len() as u32, |index| {
                lookups += 1;
                sorted
                    .get(index as usize)
                    .map(|&(start, end)| c::Range { start, end })
            });
            assert_eq!(
                found, expected,
                "range membership differs from independent linear oracle"
            );
            assert!(
                lookups <= 8,
                "range search exceeded eight lookups: {lookups}"
            );
        }
    }
    #[test]
    fn range_search_all_128_slots_and_boundaries() {
        let ranges: Vec<_> = (0..128u64)
            .map(|index| (4096 + index * 32, 4112 + index * 32))
            .collect();
        for address in 4095..=8192 {
            let expected = ranges
                .iter()
                .any(|&(start, end)| start <= address && address < end);
            let mut calls = 0;
            let found = c::code_in_ranges(address, 128, |index| {
                calls += 1;
                ranges
                    .get(index as usize)
                    .map(|&(start, end)| c::Range { start, end })
            });
            assert_eq!(found, expected);
            assert!(calls <= 8, "range search exceeded eight lookups: {calls}");
        }
    }
    #[test]
    fn range_metadata_count_and_missing_slots_fail_closed() {
        assert_eq!(std::mem::size_of::<c::Member>(), 24);
        for count in [0, 129, u32::MAX] {
            assert!(!c::code_in_ranges(4096, count, |_| panic!(
                "invalid count must not access RANGES"
            )));
        }
        for address in [0, 4095, 0x1_0000_0000_0000, u64::MAX] {
            assert!(!c::code_in_ranges(address, 128, |_| panic!(
                "noncanonical code must not access RANGES"
            )));
        }
        assert!(!c::code_in_ranges(4096, 128, |_| None));
        assert!(c::code_in_ranges(8192, 2, |index| Some(if index == 0 {
            c::Range {
                start: 4096,
                end: 8192,
            }
        } else {
            c::Range {
                start: 8192,
                end: 12288,
            }
        })));
    }
    #[test]
    fn range_admission_refuses_overlaps_and_malformed_intervals() {
        assert!(matches!(
            order_ranges(vec![(4096, 8192), (5000, 6000)]),
            Err(ObservationGap::AmbiguousSite)
        ));
        assert!(order_ranges(vec![(4096, 4096)]).is_err());
        assert!(order_ranges(vec![(8192, 4096)]).is_err());
        assert!(order_ranges(vec![(4096, 8192); 129]).is_err());
        assert_eq!(
            order_ranges(vec![(8192, 12288), (4096, 8192)]).unwrap(),
            vec![(4096, 8192), (8192, 12288)]
        );
    }
    #[test]
    fn same_site_multiple_candidates() {
        let a: ObjectHash = "a".repeat(64).try_into().unwrap();
        let b: ObjectHash = "b".repeat(64).try_into().unwrap();
        let mut advertisers = vec![a.clone()];
        merge_candidates(
            &mut advertisers,
            vec![a.clone(), b.clone()],
            &ObservationBudget::default(),
        )
        .unwrap();
        assert_eq!(advertisers, vec![a, b]);
        let limits = ObservationLimits {
            max_state_bytes: 0,
            ..Default::default()
        };
        let before = advertisers.clone();
        let c: ObjectHash = "c".repeat(64).try_into().unwrap();
        assert_eq!(
            merge_candidates(&mut advertisers, vec![c], &ObservationBudget::new(limits)),
            Err(ObservationGap::StateLimit)
        );
        assert_eq!(advertisers, before);
    }
    #[test]
    fn provider_map_capacity_is_atomic_and_cpu_charged_before_loading() {
        let maps: Vec<_> = specs()
            .into_iter()
            .map(|m| loader::MapSpecLite {
                name: m.name.into(),
                map_type: m.map_type,
                key_size: m.key_size,
                value_size: m.value_size,
                max_entries: m.max_entries,
                flags: m.flags,
            })
            .collect();
        // Independent fixed total for the actual sixteen ordinary provider maps
        // on sixteen possible CPUs, excluding the separately owned ADMIT gate.
        let required = 7_166_360;
        let budget = ObservationBudget::new(ObservationLimits {
            max_state_bytes: required - 1,
            ..Default::default()
        });
        assert_eq!(
            reserve_map_capacity(&budget, &maps, 16),
            Err(ObservationGap::StateLimit)
        );
        budget.state(required - 1).unwrap(); // failed batch did not consume a prefix
        let budget = ObservationBudget::new(ObservationLimits {
            max_state_bytes: required,
            ..Default::default()
        });
        reserve_map_capacity(&budget, &maps, 16).unwrap();
        assert_eq!(budget.state(1), Err(ObservationGap::StateLimit));
        let budget = ObservationBudget::default();
        assert_eq!(
            reserve_map_capacity(&budget, &maps, usize::MAX),
            Err(ObservationGap::StateLimit)
        );
    }

    #[test]
    fn return_link_failure_rolls_back() {
        use std::{io::Read, os::unix::net::UnixStream};
        let (link, mut peer) = UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        let owned = OwnedFd::from(link);
        assert!(paired_links(|| Ok(owned), || Err(ObservationGap::AttachFailed)).is_err());
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }
    fn synthetic_full_preparation() -> loader::Prepared {
        // Mirror of `prepare_object`'s tables: the same root names/sections
        // and the same map names in the same order, so the shared split
        // predicate and the gated allowlist read identical inputs.
        // Instruction bytes stay empty on purpose: these roots must be
        // shape-admissible but never loadable.
        let admit = || loader::MapFixup {
            insn_off: 0,
            map: "ADMIT".to_string(),
        };
        let prog = |name: &str, section: &str, is_return: bool| loader::PreparedProg {
            name: name.to_string(),
            section: section.to_string(),
            is_return,
            insns: Vec::new(),
            map_fixups: vec![admit()],
            subprogs: Vec::new(),
        };
        let progs = [
            prog("observation_entry", "uprobe", false),
            prog("observation_return", "uretprobe", true),
            prog("typed_entry", "uprobe", false),
            prog("typed_return", "uretprobe", true),
        ]
        .into_iter()
        .chain(
            loader::SOURCE_REGISTRATION_PROGS
                .iter()
                .map(|spec| prog(spec.name, spec.section, false)),
        )
        .chain(
            loader::LIFECYCLE_PROGS
                .iter()
                .map(|spec| prog(spec.name, spec.section, false)),
        )
        .collect();
        let maps = specs()
            .into_iter()
            .chain(super::super::source_owner::MAPS)
            .map(|spec| loader::MapSpecLite {
                name: spec.name.to_string(),
                map_type: spec.map_type,
                key_size: spec.key_size,
                value_size: spec.value_size,
                max_entries: spec.max_entries,
                flags: spec.flags,
            })
            .collect();
        loader::Prepared { progs, maps }
    }
    #[test]
    fn caller_compatibility_shared_legacy_split_passes_gated_shape() {
        // Caller-compatibility regression: both native controls once passed
        // the unsplit full preparation to `load_gated`, which refuses the
        // source roots. Every gated consumer must now go through the one
        // shared split. This test runs caps-free with no object file: it
        // proves (a) the shared split partitions the full shape into
        // exactly the legacy roots with every source map removed, (b)
        // `load_gated` refuses the unsplit shape with "ungated producer
        // root" before any kernel effect, and (c) the shared legacy half
        // passes `load_gated`'s shape checks and fails only later, at
        // kernel admission against the fake gate fds. What this cannot
        // prove caps-free is actual kernel load of the legacy half; that
        // is proven by the privileged native controls (`writer_gate` /
        // `writer_gate_native`), which load this same shared legacy shape
        // from real objects. No assertion here may skip: each arm either
        // asserts or panics.
        let full = synthetic_full_preparation();
        assert_eq!(full.maps.len(), 34, "mirror must track the full map shape");
        assert_eq!(full.progs.len(), 8, "mirror must track the full root shape");
        let pool = crate::observation_memory::MemoryPool::new(256 << 20);
        let gate = crate::writer_gate::fake_for_shape_tests(&pool).unwrap();
        match loader::load_gated(&full, &gate) {
            Ok(_) => panic!("unsplit full preparation must be refused by load_gated"),
            Err(error) => assert!(
                format!("{error:?}").contains("ungated producer root"),
                "unsplit refusal must be on shape, got: {error:?}"
            ),
        }
        let (legacy, source) = split_source_preparation(full);
        let legacy_roots: Vec<_> = legacy.progs.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(legacy_roots, ["observation_entry", "observation_return"]);
        assert_eq!(legacy.maps.len(), 16);
        assert_eq!(legacy.maps.iter().filter(|m| m.name == "ADMIT").count(), 1);
        for map in &legacy.maps {
            assert!(
                !super::super::source_owner::MAPS
                    .iter()
                    .any(|spec| spec.name == map.name),
                "legacy half must not retain source map {}",
                map.name
            );
        }
        assert_eq!(source.progs.len(), 6);
        assert_eq!(source.maps.len(), 18);
        for map in &source.maps {
            assert!(
                super::super::source_owner::MAPS
                    .iter()
                    .any(|spec| spec.name == map.name),
                "source half must hold only source maps, got {}",
                map.name
            );
        }
        match loader::load_gated(&source, &gate) {
            Ok(_) => panic!("source half without ADMIT must be refused by load_gated"),
            Err(error) => assert!(
                format!("{error:?}").contains("missing shared writer map"),
                "source-half refusal must be on shape, got: {error:?}"
            ),
        }
        match loader::load_gated(&legacy, &gate) {
            Ok(_) => panic!("synthetic empty roots against fake gate fds must not load"),
            Err(error) => {
                let message = format!("{error:?}");
                assert!(
                    !message.contains("ungated producer root")
                        && !message.contains("missing shared writer map"),
                    "shared legacy half must pass shape checks, got: {message}"
                );
            }
        }
    }
    #[test]
    fn typed_stack_compiles_production_entry_bodies_and_preserves_boundaries() {
        // Extract complete definitions, never a second entry/staging algorithm.
        // Atomics, maps, probe operands and clock are the host boundaries.
        fn definition<'a>(source: &'a str, name: &str, kind: &str) -> &'a str {
            let marker = format!("{kind} {name}");
            assert_eq!(source.matches(&marker).count(), 1, "ambiguous {marker}");
            let begin = source.find(&marker).unwrap();
            let end = source[begin..].find("\n}\n").expect("complete definition") + begin + 3;
            &source[begin..end]
        }
        let producer = include_str!("../../crates/ebpf/src/typed_producer.rs");
        let pending = include_str!("../../crates/ebpf/src/source_state.rs");
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut generated = format!(
            "#![allow(dead_code, private_interfaces)]\n\
             extern crate self as osslscope_bpf_contract;\n\
             #[path = {:?}] pub mod attribution;\n#[path = {:?}] pub mod source;\n\
             use attribution::*;\nuse source::*;\nuse core::ptr::addr_of_mut;\n",
            base.join("crates/bpf-contract/src/attribution.rs"),
            base.join("crates/bpf-contract/src/source.rs")
        );
        for name in ["Target {", "StageParams<'a>", "MethodEntry {"] {
            generated.push_str(definition(producer, name, "struct"));
        }
        generated.push_str(definition(producer, "StagedFrame {", "struct"));
        for name in [
            "control_cell",
            "resolve_inner",
            "resolve_inner_opt",
            "split_ids",
            "site_bind",
            "site_bind_ptr",
            "admission_ptr",
            "ready_and_guards",
            "thread_incarnation",
            "thread_incarnation_opt",
            "alloc_id",
            "alloc_id_opt",
            "spend",
            "stage_frame",
            "stage_frame_opt",
            "pop_frame",
            "release_frame",
            "row_state_is",
            "method_key",
            "ambiguity_key",
            "name_state",
            "typed_entry",
            "entry_authorized",
            "initialize_entry_target",
            "pack_entry_role",
            "entry_admission",
            "entry_invalidate",
            "method_entry",
            "fetch_entry",
            "ctx_new_entry",
            "dup_entry",
            "child_entry",
            "typed_query_entry",
            "code_shape",
            "code_role_key",
            "registration_identity_matches",
            "code_role_check",
        ] {
            generated.push_str(definition(producer, &format!("{name}("), "fn"));
        }
        for name in ["initialize_pending_zero(", "insert_empty_frame("] {
            generated.push_str(definition(producer, name, "fn"));
        }
        // Only the architecture-specific atomic intrinsic is substituted;
        // quota, retry, mode, allocation and compensation bodies stay exact.
        let atomic = "core::intrinsics::atomic_cxchg::<\n                u64,\n                { core::intrinsics::AtomicOrdering::SeqCst },\n                { core::intrinsics::AtomicOrdering::SeqCst },\n            >";
        assert_eq!(generated.matches(atomic).count(), 2);
        generated = generated.replace(atomic, "host_cxchg");
        generated.push_str("mod source_state { use super::*;\n");
        for name in ["claim_pending(", "release_pending("] {
            generated.push_str(definition(pending, name, "fn"));
        }
        generated.push_str("}\n");
        let atomic = "atomic_cxchg::<u64, { SeqCst }, { SeqCst }>";
        assert_eq!(generated.matches(atomic).count(), 2);
        generated = generated.replace(atomic, "host_cxchg");
        // Generated module visibility is needed only for the host caller;
        // this does not change any production function body.
        generated = generated
            .replace("fn claim_pending(", "pub fn claim_pending(")
            .replace("fn release_pending(", "pub fn release_pending(");
        generated.push_str(include_str!("../../tests/runtime/typed_stack_host.rs"));
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "osslscope-entry-stack-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        let input = dir.join("entry.rs");
        let binary = dir.join("entry");
        std::fs::write(&input, &generated).unwrap();
        use sha2::Digest as _;
        let digest = |bytes: &[u8]| {
            sha2::Sha256::digest(bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        eprintln!(
            "entry controls source={} producer_sha256={} generated_sha256={}",
            input.display(),
            digest(producer.as_bytes()),
            digest(generated.as_bytes())
        );
        let compiler = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
        let mut command = std::process::Command::new(compiler);
        command.args(["--edition=2021", "-Dwarnings", "-Coverflow-checks=yes"]);
        let compiled = command.arg(&input).arg("-o").arg(&binary).output().unwrap();
        assert!(
            compiled.status.success(),
            "production entry compilation: {}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let controls = std::process::Command::new(&binary).output().unwrap();
        eprintln!("{}", String::from_utf8_lossy(&controls.stdout));
        assert!(
            controls.status.success(),
            "production entry controls: {}",
            String::from_utf8_lossy(&controls.stderr)
        );
    }
    #[test]
    fn typed_bind_compiles_production_bodies_and_preserves_staging() {
        // Complete production definitions, including layout attributes. The
        // fixture doubles maps, atomics, clock and probe operands; hashing uses
        // the contract implementation. Return handlers execute complete bodies.
        fn definition<'a>(source: &'a str, marker: &str) -> &'a str {
            assert_eq!(source.matches(marker).count(), 1, "ambiguous {marker}");
            let position = source.find(marker).unwrap();
            let mut begin = source[..position].rfind('\n').map_or(0, |p| p + 1);
            while begin > 0 {
                let previous = source[..begin - 1].rfind('\n').map_or(0, |p| p + 1);
                if !source[previous..begin].starts_with("#[") {
                    break;
                }
                begin = previous;
            }
            let end = source[position..]
                .find("\n}\n")
                .expect("complete definition")
                + position
                + 3;
            &source[begin..end]
        }
        let producer = include_str!("../../crates/ebpf/src/typed_producer.rs");
        let pending = include_str!("../../crates/ebpf/src/source_state.rs");
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut generated = format!(
            "#![allow(dead_code, private_interfaces)]\n\
             extern crate self as osslscope_bpf_contract;\n\
             #[path = {:?}] pub mod attribution;\n#[path = {:?}] pub mod source;\n\
             use attribution::*;\nuse source::*;\nuse core::ptr::addr_of_mut;\n",
            base.join("crates/bpf-contract/src/attribution.rs"),
            base.join("crates/bpf-contract/src/source.rs")
        );
        for name in [
            "Target {",
            "BindInputs {",
            "BoundSelector {",
            "TailArgs {",
            "Tombstone<'a>",
            "QueryAlgoScan<'a>",
            "QueryDispatchScan<'a, 't>",
        ] {
            generated.push_str(definition(producer, &format!("struct {name}")));
        }
        for line in producer.lines().filter(|line| {
            [
                "const BPF_",
                "const LOSS_",
                "const PLAN_",
                "const TAIL_",
                "const OUT_",
                "const QUERY_",
                "const CODE_SHAPE_",
            ]
            .iter()
            .any(|prefix| line.starts_with(prefix))
        }) {
            generated.push_str(line);
            generated.push('\n');
        }
        for name in [
            "pair_return_frame",
            "validate_return_site",
            "typed_return",
            "admission_ptr",
            "site_bind_ptr",
            "pop_frame",
            "child_parent",
            "child_parent_opt",
            "handler_thread",
            "frame_depth",
            "frame_depth_opt",
            "getter_mp_return",
            "getter_pc_return",
            "newctx_return",
            "dupctx_return",
            "dup_return",
            "typed_query_return",
            "query_walk_table",
            "query_algo_slot",
            "query_dispatch_slot",
            "code_shape",
            "retire_owner_reachable",
            "retire_method",
            "ordered_read",
            "compare",
            "exchange",
            "loss",
            "control_cell",
            "split_ids",
            "resolve_inner",
            "resolve_inner_opt",
            "alloc_id",
            "alloc_id_opt",
            "spend",
            "poison_domain",
            "site_bind",
            "ready_and_guards",
            "row_state_is",
            "conflict_row",
            "method_key",
            "ambiguity_key",
            "quarantine_key",
            "quarantined",
            "quarantine",
            "must_quarantine",
            "live_index",
            "collide_old_owner",
            "reserve_pending_x",
            "own_pending_x",
            "retire_pending_x",
            "cleanup_pending_x",
            "release_frame",
            "fetch_return",
            "intern_request",
            "publish_ambiguity",
            "retire_row",
            "probe_prepared_bound",
            "prepare_reused_plan",
            "allocate_bind_ids",
            "validate_bind_inputs",
            "bind_prepare",
            "plan_store",
            "plan_load",
            "dispatch_producer_outcome",
            "commit_publish",
            "commit_precheck",
            "now_of",
            "commit_publish_locked",
            "validate_reused_bound",
            "bound_lookup",
            "publish_bound_selector",
            "reauthorize_site",
            "flip_x_tail",
            "insert_u_tail",
            "insert_owner_selector_tail",
            "insert_owner_tail",
            "reuse_bound_selector",
            "reuse_bound_selector_opt",
            "conflict_digest",
        ] {
            let body = definition(producer, &format!("fn {name}("));
            if [
                "typed_return",
                "fetch_return",
                "getter_mp_return",
                "getter_pc_return",
                "newctx_return",
                "dupctx_return",
                "dup_return",
                "typed_query_return",
                "bind_prepare",
                "commit_publish",
                "commit_publish_locked",
                "publish_bound_selector",
                "flip_x_tail",
                "insert_u_tail",
                "insert_owner_selector_tail",
                "insert_owner_tail",
                "alloc_id",
                "conflict_digest",
                "collide_old_owner",
                "dispatch_producer_outcome",
                "cleanup_pending_x",
                "retire_pending_x",
                "release_frame",
                "poison_domain",
                "resolve_inner",
                "plan_store",
                "retire_owner_reachable",
            ]
            .contains(&name)
            {
                // Rename only the definition; the observer invokes this exact
                // complete body and never substitutes a production decision.
                generated.push_str(&body.replacen(
                    &format!("fn {name}("),
                    &format!("fn actual_{name}("),
                    1,
                ));
                if ![
                    "resolve_inner",
                    "plan_store",
                    "cleanup_pending_x",
                    "dispatch_producer_outcome",
                ]
                .contains(&name)
                {
                    let begin = body.find(&format!("fn {name}(")).unwrap();
                    let brace = body[begin..].find('{').unwrap() + begin;
                    let signature = &body[begin..brace];
                    let arguments =
                        &signature[signature.find('(').unwrap() + 1..signature.rfind(')').unwrap()];
                    let names: Vec<_> = arguments
                        .split(',')
                        .filter_map(|arg| arg.split_once(':').map(|(name, _)| name.trim()))
                        .collect();
                    generated.push_str(&format!(
                        "{signature} {{ observed(\"{name}\", || actual_{name}({})) }}\n",
                        names.join(", ")
                    ));
                }
            } else {
                generated.push_str(body);
            }
        }
        // Substitute only the target-specific intrinsic, preserving each
        // ordered read and compare/exchange decision in its production caller.
        for (indent, count) in [(8, 2), (16, 2)] {
            let pad = " ".repeat(indent);
            let atomic = format!(
                "core::intrinsics::atomic_cxchg::<\n{pad}u64,\n{pad}{{ core::intrinsics::AtomicOrdering::SeqCst }},\n{pad}{{ core::intrinsics::AtomicOrdering::SeqCst }},\n{}>",
                " ".repeat(indent - 4)
            );
            assert_eq!(generated.matches(&atomic).count(), count);
            generated = generated.replace(&atomic, "host_cxchg");
        }
        let exchange =
            "core::intrinsics::atomic_xchg::<u64, { core::intrinsics::AtomicOrdering::SeqCst }>";
        assert_eq!(generated.matches(exchange).count(), 1);
        generated = generated.replace(exchange, "host_xchg");
        generated.push_str("mod source_state { use super::*;\n");
        for name in ["claim_pending", "release_pending"] {
            generated.push_str(definition(pending, &format!("fn {name}(")));
        }
        generated.push_str("}\n");
        let atomic = "atomic_cxchg::<u64, { SeqCst }, { SeqCst }>";
        assert_eq!(generated.matches(atomic).count(), 2);
        generated = generated.replace(atomic, "host_cxchg");
        generated.push_str(include_str!("../../tests/runtime/typed_bind_host.rs"));
        generated.push_str(include_str!("../../tests/runtime/typed_request_host.rs"));
        generated.push_str(include_str!("../../tests/runtime/typed_bound_host.rs"));
        generated.push_str(include_str!("../../tests/runtime/typed_return_host.rs"));
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("osslscope-bind-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let input = dir.join("bind.rs");
        let binary = dir.join("bind");
        std::fs::write(&input, &generated).unwrap();
        use sha2::Digest as _;
        let digest = |bytes: &[u8]| {
            sha2::Sha256::digest(bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        eprintln!(
            "bind controls source={} producer_sha256={} generated_sha256={}",
            input.display(),
            digest(producer.as_bytes()),
            digest(generated.as_bytes())
        );
        let compiler = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
        let compiled = std::process::Command::new(compiler)
            .args([
                "--edition=2021",
                "--test",
                "-Dwarnings",
                "-Coverflow-checks=yes",
            ])
            .arg(&input)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "production bind compilation: {}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let listed = std::process::Command::new(&binary)
            .args(["bind_controls::", "--list", "--format=terse"])
            .output()
            .unwrap();
        assert!(listed.status.success());
        assert_eq!(
            String::from_utf8_lossy(&listed.stdout)
                .lines()
                .filter(|l| l.ends_with(": test"))
                .count(),
            9
        );
        let controls = std::process::Command::new(&binary)
            .args(["bind_controls::", "--test-threads=1", "--nocapture"])
            .output()
            .unwrap();
        eprintln!("{}", String::from_utf8_lossy(&controls.stdout));
        assert!(
            controls.status.success(),
            "production bind controls: {}",
            String::from_utf8_lossy(&controls.stderr)
        );
        let listed = std::process::Command::new(&binary)
            .args(["request_controls::", "--list", "--format=terse"])
            .output()
            .unwrap();
        assert!(listed.status.success());
        let names: Vec<_> = String::from_utf8_lossy(&listed.stdout)
            .lines()
            .map(str::to_owned)
            .collect();
        assert_eq!(
            names,
            [
                "request_controls::rebuild_kdf_request_key: test",
                "request_controls::rebuild_mac_request_key: test",
            ]
        );
        let controls = std::process::Command::new(&binary)
            .args(["request_controls::", "--test-threads=1", "--nocapture"])
            .output()
            .unwrap();
        eprintln!("{}", String::from_utf8_lossy(&controls.stdout));
        assert!(
            controls.status.success(),
            "production request controls: {}",
            String::from_utf8_lossy(&controls.stderr)
        );
        let listed = std::process::Command::new(&binary)
            .args(["return_controls::", "--list", "--format=terse"])
            .output()
            .unwrap();
        assert!(listed.status.success());
        let selected = String::from_utf8_lossy(&listed.stdout)
            .lines()
            .filter(|line| line.ends_with(": test"))
            .count();
        assert!(selected > 0, "return selection must not be empty");
        let controls = std::process::Command::new(&binary)
            .args(["return_controls::", "--test-threads=1", "--nocapture"])
            .output()
            .unwrap();
        eprintln!("{}", String::from_utf8_lossy(&controls.stdout));
        assert!(
            controls.status.success(),
            "production return controls ({selected} selected): {}",
            String::from_utf8_lossy(&controls.stderr)
        );
        let listed = std::process::Command::new(&binary)
            .args(["bound_controls::", "--list", "--format=terse"])
            .output()
            .unwrap();
        assert!(listed.status.success());
        let selected = String::from_utf8_lossy(&listed.stdout)
            .lines()
            .filter(|line| line.ends_with(": test"))
            .count();
        assert_eq!(selected, 3, "complete bound publication controls");
        let controls = std::process::Command::new(&binary)
            .args(["bound_controls::", "--test-threads=1", "--nocapture"])
            .output()
            .unwrap();
        eprintln!("{}", String::from_utf8_lossy(&controls.stdout));
        assert!(
            controls.status.success(),
            "production bound publication controls ({selected} selected): {}",
            String::from_utf8_lossy(&controls.stderr)
        );
    }
    #[test]
    fn typed_query_walk_compiles_production_bodies_and_preserves_boundaries() {
        // Compile the complete production query-return/walker tail. Only the
        // external nofault, source-join, publication and loss boundaries are
        // supplied by the host fixture; there is no second walker algorithm.
        fn region<'a>(source: &'a str, start: &str, end: Option<&str>) -> &'a str {
            assert_eq!(source.matches(start).count(), 1, "ambiguous start {start}");
            let begin = source.find(start).unwrap();
            let finish = end.map_or(source.len(), |marker| {
                assert_eq!(source.matches(marker).count(), 1, "ambiguous end {marker}");
                source.find(marker).unwrap()
            });
            assert!(begin < finish, "reversed source region");
            &source[begin..finish]
        }
        let producer = include_str!("../../crates/ebpf/src/typed_producer.rs");
        let vma = include_str!("../../crates/ebpf/src/source_vma.rs");
        let fixture = include_str!("../../tests/runtime/typed_query_walk_host.rs");
        let tail = region(producer, "\n/// Query return (161):", None);
        for definition in [
            "fn typed_query_return(",
            "struct QueryAlgoScan",
            "struct QueryDispatchScan",
            "fn query_walk_table(",
            "fn query_algo_slot(",
            "fn query_dispatch_slot(",
        ] {
            assert_eq!(tail.matches(definition).count(), 1, "{definition}");
        }
        let generated = format!(
            "#![allow(dead_code, private_interfaces)]\n#[path = {:?}] mod attribution;\n\
             use attribution::{{BindPendingValue, ProducerControl}};\n{}\n{}\n{}\n\
             mod source_vma {{ {} }}\n{}\n{}\n",
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("crates/bpf-contract/src/attribution.rs"),
            region(
                producer,
                "\npub(crate) struct Target {",
                Some("\n/// Validated immutable inputs only;")
            ),
            region(
                producer,
                "\nfn split_ids(",
                Some("\n/// Pending-frame staging")
            ),
            region(
                producer,
                "\n/// Query-walk bounds",
                Some("\n/// CODE_ROLE key:")
            ),
            region(
                vma,
                "\npub struct SourceLocation {",
                Some("\n#[repr(C, align(8))]")
            ),
            tail,
            fixture,
        );
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "osslscope-query-walk-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        let input = dir.join("query_walk.rs");
        let binary = dir.join("query_walk");
        std::fs::write(&input, &generated).unwrap();
        use sha2::Digest as _;
        let digest = |bytes: &[u8]| {
            sha2::Sha256::digest(bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        eprintln!(
            "query walk source={} producer_sha256={} generated_sha256={}",
            input.display(),
            digest(producer.as_bytes()),
            digest(generated.as_bytes())
        );
        let compiler = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
        let compiled = std::process::Command::new(compiler)
            .args(["--edition=2021", "-Dwarnings", "-Coverflow-checks=yes"])
            .arg(&input)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "production walker host compilation: {}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let controls = std::process::Command::new(&binary).output().unwrap();
        eprintln!("{}", String::from_utf8_lossy(&controls.stdout));
        assert!(
            controls.status.success(),
            "production walker controls: {}",
            String::from_utf8_lossy(&controls.stderr)
        );
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF pointing to a rebuilt object; preparation only"]
    fn real_bpf_object_prepares_when_built() {
        let path = std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF")
            .expect("required test-only object path OSSL_PROVIDER_OBSERVATION_TEST_BPF");
        let object = std::fs::read(path).expect("required test-only object must be readable");
        let prepared = prepare_object(&object).expect("real object preparation");
        // P3 re-pin (was 23/6 at 5A): the P1 producer adds 11 source maps
        // (typed admission/bind/pending frames, exact-name/digest index,
        // selector dictionary, thread identity, partition/control/segment
        // index/loss; REL itself pre-existed) and the typed entry/return pair.
        assert_eq!(prepared.maps.len(), 34);
        assert_eq!(prepared.progs.len(), 8);
        for root in &prepared.progs {
            assert!(root.map_fixups.iter().any(|site| site.map == "ADMIT"));
        }
        let (prepared, source) = split_source_preparation(prepared);
        assert_eq!((prepared.maps.len(), prepared.progs.len()), (16, 2));
        assert_eq!((source.maps.len(), source.progs.len()), (18, 6));
        let all_maps: std::collections::BTreeSet<_> = prepared
            .maps
            .iter()
            .chain(&source.maps)
            .map(|m| m.name.as_str())
            .collect();
        for root in &source.progs {
            assert!(
                root.map_fixups
                    .iter()
                    .all(|site| all_maps.contains(site.map.as_str()))
            );
            assert!(!root.subprogs.iter().any(|p| p.is_callback));
        }
        // The pending insertion is a key-only leaf: one fully initialized
        // 304-byte local, no copy/other helper/static callee beneath it. These
        // checks pin the permitted emission, not a whole-chain fit claim.
        let entry = source
            .progs
            .iter()
            .find(|p| p.name == "typed_entry")
            .unwrap();
        let index = entry
            .subprogs
            .iter()
            .position(|s| s.name == "insert_empty_frame")
            .expect("pending insertion leaf");
        let start = entry.subprogs[index].insn_off as usize * 8;
        let end = entry
            .subprogs
            .get(index + 1)
            .map_or(entry.insns.len(), |s| s.insn_off as usize * 8);
        let body = &entry.insns[start..end];
        let words: Vec<_> = body.chunks_exact(8).collect();
        assert_eq!(
            words.len(),
            51,
            "review any changed insertion-leaf emission"
        );
        assert_eq!(
            words[0],
            &[0xbf, 0x12, 0, 0, 0, 0, 0, 0],
            "preserve the only key argument in r2"
        );
        assert_eq!(
            words[1],
            &[0xb7, 1, 0, 0, 0, 0, 0, 0],
            "immediate zero in r1"
        );
        for (index, word) in words[2..40].iter().enumerate() {
            assert_eq!(
                (word[0], word[1]),
                (0x7b, 0x1a),
                "u64 store of zero register to own stack"
            );
            assert_eq!(
                i16::from_le_bytes([word[2], word[3]]),
                -304 + index as i16 * 8
            );
            assert_eq!(&word[4..], &[0, 0, 0, 0]);
        }
        assert_eq!(
            words[40],
            &[0xbf, 0xa3, 0, 0, 0, 0, 0, 0],
            "value pointer derives from own stack"
        );
        assert_eq!(
            words[41],
            &[0x07, 3, 0, 0, 0xd0, 0xfe, 0xff, 0xff],
            "all 304 bytes are the inserted value"
        );
        assert_eq!(words[45], &[0xb7, 4, 0, 0, 1, 0, 0, 0], "BPF_NOEXIST");
        let calls: Vec<_> = words.iter().filter(|w| w[0] == 0x85).collect();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            *calls[0],
            &[0x85, 0, 0, 0, 2, 0, 0, 0],
            "only map_update_elem, no nested memset/callee"
        );
        let maps: Vec<_> = entry
            .map_fixups
            .iter()
            .filter(|m| (start..end).contains(&m.insn_off))
            .map(|m| m.map.as_str())
            .collect();
        assert_eq!(maps, ["BIND_PENDING"]);
        for root in prepared
            .progs
            .iter()
            .filter(|p| matches!(p.name.as_str(), "observation_entry" | "observation_return"))
        {
            assert!(root.map_fixups.iter().any(|site| site.map == "ATTR_STATE"));
            if root.name == "observation_entry" {
                assert!(
                    root.map_fixups
                        .iter()
                        .any(|site| site.map == "SOURCE_CONFIG")
                );
            }
            for (name, slots, hash) in [
                (
                    "claim_pending",
                    173,
                    "fb801e221537ccfdc917389e74f002e0d9e6a47cad4a186bf8d4b49b7eb6e5e0",
                ),
                (
                    "release_pending",
                    139,
                    "2c499c1f3f17e7fbcbf5e35d0735fd102b215cfede442a7c47de6f76dc47bedd",
                ),
            ] {
                if name == "claim_pending" && root.name == "observation_return" {
                    continue;
                }
                let index = root
                    .subprogs
                    .iter()
                    .position(|s| s.name == name)
                    .expect("actual pending helper linked into consuming root");
                let start = root.subprogs[index].insn_off as usize * 8;
                let end = root
                    .subprogs
                    .get(index + 1)
                    .map_or(root.insns.len(), |s| s.insn_off as usize * 8);
                let body = &root.insns[start..end];
                assert_eq!(body.len(), slots * 8, "{name} exact body size");
                use sha2::Digest as _;
                assert_eq!(
                    sha2::Sha256::digest(body)
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>(),
                    hash,
                    "{name} body"
                );
                let atomics: Vec<_> = body.chunks_exact(8).filter(|i| i[0] == 0xdb).collect();
                assert_eq!(
                    atomics.len(),
                    9,
                    "{name}: ordered read plus eight unrolled CAS attempts"
                );
                for atomic in atomics {
                    assert_eq!(&atomic[2..4], &24i16.to_le_bytes(), "pending_claims offset");
                    assert_eq!(
                        &atomic[4..8],
                        &0xf1u32.to_le_bytes(),
                        "BPF_CMPXCHG, not a volatile store"
                    );
                }
            }
        }
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF pointing to a rebuilt object; preparation only"]
    fn source_writer_inventory_is_exact_and_admit_dominated() {
        // Ordinary-RCU writer proof, host half: the provider object carries
        // exactly the eight reviewed writer roots (P3 re-pin: the P1 typed
        // entry/return pair joins the six 5A roots), every root references
        // the shared ADMIT gate as its first mutation guard, and the source
        // half passes the owner's exact admission against the running
        // kernel's validated registration FUNC ID. Preparation only: no
        // program loads, no links, no mode change, read-only running BTF.
        let path = std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF")
            .expect("required test-only object path OSSL_PROVIDER_OBSERVATION_TEST_BPF");
        let object = std::fs::read(path).expect("required test-only object must be readable");
        let prepared = prepare_object(&object).expect("real object preparation");
        let mut roots: Vec<_> = prepared
            .progs
            .iter()
            .map(|p| (p.name.as_str(), p.section.as_str()))
            .collect();
        roots.sort();
        assert_eq!(
            roots,
            [
                ("attr_exec", "raw_tracepoint/sched_process_exec"),
                ("attr_exit", "raw_tracepoint/sched_process_exit"),
                ("observation_entry", "uprobe"),
                ("observation_return", "uretprobe"),
                ("source_reg_in", "fentry/uprobe_register"),
                ("source_reg_out", "fexit/uprobe_register"),
                ("typed_entry", "uprobe"),
                ("typed_return", "uretprobe"),
            ]
        );
        for root in &prepared.progs {
            assert!(
                root.map_fixups.iter().any(|fix| fix.map == "ADMIT"),
                "root {} lacks the shared-gate fixup",
                root.name
            );
        }
        let (legacy, source) = split_source_preparation(prepared);
        assert_eq!((legacy.progs.len(), source.progs.len()), (2, 6));
        for root in &source.progs {
            assert!(
                !root.subprogs.iter().any(|s| s.is_callback),
                "source root {} must not take the callback BTF path",
                root.name
            );
        }
        let budget = ObservationBudget::default();
        let kernel = loader::SourceKernel::read(&budget).expect("running kernel source layout");
        assert_ne!(
            kernel.registration_btf_id(),
            0,
            "running kernel must expose uprobe_register"
        );
        super::source_acquire::RetainedSourceRoots::check(&source, kernel.registration_btf_id())
            .expect("real source half must pass owner admission");
    }
    fn source_native_fd_targets() -> Vec<String> {
        let mut targets: Vec<String> = std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let target = std::fs::read_link(entry.path()).ok()?;
                Some(format!(
                    "{} -> {}",
                    entry.file_name().to_string_lossy(),
                    target.display()
                ))
            })
            .collect();
        targets.sort();
        targets
    }
    /// FD accounting: every BPF FD (maps, programs, links) must return to
    /// baseline exactly. Non-BPF FDs must return to baseline plus exactly the
    /// one pre-existing typed-anchor app handle: a Disabled-lease bisect
    /// proves that survivor appears and persists with zero source
    /// enablement, i.e. it belongs to the pre-existing typed-retention
    /// graph, not this acquisition (follow-up: place the ghost Rc holder).
    fn source_native_assert_fds_return(before: &[String], app: &std::path::Path) {
        let after = source_native_fd_targets();
        let bpf = |fds: &[String]| {
            fds.iter()
                .filter(|fd| {
                    fd.contains("bpf-map") || fd.contains("bpf-prog") || fd.contains("bpf_link")
                })
                .count()
        };
        let app_handles = |fds: &[String]| {
            fds.iter()
                .filter(|fd| fd.contains(&app.to_string_lossy().into_owned()))
                .count()
        };
        if bpf(&after) != bpf(before)
            || after.len() != before.len() + 1
            || app_handles(&after) != app_handles(before) + 1
        {
            eprintln!("FDs before ({})", before.len());
            for fd in before {
                eprintln!("  {fd}");
            }
            eprintln!("FDs after ({})", after.len());
            for fd in &after {
                eprintln!("  {fd}");
            }
        }
        assert_eq!(bpf(&after), bpf(before), "BPF FDs must return to baseline");
        assert_eq!(after.len(), before.len() + 1, "exactly one known survivor");
        assert_eq!(
            app_handles(&after),
            app_handles(before) + 1,
            "the survivor must be the pre-existing typed-anchor app handle"
        );
    }
    /// Owned single-purpose fixture: one legacy provider-query export plus
    /// typed public exports (EVP_MAC_fetch, EVP_MAC_free,
    /// OSSL_PROVIDER_get0_provider_ctx, OPENSSL_cleanup), an exec-marker
    /// write at main start, and exit 0. Discovery must yield exactly one API
    /// site and four typed sites. The legacy query probe fires once
    /// post-release; the marker plus exit status are the independent
    /// workload oracle.
    fn source_native_fixture(dir: &std::path::Path) -> std::path::PathBuf {
        let source = dir.join("app.c");
        let app = dir.join("app");
        std::fs::write(
            &source,
            r#"
#include <stdio.h>
#include <stddef.h>
struct dispatch { int id; void (*fn)(void); };
struct algorithm { const char *names, *properties; const struct dispatch *implementation; const char *description; };
__attribute__((noinline)) static void implementation(void) { __asm__ volatile(""); }
static const struct dispatch dispatch[] = { { 70001, implementation }, { 0, 0 } };
static const struct algorithm algorithms[] = { { "FUTURE-DIGEST", 0, dispatch, 0 }, { 0, 0, 0, 0 } };
__attribute__((noinline)) const struct algorithm *OSSL_PROVIDER_query_operation(const void *provider,int op,int *no_cache) {
 *no_cache=0;
 (void)provider; (void)op;
 return algorithms;
}
void *EVP_MAC_fetch(void *c,const char *n,const char *p){ (void)n; (void)p; return c; }
void EVP_MAC_free(void *m){ (void)m; }
void *OSSL_PROVIDER_get0_provider_ctx(const void *p){ return (void *)p; }
void OPENSSL_cleanup(void){}
int main(int argc,char **argv) { if(argc!=2) return 2;
 FILE *f=fopen(argv[1],"w"); if(!f) return 4; fputs("exec\n",f); fclose(f);
 { int no_cache=-1;
   if(OSSL_PROVIDER_query_operation((void*)1,1,&no_cache)==0) return 3; }
 if(EVP_MAC_fetch((void*)1,"X",0)!=(void*)1) return 3;
 EVP_MAC_free((void*)1);
 return 0; }
"#,
        )
        .unwrap();
        assert!(
            std::process::Command::new("cc")
                .args(["-O0", "-rdynamic", "-o"])
                .arg(&app)
                .arg(&source)
                .status()
                .unwrap()
                .success()
        );
        app
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges, cc"]
    fn source_roots_load_attach_and_enable_mode1() {
        // First real load of the four retained roots: programs verify,
        // fentry/fexit links attach to uprobe_register, raw lifecycle links
        // attach, and mode flips 0 -> 1 under the closed gate. No triggers,
        // no enrollment, no target attachment beyond prearm.
        let dir =
            std::env::temp_dir().join(format!("osslscope-source-roots-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let app = source_native_fixture(&dir);
        let argv = [
            app.to_string_lossy().into_owned(),
            dir.join("marker").to_string_lossy().into_owned(),
        ];
        let child =
            crate::target::OwnedTarget::spawn_stopped(&argv, crate::target::WorkloadDest::Null)
                .unwrap();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let mut budget = ObservationBudget::default();
        let startup = crate::startup_objects::prepare_owned_startup(
            &child,
            &argv,
            &mut budget,
            Instant::now() + Duration::from_secs(15),
            &cancel,
            None,
        )
        .unwrap();
        eprintln!(
            "startup apis={} typed={}",
            startup.apis.len(),
            startup.typed.len()
        );
        assert!(!startup.typed.is_empty(), "fixture must yield typed sites");
        let crate::startup_objects::PreExecSites { apis, typed, .. } = startup;
        let object =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        let fds_before = source_native_fd_targets();
        budget.state(crate::writer_gate::RESERVATION_BYTES).unwrap();
        let pool = budget.memory.clone().unwrap_or_else(|| {
            crate::observation_memory::MemoryPool::new(budget.limits.max_state_bytes)
        });
        let gate = crate::writer_gate::WriterGate::create(&pool).unwrap();
        let mut session = ProviderSession::open_gated(budget, &object, gate.clone()).unwrap();
        session
            .prearm_startup(
                apis,
                Instant::now() + Duration::from_secs(5),
                &cancel,
                PrearmLinks::Reserve,
            )
            .unwrap();
        let lease = super::source_owner::SourceAcquisitionLease::Enabled(
            super::source_owner::NativeSourceParams::for_test(
                app.clone(),
                session.startup[&child.pid()][0].site.file_offset(),
                child.pid(),
            ),
        );
        session
            .prepare_typed_startup(
                typed,
                Instant::now() + Duration::from_secs(15),
                &cancel,
                &lease,
            )
            .unwrap();
        let roots = session.roots_enabled_receipts().expect("roots receipts");
        eprintln!(
            "roots programs={} links={} lifecycle={} mode={}->{}",
            roots.programs, roots.links, roots.lifecycle, roots.mode_before, roots.mode_after
        );
        assert_eq!((roots.programs, roots.links, roots.lifecycle), (4, 2, 2));
        assert_eq!((roots.mode_before, roots.mode_after), (0, 1));
        // Teardown integrates with the common cut: open then cut the idle
        // gate (no writers admitted) before closing sources.
        gate.open().unwrap();
        gate.close().unwrap();
        let close = session.close_source_explicit().expect("source close");
        assert!(close.cut_confirmed, "close must confirm the cut");
        assert_eq!(
            (
                close.guards_retired,
                close.guards_abandoned,
                close.domains_retired
            ),
            (0, 0, 0)
        );
        assert!(close.order_refused, "idle order must refuse at close");
        assert!(close.first_error.is_none());
        drop(session);
        drop(gate);
        drop(child);
        source_native_assert_fds_return(&fds_before, &app);
        std::fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges, cc"]
    fn source_acquisition_publishes_ready_and_mirrors_exec() {
        // Full native acquisition on an owned held child: gate open under
        // held custody, domain arm, observer enrollment, anchor with
        // mapping/hash custody, ENTRY/RETURN adoption of real links, READY
        // publication, child release, workload oracle (marker + exit 0),
        // planned-exec mirror, and accounted close.
        let dir =
            std::env::temp_dir().join(format!("osslscope-source-acquire-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let app = source_native_fixture(&dir);
        let marker = dir.join("marker");
        let argv = [
            app.to_string_lossy().into_owned(),
            marker.to_string_lossy().into_owned(),
        ];
        let mut child =
            crate::target::OwnedTarget::spawn_stopped(&argv, crate::target::WorkloadDest::Null)
                .unwrap();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let mut budget = ObservationBudget::default();
        let startup = crate::startup_objects::prepare_owned_startup(
            &child,
            &argv,
            &mut budget,
            Instant::now() + Duration::from_secs(15),
            &cancel,
            None,
        )
        .unwrap();
        eprintln!(
            "startup apis={} typed={}",
            startup.apis.len(),
            startup.typed.len()
        );
        assert!(!startup.typed.is_empty(), "fixture must yield typed sites");
        let crate::startup_objects::PreExecSites { apis, typed, .. } = startup;
        let object =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        let fds_before = source_native_fd_targets();
        budget.state(crate::writer_gate::RESERVATION_BYTES).unwrap();
        let pool = budget.memory.clone().unwrap_or_else(|| {
            crate::observation_memory::MemoryPool::new(budget.limits.max_state_bytes)
        });
        let gate = crate::writer_gate::WriterGate::create(&pool).unwrap();
        let mut session = ProviderSession::open_gated(budget, &object, gate.clone()).unwrap();
        session
            .prearm_startup(
                apis,
                Instant::now() + Duration::from_secs(5),
                &cancel,
                PrearmLinks::Reserve,
            )
            .unwrap();
        eprintln!(
            "startup attachments: {:?}",
            session
                .startup
                .iter()
                .map(|(pid, rows)| (pid, rows.len()))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            session.startup.len(),
            1,
            "fixture must yield one startup pid"
        );
        assert_eq!(
            session.startup[&child.pid()].len(),
            1,
            "fixture must yield one attachment"
        );
        let admitted = &session.startup[&child.pid()][0];
        assert!(
            admitted.links.is_empty(),
            "reserve-only prearm must create no producer links"
        );
        let cookie = admitted.cookie;
        let admitted_offset = admitted.site.file_offset();
        eprintln!("admitted site: cookie={cookie} offset={admitted_offset:#x}");
        let lease = super::source_owner::SourceAcquisitionLease::Enabled(
            super::source_owner::NativeSourceParams::for_test(
                app.clone(),
                admitted_offset,
                child.pid(),
            ),
        );
        session
            .prepare_typed_startup(
                typed,
                Instant::now() + Duration::from_secs(15),
                &cancel,
                &lease,
            )
            .unwrap();
        gate.open().unwrap();
        let receipts = session
            .acquire_source_after_open(&lease, Instant::now() + Duration::from_secs(15), &cancel)
            .unwrap_or_else(|gap| {
                panic!(
                    "acquire failed: {gap:?} owner: {:?}",
                    session.source_error()
                )
            });
        eprintln!(
            "acquired host={:#x} cookie={} offset={:#x} domain={} anchor={} epoch={:#x} object={:#x} anchor_seq={} reg={} ready_seq={} adopted={} anchor_hash={}",
            receipts.host_key,
            receipts.site_cookie,
            receipts.link_offset,
            receipts.domain.tgid,
            receipts.anchor.anchor_id,
            receipts.anchor.epoch,
            receipts.anchor.object_id,
            receipts.anchor.sequence,
            receipts.registration.registration_id,
            receipts.ready_sequence,
            receipts.adopted_links,
            receipts
                .anchor
                .hash
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        );
        assert_ne!(receipts.host_key, 0);
        assert_eq!(
            receipts.site_cookie, cookie,
            "receipt must cite the admitted cookie"
        );
        assert_eq!(
            receipts.link_offset, admitted_offset,
            "receipt must cite the admitted file offset"
        );
        assert_ne!(receipts.link_offset, 0, "header offset 0 is never admitted");
        assert_eq!(receipts.domain.tgid, child.pid());
        assert_ne!(receipts.domain.incarnation, 0);
        assert_ne!(receipts.domain.original, 0);
        assert_ne!(receipts.domain.planned, 0);
        assert_ne!(receipts.domain.original, receipts.domain.planned);
        assert_ne!(receipts.anchor.anchor_id, 0);
        assert_ne!(receipts.anchor.epoch, 0);
        assert_ne!(receipts.anchor.object_id, 0);
        assert_ne!(receipts.anchor.sequence, 0);
        assert_ne!(receipts.registration.registration_id, 0);
        assert_ne!(
            receipts.registration.registration_id,
            receipts.anchor.anchor_id
        );
        assert_ne!(receipts.ready_sequence, 0);
        // P3-I1: every typed cookie adopts its own entry/return pair into
        // the owner alongside the legacy pair, so adoptions scale with the
        // staged typed population (2 + 2 per typed site here).
        assert_eq!(
            receipts.adopted_links,
            2 + 2 * session.typed_site_records().len()
        );
        // Independent anchor oracle: hash the target file directly.
        let expected = {
            use sha2::Digest as _;
            sha2::Sha256::digest(std::fs::read(&app).unwrap())
        };
        assert_eq!(receipts.anchor.hash, expected.as_slice());
        // Release only after READY, then the independent workload oracle.
        child.release().unwrap();
        let until = Instant::now() + Duration::from_secs(15);
        while !marker.exists() {
            assert!(Instant::now() < until, "exec marker never appeared");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(std::fs::read(&marker).unwrap(), b"exec\n");
        while child.peek_exit().unwrap().is_none() {
            assert!(Instant::now() < until, "workload never exited");
            std::thread::yield_now();
        }
        assert_eq!(child.poll_exit().unwrap(), Some(0), "workload must exit 0");
        let state = session
            .note_source_exec(&lease, child.pid(), receipts.domain.planned)
            .unwrap();
        assert_eq!(state, super::source_owner::contract::DOMAIN_ACTIVE);
        // Real callback execution through the derived links: the fixture's
        // post-release provider query must surface as facts in the final
        // drain. Finalize first (common cut + drain), then close sources.
        let batch = session.finalize_until(Instant::now() + Duration::from_secs(10));
        let queries = batch
            .facts
            .iter()
            .filter(|f| f.api == wire::api(c::PUBLIC_QUERY).unwrap())
            .filter(|f| {
                matches!(
                    f.payload,
                    ObservationPayload::QueryResult {
                        outcome: ApiOutcome::Success,
                        ..
                    }
                )
            })
            .count();
        eprintln!("derived-link callbacks: query_successes={queries}");
        assert!(
            queries > 0,
            "the admitted query must fire through the derived links"
        );
        // finalize_until above already performed the common cut; the close
        // confirms it before retiring anything.
        let close = session.close_source_explicit().expect("source close");
        assert!(close.cut_confirmed, "close must confirm the cut");
        // P3-I1: the close retires the anchor, the legacy adoption guard
        // and one adoption guard per typed cookie.
        assert_eq!(
            (
                close.guards_retired,
                close.guards_abandoned,
                close.domains_retired
            ),
            (2 + session.typed_site_records().len(), 0, 1)
        );
        assert!(
            !close.order_refused,
            "READY order must stay published at close"
        );
        assert!(close.first_error.is_none());
        drop(session);
        drop(gate);
        drop(child);
        source_native_assert_fds_return(&fds_before, &app);
        std::fs::remove_dir_all(&dir).unwrap();
    }
    /// P3 hostile-control fixture: the query/fetch/free/getctx/cleanup shape
    /// of `source_native_fixture` plus a fake `EVP_MAC_CTX_new` that performs
    /// a natural nested provider-context getter call inside construction.
    /// `main_body` is the post-fixture-setup workload; it must `return 0`
    /// only when every fake public call succeeded, so the exit status proves
    /// public success while the kernel verdicts below prove attribution
    /// refusal. All handles are private malloc blocks: nonzero, never
    /// dereferenced by the observer, never transported anywhere.
    fn source_native_typed_chain_fixture(
        dir: &std::path::Path,
        main_body: &str,
    ) -> std::path::PathBuf {
        let source = dir.join("chain.c");
        let app = dir.join("chain");
        let text = format!(
            r#"
#include <stdio.h>
#include <stdlib.h>
struct dispatch {{ int id; void (*fn)(void); }};
struct algorithm {{ const char *names, *properties; const struct dispatch *implementation; const char *description; }};
__attribute__((noinline)) static void implementation(void) {{ __asm__ volatile(""); }}
static const struct dispatch dispatch[] = {{ {{ 70001, implementation }}, {{ 0, 0 }} }};
static const struct algorithm algorithms[] = {{ {{ "FUTURE-DIGEST", 0, dispatch, 0 }}, {{ 0, 0, 0, 0 }} }};
__attribute__((noinline)) const struct algorithm *OSSL_PROVIDER_query_operation(const void *provider,int op,int *no_cache) {{
 *no_cache=0;
 (void)provider; (void)op;
 return algorithms;
}}
static void *fake_libctx;
static void *fake_method;
static void *fake_provider;
void *EVP_MAC_fetch(void *c,const char *n,const char *p){{ (void)p; if(!c||!n||!*n) return 0; return fake_method; }}
void EVP_MAC_free(void *m){{ (void)m; }}
void *OSSL_PROVIDER_get0_provider_ctx(const void *p){{ if(p!=fake_provider) return 0; return fake_libctx; }}
void *EVP_MAC_CTX_new(void *m){{ if(m!=fake_method) return 0; void *u=malloc(16); if(!u) return 0; if(!OSSL_PROVIDER_get0_provider_ctx(fake_provider)) return 0; return u; }}
void OPENSSL_cleanup(void){{}}
int main(int argc,char **argv) {{ if(argc!=2) return 2;
 FILE *f=fopen(argv[1],"w"); if(!f) return 4; fputs("exec\n",f); fclose(f);
 fake_libctx=malloc(16); fake_method=malloc(16); fake_provider=malloc(16);
 if(!fake_libctx||!fake_method||!fake_provider) return 5;
 {main_body}
 return 0; }}
"#,
        );
        std::fs::write(&source, text).unwrap();
        assert!(
            std::process::Command::new("cc")
                .args(["-O0", "-rdynamic", "-o"])
                .arg(&app)
                .arg(&source)
                .status()
                .unwrap()
                .success()
        );
        app
    }
    /// Outcome of one driven typed session with a shared counter and a
    /// closed attribution collect. Counts only; no addresses, no digests.
    struct TypedCounterDrive {
        typed_sites: usize,
        copied_skipped: usize,
        counter_links: usize,
        joined_sites: usize,
        joined_calls: u64,
        definite: usize,
        unresolved_calls: u64,
        withheld_uncertain: u64,
        sample_sites: usize,
        sample_calls: u64,
        next_producer_id: u64,
        loss_cells: [u64; 8],
        staged_roles: Vec<u32>,
    }
    /// P3 hostile-control driver: full Enabled session (single-API prearm,
    /// typed prepare, gate open, source acquisition with typed admission +
    /// typed-pair attach), a shared-map counter attached at the typed sites
    /// named by `count_roles` through the session's real pins (empty here,
    /// so the counter-minted fallback engages honestly), workload release,
    /// common cut, counter close, closed attribution collect, source close.
    /// Every kernel verdict is real; `main` already proved public success
    /// via exit 0. Returns count-only receipts for the control asserts.
    /// U1 extends it with an optional copied plan (None preserves the
    /// H1/H2/H3 behavior verbatim) and a marker filename so two passes
    /// can share one fixture directory. The I2 control adds an optional
    /// third argv word (None preserves every existing receipt verbatim);
    /// the complete-chain fixture selects its live-table mode from that
    /// word (`mutate-kdf-table`/other: I2 drop44 + direct reset + second
    /// derive; `i1-swap45`/`i1-swap34`: alternate advertisement;
    /// `i3-drop45`: omitted (4,5); `i1-remap45:<nonce>`: remap race).
    fn drive_typed_session_with_counter(
        tag: &str,
        app: &std::path::Path,
        count_roles: &[u32],
        plan: Option<&super::copied_plan::CopiedPlan>,
        marker_name: &str,
        extra_arg: Option<&str>,
    ) -> TypedCounterDrive {
        use crate::capture::ClockPort as _;
        let dir = app.parent().unwrap().to_path_buf();
        let marker = dir.join(marker_name);
        let mut argv = vec![
            app.to_string_lossy().into_owned(),
            marker.to_string_lossy().into_owned(),
        ];
        if let Some(extra) = extra_arg {
            argv.push(extra.to_owned());
        }
        let mut child =
            crate::target::OwnedTarget::spawn_stopped(&argv, crate::target::WorkloadDest::Null)
                .unwrap();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let mut budget = ObservationBudget::default();
        let startup = crate::startup_objects::prepare_owned_startup(
            &child,
            &argv,
            &mut budget,
            Instant::now() + Duration::from_secs(15),
            &cancel,
            plan,
        )
        .unwrap();
        eprintln!(
            "startup apis={} typed={} copied_skipped={}",
            startup.apis.len(),
            startup.typed.len(),
            startup.copied_skipped,
        );
        assert!(!startup.typed.is_empty(), "fixture must yield typed sites");
        let copied_skipped = startup.copied_skipped;
        let crate::startup_objects::PreExecSites { apis, typed, .. } = startup;
        let object =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        let count_object =
            std::fs::read(std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT").unwrap()).unwrap();
        let fds_before = source_native_fd_targets();
        budget.state(crate::writer_gate::RESERVATION_BYTES).unwrap();
        let pool = budget.memory.clone().unwrap_or_else(|| {
            crate::observation_memory::MemoryPool::new(budget.limits.max_state_bytes)
        });
        let gate = crate::writer_gate::WriterGate::create(&pool).unwrap();
        let mut session = ProviderSession::open_gated(budget, &object, gate.clone()).unwrap();
        session
            .prearm_startup(
                apis,
                Instant::now() + Duration::from_secs(5),
                &cancel,
                PrearmLinks::Reserve,
            )
            .unwrap();
        assert_eq!(
            session.startup.len(),
            1,
            "fixture must yield one startup pid"
        );
        assert_eq!(
            session.startup[&child.pid()].len(),
            1,
            "fixture must yield one attachment"
        );
        let lease = super::source_owner::SourceAcquisitionLease::Enabled(
            super::source_owner::NativeSourceParams::for_test(
                app.to_path_buf(),
                session.startup[&child.pid()][0].site.file_offset(),
                child.pid(),
            ),
        );
        session
            .prepare_typed_startup(
                typed,
                Instant::now() + Duration::from_secs(15),
                &cancel,
                &lease,
            )
            .unwrap();
        let typed_sites = session.typed_startup.len();
        // Counter under the preparing gate (map load only, as in the P2
        // proof); links attach after the gate opens below.
        let start_ns = crate::capture::LiveClock.checked_monotonic_ns().unwrap();
        let deadline_ns = start_ns + 15_000_000_000;
        let borrowed = session.borrowed_producer_maps().expect("producer maps");
        let mut counter = crate::focused_count::FocusedCounter::open_gated_shared(
            &count_object,
            child.pid(),
            crate::focused_capture::observer_namespace().unwrap(),
            crate::focused_count::CountLimits {
                window: crate::evidence::CountAdmissionWindow {
                    start_ns,
                    deadline_ns,
                },
                ..Default::default()
            },
            gate.clone(),
            &borrowed,
        )
        .unwrap();
        gate.open().unwrap();
        let receipts = session
            .acquire_source_after_open(&lease, Instant::now() + Duration::from_secs(15), &cancel)
            .unwrap_or_else(|gap| {
                panic!(
                    "acquire failed: {gap:?} owner: {:?}",
                    session.source_error()
                )
            });
        assert_eq!(
            session.typed_site_records().len(),
            typed_sites,
            "every staged typed site must admit"
        );
        // Learned counter sites cloned from the admitted typed sites: the
        // kernel-relevant triple (verified site, pid, starttime) is real;
        // labels stay honestly unknown (no advertisers observed).
        let mut candidates = Vec::new();
        for staged in &session.typed_startup {
            if !count_roles.contains(&staged.role().id()) {
                continue;
            }
            let site = staged.site().clone();
            let starttime = site.starttime();
            let record = super::wire::contract::Record {
                pid: child.pid(),
                tid: child.pid(),
                generation: site.generation(),
                ..super::wire::contract::Record::default()
            };
            candidates.push(crate::focused_count::CountCandidate::Learned(
                VerifiedSiteCandidate {
                    site,
                    pid: child.pid(),
                    starttime,
                    generation: record.generation,
                    advertisers: Vec::new(),
                    operation: super::schema::Operation::Mac,
                    numeric_operation: 0,
                    dynamic_algorithm: super::static_tables::DynamicAlgorithmId::observed(
                        session.typed_startup[0].site().object_hash(),
                        starttime,
                        &record,
                    ),
                    observed_ns: start_ns,
                    algorithm: super::schema::AlgorithmId::try_from(u16::MAX).unwrap(),
                    alias_quality: super::schema::AliasQuality::default(),
                    function: super::schema::FunctionIdentity::new(
                        super::schema::Operation::Mac,
                        0,
                    )
                    .unwrap(),
                },
            ));
        }
        assert_eq!(
            candidates.len(),
            count_roles.len(),
            "one counter site per counted role"
        );
        counter
            .attach_candidates_pinned(
                candidates,
                start_ns,
                Instant::now() + Duration::from_secs(15),
                &cancel,
                session.typed_pins(),
            )
            .unwrap();
        let counter_links = counter.active_link_count();
        // Release only after READY, then the independent workload oracle.
        child.release().unwrap();
        let until = Instant::now() + Duration::from_secs(15);
        while !marker.exists() {
            assert!(Instant::now() < until, "exec marker never appeared");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(std::fs::read(&marker).unwrap(), b"exec\n");
        while child.peek_exit().unwrap().is_none() {
            assert!(Instant::now() < until, "workload never exited");
            std::thread::yield_now();
        }
        assert_eq!(child.poll_exit().unwrap(), Some(0), "workload must exit 0");
        session
            .note_source_exec(&lease, child.pid(), receipts.domain.planned)
            .unwrap();
        // Common cut first, then the counter close and the closed collect,
        // mirroring the production finish order.
        session.finalize_until(Instant::now() + Duration::from_secs(10));
        let cpus = counter.cpus();
        let sample = counter.close(Instant::now() + Duration::from_secs(10));
        let records: Vec<(u64, TypedSiteRecord)> = session
            .typed_site_records()
            .iter()
            .map(|(cookie, record)| (*cookie, record.clone()))
            .collect();
        session
            .charge_attribution_final(
                8192usize
                    .checked_mul(104 + 24 * cpus)
                    .and_then(|n| n.checked_add(1024 * (16 + 64)))
                    .and_then(|n| n.checked_add(1024 * (24 + 56)))
                    .and_then(|n| n.checked_add(8 * 8 * cpus))
                    .and_then(|n| n.checked_add(64))
                    .unwrap(),
            )
            .unwrap();
        let maps = session.attribution_maps().expect("attribution maps");
        let mut admitted = Vec::with_capacity(records.len());
        for (cookie, record) in &records {
            admitted.push(crate::attribution::AdmittedTypedSite {
                cookie: *cookie,
                site_id: std::num::NonZeroU64::new(record.site_id).unwrap(),
                role_id: record.role_id,
                object: record.object.clone(),
                device: record.device,
                inode: record.inode,
                offset: record.offset,
                object_id: record.object_id,
                source_epoch: record.source_epoch,
            });
        }
        let end_ns = crate::capture::LiveClock
            .checked_monotonic_ns()
            .unwrap()
            .min(deadline_ns);
        let admission = crate::evidence::CountAdmissionWindow {
            start_ns,
            deadline_ns,
        };
        let finalized = crate::attribution::collect_closed_attribution(
            gate.owned_closed().expect("closed gate"),
            &gate,
            &maps,
            cpus,
            &sample,
            &admitted,
            admission,
            crate::evidence::CaptureWindow {
                requested_start_ns: start_ns,
                requested_end_ns: deadline_ns,
                effective_start_ns: start_ns,
                effective_end_ns: end_ns.max(start_ns),
                signal_cut: false,
                count_admission: Some(admission),
            },
        )
        .unwrap_or_else(|error| panic!("closed collect failed: {error:?}"));
        let mut joined_sites = 0usize;
        let mut joined_calls = 0u64;
        for execution in &sample.sites {
            if admitted.iter().any(|site| {
                site.object == execution.site.object
                    && site.device == execution.site.device
                    && site.inode == execution.site.inode
                    && site.offset == execution.site.offset
            }) {
                joined_sites += 1;
                joined_calls += execution.calls;
            }
        }
        let sample_calls: u64 = sample.sites.iter().map(|site| site.calls).sum();
        // Progress meter for the silent paths: observer-issued ID counter
        // plus per-cell loss sums, both from already-host-read maps.
        let next_producer_id = {
            let fd = session
                .source_owner
                .as_ref()
                .unwrap()
                .owned_map("ATTRIB_CONTROL")
                .unwrap();
            let map = loader::BorrowedMap::new(fd).unwrap();
            map.shape(&[2], 4, 64).unwrap();
            let mut value = [0u8; 64];
            map.lookup(&0u32.to_ne_bytes(), &mut value).unwrap();
            u64::from_ne_bytes(value[32..40].try_into().unwrap())
        };
        let mut loss_cells = [0u64; 8];
        {
            let fd = session
                .source_owner
                .as_ref()
                .unwrap()
                .owned_map("PRODUCER_LOSS")
                .unwrap();
            let map = loader::BorrowedMap::new(fd).unwrap();
            map.shape(&[6], 4, 8).unwrap();
            for (cell, total) in loss_cells.iter_mut().enumerate() {
                let mut values = vec![0u8; 8 * cpus];
                map.lookup(&(cell as u32).to_ne_bytes(), &mut values)
                    .unwrap();
                for cpu in 0..cpus {
                    *total += u64::from_ne_bytes(values[cpu * 8..cpu * 8 + 8].try_into().unwrap());
                }
            }
        }
        eprintln!(
            "{tag}: typed={typed_sites} counter_links={counter_links} sample_sites={} sample_calls={sample_calls} joined_sites={joined_sites} joined_calls={joined_calls} definite={} unresolved={} withheld={} next_id={next_producer_id} loss={loss_cells:?}",
            sample.sites.len(),
            finalized.definite().len(),
            finalized.unresolved_calls(),
            finalized.withheld_uncertain(),
        );
        let mut staged_roles: Vec<u32> = records.iter().map(|(_, record)| record.role_id).collect();
        staged_roles.sort_unstable();
        let drive = TypedCounterDrive {
            typed_sites,
            copied_skipped,
            counter_links,
            joined_sites,
            joined_calls,
            definite: finalized.definite().len(),
            unresolved_calls: finalized.unresolved_calls(),
            withheld_uncertain: finalized.withheld_uncertain(),
            sample_sites: sample.sites.len(),
            sample_calls,
            next_producer_id,
            loss_cells,
            staged_roles,
        };
        drop(finalized);
        drop(sample);
        let close = session.close_source_explicit().expect("source close");
        assert!(close.cut_confirmed, "close must confirm the cut");
        assert!(close.first_error.is_none());
        drop(session);
        drop(gate);
        drop(child);
        source_native_assert_fds_return(&fds_before, app);
        std::fs::remove_dir_all(&dir).unwrap();
        drive
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, OSSLSCOPE_FOCUSED_COUNT_OBJECT, native BPF privileges, cc"]
    fn typed_same_handler_counts_physical_without_operational_admission() {
        // H1: same-handler/physical-first control. The typed fetch fires
        // through its admitted pair while the shared counter counts the
        // same site under a counter-minted cookie (no operational
        // admission exists anywhere). The kernel must store the physical
        // hit and assign no partition; the closed fold must keep the
        // joined call unresolved. Static-only sites never read arg0.
        let dir = std::env::temp_dir().join(format!("osslscope-typed-h1-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let app = source_native_fixture(&dir);
        let drive = drive_typed_session_with_counter("h1", &app, &[130], None, "marker", None);
        assert_eq!(drive.typed_sites, 4, "fixture yields four typed sites");
        assert_eq!(drive.counter_links, 1, "counter attaches the fetch site");
        assert_eq!(drive.joined_sites, 1, "the fetch hit must join");
        assert_eq!(drive.joined_calls, 1, "main fetches exactly once");
        assert_eq!(drive.definite, 0, "no operational admission, no partition");
        assert_eq!(drive.unresolved_calls, 1, "the hit stays unresolved");
        assert_eq!(drive.withheld_uncertain, 0);
        assert_eq!(drive.sample_sites, 1, "counter saw only the fetch site");
        assert_eq!(drive.sample_calls, 1, "every physical hit joined");
        assert!(
            drive.next_producer_id > 1,
            "kernel minted producer IDs (host seeds 1)"
        );
        assert_eq!(
            drive.loss_cells,
            [0, 0, 0, 0, 0, 0, 0, 0],
            "refusal came from verdicts, not loss"
        );
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, OSSLSCOPE_FOCUSED_COUNT_OBJECT, native BPF privileges, cc"]
    fn typed_fetch_ctx_new_without_constructor_stays_unresolved() {
        // H2: constructor-gap control. A natural fetch plus a public
        // CTX_new with a nested provider-context getter (getter_count 1)
        // but no independently typed provider constructor
        // (constructor_count 0) must never commit an owner: exit 0 proves
        // the public calls succeeded while the kernel withholds the
        // positive. This pins the exact P4 gap from the fail-closed side.
        let dir = std::env::temp_dir().join(format!("osslscope-typed-h2-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let app = source_native_typed_chain_fixture(
            &dir,
            r#"
 { int no_cache=-1;
   if(OSSL_PROVIDER_query_operation((void*)1,1,&no_cache)==0) return 3; }
 void *m=EVP_MAC_fetch(fake_libctx,"HMAC",0); if(m!=fake_method) return 3;
 void *u=EVP_MAC_CTX_new(m); if(!u) return 3;
"#,
        );
        let drive = drive_typed_session_with_counter("h2", &app, &[130, 147], None, "marker", None);
        assert_eq!(
            drive.typed_sites, 5,
            "chain fixture yields five typed sites"
        );
        assert_eq!(
            drive.counter_links, 1,
            "one multi-link batches both same-file sites"
        );
        assert_eq!(drive.joined_sites, 2, "both hits must join");
        assert_eq!(drive.joined_calls, 2, "fetch once, construct once");
        assert_eq!(drive.definite, 0, "no constructor, no owner, no partition");
        assert_eq!(drive.unresolved_calls, 2, "both hits stay unresolved");
        assert_eq!(drive.withheld_uncertain, 0);
        assert_eq!(drive.sample_sites, 2, "counter saw only the two sites");
        assert_eq!(drive.sample_calls, 2, "every physical hit joined");
        assert!(
            drive.next_producer_id > 1,
            "kernel minted producer IDs (host seeds 1)"
        );
        assert_eq!(
            drive.loss_cells,
            [0, 0, 0, 0, 0, 0, 0, 0],
            "refusal came from verdicts, not loss"
        );
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, OSSLSCOPE_FOCUSED_COUNT_OBJECT, native BPF privileges, cc"]
    fn typed_incompatible_fetch_spellings_quarantine_the_method() {
        // H3: method-ambiguity control (fetchA->M, fetchB->M, free(M),
        // fetchB->M). Incompatible observed spellings for one method must
        // create a tombstone that survives the free/refetch: the later
        // successful public construction still yields no positive. The
        // refused CTX_new entry stages no frame (tombstoned method), so
        // its paired return records the designed pair loss; both loss
        // events join the conservative unresolved remainder (4+2).
        let dir = std::env::temp_dir().join(format!("osslscope-typed-h3-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let app = source_native_typed_chain_fixture(
            &dir,
            r#"
 { int no_cache=-1;
   if(OSSL_PROVIDER_query_operation((void*)1,1,&no_cache)==0) return 3; }
 void *a=EVP_MAC_fetch(fake_libctx,"HMAC-A",0); if(a!=fake_method) return 3;
 void *b=EVP_MAC_fetch(fake_libctx,"HMAC-B",0); if(b!=fake_method) return 3;
 EVP_MAC_free(a);
 void *c=EVP_MAC_fetch(fake_libctx,"HMAC-B",0); if(c!=fake_method) return 3;
 void *u=EVP_MAC_CTX_new(c); if(!u) return 3;
"#,
        );
        let drive = drive_typed_session_with_counter("h3", &app, &[130, 147], None, "marker", None);
        assert_eq!(
            drive.typed_sites, 5,
            "chain fixture yields five typed sites"
        );
        assert_eq!(
            drive.counter_links, 1,
            "one multi-link batches both same-file sites"
        );
        assert_eq!(drive.joined_sites, 2, "both sites must join");
        assert_eq!(drive.joined_calls, 4, "three fetches plus one construct");
        assert_eq!(drive.definite, 0, "ambiguity withholds the positive");
        assert_eq!(
            drive.unresolved_calls, 6,
            "4 known hits + 2 loss events via the conservative foreign bound"
        );
        assert_eq!(drive.withheld_uncertain, 0);
        assert_eq!(drive.sample_sites, 2, "counter saw only the two sites");
        assert_eq!(drive.sample_calls, 4, "every physical hit joined");
        assert!(
            drive.next_producer_id > 1,
            "kernel minted producer IDs (host seeds 1)"
        );
        assert_eq!(
            drive.loss_cells,
            [0, 0, 1, 0, 1, 0, 0, 0],
            "exactly the quarantine tombstone (CONFLICT) + its refused \
             construction's unmatched return (PAIR)"
        );
    }
    /// U1 complete-chain fixture: a fake MAC + KDF provider behind one
    /// query surface. Public typed exports cover fetch/free/getctx/new/
    /// dup/free/reset/cleanup for both families; the MAC dispatch table
    /// advertises function IDs 1..6 (new/dup/free/init/update/final) and
    /// the KDF table 1..5 (new/dup/free/reset/derive). `main` drives the
    /// full chain (query both ops, fetch, construct with nested getctx +
    /// newctx, dup, init/update/final/derive, reset, free all, cleanup)
    /// and exits 0 only if every callback returned its contract value,
    /// so exit 0 plus the exec marker oracles the public chain. Callback
    /// bodies differ pairwise (distinct constants) so no toolchain fold
    /// can merge two callbacks onto one address.
    /// Complete-chain C template shared by the standard, firstbyte
    /// and remap fixtures. `DERIVE_ATTR` marks the derive definition's
    /// attribute slot: empty for the standard build, a section attribute
    /// isolating the derive for the firstbyte link (`.text.i2first`)
    /// or the remap link (`.text.remapx`); the remap link
    /// additionally isolates the derive's byte-twin
    /// `test_kdf_derive_y` (defined inside `#ifdef REMAP_RACE`) in
    /// `.text.remapy`. Live-table modes by
    /// third argv word: none (2-arg) normal; `mutate-kdf-table` or any
    /// other word drops (4,4) from the live KDF table and drives the
    /// direct reset + second derive (I2); `i1-swap45`/`i1-swap34`
    /// advertise an alternate same-file callback the static plan never
    /// stages (I1); `i3-drop45` omits (4,5) from the live table (I3);
    /// `i1-remap45:<nonce>` (remap build only, `REMAP_RACE`) races a
    /// page toggle against derive calls (remap control). Every mode
    /// exits 0 on the public chain. Callback bodies differ pairwise
    /// (distinct constants) so no toolchain fold can merge two
    /// callbacks onto one address. The KDF derive body is shared via
    /// the `KDF_DERIVE_BODY` macro (call-free volatile fill, behavior
    /// identical to the old memset form) so the remap link's byte-twin
    /// cannot skew from it; the twin's page bytes must equal the
    /// derive page's (verified, not trusted, by the remap control),
    /// which is what keeps mid-toggle execution sound. All other
    /// remap-only C lives inside `#ifdef REMAP_RACE`.
    fn complete_chain_c_template() -> &'static str {
        r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef REMAP_RACE
#include <sys/mman.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <time.h>
#include <stdatomic.h>
#endif
struct dispatch { int id; void (*fn)(void); };
struct algorithm { const char *names, *properties; const struct dispatch *implementation; const char *description; };
__attribute__((noinline)) void *test_mac_newctx(void *c) { (void)c; __asm__ volatile(""); void *x = malloc(32); if (x) memset(x, 0xA1, 32); return x; }
__attribute__((noinline)) void *test_mac_dupctx(void *x) { (void)x; __asm__ volatile(""); void *y = malloc(32); if (y) memset(y, 0xA2, 32); return y; }
__attribute__((noinline)) void test_mac_freectx(void *x) { __asm__ volatile(""); volatile unsigned char probe = *(volatile unsigned char *)x; (void)probe; free(x); }
__attribute__((noinline)) int test_mac_init(void *x, int v) { (void)x; __asm__ volatile(""); return v + 1; }
__attribute__((noinline)) int test_mac_update(void *x, const void *in, unsigned long len) { (void)x; (void)in; __asm__ volatile(""); return (int)(len & 0x7fffffff); }
__attribute__((noinline)) int test_mac_final(void *x, void *out) { (void)x; __asm__ volatile(""); if (out) memset(out, 0xC3, 16); return 1; }
__attribute__((noinline)) void *test_kdf_newctx(void *c) { (void)c; __asm__ volatile(""); void *x = malloc(32); if (x) memset(x, 0xB1, 32); return x; }
__attribute__((noinline)) void *test_kdf_dupctx(void *x) { (void)x; __asm__ volatile(""); void *y = malloc(32); if (y) memset(y, 0xB2, 32); return y; }
__attribute__((noinline)) void test_kdf_freectx(void *x) { __asm__ volatile(""); free(x); volatile int sink = 0; (void)sink; }
__attribute__((noinline)) void test_kdf_reset(void *x) { (void)x; __asm__ volatile(""); }
#define KDF_DERIVE_BODY { (void)x; __asm__ volatile(""); volatile unsigned char *p = (volatile unsigned char *)out; unsigned long n = len < 32 ? len : 32; if (p) { for (unsigned long i = 0; i < n; i++) p[i] = 0xC7; } return 1; }
__attribute__((noinline)) DERIVE_ATTRint test_kdf_derive(void *x, void *out, unsigned long len) KDF_DERIVE_BODY
__attribute__((noinline)) int test_kdf_derive_alt(void *x, void *out, unsigned long len) { (void)x; __asm__ volatile(""); if (out) memset(out, 0xC9, len < 32 ? len : 32); return 1; }
#ifdef REMAP_RACE
__attribute__((noinline, used, section(".text.remapy"))) int test_kdf_derive_y(void *x, void *out, unsigned long len) KDF_DERIVE_BODY
#endif
__attribute__((noinline)) int test_mac_init_alt(void *x, int v) { (void)x; __asm__ volatile(""); return v + 7; }
static const struct dispatch mac_dispatch[] = {
 { 1, (void(*)(void))test_mac_newctx }, { 2, (void(*)(void))test_mac_dupctx }, { 3, (void(*)(void))test_mac_freectx },
 { 4, (void(*)(void))test_mac_init }, { 5, (void(*)(void))test_mac_update }, { 6, (void(*)(void))test_mac_final }, { 0, 0 } };
static const struct dispatch kdf_dispatch[] = {
 { 1, (void(*)(void))test_kdf_newctx }, { 2, (void(*)(void))test_kdf_dupctx }, { 3, (void(*)(void))test_kdf_freectx },
 { 4, (void(*)(void))test_kdf_reset }, { 5, (void(*)(void))test_kdf_derive }, { 0, 0 } };
static const struct algorithm mac_algorithms[] = { { "FAKE-MAC", 0, mac_dispatch, "fake mac" }, { 0, 0, 0, 0 } };
static const struct algorithm kdf_algorithms[] = { { "FAKE-KDF", 0, kdf_dispatch, "fake kdf" }, { 0, 0, 0, 0 } };
static int g_table_mode = 0;
static struct dispatch kdf_live_dispatch[6];
static struct algorithm kdf_live_algorithms[2];
static struct dispatch mac_live_dispatch[7];
static struct algorithm mac_live_algorithms[2];
__attribute__((noinline)) const struct algorithm *OSSL_PROVIDER_query_operation(const void *provider, int op, int *no_cache) {
 (void)provider;
 *no_cache = 0;
 if (op == 3) {
  if (g_table_mode != 3) return mac_algorithms;
  for (int i = 0; i < 7; i++) mac_live_dispatch[i] = mac_dispatch[i];
  mac_live_dispatch[3].fn = (void(*)(void))test_mac_init_alt;
  mac_live_algorithms[0].names = "FAKE-MAC"; mac_live_algorithms[0].properties = 0;
  mac_live_algorithms[0].implementation = mac_live_dispatch; mac_live_algorithms[0].description = "fake mac";
  mac_live_algorithms[1].names = 0; mac_live_algorithms[1].properties = 0;
  mac_live_algorithms[1].implementation = 0; mac_live_algorithms[1].description = 0;
  return mac_live_algorithms;
 }
 if (op == 4) {
  if (!g_table_mode || g_table_mode == 3) return kdf_algorithms;
  for (int i = 0; i < 6; i++) kdf_live_dispatch[i] = kdf_dispatch[i];
  if (g_table_mode == 1) kdf_live_dispatch[3] = kdf_live_dispatch[4];
  else if (g_table_mode == 2) kdf_live_dispatch[4].fn = (void(*)(void))test_kdf_derive_alt;
  else if (g_table_mode == 4) kdf_live_dispatch[4] = kdf_live_dispatch[3];
  kdf_live_algorithms[0].names = "FAKE-KDF"; kdf_live_algorithms[0].properties = 0;
  kdf_live_algorithms[0].implementation = kdf_live_dispatch; kdf_live_algorithms[0].description = "fake kdf";
  kdf_live_algorithms[1].names = 0; kdf_live_algorithms[1].properties = 0;
  kdf_live_algorithms[1].implementation = 0; kdf_live_algorithms[1].description = 0;
  return kdf_live_algorithms;
 }
 return 0;
}
static void *fake_libctx; static void *fake_mac_method; static void *fake_kdf_method; static void *fake_provider;
void *EVP_MAC_fetch(void *c, const char *n, const char *p) { (void)p; if (!c || !n || !*n) return 0; return fake_mac_method; }
void EVP_MAC_free(void *m) { (void)m; }
void *EVP_KDF_fetch(void *c, const char *n, const char *p) { (void)p; if (!c || !n || !*n) return 0; return fake_kdf_method; }
void EVP_KDF_free(void *m) { (void)m; }
void *OSSL_PROVIDER_get0_provider_ctx(const void *p) { if (p != fake_provider) return 0; return fake_libctx; }
typedef struct { void *method, *provctx, *data; } FAKE_CTX;
void *EVP_MAC_CTX_new(void *m) {
 if (m != fake_mac_method) return 0;
 void *c = OSSL_PROVIDER_get0_provider_ctx(fake_provider); if (!c) return 0;
 void *x = test_mac_newctx(c); if (!x) return 0;
 FAKE_CTX *u = malloc(sizeof *u); if (!u) return 0;
 u->method = m; u->provctx = c; u->data = x; return u;
}
void *EVP_KDF_CTX_new(void *k) {
 if (k != fake_kdf_method) return 0;
 void *c = OSSL_PROVIDER_get0_provider_ctx(fake_provider); if (!c) return 0;
 void *x = test_kdf_newctx(c); if (!x) return 0;
 FAKE_CTX *u = malloc(sizeof *u); if (!u) return 0;
 u->method = k; u->provctx = c; u->data = x; return u;
}
void *EVP_MAC_CTX_dup(void *u) {
 FAKE_CTX *src = u; if (!src) return 0;
 void *x2 = test_mac_dupctx(src->data); if (!x2) return 0;
 FAKE_CTX *dst = malloc(sizeof *dst); if (!dst) return 0;
 *dst = *src; dst->data = x2; return dst;
}
void *EVP_KDF_CTX_dup(void *u) {
 FAKE_CTX *src = u; if (!src) return 0;
 void *x2 = test_kdf_dupctx(src->data); if (!x2) return 0;
 FAKE_CTX *dst = malloc(sizeof *dst); if (!dst) return 0;
 *dst = *src; dst->data = x2; return dst;
}
void EVP_MAC_CTX_free(void *u) { if (!u) return; test_mac_freectx(((FAKE_CTX *)u)->data); free(u); }
void EVP_KDF_CTX_free(void *u) { if (!u) return; test_kdf_freectx(((FAKE_CTX *)u)->data); free(u); }
void EVP_KDF_CTX_reset(void *u) { if (!u) return; test_kdf_reset(((FAKE_CTX *)u)->data); }
int test_mac_init_call(void *u, int v) { return test_mac_init(((FAKE_CTX *)u)->data, v); }
int test_mac_update_call(void *u, const void *in, unsigned long len) { return test_mac_update(((FAKE_CTX *)u)->data, in, len); }
int test_mac_final_call(void *u, void *out) { return test_mac_final(((FAKE_CTX *)u)->data, out); }
int test_kdf_derive_call(void *u, void *out, unsigned long len) { return test_kdf_derive(((FAKE_CTX *)u)->data, out, len); }
void OPENSSL_cleanup(void) { __asm__ volatile(""); }
#ifdef REMAP_RACE
static atomic_int g_remap_stop = 0;
static unsigned long g_remap_toggles = 0;
static void *g_remap_page;
static unsigned long g_remap_off_x, g_remap_off_y;
static int g_remap_fd = -1;
static int remap_page_offset(void *addr, unsigned long *out) {
 FILE *f = fopen("/proc/self/maps", "r");
 if (!f) return -1;
 char *line = 0; size_t n = 0;
 unsigned long want = (unsigned long)addr & ~(4095UL);
 int rc = -1;
 while (getline(&line, &n, f) > 0) {
  unsigned long lo, hi, off; char perms[8];
  if (sscanf(line, "%lx-%lx %7s %lx", &lo, &hi, perms, &off) == 4) {
   if (want >= lo && want < hi) { *out = off + (want - lo); rc = 0; break; }
  }
 }
 free(line); fclose(f);
 return rc;
}
static int remap_map(unsigned long off) {
 void *r = mmap(g_remap_page, 4096, PROT_READ | PROT_EXEC, MAP_FIXED | MAP_PRIVATE, g_remap_fd, (off_t)off);
 return r == MAP_FAILED ? -1 : 0;
}
static int remap_phase_a(void) {
 if (sysconf(_SC_PAGESIZE) != 4096) return -1;
 if ((((unsigned long)test_kdf_derive) & 4095UL) != (((unsigned long)test_kdf_derive_y) & 4095UL)) return -1;
 g_remap_page = (void *)(((unsigned long)test_kdf_derive) & ~(4095UL));
 if (remap_page_offset((void *)test_kdf_derive, &g_remap_off_x) != 0) return -1;
 if (remap_page_offset((void *)test_kdf_derive_y, &g_remap_off_y) != 0) return -1;
 if (!g_remap_off_x || !g_remap_off_y || g_remap_off_x == g_remap_off_y) return -1;
 g_remap_fd = open("/proc/self/exe", O_RDONLY);
 if (g_remap_fd < 0) return -1;
 return remap_map(g_remap_off_y);
}
static void *remap_toggler(void *unused) {
 (void)unused;
 int which = 0;
 while (!atomic_load(&g_remap_stop)) {
  unsigned long off = which ? g_remap_off_y : g_remap_off_x;
  which ^= 1;
  if (remap_map(off) != 0) _exit(8);
  g_remap_toggles++;
 }
 return 0;
}
static int remap_race(void *ku, const char *mode_arg) {
 unsigned char out[32];
 unsigned long x_exec = 0;
 int i;
 for (i = 0; i < 3; i++) {
  memset(out, 0, sizeof out);
  if (test_kdf_derive_call(ku, out, 32) != 1 || out[0] != 0xC7) return -1;
  x_exec++;
 }
 pthread_t th;
 atomic_store(&g_remap_stop, 0);
 unsigned long toggles_before = g_remap_toggles;
 if (pthread_create(&th, 0, remap_toggler, 0) != 0) return -1;
 struct timespec tick = { 0, 5000 };
 for (i = 0; i < 100000; i++) {
  if (clock_nanosleep(CLOCK_MONOTONIC, 0, &tick, 0) != 0) { atomic_store(&g_remap_stop, 1); pthread_join(th, 0); return -1; }
  memset(out, 0, sizeof out);
  if (test_kdf_derive_call(ku, out, 32) != 1 || out[0] != 0xC7) { atomic_store(&g_remap_stop, 1); pthread_join(th, 0); return -1; }
  x_exec++;
 }
 atomic_store(&g_remap_stop, 1);
 pthread_join(th, 0);
 unsigned long toggles_during = g_remap_toggles - toggles_before;
 if (remap_map(g_remap_off_x) != 0) return -1;
 const char *colon = strchr(mode_arg, ':');
 if (!colon || !colon[1]) return -1;
 const char *nonce = colon + 1;
 size_t nlen = strlen(nonce);
 if (nlen == 0 || nlen > 64) return -1;
 for (size_t k = 0; k < nlen; k++) {
  char c = nonce[k];
  if (!((c >= '0' && c <= '9') || c == '-' || c == '_')) return -1;
 }
 const char *tmp = getenv("TMPDIR");
 if (!tmp || !*tmp) tmp = "/tmp";
 char path[512];
 int w = snprintf(path, sizeof path, "%s/osslscope-remap-%s.stats", tmp, nonce);
 if (w < 0 || (size_t)w >= sizeof path) return -1;
 FILE *sf = fopen(path, "w");
 if (!sf) return -1;
 fprintf(sf, "toggles=%lu x_exec=%lu\n", toggles_during, x_exec);
 if (fclose(sf) != 0) return -1;
 close(g_remap_fd);
 g_remap_fd = -1;
 return 0;
}
#endif
int main(int argc, char **argv) {
 if (argc < 2 || argc > 3) return 2;
 FILE *f = fopen(argv[1], "w"); if (!f) return 4; fputs("exec\n", f); fclose(f);
 fake_libctx = malloc(16); fake_mac_method = malloc(16); fake_kdf_method = malloc(16); fake_provider = malloc(16);
 if (!fake_libctx || !fake_mac_method || !fake_kdf_method || !fake_provider) return 5;
 g_table_mode = 0;
 if (argc > 2) {
  if (!strcmp(argv[2], "i1-swap45")) g_table_mode = 2;
  else if (!strcmp(argv[2], "i1-swap34")) g_table_mode = 3;
  else if (!strcmp(argv[2], "i3-drop45")) g_table_mode = 4;
#ifdef REMAP_RACE
  else if (!strncmp(argv[2], "i1-remap45", 10)) g_table_mode = 5;
#endif
  else g_table_mode = 1;
 }
#ifdef REMAP_RACE
 if (g_table_mode == 5 && remap_phase_a() != 0) return 6;
#endif
 int nc = -1;
 if (OSSL_PROVIDER_query_operation(fake_provider, 3, &nc) == 0 || nc != 0) return 3;
 nc = -1;
 if (OSSL_PROVIDER_query_operation(fake_provider, 4, &nc) == 0 || nc != 0) return 3;
#ifdef REMAP_RACE
 if (g_table_mode == 5 && remap_map(g_remap_off_x) != 0) return 6;
#endif
 void *m = EVP_MAC_fetch(fake_libctx, "FAKE-MAC", 0); if (!m) return 3;
 void *k = EVP_KDF_fetch(fake_libctx, "FAKE-KDF", 0); if (!k) return 3;
 void *u = EVP_MAC_CTX_new(m); if (!u) return 3;
 void *ku = EVP_KDF_CTX_new(k); if (!ku) return 3;
 void *u2 = EVP_MAC_CTX_dup(u); if (!u2 || u2 == u) return 3;
 void *ku2 = EVP_KDF_CTX_dup(ku); if (!ku2 || ku2 == ku) return 3;
 if (test_mac_init_call(u, 41) != 42) return 3;
 if (test_mac_update_call(u, "abc", 3) != 3) return 3;
 unsigned char out[16];
 if (test_mac_final_call(u, out) != 1 || out[0] != 0xC3) return 3;
 unsigned char kout[32];
#ifdef REMAP_RACE
 if (g_table_mode == 5) { if (remap_race(ku, argv[2]) != 0) return 3; } else
#endif
 if (test_kdf_derive_call(ku, kout, 32) != 1 || kout[0] != 0xC7) return 3;
 if (g_table_mode == 1) test_kdf_reset(((FAKE_CTX *)ku)->data); else EVP_KDF_CTX_reset(ku);
 if (g_table_mode == 1) { if (test_kdf_derive_call(ku, kout, 32) != 1 || kout[0] != 0xC7) return 3; }
 EVP_MAC_CTX_free(u2); EVP_MAC_CTX_free(u); EVP_KDF_CTX_free(ku2); EVP_KDF_CTX_free(ku);
 EVP_MAC_free(m); EVP_KDF_free(k);
 OPENSSL_cleanup();
 return 0;
}
"#
    }
    fn source_native_complete_chain_fixture(dir: &std::path::Path) -> std::path::PathBuf {
        let source = dir.join("app.c");
        let app = dir.join("app");
        let rendered = complete_chain_c_template().replace("DERIVE_ATTR", "");
        assert!(
            !rendered.contains("DERIVE_ATTR"),
            "template marker must render"
        );
        std::fs::write(&source, rendered).unwrap();
        let status = std::process::Command::new("cc")
            .args(["-O0", "-rdynamic", "-o"])
            .arg(&app)
            .arg(&source)
            .status()
            .unwrap();
        assert!(status.success(), "complete-chain fixture must compile");
        app
    }
    /// Firstbyte complete-chain fixture: the same chain with the KDF
    /// derive isolated in `.text.i2first` and linked FIRST in the
    /// executable segment (minimal `_start`, no startfiles, no PLT,
    /// separate code), so the derive callback sits at the first byte
    /// of its executable VMA. x86_64 only (assembly `_start`); the
    /// control verifies the placement premise from the ELF before
    /// driving, and refuses loudly if the toolchain surprises.
    #[cfg(target_arch = "x86_64")]
    fn source_native_firstbyte_chain_fixture(dir: &std::path::Path) -> std::path::PathBuf {
        let source = dir.join("app.c");
        let app = dir.join("app");
        let start = dir.join("start.s");
        let script = dir.join("firstbyte.ld");
        let rendered = complete_chain_c_template().replace(
            "DERIVE_ATTR",
            "__attribute__((section(\".text.i2first\"))) ",
        );
        assert!(
            !rendered.contains("DERIVE_ATTR"),
            "template marker must render"
        );
        std::fs::write(&source, rendered).unwrap();
        std::fs::write(
            &start,
            ".globl _start\n_start:\n xor %rbp,%rbp\n mov %rdx,%r9\n pop %rsi\n mov %rsp,%rdx\n and $-16,%rsp\n push %rax\n push %rsp\n xor %r8d,%r8d\n xor %ecx,%ecx\n leaq main(%rip),%rdi\n call *__libc_start_main@GOTPCREL(%rip)\n hlt\n",
        )
        .unwrap();
        std::fs::write(
            &script,
            "SECTIONS { .text.i2first : { KEEP(*(.text.i2first)) } } INSERT BEFORE .text\n",
        )
        .unwrap();
        let status = std::process::Command::new("cc")
            .args([
                "-O0",
                "-fno-plt",
                "-rdynamic",
                "-nostartfiles",
                "-Wl,-z,separate-code",
            ])
            .arg({
                let mut flag = std::ffi::OsString::from("-Wl,-T,");
                flag.push(&script);
                flag
            })
            .args(["-o"])
            .arg(&app)
            .arg(&start)
            .arg(&source)
            .status()
            .unwrap();
        assert!(status.success(), "firstbyte fixture must compile");
        app
    }
    /// Remap complete-chain fixture: the same chain with the KDF derive
    /// isolated in `.text.remapx` and its byte-twin `test_kdf_derive_y`
    /// in `.text.remapy`, each page-aligned on its own page with the
    /// symbol first (same in-page offset), plus the `REMAP_RACE`
    /// page-toggle machinery and pthreads. The control verifies the
    /// placement premises from the ELF before driving (including
    /// byte-identical page contents, which is what keeps mid-toggle
    /// execution sound), and refuses loudly if the toolchain
    /// surprises.
    fn source_native_remap_chain_fixture(dir: &std::path::Path) -> std::path::PathBuf {
        let source = dir.join("app.c");
        let app = dir.join("app");
        let script = dir.join("remap.ld");
        let rendered = complete_chain_c_template()
            .replace("DERIVE_ATTR", "__attribute__((section(\".text.remapx\"))) ");
        assert!(
            !rendered.contains("DERIVE_ATTR"),
            "template marker must render"
        );
        std::fs::write(&source, rendered).unwrap();
        std::fs::write(
            &script,
            "SECTIONS { . = ALIGN(0x1000); .text.remapx : { KEEP(*(.text.remapx)) } . = ALIGN(0x1000); .text.remapy : { KEEP(*(.text.remapy)) } . = ALIGN(0x1000); } INSERT BEFORE .text\n",
        )
        .unwrap();
        let status = std::process::Command::new("cc")
            .args(["-O0", "-rdynamic", "-pthread", "-DREMAP_RACE"])
            .arg({
                let mut flag = std::ffi::OsString::from("-Wl,-T,");
                flag.push(&script);
                flag
            })
            .args(["-o"])
            .arg(&app)
            .arg(&source)
            .status()
            .unwrap();
        assert!(status.success(), "remap fixture must compile");
        app
    }
    /// Fixture public-chain oracle without BPF: every live-table mode of
    /// the standard fixture exits 0 and writes the exec marker, so any
    /// later native failure is attribution evidence, never a broken
    /// workload.
    #[test]
    fn complete_chain_fixture_all_modes_exit_zero() {
        let dir =
            std::env::temp_dir().join(format!("osslscope-fixture-modes-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let app = source_native_complete_chain_fixture(&dir);
        for (tag, extra) in [
            ("m0", None),
            ("m1", Some("mutate-kdf-table")),
            ("m2", Some("i1-swap45")),
            ("m3", Some("i1-swap34")),
            ("m4", Some("i3-drop45")),
        ] {
            let marker = dir.join(format!("marker-{tag}"));
            let mut command = std::process::Command::new(&app);
            command.arg(&marker);
            if let Some(word) = extra {
                command.arg(word);
            }
            let status = command.status().unwrap();
            assert!(status.success(), "mode {tag} must exit 0");
            assert_eq!(std::fs::read(&marker).unwrap(), b"exec\n");
        }
    }
    /// Firstbyte fixture public-chain oracle without BPF (x86_64):
    /// the minimal-startup, no-PLT layout runs the normal chain to
    /// exit 0 with the exec marker.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn firstbyte_fixture_exits_zero() {
        let dir = std::env::temp_dir().join(format!("osslscope-fixture-fb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let app = source_native_firstbyte_chain_fixture(&dir);
        let marker = dir.join("marker-fb");
        let status = std::process::Command::new(&app)
            .arg(&marker)
            .status()
            .unwrap();
        assert!(status.success(), "firstbyte normal mode must exit 0");
        assert_eq!(std::fs::read(&marker).unwrap(), b"exec\n");
    }
    /// Parse one `toggles=%lu x_exec=%lu` remap stats file. `toggles`
    /// counts mapping flips strictly inside the race loop (bracketed
    /// counter, so a still toggle cannot inflate it); `x_exec` counts
    /// derive calls that returned the expected bytes (3 steady plus
    /// the 100000 race calls — the X/Y pages are byte-identical, so
    /// every call observes identical behavior whatever the mapping).
    fn remap_stats_parse(path: &std::path::Path) -> (u64, u64) {
        let text = std::fs::read_to_string(path).unwrap();
        let mut toggles = None;
        let mut x_exec = None;
        for cell in text.split_whitespace() {
            let (key, value) = cell.split_once('=').unwrap();
            let parsed: u64 = value.parse().unwrap();
            match key {
                "toggles" => toggles = Some(parsed),
                "x_exec" => x_exec = Some(parsed),
                _ => panic!("unknown stats cell {key}"),
            }
        }
        (
            toggles.expect("stats carry toggles"),
            x_exec.expect("stats carry x_exec"),
        )
    }
    /// Remap fixture public-chain oracle without BPF: the normal chain
    /// exits 0 with the exec marker, and the remap mode exits 0 with
    /// the exact call count and a well-formed stats file — so any
    /// later native failure is attribution evidence, never a broken
    /// workload. Toggle volume is proven by the native (serial,
    /// trap-slowed loop), not here.
    #[test]
    fn remap_fixture_modes_exit_zero() {
        let dir = std::env::temp_dir().join(format!("osslscope-fixture-rm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let app = source_native_remap_chain_fixture(&dir);
        let marker = dir.join("marker-rm0");
        let status = std::process::Command::new(&app)
            .arg(&marker)
            .status()
            .unwrap();
        assert!(status.success(), "remap normal mode must exit 0");
        assert_eq!(std::fs::read(&marker).unwrap(), b"exec\n");
        let nonce = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let marker = dir.join("marker-rm5");
        let status = std::process::Command::new(&app)
            .arg(&marker)
            .arg(format!("i1-remap45:{nonce}"))
            .status()
            .unwrap();
        assert!(status.success(), "remap race mode must exit 0");
        assert_eq!(std::fs::read(&marker).unwrap(), b"exec\n");
        let stats = std::env::temp_dir().join(format!("osslscope-remap-{nonce}.stats"));
        let (toggles, x_exec) = remap_stats_parse(&stats);
        std::fs::remove_file(&stats).unwrap();
        eprintln!("remap oracle: toggles={toggles} x_exec={x_exec}");
        assert_eq!(
            x_exec, 100003,
            "3 steady plus 100000 race calls, all with expected bytes"
        );
    }
    /// U1 pass 1: legacy-only observation run. Attaches the discovered
    /// legacy API sites (the query export), releases the fixture, waits
    /// for the exit-0 oracle, and drains validated RAW ring records
    /// (op, algorithm index, function per IMPLEMENTATION plus the QUERY
    /// delimiters the matcher groups by). Any undecodable record fails
    /// the pass: the plan must rest on fully validated observations.
    /// Returns the records plus every discovered file's array-grouping
    /// inputs (multi-file: dependency tables participate in matching and
    /// lose honestly when their shapes differ).
    fn run_pass1_legacy_observation(
        app: &std::path::Path,
    ) -> (
        Vec<super::wire::contract::Record>,
        Vec<super::copied_plan::FileArrays>,
    ) {
        let dir = app.parent().unwrap().to_path_buf();
        let marker = dir.join("marker1");
        let argv = [
            app.to_string_lossy().into_owned(),
            marker.to_string_lossy().into_owned(),
        ];
        let fds_before = source_native_fd_targets();
        let mut child =
            crate::target::OwnedTarget::spawn_stopped(&argv, crate::target::WorkloadDest::Null)
                .unwrap();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let mut budget = ObservationBudget::default();
        let startup = crate::startup_objects::prepare_owned_startup(
            &child,
            &argv,
            &mut budget,
            Instant::now() + Duration::from_secs(15),
            &cancel,
            None,
        )
        .unwrap();
        assert_eq!(startup.apis.len(), 1, "fixture exposes one legacy API site");
        eprintln!(
            "pass1 startup candidates={} gaps={:?} files={}",
            startup.candidates.len(),
            startup.gaps,
            startup.plan_arrays.len(),
        );
        assert!(
            !startup.candidates.is_empty(),
            "fixture must parse dispatch candidates"
        );
        let plan_arrays = startup.plan_arrays;
        let object =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        let mut session = ProviderSession::open(ObservationLimits::default(), &object).unwrap();
        session
            .prearm_startup(
                startup.apis,
                Instant::now() + Duration::from_secs(15),
                &cancel,
                PrearmLinks::Create,
            )
            .unwrap();
        child.release().unwrap();
        let until = Instant::now() + Duration::from_secs(15);
        while !marker.exists() {
            assert!(Instant::now() < until, "pass-1 exec marker never appeared");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(std::fs::read(&marker).unwrap(), b"exec\n");
        while child.peek_exit().unwrap().is_none() {
            assert!(Instant::now() < until, "pass-1 workload never exited");
            std::thread::yield_now();
        }
        assert_eq!(child.poll_exit().unwrap(), Some(0), "pass-1 public oracle");
        let mut records = Vec::new();
        let mut decode_failures = 0usize;
        while let Some(bytes) = session.events.next() {
            match super::wire::decode_transport(&bytes) {
                Ok(transport) => records.push(transport.record()),
                Err(_) => decode_failures += 1,
            }
        }
        eprintln!(
            "pass1 records={} decode_failures={}",
            records.len(),
            decode_failures
        );
        assert_eq!(decode_failures, 0, "every ring record must validate");
        drop(session);
        drop(child);
        // Pass-1 FD hygiene is BPF-scoped: every BPF FD (maps, programs,
        // links) must return to baseline exactly. The non-BPF survivors
        // (pidfd, deleted /proc handle, retained app/libc handles) are
        // the same documented ghost-Rc phenomenon the typed driver pins
        // at +1 for its flow (see source_native_assert_fds_return);
        // placing the ghost holder is that pre-existing follow-up, and
        // pass-2's strict check covers the full-flow non-BPF baseline.
        let after = source_native_fd_targets();
        let bpf = |fds: &[String]| {
            fds.iter()
                .filter(|fd| {
                    fd.contains("bpf-map") || fd.contains("bpf-prog") || fd.contains("bpf_link")
                })
                .count()
        };
        eprintln!(
            "pass1 fds before={} after={}",
            fds_before.len(),
            after.len()
        );
        assert_eq!(bpf(&after), bpf(&fds_before), "pass-1 BPF FDs must return");
        (records, plan_arrays)
    }
    /// U1 plan assembly: pass-1 live queries exact-matched against every
    /// discovered file's array inputs (the pass-1 discovery's own parse
    /// output, not a recomputation or a reopen). Plan entries key by
    /// file hash; pass-2 discovery verifies membership in its own
    /// retained bytes before staging.
    fn stage_copied_plan_from_pass1(app: &std::path::Path) -> super::copied_plan::CopiedPlan {
        let (records, arrays) = run_pass1_legacy_observation(app);
        let live = super::copied_plan::collect_live_queries(&records);
        eprintln!("pass1 live_queries={live:?}");
        let plan_budget = ObservationBudget::default();
        super::copied_plan::generate_plan(&arrays, &live, &plan_budget).unwrap()
    }
    /// U1 complete-chain staging control: pass 1 (legacy-only) observes
    /// the live MAC+KDF queries; the plan exact-matches them to the
    /// retained arrays; pass 2 stages the query role plus all 11 copied
    /// sites through the receipt protocol and proves constructor commit:
    /// both owners commit (exact 44-mint decomposition), both dup contexts
    /// stay unpropagated, both frees retire, the loss vector carries only
    /// the by-design Phase-1 teardown poison (cell 3, from the trailing
    /// 155 cleanup; every other cell zero), and definite stays 0 because
    /// U1 attaches the operational counter nowhere (the typed-side
    /// operational links are inert by role gate). U2 attaches that counter
    /// and proves the first partitions.
    ///
    /// ```sh
    /// OSSL_PROVIDER_OBSERVATION_TEST_BPF=<provider object> \
    /// OSSLSCOPE_FOCUSED_COUNT_OBJECT=<count object> \
    /// sudo -n cargo test --locked --offline --lib -- --ignored \
    ///     copied_roles_stage_from_observed_callbacks --nocapture
    /// ```
    #[test]
    #[ignore = "two-pass copied-role staging control (sudo, cc)"]
    fn copied_roles_stage_from_observed_callbacks() {
        let dir = std::env::temp_dir().join(format!("osslscope-copied-u1-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let app = source_native_complete_chain_fixture(&dir);
        let plan = stage_copied_plan_from_pass1(&app);
        assert_eq!(plan.sites.len(), 11, "MAC 6 + KDF 5 copied sites");
        let mut roles: Vec<u32> = plan.sites.iter().map(|site| site.role_id).collect();
        roles.sort_unstable();
        assert_eq!(
            roles,
            vec![258, 259, 274, 275, 290, 291, 304, 305, 306, 307, 308]
        );
        let mut offsets: Vec<u64> = plan.sites.iter().map(|site| site.offset).collect();
        offsets.sort_unstable();
        offsets.dedup();
        assert_eq!(offsets.len(), 11, "no two callbacks share an address");
        let drive = drive_typed_session_with_counter(
            "u1",
            &app,
            &[258, 259, 274, 275, 290, 291],
            Some(&plan),
            "marker2",
            None,
        );
        assert_eq!(
            drive.staged_roles,
            vec![
                130, 131, 136, 137, 146, 147, 148, 149, 150, 151, 152, 153, 155, 161, 258, 259,
                274, 275, 290, 291, 304, 305, 306, 307, 308,
            ],
            "13 first-slice + query + 11 copied"
        );
        assert_eq!(drive.typed_sites, 25);
        assert_eq!(
            drive.copied_skipped, 0,
            "pass-2 rescan agrees with the pass-1 plan on all 11 sites"
        );
        assert_eq!(
            drive.counter_links, 1,
            "one multi-link batches the six sites"
        );
        assert_eq!(drive.joined_sites, 6, "all six counted sites join");
        assert_eq!(drive.joined_calls, 8, "1+1 new + 2+2 free + 1+1 dup");
        assert_eq!(
            drive.definite, 0,
            "U1 attaches no operational counter: typed-side operational links stay inert"
        );
        assert_eq!(
            drive.unresolved_calls, 9,
            "eight physical hits plus the teardown-poison foreign bound, all unresolved without partitions"
        );
        assert_eq!(drive.withheld_uncertain, 0);
        assert_eq!(drive.sample_sites, 6);
        assert_eq!(drive.sample_calls, 8);
        assert_eq!(
            drive.next_producer_id, 45,
            "44 mints on a counter starting at 1: 14 occurrences (fetch/query/new/dup x2, nested newctx/dupctx/getctx x2) + 1 thread + 2 request interns + 2 METHOD rows + 14 commit serials (7 x2 owners) + 11 CODE_ROLE witnesses"
        );
        assert_eq!(
            drive.loss_cells,
            [0, 0, 0, 1, 0, 0, 0, 0],
            "cell 3 is the by-design Phase-1 teardown poison from the 155 OPENSSL_cleanup entry (the chain's last call); every other cell stays zero"
        );
    }
    /// U2 operational-attach control: same two-pass staging as U1, but the
    /// pass-2 counter attaches at the five operational sites (304 init,
    /// 305 update, 306 final, 307 derive, 308 reset) instead of the
    /// lifecycle six. The first partitions prove the same-handler join end
    /// to end: every partitionable hit resolves (admission, CODE_ROLE
    /// authorization, committed X and OWNER at the entry snapshot,
    /// prepared selector, live digest) into a definite record. Site 308
    /// is retire-only by design (it retires the KDF owner at reset and
    /// never partitions), so its one hit stays unresolved next to the
    /// teardown-poison foreign bound. Lifecycle coverage stays U1's.
    ///
    /// ```sh
    /// OSSL_PROVIDER_OBSERVATION_TEST_BPF=<provider object> \
    /// OSSLSCOPE_FOCUSED_COUNT_OBJECT=<count object> \
    /// sudo -n cargo test --locked --offline --lib -- --ignored \
    ///     operational_roles_partition_from_staged_callbacks --nocapture
    /// ```
    #[test]
    #[ignore = "operational-attach control (sudo, cc)"]
    fn operational_roles_partition_from_staged_callbacks() {
        let dir = std::env::temp_dir().join(format!("osslscope-copied-u2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let app = source_native_complete_chain_fixture(&dir);
        let plan = stage_copied_plan_from_pass1(&app);
        assert_eq!(plan.sites.len(), 11, "same U1 plan: MAC 6 + KDF 5");
        let drive = drive_typed_session_with_counter(
            "u2",
            &app,
            &[304, 305, 306, 307, 308],
            Some(&plan),
            "marker2",
            None,
        );
        assert_eq!(
            drive.staged_roles,
            vec![
                130, 131, 136, 137, 146, 147, 148, 149, 150, 151, 152, 153, 155, 161, 258, 259,
                274, 275, 290, 291, 304, 305, 306, 307, 308,
            ],
            "13 first-slice + query + 11 copied"
        );
        assert_eq!(drive.typed_sites, 25);
        assert_eq!(
            drive.copied_skipped, 0,
            "pass-2 rescan agrees with the pass-1 plan on all 11 sites"
        );
        assert_eq!(
            drive.counter_links, 1,
            "one multi-link batches the five sites"
        );
        assert_eq!(drive.joined_sites, 5, "all five counted sites join");
        assert_eq!(
            drive.joined_calls, 5,
            "1 init + 1 update + 1 final + 1 derive + 1 reset"
        );
        assert_eq!(
            drive.definite, 4,
            "first partitions: every partitionable hit resolves to a definite record"
        );
        assert_eq!(
            drive.unresolved_calls, 2,
            "the retire-only 308 hit plus the teardown-poison foreign bound"
        );
        assert_eq!(drive.withheld_uncertain, 0);
        assert_eq!(drive.sample_sites, 5);
        assert_eq!(drive.sample_calls, 5);
        assert_eq!(
            drive.next_producer_id, 49,
            "U1's 44 mints plus 4 operational segment allocs, counter starts at 1"
        );
        assert_eq!(
            drive.loss_cells,
            [0, 0, 0, 1, 0, 0, 0, 0],
            "cell 3 is the by-design Phase-1 teardown poison; every other cell zero"
        );
    }
    /// I2 retire-on-absent-CODE_ROLE control: pass 1 runs the fixture
    /// normally so the plan stages all 11 copied sites including the 308
    /// reset; pass 2 runs the same binary with a third argv word, which
    /// (a) drops fun 4 from the LIVE KDF dispatch table (a duplicate fun
    /// 5 overwrites it, so the query walk publishes every CODE_ROLE row
    /// except (4,4) while static staging still matches all 11 sites),
    /// (b) invokes the reset callback directly, bypassing the
    /// first-slice wrapper retire (153) so the copied-site retire is the
    /// sole invalidator, and (c) derives a second time on the same
    /// pre-reset X after the reset. The first derive partitions (all
    /// static premises hold); nothing fires between it and the second
    /// derive except the unauthorized 308. So the second derive's
    /// refusal pins the fail-closed direction causally: 308 retired the
    /// shared X with no CODE_ROLE row, and 308's own hit never
    /// partitions. Against pre-fix objects this fails on unresolved
    /// (2, not 3): the lapsed 308 refuses without retiring, the second
    /// derive joins the 307 partition, and only the reset hit plus the
    /// poison stay unresolved.
    ///
    /// ```sh
    /// OSSL_PROVIDER_OBSERVATION_TEST_BPF=<provider object> \
    /// OSSLSCOPE_FOCUSED_COUNT_OBJECT=<count object> \
    /// sudo -n cargo test --locked --offline --lib -- --ignored \
    ///     operational_reset_without_code_role_still_retires --nocapture
    /// ```
    #[test]
    #[ignore = "retire-without-authority control (sudo, cc)"]
    fn operational_reset_without_code_role_still_retires() {
        let dir = std::env::temp_dir().join(format!("osslscope-copied-i2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let app = source_native_complete_chain_fixture(&dir);
        let plan = stage_copied_plan_from_pass1(&app);
        assert_eq!(
            plan.sites.len(),
            11,
            "pass-1 normal mode plans MAC 6 + KDF 5"
        );
        let mut roles: Vec<u32> = plan.sites.iter().map(|site| site.role_id).collect();
        roles.sort_unstable();
        assert_eq!(
            roles,
            vec![258, 259, 274, 275, 290, 291, 304, 305, 306, 307, 308]
        );
        let drive = drive_typed_session_with_counter(
            "i2",
            &app,
            &[304, 305, 306, 307, 308],
            Some(&plan),
            "marker2",
            Some("mutate-kdf-table"),
        );
        assert_eq!(
            drive.staged_roles,
            vec![
                130, 131, 136, 137, 146, 147, 148, 149, 150, 151, 152, 153, 155, 161, 258, 259,
                274, 275, 290, 291, 304, 305, 306, 307, 308,
            ],
            "13 first-slice + query + 11 copied"
        );
        assert_eq!(drive.typed_sites, 25);
        assert_eq!(
            drive.copied_skipped, 0,
            "static bytes stage the (4,4) site even though the live table drops it"
        );
        assert_eq!(
            drive.counter_links, 1,
            "one multi-link batches the five sites"
        );
        assert_eq!(drive.joined_sites, 5, "all five counted sites join");
        assert_eq!(
            drive.joined_calls, 6,
            "1 init + 1 update + 1 final + 2 derive + 1 reset"
        );
        assert_eq!(
            drive.definite, 4,
            "never certifies: only the four partitionable tuples assign, 308 assigns none"
        );
        assert_eq!(
            drive.unresolved_calls, 3,
            "still retires: the reset hit plus the post-reset derive refused on the retired X plus the teardown-poison foreign bound"
        );
        assert_eq!(drive.withheld_uncertain, 0);
        assert_eq!(drive.sample_sites, 5);
        assert_eq!(drive.sample_calls, 6);
        assert_eq!(
            drive.next_producer_id, 48,
            "U2's 49 minus the unpublished (4,4) CODE_ROLE witness; the duplicate (4,5) dedups without minting and the second derive reuses the 307 segment"
        );
        assert_eq!(
            drive.loss_cells,
            [0, 0, 0, 1, 0, 0, 0, 0],
            "cell 3 is the by-design Phase-1 teardown poison; every other cell zero"
        );
    }
    /// Fixture symbol file offset through the containing LOAD: the exact
    /// registration-offset premise for the substitution controls.
    fn fixture_symbol_file_offset(app: &std::path::Path, name: &str) -> u64 {
        let bytes = std::fs::read(app).unwrap();
        let elf = goblin::elf::Elf::parse(&bytes).unwrap();
        let sym = elf
            .syms
            .iter()
            .find(|s| elf.strtab.get_at(s.st_name) == Some(name))
            .unwrap_or_else(|| panic!("fixture must define {name}"));
        for ph in &elf.program_headers {
            if ph.p_type == goblin::elf::program_header::PT_LOAD
                && sym.st_value >= ph.p_vaddr
                && sym.st_value < ph.p_vaddr + ph.p_memsz
            {
                return ph.p_offset + (sym.st_value - ph.p_vaddr);
            }
        }
        panic!("{name} outside any LOAD");
    }
    /// I1 substitution control (KDF derive): pass 1 plans the staged
    /// derive B from static bytes; pass 2's live KDF table advertises
    /// the alternate same-file callback A for (4,5) instead. The staged
    /// B fires but must refuse: same inode, same (op,fun), different
    /// observed offset. Against pre-fix objects this fails with the U2
    /// receipt (definite 4): the inode-only join authorizes B from A's
    /// advertisement.
    ///
    /// ```sh
    /// OSSL_PROVIDER_OBSERVATION_TEST_BPF=<provider object> \
    /// OSSLSCOPE_FOCUSED_COUNT_OBJECT=<count object> \
    /// sudo -n cargo test --locked --offline --lib -- --ignored \
    ///     copied_role_substitution_same_file_offset_refuses --nocapture
    /// ```
    #[test]
    #[ignore = "substitution control (sudo, cc)"]
    fn copied_role_substitution_same_file_offset_refuses() {
        let dir = std::env::temp_dir().join(format!("osslscope-copied-i1a-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let app = source_native_complete_chain_fixture(&dir);
        let staged_b = fixture_symbol_file_offset(&app, "test_kdf_derive");
        let advertised_a = fixture_symbol_file_offset(&app, "test_kdf_derive_alt");
        assert_ne!(
            staged_b, advertised_a,
            "same file, different offsets is the premise"
        );
        let plan = stage_copied_plan_from_pass1(&app);
        assert_eq!(
            plan.sites.len(),
            11,
            "pass-1 normal mode plans MAC 6 + KDF 5"
        );
        let site307 = plan
            .sites
            .iter()
            .find(|site| site.role_id == 307)
            .expect("plan stages the derive");
        assert_eq!(
            site307.offset, staged_b,
            "the plan stages B; the refusal below is kernel-side"
        );
        let drive = drive_typed_session_with_counter(
            "i1a",
            &app,
            &[304, 305, 306, 307, 308],
            Some(&plan),
            "marker2",
            Some("i1-swap45"),
        );
        assert_eq!(
            drive.staged_roles,
            vec![
                130, 131, 136, 137, 146, 147, 148, 149, 150, 151, 152, 153, 155, 161, 258, 259,
                274, 275, 290, 291, 304, 305, 306, 307, 308,
            ],
            "13 first-slice + query + 11 copied"
        );
        assert_eq!(drive.typed_sites, 25);
        assert_eq!(
            drive.copied_skipped, 0,
            "static bytes stage B even though the live table advertises A"
        );
        assert_eq!(drive.counter_links, 1);
        assert_eq!(drive.joined_sites, 5, "all five counted sites join");
        assert_eq!(
            drive.joined_calls, 5,
            "1 init + 1 update + 1 final + 1 derive + 1 reset"
        );
        assert_eq!(
            drive.definite, 3,
            "query-for-A never authorizes staged-B: only init/update/final partition"
        );
        assert_eq!(
            drive.unresolved_calls, 3,
            "the refused derive hit plus the retire-only 308 hit plus the teardown-poison foreign bound"
        );
        assert_eq!(drive.withheld_uncertain, 0);
        assert_eq!(drive.sample_sites, 5);
        assert_eq!(drive.sample_calls, 5);
        assert_eq!(
            drive.next_producer_id, 48,
            "U2's 49 minus the refused derive's segment; the (4,5) row for A still mints"
        );
        assert_eq!(
            drive.loss_cells,
            [0, 0, 0, 1, 0, 0, 0, 0],
            "cell 3 is the by-design Phase-1 teardown poison; every other cell zero"
        );
    }
    /// I1 substitution control (MAC init): the (3,4) mirror of the derive
    /// control — pass 2's live MAC table advertises the alternate
    /// same-file init A while the plan stages B. Same discrimination:
    /// pre-fix objects partition B (definite 4); fixed objects refuse
    /// it (definite 3).
    ///
    /// ```sh
    /// OSSL_PROVIDER_OBSERVATION_TEST_BPF=<provider object> \
    /// OSSLSCOPE_FOCUSED_COUNT_OBJECT=<count object> \
    /// sudo -n cargo test --locked --offline --lib -- --ignored \
    ///     copied_role_substitution_mac_offset_refuses --nocapture
    /// ```
    #[test]
    #[ignore = "substitution control (sudo, cc)"]
    fn copied_role_substitution_mac_offset_refuses() {
        let dir = std::env::temp_dir().join(format!("osslscope-copied-i1b-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let app = source_native_complete_chain_fixture(&dir);
        let staged_b = fixture_symbol_file_offset(&app, "test_mac_init");
        let advertised_a = fixture_symbol_file_offset(&app, "test_mac_init_alt");
        assert_ne!(
            staged_b, advertised_a,
            "same file, different offsets is the premise"
        );
        let plan = stage_copied_plan_from_pass1(&app);
        assert_eq!(
            plan.sites.len(),
            11,
            "pass-1 normal mode plans MAC 6 + KDF 5"
        );
        let site304 = plan
            .sites
            .iter()
            .find(|site| site.role_id == 304)
            .expect("plan stages the init");
        assert_eq!(
            site304.offset, staged_b,
            "the plan stages B; the refusal below is kernel-side"
        );
        let drive = drive_typed_session_with_counter(
            "i1b",
            &app,
            &[304, 305, 306, 307, 308],
            Some(&plan),
            "marker2",
            Some("i1-swap34"),
        );
        assert_eq!(drive.typed_sites, 25);
        assert_eq!(
            drive.copied_skipped, 0,
            "static bytes stage B even though the live table advertises A"
        );
        assert_eq!(drive.counter_links, 1);
        assert_eq!(drive.joined_sites, 5, "all five counted sites join");
        assert_eq!(
            drive.joined_calls, 5,
            "1 init + 1 update + 1 final + 1 derive + 1 reset"
        );
        assert_eq!(
            drive.definite, 3,
            "query-for-A never authorizes staged-B: only update/final/derive partition"
        );
        assert_eq!(
            drive.unresolved_calls, 3,
            "the refused init hit plus the retire-only 308 hit plus the teardown-poison foreign bound"
        );
        assert_eq!(drive.withheld_uncertain, 0);
        assert_eq!(drive.sample_sites, 5);
        assert_eq!(drive.sample_calls, 5);
        assert_eq!(
            drive.next_producer_id, 48,
            "U2's 49 minus the refused init's segment; the (3,4) row for A still mints"
        );
        assert_eq!(
            drive.loss_cells,
            [0, 0, 0, 1, 0, 0, 0, 0],
            "cell 3 is the by-design Phase-1 teardown poison; every other cell zero"
        );
    }
    /// I3 operational-refusal control: pass 2's live KDF table omits
    /// (4,5) (a duplicate (4,4) overwrites the slot), so the staged
    /// derive fires with no CODE_ROLE row and no source authority for
    /// it. It must refuse without partitioning. This pins the
    /// fail-closed outcome on both object generations (the authority
    /// check exists in both; the fix moves it above every argument
    /// read, which the read-order audit proves structurally).
    ///
    /// ```sh
    /// OSSL_PROVIDER_OBSERVATION_TEST_BPF=<provider object> \
    /// OSSLSCOPE_FOCUSED_COUNT_OBJECT=<count object> \
    /// sudo -n cargo test --locked --offline --lib -- --ignored \
    ///     operational_callback_without_advertised_role_refuses --nocapture
    /// ```
    #[test]
    #[ignore = "operational-refusal control (sudo, cc)"]
    fn operational_callback_without_advertised_role_refuses() {
        let dir = std::env::temp_dir().join(format!("osslscope-copied-i3-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let app = source_native_complete_chain_fixture(&dir);
        let plan = stage_copied_plan_from_pass1(&app);
        assert_eq!(
            plan.sites.len(),
            11,
            "pass-1 normal mode plans MAC 6 + KDF 5"
        );
        let drive = drive_typed_session_with_counter(
            "i3",
            &app,
            &[304, 305, 306, 307, 308],
            Some(&plan),
            "marker2",
            Some("i3-drop45"),
        );
        assert_eq!(drive.typed_sites, 25);
        assert_eq!(
            drive.copied_skipped, 0,
            "static bytes stage (4,5) even though the live table drops it"
        );
        assert_eq!(drive.counter_links, 1);
        assert_eq!(drive.joined_sites, 5, "all five counted sites join");
        assert_eq!(
            drive.joined_calls, 5,
            "1 init + 1 update + 1 final + 1 derive + 1 reset"
        );
        assert_eq!(
            drive.definite, 3,
            "the unauthorized derive never partitions: only init/update/final do"
        );
        assert_eq!(
            drive.unresolved_calls, 3,
            "the refused derive hit plus the retire-only 308 hit plus the teardown-poison foreign bound"
        );
        assert_eq!(drive.withheld_uncertain, 0);
        assert_eq!(drive.sample_sites, 5);
        assert_eq!(drive.sample_calls, 5);
        assert_eq!(
            drive.next_producer_id, 47,
            "U2's 49 minus the unpublished (4,5) witness (the duplicate (4,4) dedups) minus the refused derive's segment"
        );
        assert_eq!(
            drive.loss_cells,
            [0, 0, 0, 1, 0, 0, 0, 0],
            "cell 3 is the by-design Phase-1 teardown poison; every other cell zero"
        );
    }
    /// I2 firstbyte control (x86_64): the KDF derive callback sits at
    /// the first byte of its executable VMA (ELF-verified premise
    /// below), and the plan stages that exact file offset. The derive
    /// must authorize and partition: the kernel-supplied entry IP
    /// needs no subtraction. Against pre-fix objects this fails
    /// (definite 3, not 4): `rip - 1` lands in the preceding hole and
    /// the VMA join rejects the valid callback.
    ///
    /// ```sh
    /// OSSL_PROVIDER_OBSERVATION_TEST_BPF=<provider object> \
    /// OSSLSCOPE_FOCUSED_COUNT_OBJECT=<count object> \
    /// sudo -n cargo test --locked --offline --lib -- --ignored \
    ///     copied_firstbyte_callback_authorizes_with_exact_offset --nocapture
    /// ```
    #[test]
    #[cfg(target_arch = "x86_64")]
    #[ignore = "firstbyte control (sudo, cc, x86_64)"]
    fn copied_firstbyte_callback_authorizes_with_exact_offset() {
        let dir = std::env::temp_dir().join(format!("osslscope-copied-i2b-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let app = source_native_firstbyte_chain_fixture(&dir);
        let bytes = std::fs::read(&app).unwrap();
        let elf = goblin::elf::Elf::parse(&bytes).unwrap();
        let text = elf
            .program_headers
            .iter()
            .filter(|ph| ph.p_type == goblin::elf::program_header::PT_LOAD && ph.p_flags & 1 != 0)
            .min_by_key(|ph| ph.p_vaddr)
            .expect("executable LOAD segment");
        let sym = elf
            .syms
            .iter()
            .find(|s| elf.strtab.get_at(s.st_name) == Some("test_kdf_derive"))
            .expect("derive symbol");
        assert_eq!(
            sym.st_value, text.p_vaddr,
            "the derive is the first byte of the executable VMA"
        );
        assert_eq!(text.p_vaddr % 4096, 0, "segment start is page-aligned");
        assert_eq!(
            text.p_offset % 4096,
            0,
            "segment file offset is page-aligned"
        );
        let derive_offset = text.p_offset + (sym.st_value - text.p_vaddr);
        assert_eq!(
            derive_offset, text.p_offset,
            "first VMA byte means first segment file offset"
        );
        let plan = stage_copied_plan_from_pass1(&app);
        assert_eq!(plan.sites.len(), 11, "MAC 6 + KDF 5 copied sites");
        let site307 = plan
            .sites
            .iter()
            .find(|site| site.role_id == 307)
            .expect("plan stages the derive");
        assert_eq!(
            site307.offset, derive_offset,
            "the staged offset is the exact joined registration offset"
        );
        let drive = drive_typed_session_with_counter(
            "i2b",
            &app,
            &[304, 305, 306, 307, 308],
            Some(&plan),
            "marker2",
            None,
        );
        assert_eq!(drive.typed_sites, 25);
        assert_eq!(drive.copied_skipped, 0);
        assert_eq!(drive.counter_links, 1);
        assert_eq!(drive.joined_sites, 5, "all five counted sites join");
        assert_eq!(
            drive.joined_calls, 5,
            "1 init + 1 update + 1 final + 1 derive + 1 reset"
        );
        assert_eq!(
            drive.definite, 4,
            "the firstbyte derive authorizes: entry IP needs no subtraction"
        );
        assert_eq!(
            drive.unresolved_calls, 2,
            "the retire-only 308 hit plus the teardown-poison foreign bound"
        );
        assert_eq!(drive.withheld_uncertain, 0);
        assert_eq!(drive.sample_sites, 5);
        assert_eq!(drive.sample_calls, 5);
        assert_eq!(
            drive.next_producer_id, 49,
            "U2's receipt on the firstbyte layout: 44 mints plus 4 operational segment allocs"
        );
        assert_eq!(
            drive.loss_cells,
            [0, 0, 0, 1, 0, 0, 0, 0],
            "cell 3 is the by-design Phase-1 teardown poison; every other cell zero"
        );
    }
    /// Remap-TOCTOU control: the registration (cookie C at offset X)
    /// and the query-published CODE_ROLE row (offset Y) deliberately
    /// disagree — the fixture remaps its derive page to the byte-twin
    /// page for the queries, then restores it — and a toggler thread
    /// races MAP_FIXED X<->Y flips against 100000 paced derive calls
    /// (5us monotonic sleep per call: without pacing, fast untrapped
    /// calls starve traps to noise level). Trapped fires snapshot X
    /// or Y through the live VMA join. A Y snapshot matches the row
    /// while C's guards stay LIVE: pre-fix objects authorize those
    /// transient hits (definite 4, the leak), fixed objects refuse
    /// every mismatch because the joined identity must equal the
    /// SOURCE_REG/SOURCE_ANCHOR witnesses retained for C (definite
    /// 3). Stable-mapping-only coverage missed this; the stats
    /// file's bracketed toggle count (flips strictly inside the race
    /// loop) plus the large trapped-fire count proves the window was
    /// genuinely raced, so the green is not a never-raced vacuity.
    /// The X/Y pages are byte-identical (verified below),
    /// so execution stays sound whatever mid-call flips land —
    /// only the VMA snapshot races, which is exactly the window
    /// under test. Every trapped fire refuses, so unresolved
    /// conservation is exact.
    ///
    /// ```sh
    /// OSSL_PROVIDER_OBSERVATION_TEST_BPF=<provider object> \
    /// OSSLSCOPE_FOCUSED_COUNT_OBJECT=<count object> \
    /// sudo -n cargo test --locked --offline --lib -- --ignored \
    ///     copied_role_remap_mismatch_refuses --nocapture
    /// ```
    #[test]
    #[ignore = "remap control (sudo, cc)"]
    fn copied_role_remap_mismatch_refuses() {
        let dir = std::env::temp_dir().join(format!("osslscope-copied-i1r-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let app = source_native_remap_chain_fixture(&dir);
        let bytes = std::fs::read(&app).unwrap();
        let elf = goblin::elf::Elf::parse(&bytes).unwrap();
        let derive = elf
            .syms
            .iter()
            .find(|s| elf.strtab.get_at(s.st_name) == Some("test_kdf_derive"))
            .expect("derive symbol");
        let twin = elf
            .syms
            .iter()
            .find(|s| elf.strtab.get_at(s.st_name) == Some("test_kdf_derive_y"))
            .expect("twin symbol");
        assert_eq!(
            derive.st_value % 4096,
            0,
            "the derive starts its page (the twin mirrors it below)"
        );
        assert_eq!(
            twin.st_value % 4096,
            0,
            "the twin starts its page at the same in-page offset"
        );
        assert_ne!(
            derive.st_value, twin.st_value,
            "derive and twin occupy different pages"
        );
        for sym in elf.syms.iter() {
            if sym.st_type() != goblin::elf::sym::STT_FUNC || sym.st_value == 0 {
                continue;
            }
            let name = elf.strtab.get_at(sym.st_name);
            if name == Some("test_kdf_derive") || name == Some("test_kdf_derive_y") {
                continue;
            }
            for base in [derive.st_value, twin.st_value] {
                assert!(
                    sym.st_value < base || sym.st_value >= base + 4096,
                    "no third function may share a remap page"
                );
            }
        }
        for base in [derive.st_value, twin.st_value] {
            let segment = elf
                .program_headers
                .iter()
                .find(|ph| {
                    ph.p_type == goblin::elf::program_header::PT_LOAD
                        && base >= ph.p_vaddr
                        && base < ph.p_vaddr + ph.p_memsz
                })
                .expect("remap page in a LOAD");
            assert_ne!(segment.p_flags & 1, 0, "remap pages stay executable");
            assert_eq!(segment.p_flags & 2, 0, "remap pages stay non-writable");
        }
        let derive_offset = fixture_symbol_file_offset(&app, "test_kdf_derive");
        let twin_offset = fixture_symbol_file_offset(&app, "test_kdf_derive_y");
        assert_ne!(
            derive_offset, twin_offset,
            "different pages means different file offsets (X vs Y)"
        );
        let page_x = &bytes[derive_offset as usize..derive_offset as usize + 4096];
        let page_y = &bytes[twin_offset as usize..twin_offset as usize + 4096];
        assert_eq!(
            page_x, page_y,
            "byte-identical pages keep mid-toggle execution sound; only the snapshot races"
        );
        let plan = stage_copied_plan_from_pass1(&app);
        assert_eq!(
            plan.sites.len(),
            11,
            "pass-1 normal mode plans MAC 6 + KDF 5"
        );
        let site307 = plan
            .sites
            .iter()
            .find(|site| site.role_id == 307)
            .expect("plan stages the derive");
        assert_eq!(
            site307.offset, derive_offset,
            "the plan stages X; the row below publishes Y, so the refusal is kernel-side"
        );
        let nonce = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let drive = drive_typed_session_with_counter(
            "i1r",
            &app,
            &[304, 305, 306, 307, 308],
            Some(&plan),
            "marker2",
            Some(&format!("i1-remap45:{nonce}")),
        );
        let stats = std::env::temp_dir().join(format!("osslscope-remap-{nonce}.stats"));
        let (toggles, x_exec) = remap_stats_parse(&stats);
        std::fs::remove_file(&stats).unwrap();
        eprintln!("i1r: toggles={toggles} x_exec={x_exec}");
        assert!(
            toggles >= 1000,
            "the mapping must flip inside the race loop (stable mappings miss this)"
        );
        assert_eq!(
            x_exec, 100003,
            "3 steady plus 100000 race calls, all with expected bytes"
        );
        assert_eq!(
            drive.staged_roles,
            vec![
                130, 131, 136, 137, 146, 147, 148, 149, 150, 151, 152, 153, 155, 161, 258, 259,
                274, 275, 290, 291, 304, 305, 306, 307, 308,
            ],
            "13 first-slice + query + 11 copied"
        );
        assert_eq!(drive.typed_sites, 25);
        assert_eq!(
            drive.copied_skipped, 0,
            "static bytes stage the derive at X"
        );
        assert_eq!(drive.counter_links, 1);
        assert_eq!(drive.joined_sites, 5, "all five counted sites join");
        assert!(
            drive.joined_calls >= 107,
            "3 steady + at least 100 trapped race derives plus init/update/final/reset"
        );
        assert_eq!(
            drive.definite, 3,
            "no transient snapshot authorizes: only init/update/final partition"
        );
        assert_eq!(
            drive.unresolved_calls,
            drive.joined_calls - 2,
            "every trapped derive refuses; only the 308 hit and the teardown-poison bound are extra"
        );
        assert_eq!(drive.withheld_uncertain, 0);
        assert_eq!(drive.sample_sites, 5);
        assert_eq!(drive.sample_calls, drive.joined_calls);
        assert_eq!(
            drive.next_producer_id, 48,
            "U2's 49 minus the refused derive's segment; the (4,5) row for Y still mints"
        );
        assert_eq!(
            drive.loss_cells,
            [0, 0, 0, 1, 0, 0, 0, 0],
            "cell 3 is the by-design Phase-1 teardown poison; every other cell zero"
        );
    }
    /// P3-I1 single-typed-site fixture: the query/dispatch shape of
    /// `source_native_fixture` (so discovery still yields one legacy API
    /// site) but exactly one typed export (`EVP_MAC_fetch`, role 130).
    /// `main` calls the export and exits 0 only on public success, so the
    /// exit-0 oracle proves the export EXECUTED — any attached ENTRY
    /// uprobe fired — while kernel minting (or its absence) proves what
    /// the typed callback did with that firing.
    fn source_native_single_typed_fixture(dir: &std::path::Path) -> std::path::PathBuf {
        let source = dir.join("app.c");
        let app = dir.join("app");
        std::fs::write(
            &source,
            r#"
#include <stdio.h>
#include <stddef.h>
struct dispatch { int id; void (*fn)(void); };
struct algorithm { const char *names, *properties; const struct dispatch *implementation; const char *description; };
__attribute__((noinline)) static void implementation(void) { __asm__ volatile(""); }
static const struct dispatch dispatch[] = { { 70001, implementation }, { 0, 0 } };
static const struct algorithm algorithms[] = { { "FUTURE-DIGEST", 0, dispatch, 0 }, { 0, 0, 0, 0 } };
__attribute__((noinline)) const struct algorithm *OSSL_PROVIDER_query_operation(const void *provider,int op,int *no_cache) {
 *no_cache=0;
 (void)provider; (void)op;
 return algorithms;
}
void *EVP_MAC_fetch(void *c,const char *n,const char *p){ (void)n; (void)p; return c; }
int main(int argc,char **argv) { if(argc!=2) return 2;
 FILE *f=fopen(argv[1],"w"); if(!f) return 4; fputs("exec\n",f); fclose(f);
 { int no_cache=-1;
   if(OSSL_PROVIDER_query_operation((void*)1,1,&no_cache)==0) return 3; }
 if(EVP_MAC_fetch((void*)1,"X",0)!=(void*)1) return 3;
 return 0; }
"#,
        )
        .unwrap();
        assert!(
            std::process::Command::new("cc")
                .args(["-O0", "-rdynamic", "-o"])
                .arg(&app)
                .arg(&source)
                .status()
                .unwrap()
                .success()
        );
        app
    }
    /// Host readback of the kernel-minted producer-ID counter (counts only,
    /// from the already-open ATTRIB_CONTROL map): the host seeds 1, and
    /// every mint happens strictly downstream of a passed READY gate, so a
    /// held 1 proves no typed callback passed the gate.
    fn source_native_next_producer_id(session: &ProviderSession) -> u64 {
        let fd = session
            .source_owner
            .as_ref()
            .unwrap()
            .owned_map("ATTRIB_CONTROL")
            .unwrap();
        let map = loader::BorrowedMap::new(fd).unwrap();
        map.shape(&[2], 4, 64).unwrap();
        let mut value = [0u8; 64];
        map.lookup(&0u32.to_ne_bytes(), &mut value).unwrap();
        u64::from_ne_bytes(value[32..40].try_into().unwrap())
    }
    struct TypedRefusalSetup {
        dir: std::path::PathBuf,
        app: std::path::PathBuf,
        child: crate::target::OwnedTarget,
        cancel: std::sync::atomic::AtomicBool,
        gate: crate::writer_gate::WriterGate,
        session: ProviderSession,
        admitted_offset: u64,
    }
    /// Owned session over the single-typed-site fixture, carried through
    /// reserve-only prearm, typed preparation and gate open. Asserts the
    /// exact single-cookie shape the refusal controls depend on.
    fn typed_refusal_setup(suffix: &str) -> TypedRefusalSetup {
        let dir = std::env::temp_dir().join(format!(
            "osslscope-typed-refuse-{suffix}-{}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        let app = source_native_single_typed_fixture(&dir);
        let argv = [
            app.to_string_lossy().into_owned(),
            dir.join("marker").to_string_lossy().into_owned(),
        ];
        let child =
            crate::target::OwnedTarget::spawn_stopped(&argv, crate::target::WorkloadDest::Null)
                .unwrap();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let mut budget = ObservationBudget::default();
        let startup = crate::startup_objects::prepare_owned_startup(
            &child,
            &argv,
            &mut budget,
            Instant::now() + Duration::from_secs(15),
            &cancel,
            None,
        )
        .unwrap();
        let crate::startup_objects::PreExecSites { apis, typed, .. } = startup;
        let object =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        budget.state(crate::writer_gate::RESERVATION_BYTES).unwrap();
        let pool = budget.memory.clone().unwrap_or_else(|| {
            crate::observation_memory::MemoryPool::new(budget.limits.max_state_bytes)
        });
        let gate = crate::writer_gate::WriterGate::create(&pool).unwrap();
        let mut session = ProviderSession::open_gated(budget, &object, gate.clone()).unwrap();
        session
            .prearm_startup(
                apis,
                Instant::now() + Duration::from_secs(5),
                &cancel,
                PrearmLinks::Reserve,
            )
            .unwrap();
        assert_eq!(session.startup[&child.pid()].len(), 1);
        let admitted_offset = session.startup[&child.pid()][0].site.file_offset();
        assert_ne!(admitted_offset, 0);
        let lease = super::source_owner::SourceAcquisitionLease::Enabled(
            super::source_owner::NativeSourceParams::for_test(
                app.clone(),
                admitted_offset,
                child.pid(),
            ),
        );
        session
            .prepare_typed_startup(
                typed,
                Instant::now() + Duration::from_secs(15),
                &cancel,
                &lease,
            )
            .unwrap();
        let roles: Vec<u32> = session
            .typed_startup
            .iter()
            .map(|staged| staged.role().id())
            .collect();
        assert_eq!(
            roles,
            vec![130],
            "refusal fixture must stage exactly the fetch cookie"
        );
        gate.open().unwrap();
        TypedRefusalSetup {
            dir,
            app,
            child,
            cancel,
            gate,
            session,
            admitted_offset,
        }
    }
    /// U4 dual-API fixture: the query/dispatch shape of
    /// `source_native_single_typed_fixture` (so discovery still yields
    /// typed role 130) plus a second legacy export
    /// (`OSSL_PROVIDER_unquery_operation`), so discovery yields TWO
    /// legacy API sites in one file. `main` calls both exports and the
    /// fetch, and exits 0 only on public success.
    fn source_native_dual_api_fixture(dir: &std::path::Path) -> std::path::PathBuf {
        let source = dir.join("app.c");
        let app = dir.join("app");
        std::fs::write(
            &source,
            r#"
#include <stdio.h>
#include <stddef.h>
struct dispatch { int id; void (*fn)(void); };
struct algorithm { const char *names, *properties; const struct dispatch *implementation; const char *description; };
__attribute__((noinline)) static void implementation(void) { __asm__ volatile(""); }
static const struct dispatch dispatch[] = { { 70001, implementation }, { 0, 0 } };
static const struct algorithm algorithms[] = { { "FUTURE-DIGEST", 0, dispatch, 0 }, { 0, 0, 0, 0 } };
__attribute__((noinline)) const struct algorithm *OSSL_PROVIDER_query_operation(const void *provider,int op,int *no_cache) {
 *no_cache=0;
 (void)provider; (void)op;
 return algorithms;
}
__attribute__((noinline)) void OSSL_PROVIDER_unquery_operation(const void *provider,int op,const struct algorithm *algs) {
 (void)provider; (void)op; (void)algs;
}
void *EVP_MAC_fetch(void *c,const char *n,const char *p){ (void)n; (void)p; return c; }
int main(int argc,char **argv) { if(argc!=2) return 2;
 FILE *f=fopen(argv[1],"w"); if(!f) return 4; fputs("exec\n",f); fclose(f);
 { int no_cache=-1;
   if(OSSL_PROVIDER_query_operation((void*)1,1,&no_cache)==0) return 3; }
 OSSL_PROVIDER_unquery_operation((void*)1,1,algorithms);
 if(EVP_MAC_fetch((void*)1,"X",0)!=(void*)1) return 3;
 return 0; }
"#,
        )
        .unwrap();
        assert!(
            std::process::Command::new("cc")
                .args(["-O0", "-rdynamic", "-o"])
                .arg(&app)
                .arg(&source)
                .status()
                .unwrap()
                .success()
        );
        app
    }
    struct MultiAttachmentSetup {
        dir: std::path::PathBuf,
        app: std::path::PathBuf,
        child: crate::target::OwnedTarget,
        cancel: std::sync::atomic::AtomicBool,
        gate: crate::writer_gate::WriterGate,
        session: ProviderSession,
        admitted_offsets: Vec<u64>,
    }
    /// U4 setup: dual-API fixture through discovery, open, full prearm
    /// (both legacy attachments, Reserve) and typed preparation, gate
    /// opened, child still held. Asserts the two-attachment premise.
    fn multi_attachment_setup(tag: &str) -> MultiAttachmentSetup {
        multi_attachment_setup_with_session_limits(tag, ObservationLimits::default())
    }
    /// Same as `multi_attachment_setup` but with custom session limits
    /// applied after discovery (discovery itself runs under the default
    /// budget, so a small `max_links` only constrains prearm/acquire).
    fn multi_attachment_setup_with_session_limits(
        tag: &str,
        session_limits: ObservationLimits,
    ) -> MultiAttachmentSetup {
        let dir = std::env::temp_dir().join(format!(
            "osslscope-multi-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let app = source_native_dual_api_fixture(&dir);
        let marker = dir.join("marker");
        let argv = vec![
            app.to_string_lossy().into_owned(),
            marker.to_string_lossy().into_owned(),
        ];
        let child =
            crate::target::OwnedTarget::spawn_stopped(&argv, crate::target::WorkloadDest::Null)
                .unwrap();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let mut budget = ObservationBudget::default();
        let startup = crate::startup_objects::prepare_owned_startup(
            &child,
            &argv,
            &mut budget,
            Instant::now() + Duration::from_secs(120),
            &cancel,
            None,
        )
        .unwrap();
        let crate::startup_objects::PreExecSites { apis, typed, .. } = startup;
        assert_eq!(
            apis.len(),
            2,
            "dual-API fixture must yield two legacy sites"
        );
        assert_eq!(typed.len(), 1, "dual-API fixture keeps one typed export");
        budget.limits = session_limits;
        let object =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        budget.state(crate::writer_gate::RESERVATION_BYTES).unwrap();
        let pool = budget.memory.clone().unwrap_or_else(|| {
            crate::observation_memory::MemoryPool::new(budget.limits.max_state_bytes)
        });
        let gate = crate::writer_gate::WriterGate::create(&pool).unwrap();
        let mut session = ProviderSession::open_gated(budget, &object, gate.clone()).unwrap();
        session
            .prearm_startup(
                apis,
                Instant::now() + Duration::from_secs(5),
                &cancel,
                PrearmLinks::Reserve,
            )
            .unwrap();
        let pid = child.pid();
        assert_eq!(session.startup[&pid].len(), 2);
        let admitted_offsets = session.startup[&pid]
            .iter()
            .map(|a| a.site.file_offset())
            .collect::<Vec<_>>();
        let lease = super::source_owner::SourceAcquisitionLease::Enabled(
            super::source_owner::NativeSourceParams::for_test_multi(
                admitted_offsets
                    .iter()
                    .map(|offset| (app.clone(), *offset, pid))
                    .collect(),
            ),
        );
        session
            .prepare_typed_startup(
                typed,
                Instant::now() + Duration::from_secs(15),
                &cancel,
                &lease,
            )
            .unwrap();
        assert_eq!(session.typed_startup.len(), 1);
        gate.open().unwrap();
        MultiAttachmentSetup {
            dir,
            app,
            child,
            cancel,
            gate,
            session,
            admitted_offsets,
        }
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges, cc"]
    fn typed_failed_entry_registration_withholds_ready_and_operands() {
        // P3-I1 failed-registration control (ENTRY): the typed ENTRY
        // request arms for the wrong offset while the actual link uses the
        // true one. The kernel refuses with a genuine refused receipt: the
        // capability never creates its adoption guard (ledger stays
        // Minted), no READY can publish, and the acquisition refuses as a
        // whole. The ENTRY link itself IS attached and FIRES when the
        // workload executes the export (exit 0 proves public success) —
        // yet the kernel mints nothing (next_producer_id holds 1), proving
        // typed_entry refused at the READY gate before any operand read:
        // without the capability the operand readers stay unavailable.
        let baseline = source_native_fd_targets();
        let mut setup = typed_refusal_setup("entry");
        let pid = setup.child.pid();
        let marker = setup.dir.join("marker");
        let params = super::source_owner::NativeSourceParams::for_test(
            setup.app.clone(),
            setup.admitted_offset,
            pid,
        );
        let admitted = setup.session.admitted_source_site(&params).unwrap();
        let typed = {
            let session = &mut setup.session;
            let owner = session.source_owner.as_mut().expect("source owner");
            let budget = &session.budget;
            owner.note_gate_open_observed().unwrap();
            let domain = owner.arm_domain(pid).unwrap();
            let host_key = owner.enroll_observer().unwrap();
            let scope = super::source_owner::RequestScope {
                site_cookie: admitted.site_cookie,
                host_key,
                incarnation: domain.incarnation,
                planned_image: domain.planned,
                link_offset: admitted.link_offset,
                target_pid: admitted.tgid,
                target: admitted.target,
                expected_artifact: admitted.expected_artifact,
            };
            let anchor = owner
                .anchor_source(&scope, budget, None)
                .unwrap_or_else(|gap| {
                    panic!(
                        "anchor failed: {gap:?} owner: {:?}",
                        owner.take_last_error()
                    )
                });
            assert_eq!(
                owner.guard_life_test(anchor.anchor_id),
                Some(super::source_acquire::GuardLife::Live)
            );
            owner.fail_next_typed_entry();
            super::source_owner::TypedAcquisitionScope {
                anchor,
                host_key,
                incarnation: domain.incarnation,
                planned_image: domain.planned,
            }
        };
        let error = setup
            .session
            .acquire_typed_sites(
                &typed,
                Instant::now() + Duration::from_secs(15),
                &setup.cancel,
            )
            .unwrap_err();
        assert_eq!(error, ObservationGap::Invalidated);
        {
            let session = &mut setup.session;
            let typed_empty = session.typed_site_records().is_empty();
            let owner = session.source_owner.as_mut().expect("source owner");
            let registration = owner.last_typed_registration_test();
            assert_ne!(registration, 0, "the refused ENTRY minted a registration");
            assert_eq!(
                owner.guard_life_test(registration),
                Some(super::source_acquire::GuardLife::Minted),
                "ENTRY refusal must precede guard creation"
            );
            assert_eq!(
                owner.adopted_link_count(),
                1,
                "only the refused ENTRY link attached"
            );
            assert!(typed_empty, "refused cookies record nothing");
            assert!(!owner.acquisition_ready(), "no READY, no release");
            owner.refuse_acquisition();
            eprintln!(
                "typed ENTRY refused: reg={registration} adopted=1 next_id={} (pre-release)",
                source_native_next_producer_id(session)
            );
        }
        setup.child.release().unwrap();
        let until = Instant::now() + Duration::from_secs(15);
        // P3-I1 fix-round-1: poll until the marker CARRIES the payload,
        // not merely exists: exists-then-single-read races the
        // fixture's fopen("w") (creates the empty file) against its
        // fclose (flushes "exec\n"). The four pre-existing sites keep
        // the P3 shape verbatim; only these new controls poll.
        loop {
            if let Ok(body) = std::fs::read(&marker) {
                if body == b"exec\n" {
                    break;
                }
            }
            assert!(Instant::now() < until, "exec marker never carried exec");
            std::thread::sleep(Duration::from_millis(1));
        }
        while setup.child.peek_exit().unwrap().is_none() {
            assert!(Instant::now() < until, "workload never exited");
            std::thread::yield_now();
        }
        assert_eq!(
            setup.child.poll_exit().unwrap(),
            Some(0),
            "workload must exit 0: the export executed, so the ENTRY link fired"
        );
        assert_eq!(
            source_native_next_producer_id(&setup.session),
            1,
            "typed_entry refused at the READY gate before any mint"
        );
        let lease = super::source_owner::SourceAcquisitionLease::Enabled(params);
        let state = setup
            .session
            .note_source_exec(&lease, pid, typed.planned_image)
            .unwrap();
        assert_eq!(state, super::source_owner::contract::DOMAIN_ACTIVE);
        setup.gate.close().unwrap();
        let close = setup.session.close_source_explicit().expect("source close");
        assert!(close.cut_confirmed, "close must confirm the cut");
        assert_eq!(
            (
                close.guards_retired,
                close.guards_abandoned,
                close.domains_retired
            ),
            (1, 0, 1),
            "anchor retired; the Minted typed id owns no kernel row"
        );
        assert!(close.order_refused, "refused order must refuse");
        assert!(close.first_error.is_none());
        drop(setup.session);
        drop(setup.gate);
        drop(setup.child);
        assert_eq!(
            source_native_fd_targets(),
            baseline,
            "teardown must release every fd"
        );
        std::fs::remove_dir_all(&setup.dir).unwrap();
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges, cc"]
    fn acquire_shares_staged_anchor_for_same_file() {
        // U3 frugality: the admitted API and the staged typed site live
        // in the same fixture file, so the source anchor must reuse the
        // staging capture (the same Rc) instead of re-capturing — the
        // mapping is captured and charged once. Rc identity (not byte
        // equality) proves no second capture happened.
        let baseline = source_native_fd_targets();
        let mut setup = typed_refusal_setup("shared-anchor");
        let pid = setup.child.pid();
        let marker = setup.dir.join("marker");
        let lease = super::source_owner::SourceAcquisitionLease::Enabled(
            super::source_owner::NativeSourceParams::for_test(
                setup.app.clone(),
                setup.admitted_offset,
                pid,
            ),
        );
        let receipts = setup
            .session
            .acquire_source_after_open(
                &lease,
                Instant::now() + Duration::from_secs(15),
                &setup.cancel,
            )
            .unwrap_or_else(|gap| {
                panic!(
                    "acquire failed: {gap:?} owner: {:?}",
                    setup.session.source_error()
                )
            });
        assert_eq!(
            setup.session.typed_site_records().len(),
            1,
            "the staged fetch cookie must admit"
        );
        assert_eq!(receipts.adopted_links, 4, "legacy pair plus the typed pair");
        let staged = setup.session.typed_startup[0].anchor().clone();
        let owned = setup
            .session
            .source_owner
            .as_ref()
            .expect("source owner")
            .anchor_rc_test()
            .expect("anchor retained");
        assert!(
            std::rc::Rc::ptr_eq(&staged, &owned),
            "owner must share the staged capture, not re-capture the file"
        );
        setup.child.release().unwrap();
        let until = Instant::now() + Duration::from_secs(15);
        loop {
            if let Ok(body) = std::fs::read(&marker) {
                if body == b"exec\n" {
                    break;
                }
            }
            assert!(Instant::now() < until, "exec marker never carried exec");
            std::thread::sleep(Duration::from_millis(1));
        }
        while setup.child.peek_exit().unwrap().is_none() {
            assert!(Instant::now() < until, "workload never exited");
            std::thread::yield_now();
        }
        assert_eq!(setup.child.poll_exit().unwrap(), Some(0));
        setup
            .session
            .note_source_exec(&lease, pid, receipts.domain.planned)
            .unwrap();
        setup.gate.close().unwrap();
        let close = setup.session.close_source_explicit().expect("source close");
        assert!(close.cut_confirmed, "close must confirm the cut");
        assert!(close.first_error.is_none());
        drop(setup.session);
        drop(setup.gate);
        drop(setup.child);
        // Full-acquire flow hygiene: BPF FDs return exactly; the one
        // non-BPF survivor is the pre-existing typed-anchor app handle
        // the typed driver pins at +1 for this flow shape.
        source_native_assert_fds_return(&baseline, &setup.app);
        std::fs::remove_dir_all(&setup.dir).unwrap();
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges, cc"]
    fn multi_attachment_acquire_registers_every_attachment_under_one_anchor() {
        // U4: two legacy attachments in one file acquire as one order:
        // one shared file anchor, one registration per attachment, one
        // READY per attachment (non-terminal per-capability, terminal
        // last). Every per-attachment guard stays live through the
        // final consumers (close retires exactly the listed set).
        let baseline = source_native_fd_targets();
        let mut setup = multi_attachment_setup("acquire");
        let pid = setup.child.pid();
        let marker = setup.dir.join("marker");
        let lease = super::source_owner::SourceAcquisitionLease::Enabled(
            super::source_owner::NativeSourceParams::for_test_multi(
                setup
                    .admitted_offsets
                    .iter()
                    .map(|offset| (setup.app.clone(), *offset, pid))
                    .collect(),
            ),
        );
        let receipts = setup
            .session
            .acquire_source_after_open(
                &lease,
                Instant::now() + Duration::from_secs(15),
                &setup.cancel,
            )
            .unwrap_or_else(|gap| {
                panic!(
                    "multi acquire failed: {gap:?} owner: {:?}",
                    setup.session.source_error()
                )
            });
        assert_eq!(receipts.attachments.len(), 2);
        assert_eq!(receipts.site_cookie, receipts.attachments[0].site_cookie);
        assert_eq!(receipts.link_offset, receipts.attachments[0].link_offset);
        assert_eq!(
            receipts.attachments[0].link_offset, setup.admitted_offsets[0],
            "claim order is admission order"
        );
        assert_eq!(
            receipts.attachments[1].link_offset,
            setup.admitted_offsets[1],
        );
        assert_eq!(
            receipts.attachments[0].anchor.anchor_id, receipts.attachments[1].anchor.anchor_id,
            "one file, one shared anchor"
        );
        assert_ne!(
            receipts.attachments[0].registration.registration_id,
            receipts.attachments[1].registration.registration_id,
            "one registration per attachment"
        );
        assert!(
            receipts.attachments[0].ready_sequence < receipts.attachments[1].ready_sequence,
            "READY publishes in admission order"
        );
        assert_eq!(
            receipts.adopted_links, 6,
            "two legacy pairs plus the typed pair"
        );
        assert_eq!(setup.session.typed_site_records().len(), 1);
        // Per-attachment guards live through the final consumers.
        let owner = setup.session.source_owner.as_ref().expect("source owner");
        assert_eq!(
            owner.guard_life_test(receipts.attachments[0].anchor.anchor_id),
            Some(super::source_acquire::GuardLife::Live)
        );
        for attachment in &receipts.attachments {
            assert_eq!(
                owner.guard_life_test(attachment.registration.registration_id),
                Some(super::source_acquire::GuardLife::Live),
                "cookie {} guard must be live",
                attachment.site_cookie,
            );
        }
        setup.child.release().unwrap();
        let until = Instant::now() + Duration::from_secs(15);
        loop {
            if let Ok(body) = std::fs::read(&marker) {
                if body == b"exec\n" {
                    break;
                }
            }
            assert!(Instant::now() < until, "exec marker never carried exec");
            std::thread::sleep(Duration::from_millis(1));
        }
        while setup.child.peek_exit().unwrap().is_none() {
            assert!(Instant::now() < until, "workload never exited");
            std::thread::yield_now();
        }
        assert_eq!(setup.child.poll_exit().unwrap(), Some(0));
        setup
            .session
            .note_source_exec(&lease, pid, receipts.domain.planned)
            .unwrap();
        setup.gate.close().unwrap();
        let close = setup.session.close_source_explicit().expect("source close");
        assert!(close.cut_confirmed, "close must confirm the cut");
        assert!(close.first_error.is_none());
        assert!(!close.order_refused, "the completed order must not refuse");
        assert_eq!(
            (
                close.guards_retired,
                close.guards_abandoned,
                close.domains_retired
            ),
            (4, 0, 1),
            "one anchor plus three registrations retire, none abandoned"
        );
        drop(setup.session);
        drop(setup.gate);
        drop(setup.child);
        // Discovery ran in the setup helper (its rest dropped on
        // return), so unlike the inline drivers there is no ghost
        // handle: teardown releases every fd exactly.
        assert_eq!(
            source_native_fd_targets(),
            baseline,
            "teardown must release every fd"
        );
        std::fs::remove_dir_all(&setup.dir).unwrap();
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges, cc"]
    fn multi_attachment_typed_refusal_fails_the_order_with_receipts() {
        // U4 mid-order refusal: both legacy pairs adopt, then the armed
        // typed ENTRY refuses, so the whole multi-attachment order
        // refuses (partial authority is worse than none). The close
        // receipts diagnose the refusal; every adopted per-attachment
        // link and guard is accounted (retired, none leaked).
        let mut setup = multi_attachment_setup("refuse");
        let pid = setup.child.pid();
        setup
            .session
            .source_owner
            .as_ref()
            .expect("source owner")
            .fail_next_typed_entry();
        let lease = super::source_owner::SourceAcquisitionLease::Enabled(
            super::source_owner::NativeSourceParams::for_test_multi(
                setup
                    .admitted_offsets
                    .iter()
                    .map(|offset| (setup.app.clone(), *offset, pid))
                    .collect(),
            ),
        );
        let error = match setup.session.acquire_source_after_open(
            &lease,
            Instant::now() + Duration::from_secs(15),
            &setup.cancel,
        ) {
            Ok(_) => panic!("armed typed ENTRY must refuse the order"),
            Err(error) => error,
        };
        assert_eq!(error, ObservationGap::AttachFailed);
        assert_eq!(
            setup
                .session
                .source_owner
                .as_ref()
                .expect("source owner")
                .adopted_link_count(),
            5,
            "both legacy pairs plus the refused typed ENTRY link adopt"
        );
        let diagnosis = setup.session.source_error().expect("refusal diagnosis");
        assert!(
            diagnosis.contains("ENTRY") || diagnosis.contains("entry"),
            "diagnosis names the typed ENTRY refusal: {diagnosis}"
        );
        setup.child.release().unwrap();
        let until = Instant::now() + Duration::from_secs(15);
        while setup.child.peek_exit().unwrap().is_none() {
            assert!(Instant::now() < until, "workload never exited");
            std::thread::yield_now();
        }
        assert_eq!(setup.child.poll_exit().unwrap(), Some(0));
        setup.gate.close().unwrap();
        let close = setup.session.close_source_explicit().expect("source close");
        assert!(close.order_refused, "the refused order must refuse");
        assert!(
            close.first_error.is_none(),
            "clean guard retirement carries no close error"
        );
        assert_eq!(
            (
                close.guards_retired,
                close.guards_abandoned,
                close.domains_retired
            ),
            (3, 0, 1),
            "anchor plus two legacy registrations retire, none abandoned"
        );
        drop(setup.session);
        drop(setup.gate);
        drop(setup.child);
        std::fs::remove_dir_all(&setup.dir).unwrap();
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges, cc"]
    fn multi_attachment_over_claimed_order_refuses_before_any_effect() {
        // U4 over-limit: three claims against two retained attachments
        // refuse at admission, before any kernel effect. The close
        // receipts carry the admission diagnosis; nothing adopts.
        let mut setup = multi_attachment_setup("overclaim");
        let pid = setup.child.pid();
        let mut triples = setup
            .admitted_offsets
            .iter()
            .map(|offset| (setup.app.clone(), *offset, pid))
            .collect::<Vec<_>>();
        triples.push((setup.app.clone(), 0x1234, pid));
        let lease = super::source_owner::SourceAcquisitionLease::Enabled(
            super::source_owner::NativeSourceParams::for_test_multi(triples),
        );
        let error = match setup.session.acquire_source_after_open(
            &lease,
            Instant::now() + Duration::from_secs(15),
            &setup.cancel,
        ) {
            Ok(_) => panic!("over-claimed order must refuse"),
            Err(error) => error,
        };
        assert_eq!(error, ObservationGap::Invalidated);
        assert_eq!(
            setup
                .session
                .source_owner
                .as_ref()
                .expect("source owner")
                .adopted_link_count(),
            0,
            "admission refusal adopts nothing"
        );
        let diagnosis = setup.session.source_error().expect("refusal diagnosis");
        assert!(
            diagnosis.contains("admission refused"),
            "diagnosis names the admission refusal: {diagnosis}"
        );
        setup.child.release().unwrap();
        let until = Instant::now() + Duration::from_secs(15);
        while setup.child.peek_exit().unwrap().is_none() {
            assert!(Instant::now() < until, "workload never exited");
            std::thread::yield_now();
        }
        assert_eq!(setup.child.poll_exit().unwrap(), Some(0));
        setup.gate.close().unwrap();
        let close = setup.session.close_source_explicit().expect("source close");
        assert!(close.order_refused, "the refused order must refuse");
        assert!(
            close.first_error.is_none(),
            "refusal before any effect carries no close error"
        );
        assert_eq!(
            (
                close.guards_retired,
                close.guards_abandoned,
                close.domains_retired
            ),
            (0, 0, 0),
            "refusal before any effect retires nothing"
        );
        drop(setup.session);
        drop(setup.gate);
        drop(setup.child);
        std::fs::remove_dir_all(&setup.dir).unwrap();
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges, cc"]
    fn multi_attachment_prearm_reserve_counts_planned_links() {
        // ER-S2-I1 prearm: reserve-only prearms count two planned links
        // each against `max_links`, and the complete prearm order reserves
        // before any effect (no partial prearm on refusal). Dual-API
        // fixture yields two legacy sites, so max 4 fits exactly while
        // max 3 and max 2 (the counterexample shape) refuse with LinkLimit
        // and zero startup attachments.
        for (max_links, expect_ok) in [(4usize, true), (3, false), (2, false)] {
            let dir = std::env::temp_dir().join(format!(
                "osslscope-prearm-link-{max_links}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&dir).unwrap();
            let app = source_native_dual_api_fixture(&dir);
            let marker = dir.join("marker");
            let argv = vec![
                app.to_string_lossy().into_owned(),
                marker.to_string_lossy().into_owned(),
            ];
            let mut child =
                crate::target::OwnedTarget::spawn_stopped(&argv, crate::target::WorkloadDest::Null)
                    .unwrap();
            let cancel = std::sync::atomic::AtomicBool::new(false);
            let mut budget = ObservationBudget::default();
            let startup = crate::startup_objects::prepare_owned_startup(
                &child,
                &argv,
                &mut budget,
                Instant::now() + Duration::from_secs(120),
                &cancel,
                None,
            )
            .unwrap();
            let crate::startup_objects::PreExecSites {
                apis,
                typed,
                candidates,
                ..
            } = startup;
            assert_eq!(apis.len(), 2, "dual-API fixture must yield two sites");
            drop(typed);
            drop(candidates);
            budget.limits.max_links = max_links;
            let object =
                std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap())
                    .unwrap();
            budget.state(crate::writer_gate::RESERVATION_BYTES).unwrap();
            let pool = budget.memory.clone().unwrap_or_else(|| {
                crate::observation_memory::MemoryPool::new(budget.limits.max_state_bytes)
            });
            let gate = crate::writer_gate::WriterGate::create(&pool).unwrap();
            let mut session = ProviderSession::open_gated(budget, &object, gate.clone()).unwrap();
            let pid = child.pid();
            let result = session.prearm_startup(
                apis,
                Instant::now() + Duration::from_secs(5),
                &cancel,
                PrearmLinks::Reserve,
            );
            if expect_ok {
                result.unwrap_or_else(|gap| {
                    panic!("max_links={max_links} must fit two reserves: {gap:?}")
                });
                assert_eq!(
                    session.startup.get(&pid).map_or(0, Vec::len),
                    2,
                    "max_links={max_links} prearms both reserves"
                );
                assert_eq!(session.link_pressure(), 4, "two reserves pressure 4");
            } else {
                assert_eq!(
                    result.unwrap_err(),
                    ObservationGap::LinkLimit,
                    "max_links={max_links} must refuse two reserves"
                );
                assert_eq!(
                    session.startup.get(&pid).map_or(0, Vec::len),
                    0,
                    "max_links={max_links} leaves no partial prearm"
                );
            }
            child.release().unwrap();
            let until = Instant::now() + Duration::from_secs(15);
            while child.peek_exit().unwrap().is_none() {
                assert!(Instant::now() < until, "workload never exited");
                std::thread::yield_now();
            }
            assert_eq!(child.poll_exit().unwrap(), Some(0));
            drop(session);
            drop(gate);
            drop(child);
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges, cc"]
    fn multi_attachment_acquire_link_budget_exact_fits() {
        // ER-S2-I1 acquisition exact-fit: dual-API needs 6 links (two
        // legacy pairs + one typed pair); max 6 fits exactly with 6
        // adoptions.
        let baseline = source_native_fd_targets();
        {
            let mut setup = multi_attachment_setup("link-exact");
            let pid = setup.child.pid();
            let marker = setup.dir.join("marker");
            setup.session.budget.limits.max_links = 6;
            let lease = super::source_owner::SourceAcquisitionLease::Enabled(
                super::source_owner::NativeSourceParams::for_test_multi(
                    setup
                        .admitted_offsets
                        .iter()
                        .map(|offset| (setup.app.clone(), *offset, pid))
                        .collect(),
                ),
            );
            let receipts = setup
                .session
                .acquire_source_after_open(
                    &lease,
                    Instant::now() + Duration::from_secs(15),
                    &setup.cancel,
                )
                .unwrap_or_else(|gap| {
                    panic!(
                        "max_links=6 must fit the dual-API order: {gap:?} owner: {:?}",
                        setup.session.source_error()
                    )
                });
            assert_eq!(receipts.attachments.len(), 2);
            assert_eq!(receipts.adopted_links, 6, "two legacy pairs + typed pair");
            setup.child.release().unwrap();
            let until = Instant::now() + Duration::from_secs(15);
            loop {
                if let Ok(body) = std::fs::read(&marker) {
                    if body == b"exec\n" {
                        break;
                    }
                }
                assert!(Instant::now() < until, "exec marker never carried exec");
                std::thread::sleep(Duration::from_millis(1));
            }
            while setup.child.peek_exit().unwrap().is_none() {
                assert!(Instant::now() < until, "workload never exited");
                std::thread::yield_now();
            }
            assert_eq!(setup.child.poll_exit().unwrap(), Some(0));
            setup
                .session
                .note_source_exec(&lease, pid, receipts.domain.planned)
                .unwrap();
            setup.gate.close().unwrap();
            let close = setup.session.close_source_explicit().expect("source close");
            assert!(close.cut_confirmed);
            assert_eq!(
                (
                    close.guards_retired,
                    close.guards_abandoned,
                    close.domains_retired
                ),
                (4, 0, 1),
                "anchor plus three registrations retire"
            );
            drop(setup.session);
            drop(setup.gate);
            drop(setup.child);
            assert_eq!(
                source_native_fd_targets(),
                baseline,
                "exact-fit teardown must release every fd"
            );
            std::fs::remove_dir_all(&setup.dir).unwrap();
        }
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges, cc"]
    fn multi_attachment_acquire_link_budget_over_refuses() {
        // ER-S2-I1 acquisition over-limit: max 5 and max 2 (the dual-API
        // counterexample shape) refuse with LinkLimit, zero adoptions and
        // a link-budget diagnosis, before any kernel effect.
        // Over-limit: max 5 and max 2 refuse before any effect.
        for max_links in [5usize, 2] {
            let mut setup = multi_attachment_setup(&format!("link-over-{max_links}"));
            let pid = setup.child.pid();
            setup.session.budget.limits.max_links = max_links;
            let lease = super::source_owner::SourceAcquisitionLease::Enabled(
                super::source_owner::NativeSourceParams::for_test_multi(
                    setup
                        .admitted_offsets
                        .iter()
                        .map(|offset| (setup.app.clone(), *offset, pid))
                        .collect(),
                ),
            );
            let error = match setup.session.acquire_source_after_open(
                &lease,
                Instant::now() + Duration::from_secs(15),
                &setup.cancel,
            ) {
                Ok(_) => panic!("max_links={max_links} must refuse the dual-API order"),
                Err(error) => error,
            };
            assert_eq!(
                error,
                ObservationGap::LinkLimit,
                "max_links={max_links} gap"
            );
            assert_eq!(
                setup
                    .session
                    .source_owner
                    .as_ref()
                    .expect("source owner")
                    .adopted_link_count(),
                0,
                "max_links={max_links} adopts nothing (counterexample: buggy code adopted 4)"
            );
            let diagnosis = setup.session.source_error().expect("refusal diagnosis");
            assert!(
                diagnosis.contains("link budget refused"),
                "max_links={max_links} diagnosis names the link budget: {diagnosis}"
            );
            setup.child.release().unwrap();
            let until = Instant::now() + Duration::from_secs(15);
            while setup.child.peek_exit().unwrap().is_none() {
                assert!(Instant::now() < until, "workload never exited");
                std::thread::yield_now();
            }
            assert_eq!(setup.child.poll_exit().unwrap(), Some(0));
            setup.gate.close().unwrap();
            let close = setup.session.close_source_explicit().expect("source close");
            assert!(close.order_refused, "the refused order must refuse");
            assert_eq!(
                (
                    close.guards_retired,
                    close.guards_abandoned,
                    close.domains_retired
                ),
                (0, 0, 0),
                "refusal before any effect retires nothing"
            );
            drop(setup.session);
            drop(setup.gate);
            drop(setup.child);
            std::fs::remove_dir_all(&setup.dir).unwrap();
        }
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges, cc"]
    fn multi_attachment_admission_small_budget_refuses_and_exact_admits() {
        // ER-S2-I2 admission: the matching/admission buffers charge the
        // caller budget before allocation. A budget one byte below the
        // admission charge refuses with StateLimit through the real
        // admission path; the exact byte admits both attachments.
        for (tight, expect_ok) in [(true, false), (false, true)] {
            let dir = std::env::temp_dir().join(format!(
                "osslscope-admit-budget-{}-{}-{}",
                if tight { "tight" } else { "exact" },
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&dir).unwrap();
            let app = source_native_dual_api_fixture(&dir);
            let marker = dir.join("marker");
            let argv = vec![
                app.to_string_lossy().into_owned(),
                marker.to_string_lossy().into_owned(),
            ];
            let mut child =
                crate::target::OwnedTarget::spawn_stopped(&argv, crate::target::WorkloadDest::Null)
                    .unwrap();
            let cancel = std::sync::atomic::AtomicBool::new(false);
            let mut budget = ObservationBudget::default();
            let startup = crate::startup_objects::prepare_owned_startup(
                &child,
                &argv,
                &mut budget,
                Instant::now() + Duration::from_secs(120),
                &cancel,
                None,
            )
            .unwrap();
            let crate::startup_objects::PreExecSites {
                apis,
                typed,
                candidates,
                ..
            } = startup;
            assert_eq!(apis.len(), 2);
            drop(typed);
            drop(candidates);
            budget.state(crate::writer_gate::RESERVATION_BYTES).unwrap();
            let pool = budget.memory.clone().unwrap_or_else(|| {
                crate::observation_memory::MemoryPool::new(budget.limits.max_state_bytes)
            });
            let gate = crate::writer_gate::WriterGate::create(&pool).unwrap();
            let mut session = ProviderSession::open_gated(
                budget,
                &std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap())
                    .unwrap(),
                gate.clone(),
            )
            .unwrap();
            session
                .prearm_startup(
                    apis,
                    Instant::now() + Duration::from_secs(5),
                    &cancel,
                    PrearmLinks::Reserve,
                )
                .unwrap();
            let pid = child.pid();
            assert_eq!(session.startup[&pid].len(), 2);
            let charge = super::source_owner::multi_attachment_admission_charge(2).unwrap();
            let spent = session.budget.state_spent_test();
            session.budget.limits.max_state_bytes = if tight {
                spent + charge - 1
            } else {
                spent + charge
            };
            let triples = session.startup[&pid]
                .iter()
                .map(|a| (app.clone(), a.site.file_offset(), pid))
                .collect::<Vec<_>>();
            let result = multi_admit(&session, triples);
            if expect_ok {
                let admitted = result
                    .unwrap_or_else(|gap| panic!("exact admission budget must admit: {gap:?}"));
                assert_eq!(admitted.len(), 2);
                drop(admitted);
            } else {
                let error = match result {
                    Ok(_) => panic!("tight admission budget must refuse"),
                    Err(error) => error,
                };
                assert_eq!(
                    error,
                    ObservationGap::StateLimit,
                    "tight admission budget must refuse"
                );
            }
            child.release().unwrap();
            let until = Instant::now() + Duration::from_secs(15);
            while child.peek_exit().unwrap().is_none() {
                assert!(Instant::now() < until, "workload never exited");
                std::thread::yield_now();
            }
            assert_eq!(child.poll_exit().unwrap(), Some(0));
            drop(session);
            drop(gate);
            drop(child);
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges, cc"]
    fn multi_attachment_acquisition_small_budget_refuses() {
        // ER-S2-I2 acquisition tight: a budget one byte below the
        // acquisition charge refuses with StateLimit and zero adoptions
        // through the real acquisition path.
        let admission = super::source_owner::multi_attachment_admission_charge(2).unwrap();
        let acquisition = super::source_owner::multi_attachment_acquisition_charge(2).unwrap();
        // Tight: admission fits but the acquisition buffers refuse.
        {
            let mut setup = multi_attachment_setup("acq-tight");
            let pid = setup.child.pid();
            let spent = setup.session.budget.state_spent_test();
            setup.session.budget.limits.max_state_bytes = spent + admission + acquisition - 1;
            let lease = super::source_owner::SourceAcquisitionLease::Enabled(
                super::source_owner::NativeSourceParams::for_test_multi(
                    setup
                        .admitted_offsets
                        .iter()
                        .map(|offset| (setup.app.clone(), *offset, pid))
                        .collect(),
                ),
            );
            let error = match setup.session.acquire_source_after_open(
                &lease,
                Instant::now() + Duration::from_secs(15),
                &setup.cancel,
            ) {
                Ok(_) => panic!("tight acquisition budget must refuse"),
                Err(error) => error,
            };
            assert_eq!(error, ObservationGap::StateLimit, "tight gap");
            assert_eq!(
                setup
                    .session
                    .source_owner
                    .as_ref()
                    .expect("source owner")
                    .adopted_link_count(),
                0,
                "tight acquisition adopts nothing"
            );
            let diagnosis = setup.session.source_error().expect("refusal diagnosis");
            assert!(
                diagnosis.contains("acquisition buffers refused"),
                "diagnosis names the acquisition buffers: {diagnosis}"
            );
            setup.child.release().unwrap();
            let until = Instant::now() + Duration::from_secs(15);
            while setup.child.peek_exit().unwrap().is_none() {
                assert!(Instant::now() < until, "workload never exited");
                std::thread::yield_now();
            }
            assert_eq!(setup.child.poll_exit().unwrap(), Some(0));
            setup.gate.close().unwrap();
            let close = setup.session.close_source_explicit().expect("source close");
            assert!(close.order_refused);
            assert_eq!(
                (
                    close.guards_retired,
                    close.guards_abandoned,
                    close.domains_retired
                ),
                (0, 0, 0),
            );
            drop(setup.session);
            drop(setup.gate);
            drop(setup.child);
            std::fs::remove_dir_all(&setup.dir).unwrap();
        }
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges, cc"]
    fn multi_attachment_acquisition_small_budget_exact_fits() {
        // ER-S2-I2 acquisition exact-fit: the full-order budget
        // (admission + acquisition + the typed per-site charge) fits with
        // 6 adoptions.
        let admission = super::source_owner::multi_attachment_admission_charge(2).unwrap();
        let acquisition = super::source_owner::multi_attachment_acquisition_charge(2).unwrap();
        // Exact: the full order fits with 6 adoptions.
        {
            let mut setup = multi_attachment_setup("acq-exact");
            let pid = setup.child.pid();
            let marker = setup.dir.join("marker");
            let spent = setup.session.budget.state_spent_test();
            // One typed site at 512 + 96, matching `acquire_typed_sites`.
            setup.session.budget.limits.max_state_bytes =
                spent + admission + acquisition + 512 + 96;
            let lease = super::source_owner::SourceAcquisitionLease::Enabled(
                super::source_owner::NativeSourceParams::for_test_multi(
                    setup
                        .admitted_offsets
                        .iter()
                        .map(|offset| (setup.app.clone(), *offset, pid))
                        .collect(),
                ),
            );
            let receipts = setup
                .session
                .acquire_source_after_open(
                    &lease,
                    Instant::now() + Duration::from_secs(15),
                    &setup.cancel,
                )
                .unwrap_or_else(|gap| {
                    panic!(
                        "exact acquisition budget must fit: {gap:?} owner: {:?}",
                        setup.session.source_error()
                    )
                });
            assert_eq!(receipts.attachments.len(), 2);
            assert_eq!(receipts.adopted_links, 6);
            setup.child.release().unwrap();
            let until = Instant::now() + Duration::from_secs(15);
            loop {
                if let Ok(body) = std::fs::read(&marker) {
                    if body == b"exec\n" {
                        break;
                    }
                }
                assert!(Instant::now() < until, "exec marker never carried exec");
                std::thread::sleep(Duration::from_millis(1));
            }
            while setup.child.peek_exit().unwrap().is_none() {
                assert!(Instant::now() < until, "workload never exited");
                std::thread::yield_now();
            }
            assert_eq!(setup.child.poll_exit().unwrap(), Some(0));
            setup
                .session
                .note_source_exec(&lease, pid, receipts.domain.planned)
                .unwrap();
            setup.gate.close().unwrap();
            let close = setup.session.close_source_explicit().expect("source close");
            assert!(close.cut_confirmed);
            assert_eq!(
                (
                    close.guards_retired,
                    close.guards_abandoned,
                    close.domains_retired
                ),
                (4, 0, 1),
            );
            drop(setup.session);
            drop(setup.gate);
            drop(setup.child);
            std::fs::remove_dir_all(&setup.dir).unwrap();
        }
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges, cc"]
    fn multi_attachment_receipts_retain_acquisition_charge_across_session_teardown() {
        // ER-S2-I2 lifetime: the returned receipts own the
        // acquisition-peak reservation, so the returned-attachment
        // storage stays charged across session teardown and the
        // charge releases exactly when the receipts do.
        let acquisition = super::source_owner::multi_attachment_acquisition_charge(2).unwrap();
        let baseline = source_native_fd_targets();
        let mut setup = multi_attachment_setup("acq-lifetime");
        let pid = setup.child.pid();
        let marker = setup.dir.join("marker");
        let lease = super::source_owner::SourceAcquisitionLease::Enabled(
            super::source_owner::NativeSourceParams::for_test_multi(
                setup
                    .admitted_offsets
                    .iter()
                    .map(|offset| (setup.app.clone(), *offset, pid))
                    .collect(),
            ),
        );
        let receipts = setup
            .session
            .acquire_source_after_open(
                &lease,
                Instant::now() + Duration::from_secs(15),
                &setup.cancel,
            )
            .unwrap_or_else(|gap| {
                panic!(
                    "default-budget acquisition must fit: {gap:?} owner: {:?}",
                    setup.session.source_error()
                )
            });
        assert_eq!(receipts.attachments.len(), 2);
        assert_eq!(receipts.adopted_links, 6);
        let probe = setup.session.budget.clone();
        assert_eq!(
            receipts.retained_state_spent_test(),
            Some(probe.state_spent_test()),
            "receipts observe the live shared accounting"
        );
        setup.child.release().unwrap();
        let until = Instant::now() + Duration::from_secs(15);
        loop {
            if let Ok(body) = std::fs::read(&marker) {
                if body == b"exec\n" {
                    break;
                }
            }
            assert!(Instant::now() < until, "exec marker never carried exec");
            std::thread::sleep(Duration::from_millis(1));
        }
        while setup.child.peek_exit().unwrap().is_none() {
            assert!(Instant::now() < until, "workload never exited");
            std::thread::yield_now();
        }
        assert_eq!(setup.child.poll_exit().unwrap(), Some(0));
        setup
            .session
            .note_source_exec(&lease, pid, receipts.domain.planned)
            .unwrap();
        setup.gate.close().unwrap();
        let close = setup.session.close_source_explicit().expect("source close");
        assert!(close.cut_confirmed);
        assert_eq!(
            (
                close.guards_retired,
                close.guards_abandoned,
                close.domains_retired
            ),
            (4, 0, 1),
        );
        // Session teardown while the receipts are retained: the
        // shared accounting must still carry the acquisition charge.
        drop(setup.session);
        drop(setup.gate);
        drop(setup.child);
        let spent_charged = probe.state_spent_test();
        assert_eq!(
            receipts.retained_state_spent_test(),
            Some(spent_charged),
            "receipts still observe live accounting after session teardown"
        );
        assert!(
            spent_charged >= acquisition,
            "teardown must not release the retained charge: spent {spent_charged} < {acquisition}"
        );
        // Release boundary: dropping the receipts frees the returned
        // storage and refunds exactly its charge.
        drop(receipts);
        assert_eq!(
            probe.state_spent_test(),
            spent_charged - acquisition,
            "receipt release refunds exactly the acquisition charge"
        );
        assert_eq!(
            source_native_fd_targets(),
            baseline,
            "lifetime teardown must release every fd"
        );
        std::fs::remove_dir_all(&setup.dir).unwrap();
    }
    fn multi_admit(
        session: &ProviderSession,
        triples: Vec<(std::path::PathBuf, u64, u32)>,
    ) -> Result<Vec<super::source_owner::AdmittedSourceSite>, ObservationGap> {
        session.admitted_source_sites(&super::source_owner::NativeSourceParams::for_test_multi(
            triples,
        ))
    }
    fn multi_refuses(
        session: &ProviderSession,
        triples: Vec<(std::path::PathBuf, u64, u32)>,
        what: &str,
    ) {
        let error = match multi_admit(session, triples) {
            Ok(_) => panic!("{what} must refuse"),
            Err(error) => error,
        };
        assert_eq!(error, ObservationGap::Invalidated, "{what} gap");
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges"]
    fn real_openssl_multi_attachment_admission_passes_and_over_limit_refuses() {
        // U4: the real /usr/bin/openssl closure yields 62 legacy API
        // attachments in one file; the multi-attachment lease admits
        // all 38 (exact count, distinct match, legacy-range cookies).
        // The same session then refuses every over-limit shape: over-
        // and under-claimed orders, double-matched attachments,
        // substituted offset/file/PID, empty claims and an out-of-range
        // cookie. Admission is host-side and pure; privilege here is
        // setup-only (the BPF load the session harness requires).
        let baseline = source_native_fd_targets();
        let dir = std::env::temp_dir().join(format!(
            "osslscope-multi-real-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("abc.txt"), b"abc").unwrap();
        let argv = vec![
            "/usr/bin/openssl".to_string(),
            "mac".to_string(),
            "-digest".to_string(),
            "SHA256".to_string(),
            "-macopt".to_string(),
            format!("hexkey:{}", "0b".repeat(20)),
            "-in".to_string(),
            dir.join("abc.txt").to_string_lossy().into_owned(),
            "HMAC".to_string(),
        ];
        let mut child =
            crate::target::OwnedTarget::spawn_stopped(&argv, crate::target::WorkloadDest::Null)
                .unwrap();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let mut budget = ObservationBudget::default();
        let startup = crate::startup_objects::prepare_owned_startup(
            &child,
            &argv,
            &mut budget,
            Instant::now() + Duration::from_secs(120),
            &cancel,
            None,
        )
        .unwrap();
        // Bind and release explicitly: pattern-ignored (`..`/`_`) fields
        // stay in the scrutinee until scope end (past the FD assert
        // below), which is the per-file ghost handle the typed driver
        // pins at +1 for its single-file flow.
        let crate::startup_objects::PreExecSites {
            apis,
            typed,
            candidates,
            ..
        } = startup;
        assert_eq!(typed.len(), 17, "real openssl yields 17 typed exports");
        drop(typed);
        drop(candidates);
        assert_eq!(
            apis.len(),
            62,
            "real openssl must yield 62 legacy sites (38 + 24 additive)"
        );
        let object =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        budget.state(crate::writer_gate::RESERVATION_BYTES).unwrap();
        let pool = budget.memory.clone().unwrap_or_else(|| {
            crate::observation_memory::MemoryPool::new(budget.limits.max_state_bytes)
        });
        let gate = crate::writer_gate::WriterGate::create(&pool).unwrap();
        let mut session = ProviderSession::open_gated(budget, &object, gate.clone()).unwrap();
        session
            .prearm_startup(
                apis,
                Instant::now() + Duration::from_secs(30),
                &cancel,
                PrearmLinks::Reserve,
            )
            .unwrap();
        let pid = child.pid();
        assert_eq!(session.startup[&pid].len(), 62);
        // Claims from the retained attachments themselves (FD-path
        // targets, no pathname premise); FDs stay alive for the matrix.
        let mut fds = Vec::new();
        let mut triples = Vec::new();
        for attachment in &session.startup[&pid] {
            let fd = attachment
                .site
                .attachment_fd()
                .try_clone_to_owned()
                .unwrap();
            triples.push((
                std::path::PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd())),
                attachment.site.file_offset(),
                pid,
            ));
            fds.push(fd);
        }
        // Admissions (and their per-claim target dups) scope tightly:
        // nothing admitted outlives this block.
        {
            let admitted = multi_admit(&session, triples.clone()).expect("38 claims must admit");
            assert_eq!(admitted.len(), 62);
            assert_eq!(
                admitted.iter().map(|a| a.site_cookie).collect::<Vec<_>>(),
                (1..=62u64).collect::<Vec<_>>(),
                "claim order is admission order, cookies sequential"
            );
            for (a, &(_, offset, _)) in admitted.iter().zip(triples.iter()) {
                assert_eq!(a.link_offset, offset);
            }
            assert!(
                session.startup[&pid].iter().all(|a| a.links.is_empty()),
                "reserve-only prearm carries no producer links"
            );
            let (device, inode) = (admitted[0].device, admitted[0].inode);
            assert!(
                admitted
                    .iter()
                    .all(|a| (a.device, a.inode) == (device, inode)),
                "all 62 attachments share one backing file (single-anchor order)"
            );
            assert!(
                admitted
                    .iter()
                    .all(|a| a.expected_artifact == admitted[0].expected_artifact),
                "one file, one artifact hash"
            );
            // Over-limit matrix: every shape refuses.
            let mut over = triples.clone();
            over.push((over[0].0.clone(), 0x1234, pid));
            multi_refuses(&session, over, "over-claimed");
            let mut under = triples.clone();
            under.pop();
            multi_refuses(&session, under, "under-claimed");
            let mut dup = triples.clone();
            dup[61] = dup[0].clone();
            multi_refuses(&session, dup, "double-matched");
            let mut offset = triples.clone();
            offset[0].1 += 1;
            multi_refuses(&session, offset, "substituted offset");
            let mut file = triples.clone();
            file[0].0 = std::path::PathBuf::from("/bin/true");
            multi_refuses(&session, file, "substituted file");
            let mut recycled = triples.clone();
            recycled[0].2 += 1;
            multi_refuses(&session, recycled, "recycled pid");
            multi_refuses(&session, Vec::new(), "empty claims");
        }
        session.startup.get_mut(&pid).unwrap()[0].cookie = 5000;
        multi_refuses(&session, triples.clone(), "out-of-range cookie");
        session.startup.get_mut(&pid).unwrap()[0].cookie = 1;
        assert_eq!(
            multi_admit(&session, triples.clone())
                .expect("restored cookie admits")
                .len(),
            62
        );
        drop(fds);
        child.release().unwrap();
        let until = Instant::now() + Duration::from_secs(15);
        while child.peek_exit().unwrap().is_none() && Instant::now() < until {
            std::thread::yield_now();
        }
        assert_eq!(child.poll_exit().unwrap(), Some(0));
        drop(session);
        drop(gate);
        drop(child);
        assert_eq!(
            source_native_fd_targets(),
            baseline,
            "admission-only flow must release every fd"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
    /// U5 expected MAC digest: `openssl mac -digest SHA256 -macopt
    /// hexkey:0b*20 -in abc.txt HMAC` over input `abc`. Python-`hmac`
    /// verified (§13.2, re-verified by the U5 oracle leg): the observed
    /// workload stdout must equal this and a fresh unobserved re-run.
    const U5_MAC_DIGEST: &str = "721E281E92410E545A431EAC66267721B917C6BEAF08A86D6E4BC67B657B92DE";
    /// U5 real-`openssl mac` argv (P4 lane, §13.1 verbatim): ordinary
    /// unmodified HMAC-SHA256 over the `abc.txt` input in `dir`.
    fn u5_openssl_mac_argv(dir: &std::path::Path) -> Vec<String> {
        vec![
            "/usr/bin/openssl".to_string(),
            "mac".to_string(),
            "-digest".to_string(),
            "SHA256".to_string(),
            "-macopt".to_string(),
            format!("hexkey:{}", "0b".repeat(20)),
            "-in".to_string(),
            dir.join("abc.txt").to_string_lossy().into_owned(),
            "HMAC".to_string(),
        ]
    }
    /// U5 pass 1: legacy-only observation of the real `openssl mac`
    /// workload (38 API sites, real argv, no marker) drained for live
    /// query observations, exact-matched to the retained arrays into a
    /// copied-role staging plan. Returns the plan plus the observed
    /// workload digest (pass-1 oracle agreement).
    fn u5_pass1_plan_from_live_queries(
        argv: &[String],
        dir: &std::path::Path,
    ) -> (super::copied_plan::CopiedPlan, String) {
        let stdout_path = dir.join("out1.txt");
        std::fs::write(&stdout_path, b"").unwrap();
        let mut child = crate::target::OwnedTarget::spawn_stopped(
            argv,
            crate::target::WorkloadDest::File(stdout_path.clone()),
        )
        .unwrap();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let mut budget = ObservationBudget::default();
        let startup = crate::startup_objects::prepare_owned_startup(
            &child,
            argv,
            &mut budget,
            Instant::now() + Duration::from_secs(120),
            &cancel,
            None,
        )
        .unwrap();
        assert_eq!(
            startup.apis.len(),
            62,
            "real openssl yields 62 legacy sites (38 + 24 additive Task-7 APIs)"
        );
        assert_eq!(
            startup.typed.len(),
            17,
            "real openssl yields 17 typed exports"
        );
        eprintln!(
            "u5 pass1 startup candidates={} gaps={:?} files={}",
            startup.candidates.len(),
            startup.gaps,
            startup.plan_arrays.len(),
        );
        assert_eq!(
            startup.candidates.len(),
            10722,
            "real openssl parses its full dispatch closure"
        );
        assert_eq!(
            startup.gaps,
            std::collections::BTreeSet::from([
                ObservationGap::MalformedElf,
                ObservationGap::DispatchPartial,
                ObservationGap::SamplingPartial,
            ]),
            "the known discovery gaps, nothing else"
        );
        assert_eq!(
            startup.plan_arrays.len(),
            6,
            "six parsed files carry arrays"
        );
        // Bind and release explicitly: pattern-ignored (`..`) fields
        // stay in the scrutinee until scope end (the §21.2 ghost-Rc
        // lesson); candidates retain the parsed lib file handles.
        let crate::startup_objects::PreExecSites {
            apis,
            typed,
            candidates,
            plan_arrays,
            ..
        } = startup;
        drop(typed);
        drop(candidates);
        let object =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        let fds_before = source_native_fd_targets();
        let mut session = ProviderSession::open(ObservationLimits::default(), &object).unwrap();
        session
            .prearm_startup(
                apis,
                Instant::now() + Duration::from_secs(30),
                &cancel,
                PrearmLinks::Create,
            )
            .unwrap();
        child.release().unwrap();
        let until = Instant::now() + Duration::from_secs(30);
        while child.peek_exit().unwrap().is_none() {
            assert!(Instant::now() < until, "pass-1 workload never exited");
            std::thread::yield_now();
        }
        assert_eq!(child.poll_exit().unwrap(), Some(0), "pass-1 public oracle");
        child.finish_observation().unwrap();
        let digest = std::fs::read_to_string(&stdout_path).unwrap();
        let digest = digest.trim().to_ascii_uppercase();
        assert_eq!(digest, U5_MAC_DIGEST, "pass-1 observed digest must verify");
        let mut records = Vec::new();
        let mut decode_failures = 0usize;
        while let Some(bytes) = session.events.next() {
            match super::wire::decode_transport(&bytes) {
                Ok(transport) => records.push(transport.record()),
                Err(_) => decode_failures += 1,
            }
        }
        eprintln!(
            "u5 pass1 records={} decode_failures={}",
            records.len(),
            decode_failures
        );
        assert_eq!(decode_failures, 0, "every ring record must validate");
        assert_eq!(records.len(), 528, "the deterministic legacy record volume");
        drop(session);
        drop(child);
        let after = source_native_fd_targets();
        let bpf = |fds: &[String]| {
            fds.iter()
                .filter(|fd| {
                    fd.contains("bpf-map") || fd.contains("bpf-prog") || fd.contains("bpf_link")
                })
                .count()
        };
        assert_eq!(bpf(&after), bpf(&fds_before), "pass-1 BPF FDs must return");
        let live = super::copied_plan::collect_live_queries(&records);
        eprintln!("u5 pass1 live_queries={live:?}");
        assert_eq!(live.len(), 1, "exactly the MAC query survives agreement");
        assert_eq!(live[0].operation, 3, "the kept query is op MAC");
        assert_eq!(
            live[0]
                .algos
                .iter()
                .map(|(index, _)| *index)
                .collect::<Vec<_>>(),
            (0..9).collect::<Vec<_>>(),
            "nine dense live algorithm indices"
        );
        let plan_budget = ObservationBudget::default();
        let plan = super::copied_plan::generate_plan(&plan_arrays, &live, &plan_budget).unwrap();
        eprintln!("u5 pass1 plan sites={:?}", plan.sites);
        assert!(
            !plan.sites.is_empty(),
            "the live MAC queries must stage copied-role sites"
        );
        (plan, digest)
    }
    /// U5 committed fit pin (S2-N2): the verbatim P4 re-run (§13.1/§13.6)
    /// procedure on the real binary. Direct-exec ordinary unmodified
    /// `openssl mac` (HMAC-SHA256) on host 7.0.0-38 drives the §12.3
    /// session shape — pass-1 live-query plan, Enabled 38-claim lease,
    /// typed admit+attach, shared counter at the staged operational
    /// roles, common cut, closed collect — asserting exact staging,
    /// full in-kernel chain verdicts, fit under the frozen 64 MiB
    /// ceiling at every phase, and oracle agreement of the observed
    /// digest with the Python-verified value plus a fresh unobserved
    /// re-run. Diagnostic truncations from §13.1 (prearm to 1 API,
    /// typed to 2) are gone: U3+U4 run the full order.
    ///
    /// The first positive is GREEN (U146 §27): role 146 stages at
    /// its forwarder-derived trampoline through its own resolve, the
    /// getter observation lands exactly once on the committing 147
    /// parent (four trampoline executions, one committing parent —
    /// bind_prepare enforces getter_count == 1 with zero flags, so a
    /// second getter would have refused), the owner commits, and the
    /// three joined operational hits attribute into definite
    /// partitions — the receipt below pins that positive exactly.
    ///
    /// ```sh
    /// OSSL_PROVIDER_OBSERVATION_TEST_BPF=<provider object> \
    /// OSSLSCOPE_FOCUSED_COUNT_OBJECT=<count object> \
    /// sudo -n <lib test binary> \
    ///     real_openssl_mac_full_acquire_fits_with_oracle_agreement --test-threads=1
    /// ```
    #[test]
    #[ignore = "U5 real-openssl fit pin (sudo, pinned BPF objects)"]
    fn real_openssl_mac_full_acquire_fits_with_oracle_agreement() {
        use crate::capture::ClockPort as _;
        let ceiling: usize =
            crate::provider_observation::ObservationLimits::default().max_state_bytes;
        let dir = std::env::temp_dir().join(format!(
            "osslscope-u5-positive-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("abc.txt"), b"abc").unwrap();
        let argv = u5_openssl_mac_argv(&dir);
        let (plan, pass1_digest) = u5_pass1_plan_from_live_queries(&argv, &dir);
        assert_eq!(pass1_digest, U5_MAC_DIGEST);
        let mut plan_roles: Vec<u32> = plan.sites.iter().map(|site| site.role_id).collect();
        plan_roles.sort_unstable();
        eprintln!("u5 plan roles={plan_roles:?}");
        assert_eq!(
            plan.sites.len(),
            49,
            "the live MAC array stages 49 callbacks"
        );
        assert_eq!(
            plan_roles,
            vec![
                258, 258, 258, 258, 258, 258, 258, 258, 258, 274, 274, 274, 274, 274, 274, 274,
                274, 290, 290, 290, 290, 290, 290, 290, 290, 304, 304, 304, 304, 304, 304, 304,
                304, 305, 305, 305, 305, 305, 305, 305, 305, 306, 306, 306, 306, 306, 306, 306,
                306,
            ],
            "nine constructors with eight lifecycle/dup/init/update/final each"
        );
        // Pass 2: the full §12.3 session shape with the pass-1 plan.
        let baseline = source_native_fd_targets();
        let stdout_path = dir.join("out2.txt");
        std::fs::write(&stdout_path, b"").unwrap();
        let mut child = crate::target::OwnedTarget::spawn_stopped(
            &argv,
            crate::target::WorkloadDest::File(stdout_path.clone()),
        )
        .unwrap();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let mut budget = ObservationBudget::default();
        let startup = crate::startup_objects::prepare_owned_startup(
            &child,
            &argv,
            &mut budget,
            Instant::now() + Duration::from_secs(120),
            &cancel,
            Some(&plan),
        )
        .unwrap();
        eprintln!(
            "u5 startup apis={} typed={} copied_skipped={}",
            startup.apis.len(),
            startup.typed.len(),
            startup.copied_skipped,
        );
        assert_eq!(
            startup.apis.len(),
            62,
            "pass-2 rescan keeps 62 legacy sites (38 + 24 additive)"
        );
        assert_eq!(
            startup.copied_skipped, 0,
            "pass-2 rescan agrees with the pass-1 plan on every site"
        );
        assert_eq!(
            startup.typed.len(),
            18 + plan.sites.len(),
            "17 first-slice + query + every planned copied site"
        );
        let spent_discovery = budget.state_spent_test();
        eprintln!("u5 spent after-discovery={spent_discovery}");
        assert!(spent_discovery < ceiling, "discovery must fit the ceiling");
        // Bind and release explicitly (§21.2 ghost-Rc lesson, as in
        // pass 1 above); only gaps/copied_skipped/plan_arrays stay.
        let crate::startup_objects::PreExecSites {
            apis,
            typed,
            candidates,
            ..
        } = startup;
        drop(candidates);
        let object =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        let count_object =
            std::fs::read(std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT").unwrap()).unwrap();
        budget.state(crate::writer_gate::RESERVATION_BYTES).unwrap();
        let pool = budget.memory.clone().unwrap_or_else(|| {
            crate::observation_memory::MemoryPool::new(budget.limits.max_state_bytes)
        });
        let gate = crate::writer_gate::WriterGate::create(&pool).unwrap();
        let mut session = ProviderSession::open_gated(budget, &object, gate.clone()).unwrap();
        session
            .prearm_startup(
                apis,
                Instant::now() + Duration::from_secs(30),
                &cancel,
                PrearmLinks::Reserve,
            )
            .unwrap();
        let pid = child.pid();
        assert_eq!(session.startup[&pid].len(), 62);
        let spent_prearm = session.budget.state_spent_test();
        eprintln!("u5 spent after-prearm={spent_prearm}");
        assert!(spent_prearm < ceiling, "prearm must fit the ceiling");
        // Claims from the retained attachments themselves (FD-path
        // targets, no pathname premise); FDs stay alive through acquire.
        let mut fds = Vec::new();
        let mut triples = Vec::new();
        for attachment in &session.startup[&pid] {
            let fd = attachment
                .site
                .attachment_fd()
                .try_clone_to_owned()
                .unwrap();
            triples.push((
                std::path::PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd())),
                attachment.site.file_offset(),
                pid,
            ));
            fds.push(fd);
        }
        let lease = super::source_owner::SourceAcquisitionLease::Enabled(
            super::source_owner::NativeSourceParams::for_test_multi(triples),
        );
        session
            .prepare_typed_startup(
                typed,
                Instant::now() + Duration::from_secs(60),
                &cancel,
                &lease,
            )
            .unwrap();
        let typed_sites = session.typed_startup.len();
        let spent_prepare = session.budget.state_spent_test();
        eprintln!("u5 spent after-prepare-typed={spent_prepare}");
        assert!(
            spent_prepare < ceiling,
            "typed prepare must fit the ceiling"
        );
        let start_ns = crate::capture::LiveClock.checked_monotonic_ns().unwrap();
        let deadline_ns = start_ns + 15_000_000_000;
        let borrowed = session.borrowed_producer_maps().expect("producer maps");
        let mut counter = crate::focused_count::FocusedCounter::open_gated_shared(
            &count_object,
            child.pid(),
            crate::focused_capture::observer_namespace().unwrap(),
            crate::focused_count::CountLimits {
                window: crate::evidence::CountAdmissionWindow {
                    start_ns,
                    deadline_ns,
                },
                ..Default::default()
            },
            gate.clone(),
            &borrowed,
        )
        .unwrap();
        gate.open().unwrap();
        let receipts = session
            .acquire_source_after_open(&lease, Instant::now() + Duration::from_secs(60), &cancel)
            .unwrap_or_else(|gap| {
                panic!(
                    "full-62 acquire failed: {gap:?} owner: {:?}",
                    session.source_error()
                )
            });
        let spent_acquire = session.budget.state_spent_test();
        eprintln!("u5 spent after-acquire={spent_acquire}");
        assert!(
            spent_acquire < ceiling,
            "full-62 acquire must fit the ceiling"
        );
        assert_eq!(receipts.attachments.len(), 62, "every claim acquires");
        assert_eq!(
            receipts
                .attachments
                .iter()
                .map(|a| a.site_cookie)
                .collect::<Vec<_>>(),
            (1..=62u64).collect::<Vec<_>>(),
            "claim order is admission order, cookies sequential"
        );
        assert!(
            receipts.attachments.windows(2).all(|pair| {
                pair[0].anchor.anchor_id == pair[1].anchor.anchor_id
                    && pair[0].ready_sequence < pair[1].ready_sequence
            }),
            "one shared anchor, READY in admission order"
        );
        assert_eq!(
            session.typed_site_records().len(),
            typed_sites,
            "every staged typed site must admit"
        );
        drop(fds);
        // Counter at the staged operational roles (304-308 present).
        let mut count_roles: Vec<u32> = session
            .typed_site_records()
            .values()
            .map(|record| record.role_id)
            .filter(|role| (304..=308).contains(role))
            .collect();
        count_roles.sort_unstable();
        count_roles.dedup();
        eprintln!("u5 count_roles={count_roles:?}");
        assert_eq!(
            count_roles,
            vec![304, 305, 306],
            "MAC init/update/final stage, KDF derive/reset do not"
        );
        let mut candidates = Vec::new();
        for staged in &session.typed_startup {
            if !count_roles.contains(&staged.role().id()) {
                continue;
            }
            let site = staged.site().clone();
            let starttime = site.starttime();
            let record = super::wire::contract::Record {
                pid: child.pid(),
                tid: child.pid(),
                generation: site.generation(),
                ..super::wire::contract::Record::default()
            };
            candidates.push(crate::focused_count::CountCandidate::Learned(
                VerifiedSiteCandidate {
                    site,
                    pid: child.pid(),
                    starttime,
                    generation: record.generation,
                    advertisers: Vec::new(),
                    operation: super::schema::Operation::Mac,
                    numeric_operation: 0,
                    dynamic_algorithm: super::static_tables::DynamicAlgorithmId::observed(
                        session.typed_startup[0].site().object_hash(),
                        starttime,
                        &record,
                    ),
                    observed_ns: start_ns,
                    algorithm: super::schema::AlgorithmId::try_from(u16::MAX).unwrap(),
                    alias_quality: super::schema::AliasQuality::default(),
                    function: super::schema::FunctionIdentity::new(
                        super::schema::Operation::Mac,
                        0,
                    )
                    .unwrap(),
                },
            ));
        }
        let staged_operational = session
            .typed_startup
            .iter()
            .filter(|staged| count_roles.contains(&staged.role().id()))
            .count();
        assert_eq!(
            candidates.len(),
            staged_operational,
            "one counter site per staged operational site"
        );
        assert_eq!(
            staged_operational, 24,
            "eight staged sites per operational role"
        );
        counter
            .attach_candidates_pinned(
                candidates,
                start_ns,
                Instant::now() + Duration::from_secs(15),
                &cancel,
                session.typed_pins(),
            )
            .unwrap();
        let counter_links = counter.active_link_count();
        // Release only after READY, then the independent workload oracle.
        child.release().unwrap();
        let until = Instant::now() + Duration::from_secs(30);
        while child.peek_exit().unwrap().is_none() {
            assert!(Instant::now() < until, "workload never exited");
            std::thread::yield_now();
        }
        assert_eq!(child.poll_exit().unwrap(), Some(0), "workload must exit 0");
        child.finish_observation().unwrap();
        let digest = std::fs::read_to_string(&stdout_path).unwrap();
        let digest = digest.trim().to_ascii_uppercase();
        assert_eq!(digest, U5_MAC_DIGEST, "observed digest must verify");
        let rerun = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .output()
            .unwrap();
        assert!(rerun.status.success(), "unobserved re-run must exit 0");
        let rerun_digest = String::from_utf8_lossy(&rerun.stdout);
        assert_eq!(
            rerun_digest.trim().to_ascii_uppercase(),
            U5_MAC_DIGEST,
            "unobserved re-run must agree"
        );
        assert_eq!(
            digest,
            rerun_digest.trim().to_ascii_uppercase(),
            "observed and re-run digests agree"
        );
        session
            .note_source_exec(&lease, child.pid(), receipts.domain.planned)
            .unwrap();
        session.finalize_until(Instant::now() + Duration::from_secs(10));
        let cpus = counter.cpus();
        let sample = counter.close(Instant::now() + Duration::from_secs(10));
        let records: Vec<(u64, TypedSiteRecord)> = session
            .typed_site_records()
            .iter()
            .map(|(cookie, record)| (*cookie, record.clone()))
            .collect();
        session
            .charge_attribution_final(
                8192usize
                    .checked_mul(104 + 24 * cpus)
                    .and_then(|n| n.checked_add(1024 * (16 + 64)))
                    .and_then(|n| n.checked_add(1024 * (24 + 56)))
                    .and_then(|n| n.checked_add(8 * 8 * cpus))
                    .and_then(|n| n.checked_add(64))
                    .unwrap(),
            )
            .unwrap();
        let spent_collect = session.budget.state_spent_test();
        eprintln!("u5 spent after-collect-charge={spent_collect}");
        assert!(
            spent_collect < ceiling,
            "collect charge must fit the ceiling"
        );
        let maps = session.attribution_maps().expect("attribution maps");
        let mut admitted = Vec::with_capacity(records.len());
        for (cookie, record) in &records {
            admitted.push(crate::attribution::AdmittedTypedSite {
                cookie: *cookie,
                site_id: std::num::NonZeroU64::new(record.site_id).unwrap(),
                role_id: record.role_id,
                object: record.object.clone(),
                device: record.device,
                inode: record.inode,
                offset: record.offset,
                object_id: record.object_id,
                source_epoch: record.source_epoch,
            });
        }
        let end_ns = crate::capture::LiveClock
            .checked_monotonic_ns()
            .unwrap()
            .min(deadline_ns);
        let admission = crate::evidence::CountAdmissionWindow {
            start_ns,
            deadline_ns,
        };
        let finalized = crate::attribution::collect_closed_attribution(
            gate.owned_closed().expect("closed gate"),
            &gate,
            &maps,
            cpus,
            &sample,
            &admitted,
            admission,
            crate::evidence::CaptureWindow {
                requested_start_ns: start_ns,
                requested_end_ns: deadline_ns,
                effective_start_ns: start_ns,
                effective_end_ns: end_ns.max(start_ns),
                signal_cut: false,
                count_admission: Some(admission),
            },
        )
        .unwrap_or_else(|error| panic!("closed collect failed: {error:?}"));
        let mut joined_sites = 0usize;
        let mut joined_calls = 0u64;
        for execution in &sample.sites {
            if admitted.iter().any(|site| {
                site.object == execution.site.object
                    && site.device == execution.site.device
                    && site.inode == execution.site.inode
                    && site.offset == execution.site.offset
            }) {
                joined_sites += 1;
                joined_calls += execution.calls;
            }
        }
        let sample_calls: u64 = sample.sites.iter().map(|site| site.calls).sum();
        let next_producer_id = {
            let fd = session
                .source_owner
                .as_ref()
                .unwrap()
                .owned_map("ATTRIB_CONTROL")
                .unwrap();
            let map = loader::BorrowedMap::new(fd).unwrap();
            map.shape(&[2], 4, 64).unwrap();
            let mut value = [0u8; 64];
            map.lookup(&0u32.to_ne_bytes(), &mut value).unwrap();
            u64::from_ne_bytes(value[32..40].try_into().unwrap())
        };
        let mut loss_cells = [0u64; 8];
        {
            let fd = session
                .source_owner
                .as_ref()
                .unwrap()
                .owned_map("PRODUCER_LOSS")
                .unwrap();
            let map = loader::BorrowedMap::new(fd).unwrap();
            map.shape(&[6], 4, 8).unwrap();
            for (cell, total) in loss_cells.iter_mut().enumerate() {
                let mut values = vec![0u8; 8 * cpus];
                map.lookup(&(cell as u32).to_ne_bytes(), &mut values)
                    .unwrap();
                for cpu in 0..cpus {
                    *total += u64::from_ne_bytes(values[cpu * 8..cpu * 8 + 8].try_into().unwrap());
                }
            }
        }
        eprintln!(
            "u5: typed={typed_sites} counter_links={counter_links} sample_sites={} sample_calls={sample_calls} joined_sites={joined_sites} joined_calls={joined_calls} definite={} unresolved={} withheld={} next_id={next_producer_id} loss={loss_cells:?}",
            sample.sites.len(),
            finalized.definite().len(),
            finalized.unresolved_calls(),
            finalized.withheld_uncertain(),
        );
        let mut staged_roles: Vec<u32> = records.iter().map(|(_, record)| record.role_id).collect();
        staged_roles.sort_unstable();
        eprintln!("u5 staged_roles={staged_roles:?}");
        assert_eq!(
            staged_roles,
            vec![
                5, 130, 131, 136, 137, 142, 143, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155,
                161, 258, 258, 258, 258, 258, 258, 258, 258, 258, 274, 274, 274, 274, 274, 274,
                274, 274, 290, 290, 290, 290, 290, 290, 290, 290, 304, 304, 304, 304, 304, 304,
                304, 304, 305, 305, 305, 305, 305, 305, 305, 305, 306, 306, 306, 306, 306, 306,
                306, 306,
            ],
            "17 first-slice + query + 49 copied, every one admitted"
        );
        assert_eq!(typed_sites, 67, "17 first-slice + query + 49 copied");
        assert_eq!(counter_links, 1, "one multi-link batches the 24 sites");
        assert_eq!(sample.sites.len(), 24, "every operational site sampled");
        assert_eq!(sample_calls, 3, "HMAC init + update + final fire");
        assert_eq!(joined_sites, 24, "every sample joins an admitted site");
        assert_eq!(joined_calls, 3, "the three operational hits join");
        // POSITIVE (U146 §27): 146 fires at its derived trampoline
        // (four executions, one per getter call site), the getter
        // observation lands exactly once on the committing 147
        // parent, the owner commits, and the three joined operational
        // hits attribute into definite partitions next to the loss
        // cells. Conservation: 3 known + 3 loss-bound foreign − 3
        // assigned = 3 unresolved.
        assert_eq!(
            finalized.definite().len(),
            3,
            "positive: one partition per joined operational hit"
        );
        assert_eq!(
            finalized.unresolved_calls(),
            3,
            "the 3 loss-bound foreign calls; every joined hit attributed"
        );
        assert_eq!(finalized.withheld_uncertain(), 0);
        assert_eq!(
            next_producer_id, 72,
            "the 57-mint U5K baseline plus 4 getter occurrences plus 7 owner-commit IDs plus 3 operational segments"
        );
        assert_eq!(
            loss_cells,
            [0, 0, 1, 2, 0, 0, 0, 0],
            "the op-1 frame miss plus the two teardown poisons; zero key-collision refusals"
        );
        drop(finalized);
        drop(sample);
        let close = session.close_source_explicit().expect("source close");
        assert!(close.cut_confirmed, "close must confirm the cut");
        assert!(close.first_error.is_none());
        assert!(!close.order_refused, "the completed order must not refuse");
        drop(session);
        drop(gate);
        drop(child);
        drop(receipts);
        drop(lease);
        assert_eq!(
            source_native_fd_targets(),
            baseline,
            "the full real-binary flow must release every fd"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
    /// U5-unblock native: typed role 161 fires on real libcrypto.
    /// Direct-exec ordinary unmodified `openssl mac` (the P4 lane)
    /// through the §12.3 session shape with a shared counter at the
    /// staged 161 site only. Asserts 161 stages co-attached with the
    /// legacy query API at the forwarder-derived trampoline (not the
    /// dead export stub) and that the site executes during the
    /// workload, with the typed query pair observing it (producer IDs
    /// advance past the query-less baseline).
    ///
    /// ```sh
    /// OSSL_PROVIDER_OBSERVATION_TEST_BPF=<provider object> \
    /// OSSLSCOPE_FOCUSED_COUNT_OBJECT=<count object> \
    /// sudo -n <lib test binary> \
    ///     typed_query_role_fires_on_real_libcrypto --test-threads=1
    /// ```
    #[test]
    #[ignore = "U5-unblock 161 native (sudo, pinned BPF objects)"]
    fn typed_query_role_fires_on_real_libcrypto() {
        use crate::capture::ClockPort as _;
        let dir = std::env::temp_dir().join(format!(
            "osslscope-u5u-native161-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("abc.txt"), b"abc").unwrap();
        let argv = u5_openssl_mac_argv(&dir);
        let (plan, pass1_digest) = u5_pass1_plan_from_live_queries(&argv, &dir);
        assert_eq!(pass1_digest, U5_MAC_DIGEST);
        assert!(!plan.sites.is_empty(), "161 stages only on a live plan");
        let baseline = source_native_fd_targets();
        let stdout_path = dir.join("out2.txt");
        std::fs::write(&stdout_path, b"").unwrap();
        let mut child = crate::target::OwnedTarget::spawn_stopped(
            &argv,
            crate::target::WorkloadDest::File(stdout_path.clone()),
        )
        .unwrap();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let mut budget = ObservationBudget::default();
        let startup = crate::startup_objects::prepare_owned_startup(
            &child,
            &argv,
            &mut budget,
            Instant::now() + Duration::from_secs(120),
            &cancel,
            Some(&plan),
        )
        .unwrap();
        assert_eq!(
            startup.apis.len(),
            62,
            "pass-2 rescan keeps 62 legacy sites (38 + 24 additive)"
        );
        assert_eq!(
            startup.typed.len(),
            67,
            "17 first-slice + query + 49 copied stage"
        );
        let crate::startup_objects::PreExecSites {
            apis,
            typed,
            candidates,
            ..
        } = startup;
        drop(candidates);
        let object =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        let count_object =
            std::fs::read(std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT").unwrap()).unwrap();
        budget.state(crate::writer_gate::RESERVATION_BYTES).unwrap();
        let pool = budget.memory.clone().unwrap_or_else(|| {
            crate::observation_memory::MemoryPool::new(budget.limits.max_state_bytes)
        });
        let gate = crate::writer_gate::WriterGate::create(&pool).unwrap();
        let mut session = ProviderSession::open_gated(budget, &object, gate.clone()).unwrap();
        session
            .prearm_startup(
                apis,
                Instant::now() + Duration::from_secs(30),
                &cancel,
                PrearmLinks::Reserve,
            )
            .unwrap();
        let pid = child.pid();
        assert_eq!(session.startup[&pid].len(), 62);
        let legacy_query_offset = session.startup[&pid]
            .iter()
            .find(|attachment| attachment.api == 8)
            .unwrap()
            .site
            .file_offset();
        let mut fds = Vec::new();
        let mut triples = Vec::new();
        for attachment in &session.startup[&pid] {
            let fd = attachment
                .site
                .attachment_fd()
                .try_clone_to_owned()
                .unwrap();
            triples.push((
                std::path::PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd())),
                attachment.site.file_offset(),
                pid,
            ));
            fds.push(fd);
        }
        let lease = super::source_owner::SourceAcquisitionLease::Enabled(
            super::source_owner::NativeSourceParams::for_test_multi(triples),
        );
        session
            .prepare_typed_startup(
                typed,
                Instant::now() + Duration::from_secs(60),
                &cancel,
                &lease,
            )
            .unwrap();
        let start_ns = crate::capture::LiveClock.checked_monotonic_ns().unwrap();
        let deadline_ns = start_ns + 15_000_000_000;
        let borrowed = session.borrowed_producer_maps().expect("producer maps");
        let mut counter = crate::focused_count::FocusedCounter::open_gated_shared(
            &count_object,
            child.pid(),
            crate::focused_capture::observer_namespace().unwrap(),
            crate::focused_count::CountLimits {
                window: crate::evidence::CountAdmissionWindow {
                    start_ns,
                    deadline_ns,
                },
                ..Default::default()
            },
            gate.clone(),
            &borrowed,
        )
        .unwrap();
        gate.open().unwrap();
        let receipts = session
            .acquire_source_after_open(&lease, Instant::now() + Duration::from_secs(60), &cancel)
            .unwrap_or_else(|gap| {
                panic!(
                    "full-62 acquire failed: {gap:?} owner: {:?}",
                    session.source_error()
                )
            });
        assert_eq!(receipts.attachments.len(), 62, "every claim acquires");
        drop(fds);
        let typed_161: Vec<u64> = session
            .typed_site_records()
            .values()
            .filter(|record| record.role_id == 161)
            .map(|record| record.offset)
            .collect();
        assert_eq!(
            typed_161.len(),
            1,
            "exactly one 161 site stages from the single libcrypto"
        );
        eprintln!(
            "u5u native161 legacy8={legacy_query_offset} typed161={}",
            typed_161[0]
        );
        assert_eq!(
            typed_161[0], legacy_query_offset,
            "161 stages co-attached with legacy query at the derived trampoline"
        );
        let mut candidates = Vec::new();
        for staged in &session.typed_startup {
            if staged.role().id() != 161 {
                continue;
            }
            let site = staged.site().clone();
            let starttime = site.starttime();
            let record = super::wire::contract::Record {
                pid: child.pid(),
                tid: child.pid(),
                generation: site.generation(),
                ..super::wire::contract::Record::default()
            };
            candidates.push(crate::focused_count::CountCandidate::Learned(
                VerifiedSiteCandidate {
                    site,
                    pid: child.pid(),
                    starttime,
                    generation: record.generation,
                    advertisers: Vec::new(),
                    operation: super::schema::Operation::Mac,
                    numeric_operation: 0,
                    dynamic_algorithm: super::static_tables::DynamicAlgorithmId::observed(
                        session.typed_startup[0].site().object_hash(),
                        starttime,
                        &record,
                    ),
                    observed_ns: start_ns,
                    algorithm: super::schema::AlgorithmId::try_from(u16::MAX).unwrap(),
                    alias_quality: super::schema::AliasQuality::default(),
                    function: super::schema::FunctionIdentity::new(
                        super::schema::Operation::Mac,
                        0,
                    )
                    .unwrap(),
                },
            ));
        }
        assert_eq!(candidates.len(), 1, "the counter watches the 161 site only");
        counter
            .attach_candidates_pinned(
                candidates,
                start_ns,
                Instant::now() + Duration::from_secs(15),
                &cancel,
                session.typed_pins(),
            )
            .unwrap();
        assert_eq!(counter.active_link_count(), 1, "one link on the 161 site");
        child.release().unwrap();
        let until = Instant::now() + Duration::from_secs(30);
        while child.peek_exit().unwrap().is_none() {
            assert!(Instant::now() < until, "workload never exited");
            std::thread::yield_now();
        }
        assert_eq!(child.poll_exit().unwrap(), Some(0), "workload must exit 0");
        child.finish_observation().unwrap();
        let digest = std::fs::read_to_string(&stdout_path).unwrap();
        assert_eq!(
            digest.trim().to_ascii_uppercase(),
            U5_MAC_DIGEST,
            "observed digest must verify"
        );
        session
            .note_source_exec(&lease, child.pid(), receipts.domain.planned)
            .unwrap();
        session.finalize_until(Instant::now() + Duration::from_secs(10));
        let sample = counter.close(Instant::now() + Duration::from_secs(10));
        assert_eq!(sample.sites.len(), 1, "only the 161 site sampled");
        eprintln!(
            "u5u native161 offset={} calls={}",
            sample.sites[0].site.offset, sample.sites[0].calls
        );
        assert_eq!(
            sample.sites[0].site.offset, typed_161[0],
            "the sampled site is the staged 161 site"
        );
        assert_eq!(
            sample.sites[0].calls, 2,
            "the trampoline executes for the op-3 MAC query and the op-1 query"
        );
        let next_producer_id = {
            let fd = session
                .source_owner
                .as_ref()
                .unwrap()
                .owned_map("ATTRIB_CONTROL")
                .unwrap();
            let map = loader::BorrowedMap::new(fd).unwrap();
            map.shape(&[2], 4, 64).unwrap();
            let mut value = [0u8; 64];
            map.lookup(&0u32.to_ne_bytes(), &mut value).unwrap();
            u64::from_ne_bytes(value[32..40].try_into().unwrap())
        };
        eprintln!("u5u native161 next_id={next_producer_id}");
        assert!(
            next_producer_id > 7,
            "the typed query pair observed the firing (past the query-less 6-mint baseline)"
        );
        drop(sample);
        let close = session.close_source_explicit().expect("source close");
        assert!(close.cut_confirmed, "close must confirm the cut");
        assert!(close.first_error.is_none());
        assert!(!close.order_refused, "the completed order must not refuse");
        drop(session);
        drop(gate);
        drop(child);
        drop(receipts);
        drop(lease);
        assert_eq!(
            source_native_fd_targets(),
            baseline,
            "the native must release every fd"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
    /// U146 native: typed role 146 fires on real libcrypto.
    /// Direct-exec ordinary unmodified `openssl mac` (the P4 lane)
    /// through the §12.3 session shape with a shared counter at the
    /// staged 146 site only. Asserts exactly one 146 stages, that the
    /// staged site executes during the workload (the raw export stub
    /// never executes — U5K gdb STUB 0 / TRAMP 4 — so firing proves
    /// own-resolve derivation to the trampoline), and that the typed
    /// pair observed the firing (producer IDs advance past the
    /// 146-less 57-mint baseline). Unlike 161 there is no legacy peer
    /// to co-attach against: no legacy API derives this symbol.
    ///
    /// ```sh
    /// OSSL_PROVIDER_OBSERVATION_TEST_BPF=<provider object> \
    /// OSSLSCOPE_FOCUSED_COUNT_OBJECT=<count object> \
    /// sudo -n <lib test binary> \
    ///     typed_getctx_role_fires_on_real_libcrypto --test-threads=1
    /// ```
    #[test]
    #[ignore = "U146 146 native (sudo, pinned BPF objects)"]
    fn typed_getctx_role_fires_on_real_libcrypto() {
        use crate::capture::ClockPort as _;
        let dir = std::env::temp_dir().join(format!(
            "osslscope-u146-native146-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("abc.txt"), b"abc").unwrap();
        let argv = u5_openssl_mac_argv(&dir);
        let (plan, pass1_digest) = u5_pass1_plan_from_live_queries(&argv, &dir);
        assert_eq!(pass1_digest, U5_MAC_DIGEST);
        assert!(!plan.sites.is_empty(), "146 stages only on a live plan");
        let baseline = source_native_fd_targets();
        let stdout_path = dir.join("out2.txt");
        std::fs::write(&stdout_path, b"").unwrap();
        let mut child = crate::target::OwnedTarget::spawn_stopped(
            &argv,
            crate::target::WorkloadDest::File(stdout_path.clone()),
        )
        .unwrap();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let mut budget = ObservationBudget::default();
        let startup = crate::startup_objects::prepare_owned_startup(
            &child,
            &argv,
            &mut budget,
            Instant::now() + Duration::from_secs(120),
            &cancel,
            Some(&plan),
        )
        .unwrap();
        assert_eq!(
            startup.apis.len(),
            62,
            "pass-2 rescan keeps 62 legacy sites (38 + 24 additive)"
        );
        assert_eq!(
            startup.typed.len(),
            67,
            "17 first-slice + query + 49 copied stage"
        );
        let crate::startup_objects::PreExecSites {
            apis,
            typed,
            candidates,
            ..
        } = startup;
        drop(candidates);
        let object =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        let count_object =
            std::fs::read(std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT").unwrap()).unwrap();
        budget.state(crate::writer_gate::RESERVATION_BYTES).unwrap();
        let pool = budget.memory.clone().unwrap_or_else(|| {
            crate::observation_memory::MemoryPool::new(budget.limits.max_state_bytes)
        });
        let gate = crate::writer_gate::WriterGate::create(&pool).unwrap();
        let mut session = ProviderSession::open_gated(budget, &object, gate.clone()).unwrap();
        session
            .prearm_startup(
                apis,
                Instant::now() + Duration::from_secs(30),
                &cancel,
                PrearmLinks::Reserve,
            )
            .unwrap();
        let pid = child.pid();
        assert_eq!(session.startup[&pid].len(), 62);
        let mut fds = Vec::new();
        let mut triples = Vec::new();
        for attachment in &session.startup[&pid] {
            let fd = attachment
                .site
                .attachment_fd()
                .try_clone_to_owned()
                .unwrap();
            triples.push((
                std::path::PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd())),
                attachment.site.file_offset(),
                pid,
            ));
            fds.push(fd);
        }
        let lease = super::source_owner::SourceAcquisitionLease::Enabled(
            super::source_owner::NativeSourceParams::for_test_multi(triples),
        );
        session
            .prepare_typed_startup(
                typed,
                Instant::now() + Duration::from_secs(60),
                &cancel,
                &lease,
            )
            .unwrap();
        let start_ns = crate::capture::LiveClock.checked_monotonic_ns().unwrap();
        let deadline_ns = start_ns + 15_000_000_000;
        let borrowed = session.borrowed_producer_maps().expect("producer maps");
        let mut counter = crate::focused_count::FocusedCounter::open_gated_shared(
            &count_object,
            child.pid(),
            crate::focused_capture::observer_namespace().unwrap(),
            crate::focused_count::CountLimits {
                window: crate::evidence::CountAdmissionWindow {
                    start_ns,
                    deadline_ns,
                },
                ..Default::default()
            },
            gate.clone(),
            &borrowed,
        )
        .unwrap();
        gate.open().unwrap();
        let receipts = session
            .acquire_source_after_open(&lease, Instant::now() + Duration::from_secs(60), &cancel)
            .unwrap_or_else(|gap| {
                panic!(
                    "full-62 acquire failed: {gap:?} owner: {:?}",
                    session.source_error()
                )
            });
        assert_eq!(receipts.attachments.len(), 62, "every claim acquires");
        drop(fds);
        let typed_146: Vec<u64> = session
            .typed_site_records()
            .values()
            .filter(|record| record.role_id == 146)
            .map(|record| record.offset)
            .collect();
        assert_eq!(
            typed_146.len(),
            1,
            "exactly one 146 site stages from the single libcrypto"
        );
        eprintln!("u146 native146 staged146={}", typed_146[0]);
        let mut candidates = Vec::new();
        for staged in &session.typed_startup {
            if staged.role().id() != 146 {
                continue;
            }
            let site = staged.site().clone();
            let starttime = site.starttime();
            let record = super::wire::contract::Record {
                pid: child.pid(),
                tid: child.pid(),
                generation: site.generation(),
                ..super::wire::contract::Record::default()
            };
            candidates.push(crate::focused_count::CountCandidate::Learned(
                VerifiedSiteCandidate {
                    site,
                    pid: child.pid(),
                    starttime,
                    generation: record.generation,
                    advertisers: Vec::new(),
                    operation: super::schema::Operation::Mac,
                    numeric_operation: 0,
                    dynamic_algorithm: super::static_tables::DynamicAlgorithmId::observed(
                        session.typed_startup[0].site().object_hash(),
                        starttime,
                        &record,
                    ),
                    observed_ns: start_ns,
                    algorithm: super::schema::AlgorithmId::try_from(u16::MAX).unwrap(),
                    alias_quality: super::schema::AliasQuality::default(),
                    function: super::schema::FunctionIdentity::new(
                        super::schema::Operation::Mac,
                        0,
                    )
                    .unwrap(),
                },
            ));
        }
        assert_eq!(candidates.len(), 1, "the counter watches the 146 site only");
        counter
            .attach_candidates_pinned(
                candidates,
                start_ns,
                Instant::now() + Duration::from_secs(15),
                &cancel,
                session.typed_pins(),
            )
            .unwrap();
        assert_eq!(counter.active_link_count(), 1, "one link on the 146 site");
        child.release().unwrap();
        let until = Instant::now() + Duration::from_secs(30);
        while child.peek_exit().unwrap().is_none() {
            assert!(Instant::now() < until, "workload never exited");
            std::thread::yield_now();
        }
        assert_eq!(child.poll_exit().unwrap(), Some(0), "workload must exit 0");
        child.finish_observation().unwrap();
        let digest = std::fs::read_to_string(&stdout_path).unwrap();
        assert_eq!(
            digest.trim().to_ascii_uppercase(),
            U5_MAC_DIGEST,
            "observed digest must verify"
        );
        session
            .note_source_exec(&lease, child.pid(), receipts.domain.planned)
            .unwrap();
        session.finalize_until(Instant::now() + Duration::from_secs(10));
        let sample = counter.close(Instant::now() + Duration::from_secs(10));
        assert_eq!(sample.sites.len(), 1, "only the 146 site sampled");
        eprintln!(
            "u146 native146 offset={} calls={}",
            sample.sites[0].site.offset, sample.sites[0].calls
        );
        assert_eq!(
            sample.sites[0].site.offset, typed_146[0],
            "the sampled site is the staged 146 site"
        );
        assert_eq!(
            sample.sites[0].calls, 4,
            "one MAC-constructor getter, one settable getter, two digest-internal getters"
        );
        let next_producer_id = {
            let fd = session
                .source_owner
                .as_ref()
                .unwrap()
                .owned_map("ATTRIB_CONTROL")
                .unwrap();
            let map = loader::BorrowedMap::new(fd).unwrap();
            map.shape(&[2], 4, 64).unwrap();
            let mut value = [0u8; 64];
            map.lookup(&0u32.to_ne_bytes(), &mut value).unwrap();
            u64::from_ne_bytes(value[32..40].try_into().unwrap())
        };
        eprintln!("u146 native146 next_id={next_producer_id}");
        assert!(
            next_producer_id > 58,
            "the typed pair observed the firing (past the 146-less 57-mint baseline)"
        );
        drop(sample);
        let close = session.close_source_explicit().expect("source close");
        assert!(close.cut_confirmed, "close must confirm the cut");
        assert!(close.first_error.is_none());
        assert!(!close.order_refused, "the completed order must not refuse");
        drop(session);
        drop(gate);
        drop(child);
        drop(receipts);
        drop(lease);
        assert_eq!(
            source_native_fd_targets(),
            baseline,
            "the native must release every fd"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
    /// Families-stage KDF oracle: stock `openssl kdf` HKDF over RFC
    /// 5869 Test Case 1 (SHA-256, 22-octet 0x0b key, 13-octet salt,
    /// 10-octet info, L=42). Colon-stripped uppercase stdout. Both the
    /// host 3.5.5 CLI and the private 3.0.22/4.0.3 builds emit this
    /// exact output unobserved; the probe asserts the observed run and
    /// a fresh unobserved re-run agree with it independently.
    const FAM_KDF_OKM: &str =
        "3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56ECC4C5BF34007208D5B887185865";
    /// Families-stage openssl argv[0]: `OSSLSCOPE_TEST_OPENSSL` selects
    /// the library lane (host 3.5.5 default; private 3.0.22/4.0.3 CLI
    /// paths with a matching `LD_LIBRARY_PATH` for those lanes). The
    /// test binary links no libcrypto, so the lane env only affects
    /// the spawned workload. Every probe prints the resolved binary
    /// plus a deterministic FNV-1a/64 for run provenance.
    fn fam_openssl_argv0() -> String {
        std::env::var_os("OSSLSCOPE_TEST_OPENSSL")
            .map(|path| {
                path.into_string()
                    .expect("OSSLSCOPE_TEST_OPENSSL must be a UTF-8 executable path")
            })
            .unwrap_or_else(|| "/usr/bin/openssl".into())
    }
    /// Families-stage stock KDF argv (P4 lane shape): ordinary
    /// unmodified HKDF, no added getter/query calls.
    fn fam_openssl_kdf_argv(openssl: &str) -> Vec<String> {
        vec![
            openssl.to_string(),
            "kdf".to_string(),
            "-keylen".to_string(),
            "42".to_string(),
            "-kdfopt".to_string(),
            "digest:SHA256".to_string(),
            "-kdfopt".to_string(),
            format!("hexkey:{}", "0b".repeat(22)),
            "-kdfopt".to_string(),
            "hexsalt:000102030405060708090a0b0c".to_string(),
            "-kdfopt".to_string(),
            "hexinfo:f0f1f2f3f4f5f6f7f8f9".to_string(),
            "HKDF".to_string(),
        ]
    }
    /// Families-stage stock PBKDF2 argv (the Task-3 migration
    /// post-leg): ordinary unmodified PBKDF2-HMAC-SHA256, password
    /// `password`, salt bytes 0x00..=0x0c, 4096 iterations, 42
    /// output bytes. Oracle is [`FAM_PBKDF2_OKM`] (agrees with
    /// Python `hashlib.pbkdf2_hmac`, an independent
    /// implementation).
    fn fam_openssl_pbkdf2_argv(openssl: &str) -> Vec<String> {
        vec![
            openssl.to_string(),
            "kdf".to_string(),
            "-keylen".to_string(),
            "42".to_string(),
            "-kdfopt".to_string(),
            "digest:SHA256".to_string(),
            "-kdfopt".to_string(),
            "pass:password".to_string(),
            "-kdfopt".to_string(),
            "hexsalt:000102030405060708090a0b0c".to_string(),
            "-kdfopt".to_string(),
            "iter:4096".to_string(),
            "PBKDF2".to_string(),
        ]
    }
    /// PBKDF2-HMAC-SHA256(`password`, 0x00..=0x0c, 4096, 42):
    /// stock-CLI output, verified byte-identical against Python
    /// `hashlib.pbkdf2_hmac` (independent implementation) before
    /// the Task-3 migration test pinned it.
    const FAM_PBKDF2_OKM: &str =
        "D8A20D7F14C762FF946EB9F73901B2DFD51AEB70CF471ECA573DC7842A563522DB75E1F374020548B681";
    /// Families-stage stock MAC argv (U5 §13.1 shape, lane-aware
    /// argv[0]): ordinary unmodified HMAC-SHA256 over the `abc.txt`
    /// input in `dir` (the caller creates it before pass 1 spawns
    /// the workload). Oracle is [`U5_MAC_DIGEST`].
    fn fam_openssl_mac_argv(openssl: &str, dir: &std::path::Path) -> Vec<String> {
        vec![
            openssl.to_string(),
            "mac".to_string(),
            "-digest".to_string(),
            "SHA256".to_string(),
            "-macopt".to_string(),
            format!("hexkey:{}", "0b".repeat(20)),
            "-in".to_string(),
            dir.join("abc.txt").to_string_lossy().into_owned(),
            "HMAC".to_string(),
        ]
    }
    /// Families-stage canary needles: the KDF workload's input
    /// key material in the byte shapes that must never cross the
    /// observer boundary — the raw 22-octet 0x0b key and its exact
    /// `hexkey:` argv spelling. Public algorithm names ("HKDF",
    /// "HMAC", "SHA2-256") are expected in ring records and are NOT
    /// needles.
    fn fam_canary_needles() -> Vec<Vec<u8>> {
        vec![
            vec![0x0bu8; 22],
            format!("hexkey:{}", "0b".repeat(22)).into_bytes(),
        ]
    }
    /// Families-stage MAC canary needles: the MAC workload's input
    /// key material — the raw 20-octet 0x0b key and its exact
    /// `hexkey:` argv spelling. Pass 1 scans the union of all
    /// stock workloads' needles on every lane (strictly stronger
    /// than any one alone; distinct key shapes cannot
    /// cross-match an honest ring).
    fn fam_canary_needles_mac() -> Vec<Vec<u8>> {
        vec![
            vec![0x0bu8; 20],
            format!("hexkey:{}", "0b".repeat(20)).into_bytes(),
        ]
    }
    /// Families-stage PBKDF2 canary needles: the migration
    /// post-leg password in its raw and `pass:` argv shapes. The
    /// salt is public (never a needle); the password is key
    /// material and must never cross the observer boundary.
    fn fam_canary_needles_pbkdf2() -> Vec<Vec<u8>> {
        vec![b"password".to_vec(), b"pass:password".to_vec()]
    }
    /// Families-stage canary scan: returns the index of the first
    /// needle found in `haystack`, or `None` when clean. Every
    /// families pass-1 run scans its raw ring bytes (the negative
    /// leg); the unit tests below pin the positive leg (a planted
    /// needle is caught) and the negative leg (clean input passes).
    fn fam_canary_scan(haystack: &[u8], needles: &[Vec<u8>]) -> Option<usize> {
        needles.iter().position(|needle| {
            !needle.is_empty()
                && haystack
                    .windows(needle.len())
                    .any(|window| window == needle.as_slice())
        })
    }
    #[test]
    fn fam_canary_scan_finds_planted_key_material() {
        let needles = fam_canary_needles();
        assert_eq!(needles.len(), 2);
        // Positive leg: each needle planted in noise is caught.
        for (index, needle) in needles.iter().enumerate() {
            let mut haystack = vec![0xAAu8; 64];
            haystack.extend_from_slice(needle);
            haystack.extend_from_slice(&[0x55u8; 64]);
            assert_eq!(
                fam_canary_scan(&haystack, &needles),
                Some(index),
                "planted needle {index} must be caught"
            );
        }
        // Public algorithm names are not secrets: never flagged.
        let names = b"HKDF\0HMAC\0SHA2-256\0query-result-ok";
        assert_eq!(fam_canary_scan(names, &needles), None);
        // Empty haystack and empty needle set stay clean.
        assert_eq!(fam_canary_scan(&[], &needles), None);
        assert_eq!(fam_canary_scan(names, &[]), None);
    }
    /// Families-stage pass 1: legacy-only observation of a stock
    /// workload drained for live query observations, exact-matched to
    /// the retained arrays into a copied-role staging plan. Mirrors
    /// `u5_pass1_plan_from_live_queries` (which stays verbatim) but
    /// asserts lane-independent invariants only — exact discovery
    /// counts differ per libcrypto build and are printed, not pinned.
    /// Every run also scans its raw ring bytes for key material (the
    /// canary negative leg). Returns the plan plus the observed
    /// workload stdout digest.
    fn fam_pass1_plan_from_live_queries(
        argv: &[String],
        dir: &std::path::Path,
        tag: &str,
        oracle: &str,
        expected_op: u32,
    ) -> (super::copied_plan::CopiedPlan, String) {
        let stdout_path = dir.join(format!("{tag}-out1.txt"));
        std::fs::write(&stdout_path, b"").unwrap();
        let mut child = crate::target::OwnedTarget::spawn_stopped(
            argv,
            crate::target::WorkloadDest::File(stdout_path.clone()),
        )
        .unwrap();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let mut budget = ObservationBudget::default();
        let startup = crate::startup_objects::prepare_owned_startup(
            &child,
            argv,
            &mut budget,
            Instant::now() + Duration::from_secs(120),
            &cancel,
            None,
        )
        .unwrap();
        eprintln!(
            "{tag} pass1 startup apis={} typed={} candidates={} gaps={:?} files={}",
            startup.apis.len(),
            startup.typed.len(),
            startup.candidates.len(),
            startup.gaps,
            startup.plan_arrays.len(),
        );
        assert!(
            !startup.apis.is_empty(),
            "{tag}: pass-1 discovery must stage legacy sites"
        );
        assert!(
            !startup.typed.is_empty(),
            "{tag}: pass-1 discovery must stage typed exports"
        );
        assert!(
            !startup.plan_arrays.is_empty(),
            "{tag}: pass-1 discovery must retain plan arrays"
        );
        let crate::startup_objects::PreExecSites {
            apis,
            typed,
            candidates,
            plan_arrays,
            ..
        } = startup;
        drop(typed);
        drop(candidates);
        let object =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        let fds_before = source_native_fd_targets();
        let mut session = ProviderSession::open(ObservationLimits::default(), &object).unwrap();
        session
            .prearm_startup(
                apis,
                Instant::now() + Duration::from_secs(30),
                &cancel,
                PrearmLinks::Create,
            )
            .unwrap();
        child.release().unwrap();
        let until = Instant::now() + Duration::from_secs(30);
        while child.peek_exit().unwrap().is_none() {
            assert!(
                Instant::now() < until,
                "{tag}: pass-1 workload never exited"
            );
            std::thread::yield_now();
        }
        assert_eq!(
            child.poll_exit().unwrap(),
            Some(0),
            "{tag}: pass-1 public oracle"
        );
        child.finish_observation().unwrap();
        let digest = std::fs::read_to_string(&stdout_path).unwrap();
        let digest = digest
            .trim()
            .replace([':', '\n', ' '], "")
            .to_ascii_uppercase();
        assert_eq!(
            digest, oracle,
            "{tag}: pass-1 observed workload output must verify"
        );
        let mut records = Vec::new();
        let mut decode_failures = 0usize;
        let mut ring_bytes = Vec::new();
        while let Some(bytes) = session.events.next() {
            ring_bytes.extend_from_slice(&bytes);
            match super::wire::decode_transport(&bytes) {
                Ok(transport) => records.push(transport.record()),
                Err(_) => decode_failures += 1,
            }
        }
        eprintln!(
            "{tag} pass1 records={} decode_failures={} ring_bytes={}",
            records.len(),
            decode_failures,
            ring_bytes.len(),
        );
        assert_eq!(decode_failures, 0, "{tag}: every ring record must validate");
        // Canary negative leg: no input key material in the raw ring
        // (union of all stock workloads' needles on every lane).
        let mut needles = fam_canary_needles();
        needles.extend(fam_canary_needles_mac());
        needles.extend(fam_canary_needles_pbkdf2());
        assert_eq!(
            fam_canary_scan(&ring_bytes, &needles),
            None,
            "{tag}: raw ring bytes must carry no key material"
        );
        eprintln!("{tag} pass1 canary=clean ring_bytes={}", ring_bytes.len());
        assert!(
            !records.is_empty(),
            "{tag}: pass-1 must observe ring records"
        );
        drop(session);
        drop(child);
        let after = source_native_fd_targets();
        let bpf = |fds: &[String]| {
            fds.iter()
                .filter(|fd| {
                    fd.contains("bpf-map") || fd.contains("bpf-prog") || fd.contains("bpf_link")
                })
                .count()
        };
        assert_eq!(
            bpf(&after),
            bpf(&fds_before),
            "{tag}: pass-1 BPF FDs must return"
        );
        let live = super::copied_plan::collect_live_queries(&records);
        eprintln!("{tag} pass1 live_queries={live:?}");
        assert!(
            !live.is_empty(),
            "{tag}: at least one live query must survive agreement"
        );
        assert!(
            live.iter()
                .all(|query| query.operation == 3 || query.operation == 4),
            "{tag}: live queries stay in the MAC/KDF first slice"
        );
        assert!(
            live.iter().any(|query| query.operation == expected_op),
            "{tag}: the workload must produce a live op-{expected_op} query"
        );
        let plan_budget = ObservationBudget::default();
        let plan = super::copied_plan::generate_plan(&plan_arrays, &live, &plan_budget).unwrap();
        let mut plan_roles: Vec<u32> = plan.sites.iter().map(|site| site.role_id).collect();
        plan_roles.sort_unstable();
        eprintln!("{tag} pass1 plan roles={plan_roles:?}");
        assert!(
            !plan.sites.is_empty(),
            "{tag}: the live queries must stage copied-role sites"
        );
        (plan, digest)
    }
    /// Families-stage KDF firemap: the full §12.3 session shape on the
    /// stock HKDF workload with a shared counter at EVERY staged typed
    /// site. Prints the per-role fire table (role, offset, calls) —
    /// the behavioral firing evidence for the KDF lane (131/137/143/
    /// 148/150/152/153, copied 259/275/291/307/308), the dup lane
    /// (151/152), the unload lane and role-5 re-verification (role 5),
    /// plus teardown (154/155) — and asserts the oracle, the staging
    /// census, and KDF fetch/constructor/operational firing.
    ///
    /// ```sh
    /// OSSL_PROVIDER_OBSERVATION_TEST_BPF=<provider object> \
    /// OSSLSCOPE_FOCUSED_COUNT_OBJECT=<count object> \
    /// [OSSLSCOPE_TEST_OPENSSL=<lane CLI> LD_LIBRARY_PATH=<lane lib>] \
    /// sudo -n <lib test binary> \
    ///     kdf_typed_roles_fire_on_stock_hkdf_workload --test-threads=1
    /// ```
    #[test]
    #[ignore = "families KDF firemap (sudo, pinned BPF objects)"]
    fn kdf_typed_roles_fire_on_stock_hkdf_workload() {
        use crate::capture::ClockPort as _;
        let ceiling: usize =
            crate::provider_observation::ObservationLimits::default().max_state_bytes;
        const TAG: &str = "fam-kdf";
        let openssl = fam_openssl_argv0();
        let cli_bytes = std::fs::read(&openssl).unwrap();
        // Deterministic FNV-1a/64 over the CLI bytes: lane provenance
        // without a new dependency (exact sha256 lives in the lane
        // receipts, not the observer).
        let mut h64: u64 = 0xcbf29ce484222325;
        for byte in &cli_bytes {
            h64 ^= *byte as u64;
            h64 = h64.wrapping_mul(0x100000001b3);
        }
        eprintln!(
            "{TAG} openssl={openssl} bytes={} fnv1a64={h64:016x}",
            cli_bytes.len(),
        );
        let dir = std::env::temp_dir().join(format!(
            "osslscope-fam-kdf-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let argv = fam_openssl_kdf_argv(&openssl);
        let (plan, pass1_digest) =
            fam_pass1_plan_from_live_queries(&argv, &dir, TAG, FAM_KDF_OKM, 4);
        assert_eq!(pass1_digest, FAM_KDF_OKM);
        let baseline = source_native_fd_targets();
        let stdout_path = dir.join("out2.txt");
        std::fs::write(&stdout_path, b"").unwrap();
        let mut child = crate::target::OwnedTarget::spawn_stopped(
            &argv,
            crate::target::WorkloadDest::File(stdout_path.clone()),
        )
        .unwrap();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let mut budget = ObservationBudget::default();
        let startup = crate::startup_objects::prepare_owned_startup(
            &child,
            &argv,
            &mut budget,
            Instant::now() + Duration::from_secs(120),
            &cancel,
            Some(&plan),
        )
        .unwrap();
        eprintln!(
            "{TAG} startup apis={} typed={} copied_skipped={}",
            startup.apis.len(),
            startup.typed.len(),
            startup.copied_skipped,
        );
        assert_eq!(
            startup.copied_skipped, 0,
            "{TAG}: pass-2 rescan agrees with the pass-1 plan on every site"
        );
        let spent_discovery = budget.state_spent_test();
        eprintln!("{TAG} spent after-discovery={spent_discovery}");
        assert!(
            spent_discovery < ceiling,
            "{TAG}: discovery must fit the ceiling"
        );
        let crate::startup_objects::PreExecSites {
            apis,
            typed,
            candidates,
            ..
        } = startup;
        let legacy_sites = apis.len();
        drop(candidates);
        let object =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        let count_object =
            std::fs::read(std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT").unwrap()).unwrap();
        budget.state(crate::writer_gate::RESERVATION_BYTES).unwrap();
        let pool = budget.memory.clone().unwrap_or_else(|| {
            crate::observation_memory::MemoryPool::new(budget.limits.max_state_bytes)
        });
        let gate = crate::writer_gate::WriterGate::create(&pool).unwrap();
        let mut session = ProviderSession::open_gated(budget, &object, gate.clone()).unwrap();
        session
            .prearm_startup(
                apis,
                Instant::now() + Duration::from_secs(30),
                &cancel,
                PrearmLinks::Reserve,
            )
            .unwrap();
        let pid = child.pid();
        assert_eq!(session.startup[&pid].len(), legacy_sites);
        let spent_prearm = session.budget.state_spent_test();
        eprintln!("{TAG} spent after-prearm={spent_prearm}");
        assert!(spent_prearm < ceiling, "{TAG}: prearm must fit the ceiling");
        let mut fds = Vec::new();
        let mut triples = Vec::new();
        for attachment in &session.startup[&pid] {
            let fd = attachment
                .site
                .attachment_fd()
                .try_clone_to_owned()
                .unwrap();
            triples.push((
                std::path::PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd())),
                attachment.site.file_offset(),
                pid,
            ));
            fds.push(fd);
        }
        let lease = super::source_owner::SourceAcquisitionLease::Enabled(
            super::source_owner::NativeSourceParams::for_test_multi(triples),
        );
        session
            .prepare_typed_startup(
                typed,
                Instant::now() + Duration::from_secs(60),
                &cancel,
                &lease,
            )
            .unwrap();
        let typed_sites = session.typed_startup.len();
        let spent_prepare = session.budget.state_spent_test();
        eprintln!("{TAG} spent after-prepare-typed={spent_prepare}");
        assert!(
            spent_prepare < ceiling,
            "{TAG}: typed prepare must fit the ceiling"
        );
        let start_ns = crate::capture::LiveClock.checked_monotonic_ns().unwrap();
        let deadline_ns = start_ns + 15_000_000_000;
        let borrowed = session.borrowed_producer_maps().expect("producer maps");
        let mut counter = crate::focused_count::FocusedCounter::open_gated_shared(
            &count_object,
            child.pid(),
            crate::focused_capture::observer_namespace().unwrap(),
            crate::focused_count::CountLimits {
                window: crate::evidence::CountAdmissionWindow {
                    start_ns,
                    deadline_ns,
                },
                ..Default::default()
            },
            gate.clone(),
            &borrowed,
        )
        .unwrap();
        gate.open().unwrap();
        let receipts = session
            .acquire_source_after_open(&lease, Instant::now() + Duration::from_secs(60), &cancel)
            .unwrap_or_else(|gap| {
                panic!(
                    "{TAG}: full-{legacy_sites} acquire failed: {gap:?} owner: {:?}",
                    session.source_error()
                )
            });
        let spent_acquire = session.budget.state_spent_test();
        eprintln!("{TAG} spent after-acquire={spent_acquire}");
        assert!(
            spent_acquire < ceiling,
            "{TAG}: full acquire must fit the ceiling"
        );
        assert_eq!(
            receipts.attachments.len(),
            legacy_sites,
            "{TAG}: every claim acquires"
        );
        assert_eq!(
            session.typed_site_records().len(),
            typed_sites,
            "{TAG}: every staged typed site must admit"
        );
        drop(fds);
        // Firemap: the counter watches every staged typed site.
        let mut staged_roles: Vec<u32> = session
            .typed_site_records()
            .values()
            .map(|record| record.role_id)
            .collect();
        staged_roles.sort_unstable();
        eprintln!("{TAG} staged_roles={staged_roles:?}");
        for role in [
            5u32, 130, 131, 136, 137, 142, 143, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155,
            161,
        ] {
            assert!(
                staged_roles.contains(&role),
                "{TAG}: first-slice role {role} must stage"
            );
        }
        let mut candidates = Vec::new();
        for staged in &session.typed_startup {
            let site = staged.site().clone();
            let starttime = site.starttime();
            let record = super::wire::contract::Record {
                pid: child.pid(),
                tid: child.pid(),
                generation: site.generation(),
                ..super::wire::contract::Record::default()
            };
            let operation = match staged.role().id() {
                131 | 137 | 143 | 148 | 150 | 152 | 153 | 259 | 275 | 291 | 307 | 308 => {
                    super::schema::Operation::Kdf
                }
                _ => super::schema::Operation::Mac,
            };
            candidates.push(crate::focused_count::CountCandidate::Learned(
                VerifiedSiteCandidate {
                    site,
                    pid: child.pid(),
                    starttime,
                    generation: record.generation,
                    advertisers: Vec::new(),
                    operation,
                    numeric_operation: 0,
                    dynamic_algorithm: super::static_tables::DynamicAlgorithmId::observed(
                        session.typed_startup[0].site().object_hash(),
                        starttime,
                        &record,
                    ),
                    observed_ns: start_ns,
                    algorithm: super::schema::AlgorithmId::try_from(u16::MAX).unwrap(),
                    alias_quality: super::schema::AliasQuality::default(),
                    function: super::schema::FunctionIdentity::new(operation, 0).unwrap(),
                },
            ));
        }
        assert_eq!(
            candidates.len(),
            typed_sites,
            "{TAG}: one counter site per staged typed site"
        );
        counter
            .attach_candidates_pinned(
                candidates,
                start_ns,
                Instant::now() + Duration::from_secs(15),
                &cancel,
                session.typed_pins(),
            )
            .unwrap();
        let counter_links = counter.active_link_count();
        child.release().unwrap();
        let until = Instant::now() + Duration::from_secs(30);
        while child.peek_exit().unwrap().is_none() {
            assert!(Instant::now() < until, "{TAG}: workload never exited");
            std::thread::yield_now();
        }
        assert_eq!(
            child.poll_exit().unwrap(),
            Some(0),
            "{TAG}: workload must exit 0"
        );
        child.finish_observation().unwrap();
        let digest = std::fs::read_to_string(&stdout_path).unwrap();
        let digest = digest
            .trim()
            .replace([':', '\n', ' '], "")
            .to_ascii_uppercase();
        assert_eq!(
            digest, FAM_KDF_OKM,
            "{TAG}: observed KDF output must verify"
        );
        let rerun = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .output()
            .unwrap();
        assert!(
            rerun.status.success(),
            "{TAG}: unobserved re-run must exit 0"
        );
        let rerun_digest = String::from_utf8_lossy(&rerun.stdout);
        let rerun_digest = rerun_digest
            .trim()
            .replace([':', '\n', ' '], "")
            .to_ascii_uppercase();
        assert_eq!(
            rerun_digest, FAM_KDF_OKM,
            "{TAG}: unobserved re-run must agree"
        );
        session
            .note_source_exec(&lease, child.pid(), receipts.domain.planned)
            .unwrap();
        session.finalize_until(Instant::now() + Duration::from_secs(10));
        let sample = counter.close(Instant::now() + Duration::from_secs(10));
        // Join samples to staged roles by (object, device, inode, offset).
        let admitted: Vec<(u32, crate::evidence::ObjectId, u64, u64, u64)> = session
            .typed_site_records()
            .values()
            .map(|record| {
                (
                    record.role_id,
                    record.object.clone(),
                    record.device,
                    record.inode,
                    record.offset,
                )
            })
            .collect();
        let mut fire: Vec<(u32, u64, u64)> = Vec::new();
        for execution in &sample.sites {
            let role = admitted
                .iter()
                .find(|(_, object, device, inode, offset)| {
                    *object == execution.site.object
                        && *device == execution.site.device
                        && *inode == execution.site.inode
                        && *offset == execution.site.offset
                })
                .map(|(role, ..)| *role)
                .unwrap_or(u32::MAX);
            fire.push((role, execution.site.offset, execution.calls));
        }
        fire.sort_unstable();
        for (role, offset, calls) in &fire {
            eprintln!("{TAG} fire role={role} offset={offset} calls={calls}");
        }
        eprintln!(
            "{TAG}: typed={typed_sites} counter_links={counter_links} sample_sites={}",
            sample.sites.len(),
        );
        assert_eq!(
            sample.sites.len(),
            typed_sites,
            "{TAG}: every staged site sampled"
        );
        let calls_of = |role: u32| -> u64 {
            fire.iter()
                .filter(|(r, ..)| *r == role)
                .map(|(_, _, calls)| *calls)
                .sum()
        };
        // RED-first behavioral pins: the KDF workload must fetch, bind
        // the provider, construct the context, and drive the provider's
        // derive entry through the staged sites.
        assert!(calls_of(131) > 0, "{TAG}: EVP_KDF_fetch (131) must fire");
        assert!(calls_of(148) > 0, "{TAG}: EVP_KDF_CTX_new (148) must fire");
        assert!(
            calls_of(143) > 0,
            "{TAG}: EVP_KDF_get0_provider (143) must fire"
        );
        assert!(
            calls_of(307) + calls_of(308) > 0,
            "{TAG}: KDF operational derive (307/308) must fire"
        );
        drop(sample);
        let close = session.close_source_explicit().expect("source close");
        assert!(close.cut_confirmed, "{TAG}: close must confirm the cut");
        assert!(close.first_error.is_none());
        assert!(
            !close.order_refused,
            "{TAG}: the completed order must not refuse"
        );
        drop(session);
        drop(gate);
        drop(child);
        drop(receipts);
        drop(lease);
        assert_eq!(
            source_native_fd_targets(),
            baseline,
            "{TAG}: the full flow must release every fd"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
    /// Families-stage closed-collect receipt: the public numbers a
    /// positive/refusal pin asserts. Mirrors the U5 tail (which stays
    /// verbatim); only families tests use this helper. Task 3 also
    /// retains the certified result itself (`finalized`), the joined
    /// physical sample (`sample`), and the real report window/pid —
    /// the actual producer records the v2.5 document flows project
    /// (never copies or re-derivations).
    struct FamAcquireReceipt {
        typed_sites: usize,
        counter_links: usize,
        sample_sites: usize,
        sample_calls: u64,
        joined_sites: usize,
        joined_calls: u64,
        definite: usize,
        unresolved: u64,
        withheld: u64,
        next_id: u64,
        loss: [u64; 8],
        staged_roles: Vec<u32>,
        count_roles: Vec<u32>,
        finalized: crate::attribution::FinalizedAttribution,
        sample: crate::focused_count::CountSample,
        pid: u32,
        window: crate::evidence::CaptureWindow,
    }
    /// Families-stage full acquire: pass-1 live-query plan, Enabled
    /// full-claim lease, typed admit+attach, shared counter at the
    /// given operational roles, common cut, closed collect. Asserts
    /// the workload oracle (observed + fresh re-run), ceiling fit at
    /// every phase, full admission, cut confirmation, and FD release;
    /// returns the receipt for the caller to pin. `operation` labels
    /// the counter candidates (observer-side nominal label, as in U5)
    /// and selects the pass-1 live-query op (MAC 3 / KDF 4 — the
    /// first slice only).
    fn fam_full_acquire(
        argv: &[String],
        dir: &std::path::Path,
        tag: &str,
        oracle: &str,
        wanted_roles: &[u32],
        operation: super::schema::Operation,
    ) -> FamAcquireReceipt {
        use crate::capture::ClockPort as _;
        let ceiling: usize =
            crate::provider_observation::ObservationLimits::default().max_state_bytes;
        let normalize = |text: &str| {
            text.trim()
                .replace([':', '\n', ' '], "")
                .to_ascii_uppercase()
        };
        let expected_op = match operation {
            super::schema::Operation::Mac => 3,
            super::schema::Operation::Kdf => 4,
            _ => panic!("{tag}: fam_full_acquire covers the MAC/KDF first slice only"),
        };
        let (plan, pass1_digest) =
            fam_pass1_plan_from_live_queries(argv, dir, tag, oracle, expected_op);
        assert_eq!(pass1_digest, oracle);
        let baseline = source_native_fd_targets();
        let stdout_path = dir.join("out2.txt");
        std::fs::write(&stdout_path, b"").unwrap();
        let mut child = crate::target::OwnedTarget::spawn_stopped(
            argv,
            crate::target::WorkloadDest::File(stdout_path.clone()),
        )
        .unwrap();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let mut budget = ObservationBudget::default();
        let startup = crate::startup_objects::prepare_owned_startup(
            &child,
            argv,
            &mut budget,
            Instant::now() + Duration::from_secs(120),
            &cancel,
            Some(&plan),
        )
        .unwrap();
        eprintln!(
            "{tag} startup apis={} typed={} copied_skipped={}",
            startup.apis.len(),
            startup.typed.len(),
            startup.copied_skipped,
        );
        assert_eq!(
            startup.copied_skipped, 0,
            "{tag}: pass-2 rescan agrees with the pass-1 plan on every site"
        );
        let spent_discovery = budget.state_spent_test();
        eprintln!("{tag} spent after-discovery={spent_discovery}");
        assert!(
            spent_discovery < ceiling,
            "{tag}: discovery must fit the ceiling"
        );
        let crate::startup_objects::PreExecSites {
            apis,
            typed,
            candidates,
            ..
        } = startup;
        let legacy_sites = apis.len();
        drop(candidates);
        let object =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        let count_object =
            std::fs::read(std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT").unwrap()).unwrap();
        budget.state(crate::writer_gate::RESERVATION_BYTES).unwrap();
        let pool = budget.memory.clone().unwrap_or_else(|| {
            crate::observation_memory::MemoryPool::new(budget.limits.max_state_bytes)
        });
        let gate = crate::writer_gate::WriterGate::create(&pool).unwrap();
        let mut session = ProviderSession::open_gated(budget, &object, gate.clone()).unwrap();
        session
            .prearm_startup(
                apis,
                Instant::now() + Duration::from_secs(30),
                &cancel,
                PrearmLinks::Reserve,
            )
            .unwrap();
        let pid = child.pid();
        assert_eq!(session.startup[&pid].len(), legacy_sites);
        let spent_prearm = session.budget.state_spent_test();
        eprintln!("{tag} spent after-prearm={spent_prearm}");
        assert!(spent_prearm < ceiling, "{tag}: prearm must fit the ceiling");
        let mut fds = Vec::new();
        let mut triples = Vec::new();
        for attachment in &session.startup[&pid] {
            let fd = attachment
                .site
                .attachment_fd()
                .try_clone_to_owned()
                .unwrap();
            triples.push((
                std::path::PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd())),
                attachment.site.file_offset(),
                pid,
            ));
            fds.push(fd);
        }
        let lease = super::source_owner::SourceAcquisitionLease::Enabled(
            super::source_owner::NativeSourceParams::for_test_multi(triples),
        );
        session
            .prepare_typed_startup(
                typed,
                Instant::now() + Duration::from_secs(60),
                &cancel,
                &lease,
            )
            .unwrap();
        let typed_sites = session.typed_startup.len();
        let spent_prepare = session.budget.state_spent_test();
        eprintln!("{tag} spent after-prepare-typed={spent_prepare}");
        assert!(
            spent_prepare < ceiling,
            "{tag}: typed prepare must fit the ceiling"
        );
        let start_ns = crate::capture::LiveClock.checked_monotonic_ns().unwrap();
        let deadline_ns = start_ns + 15_000_000_000;
        let borrowed = session.borrowed_producer_maps().expect("producer maps");
        let mut counter = crate::focused_count::FocusedCounter::open_gated_shared(
            &count_object,
            child.pid(),
            crate::focused_capture::observer_namespace().unwrap(),
            crate::focused_count::CountLimits {
                window: crate::evidence::CountAdmissionWindow {
                    start_ns,
                    deadline_ns,
                },
                ..Default::default()
            },
            gate.clone(),
            &borrowed,
        )
        .unwrap();
        gate.open().unwrap();
        let receipts = session
            .acquire_source_after_open(&lease, Instant::now() + Duration::from_secs(60), &cancel)
            .unwrap_or_else(|gap| {
                panic!(
                    "{tag}: full-{legacy_sites} acquire failed: {gap:?} owner: {:?}",
                    session.source_error()
                )
            });
        let spent_acquire = session.budget.state_spent_test();
        eprintln!("{tag} spent after-acquire={spent_acquire}");
        assert!(
            spent_acquire < ceiling,
            "{tag}: full acquire must fit the ceiling"
        );
        assert_eq!(
            receipts.attachments.len(),
            legacy_sites,
            "{tag}: every claim acquires"
        );
        assert_eq!(
            session.typed_site_records().len(),
            typed_sites,
            "{tag}: every staged typed site must admit"
        );
        drop(fds);
        let mut count_roles: Vec<u32> = session
            .typed_site_records()
            .values()
            .map(|record| record.role_id)
            .filter(|role| wanted_roles.contains(role))
            .collect();
        count_roles.sort_unstable();
        count_roles.dedup();
        eprintln!("{tag} count_roles={count_roles:?}");
        assert_eq!(
            count_roles, wanted_roles,
            "{tag}: the wanted operational roles stage"
        );
        let mut candidates = Vec::new();
        for staged in &session.typed_startup {
            if !count_roles.contains(&staged.role().id()) {
                continue;
            }
            let site = staged.site().clone();
            let starttime = site.starttime();
            let record = super::wire::contract::Record {
                pid: child.pid(),
                tid: child.pid(),
                generation: site.generation(),
                ..super::wire::contract::Record::default()
            };
            candidates.push(crate::focused_count::CountCandidate::Learned(
                VerifiedSiteCandidate {
                    site,
                    pid: child.pid(),
                    starttime,
                    generation: record.generation,
                    advertisers: Vec::new(),
                    operation,
                    numeric_operation: 0,
                    dynamic_algorithm: super::static_tables::DynamicAlgorithmId::observed(
                        session.typed_startup[0].site().object_hash(),
                        starttime,
                        &record,
                    ),
                    observed_ns: start_ns,
                    algorithm: super::schema::AlgorithmId::try_from(u16::MAX).unwrap(),
                    alias_quality: super::schema::AliasQuality::default(),
                    function: super::schema::FunctionIdentity::new(operation, 0).unwrap(),
                },
            ));
        }
        let staged_operational = session
            .typed_startup
            .iter()
            .filter(|staged| count_roles.contains(&staged.role().id()))
            .count();
        assert_eq!(
            candidates.len(),
            staged_operational,
            "{tag}: one counter site per staged operational site"
        );
        counter
            .attach_candidates_pinned(
                candidates,
                start_ns,
                Instant::now() + Duration::from_secs(15),
                &cancel,
                session.typed_pins(),
            )
            .unwrap();
        let counter_links = counter.active_link_count();
        child.release().unwrap();
        let until = Instant::now() + Duration::from_secs(30);
        while child.peek_exit().unwrap().is_none() {
            assert!(Instant::now() < until, "{tag}: workload never exited");
            std::thread::yield_now();
        }
        assert_eq!(
            child.poll_exit().unwrap(),
            Some(0),
            "{tag}: workload must exit 0"
        );
        child.finish_observation().unwrap();
        let digest = normalize(&std::fs::read_to_string(&stdout_path).unwrap());
        assert_eq!(digest, oracle, "{tag}: observed output must verify");
        let rerun = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .output()
            .unwrap();
        assert!(
            rerun.status.success(),
            "{tag}: unobserved re-run must exit 0"
        );
        let rerun_digest = normalize(&String::from_utf8_lossy(&rerun.stdout));
        assert_eq!(rerun_digest, oracle, "{tag}: unobserved re-run must agree");
        assert_eq!(digest, rerun_digest, "{tag}: observed and re-run agree");
        session
            .note_source_exec(&lease, child.pid(), receipts.domain.planned)
            .unwrap();
        session.finalize_until(Instant::now() + Duration::from_secs(10));
        let cpus = counter.cpus();
        let sample = counter.close(Instant::now() + Duration::from_secs(10));
        let records: Vec<(u64, TypedSiteRecord)> = session
            .typed_site_records()
            .iter()
            .map(|(cookie, record)| (*cookie, record.clone()))
            .collect();
        session
            .charge_attribution_final(
                8192usize
                    .checked_mul(104 + 24 * cpus)
                    .and_then(|n| n.checked_add(1024 * (16 + 64)))
                    .and_then(|n| n.checked_add(1024 * (24 + 56)))
                    .and_then(|n| n.checked_add(8 * 8 * cpus))
                    .and_then(|n| n.checked_add(64))
                    .unwrap(),
            )
            .unwrap();
        let spent_collect = session.budget.state_spent_test();
        eprintln!("{tag} spent after-collect-charge={spent_collect}");
        assert!(
            spent_collect < ceiling,
            "{tag}: collect charge must fit the ceiling"
        );
        let maps = session.attribution_maps().expect("attribution maps");
        let mut admitted = Vec::with_capacity(records.len());
        for (cookie, record) in &records {
            admitted.push(crate::attribution::AdmittedTypedSite {
                cookie: *cookie,
                site_id: std::num::NonZeroU64::new(record.site_id).unwrap(),
                role_id: record.role_id,
                object: record.object.clone(),
                device: record.device,
                inode: record.inode,
                offset: record.offset,
                object_id: record.object_id,
                source_epoch: record.source_epoch,
            });
        }
        let end_ns = crate::capture::LiveClock
            .checked_monotonic_ns()
            .unwrap()
            .min(deadline_ns);
        let admission = crate::evidence::CountAdmissionWindow {
            start_ns,
            deadline_ns,
        };
        let report_window = crate::evidence::CaptureWindow {
            requested_start_ns: start_ns,
            requested_end_ns: deadline_ns,
            effective_start_ns: start_ns,
            effective_end_ns: end_ns.max(start_ns),
            signal_cut: false,
            count_admission: Some(admission),
        };
        let finalized = crate::attribution::collect_closed_attribution(
            gate.owned_closed().expect("closed gate"),
            &gate,
            &maps,
            cpus,
            &sample,
            &admitted,
            admission,
            report_window,
        )
        .unwrap_or_else(|error| panic!("{tag}: closed collect failed: {error:?}"));
        let mut joined_sites = 0usize;
        let mut joined_calls = 0u64;
        for execution in &sample.sites {
            if admitted.iter().any(|site| {
                site.object == execution.site.object
                    && site.device == execution.site.device
                    && site.inode == execution.site.inode
                    && site.offset == execution.site.offset
            }) {
                joined_sites += 1;
                joined_calls += execution.calls;
            }
        }
        let sample_calls: u64 = sample.sites.iter().map(|site| site.calls).sum();
        let next_producer_id = {
            let fd = session
                .source_owner
                .as_ref()
                .unwrap()
                .owned_map("ATTRIB_CONTROL")
                .unwrap();
            let map = loader::BorrowedMap::new(fd).unwrap();
            map.shape(&[2], 4, 64).unwrap();
            let mut value = [0u8; 64];
            map.lookup(&0u32.to_ne_bytes(), &mut value).unwrap();
            u64::from_ne_bytes(value[32..40].try_into().unwrap())
        };
        let mut loss_cells = [0u64; 8];
        {
            let fd = session
                .source_owner
                .as_ref()
                .unwrap()
                .owned_map("PRODUCER_LOSS")
                .unwrap();
            let map = loader::BorrowedMap::new(fd).unwrap();
            map.shape(&[6], 4, 8).unwrap();
            for (cell, total) in loss_cells.iter_mut().enumerate() {
                let mut values = vec![0u8; 8 * cpus];
                map.lookup(&(cell as u32).to_ne_bytes(), &mut values)
                    .unwrap();
                for cpu in 0..cpus {
                    *total += u64::from_ne_bytes(values[cpu * 8..cpu * 8 + 8].try_into().unwrap());
                }
            }
        }
        eprintln!(
            "{tag}: typed={typed_sites} counter_links={counter_links} sample_sites={} sample_calls={sample_calls} joined_sites={joined_sites} joined_calls={joined_calls} definite={} unresolved={} withheld={} next_id={next_producer_id} loss={loss_cells:?}",
            sample.sites.len(),
            finalized.definite().len(),
            finalized.unresolved_calls(),
            finalized.withheld_uncertain(),
        );
        let mut staged_roles: Vec<u32> = records.iter().map(|(_, record)| record.role_id).collect();
        staged_roles.sort_unstable();
        eprintln!("{tag} staged_roles={staged_roles:?}");
        for execution in &sample.sites {
            if execution.calls == 0 {
                continue;
            }
            let role = admitted
                .iter()
                .find(|site| {
                    site.object == execution.site.object
                        && site.device == execution.site.device
                        && site.inode == execution.site.inode
                        && site.offset == execution.site.offset
                })
                .map(|site| site.role_id)
                .unwrap_or(u32::MAX);
            eprintln!(
                "{tag} hit role={role} offset={} calls={} first_ns={} last_ns={}",
                execution.site.offset, execution.calls, execution.first_ns, execution.last_ns,
            );
        }
        let receipt = FamAcquireReceipt {
            typed_sites,
            counter_links,
            sample_sites: sample.sites.len(),
            sample_calls,
            joined_sites,
            joined_calls,
            definite: finalized.definite().len(),
            unresolved: finalized.unresolved_calls(),
            withheld: finalized.withheld_uncertain(),
            next_id: next_producer_id,
            loss: loss_cells,
            staged_roles,
            count_roles,
            finalized,
            sample,
            pid,
            window: report_window,
        };
        let close = session.close_source_explicit().expect("source close");
        assert!(close.cut_confirmed, "{tag}: close must confirm the cut");
        assert!(close.first_error.is_none());
        assert!(
            !close.order_refused,
            "{tag}: the completed order must not refuse"
        );
        drop(session);
        drop(gate);
        drop(child);
        drop(receipts);
        drop(lease);
        assert_eq!(
            source_native_fd_targets(),
            baseline,
            "{tag}: the full flow must release every fd"
        );
        std::fs::remove_dir_all(dir).unwrap();
        receipt
    }
    /// Families-stage KDF positive pin (host 3.5.5 lane): the U5
    /// §12.3 shape on the stock HKDF workload with the counter at the
    /// KDF operational roles (307/308). The derive hit (307)
    /// attributes into one definite partition; the reset hit (308) is
    /// the free-path teardown reset — `kdf_hkdf_free` calls the
    /// dispatch RESET entry directly on 3.0/3.5 (HKDF provider source),
    /// after the operational interval — and correctly fails closed
    /// (definite=0 for it even alone, conservation holds either way).
    /// On 4.0.3 free bypasses the dispatch entry via `reset_ex`, so
    /// 308 stays dark there (firemap §28). Conservation: 2 known + 3
    /// loss-bound foreign − 1 assigned = 4 unresolved.
    ///
    /// ```sh
    /// OSSL_PROVIDER_OBSERVATION_TEST_BPF=<provider object> \
    /// OSSLSCOPE_FOCUSED_COUNT_OBJECT=<count object> \
    /// sudo -n <lib test binary> \
    ///     kdf_full_acquire_positive_on_stock_hkdf_workload --test-threads=1
    /// ```
    #[test]
    #[ignore = "families KDF positive (sudo, pinned BPF objects)"]
    fn kdf_full_acquire_positive_on_stock_hkdf_workload() {
        const TAG: &str = "fam-kdf-pos";
        let openssl = fam_openssl_argv0();
        assert_eq!(
            openssl, "/usr/bin/openssl",
            "the KDF positive pin is host-lane exact"
        );
        let dir = std::env::temp_dir().join(format!(
            "osslscope-fam-kdf-pos-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let argv = fam_openssl_kdf_argv(&openssl);
        let receipt = fam_full_acquire(
            &argv,
            &dir,
            TAG,
            FAM_KDF_OKM,
            &[307, 308],
            super::schema::Operation::Kdf,
        );
        assert_eq!(receipt.count_roles, vec![307, 308]);
        assert_eq!(
            receipt.typed_sites, 130,
            "17 first-slice + query + 49 MAC + 63 KDF"
        );
        assert_eq!(receipt.counter_links, 1);
        assert_eq!(receipt.sample_sites, 26, "14 derive + 12 reset staged");
        assert_eq!(receipt.sample_calls, 2, "KDF derive + free-path reset fire");
        assert_eq!(
            receipt.joined_sites, 26,
            "every sample joins an admitted site"
        );
        assert_eq!(receipt.joined_calls, 2, "both operational hits join");
        assert_eq!(
            receipt.definite, 1,
            "positive: the derive hit attributes; the teardown reset fails closed"
        );
        assert_eq!(
            receipt.unresolved, 4,
            "the teardown hit plus the 3 loss-bound foreign calls"
        );
        assert_eq!(receipt.withheld, 0);
        assert_eq!(receipt.next_id, 151);
        assert_eq!(
            receipt.loss,
            [0, 0, 1, 2, 0, 0, 0, 0],
            "same loss shape as U5 (frame miss + teardown poisons)"
        );
        let mut expected_roles = vec![
            5, 130, 131, 136, 137, 142, 143, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 161,
        ];
        expected_roles.extend(std::iter::repeat_n(258, 9));
        expected_roles.extend(std::iter::repeat_n(259, 14));
        expected_roles.extend(std::iter::repeat_n(274, 8));
        expected_roles.extend(std::iter::repeat_n(275, 12));
        expected_roles.extend(std::iter::repeat_n(290, 8));
        expected_roles.extend(std::iter::repeat_n(291, 11));
        expected_roles.extend(std::iter::repeat_n(304, 8));
        expected_roles.extend(std::iter::repeat_n(305, 8));
        expected_roles.extend(std::iter::repeat_n(306, 8));
        expected_roles.extend(std::iter::repeat_n(307, 14));
        expected_roles.extend(std::iter::repeat_n(308, 12));
        assert_eq!(
            receipt.staged_roles, expected_roles,
            "17 first-slice + query + 49 MAC + 63 KDF copied, every one admitted"
        );
    }
    /// Families-stage 3.0.22 KDF refusal pin: the §12.3 shape on the
    /// stock HKDF workload with the counter at 307/308. The 3.0
    /// constructors never call the public provider-context getter
    /// (role 146 dark, firemap §28; H1 source finding), so no owner
    /// can commit and the closed collect must fail closed with
    /// definite=0 — a completed order with zero manufactured
    /// attribution. Requires `OSSLSCOPE_TEST_OPENSSL` +
    /// `LD_LIBRARY_PATH` selecting the 3.0.22 lane.
    ///
    /// ```sh
    /// OSSL_PROVIDER_OBSERVATION_TEST_BPF=<provider object> \
    /// OSSLSCOPE_FOCUSED_COUNT_OBJECT=<count object> \
    /// OSSLSCOPE_TEST_OPENSSL=<3.0.22 CLI> LD_LIBRARY_PATH=<3.0.22 lib> \
    /// sudo -n <lib test binary> \
    ///     kdf_refuses_without_natural_getter_on_3022 --test-threads=1
    /// ```
    #[test]
    #[ignore = "families 3.0.22 KDF refusal (sudo, pinned BPF objects)"]
    fn kdf_refuses_without_natural_getter_on_3022() {
        const TAG: &str = "fam-kdf-30neg";
        let openssl = fam_openssl_argv0();
        assert_ne!(
            openssl, "/usr/bin/openssl",
            "the 3.0.22 refusal pin needs OSSLSCOPE_TEST_OPENSSL on the 3.0.22 lane"
        );
        let dir = std::env::temp_dir().join(format!(
            "osslscope-fam-kdf-30neg-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let argv = fam_openssl_kdf_argv(&openssl);
        let receipt = fam_full_acquire(
            &argv,
            &dir,
            TAG,
            FAM_KDF_OKM,
            &[307, 308],
            super::schema::Operation::Kdf,
        );
        assert_eq!(receipt.count_roles, vec![307, 308]);
        assert_eq!(
            receipt.typed_sites, 109,
            "17 first-slice + query + 91 copied"
        );
        assert_eq!(receipt.counter_links, 1);
        assert_eq!(receipt.sample_sites, 22, "12 derive + 10 reset staged");
        assert_eq!(receipt.sample_calls, 2, "derive + free-path reset fire");
        assert_eq!(
            receipt.joined_sites, 22,
            "every sample joins an admitted site"
        );
        assert_eq!(receipt.joined_calls, 2, "both operational hits join");
        assert_eq!(
            receipt.definite, 0,
            "refusal: no getter, no commit, no partition"
        );
        assert_eq!(
            receipt.unresolved, 5,
            "both joined hits plus the 3 loss-bound foreign calls"
        );
        assert_eq!(receipt.withheld, 0);
        assert_eq!(receipt.next_id, 107);
        assert_eq!(
            receipt.loss,
            [0, 0, 1, 2, 0, 0, 0, 0],
            "same loss shape as U5 (frame miss + teardown poisons)"
        );
    }
    /// Families-stage 4.0.3 KDF positive pin: the §12.3 shape on the
    /// stock HKDF workload with the counter at 307/308. The derive
    /// hit (307) attributes; the dispatch RESET entry (308) stays
    /// dark because 4.0.3 free bypasses it via `reset_ex` (firemap
    /// §28), so only one hit joins. Requires
    /// `OSSLSCOPE_TEST_OPENSSL` + `LD_LIBRARY_PATH` selecting the
    /// 4.0.3 lane.
    ///
    /// ```sh
    /// OSSL_PROVIDER_OBSERVATION_TEST_BPF=<provider object> \
    /// OSSLSCOPE_FOCUSED_COUNT_OBJECT=<count object> \
    /// OSSLSCOPE_TEST_OPENSSL=<4.0.3 CLI> LD_LIBRARY_PATH=<4.0.3 lib> \
    /// sudo -n <lib test binary> \
    ///     kdf_full_acquire_positive_on_403 --test-threads=1
    /// ```
    #[test]
    #[ignore = "families 4.0.3 KDF positive (sudo, pinned BPF objects)"]
    fn kdf_full_acquire_positive_on_403() {
        const TAG: &str = "fam-kdf-40pos";
        let openssl = fam_openssl_argv0();
        assert_ne!(
            openssl, "/usr/bin/openssl",
            "the 4.0.3 positive pin needs OSSLSCOPE_TEST_OPENSSL on the 4.0.3 lane"
        );
        let dir = std::env::temp_dir().join(format!(
            "osslscope-fam-kdf-40pos-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let argv = fam_openssl_kdf_argv(&openssl);
        let receipt = fam_full_acquire(
            &argv,
            &dir,
            TAG,
            FAM_KDF_OKM,
            &[307, 308],
            super::schema::Operation::Kdf,
        );
        assert_eq!(receipt.count_roles, vec![307, 308]);
        assert_eq!(
            receipt.typed_sites, 144,
            "17 first-slice + query + 126 copied"
        );
        assert_eq!(receipt.counter_links, 1);
        assert_eq!(receipt.sample_sites, 30, "16 derive + 14 reset staged");
        assert_eq!(receipt.sample_calls, 1, "only derive fires on 4.0.3");
        assert_eq!(
            receipt.joined_sites, 30,
            "every sample joins an admitted site"
        );
        assert_eq!(receipt.joined_calls, 1, "the derive hit joins");
        assert_eq!(receipt.definite, 1, "positive: the derive hit attributes");
        assert_eq!(
            receipt.unresolved, 3,
            "the 3 loss-bound foreign calls; the joined hit attributed"
        );
        assert_eq!(receipt.withheld, 0);
        assert_eq!(receipt.next_id, 165);
        assert_eq!(
            receipt.loss,
            [0, 0, 1, 2, 0, 0, 0, 0],
            "same loss shape as U5 (frame miss + teardown poisons)"
        );
    }
    /// Task-3 queue-head MAC-on-4.0.3 pin: the §12.3 shape on the
    /// stock HMAC workload (U5 §13.1 argv, lane-aware argv[0]) with
    /// the counter at the MAC operational roles (304/305/306).
    /// Expected PROVEN (the KDF-lane firemap shows 146 firing on
    /// 4.0.3, so the getter route is available): init/update/final
    /// attribute into definite partitions. Requires
    /// `OSSLSCOPE_TEST_OPENSSL` + `LD_LIBRARY_PATH` selecting the
    /// 4.0.3 lane.
    ///
    /// ```sh
    /// OSSL_PROVIDER_OBSERVATION_TEST_BPF=<provider object> \
    /// OSSLSCOPE_FOCUSED_COUNT_OBJECT=<count object> \
    /// OSSLSCOPE_TEST_OPENSSL=<4.0.3 CLI> LD_LIBRARY_PATH=<4.0.3 lib> \
    /// sudo -n <lib test binary> \
    ///     mac_full_acquire_positive_on_403 --test-threads=1
    /// ```
    #[test]
    #[ignore = "task-3 queue head: 4.0.3 MAC positive (sudo, pinned BPF objects)"]
    fn mac_full_acquire_positive_on_403() {
        const TAG: &str = "task3-mac-40pos";
        let openssl = fam_openssl_argv0();
        assert_ne!(
            openssl, "/usr/bin/openssl",
            "the 4.0.3 MAC pin needs OSSLSCOPE_TEST_OPENSSL on the 4.0.3 lane"
        );
        let dir = std::env::temp_dir().join(format!(
            "osslscope-task3-mac-40pos-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("abc.txt"), b"abc").unwrap();
        let argv = fam_openssl_mac_argv(&openssl, &dir);
        let receipt = fam_full_acquire(
            &argv,
            &dir,
            TAG,
            U5_MAC_DIGEST,
            &[304, 305, 306],
            super::schema::Operation::Mac,
        );
        assert_eq!(receipt.count_roles, vec![304, 305, 306]);
        // The 4.0.3 MAC provider behaves exactly like host U5
        // (first-guess RED held on the first run): the same 49-site
        // MAC plan, the same three operational hits, the same
        // commit/segment mint census.
        assert_eq!(
            receipt.typed_sites, 67,
            "17 first-slice + query + 49 copied"
        );
        assert_eq!(receipt.counter_links, 1);
        assert_eq!(receipt.sample_sites, 24, "every operational site sampled");
        assert_eq!(receipt.sample_calls, 3, "HMAC init + update + final fire");
        assert_eq!(
            receipt.joined_sites, 24,
            "every sample joins an admitted site"
        );
        assert_eq!(receipt.joined_calls, 3, "the three operational hits join");
        assert_eq!(
            receipt.definite, 3,
            "positive: one partition per joined operational hit"
        );
        assert_eq!(
            receipt.unresolved, 3,
            "the 3 loss-bound foreign calls; every joined hit attributed"
        );
        assert_eq!(receipt.withheld, 0);
        assert_eq!(receipt.next_id, 72, "same mint census as host U5");
        assert_eq!(
            receipt.loss,
            [0, 0, 1, 2, 0, 0, 0, 0],
            "same loss shape as U5 (frame miss + teardown poisons)"
        );
        let mut expected_roles = vec![
            5, 130, 131, 136, 137, 142, 143, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 161,
        ];
        expected_roles.extend(std::iter::repeat_n(258, 9));
        expected_roles.extend(std::iter::repeat_n(274, 8));
        expected_roles.extend(std::iter::repeat_n(290, 8));
        expected_roles.extend(std::iter::repeat_n(304, 8));
        expected_roles.extend(std::iter::repeat_n(305, 8));
        expected_roles.extend(std::iter::repeat_n(306, 8));
        assert_eq!(
            receipt.staged_roles, expected_roles,
            "17 first-slice + query + 49 MAC copied, every one admitted"
        );
    }
    // ---- Task 3 (5C): v2.5 flows over actual producer records ----
    //
    // Production capture keeps the Disabled source lease (the
    // test-only `Enabled` hardening stands), so installed binaries
    // emit v2.4. The execution flows below run the REAL producer
    // session (sudo, pinned objects), the REAL closed collect, the
    // REAL production project() + projection, and the REAL
    // report/check delivery the installed binaries call
    // (consume_document), plus a real consumer import of the CBOM
    // — before/after an HKDF→PBKDF2 migration, compared against
    // independent workload truth.

    /// Task-3 native document: the REAL production `project()`
    /// over the retained physical sample plus the REAL
    /// projection of the retained certified result. No copies,
    /// no re-derivations, no hand-built partitions.
    fn task3_native_doc(receipt: FamAcquireReceipt) -> crate::evidence::CaptureDocument {
        let FamAcquireReceipt {
            finalized,
            mut sample,
            pid,
            window,
            ..
        } = receipt;
        // The native counter candidates are nominal counting labels
        // (function 0, operation 0, unknown algorithm) —
        // placeholders for the counting plane, never observed ABI
        // metadata. project() would render them as ObservedPublicAbi
        // provenance (which the semantic check rightly rejects:
        // a 0-function observed association is invalid); clearing
        // them refuses to mislabel placeholders as observations.
        // Physical sites (counts plus Unknown-coverage hints)
        // still project verbatim.
        sample.associations.clear();
        let mut doc = crate::focused_capture::project(
            pid,
            window,
            sample,
            &[],
            &std::collections::BTreeSet::new(),
        );
        finalized
            .project_into_document(&mut doc)
            .expect("a certified closed result projects");
        doc
    }

    /// Independent libcrypto identity: resolve argv[0]'s libcrypto
    /// through the LOADER (`ldd`, inheriting the lane env) and
    /// hash the file bytes with the frozen whole-file
    /// construction. Independent of every observer-admitted
    /// identity — the workload-truth leg for selector objects.
    fn task3_libcrypto_sha256(openssl_argv0: &str) -> String {
        let ldd = std::process::Command::new("ldd")
            .arg(openssl_argv0)
            .output()
            .expect("ldd runs");
        assert!(ldd.status.success(), "ldd must resolve {openssl_argv0}");
        let text = String::from_utf8(ldd.stdout).expect("ldd output is UTF-8");
        let path = text
            .lines()
            .find_map(|line| {
                let (lib, rest) = line.trim().split_once("=>")?;
                if !lib.trim().starts_with("libcrypto.so") {
                    return None;
                }
                Some(rest.split_whitespace().next()?.to_string())
            })
            .unwrap_or_else(|| panic!("ldd resolves no libcrypto for {openssl_argv0}"));
        let bytes = std::fs::read(&path).expect("libcrypto file reads");
        crate::kinds::prov_hash(&bytes)
    }

    /// Independent PBKDF2 recomputation (stdlib `hashlib` only —
    /// no third-party oracle dependency): the exact migration
    /// post-leg parameters.
    fn task3_hashlib_pbkdf2() -> String {
        let out = std::process::Command::new("python3")
            .arg("-c")
            .arg("import hashlib; print(hashlib.pbkdf2_hmac('sha256', b'password', bytes(range(13)), 4096, 42).hex().upper())")
            .output()
            .expect("python3 runs");
        assert!(out.status.success(), "hashlib recomputation runs");
        String::from_utf8(out.stdout)
            .expect("hashlib output is UTF-8")
            .trim()
            .to_string()
    }

    /// Independent HKDF recomputation (RFC 5869 extract+expand
    /// via stdlib `hmac`): the exact families-stage parameters
    /// (22-octet 0x0b IKM, salt 0x00..=0x0c, info 0xf0..=0xf9,
    /// 42 bytes).
    fn task3_hmac_hkdf() -> String {
        let out = std::process::Command::new("python3")
            .arg("-c")
            .arg("import hmac, hashlib; ikm = bytes([0x0b]*22); salt = bytes(range(13)); info = bytes(range(0xf0, 0xfa)); prk = hmac.new(salt, ikm, hashlib.sha256).digest(); okm = b''; t = b''; i = 1\nwhile len(okm) < 42:\n    t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest(); okm += t; i += 1\nprint(okm[:42].hex().upper())")
            .output()
            .expect("python3 runs");
        assert!(out.status.success(), "hmac recomputation runs");
        String::from_utf8(out.stdout)
            .expect("hmac output is UTF-8")
            .trim()
            .to_string()
    }

    /// Real-consumer CBOM import: the official CycloneDX library
    /// deserializes our CBOM and must find every expected
    /// component name (exact match). `TASK3_CDX_PYTHON` (the
    /// consumer interpreter) and `TASK3_CDX_SCRIPT` (the import
    /// script) are both required — a missing consumer fails the
    /// test, never skips it.
    fn task3_consumer_import(tag: &str, cbom_path: &std::path::Path, expected: &[&str]) {
        let python = std::env::var("TASK3_CDX_PYTHON")
            .expect("TASK3_CDX_PYTHON selects the consumer interpreter");
        let script =
            std::env::var("TASK3_CDX_SCRIPT").expect("TASK3_CDX_SCRIPT selects the import script");
        let out = std::process::Command::new(&python)
            .arg(&script)
            .arg(cbom_path)
            .args(expected)
            .output()
            .unwrap_or_else(|error| panic!("{tag}: consumer import spawns: {error:?}"));
        let stdout = String::from_utf8_lossy(&out.stdout);
        eprintln!("{tag} consumer import:\n{stdout}");
        assert!(
            out.status.success(),
            "{tag}: consumer import must accept the CBOM: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn task3_focused_result(
        document: crate::evidence::CaptureDocument,
    ) -> crate::focused_capture::FocusedResult {
        // child_exit Some(0): fam_full_acquire asserts the
        // observed workload exits 0 in-flow — truthful, not a
        // default. The document already carries the projection
        // (the production finish() shape).
        crate::focused_capture::FocusedResult {
            document,
            child_exit: Some(0),
            workload_discarded: false,
            fence_withheld: 0,
            loss_totals: [0; 8],
            _reservation: None,
        }
    }

    /// Task-3 item 5: the HKDF→PBKDF2 migration through the REAL
    /// v2.5 flows. Both legs run the actual producer session on
    /// the host lane (sudo, pinned objects); each leg's retained
    /// certified result projects through the real production
    /// assembly; policy (violation/pass/inconclusive), the real
    /// report/check delivery, and a real consumer import run on
    /// each leg's document; the migration comparison asserts the
    /// pre selector stops matching post-migration while the post
    /// selector starts. Workload truth is independent throughout
    /// (stdlib oracle recomputation, loader-resolved libcrypto
    /// identity). Requires `TASK3_CDX_PYTHON` +
    /// `TASK3_CDX_SCRIPT` for the consumer leg.
    ///
    /// ```sh
    /// OSSL_PROVIDER_OBSERVATION_TEST_BPF=<provider object> \
    /// OSSLSCOPE_FOCUSED_COUNT_OBJECT=<count object> \
    /// TASK3_CDX_PYTHON=<consumer venv python> \
    /// TASK3_CDX_SCRIPT=<import script> \
    /// sudo -n <lib test binary> \
    ///     task3_kdf_migration_flows --test-threads=1
    /// ```
    #[test]
    #[ignore = "task-3 item 5: KDF migration flows (sudo, pinned BPF, cdx consumer)"]
    fn task3_kdf_migration_flows_through_report_check_and_consumer() {
        const TAG: &str = "task3-migrate";
        let openssl = fam_openssl_argv0();
        assert_eq!(
            openssl, "/usr/bin/openssl",
            "the migration flows pin the host lane"
        );
        let base = std::env::temp_dir().join(format!(
            "osslscope-task3-migrate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&base).unwrap();
        // Pre leg (HKDF): the pinned KDF positive shape.
        let pre_dir = base.join("pre");
        std::fs::create_dir(&pre_dir).unwrap();
        let pre_argv = fam_openssl_kdf_argv(&openssl);
        let pre = fam_full_acquire(
            &pre_argv,
            &pre_dir,
            "task3-migrate-pre",
            FAM_KDF_OKM,
            &[307, 308],
            super::schema::Operation::Kdf,
        );
        assert_eq!(pre.typed_sites, 130, "the KDF positive shape");
        assert_eq!(pre.definite, 1, "the derive hit attributes");
        assert_eq!(pre.unresolved, 4);
        assert_eq!(pre.withheld, 0);
        assert_eq!(pre.next_id, 151);
        assert_eq!(pre.loss, [0, 0, 1, 2, 0, 0, 0, 0]);
        assert_eq!(task3_hmac_hkdf(), FAM_KDF_OKM, "independent HKDF oracle");
        // Post leg (PBKDF2): no nested-HMAC query (PBKDF2 never
        // queries op 3), so 63 copied sites (typed=81); only the
        // derive hit fires (308 stays dark — no dispatch RESET on
        // the free path) and attributes into one definite
        // partition. Two illegible events (POISON=2) stay bounded
        // inside unresolved=4 — the same accounting as the KDF
        // pin's single poison.
        let post_dir = base.join("post");
        std::fs::create_dir(&post_dir).unwrap();
        let post_argv = fam_openssl_pbkdf2_argv(&openssl);
        let post = fam_full_acquire(
            &post_argv,
            &post_dir,
            "task3-migrate-post",
            FAM_PBKDF2_OKM,
            &[307, 308],
            super::schema::Operation::Kdf,
        );
        assert_eq!(
            task3_hashlib_pbkdf2(),
            FAM_PBKDF2_OKM,
            "independent PBKDF2 oracle"
        );
        assert_eq!(post.count_roles, vec![307, 308]);
        assert_eq!(post.typed_sites, 81, "17 first-slice + query + 63 copied");
        assert_eq!(post.counter_links, 1);
        assert_eq!(post.sample_sites, 26);
        assert_eq!(post.sample_calls, 1, "only the derive hit fires");
        assert_eq!(post.joined_sites, 26);
        assert_eq!(post.joined_calls, 1);
        assert_eq!(post.definite, 1, "positive: the derive hit attributes");
        assert_eq!(post.unresolved, 4);
        assert_eq!(post.withheld, 0);
        assert_eq!(post.next_id, 84);
        assert_eq!(
            post.loss,
            [0, 0, 2, 2, 0, 0, 0, 0],
            "two illegible events, both bounded into unresolved"
        );
        let mut expected_roles = vec![
            5, 130, 131, 136, 137, 142, 143, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 161,
        ];
        expected_roles.extend(std::iter::repeat_n(259, 14));
        expected_roles.extend(std::iter::repeat_n(275, 12));
        expected_roles.extend(std::iter::repeat_n(291, 11));
        expected_roles.extend(std::iter::repeat_n(307, 14));
        expected_roles.extend(std::iter::repeat_n(308, 12));
        assert_eq!(
            post.staged_roles, expected_roles,
            "17 first-slice + query + 63 PBKDF2 copied, every one admitted"
        );
        // Native documents from the actual producer records.
        let pre_doc = task3_native_doc(pre);
        let post_doc = task3_native_doc(post);
        for (name, doc) in [("pre", &pre_doc), ("post", &post_doc)] {
            assert_eq!(
                doc.schema,
                crate::evidence::CAPTURE_SCHEMA_V2_5,
                "{TAG}-{name}: projection upgrades the schema"
            );
            let bytes = crate::report::render_json(doc).expect("report renders");
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            crate::schema::validate_v2(&json).expect("v2.5 validates");
            crate::schema::check_v2_semantics(&json).expect("v2.5 is semantic-clean");
            assert!(!doc.execution_attributions.is_empty());
            assert_eq!(doc.algorithm_selectors.len(), 1);
        }
        // Workload truth: canonical names equal the workloads'
        // algorithms, both legs' selector objects equal the
        // loader-resolved libcrypto, and the migration changes
        // the object-bound identity.
        let lib = task3_libcrypto_sha256(&openssl);
        eprintln!("{TAG} loader libcrypto sha256={lib}");
        let pre_sel = &pre_doc.algorithm_selectors[0];
        let post_sel = &post_doc.algorithm_selectors[0];
        eprintln!(
            "{TAG}-pre selector object={} operation={} id={}",
            pre_sel.object.0, pre_sel.operation, pre_sel.id
        );
        eprintln!(
            "{TAG}-post selector object={} operation={} id={}",
            post_sel.object.0, post_sel.operation, post_sel.id
        );
        assert_eq!(pre_sel.canonical_name.as_deref(), Some("HKDF"));
        assert_eq!(post_sel.canonical_name.as_deref(), Some("PBKDF2"));
        assert_eq!(pre_sel.object.0, lib);
        assert_eq!(post_sel.object.0, lib);
        assert_ne!(
            pre_sel.id, post_sel.id,
            "the migration changes the identity"
        );
        for (name, doc, sel) in [("pre", &pre_doc, pre_sel), ("post", &post_doc, post_sel)] {
            let bound = doc.attribution_bounds.expect("bounds ride");
            eprintln!(
                "{TAG}-{name}: definite={} unresolved={} withheld={} selector={}:{}",
                doc.execution_attributions
                    .iter()
                    .map(|r| r.calls)
                    .sum::<u64>(),
                bound.unresolved_calls,
                bound.withheld_uncertain,
                sel.object.0.chars().take(16).collect::<String>(),
                sel.id.chars().take(16).collect::<String>(),
            );
            // Execution policy on the real records: the matching
            // deny violates, the matching require passes, and an
            // unmatched selector stays inconclusive (absence
            // unprovable while calls are unresolved).
            let violated = crate::policy::evaluate_document(
                &[crate::policy::PolicyRule::deny_selector(
                    &sel.object.0,
                    &sel.id,
                )],
                doc,
            );
            assert_eq!(
                violated.overall(),
                crate::policy::PolicyOutcome::Violation,
                "{TAG}-{name}: matching deny violates"
            );
            let passed = crate::policy::evaluate_document(
                &[crate::policy::PolicyRule::require_selector(
                    &sel.object.0,
                    &sel.id,
                )],
                doc,
            );
            assert_eq!(
                passed.overall(),
                crate::policy::PolicyOutcome::Pass,
                "{TAG}-{name}: matching require passes"
            );
            let open = crate::policy::evaluate_document(
                &[crate::policy::PolicyRule::require_selector(
                    &sel.object.0,
                    &"f".repeat(64),
                )],
                doc,
            );
            assert_eq!(
                open.overall(),
                crate::policy::PolicyOutcome::Inconclusive,
                "{TAG}-{name}: unmatched require stays inconclusive"
            );
        }
        // Migration comparison: the pre identity stops matching
        // post-migration (absence unprovable → inconclusive, never
        // a pass), while the post identity starts violating.
        let gone = crate::policy::evaluate_document(
            &[crate::policy::PolicyRule::deny_selector(
                &pre_sel.object.0,
                &pre_sel.id,
            )],
            &post_doc,
        );
        assert_eq!(gone.overall(), crate::policy::PolicyOutcome::Inconclusive);
        let arrived = crate::policy::evaluate_document(
            &[crate::policy::PolicyRule::deny_selector(
                &post_sel.object.0,
                &post_sel.id,
            )],
            &post_doc,
        );
        assert_eq!(arrived.overall(), crate::policy::PolicyOutcome::Violation);
        // The REAL report/check delivery on each leg's document
        // (the functions the installed binaries call), with real
        // artifacts and a real consumer import of each CBOM.
        for (name, doc, algorithm) in [("pre", pre_doc, "HKDF"), ("post", post_doc, "PBKDF2")] {
            let out = base.join(format!("{name}.json"));
            let cbom = base.join(format!("{name}.cbom.json"));
            let request = crate::report::OutputRequest {
                format: crate::report::OutputFormat::Json,
                primary: crate::report::OutputDest::File(out),
                cbom: Some(crate::report::OutputDest::File(cbom.clone())),
            };
            let report = crate::report::consume_document(
                task3_focused_result(doc.clone()),
                crate::report::CaptureCommand::Report,
                &request,
            );
            assert!(report.delivery.primary.ok, "{TAG}-{name}: report delivers");
            assert_eq!(
                report.exit_code, 3,
                "{TAG}-{name}: report exits pass+partial"
            );
            let sel = &report.document.algorithm_selectors[0];
            let rules = vec![crate::policy::PolicyRule::deny_selector(
                &sel.object.0,
                &sel.id,
            )];
            let checked = crate::report::consume_document(
                task3_focused_result(report.document.clone()),
                crate::report::CaptureCommand::Check { rules: &rules },
                &request,
            );
            assert_eq!(checked.exit_code, 10, "{TAG}-{name}: check exits violation");
            assert!(
                checked.document.policy.is_some(),
                "{TAG}-{name}: the checked document carries policy"
            );
            let open_rules = vec![crate::policy::PolicyRule::require_selector(
                &sel.object.0,
                &"f".repeat(64),
            )];
            let open = crate::report::consume_document(
                task3_focused_result(doc),
                crate::report::CaptureCommand::Check { rules: &open_rules },
                &request,
            );
            assert_eq!(open.exit_code, 11, "{TAG}-{name}: check exits inconclusive");
            task3_consumer_import(
                &format!("{TAG}-{name}"),
                &cbom,
                &[&format!("{algorithm} (KDF) via object-bound execution")],
            );
        }
        std::fs::remove_dir_all(&base).unwrap();
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges, cc"]
    fn typed_failed_return_registration_withholds_ready_and_operands() {
        // P3-I1 failed-registration control (RETURN): ENTRY succeeds (the
        // adoption guard is created PREPARING) but the armed RETURN claims
        // the wrong offset, so the kernel quarantines the staged row and
        // refuses with a genuine refused receipt. The capability never
        // adopts (guard stays PREPARING, never LIVE), no READY can
        // publish, and the acquisition refuses as a whole. Both links ARE
        // attached and FIRE when the workload executes the export (exit 0
        // proves public success) — yet the kernel mints nothing
        // (next_producer_id holds 1), proving both typed callbacks refused
        // at the READY gate before any operand read.
        let baseline = source_native_fd_targets();
        let mut setup = typed_refusal_setup("return");
        let pid = setup.child.pid();
        let marker = setup.dir.join("marker");
        let params = super::source_owner::NativeSourceParams::for_test(
            setup.app.clone(),
            setup.admitted_offset,
            pid,
        );
        let admitted = setup.session.admitted_source_site(&params).unwrap();
        let typed = {
            let session = &mut setup.session;
            let owner = session.source_owner.as_mut().expect("source owner");
            let budget = &session.budget;
            owner.note_gate_open_observed().unwrap();
            let domain = owner.arm_domain(pid).unwrap();
            let host_key = owner.enroll_observer().unwrap();
            let scope = super::source_owner::RequestScope {
                site_cookie: admitted.site_cookie,
                host_key,
                incarnation: domain.incarnation,
                planned_image: domain.planned,
                link_offset: admitted.link_offset,
                target_pid: admitted.tgid,
                target: admitted.target,
                expected_artifact: admitted.expected_artifact,
            };
            let anchor = owner
                .anchor_source(&scope, budget, None)
                .unwrap_or_else(|gap| {
                    panic!(
                        "anchor failed: {gap:?} owner: {:?}",
                        owner.take_last_error()
                    )
                });
            assert_eq!(
                owner.guard_life_test(anchor.anchor_id),
                Some(super::source_acquire::GuardLife::Live)
            );
            owner.fail_next_typed_return();
            super::source_owner::TypedAcquisitionScope {
                anchor,
                host_key,
                incarnation: domain.incarnation,
                planned_image: domain.planned,
            }
        };
        let error = setup
            .session
            .acquire_typed_sites(
                &typed,
                Instant::now() + Duration::from_secs(15),
                &setup.cancel,
            )
            .unwrap_err();
        assert_eq!(error, ObservationGap::Invalidated);
        {
            let session = &mut setup.session;
            let typed_empty = session.typed_site_records().is_empty();
            let owner = session.source_owner.as_mut().expect("source owner");
            let registration = owner.last_typed_registration_test();
            assert_ne!(registration, 0, "the refused RETURN minted a registration");
            assert_eq!(
                owner.guard_life_test(registration),
                Some(super::source_acquire::GuardLife::Preparing),
                "RETURN refusal must precede adoption"
            );
            assert_eq!(
                owner.adopted_link_count(),
                2,
                "both links attached; the pair never adopted"
            );
            assert!(typed_empty, "refused cookies record nothing");
            assert!(!owner.acquisition_ready(), "no READY, no release");
            owner.refuse_acquisition();
            eprintln!(
                "typed RETURN refused: reg={registration} adopted=2 next_id={} (pre-release)",
                source_native_next_producer_id(session)
            );
        }
        setup.child.release().unwrap();
        let until = Instant::now() + Duration::from_secs(15);
        // P3-I1 fix-round-1: poll until the marker CARRIES the payload,
        // not merely exists: exists-then-single-read races the
        // fixture's fopen("w") (creates the empty file) against its
        // fclose (flushes "exec\n"). The four pre-existing sites keep
        // the P3 shape verbatim; only these new controls poll.
        loop {
            if let Ok(body) = std::fs::read(&marker) {
                if body == b"exec\n" {
                    break;
                }
            }
            assert!(Instant::now() < until, "exec marker never carried exec");
            std::thread::sleep(Duration::from_millis(1));
        }
        while setup.child.peek_exit().unwrap().is_none() {
            assert!(Instant::now() < until, "workload never exited");
            std::thread::yield_now();
        }
        assert_eq!(
            setup.child.poll_exit().unwrap(),
            Some(0),
            "workload must exit 0: the export executed, so both links fired"
        );
        assert_eq!(
            source_native_next_producer_id(&setup.session),
            1,
            "typed callbacks refused at the READY gate before any mint"
        );
        let lease = super::source_owner::SourceAcquisitionLease::Enabled(params);
        let state = setup
            .session
            .note_source_exec(&lease, pid, typed.planned_image)
            .unwrap();
        assert_eq!(state, super::source_owner::contract::DOMAIN_ACTIVE);
        setup.gate.close().unwrap();
        let close = setup.session.close_source_explicit().expect("source close");
        assert!(close.cut_confirmed, "close must confirm the cut");
        assert_eq!(
            (
                close.guards_retired,
                close.guards_abandoned,
                close.domains_retired
            ),
            (1, 0, 1),
            "anchor retired; the unlisted PREPARING typed id retires with its maps"
        );
        assert!(close.order_refused, "refused order must refuse");
        assert!(close.first_error.is_none());
        drop(setup.session);
        drop(setup.gate);
        drop(setup.child);
        assert_eq!(
            source_native_fd_targets(),
            baseline,
            "teardown must release every fd"
        );
        std::fs::remove_dir_all(&setup.dir).unwrap();
    }
    struct SourceRefusalSetup {
        dir: std::path::PathBuf,
        app: std::path::PathBuf,
        child: crate::target::OwnedTarget,
        cancel: std::sync::atomic::AtomicBool,
        gate: crate::writer_gate::WriterGate,
        session: ProviderSession,
        admitted_offset: u64,
    }
    /// Owned session carried through reserve-only prearm, typed preparation
    /// and gate open: the exact position where acquisition verifies its
    /// claim against the admitted site.
    fn source_refusal_setup(suffix: &str) -> SourceRefusalSetup {
        let dir = std::env::temp_dir().join(format!(
            "osslscope-source-refuse-{suffix}-{}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        let app = source_native_fixture(&dir);
        let argv = [
            app.to_string_lossy().into_owned(),
            dir.join("marker").to_string_lossy().into_owned(),
        ];
        let child =
            crate::target::OwnedTarget::spawn_stopped(&argv, crate::target::WorkloadDest::Null)
                .unwrap();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let mut budget = ObservationBudget::default();
        let startup = crate::startup_objects::prepare_owned_startup(
            &child,
            &argv,
            &mut budget,
            Instant::now() + Duration::from_secs(15),
            &cancel,
            None,
        )
        .unwrap();
        let crate::startup_objects::PreExecSites { apis, typed, .. } = startup;
        let object =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        budget.state(crate::writer_gate::RESERVATION_BYTES).unwrap();
        let pool = budget.memory.clone().unwrap_or_else(|| {
            crate::observation_memory::MemoryPool::new(budget.limits.max_state_bytes)
        });
        let gate = crate::writer_gate::WriterGate::create(&pool).unwrap();
        let mut session = ProviderSession::open_gated(budget, &object, gate.clone()).unwrap();
        session
            .prearm_startup(
                apis,
                Instant::now() + Duration::from_secs(5),
                &cancel,
                PrearmLinks::Reserve,
            )
            .unwrap();
        assert_eq!(session.startup[&child.pid()].len(), 1);
        let admitted_offset = session.startup[&child.pid()][0].site.file_offset();
        assert_ne!(admitted_offset, 0);
        let lease = super::source_owner::SourceAcquisitionLease::Enabled(
            super::source_owner::NativeSourceParams::for_test(
                app.clone(),
                admitted_offset,
                child.pid(),
            ),
        );
        session
            .prepare_typed_startup(
                typed,
                Instant::now() + Duration::from_secs(15),
                &cancel,
                &lease,
            )
            .unwrap();
        gate.open().unwrap();
        SourceRefusalSetup {
            dir,
            app,
            child,
            cancel,
            gate,
            session,
            admitted_offset,
        }
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges, cc"]
    fn source_acquisition_rejects_substituted_file_and_offset() {
        // Claim-vs-truth binding: a substituted offset (the legacy header
        // offset 0, or any off-by-one) or a substituted file (even a
        // byte-identical copy: identity is the admitted inode, not content)
        // refuses before any kernel effect. Fresh owned session per case.
        // FD contract for a refused acquisition: the refusal itself has
        // exactly zero fd effects (snapshot equality across the refused
        // call), and teardown releases everything back to the case-open
        // baseline (no survivors at all: nothing was ever adopted, so the
        // success-path ghost allowance does not apply).
        let baseline = source_native_fd_targets();
        for case in ["header-offset", "off-by-one", "substituted-file"] {
            let mut setup = source_refusal_setup(case);
            let (link_offset, target) = match case {
                "header-offset" => (0, setup.app.clone()),
                "off-by-one" => (setup.admitted_offset + 1, setup.app.clone()),
                _ => {
                    let copy = setup.dir.join("app-copy");
                    std::fs::copy(&setup.app, &copy).unwrap();
                    assert_eq!(
                        std::fs::read(&copy).unwrap(),
                        std::fs::read(&setup.app).unwrap(),
                        "the substituted file must be byte-identical"
                    );
                    (setup.admitted_offset, copy)
                }
            };
            let bad = super::source_owner::SourceAcquisitionLease::Enabled(
                super::source_owner::NativeSourceParams::for_test(
                    target,
                    link_offset,
                    setup.child.pid(),
                ),
            );
            let fds_pre_acquire = source_native_fd_targets();
            let result = setup.session.acquire_source_after_open(
                &bad,
                Instant::now() + Duration::from_secs(15),
                &setup.cancel,
            );
            assert_eq!(
                source_native_fd_targets(),
                fds_pre_acquire,
                "{case}: refused acquisition must have zero fd effects"
            );
            let error = match result {
                Ok(_) => panic!("{case} must refuse"),
                Err(error) => error,
            };
            assert_eq!(error, ObservationGap::Invalidated, "{case}");
            assert_eq!(
                setup
                    .session
                    .source_owner
                    .as_ref()
                    .expect("source owner")
                    .adopted_link_count(),
                0,
                "{case}: refusal must precede any link adoption"
            );
            setup.gate.close().unwrap();
            let close = setup.session.close_source_explicit().expect("source close");
            assert!(close.cut_confirmed, "{case}: close must confirm the cut");
            assert_eq!(
                (
                    close.guards_retired,
                    close.guards_abandoned,
                    close.domains_retired
                ),
                (0, 0, 0),
                "{case}"
            );
            assert!(close.order_refused, "{case}: refused order must refuse");
            assert!(close.first_error.is_none(), "{case}");
            drop(setup.session);
            drop(setup.gate);
            drop(setup.child);
            assert_eq!(
                source_native_fd_targets(),
                baseline,
                "{case}: teardown must release every fd"
            );
            std::fs::remove_dir_all(&setup.dir).unwrap();
            eprintln!("{case}: refused Invalidated with zero adoptions");
        }
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges, cc"]
    fn source_disarm_keeps_unrelated_registrations_quiet_and_pairable() {
        // P2-I2: every completed synchronous request disarms (its row is
        // deleted). An unrelated native registration between source
        // transactions and after READY stays quiet (PAIR never leaves 0,
        // observer stays live), and every later legitimate request still
        // pairs (each subsequent phase succeeds). Against a stale
        // completed row the first control would refuse and terminally
        // poison PAIR, failing the phase that follows it.
        let baseline = source_native_fd_targets();
        let mut setup = source_refusal_setup("disarm");
        let pid = setup.child.pid();
        let marker = setup.dir.join("marker");
        let params = super::source_owner::NativeSourceParams::for_test(
            setup.app.clone(),
            setup.admitted_offset,
            pid,
        );
        let admitted = setup.session.admitted_source_site(&params).unwrap();
        let entry_prog =
            std::os::fd::AsRawFd::as_raw_fd(&setup.session.loaded.progs["observation_entry"]);
        let return_prog =
            std::os::fd::AsRawFd::as_raw_fd(&setup.session.loaded.progs["observation_return"]);
        let (planned, anchor_hash) = {
            let session = &mut setup.session;
            let owner = session.source_owner.as_mut().expect("source owner");
            let budget = &session.budget;
            owner.note_gate_open_observed().unwrap();
            let domain = owner.arm_domain(pid).unwrap();
            let host_key = owner.enroll_observer().unwrap();
            let scope = super::source_owner::RequestScope {
                site_cookie: admitted.site_cookie,
                host_key,
                incarnation: domain.incarnation,
                planned_image: domain.planned,
                link_offset: admitted.link_offset,
                target_pid: admitted.tgid,
                target: admitted.target,
                expected_artifact: admitted.expected_artifact,
            };
            let anchor = owner
                .anchor_source(&scope, budget, None)
                .unwrap_or_else(|gap| {
                    panic!(
                        "anchor failed: {gap:?} owner: {:?}",
                        owner.take_last_error()
                    )
                });
            assert!(
                owner.request_absent_test(host_key).unwrap(),
                "anchor must disarm its completed request"
            );
            assert_eq!(owner.pair_state_test().unwrap(), 0);
            // Control A: unrelated registration between anchor and entry/return.
            drop(owner.fire_unrelated_registration().unwrap());
            assert_eq!(
                owner.pair_state_test().unwrap(),
                0,
                "control A must stay quiet"
            );
            assert!(owner.request_absent_test(host_key).unwrap());
            let registration = owner
                .register_entry_return(&scope, entry_prog, return_prog, &anchor)
                .unwrap_or_else(|gap| {
                    panic!(
                        "entry/return failed after quiet control: {gap:?} owner: {:?}",
                        owner.take_last_error()
                    )
                });
            assert!(
                owner.request_absent_test(host_key).unwrap(),
                "entry/return must disarm their completed requests"
            );
            // Control B: unrelated registration between adoption and READY.
            drop(owner.fire_unrelated_registration().unwrap());
            assert_eq!(
                owner.pair_state_test().unwrap(),
                0,
                "control B must stay quiet"
            );
            let ready = owner
                .publish_ready(&scope, &anchor, &registration)
                .unwrap_or_else(|gap| {
                    panic!(
                        "ready failed after quiet control: {gap:?} owner: {:?}",
                        owner.take_last_error()
                    )
                });
            assert_ne!(ready, 0);
            assert!(owner.acquisition_ready());
            assert!(
                owner.request_absent_test(host_key).unwrap(),
                "ready must disarm its completed request"
            );
            // Control C: unrelated registration after READY.
            drop(owner.fire_unrelated_registration().unwrap());
            assert_eq!(
                owner.pair_state_test().unwrap(),
                0,
                "control C must stay quiet"
            );
            assert_eq!(
                owner.observer_state_test().unwrap(),
                2,
                "observer stays live through quiet controls"
            );
            assert_ne!(anchor.anchor_id, 0);
            assert_ne!(registration.registration_id, 0);
            assert_eq!(owner.adopted_link_count(), 2);
            eprintln!("disarm controls quiet: pair=0 observer=2 adopted=2 ready_seq={ready}");
            (domain.planned, anchor.hash)
        };
        // Independent anchor oracle: hash the target file directly.
        let expected = {
            use sha2::Digest as _;
            sha2::Sha256::digest(std::fs::read(&setup.app).unwrap())
        };
        assert_eq!(anchor_hash, expected.as_slice());
        // Release only after READY, then the independent workload oracle.
        setup.child.release().unwrap();
        let until = Instant::now() + Duration::from_secs(15);
        while !marker.exists() {
            assert!(Instant::now() < until, "exec marker never appeared");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(std::fs::read(&marker).unwrap(), b"exec\n");
        while setup.child.peek_exit().unwrap().is_none() {
            assert!(Instant::now() < until, "workload never exited");
            std::thread::yield_now();
        }
        assert_eq!(
            setup.child.poll_exit().unwrap(),
            Some(0),
            "workload must exit 0"
        );
        let lease = super::source_owner::SourceAcquisitionLease::Enabled(params);
        let state = setup
            .session
            .note_source_exec(&lease, pid, planned)
            .unwrap();
        assert_eq!(state, super::source_owner::contract::DOMAIN_ACTIVE);
        // Final consumers (exec mirror above) run before the cut; the cut
        // runs before the close.
        setup.gate.close().unwrap();
        let close = setup.session.close_source_explicit().expect("source close");
        assert!(close.cut_confirmed, "close must confirm the cut");
        assert_eq!(
            (
                close.guards_retired,
                close.guards_abandoned,
                close.domains_retired
            ),
            (2, 0, 1)
        );
        assert!(
            !close.order_refused,
            "READY order must stay published at close"
        );
        assert!(close.first_error.is_none());
        drop(setup.session);
        drop(setup.gate);
        drop(setup.child);
        assert_eq!(
            source_native_fd_targets(),
            baseline,
            "teardown must release every fd"
        );
        std::fs::remove_dir_all(&setup.dir).unwrap();
    }
    /// P2-I3 failed-cut control: the gate cut fails, so the source close
    /// refuses without touching guards, domains, order or custody; writers
    /// stay safe (an unrelated registration stays quiet against the
    /// disarmed row). Teardown then releases everything.
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges, cc"]
    fn source_close_failed_cut_retains_custody_and_stays_safe() {
        let baseline = source_native_fd_targets();
        let mut setup = source_refusal_setup("close-cut");
        let pid = setup.child.pid();
        let lease = super::source_owner::SourceAcquisitionLease::Enabled(
            super::source_owner::NativeSourceParams::for_test(
                setup.app.clone(),
                setup.admitted_offset,
                pid,
            ),
        );
        let receipts = setup
            .session
            .acquire_source_after_open(
                &lease,
                Instant::now() + Duration::from_secs(15),
                &setup.cancel,
            )
            .unwrap_or_else(|gap| {
                panic!(
                    "acquire failed: {gap:?} owner: {:?}",
                    setup.session.source_error()
                )
            });
        setup.child.release().unwrap();
        let until = Instant::now() + Duration::from_secs(15);
        while setup.child.peek_exit().unwrap().is_none() {
            assert!(Instant::now() < until, "workload never exited");
            std::thread::yield_now();
        }
        assert_eq!(setup.child.poll_exit().unwrap(), Some(0));
        let planned = receipts.domain.planned;
        let state = setup
            .session
            .note_source_exec(&lease, pid, planned)
            .unwrap();
        assert_eq!(state, super::source_owner::contract::DOMAIN_ACTIVE);
        // Fail the common cut, then attempt the close.
        setup.gate.fail_next_delete();
        assert!(setup.gate.close().is_err(), "cut must fail");
        let close = setup.session.close_source_explicit().expect("source close");
        assert!(!close.cut_confirmed, "close must not confirm a failed cut");
        assert_eq!(close.first_error, Some(ObservationGap::Invalidated));
        assert_eq!(
            (
                close.guards_retired,
                close.guards_abandoned,
                close.domains_retired
            ),
            (0, 0, 0)
        );
        assert!(
            !close.order_refused,
            "failed close must not disturb the READY order"
        );
        // Custody retained: adopted links, anchor, loaded roots, LIVE
        // guards, and the kernel domain row untouched (still ACTIVE: the
        // host performed no racing read-modify-write of live state).
        // P3-I1: the owner also retains every adopted typed pair.
        let owner = setup.session.source_owner.as_ref().expect("source owner");
        assert_eq!(
            owner.adopted_link_count(),
            2 + 2 * setup.session.typed_site_records().len()
        );
        assert!(owner.anchor_retained_test());
        let roots = setup
            .session
            .roots_enabled_receipts()
            .expect("roots receipts");
        assert_eq!((roots.programs, roots.links, roots.lifecycle), (4, 2, 2));
        assert_eq!(
            owner.guard_life_test(receipts.anchor.anchor_id),
            Some(super::source_acquire::GuardLife::Live)
        );
        assert_eq!(
            owner.guard_life_test(receipts.registration.registration_id),
            Some(super::source_acquire::GuardLife::Live)
        );
        assert_eq!(
            owner.domain_state_test(pid).unwrap(),
            super::source_owner::contract::DOMAIN_ACTIVE
        );
        assert!(owner.acquisition_ready());
        // Writers safe: the failed close left kernel state coherent, so an
        // unrelated registration on the observer thread stays quiet.
        drop(owner.fire_unrelated_registration().unwrap());
        assert_eq!(owner.pair_state_test().unwrap(), 0);
        assert_eq!(owner.observer_state_test().unwrap(), 2);
        eprintln!("failed-cut close refused with full custody retained");
        drop(setup.session);
        drop(setup.gate);
        drop(setup.child);
        assert_eq!(
            source_native_fd_targets(),
            baseline,
            "teardown must release every fd"
        );
        std::fs::remove_dir_all(&setup.dir).unwrap();
    }
    /// P2-I3 failed-retirement control: the first guard retirement fails
    /// (injected), so the close stops with custody retained and the kernel
    /// domain row untouched (no host racing update: the domain loop never
    /// runs). Writers stay safe; teardown releases everything.
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges, cc"]
    fn source_close_failed_retirement_retains_custody_and_stays_safe() {
        let baseline = source_native_fd_targets();
        let mut setup = source_refusal_setup("close-retire");
        let pid = setup.child.pid();
        let lease = super::source_owner::SourceAcquisitionLease::Enabled(
            super::source_owner::NativeSourceParams::for_test(
                setup.app.clone(),
                setup.admitted_offset,
                pid,
            ),
        );
        let receipts = setup
            .session
            .acquire_source_after_open(
                &lease,
                Instant::now() + Duration::from_secs(15),
                &setup.cancel,
            )
            .unwrap_or_else(|gap| {
                panic!(
                    "acquire failed: {gap:?} owner: {:?}",
                    setup.session.source_error()
                )
            });
        setup.child.release().unwrap();
        let until = Instant::now() + Duration::from_secs(15);
        while setup.child.peek_exit().unwrap().is_none() {
            assert!(Instant::now() < until, "workload never exited");
            std::thread::yield_now();
        }
        assert_eq!(setup.child.poll_exit().unwrap(), Some(0));
        let planned = receipts.domain.planned;
        let state = setup
            .session
            .note_source_exec(&lease, pid, planned)
            .unwrap();
        assert_eq!(state, super::source_owner::contract::DOMAIN_ACTIVE);
        setup.gate.close().unwrap();
        setup
            .session
            .source_owner
            .as_ref()
            .expect("source owner")
            .fail_next_guard_retire();
        let close = setup.session.close_source_explicit().expect("source close");
        assert!(close.cut_confirmed, "the cut itself succeeded");
        assert_eq!(close.first_error, Some(ObservationGap::BpfUnavailable));
        assert_eq!(
            (
                close.guards_retired,
                close.guards_abandoned,
                close.domains_retired
            ),
            (0, 0, 0)
        );
        assert!(
            !close.order_refused,
            "failed close must not disturb the READY order"
        );
        let owner = setup.session.source_owner.as_ref().expect("source owner");
        // P3-I1: the owner also retains every adopted typed pair.
        assert_eq!(
            owner.adopted_link_count(),
            2 + 2 * setup.session.typed_site_records().len()
        );
        assert!(owner.anchor_retained_test());
        let roots = setup
            .session
            .roots_enabled_receipts()
            .expect("roots receipts");
        assert_eq!((roots.programs, roots.links, roots.lifecycle), (4, 2, 2));
        assert_eq!(
            owner.guard_life_test(receipts.anchor.anchor_id),
            Some(super::source_acquire::GuardLife::Live)
        );
        assert_eq!(
            owner.guard_life_test(receipts.registration.registration_id),
            Some(super::source_acquire::GuardLife::Live)
        );
        assert_eq!(
            owner.domain_state_test(pid).unwrap(),
            super::source_owner::contract::DOMAIN_ACTIVE
        );
        assert!(owner.acquisition_ready());
        drop(owner.fire_unrelated_registration().unwrap());
        assert_eq!(owner.pair_state_test().unwrap(), 0);
        eprintln!("failed-retirement close refused with full custody retained");
        drop(setup.session);
        drop(setup.gate);
        drop(setup.child);
        assert_eq!(
            source_native_fd_targets(),
            baseline,
            "teardown must release every fd"
        );
        std::fs::remove_dir_all(&setup.dir).unwrap();
    }
    /// P2-I3 concurrent-close control: a close attempted while the gate is
    /// still open (acquisition mid-flight) refuses without disturbing the
    /// live acquisition — which then completes normally — proving the
    /// refused close touched neither custody nor kernel state.
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges, cc"]
    fn source_close_while_live_refuses_and_acquisition_completes() {
        let baseline = source_native_fd_targets();
        let mut setup = source_refusal_setup("close-live");
        let pid = setup.child.pid();
        let marker = setup.dir.join("marker");
        let params = super::source_owner::NativeSourceParams::for_test(
            setup.app.clone(),
            setup.admitted_offset,
            pid,
        );
        let admitted = setup.session.admitted_source_site(&params).unwrap();
        let entry_prog =
            std::os::fd::AsRawFd::as_raw_fd(&setup.session.loaded.progs["observation_entry"]);
        let return_prog =
            std::os::fd::AsRawFd::as_raw_fd(&setup.session.loaded.progs["observation_return"]);
        let (planned, anchor_id, registration_id) = {
            let session = &mut setup.session;
            let owner = session.source_owner.as_mut().expect("source owner");
            let budget = &session.budget;
            owner.note_gate_open_observed().unwrap();
            let domain = owner.arm_domain(pid).unwrap();
            let host_key = owner.enroll_observer().unwrap();
            let scope = super::source_owner::RequestScope {
                site_cookie: admitted.site_cookie,
                host_key,
                incarnation: domain.incarnation,
                planned_image: domain.planned,
                link_offset: admitted.link_offset,
                target_pid: admitted.tgid,
                target: admitted.target,
                expected_artifact: admitted.expected_artifact,
            };
            let anchor = owner
                .anchor_source(&scope, budget, None)
                .unwrap_or_else(|gap| {
                    panic!(
                        "anchor failed: {gap:?} owner: {:?}",
                        owner.take_last_error()
                    )
                });
            // Concurrent close while live: gate open, anchor LIVE, domain
            // ARMED. Must refuse with everything retained.
            let refused = owner.close_source();
            assert!(
                !refused.cut_confirmed,
                "live close must not confirm any cut"
            );
            assert_eq!(refused.first_error, Some(ObservationGap::Invalidated));
            assert_eq!(
                (
                    refused.guards_retired,
                    refused.guards_abandoned,
                    refused.domains_retired
                ),
                (0, 0, 0)
            );
            assert!(
                !refused.order_refused,
                "refused close must not touch the live order"
            );
            assert!(owner.anchor_retained_test());
            assert_eq!(
                owner.guard_life_test(anchor.anchor_id),
                Some(super::source_acquire::GuardLife::Live)
            );
            assert_eq!(
                owner.domain_state_test(pid).unwrap(),
                super::source_owner::contract::DOMAIN_ARMED,
                "no host racing update of the live domain row"
            );
            eprintln!("live close refused with custody retained; continuing");
            // The live acquisition continues undisturbed to READY.
            let registration = owner
                .register_entry_return(&scope, entry_prog, return_prog, &anchor)
                .unwrap_or_else(|gap| {
                    panic!(
                        "entry/return failed after refused close: {gap:?} owner: {:?}",
                        owner.take_last_error()
                    )
                });
            let ready = owner
                .publish_ready(&scope, &anchor, &registration)
                .unwrap_or_else(|gap| {
                    panic!(
                        "ready failed after refused close: {gap:?} owner: {:?}",
                        owner.take_last_error()
                    )
                });
            assert_ne!(ready, 0);
            assert!(owner.acquisition_ready());
            assert_eq!(owner.adopted_link_count(), 2);
            (
                domain.planned,
                anchor.anchor_id,
                registration.registration_id,
            )
        };
        setup.child.release().unwrap();
        let until = Instant::now() + Duration::from_secs(15);
        while !marker.exists() {
            assert!(Instant::now() < until, "exec marker never appeared");
            std::thread::sleep(Duration::from_millis(1));
        }
        while setup.child.peek_exit().unwrap().is_none() {
            assert!(Instant::now() < until, "workload never exited");
            std::thread::yield_now();
        }
        assert_eq!(setup.child.poll_exit().unwrap(), Some(0));
        let lease = super::source_owner::SourceAcquisitionLease::Enabled(params);
        let state = setup
            .session
            .note_source_exec(&lease, pid, planned)
            .unwrap();
        assert_eq!(state, super::source_owner::contract::DOMAIN_ACTIVE);
        setup.gate.close().unwrap();
        let close = setup.session.close_source_explicit().expect("source close");
        assert!(close.cut_confirmed, "close must confirm the cut");
        assert_eq!(
            (
                close.guards_retired,
                close.guards_abandoned,
                close.domains_retired
            ),
            (2, 0, 1)
        );
        assert!(
            !close.order_refused,
            "READY order must stay published at close"
        );
        assert!(close.first_error.is_none());
        assert_eq!(
            setup
                .session
                .source_owner
                .as_ref()
                .expect("source owner")
                .guard_life_test(anchor_id),
            Some(super::source_acquire::GuardLife::Retired)
        );
        assert_eq!(
            setup
                .session
                .source_owner
                .as_ref()
                .expect("source owner")
                .guard_life_test(registration_id),
            Some(super::source_acquire::GuardLife::Retired)
        );
        drop(setup.session);
        drop(setup.gate);
        drop(setup.child);
        assert_eq!(
            source_native_fd_targets(),
            baseline,
            "teardown must release every fd"
        );
        std::fs::remove_dir_all(&setup.dir).unwrap();
    }
    #[test]
    #[ignore = "requires privileged BPF and fresh observation/count objects"]
    fn pooled_discovery_recovers_same_target_without_recharging_or_duplicate_admission() {
        use crate::capture::ClockPort;
        use crate::focused_count::{CountCandidate, CountLimits, FocusedCounter};
        use std::process::{Command, Stdio};
        struct Owned(std::process::Child);
        impl Drop for Owned {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        fn remaining_state(budget: &ObservationBudget) -> usize {
            let (mut low, mut high) = (0, budget.limits.max_state_bytes);
            while low < high {
                let mid = low + (high - low).div_ceil(2);
                if budget.reserve_state(mid).is_ok() {
                    low = mid;
                } else {
                    high = mid - 1;
                }
            }
            low
        }
        let object =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        let count_object =
            std::fs::read(std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT").unwrap()).unwrap();
        for (case, free, prearmed) in [
            ("inventory", 16 << 20, false),
            ("export", (23 << 20) - 1, false),
            ("static_after_api", 16 << 20, true),
        ] {
            let child = Owned(
                Command::new("/usr/bin/openssl")
                    .args([
                        "speed", "-elapsed", "-seconds", "30", "-evp", "SHA512", "-bytes", "64",
                    ])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            std::thread::sleep(Duration::from_millis(100));
            let pid = child.0.id();
            let records = inventory::snapshot(&inventory::SnapshotOptions {
                pids: vec![pid],
                ..Default::default()
            })
            .processes;
            assert_eq!(records.len(), 1);
            let pool = crate::observation_memory::MemoryPool::new(64 << 20);
            let mut budget = ObservationBudget::new(ObservationLimits {
                max_processes: 1,
                ..Default::default()
            });
            budget.memory = Some(pool.clone());
            let mut session = ProviderSession::open_budgeted(budget, &object).unwrap();
            session.set_deadline(Instant::now() + Duration::from_secs(10));
            if prearmed {
                EXPIRE_STATIC.with(|flag| flag.set(true));
                let first = session.reconcile_records(&records);
                assert!(first.gaps.contains(&ObservationGap::SnapshotLag));
                assert!(session.link_count() > 0);
                session.set_deadline(Instant::now() + Duration::from_secs(10));
            }
            let busy = pool.reserve((64 << 20) - free).unwrap();
            let blocked = session.reconcile_records(&records);
            assert!(
                blocked
                    .gaps
                    .iter()
                    .any(|g| matches!(g, ObservationGap::ReadLimit | ObservationGap::StateLimit)),
                "{case}: missing capacity gap"
            );
            let target = session
                .targets
                .get(&pid)
                .expect("temporary refusal must retain acquired process/object custody");
            assert!(
                !target.ready,
                "{case}: shared refusal must not seal incomplete discovery"
            );
            let generation = target.process.generation();
            let reads = session.budget.elf_read_bytes();
            if !prearmed {
                assert_eq!(reads, 0, "{case}: no-IO pool refusal charged reads");
            }
            let state = remaining_state(&session.budget);
            let cookies = session.next_cookie;
            let links = session.link_count();
            for _ in 0..3 {
                session.set_deadline(Instant::now() + Duration::from_secs(10));
                let again = session.reconcile_records(&records);
                assert!(again.static_candidates.is_empty());
                assert!(!session.targets[&pid].ready);
                assert_eq!(session.targets[&pid].process.generation(), generation);
                assert_eq!(
                    session.budget.elf_read_bytes(),
                    reads,
                    "{case}: completed/refused phases were repeated"
                );
                assert_eq!(
                    remaining_state(&session.budget),
                    state,
                    "{case}: retry burned retained state"
                );
                assert_eq!(
                    (session.next_cookie, session.link_count()),
                    (cookies, links)
                );
            }
            drop(busy);
            session.set_deadline(Instant::now() + Duration::from_secs(10));
            let recovered = session.reconcile_records(&records);
            assert!(session.targets[&pid].ready);
            assert!(
                session.budget.elf_read_bytes() >= reads,
                "{case}: actual work was refunded"
            );
            assert_eq!(session.targets[&pid].process.generation(), generation);
            assert!(
                !recovered.static_candidates.is_empty(),
                "{case}: missing recovered physical candidates"
            );
            if prearmed {
                assert_eq!(
                    (session.next_cookie, session.link_count()),
                    (cookies, links)
                );
            }
            let now = crate::capture::LiveClock.checked_monotonic_ns().unwrap();
            let mut counter = FocusedCounter::open(
                &count_object,
                pid,
                crate::focused_capture::observer_namespace().unwrap(),
                CountLimits {
                    window: crate::evidence::CountAdmissionWindow {
                        start_ns: now,
                        deadline_ns: now + 10_000_000_000,
                    },
                    ..Default::default()
                },
            )
            .unwrap();
            let candidates: Vec<_> = recovered
                .static_candidates
                .into_iter()
                .map(CountCandidate::Static)
                .collect();
            counter.attach_candidates(candidates.clone(), now).unwrap();
            let physical = counter.active_site_count();
            counter.attach_candidates(candidates, now).unwrap();
            assert_eq!(
                counter.active_site_count(),
                physical,
                "{case}: duplicate physical admission"
            );
            assert!(
                session
                    .reconcile_records(&records)
                    .static_candidates
                    .is_empty()
            );
            std::thread::sleep(Duration::from_millis(100));
            let count = counter.close(Instant::now() + Duration::from_secs(1));
            let calls: u64 = count
                .sites
                .iter()
                .chain(&count.fenced)
                .map(|s| s.calls)
                .sum();
            let result = session.close_until(Instant::now() + Duration::from_secs(1));
            let api: u64 = result.api_activity.iter().map(|a| a.row.entries).sum();
            assert!(
                calls > 0 && api > 0,
                "{case}: recovery requires separate positive physical/API evidence"
            );
            println!(
                "{case}: same retained generation {generation}, {physical} unique physical sites, {calls} physical entries, {api} API entries; blocked reads={reads}; no repeated read/state/cookie/link charges"
            );
        }
    }
    #[test]
    #[ignore = "requires privileged BPF and fresh observation object"]
    fn reconcile_records_shapes_foreign_backing_refusal() {
        // Root-only choreography: B (a libcrypto-preloaded sleeper in a
        // child user namespace, running as the invoking user) keeps
        // world-readable maps but refuses map_files opens cross-userns;
        // A (forked post-BPF-load, deprivileged to the invoking user)
        // snapshots and reconciles B, so the range-bound opens fail
        // EPERM deterministically and the refusal must shape itself.
        // SAFETY: geteuid has no preconditions and cannot fail.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skip foreign-refusal pin: needs root");
            return;
        }
        let target: u32 = match std::env::var("SUDO_UID").ok().and_then(|v| v.parse().ok()) {
            Some(uid) if uid != 0 => uid,
            _ => {
                eprintln!("skip foreign-refusal pin: needs SUDO_UID of an unprivileged user");
                return;
            }
        };
        // SAFETY: single-threaded test; B only drops privilege and execs.
        let b_pid = unsafe { libc::fork() };
        assert!(b_pid >= 0, "fork failed");
        if b_pid == 0 {
            // SAFETY: dropping from root to the invoking uid; checked.
            if unsafe { libc::setuid(target) } != 0 {
                unsafe { libc::_exit(3) };
            }
            let unshare = std::ffi::CString::new("/usr/bin/unshare").unwrap();
            let dash_u = std::ffi::CString::new("-U").unwrap();
            let env = std::ffi::CString::new("env").unwrap();
            let preload = std::ffi::CString::new("LD_PRELOAD=libcrypto.so.3").unwrap();
            let sleep = std::ffi::CString::new("sleep").unwrap();
            let secs = std::ffi::CString::new("120").unwrap();
            let argv = [
                unshare.as_ptr(),
                dash_u.as_ptr(),
                env.as_ptr(),
                preload.as_ptr(),
                sleep.as_ptr(),
                secs.as_ptr(),
                std::ptr::null(),
            ];
            // SAFETY: argv is NUL-terminated C strings; exec replaces the image.
            unsafe {
                libc::execv(unshare.as_ptr(), argv.as_ptr());
                libc::_exit(3);
            }
        }
        let b_pid = b_pid as u32;
        // Unwind-safe vehicle custody: any panic after the fork
        // (object/session unwraps, pipe/fork asserts, verdict
        // asserts) still kills and reaps the 120-second sleeper.
        // Explicit reaps below disarm the guard first: signalling a
        // reaped pid after reuse could hit another process.
        struct ReapOnDrop {
            pid: libc::pid_t,
            armed: bool,
        }
        impl Drop for ReapOnDrop {
            fn drop(&mut self) {
                if !self.armed {
                    return;
                }
                // The pid is the live unreaped vehicle (every
                // explicit reap disarms first); the shared teardown
                // is EINTR-retried, bounded, and never panics, so it
                // is unwind-safe here.
                crate::target::kill_test_child(self.pid as u32, Duration::from_secs(5));
            }
        }
        let mut vehicle = ReapOnDrop {
            pid: b_pid as libc::pid_t,
            armed: true,
        };
        // Bounded readiness: comm == sleep plus settled maps.
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut stable: Option<String> = None;
        let ready = loop {
            let comm = std::fs::read_to_string(format!("/proc/{b_pid}/comm")).unwrap_or_default();
            let maps_now = std::fs::read_to_string(format!("/proc/{b_pid}/maps")).ok();
            let settled = comm.trim() == "sleep"
                && maps_now.is_some()
                && stable
                    .as_ref()
                    .is_some_and(|last| Some(last) == maps_now.as_ref());
            stable = maps_now;
            if settled {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        if !ready {
            eprintln!("skip foreign-refusal pin: target never settled");
            vehicle.armed = false;
            crate::target::kill_test_child(b_pid, Duration::from_secs(5));
            return;
        }
        let object =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        let mut session = ProviderSession::open(
            ObservationLimits {
                max_processes: 1,
                ..Default::default()
            },
            &object,
        )
        .unwrap();
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: fds points to two writable ints; return checked.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: single-threaded test; A only snapshots/reconciles with
        // COW-local session state, reports one byte, and _exits.
        let forked = unsafe { libc::fork() };
        assert!(forked >= 0, "fork failed");
        if forked == 0 {
            // SAFETY: we own fds[0]; closing the unused read end.
            unsafe { libc::close(fds[0]) };
            // SAFETY: dropping from root to the invoking uid; checked.
            let verdict: u8 = if unsafe { libc::setuid(target) } != 0 {
                0
            } else {
                // Direct shape probe: maps must read, one file-backed
                // range's entry must refuse with a permission errno.
                let shape = (|| {
                    let maps = std::fs::read_to_string(format!("/proc/{b_pid}/maps")).ok()?;
                    let range = maps.lines().find_map(|line| {
                        let mut fields = line.split_ascii_whitespace();
                        let range = fields.next()?;
                        fields.next()?;
                        fields.next()?;
                        fields.next()?;
                        (fields.next()? != "0").then_some(range)
                    })?;
                    match std::fs::File::open(format!("/proc/{b_pid}/map_files/{range}")) {
                        Ok(_) => None,
                        Err(e) => e.raw_os_error(),
                    }
                })();
                match shape {
                    Some(errno) if errno == libc::EPERM || errno == libc::EACCES => {
                        let records = inventory::snapshot(&inventory::SnapshotOptions {
                            pids: vec![b_pid],
                            ..Default::default()
                        })
                        .processes;
                        if records.len() != 1 {
                            2
                        } else {
                            // A silently failed LD_PRELOAD leaves no
                            // operational exports, so acquisition is
                            // correctly skipped and there is no refusal
                            // to shape: skip, don't fail.
                            let observable = records[0].modules.iter().any(|m| {
                                m.info.exports.iter().any(|api| {
                                    api.operational_id().is_some()
                                        || (1..=16).any(|id| {
                                            wire::api(id) == Ok(ObservationApi::Inventoried(*api))
                                        })
                                })
                            });
                            if !observable {
                                2
                            } else {
                                session.set_deadline(Instant::now() + Duration::from_secs(10));
                                let batch = session.reconcile_records(&records);
                                u8::from(
                                    batch
                                        .refusals
                                        .iter()
                                        .any(|r| r == "backing-denied:permission-denied"),
                                )
                            }
                        }
                    }
                    _ => 2,
                }
            };
            // Best-effort report: any write failure ends here and the
            // parent fails on the short read.
            let _ = crate::target::write_all_pipe(fds[1], &[verdict]);
            // SAFETY: fds[1] is the owned pipe end; _exit never returns.
            unsafe {
                libc::close(fds[1]);
                libc::_exit(0);
            }
        }
        // SAFETY: we own fds[1]; closing the unused write end.
        unsafe { libc::close(fds[1]) };
        // One deadline spans the verdict read and the worker's exit:
        // a worker that never reports — or reports and never exits —
        // fails the pin, never hangs the suite. Waits are
        // EINTR-retried; an interrupted wait never reads as an
        // exited child. The vehicle guard reaps B on every unwind.
        let verdict_deadline = Instant::now() + Duration::from_secs(120);
        let mut buf = [0u8; 1];
        if let Err(e) = crate::target::read_exact_deadline(fds[0], &mut buf, verdict_deadline) {
            crate::target::kill_test_child(forked as u32, Duration::from_secs(5));
            // SAFETY: we own fds[0].
            unsafe { libc::close(fds[0]) };
            panic!("foreign-refusal pin verdict unread ({e}); worker killed");
        }
        // SAFETY: we own fds[0].
        unsafe { libc::close(fds[0]) };
        match crate::target::wait_test_child(forked as u32, verdict_deadline) {
            crate::target::TestChildWait::Reaped(status) => assert!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "foreign-refusal pin worker exited abnormally: {status}"
            ),
            crate::target::TestChildWait::Gone => {
                panic!("foreign-refusal pin worker reaped elsewhere (sole-reaper violated)")
            }
            crate::target::TestChildWait::Timeout => {
                crate::target::kill_test_child(forked as u32, Duration::from_secs(5));
                panic!("foreign-refusal pin worker reported but never exited; killed");
            }
        }
        vehicle.armed = false;
        crate::target::kill_test_child(b_pid, Duration::from_secs(5));
        match buf[0] {
            1 => {}
            2 => {
                eprintln!("skip foreign-refusal pin: shape absent on this kernel");
                return;
            }
            _ => panic!("foreign backing refusal was not shaped"),
        }
    }

    #[test]
    #[ignore = "requires privileged BPF and fresh observation object"]
    fn verified_inventory_recovers_a_previously_refused_locator() {
        use std::process::{Command, Stdio};
        struct Owned(std::process::Child);
        impl Drop for Owned {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let child = Owned(
            Command::new("/usr/bin/openssl")
                .args([
                    "speed", "-elapsed", "-seconds", "30", "-evp", "SHA512", "-bytes", "64",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        std::thread::sleep(Duration::from_millis(100));
        let records = inventory::snapshot(&inventory::SnapshotOptions {
            pids: vec![child.0.id()],
            ..Default::default()
        })
        .processes;
        assert_eq!(records.len(), 1);
        let mut locators = records.clone();
        let library = locators[0]
            .modules
            .iter_mut()
            .find(|m| {
                m.info
                    .exports
                    .iter()
                    .any(|api| api.operational_id().is_some())
            })
            .unwrap();
        assert_eq!(library.identity_status, inventory::IdentityStatus::Verified);
        let library_hash: ObjectHash = library.info.sha256.clone().try_into().unwrap();
        library.identity_status = inventory::IdentityStatus::LocatorCandidate;
        let object =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        let mut session = ProviderSession::open(
            ObservationLimits {
                max_processes: 1,
                ..Default::default()
            },
            &object,
        )
        .unwrap();
        session.set_deadline(Instant::now() + Duration::from_secs(10));
        let first = session.reconcile_records(&locators);
        assert!(first.gaps.contains(&ObservationGap::IdentityUnverified));
        assert!(
            !first
                .static_candidates
                .iter()
                .any(|c| c.site().object_hash() == &library_hash)
        );
        drop(first);
        let original = session.targets[&child.0.id()].process.generation();
        // Stable locator-only snapshots must not promote or churn custody.
        session.reconcile_records(&locators);
        assert_eq!(
            session.targets[&child.0.id()].process.generation(),
            original
        );
        session.set_deadline(Instant::now() + Duration::from_secs(10));
        // A newly verified inventory row is only a reason for fresh acquisition.
        let retirement = session.reconcile_records(&records);
        assert_eq!(retirement.refreshed_processes, vec![child.0.id()]);
        assert!(retirement.static_candidates.is_empty());
        assert!(!retirement.gaps.contains(&ObservationGap::ProcessChanged));
        let recovered = session.reconcile_records(&records);
        assert!(
            recovered
                .static_candidates
                .iter()
                .any(|c| c.site().object_hash() == &library_hash),
            "verified inventory never reacquired the refused library"
        );
        assert_ne!(
            session.targets[&child.0.id()].process.generation(),
            original
        );
        let generation = session.targets[&child.0.id()].process.generation();
        let cookies = session.next_cookie;
        let reads = session.budget.elf_read_bytes();
        let again = session.reconcile_records(&records);
        assert!(again.refreshed_processes.is_empty());
        assert!(again.static_candidates.is_empty());
        assert_eq!(
            session.targets[&child.0.id()].process.generation(),
            generation
        );
        assert_eq!(session.next_cookie, cookies);
        assert_eq!(session.budget.elf_read_bytes(), reads);
        std::thread::sleep(Duration::from_millis(100));
        let final_batch = session.close_until(Instant::now() + Duration::from_secs(1));
        assert!(final_batch.api_activity.iter().any(|a| a.row.entries > 0));
    }

    #[test]
    #[ignore = "requires privileged BPF and fresh observation object"]
    fn discovery_tick_expiry_resumes_same_admitted_process() {
        let argv = [
            "/usr/bin/openssl",
            "speed",
            "-elapsed",
            "-seconds",
            "8",
            "-evp",
            "SHA512",
            "-bytes",
            "64",
        ]
        .map(str::to_owned)
        .to_vec();
        let mut child =
            crate::target::OwnedTarget::spawn_stopped(&argv, crate::target::WorkloadDest::Null)
                .unwrap();
        child.release_retaining_exit().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let records = inventory::snapshot(&inventory::SnapshotOptions {
            pids: vec![child.pid()],
            ..Default::default()
        })
        .processes;
        assert_eq!(records.len(), 1);
        let object =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        let mut session = ProviderSession::open(
            ObservationLimits {
                max_processes: 1,
                ..Default::default()
            },
            &object,
        )
        .unwrap();
        use crate::provider_observation::objects::{EXPIRE_ACQUIRE, EXPIRE_CANDIDATE};
        session.set_deadline(Instant::now() + Duration::from_secs(10));
        EXPIRE_ACQUIRE.with(|flag| flag.set(true));
        let acquire = session.reconcile_records(&records);
        assert!(acquire.gaps.contains(&ObservationGap::SnapshotLag));
        assert!(session.targets.is_empty());
        session.set_deadline(Instant::now() + Duration::from_secs(10));
        EXPIRE_STATIC.with(|flag| flag.set(true));
        let first = session.reconcile_records(&records);
        assert!(first.static_candidates.is_empty());
        assert!(first.gaps.contains(&ObservationGap::SnapshotLag));
        assert!(!first.gaps.contains(&ObservationGap::ProcessLimit));
        assert!(!session.targets[&child.pid()].ready);
        let cookies = session.next_cookie;
        session.set_deadline(Instant::now() + Duration::from_secs(10));
        EXPIRE_CANDIDATE.with(|flag| flag.set(true));
        let partial = session.reconcile_records(&records);
        assert!(partial.gaps.contains(&ObservationGap::SnapshotLag));
        assert!(partial.static_candidates.is_empty());
        let read_prefix = session.budget.elf_read_bytes();
        session.set_deadline(Instant::now() + Duration::from_secs(10));
        let second = session.reconcile_records(&records);
        assert!(
            !second.gaps.contains(&ObservationGap::ProcessLimit),
            "deadline leaked the only admission"
        );
        assert!(
            !second.static_candidates.is_empty(),
            "deadline cached incomplete static discovery"
        );
        assert_eq!(session.next_cookie, cookies, "API links were replayed");
        assert!(
            session.budget.elf_read_bytes() >= read_prefix,
            "real reads were refunded"
        );
        assert!(session.targets[&child.pid()].ready);
        eprintln!(
            "discovery resumed: candidates={}, API cookie high-water={}, charged reads={}",
            second.static_candidates.len(),
            cookies,
            session.budget.elf_read_bytes()
        );
        assert!(session.link_count() > 0);
        assert!(
            session
                .reconcile_records(&records)
                .static_candidates
                .is_empty(),
            "completed target rediscovered"
        );
        use crate::capture::ClockPort;
        let count_object =
            std::fs::read(std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT").unwrap()).unwrap();
        let now = crate::capture::LiveClock.checked_monotonic_ns().unwrap();
        let mut counter = crate::focused_count::FocusedCounter::open(
            &count_object,
            child.pid(),
            crate::focused_capture::observer_namespace().unwrap(),
            crate::focused_count::CountLimits {
                window: crate::evidence::CountAdmissionWindow {
                    start_ns: now,
                    deadline_ns: now + 10_000_000_000,
                },
                ..Default::default()
            },
        )
        .unwrap();
        counter
            .attach_candidates(
                second
                    .static_candidates
                    .into_iter()
                    .map(crate::focused_count::CountCandidate::Static)
                    .collect(),
                now,
            )
            .unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let counts = counter.close(Instant::now() + Duration::from_secs(1));
        let calls: u64 = counts
            .sites
            .iter()
            .chain(&counts.fenced)
            .map(|s| s.calls)
            .sum();
        assert!(
            calls > 0,
            "resumed static candidates did not retain native counts"
        );
        eprintln!("resumed discovery native calls={calls}");
        session.close_until(Instant::now() + Duration::from_millis(100));
        child.finish_observation().unwrap();
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
#[path = "../../tests/support/provider_forwarder.rs"]
mod startup_fixture;
#[cfg(all(test, target_arch = "x86_64"))]
mod startup_api_controls {
    use super::*;
    // A held child inherits all concurrent parent fixture maps. Keep their
    // lifetimes separate so another test cannot unlink an inherited code file.
    static MAPPED_FIXTURES: std::sync::Mutex<()> = std::sync::Mutex::new(());
    struct FixtureMapping(*mut libc::c_void, usize);
    impl Drop for FixtureMapping {
        fn drop(&mut self) {
            unsafe {
                libc::munmap(self.0, self.1);
            }
        }
    }
    struct ReconcileFixture {
        child: crate::target::OwnedTarget,
        startup: BTreeMap<u32, Vec<Attachment>>,
        targets: BTreeMap<u32, Target>,
        record: inventory::ProcessRecord,
        link_peer: std::os::unix::net::UnixStream,
        _mapping: FixtureMapping,
        _file: startup_fixture::ForwarderFixture,
        budget: ObservationBudget,
    }
    fn reconcile_fixture(adopted: bool) -> ReconcileFixture {
        let f = startup_fixture::ForwarderFixture::new(
            ".byte 0xe9\n.long query_impl-.-4",
            ".byte 0xeb\n.byte unquery_impl-.-1",
        );
        let file = f.file();
        let len = file.metadata().unwrap().len() as usize;
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        assert_ne!(address, libc::MAP_FAILED);
        let mapping = FixtureMapping(address, len);
        let child = crate::target::OwnedTarget::spawn_stopped(
            &["/bin/true".into()],
            crate::target::WorkloadDest::Null,
        )
        .unwrap();
        let budget = ObservationBudget::default();
        let mapped_file = file.try_clone().unwrap();
        let objects::StartupCandidates { apis: sites, .. } = objects::startup_candidates(
            objects::StartupProcess::held(&child).unwrap(),
            file,
            &budget,
            None,
        )
        .unwrap();
        let (_, site) = sites
            .into_iter()
            .map(|s| s.into_parts())
            .find(|(api, _)| *api == wire::api(c::PUBLIC_QUERY).unwrap())
            .unwrap();
        let mut attachment = Attachment {
            object: object_id(&site),
            site,
            links: Vec::new(),
            cookie: 81,
            api: c::PUBLIC_QUERY,
            generation: 19,
            advertisers: Vec::new(),
            original: None,
            historical: false,
        };
        let (link, link_peer) = std::os::unix::net::UnixStream::pair().unwrap();
        link_peer.set_nonblocking(true).unwrap();
        attachment.links.push(link.into());
        let record = inventory::snapshot(&inventory::SnapshotOptions {
            pids: vec![child.pid()],
            ..Default::default()
        })
        .processes
        .remove(0);
        let mut targets = BTreeMap::new();
        let mut startup = BTreeMap::new();
        if adopted {
            let process = objects::fixture_support::mapped_process(&record, mapped_file, &budget);
            let mapped = process
                .resolve_api(wire::api(c::PUBLIC_QUERY).unwrap())
                .into_iter()
                .find(|s| s.site.object_hash() == attachment.site.object_hash())
                .unwrap()
                .site;
            attachment.adopt_site(mapped).unwrap();
            targets.insert(
                child.pid(),
                Target {
                    process,
                    starttime: record.starttime,
                    generation: 19,
                    attachments: vec![attachment],
                    ranges: 1,
                    ready: true,
                },
            );
        } else {
            startup.insert(child.pid(), vec![attachment]);
        }
        ReconcileFixture {
            child,
            startup,
            targets,
            record,
            link_peer,
            _mapping: mapping,
            _file: f,
            budget,
        }
    }
    #[test]
    fn final_cut_mixed_sources_require_each_attachments_own_terminal_authority() {
        let _fixtures = MAPPED_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
        for case in ["live", "terminal", "permanent", "nonterminal-unavailable"] {
            let mut fixture = reconcile_fixture(true);
            let pid = fixture.child.pid();
            let target = fixture.targets.get_mut(&pid).unwrap();
            let site = target
                .process
                .resolve_api(wire::api(c::PUBLIC_UNQUERY).unwrap())
                .remove(0)
                .site;
            assert!(!site.is_startup());
            let (link, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
            peer.set_nonblocking(true).unwrap();
            target.attachments.push(Attachment {
                object: object_id(&site),
                site,
                cookie: 82,
                api: c::PUBLIC_UNQUERY,
                links: vec![link.into()],
                generation: 19,
                advertisers: Vec::new(),
                original: None,
                historical: false,
            });
            if case == "permanent" {
                target
                    .process
                    .remember_refusal(ObservationGap::ObjectChanged);
            }
            if case == "nonterminal-unavailable" {
                objects::fixture_support::lose_mapped_process_directory(&mut target.process);
                assert_eq!(
                    target.process.revalidate_fresh(),
                    Err(ObservationGap::ProcessUnavailable)
                );
            }
            if matches!(case, "terminal" | "permanent") {
                fixture.child.finish_observation().unwrap();
            }
            let mut terminal = BTreeSet::new();
            let refused = final_source_refusals(
                &fixture.targets,
                &fixture.startup,
                &mut ObservationBatch::default(),
                Instant::now() + Duration::from_secs(2),
                &mut terminal,
            );
            let record = |cookie, api| c::Record {
                pid,
                cookie,
                api,
                generation: 19,
                ..Default::default()
            };
            let original = final_record_binding(
                &fixture.targets,
                &fixture.startup,
                &refused,
                &terminal,
                &record(81, c::PUBLIC_QUERY),
            );
            let mapped = final_record_binding(
                &fixture.targets,
                &fixture.startup,
                &refused,
                &terminal,
                &record(82, c::PUBLIC_UNQUERY),
            );
            if case == "live" {
                assert!(original.unwrap().unwrap().process.is_some());
                assert!(mapped.unwrap().unwrap().process.is_some());
            } else if case == "terminal" {
                assert!(
                    mapped.is_err(),
                    "terminal PID fallback admitted a mapped-only cookie"
                );
                assert!(
                    original.unwrap().unwrap().process.is_none(),
                    "terminal original retained live relocation authority"
                );
            } else {
                assert!(original.is_err());
                assert!(mapped.is_err());
            }
            use std::io::Read;
            assert_eq!(fixture.targets[&pid].attachments.len(), 2);
            assert_eq!(
                fixture.link_peer.read(&mut [0]).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            assert_eq!(
                peer.read(&mut [0]).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
    }
    #[test]
    fn final_cut_validation_retains_terminal_owners_and_permanent_refusals() {
        let _fixtures = MAPPED_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
        for poisoned in [false, true] {
            let mut fixture = reconcile_fixture(true);
            let pid = fixture.child.pid();
            if poisoned {
                fixture.targets[&pid]
                    .process
                    .remember_refusal(ObservationGap::ObjectChanged);
            }
            fixture.child.finish_observation().unwrap();
            let mut batch = ObservationBatch::default();
            let refused = final_source_refusals(
                &fixture.targets,
                &fixture.startup,
                &mut batch,
                Instant::now() + Duration::from_secs(2),
                &mut BTreeSet::new(),
            );
            assert_eq!(
                refused.get(&pid).copied(),
                poisoned.then_some(ObservationGap::ObjectChanged)
            );
            // Validation must not close links or erase binding owners, including
            // rejected sources: disposal belongs after bounded decode/seal.
            assert_eq!(fixture.targets[&pid].attachments.len(), 1);
            use std::io::Read;
            assert_eq!(
                fixture.link_peer.read(&mut [0]).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            let r = c::Record {
                pid,
                cookie: 81,
                api: c::PUBLIC_QUERY,
                generation: 19,
                ..Default::default()
            };
            assert!(
                record_binding(&fixture.targets, &fixture.startup, &r)
                    .unwrap()
                    .is_some()
            );
        }
    }
    #[test]
    fn terminal_reconcile_before_drain_preserves_startup_and_adopted_query_owners() {
        let _fixtures = MAPPED_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
        for stage in ["startup", "adopted", "partial"] {
            let adopted = stage != "startup";
            let mut fixture = reconcile_fixture(adopted);
            let pid = fixture.child.pid();
            if stage == "partial" {
                // First construction has moved the physical owner into Target,
                // but adoption's initial validation can fail before replacement.
                let attachment = &mut fixture.targets.get_mut(&pid).unwrap().attachments[0];
                attachment.site = attachment.original.take().unwrap();
            }
            let mut r = c::Record {
                version: c::VERSION,
                size: 96,
                kind: c::ALGORITHM_BEGIN,
                pid,
                tid: pid,
                cookie: 81,
                generation: 19,
                invocation: 7,
                api: c::PUBLIC_QUERY,
                operation: 1,
                outcome: 1,
                cacheability: 1,
                ..Default::default()
            };
            let decode = |r: &c::Record| {
                wire::decode_transport(unsafe {
                    std::slice::from_raw_parts((r as *const c::Record).cast(), 96)
                })
                .unwrap()
            };
            let identity = record_binding(&fixture.targets, &fixture.startup, &r)
                .unwrap()
                .unwrap();
            let hash = identity.attachment.site.object_hash().clone();
            let object = identity.attachment.object;
            let file_fd = identity
                .attachment
                .original
                .as_ref()
                .unwrap_or(&identity.attachment.site)
                .attachment_fd()
                .as_raw_fd();
            let link_fd = identity.attachment.links[0].as_raw_fd();
            let mut aliases = super::super::assembly::Sequences::default();
            let mut batch = ObservationBatch::default();
            assert!(
                assemble_payload(decode(&r), &mut aliases, &fixture.budget, &mut batch).is_none()
            );
            fixture.child.release_retaining_exit().unwrap();
            let until = Instant::now() + Duration::from_secs(2);
            while fixture.child.peek_exit().unwrap().is_none() {
                assert!(Instant::now() < until);
                std::thread::yield_now();
            }
            // The same first-acquisition / mapped-revalidation failure decisions
            // used by reconcile, before the subsequent queued transport drain.
            let gap = if adopted {
                reconcile_retirement_gap(
                    Some(fixture.record.starttime),
                    fixture.record.starttime,
                    || fixture.targets[&pid].process.revalidate_fresh(),
                )
                .unwrap()
            } else {
                objects::acquire_incarnation(&fixture.record)
                    .err()
                    .expect("terminal first acquisition fails")
            };
            assert!(
                identity_failure(gap),
                "host stimulus must reach reconcile's actual retirement branch"
            );
            let mut membership = true;
            let mut code_ranges = usize::from(adopted);
            let kept = retire_source_owners(
                (&mut fixture.startup, &mut fixture.targets),
                &mut aliases,
                pid,
                Some(&fixture.record),
                gap,
                &mut batch,
                |_, _| {
                    assert!(unsafe { libc::fcntl(file_fd, libc::F_GETFD) } >= 0);
                    assert!(unsafe { libc::fcntl(link_fd, libc::F_GETFD) } >= 0);
                    membership = false;
                    code_ranges = 0;
                    Ok(())
                },
            );
            assert!(
                kept,
                "reconcile erased validated terminal original owner; adopted={adopted}"
            );
            assert!(!membership && code_ranges == 0);
            assert!(
                fixture.targets.is_empty(),
                "terminal reconcile retained mapped relocation authority"
            );
            assert!(
                fixture
                    .startup
                    .get(&pid)
                    .is_some_and(|rows| !rows.is_empty()),
                "retirement dropped terminal owner at {stage} stage"
            );
            assert!(
                aliases.incomplete(),
                "retirement orphaned a pending alias boundary"
            );
            use std::io::Read;
            assert_eq!(
                fixture.link_peer.read(&mut [0]).unwrap(),
                0,
                "terminal history retained an armed link"
            );
            assert!(unsafe { libc::fcntl(file_fd, libc::F_GETFD) } >= 0);
            let binding = record_binding(&fixture.targets, &fixture.startup, &r)
                .unwrap()
                .unwrap();
            assert!(binding.process.is_none());
            assert!(binding.attachment.historical);
            assert!(
                binding.attachment.site.revalidate_object().is_err(),
                "historical source cannot authorize a new attachment"
            );
            assert_eq!(
                (
                    binding.attachment.cookie,
                    binding.attachment.generation,
                    binding.attachment.object
                ),
                (81, 19, object)
            );
            assert_eq!(binding.starttime, fixture.record.starttime);
            assert_eq!(binding.attachment.site.object_hash(), &hash);
            let mut query = r;
            query.invocation = 8;
            query.kind = c::QUERY;
            let mut begin = query;
            begin.kind = c::ALGORITHM_BEGIN;
            r.kind = c::ALIAS;
            r.algorithm = c::OTHER;
            r.function = c::OTHER;
            r.outcome = 0;
            let mut end = r;
            end.kind = c::ALIAS_END;
            end.function = 1;
            let mut alias8 = r;
            alias8.invocation = 8;
            let mut end8 = end;
            end8.invocation = 8;
            let mut query_results = 0;
            let mut advertisements = 0;
            for queued in [r, end, query, begin, alias8, end8] {
                let binding = record_binding(&fixture.targets, &fixture.startup, &queued)
                    .unwrap()
                    .unwrap();
                assert!(binding.process.is_none());
                assert_eq!(binding.attachment.site.object_hash(), &hash);
                if let Some(payload) =
                    assemble_payload(decode(&queued), &mut aliases, &fixture.budget, &mut batch)
                {
                    match payload {
                        ObservationPayload::QueryResult { .. } => query_results += 1,
                        ObservationPayload::Algorithm { .. } => advertisements += 1,
                        _ => (),
                    }
                }
            }
            assert_eq!((query_results, advertisements), (1, 2));
            assert!(!aliases.incomplete());
            assert!(batch.learned_sites.is_empty());
            assert!(batch.gaps.contains(&ObservationGap::ProcessUnavailable));
            assert!(batch.gaps.contains(&ObservationGap::IntervalUnknown));
            fixture.child.finish_observation().unwrap();
        }
    }
    #[test]
    fn terminal_reconcile_refuses_readable_mismatches_conflicts_and_live_failure() {
        let _fixtures = MAPPED_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
        for adopted in [false, true] {
            for case in ["live", "starttime", "namespace", "object", "role"] {
                let mut fixture = reconcile_fixture(adopted);
                let pid = fixture.child.pid();
                let r = c::Record {
                    pid,
                    tid: pid,
                    cookie: 81,
                    generation: 19,
                    api: c::PUBLIC_QUERY,
                    ..Default::default()
                };
                if case != "live" {
                    fixture.child.release_retaining_exit().unwrap();
                    let until = Instant::now() + Duration::from_secs(2);
                    while fixture.child.peek_exit().unwrap().is_none() {
                        assert!(Instant::now() < until);
                        std::thread::yield_now();
                    }
                }
                match case {
                    "starttime" => fixture.record.starttime += 1,
                    "namespace" => fixture.record.namespaces.pid.as_mut().unwrap().inode += 1,
                    "object" => {
                        use std::os::unix::fs::PermissionsExt;
                        let binding = record_binding(&fixture.targets, &fixture.startup, &r)
                            .unwrap()
                            .unwrap();
                        let file = format!(
                            "/proc/self/fd/{}",
                            binding.attachment.site.attachment_fd().as_raw_fd()
                        );
                        std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600))
                            .unwrap();
                    }
                    _ => (),
                }
                let mut aliases = super::super::assembly::Sequences::default();
                let mut batch = ObservationBatch::default();
                let gap = if case == "role" {
                    ObservationGap::AmbiguousSite
                } else {
                    ObservationGap::BackingUnavailable
                };
                assert!(
                    !retire_source_owners(
                        (&mut fixture.startup, &mut fixture.targets),
                        &mut aliases,
                        pid,
                        Some(&fixture.record),
                        gap,
                        &mut batch,
                        |_, _| Ok(())
                    ),
                    "generic failure became historical authority: case={case}, adopted={adopted}"
                );
                assert!(
                    record_binding(&fixture.targets, &fixture.startup, &r)
                        .unwrap()
                        .is_none()
                );
                assert!(fixture.startup.is_empty() && fixture.targets.is_empty());
                match case {
                    "starttime" => assert!(batch.gaps.contains(&ObservationGap::ProcessChanged)),
                    "namespace" => assert!(batch.gaps.contains(&ObservationGap::NamespaceChanged)),
                    "object" => assert!(batch.gaps.contains(&ObservationGap::ObjectChanged)),
                    _ => (),
                }
                if case != "live" {
                    fixture.child.finish_observation().unwrap();
                }
            }
        }
    }
    fn comparison_then_exit(comparison: ObservationGap) {
        let _fixtures = MAPPED_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
        for adopted in [false, true] {
            let mut fixture = reconcile_fixture(adopted);
            let pid = fixture.child.pid();
            // Obtain the failure from an actual readable identity comparison.
            // The snapshot passed to retirement remains the prior matching one.
            let confirmed = if comparison == ObservationGap::ProcessUnavailable {
                None
            } else {
                let mut compared = fixture.record.clone();
                match comparison {
                    ObservationGap::NamespaceChanged => {
                        compared.namespaces.mount.as_mut().unwrap().inode += 1
                    }
                    ObservationGap::ProcessChanged => compared.starttime += 1,
                    _ => unreachable!(),
                }
                let gap = objects::acquire_incarnation(&compared)
                    .err()
                    .expect("readable comparison must fail");
                assert_eq!(gap, comparison);
                Some(gap)
            };
            fixture.child.release_retaining_exit().unwrap();
            let until = Instant::now() + Duration::from_secs(2);
            while fixture.child.peek_exit().unwrap().is_none() {
                assert!(Instant::now() < until);
                std::thread::yield_now();
            }
            let unavailable = objects::acquire_incarnation(&fixture.record).err().unwrap();
            // This second observation is absence, not evidence of a mismatch.
            if confirmed.is_none() {
                assert_eq!(unavailable, ObservationGap::ProcessUnavailable);
            }
            let gap = confirmed.unwrap_or(unavailable);
            let r = c::Record {
                pid,
                tid: pid,
                cookie: 81,
                generation: 19,
                api: c::PUBLIC_QUERY,
                ..Default::default()
            };
            let mut aliases = super::super::assembly::Sequences::default();
            let mut batch = ObservationBatch::default();
            let preserve = retire_source_owners(
                (&mut fixture.startup, &mut fixture.targets),
                &mut aliases,
                pid,
                Some(&fixture.record),
                gap,
                &mut batch,
                |_, _| Ok(()),
            );
            if confirmed.is_some() {
                assert!(
                    !preserve,
                    "confirmed {comparison:?} was overwritten by later exit/unavailability; adopted={adopted}"
                );
                assert!(
                    record_binding(&fixture.targets, &fixture.startup, &r)
                        .unwrap()
                        .is_none()
                );
                assert!(fixture.startup.is_empty() && fixture.targets.is_empty());
            } else {
                assert!(
                    preserve,
                    "unavailable post-exit observation lost valid original queued ownership"
                );
                let binding = record_binding(&fixture.targets, &fixture.startup, &r)
                    .unwrap()
                    .unwrap();
                assert!(binding.attachment.historical && binding.process.is_none());
                assert!(binding.attachment.links.is_empty());
                assert!(batch.gaps.contains(&ObservationGap::ProcessUnavailable));
            }
            fixture.child.finish_observation().unwrap();
        }
    }
    #[test]
    fn confirmed_namespace_mismatch_cannot_be_overridden_by_later_exit() {
        comparison_then_exit(ObservationGap::NamespaceChanged);
    }
    #[test]
    fn confirmed_process_mismatch_cannot_be_overridden_by_later_exit() {
        comparison_then_exit(ObservationGap::ProcessChanged);
    }
    #[test]
    fn unavailable_post_exit_observation_preserves_only_original_history() {
        comparison_then_exit(ObservationGap::ProcessUnavailable);
    }
    #[test]
    fn cached_confirmed_mismatch_survives_a_later_unavailable_return() {
        let _fixtures = MAPPED_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
        for namespace in [true, false] {
            let mut fixture = reconcile_fixture(true);
            let pid = fixture.child.pid();
            let mut compared = fixture.record.clone();
            if namespace {
                compared.namespaces.mount.as_mut().unwrap().inode += 1;
            } else {
                compared.starttime += 1;
            }
            let confirmed = objects::acquire_incarnation(&compared).err().unwrap();
            assert_eq!(
                confirmed,
                if namespace {
                    ObservationGap::NamespaceChanged
                } else {
                    ObservationGap::ProcessChanged
                }
            );
            objects::fixture_support::remember_compared_failure(
                &fixture.targets[&pid].process,
                &compared,
            );
            fixture.child.release_retaining_exit().unwrap();
            let until = Instant::now() + Duration::from_secs(2);
            while fixture.child.peek_exit().unwrap().is_none() {
                assert!(Instant::now() < until);
                std::thread::yield_now();
            }
            let later = fixture.targets[&pid]
                .process
                .revalidate_fresh()
                .unwrap_err();
            assert_eq!(later, ObservationGap::ProcessUnavailable);
            let mut aliases = super::super::assembly::Sequences::default();
            let mut batch = ObservationBatch::default();
            assert!(
                !retire_source_owners(
                    (&mut fixture.startup, &mut fixture.targets),
                    &mut aliases,
                    pid,
                    None,
                    later,
                    &mut batch,
                    |_, _| Ok(())
                ),
                "cached confirmed {confirmed:?} was lost behind later unavailability"
            );
            assert!(fixture.startup.is_empty() && fixture.targets.is_empty());
            fixture.child.finish_observation().unwrap();
        }
    }
    #[test]
    fn cold_attach_refusal_retires_before_later_exit_can_override_it() {
        let _fixtures = MAPPED_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
        for expected in [
            ObservationGap::NamespaceChanged,
            ObservationGap::ProcessChanged,
            ObservationGap::ProcessUnavailable,
        ] {
            let mut fixture = reconcile_fixture(true);
            let pid = fixture.child.pid();
            let mut compared = fixture.record.clone();
            match expected {
                ObservationGap::NamespaceChanged => {
                    compared.namespaces.mount.as_mut().unwrap().inode += 1
                }
                ObservationGap::ProcessChanged => compared.starttime += 1,
                _ => (),
            }
            let mut batch = ObservationBatch::default();
            let mut later_signature = false;
            let confirmed = if expected == ObservationGap::ProcessUnavailable {
                None
            } else {
                Some(objects::acquire_incarnation(&compared).err().unwrap())
            };
            if let Some(gap) = confirmed {
                assert_eq!(gap, expected);
            }
            // Enter the exact cold attach-pair error branch. Its propagated
            // reason must survive before any later signature can be attempted.
            let setup = (|| {
                cold_attach_error(confirmed.unwrap_or(expected), &mut batch)?;
                later_signature = true;
                Ok(())
            })();
            fixture.child.release_retaining_exit().unwrap();
            let until = Instant::now() + Duration::from_secs(2);
            while fixture.child.peek_exit().unwrap().is_none() {
                assert!(Instant::now() < until);
                std::thread::yield_now();
            }
            let unavailable = fixture.targets[&pid]
                .process
                .revalidate_fresh()
                .unwrap_err();
            assert_eq!(unavailable, ObservationGap::ProcessUnavailable);
            let mut aliases = super::super::assembly::Sequences::default();
            let preserve = retire_source_owners(
                (&mut fixture.startup, &mut fixture.targets),
                &mut aliases,
                pid,
                None,
                setup.err().unwrap_or(unavailable),
                &mut batch,
                |_, _| Ok(()),
            );
            if confirmed.is_some() {
                assert!(
                    !later_signature,
                    "cold {expected:?} permitted another signature attempt"
                );
                assert!(
                    !preserve,
                    "cold {expected:?} was replaced by later unavailability"
                );
                assert!(fixture.startup.is_empty() && fixture.targets.is_empty());
            } else {
                assert!(
                    later_signature && preserve,
                    "unavailability requires independent terminal-original checks"
                );
                assert!(fixture.targets.is_empty());
                assert!(
                    fixture.startup[&pid]
                        .iter()
                        .all(|a| a.historical && a.links.is_empty())
                );
            }
            assert!(batch.gaps.contains(&expected));
            fixture.child.finish_observation().unwrap();
        }
    }
    #[test]
    fn ordinary_cold_attach_failure_remains_partial() {
        let mut batch = ObservationBatch::default();
        assert_eq!(
            cold_attach_error(ObservationGap::AttachFailed, &mut batch),
            Ok(())
        );
        assert!(batch.gaps.contains(&ObservationGap::AttachFailed));
    }
    #[test]
    fn cold_attach_unavailability_does_not_grant_live_history() {
        let _fixtures = MAPPED_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
        let mut fixture = reconcile_fixture(true);
        let pid = fixture.child.pid();
        let mut batch = ObservationBatch::default();
        assert_eq!(
            cold_attach_error(ObservationGap::ProcessUnavailable, &mut batch),
            Ok(())
        );
        let mut aliases = super::super::assembly::Sequences::default();
        assert!(
            !retire_source_owners(
                (&mut fixture.startup, &mut fixture.targets),
                &mut aliases,
                pid,
                None,
                ObservationGap::ProcessUnavailable,
                &mut batch,
                |_, _| Ok(())
            ),
            "an unavailable error cannot substitute for an independently terminal original pidfd"
        );
        assert!(fixture.startup.is_empty() && fixture.targets.is_empty());
    }
    #[test]
    fn candidate_validation_refusal_survives_controller_gap_then_exit() {
        let _fixtures = MAPPED_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
        for expected in [
            ObservationGap::NamespaceChanged,
            ObservationGap::ProcessChanged,
            ObservationGap::ProcessUnavailable,
        ] {
            let mut fixture = reconcile_fixture(true);
            let pid = fixture.child.pid();
            let mut compared = fixture.record.clone();
            match expected {
                ObservationGap::NamespaceChanged => {
                    compared.namespaces.mount.as_mut().unwrap().inode += 1
                }
                ObservationGap::ProcessChanged => compared.starttime += 1,
                _ => compared.namespaces.mount = None,
            }
            assert_eq!(
                candidate_validation_result(
                    &fixture.targets[&pid].process,
                    fixture.targets[&pid].process.revalidate()
                ),
                Ok(())
            );
            assert_eq!(process_retirement_gap(&fixture.targets[&pid].process), None);
            let validation = objects::acquire_incarnation(&compared).map(|_| ());
            assert_eq!(validation, Err(expected));
            assert_eq!(
                candidate_validation_result(&fixture.targets[&pid].process, validation),
                Err(expected)
            );
            assert_eq!(fixture.targets[&pid].process.revalidate(), Ok(()));
            assert_eq!(
                process_retirement_gap(&fixture.targets[&pid].process),
                if expected == ObservationGap::ProcessUnavailable {
                    None
                } else {
                    Some(expected)
                }
            );
            // The controller keeps the diagnostic and retires Count. Provider
            // ownership must still remember confirmed validation provenance.
            fixture.child.release_retaining_exit().unwrap();
            let until = Instant::now() + Duration::from_secs(2);
            while fixture.child.peek_exit().unwrap().is_none() {
                assert!(Instant::now() < until);
                std::thread::yield_now();
            }
            let mut aliases = super::super::assembly::Sequences::default();
            let mut batch = ObservationBatch::default();
            let preserve = retire_source_owners(
                (&mut fixture.startup, &mut fixture.targets),
                &mut aliases,
                pid,
                None,
                ObservationGap::ProcessUnavailable,
                &mut batch,
                |_, _| Ok(()),
            );
            if expected == ObservationGap::ProcessUnavailable {
                assert!(
                    preserve,
                    "unavailability must not become confirmed source refusal"
                );
            } else {
                assert!(
                    !preserve,
                    "candidate {expected:?} became only a controller diagnostic before exit"
                );
                assert!(batch.gaps.contains(&expected));
                assert!(fixture.startup.is_empty() && fixture.targets.is_empty());
            }
            fixture.child.finish_observation().unwrap();
        }
    }
    #[test]
    fn startup_mapped_membership_never_renews_an_invalidated_advertisement_lease() {
        let previous = c::Member {
            generation: 19,
            epoch: 0,
            range_count: 0,
            reserved: 0,
        };
        let adopted = mapped_member(Some(previous), 19, 7).unwrap();
        assert_eq!(
            (adopted.generation, adopted.epoch, adopted.range_count),
            (19, 0, 7)
        );
        assert!(mapped_member(Some(previous), 20, 7).is_err());
        assert_eq!(mapped_member(None, 20, 7).unwrap().epoch, 1);
    }
    fn metadata_attachment(
        child: &crate::target::OwnedTarget,
    ) -> (startup_fixture::ForwarderFixture, Attachment) {
        let f = startup_fixture::ForwarderFixture::new(
            ".byte 0xe9\n.long query_impl-.-4",
            ".byte 0xeb\n.byte unquery_impl-.-1",
        );
        let objects::StartupCandidates { apis: sites, .. } = objects::startup_candidates(
            objects::StartupProcess::held(child).unwrap(),
            f.file(),
            &ObservationBudget::default(),
            None,
        )
        .unwrap();
        let (_, site) = sites
            .into_iter()
            .map(|s| s.into_parts())
            .find(|(api, _)| *api == wire::api(c::PUBLIC_QUERY).unwrap())
            .unwrap();
        let attachment = Attachment {
            object: object_id(&site),
            site,
            links: Vec::new(),
            cookie: 81,
            api: c::PUBLIC_QUERY,
            generation: 19,
            advertisers: Vec::new(),
            original: None,
            historical: false,
        };
        (f, attachment)
    }
    #[test]
    fn startup_query_binding_preserves_identity_and_refuses_stale_records() {
        let child = crate::target::OwnedTarget::spawn_stopped(
            &["/bin/true".into()],
            crate::target::WorkloadDest::Null,
        )
        .unwrap();
        let (_fixture, a) = metadata_attachment(&child);
        let starttime = a.site.starttime();
        let hash = a.site.object_hash().clone();
        let r = c::Record {
            pid: child.pid(),
            tid: child.pid(),
            generation: 19,
            cookie: 81,
            api: c::PUBLIC_QUERY,
            ..Default::default()
        };
        let startup = BTreeMap::from([(child.pid(), vec![a])]);
        let targets = BTreeMap::new();
        let binding = record_binding(&targets, &startup, &r)
            .unwrap()
            .expect("first natural query must reach the assembler before any mapped snapshot");
        assert_eq!(binding.starttime, starttime);
        assert_eq!(binding.attachment.site.object_hash(), &hash);
        assert_ne!(binding.attachment.object, 0);
        assert!(
            binding.process.is_none(),
            "startup grants no mapped code authority"
        );
        let mut stale = r;
        stale.generation += 1;
        assert!(
            record_binding(&targets, &startup, &stale)
                .unwrap()
                .is_none()
        );
        let mut stale = r;
        stale.cookie += 1;
        assert!(record_binding(&targets, &startup, &stale).is_err());
        let mut stale = r;
        stale.api = c::GET_DISPATCH;
        assert!(record_binding(&targets, &startup, &stale).is_err());
    }
    #[test]
    fn additive_operational_api_identities_round_trip_through_wire_and_spellings() {
        use crate::api_activity::{API_NAMES, ApiId};
        // Task 7 (5G) round 2: 49-72 are first-class operational identities;
        // 73+ refuses; every export spelling resolves exactly once.
        assert_eq!(API_NAMES.len(), 53);
        let mut seen = std::collections::BTreeSet::new();
        for id in 20..=72u32 {
            let api = ApiId::try_from(id).unwrap_or_else(|_| panic!("ApiId {id}"));
            assert_eq!(u32::from(api), id);
            let name = api.export_name();
            assert!(seen.insert(name), "duplicate spelling {name}");
            let wired = wire::api(id).expect("wire identity");
            assert_eq!(wired.export_name(), Some(name));
        }
        for id in [0, 19, 73, 127, 128, 256, u32::MAX] {
            assert!(ApiId::try_from(id).is_err(), "ApiId {id} must refuse");
        }
        // wire::api also serves the inventoried 1-19 plane; 19 is valid wire.
        for id in [0, 73, 127, 128, 256, u32::MAX] {
            assert!(wire::api(id).is_err(), "wire {id} must refuse");
        }
        assert!(wire::api(19).is_ok());
        assert_eq!(ApiId::all().count(), 53);
    }
    const TASK7_CPROBE_SRC: &str = include_str!("../../tests/runtime/task7_cprobe.c");

    struct Task7Run {
        tag: String,
        exit: Option<i32>,
        rows: Vec<crate::api_activity::ApiActivityRow>,
        gaps: Vec<ObservationGap>,
        stdout: Vec<u8>,
    }

    fn task7_openssl() -> String {
        std::env::var_os("OSSLSCOPE_TEST_OPENSSL")
            .map(|path| {
                path.into_string()
                    .expect("OSSLSCOPE_TEST_OPENSSL must be UTF-8")
            })
            .unwrap_or_else(|| "/usr/bin/openssl".into())
    }

    /// Lane root for a lane CLI (`.../apps/openssl`); None means host system paths.
    fn task7_lane_root(openssl: &str) -> Option<std::path::PathBuf> {
        let path = std::path::Path::new(openssl);
        if path.file_name().and_then(|n| n.to_str()) != Some("openssl") {
            return None;
        }
        let apps = path.parent()?;
        if apps.file_name().and_then(|n| n.to_str()) != Some("apps") {
            return None;
        }
        apps.parent().map(|root| root.to_path_buf())
    }

    fn task7_fixture(openssl: &str, dir: &std::path::Path, args: &[&str]) {
        let status = std::process::Command::new(openssl)
            .args(args)
            .current_dir(dir)
            .status()
            .unwrap();
        assert!(status.success(), "fixture failed: {args:?}");
    }

    fn task7_compile_cprobe(
        dir: &std::path::Path,
        lane_root: Option<&std::path::Path>,
    ) -> std::path::PathBuf {
        let src = dir.join("task7_cprobe.c");
        let app = dir.join("task7_cprobe");
        std::fs::write(&src, TASK7_CPROBE_SRC).unwrap();
        let mut cmd = std::process::Command::new("cc");
        cmd.args(["-O1", "-Wno-deprecated-declarations", "-o"])
            .arg(&app)
            .arg(&src);
        if let Some(root) = lane_root {
            cmd.arg(format!("-I{}", root.join("include").display()));
            cmd.arg(format!("-L{}", root.display()));
        }
        cmd.arg("-lcrypto");
        let status = cmd.status().expect("cc must exist for Task-7 C legs");
        assert!(status.success(), "cprobe build failed");
        app
    }

    fn task7_object() -> Vec<u8> {
        std::fs::read(
            std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").expect("fresh BPF object"),
        )
        .unwrap()
    }

    /// Run one workload under a fresh observed session; absolute argv.
    fn task7_run(
        tag: &str,
        argv: &[String],
        dir: &std::path::Path,
        object: &[u8],
        capture: bool,
    ) -> Task7Run {
        let out_path = dir.join(format!("{tag}.out"));
        let dest = if capture {
            crate::target::WorkloadDest::File(out_path.clone())
        } else {
            crate::target::WorkloadDest::Null
        };
        let mut child = crate::target::OwnedTarget::spawn_stopped(argv, dest).unwrap();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let mut budget = ObservationBudget::default();
        let startup = crate::startup_objects::prepare_owned_startup(
            &child,
            argv,
            &mut budget,
            Instant::now() + Duration::from_secs(120),
            &cancel,
            None,
        )
        .unwrap();
        let mut session = ProviderSession::open_budgeted(budget, object).unwrap();
        session
            .prearm_startup(
                startup.apis,
                Instant::now() + Duration::from_secs(30),
                &cancel,
                PrearmLinks::Create,
            )
            .unwrap();
        child.release_retaining_exit().unwrap();
        // Hang detector, not a perf pin: 120 s covers a slow randomized DH
        // prime search inside an observed C leg under full-suite load.
        let until = Instant::now() + Duration::from_secs(120);
        while child.peek_exit().unwrap().is_none() {
            assert!(Instant::now() < until, "{tag}: workload hung");
            std::thread::yield_now();
        }
        let exit = child.peek_exit().unwrap();
        let snapshot = inventory::snapshot(&inventory::SnapshotOptions {
            pids: vec![child.pid()],
            ..Default::default()
        });
        let reconciliation = session.reconcile(&snapshot);
        let mut batch = session.close_until(Instant::now() + Duration::from_secs(10));
        for gap in reconciliation.gaps {
            batch.gap(gap);
        }
        // Budget-denylist: ceiling/resource failures are never acceptable here.
        for gap in &batch.gaps {
            assert!(
                !matches!(
                    gap,
                    ObservationGap::StateLimit
                        | ObservationGap::ReadLimit
                        | ObservationGap::BpfUnavailable
                        | ObservationGap::AttachFailed
                        | ObservationGap::InvalidObject
                        | ObservationGap::InvalidWire
                        | ObservationGap::ClassifierFailed
                        | ObservationGap::TargetReadFailed
                        | ObservationGap::ProcessLimit
                        | ObservationGap::ObjectLimit
                        | ObservationGap::LinkLimit
                        | ObservationGap::PendingLimit
                        | ObservationGap::DepthLimit
                        | ObservationGap::SiteLimit
                        | ObservationGap::FactLimit
                ),
                "{tag}: budget gap {gap:?}"
            );
        }
        let rows: Vec<_> = batch.api_activity.iter().map(|a| a.row.clone()).collect();
        let stdout = if capture {
            std::fs::read(&out_path).unwrap_or_default()
        } else {
            Vec::new()
        };
        eprintln!("TASK7 {tag} exit={exit:?} gaps={:?}", batch.gaps);
        for id in 49..=72u32 {
            let (e, ok, fail, mm, un) = task7_totals(&rows, id);
            if e > 0 {
                eprintln!(
                    "TASK7 {tag} api={id} entries={e} ok={ok} fail={fail} mm={mm} unsup={un}"
                );
            }
        }
        child.finish_observation().unwrap();
        Task7Run {
            tag: tag.to_string(),
            exit,
            rows,
            gaps: batch.gaps,
            stdout,
        }
    }

    fn task7_totals(
        rows: &[crate::api_activity::ApiActivityRow],
        api: u32,
    ) -> (u64, u64, u64, u64, u64) {
        rows.iter()
            .filter(|r| u32::from(r.api) == api)
            .fold((0, 0, 0, 0, 0), |acc, r| {
                (
                    acc.0 + r.entries,
                    acc.1 + r.observed_success,
                    acc.2 + r.observed_failure,
                    acc.3 + r.verification_mismatch,
                    acc.4 + r.unsupported,
                )
            })
    }

    /// Attached-but-uncalled: rows present, every counter zero, attached.
    /// Live-decoded rows always carry attachment+finality (wire.rs); only
    /// `unavailable()` rows set not_attached.
    fn task7_assert_idle(run: &Task7Run, api: u32) {
        let rows: Vec<_> = run
            .rows
            .iter()
            .filter(|r| u32::from(r.api) == api)
            .collect();
        assert!(
            !rows.is_empty(),
            "{}: api {api} has no row (not attached?)",
            run.tag
        );
        for r in rows {
            assert_eq!(
                (r.entries, r.observed_success, r.observed_failure),
                (0, 0, 0),
                "{}: api {api}",
                run.tag
            );
            assert_eq!(
                (r.verification_mismatch, r.unsupported),
                (0, 0),
                "{}: api {api}",
                run.tag
            );
            let g = &r.gaps;
            assert_eq!(
                (g.map, g.depth, g.unpaired, g.tail, g.unsupported_return),
                (0, 0, 0, 0, 0),
                "{}: api {api}",
                run.tag
            );
            assert!(
                !g.saturated && !g.not_attached && g.attachment && g.finality,
                "{}: api {api}",
                run.tag
            );
        }
    }

    /// Void-exclusivity (D1 pin): every return classified success, nothing else.
    fn task7_assert_void_clean(run: &Task7Run, api: u32) {
        let rows: Vec<_> = run
            .rows
            .iter()
            .filter(|r| u32::from(r.api) == api)
            .collect();
        assert!(!rows.is_empty(), "{}: api {api} has no row", run.tag);
        let (e, ok, fail, mm, un) = task7_totals(&run.rows, api);
        assert!(e > 0, "{}: api {api} never fired", run.tag);
        assert_eq!((ok, fail, mm, un), (e, 0, 0, 0), "{}: api {api}", run.tag);
        for r in rows {
            let g = &r.gaps;
            assert_eq!(
                (g.map, g.depth, g.unpaired, g.tail, g.unsupported_return),
                (0, 0, 0, 0, 0),
                "{}: api {api}",
                run.tag
            );
            assert!(
                !g.saturated && !g.not_attached && g.attachment && g.finality,
                "{}: api {api}",
                run.tag
            );
        }
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges, cc"]
    fn task7_g1_kem_control() {
        let openssl = task7_openssl();
        let lane_root = task7_lane_root(&openssl);
        let object = task7_object();
        let dir = std::env::temp_dir().join(format!("task7-g1-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let s = |name: &str| dir.join(name).to_string_lossy().into_owned();
        task7_fixture(
            &openssl,
            &dir,
            &["genpkey", "-algorithm", "ML-KEM-768", "-out", "mlkem.pem"],
        );
        task7_fixture(
            &openssl,
            &dir,
            &[
                "pkey",
                "-in",
                "mlkem.pem",
                "-pubout",
                "-out",
                "mlkem-pub.pem",
            ],
        );
        task7_fixture(
            &openssl,
            &dir,
            &[
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                "rsa.pem",
            ],
        );
        task7_fixture(
            &openssl,
            &dir,
            &["pkey", "-in", "rsa.pem", "-pubout", "-out", "rsa-pub.pem"],
        );
        task7_fixture(
            &openssl,
            &dir,
            &[
                "pkeyutl",
                "-encap",
                "-inkey",
                "mlkem-pub.pem",
                "-pubin",
                "-secret",
                "s1",
                "-out",
                "ct1",
            ],
        );
        let mut ct_bad = std::fs::read(dir.join("ct1")).unwrap();
        ct_bad[10] ^= 0x01;
        std::fs::write(dir.join("ct_bad"), &ct_bad).unwrap();
        std::fs::write(dir.join("ct_trunc"), &ct_bad[..10]).unwrap();
        let cprobe = task7_compile_cprobe(&dir, lane_root.as_deref());
        let cprobe = cprobe.to_string_lossy().into_owned();
        // T1 ML-KEM-768 (PQC): pkeyutl size-queries then runs (entries==2).
        let r = task7_run(
            "g1-encap-mlkem",
            &[
                openssl.clone(),
                "pkeyutl".into(),
                "-encap".into(),
                "-inkey".into(),
                s("mlkem-pub.pem"),
                "-pubin".into(),
                "-secret".into(),
                s("sA"),
                "-out".into(),
                s("ctA"),
            ],
            &dir,
            &object,
            false,
        );
        assert_eq!(r.exit, Some(0));
        assert_eq!(task7_totals(&r.rows, 49), (2, 2, 0, 0, 0));
        let r = task7_run(
            "g1-decap-mlkem",
            &[
                openssl.clone(),
                "pkeyutl".into(),
                "-decap".into(),
                "-inkey".into(),
                s("mlkem.pem"),
                "-in".into(),
                s("ctA"),
                "-secret".into(),
                s("sB"),
            ],
            &dir,
            &object,
            false,
        );
        assert_eq!(r.exit, Some(0));
        assert_eq!(task7_totals(&r.rows, 50), (2, 2, 0, 0, 0));
        assert_eq!(
            std::fs::read(dir.join("sA")).unwrap(),
            std::fs::read(dir.join("sB")).unwrap()
        );
        // T1 RSA-KEM (classic): same two-phase shape.
        let r = task7_run(
            "g1-encap-rsa",
            &[
                openssl.clone(),
                "pkeyutl".into(),
                "-encap".into(),
                "-inkey".into(),
                s("rsa-pub.pem"),
                "-pubin".into(),
                "-secret".into(),
                s("sR"),
                "-out".into(),
                s("ctR"),
            ],
            &dir,
            &object,
            false,
        );
        assert_eq!(r.exit, Some(0));
        assert_eq!(task7_totals(&r.rows, 49), (2, 2, 0, 0, 0));
        let r = task7_run(
            "g1-decap-rsa",
            &[
                openssl.clone(),
                "pkeyutl".into(),
                "-decap".into(),
                "-inkey".into(),
                s("rsa.pem"),
                "-in".into(),
                s("ctR"),
                "-secret".into(),
                s("sR2"),
            ],
            &dir,
            &object,
            false,
        );
        assert_eq!(r.exit, Some(0));
        assert_eq!(task7_totals(&r.rows, 50), (2, 2, 0, 0, 0));
        assert_eq!(
            std::fs::read(dir.join("sR")).unwrap(),
            std::fs::read(dir.join("sR2")).unwrap()
        );
        // Size-query-only leg: one NULL-out call, then stop.
        let r = task7_run(
            "g1-encap-query",
            &[cprobe.clone(), "encap-query".into()],
            &dir,
            &object,
            true,
        );
        assert_eq!(r.exit, Some(0));
        assert!(String::from_utf8_lossy(&r.stdout).contains("encap_query rv=1"));
        assert_eq!(task7_totals(&r.rows, 49), (1, 1, 0, 0, 0));
        // T3: truncated ciphertext fails the actual call (query still succeeds).
        let r = task7_run(
            "g1-decap-trunc",
            &[
                openssl.clone(),
                "pkeyutl".into(),
                "-decap".into(),
                "-inkey".into(),
                s("mlkem.pem"),
                "-in".into(),
                s("ct_trunc"),
                "-secret".into(),
                s("sU"),
            ],
            &dir,
            &object,
            false,
        );
        assert_eq!(r.exit, Some(1));
        assert_eq!(task7_totals(&r.rows, 50), (2, 1, 1, 0, 0));
        // Tampered-ciphertext oracle leg: ML-KEM implicit rejection keeps
        // exit 0 with a divergent secret (proves the leg is meaningful).
        let r = task7_run(
            "g1-decap-tamper",
            &[
                openssl.clone(),
                "pkeyutl".into(),
                "-decap".into(),
                "-inkey".into(),
                s("mlkem.pem"),
                "-in".into(),
                s("ct_bad"),
                "-secret".into(),
                s("sT"),
            ],
            &dir,
            &object,
            false,
        );
        assert_eq!(r.exit, Some(0));
        assert_eq!(task7_totals(&r.rows, 50), (2, 2, 0, 0, 0));
        assert_ne!(
            std::fs::read(dir.join("s1")).unwrap(),
            std::fs::read(dir.join("sT")).unwrap()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges, cc"]
    fn task7_g2_keygen_control() {
        let openssl = task7_openssl();
        let object = task7_object();
        let dir = std::env::temp_dir().join(format!("task7-g2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let s = |name: &str| dir.join(name).to_string_lossy().into_owned();
        // T1 EC keygen: init + keygen once each; the key must parse back.
        let r = task7_run(
            "g2-genpkey-ec",
            &[
                openssl.clone(),
                "genpkey".into(),
                "-algorithm".into(),
                "EC".into(),
                "-pkeyopt".into(),
                "ec_paramgen_curve:P-256".into(),
                "-out".into(),
                s("ec1.pem"),
            ],
            &dir,
            &object,
            false,
        );
        assert_eq!(r.exit, Some(0));
        assert_eq!(task7_totals(&r.rows, 51), (1, 1, 0, 0, 0));
        assert_eq!(task7_totals(&r.rows, 52), (1, 1, 0, 0, 0));
        task7_fixture(
            &openssl,
            &dir,
            &["pkey", "-in", "ec1.pem", "-noout", "-text"],
        );
        // T1 DH paramgen: init + paramgen once each; params must parse back.
        let r = task7_run(
            "g2-genparam-dh",
            &[
                openssl.clone(),
                "genpkey".into(),
                "-genparam".into(),
                "-algorithm".into(),
                "DH".into(),
                "-pkeyopt".into(),
                "dh_paramgen_prime_len:512".into(),
                "-out".into(),
                s("dhp.pem"),
            ],
            &dir,
            &object,
            false,
        );
        assert_eq!(r.exit, Some(0));
        assert_eq!(task7_totals(&r.rows, 53), (1, 1, 0, 0, 0));
        assert_eq!(task7_totals(&r.rows, 54), (1, 1, 0, 0, 0));
        task7_fixture(
            &openssl,
            &dir,
            &["dhparam", "-in", "dhp.pem", "-noout", "-text"],
        );
        // T3: RSA keygen with an even public exponent fails inside keygen.
        let r = task7_run(
            "g2-pubexp2",
            &[
                openssl.clone(),
                "genpkey".into(),
                "-algorithm".into(),
                "RSA".into(),
                "-pkeyopt".into(),
                "rsa_keygen_bits:512".into(),
                "-pkeyopt".into(),
                "rsa_keygen_pubexp:2".into(),
                "-out".into(),
                s("badX"),
            ],
            &dir,
            &object,
            false,
        );
        assert_eq!(r.exit, Some(1));
        assert_eq!(task7_totals(&r.rows, 51), (1, 1, 0, 0, 0));
        assert_eq!(task7_totals(&r.rows, 52), (1, 0, 1, 0, 0));
        // T3: DH paramgen with a 64-bit prime fails inside paramgen.
        let r = task7_run(
            "g2-tiny-dh",
            &[
                openssl.clone(),
                "genpkey".into(),
                "-genparam".into(),
                "-algorithm".into(),
                "DH".into(),
                "-pkeyopt".into(),
                "dh_paramgen_prime_len:64".into(),
                "-out".into(),
                s("dhTX"),
            ],
            &dir,
            &object,
            false,
        );
        assert_eq!(r.exit, Some(1));
        assert_eq!(task7_totals(&r.rows, 53), (1, 1, 0, 0, 0));
        assert_eq!(task7_totals(&r.rows, 54), (1, 0, 1, 0, 0));
        // T3: EC keygen without a curve fails inside keygen.
        let r = task7_run(
            "g2-ec-nocurve",
            &[
                openssl.clone(),
                "genpkey".into(),
                "-algorithm".into(),
                "EC".into(),
                "-out".into(),
                s("ecX"),
            ],
            &dir,
            &object,
            false,
        );
        assert_eq!(r.exit, Some(1));
        assert_eq!(task7_totals(&r.rows, 52), (1, 0, 1, 0, 0));
        // T3: paramgen for RSA fails inside paramgen_init (no params exist).
        let r = task7_run(
            "g2-genparam-rsa",
            &[
                openssl.clone(),
                "genpkey".into(),
                "-genparam".into(),
                "-algorithm".into(),
                "RSA".into(),
                "-out".into(),
                s("x1"),
            ],
            &dir,
            &object,
            false,
        );
        assert_eq!(r.exit, Some(1));
        assert_eq!(task7_totals(&r.rows, 53), (1, 0, 1, 0, 0));
        task7_assert_idle(&r, 54);
        // T3-negative: unknown algorithm dies in fetch, before any init call.
        let r = task7_run(
            "g2-bad-alg",
            &[
                openssl.clone(),
                "genpkey".into(),
                "-algorithm".into(),
                "NOPE".into(),
                "-out".into(),
                s("x3"),
            ],
            &dir,
            &object,
            false,
        );
        assert_eq!(r.exit, Some(1));
        task7_assert_idle(&r, 51);
        task7_assert_idle(&r, 52);
        std::fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges, cc"]
    fn task7_g3_derive_check_control() {
        let openssl = task7_openssl();
        let lane_root = task7_lane_root(&openssl);
        let object = task7_object();
        let dir = std::env::temp_dir().join(format!("task7-g3-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let s = |name: &str| dir.join(name).to_string_lossy().into_owned();
        task7_fixture(
            &openssl,
            &dir,
            &[
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
                "ec1.pem",
            ],
        );
        task7_fixture(
            &openssl,
            &dir,
            &[
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
                "ec2.pem",
            ],
        );
        task7_fixture(
            &openssl,
            &dir,
            &["pkey", "-in", "ec2.pem", "-pubout", "-out", "ec2pub.pem"],
        );
        task7_fixture(
            &openssl,
            &dir,
            &[
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                "rsa.pem",
            ],
        );
        task7_fixture(
            &openssl,
            &dir,
            &[
                "genpkey",
                "-genparam",
                "-algorithm",
                "DH",
                "-pkeyopt",
                "dh_paramgen_prime_len:512",
                "-out",
                "dhp.pem",
            ],
        );
        task7_fixture(
            &openssl,
            &dir,
            &["ecparam", "-name", "prime256v1", "-out", "ecp.pem"],
        );
        let mut dhp_bad = std::fs::read(dir.join("dhp.pem")).unwrap();
        dhp_bad[60] ^= 0x01;
        std::fs::write(dir.join("dhp_bad.pem"), &dhp_bad).unwrap();
        let cprobe = task7_compile_cprobe(&dir, lane_root.as_deref());
        let cprobe = cprobe.to_string_lossy().into_owned();
        // T1 ECDH derive: 32-byte secret, deterministic across two runs.
        let r = task7_run(
            "g3-derive",
            &[
                openssl.clone(),
                "pkeyutl".into(),
                "-derive".into(),
                "-inkey".into(),
                s("ec1.pem"),
                "-peerkey".into(),
                s("ec2pub.pem"),
                "-out".into(),
                s("sec1"),
            ],
            &dir,
            &object,
            false,
        );
        assert_eq!(r.exit, Some(0));
        assert_eq!(task7_totals(&r.rows, 55), (1, 1, 0, 0, 0));
        task7_fixture(
            &openssl,
            &dir,
            &[
                "pkeyutl",
                "-derive",
                "-inkey",
                "ec1.pem",
                "-peerkey",
                "ec2pub.pem",
                "-out",
                "sec2",
            ],
        );
        assert_eq!(std::fs::read(dir.join("sec1")).unwrap().len(), 32);
        assert_eq!(
            std::fs::read(dir.join("sec1")).unwrap(),
            std::fs::read(dir.join("sec2")).unwrap()
        );
        // T3: RSA has no derive op: derive_init returns documented -2.
        let r = task7_run(
            "g3-rsa-derive",
            &[
                openssl.clone(),
                "pkeyutl".into(),
                "-derive".into(),
                "-inkey".into(),
                s("rsa.pem"),
                "-peerkey".into(),
                s("ec2pub.pem"),
                "-out".into(),
                s("secX"),
            ],
            &dir,
            &object,
            false,
        );
        assert_eq!(r.exit, Some(1));
        assert_eq!(task7_totals(&r.rows, 55), (1, 0, 1, 0, 1));
        // T1/T3 check-family: stock valid legs + C invalid-key legs.
        let r = task7_run(
            "g3-check",
            &[
                openssl.clone(),
                "pkey".into(),
                "-in".into(),
                s("ec1.pem"),
                "-check".into(),
                "-noout".into(),
            ],
            &dir,
            &object,
            true,
        );
        assert_eq!(r.exit, Some(0));
        assert!(String::from_utf8_lossy(&r.stdout).contains("Key is valid"));
        assert_eq!(task7_totals(&r.rows, 56), (1, 1, 0, 0, 0));
        let r = task7_run(
            "g3-check-bad",
            &[cprobe.clone(), "check-bad".into()],
            &dir,
            &object,
            true,
        );
        assert_eq!(r.exit, Some(0));
        assert!(String::from_utf8_lossy(&r.stdout).contains("check_bad rv=0"));
        assert_eq!(task7_totals(&r.rows, 56), (1, 0, 1, 0, 0));
        let r = task7_run(
            "g3-pubcheck",
            &[
                openssl.clone(),
                "pkey".into(),
                "-in".into(),
                s("ec1.pem"),
                "-pubcheck".into(),
                "-noout".into(),
            ],
            &dir,
            &object,
            true,
        );
        assert_eq!(r.exit, Some(0));
        assert!(String::from_utf8_lossy(&r.stdout).contains("Key is valid"));
        assert_eq!(task7_totals(&r.rows, 57), (1, 1, 0, 0, 0));
        let r = task7_run(
            "g3-pubcheck-bad",
            &[cprobe.clone(), "pubcheck-bad".into()],
            &dir,
            &object,
            true,
        );
        assert_eq!(r.exit, Some(0));
        assert!(String::from_utf8_lossy(&r.stdout).contains("pubcheck_bad rv=0"));
        assert_eq!(task7_totals(&r.rows, 57), (1, 0, 1, 0, 0));
        let r = task7_run(
            "g3-dhparam-check",
            &[
                openssl.clone(),
                "dhparam".into(),
                "-check".into(),
                "-in".into(),
                s("dhp.pem"),
                "-noout".into(),
            ],
            &dir,
            &object,
            false,
        );
        assert_eq!(r.exit, Some(0));
        assert_eq!(task7_totals(&r.rows, 58), (1, 1, 0, 0, 0));
        let r = task7_run(
            "g3-ecparam-check",
            &[
                openssl.clone(),
                "ecparam".into(),
                "-check".into(),
                "-in".into(),
                s("ecp.pem"),
                "-noout".into(),
            ],
            &dir,
            &object,
            false,
        );
        assert_eq!(r.exit, Some(0));
        assert_eq!(task7_totals(&r.rows, 58), (1, 1, 0, 0, 0));
        let r = task7_run(
            "g3-dhparam-tamper",
            &[
                openssl.clone(),
                "dhparam".into(),
                "-check".into(),
                "-in".into(),
                s("dhp_bad.pem"),
                "-noout".into(),
            ],
            &dir,
            &object,
            false,
        );
        assert_ne!(r.exit, Some(0));
        assert_eq!(task7_totals(&r.rows, 58), (1, 0, 1, 0, 0));
        // 59 has no stock path: C legs with marker oracles (non-stock caveat).
        let r = task7_run(
            "g3-copyparams-ok",
            &[cprobe.clone(), "copyparams-ok".into()],
            &dir,
            &object,
            true,
        );
        assert_eq!(r.exit, Some(0));
        assert!(String::from_utf8_lossy(&r.stdout).contains("copyparams_ok rv=1"));
        assert_eq!(task7_totals(&r.rows, 59), (1, 1, 0, 0, 0));
        let r = task7_run(
            "g3-copyparams-bad",
            &[cprobe.clone(), "copyparams-bad".into()],
            &dir,
            &object,
            true,
        );
        assert_eq!(r.exit, Some(0));
        assert!(String::from_utf8_lossy(&r.stdout).contains("copyparams_bad rv=0"));
        assert_eq!(task7_totals(&r.rows, 59), (1, 0, 1, 0, 0));
        std::fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges, cc"]
    fn task7_g4_digestsign_control() {
        let openssl = task7_openssl();
        let lane_root = task7_lane_root(&openssl);
        let object = task7_object();
        let dir = std::env::temp_dir().join(format!("task7-g4-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let s = |name: &str| dir.join(name).to_string_lossy().into_owned();
        std::fs::write(dir.join("data16"), b"0123456789abcdef").unwrap();
        std::fs::write(dir.join("data1m"), vec![0x42u8; 1 << 20]).unwrap();
        task7_fixture(
            &openssl,
            &dir,
            &[
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                "rsa.pem",
            ],
        );
        task7_fixture(
            &openssl,
            &dir,
            &["pkey", "-in", "rsa.pem", "-pubout", "-out", "rsa-pub.pem"],
        );
        task7_fixture(
            &openssl,
            &dir,
            &[
                "dgst", "-sha256", "-sign", "rsa.pem", "-out", "sig", "data16",
            ],
        );
        let mut sig_bad = std::fs::read(dir.join("sig")).unwrap();
        sig_bad[0] ^= 0xff;
        std::fs::write(dir.join("sig_bad"), &sig_bad).unwrap();
        let cprobe = task7_compile_cprobe(&dir, lane_root.as_deref());
        let cprobe = cprobe.to_string_lossy().into_owned();
        // T1 sign/verify pair with the application oracle.
        let r = task7_run(
            "g4-sign",
            &[
                openssl.clone(),
                "dgst".into(),
                "-sha256".into(),
                "-sign".into(),
                s("rsa.pem"),
                "-out".into(),
                s("sigA"),
                s("data16"),
            ],
            &dir,
            &object,
            false,
        );
        assert_eq!(r.exit, Some(0));
        assert_eq!(task7_totals(&r.rows, 60), (1, 1, 0, 0, 0));
        assert_eq!(task7_totals(&r.rows, 61), (1, 1, 0, 0, 0));
        let r = task7_run(
            "g4-verify",
            &[
                openssl.clone(),
                "dgst".into(),
                "-sha256".into(),
                "-verify".into(),
                s("rsa-pub.pem"),
                "-signature".into(),
                s("sig"),
                s("data16"),
            ],
            &dir,
            &object,
            true,
        );
        assert_eq!(r.exit, Some(0));
        assert!(String::from_utf8_lossy(&r.stdout).contains("Verified OK"));
        assert_eq!(task7_totals(&r.rows, 62), (1, 1, 0, 0, 0));
        assert_eq!(task7_totals(&r.rows, 63), (1, 1, 0, 0, 0));
        // T1 multi-block: 1 MiB through pkeyutl raw streaming = 512 Updates.
        let r = task7_run(
            "g4-sign-raw",
            &[
                openssl.clone(),
                "pkeyutl".into(),
                "-sign".into(),
                "-rawin".into(),
                "-digest".into(),
                "sha256".into(),
                "-inkey".into(),
                s("rsa.pem"),
                "-in".into(),
                s("data1m"),
                "-out".into(),
                s("sig2"),
            ],
            &dir,
            &object,
            false,
        );
        assert_eq!(r.exit, Some(0));
        assert_eq!(task7_totals(&r.rows, 61), (512, 512, 0, 0, 0));
        let r = task7_run(
            "g4-verify-raw",
            &[
                openssl.clone(),
                "pkeyutl".into(),
                "-verify".into(),
                "-rawin".into(),
                "-digest".into(),
                "sha256".into(),
                "-pubin".into(),
                "-inkey".into(),
                s("rsa-pub.pem"),
                "-sigfile".into(),
                s("sig2"),
                "-in".into(),
                s("data1m"),
            ],
            &dir,
            &object,
            false,
        );
        assert_eq!(r.exit, Some(0));
        assert_eq!(task7_totals(&r.rows, 63), (512, 512, 0, 0, 0));
        // T3: tampered signature mismatches at Final; Init/Update stay clean
        // (pins the no-new-mismatch arm: 62/63 never report mismatch).
        let r = task7_run(
            "g4-verify-tamper",
            &[
                openssl.clone(),
                "dgst".into(),
                "-sha256".into(),
                "-verify".into(),
                s("rsa-pub.pem"),
                "-signature".into(),
                s("sig_bad"),
                s("data16"),
            ],
            &dir,
            &object,
            true,
        );
        assert_eq!(r.exit, Some(1));
        assert!(String::from_utf8_lossy(&r.stdout).contains("Verification failure"));
        assert_eq!(task7_totals(&r.rows, 45), (1, 0, 1, 1, 0));
        assert_eq!(task7_totals(&r.rows, 62), (1, 1, 0, 0, 0));
        assert_eq!(task7_totals(&r.rows, 63), (1, 1, 0, 0, 0));
        // T3: C failure legs the CLI cannot induce (non-stock caveat).
        let r = task7_run(
            "g4-signinit-bad",
            &[cprobe.clone(), "signinit-bad".into()],
            &dir,
            &object,
            true,
        );
        assert_eq!(r.exit, Some(0));
        assert!(String::from_utf8_lossy(&r.stdout).contains("signinit_bad rv=0"));
        assert_eq!(task7_totals(&r.rows, 60), (1, 0, 1, 0, 0));
        let r = task7_run(
            "g4-verifyinit-bad",
            &[cprobe.clone(), "verifyinit-bad".into()],
            &dir,
            &object,
            true,
        );
        assert_eq!(r.exit, Some(0));
        assert!(String::from_utf8_lossy(&r.stdout).contains("verifyinit_bad rv=0"));
        assert_eq!(task7_totals(&r.rows, 62), (1, 0, 1, 0, 0));
        let r = task7_run(
            "g4-signupdate-bad",
            &[cprobe.clone(), "signupdate-bad".into()],
            &dir,
            &object,
            true,
        );
        assert_eq!(r.exit, Some(0));
        assert!(String::from_utf8_lossy(&r.stdout).contains("signupdate_bad rv=0"));
        assert_eq!(task7_totals(&r.rows, 61), (1, 0, 1, 0, 0));
        let r = task7_run(
            "g4-verifyupdate-bad",
            &[cprobe.clone(), "verifyupdate-bad".into()],
            &dir,
            &object,
            true,
        );
        assert_eq!(r.exit, Some(0));
        assert!(String::from_utf8_lossy(&r.stdout).contains("verifyupdate_bad rv=0"));
        assert_eq!(task7_totals(&r.rows, 63), (1, 0, 1, 0, 0));
        std::fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges, cc"]
    fn task7_g5_oneshot_control() {
        let openssl = task7_openssl();
        let lane_root = task7_lane_root(&openssl);
        let object = task7_object();
        let dir = std::env::temp_dir().join(format!("task7-g5-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("data16"), b"0123456789abcdef").unwrap();
        let cprobe = task7_compile_cprobe(&dir, lane_root.as_deref());
        let cprobe = cprobe.to_string_lossy().into_owned();
        // T1 EVP_Q_mac via stock HKDF (RFC 5869 TC1, the FAM_KDF_OKM oracle).
        let r = task7_run(
            "g5-kdf-hkdf",
            &[
                openssl.clone(),
                "kdf".into(),
                "-keylen".into(),
                "42".into(),
                "-kdfopt".into(),
                "digest:SHA256".into(),
                "-kdfopt".into(),
                format!("hexkey:{}", "0b".repeat(22)),
                "-kdfopt".into(),
                "hexsalt:000102030405060708090a0b0c".into(),
                "-kdfopt".into(),
                "hexinfo:f0f1f2f3f4f5f6f7f8f9".into(),
                "HKDF".into(),
            ],
            &dir,
            &object,
            true,
        );
        assert_eq!(r.exit, Some(0));
        let stripped: String = String::from_utf8_lossy(&r.stdout)
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect();
        assert_eq!(
            stripped,
            "3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56ECC4C5BF34007208D5B887185865"
        );
        assert_eq!(task7_totals(&r.rows, 65), (1, 1, 0, 0, 0));
        // T1 EVP_Q_digest via C (no stock path; oracle = independent CLI digest).
        task7_fixture(
            &openssl,
            &dir,
            &["dgst", "-sha256", "-hex", "-out", "qref.hex", "data16"],
        );
        let r = task7_run(
            "g5-qdigest-ok",
            &[cprobe.clone(), "qdigest-ok".into()],
            &dir,
            &object,
            true,
        );
        assert_eq!(r.exit, Some(0));
        let out = String::from_utf8_lossy(&r.stdout);
        assert!(out.contains("qdigest_ok rv=1"));
        let expect =
            String::from_utf8_lossy(&std::fs::read(dir.join("qref.hex")).unwrap()).into_owned();
        let hex: String = out.lines().nth(1).unwrap().trim().to_string();
        assert!(
            expect.to_lowercase().contains(&hex.to_lowercase()),
            "C digest must equal CLI digest"
        );
        assert_eq!(task7_totals(&r.rows, 64), (1, 1, 0, 0, 0));
        // T1 EVP_Q_mac via C with the same cross-check shape (CLI mac oracle).
        std::fs::write(dir.join("qdata"), b"0123456789abcdef").unwrap();
        task7_fixture(
            &openssl,
            &dir,
            &[
                "mac",
                "-digest",
                "SHA256",
                "-macopt",
                "hexkey:000102030405060708090a0b0c0d0e0f",
                "-in",
                "qdata",
                "-out",
                "mref.hex",
                "HMAC",
            ],
        );
        let r = task7_run(
            "g5-qmac-ok",
            &[cprobe.clone(), "qmac-ok".into()],
            &dir,
            &object,
            true,
        );
        assert_eq!(r.exit, Some(0));
        let out = String::from_utf8_lossy(&r.stdout);
        assert!(out.contains("qmac_ok null=0"));
        let expect =
            String::from_utf8_lossy(&std::fs::read(dir.join("mref.hex")).unwrap()).into_owned();
        let hex: String = out.lines().nth(1).unwrap().trim().to_string();
        assert!(
            expect.to_lowercase().contains(&hex.to_lowercase()),
            "C MAC must equal CLI MAC"
        );
        assert_eq!(task7_totals(&r.rows, 65), (1, 1, 0, 0, 0));
        // T3: unknown names fail (0 / NULL).
        let r = task7_run(
            "g5-qdigest-bad",
            &[cprobe.clone(), "qdigest-bad".into()],
            &dir,
            &object,
            true,
        );
        assert_eq!(r.exit, Some(0));
        assert!(String::from_utf8_lossy(&r.stdout).contains("qdigest_bad rv=0"));
        assert_eq!(task7_totals(&r.rows, 64), (1, 0, 1, 0, 0));
        let r = task7_run(
            "g5-qmac-bad",
            &[cprobe.clone(), "qmac-bad".into()],
            &dir,
            &object,
            true,
        );
        assert_eq!(r.exit, Some(0));
        assert!(String::from_utf8_lossy(&r.stdout).contains("qmac_bad null=1"));
        assert_eq!(task7_totals(&r.rows, 65), (1, 0, 1, 0, 0));
        std::fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges, cc"]
    fn task7_g6_rand_control() {
        let openssl = task7_openssl();
        let lane_root = task7_lane_root(&openssl);
        let object = task7_object();
        let dir = std::env::temp_dir().join(format!("task7-g6-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        task7_fixture(
            &openssl,
            &dir,
            &[
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
                "ec1.pem",
            ],
        );
        let s = |name: &str| dir.join(name).to_string_lossy().into_owned();
        let cprobe = task7_compile_cprobe(&dir, lane_root.as_deref());
        let cprobe = cprobe.to_string_lossy().into_owned();
        // T1 RAND_CTX lifecycle via stock `rand`: 32 hex chars out.
        let r = task7_run(
            "g6-rand",
            &[openssl.clone(), "rand".into(), "-hex".into(), "16".into()],
            &dir,
            &object,
            true,
        );
        assert_eq!(r.exit, Some(0));
        let hex = String::from_utf8_lossy(&r.stdout).trim().to_string();
        assert_eq!(hex.len(), 32);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        let (e67, ok67, _, _, _) = task7_totals(&r.rows, 67);
        assert!(e67 >= 1 && ok67 == e67, "67 must fire successfully");
        task7_assert_void_clean(&r, 68);
        // T1/T3 EVP_RAND_nonce via C (no stock path: no internal callers).
        let r = task7_run(
            "g6-nonce-ok",
            &[cprobe.clone(), "nonce-ok".into()],
            &dir,
            &object,
            true,
        );
        assert_eq!(r.exit, Some(0));
        assert!(String::from_utf8_lossy(&r.stdout).contains("nonce_ok rv=1"));
        assert_eq!(task7_totals(&r.rows, 66), (1, 1, 0, 0, 0));
        let r = task7_run(
            "g6-nonce-bad",
            &[cprobe.clone(), "nonce-bad".into()],
            &dir,
            &object,
            true,
        );
        assert_eq!(r.exit, Some(0));
        assert!(String::from_utf8_lossy(&r.stdout).contains("nonce_bad rv=0"));
        assert_eq!(task7_totals(&r.rows, 66), (1, 0, 1, 0, 0));
        // T3-negative for 67: `pkey -check` frees (possibly NULL) RAND
        // contexts but news none — attached, zero entries, zero gaps.
        let r = task7_run(
            "g6-check-neg67",
            &[
                openssl.clone(),
                "pkey".into(),
                "-in".into(),
                s("ec1.pem"),
                "-check".into(),
                "-noout".into(),
            ],
            &dir,
            &object,
            false,
        );
        assert_eq!(r.exit, Some(0));
        assert_eq!(task7_totals(&r.rows, 56), (1, 1, 0, 0, 0));
        task7_assert_idle(&r, 67);
        task7_assert_void_clean(&r, 68);
        std::fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges, cc"]
    fn task7_g7_mdctx_control() {
        let openssl = task7_openssl();
        let object = task7_object();
        let dir = std::env::temp_dir().join(format!("task7-g7-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let s = |name: &str| dir.join(name).to_string_lossy().into_owned();
        std::fs::write(dir.join("data1m"), vec![0x42u8; 1 << 20]).unwrap();
        task7_fixture(
            &openssl,
            &dir,
            &[
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
                "ec1.pem",
            ],
        );
        task7_fixture(
            &openssl,
            &dir,
            &[
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
                "ec2.pem",
            ],
        );
        task7_fixture(
            &openssl,
            &dir,
            &["pkey", "-in", "ec2.pem", "-pubout", "-out", "ec2pub.pem"],
        );
        // T1: the digest BIO news one MD_CTX and frees (CTX + NULL guard).
        let r = task7_run(
            "g7-dgst",
            &[
                openssl.clone(),
                "dgst".into(),
                "-sha256".into(),
                s("data1m"),
            ],
            &dir,
            &object,
            true,
        );
        assert_eq!(r.exit, Some(0));
        assert!(String::from_utf8_lossy(&r.stdout).contains("SHA2-256("));
        assert_eq!(task7_totals(&r.rows, 69), (1, 1, 0, 0, 0));
        assert_eq!(task7_totals(&r.rows, 70), (2, 2, 0, 0, 0));
        task7_assert_void_clean(&r, 70);
        // T3-negative for 69: derive frees an MD_CTX without news.
        let r = task7_run(
            "g7-derive-neg69",
            &[
                openssl.clone(),
                "pkeyutl".into(),
                "-derive".into(),
                "-inkey".into(),
                s("ec1.pem"),
                "-peerkey".into(),
                s("ec2pub.pem"),
                "-out".into(),
                s("sec1"),
            ],
            &dir,
            &object,
            false,
        );
        assert_eq!(r.exit, Some(0));
        task7_assert_idle(&r, 69);
        task7_assert_void_clean(&r, 70);
        std::fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF, native BPF privileges, cc"]
    fn task7_g8_cipherctx_control() {
        let openssl = task7_openssl();
        let object = task7_object();
        let dir = std::env::temp_dir().join(format!("task7-g8-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let s = |name: &str| dir.join(name).to_string_lossy().into_owned();
        std::fs::write(dir.join("data16"), b"0123456789abcdef").unwrap();
        // T1: the cipher BIO news/frees seven CIPHER_CTXs on one enc run.
        let r = task7_run(
            "g8-enc",
            &[
                openssl.clone(),
                "enc".into(),
                "-aes-256-cbc".into(),
                "-pass".into(),
                "pass:x".into(),
                "-in".into(),
                s("data16"),
                "-out".into(),
                s("e1"),
            ],
            &dir,
            &object,
            false,
        );
        assert_eq!(r.exit, Some(0));
        assert_eq!(task7_totals(&r.rows, 71), (7, 7, 0, 0, 0));
        assert_eq!(task7_totals(&r.rows, 72), (7, 7, 0, 0, 0));
        task7_assert_void_clean(&r, 72);
        // Round-trip oracle: decrypt with the same password, compare bytes.
        task7_fixture(
            &openssl,
            &dir,
            &[
                "enc",
                "-d",
                "-aes-256-cbc",
                "-pass",
                "pass:x",
                "-in",
                "e1",
                "-out",
                "d1",
            ],
        );
        assert_eq!(
            std::fs::read(dir.join("data16")).unwrap(),
            std::fs::read(dir.join("d1")).unwrap()
        );
        // T3-negative for 71/72: plain digest touches no cipher contexts.
        let r = task7_run(
            "g8-dgst-neg71",
            &[
                openssl.clone(),
                "dgst".into(),
                "-sha256".into(),
                s("data16"),
            ],
            &dir,
            &object,
            false,
        );
        assert_eq!(r.exit, Some(0));
        task7_assert_idle(&r, 71);
        task7_assert_idle(&r, 72);
        std::fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    fn legacy_startup_acquisition_survives_retained_typed_prefix_then_refusal() {
        use crate::startup_objects::{StartupAcquisition, acquire_startup};
        // Three real, distinct retained ELF files. No fixture function executes.
        let mut body = String::from("ret\n");
        for id in 20..=72 {
            let name = wire::api(id).unwrap().export_name().unwrap();
            body.push_str(&format!(
                ".globl {name}\n.type {name},@function\n{name}: mov $1,%eax\nret\n.size {name},.-{name}\n"
            ));
        }
        body.push_str(".globl EVP_MAC_fetch\n.type EVP_MAC_fetch,@function\nEVP_MAC_fetch: mov %rdi,%rax\nret\n.size EVP_MAC_fetch,.-EVP_MAC_fetch\n");
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        assert_eq!(page, 4096, "this fixture uses the x86_64 base-page ABI");
        let mut fixtures: Vec<_> = [240, 4, 240]
            .into_iter()
            .map(|pages| {
                let mut f = startup_fixture::ForwarderFixture::new(&body, "ret");
                assert!(f.image.len() <= pages * page);
                f.image.resize(pages * page, 0);
                f
            })
            .collect();
        let child = crate::target::OwnedTarget::spawn_stopped(
            &["/bin/true".into()],
            crate::target::WorkloadDest::Null,
        )
        .unwrap();
        let custody = objects::StartupProcess::held(&child).unwrap();
        let discovery = ObservationBudget::default();
        let mut legacy = Vec::new();
        let mut typed = Vec::new();
        for (index, fixture) in fixtures.iter_mut().enumerate() {
            let sources =
                objects::startup_candidates(custody.clone(), fixture.file(), &discovery, None)
                    .unwrap();
            assert_eq!(sources.typed.len(), 1);
            typed.extend(sources.typed);
            if index == 0 {
                legacy = sources.apis;
            }
        }
        assert_eq!(legacy.len(), 55); // 53 operational exports plus query/unquery
        let anchor = 240 * (page + 64) + 4096;
        // This models remaining acquisition headroom after discovery. BOTH
        // stages share this account, including every retained anchor prefix.
        let budget = ObservationBudget::new(ObservationLimits {
            max_state_bytes: anchor + 53 * (96 + 512 + 256) + (16 << 10) + 4096,
            ..Default::default()
        });
        let mut roles = Roles::default();
        let mut startup = BTreeMap::new();
        let mut armed = BTreeSet::new();
        let mut retained = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let mut legacy_result = None;
        let mut typed_result = None;
        let outcomes = acquire_startup(|stage| match stage {
            StartupAcquisition::Legacy => {
                let result = (|| {
                    let mut resolved = Vec::new();
                    for source in std::mem::take(&mut legacy) {
                        let (api, site) = source.into_parts();
                        let Some(id) = (20..=72).find(|&id| wire::api(id) == Ok(api)) else {
                            continue;
                        };
                        roles.observe(
                            role_site(site.pid(), site.starttime(), &site),
                            id,
                            &budget,
                        )?;
                        resolved.push((id, site));
                    }
                    for (index, (api, site)) in resolved.into_iter().enumerate() {
                        budget.state(512)?;
                        let links = paired_links(
                            || Ok(std::fs::File::open("/dev/null").unwrap().into()),
                            || Ok(std::fs::File::open("/dev/null").unwrap().into()),
                        )?;
                        budget.state(256)?;
                        let attachment = Attachment {
                            object: object_id(&site),
                            site,
                            links,
                            cookie: index as u64 + 1,
                            api,
                            generation: 1,
                            advertisers: Vec::new(),
                            original: None,
                            historical: false,
                        };
                        retain_and_arm(&mut startup, child.pid(), attachment, |a| {
                            validate_then_arm(
                                || a.site.revalidate_object(),
                                || {
                                    armed.insert(a.cookie);
                                    Ok(())
                                },
                            )
                        })?;
                    }
                    Ok(())
                })();
                legacy_result = Some(result);
                result
            }
            StartupAcquisition::TypedSources => {
                let result = retain_typed_startup(
                    std::mem::take(&mut typed),
                    &budget.clone(),
                    &mut retained,
                    deadline,
                    &cancel,
                );
                typed_result = Some(result);
                result
            }
        });
        assert_eq!(
            legacy_result,
            Some(Ok(())),
            "optional anchors starved legacy acquisition"
        );
        assert_eq!(typed_result, Some(Err(ObservationGap::StateLimit)));
        assert_eq!(outcomes, [Ok(()), Err(ObservationGap::StateLimit)]);
        assert_eq!(
            retained.len(),
            1,
            "successful source prefix must remain retained"
        );
        assert_eq!(startup[&child.pid()].len(), 53);
        assert_eq!(armed.len(), 53);
        for a in &startup[&child.pid()] {
            assert!(roles.accepts(role_site(a.site.pid(), a.site.starttime(), &a.site), a.api));
            assert_eq!(a.links.len(), 2);
            assert!(
                a.links
                    .iter()
                    .all(|fd| unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } >= 0)
            );
            a.site.revalidate_object().unwrap();
        }
        // The actual installed-owner seam is exercised with inert host FDs;
        // this is ordering/custody evidence, not a native BPF attachment claim.
    }
    #[test]
    fn startup_partial_arm_failure_keeps_link_and_file_owners_until_cleanup() {
        use std::os::fd::AsRawFd;
        let child = crate::target::OwnedTarget::spawn_stopped(
            &["/bin/true".into()],
            crate::target::WorkloadDest::Null,
        )
        .unwrap();
        for gap in [
            ObservationGap::AttachFailed,
            ObservationGap::SnapshotLag,
            ObservationGap::ObjectChanged,
        ] {
            let (_fixture, mut a) = metadata_attachment(&child);
            a.links
                .push(std::fs::File::open("/dev/null").unwrap().into());
            let fd = a.links[0].as_raw_fd();
            let file = a.site.attachment_fd().as_raw_fd();
            let mut startup = BTreeMap::new();
            assert_eq!(
                retain_and_arm(&mut startup, child.pid(), a, |_| Err(gap)),
                Err(gap)
            );
            assert_eq!(startup[&child.pid()].len(), 1);
            assert!(unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0);
            assert!(unsafe { libc::fcntl(file, libc::F_GETFD) } >= 0);
            let a = startup.remove(&child.pid()).unwrap().pop().unwrap();
            disarm_links(a.links, || {
                assert!(
                    unsafe { libc::fcntl(file, libc::F_GETFD) } >= 0,
                    "file custody must outlive disarming links"
                );
                Ok(())
            })
            .unwrap();
            assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
            assert!(unsafe { libc::fcntl(file, libc::F_GETFD) } >= 0);
            drop(a.site);
            assert_eq!(unsafe { libc::fcntl(file, libc::F_GETFD) }, -1);
        }
    }
    #[test]
    #[ignore = "requires fresh observation object and native tracing privileges"]
    fn first_natural_stock_queries_survive_without_a_mapped_snapshot() {
        let object =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        let executable = std::env::var_os("OSSLSCOPE_TEST_OPENSSL")
            .map(|path| {
                path.into_string()
                    .expect("OSSLSCOPE_TEST_OPENSSL must be a UTF-8 executable path")
            })
            .unwrap_or_else(|| "/usr/bin/openssl".into());
        for algorithm in ["-sha512", "-sha3-256"] {
            let argv = [executable.as_str(), "dgst", algorithm, "/dev/null"]
                .map(str::to_owned)
                .to_vec();
            let mut child =
                crate::target::OwnedTarget::spawn_stopped(&argv, crate::target::WorkloadDest::Null)
                    .unwrap();
            let cancel = std::sync::atomic::AtomicBool::new(false);
            let mut budget = ObservationBudget::default();
            let startup = crate::startup_objects::prepare_owned_startup(
                &child,
                &argv,
                &mut budget,
                Instant::now() + Duration::from_secs(15),
                &cancel,
                None,
            )
            .unwrap();
            let mut session = ProviderSession::open_budgeted(budget, &object).unwrap();
            session
                .prearm_startup(
                    startup.apis,
                    Instant::now() + Duration::from_secs(5),
                    &cancel,
                    PrearmLinks::Create,
                )
                .unwrap();
            let rows = &session.startup[&child.pid()];
            let query = rows
                .iter()
                .find(|a| a.api == c::PUBLIC_QUERY)
                .expect("typed natural public query site");
            let identity = (
                query.site.starttime(),
                query.generation,
                query.site.object_hash().clone(),
            );
            assert!(session.targets.is_empty());
            let member = session.members.get(&child.pid(), 0).unwrap();
            assert_eq!(
                member.range_count, 0,
                "held process cannot supply predicted code ranges"
            );
            child.release_retaining_exit().unwrap();
            let until = Instant::now() + Duration::from_secs(5);
            while child.peek_exit().unwrap().is_none() {
                assert!(Instant::now() < until);
                std::thread::yield_now();
            }
            assert_eq!(child.peek_exit().unwrap(), Some(0));
            // Actual controller ordering includes reconcile before drain even
            // when the natural process exits during discovery.
            let snapshot = inventory::snapshot(&inventory::SnapshotOptions {
                pids: vec![child.pid()],
                ..Default::default()
            });
            let reconciliation = session.reconcile(&snapshot);
            // One bounded drain after ordinary exit; no readiness/query/getter
            // protocol, sleeps, target pacing or repeated library contexts.
            let mut batch = session.close_until(Instant::now() + Duration::from_secs(2));
            for gap in reconciliation.gaps {
                batch.gap(gap);
            }
            let facts: Vec<_> = batch
                .facts
                .iter()
                .filter(|f| f.api == wire::api(c::PUBLIC_QUERY).unwrap())
                .collect();
            let queries = facts
                .iter()
                .filter(|f| {
                    matches!(
                        f.payload,
                        ObservationPayload::QueryResult {
                            outcome: ApiOutcome::Success,
                            ..
                        }
                    )
                })
                .count();
            let advertisements = facts
                .iter()
                .filter(|f| matches!(f.payload, ObservationPayload::Algorithm { .. }))
                .count();
            assert!(
                queries > 0 && advertisements > 0,
                "{algorithm}: natural query={queries}, advertisements={advertisements}, gaps={:?}",
                batch.gaps
            );
            assert!(facts.iter().all(|f| f.pid == child.pid()
                && f.starttime == identity.0
                && f.generation == identity.1
                && f.object_sha256 == identity.2));
            assert!(
                batch.learned_sites.is_empty(),
                "unmapped startup grants no learned callback authority"
            );
            assert!(batch.gaps.contains(&ObservationGap::ProcessUnavailable));
            assert!(batch.gaps.contains(&ObservationGap::IntervalUnknown));
            assert!(batch.gaps.contains(&ObservationGap::FirstQueryUnknown));
            assert!(batch.gaps.contains(&ObservationGap::SamplingPartial));
            child.finish_observation().unwrap();
            println!(
                "{algorithm}: {queries} natural public query successes, {advertisements} algorithm advertisements; correct retained identity; ranges unknown; no callback attribution or COMPLETE; gaps={:?}",
                batch.gaps
            );
        }
    }
    /// Families-stage legacy-provider lane: stock `openssl dgst -md4
    /// -provider legacy` (MD4 ships only in the legacy provider)
    /// through legacy-only observation. Asserts exit 0, the
    /// independent MD4("abc") oracle, and observed successful queries
    /// plus advertisements — discovery-level evidence for the second
    /// configured provider. A no-legacy re-run must fail, proving the
    /// oracle depends on the legacy provider. Digest has no typed
    /// first-slice roles, so no attribution pin is claimed here.
    /// Lane env: `OSSLSCOPE_TEST_OPENSSL` selects the CLI;
    /// `OSSLSCOPE_TEST_PROVIDER_PATH` adds `-provider-path` when the
    /// lane module dir is not the compiled-in default (private
    /// 3.0.22/4.0.3 build trees).
    ///
    /// ```sh
    /// OSSL_PROVIDER_OBSERVATION_TEST_BPF=<provider object> \
    /// [OSSLSCOPE_TEST_OPENSSL=<lane CLI> LD_LIBRARY_PATH=<lane lib> \
    ///  OSSLSCOPE_TEST_PROVIDER_PATH=<lane providers dir>] \
    /// sudo -n <lib test binary> \
    ///     legacy_provider_md4_queries_are_observed --test-threads=1
    /// ```
    #[test]
    #[ignore = "families legacy-provider lane (sudo, pinned BPF objects)"]
    fn legacy_provider_md4_queries_are_observed() {
        const TAG: &str = "fam-legacy";
        const MD4_ABC: &str = "a448017aaf21d8525fc10ae87aa6729d";
        // This module is a top-level sibling of `tests`, so the lane
        // env parses inline (same as the neighboring startup test).
        let openssl = std::env::var_os("OSSLSCOPE_TEST_OPENSSL")
            .map(|path| {
                path.into_string()
                    .expect("OSSLSCOPE_TEST_OPENSSL must be a UTF-8 executable path")
            })
            .unwrap_or_else(|| "/usr/bin/openssl".into());
        let dir = std::env::temp_dir().join(format!(
            "osslscope-fam-legacy-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("abc.txt"), b"abc").unwrap();
        let mut argv = vec![openssl.clone(), "dgst".to_string(), "-md4".to_string()];
        if let Some(path) = std::env::var_os("OSSLSCOPE_TEST_PROVIDER_PATH") {
            argv.push("-provider-path".to_string());
            argv.push(
                path.into_string()
                    .expect("OSSLSCOPE_TEST_PROVIDER_PATH must be UTF-8"),
            );
        }
        argv.push("-provider".to_string());
        argv.push("legacy".to_string());
        argv.push(dir.join("abc.txt").to_string_lossy().into_owned());
        eprintln!("{TAG} argv={argv:?}");
        let object =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        let stdout_path = dir.join("out.txt");
        std::fs::write(&stdout_path, b"").unwrap();
        let mut child = crate::target::OwnedTarget::spawn_stopped(
            &argv,
            crate::target::WorkloadDest::File(stdout_path.clone()),
        )
        .unwrap();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let mut budget = ObservationBudget::default();
        let startup = crate::startup_objects::prepare_owned_startup(
            &child,
            &argv,
            &mut budget,
            Instant::now() + Duration::from_secs(15),
            &cancel,
            None,
        )
        .unwrap();
        let mut session = ProviderSession::open_budgeted(budget, &object).unwrap();
        session
            .prearm_startup(
                startup.apis,
                Instant::now() + Duration::from_secs(5),
                &cancel,
                PrearmLinks::Create,
            )
            .unwrap();
        let rows = &session.startup[&child.pid()];
        let query = rows
            .iter()
            .find(|a| a.api == c::PUBLIC_QUERY)
            .expect("typed natural public query site");
        let identity = (
            query.site.starttime(),
            query.generation,
            query.site.object_hash().clone(),
        );
        assert!(session.targets.is_empty());
        child.release_retaining_exit().unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        while child.peek_exit().unwrap().is_none() {
            assert!(Instant::now() < until, "{TAG}: workload never exited");
            std::thread::yield_now();
        }
        assert_eq!(child.peek_exit().unwrap(), Some(0), "{TAG}: public oracle");
        let snapshot = inventory::snapshot(&inventory::SnapshotOptions {
            pids: vec![child.pid()],
            ..Default::default()
        });
        let reconciliation = session.reconcile(&snapshot);
        let mut batch = session.close_until(Instant::now() + Duration::from_secs(2));
        for gap in reconciliation.gaps {
            batch.gap(gap);
        }
        let facts: Vec<_> = batch
            .facts
            .iter()
            .filter(|f| f.api == wire::api(c::PUBLIC_QUERY).unwrap())
            .collect();
        let queries = facts
            .iter()
            .filter(|f| {
                matches!(
                    f.payload,
                    ObservationPayload::QueryResult {
                        outcome: ApiOutcome::Success,
                        ..
                    }
                )
            })
            .count();
        let advertisements = facts
            .iter()
            .filter(|f| matches!(f.payload, ObservationPayload::Algorithm { .. }))
            .count();
        eprintln!(
            "{TAG} queries={queries} advertisements={advertisements} gaps={:?}",
            batch.gaps
        );
        assert!(
            queries > 0 && advertisements > 0,
            "{TAG}: natural query={queries}, advertisements={advertisements}, gaps={:?}",
            batch.gaps
        );
        assert!(facts.iter().all(|f| f.pid == child.pid()
            && f.starttime == identity.0
            && f.generation == identity.1
            && f.object_sha256 == identity.2));
        assert!(
            batch.learned_sites.is_empty(),
            "{TAG}: unmapped startup grants no learned callback authority"
        );
        child.finish_observation().unwrap();
        let output = std::fs::read_to_string(&stdout_path).unwrap();
        assert!(
            output.to_ascii_lowercase().contains(MD4_ABC),
            "{TAG}: observed output must carry the MD4 oracle, got {output:?}"
        );
        // The oracle depends on the legacy provider: the same digest
        // without `-provider legacy` must fail (default has no MD4).
        let mut bare = vec![openssl, "dgst".to_string(), "-md4".to_string()];
        bare.push(dir.join("abc.txt").to_string_lossy().into_owned());
        let rerun = std::process::Command::new(&bare[0])
            .args(&bare[1..])
            .output()
            .unwrap();
        assert!(
            !rerun.status.success()
                || !String::from_utf8_lossy(&rerun.stdout)
                    .to_ascii_lowercase()
                    .contains(MD4_ABC),
            "{TAG}: MD4 without the legacy provider must not verify"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    fn startup_pending_aliases_and_cookie_survive_first_mapped_authority() {
        let _fixtures = MAPPED_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
        use std::os::fd::AsRawFd;
        let f = startup_fixture::ForwarderFixture::new(
            ".byte 0xe9\n.long query_impl-.-4",
            ".byte 0xeb\n.byte unquery_impl-.-1",
        );
        let file = f.file();
        let len = file.metadata().unwrap().len() as usize;
        // Map real retained executable bytes before fork. The held child
        // inherits this fixture map; no fixture function or target protocol runs.
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        assert_ne!(address, libc::MAP_FAILED);
        struct Mapping(*mut libc::c_void, usize);
        impl Drop for Mapping {
            fn drop(&mut self) {
                unsafe {
                    libc::munmap(self.0, self.1);
                }
            }
        }
        let _mapping = Mapping(address, len);
        let child = crate::target::OwnedTarget::spawn_stopped(
            &["/bin/true".into()],
            crate::target::WorkloadDest::Null,
        )
        .unwrap();
        let budget = ObservationBudget::default();
        let mapped_file = file.try_clone().unwrap();
        let objects::StartupCandidates { apis: sites, .. } = objects::startup_candidates(
            objects::StartupProcess::held(&child).unwrap(),
            file,
            &budget,
            None,
        )
        .unwrap();
        let (_, site) = sites
            .into_iter()
            .map(|s| s.into_parts())
            .find(|(api, _)| *api == wire::api(c::PUBLIC_QUERY).unwrap())
            .unwrap();
        let object = object_id(&site);
        let starttime = site.starttime();
        let hash = site.object_hash().clone();
        let a = Attachment {
            site,
            object,
            links: Vec::new(),
            cookie: 81,
            generation: 19,
            api: c::PUBLIC_QUERY,
            advertisers: Vec::new(),
            original: None,
            historical: false,
        };
        let records = inventory::snapshot(&inventory::SnapshotOptions {
            pids: vec![child.pid()],
            ..Default::default()
        })
        .processes;
        let process = objects::fixture_support::mapped_process(&records[0], mapped_file, &budget);
        let mapped = process
            .resolve_api(wire::api(c::PUBLIC_QUERY).unwrap())
            .into_iter()
            .find(|s| s.site.object_hash() == &hash)
            .expect("independently mapped fixture authority")
            .site;
        let mut targets = BTreeMap::from([(
            child.pid(),
            Target {
                process,
                starttime,
                generation: 19,
                attachments: Vec::new(),
                ranges: 0,
                ready: false,
            },
        )]);
        let mut startup = BTreeMap::from([(child.pid(), vec![a])]);
        let mut r = c::Record {
            version: c::VERSION,
            size: 96,
            kind: c::ALGORITHM_BEGIN,
            pid: child.pid(),
            tid: child.pid(),
            cookie: 81,
            generation: 19,
            invocation: 7,
            api: c::PUBLIC_QUERY,
            operation: 1,
            outcome: 1,
            cacheability: 1,
            ..Default::default()
        };
        let decode = |r: &c::Record| {
            wire::decode_transport(unsafe {
                std::slice::from_raw_parts((r as *const c::Record).cast(), 96)
            })
            .unwrap()
        };
        let mut aliases = super::super::assembly::Sequences::default();
        let mut batch = ObservationBatch::default();
        assert!(
            record_binding(&targets, &startup, &r)
                .unwrap()
                .unwrap()
                .process
                .is_none()
        );
        assert!(assemble_payload(decode(&r), &mut aliases, &budget, &mut batch).is_none());
        assert!(aliases.incomplete());
        let mut a = startup.get_mut(&child.pid()).unwrap().pop().unwrap();
        a.adopt_site(mapped).unwrap();
        assert_eq!((a.cookie, a.generation, a.object), (81, 19, object));
        assert!(a.original.as_ref().unwrap().is_startup());
        targets.get_mut(&child.pid()).unwrap().attachments.push(a);
        let binding = record_binding(&targets, &startup, &r).unwrap().unwrap();
        assert_eq!(binding.starttime, starttime);
        assert_eq!(binding.attachment.site.object_hash(), &hash);
        assert!(binding.process.is_some());
        r.kind = c::ALIAS;
        r.algorithm = c::OTHER;
        r.function = c::OTHER;
        r.outcome = 0;
        assert!(assemble_payload(decode(&r), &mut aliases, &budget, &mut batch).is_none());
        r.kind = c::ALIAS_END;
        r.function = 1;
        let payload = assemble_payload(decode(&r), &mut aliases, &budget, &mut batch).unwrap();
        assert!(matches!(payload, ObservationPayload::Algorithm { .. }));
        assert!(!aliases.incomplete());
        assert!(
            batch.gaps.is_empty(),
            "handoff lost pending alias boundary: {:?}",
            batch.gaps
        );
        assemble_payload(decode(&r), &mut aliases, &budget, &mut batch);
        assert!(
            batch.gaps.contains(&ObservationGap::InvalidWire),
            "replayed terminal alias cannot become fresh evidence"
        );
    }
    #[test]
    #[ignore = "requires fresh observation object and native tracing privileges"]
    fn mapped_transition_reuses_prearmed_operational_and_metadata_cookies() {
        let dir = std::env::temp_dir().join(format!("osslscope-api-adopt-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let source = dir.join("app.c");
        let app = dir.join("app");
        std::fs::write(
            &source,
            r#"
#include <stdio.h>
#include <unistd.h>
#include <stddef.h>
static const char *ready, *go, *done;
struct dispatch { int id; void (*fn)(void); };
struct algorithm { const char *names, *properties; const struct dispatch *implementation; const char *description; };
__attribute__((noinline)) static void implementation(void) { __asm__ volatile(""); }
static const struct dispatch dispatch[] = { { 70001, implementation }, { 0, 0 } };
static const struct algorithm algorithms[] = { { "FUTURE-DIGEST", 0, dispatch, 0 }, { 0, 0, 0, 0 } };
__attribute__((noinline)) const struct algorithm *OSSL_PROVIDER_query_operation(const void *provider,int op,int *no_cache) {
 *no_cache=0;
 FILE *f=fopen(ready,"w"); if(!f) return 0; fclose(f);
 for(int i=0;i<15000 && access(go,F_OK);i++) usleep(1000);
 return access(go,F_OK)==0 ? algorithms : 0;
}
__attribute__((noinline)) int EVP_DigestUpdate(void *ctx,const void *data,size_t len) {
 int no_cache=-1;
 return OSSL_PROVIDER_query_operation((void*)1,1,&no_cache)!=0;
}
int main(int argc,char **argv) { if(argc!=4) return 2; ready=argv[1];go=argv[2];done=argv[3];
 if(EVP_DigestUpdate((void*)1,(void*)2,3)!=1) return 3;
 FILE *f=fopen(done,"w");if(!f)return 4;fclose(f);return 0; }
"#,
        )
        .unwrap();
        assert!(
            std::process::Command::new("cc")
                .args(["-O0", "-rdynamic", "-o"])
                .arg(&app)
                .arg(&source)
                .status()
                .unwrap()
                .success()
        );
        let ready = dir.join("ready");
        let go = dir.join("go");
        let done = dir.join("done");
        let argv = [&app, &ready, &go, &done]
            .map(|p| p.to_string_lossy().into_owned())
            .to_vec();
        let mut child =
            crate::target::OwnedTarget::spawn_stopped(&argv, crate::target::WorkloadDest::Null)
                .unwrap();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let mut budget = ObservationBudget::default();
        let startup = crate::startup_objects::prepare_owned_startup(
            &child,
            &argv,
            &mut budget,
            Instant::now() + Duration::from_secs(15),
            &cancel,
            None,
        )
        .unwrap();
        let object =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        let mut session = ProviderSession::open(ObservationLimits::default(), &object).unwrap();
        session
            .prearm_startup(
                startup.apis,
                Instant::now() + Duration::from_secs(5),
                &cancel,
                PrearmLinks::Create,
            )
            .unwrap();
        let before: BTreeSet<_> = session.api_owners.keys().copied().collect();
        assert_eq!(before.len(), 1);
        let query = session.startup[&child.pid()]
            .iter()
            .find(|a| a.api == c::PUBLIC_QUERY)
            .unwrap();
        let metadata_identity = (
            query.cookie,
            query.generation,
            query.object,
            query.site.starttime(),
            query.site.object_hash().clone(),
        );
        child.release_retaining_exit().unwrap();
        let until = Instant::now() + Duration::from_secs(10);
        while !ready.exists() {
            assert!(Instant::now() < until);
            std::thread::sleep(Duration::from_millis(1));
        }
        let snapshot = inventory::snapshot(&inventory::SnapshotOptions {
            pids: vec![child.pid()],
            ..Default::default()
        });
        let batch = session.reconcile(&snapshot);
        assert!(
            session.targets.get(&child.pid()).is_some_and(|t| t.ready),
            "{:?}",
            batch.gaps
        );
        assert_eq!(
            session.api_owners.keys().copied().collect::<BTreeSet<_>>(),
            before,
            "same-site API handoff minted duplicate physical probes"
        );
        assert!(session.startup.is_empty());
        let query = session.targets[&child.pid()]
            .attachments
            .iter()
            .find(|a| a.api == c::PUBLIC_QUERY)
            .unwrap();
        assert_eq!(
            (query.cookie, query.generation, query.object),
            (
                metadata_identity.0,
                metadata_identity.1,
                metadata_identity.2
            )
        );
        assert!(query.original.is_some());
        std::fs::write(&go, b"go").unwrap();
        while !done.exists() {
            assert!(Instant::now() < until);
            std::thread::sleep(Duration::from_millis(1));
        }
        // The done marker precedes exit. Terminal history requires the owned
        // pidfd to be ready before close: an unavailable but nonterminal source
        // must still be refused (covered by the live-failure host controls).
        // The query was held across adoption above; this wait only establishes
        // custody for its already queued return and advertisements.
        while child.peek_exit().unwrap().is_none() {
            assert!(Instant::now() < until);
            std::thread::yield_now();
        }
        assert_eq!(child.peek_exit().unwrap(), Some(0));
        let final_batch = session.close();
        let rows: Vec<_> = final_batch
            .api_activity
            .iter()
            .filter(|a| u32::from(a.row.api) == 22)
            .collect();
        assert_eq!(rows.len(), 1);
        let row = &rows[0].row;
        assert_eq!(
            (
                row.entries,
                row.observed_success,
                row.observed_failure,
                row.gaps.unpaired,
                row.gaps.tail
            ),
            (1, 1, 0, 0, 0)
        );
        let facts: Vec<_> = final_batch
            .facts
            .iter()
            .filter(|f| f.api == wire::api(c::PUBLIC_QUERY).unwrap())
            .collect();
        assert!(
            facts.iter().any(|f| matches!(
                f.payload,
                ObservationPayload::QueryResult {
                    outcome: ApiOutcome::Success,
                    ..
                }
            )),
            "pending startup query return was orphaned: reconcile_gaps={:?}, final_gaps={:?}, fact_count={}, query_fact_count={}",
            batch.gaps,
            final_batch.gaps,
            final_batch.facts.len(),
            facts.len()
        );
        assert!(
            facts
                .iter()
                .any(|f| matches!(f.payload, ObservationPayload::Algorithm { .. })),
            "pending startup advertisement was lost"
        );
        assert!(facts.iter().all(|f| f.starttime == metadata_identity.3
            && f.generation == metadata_identity.1
            && f.object_sha256 == metadata_identity.4));
        child.finish_observation().unwrap();
        println!(
            "mapped handoff: same operational/metadata cookies and generation; one paired scalar success; pending natural fixture query/advertisement retained; no tail/unpaired gap"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    #[ignore = "requires privileged BPF and fresh observation object"]
    fn retire_then_readd_reacquires_operational_target_with_tight_budget() {
        // Regression: after a retire drops the live target, the re-add
        // must succeed so steady-state operational observation survives
        // the transition. The first attach's spend is permanent without
        // a retire-time release, so pre-fix the re-add always fails
        // StateLimit and operational rows stay zero.
        let argv = [
            "/usr/bin/openssl",
            "speed",
            "-elapsed",
            "-seconds",
            "60",
            "-evp",
            "SHA256",
            "-bytes",
            "64",
        ]
        .map(str::to_owned)
        .to_vec();
        let mut child =
            crate::target::OwnedTarget::spawn_stopped(&argv, crate::target::WorkloadDest::Null)
                .unwrap();
        child.release_retaining_exit().unwrap();
        std::thread::sleep(Duration::from_millis(500));
        let records = inventory::snapshot(&inventory::SnapshotOptions {
            pids: vec![child.pid()],
            ..Default::default()
        })
        .processes;
        assert_eq!(records.len(), 1);
        let pid = child.pid();
        let object =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        let mut session = ProviderSession::open_budgeted(
            ObservationBudget::new(ObservationLimits::default()),
            &object,
        )
        .unwrap();
        session.set_deadline(Instant::now() + Duration::from_secs(120));
        let first = session.reconcile_records(&records);
        assert!(
            session.targets.contains_key(&pid),
            "first acquire must attach; gaps={:?}",
            first.gaps
        );
        // The attach must spend above the watermark, otherwise the
        // release assertions below prove nothing.
        let spent_after_attach = session.budget.state_spent_test();
        let attach_spend = spent_after_attach - session.setup_state_spent;
        assert!(
            attach_spend > 1 << 20,
            "attach must spend a nontrivial amount for the tight-budget check"
        );
        // Tighten the ceiling to spent-plus-half-an-attach: the re-add
        // costs about one attach, so pre-fix (no release) it must fail
        // StateLimit here, while post-fix the release frees a full
        // attach worth of room. Smaller caller limits are honored.
        session.budget.limits.max_state_bytes = spent_after_attach + attach_spend / 2;
        assert!(
            spent_after_attach > session.setup_state_spent,
            "attach must spend above the setup watermark"
        );
        let reads_after_attach = session.budget.spent_reads();
        assert!(
            reads_after_attach > session.setup_reads_spent,
            "attach must spend reads above the setup watermark"
        );
        session.set_deadline(Instant::now() + Duration::from_secs(120));
        session.retire_for_gap(
            pid,
            None,
            ObservationGap::ProcessChanged,
            &mut ObservationBatch::default(),
        );
        assert!(session.targets.is_empty(), "retire must drop the target");
        // Mechanism: with nothing live, retire releases acquisition
        // spend back to the setup watermark. Standing setup leases stay
        // live (their guards subtract on drop), so the release keeps
        // floor + reserved, never below.
        assert_eq!(
            session.budget.state_spent_test(),
            session.setup_state_spent + session.budget.reserved_test(),
            "retire must release non-reserved acquisition spend to the setup watermark"
        );
        assert_eq!(
            session.budget.spent_reads(),
            session.setup_reads_spent,
            "retire must release read spend to the setup watermark"
        );
        let records2 = inventory::snapshot(&inventory::SnapshotOptions {
            pids: vec![pid],
            ..Default::default()
        })
        .processes;
        assert_eq!(records2.len(), 1);
        session.set_deadline(Instant::now() + Duration::from_secs(120));
        let second = session.reconcile_records(&records2);
        assert!(
            session.targets.get(&pid).is_some_and(|t| t.ready),
            "re-add after retire must re-acquire a ready target; gaps={:?}",
            second.gaps
        );
        child.finish_observation().unwrap();
    }

    #[test]
    #[ignore = "requires privileged BPF and fresh observation object"]
    fn recoverable_retire_reuses_shared_admission_under_tight_process_budget() {
        // Regression: with max_processes = 1 (the focused spawn path), a
        // retire on a recoverable gap (ReadLimit from revalidation, not an
        // identity change) must preserve the incarnation so the next tick
        // re-adds through the shared admission. Pre-fix the re-add took
        // the fresh path, starved on ProcessLimit forever (the retired
        // lease stays alive through retained site custody), and the run
        // went permanently blind mid-window.
        let argv = [
            "/usr/bin/openssl",
            "speed",
            "-elapsed",
            "-seconds",
            "60",
            "-evp",
            "SHA256",
            "-bytes",
            "64",
        ]
        .map(str::to_owned)
        .to_vec();
        let mut child =
            crate::target::OwnedTarget::spawn_stopped(&argv, crate::target::WorkloadDest::Null)
                .unwrap();
        child.release_retaining_exit().unwrap();
        std::thread::sleep(Duration::from_millis(500));
        let records = inventory::snapshot(&inventory::SnapshotOptions {
            pids: vec![child.pid()],
            ..Default::default()
        })
        .processes;
        assert_eq!(records.len(), 1);
        let pid = child.pid();
        let object =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        let limits = super::super::ObservationLimits {
            max_processes: 1,
            ..Default::default()
        };
        let max_reads = limits.max_elf_read_bytes;
        let mut session =
            ProviderSession::open_budgeted(ObservationBudget::new(limits), &object).unwrap();
        session.set_deadline(Instant::now() + Duration::from_secs(120));
        let first = session.reconcile_records(&records);
        assert!(
            session.targets.contains_key(&pid),
            "first acquire must attach; gaps={:?}",
            first.gaps
        );
        // Pin the incarnation across the retire, simulating the focused
        // counter's learned-site custody: without the preserved-incarnation
        // path the re-add takes a fresh admission and must fail
        // ProcessLimit here (max_processes = 1, lease still held).
        let _pinned = session.targets[&pid].process.retained_incarnation();
        // Let the revalidation memo expire (1s grace): the attach's
        // fence checks stamp it, and the retirement check below must run
        // full — same as live tick spacing.
        std::thread::sleep(Duration::from_millis(1200));
        // Exhaust the read budget: the next reconcile's retirement
        // revalidation fails ReadLimit (recoverable), forcing the
        // preserve-and-defer path instead of a terminal retire.
        let room = max_reads.saturating_sub(session.budget.elf_read_bytes());
        session.budget.read(room).unwrap();
        let records2 = inventory::snapshot(&inventory::SnapshotOptions {
            pids: vec![pid],
            ..Default::default()
        })
        .processes;
        assert_eq!(records2.len(), 1);
        session.set_deadline(Instant::now() + Duration::from_secs(120));
        let retired = session.reconcile_records(&records2);
        assert!(
            retired.gaps.contains(&ObservationGap::ReadLimit),
            "retire must record the honest gap; gaps={:?}",
            retired.gaps
        );
        assert!(
            session.targets.is_empty(),
            "recoverable retire must drop the target"
        );
        assert!(
            session.refreshing.contains_key(&pid),
            "recoverable retire must preserve the incarnation for re-add"
        );
        // The re-add is deferred one tick (same cost class as the first
        // attach, so it must not run inside the retiring tick).
        let records3 = inventory::snapshot(&inventory::SnapshotOptions {
            pids: vec![pid],
            ..Default::default()
        })
        .processes;
        assert_eq!(records3.len(), 1);
        session.set_deadline(Instant::now() + Duration::from_secs(120));
        let recovered = session.reconcile_records(&records3);
        assert!(
            !recovered.gaps.contains(&ObservationGap::ProcessLimit),
            "re-add must reuse the shared admission; gaps={:?}",
            recovered.gaps
        );
        assert!(
            session.targets.get(&pid).is_some_and(|t| t.ready),
            "re-add after recoverable retire must re-acquire a ready target; gaps={:?}",
            recovered.gaps
        );
        drop(_pinned);
        child.finish_observation().unwrap();
    }
}
