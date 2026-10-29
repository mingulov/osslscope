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
#[derive(Default)]
pub struct ObservationBatch {
    pub facts: Vec<ObservationFact>,
    pub gaps: Vec<ObservationGap>,
    pub learned_sites: Vec<VerifiedSiteCandidate>,
    pub static_candidates: Vec<VerifiedStaticCandidate>,
    pub api_activity: Vec<ProcessApiActivity>,
    /// Internal provider reacquisition marker for stronger inventory authority.
    /// Count may bridge only after independently revalidating retained custody;
    /// this is not a claim that process or backing code changed identity.
    pub refreshed_processes: Vec<u32>,
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
/// Pure object ABI admission, shared with ordinary command preflight.
pub(crate) fn prepare_object(object: &[u8]) -> Result<loader::Prepared, ObservationGap> {
    let programs = [
        loader::ProgSpec::uprobe("observation_entry"),
        loader::ProgSpec::uretprobe("observation_return"),
    ];
    loader::prepare(object, &specs(), &programs).map_err(|_| ObservationGap::InvalidObject)
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
#[cfg(test)]
thread_local! { static EXPIRE_STATIC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
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
    events: RingBuf<MapData>,
    config: BpfMap<MapData, u64, c::Config>,
    members: BpfMap<MapData, u32, c::Member>,
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
    roles: Roles,
    aliases: super::assembly::Sequences,
    budget: ObservationBudget,
    next_cookie: u64,
    next_generation: u64,
    emitted: usize,
    learned: BTreeSet<(u32, u64, u64, u64, u64)>,
    last_loss: [u64; 8],
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
        if let Some(gap) = process_retirement_gap(&target.process) {
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
        let mut prepared = prepare_object(object)?;
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
        let loaded =
            loader::load_gated(&prepared, &gate).map_err(|_| ObservationGap::BpfUnavailable)?;
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
            ranges: BpfMap::try_from(map(&loaded, "RANGES")?)
                .map_err(|_| ObservationGap::InvalidObject)?,
            loss: PerCpuArray::try_from(map(&loaded, "LOSS")?)
                .map_err(|_| ObservationGap::InvalidObject)?,
            loaded,
            targets: BTreeMap::new(),
            refreshing: BTreeMap::new(),
            roles: Roles::default(),
            aliases: super::assembly::Sequences::default(),
            budget,
            next_cookie: 1,
            next_generation: 1,
            emitted: 0,
            learned: BTreeSet::new(),
            last_loss: [0; 8],
            last_drain: Instant::now(),
            closed: false,
        })
    }
    fn link_count(&self) -> usize {
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
    }
    fn attach_pair(
        &mut self,
        pid: u32,
        api: u32,
        site: VerifiedSite,
        advertisers: Vec<ObjectHash>,
        existing: usize,
        generation: u64,
    ) -> Result<Attachment, ObservationGap> {
        if self.final_drain || !self.gate.admitting() {
            return Err(ObservationGap::Invalidated);
        }
        if self.link_count() + existing + 2 > self.budget.limits.max_links {
            return Err(ObservationGap::LinkLimit);
        }
        self.budget.state(512 + advertisers.len() * 96)?;
        site.revalidate_object()?;
        let cookie = self.next_cookie;
        self.next_cookie = self
            .next_cookie
            .checked_add(1)
            .ok_or(ObservationGap::LinkLimit)?;
        let path = CString::new(format!(
            "/proc/self/fd/{}",
            site.attachment_fd().as_raw_fd()
        ))
        .map_err(|_| ObservationGap::AttachFailed)?;
        (|| {
            let links = paired_links(
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
            )?;
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
        retire_source_owners(
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
        )
    }
    pub(crate) fn set_deadline(&self, deadline: Instant) {
        self.budget.set_deadline(deadline);
    }
    pub fn reconcile(&mut self, snapshot: &inventory::Snapshot) -> ObservationBatch {
        self.reconcile_records(&snapshot.processes)
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
        for (pid, gap) in retire {
            self.retire_for_gap(pid, records.iter().find(|r| r.pid == pid), gap, &mut b);
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
            if refreshed.contains(&record.pid) {
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
            for id in (1..=16).chain(20..=48) {
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
            target.process.revalidate()?;
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
            target.process.revalidate()?;
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
                self.retire_for_gap(pid, Some(record), g, b);
            }
            return Err(g);
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
                self.retire_for_gap(pid, None, gap, &mut b);
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
        loop {
            if Instant::now() >= deadline {
                b.gap(ObservationGap::DrainOverrun);
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
                break;
            }
        }
        for index in 0..8 {
            match self.loss.get(&(index as u32), 0) {
                Ok(values) => {
                    let total = values.iter().fold(0u64, |sum, v| sum.saturating_add(*v));
                    if total > self.last_loss[index] {
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
        let target = self.targets.get_mut(&pid).unwrap();
        if let Some(existing) = target
            .attachments
            .iter_mut()
            .find(|a| same_site(&a.site, &site))
        {
            if let Err(g) = merge_candidates(&mut existing.advertisers, advertisers, &self.budget) {
                b.gap(g)
            }
            return;
        }
        if let Err(g) = target.process.revalidate() {
            b.gap(g);
            self.retire_for_gap(pid, None, g, b);
            return;
        }
        let generation = target.generation;
        match self.attach_pair(pid, api, site, advertisers, 0, generation) {
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
                    self.retire_for_gap(pid, None, g, b);
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
    /// Sealed public-export capability: static table shapes never grant an ABI.
    pub(crate) fn prearm_startup(
        &mut self,
        sites: Vec<super::objects::StartupApiSite>,
        deadline: Instant,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<(), ObservationGap> {
        if self.final_drain || !self.gate.admitting() {
            return Err(ObservationGap::Invalidated);
        }
        let mut resolved = Vec::new();
        for site in sites {
            let (api, site) = site.into_parts();
            let id = (1..=16)
                .chain(20..=48)
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
        for (api, site) in resolved {
            if cancel.load(std::sync::atomic::Ordering::Relaxed) || Instant::now() >= deadline {
                return Err(ObservationGap::SnapshotLag);
            }
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
            let advertisers = if api == c::PROVIDER_INIT {
                vec![site.object_hash().clone()]
            } else {
                Vec::new()
            };
            let a = self.attach_pair(pid, api, site, advertisers, 0, generation)?;
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
fn arm_attachment(
    config: &mut BpfMap<MapData, u64, c::Config>,
    process: &VerifiedProcess,
    a: &Attachment,
    pid: u32,
    generation: u64,
) -> Result<(), ObservationGap> {
    let result = validate_then_arm(
        || {
            process.revalidate()?;
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
        // Independent fixed total for the actual thirteen ordinary provider maps
        // on sixteen possible CPUs, excluding the separately owned ADMIT gate.
        let required = 7_034_952;
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
    #[test]
    #[ignore = "requires OSSL_PROVIDER_OBSERVATION_TEST_BPF pointing to a rebuilt object; preparation only"]
    fn real_bpf_object_prepares_when_built() {
        let path = std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF")
            .expect("required test-only object path OSSL_PROVIDER_OBSERVATION_TEST_BPF");
        let object = std::fs::read(path).expect("required test-only object must be readable");
        let result = loader::prepare(
            &object,
            &specs(),
            &[
                loader::ProgSpec::uprobe("observation_entry"),
                loader::ProgSpec::uretprobe("observation_return"),
            ],
        );
        assert!(
            result.is_ok(),
            "real object preparation: {}",
            result.err().unwrap()
        );
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
        let (_, sites, _) = objects::startup_candidates(
            objects::StartupProcess::held(&child).unwrap(),
            file,
            &budget,
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
                    target.process.revalidate(),
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
                    || fixture.targets[&pid].process.revalidate(),
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
            let later = fixture.targets[&pid].process.revalidate().unwrap_err();
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
            let unavailable = fixture.targets[&pid].process.revalidate().unwrap_err();
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
        let (_, sites, _) = objects::startup_candidates(
            objects::StartupProcess::held(child).unwrap(),
            f.file(),
            &ObservationBudget::default(),
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
            )
            .unwrap();
            let mut session = ProviderSession::open_budgeted(budget, &object).unwrap();
            session
                .prearm_startup(
                    startup.apis,
                    Instant::now() + Duration::from_secs(5),
                    &cancel,
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
        let (_, sites, _) = objects::startup_candidates(
            objects::StartupProcess::held(&child).unwrap(),
            file,
            &budget,
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
}
