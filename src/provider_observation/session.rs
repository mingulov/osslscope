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
    loaded: loader::Loaded,
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
        let member = self
            .members
            .get(&candidate.pid, 0)
            .map_err(|_| ObservationGap::MembershipUnknown)?;
        validate_candidate_member(&member, target.generation)?;
        target.process.revalidate()?;
        candidate.site.revalidate_object()
    }

    pub fn open(limits: ObservationLimits, object: &[u8]) -> Result<Self, ObservationGap> {
        Self::open_budgeted(ObservationBudget::new(limits), object)
    }
    pub(crate) fn open_budgeted(
        budget: ObservationBudget,
        object: &[u8],
    ) -> Result<Self, ObservationGap> {
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
        let loaded = loader::load(&prepared).map_err(|_| ObservationGap::BpfUnavailable)?;
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
    ) -> Result<Attachment, ObservationGap> {
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
                links,
                site,
                cookie,
                api,
                advertisers,
            })
        })()
    }
    fn retire(&mut self, pid: u32, b: &mut ObservationBatch) {
        self.aliases.retire(pid);
        b.learned_sites.retain(|site| site.pid != pid);
        b.static_candidates.retain(|site| site.pid() != pid);
        // Disarm before dropping links. Never walk kernel-private opaque joins.
        if self.members.remove(&pid).is_err() {
            b.gap(ObservationGap::Invalidated)
        }
        self.retire_startup(pid);
        if let Some(target) = self.targets.remove(&pid) {
            for a in target.attachments {
                let _ = self.config.remove(&a.cookie);
                drop(a.links);
            }
            for index in 0..target.ranges {
                let _ = self.ranges.remove(&c::RangeKey {
                    pid,
                    index: index as u32,
                });
            }
        }
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
        if self.closed {
            return b;
        }
        let retire: Vec<_> = self
            .targets
            .iter()
            .filter_map(|(&pid, t)| {
                reconcile_retirement_gap(
                    records.iter().find(|p| p.pid == pid).map(|p| p.starttime),
                    t.starttime,
                    || t.process.revalidate(),
                )
                .map(|gap| (pid, gap))
            })
            .collect();
        for (pid, gap) in retire {
            self.retire(pid, &mut b);
            b.gap(gap);
            b.gap(ObservationGap::IntervalUnknown)
        }
        for record in records {
            if self.targets.get(&record.pid).is_some_and(|t| t.ready) {
                continue;
            }
            match self.add_target(record, &mut b) {
                Ok(()) => {}
                Err(g) => b.gap(g),
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
        let mut target = if let Some(target) = self.targets.remove(&record.pid) {
            target
        } else {
            let Some(process) = acquire_observable(record, &mut self.budget)? else {
                return Ok(());
            };
            // Only the first mapped adoption of the original held incarnation
            // may retain its scalar epoch. Real retirement/remapping allocates a
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
            let mut public_sites = Vec::new();
            for id in (1..=16).chain(20..=48) {
                for resolved in target.process.resolve_api(wire::api(id)?) {
                    self.roles.observe(
                        role_site(pid, record.starttime, &resolved.site),
                        id,
                        &self.budget,
                    )?;
                    self.budget
                        .state(2 * std::mem::size_of::<(u32, ApiSite)>())?;
                    public_sites.push((id, resolved));
                }
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
                        a.site.revalidate_object()?;
                        resolved.site.revalidate_object()?;
                        if a.site.object_hash() != resolved.site.object_hash() {
                            return Err(ObservationGap::ObjectChanged);
                        }
                        a.site = resolved.site;
                        arm_attachment(&mut self.config, &target.process, &a, pid, generation)
                    })();
                    if let Err(gap) = adopt {
                        let _ = self.config.remove(&a.cookie);
                        return Err(gap);
                    }
                    target.attachments.push(a);
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
                ) {
                    Ok(a) => {
                        arm_attachment(&mut self.config, &target.process, &a, pid, generation)?;
                        target.attachments.push(a)
                    }
                    Err(g) => b.gap(g),
                }
            }
            #[cfg(test)]
            EXPIRE_STATIC.with(|flag| {
                if flag.replace(false) {
                    self.budget.set_deadline(Instant::now());
                }
            });
            b.static_candidates
                .extend(target.process.static_candidates(&self.budget)?);
            for g in target.process.gaps() {
                b.gap(g)
            }
            target.process.revalidate()?;
            if target.attachments.is_empty() && b.static_candidates.is_empty() {
                return Err(ObservationGap::SymbolUnavailable);
            }
            self.members
                .insert(
                    pid,
                    c::Member {
                        generation,
                        epoch: 1,
                        range_count: target.ranges as u32,
                        reserved: 0,
                    },
                    0,
                )
                .map_err(|_| ObservationGap::AttachFailed)?;
            self.retire_startup(pid);
            // The second check fences setup changes after all links and membership.
            target.process.revalidate()?;
            Ok(())
        })();
        target.ready = result.is_ok();
        self.targets.insert(pid, target);
        if let Err(g) = result {
            if g != ObservationGap::SnapshotLag {
                self.retire(pid, b);
            }
            return Err(g);
        }
        b.gap(ObservationGap::FirstQueryUnknown);
        b.gap(ObservationGap::SamplingPartial);
        Ok(())
    }
    pub fn drain(&mut self, deadline: Instant) -> ObservationBatch {
        let mut b = ObservationBatch::default();
        let invalid: Vec<_> = self
            .startup
            .iter()
            .filter_map(|(&pid, rows)| {
                rows.iter()
                    .find_map(|a| a.site.revalidate_object().err())
                    .map(|gap| (pid, gap))
            })
            .collect();
        for (pid, gap) in invalid {
            b.gap(gap);
            self.retire(pid, &mut b);
        }
        if self.last_drain.elapsed() > Duration::from_millis(200) {
            b.gap(ObservationGap::SnapshotLag)
        }
        self.last_drain = Instant::now();
        let retired: Vec<_> = self
            .targets
            .iter()
            .filter_map(|(&pid, t)| t.process.revalidate().err().map(|g| (pid, g)))
            .collect();
        for (pid, g) in retired {
            self.retire(pid, &mut b);
            b.gap(g)
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
        if self.aliases.incomplete() {
            b.gap(ObservationGap::IntervalUnknown);
        }
        b
    }
    fn consume(&mut self, event: wire::Transport, b: &mut ObservationBatch) {
        let r = event.record();
        let Some(target) = self.targets.get(&r.pid) else {
            return;
        };
        if target.generation != r.generation {
            return;
        }
        let Some(attachment) = target
            .attachments
            .iter()
            .find(|a| a.cookie == r.cookie && a.api == r.api)
        else {
            b.gap(ObservationGap::InvalidWire);
            return;
        };
        if !self
            .roles
            .accepts(role_site(r.pid, target.starttime, &attachment.site), r.api)
        {
            b.gap(ObservationGap::AmbiguousSite);
            return;
        }
        let hash = attachment.site.object_hash().clone();
        let advertisers = attachment.advertisers.clone();
        let starttime = target.starttime;
        let Some(mut payload) = assemble_payload(event, &mut self.aliases, &self.budget, b) else {
            return;
        };
        if r.code != 0 {
            let site = match target
                .process
                .relocate(TransientCodeAddress::from_kernel_event(r.code))
            {
                Ok(s) => s,
                Err(g) => {
                    b.gap(g);
                    if identity_failure(g) {
                        self.retire(r.pid, b)
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
            self.retire(pid, b);
            return;
        }
        let generation = target.generation;
        match self.attach_pair(pid, api, site, advertisers, 0) {
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
                    self.retire(pid, b);
                    return;
                }
                self.targets.get_mut(&pid).unwrap().attachments.push(a);
            }
            Err(g) => {
                b.gap(g);
                if identity_failure(g) {
                    self.retire(pid, b)
                }
            }
        }
    }
    pub(crate) fn set_api_window(&mut self, start: u64, end: u64) -> Result<(), ObservationGap> {
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
    /// Separate sealed operational export capability: no static candidate casts.
    pub(crate) fn prearm_operational(
        &mut self,
        sites: Vec<super::objects::StartupApiSite>,
        deadline: Instant,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<(), ObservationGap> {
        let mut resolved = Vec::new();
        for site in sites {
            let (api, site) = site.into_parts();
            let id = u32::from(api);
            let key = role_site(site.pid(), site.starttime(), &site);
            self.roles.observe(key, id, &self.budget)?;
            resolved.push((id, site));
        }
        let generation = self.next_generation;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(ObservationGap::ProcessLimit)?;
        for (api, site) in resolved {
            if cancel.load(std::sync::atomic::Ordering::Relaxed) || Instant::now() >= deadline {
                return Err(ObservationGap::SnapshotLag);
            }
            let pid = site.pid();
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
            let a = self.attach_pair(pid, api, site, Vec::new(), 0)?;
            a.site.revalidate_object()?;
            self.config
                .insert(
                    a.cookie,
                    c::Config {
                        generation,
                        object: 0,
                        pid,
                        api,
                    },
                    0,
                )
                .map_err(|_| ObservationGap::AttachFailed)?;
            a.site.revalidate_object()?;
            self.startup.entry(pid).or_default().push(a);
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
                .map_err(|_| ObservationGap::AttachFailed)?;
        }
        Ok(())
    }
    pub fn close(self) -> ObservationBatch {
        self.close_until(Instant::now() + Duration::from_millis(100))
    }
    pub(crate) fn close_until(mut self, deadline: Instant) -> ObservationBatch {
        let mut b = self.drain(deadline);
        let pids: Vec<_> = self.targets.keys().copied().collect();
        for pid in pids {
            self.retire(pid, &mut b)
        }
        let pids: Vec<_> = self.startup.keys().copied().collect();
        for pid in pids {
            self.retire(pid, &mut b);
        }
        for (&cookie, &(pid, starttime, api)) in &self.api_owners {
            match self
                .api_totals
                .get(&cookie, 0)
                .map_err(|_| ObservationGap::InvalidWire)
                .and_then(|values| {
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
                        object: object_id(&a.site),
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

#[cfg(test)]
mod startup_api_controls {
    use super::*;
    #[test]
    #[ignore = "requires fresh observation object and native tracing privileges"]
    fn mapped_transition_reuses_prearmed_operational_cookies() {
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
__attribute__((noinline)) int EVP_DigestUpdate(void *ctx,const void *data,size_t len) {
 FILE *f=fopen(ready,"w"); if(!f) return 0; fclose(f);
 for(int i=0;i<15000 && access(go,F_OK);i++) usleep(1000);
 return access(go,F_OK)==0;
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
            .prearm_operational(
                startup.apis,
                Instant::now() + Duration::from_secs(5),
                &cancel,
            )
            .unwrap();
        let before: BTreeSet<_> = session.api_owners.keys().copied().collect();
        assert_eq!(before.len(), 1);
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
        std::fs::write(&go, b"go").unwrap();
        while !done.exists() {
            assert!(Instant::now() < until);
            std::thread::sleep(Duration::from_millis(1));
        }
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
        println!(
            "mapped handoff: same cookie, one entry, one paired successful return, no tail/unpaired gap"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
