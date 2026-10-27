// SPDX-License-Identifier: GPL-3.0-or-later
//! Owned, synchronous public-ABI session. No legacy discovery/session graph.
use super::{
    wire::{self, contract as c},
    *,
};
use crate::{inventory, loader};
use aya::maps::{Array, HashMap as BpfMap, Map, MapData, PerCpuArray, RingBuf};
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
#[derive(Default)]
pub struct ObservationBatch {
    pub facts: Vec<ObservationFact>,
    pub gaps: Vec<ObservationGap>,
    pub learned_sites: Vec<VerifiedSiteCandidate>,
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
struct Attachment {
    links: Vec<OwnedFd>,
    site: VerifiedSite,
    cookie: u64,
    api: u32,
    advertisers: Vec<ObjectHash>,
}
struct Target {
    process: VerifiedProcess,
    starttime: u64,
    generation: u64,
    attachments: Vec<Attachment>,
    ranges: usize,
}
pub struct ProviderSession {
    loaded: loader::Loaded,
    events: RingBuf<MapData>,
    config: BpfMap<MapData, u64, c::Config>,
    members: BpfMap<MapData, u32, c::Member>,
    ranges: BpfMap<MapData, c::RangeKey, c::Range>,
    loss: PerCpuArray<MapData, u64>,
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
fn specs() -> Vec<loader::MapSpec> {
    let shapes = [
        ("EVENTS", 27, 0, 0, 1 << 20),
        ("CONFIG", 1, 8, 24, 1024),
        ("MEMBERS", 1, 4, 24, 64),
        ("NAMESPACE", 2, 4, 16, 1),
        ("RANGES", 1, 8, 16, 8192),
        ("THREADS", 1, 16, 16, 4096),
        ("PENDING", 1, 24, 56, 4096),
        ("CURSORS", 1, 48, 4, 4096),
        ("LOSS", 6, 4, 8, 8),
        ("ALG_CLASS", 1, 8, 42, 1024),
        ("TRIP_CLASS", 1, 8, 22, 64),
        ("FUNCTIONS", 1, 8, 4, 1024),
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
    /// D3 membership epoch and mapped-object generation domains.
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
        if member.generation != target.generation || member.epoch != 1 {
            return Err(ObservationGap::MembershipUnknown);
        }
        target.process.revalidate()?;
        candidate.site.revalidate_object()
    }

    pub fn open(limits: ObservationLimits, object: &[u8]) -> Result<Self, ObservationGap> {
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
        let budget = ObservationBudget::new(limits);
        budget.state(
            object
                .len()
                .checked_mul(4)
                .ok_or(ObservationGap::StateLimit)?,
        )?;
        let programs = [
            loader::ProgSpec::uprobe("observation_entry"),
            loader::ProgSpec::uretprobe("observation_return"),
        ];
        let mut prepared = loader::prepare(object, &specs(), &programs)
            .map_err(|_| ObservationGap::InvalidObject)?;
        // Retain hard bounds while honoring lower pending/process limits in actual maps.
        for m in &mut prepared.maps {
            if matches!(m.name.as_str(), "PENDING" | "THREADS" | "CURSORS") {
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
        let mut functions = BpfMap::<_, u64, u32>::try_from(map(&loaded, "FUNCTIONS")?)
            .map_err(|_| ObservationGap::InvalidObject)?;
        for f in crate::kinds::FUNCS {
            if let Some(op) =
                f.op.and_then(|name| crate::kinds::OPS.iter().find(|op| op.name == name))
            {
                functions
                    .insert(((op.id as u64) << 32) | f.id as u64, f.id, 0)
                    .map_err(|_| ObservationGap::ClassifierFailed)?;
            }
        }
        ossl_bpf_sys::map_freeze(loaded.maps["FUNCTIONS"].as_raw_fd())
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
        Ok(Self {
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
            .sum()
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
        // Disarm before dropping links. Never walk kernel-private opaque joins.
        if self.members.remove(&pid).is_err() {
            b.gap(ObservationGap::Invalidated)
        }
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
    pub fn reconcile(&mut self, snapshot: &inventory::Snapshot) -> ObservationBatch {
        let mut b = ObservationBatch::default();
        if self.closed {
            return b;
        }
        let retire: Vec<_> = self
            .targets
            .iter()
            .filter_map(|(&pid, t)| {
                reconcile_retirement_gap(
                    snapshot
                        .processes
                        .iter()
                        .find(|p| p.pid == pid)
                        .map(|p| p.starttime),
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
        for record in &snapshot.processes {
            if self.targets.contains_key(&record.pid) {
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
        let Some(process) = acquire_observable(record, &mut self.budget)? else {
            return Ok(());
        };
        let ranges = order_ranges(process.executable_ranges()?)?;
        let generation = self.next_generation;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(ObservationGap::ProcessLimit)?;
        let mut target = Target {
            process,
            starttime: record.starttime,
            generation,
            attachments: Vec::new(),
            ranges: ranges.len(),
        };
        let pid = record.pid;
        let result = (|| {
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
            for id in 1..=15 {
                for resolved in target.process.resolve_api(wire::api(id)?) {
                    let key = role_site(pid, record.starttime, &resolved.site);
                    if !self.roles.observe(key, id, &self.budget)? {
                        disarm_site(&mut target, &resolved.site, &mut self.config)?;
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
            }
            for g in target.process.gaps() {
                b.gap(g)
            }
            target.process.revalidate()?;
            if target.attachments.is_empty() {
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
            // The second check fences setup changes after all links and membership.
            target.process.revalidate()?;
            Ok(())
        })();
        self.targets.insert(pid, target);
        if let Err(g) = result {
            self.retire(pid, b);
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
        if matches!(payload, ObservationPayload::Invalidation { .. }) {
            b.gap(ObservationGap::Invalidated)
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
    pub fn close(mut self) -> ObservationBatch {
        let mut b = self.drain(Instant::now() + Duration::from_millis(100));
        let pids: Vec<_> = self.targets.keys().copied().collect();
        for pid in pids {
            self.retire(pid, &mut b)
        }
        self.closed = true;
        b
    }
}
impl Drop for ProviderSession {
    fn drop(&mut self) {
        let pids: Vec<_> = self.targets.keys().copied().collect();
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
        module
            .info
            .exports
            .iter()
            .any(|api| (1..=15).any(|id| wire::api(id) == Ok(ObservationApi::Inventoried(*api))))
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
            if r.kind == c::QUERY {
                if let Err(g) = aliases.begin(&r, budget) {
                    b.gap(g);
                }
            } else if r.kind == c::INVALIDATION {
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
                    inventory::Api::OsslProviderGet0Dispatch,
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
            .push(inventory::Api::OsslProviderLoad);
        assert!(matches!(
            acquire_observable(&record, &mut budget),
            Err(ObservationGap::ProcessUnavailable)
        ));
        assert!(matches!(
            acquire_observable(&record, &mut budget),
            Err(ObservationGap::ProcessLimit)
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
}
