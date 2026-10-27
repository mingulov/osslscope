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
    pub fn function(&self) -> FunctionIdentity {
        self.function
    }
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
        ("MEMBERS", 1, 4, 16, 64),
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
    fn attach(
        &mut self,
        pid: u32,
        generation: u64,
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
        let result = (|| {
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
            self.config
                .insert(
                    cookie,
                    c::Config {
                        generation,
                        object: object_id(&site),
                        pid,
                        api,
                    },
                    0,
                )
                .map_err(|_| ObservationGap::AttachFailed)?;
            Ok(Attachment {
                links,
                site,
                cookie,
                api,
                advertisers,
            })
        })();
        if result.is_err() {
            let _ = self.config.remove(&cookie);
        }
        result
    }
    fn retire(&mut self, pid: u32, b: &mut ObservationBatch) {
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
                if !snapshot
                    .processes
                    .iter()
                    .any(|p| p.pid == pid && p.starttime == t.starttime)
                    || t.process.revalidate().is_err()
                {
                    Some(pid)
                } else {
                    None
                }
            })
            .collect();
        for pid in retire {
            self.retire(pid, &mut b);
            b.gap(ObservationGap::IntervalUnknown)
        }
        for record in &snapshot.processes {
            if self.targets.contains_key(&record.pid) {
                continue;
            }
            if self.targets.len() >= self.budget.limits.max_processes {
                b.gap(ObservationGap::ProcessLimit);
                break;
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
        let process = acquire(record, &mut self.budget)?;
        let ranges = process.executable_ranges()?;
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
                    if target
                        .attachments
                        .iter()
                        .any(|a| same_site(&a.site, &resolved.site))
                    {
                        b.gap(ObservationGap::AmbiguousSite);
                        continue;
                    }
                    let advertisers = if id == c::PROVIDER_INIT {
                        vec![resolved.site.object_hash().clone()]
                    } else {
                        Vec::new()
                    };
                    match self.attach(
                        pid,
                        generation,
                        id,
                        resolved.site,
                        advertisers,
                        target.attachments.len() * 2,
                    ) {
                        Ok(a) => target.attachments.push(a),
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
                Some(bytes) => wire::decode(&bytes),
                None => break,
            };
            match event {
                Ok(e) => self.consume(e, &mut b),
                Err(g) => b.gap(g),
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
                Err(_) => b.gap(ObservationGap::BpfUnavailable),
            }
        }
        b
    }
    fn consume(&mut self, event: wire::ProviderEvent, b: &mut ObservationBatch) {
        let r = event.record;
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
        let hash = attachment.site.object_hash().clone();
        let advertisers = attachment.advertisers.clone();
        let starttime = target.starttime;
        let mut payload = event.into_payload();
        if r.code != 0 {
            let site = match target
                .process
                .relocate(TransientCodeAddress::from_kernel_event(r.code))
            {
                Ok(s) => s,
                Err(g) => {
                    b.gap(g);
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
                c::QUERY | c::ALGORITHM => ObservationSource::ProviderQuery,
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
        let Some(target) = self.targets.get_mut(&pid) else {
            return;
        };
        if let Some(existing) = target
            .attachments
            .iter_mut()
            .find(|a| same_site(&a.site, &site))
        {
            if existing.api != api {
                b.gap(ObservationGap::AmbiguousSite);
                return;
            }
            if let Err(g) = merge_candidates(&mut existing.advertisers, advertisers, &self.budget) {
                b.gap(g)
            }
            return;
        }
        if let Err(g) = target.process.revalidate() {
            b.gap(g);
            return;
        }
        let generation = target.generation;
        match self.attach(pid, generation, api, site, advertisers, 0) {
            Ok(a) => {
                if let Some(target) = self.targets.get_mut(&pid) {
                    if let Err(g) = target.process.revalidate() {
                        let _ = self.config.remove(&a.cookie);
                        b.gap(g);
                        return;
                    }
                    target.attachments.push(a);
                }
            }
            Err(g) => b.gap(g),
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
    use super::*;
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
        use std::os::fd::FromRawFd;
        let raw = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
        assert!(raw >= 0);
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };
        assert!(paired_links(|| Ok(owned), || Err(ObservationGap::AttachFailed)).is_err());
        assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFD) }, -1);
    }
    #[test]
    fn real_bpf_object_prepares_when_built() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("crates/ebpf/target/bpfel-unknown-none/release/osslscope-provider-observation");
        let Ok(object) = std::fs::read(path) else {
            return;
        };
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
