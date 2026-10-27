// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded retained-site counter. Samples are cumulative available-prefix
//! evidence, including fenced generations; they never assert terminal finality.
use crate::{
    evidence::*, inventory::NamespaceId, loader, provider_observation::VerifiedSiteCandidate,
};
use osslscope_ebpf_common::{CountValue, split_key};
use std::{
    ffi::CString,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    time::Instant,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CountFailure {
    Object,
    Map,
    Namespace,
    Identity,
    Attach,
    Read,
    Resource,
    Close,
}
#[derive(Clone, Copy, Debug)]
pub struct CountLimits {
    pub max_links: usize,
    pub max_cookies: usize,
    pub max_keys: usize,
    pub max_cpus: usize,
    pub max_state_bytes: usize,
    pub window: CountAdmissionWindow,
}
impl Default for CountLimits {
    fn default() -> Self {
        Self {
            max_links: 512,
            max_cookies: 4096,
            max_keys: 8192,
            max_cpus: 256,
            max_state_bytes: 32 << 20,
            window: CountAdmissionWindow {
                start_ns: 0,
                deadline_ns: 0,
            },
        }
    }
}
impl CountLimits {
    fn validate(self) -> Result<(), CountFailure> {
        let hard = Self::default();
        if self.max_links == 0
            || self.max_links > hard.max_links
            || self.max_cookies == 0
            || self.max_cookies > hard.max_cookies
            || self.max_keys == 0
            || self.max_keys > hard.max_keys
            || self.max_cpus == 0
            || self.max_cpus > hard.max_cpus
            || self.max_state_bytes == 0
            || self.max_state_bytes > hard.max_state_bytes
        {
            return Err(CountFailure::Resource);
        }
        Ok(())
    }
}
#[derive(Clone, Default)]
pub struct CountSample {
    pub sites: Vec<SiteExecution>,
    pub fenced: Vec<SiteExecution>,
    pub gaps: Vec<GapCounter>,
    pub admitted: u64,
    pub dropfail: u64,
    pub namespace_failures: u64,
    pub unattributed: u64,
}
mod fold;
pub use fold::{CountFold, SiteBinding};

fn gap(name: &str, value: u64) -> GapCounter {
    let (units, source) = match name {
        "focused_unattributed" | "focused_dropfail" => {
            (CounterUnits::Calls, CounterSource::KernelMap)
        }
        "focused_namespace_failures" => (CounterUnits::Events, CounterSource::KernelMap),
        "focused_metadata_changed" => (CounterUnits::Events, CounterSource::Discovery),
        "focused_attach" => (CounterUnits::Probes, CounterSource::Attach),
        "focused_identity" | "focused_namespace" | "focused_close" => {
            (CounterUnits::Events, CounterSource::Lifecycle)
        }
        "focused_resource" => (CounterUnits::Events, CounterSource::Setup),
        _ => (CounterUnits::Events, CounterSource::Drain),
    };
    GapCounter {
        name: name.into(),
        kind: CounterKind::Loss,
        units,
        source,
        value,
    }
}
/// Convert native retained-FD identity to the evidence/maps encoding explicitly.
pub fn evidence_device(native: u64) -> u64 {
    crate::plan::encode_device(libc::major(native), libc::minor(native))
}
struct Attachment {
    link: OwnedFd,
    candidates: Vec<VerifiedSiteCandidate>,
}
/// Owns maps, retained namespace, links and candidate custody. Links are closed
/// before candidate custody is released, including during unwinding/Drop.
pub struct FocusedCounter {
    loaded: loader::Loaded,
    namespace: File,
    expected_namespace: NamespaceId,
    pid: u32,
    starttime: Option<u64>,
    limits: CountLimits,
    cpus: usize,
    fold: CountFold,
    attachments: Vec<Attachment>,
    retired: bool,
    totals: [u64; 3],
}
impl FocusedCounter {
    pub fn open(
        bytes: &[u8],
        pid: u32,
        namespace: NamespaceId,
        limits: CountLimits,
    ) -> Result<Self, CountFailure> {
        limits.validate()?;
        if pid == 0 {
            return Err(CountFailure::Identity);
        }
        if limits.window.start_ns == 0 || limits.window.deadline_ns <= limits.window.start_ns {
            return Err(CountFailure::Object);
        }
        let mut fold = CountFold::new(limits)?;
        fold.charge(bytes.len().checked_mul(4).ok_or(CountFailure::Resource)?)?;
        let prepared = loader::prepare_focused_count(bytes).map_err(|_| CountFailure::Object)?;
        let cpus = aya::util::nr_cpus().map_err(|_| CountFailure::Read)?;
        if cpus == 0 || cpus > limits.max_cpus {
            return Err(CountFailure::Resource);
        }
        fold.charge(
            cpus.checked_mul(48)
                .and_then(|n| n.checked_add(limits.max_keys * 192))
                .ok_or(CountFailure::Resource)?,
        )?;
        let ns = File::open("/proc/self/ns/pid").map_err(|_| CountFailure::Namespace)?;
        validate_namespace(&ns, namespace)?;
        let loaded = loader::load(&prepared).map_err(|_| CountFailure::Object)?;
        // Inspect actual kernel FDs before every typed-sized IO, including init.
        for shape in loader::FOCUSED_COUNT_MAPS {
            checked_map(&loaded, shape.name)?;
        }
        let mut counter = Self {
            loaded,
            namespace: ns,
            expected_namespace: namespace,
            pid,
            starttime: None,
            limits,
            cpus,
            fold,
            attachments: Vec::new(),
            retired: false,
            totals: [0; 3],
        };
        let NamespaceId { device, inode } = namespace;
        let mut config = [0u8; 16];
        config[..8].copy_from_slice(&device.to_ne_bytes());
        config[8..].copy_from_slice(&inode.to_ne_bytes());
        counter.write("TARGET", 0, &0u64.to_ne_bytes())?;
        counter.write("NS_CONFIG", 0, &config)?;
        counter.write("GEN", 0, &counter.fold.generation.to_ne_bytes())?;
        counter.write("WINDOW", 0, &limits.window.start_ns.to_ne_bytes())?;
        counter.write("WINDOW", 1, &limits.window.deadline_ns.to_ne_bytes())?;
        validate_namespace(&counter.namespace, namespace)?;
        counter.write("TARGET", 0, &(pid as u64).to_ne_bytes())?;
        counter.retired = false;
        Ok(counter)
    }
    fn write(&self, name: &str, key: u32, value: &[u8]) -> Result<(), CountFailure> {
        checked_map(&self.loaded, name)?
            .update(&key.to_ne_bytes(), value)
            .map_err(|_| CountFailure::Map)
    }
    fn failure(&mut self, e: CountFailure) {
        self.fold.gap(match e {
            CountFailure::Namespace => "focused_namespace",
            CountFailure::Identity => "focused_identity",
            CountFailure::Attach => "focused_attach",
            CountFailure::Resource => "focused_resource",
            CountFailure::Close => "focused_close",
            _ => "focused_read",
        });
    }
    fn close_links(&mut self) {
        // Destructure explicitly: link must close before the candidate FD.
        for Attachment { link, candidates } in self.attachments.drain(..) {
            drop(link);
            drop(candidates);
        }
    }
    pub fn retire(&mut self) {
        if self.retired && self.attachments.is_empty() {
            return;
        }
        if self.write("TARGET", 0, &0u64.to_ne_bytes()).is_err() {
            self.failure(CountFailure::Close);
        }
        self.close_links();
        if let Err(e) = self.fold.fence() {
            self.failure(e);
        }
        self.retired = true;
    }
    pub fn attach(
        &mut self,
        candidate: VerifiedSiteCandidate,
        installed_ns: u64,
    ) -> Result<(), CountFailure> {
        self.attach_group(vec![candidate], installed_ns)
    }
    /// Attach one same-physical-site batch with its metadata frozen before the
    /// first link. Mixed physical sites/epochs are refused before attachment.
    pub fn attach_group(
        &mut self,
        candidates: Vec<VerifiedSiteCandidate>,
        installed_ns: u64,
    ) -> Result<(), CountFailure> {
        let result = self.attach_group_inner(candidates, installed_ns);
        if let Err(e) = result {
            self.failure(e);
            if self.retired && !self.attachments.is_empty() {
                self.retire();
            }
        }
        result
    }
    fn attach_group_inner(
        &mut self,
        candidates: Vec<VerifiedSiteCandidate>,
        installed_ns: u64,
    ) -> Result<(), CountFailure> {
        let first = candidates.first().ok_or(CountFailure::Identity)?;
        if first.pid() != self.pid
            || self.starttime.is_some_and(|s| s != first.starttime())
            || installed_ns == 0
        {
            return Err(CountFailure::Identity);
        }
        validate_namespace(&self.namespace, self.expected_namespace)?;
        for candidate in &candidates {
            if candidate.pid() != first.pid()
                || candidate.starttime() != first.starttime()
                || candidate.generation() != first.generation()
                || candidate.site().generation() != first.site().generation()
                || candidate.site().native_device() != first.site().native_device()
                || candidate.site().inode() != first.site().inode()
                || candidate.site().file_offset() != first.site().file_offset()
                || candidate.site().object_hash() != first.site().object_hash()
            {
                return Err(CountFailure::Identity);
            }
            candidate
                .site()
                .revalidate_object()
                .map_err(|_| CountFailure::Identity)?;
        }
        // Charge retention/conversion before constructing owned metadata.
        let state = candidates
            .iter()
            .try_fold(1024usize, |n, c| {
                c.advertiser_candidates()
                    .len()
                    .checked_mul(1024)
                    .and_then(|v| v.checked_add(1024))
                    .and_then(|v| n.checked_add(v))
            })
            .ok_or(CountFailure::Resource)?;
        self.fold.charge(state)?;
        let mut site_binding = binding(first, installed_ns);
        for candidate in candidates.iter().skip(1) {
            site_binding
                .candidates
                .extend(binding(candidate, installed_ns).candidates);
        }
        if self
            .fold
            .session
            .is_some_and(|s| s != site_binding.session_generation)
            || self.fold.rows.values().any(|r| {
                r.active
                    && r.row.site == site_binding.site
                    && r.mapping != site_binding.mapping_generation
            })
        {
            self.retire();
        }
        if self.fold.generation == 0 {
            return Err(CountFailure::Resource);
        }
        if self.retired {
            self.write("GEN", 0, &self.fold.generation.to_ne_bytes())?;
            validate_namespace(&self.namespace, self.expected_namespace)?;
        }
        let program = self
            .loaded
            .progs
            .get("count_entry")
            .ok_or(CountFailure::Object)?
            .as_raw_fd();
        let path = CString::new(format!(
            "/proc/self/fd/{}",
            first.site().attachment_fd().as_raw_fd()
        ))
        .map_err(|_| CountFailure::Attach)?;
        let mut link = None;
        self.fold.attach(site_binding, |cookie, _| {
            let fd = ossl_bpf_sys::link_create_uprobe_multi(
                program,
                &path,
                &[first.site().file_offset()],
                &[cookie as u64],
                self.pid,
            )
            .map_err(|_| CountFailure::Attach)?;
            if candidates
                .iter()
                .any(|c| c.site().revalidate_object().is_err())
            {
                drop(fd);
                return Err(CountFailure::Identity);
            }
            if validate_namespace(&self.namespace, self.expected_namespace).is_err() {
                drop(fd);
                return Err(CountFailure::Namespace);
            }
            link = Some(fd);
            Ok(())
        })?;
        self.starttime = Some(first.starttime());
        if let Some(link) = link {
            self.attachments.push(Attachment { link, candidates });
        }
        if self.retired {
            self.write("TARGET", 0, &(self.pid as u64).to_ne_bytes())?;
            self.retired = false;
        }
        Ok(())
    }
    pub fn sample(&mut self, deadline: Instant) -> CountSample {
        if let Err(e) = self.read_snapshot(deadline) {
            self.failure(e);
        }
        let mut sample = self.fold.sample();
        [sample.admitted, sample.dropfail, sample.namespace_failures] = self.totals;
        if sample.dropfail > 0 {
            sample.gaps.push(gap("focused_dropfail", sample.dropfail));
        }
        if sample.namespace_failures > 0 {
            sample
                .gaps
                .push(gap("focused_namespace_failures", sample.namespace_failures));
        }
        // Concurrent reads are prefixes, not a consistent terminal cut. A
        // mismatch stays a gap; never invent counts to balance the ledger.
        let counted = SiteExecution::sum_calls(&sample.sites)
            .saturating_add(SiteExecution::sum_calls(&sample.fenced))
            .saturating_add(sample.unattributed)
            .saturating_add(sample.dropfail);
        if counted != sample.admitted {
            sample.gaps.push(gap("focused_ledger_mismatch", 1));
        }
        sample
    }
    fn read_snapshot(&mut self, deadline: Instant) -> Result<(), CountFailure> {
        let check = || {
            if Instant::now() >= deadline {
                Err(CountFailure::Read)
            } else {
                Ok(())
            }
        };
        check()?;
        let map = checked_map(&self.loaded, "COUNTS")?;
        let keys = map
            .keys(self.limits.max_keys as u32)
            .map_err(|_| CountFailure::Read)?;
        let mut bytes = vec![0u8; self.cpus * 24];
        for key in keys {
            check()?;
            map.lookup(&key, &mut bytes)
                .map_err(|_| CountFailure::Read)?;
            let values: Vec<_> = bytes
                .chunks_exact(24)
                .map(|v| CountValue {
                    count: u64::from_ne_bytes(v[..8].try_into().unwrap()),
                    first_ns: u64::from_ne_bytes(v[8..16].try_into().unwrap()),
                    last_ns: u64::from_ne_bytes(v[16..].try_into().unwrap()),
                })
                .collect();
            let (cookie, generation) = split_key(u64::from_ne_bytes(
                key.try_into().map_err(|_| CountFailure::Read)?,
            ));
            self.fold.observe(cookie, generation, &values)?;
        }
        for (i, name) in ["ADMITTED", "DROPFAIL", "NSFAIL"].iter().enumerate() {
            check()?;
            let map = checked_map(&self.loaded, name)?;
            let mut bytes = vec![0u8; self.cpus * 8];
            map.lookup(&0u32.to_ne_bytes(), &mut bytes)
                .map_err(|_| CountFailure::Read)?;
            let total = bytes
                .chunks_exact(8)
                .try_fold(0u64, |n, v| {
                    n.checked_add(u64::from_ne_bytes(v.try_into().unwrap()))
                })
                .ok_or(CountFailure::Read)?;
            if total < self.totals[i] {
                return Err(CountFailure::Read);
            }
            self.totals[i] = total;
        }
        check()
    }
    pub fn close(mut self, deadline: Instant) -> CountSample {
        self.retire();
        self.sample(deadline)
    }
}
impl Drop for FocusedCounter {
    fn drop(&mut self) {
        if !self.retired {
            let _ = self.write("TARGET", 0, &0u64.to_ne_bytes());
        }
        self.close_links();
    }
}
fn checked_map<'a>(
    loaded: &'a loader::Loaded,
    name: &str,
) -> Result<loader::BorrowedMap<'a>, CountFailure> {
    let shape = loader::FOCUSED_COUNT_MAPS
        .iter()
        .find(|s| s.name == name)
        .ok_or(CountFailure::Map)?;
    let map = loader::BorrowedMap::new(loaded.maps.get(name).ok_or(CountFailure::Map)?.as_fd())
        .map_err(|_| CountFailure::Map)?;
    let info = map.info;
    if [
        info.map_type,
        info.key_size,
        info.value_size,
        info.max_entries,
        info.flags,
    ] != [
        shape.map_type,
        shape.key_size,
        shape.value_size,
        shape.max_entries,
        shape.flags,
    ] {
        return Err(CountFailure::Map);
    }
    Ok(map)
}
fn validate_namespace(retained: &File, expected: NamespaceId) -> Result<(), CountFailure> {
    fn identity(file: &File) -> Result<NamespaceId, CountFailure> {
        let meta = file.metadata().map_err(|_| CountFailure::Namespace)?;
        Ok(NamespaceId {
            device: meta.dev(),
            inode: meta.ino(),
        })
    }
    let current = File::open("/proc/self/ns/pid").map_err(|_| CountFailure::Namespace)?;
    let proc_pid = std::fs::read_link("/proc/self").map_err(|_| CountFailure::Namespace)?;
    if identity(retained)? != expected
        || identity(&current)? != expected
        || proc_pid.to_str().and_then(|s| s.parse::<u32>().ok()) != Some(std::process::id())
    {
        return Err(CountFailure::Namespace);
    }
    Ok(())
}
fn binding(candidate: &VerifiedSiteCandidate, installed_ns: u64) -> SiteBinding {
    let site = candidate.site();
    // No provider-class or complete candidate-set inference from advertisement.
    let candidates = candidate
        .advertiser_candidates()
        .iter()
        .map(|advertiser| {
            CandidateIdentity::new(
                ObjectId(advertiser.clone().into()),
                "unknown".into(),
                operation_id(candidate.operation()),
                candidate.function().id(),
                vec![candidate.algorithm().label().into()],
                candidate.alias_quality().weak,
            )
        })
        .collect();
    SiteBinding {
        site: SiteKey {
            object: ObjectId(site.object_hash().clone().into()),
            device: evidence_device(site.native_device()),
            inode: site.inode(),
            offset: site.file_offset(),
        },
        session_generation: candidate.generation(),
        mapping_generation: site.generation(),
        candidates,
        installed_ns,
    }
}
fn operation_id(operation: crate::provider_observation::Operation) -> u32 {
    (0..=22)
        .find(|id| crate::provider_observation::Operation::from_id(*id) == Some(operation))
        .unwrap_or(0)
}
