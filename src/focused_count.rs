// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded retained-site counter. Samples are cumulative available-prefix
//! evidence, including fenced generations; they never assert terminal finality.
use crate::{
    evidence::*,
    inventory::NamespaceId,
    loader,
    provider_observation::{
        VerifiedSite, VerifiedSiteCandidate, VerifiedStaticCandidate,
        static_tables::{DynamicAlgorithmId, StaticTableProvenance, TableStorage},
    },
};
use osslscope_ebpf_common::{CountValue, split_key};
use std::{
    collections::BTreeMap,
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
    Deferred,
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
pub use crate::provider_observation::MetadataOrigin;
#[derive(Clone)]
pub enum CountCandidate {
    Static(VerifiedStaticCandidate),
    Learned(VerifiedSiteCandidate),
}
impl CountCandidate {
    pub fn site(&self) -> &VerifiedSite {
        match self {
            Self::Static(c) => c.site(),
            Self::Learned(c) => c.site(),
        }
    }
    pub fn pid(&self) -> u32 {
        match self {
            Self::Static(c) => c.pid(),
            Self::Learned(c) => c.pid(),
        }
    }
    pub fn starttime(&self) -> u64 {
        match self {
            Self::Static(c) => c.starttime(),
            Self::Learned(c) => c.starttime(),
        }
    }
}
/// Safe association metadata, independent from the frozen legacy attribution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateAssociation {
    pub origin: MetadataOrigin,
    pub algorithm: Option<DynamicAlgorithmId>,
    pub known_algorithm: Option<u16>,
    pub alias_quality: crate::provider_observation::AliasQuality,
    pub operation: Option<u32>,
    pub function_id: u32,
    pub advertisers: Vec<crate::provider_observation::ObjectHash>,
    pub static_provenance: Option<StaticTableProvenance>,
    pub storage: Option<TableStorage>,
    pub partial: bool,
    pub observed_ns: u64,
    pub observation_generation: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteAssociations {
    pub site: SiteKey,
    pub count_generation: u32,
    pub associations: Vec<CandidateAssociation>,
}
#[derive(Clone, Default)]
pub struct CountSample {
    pub sites: Vec<SiteExecution>,
    pub associations: Vec<SiteAssociations>,
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
    candidates: Vec<CountCandidate>,
}
#[cfg(test)]
thread_local! {
    static EXPIRE_AFTER_LINK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static EXPIRE_BEFORE_NATIVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
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
    associations: BTreeMap<u32, SiteAssociations>,
    startup_only: std::collections::BTreeSet<u32>,
    mapped_generation: Option<u64>,
    authority_refresh_pending: bool,
    mapped_guards: Vec<crate::provider_observation::VerifiedSite>,
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
            associations: BTreeMap::new(),
            startup_only: Default::default(),
            mapped_generation: None,
            authority_refresh_pending: false,
            mapped_guards: Vec::new(),
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
    /// Scalar readiness derived from owned physical links, not advertisements.
    pub fn active_site_count(&self) -> usize {
        self.fold.rows.values().filter(|r| r.active).count()
    }
    pub fn active_link_count(&self) -> usize {
        self.attachments.len()
    }
    /// Recheck independently retained Count custody, without obtaining any
    /// attachment authority from inventory metadata or the refresh marker.
    pub(crate) fn retain_authority(&mut self, refresh: bool) -> Result<(), CountFailure> {
        let result = (|| {
            validate_namespace(&self.namespace, self.expected_namespace)?;
            for attachment in &self.attachments {
                attachment.candidates[0]
                    .site()
                    .revalidate_object()
                    .map_err(|_| CountFailure::Identity)?;
            }
            // Startup FDs alone permit the initial exec; mapped guards preserve
            // the stronger mapping constraint once a file has been adopted.
            for guard in &self.mapped_guards {
                guard
                    .revalidate_object()
                    .map_err(|_| CountFailure::Identity)?;
            }
            Ok(())
        })();
        if let Err(failure) = result {
            self.failure(failure);
            self.retire();
        } else if refresh && !self.retired {
            self.authority_refresh_pending = true;
        }
        result
    }
    pub fn retire(&mut self) {
        if self.retired && self.attachments.is_empty() {
            return;
        }
        if self.write("TARGET", 0, &0u64.to_ne_bytes()).is_err() {
            self.failure(CountFailure::Close);
        }
        self.close_links();
        self.mapped_guards.clear();
        self.startup_only.clear();
        self.mapped_generation = None;
        self.authority_refresh_pending = false;
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
    /// Compatibility wrapper; learned metadata shares the same physical ledger.
    pub fn attach_group(
        &mut self,
        candidates: Vec<VerifiedSiteCandidate>,
        installed_ns: u64,
    ) -> Result<(), CountFailure> {
        let first = candidates.first().ok_or(CountFailure::Identity)?;
        if candidates.iter().any(|c| {
            site_key(c.site()) != site_key(first.site())
                || c.site().generation() != first.site().generation()
                || c.starttime() != first.starttime()
                || c.pid() != first.pid()
        }) {
            return Err(CountFailure::Identity);
        }
        self.attach_candidates(
            candidates
                .into_iter()
                .map(CountCandidate::Learned)
                .collect(),
            installed_ns,
        )
    }
    /// Group physical cookies by retained backing descriptor. Static candidates
    /// enter only the Count program, which has no argument or return reads.
    pub fn attach_candidates(
        &mut self,
        candidates: Vec<CountCandidate>,
        installed_ns: u64,
    ) -> Result<(), CountFailure> {
        self.attach_candidates_with_control(candidates, installed_ns, None)
    }
    pub(crate) fn attach_candidates_controlled(
        &mut self,
        candidates: Vec<CountCandidate>,
        installed_ns: u64,
        deadline: Instant,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<(), CountFailure> {
        self.attach_candidates_with_control(candidates, installed_ns, Some((deadline, cancel)))
    }
    fn attach_candidates_with_control(
        &mut self,
        candidates: Vec<CountCandidate>,
        installed_ns: u64,
        control: Option<(Instant, &std::sync::atomic::AtomicBool)>,
    ) -> Result<(), CountFailure> {
        let result = self.attach_candidates_inner(candidates, installed_ns, control);
        if let Err(e) = result {
            if e != CountFailure::Deferred {
                self.failure(e);
            }
            if matches!(e, CountFailure::Identity | CountFailure::Namespace) {
                self.retire();
            }
        }
        result
    }
    fn attach_candidates_inner(
        &mut self,
        candidates: Vec<CountCandidate>,
        installed_ns: u64,
        control: Option<(Instant, &std::sync::atomic::AtomicBool)>,
    ) -> Result<(), CountFailure> {
        let hard_deadline = self.limits.window.deadline_ns;
        let checkpoint = |native: bool| {
            use crate::capture::ClockPort;
            if control.is_some_and(|(_, c)| c.load(std::sync::atomic::Ordering::Relaxed)) {
                return Err(CountFailure::Attach);
            }
            if crate::capture::LiveClock
                .checked_monotonic_ns()
                .ok_or(CountFailure::Read)?
                >= hard_deadline
            {
                return Err(CountFailure::Attach);
            }
            if !native && control.is_some_and(|(d, _)| Instant::now() >= d) {
                return Err(CountFailure::Deferred);
            }
            Ok(())
        };
        checkpoint(false)?;
        if candidates.is_empty() {
            return Ok(());
        }
        let first = &candidates[0];
        if installed_ns == 0
            || first.pid() != self.pid
            || self.starttime.is_some_and(|s| s != first.starttime())
        {
            return Err(CountFailure::Identity);
        }
        let starttime = first.starttime();
        let mapping = first.site().generation();
        let startup = first.site().is_startup();
        if candidates.iter().any(|c| {
            c.pid() != self.pid
                || c.starttime() != starttime
                || c.site().generation() != mapping
                || c.site().is_startup() != startup
        }) {
            return Err(CountFailure::Identity);
        }
        validate_namespace(&self.namespace, self.expected_namespace)?;
        // Each process/object identity is revalidated once per retained file;
        // no per-row procfs traversal or repeated ELF parsing is required.
        let mut files: BTreeMap<(u64, u64), Vec<CountCandidate>> = BTreeMap::new();
        let input_charge = candidates
            .iter()
            .try_fold(0usize, |total, c| {
                let advertisers = match c {
                    CountCandidate::Static(_) => 0,
                    CountCandidate::Learned(c) => c.advertiser_candidates().len(),
                };
                advertisers
                    .checked_mul(1024)?
                    .checked_add(512)?
                    .checked_add(total)
            })
            .ok_or(CountFailure::Resource)?;
        let scratch_charge = self
            .fold
            .rows
            .len()
            .checked_mul(1024)
            .ok_or(CountFailure::Resource)?;
        let planning_charge = input_charge
            .checked_add(scratch_charge)
            .ok_or(CountFailure::Resource)?;
        self.fold.checked_charge(planning_charge)?;
        for candidate in candidates {
            files
                .entry((candidate.site().native_device(), candidate.site().inode()))
                .or_default()
                .push(candidate);
        }
        for file in files.values() {
            checkpoint(false)?;
            file[0]
                .site()
                .revalidate_object()
                .map_err(|_| CountFailure::Identity)?;
            if file
                .iter()
                .any(|c| c.site().object_hash() != file[0].site().object_hash())
            {
                return Err(CountFailure::Identity);
            }
        }
        // The first mapped epoch may arrive in several static/live batches.
        // Later epochs still fence normally; never let a partial first batch
        // make CountFold fence an unmatched startup cookie behind live links.
        let refresh = !startup && self.authority_refresh_pending;
        if refresh {
            self.retain_authority(false)?;
        }
        let transition = !startup
            && (refresh
                || (self.mapped_generation.is_none_or(|g| g == mapping)
                    && !self.startup_only.is_empty()));
        let mut promotions = Vec::new();
        let mut guards = Vec::new();
        if transition {
            let retained: BTreeMap<_, _> = self
                .attachments
                .iter()
                .flat_map(|a| &a.candidates)
                .map(|c| (site_key(c.site()), c.site()))
                .collect();
            let rows: BTreeMap<_, _> = self
                .fold
                .rows
                .iter()
                .filter(|(cookie, r)| (refresh || self.startup_only.contains(cookie)) && r.active)
                .map(|(&cookie, r)| (&r.row.site, cookie))
                .collect();
            for file in files.values() {
                let mut checked = false;
                for c in file {
                    let key = site_key(c.site());
                    if let Some(&cookie) = rows.get(&key) {
                        let previous = retained.get(&key).ok_or(CountFailure::Identity)?;
                        if !checked {
                            previous
                                .revalidate_object()
                                .map_err(|_| CountFailure::Identity)?;
                            guards.push(c.site().clone());
                            checked = true;
                        }
                        if !c
                            .site()
                            .matches_retained(previous)
                            .map_err(|_| CountFailure::Identity)?
                        {
                            return Err(CountFailure::Identity);
                        }
                        promotions.push(cookie);
                    }
                }
            }
        } else if self.fold.rows.iter().any(|(cookie, r)| {
            r.active && r.mapping != mapping && !self.startup_only.contains(cookie)
        }) || self.mapped_generation.is_some_and(|g| g != mapping)
        {
            self.retire();
        }
        if self.fold.generation == 0 {
            return Err(CountFailure::Resource);
        }
        if self.retired {
            self.write("GEN", 0, &self.fold.generation.to_ne_bytes())?;
        }
        // Plan on a copy: rows become visible only after every new link has
        // succeeded and both identity checks have passed.
        let mut planned = self.fold.clone_charged(planning_charge)?;
        if transition {
            planned.session = Some(mapping);
            if refresh {
                // All retained custody was independently revalidated. This is
                // provider bookkeeping only, not a code-mapping replacement.
                for row in planned.rows.values_mut().filter(|row| row.active) {
                    row.mapping = mapping;
                }
            }
            for cookie in &promotions {
                planned.rows.get_mut(cookie).expect("verified row").mapping = mapping;
            }
        }
        let mut prepared = Vec::new();
        let mut additions = Vec::new();
        let mut metadata = Vec::new();
        let program = self
            .loaded
            .progs
            .get("count_entry")
            .ok_or(CountFailure::Object)?
            .as_raw_fd();
        for file in files.into_values() {
            checkpoint(false)?;
            let mut sites: BTreeMap<u64, Vec<&CountCandidate>> = BTreeMap::new();
            for c in &file {
                sites.entry(c.site().file_offset()).or_default().push(c);
            }
            let mut offsets = Vec::new();
            let mut cookies = Vec::new();
            for (offset, group) in sites {
                let mut binding = count_binding(group[0], installed_ns);
                for c in group.iter().skip(1) {
                    binding
                        .candidates
                        .extend(count_binding(c, installed_ns).candidates);
                }
                let key = binding.site.clone();
                let (cookie, generation) = planned.attach(binding, |cookie, _| {
                    offsets.push(offset);
                    cookies.push(cookie as u64);
                    Ok(())
                })?;
                for c in group {
                    metadata.push((
                        cookie,
                        generation,
                        key.clone(),
                        association(c, installed_ns),
                    ));
                }
            }
            if offsets.is_empty() {
                continue;
            }
            if self.attachments.len() + prepared.len() >= self.limits.max_links {
                return Err(CountFailure::Resource);
            }
            planned.charge(256 + offsets.len() * 32)?;
            let path = CString::new(format!(
                "/proc/self/fd/{}",
                file[0].site().attachment_fd().as_raw_fd()
            ))
            .map_err(|_| CountFailure::Attach)?;
            prepared.push((file, path, offsets, cookies));
        }
        // All rows, associations, capacities and file locators are preflighted.
        // Once native effects begin, finish this bounded transaction despite a
        // scheduling tick expiry. Cancellation, identity and the hard Count
        // window remain checked before every subsequent native call.
        #[cfg(test)]
        EXPIRE_BEFORE_NATIVE.with(|flag| {
            if flag.replace(false) {
                let deadline = control.expect("controlled deadline test").0;
                std::thread::sleep(
                    deadline.saturating_duration_since(Instant::now())
                        + std::time::Duration::from_millis(1),
                );
            }
        });
        checkpoint(false)?;
        for (index, (file, path, offsets, cookies)) in prepared.into_iter().enumerate() {
            checkpoint(index > 0)?;
            file[0]
                .site()
                .revalidate_object()
                .map_err(|_| CountFailure::Identity)?;
            checkpoint(index > 0)?;
            // Cookies are never reused after a possibly observed native call.
            self.fold.next_cookie =
                cookies.last().copied().expect("nonempty native offsets") as u32 + 1;
            let link = ossl_bpf_sys::link_create_uprobe_multi(
                program, &path, &offsets, &cookies, self.pid,
            )
            .map_err(|_| CountFailure::Attach)?;
            #[cfg(test)]
            EXPIRE_AFTER_LINK.with(|flag| {
                if flag.replace(false) {
                    let deadline = control.expect("controlled deadline test").0;
                    std::thread::sleep(
                        deadline.saturating_duration_since(Instant::now())
                            + std::time::Duration::from_millis(1),
                    );
                }
            });
            file[0]
                .site()
                .revalidate_object()
                .map_err(|_| CountFailure::Identity)?;
            additions.push(Attachment {
                link,
                candidates: file,
            });
        }
        if control.is_some_and(|(_, c)| c.load(std::sync::atomic::Ordering::Relaxed)) {
            return Err(CountFailure::Attach);
        }
        validate_namespace(&self.namespace, self.expected_namespace)?;
        for a in &additions {
            a.candidates[0]
                .site()
                .revalidate_object()
                .map_err(|_| CountFailure::Identity)?;
        }
        for guard in &guards {
            guard
                .revalidate_object()
                .map_err(|_| CountFailure::Identity)?;
        }
        self.fold = planned;
        // Keep one latest mapped guard per retained file; all prior guards
        // were checked above before any authority-only replacement.
        for guard in guards {
            if let Some(previous) = self.mapped_guards.iter_mut().find(|previous| {
                previous.native_device() == guard.native_device()
                    && previous.inode() == guard.inode()
            }) {
                *previous = guard;
            } else {
                self.mapped_guards.push(guard);
            }
        }
        if refresh {
            self.authority_refresh_pending = false;
        }
        if startup {
            self.startup_only.extend(
                self.fold
                    .rows
                    .iter()
                    .filter(|(_, r)| r.active)
                    .map(|(&c, _)| c),
            );
        } else {
            self.mapped_generation = Some(mapping);
            for cookie in promotions {
                self.startup_only.remove(&cookie);
            }
        }
        self.attachments.extend(additions);
        for (cookie, count_generation, site, association) in metadata {
            let row = self
                .associations
                .entry(cookie)
                .or_insert_with(|| SiteAssociations {
                    site,
                    count_generation,
                    associations: Vec::new(),
                });
            if !row
                .associations
                .iter()
                .any(|a| same_association(a, &association))
            {
                row.associations.push(association);
            }
        }
        self.starttime = Some(starttime);
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
        sample.associations = self.associations.values().cloned().collect();
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
                candidate.numeric_operation(),
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

fn site_key(site: &VerifiedSite) -> SiteKey {
    SiteKey {
        object: ObjectId(site.object_hash().clone().into()),
        device: evidence_device(site.native_device()),
        inode: site.inode(),
        offset: site.file_offset(),
    }
}
fn count_binding(candidate: &CountCandidate, installed_ns: u64) -> SiteBinding {
    let mut b = match candidate {
        CountCandidate::Learned(c) => binding(c, installed_ns),
        CountCandidate::Static(c) => SiteBinding {
            site: site_key(c.site()),
            session_generation: c.site().generation(),
            mapping_generation: c.site().generation(),
            candidates: Vec::new(),
            installed_ns,
        },
    };
    // Advertisement generations cannot multiply physical entries. Only the
    // verified process/mapping incarnation owns this attachment lifetime.
    b.session_generation = candidate.site().generation();
    b
}
fn association(candidate: &CountCandidate, observed_ns: u64) -> CandidateAssociation {
    match candidate {
        CountCandidate::Static(c) => CandidateAssociation {
            origin: MetadataOrigin::StaticPublicTableCandidate,
            algorithm: c.algorithm(),
            known_algorithm: c.known_algorithm(),
            alias_quality: c.alias_quality(),
            operation: c.operation_hint(),
            function_id: c.function_id(),
            advertisers: Vec::new(),
            static_provenance: Some(c.provenance()),
            storage: Some(c.storage()),
            partial: c.partial(),
            observed_ns,
            observation_generation: c.site().generation(),
        },
        CountCandidate::Learned(c) => CandidateAssociation {
            origin: MetadataOrigin::ObservedPublicAbi,
            algorithm: Some(c.dynamic_algorithm()),
            known_algorithm: Some(c.algorithm().into()),
            alias_quality: c.alias_quality(),
            operation: Some(c.numeric_operation()),
            function_id: c.function().id(),
            advertisers: c.advertiser_candidates().to_vec(),
            static_provenance: None,
            storage: None,
            partial: c.alias_quality().status != crate::provider_observation::AliasStatus::Complete,
            observed_ns: c.observed_ns(),
            observation_generation: c.generation(),
        },
    }
}
fn same_association(a: &CandidateAssociation, b: &CandidateAssociation) -> bool {
    let mut b = b.clone();
    b.observed_ns = a.observed_ns;
    *a == b
}

#[cfg(test)]
mod startup_controls {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::Duration;
    #[test]
    #[ignore = "requires privileged BPF and fresh observation/count objects"]
    fn owned_authority_refresh_preserves_stock_population_and_known_calls() {
        use crate::capture::ClockPort;
        use crate::provider_observation::{
            ObservationBatch, ObservationBudget, ObservationGap, ObservationLimits, ProviderSession,
        };
        use std::{
            fs,
            io::{BufRead, BufReader, Write},
            os::fd::FromRawFd,
            process::Command,
        };
        let dir =
            std::env::temp_dir().join(format!("osslscope-owned-refresh-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let provider = dir.join("fixture.so");
        let app = dir.join("fixture");
        assert!(
            Command::new("cc")
                .args(["-shared", "-fPIC", "-O1", "-Wl,-Bsymbolic", "-o"])
                .arg(&provider)
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/provider_observation_provider.c"
                ))
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("cc")
                .args(["-O1", "-o"])
                .arg(&app)
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/provider_observation.c"
                ))
                .arg(format!("-L{}", dir.display()))
                .arg(format!("-Wl,-rpath,{}", dir.display()))
                .args(["-Wl,--no-as-needed", "-l:fixture.so", "-lcrypto", "-ldl"])
                .status()
                .unwrap()
                .success()
        );
        let bytes = fs::read(&provider).unwrap();
        let elf = goblin::elf::Elf::parse(&bytes).unwrap();
        let symbol = elf
            .dynsyms
            .iter()
            .find(|s| elf.dynstrtab.get_at(s.st_name) == Some("fixture_count_entry"))
            .unwrap();
        let segment = elf
            .program_headers
            .iter()
            .find(|p| {
                p.p_type == 1
                    && symbol.st_value >= p.p_vaddr
                    && symbol.st_value < p.p_vaddr + p.p_filesz
            })
            .unwrap();
        let offset = segment.p_offset + symbol.st_value - segment.p_vaddr;
        let object: String = {
            use sha2::{Digest, Sha256};
            Sha256::digest(&bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        };
        let input = dir.join("commands");
        assert!(
            Command::new("mkfifo")
                .arg(&input)
                .status()
                .unwrap()
                .success()
        );
        let mut commands = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&input)
            .unwrap();
        let mut pipe = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let read = unsafe { fs::File::from_raw_fd(pipe[0]) };
        let write = unsafe { fs::File::from_raw_fd(pipe[1]) };
        let argv = vec![
            app.to_str().unwrap().into(),
            provider.to_str().unwrap().into(),
            input.to_str().unwrap().into(),
        ];
        struct Child(crate::target::OwnedTarget);
        impl Drop for Child {
            fn drop(&mut self) {
                // This test alone owns this finite fixture, including panic paths.
                if self.0.state() != crate::target::CustodyState::Reaped {
                    unsafe {
                        libc::kill(self.0.pid() as i32, libc::SIGKILL);
                    }
                    let _ = self.0.finish_observation();
                }
            }
        }
        let mut child = Child(
            crate::target::OwnedTarget::spawn_stopped(
                &argv,
                crate::target::WorkloadDest::Fd(write.as_raw_fd()),
            )
            .unwrap(),
        );
        let cancel = AtomicBool::new(false);
        let startup = crate::startup_objects::prepare_owned_startup(
            &child.0,
            &argv,
            &mut ObservationBudget::default(),
            Instant::now() + Duration::from_secs(20),
            &cancel,
        )
        .unwrap();
        let bytes = fs::read(std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT").unwrap()).unwrap();
        let start = crate::capture::LiveClock.checked_monotonic_ns().unwrap();
        let mut counter = FocusedCounter::open(
            &bytes,
            child.0.pid(),
            crate::focused_capture::observer_namespace().unwrap(),
            CountLimits {
                window: CountAdmissionWindow {
                    start_ns: start,
                    deadline_ns: start + 60_000_000_000,
                },
                ..Default::default()
            },
        )
        .unwrap();
        counter
            .attach_candidates(
                startup
                    .candidates
                    .into_iter()
                    .map(CountCandidate::Static)
                    .collect(),
                start,
            )
            .unwrap();
        let population = counter.active_site_count();
        let cookies = counter.fold.next_cookie;
        let links = counter.active_link_count();
        assert!(
            population > 2048 && population <= 4096,
            "real stock population={population}"
        );
        child.0.release_retaining_exit().unwrap();
        drop(write);
        let mut output = BufReader::new(read);
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        assert_eq!(line, "ready\n");
        let mut command = |text: &str| -> String {
            writeln!(commands, "{text}").unwrap();
            commands.flush().unwrap();
            let mut response = String::new();
            loop {
                let mut line = String::new();
                assert!(output.read_line(&mut line).unwrap() > 0);
                let ack = line.starts_with("ack ");
                response.push_str(&line);
                if ack {
                    assert!(
                        line.starts_with(&format!("ack {} 1 ", &text[..1])),
                        "{response}"
                    );
                    break;
                }
            }
            response
        };
        command("I");
        command("P");
        command("Q");
        assert!(command("C37").contains("calls C 37 37"));
        let known = |sample: &CountSample| {
            sample
                .sites
                .iter()
                .chain(&sample.fenced)
                .filter(|s| s.site.object.0 == object && s.site.offset == offset)
                .map(|s| s.calls)
                .sum::<u64>()
        };
        println!(
            "prearm population={population} cookies={} links={links}",
            cookies - 1
        );
        assert_eq!(
            known(&counter.sample(Instant::now() + Duration::from_secs(2))),
            37
        );
        let records = crate::inventory::snapshot(&crate::inventory::SnapshotOptions {
            pids: vec![child.0.pid()],
            ..Default::default()
        })
        .processes;
        assert_eq!(records.len(), 1);
        let mut partial = records.clone();
        let library = partial[0]
            .modules
            .iter_mut()
            .find(|m| m.info.kind == crate::inventory::ObjectKind::OpenSslCompatible)
            .unwrap();
        assert_eq!(
            library.identity_status,
            crate::inventory::IdentityStatus::Verified
        );
        library.identity_status = crate::inventory::IdentityStatus::LocatorCandidate;
        let observation =
            fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        let budget = ObservationBudget::new(ObservationLimits {
            max_processes: 1,
            ..Default::default()
        });
        let mut session = ProviderSession::open_budgeted(budget.clone(), &observation).unwrap();
        let mut gaps = std::collections::BTreeSet::new();
        let mut state = 0;
        let apply = |session: &ProviderSession,
                     counter: &mut FocusedCounter,
                     batch: &ObservationBatch,
                     gaps: &mut _,
                     state: &mut _| {
            crate::focused_capture::process_batch(
                session,
                counter,
                batch,
                child.0.pid(),
                (
                    start + 60_000_000_000,
                    Instant::now() + Duration::from_secs(10),
                    &cancel,
                ),
                gaps,
                state,
            )
            .unwrap();
        };
        session.set_deadline(Instant::now() + Duration::from_secs(10));
        let first = session.reconcile_records(&partial);
        assert!(first.gaps.contains(&ObservationGap::IdentityUnverified));
        apply(&session, &mut counter, &first, &mut gaps, &mut state);
        assert_eq!(
            counter.active_site_count(),
            population,
            "locator uncertainty retired independently valid prearmed sites"
        );
        assert_eq!(counter.fold.next_cookie, cookies);
        session.set_deadline(Instant::now() + Duration::from_secs(10));
        let refresh = session.reconcile_records(&records);
        assert_eq!(refresh.refreshed_processes, vec![child.0.pid()]);
        assert!(refresh.static_candidates.is_empty());
        apply(&session, &mut counter, &refresh, &mut gaps, &mut state);
        let recovered = session.reconcile_records(&records);
        assert!(
            !recovered.static_candidates.is_empty(),
            "reacquisition gaps: {:?}",
            recovered.gaps
        );
        apply(&session, &mut counter, &recovered, &mut gaps, &mut state);
        assert_eq!(counter.active_site_count(), population);
        assert_eq!(
            counter.fold.next_cookie, cookies,
            "authority refresh replayed cookies"
        );
        assert_eq!(
            counter.active_link_count(),
            links,
            "authority refresh duplicated links"
        );
        assert_eq!(counter.fold.generation, 1);
        assert!(command("C11").contains("calls C 11 48"));
        assert_eq!(
            known(&counter.sample(Instant::now() + Duration::from_secs(2))),
            48
        );
        let reads_after = budget.elf_read_bytes();
        let state_after = (
            counter.fold.next_cookie,
            counter.fold.state_bytes,
            counter.active_link_count(),
        );
        for _ in 0..3 {
            let stable = session.reconcile_records(&records);
            assert!(stable.static_candidates.is_empty() && stable.refreshed_processes.is_empty());
            apply(&session, &mut counter, &stable, &mut gaps, &mut state);
            assert_eq!(budget.elf_read_bytes(), reads_after);
            assert_eq!(
                (
                    counter.fold.next_cookie,
                    counter.fold.state_bytes,
                    counter.active_link_count()
                ),
                state_after
            );
        }
        // A real retained-file stamp change must defeat the refresh marker.
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&provider, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(counter.retain_authority(true), Err(CountFailure::Identity));
        assert_eq!(counter.active_site_count(), 0);
        assert_eq!(counter.active_link_count(), 0);
        let final_sample = counter.close(Instant::now() + Duration::from_secs(2));
        assert_eq!(
            known(&final_sample),
            48,
            "fenced historical+current conservation"
        );
        assert!(final_sample.sites.is_empty());
        session.close_until(Instant::now() + Duration::from_secs(1));
        writeln!(commands, "E").unwrap();
        commands.flush().unwrap();
        let end = Instant::now() + Duration::from_secs(2);
        while child.0.peek_exit().unwrap().is_none() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(child.0.peek_exit().unwrap(), Some(0));
        child.0.finish_observation().unwrap();
        println!(
            "owned prearm={population} physical sites cookies={} links={links}; partial mapped/verified refresh/stable; independent 37+11=48 physical entries, final fenced=48; cap=4096",
            cookies - 1
        );
        println!(
            "stable Count state={} bytes, provider ELF reads={reads_after}; real backing stamp change retired all links without changing conserved48",
            state_after.1
        );
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    #[ignore = "requires privileged BPF and freshly built focused count object"]
    fn first_mapped_epoch_in_partial_batches_preserves_native_cookies() {
        use crate::capture::ClockPort;
        let argv = [
            "/usr/bin/openssl",
            "speed",
            "-elapsed",
            "-seconds",
            "5",
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
        let sites = crate::startup_objects::prepare_owned_startup(
            &child,
            &argv,
            &mut crate::provider_observation::ObservationBudget::default(),
            Instant::now() + Duration::from_secs(10),
            &AtomicBool::new(false),
        )
        .unwrap();
        let bytes =
            std::fs::read(std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT").unwrap()).unwrap();
        let start_ns = crate::capture::LiveClock.checked_monotonic_ns().unwrap();
        let mut counter = FocusedCounter::open(
            &bytes,
            child.pid(),
            crate::focused_capture::observer_namespace().unwrap(),
            CountLimits {
                window: CountAdmissionWindow {
                    start_ns,
                    deadline_ns: start_ns + 15_000_000_000,
                },
                ..Default::default()
            },
        )
        .unwrap();
        counter
            .attach_candidates(
                sites
                    .candidates
                    .into_iter()
                    .map(CountCandidate::Static)
                    .collect(),
                start_ns,
            )
            .unwrap();
        let cookies = counter.fold.next_cookie;
        let physical = counter.active_site_count();
        child.release_retaining_exit().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let record = crate::inventory::snapshot(&crate::inventory::SnapshotOptions {
            pids: vec![child.pid()],
            limits: crate::inventory::Limits {
                max_pids: 1,
                max_objects: 256,
                max_objects_per_process: 256,
                ..Default::default()
            },
        })
        .processes
        .remove(0);
        let mut budget = crate::provider_observation::ObservationBudget::default();
        let mapped = crate::provider_observation::acquire(&record, &mut budget).unwrap();
        let mut candidates = mapped.static_candidates(&budget).unwrap();
        assert!(candidates.len() > 2);
        let first = candidates.remove(0);
        let installed = crate::capture::LiveClock.checked_monotonic_ns().unwrap();
        counter
            .attach_candidates(vec![CountCandidate::Static(first)], installed)
            .unwrap();
        counter
            .attach_candidates(
                candidates.into_iter().map(CountCandidate::Static).collect(),
                installed,
            )
            .unwrap();
        assert_eq!(
            counter.fold.generation, 1,
            "partial first mapping must not fence behind live links"
        );
        assert_eq!(
            counter.fold.next_cookie, cookies,
            "first mapping allocated duplicate physical cookies"
        );
        assert_eq!(counter.active_site_count(), physical);
        let before: u64 = counter
            .sample(Instant::now() + Duration::from_secs(1))
            .sites
            .iter()
            .map(|s| s.calls)
            .sum();
        std::thread::sleep(Duration::from_millis(100));
        let after: u64 = counter
            .sample(Instant::now() + Duration::from_secs(1))
            .sites
            .iter()
            .map(|s| s.calls)
            .sum();
        assert!(
            after > before && before > 0,
            "native entries must continue with the original cookies"
        );
        counter.close(Instant::now() + Duration::from_secs(1));
        child.finish_observation().unwrap();
    }
    #[test]
    #[ignore = "requires privileged BPF and freshly built focused count object"]
    fn cancelled_startup_transaction_closes_partial_links_and_burns_cookies() {
        use crate::capture::ClockPort;
        let argv = vec![
            "/usr/bin/openssl".into(),
            "dgst".into(),
            "-sha512".into(),
            "/dev/null".into(),
        ];
        let child =
            crate::target::OwnedTarget::spawn_stopped(&argv, crate::target::WorkloadDest::Null)
                .unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let sites = crate::startup_objects::prepare_owned_startup(
            &child,
            &argv,
            &mut crate::provider_observation::ObservationBudget::default(),
            Instant::now() + Duration::from_secs(10),
            &cancelled,
        )
        .unwrap();
        let distinct: std::collections::BTreeSet<_> = sites
            .candidates
            .iter()
            .map(|s| (s.site().native_device(), s.site().inode()))
            .collect();
        assert!(
            distinct.len() > 1,
            "rollback requires multiple retained files"
        );
        let bytes =
            std::fs::read(std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT").unwrap()).unwrap();
        let start_ns = crate::capture::LiveClock.checked_monotonic_ns().unwrap();
        let mut counter = FocusedCounter::open(
            &bytes,
            child.pid(),
            crate::focused_capture::observer_namespace().unwrap(),
            CountLimits {
                window: CountAdmissionWindow {
                    start_ns,
                    deadline_ns: start_ns + 10_000_000_000,
                },
                ..Default::default()
            },
        )
        .unwrap();
        let link_fds = || -> usize {
            std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .flatten()
                .filter(|p| {
                    std::fs::read_link(p.path()).is_ok_and(|n| {
                        n.to_string_lossy().contains("bpf-link")
                            || n.to_string_lossy().contains("bpf_link")
                    })
                })
                .count()
        };
        let baseline = link_fds();
        let stop = Arc::new(AtomicBool::new(false));
        let observed = Arc::new(AtomicBool::new(false));
        let watch = {
            let cancelled = cancelled.clone();
            let stop = stop.clone();
            let observed = observed.clone();
            std::thread::spawn(move || {
                let until = Instant::now() + Duration::from_secs(10);
                while !stop.load(Ordering::Acquire) && Instant::now() < until {
                    if link_fds() > baseline {
                        observed.store(true, Ordering::Release);
                        cancelled.store(true, Ordering::Release);
                        break;
                    }
                    std::thread::yield_now();
                }
            })
        };
        let result = counter.attach_candidates_controlled(
            sites
                .candidates
                .into_iter()
                .map(CountCandidate::Static)
                .collect(),
            start_ns,
            Instant::now() + Duration::from_secs(10),
            &cancelled,
        );
        stop.store(true, Ordering::Release);
        watch.join().unwrap();
        assert!(
            observed.load(Ordering::Acquire),
            "no actual in-progress native link was observed"
        );
        assert_eq!(result, Err(CountFailure::Attach));
        assert_eq!(counter.active_site_count(), 0);
        assert_eq!(counter.active_link_count(), 0);
        assert!(
            counter.fold.next_cookie > 1,
            "potentially used cookies must be burned"
        );
        assert_eq!(link_fds(), baseline, "rollback leaked native links");
        assert!(
            child.peek_exit().unwrap().is_none(),
            "cancelled setup released the child"
        );
        drop(counter);
        drop(child);
    }
    #[test]
    #[ignore = "requires privileged BPF and fresh count object"]
    fn tick_expiry_after_native_link_commits_once() {
        use crate::capture::ClockPort;
        let argv = ["/usr/bin/openssl", "dgst", "-sha512", "/dev/null"]
            .map(str::to_owned)
            .to_vec();
        let mut child =
            crate::target::OwnedTarget::spawn_stopped(&argv, crate::target::WorkloadDest::Null)
                .unwrap();
        let cancel = AtomicBool::new(false);
        let sites = crate::startup_objects::prepare_owned_startup(
            &child,
            &argv,
            &mut crate::provider_observation::ObservationBudget::default(),
            Instant::now() + Duration::from_secs(10),
            &cancel,
        )
        .unwrap();
        let bytes =
            std::fs::read(std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT").unwrap()).unwrap();
        let start = crate::capture::LiveClock.checked_monotonic_ns().unwrap();
        let mut counter = FocusedCounter::open(
            &bytes,
            child.pid(),
            crate::focused_capture::observer_namespace().unwrap(),
            CountLimits {
                window: CountAdmissionWindow {
                    start_ns: start,
                    deadline_ns: start + 15_000_000_000,
                },
                ..Default::default()
            },
        )
        .unwrap();
        let candidates: Vec<_> = sites
            .candidates
            .into_iter()
            .map(CountCandidate::Static)
            .collect();
        let initial = (counter.fold.next_cookie, counter.fold.state_bytes);
        for _ in 0..2 {
            EXPIRE_BEFORE_NATIVE.with(|flag| flag.set(true));
            assert_eq!(
                counter.attach_candidates_controlled(
                    candidates.clone(),
                    start,
                    Instant::now() + Duration::from_secs(1),
                    &cancel
                ),
                Err(CountFailure::Deferred)
            );
            assert_eq!(
                (counter.fold.next_cookie, counter.fold.state_bytes),
                initial,
                "provisional pre-native state or cookies leaked"
            );
            assert_eq!(counter.active_link_count(), 0);
            EXPIRE_BEFORE_NATIVE
                .with(|flag| assert!(!flag.get(), "did not reach the planned boundary"));
        }
        EXPIRE_AFTER_LINK.with(|flag| flag.set(true));
        counter
            .attach_candidates_controlled(
                candidates,
                start,
                Instant::now() + Duration::from_secs(1),
                &cancel,
            )
            .expect("tick expiry must commit native effects once");
        let cookies = counter.fold.next_cookie;
        let state = counter.fold.state_bytes;
        let links = counter.active_link_count();
        assert!(cookies > 2000 && cookies <= 4097);
        child.release_retaining_exit().unwrap();
        let wait = Instant::now() + Duration::from_secs(5);
        while child.peek_exit().unwrap().is_none() {
            assert!(Instant::now() < wait, "ordinary digest did not exit");
            std::thread::sleep(Duration::from_millis(5));
        }
        let before_calls: u64 = counter
            .sample(Instant::now() + Duration::from_secs(1))
            .sites
            .iter()
            .map(|s| s.calls)
            .sum();
        counter
            .attach_candidates_controlled(
                Vec::new(),
                start,
                Instant::now() + Duration::from_secs(1),
                &cancel,
            )
            .unwrap();
        assert_eq!(
            (
                counter.fold.next_cookie,
                counter.fold.state_bytes,
                counter.active_link_count()
            ),
            (cookies, state, links)
        );
        let sample = counter.close(Instant::now() + Duration::from_secs(1));
        let calls: u64 = sample
            .sites
            .iter()
            .chain(&sample.fenced)
            .map(|s| s.calls)
            .sum();
        assert!(calls > 0);
        assert_eq!(calls, before_calls, "next tick or close duplicated counts");
        eprintln!(
            "deadline transaction: cookies={}, state={}, links={}, calls={}",
            cookies - 1,
            state,
            links,
            calls
        );
        child.finish_observation().unwrap();
    }
}
