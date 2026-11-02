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
use sha2::{Digest, Sha256};
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
/// Reserved ENGINE probe cookie range: `[ENGINE_COOKIE_BASE,
/// ENGINE_COOKIE_END)`. Site cookies mint upward from 1 under
/// `max_cookies` (4096); session-pinned cookies stay far below (legacy
/// mints need ~1.8B links to reach here; `LinkLimit` refuses far
/// earlier) and the session typed range starts at `2^31` above.
/// ENGINE tripwire probes mint upward from the base, so the two planes
/// never share a cookie and the BPF program (which counts any u32
/// cookie) needs no changes. Bounded above so a row-less typed-range
/// cookie still folds foreign, never engine-shaped.
pub const ENGINE_COOKIE_BASE: u32 = 0x7000_0000;
pub const ENGINE_COOKIE_END: u32 = 0x8000_0000;
/// True iff the cookie belongs to the reserved ENGINE probe range.
pub fn is_engine_cookie(cookie: u32) -> bool {
    (ENGINE_COOKIE_BASE..ENGINE_COOKIE_END).contains(&cookie)
}
/// One drained ENGINE probe count: the raw (cookie, generation) key
/// plus cumulative calls and first/last hit stamps. Meanings (probe
/// symbol/module) join userspace-side via the planned ProbeSet.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct EngineCount {
    pub cookie: u32,
    pub generation: u32,
    pub calls: u64,
    pub first_ns: u64,
    pub last_ns: u64,
}
/// Bound on ENGINE probes per counter: 32 probed symbols per
/// caller module, and ENGINE keys share the 8192-key COUNTS map
/// with site rows — 2048 leaves headroom for both planes.
pub(crate) const MAX_ENGINE_PROBES: usize = 2048;
/// One ENGINE tripwire probe to attach: caller-module path plus file
/// offset, with the expected attach-time file identity (native stat
/// domain) for TOCTOU verification.
#[derive(Clone, Debug)]
pub(crate) struct EngineProbePlan {
    pub path: String,
    pub offset: u64,
    pub device: u64,
    pub inode: u64,
    /// SHA-256 over the exact module bytes the session parsed
    /// this offset from. The attach re-hashes the pinned file
    /// and refuses on mismatch: a caller DSO modified in place
    /// between parsing and attachment keeps (device, inode) but
    /// must never receive a stale stub offset.
    pub sha256: [u8; 32],
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
    pub engine: Vec<EngineCount>,
}
mod fold;
pub use fold::{CountFold, SiteBinding};

/// Conservation total over every counted plane: provider sites (live
/// plus fenced), ENGINE probe counts, unattributed foreign keys and
/// map-full drops must equal the BPF admitted ledger exactly.
fn ledger_counted(sample: &CountSample) -> u64 {
    SiteExecution::sum_calls(&sample.sites)
        .saturating_add(SiteExecution::sum_calls(&sample.fenced))
        .saturating_add(
            sample
                .engine
                .iter()
                .fold(0u64, |n, e| n.saturating_add(e.calls)),
        )
        .saturating_add(sample.unattributed)
        .saturating_add(sample.dropfail)
}
/// Dedupe ENGINE plans by physical (device, inode, offset)
/// identity: hardlinked paths describing the same stub attach
/// once. Returns the unique input indices (first occurrence wins)
/// plus, for every input, its unique slot (aliases share the
/// surviving twin's cookie, keeping the returned cookies
/// input-aligned). `None` when aliases disagree on the content
/// digest (the module changed between the two plan reads):
/// collapsing would bless one stale parse silently, so the
/// attach refuses instead.
fn dedupe_engine_plans(probes: &[EngineProbePlan]) -> Option<(Vec<usize>, Vec<usize>)> {
    let mut seen: BTreeMap<(u64, u64, u64), usize> = BTreeMap::new();
    let mut unique: Vec<usize> = Vec::new();
    let mut slots = Vec::with_capacity(probes.len());
    for (i, p) in probes.iter().enumerate() {
        if let Some(&u) = seen.get(&(p.device, p.inode, p.offset)) {
            if probes[unique[u]].sha256 != p.sha256 {
                return None;
            }
            slots.push(u);
        } else {
            seen.insert((p.device, p.inode, p.offset), unique.len());
            slots.push(unique.len());
            unique.push(i);
        }
    }
    Some((unique, slots))
}
/// Map a pinned-file re-read failure: only demonstrated
/// instability (a mid-read tear) or growth past the bound the
/// parse succeeded under establishes a changed file
/// (`Identity`); ordinary I/O failures are `Read`, never a
/// fabricated object change.
fn map_pin_read_error(kind: std::io::ErrorKind) -> CountFailure {
    match kind {
        std::io::ErrorKind::InvalidData | std::io::ErrorKind::FileTooLarge => {
            CountFailure::Identity
        }
        _ => CountFailure::Read,
    }
}
/// True iff the retained ENGINE pin still shows the attach-time
/// [`Stamp`]: same (device, inode, size, mode, links, mtime,
/// ctime). Any in-place modification bumps ctime at least, so a
/// stale stub offset can never survive undetected into the join.
fn engine_pin_unchanged(pin: &File, stamp: &crate::provider_observation::objects::Stamp) -> bool {
    pin.metadata()
        .map(|m| crate::provider_observation::objects::Stamp::of(&m) == *stamp)
        .unwrap_or(false)
}
fn gap(name: &str, value: u64) -> GapCounter {
    let (units, source) = match name {
        "focused_unattributed" | "focused_dropfail" => {
            (CounterUnits::Calls, CounterSource::KernelMap)
        }
        "focused_namespace_failures" | "focused_saturated" => {
            (CounterUnits::Events, CounterSource::KernelMap)
        }
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
/// Component budget for the kernel-layout read behind marker patching.
/// Capped at the counter's own remaining state allowance, never a fresh
/// default: the BTF scratch reserves against this before opening or
/// allocating.
fn component_budget(
    max_state_bytes: usize,
) -> crate::provider_observation::schema::ObservationBudget {
    crate::provider_observation::schema::ObservationBudget::new(
        crate::provider_observation::schema::ObservationLimits {
            max_state_bytes,
            ..Default::default()
        },
    )
}
struct Attachment {
    link: OwnedFd,
    candidates: Vec<CountCandidate>,
}
/// One live ENGINE probe group: the uprobe_multi link plus its
/// retained module pin. Dropped link-first like [`Attachment`].
/// The attach-time `Stamp` makes the pin live custody:
/// `retain_authority` revalidates it like every provider file.
struct EngineAttachment {
    link: OwnedFd,
    pin: File,
    stamp: crate::provider_observation::objects::Stamp,
}
#[cfg(test)]
thread_local! {
    static EXPIRE_AFTER_LINK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static EXPIRE_BEFORE_NATIVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
/// Owns maps, retained namespace, links and candidate custody. Links are closed
/// before candidate custody is released, including during unwinding/Drop.
pub struct FocusedCounter {
    gate: crate::writer_gate::WriterGate,
    loaded: loader::GatedLoaded,
    namespace: File,
    expected_namespace: NamespaceId,
    pid: u32,
    starttime: Option<u64>,
    limits: CountLimits,
    cpus: usize,
    fold: CountFold,
    attachments: Vec<Attachment>,
    engine_attachments: Vec<EngineAttachment>,
    next_engine_cookie: u32,
    /// Retire count, advanced by every `retire()` call even with
    /// no links. The ENGINE plane records it at attach and
    /// blinds when it moves: any retire destroys ENGINE links.
    engine_epoch: u64,
    retired: bool,
    totals: [u64; 3],
    associations: BTreeMap<u32, SiteAssociations>,
    startup_only: std::collections::BTreeSet<u32>,
    mapped_generation: Option<u64>,
    authority_refresh_pending: bool,
    mapped_guards: Vec<crate::provider_observation::VerifiedSite>,
    /// Shaped link-failure tops (R06 rule: sorted + deduped here, capped
    /// at the document). The session drains these at projection; the
    /// counters keep the exact failure counts regardless.
    attach_diagnostics: std::collections::BTreeSet<String>,
}
/// One-shot stable physical acquisition. It keeps the actual counter/maps and
/// successful shared-gate owner alive; a copied sample is never this capability.
struct ClosedPhysicalSnapshot {
    owner: FocusedCounter,
    closed_gate: crate::writer_gate::OwnedClosedGate,
    sample: CountSample,
}
impl ClosedPhysicalSnapshot {
    fn into_sample(self) -> CountSample {
        debug_assert!(self.closed_gate.matches(&self.owner.gate));
        self.sample
    }
}
impl FocusedCounter {
    pub fn open(
        bytes: &[u8],
        pid: u32,
        namespace: NamespaceId,
        limits: CountLimits,
    ) -> Result<Self, CountFailure> {
        limits.validate()?;
        // Peak-validate the transient BTF scratch against the component
        // budget before preparing: a small-but-valid budget refuses with
        // Resource here, before any BTF open or allocation.
        if limits.max_state_bytes < loader::COUNT_JOIN_SCRATCH_BYTES {
            return Err(CountFailure::Resource);
        }
        let component = component_budget(limits.max_state_bytes);
        loader::prepare_focused_count(bytes, &component).map_err(|_| CountFailure::Object)?;
        if pid == 0 {
            return Err(CountFailure::Identity);
        }
        if limits.window.start_ns == 0 || limits.window.deadline_ns <= limits.window.start_ns {
            return Err(CountFailure::Object);
        }
        let ns = File::open("/proc/self/ns/pid").map_err(|_| CountFailure::Namespace)?;
        validate_namespace(&ns, namespace)?;
        let pool = crate::observation_memory::MemoryPool::new(limits.max_state_bytes);
        let gate =
            crate::writer_gate::WriterGate::create(&pool).map_err(|_| CountFailure::Object)?;
        let counter = Self::open_gated(bytes, pid, namespace, limits, gate.clone())?;
        gate.open().map_err(|_| CountFailure::Object)?;
        Ok(counter)
    }
    pub(crate) fn open_gated(
        bytes: &[u8],
        pid: u32,
        namespace: NamespaceId,
        limits: CountLimits,
        gate: crate::writer_gate::WriterGate,
    ) -> Result<Self, CountFailure> {
        Self::open_gated_inner(bytes, pid, namespace, limits, gate, None)
    }
    /// Open against session-borrowed producer/source maps (same kernel
    /// maps, dup'd FDs) instead of creating private ones. Every borrowed
    /// name must resolve; anything else refuses. The producer stays inert
    /// until the session admits typed sites.
    pub(crate) fn open_gated_shared(
        bytes: &[u8],
        pid: u32,
        namespace: NamespaceId,
        limits: CountLimits,
        gate: crate::writer_gate::WriterGate,
        borrowed: &std::collections::BTreeMap<String, std::os::fd::BorrowedFd<'_>>,
    ) -> Result<Self, CountFailure> {
        Self::open_gated_inner(bytes, pid, namespace, limits, gate, Some(borrowed))
    }
    fn open_gated_inner(
        bytes: &[u8],
        pid: u32,
        namespace: NamespaceId,
        limits: CountLimits,
        gate: crate::writer_gate::WriterGate,
        borrowed: Option<&std::collections::BTreeMap<String, std::os::fd::BorrowedFd<'_>>>,
    ) -> Result<Self, CountFailure> {
        limits.validate()?;
        if pid == 0 {
            return Err(CountFailure::Identity);
        }
        if limits.window.start_ns == 0 || limits.window.deadline_ns <= limits.window.start_ns {
            return Err(CountFailure::Object);
        }
        let mut fold = CountFold::new(limits)?;
        fold.charge(crate::writer_gate::RESERVATION_BYTES + crate::writer_gate::INJECTION_BYTES)?;
        fold.charge(bytes.len().checked_mul(4).ok_or(CountFailure::Resource)?)?;
        // Peak-validate the transient BTF scratch against the remaining
        // component budget (checked, not committed: the reservation
        // releases when the layout read ends), then hand the layout
        // reader a component budget capped at that same remainder.
        fold.checked_charge(loader::COUNT_JOIN_SCRATCH_BYTES)?;
        let remaining = limits
            .max_state_bytes
            .checked_sub(fold.state_bytes)
            .ok_or(CountFailure::Resource)?;
        let component = component_budget(remaining);
        let prepared =
            loader::prepare_focused_count(bytes, &component).map_err(|_| CountFailure::Object)?;
        let cpus = aya::util::nr_cpus().map_err(|_| CountFailure::Read)?;
        if cpus == 0 || cpus > limits.max_cpus {
            return Err(CountFailure::Resource);
        }
        // Final enumeration retains a bounded set of every observed physical
        // identity alongside the live fold. Charge its full capacity up front.
        fold.charge(
            limits
                .max_keys
                .checked_mul(64)
                .ok_or(CountFailure::Resource)?,
        )?;
        fold.charge(
            cpus.checked_mul(48)
                .and_then(|n| n.checked_add(limits.max_keys * 192))
                .ok_or(CountFailure::Resource)?,
        )?;
        let ns = File::open("/proc/self/ns/pid").map_err(|_| CountFailure::Namespace)?;
        validate_namespace(&ns, namespace)?;
        let loaded = match borrowed {
            Some(borrowed) => loader::load_gated_borrowed(&prepared, &gate, borrowed),
            None => loader::load_gated(&prepared, &gate),
        }
        .map_err(|_| CountFailure::Object)?;
        // Inspect actual kernel FDs before every typed-sized IO, including init.
        for shape in loader::FOCUSED_COUNT_MAPS {
            checked_map(&loaded, shape.name)?;
        }
        let mut counter = Self {
            gate,
            loaded,
            namespace: ns,
            expected_namespace: namespace,
            pid,
            starttime: None,
            limits,
            cpus,
            fold,
            attachments: Vec::new(),
            engine_attachments: Vec::new(),
            next_engine_cookie: ENGINE_COOKIE_BASE,
            engine_epoch: 0,
            retired: false,
            totals: [0; 3],
            associations: BTreeMap::new(),
            startup_only: Default::default(),
            mapped_generation: None,
            authority_refresh_pending: false,
            mapped_guards: Vec::new(),
            attach_diagnostics: std::collections::BTreeSet::new(),
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
    pub(crate) fn cpus(&self) -> usize {
        self.cpus
    }
    fn write(&self, name: &str, key: u32, value: &[u8]) -> Result<(), CountFailure> {
        if !self.gate.admitting() {
            return Err(CountFailure::Close);
        }
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
        // Destructure explicitly: ENGINE links close before pins.
        for EngineAttachment { link, pin, .. } in self.engine_attachments.drain(..) {
            drop(link);
            drop(pin);
        }
    }
    /// Scalar readiness derived from owned physical links, not advertisements.
    pub fn active_site_count(&self) -> usize {
        self.fold.rows.values().filter(|r| r.active).count()
    }
    pub fn active_link_count(&self) -> usize {
        self.attachments
            .len()
            .saturating_add(self.engine_attachments.len())
    }
    /// Retire count for the ENGINE plane's dead-link check.
    pub(crate) fn engine_epoch(&self) -> u64 {
        self.engine_epoch
    }
    /// Record one failed link as a shaped attach diagnostic (R06
    /// vocabulary: static program, first group file-offset, Debug
    /// kind token). Sorted + deduped; the session drains at projection.
    fn record_link_diagnostic(&mut self, offset: u64, error: &std::io::Error) {
        let top =
            crate::acquire_cause::AcquisitionCause::link_top("count_entry", offset, error.kind());
        self.attach_diagnostics
            .insert(crate::acquire_cause::AcquisitionCause::Attach.diagnostic(&top));
    }
    /// Drain the recorded link diagnostics for the document path.
    pub(crate) fn take_attach_diagnostics(&mut self) -> std::collections::BTreeSet<String> {
        std::mem::take(&mut self.attach_diagnostics)
    }
    /// Test-only stimulus peek: true while an undrained link
    /// diagnostic sits in the counter. The session drain runs at
    /// finish; polls cannot see the diagnostic until then, so a
    /// session-level pin synchronizes on this instead of spinning
    /// on the session set.
    #[cfg(test)]
    pub(crate) fn attach_diagnostics_pending_for_test(&self) -> bool {
        !self.attach_diagnostics.is_empty()
    }
    /// Pure ENGINE-pin custody check (no retire, no gaps):
    /// every retained pin still shows its attach-time stamp.
    /// Exit-safe (file stamps only, no live-target checks), so
    /// the finish cut uses this instead of full retention.
    pub(crate) fn engine_pins_unchanged(&self) -> bool {
        self.engine_attachments
            .iter()
            .all(|a| engine_pin_unchanged(&a.pin, &a.stamp))
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
            // ENGINE pins are live custody too: a caller DSO
            // modified after attachment must retire the counter
            // rather than join counts to stale symbols.
            for attachment in &self.engine_attachments {
                if !engine_pin_unchanged(&attachment.pin, &attachment.stamp) {
                    return Err(CountFailure::Identity);
                }
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
        // Unconditional: the ENGINE plane compares epochs to
        // detect dead links, so every call must be visible even
        // when there is nothing left to close.
        self.engine_epoch = self.engine_epoch.wrapping_add(1);
        if self.retired && self.attachments.is_empty() && self.engine_attachments.is_empty() {
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
        self.attach_candidates_with_control(candidates, installed_ns, None, None)
    }
    pub(crate) fn attach_candidates_controlled(
        &mut self,
        candidates: Vec<CountCandidate>,
        installed_ns: u64,
        deadline: Instant,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<(), CountFailure> {
        self.attach_candidates_with_control(
            candidates,
            installed_ns,
            Some((deadline, cancel)),
            None,
        )
    }
    /// Attach with optional session-pinned cookies: sites present in `pins`
    /// attach under the session's cookie for the same physical site, so
    /// both programs resolve one SITE_BIND row. Absent or out-of-range
    /// pins fall back to counter-minted cookies (physical evidence
    /// preserved; the site stays unattributed).
    #[allow(
        dead_code,
        reason = "exercised by session native controls; production counter wiring is staged"
    )]
    pub(crate) fn attach_candidates_pinned(
        &mut self,
        candidates: Vec<CountCandidate>,
        installed_ns: u64,
        deadline: Instant,
        cancel: &std::sync::atomic::AtomicBool,
        pins: &std::collections::BTreeMap<(u64, u64, u64), u64>,
    ) -> Result<(), CountFailure> {
        self.attach_candidates_with_control(
            candidates,
            installed_ns,
            Some((deadline, cancel)),
            Some(pins),
        )
    }
    /// Attach caller-attributed ENGINE tripwire probes to the count
    /// program. Each probe counts in-kernel under a reserved-range
    /// cookie; returns the minted cookies in input order for the
    /// session's ProbeSet join. Transactional per call: a mid-batch
    /// failure drops every link this call created, while minted
    /// cookies stay consumed (never reused after a possibly observed
    /// native call — a dropped link's hits drain as unjoinable
    /// ENGINE loss, never site evidence). Identity, namespace,
    /// window and budget discipline mirror the site path; probe
    /// meanings stay with the session (ProbeSet), never here.
    /// Plans aliasing the same physical (device, inode, offset)
    /// stub attach once: the surviving twin's cookie is returned
    /// for every alias (input-aligned), so one stub never counts
    /// under two cookies.
    pub(crate) fn attach_engine_probes(
        &mut self,
        probes: &[EngineProbePlan],
        pid: u32,
        starttime: u64,
        deadline: Instant,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<Vec<u32>, CountFailure> {
        // Unlike the site path, an ENGINE attach failure never
        // retires the counter: a swapped module file is plane-local
        // (the session blinds the ENGINE plane), and target-level
        // identity loss is the session snapshot's own verdict.
        let result = self.attach_engine_probes_inner(probes, pid, starttime, deadline, cancel);
        if let Err(e) = result {
            if e != CountFailure::Deferred {
                self.failure(e);
            }
        }
        result
    }
    fn attach_engine_probes_inner(
        &mut self,
        probes: &[EngineProbePlan],
        pid: u32,
        starttime: u64,
        deadline: Instant,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<Vec<u32>, CountFailure> {
        use std::sync::atomic::Ordering;
        if !self.gate.admitting() {
            return Err(CountFailure::Close);
        }
        if probes.is_empty() {
            return Ok(Vec::new());
        }
        if probes.len() > MAX_ENGINE_PROBES {
            return Err(CountFailure::Resource);
        }
        if pid != self.pid || self.starttime.is_some_and(|s| s != starttime) {
            return Err(CountFailure::Identity);
        }
        validate_namespace(&self.namespace, self.expected_namespace)?;
        let hard_deadline = self.limits.window.deadline_ns;
        let checkpoint = |native: bool| {
            use crate::capture::ClockPort;
            if cancel.load(Ordering::Relaxed) {
                return Err(CountFailure::Attach);
            }
            if crate::capture::LiveClock
                .checked_monotonic_ns()
                .ok_or(CountFailure::Read)?
                >= hard_deadline
            {
                return Err(CountFailure::Attach);
            }
            if !native && Instant::now() >= deadline {
                return Err(CountFailure::Deferred);
            }
            Ok(())
        };
        checkpoint(false)?;
        // Dedupe aliased plans before any native effect: one stub
        // attaches once (the returned cookies stay input-aligned
        // via the slot table below). A fingerprint conflict
        // refuses: the module changed between plan reads.
        let Some((unique, slots)) = dedupe_engine_plans(probes) else {
            return Err(CountFailure::Identity);
        };
        // Bounded planning charge, validated before any native
        // effect and committed only with the links below.
        let planning_charge = unique
            .iter()
            .try_fold(0usize, |total, &i| {
                total
                    .checked_add(probes[i].path.len())
                    .and_then(|n| n.checked_add(64))
            })
            .ok_or(CountFailure::Resource)?;
        self.fold.checked_charge(planning_charge)?;
        // Mint first and commit the cursor before any native
        // effect: cookies stay consumed even when a later group
        // fails (never reused after a possibly observed native
        // call). Only range exhaustion (no native effect) refuses
        // without consuming.
        let mut cookies = Vec::with_capacity(unique.len());
        let mut next = self.next_engine_cookie;
        for _ in &unique {
            if next >= ENGINE_COOKIE_END {
                return Err(CountFailure::Resource);
            }
            cookies.push(next);
            next += 1;
        }
        self.next_engine_cookie = next;
        let program = self
            .loaded
            .progs
            .get("count_entry")
            .ok_or(CountFailure::Object)?
            .as_raw_fd();
        // Group offsets+cookies per module: one uprobe_multi link each.
        let mut groups: BTreeMap<&str, Vec<(u64, u64)>> = BTreeMap::new();
        for (&i, cookie) in unique.iter().zip(cookies.iter()) {
            groups
                .entry(probes[i].path.as_str())
                .or_default()
                .push((probes[i].offset, u64::from(*cookie)));
        }
        let mut additions = Vec::new();
        for (index, (module, pairs)) in groups.iter().enumerate() {
            checkpoint(index > 0)?;
            // Pin the module and verify the planned identity against
            // the opened file (fd-bound: no path TOCTOU). The link
            // binds through the fd-path, and the pin is retained
            // with it.
            let pin = File::open(module).map_err(|_| CountFailure::Attach)?;
            let stat = pin.metadata().map_err(|_| CountFailure::Attach)?;
            // Every plan for this module must agree with the opened
            // file: a swapped file — or disagreeing plans — refuses
            // the whole batch rather than attaching half-bound.
            let consistent = unique
                .iter()
                .filter(|&&i| probes[i].path == *module)
                .all(|&i| stat.dev() == probes[i].device && stat.ino() == probes[i].inode);
            if !consistent {
                return Err(CountFailure::Identity);
            }
            // Content fingerprint over the pinned file (fd-bound
            // re-read under the same cap the session parsed
            // with: no path TOCTOU). Every unique plan for this
            // module must name the digest of the bytes its stub
            // offset was parsed from — a caller DSO modified in
            // place between parsing and attachment keeps
            // (device, inode) but refuses here, before any link.
            let pinned = pin.try_clone().map_err(|_| CountFailure::Attach)?;
            let pinned_bytes =
                crate::plan::read_bounded_from(pinned, crate::plan::MAX_OBJECT_BYTES)
                    .map_err(|e| map_pin_read_error(e.kind()))?;
            let pinned_digest: [u8; 32] = Sha256::digest(&pinned_bytes.bytes).into();
            let fingerprinted = unique
                .iter()
                .filter(|&&i| probes[i].path == *module)
                .all(|&i| probes[i].sha256 == pinned_digest);
            if !fingerprinted {
                return Err(CountFailure::Identity);
            }
            let fd_path = CString::new(format!("/proc/self/fd/{}", pin.as_raw_fd()))
                .map_err(|_| CountFailure::Attach)?;
            let offsets: Vec<u64> = pairs.iter().map(|(off, _)| *off).collect();
            let group_cookies: Vec<u64> = pairs.iter().map(|(_, c)| *c).collect();
            checkpoint(index > 0)?;
            let link = match ossl_bpf_sys::link_create_uprobe_multi(
                program,
                &fd_path,
                &offsets,
                &group_cookies,
                self.pid,
            ) {
                Ok(link) => link,
                Err(error) => {
                    self.record_link_diagnostic(
                        pairs.first().map(|(off, _)| *off).unwrap_or_default(),
                        &error,
                    );
                    return Err(CountFailure::Attach);
                }
            };
            // Post-link stability: the digest proved the content
            // at re-read time; an unchanged stamp across the link
            // call proves the link bound those same bytes (any
            // in-between write bumps ctime). Retained as the live
            // custody stamp for `retain_authority`.
            let fresh = pin.metadata().map_err(|_| CountFailure::Attach)?;
            let stamp = crate::provider_observation::objects::Stamp::of(&fresh);
            if stamp != crate::provider_observation::objects::Stamp::of(&stat) {
                return Err(CountFailure::Identity);
            }
            additions.push(EngineAttachment { link, pin, stamp });
        }
        if cancel.load(Ordering::Relaxed) {
            return Err(CountFailure::Attach);
        }
        validate_namespace(&self.namespace, self.expected_namespace)?;
        // Commit only after every link succeeded: a planning-charge
        // refusal here still drops the new links (transactional).
        // (Validated upfront, so this cannot fail without an
        // intervening same-thread mutation.)
        if self.fold.charge(planning_charge).is_err() {
            return Err(CountFailure::Resource);
        }
        self.engine_attachments.extend(additions);
        self.starttime = Some(starttime);
        if self.retired {
            self.write("TARGET", 0, &(self.pid as u64).to_ne_bytes())?;
            self.retired = false;
        }
        // Input-aligned cookies: aliases share the surviving
        // twin's cookie, so the session joins one stub once.
        Ok(slots.iter().map(|&s| cookies[s]).collect())
    }
    fn attach_candidates_with_control(
        &mut self,
        candidates: Vec<CountCandidate>,
        installed_ns: u64,
        control: Option<(Instant, &std::sync::atomic::AtomicBool)>,
        pins: Option<&std::collections::BTreeMap<(u64, u64, u64), u64>>,
    ) -> Result<(), CountFailure> {
        let result = self.attach_candidates_inner(candidates, installed_ns, control, pins);
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
        pins: Option<&std::collections::BTreeMap<(u64, u64, u64), u64>>,
    ) -> Result<(), CountFailure> {
        if !self.gate.admitting() {
            return Err(CountFailure::Close);
        }
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
                let pinned = pins
                    .and_then(|pins| pins.get(&(key.device, key.inode, key.offset)).copied())
                    .and_then(|cookie| u32::try_from(cookie).ok());
                if pins.is_some() && pinned.is_none() {
                    planned.gap("typed_pin_missing");
                }
                let (cookie, generation) = match pinned {
                    Some(cookie) => planned.attach_pinned(binding, cookie, |cookie, _| {
                        offsets.push(offset);
                        cookies.push(cookie as u64);
                        Ok(())
                    })?,
                    None => planned.attach(binding, |cookie, _| {
                        offsets.push(offset);
                        cookies.push(cookie as u64);
                        Ok(())
                    })?,
                };
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
            let link = match ossl_bpf_sys::link_create_uprobe_multi(
                program, &path, &offsets, &cookies, self.pid,
            ) {
                Ok(link) => link,
                Err(error) => {
                    self.record_link_diagnostic(
                        offsets.first().copied().unwrap_or_default(),
                        &error,
                    );
                    return Err(CountFailure::Attach);
                }
            };
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
        if let Err(e) = self.read_snapshot(deadline, false) {
            self.failure(e);
        }
        self.current_sample()
    }
    fn current_sample(&self) -> CountSample {
        let mut sample = self.fold.sample();
        sample.associations = self.associations.values().cloned().collect();
        [sample.admitted, sample.dropfail, sample.namespace_failures] = self.totals;
        if self.totals.contains(&u64::MAX)
            && !sample.gaps.iter().any(|g| g.name == "focused_saturated")
        {
            sample.gaps.push(gap("focused_saturated", 1));
        }
        if sample.dropfail > 0 {
            sample.gaps.push(gap("focused_dropfail", sample.dropfail));
        }
        if sample.namespace_failures > 0 {
            sample
                .gaps
                .push(gap("focused_namespace_failures", sample.namespace_failures));
        }
        // Live reads remain concurrent prefixes. A retained successful delete
        // makes this a stable writer cut; failed reads/conservation stay gaps.
        if !self.gate.admitting() && self.gate.receipt().is_none() {
            sample.gaps.push(gap("focused_cut_unavailable", 1));
        }
        // Never invent counts to balance the ledger.
        if ledger_counted(&sample) != sample.admitted {
            sample.gaps.push(gap("focused_ledger_mismatch", 1));
        }
        sample
    }
    fn read_snapshot(&mut self, deadline: Instant, strict: bool) -> Result<(), CountFailure> {
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
        let mut final_keys = std::collections::BTreeSet::new();
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
            if strict && !final_keys.insert((cookie, generation)) {
                return Err(CountFailure::Read);
            }
            self.fold.observe(cookie, generation, &values)?;
        }
        if strict {
            self.fold.validate_final_keys(&final_keys)?;
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
    /// Consuming acquisition prevents replay and retains real kernel/source
    /// owners until the final snapshot has been projected. This is physical
    /// evidence only; it does not certify an attribution dictionary or partition.
    fn read_closed(
        &mut self,
        deadline: Instant,
    ) -> Result<(crate::writer_gate::OwnedClosedGate, CountSample), CountFailure> {
        (|| {
            self.gate.close().map_err(|_| CountFailure::Close)?;
            let closed_gate = self.gate.owned_closed().map_err(|_| CountFailure::Close)?;
            if !closed_gate.matches(&self.gate) {
                return Err(CountFailure::Identity);
            }
            self.read_snapshot(deadline, true)?;
            let sample = self.current_sample();
            if sample.gaps.iter().any(|gap| {
                matches!(
                    gap.name.as_str(),
                    "focused_saturated" | "focused_ledger_mismatch" | "focused_cut_unavailable"
                )
            }) {
                return Err(CountFailure::Read);
            }
            let receipt = closed_gate.receipt();
            if sample
                .sites
                .iter()
                .chain(&sample.fenced)
                .any(|row| row.last_ns > receipt.close_after_ns)
            {
                return Err(CountFailure::Read);
            }
            Ok((closed_gate, sample))
        })()
    }
    pub fn close(mut self, deadline: Instant) -> CountSample {
        match self.read_closed(deadline) {
            Ok((closed_gate, sample)) => ClosedPhysicalSnapshot {
                owner: self,
                closed_gate,
                sample,
            }
            .into_sample(),
            Err(error) => {
                // Preserve the useful observed physical prefix, explicitly
                // unavailable as a final snapshot. Never reread or certify it.
                self.failure(error);
                let mut sample = self.current_sample();
                sample
                    .gaps
                    .push(gap("focused_final_snapshot_unavailable", 1));
                sample
            }
        }
    }
}
impl Drop for FocusedCounter {
    fn drop(&mut self) {
        if !self.retired && self.gate.admitting() {
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
    #[ignore = "requires privileged BPF and fresh focused count object"]
    fn native_saturated_physical_cells_keep_evidence_and_poison_final_sample() {
        let object =
            std::fs::read(std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT").unwrap()).unwrap();
        let counter = FocusedCounter::open(
            &object,
            std::process::id(),
            crate::focused_capture::observer_namespace().unwrap(),
            CountLimits {
                window: CountAdmissionWindow {
                    start_ns: 1,
                    deadline_ns: u64::MAX,
                },
                ..Default::default()
            },
        )
        .unwrap();
        let mut counts = vec![0; counter.cpus * 24];
        counts[..8].copy_from_slice(&u64::MAX.to_ne_bytes());
        counts[8..16].copy_from_slice(&1u64.to_ne_bytes());
        counts[16..24].copy_from_slice(&2u64.to_ne_bytes());
        unsafe {
            ossl_bpf_sys::map_update_elem(
                counter.loaded.maps["COUNTS"].as_raw_fd(),
                &((7u64 << 32) | 1).to_ne_bytes(),
                &counts,
                0,
            )
        }
        .unwrap();
        let mut admitted = vec![0; counter.cpus * 8];
        admitted[..8].copy_from_slice(&u64::MAX.to_ne_bytes());
        unsafe {
            ossl_bpf_sys::map_update_elem(
                counter.loaded.maps["ADMITTED"].as_raw_fd(),
                &0u32.to_ne_bytes(),
                &admitted,
                0,
            )
        }
        .unwrap();
        let sample = counter.close(Instant::now() + Duration::from_secs(1));
        assert_eq!(sample.unattributed, u64::MAX);
        assert_eq!(sample.admitted, u64::MAX);
        assert!(
            sample.gaps.iter().any(|g| g.name == "focused_saturated"),
            "equal saturated ledgers cannot certify conservation"
        );
    }
    #[test]
    #[ignore = "requires privileged BPF and fresh focused count object"]
    fn native_engine_probes_count_caller_plt_calls() {
        use crate::capture::ClockPort;
        use std::{
            fs,
            io::{BufRead, BufReader, Write},
            os::{
                fd::{AsRawFd, FromRawFd},
                unix::fs::MetadataExt as _,
            },
            process::Command,
        };
        let dir =
            std::env::temp_dir().join(format!("osslscope-engine-probes-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let app = dir.join("engine_probe_calls");
        assert!(
            Command::new("cc")
                .args(["-O1", "-o"])
                .arg(&app)
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/engine_probe_calls.c"
                ))
                .args(["-lcrypto"])
                .status()
                .unwrap()
                .success()
        );
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
        let argv = vec![app.to_str().unwrap().into(), input.to_str().unwrap().into()];
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
        child.0.release_retaining_exit().unwrap();
        drop(write);
        let mut output = BufReader::new(read);
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        assert_eq!(line, "ready\n");
        // Live maps now show libcrypto: plan caller-attributed ENGINE probes.
        let maps = crate::discovery::maps::read_maps(child.0.pid()).unwrap();
        let lc_path = crate::discovery::legacy::find_libcrypto(&maps).expect("libcrypto mapped");
        let lc = crate::plan::read_file_bound(&lc_path).unwrap();
        let mut mod_bufs: Vec<(String, Vec<u8>)> = Vec::new();
        for path in crate::discovery::legacy::target_modules(&maps, &lc_path) {
            if let Ok(fb) = crate::plan::read_file_bound(&path) {
                mod_bufs.push((path, fb.bytes.to_vec()));
            }
        }
        let modules: Vec<crate::discovery::legacy::Module<'_>> = mod_bufs
            .iter()
            .map(|(p, b)| crate::discovery::legacy::Module { path: p, bytes: b })
            .collect();
        let set = crate::discovery::legacy::probes_for(
            &lc_path,
            &lc.bytes,
            &modules,
            (crate::plan::render_device(lc.dev), lc.ino),
        )
        .unwrap();
        // Attach only this fixture's caller-attributed non-load probes.
        let app_str = app.to_str().unwrap().to_string();
        let wanted: Vec<&crate::discovery::legacy::Probe> = set
            .probes
            .iter()
            .filter(|p| p.module == app_str && p.family.is_none())
            .collect();
        assert!(
            wanted.iter().any(|p| p.symbol == "ENGINE_by_id"),
            "fixture PLT plans by_id"
        );
        let meta = fs::metadata(&app).unwrap();
        let app_bytes = &mod_bufs
            .iter()
            .find(|(p, _)| p == &app_str)
            .expect("fixture bytes scanned")
            .1;
        let digest: [u8; 32] = {
            use sha2::{Digest, Sha256};
            Sha256::digest(app_bytes).into()
        };
        let plans: Vec<EngineProbePlan> = wanted
            .iter()
            .map(|p| EngineProbePlan {
                path: p.module.clone(),
                offset: p.offset,
                device: meta.dev(),
                inode: meta.ino(),
                sha256: digest,
            })
            .collect();
        let records = crate::inventory::snapshot(&crate::inventory::SnapshotOptions {
            pids: vec![child.0.pid()],
            ..Default::default()
        })
        .processes;
        assert_eq!(records.len(), 1);
        let cookies = counter
            .attach_engine_probes(
                &plans,
                child.0.pid(),
                records[0].starttime,
                Instant::now() + Duration::from_secs(10),
                &cancel,
            )
            .unwrap();
        assert_eq!(cookies.len(), plans.len());
        let by_id = cookies[wanted
            .iter()
            .position(|p| p.symbol == "ENGINE_by_id")
            .unwrap()];
        assert!(is_engine_cookie(by_id));
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
        assert!(command("B").contains("did=5"));
        let sample = counter.sample(Instant::now() + Duration::from_secs(5));
        let by_id_calls: u64 = sample
            .engine
            .iter()
            .filter(|e| e.cookie == by_id)
            .map(|e| e.calls)
            .sum();
        assert_eq!(by_id_calls, 5, "five PLT ENGINE_by_id calls counted");
        assert_eq!(sample.unattributed, 0, "engine hits never land foreign");
        assert!(
            !sample
                .gaps
                .iter()
                .any(|g| g.name == "focused_ledger_mismatch"),
            "ledger balances engine plane"
        );
        writeln!(commands, "E").unwrap();
        commands.flush().unwrap();
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(code) = child.0.peek_exit().unwrap() {
                assert_eq!(code, 0);
                break;
            }
            assert!(Instant::now() < until, "fixture must exit");
            std::thread::yield_now();
        }
        child.0.finish_observation().unwrap();
        let final_sample = counter.close(Instant::now() + Duration::from_secs(5));
        let final_calls: u64 = final_sample
            .engine
            .iter()
            .filter(|e| e.cookie == by_id)
            .map(|e| e.calls)
            .sum();
        assert_eq!(final_calls, 5, "closed cut keeps engine counts");
        assert!(
            !final_sample
                .gaps
                .iter()
                .any(|g| g.name == "focused_ledger_mismatch"),
            "closed ledger balances engine plane"
        );
    }
    #[test]
    #[ignore = "requires privileged BPF and fresh focused count object"]
    fn native_engine_alias_plans_count_stub_once() {
        use crate::capture::ClockPort;
        use std::{
            fs,
            io::{BufRead, BufReader, Write},
            os::{
                fd::{AsRawFd, FromRawFd},
                unix::fs::MetadataExt as _,
            },
            process::Command,
        };
        let dir =
            std::env::temp_dir().join(format!("osslscope-engine-alias-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let app = dir.join("engine_probe_calls");
        assert!(
            Command::new("cc")
                .args(["-O1", "-o"])
                .arg(&app)
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/engine_probe_calls.c"
                ))
                .args(["-lcrypto"])
                .status()
                .unwrap()
                .success()
        );
        // Hardlink alias: same stub reached under two paths.
        let alias = dir.join("engine_probe_calls_alias");
        fs::hard_link(&app, &alias).unwrap();
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
        let argv = vec![app.to_str().unwrap().into(), input.to_str().unwrap().into()];
        struct Child(crate::target::OwnedTarget);
        impl Drop for Child {
            fn drop(&mut self) {
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
        child.0.release_retaining_exit().unwrap();
        drop(write);
        let mut output = BufReader::new(read);
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        assert_eq!(line, "ready\n");
        let maps = crate::discovery::maps::read_maps(child.0.pid()).unwrap();
        let lc_path = crate::discovery::legacy::find_libcrypto(&maps).expect("libcrypto mapped");
        let lc = crate::plan::read_file_bound(&lc_path).unwrap();
        let mut mod_bufs: Vec<(String, Vec<u8>)> = Vec::new();
        for path in crate::discovery::legacy::target_modules(&maps, &lc_path) {
            if let Ok(fb) = crate::plan::read_file_bound(&path) {
                mod_bufs.push((path, fb.bytes.to_vec()));
            }
        }
        let modules: Vec<crate::discovery::legacy::Module<'_>> = mod_bufs
            .iter()
            .map(|(p, b)| crate::discovery::legacy::Module { path: p, bytes: b })
            .collect();
        let set = crate::discovery::legacy::probes_for(
            &lc_path,
            &lc.bytes,
            &modules,
            (crate::plan::render_device(lc.dev), lc.ino),
        )
        .unwrap();
        let app_str = app.to_str().unwrap().to_string();
        let probe = set
            .probes
            .iter()
            .find(|p| p.module == app_str && p.symbol == "ENGINE_by_id")
            .expect("fixture PLT plans by_id");
        let meta = fs::metadata(&app).unwrap();
        let app_bytes = &mod_bufs
            .iter()
            .find(|(p, _)| p == &app_str)
            .expect("fixture bytes scanned")
            .1;
        let digest: [u8; 32] = {
            use sha2::{Digest, Sha256};
            Sha256::digest(app_bytes).into()
        };
        // Same (dev, ino, offset) under two paths: one stub.
        let plans = vec![
            EngineProbePlan {
                path: probe.module.clone(),
                offset: probe.offset,
                device: meta.dev(),
                inode: meta.ino(),
                sha256: digest,
            },
            EngineProbePlan {
                path: alias.to_str().unwrap().to_string(),
                offset: probe.offset,
                device: meta.dev(),
                inode: meta.ino(),
                sha256: digest,
            },
        ];
        let records = crate::inventory::snapshot(&crate::inventory::SnapshotOptions {
            pids: vec![child.0.pid()],
            ..Default::default()
        })
        .processes;
        assert_eq!(records.len(), 1);
        let cookies = counter
            .attach_engine_probes(
                &plans,
                child.0.pid(),
                records[0].starttime,
                Instant::now() + Duration::from_secs(10),
                &cancel,
            )
            .unwrap();
        assert_eq!(cookies.len(), 2);
        writeln!(commands, "B").unwrap();
        commands.flush().unwrap();
        loop {
            let mut ack = String::new();
            assert!(output.read_line(&mut ack).unwrap() > 0);
            if ack.starts_with("ack B 1 ") {
                assert!(ack.contains("did=5"));
                break;
            }
        }
        let sample = counter.sample(Instant::now() + Duration::from_secs(5));
        // Sum over distinct returned cookies: aliased plans share
        // one cookie after the fix, so distinct-counting is what
        // proves the stub fired once per call.
        let mut distinct = cookies.clone();
        distinct.sort_unstable();
        distinct.dedup();
        let total: u64 = distinct
            .iter()
            .flat_map(|c| sample.engine.iter().filter(move |e| e.cookie == *c))
            .map(|e| e.calls)
            .sum();
        assert_eq!(total, 5, "aliased plans count the stub once");
        writeln!(commands, "E").unwrap();
        commands.flush().unwrap();
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(code) = child.0.peek_exit().unwrap() {
                assert_eq!(code, 0);
                break;
            }
            assert!(Instant::now() < until, "fixture must exit");
            std::thread::yield_now();
        }
        let _ = child.0.finish_observation();
    }
    #[test]
    #[ignore = "requires privileged BPF and fresh focused count object"]
    fn native_engine_pin_change_retires_counter() {
        use crate::capture::ClockPort;
        use std::{
            fs,
            io::{BufRead, BufReader},
            os::{
                fd::{AsRawFd, FromRawFd},
                unix::fs::{MetadataExt as _, PermissionsExt as _},
            },
            process::Command,
        };
        let dir =
            std::env::temp_dir().join(format!("osslscope-engine-pinchg-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let app = dir.join("engine_probe_calls");
        assert!(
            Command::new("cc")
                .args(["-O1", "-o"])
                .arg(&app)
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/engine_probe_calls.c"
                ))
                .args(["-lcrypto"])
                .status()
                .unwrap()
                .success()
        );
        let input = dir.join("commands");
        assert!(
            Command::new("mkfifo")
                .arg(&input)
                .status()
                .unwrap()
                .success()
        );
        let commands = fs::OpenOptions::new()
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
        let argv = vec![app.to_str().unwrap().into(), input.to_str().unwrap().into()];
        struct Child(crate::target::OwnedTarget);
        impl Drop for Child {
            fn drop(&mut self) {
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
        child.0.release_retaining_exit().unwrap();
        drop(write);
        let mut output = BufReader::new(read);
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        assert_eq!(line, "ready\n");
        let maps = crate::discovery::maps::read_maps(child.0.pid()).unwrap();
        let lc_path = crate::discovery::legacy::find_libcrypto(&maps).expect("libcrypto mapped");
        let lc = crate::plan::read_file_bound(&lc_path).unwrap();
        let mut mod_bufs: Vec<(String, Vec<u8>)> = Vec::new();
        for path in crate::discovery::legacy::target_modules(&maps, &lc_path) {
            if let Ok(fb) = crate::plan::read_file_bound(&path) {
                mod_bufs.push((path, fb.bytes.to_vec()));
            }
        }
        let modules: Vec<crate::discovery::legacy::Module<'_>> = mod_bufs
            .iter()
            .map(|(p, b)| crate::discovery::legacy::Module { path: p, bytes: b })
            .collect();
        let set = crate::discovery::legacy::probes_for(
            &lc_path,
            &lc.bytes,
            &modules,
            (crate::plan::render_device(lc.dev), lc.ino),
        )
        .unwrap();
        let app_str = app.to_str().unwrap().to_string();
        let probe = set
            .probes
            .iter()
            .find(|p| p.module == app_str && p.symbol == "ENGINE_by_id")
            .expect("fixture PLT plans by_id");
        let meta = fs::metadata(&app).unwrap();
        let app_bytes = &mod_bufs
            .iter()
            .find(|(p, _)| p == &app_str)
            .expect("fixture bytes scanned")
            .1;
        let digest: [u8; 32] = {
            use sha2::{Digest, Sha256};
            Sha256::digest(app_bytes).into()
        };
        let plans = vec![EngineProbePlan {
            path: probe.module.clone(),
            offset: probe.offset,
            device: meta.dev(),
            inode: meta.ino(),
            sha256: digest,
        }];
        let records = crate::inventory::snapshot(&crate::inventory::SnapshotOptions {
            pids: vec![child.0.pid()],
            ..Default::default()
        })
        .processes;
        assert_eq!(records.len(), 1);
        counter
            .attach_engine_probes(
                &plans,
                child.0.pid(),
                records[0].starttime,
                Instant::now() + Duration::from_secs(10),
                &cancel,
            )
            .unwrap();
        assert_eq!(counter.active_link_count(), 1);
        // A retained ENGINE pin is live custody: flipping one mode
        // bit mid-window (same inode, same bytes) must fail
        // authority and retire the counter, exactly like a changed
        // provider backing file.
        let mut perms = fs::metadata(&app).unwrap().permissions();
        perms.set_mode(perms.mode() ^ 0o001);
        fs::set_permissions(&app, perms).unwrap();
        assert_eq!(counter.retain_authority(false), Err(CountFailure::Identity));
        assert_eq!(counter.active_link_count(), 0);
        let _ = commands;
        let _ = output;
    }
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
            None,
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
            None,
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
    fn unprivileged_attach_records_link_diagnostic() {
        // Root forks a worker child that performs the whole setup
        // itself, then installs a seccomp filter denying only bpf()
        // with EPERM — validation (procfs opens, fstat, reads)
        // proceeds untouched, but the attach's link_create fails
        // deterministically and the failure must shape itself as a
        // link diagnostic.
        // SAFETY: geteuid has no preconditions and cannot fail.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skip link pin: needs root");
            return;
        }
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: fds points to two writable ints; return checked.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: single-threaded test; the child runs the worker
        // (setup, release, deprivilege, attach), reports one verdict
        // byte, and _exits.
        let forked = unsafe { libc::fork() };
        assert!(forked >= 0, "fork failed");
        if forked == 0 {
            // SAFETY: we own fds[0]; closing the unused read end.
            unsafe { libc::close(fds[0]) };
            let verdict: u8 = worker_verdict();
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
        // exited child.
        let deadline = Instant::now() + Duration::from_secs(120);
        let mut buf = [0u8; 1];
        if let Err(e) = crate::target::read_exact_deadline(fds[0], &mut buf, deadline) {
            crate::target::kill_test_child(forked as u32, Duration::from_secs(5));
            // SAFETY: we own fds[0].
            unsafe { libc::close(fds[0]) };
            panic!("link pin verdict unread ({e}); worker killed");
        }
        // SAFETY: we own fds[0].
        unsafe { libc::close(fds[0]) };
        match crate::target::wait_test_child(forked as u32, deadline) {
            crate::target::TestChildWait::Reaped(status) => assert!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "link pin worker exited abnormally: {status}"
            ),
            crate::target::TestChildWait::Gone => {
                panic!("link pin worker reaped elsewhere (sole-reaper violated)")
            }
            crate::target::TestChildWait::Timeout => {
                crate::target::kill_test_child(forked as u32, Duration::from_secs(5));
                panic!("link pin worker reported but never exited; killed");
            }
        }
        match buf[0] {
            1 => {}
            2 => {
                eprintln!("skip link pin: seccomp-bpf unsupported or foreign arch");
                return;
            }
            other => {
                panic!("link diagnostic verdict {other} (10-17=CountFailure, 5=no-diag, 6=vacuous)")
            }
        }
    }

    /// Post-fork worker for [`unprivileged_attach_records_link_diagnostic`]:
    /// 1 ok, 2 skip (seccomp-bpf positively unsupported, or foreign
    /// arch the x86_64-only filter cannot deny), 0 filter installed
    /// yet the link succeeded (broken pin), 5 attach-Attach without a
    /// shaped diagnostic, 10-17 any other [`CountFailure`], 3 setup
    /// failure (missing object/vehicle support, or a failed install
    /// on a supporting kernel).
    fn worker_verdict() -> u8 {
        use crate::capture::ClockPort;
        let argv = vec![
            "/usr/bin/openssl".to_string(),
            "dgst".to_string(),
            "-sha512".to_string(),
            "/dev/null".to_string(),
        ];
        let child = match crate::target::OwnedTarget::spawn_stopped(
            &argv,
            crate::target::WorkloadDest::Null,
        ) {
            Ok(child) => child,
            Err(_) => return 3,
        };
        let cancelled = Arc::new(AtomicBool::new(false));
        let sites = match crate::startup_objects::prepare_owned_startup(
            &child,
            &argv,
            &mut crate::provider_observation::ObservationBudget::default(),
            Instant::now() + Duration::from_secs(10),
            &cancelled,
            None,
        ) {
            Ok(sites) if !sites.candidates.is_empty() => sites,
            _ => return 3,
        };
        let bytes = match std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT")
            .and_then(|path| std::fs::read(path).ok())
        {
            Some(bytes) => bytes,
            None => return 3,
        };
        let Some(start_ns) = crate::capture::LiveClock.checked_monotonic_ns() else {
            return 3;
        };
        let observer = match crate::focused_capture::observer_namespace() {
            Ok(namespace) => namespace,
            Err(_) => return 3,
        };
        let mut counter = match FocusedCounter::open(
            &bytes,
            child.pid(),
            observer,
            CountLimits {
                window: CountAdmissionWindow {
                    start_ns,
                    deadline_ns: start_ns + 10_000_000_000,
                },
                ..Default::default()
            },
        ) {
            Ok(counter) => counter,
            Err(_) => return 3,
        };
        // Seccomp self-restriction: deny only the bpf() syscall with
        // EPERM, allow everything else. Validation (procfs opens,
        // fstat, reads) proceeds untouched, while the first BPF
        // operation of the attach — link_create — fails
        // deterministically. The filter is per-task, so the parent
        // test process is unaffected.
        // SAFETY: the program is six classic-BPF instructions over
        // struct seccomp_data (nr at 0, arch at 4); jump targets are
        // in range; non-x86_64 falls through to ALLOW (foreign arch
        // then skips via verdict 2 instead of dying); prctl args are
        // valid; NO_NEW_PRIVS first for the unprivileged-install rule.
        #[repr(C)]
        struct SockFilter {
            code: u16,
            jt: u8,
            jf: u8,
            k: u32,
        }
        #[repr(C)]
        struct SockFprog {
            len: u16,
            filter: *const SockFilter,
        }
        const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
        const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
        const SECCOMP_RET_ALLOW: u32 = 0x7FFF_0000;
        // The deny filter below is x86_64-only; any other arch
        // must skip (positively identified), never pass vacuously or
        // fail spuriously.
        if !cfg!(target_arch = "x86_64") {
            return 2;
        }
        // Positively identify kernel support before installing. The
        // NULL-filter probe installs nothing, so NO_NEW_PRIVS is not
        // needed yet — and every outcome is classified explicitly:
        // only a recognized lack of support skips; anything
        // unexpected fails.
        // SAFETY: prctl with a NULL filter installs nothing; the
        // return/errno pair is only inspected (no syscall between
        // the prctl and the errno read, so the errno is the
        // probe's).
        let probe = unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, 0) };
        if probe == 0 {
            // A NULL filter cannot install: success here is
            // impossible — fail, investigate, do not skip.
            return 3;
        }
        match std::io::Error::last_os_error().raw_os_error() {
            // The kernel has no SECCOMP_MODE_FILTER: positively
            // identified missing prerequisite, skip.
            Some(libc::EINVAL) => return 2,
            // The mode exists (only the NULL address was refused):
            // supported, proceed to install.
            Some(libc::EFAULT) => {}
            // Anything else (EPERM, EACCES, ...) is unexpected:
            // fail, investigate, do not skip.
            _ => return 3,
        }
        let jailed = {
            let prog = [
                SockFilter {
                    code: 0x20,
                    jt: 0,
                    jf: 0,
                    k: 4,
                },
                SockFilter {
                    code: 0x15,
                    jt: 0,
                    jf: 0,
                    k: AUDIT_ARCH_X86_64,
                },
                SockFilter {
                    code: 0x20,
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
                SockFilter {
                    code: 0x15,
                    jt: 0,
                    jf: 1,
                    k: libc::SYS_bpf as u32,
                },
                SockFilter {
                    code: 0x06,
                    jt: 0,
                    jf: 0,
                    k: SECCOMP_RET_ERRNO | libc::EPERM as u32,
                },
                SockFilter {
                    code: 0x06,
                    jt: 0,
                    jf: 0,
                    k: SECCOMP_RET_ALLOW,
                },
            ];
            let fprog = SockFprog {
                len: prog.len() as u16,
                filter: prog.as_ptr(),
            };
            unsafe {
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
                    && libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &fprog) == 0
            }
        };
        // Support was proven above: a failed install is a broken
        // pin, not a skip.
        if !jailed {
            return 3;
        }
        // Fail-open count: if /proc/self/fd is unreadable the attach
        // below fails too and the pin fails on the resulting
        // CountFailure — a broken pin can only go undetected
        // alongside a broken /proc.
        let link_fds = || -> usize {
            std::fs::read_dir("/proc/self/fd")
                .map(|dir| {
                    dir.flatten()
                        .filter(|p| {
                            std::fs::read_link(p.path()).is_ok_and(|n| {
                                n.to_string_lossy().contains("bpf-link")
                                    || n.to_string_lossy().contains("bpf_link")
                            })
                        })
                        .count()
                })
                .unwrap_or(0)
        };
        let baseline = link_fds();
        let cancel = AtomicBool::new(false);
        let verdict = match counter.attach_candidates_controlled(
            sites
                .candidates
                .into_iter()
                .map(CountCandidate::Static)
                .collect(),
            start_ns,
            Instant::now() + Duration::from_secs(10),
            &cancel,
        ) {
            Ok(()) => {
                // The filter is installed on a known arch: a new link
                // means the denial did not deny (broken pin). No new
                // link with Ok means the attach went nowhere (6).
                if link_fds() > baseline { 0 } else { 6 }
            }
            Err(CountFailure::Attach) => {
                let diags = counter.take_attach_diagnostics();
                if diags.iter().any(|d| {
                    d.starts_with("attach:link count_entry@0x")
                        && crate::acquire_cause::attach_template_shape(
                            d.strip_prefix("attach:").unwrap_or(""),
                        )
                }) {
                    1
                } else {
                    5
                }
            }
            Err(CountFailure::Object) => 10,
            Err(CountFailure::Map) => 11,
            Err(CountFailure::Namespace) => 12,
            Err(CountFailure::Identity) => 13,
            Err(CountFailure::Deferred) => 14,
            Err(CountFailure::Read) => 15,
            Err(CountFailure::Resource) => 16,
            Err(CountFailure::Close) => 17,
        };
        drop(counter);
        drop(child);
        verdict
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
            None,
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
            None,
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

#[cfg(test)]
mod budget_tests {
    use super::*;
    #[test]
    #[ignore = "requires privileged BPF and fresh focused count object"]
    fn native_engine_attach_refuses_stale_fingerprint() {
        use crate::capture::ClockPort;
        use std::{
            os::unix::fs::MetadataExt as _,
            sync::atomic::AtomicBool,
            time::{Duration, Instant},
        };
        // No fixture: the digest check runs before any link
        // effect, so a wrong digest must refuse on any live pid
        // with any readable file.
        let me = std::process::id();
        let exe = std::env::current_exe().unwrap();
        let meta = std::fs::metadata(&exe).unwrap();
        let records = crate::inventory::snapshot(&crate::inventory::SnapshotOptions {
            pids: vec![me],
            ..Default::default()
        })
        .processes;
        assert_eq!(records.len(), 1);
        let cancel = AtomicBool::new(false);
        let bytes =
            std::fs::read(std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT").unwrap()).unwrap();
        let start = crate::capture::LiveClock.checked_monotonic_ns().unwrap();
        let mut counter = FocusedCounter::open(
            &bytes,
            me,
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
        let plans = vec![EngineProbePlan {
            path: exe.to_str().unwrap().to_string(),
            offset: 0x1000,
            device: meta.dev(),
            inode: meta.ino(),
            sha256: [0u8; 32],
        }];
        // Correct identity, wrong content digest: the pinned bytes
        // no longer match the parse this offset came from.
        assert_eq!(
            counter.attach_engine_probes(
                &plans,
                me,
                records[0].starttime,
                Instant::now() + Duration::from_secs(10),
                &cancel,
            ),
            Err(CountFailure::Identity)
        );
        assert_eq!(counter.active_link_count(), 0);
    }
    #[test]
    #[ignore = "requires privileged BPF and fresh focused count object"]
    fn native_engine_epoch_advances_on_every_retire() {
        use crate::capture::ClockPort;
        let me = std::process::id();
        let bytes =
            std::fs::read(std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT").unwrap()).unwrap();
        let start = crate::capture::LiveClock.checked_monotonic_ns().unwrap();
        let mut counter = FocusedCounter::open(
            &bytes,
            me,
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
        // Every retire advances the epoch unconditionally — even
        // with no links — so a plane can tell dead links from
        // live ones by comparison alone.
        assert_eq!(counter.engine_epoch(), 0);
        counter.retire();
        assert_eq!(counter.engine_epoch(), 1);
        counter.retire();
        assert_eq!(counter.engine_epoch(), 2);
    }
    #[test]
    fn engine_plan_dedupe_collapses_hardlink_aliases() {
        let plans = vec![
            EngineProbePlan {
                path: "/x/a".into(),
                offset: 7,
                device: 1,
                inode: 2,
                sha256: [9u8; 32],
            },
            EngineProbePlan {
                path: "/x/b".into(),
                offset: 7,
                device: 1,
                inode: 2,
                sha256: [9u8; 32],
            },
            EngineProbePlan {
                path: "/x/a".into(),
                offset: 9,
                device: 1,
                inode: 2,
                sha256: [9u8; 32],
            },
            EngineProbePlan {
                path: "/x/c".into(),
                offset: 7,
                device: 1,
                inode: 3,
                sha256: [9u8; 32],
            },
        ];
        let (unique, slots) = dedupe_engine_plans(&plans).unwrap();
        assert_eq!(unique, vec![0, 2, 3]);
        assert_eq!(slots, vec![0, 0, 1, 2]);
    }
    #[test]
    fn pin_read_error_maps_tears_not_io_failures() {
        use std::io::ErrorKind;
        // Demonstrated instability: the file changed under the
        // read (or outgrew the bound the parse succeeded under).
        assert_eq!(
            map_pin_read_error(ErrorKind::InvalidData),
            CountFailure::Identity
        );
        assert_eq!(
            map_pin_read_error(ErrorKind::FileTooLarge),
            CountFailure::Identity
        );
        // Ordinary read failures establish no change: Read, never
        // a fabricated ObjectChanged.
        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::NotFound,
            ErrorKind::BrokenPipe,
            ErrorKind::Other,
        ] {
            assert_eq!(map_pin_read_error(kind), CountFailure::Read, "{kind:?}");
        }
    }
    #[test]
    fn engine_plan_dedupe_refuses_fingerprint_conflict() {
        // Same physical stub, disagreeing content digests (the
        // module changed between the two plan reads): collapsing
        // would bless one parse silently — refuse instead.
        let plans = vec![
            EngineProbePlan {
                path: "/x/a".into(),
                offset: 7,
                device: 1,
                inode: 2,
                sha256: [1u8; 32],
            },
            EngineProbePlan {
                path: "/x/b".into(),
                offset: 7,
                device: 1,
                inode: 2,
                sha256: [2u8; 32],
            },
        ];
        assert!(dedupe_engine_plans(&plans).is_none());
    }
    #[test]
    fn engine_pin_stamp_catches_mode_and_size_change() {
        use crate::provider_observation::objects::Stamp;
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("osslscope-pin-stamp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mod");
        std::fs::write(&path, b"bytes").unwrap();
        let pin = std::fs::File::open(&path).unwrap();
        let stamp = Stamp::of(&pin.metadata().unwrap());
        assert!(engine_pin_unchanged(&pin, &stamp));
        // A mode flip (no content change) still invalidates.
        let mut perms = pin.metadata().unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
        assert!(!engine_pin_unchanged(&pin, &stamp));
        std::fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    fn ledger_balances_engine_counts_with_admission() {
        let sample = CountSample {
            engine: vec![EngineCount {
                cookie: ENGINE_COOKIE_BASE,
                generation: 1,
                calls: 7,
                first_ns: 2,
                last_ns: 3,
            }],
            unattributed: 5,
            dropfail: 1,
            ..Default::default()
        };
        assert_eq!(ledger_counted(&sample), 13);
    }
    /// Small-budget control through the real counter-opening path: a
    /// small-but-valid `max_state_bytes` refuses with Resource before any
    /// BTF open or allocation (unprivileged: the refusal precedes the
    /// first kernel effect). The companion proves the refusal is
    /// budget-specific: default limits with garbage bytes fail shape
    /// admission with Object instead.
    #[test]
    fn small_valid_budget_refuses_before_btf_scratch() {
        let namespace = crate::focused_capture::observer_namespace().unwrap();
        let small = CountLimits {
            max_state_bytes: 1 << 20,
            window: CountAdmissionWindow {
                start_ns: 1,
                deadline_ns: 2,
            },
            ..Default::default()
        };
        small.validate().unwrap();
        assert!(loader::COUNT_JOIN_SCRATCH_BYTES > small.max_state_bytes);
        assert!(matches!(
            FocusedCounter::open(&[0u8; 64], 1234, namespace, small),
            Err(CountFailure::Resource)
        ));
        let roomy = CountLimits {
            window: CountAdmissionWindow {
                start_ns: 1,
                deadline_ns: 2,
            },
            ..Default::default()
        };
        assert!(matches!(
            FocusedCounter::open(&[0u8; 64], 1234, namespace, roomy),
            Err(CountFailure::Object)
        ));
    }
}
