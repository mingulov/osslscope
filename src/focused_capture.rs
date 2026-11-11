// SPDX-License-Identifier: GPL-3.0-or-later
//! One-process synchronous focused capture. Advertisements only permit bounded
//! callback attachment; open attribution and the production tail stay unknown.
use crate::{
    capture::{self, ClockPort, LiveClock},
    discovery::{elf, legacy, maps},
    evidence::*,
    focused_count::{
        CountCandidate, CountFailure, CountLimits, CountSample, EngineCount, EngineProbePlan,
        FocusedCounter, evidence_device,
    },
    inventory::{
        self,
        scope::{ScopedScanner, Selection},
    },
    provider_observation::{
        AliasStatus, Cacheability, ObservationBatch, ObservationGap, ObservationLimits,
        ObservationPayload, ProviderSession, cli::Signals,
    },
    target::{OwnedTarget, TargetDisposition},
};
use anyhow::{Context, bail};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    os::unix::fs::MetadataExt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

const POLL: Duration = Duration::from_millis(100);
const DRAIN: Duration = Duration::from_millis(25);
const RESCAN: Duration = Duration::from_secs(1);
#[derive(Clone, Debug)]
pub struct FocusedConfig {
    pub duration: Duration,
    pub timeout: Duration,
    pub grace: Duration,
    /// Run-shared ELF parse cache handle (F8d RESTORATION; `None`
    /// parses uncached). Clone shares the run's cache.
    pub parsed_cache:
        Option<std::rc::Rc<std::cell::RefCell<crate::provider_observation::objects::ParseCache>>>,
}
impl Default for FocusedConfig {
    fn default() -> Self {
        Self {
            duration: Duration::from_secs(30),
            timeout: Duration::from_secs(60),
            grace: Duration::from_secs(5),
            parsed_cache: None,
        }
    }
}
impl FocusedConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        for (name, value) in [
            ("duration", self.duration),
            ("timeout", self.timeout),
            ("grace", self.grace),
        ] {
            if value.is_zero() {
                bail!("focused {name} must be positive");
            }
            crate::args::parse_seconds(name, &value.as_secs_f64().to_string())
                .map_err(anyhow::Error::msg)?;
        }
        Ok(())
    }
}
#[derive(Clone)]
pub struct FocusedObjects {
    pub observation: Arc<[u8]>,
    pub count: Arc<[u8]>,
    pub count_sha256: [u8; 32],
}
/// Target acquisition has no usable selected-process observation.
#[derive(Debug)]
pub struct TargetUnavailable;
impl std::fmt::Display for TargetUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("focused target unavailable")
    }
}
impl std::error::Error for TargetUnavailable {}
pub struct FocusedResult {
    pub document: CaptureDocument,
    pub child_exit: Option<i32>,
    pub workload_discarded: bool,
    /// 6A fence conservation: count-plane withheld calls plus
    /// provider-plane dropped records, merged at seal into the
    /// member loss ledger (`LossSummary.loss`).
    pub fence_withheld: u64,
    /// 6A final per-index LOSS deltas (session scope, read after
    /// the closing drain): the coordinator folds these into the
    /// cumulative `SessionLoss.ring` exactly once at seal.
    pub loss_totals: [u64; 8],
    pub(crate) _reservation: Option<crate::observation_memory::MemoryLease>,
}

/// No event-order proof is exposed within a batch. Invalidation therefore
/// discards new live metadata; static code lifetime is checked independently.
fn batch_invalidates_advertisements(batch: &ObservationBatch, pid: u32) -> bool {
    batch.facts.iter().any(|f| {
        f.pid == pid
            && matches!(
                f.payload,
                ObservationPayload::Invalidation { .. }
                    | ObservationPayload::QueryResult {
                        cacheability: Cacheability::Volatile | Cacheability::Unknown,
                        ..
                    }
            )
    }) || batch.gaps.iter().any(|g| {
        matches!(
            g,
            ObservationGap::ProcessUnavailable
                | ObservationGap::ProcessChanged
                | ObservationGap::NamespaceChanged
                | ObservationGap::BackingUnavailable
                | ObservationGap::IdentityUnverified
                | ObservationGap::ObjectChanged
                | ObservationGap::MalformedMaps
                | ObservationGap::QueueLoss
                | ObservationGap::PendingLimit
                | ObservationGap::DepthLimit
                | ObservationGap::DrainOverrun
                | ObservationGap::SnapshotLag
                | ObservationGap::InvalidWire
                | ObservationGap::TargetReadFailed
                | ObservationGap::UnpairedReturn
                | ObservationGap::RelocationRefused
                | ObservationGap::MembershipUnknown
                | ObservationGap::RegistrationRace
                | ObservationGap::Invalidated
                | ObservationGap::BpfUnavailable
                | ObservationGap::FactLimit
                | ObservationGap::StateLimit
        )
    })
}
/// Target-memory observation loss does not invalidate retained executable code.
/// Actual process, namespace and backing changes still retire every link.
pub fn batch_requires_retirement(batch: &ObservationBatch, pid: u32) -> bool {
    batch.facts.iter().any(|f| {
        f.pid == pid
            && matches!(
                f.payload,
                ObservationPayload::Invalidation {
                    cause: crate::provider_observation::InvalidationCause::IdentityChanged
                }
            )
    }) || batch.gaps.iter().any(|g| {
        matches!(
            g,
            ObservationGap::ProcessUnavailable
                | ObservationGap::ProcessChanged
                | ObservationGap::NamespaceChanged
                | ObservationGap::BackingUnavailable
                | ObservationGap::ObjectChanged
                | ObservationGap::MalformedMaps
                | ObservationGap::MembershipUnknown
                | ObservationGap::BpfUnavailable
        )
    })
}
fn loss(name: &str, source: CounterSource, value: u64) -> GapCounter {
    GapCounter {
        name: name.into(),
        source,
        value,
        kind: CounterKind::Loss,
        units: CounterUnits::Events,
    }
}
fn observation_loss(gap: ObservationGap) -> GapCounter {
    use ObservationGap::*;
    let (name, source) = match gap {
        FirstQueryUnknown => ("focused.first_query_unknown", CounterSource::Discovery),
        IntervalUnknown | SamplingPartial => ("focused.interval_unknown", CounterSource::Discovery),
        AmbiguousSite | DispatchPartial => ("focused.ambiguity", CounterSource::Discovery),
        QueueLoss | PendingLimit | DepthLimit | UnpairedReturn | InvalidWire => {
            ("focused.observation_loss", CounterSource::KernelRing)
        }
        ProcessUnavailable | ProcessChanged | NamespaceChanged | ObjectChanged
        | IdentityUnverified | MembershipUnknown | Invalidated | RegistrationRace => {
            ("focused.identity_unknown", CounterSource::Lifecycle)
        }
        ProcessLimit | ObjectLimit | LinkLimit | SiteLimit | FactLimit | StateLimit | ReadLimit => {
            ("focused.limit", CounterSource::Discovery)
        }
        CompanionsUnavailable => ("focused.companions_unavailable", CounterSource::Setup),
        BpfUnavailable | InvalidObject | ClassifierFailed => {
            ("focused.tracing_unavailable", CounterSource::Setup)
        }
        AttachFailed => ("focused.observation_attach", CounterSource::Attach),
        // I-2: the kernel-panic quarantine refusal names itself — a
        // refused attach is not a drain/read failure (never read_unknown).
        QuarantinedApi => ("focused.attach_refused_quarantined", CounterSource::Attach),
        _ => ("focused.read_unknown", CounterSource::Drain),
    };
    loss(name, source, 1)
}

/// Project the latest cumulative sample exactly once. No advertised identity
/// establishes a complete candidate set or a certified provider class.
pub fn project(
    pid: u32,
    window: CaptureWindow,
    mut sample: CountSample,
    gaps: &[ObservationGap],
    attach_diagnostics: &BTreeSet<String>,
) -> CaptureDocument {
    let mut partition = LegacyCallPartition::default();
    let mut objects = BTreeSet::new();
    for site in sample.sites.iter_mut().chain(&mut sample.fenced) {
        site.candidates_coverage = CandidateCoverage::Unknown;
        if site.candidates.is_empty() {
            partition.unfenced_tails = partition.unfenced_tails.saturating_add(site.calls);
        } else {
            partition.shared_ambiguous = partition.shared_ambiguous.saturating_add(site.calls);
        }
        objects.insert((site.site.object.clone(), site.site.device, site.site.inode));
        for candidate in &site.candidates {
            // D3 identifies advertisers by hash only. Zero locators explicitly
            // mean unavailable; they never borrow the backing code's identity.
            objects.insert((candidate.provider.clone(), 0, 0));
        }
    }
    let attached = sample.sites.len() as u64;
    let discovered = attached.saturating_add(sample.fenced.len() as u64);
    // Executed-site set for the bounded metadata pre-scan below; read
    // before the fenced rows drain into generation buckets.
    let used = used_site_generations(sample.sites.iter().chain(sample.fenced.iter()));
    let mut fenced: BTreeMap<u32, Vec<SiteExecution>> = BTreeMap::new();
    for site in sample.fenced {
        fenced.entry(site.generation).or_default().push(site);
    }
    sample
        .gaps
        .extend(gaps.iter().copied().map(observation_loss));
    sample
        .gaps
        .push(loss("focused.first_call_unknown", CounterSource::Attach, 1));
    sample
        .gaps
        .push(loss("focused.finality_unknown", CounterSource::Drain, 1));
    // Unknown-cookie and ledger counters never create physical site counts.
    if sample.unattributed > 0 {
        let mut counter = loss(
            "focused.unattributed",
            CounterSource::KernelMap,
            sample.unattributed,
        );
        counter.units = CounterUnits::Calls;
        sample.gaps.push(counter);
    }
    let associations = std::mem::take(&mut sample.associations);
    // Bounded metadata projection (5D) is pre-scanned so omission
    // counts record their gaps here, before finalization — the
    // post-finalize projection below applies the same selection.
    let selection = select_metadata_rows(&associations, &used, METADATA_PROJECTION_BUDGET_BYTES);
    if selection.omitted_sites > 0 || selection.omitted_associations > 0 {
        sample.gaps.push(loss(
            "focused.metadata_output_limit",
            CounterSource::Discovery,
            1,
        ));
        for (name, value, units) in [
            (
                "focused.metadata_omitted_sites",
                selection.omitted_sites,
                CounterUnits::Sites,
            ),
            (
                "focused.metadata_omitted_associations",
                selection.omitted_associations,
                CounterUnits::TableRows,
            ),
        ] {
            sample.gaps.push(GapCounter {
                name: name.into(),
                source: CounterSource::Discovery,
                value: u64::try_from(value).unwrap_or(u64::MAX),
                kind: CounterKind::Activity,
                units,
            });
        }
    }
    let mut document = crate::evidence::finalize(FinalizeInput {
        corpse_wait: None,
        window,
        sites: sample.sites,
        fenced: fenced
            .into_iter()
            .map(|(generation, sites)| FencedGeneration { generation, sites })
            .collect(),
        objects: objects
            .into_iter()
            .map(|(id, device, inode)| ObjectRecord {
                id,
                device,
                inode,
                display_locator: "unknown".into(),
            })
            .collect(),
        coverage: vec![ScopeCoverage {
            scope: "focused.execution".into(),
            expected: ExpectedScope::Unknown,
            discovered,
            attached,
        }],
        counters: sample.gaps,
        fatal: None,
        target: TargetRecord::new(pid, "unknown".into(), String::new(), String::new()),
        openssl: OpensslVersion::unknown(),
        disposition: None,
        policy: None,
        legacy_partition: partition,
        engine_observations: Vec::new(),
        traversal: None,
    });
    document.candidate_associations = associations;
    // R06: failed-attach/backing diagnostics ride the document (sorted
    // set take, capped — deterministic; the counters stay the exact
    // counts regardless). Same rule as the capture path.
    document.attach_diagnostics = attach_diagnostics
        .iter()
        .take(crate::capture::ATTACH_DIAGNOSTICS_CAP)
        .cloned()
        .collect();
    let projection = project_metadata_bounded(&document, METADATA_PROJECTION_BUDGET_BYTES);
    debug_assert_eq!(projection.omitted_sites, selection.omitted_sites);
    debug_assert_eq!(
        projection.omitted_associations,
        selection.omitted_associations
    );
    document.algorithm_identities = projection.algorithm_identities;
    document.site_provenance = projection.site_provenance;
    document
}
/// Fold one counter sample's cumulative ENGINE counts into
/// per-cookie news for the collector: sums across count
/// generations per cookie (the binding epoch is the join key, not
/// the count fence), then differences against the previous sample's
/// cumulative sums. Returns only nonzero news; updates `prev` in
/// place. Drains are cumulative by construction, so a decrease
/// clamps to zero news rather than negative evidence.
fn engine_news(prev: &mut BTreeMap<u32, u64>, engine: &[EngineCount]) -> Vec<(u64, u64)> {
    let mut current: BTreeMap<u32, u64> = BTreeMap::new();
    for e in engine {
        current
            .entry(e.cookie)
            .and_modify(|n| *n = n.saturating_add(e.calls))
            .or_insert(e.calls);
    }
    let mut news = Vec::new();
    for (cookie, total) in &current {
        let delta = total.saturating_sub(prev.get(cookie).copied().unwrap_or(0));
        if delta > 0 {
            news.push((u64::from(*cookie), delta));
        }
    }
    for (cookie, total) in current {
        prev.insert(cookie, total);
    }
    news
}
/// Libcrypto admitted for ENGINE probe planning: maps path plus
/// fresh evidence-encoded stat identity, cross-checked against the
/// admitted inventory record (a dlopen/exec race skips this
/// snapshot; the maps dev-string is never compared —
/// btrfs/overlay diverge it).
struct AdmittedLibcrypto {
    path: String,
    device: u64,
    inode: u64,
}
/// Diff the current caller set against the plan-time baseline:
/// every new path or changed (device, inode) identity is one
/// more module with unknown imports (single-plan policy: never
/// rescanned, always gap-counted). The baseline grows to absorb
/// news, so each change counts once; paths vanished from maps
/// stay (their pinned evidence remains valid, no loss). Returns
/// (new skipped count, overflow): overflow means the baseline is
/// full and an unseen path appeared — the caller must blind,
/// since further changes are untrackable.
fn diff_caller_set(
    baseline: &mut BTreeMap<String, Option<(u64, u64)>>,
    current: &[(String, Option<(u64, u64)>)],
    cap: usize,
) -> (u64, bool) {
    let mut skipped = 0u64;
    let mut overflow = false;
    for (path, identity) in current {
        match baseline.get(path) {
            Some(known) if known == identity => {}
            Some(_) => {
                baseline.insert(path.clone(), *identity);
                skipped = skipped.saturating_add(1);
            }
            None => {
                if baseline.len() >= cap {
                    overflow = true;
                } else {
                    baseline.insert(path.clone(), *identity);
                    skipped = skipped.saturating_add(1);
                }
            }
        }
    }
    (skipped, overflow)
}
/// Dedupe wanted probes by physical (device, inode, offset)
/// identity: hardlinked paths describing the same stub emit
/// once (first wanted index wins). Probes whose module
/// identity is unknown are kept — the attach stage blinds
/// loudly on unjoinable modules rather than guessing.
fn dedupe_wanted_probes(
    wanted: &[usize],
    probes: &[crate::discovery::legacy::Probe],
    identities: &BTreeMap<String, (u64, u64)>,
) -> Vec<usize> {
    let mut seen: BTreeSet<(u64, u64, u64)> = BTreeSet::new();
    let mut unique = Vec::with_capacity(wanted.len());
    for &w in wanted {
        let p = &probes[w];
        if let Some(&(device, inode)) = identities.get(&p.module) {
            if !seen.insert((device, inode, p.offset)) {
                continue;
            }
        }
        unique.push(w);
    }
    unique
}
fn select_engine_libcrypto(
    maps: &[maps::Mapping],
    modules: &[inventory::ModuleRecord],
) -> Option<AdmittedLibcrypto> {
    let path = legacy::find_libcrypto(maps)?;
    let entry = maps.iter().find(|m| m.path == path)?;
    // Fresh stat-domain identity; swapped-away files refuse here.
    let fresh = std::fs::metadata(&entry.path).ok()?;
    // H5: ino-only maps guard plus full stat-domain admission
    // against the inventory record.
    if fresh.ino() != entry.ino {
        return None;
    }
    modules
        .iter()
        .any(|m| m.info.device == fresh.dev() && m.info.inode == fresh.ino())
        .then(|| AdmittedLibcrypto {
            path,
            device: evidence_device(fresh.dev()),
            inode: fresh.ino(),
        })
}
/// Map an ENGINE attach failure to its session gap, or None when
/// the outcome surfaces elsewhere (Deferred retries next
/// snapshot; Close means shutdown is already closing the gate,
/// which finish() reports itself).
fn map_engine_attach_failure(f: CountFailure) -> Option<ObservationGap> {
    match f {
        CountFailure::Deferred | CountFailure::Close => None,
        CountFailure::Identity => Some(ObservationGap::ObjectChanged),
        CountFailure::Namespace => Some(ObservationGap::NamespaceChanged),
        CountFailure::Resource => Some(ObservationGap::StateLimit),
        CountFailure::Attach => Some(ObservationGap::AttachFailed),
        CountFailure::Object | CountFailure::Map => Some(ObservationGap::BpfUnavailable),
        CountFailure::Read => Some(ObservationGap::IntervalUnknown),
    }
}
/// True iff the planned ProbeSet reports an absent ENGINE
/// interface (4.x dynsyms carry no ENGINE_*): the Unsupported
/// (explicit fact) signal, distinct from an empty caller surface.
fn engine_interface_absent(set: &legacy::ProbeSet) -> bool {
    set.findings
        .iter()
        .any(|f| f == legacy::FINDING_ENGINE_ABSENT)
}
fn now_ns() -> anyhow::Result<u64> {
    LiveClock
        .checked_monotonic_ns()
        .filter(|n| *n > 0)
        .context("focused monotonic clock unavailable")
}
fn unix_ns() -> Option<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()?
            .as_nanos(),
    )
    .ok()
}
pub(crate) fn observer_namespace() -> anyhow::Result<inventory::NamespaceId> {
    let metadata = std::fs::File::open("/proc/self/ns/pid")?.metadata()?;
    Ok(inventory::NamespaceId {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

pub(crate) enum BatchProgress {
    Applied(bool),
    Deferred,
}
pub(crate) fn process_batch(
    session: &ProviderSession,
    counter: &mut FocusedCounter,
    batch: &ObservationBatch,
    pid: u32,
    control: (u64, Instant, &AtomicBool),
    gaps: &mut BTreeSet<ObservationGap>,
    state_bytes: &mut usize,
) -> anyhow::Result<BatchProgress> {
    gaps.extend(batch.gaps.iter().copied());
    if batch_requires_retirement(batch, pid) {
        counter.retire();
        return Ok(BatchProgress::Applied(false));
    }
    if batch.refreshed_processes.contains(&pid)
        || batch.gaps.contains(&ObservationGap::IdentityUnverified)
    {
        // Inventory metadata is not the independent authority of existing
        // Count links. Validate that custody now; never let the hint alone
        // retain a changed process, namespace, mapping or backing file.
        if counter
            .retain_authority(batch.refreshed_processes.contains(&pid))
            .is_err()
        {
            return Ok(BatchProgress::Applied(false));
        }
    }
    let (deadline_ns, deadline, cancel) = control;
    if Instant::now() >= deadline {
        return Ok(BatchProgress::Deferred);
    }
    let discard_live = batch_invalidates_advertisements(batch, pid);
    let count = batch
        .static_candidates
        .len()
        .checked_add(batch.learned_sites.len());
    let admitted = count
        .and_then(|n| n.checked_mul(256))
        .and_then(|n| state_bytes.checked_add(n));
    if admitted.is_none_or(|n| n > 8 << 20) {
        gaps.insert(ObservationGap::StateLimit);
        return Ok(BatchProgress::Applied(false));
    }

    let mut candidates: Vec<_> = batch
        .static_candidates
        .iter()
        .filter(|c| c.pid() == pid)
        .cloned()
        .map(CountCandidate::Static)
        .collect();
    if !discard_live {
        for candidate in batch.learned_sites.iter().cloned() {
            if candidate.pid() != pid {
                continue;
            }
            if candidate.alias_quality().status != AliasStatus::Complete {
                gaps.insert(ObservationGap::AmbiguousSite);
            }
            if let Err(gap) = session.revalidate_candidate(&candidate) {
                gaps.insert(gap);
                counter.retire();
                return Ok(BatchProgress::Applied(false));
            }
            candidates.push(CountCandidate::Learned(candidate));
        }
    }
    let installed = now_ns()?;
    if installed >= deadline_ns {
        return Ok(BatchProgress::Applied(false));
    }
    let attached = counter.attach_candidates_controlled(candidates, installed, deadline, cancel);
    if attached == Err(crate::focused_count::CountFailure::Deferred) {
        // Only provisional controller/counter allocations were made. Native
        // errors and cancellations are terminal for this batch, never replayed.
        return Ok(BatchProgress::Deferred);
    }
    let valid = attached.is_ok();
    // Refusal diagnostic (stderr only; no behavior change): when a
    // site-bulk batch attaches nothing or carries a limit gap, name
    // the refusing gate — counter fold/link vs session budget vs
    // shared pool — with per-member attribution. The gap set below
    // is exactly the `focused.limit` set above.
    if !valid
        || batch.gaps.iter().any(|g| {
            matches!(
                g,
                ObservationGap::ProcessLimit
                    | ObservationGap::ObjectLimit
                    | ObservationGap::LinkLimit
                    | ObservationGap::SiteLimit
                    | ObservationGap::FactLimit
                    | ObservationGap::StateLimit
                    | ObservationGap::ReadLimit
            )
        })
    {
        let (fold_spent, fold_max, links, max_links) = counter.refusal_accounting();
        let (budget_spent, budget_max, pool) = session.refusal_accounting();
        eprintln!(
            "osslscope: focused site-bulk refused (pid={}, static={}, learned={}, gaps={:?}, attach={:?}, fold={}/{}, links={}/{}, budget={}/{}, pool={:?})",
            pid,
            batch.static_candidates.len(),
            batch.learned_sites.len(),
            batch.gaps,
            attached.as_ref().err(),
            fold_spent,
            fold_max,
            links,
            max_links,
            budget_spent,
            budget_max,
            pool,
        );
    }
    if valid {
        *state_bytes = admitted.unwrap();
    }
    Ok(BatchProgress::Applied(
        valid && counter.active_site_count() > 0 && now_ns()? < deadline_ns,
    ))
}

/// Cap on caller modules scanned for ENGINE probe planning per
/// session (target_modules order); further modules stay unplanned
/// behind an explicit gap.
const MAX_ENGINE_PLAN_MODULES: usize = 16;
/// One maps-consistent caller module scanned for ENGINE probe
/// planning: path, bytes, fresh evidence-encoded stat identity,
/// and the content digest the offsets were parsed from (the attach
/// re-hashes).
struct ScannedCallerModule {
    path: String,
    bytes: Vec<u8>,
    device: u64,
    inode: u64,
    sha256: [u8; 32],
}
/// Cap on caller-set baseline entries watched for late mappings
/// and replacements. Past this the plane blinds: further caller
/// churn is untrackable, and unwatched unknowns must not pass
/// silently (candidates past the cap at plan time are already
/// skipped, never watched).
const MAX_ENGINE_CALLER_WATCH: usize = 256;
/// Cap on total ELF bytes read for ENGINE probe planning per
/// session; modules past this stay unplanned behind the
/// skipped-modules gap, never a silent skip.
const MAX_ENGINE_PLAN_BYTES: usize = 32 << 20;
/// Live ENGINE tripwire plane: at most one planned ProbeSet per
/// session (no mid-window replan — a libcrypto replacement blinds
/// with an explicit gap, mirroring discovery's blind latch without
/// its re-attach).
struct EnginePlane {
    state: EnginePlaneState,
    collector: capture::EngineCollector,
    /// Binding generation for the collector join (0 = unbound).
    generation: u64,
    /// Per-cookie cumulative sums from the last sample (news basis).
    prev: BTreeMap<u32, u64>,
    /// Attached module identities for the final object join:
    /// path → (device, inode, build-id or empty).
    modules: BTreeMap<String, (u64, u64, String)>,
    /// Caller modules skipped during planning (imports unknown).
    skipped_modules: u64,
    /// Planned ENGINE call paths left unprobed (cap/stub-less).
    uninstrumented: u64,
    /// Address-taken imports (diagnostic facts, never probes).
    addrtaken: u64,
    /// Any snapshot mapped libcrypto (unplanned-at-finish with
    /// this set is failed observation, not a non-OpenSSL target).
    ever_mapped: bool,
    /// Counter retire epoch recorded at attach. Any retire
    /// destroys ENGINE links, so a moved epoch blinds the plane.
    counter_epoch: u64,
    /// Caller-set baseline: every candidate path at plan time →
    /// fresh stat identity (None if unstatable). Late mappings
    /// and replacements gap via `skipped_modules` (single-plan
    /// policy: never rescanned); capped, overflow blinds.
    callers: BTreeMap<String, Option<(u64, u64)>>,
    /// Drained-but-unvalidated ENGINE news (cookie → calls),
    /// bounded by attached-cookie count. Joins only after a
    /// passing validation proves the planned bytes unchanged
    /// across the drain; a failed validation drops it (ambiguous
    /// increments are withheld, never joined).
    pending: BTreeMap<u64, u64>,
}
#[derive(Clone, PartialEq, Eq)]
enum EnginePlaneState {
    Unplanned,
    Planned {
        device: u64,
        inode: u64,
        libcrypto: String,
    },
    Blind,
    Unsupported,
}
impl EnginePlane {
    fn new() -> Self {
        Self {
            state: EnginePlaneState::Unplanned,
            collector: capture::EngineCollector::new(),
            generation: 0,
            prev: BTreeMap::new(),
            modules: BTreeMap::new(),
            skipped_modules: 0,
            uninstrumented: 0,
            addrtaken: 0,
            ever_mapped: false,
            counter_epoch: 0,
            callers: BTreeMap::new(),
            pending: BTreeMap::new(),
        }
    }
}
/// Reusable bounded process observation. Fields close counter/provider links
/// before releasing original owned custody, including error/drop paths.
pub(crate) struct FocusedSession {
    gate: Option<crate::writer_gate::WriterGate>,
    counter: Option<FocusedCounter>,
    session: Option<ProviderSession>,
    _foreign: Option<crate::provider_observation::objects::ProcessIncarnation>,
    owned: Option<OwnedTarget>,
    pid: u32,
    starttime: u64,
    namespaces: inventory::NamespaceIds,
    scanner: ScopedScanner,
    initial_metadata: Option<inventory::ProcessRecord>,
    pending: Option<ObservationBatch>,
    /// 6A session-detected exec witnesses (pids) since the last
    /// `take_exec_witnesses` (coordinator drains per tick).
    exec_pending: Vec<u32>,
    /// 6A additive-refresh instants (producer ns) since the last
    /// `take_module_refreshes` (coordinator drains per tick and
    /// stamps record ticks).
    refresh_pending: Vec<u64>,
    /// 6A previous completed drain's read instant (producer ns),
    /// the conservative edge when a witness carries no trusted
    /// timestamp (§1.8). Starts at session start.
    last_clean_drain_ns: u64,
    /// R7-1 deferred-exec hold latch: true while the session
    /// holds a deferred exec retry (`exec_fence_held`, latched
    /// from every fresh batch). While latched, witness-free
    /// drains are NOT clean — the clean instant stays frozen at
    /// the pre-detection edge so the retry-time fence uses the
    /// DETECTION instant's preceding-clean edge, never the retry
    /// instant. Releases when the retry completes (witness) or
    /// the session drops the hold (stale-marker unlink).
    exec_fence_pending: bool,
    gaps: BTreeSet<ObservationGap>,
    /// Shaped attach/backing diagnostics: link failures drained from
    /// the counter plus batch refusals (R06 rule: sorted + deduped
    /// here, capped at the document).
    attach_diagnostics: BTreeSet<String>,
    engine: EnginePlane,
    state_bytes: usize,
    inventory_gaps: u64,
    sample: CountSample,
    next_snapshot: Instant,
    ready: bool,
    start_ns: u64,
    deadline_ns: u64,
    end: Instant,
    wall_start: Option<u64>,
    signal_cut: bool,
    workload_discarded: bool,
    /// Admission-event sysctl sample (T5 schema D-record rule 7):
    /// sampled once in `open`, retained, never reread.
    sysctls: Option<crate::evidence::SysctlContext>,
    _reservation: crate::observation_memory::MemoryLease,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionProgress {
    Running,
    Exited,
    StopRequested,
    Unverifiable,
}
impl FocusedSession {
    /// Hollow session for coordinator unit tests (N7/N8b/N13): no
    /// links, no maps, no custody — seal/close paths project empty
    /// documents without touching BPF or `/proc`. Test-only; never
    /// shipped (`#[cfg(test)]`).
    #[cfg(test)]
    pub(crate) fn hollow_for_coordinator_tests(
        pid: u32,
        starttime: u64,
        namespaces: crate::inventory::NamespaceIds,
        pool: &crate::observation_memory::MemoryPool,
    ) -> Self {
        Self {
            gate: None,
            counter: None,
            session: None,
            _foreign: None,
            owned: None,
            pid,
            starttime,
            namespaces,
            scanner: crate::inventory::scope::ScopedScanner::new(
                crate::inventory::scope::Selection {
                    pids: vec![pid],
                    ..Default::default()
                },
                crate::inventory::Limits::default(),
            )
            .expect("pid-only scanner selection"),
            initial_metadata: None,
            pending: None,
            exec_pending: Vec::new(),
            refresh_pending: Vec::new(),
            last_clean_drain_ns: 0,
            exec_fence_pending: false,
            gaps: std::collections::BTreeSet::new(),
            attach_diagnostics: std::collections::BTreeSet::new(),
            engine: EnginePlane::new(),
            state_bytes: 0,
            inventory_gaps: 0,
            sample: crate::focused_count::CountSample::default(),
            next_snapshot: std::time::Instant::now(),
            ready: false,
            start_ns: 0,
            deadline_ns: 0,
            end: std::time::Instant::now(),
            wall_start: None,
            signal_cut: false,
            workload_discarded: false,
            sysctls: None,
            _reservation: pool.reserve(1024).expect("hollow lease"),
        }
    }
    /// fix6 F2: hollow shell around a REAL provider session for
    /// the coordinator receipt-discipline schedule test (R6-2):
    /// receipts/totals come from the real session maps and logic,
    /// everything else stays hollow. Test-only.
    #[cfg(test)]
    pub(crate) fn with_session_for_coordinator_tests(
        pid: u32,
        starttime: u64,
        namespaces: crate::inventory::NamespaceIds,
        pool: &crate::observation_memory::MemoryPool,
        session: crate::provider_observation::session::ProviderSession,
    ) -> Self {
        let mut hollow = Self::hollow_for_coordinator_tests(pid, starttime, namespaces, pool);
        hollow.session = Some(session);
        hollow
    }
    /// fix6 F2 test seam: drain the inner real session (clean,
    /// empty ring — consumes and accounts).
    #[cfg(test)]
    pub(crate) fn drain_for_test(&mut self) {
        if let Some(s) = self.session.as_mut() {
            let _ = s.drain(std::time::Instant::now() + std::time::Duration::from_secs(10));
        }
    }
    /// fix6 F2 test seam: peek the inner real session (the real
    /// reconcile-path peek over an empty batch).
    #[cfg(test)]
    pub(crate) fn peek_for_test(&mut self) -> crate::provider_observation::ObservationBatch {
        self.session
            .as_mut()
            .map(|s| s.peek_loss_lanes_for_test())
            .unwrap_or_default()
    }
    /// fix6 F2 test seam: inject a LOSS lane delta into the inner
    /// real session's loss map.
    #[cfg(test)]
    pub(crate) fn set_loss_lane_for_test(&mut self, lane: u32, value: u64) {
        if let Some(s) = self.session.as_mut() {
            s.set_loss_lane_for_test(lane, value);
        }
    }
    /// fix6 F2 test seam: anchor the inner real session's receipt
    /// tick clock at nominal `tick`.
    #[cfg(test)]
    pub(crate) fn set_loss_tick_for_test(&mut self, tick: u64, tick_ns: u64) {
        if let Some(s) = self.session.as_mut() {
            s.set_loss_tick_for_test(tick, tick_ns);
        }
    }
    /// Persistent host ceilings plus bounded scanner/pins/argv, source bytes,
    /// and map payload/entry overhead. Temporary ELF bytes and parser metadata
    /// are leased separately on the same pool before allocation.
    pub(crate) fn reservation_bytes(objects: &FocusedObjects) -> anyhow::Result<usize> {
        let cpus = aya::util::nr_cpus().map_err(|(_, e)| e)?;
        if cpus == 0 || cpus > CountLimits::default().max_cpus {
            bail!("focused CPU capacity exceeded");
        }
        if objects.observation.len() > 16 << 20 || objects.count.len() > 16 << 20 {
            bail!("focused companion capacity exceeded");
        }
        // 6A admitted-member ledger storage (§3.1, frozen): each
        // member ledger holds at most 64 lost windows in the compact
        // 24 B layout plus scalars (1576 B ≤ 2 KiB), charged to the
        // session lease as `LEDGER_BYTES = 2 KiB` per admitted
        // member.
        const LEDGER_BYTES: usize = 2 << 10;
        let mut bytes =
            (104usize << 20) + objects.observation.len() + objects.count.len() + LEDGER_BYTES;
        // Borrowed maps are charged once, by the session-side owner: when a
        // session companion exists the counter shares its producer/source
        // maps instead of creating them. Standalone counters (no session
        // companion) create private maps and are charged for them here.
        let shared = !objects.observation.is_empty();
        for spec in crate::loader::FOCUSED_COUNT_MAPS {
            // The counter borrows these from the session owner instead of
            // creating them; the session side charges them once.
            if shared && crate::loader::BORROWED_COUNT_MAPS.contains(&spec.name) {
                continue;
            }
            bytes = bytes
                .checked_add(
                    spec.reservation_bytes(cpus)
                        .context("focused map capacity overflow")?,
                )
                .context("focused map reservation overflow")?;
        }
        for spec in crate::provider_observation::session::specs() {
            bytes = bytes
                .checked_add(
                    spec.reservation_bytes(cpus)
                        .context("focused map capacity overflow")?,
                )
                .context("focused map reservation overflow")?;
        }
        Ok(bytes)
    }
    /// No signal handlers are installed here. expected is a coordinator's
    /// scanned incarnation and initial metadata, never attachment authority.
    pub(crate) fn open(
        config: FocusedConfig,
        target: capture::Target,
        objects: FocusedObjects,
        setup_deadline: Instant,
        cancel: &AtomicBool,
        expected: Option<&inventory::ProcessRecord>,
    ) -> anyhow::Result<Self> {
        let pool = crate::observation_memory::MemoryPool::new(256 << 20);
        let reservation = pool
            .reserve(Self::reservation_bytes(&objects)?)
            .context("focused memory admission refused")?;
        Self::open_reserved(
            config,
            target,
            objects,
            setup_deadline,
            cancel,
            expected,
            reservation,
        )
    }
    pub(crate) fn open_reserved(
        config: FocusedConfig,
        target: capture::Target,
        objects: FocusedObjects,
        setup_deadline: Instant,
        cancel: &AtomicBool,
        expected: Option<&inventory::ProcessRecord>,
        reservation: crate::observation_memory::MemoryLease,
    ) -> anyhow::Result<Self> {
        Self::open_reserved_window(
            config,
            target,
            objects,
            (setup_deadline, None),
            cancel,
            expected,
            reservation,
        )
    }
    pub(crate) fn open_scanned_reserved(
        config: FocusedConfig,
        objects: FocusedObjects,
        deadlines: (Instant, Instant),
        cancel: &AtomicBool,
        expected: &inventory::ProcessRecord,
        reservation: crate::observation_memory::MemoryLease,
    ) -> anyhow::Result<Self> {
        Self::open_reserved_window(
            config,
            capture::Target::Pid(expected.pid),
            objects,
            (deadlines.0, Some(deadlines.1)),
            cancel,
            Some(expected),
            reservation,
        )
    }
    fn open_reserved_window(
        config: FocusedConfig,
        target: capture::Target,
        objects: FocusedObjects,
        deadlines: (Instant, Option<Instant>),
        cancel: &AtomicBool,
        expected: Option<&inventory::ProcessRecord>,
        reservation: crate::observation_memory::MemoryLease,
    ) -> anyhow::Result<Self> {
        let (setup_deadline, observation_end) = deadlines;
        config.validate()?;
        if reservation.bytes() < Self::reservation_bytes(&objects)? {
            bail!("focused memory reservation too small");
        }
        let pool = reservation.pool();
        let mut budget = crate::provider_observation::ObservationBudget::new(ObservationLimits {
            max_processes: 1,
            max_links: 512,
            ..Default::default()
        });
        budget.memory = Some(pool.clone());
        budget.parsed_cache = config.parsed_cache.clone();
        budget.set_deadline(setup_deadline);
        if <[u8; 32]>::from(Sha256::digest(&objects.count)) != objects.count_sha256 {
            bail!("focused count object identity mismatch");
        }
        let setup_deadline = setup_deadline.min(
            Instant::now()
                .checked_add(config.timeout)
                .context("focused setup deadline overflow")?,
        );
        let workload_discarded = matches!(
            &target,
            capture::Target::Spawn {
                workload: crate::target::WorkloadDest::Null,
                ..
            }
        );
        let startup_argv = match &target {
            capture::Target::Spawn { argv, .. } => Some(argv.clone()),
            _ => None,
        };
        let mut owned = match target {
            capture::Target::Pid(pid) if pid > 0 && pid <= i32::MAX as u32 => (pid, None),
            capture::Target::Pid(_) => return Err(TargetUnavailable.into()),
            capture::Target::Spawn { argv, workload } => {
                let child = OwnedTarget::spawn_stopped_with_control(
                    &argv,
                    workload,
                    setup_deadline,
                    cancel,
                )?;
                (child.pid(), Some(child))
            }
        };
        let pid = owned.0;
        if cancel.load(Ordering::Relaxed) || Instant::now() >= setup_deadline {
            bail!("focused setup interrupted or expired");
        }
        // Readable target acquisition is independent of tracing availability.
        // Acquire only proc/maps identity before release. Inspecting inherited
        // observer mappings here can spend the setup budget on an unrelated ELF;
        // actual object inventory/reconciliation starts after release below.
        let (initial_record, initial_reads) = if let Some(expected) = expected {
            // The exports bound derives from the Api vocabulary (6A):
            // `exports` is deduplicated over variants, so our own
            // snapshots always fit; only forged metadata can exceed it.
            // Stale-bound history (disclosure): 16 entries
            // (pre-Oct-28) → 46 (Oct-28 312cf3f) → `Api::COUNT`
            // (70 current variants); the live count keeps the bound
            // exact as variants churn.
            if owned.1.is_some()
                || expected.pid != pid
                || expected.modules.len() > 256
                || expected.modules.iter().any(|m| {
                    m.info.sha256.len() != 64 || m.info.exports.len() > crate::inventory::Api::COUNT
                })
            {
                return Err(TargetUnavailable.into());
            }
            (expected.clone(), 0)
        } else {
            let snapshot = inventory::snapshot(&inventory::SnapshotOptions {
                pids: vec![pid],
                resolve_paths: false,
                limits: inventory::Limits {
                    max_pids: 1,
                    max_objects_per_process: 0,
                    max_objects: 256,
                    max_read_bytes: 256 << 20,
                    timeout: RESCAN.min(setup_deadline.saturating_duration_since(Instant::now())),
                    ..Default::default()
                },
            });
            (
                snapshot
                    .processes
                    .into_iter()
                    .find(|p| p.pid == pid)
                    .ok_or(TargetUnavailable)?,
                snapshot.totals.read_bytes,
            )
        };
        let starttime = initial_record.starttime;
        // Metadata is only a locator: fresh retained acquisition checks the exact
        // scanned incarnation before any BPF attachment, including supplied snapshots.
        let foreign = if owned.1.is_none() {
            Some(
                crate::provider_observation::objects::acquire_incarnation(&initial_record)
                    .map_err(|_| TargetUnavailable)?,
            )
        } else {
            None
        };
        let mut scanner = ScopedScanner::new(
            Selection {
                pids: vec![pid],
                ..Default::default()
            },
            inventory::Limits {
                max_pids: 1,
                max_objects_per_process: 256,
                max_objects: 256,
                max_read_bytes: (256u64 << 20).saturating_sub(initial_reads),
                timeout: RESCAN.min(setup_deadline.saturating_duration_since(Instant::now())),
                ..Default::default()
            },
        )
        .map_err(|_| TargetUnavailable)?;
        scanner.set_memory_pool(pool);
        // F8d restoration: the per-target rescan prefills the
        // same run-shared cache the session below parses from.
        if let Some(cache) = &budget.parsed_cache {
            scanner.set_parsed_cache(cache.clone());
        }
        let mut gaps = BTreeSet::new();
        let gate = if objects.observation.is_empty() && objects.count.is_empty() {
            None
        } else {
            match crate::writer_gate::WriterGate::create(&reservation.pool()) {
                Ok(gate) => Some(gate),
                Err(_) => {
                    gaps.insert(ObservationGap::BpfUnavailable);
                    None
                }
            }
        };
        let mut session = if objects.observation.is_empty() {
            gaps.insert(ObservationGap::CompanionsUnavailable);
            None
        } else if gate.is_none() {
            gaps.insert(ObservationGap::BpfUnavailable);
            None
        } else {
            match ProviderSession::open_gated(
                budget.clone(),
                &objects.observation,
                gate.as_ref().unwrap().clone(),
            ) {
                Ok(s) => Some(s),
                Err(gap) => {
                    gaps.insert(gap);
                    None
                }
            }
        };
        if cancel.load(Ordering::Relaxed) || Instant::now() >= setup_deadline {
            bail!("focused setup interrupted or expired");
        }
        let mut preexec = if let (Some(child), Some(argv)) = (&owned.1, &startup_argv) {
            if objects.count.is_empty() {
                None
            } else {
                match crate::startup_objects::prepare_owned_startup(
                    child,
                    argv,
                    &mut budget,
                    setup_deadline,
                    cancel,
                    None,
                ) {
                    Ok(sites) => Some(sites),
                    Err(gap) => {
                        gaps.insert(gap);
                        None
                    }
                }
            }
        } else {
            None
        };
        let start_ns = now_ns()?;
        let wall_start = unix_ns();
        // Foreign watch sessions share the coordinator's absolute end. Setup
        // consumes that window; later members cannot extend earlier BPF windows.
        let now = Instant::now();
        let end = now
            .checked_add(config.duration)
            .context("focused duration overflow")?;
        let end = observation_end.map_or(end, |limit| limit.min(end));
        let deadline_ns = start_ns
            .checked_add(u64::try_from(
                end.saturating_duration_since(now).as_nanos(),
            )?)
            .context("focused admission overflow")?;
        if let Some(gap) = session
            .as_mut()
            .and_then(|s| s.set_api_window(start_ns, deadline_ns).err())
        {
            gaps.insert(gap);
            // Never keep the unbounded standalone-session default on failure.
            session = None;
        }
        // Typed startup runs before the counter opens so the counter can
        // borrow the session's producer/source maps (one relationship pool
        // across both programs) instead of creating private ones.
        if let Some(session) = &mut session {
            if let Some(preexec) = &mut preexec {
                for result in crate::startup_objects::acquire_startup(|stage| match stage {
                    crate::startup_objects::StartupAcquisition::Legacy => session.prearm_startup(
                        std::mem::take(&mut preexec.apis),
                        setup_deadline,
                        cancel,
                        crate::provider_observation::session::PrearmLinks::Create,
                    ),
                    crate::startup_objects::StartupAcquisition::TypedSources => session
                        .prepare_typed_startup(
                            std::mem::take(&mut preexec.typed),
                            setup_deadline,
                            cancel,
                            &crate::provider_observation::SourceAcquisitionLease::Disabled,
                        ),
                }) {
                    if let Err(gap) = result {
                        gaps.insert(gap);
                    }
                }
                // The native source lease stays disabled in production: both
                // calls below are inert under a Disabled lease (immediate Ok,
                // zero effects) and exist so the lease-gated acquisition path
                // has production reachability for the native qualification.
                let disabled = crate::provider_observation::SourceAcquisitionLease::Disabled;
                if let Err(gap) =
                    session.acquire_source_after_open(&disabled, setup_deadline, cancel)
                {
                    gaps.insert(gap);
                }
                if let Err(gap) = session.note_source_exec(&disabled, 0, 0) {
                    gaps.insert(gap);
                }
            }
        }
        if cancel.load(Ordering::Relaxed) || Instant::now() >= setup_deadline {
            bail!("focused setup interrupted or expired");
        }
        let mut counter = if objects.count.is_empty() {
            gaps.insert(ObservationGap::CompanionsUnavailable);
            None
        } else if gate.is_none() {
            gaps.insert(ObservationGap::BpfUnavailable);
            None
        } else {
            match observer_namespace() {
                Ok(namespace) => {
                    let limits = CountLimits {
                        window: CountAdmissionWindow {
                            start_ns,
                            deadline_ns,
                        },
                        max_state_bytes: 24 << 20,
                        ..Default::default()
                    };
                    let gate = gate.as_ref().unwrap().clone();
                    // Shared maps when the session lends them; private
                    // (inert producer) for standalone counters.
                    let borrowed = session.as_ref().and_then(|s| s.borrowed_producer_maps());
                    let opened = match borrowed {
                        Some(ref maps) => FocusedCounter::open_gated_shared(
                            &objects.count,
                            pid,
                            namespace,
                            limits,
                            gate,
                            maps,
                        ),
                        None => {
                            FocusedCounter::open_gated(&objects.count, pid, namespace, limits, gate)
                        }
                    };
                    match opened {
                        Ok(c) => Some(c),
                        Err(_) => {
                            gaps.insert(ObservationGap::BpfUnavailable);
                            None
                        }
                    }
                }
                Err(_) => {
                    gaps.insert(ObservationGap::NamespaceChanged);
                    None
                }
            }
        };
        if cancel.load(Ordering::Relaxed) || Instant::now() >= setup_deadline {
            bail!("focused setup interrupted or expired");
        }
        if let (Some(preexec), Some(counter)) = (preexec, &mut counter) {
            gaps.extend(preexec.gaps);
            if counter
                .attach_candidates_controlled(
                    preexec
                        .candidates
                        .into_iter()
                        .map(CountCandidate::Static)
                        .collect(),
                    now_ns()?,
                    setup_deadline,
                    cancel,
                )
                .is_err()
            {
                gaps.insert(ObservationGap::AttachFailed);
            }
        }
        if cancel.load(Ordering::Relaxed) || Instant::now() >= setup_deadline {
            bail!("focused setup interrupted or expired");
        }
        if let Some(gate) = &gate {
            gate.open()?;
        }
        if let Some(child) = &mut owned.1 {
            child.release_retaining_exit()?;
        }
        Ok(Self {
            gate,
            counter,
            session,
            _foreign: foreign,
            owned: owned.1,
            pid,
            starttime,
            namespaces: initial_record.namespaces.clone(),
            scanner,
            initial_metadata: expected.map(|_| initial_record),
            pending: None,
            exec_pending: Vec::new(),
            refresh_pending: Vec::new(),
            last_clean_drain_ns: start_ns,
            exec_fence_pending: false,
            gaps,
            attach_diagnostics: BTreeSet::new(),
            engine: EnginePlane::new(),
            state_bytes: 0,
            inventory_gaps: 0,
            sample: CountSample::default(),
            next_snapshot: Instant::now()
                + if startup_argv.is_some() {
                    POLL
                } else {
                    Duration::ZERO
                },
            ready: false,
            start_ns,
            deadline_ns,
            end,
            wall_start,
            signal_cut: false,
            workload_discarded,
            sysctls: Some(crate::evidence::sample_sysctls_from(std::path::Path::new(
                "/proc/sys",
            ))),
            _reservation: reservation,
        })
    }
    /// Admission warm-tier signal: true once this member attached
    /// callbacks — its parses completed into the run-shared cache,
    /// so later members most likely clone instead of needing a
    /// working transient of their own.
    pub(crate) fn has_attached(&self) -> bool {
        self.ready
    }
    #[cfg(test)]
    pub(crate) fn set_attached_for_test(&mut self) {
        self.ready = true;
    }
    fn apply_batch(
        &mut self,
        batch: ObservationBatch,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> anyhow::Result<()> {
        self.gaps.extend(batch.gaps.iter().copied());
        // Batch refusals merge alongside the gaps (fresh and re-driven
        // pending batches share this funnel); the set dedupes replays.
        self.attach_diagnostics
            .extend(batch.refusals.iter().cloned());
        if let (Some(session), Some(counter)) = (&self.session, &mut self.counter) {
            match process_batch(
                session,
                counter,
                &batch,
                self.pid,
                (self.deadline_ns, deadline, cancel),
                &mut self.gaps,
                &mut self.state_bytes,
            )? {
                BatchProgress::Deferred => {
                    // Candidate/file/custody storage is already charged to the
                    // shared provider budget. Keep at most one batch; attach
                    // revalidates every retained file/mapping on the next tick.
                    self.pending = Some(batch);
                }
                BatchProgress::Applied(attached) => {
                    if attached && !self.ready {
                        eprintln!(
                            "osslscope: focused callbacks attached (pid={}, sites={})",
                            self.pid,
                            counter.active_site_count()
                        );
                        self.ready = true;
                    }
                }
            }
        }
        Ok(())
    }
    /// One bounded work pass, no sleeping. The caller owns cadence and signals.
    pub(crate) fn poll(
        &mut self,
        now: Instant,
        cancel: &AtomicBool,
    ) -> anyhow::Result<SessionProgress> {
        self.poll_inner(now, now + RESCAN, cancel, None)
    }
    /// Coordinator-owned discovery. None records means drain only; an empty
    /// supplied slice means visibility loss. Never fall back to numeric PID scans.
    pub(crate) fn poll_scanned(
        &mut self,
        now: Instant,
        deadline: Instant,
        cancel: &AtomicBool,
        records: Option<&[inventory::ProcessRecord]>,
        inventory_partial: bool,
    ) -> anyhow::Result<SessionProgress> {
        if inventory_partial {
            self.inventory_gaps = self.inventory_gaps.saturating_add(1);
        }
        self.initial_metadata = None;
        self.poll_inner(now, deadline, cancel, Some(records))
    }
    /// ENGINE tripwire plane: plan once from the first snapshot
    /// showing admitted libcrypto, then verify the binding each
    /// snapshot (a replacement blinds with an explicit gap).
    fn plan_engine_probes(
        &mut self,
        records: &[inventory::ProcessRecord],
        tick_end: Instant,
        cancel: &AtomicBool,
    ) {
        if matches!(
            self.engine.state,
            EnginePlaneState::Blind | EnginePlaneState::Unsupported
        ) {
            return;
        }
        let Some(record) = records.iter().find(|p| {
            p.pid == self.pid && p.starttime == self.starttime && p.namespaces == self.namespaces
        }) else {
            return;
        };
        let Ok(maps) = maps::read_maps(self.pid) else {
            return;
        };
        if legacy::find_libcrypto(&maps).is_some() {
            self.engine.ever_mapped = true;
        }
        // Owned binding copy: the Planned arm below reassigns
        // the state, so it cannot borrow the match scrutinee.
        let planned_binding = match &self.engine.state {
            EnginePlaneState::Planned {
                device,
                inode,
                libcrypto,
            } => Some((*device, *inode, libcrypto.clone())),
            _ => None,
        };
        if let Some((device, inode, libcrypto)) = planned_binding {
            // Dead-link check first: any counter retire
            // (provider mapping transitions, sample-time
            // namespace loss, custody failure) destroys the
            // ENGINE links, so a moved epoch blinds rather
            // than joining silence as evidence.
            let retired = match self.counter.as_ref() {
                Some(counter) => counter.engine_epoch() != self.engine.counter_epoch,
                None => true,
            };
            if retired {
                // Post-retire pins are gone with the links: pending
                // is unverifiable (ambiguous), so drop it — a pure
                // provider transition over-withholds clean news, the
                // honest price of an unknowable cause.
                self.engine.pending.clear();
                self.engine.state = EnginePlaneState::Blind;
                self.gaps.insert(ObservationGap::Invalidated);
                return;
            }
            // Live pin custody: revalidate before trusting
            // another snapshot's joins. A caller DSO changed
            // mid-window retires the counter inside and blinds
            // here — the engine-only path has no provider
            // batches to trigger retention otherwise.
            let pin_failed = match self.counter.as_mut() {
                Some(counter) => counter.retain_authority(false).is_err(),
                None => true,
            };
            if pin_failed {
                self.engine.pending.clear();
                self.engine.state = EnginePlaneState::Blind;
                self.gaps.insert(ObservationGap::Invalidated);
                return;
            }
            // Certified clean: no change in (attach, now] proves
            // every pending increment counted the planned bytes —
            // join them. Later blinds in this arm (binding, caller
            // overflow) lose nothing already certified.
            let pending: Vec<(u64, u64)> = std::mem::take(&mut self.engine.pending)
                .into_iter()
                .collect();
            if !pending.is_empty() {
                self.engine
                    .collector
                    .accumulate(self.engine.generation, &pending, &[]);
            }
            // Binding check: a DIFFERENT admitted identity
            // blinds; None is a transient race (keep, retry).
            if let Some(lib) = select_engine_libcrypto(&maps, &record.modules) {
                if lib.device != device || lib.inode != inode {
                    self.engine.state = EnginePlaneState::Blind;
                    self.gaps.insert(ObservationGap::ObjectChanged);
                    return;
                }
            }
            // Caller-set watch: late mappings and replacements
            // gap as skipped (imports unknown, never rescanned
            // under the single-plan policy) while the plane
            // keeps joining its bound evidence. A full baseline
            // blinds: untrackable churn must not pass silently.
            let current: Vec<(String, Option<(u64, u64)>)> =
                legacy::target_modules(&maps, libcrypto.as_str())
                    .iter()
                    .map(|path| {
                        let identity = std::fs::metadata(path).ok().map(|m| (m.dev(), m.ino()));
                        (path.clone(), identity)
                    })
                    .collect();
            let (news, overflow) =
                diff_caller_set(&mut self.engine.callers, &current, MAX_ENGINE_CALLER_WATCH);
            self.engine.skipped_modules = self.engine.skipped_modules.saturating_add(news);
            if overflow {
                self.engine.state = EnginePlaneState::Blind;
                self.gaps.insert(ObservationGap::ObjectLimit);
            }
        } else if matches!(self.engine.state, EnginePlaneState::Unplanned) {
            let Some(lib) = select_engine_libcrypto(&maps, &record.modules) else {
                return;
            };
            self.attach_engine_plane(&maps, &lib, tick_end, cancel);
        }
        // Blind/Unsupported returned at the top: terminal, no-op.
    }
    /// Plan, attach and bind one ENGINE ProbeSet. Terminal states
    /// (Unsupported/Blind) and gaps keep every outcome explicit;
    /// transient races return Unplanned for the next snapshot.
    fn attach_engine_plane(
        &mut self,
        maps: &[maps::Mapping],
        lib: &AdmittedLibcrypto,
        tick_end: Instant,
        cancel: &AtomicBool,
    ) {
        // Identity-bound libcrypto bytes (swap-during-read retries;
        // unreadable-now retries on NotFound, blinds otherwise).
        let lc = match crate::plan::read_file_bound(&lib.path) {
            Ok(fb) if fb.dev == lib.device && fb.ino == lib.inode => fb,
            Ok(_) => return,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => {
                self.engine.state = EnginePlaneState::Blind;
                self.gaps.insert(ObservationGap::ClassifierFailed);
                return;
            }
        };
        // Caller modules: maps-consistent identity only, bounded
        // count+bytes; anything else stays unplanned behind a gap.
        let mut mod_bufs: Vec<ScannedCallerModule> = Vec::new();
        let mut skipped = 0u64;
        let mut bytes_total = lc.bytes.len();
        // Caller admission is maps-consistency only (no record
        // membership: the inventory record is scoped to
        // provider-relevant modules, while any mapped caller may
        // import ENGINE_* — the attach-time fstat check closes the
        // plan→attach race instead). Scan order is maps order;
        // prioritizing record-known libcrypto consumers is future
        // work if the module cap ever binds on a real target.
        let candidates = legacy::target_modules(maps, &lib.path);
        // Caller-set baseline for the late-mapping watch: fresh
        // stat identity per candidate (None if unstatable).
        // Candidates past the watch cap stay skipped-but-unwatched
        // (the scan loop below already gaps everything past the
        // far smaller scan cap — no double count here).
        self.engine.callers = candidates
            .iter()
            .take(MAX_ENGINE_CALLER_WATCH)
            .map(|path| {
                let identity = std::fs::metadata(path).ok().map(|m| (m.dev(), m.ino()));
                (path.clone(), identity)
            })
            .collect();
        for (index, path) in candidates.iter().enumerate() {
            if mod_bufs.len() >= MAX_ENGINE_PLAN_MODULES {
                skipped += 1;
                continue;
            }
            let maps_ino = maps
                .iter()
                .find(|m| &m.path == path)
                .map(|m| m.ino)
                .unwrap_or(0);
            let fresh = match std::fs::metadata(path) {
                Ok(m) => m,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };
            if fresh.ino() != maps_ino {
                skipped += 1;
                continue;
            }
            let fb = match crate::plan::read_file_bound(path) {
                Ok(fb) if fb.dev == evidence_device(fresh.dev()) && fb.ino == fresh.ino() => fb,
                _ => {
                    skipped += 1;
                    continue;
                }
            };
            bytes_total = bytes_total.saturating_add(fb.bytes.len());
            if bytes_total > MAX_ENGINE_PLAN_BYTES {
                // Count this module plus every unscanned remainder.
                skipped = skipped.saturating_add((candidates.len() - index) as u64);
                break;
            }
            mod_bufs.push(ScannedCallerModule {
                path: path.clone(),
                bytes: fb.bytes.to_vec(),
                device: evidence_device(fresh.dev()),
                inode: fresh.ino(),
                sha256: Sha256::digest(&fb.bytes).into(),
            });
        }
        self.engine.skipped_modules = self.engine.skipped_modules.saturating_add(skipped);
        let modules: Vec<legacy::Module<'_>> = mod_bufs
            .iter()
            .map(|m| legacy::Module {
                path: &m.path,
                bytes: &m.bytes,
            })
            .collect();
        let set = match legacy::probes_for(
            &lib.path,
            &lc.bytes,
            &modules,
            (crate::plan::render_device(lc.dev), lc.ino),
        ) {
            Ok(set) => set,
            Err(_) => {
                self.engine.state = EnginePlaneState::Blind;
                self.gaps.insert(ObservationGap::ClassifierFailed);
                return;
            }
        };
        self.engine.addrtaken = self
            .engine
            .addrtaken
            .saturating_add(set.address_taken.len() as u64);
        self.engine.uninstrumented = self
            .engine
            .uninstrumented
            .saturating_add(set.engine_uninstrumented);
        // Unscannable callers carry zero probes and zero gap
        // symbols: their imports are unknown, exactly like a
        // skipped module.
        self.engine.skipped_modules = self
            .engine
            .skipped_modules
            .saturating_add(set.unscannable_modules);
        if engine_interface_absent(&set) {
            // Absent interface (4.x style): explicit terminal fact.
            self.engine.state = EnginePlaneState::Unsupported;
            return;
        }
        // Attachable surface: ENGINE-indexed symbols only (meth,
        // low-level and load probes never join engine_observations,
        // so attaching them would spend links and COUNTS keys for
        // joinable-nothing). by_id counts at symbol level here —
        // engine-id strings stay a harvest-only taxonomy.
        let wanted: Vec<usize> = set
            .probes
            .iter()
            .enumerate()
            .filter(|(_, p)| engine_index(&p.symbol).is_some())
            .map(|(i, _)| i)
            .collect();
        // Collapse hardlinked-path aliases to one probe per
        // physical (device, inode, offset) stub: the counter
        // attaches each stub once, and the join below must not
        // emit the same minted cookie from two ProbeSet rows.
        let identities: BTreeMap<String, (u64, u64)> = mod_bufs
            .iter()
            .map(|m| (m.path.clone(), (m.device, m.inode)))
            .collect();
        let wanted = dedupe_wanted_probes(&wanted, &set.probes, &identities);
        let mut plans = Vec::with_capacity(wanted.len());
        for &i in &wanted {
            let probe = &set.probes[i];
            let Some(found) = mod_bufs.iter().find(|m| m.path == probe.module) else {
                // Probe for a module we never read: cannot join it
                // safely — blind rather than misattribute.
                self.engine.state = EnginePlaneState::Blind;
                self.gaps.insert(ObservationGap::ClassifierFailed);
                return;
            };
            self.engine.modules.insert(
                probe.module.clone(),
                (found.device, found.inode, String::new()),
            );
            plans.push(EngineProbePlan {
                path: probe.module.clone(),
                offset: probe.offset,
                device: found.device,
                inode: found.inode,
                sha256: found.sha256,
            });
        }
        let attach = match self.counter.as_mut() {
            Some(counter) => {
                counter.attach_engine_probes(&plans, self.pid, self.starttime, tick_end, cancel)
            }
            None => return,
        };
        let cookies = match attach {
            Ok(cookies) => cookies,
            Err(e) => match map_engine_attach_failure(e) {
                Some(gap) => {
                    self.engine.state = EnginePlaneState::Blind;
                    self.gaps.insert(gap);
                    return;
                }
                None => return,
            },
        };
        if cookies.len() != plans.len() {
            // Unjoinable alignment: blind rather than misattribute.
            self.engine.state = EnginePlaneState::Blind;
            self.gaps.insert(ObservationGap::ClassifierFailed);
            return;
        }
        // Snapshoted meanings: attached probes only, remapped to
        // their minted cookies under the actual count program.
        let mut attached = legacy::ProbeSet {
            libcrypto: set.libcrypto.clone(),
            ..Default::default()
        };
        for (&i, &cookie) in wanted.iter().zip(cookies.iter()) {
            let mut probe = set.probes[i].clone();
            probe.cookie = u64::from(cookie);
            probe.program = "count_entry";
            attached.probes.push(probe);
        }
        let mut pins: Vec<crate::discovery::session::TripModulePin> = Vec::new();
        let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
        for plan in &plans {
            if seen.insert((plan.path.clone(), "count_entry".into())) {
                pins.push(crate::discovery::session::TripModulePin {
                    module: plan.path.clone(),
                    program: "count_entry".into(),
                    dev: crate::plan::render_device(plan.device),
                    ino: plan.inode,
                });
            }
        }
        // Build-ids for the final object join, computed now so the
        // (large) module bytes drop with this snapshot.
        for m in &mod_bufs {
            if let Some(entry) = self.engine.modules.get_mut(&m.path) {
                entry.2 = elf::read_build_id(&m.bytes).unwrap_or_default();
            }
        }
        self.engine.generation += 1;
        let generation = self.engine.generation;
        self.engine
            .collector
            .snapshot_binding(generation, Some(attached), &pins);
        self.engine.counter_epoch = self
            .counter
            .as_ref()
            .map(|c| c.engine_epoch())
            .unwrap_or(u64::MAX);
        self.engine.state = EnginePlaneState::Planned {
            device: lib.device,
            inode: lib.inode,
            libcrypto: lib.path.clone(),
        };
    }
    fn poll_inner(
        &mut self,
        now: Instant,
        deadline: Instant,
        cancel: &AtomicBool,
        scanned: Option<Option<&[inventory::ProcessRecord]>>,
    ) -> anyhow::Result<SessionProgress> {
        self.signal_cut |= cancel.load(Ordering::Relaxed);
        if self.signal_cut || now >= self.end || Instant::now() >= self.end {
            self.pending = None;
            return Ok(SessionProgress::StopRequested);
        }
        // Peek before any maps read: an exited short command keeps its valid
        // prearmed historical counts without a post-exit mapping prerequisite.
        if let Some(child) = &self.owned {
            if child.peek_exit()?.is_some() {
                self.pending = None;
                return Ok(SessionProgress::Exited);
            }
        }
        let tick_end = (now + RESCAN).min(self.end).min(deadline);
        if let Some(session) = &self.session {
            session.set_deadline(tick_end);
        }
        if let Some(batch) = self.pending.take() {
            self.apply_batch(batch, tick_end, cancel)?;
            if self.pending.is_some() {
                return Ok(SessionProgress::Running);
            }
        }
        if scanned.is_some_and(|r| r.is_some()) || (scanned.is_none() && now >= self.next_snapshot)
        {
            let owned_records;
            let records = if let Some(Some(records)) = scanned {
                records
            } else {
                owned_records = if let Some(record) = self.initial_metadata.take() {
                    vec![record]
                } else {
                    let snapshot = self
                        .scanner
                        .snapshot_for(tick_end.saturating_duration_since(Instant::now()));
                    if !snapshot.gaps.is_empty() {
                        self.inventory_gaps = self.inventory_gaps.saturating_add(1);
                    }
                    snapshot.processes
                };
                &owned_records
            };
            if !records.iter().any(|p| {
                p.pid == self.pid
                    && p.starttime == self.starttime
                    && p.namespaces == self.namespaces
            }) {
                self.gaps.insert(ObservationGap::ProcessChanged);
                if let Some(c) = &mut self.counter {
                    c.retire();
                }
                self.pending = None;
                return Ok(SessionProgress::Unverifiable);
            }
            if cancel.load(Ordering::Relaxed) || Instant::now() >= tick_end {
                self.signal_cut |= cancel.load(Ordering::Relaxed);
                self.gaps.insert(ObservationGap::SnapshotLag);
                return Ok(if self.signal_cut {
                    SessionProgress::StopRequested
                } else {
                    SessionProgress::Running
                });
            }
            if let Some(s) = &mut self.session {
                let batch = s.reconcile_records(records);
                // R7-1: read the live deferred-exec hold with the
                // fresh batch (the session borrow ends here).
                let held = s.exec_fence_held();
                // 6A: fresh-reconcile signals only (pending
                // re-drives must not duplicate them).
                self.note_batch_exec_signals(&batch, held);
                if batch.additive_refreshes.contains(&self.pid) {
                    if let Ok(ns) = now_ns() {
                        self.refresh_pending.push(ns);
                    }
                }
                self.apply_batch(batch, tick_end, cancel)?;
            }
            self.plan_engine_probes(records, tick_end, cancel);
            self.next_snapshot = Instant::now() + RESCAN;
            if self.pending.is_some() {
                return Ok(SessionProgress::Running);
            }
        }
        self.signal_cut |= cancel.load(Ordering::Relaxed);
        if self.signal_cut {
            self.pending = None;
            return Ok(SessionProgress::StopRequested);
        }
        if Instant::now() >= tick_end {
            self.gaps.insert(ObservationGap::SnapshotLag);
            return Ok(SessionProgress::Running);
        }
        if let Some(s) = &mut self.session {
            let batch = s.drain((Instant::now() + DRAIN).min(tick_end));
            // R7-1: read the live deferred-exec hold with the
            // fresh batch (the session borrow ends here).
            let held = s.exec_fence_held();
            // 6A: drain batches carry the same fresh signals as
            // reconcile batches (the drain wins the race for maps
            // changes); collect them identically or drain-detected
            // execs and refreshes are silently dropped.
            if batch.additive_refreshes.contains(&self.pid) {
                if let Ok(ns) = now_ns() {
                    self.refresh_pending.push(ns);
                }
            }
            self.apply_drain_batch(batch, held, tick_end, cancel)?;
        }
        self.signal_cut |= cancel.load(Ordering::Relaxed);
        if self.signal_cut {
            self.pending = None;
            return Ok(SessionProgress::StopRequested);
        }
        if let Some(c) = &mut self.counter {
            self.sample = c.sample((Instant::now() + DRAIN).min(tick_end));
            if self.sample.namespace_failures > 0 {
                c.retire();
                self.gaps.insert(ObservationGap::NamespaceChanged);
            }
        }
        // ENGINE news from this sample into plane pending. The
        // join waits for the next clean snapshot validation (or
        // the finish cut): drains between validations are
        // unvalidated, and a change found later must withhold
        // them rather than join stale-symbol counts.
        if matches!(self.engine.state, EnginePlaneState::Planned { .. }) {
            let news = engine_news(&mut self.engine.prev, &self.sample.engine);
            for (cookie, n) in news {
                self.engine
                    .pending
                    .entry(cookie)
                    .and_modify(|total| *total = total.saturating_add(n))
                    .or_insert(n);
            }
        }
        Ok(SessionProgress::Running)
    }
    /// Test-only ENGINE-plane binding probe (native controls gate
    /// paced stimulus on the bound plane: zero pre-window loss).
    #[cfg(test)]
    pub(crate) fn engine_planned_for_test(&self) -> bool {
        matches!(self.engine.state, EnginePlaneState::Planned { .. })
    }
    /// Test-only ENGINE-plane blind probe (retire-invalidation
    /// natives assert the loud blind, never silent death).
    #[cfg(test)]
    pub(crate) fn engine_blind_for_test(&self) -> bool {
        matches!(self.engine.state, EnginePlaneState::Blind)
    }
    /// Test-only session gap probe (retire-invalidation natives
    /// assert the explicit coverage gap reached the session).
    #[cfg(test)]
    pub(crate) fn session_gaps_for_test(&self) -> Vec<ObservationGap> {
        self.gaps.iter().copied().collect()
    }
    /// Test-only skipped-caller probe (caller-watch natives
    /// assert late mappings gap without blinding the plane).
    #[cfg(test)]
    pub(crate) fn engine_skipped_modules_for_test(&self) -> u64 {
        self.engine.skipped_modules
    }
    /// Fence active counting before another member's final output can block.
    pub(crate) fn stop_admission(&mut self, cancel: &AtomicBool) {
        self.signal_cut |= cancel.load(Ordering::Relaxed);
        self.pending = None;
        if let Some(gate) = &self.gate {
            if gate.close().is_err() {
                self.gaps.insert(ObservationGap::BpfUnavailable);
            }
        }
    }
    fn typed_admitted(&self) -> bool {
        self.session
            .as_ref()
            .is_some_and(|s| !s.typed_site_records().is_empty())
    }
    /// One-shot closed attribution over the finished sample. Assembles the
    /// borrowed maps, admitted-site view and windows, charges the session
    /// budget for the bounded host buffers, and runs the certifying
    /// collect+fold. Returns `None` without effect when no typed sites
    /// were admitted, or when any refusal voids the cut.
    fn collect_attribution(
        &mut self,
        counter_cpus: Option<usize>,
        report: CaptureWindow,
        admission: CountAdmissionWindow,
    ) -> Option<crate::attribution::FinalizedAttribution> {
        let gate = self.gate.as_ref()?;
        let cpus = counter_cpus?;
        // Clone the small site records up front so the budget charge
        // below can borrow the session mutably.
        let records: Vec<(u64, crate::provider_observation::session::TypedSiteRecord)> = {
            let session = self.session.as_ref()?;
            session
                .typed_site_records()
                .iter()
                .map(|(cookie, record)| (*cookie, record.clone()))
                .collect()
        };
        if records.is_empty() {
            return None;
        }
        let session = self.session.as_mut()?;
        // Worst-case host buffers: full key iterations plus per-CPU
        // values, all under kernel-enforced caps. Charged before any
        // borrow so a blown budget refuses before any kernel read.
        let bound = 8192usize
            .checked_mul(104 + 24 * cpus)?
            .checked_add(1024 * (16 + 64))?
            .checked_add(1024 * (24 + 56))?
            .checked_add(8 * 8 * cpus)?
            .checked_add(64)?;
        session.charge_attribution_final(bound).ok()?;
        let maps = session.attribution_maps()?;
        let mut admitted = Vec::with_capacity(records.len());
        for (cookie, record) in &records {
            admitted.push(crate::attribution::AdmittedTypedSite {
                cookie: *cookie,
                site_id: std::num::NonZeroU64::new(record.site_id)?,
                role_id: record.role_id,
                object: record.object.clone(),
                device: record.device,
                inode: record.inode,
                offset: record.offset,
                object_id: record.object_id,
                source_epoch: record.source_epoch,
            });
        }
        let closed_gate = gate.owned_closed().ok()?;
        crate::attribution::collect_closed_attribution(
            closed_gate,
            gate,
            &maps,
            cpus,
            &self.sample,
            &admitted,
            admission,
            report,
        )
        .ok()
    }
    /// 6A session-detected exec witnesses (exe-stamp flips) since
    /// the last take. The coordinator drains this per tick and
    /// seals the image epoch (§1.4).
    pub(crate) fn take_exec_witnesses(&mut self) -> Vec<u32> {
        std::mem::take(&mut self.exec_pending)
    }
    /// 6A additive-refresh instants (producer ns) since the last
    /// take. The coordinator drains this per tick, stamps record
    /// ticks, and emits the `additive_module_refresh` detail (§1.2).
    pub(crate) fn take_module_refreshes(&mut self) -> Vec<u64> {
        std::mem::take(&mut self.refresh_pending)
    }
    /// 6A cumulative per-index LOSS deltas (session scope,
    /// unlocalized — the coordinator folds these into
    /// `SessionLoss.ring`).
    /// 6B snapshot access: the live counter (map reads + fold
    /// views) without consuming anything.
    pub(crate) fn counter(&self) -> Option<&crate::focused_count::FocusedCounter> {
        self.counter.as_ref()
    }

    pub(crate) fn session_loss_totals(&self) -> [u64; 8] {
        self.session
            .as_ref()
            .map(|s| s.loss_totals())
            .unwrap_or([0; 8])
    }
    /// R7-3: live provider-session links (the deferral's future
    /// clients — counter/ENGINE links close on their own paths
    /// and never enter the deferred set). The coordinator sums
    /// this across members for the per-tick cleanup allowance.
    pub(crate) fn provider_live_links(&self) -> usize {
        self.session.as_ref().map(|s| s.link_count()).unwrap_or(0)
    }
    /// 6A successful-read receipts (§4.1 `[S,T+1)` rule): per-lane
    /// (LOSS read sequence, certified tick), `None` when no
    /// provider session contributes (nothing to prove). The
    /// coordinator advances a lane's baseline tick only to the
    /// oldest certified tick across live sessions, retaining the
    /// last successful baseline through failures. fix6 (R6-2):
    /// the certified tick is the last ACCOUNTED read's tick
    /// (peeks certify accounted coverage, never their own read
    /// tick — receipts advance cadence without certifying
    /// unaccounted reads).
    pub(crate) fn session_loss_read_receipts(&self) -> Option<[(u64, u64); 8]> {
        self.session.as_ref().map(|s| s.loss_read_receipts())
    }
    /// N4: install the coordinator's tick clock for receipt
    /// stamping (called once at admission; no-op without a
    /// provider session — nothing to stamp).
    pub(crate) fn set_loss_tick_clock(&mut self, origin_ns: u64, tick_ns: u64) {
        if let Some(s) = self.session.as_mut() {
            s.set_loss_tick_clock(origin_ns, tick_ns);
        }
    }
    /// R7-1 fresh-batch exec fence bridge (called for every
    /// FRESH reconcile/drain batch — pending re-drives must not
    /// duplicate signals, as before). A batch that DETECTS an
    /// exec — a completion witness OR a deferred-detection
    /// signal — fences BEFORE it is applied, using the PRECEDING
    /// clean instant. Witnesses collect into `exec_pending` for
    /// the coordinator seal; detections never seal (the witness
    /// still rides retry completion). `held` is the session's
    /// live `exec_fence_held`, latched here: while latched, the
    /// batch counts as detecting even when witness-free, so the
    /// drain must not advance the clean instant past a deferred
    /// exec. Returns true when this batch is detecting.
    fn note_batch_exec_signals(&mut self, batch: &ObservationBatch, held: bool) -> bool {
        let signaled = !batch.exec_witnesses.is_empty() || !batch.exec_deferred.is_empty();
        let detecting = signaled || self.exec_fence_pending;
        for pid in batch.exec_witnesses.iter().copied() {
            if !self.exec_pending.contains(&pid) {
                self.exec_pending.push(pid);
            }
        }
        if signaled {
            self.note_kernel_edge(None);
        }
        self.exec_fence_pending = held;
        detecting
    }
    /// R7-1 drain-batch funnel: exec-fence bridge, then apply,
    /// then the clean-instant advance (a detecting drain — fresh
    /// signal or latched hold — leaves `last_clean_drain_ns` at
    /// the previous clean drain; only a clean unheld drain
    /// advances it).
    fn apply_drain_batch(
        &mut self,
        batch: ObservationBatch,
        held: bool,
        tick_end: Instant,
        cancel: &AtomicBool,
    ) -> anyhow::Result<()> {
        let detecting = self.note_batch_exec_signals(&batch, held);
        self.apply_batch(batch, tick_end, cancel)?;
        if !detecting {
            if let Ok(ns) = now_ns() {
                self.last_clean_drain_ns = ns;
            }
        }
        Ok(())
    }
    /// 6A kernel-edge fence (§1.8): fence the counter (generation
    /// guard + withholding) and the provider session (BPF rows +
    /// post-edge record filter) at `edge_ns`. `None` resolves to
    /// the previous CLEAN drain's read instant — an exec-detecting
    /// drain never advances it (conservative: the edge may be as
    /// old as the last clean drain). One-way; earliest edge wins
    /// at both layers.
    pub(crate) fn note_kernel_edge(&mut self, edge_ns: Option<u64>) {
        let edge = edge_ns.unwrap_or(self.last_clean_drain_ns);
        if let Some(c) = &mut self.counter {
            c.note_fence_edge(edge);
        }
        if let Some(s) = &mut self.session {
            s.fence_target(self.pid, edge);
        }
    }
    /// 6A thread-exit row cleanup (§1.2): drop a confirmed-dead
    /// tid's pairing rows; the TGID member and its counts survive.
    /// No-op without a provider session (nothing to clean). N10:
    /// cleanup failures record a `BpfUnavailable` gap on the
    /// segment document — a stale THREADS row can be adopted by a
    /// recycled tid, so possible leftovers are uncertainty, never
    /// silent.
    pub(crate) fn remove_thread_rows(&mut self, tid: u32) {
        if let Some(s) = &mut self.session {
            if s.remove_thread_rows(self.pid, tid) > 0 {
                self.gaps.insert(ObservationGap::BpfUnavailable);
            }
        }
    }
    /// 6A suspension for retained-unknown members (§2.4): retire
    /// the counter (BPF stops; rows fence into history) and evict
    /// the provider target into the gap-free refresh handoff. The
    /// next reconcile re-adds via the retained incarnation. The
    /// coordinator records the unknown window in the loss ledger.
    pub(crate) fn suspend_retained(&mut self) {
        if let Some(c) = &mut self.counter {
            c.retire();
        }
        if let Some(s) = &mut self.session {
            s.suspend_target(self.pid);
        }
    }
    /// 6A suspension under membership uncertainty (§§1.6, 2.4):
    /// fence at the uncertainty edge FIRST (inter-tick aggregates
    /// withhold whole into conserved loss — an unknown-window
    /// annotation alone never satisfies the attribution
    /// prohibition), then suspend as above. The provider fence
    /// clears after the first clean post-recovery drain (bounded
    /// window, not a pre-seal fence); the counter re-attaches
    /// under a fresh generation on recovery.
    pub(crate) fn suspend_retained_with_edge(&mut self, edge_ns: u64) {
        self.note_kernel_edge(Some(edge_ns));
        self.suspend_retained();
    }
    /// 6A seal after a kernel-edge fence: late/resolve fence, then
    /// the normal close drain (withholding applies throughout).
    pub(crate) fn finish_with_edge(
        mut self,
        deadline: Instant,
        edge_ns: Option<u64>,
    ) -> anyhow::Result<FocusedResult> {
        self.note_kernel_edge(edge_ns);
        self.finish(deadline)
    }
    pub(crate) fn finish(mut self, deadline: Instant) -> anyhow::Result<FocusedResult> {
        self.pending = None;
        // One successful map-in-map delete closes metadata, API and physical
        // writers together. Keep all binding owners until drain/snapshot finish.
        if let Some(gate) = &self.gate {
            if gate.close().is_err() {
                self.gaps.insert(ObservationGap::BpfUnavailable);
            }
            if Instant::now() >= deadline {
                self.gaps.insert(ObservationGap::DrainOverrun);
            }
        }
        let end_ns = now_ns()?.min(self.deadline_ns);
        let mut api_activity = Vec::new();
        let mut fence_withheld = 0u64;
        let mut loss_totals = [0u64; 8];
        if let Some(s) = self.session.as_mut() {
            let batch = s.finalize_until(deadline);
            fence_withheld = fence_withheld.saturating_add(s.take_fence_withheld());
            loss_totals = s.loss_totals();
            if batch_invalidates_advertisements(&batch, self.pid) {
                self.gaps.insert(ObservationGap::Invalidated);
            }
            self.gaps.extend(batch.gaps);
            api_activity = batch
                .api_activity
                .into_iter()
                .filter(|a| a.pid == self.pid && a.starttime == self.starttime)
                .map(|a| a.row)
                .collect();
        }
        // ENGINE closed-cut validation: the counter is consumed
        // once below for both planes, so custody is verified
        // first. Pass → pending + closed tail join; fail → drop
        // pending, blind with Invalidated, tail withheld (a change
        // after the last snapshot must not enter through the cut).
        if matches!(self.engine.state, EnginePlaneState::Planned { .. }) {
            // Exit-safe ENGINE custody only: full retention
            // requires a live target (provider pidfd/maps checks),
            // but the closed cut routinely runs post-exit. Pin
            // stamps + epoch fully determine ENGINE attribution
            // integrity (no change in (attach, finish] proves the
            // tail counted the planned bytes).
            let cut_clean = match self.counter.as_ref() {
                Some(c) => {
                    c.engine_epoch() == self.engine.counter_epoch && c.engine_pins_unchanged()
                }
                None => false,
            };
            if !cut_clean {
                self.engine.pending.clear();
                self.engine.state = EnginePlaneState::Blind;
                self.gaps.insert(ObservationGap::Invalidated);
            }
        }
        let counter_cpus = self.counter.as_ref().map(|c| c.cpus());
        if let Some(mut c) = self.counter.take() {
            // Drain link diagnostics before close() consumes the
            // counter (after the take there is nothing to drain).
            self.attach_diagnostics.extend(c.take_attach_diagnostics());
            self.sample = c.close(deadline);
            fence_withheld = fence_withheld.saturating_add(self.sample.fence_withheld);
        }
        // Final ENGINE news from the closed cut, then join counts
        // to probe meanings + pinned module identities. A blinded
        // plane joins only validated pre-blind counts; pending and
        // post-blind drains stay ledger-balanced but unevidenced
        // (they would misattribute replacement bytes to stale
        // meanings).
        let mut engine_observations = Vec::new();
        if matches!(
            self.engine.state,
            EnginePlaneState::Planned { .. } | EnginePlaneState::Blind
        ) {
            if matches!(self.engine.state, EnginePlaneState::Planned { .. }) {
                let tail = engine_news(&mut self.engine.prev, &self.sample.engine);
                for (cookie, n) in tail {
                    self.engine
                        .pending
                        .entry(cookie)
                        .and_modify(|total| *total = total.saturating_add(n))
                        .or_insert(n);
                }
                let pending: Vec<(u64, u64)> = std::mem::take(&mut self.engine.pending)
                    .into_iter()
                    .collect();
                if !pending.is_empty() {
                    self.engine
                        .collector
                        .accumulate(self.engine.generation, &pending, &[]);
                }
            }
            let objects: Vec<ObjectRecord> = self
                .engine
                .modules
                .iter()
                .map(|(path, (device, ino, bid))| {
                    let id = if bid.is_empty() {
                        ObjectId(format!(
                            "unverified:{}:{ino}",
                            crate::plan::render_device(*device)
                        ))
                    } else {
                        ObjectId(format!("build:{bid}"))
                    };
                    ObjectRecord {
                        id,
                        device: *device,
                        inode: *ino,
                        display_locator: path.clone(),
                    }
                })
                .collect();
            let (obs, unkeyed) = self.engine.collector.build(&objects);
            engine_observations = obs;
            if unkeyed > 0 {
                let mut counter = loss("focused.engine_unkeyed", CounterSource::KernelMap, unkeyed);
                counter.units = CounterUnits::Calls;
                self.sample.gaps.push(counter);
            }
        }
        if matches!(self.engine.state, EnginePlaneState::Unsupported) {
            // Absent interface (4.x style): explicit terminal fact.
            self.sample.gaps.push(GapCounter {
                name: "focused.engine_absent".into(),
                source: CounterSource::Discovery,
                value: 1,
                kind: CounterKind::Activity,
                units: CounterUnits::Events,
            });
        }
        if matches!(self.engine.state, EnginePlaneState::Unplanned) && self.engine.ever_mapped {
            // Libcrypto was mapped but no plan ever bound: failed
            // observation, never a silent skip.
            self.sample.gaps.push(loss(
                "focused.engine_unplanned",
                CounterSource::Discovery,
                1,
            ));
        }
        if self.engine.skipped_modules > 0 {
            self.sample.gaps.push(loss(
                "focused.engine_module_skipped",
                CounterSource::Discovery,
                self.engine.skipped_modules,
            ));
        }
        if self.engine.uninstrumented > 0 {
            self.sample.gaps.push(loss(
                "focused.engine_uninstrumented",
                CounterSource::Discovery,
                self.engine.uninstrumented,
            ));
        }
        if self.engine.addrtaken > 0 {
            self.sample.gaps.push(GapCounter {
                name: "focused.engine_addrtaken".into(),
                source: CounterSource::Discovery,
                value: self.engine.addrtaken,
                kind: CounterKind::Activity,
                units: CounterUnits::Events,
            });
        }
        if self.owned.is_some() {
            self.sample
                .gaps
                .push(loss("focused.startup_partial", CounterSource::Discovery, 1));
        }
        if self.inventory_gaps > 0 {
            self.sample.gaps.push(loss(
                "focused.inventory_partial",
                CounterSource::Discovery,
                self.inventory_gaps,
            ));
        }
        // One-shot closed attribution: claim, strict final reads, collect,
        // fold. Unattempted without admitted typed sites (legacy-only);
        // refused collects keep the physical evidence below and record a
        // gap instead of a result.
        let report = CaptureWindow {
            requested_start_ns: self.start_ns,
            requested_end_ns: self.deadline_ns,
            effective_start_ns: self.start_ns,
            effective_end_ns: end_ns.max(self.start_ns),
            signal_cut: self.signal_cut,
            count_admission: Some(CountAdmissionWindow {
                start_ns: self.start_ns,
                deadline_ns: self.deadline_ns,
            }),
        };
        let admission = CountAdmissionWindow {
            start_ns: self.start_ns,
            deadline_ns: self.deadline_ns,
        };
        let finalized_attribution = self.collect_attribution(counter_cpus, report, admission);
        // Projectability is pre-scanned so a refusal records its
        // typed gap here, before finalization — the post-finalize
        // projection below is infallible after this gate.
        let projectable = finalized_attribution
            .as_ref()
            .is_some_and(|a| a.is_projectable());
        if self.typed_admitted() && finalized_attribution.is_none() {
            self.sample.gaps.push(loss(
                "focused.attribution_refused",
                CounterSource::Discovery,
                1,
            ));
        } else if finalized_attribution.is_some() && !projectable {
            self.sample.gaps.push(loss(
                "focused.attribution_projection_refused",
                CounterSource::Discovery,
                1,
            ));
        }
        let mut document = project(
            self.pid,
            report,
            std::mem::take(&mut self.sample),
            &self.gaps.iter().copied().collect::<Vec<_>>(),
            &self.attach_diagnostics,
        );
        if !engine_observations.is_empty() {
            // The live ENGINE plane joins here (project/finalize
            // carry none); sorted exactly as finalize would.
            document.engine_observations = engine_observations;
            document.engine_observations.sort();
        }
        if projectable {
            if let Some(ref attribution) = finalized_attribution {
                // Infallible after the pre-scan (the projection
                // re-checks and fails closed atomically); the
                // binding documents the unreachable error.
                let _ = attribution.project_into_document(&mut document);
            }
        }
        document.api_activity = crate::api_activity::merge(api_activity)?;
        let disposition = match &mut self.owned {
            Some(child) => child.finish_observation()?,
            None => TargetDisposition::Detached { pid: self.pid },
        };
        let child_exit = match disposition {
            TargetDisposition::Exited { code } => Some(code),
            _ => None,
        };
        document.disposition = Some(match (self.owned.is_some(), disposition) {
            (_, TargetDisposition::Exited { code }) => DispositionRecord::exited(code),
            (true, TargetDisposition::Detached { pid }) => DispositionRecord::detached_running(pid),
            (false, TargetDisposition::Detached { pid }) => {
                DispositionRecord::foreign_observed(pid)
            }
        });
        crate::evidence::stamp_context(
            &mut document,
            CaptureContext {
                kernel_release: crate::doctor::uname_release_opt().unwrap_or_default(),
                wall_start_unix_ns: self.wall_start,
                wall_end_unix_ns: unix_ns(),
                sysctls: self.sysctls.clone(),
            },
        );
        Ok(FocusedResult {
            document,
            child_exit,
            workload_discarded: self.workload_discarded,
            fence_withheld,
            loss_totals,
            _reservation: Some(self._reservation),
        })
    }
}

/// Synchronous one-process wrapper: exactly one signal owner, outside sessions.
pub fn run(
    config: FocusedConfig,
    target: capture::Target,
    objects: FocusedObjects,
    setup_deadline: Instant,
) -> anyhow::Result<FocusedResult> {
    config.validate()?;
    let signals = Signals::install().context("focused signal setup failed")?;
    let cancel = signals.cancel();
    let grace = config.grace;
    let mut session = FocusedSession::open(config, target, objects, setup_deadline, cancel, None)?;
    loop {
        let now = Instant::now();
        if session.poll(now, cancel)? != SessionProgress::Running {
            break;
        }
        std::thread::sleep(
            (now + POLL)
                .min(session.end)
                .saturating_duration_since(Instant::now()),
        );
    }
    session.finish(Instant::now() + grace)
}

#[cfg(test)]
mod session_tests {
    use super::*;
    fn objects() -> FocusedObjects {
        FocusedObjects {
            observation: Arc::from([]),
            count: Arc::from([]),
            count_sha256: Sha256::digest([]).into(),
        }
    }
    fn record() -> inventory::ProcessRecord {
        inventory::snapshot(&inventory::SnapshotOptions {
            pids: vec![std::process::id()],
            resolve_paths: false,
            limits: inventory::Limits {
                max_objects_per_process: 0,
                ..Default::default()
            },
        })
        .processes
        .remove(0)
    }
    #[test]
    fn engine_news_differences_cumulative_samples_per_cookie() {
        use crate::focused_count::{ENGINE_COOKIE_BASE, EngineCount};
        let base = ENGINE_COOKIE_BASE;
        let mut prev = BTreeMap::new();
        let first = vec![
            EngineCount {
                cookie: base,
                generation: 1,
                calls: 5,
                first_ns: 2,
                last_ns: 3,
            },
            EngineCount {
                cookie: base,
                generation: 2,
                calls: 2,
                first_ns: 4,
                last_ns: 5,
            },
            EngineCount {
                cookie: base + 1,
                generation: 1,
                calls: 3,
                first_ns: 2,
                last_ns: 3,
            },
        ];
        assert_eq!(
            engine_news(&mut prev, &first),
            vec![(u64::from(base), 7), (u64::from(base + 1), 3)]
        );
        let second = vec![
            EngineCount {
                cookie: base,
                generation: 1,
                calls: 5,
                first_ns: 2,
                last_ns: 3,
            },
            EngineCount {
                cookie: base,
                generation: 2,
                calls: 4,
                first_ns: 4,
                last_ns: 9,
            },
            EngineCount {
                cookie: base + 1,
                generation: 1,
                calls: 3,
                first_ns: 2,
                last_ns: 3,
            },
        ];
        assert_eq!(engine_news(&mut prev, &second), vec![(u64::from(base), 2)]);
    }
    #[test]
    fn engine_libcrypto_select_binds_maps_to_record_identity() {
        use std::os::unix::fs::MetadataExt as _;
        // A same-named copy stands in for libcrypto: selection stats
        // and matches identity only (ELF parsing plans later, live).
        let dir =
            std::env::temp_dir().join(format!("osslscope-engine-select-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let fake = dir.join("libcrypto.so.9");
        std::fs::copy("/bin/true", &fake).unwrap();
        let meta = std::fs::metadata(&fake).unwrap();
        let maps = vec![crate::discovery::maps::Mapping {
            start: 0x1000,
            end: 0x2000,
            x: true,
            offset: 0,
            dev: "00:00".into(),
            ino: meta.ino(),
            path: fake.to_str().unwrap().into(),
        }];
        let module = inventory::ModuleRecord {
            info: inventory::ModuleInfo {
                sha256: String::new(),
                device: meta.dev(),
                inode: meta.ino(),
                size_bytes: 0,
                architecture: inventory::Architecture::X86_64,
                kind: inventory::ObjectKind::OpenSslCompatible,
                exports: Vec::new(),
                depends_on_libcrypto: false,
                depends_on_libssl: false,
            },
            identity_status: inventory::IdentityStatus::Verified,
            verified_path: None,
            verified_path_unavailable: None,
            maps_spelling: None,
        };
        let admitted = select_engine_libcrypto(&maps, std::slice::from_ref(&module))
            .expect("matching identity admits");
        assert_eq!(admitted.path, fake.to_str().unwrap());
        assert_eq!(admitted.device, evidence_device(meta.dev()));
        assert_eq!(admitted.inode, meta.ino());
        // Swapped-away file (maps ino stale) refuses.
        let stale_maps = vec![crate::discovery::maps::Mapping {
            ino: meta.ino().wrapping_add(1),
            ..maps[0].clone()
        }];
        assert!(select_engine_libcrypto(&stale_maps, std::slice::from_ref(&module)).is_none());
        // Unadmitted identity (absent from the record) refuses.
        assert!(select_engine_libcrypto(&maps, &[]).is_none());
        // No libcrypto mapping refuses.
        assert!(select_engine_libcrypto(&[], std::slice::from_ref(&module)).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    #[ignore = "requires privileged BPF and fresh focused count object"]
    fn native_session_routes_engine_calls_to_observations() {
        use std::{
            fs,
            io::{BufRead, BufReader, Write},
            os::fd::{AsRawFd, FromRawFd},
            process::Command,
        };
        let dir =
            std::env::temp_dir().join(format!("osslscope-engine-session-{}", std::process::id()));
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
        let count = fs::read(std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT").unwrap()).unwrap();
        let objects = FocusedObjects {
            observation: Arc::from([]),
            count_sha256: Sha256::digest(&count).into(),
            count: Arc::from(count),
        };
        let cancel = AtomicBool::new(false);
        let mut session = FocusedSession::open(
            FocusedConfig::default(),
            capture::Target::Spawn {
                argv: vec![app.to_str().unwrap().into(), input.to_str().unwrap().into()],
                workload: crate::target::WorkloadDest::Fd(write.as_raw_fd()),
            },
            objects,
            Instant::now() + Duration::from_secs(30),
            &cancel,
            None,
        )
        .unwrap();
        drop(write);
        let mut output = BufReader::new(read);
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        assert_eq!(line, "ready\n");
        // Drive polls until the ENGINE plane binds (FIFO pacing
        // holds every call until after attach: zero pre-window loss).
        let until = Instant::now() + Duration::from_secs(20);
        loop {
            assert_eq!(
                session.poll(Instant::now(), &cancel).unwrap(),
                SessionProgress::Running
            );
            if session.engine_planned_for_test() {
                break;
            }
            assert!(Instant::now() < until, "engine plane must bind");
            std::thread::sleep(Duration::from_millis(100));
        }
        writeln!(commands, "B").unwrap();
        commands.flush().unwrap();
        let mut ack = String::new();
        output.read_line(&mut ack).unwrap();
        assert!(
            ack.starts_with("ack B 1 ") && ack.contains("did=5"),
            "{ack}"
        );
        for _ in 0..5 {
            assert_eq!(
                session.poll(Instant::now(), &cancel).unwrap(),
                SessionProgress::Running
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        writeln!(commands, "E").unwrap();
        commands.flush().unwrap();
        loop {
            match session.poll(Instant::now(), &cancel).unwrap() {
                SessionProgress::Exited | SessionProgress::StopRequested => break,
                SessionProgress::Running => {}
                other => panic!("unexpected progress: {other:?}"),
            }
            assert!(Instant::now() < until, "fixture must exit");
            std::thread::sleep(Duration::from_millis(100));
        }
        let result = session
            .finish(Instant::now() + Duration::from_secs(10))
            .unwrap();
        assert_eq!(result.child_exit, Some(0));
        let by_id_entry = crate::evidence::engine_index("ENGINE_by_id").unwrap();
        let by_id_calls: u64 = result
            .document
            .engine_observations
            .iter()
            .filter(|o| o.entrypoint == by_id_entry)
            .map(|o| o.calls)
            .sum();
        assert_eq!(by_id_calls, 5, "five paced by_id calls observed live");
        assert!(
            result
                .document
                .engine_observations
                .iter()
                .all(|o| o.window == crate::evidence::EngineWindow::InWindow),
            "paced calls are in-window"
        );
        assert!(
            !result
                .document
                .counters
                .iter()
                .any(|c| c.name == "focused_ledger_mismatch" || c.name == "focused.engine_unkeyed"),
            "engine plane balances"
        );
    }
    #[test]
    #[ignore = "requires privileged BPF and fresh focused count object"]
    fn native_session_engine_plane_blinds_on_pin_change() {
        use std::{
            fs,
            io::{BufRead, BufReader, Write},
            os::{
                fd::{AsRawFd, FromRawFd},
                unix::fs::PermissionsExt as _,
            },
            process::Command,
        };
        let dir = std::env::temp_dir().join(format!(
            "osslscope-engine-planeblind-{}",
            std::process::id()
        ));
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
        let count = fs::read(std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT").unwrap()).unwrap();
        let objects = FocusedObjects {
            observation: Arc::from([]),
            count_sha256: Sha256::digest(&count).into(),
            count: Arc::from(count),
        };
        let cancel = AtomicBool::new(false);
        let mut session = FocusedSession::open(
            FocusedConfig::default(),
            capture::Target::Spawn {
                argv: vec![app.to_str().unwrap().into(), input.to_str().unwrap().into()],
                workload: crate::target::WorkloadDest::Fd(write.as_raw_fd()),
            },
            objects,
            Instant::now() + Duration::from_secs(60),
            &cancel,
            None,
        )
        .unwrap();
        drop(write);
        let mut output = BufReader::new(read);
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        assert_eq!(line, "ready\n");
        let until = Instant::now() + Duration::from_secs(20);
        loop {
            assert_eq!(
                session.poll(Instant::now(), &cancel).unwrap(),
                SessionProgress::Running
            );
            if session.engine_planned_for_test() {
                break;
            }
            assert!(Instant::now() < until, "engine plane must bind");
            std::thread::sleep(Duration::from_millis(100));
        }
        // Mid-window pin change: the plane must blind loudly on
        // the next snapshot (past the 1s rescan cadence), never
        // stay Planned over dead links.
        let mut perms = fs::metadata(&app).unwrap().permissions();
        perms.set_mode(perms.mode() ^ 0o001);
        fs::set_permissions(&app, perms).unwrap();
        let blind_until = Instant::now() + Duration::from_secs(20);
        loop {
            assert_eq!(
                session.poll(Instant::now(), &cancel).unwrap(),
                SessionProgress::Running
            );
            if session.engine_blind_for_test() {
                break;
            }
            assert!(Instant::now() < blind_until, "plane must blind");
            std::thread::sleep(Duration::from_millis(300));
        }
        assert!(
            session
                .session_gaps_for_test()
                .contains(&ObservationGap::Invalidated),
            "retire-invalidated plane carries an explicit gap"
        );
        writeln!(commands, "E").unwrap();
        commands.flush().unwrap();
        loop {
            match session.poll(Instant::now(), &cancel).unwrap() {
                SessionProgress::Exited | SessionProgress::StopRequested => break,
                SessionProgress::Running => {}
                other => panic!("unexpected progress: {other:?}"),
            }
            assert!(Instant::now() < blind_until, "fixture must exit");
            std::thread::sleep(Duration::from_millis(100));
        }
        let result = session
            .finish(Instant::now() + Duration::from_secs(10))
            .unwrap();
        assert_eq!(result.child_exit, Some(0));
        assert!(
            result
                .document
                .counters
                .iter()
                .any(|c| c.name == "focused.identity_unknown"),
            "invalidation reaches the finished document"
        );
    }
    #[test]
    #[ignore = "requires privileged BPF and fresh focused count object"]
    fn native_session_engine_plane_withholds_ambiguous_counts() {
        use std::{
            fs,
            io::{BufRead, BufReader, Write},
            os::{
                fd::{AsRawFd, FromRawFd},
                unix::fs::PermissionsExt as _,
            },
            process::Command,
        };
        let dir =
            std::env::temp_dir().join(format!("osslscope-engine-withhold-{}", std::process::id()));
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
        let count = fs::read(std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT").unwrap()).unwrap();
        let objects = FocusedObjects {
            observation: Arc::from([]),
            count_sha256: Sha256::digest(&count).into(),
            count: Arc::from(count),
        };
        let cancel = AtomicBool::new(false);
        let mut session = FocusedSession::open(
            FocusedConfig::default(),
            capture::Target::Spawn {
                argv: vec![app.to_str().unwrap().into(), input.to_str().unwrap().into()],
                workload: crate::target::WorkloadDest::Fd(write.as_raw_fd()),
            },
            objects,
            Instant::now() + Duration::from_secs(60),
            &cancel,
            None,
        )
        .unwrap();
        drop(write);
        let mut output = BufReader::new(read);
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        assert_eq!(line, "ready\n");
        let until = Instant::now() + Duration::from_secs(20);
        loop {
            assert_eq!(
                session.poll(Instant::now(), &cancel).unwrap(),
                SessionProgress::Running
            );
            if session.engine_planned_for_test() {
                break;
            }
            assert!(Instant::now() < until, "engine plane must bind");
            std::thread::sleep(Duration::from_millis(100));
        }
        // Change FIRST, then call: every post-change drain is
        // unverifiable (the mode flip stands in for any file
        // change — bytes are untestable in place on a running
        // executable — and the design withholds on any stamp
        // change). No pre-change calls exist, so no snapshot can
        // have clean-joined anything: the only correct outcome is
        // blind + fully withheld.
        let mut perms = fs::metadata(&app).unwrap().permissions();
        perms.set_mode(perms.mode() ^ 0o001);
        fs::set_permissions(&app, perms).unwrap();
        writeln!(commands, "B").unwrap();
        commands.flush().unwrap();
        let mut ack = String::new();
        output.read_line(&mut ack).unwrap();
        assert!(
            ack.starts_with("ack B 1 ") && ack.contains("did=5"),
            "{ack}"
        );
        let blind_until = Instant::now() + Duration::from_secs(20);
        loop {
            assert_eq!(
                session.poll(Instant::now(), &cancel).unwrap(),
                SessionProgress::Running
            );
            if session.engine_blind_for_test() {
                break;
            }
            assert!(Instant::now() < blind_until, "plane must blind");
            std::thread::sleep(Duration::from_millis(300));
        }
        assert!(
            session
                .session_gaps_for_test()
                .contains(&ObservationGap::Invalidated),
            "withholding carries an explicit gap"
        );
        writeln!(commands, "E").unwrap();
        commands.flush().unwrap();
        loop {
            match session.poll(Instant::now(), &cancel).unwrap() {
                SessionProgress::Exited | SessionProgress::StopRequested => break,
                SessionProgress::Running => {}
                other => panic!("unexpected progress: {other:?}"),
            }
            assert!(Instant::now() < blind_until, "fixture must exit");
            std::thread::sleep(Duration::from_millis(100));
        }
        let result = session
            .finish(Instant::now() + Duration::from_secs(10))
            .unwrap();
        assert_eq!(result.child_exit, Some(0));
        let by_id_entry = crate::evidence::engine_index("ENGINE_by_id").unwrap();
        let by_id_calls: u64 = result
            .document
            .engine_observations
            .iter()
            .filter(|o| o.entrypoint == by_id_entry)
            .map(|o| o.calls)
            .sum();
        assert_eq!(by_id_calls, 0, "ambiguous increments withheld");
    }
    #[test]
    #[ignore = "requires privileged BPF and fresh focused count object"]
    fn native_session_engine_finish_validates_closed_tail() {
        use std::{
            fs,
            io::{BufRead, BufReader, Write},
            os::{
                fd::{AsRawFd, FromRawFd},
                unix::fs::PermissionsExt as _,
            },
            process::Command,
        };
        let dir =
            std::env::temp_dir().join(format!("osslscope-engine-fintail-{}", std::process::id()));
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
        let count = fs::read(std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT").unwrap()).unwrap();
        let objects = FocusedObjects {
            observation: Arc::from([]),
            count_sha256: Sha256::digest(&count).into(),
            count: Arc::from(count),
        };
        let cancel = AtomicBool::new(false);
        let mut session = FocusedSession::open(
            FocusedConfig::default(),
            capture::Target::Spawn {
                argv: vec![app.to_str().unwrap().into(), input.to_str().unwrap().into()],
                workload: crate::target::WorkloadDest::Fd(write.as_raw_fd()),
            },
            objects,
            Instant::now() + Duration::from_secs(60),
            &cancel,
            None,
        )
        .unwrap();
        drop(write);
        let mut output = BufReader::new(read);
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        assert_eq!(line, "ready\n");
        let until = Instant::now() + Duration::from_secs(20);
        loop {
            assert_eq!(
                session.poll(Instant::now(), &cancel).unwrap(),
                SessionProgress::Running
            );
            if session.engine_planned_for_test() {
                break;
            }
            assert!(Instant::now() < until, "engine plane must bind");
            std::thread::sleep(Duration::from_millis(100));
        }
        // Change, call, then finish with NO poll between: no
        // snapshot can validate first, so the closed cut itself
        // must validate and withhold the 5-call tail. The live
        // child is reaped by pid after (finish consumes the
        // session).
        let pid = session.pid;
        let mut perms = fs::metadata(&app).unwrap().permissions();
        perms.set_mode(perms.mode() ^ 0o001);
        fs::set_permissions(&app, perms).unwrap();
        writeln!(commands, "B").unwrap();
        commands.flush().unwrap();
        let mut tail_ack = String::new();
        output.read_line(&mut tail_ack).unwrap();
        assert!(
            tail_ack.starts_with("ack B 1 ") && tail_ack.contains("did=5"),
            "{tail_ack}"
        );
        let result = session
            .finish(Instant::now() + Duration::from_secs(10))
            .unwrap();
        let by_id_entry = crate::evidence::engine_index("ENGINE_by_id").unwrap();
        let by_id_calls: u64 = result
            .document
            .engine_observations
            .iter()
            .filter(|o| o.entrypoint == by_id_entry)
            .map(|o| o.calls)
            .sum();
        assert_eq!(by_id_calls, 0, "closed tail withheld without validation");
        assert!(
            result
                .document
                .counters
                .iter()
                .any(|c| c.name == "focused.identity_unknown"),
            "finish-time invalidation reaches the document"
        );
        unsafe {
            libc::kill(pid as i32, libc::SIGKILL);
        }
        let mut status = 0;
        unsafe {
            libc::waitpid(pid as i32, &mut status, 0);
        }
        let _ = commands;
        let _ = output;
    }
    #[test]
    #[ignore = "requires privileged BPF and fresh focused count object"]
    fn native_session_engine_plane_gaps_late_mapping() {
        use std::{
            fs,
            io::{BufRead, BufReader, Write},
            os::fd::{AsRawFd, FromRawFd},
            process::Command,
        };
        let dir =
            std::env::temp_dir().join(format!("osslscope-engine-latemap-{}", std::process::id()));
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
        // Never-executed blob: a new exec mapping the plane never
        // scanned (same maps event as a late dlopen).
        let blob = dir.join("late.bin");
        fs::write(&blob, vec![0u8; 8192]).unwrap();
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
        let count = fs::read(std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT").unwrap()).unwrap();
        let objects = FocusedObjects {
            observation: Arc::from([]),
            count_sha256: Sha256::digest(&count).into(),
            count: Arc::from(count),
        };
        let cancel = AtomicBool::new(false);
        let mut session = FocusedSession::open(
            FocusedConfig::default(),
            capture::Target::Spawn {
                argv: vec![app.to_str().unwrap().into(), input.to_str().unwrap().into()],
                workload: crate::target::WorkloadDest::Fd(write.as_raw_fd()),
            },
            objects,
            Instant::now() + Duration::from_secs(60),
            &cancel,
            None,
        )
        .unwrap();
        drop(write);
        let mut output = BufReader::new(read);
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        assert_eq!(line, "ready\n");
        let until = Instant::now() + Duration::from_secs(20);
        loop {
            assert_eq!(
                session.poll(Instant::now(), &cancel).unwrap(),
                SessionProgress::Running
            );
            if session.engine_planned_for_test() {
                break;
            }
            assert!(Instant::now() < until, "engine plane must bind");
            std::thread::sleep(Duration::from_millis(100));
        }
        let skipped_before = session.engine_skipped_modules_for_test();
        writeln!(commands, "M").unwrap();
        writeln!(commands, "{}", blob.to_str().unwrap()).unwrap();
        commands.flush().unwrap();
        let mut ack = String::new();
        output.read_line(&mut ack).unwrap();
        assert!(ack.starts_with("ack M 1 "), "{ack}");
        // The late mapping gaps exactly once (past the 1s rescan
        // cadence) while the plane stays Planned: existing
        // evidence keeps joining, the unknown stays unknown.
        let gap_until = Instant::now() + Duration::from_secs(20);
        loop {
            assert_eq!(
                session.poll(Instant::now(), &cancel).unwrap(),
                SessionProgress::Running
            );
            assert!(
                session.engine_planned_for_test(),
                "late mapping gaps, never blinds"
            );
            if session.engine_skipped_modules_for_test() == skipped_before + 1 {
                break;
            }
            assert!(Instant::now() < gap_until, "late mapping must gap");
            std::thread::sleep(Duration::from_millis(300));
        }
        // One more snapshot past cadence: still exactly once.
        std::thread::sleep(Duration::from_secs(2));
        assert_eq!(
            session.poll(Instant::now(), &cancel).unwrap(),
            SessionProgress::Running
        );
        assert_eq!(
            session.engine_skipped_modules_for_test(),
            skipped_before + 1,
            "caller news counts once"
        );
        writeln!(commands, "E").unwrap();
        commands.flush().unwrap();
        loop {
            match session.poll(Instant::now(), &cancel).unwrap() {
                SessionProgress::Exited | SessionProgress::StopRequested => break,
                SessionProgress::Running => {}
                other => panic!("unexpected progress: {other:?}"),
            }
            assert!(Instant::now() < gap_until, "fixture must exit");
            std::thread::sleep(Duration::from_millis(100));
        }
        let result = session
            .finish(Instant::now() + Duration::from_secs(10))
            .unwrap();
        assert_eq!(result.child_exit, Some(0));
        let skipped_counter = result
            .document
            .counters
            .iter()
            .find(|c| c.name == "focused.engine_module_skipped")
            .map(|c| c.value);
        assert_eq!(
            skipped_counter,
            Some(skipped_before + 1),
            "late mapping reaches the finished document"
        );
    }
    #[test]
    fn engine_absent_signal_is_the_planner_finding() {
        let absent = crate::discovery::legacy::ProbeSet {
            findings: vec![crate::discovery::legacy::FINDING_ENGINE_ABSENT.to_string()],
            ..Default::default()
        };
        assert!(engine_interface_absent(&absent));
        assert!(!engine_interface_absent(
            &crate::discovery::legacy::ProbeSet::default()
        ));
    }
    #[test]
    fn wanted_dedupe_collapses_hardlink_aliases() {
        use crate::discovery::legacy::Probe;
        let probes = vec![
            Probe {
                cookie: 0,
                symbol: "ENGINE_by_id".into(),
                offset: 7,
                module: "/x/a".into(),
                family: None,
                str_arg: None,
                program: "trip_count",
            },
            Probe {
                cookie: 1,
                symbol: "ENGINE_by_id".into(),
                offset: 7,
                module: "/x/b".into(),
                family: None,
                str_arg: None,
                program: "trip_count",
            },
            Probe {
                cookie: 2,
                symbol: "ENGINE_init".into(),
                offset: 9,
                module: "/x/a".into(),
                family: None,
                str_arg: None,
                program: "trip_count",
            },
        ];
        let identities: BTreeMap<String, (u64, u64)> =
            BTreeMap::from([("/x/a".to_string(), (1, 2)), ("/x/b".to_string(), (1, 2))]);
        // Same (dev, ino, offset) under two paths: first wins.
        assert_eq!(
            dedupe_wanted_probes(&[0, 1, 2], &probes, &identities),
            vec![0, 2]
        );
        // Missing identity keeps the probe (the attach stage
        // blinds loudly on unjoinable modules instead).
        assert_eq!(
            dedupe_wanted_probes(&[0, 1, 2], &probes, &BTreeMap::new()),
            vec![0, 1, 2]
        );
    }
    #[test]
    fn caller_diff_counts_new_and_replaced_once() {
        // Baseline: /a scanned, /b skipped-at-plan (unstatable).
        let mut baseline: BTreeMap<String, Option<(u64, u64)>> =
            BTreeMap::from([("/a".to_string(), Some((1, 2))), ("/b".to_string(), None)]);
        // Unchanged set: silent.
        let (skipped, overflow) = diff_caller_set(
            &mut baseline,
            &[("/a".to_string(), Some((1, 2))), ("/b".to_string(), None)],
            8,
        );
        assert_eq!((skipped, overflow), (0, false));
        // New path + replacement + /b reappearing: three unknowns.
        let (skipped, overflow) = diff_caller_set(
            &mut baseline,
            &[
                ("/a".to_string(), Some((1, 3))),
                ("/b".to_string(), Some((4, 5))),
                ("/c".to_string(), Some((6, 7))),
            ],
            8,
        );
        assert_eq!((skipped, overflow), (3, false));
        // Repeating the same set counts nothing (baseline grew).
        let (skipped, overflow) = diff_caller_set(
            &mut baseline,
            &[
                ("/a".to_string(), Some((1, 3))),
                ("/b".to_string(), Some((4, 5))),
                ("/c".to_string(), Some((6, 7))),
            ],
            8,
        );
        assert_eq!((skipped, overflow), (0, false));
        // Vanished-from-maps entries stay (no loss, no recount).
        let (skipped, overflow) =
            diff_caller_set(&mut baseline, &[("/a".to_string(), Some((1, 3)))], 8);
        assert_eq!((skipped, overflow), (0, false));
        // Full baseline + unseen path: overflow (caller blinds).
        baseline.insert("/d".to_string(), Some((8, 8)));
        let (skipped, overflow) = diff_caller_set(
            &mut baseline,
            &[
                ("/a".to_string(), Some((1, 3))),
                ("/e".to_string(), Some((9, 9))),
            ],
            4,
        );
        assert_eq!((skipped, overflow), (0, true));
    }
    #[test]
    fn scanned_session_clips_kernel_window_and_uses_fresh_incarnation() {
        let expected = record();
        let objects = objects();
        let pool = crate::observation_memory::MemoryPool::new(256 << 20);
        let lease = pool
            .reserve(FocusedSession::reservation_bytes(&objects).unwrap())
            .unwrap();
        let end = Instant::now() + Duration::from_secs(2);
        let cancel = AtomicBool::new(false);
        let mut session = FocusedSession::open_scanned_reserved(
            FocusedConfig::default(),
            objects,
            (end, end),
            &cancel,
            &expected,
            lease,
        )
        .unwrap();
        assert!(session.end <= end);
        assert!(session.deadline_ns - session.start_ns <= 2_000_000_000);
        assert_eq!(
            session
                .poll_scanned(Instant::now(), end, &cancel, None, false)
                .unwrap(),
            SessionProgress::Running
        );
        let mut replacement = expected;
        replacement.starttime += 1;
        assert_eq!(
            session
                .poll_scanned(Instant::now(), end, &cancel, Some(&[replacement]), false)
                .unwrap(),
            SessionProgress::Unverifiable
        );
        assert!(session.gaps.contains(&ObservationGap::ProcessChanged));
    }
    #[test]
    fn session_reservation_precedes_open_and_contended_parse_needs_cache() {
        // Session-like companions for the reservation: a session's
        // counter borrows maps, so the estimate skips the shared set.
        // (The `open_reserved` below still runs standalone companions.)
        // F8d RESTORATION: the estimate MUST use production object
        // sizes (1 KiB fakes understated two sessions by 776 KiB and
        // asserted a fit production never had — the vacuous 2-pid
        // observation). Lengths only (content-independent); update
        // when the built BPF objects change size.
        const PRODUCTION_OBSERVATION_LEN: usize = 218_504;
        const PRODUCTION_COUNT_LEN: usize = 171_912;
        let estimate = FocusedObjects {
            observation: Arc::from(vec![0u8; PRODUCTION_OBSERVATION_LEN]),
            count: Arc::from(vec![0u8; PRODUCTION_COUNT_LEN]),
            count_sha256: Sha256::digest(vec![0u8; PRODUCTION_COUNT_LEN]).into(),
        };
        let objects = objects();
        let bytes = FocusedSession::reservation_bytes(&estimate).unwrap();
        println!("persistent session reservation {bytes} bytes on this CPU configuration");
        let pool = crate::observation_memory::MemoryPool::new(256 << 20);
        let one = pool.reserve(bytes).unwrap();
        let two = pool.reserve(bytes).unwrap();
        // After two sessions retain their reservations, a FRESH
        // libcrypto parse no longer fits: this is the live
        // contention that starved the second session's parse.
        // The scan prefills the run-shared cache while the pool
        // is idle, so live sessions hit the cache (no scratch)
        // instead of re-parsing; assert the contention honestly
        // here (the old `.unwrap()` asserted a fit production
        // never had).
        //
        // CI-fix: per-CPU map growth leaves that contention only
        // on many-CPU hosts; 4-CPU CI runners left slack a stock
        // parse fit (check.yml runs 42861210551 + 42974059023).
        // The clamp takes the host-dependent slack (leaving one
        // byte short of a stock scratch); already-contended
        // hosts take no filler.
        let stock = crate::inventory::elf::parser_scratch_bytes(6_386_528).unwrap();
        {
            let _pressure = pool.clamp_free_to(stock - 1);
            assert!(pool.reserve(stock).is_none());
            assert!(
                pool.reserve(crate::inventory::elf::parser_scratch_bytes(128 << 20).unwrap())
                    .is_none()
            );
        }
        drop(two);
        drop(one);
        let expected = record();
        let too_small = pool.reserve(bytes - 1).unwrap();
        assert!(
            FocusedSession::open_reserved(
                FocusedConfig::default(),
                capture::Target::Pid(expected.pid),
                objects,
                Instant::now() + Duration::from_secs(2),
                &AtomicBool::new(false),
                Some(&expected),
                too_small
            )
            .is_err()
        );
        assert!(pool.reserve(256 << 20).is_some());
    }
    #[test]
    fn supplied_incarnation_is_checked_before_open_and_foreign_survives() {
        let expected = record();
        let cancel = AtomicBool::new(false);
        for namespace in [false, true] {
            let mut stale = expected.clone();
            if namespace {
                stale.namespaces.pid.as_mut().unwrap().inode += 1;
            } else {
                stale.starttime += 1;
            }
            assert!(
                FocusedSession::open(
                    FocusedConfig::default(),
                    capture::Target::Pid(expected.pid),
                    objects(),
                    Instant::now() + Duration::from_secs(2),
                    &cancel,
                    Some(&stale)
                )
                .is_err()
            );
        }
        let mut session = FocusedSession::open(
            FocusedConfig::default(),
            capture::Target::Pid(expected.pid),
            objects(),
            Instant::now() + Duration::from_secs(2),
            &cancel,
            Some(&expected),
        )
        .unwrap();
        session.pending = Some(ObservationBatch::default());
        cancel.store(true, Ordering::Relaxed);
        assert_eq!(
            session.poll(Instant::now(), &cancel).unwrap(),
            SessionProgress::StopRequested
        );
        assert!(
            session.pending.is_none(),
            "cancellation must discard pending attachment work"
        );
        let result = session.finish(Instant::now()).unwrap();
        assert!(result.document.window.signal_cut);
        assert_eq!(unsafe { libc::kill(expected.pid as i32, 0) }, 0);
    }
    #[test]
    fn disappeared_foreign_incarnation_is_unverifiable_not_owned_exit() {
        let mut app = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let expected = inventory::snapshot(&inventory::SnapshotOptions {
            pids: vec![app.id()],
            resolve_paths: false,
            limits: inventory::Limits {
                max_objects_per_process: 0,
                ..Default::default()
            },
        })
        .processes
        .remove(0);
        let cancel = AtomicBool::new(false);
        let mut session = FocusedSession::open(
            FocusedConfig::default(),
            capture::Target::Pid(app.id()),
            objects(),
            Instant::now() + Duration::from_secs(2),
            &cancel,
            Some(&expected),
        )
        .unwrap();
        app.kill().unwrap();
        app.wait().unwrap(); // fixture owner, never the observing session
        session.initial_metadata = None;
        session.pending = Some(ObservationBatch::default());
        assert_eq!(
            session.poll(Instant::now(), &cancel).unwrap(),
            SessionProgress::Unverifiable
        );
        assert!(session.pending.is_none());
        session.finish(Instant::now()).unwrap();
    }
    #[test]
    fn finished_document_carries_observer_kernel_release() {
        let mut app = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let expected = inventory::snapshot(&inventory::SnapshotOptions {
            pids: vec![app.id()],
            resolve_paths: false,
            limits: inventory::Limits {
                max_objects_per_process: 0,
                ..Default::default()
            },
        })
        .processes
        .remove(0);
        let cancel = AtomicBool::new(false);
        let session = FocusedSession::open(
            FocusedConfig::default(),
            capture::Target::Pid(app.id()),
            objects(),
            Instant::now() + Duration::from_secs(2),
            &cancel,
            Some(&expected),
        )
        .unwrap();
        let result = session.finish(Instant::now()).unwrap();
        app.kill().unwrap();
        app.wait().unwrap();
        // The observer kernel is free context (uname), not staged
        // evidence: finish() must carry it, never an empty string.
        let context = result.document.context.expect("finish sets context");
        assert_eq!(
            context.kernel_release,
            crate::doctor::uname_release_opt().unwrap_or_default()
        );
        assert!(!context.kernel_release.is_empty());
    }

    #[test]
    fn cancelled_session_setup_never_resets_callers_signal() {
        let cancel = AtomicBool::new(true);
        assert!(
            FocusedSession::open(
                FocusedConfig::default(),
                capture::Target::Spawn {
                    argv: vec!["/bin/true".into()],
                    workload: crate::target::WorkloadDest::Null
                },
                objects(),
                Instant::now() + Duration::from_secs(2),
                &cancel,
                None
            )
            .is_err()
        );
        assert!(cancel.load(Ordering::Relaxed));
    }

    #[test]
    #[ignore = "requires privileged BPF and fresh focused count object"]
    fn denied_link_diagnostic_survives_session_finish() {
        // Root forks a worker that opens a real FocusedSession on a
        // spawned vehicle, then installs a seccomp filter denying only
        // bpf() with EPERM: the attach's link_create fails
        // deterministically, and finish() must carry the shaped link
        // diagnostic onto the document. The counter is consumed by
        // close() before projection, so the drain must happen at the
        // take — this test pins that ordering (a drain after the
        // take silently drops every link diagnostic).
        // SAFETY: geteuid has no preconditions and cannot fail.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skip finish pin: needs root");
            return;
        }
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: fds points to two writable ints; return checked.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: single-threaded test; the child runs the worker
        // (session open, vehicle-pid handoff, seccomp deny, polls,
        // finish), reports the verdict byte, and _exits.
        let forked = unsafe { libc::fork() };
        assert!(forked >= 0, "fork failed");
        if forked == 0 {
            // SAFETY: we own fds[0]; closing the unused read end.
            unsafe { libc::close(fds[0]) };
            // Protocol: the worker writes the vehicle incarnation
            // (pid + starttime, 12 bytes LE) first, then this
            // wrapper writes the verdict byte.
            let verdict: u8 = finish_worker_verdict(fds[1]);
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
        // One deadline spans the pid handoff, the verdict read, and
        // the worker's exit: a worker that never reports — or reports
        // and never exits — fails the pin, never hangs the suite.
        // Waits are EINTR-retried; an interrupted wait never reads as
        // an exited child.
        let deadline = Instant::now() + Duration::from_secs(180);
        // Stage 1: vehicle-incarnation custody handoff (pid +
        // starttime, 12 bytes). The worker writes it immediately
        // after opening the session, so every later timeout path can
        // stop the long-lived vehicle too (finish() detaches a live
        // workload; it never kills it). Timeout paths signal through
        // a starttime-verified pidfd, never the bare number: the
        // parent cannot reap its grandchild, so the number alone
        // could name a recycled process.
        // Residual window: a worker wedged inside session open past
        // its own 30s setup deadline (lock-hang only) never hands
        // off its pid — accepted, documented, never observed.
        let mut handoff = [0u8; 12];
        if let Err(e) = crate::target::read_exact_deadline(fds[0], &mut handoff, deadline) {
            crate::target::kill_test_child(forked as u32, Duration::from_secs(5));
            // SAFETY: we own fds[0].
            unsafe { libc::close(fds[0]) };
            panic!("finish pin vehicle handoff unread ({e}); worker killed");
        }
        let vehicle = u32::from_le_bytes(handoff[..4].try_into().unwrap());
        let vehicle_starttime = u64::from_le_bytes(handoff[4..].try_into().unwrap());
        // Stage 2: verdict byte.
        let mut buf = [0u8; 1];
        if let Err(e) = crate::target::read_exact_deadline(fds[0], &mut buf, deadline) {
            // Timeout-path custody: stop the vehicle first (it
            // outlives the wedged worker), then the worker. The
            // vehicle is a grandchild: signal through the
            // starttime-verified pidfd, never the bare number.
            crate::target::kill_test_grandchild(vehicle, vehicle_starttime);
            crate::target::kill_test_child(forked as u32, Duration::from_secs(5));
            // SAFETY: we own fds[0].
            unsafe { libc::close(fds[0]) };
            panic!("finish pin verdict unread ({e}); vehicle and worker killed");
        }
        // SAFETY: we own fds[0].
        unsafe { libc::close(fds[0]) };
        match crate::target::wait_test_child(forked as u32, deadline) {
            crate::target::TestChildWait::Reaped(status) => assert!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "finish pin worker exited abnormally: {status}"
            ),
            crate::target::TestChildWait::Gone => {
                panic!("finish pin worker reaped elsewhere (sole-reaper violated)")
            }
            crate::target::TestChildWait::Timeout => {
                crate::target::kill_test_grandchild(vehicle, vehicle_starttime);
                crate::target::kill_test_child(forked as u32, Duration::from_secs(5));
                panic!("finish pin worker reported but never exited; vehicle and worker killed");
            }
        }
        match buf[0] {
            1 => {}
            2 => {
                eprintln!(
                    "skip finish pin: seccomp-bpf unsupported, foreign arch, \
                     or no post-filter attach observed"
                );
                return;
            }
            other => {
                panic!("finish pin verdict {other} (0=link-succeeded, 3=setup, 5=no-diag)")
            }
        }
    }

    /// Post-fork worker for
    /// [`denied_link_diagnostic_survives_session_finish`]: 1 ok, 2
    /// skip (seccomp-bpf positively unsupported, foreign arch the
    /// x86_64-only filter cannot deny, or a cleanly polled session
    /// that never attempted a post-filter link), 0 filter installed
    /// yet a link succeeded (broken pin), 5 finished without a
    /// shaped link diagnostic, 3 setup failure. `pipe` carries the
    /// vehicle-incarnation handoff (pid + starttime, 12 bytes LE);
    /// the wrapper writes the verdict byte. No panics past session
    /// open: every outcome returns a code so the vehicle kill below
    /// always runs.
    fn finish_worker_verdict(pipe: std::os::fd::RawFd) -> u8 {
        let count = match std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT")
            .and_then(|path| std::fs::read(path).ok())
        {
            Some(bytes) => bytes,
            None => return 3,
        };
        let objects = FocusedObjects {
            observation: Arc::from([]),
            count_sha256: Sha256::digest(&count).into(),
            count: Arc::from(count),
        };
        let cancel = AtomicBool::new(false);
        // A live vehicle: `dgst` would exit before the denied attach
        // runs; `speed` keeps libcrypto mapped while the worker
        // polls. It is LONG-lived (`-seconds` bounds one benchmark,
        // not the run) and finish() detaches it — so the worker
        // hands its pid to the parent immediately (timeout-path
        // custody) and always stops it before reporting.
        let session = match FocusedSession::open(
            FocusedConfig::default(),
            capture::Target::Spawn {
                argv: vec![
                    "/usr/bin/openssl".into(),
                    "speed".into(),
                    "-seconds".into(),
                    "10".into(),
                ],
                workload: crate::target::WorkloadDest::Null,
            },
            objects,
            Instant::now() + Duration::from_secs(30),
            &cancel,
            None,
        ) {
            Ok(session) => session,
            Err(_) => return 3,
        };
        let vehicle = session
            .owned
            .as_ref()
            .map(|owned| owned.pid())
            .unwrap_or(session.pid);
        // The handoff carries the incarnation (pid + starttime), not
        // just the number: the parent cannot reap its grandchild, so
        // a bare pid could name a recycled process by the time a
        // timeout path signals it. A vehicle already gone here died
        // instantly: broken setup, fail (the session's own custody
        // reaps the zombie).
        let Some(vehicle_starttime) = crate::target::process_starttime(vehicle) else {
            crate::target::kill_test_child(vehicle, Duration::from_secs(5));
            return 3;
        };
        let mut handoff = [0u8; 12];
        handoff[..4].copy_from_slice(&vehicle.to_le_bytes());
        handoff[4..].copy_from_slice(&vehicle_starttime.to_le_bytes());
        if crate::target::write_all_pipe(pipe, &handoff).is_err() {
            // The parent is gone: nothing to report to; stop the
            // vehicle and fail.
            crate::target::kill_test_child(vehicle, Duration::from_secs(5));
            return 3;
        }
        // Single cleanup point: every post-open outcome returns
        // through here, so the vehicle kill below always runs.
        let verdict = (|mut session: FocusedSession, cancel: AtomicBool| -> u8 {
            // Seccomp self-restriction: deny only the bpf() syscall with
            // EPERM (same shape as the counter-level link pin —
            // validation proceeds untouched, the attach's link_create
            // fails deterministically). Skips stay positively identified:
            // foreign arch, or a kernel that demonstrably lacks
            // SECCOMP_MODE_FILTER.
            if !cfg!(target_arch = "x86_64") {
                return 2;
            }
            // Positively identify kernel support before installing.
            // The NULL-filter probe installs nothing — and every outcome
            // is classified explicitly: only a recognized lack of
            // support skips; anything unexpected fails.
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
            // SAFETY: the program is six classic-BPF instructions over
            // struct seccomp_data (nr at 0, arch at 4); jump targets are
            // in range; prctl args are valid; NO_NEW_PRIVS first for the
            // unprivileged-install rule.
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
            fn is_link_top(diagnostic: &String) -> bool {
                diagnostic.starts_with("attach:link count_entry@0x")
                    && crate::acquire_cause::attach_template_shape(
                        diagnostic.strip_prefix("attach:").unwrap_or(""),
                    )
            }
            // Successful, diagnostic-free setup: the counter must be live
            // and no diagnostic may predate the filter — a pre-filter
            // diagnostic would masquerade as the denied-link stimulus
            // below. (Setup failures return 3; nothing panics past
            // session open, so the vehicle kill always runs.)
            // The stimulus is visible in two places: the session set
            // (batch refusals, drained counter diags) and — until
            // finish drains it — the counter itself. Both must be
            // clean before the filter: a pre-filter diagnostic would
            // masquerade as the denied-link stimulus below.
            let stimulus_pending = |session: &FocusedSession| {
                session.attach_diagnostics.iter().any(is_link_top)
                    || session
                        .counter
                        .as_ref()
                        .is_some_and(|counter| counter.attach_diagnostics_pending_for_test())
            };
            if session.counter.is_none() || stimulus_pending(&session) {
                return 3;
            }
            // Fail-open count: if /proc/self/fd is unreadable the polls
            // below fail too and the pin fails on the missing stimulus —
            // a broken pin can only go undetected alongside a broken /proc.
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
            // Wait for the independently established post-filter
            // stimulus under a deadline: polls run the denied attach
            // and the loop ends when its shaped diagnostic lands (in
            // the counter, visible via the test peek, or the session
            // set). The wait is on the outcome, not on whichever
            // plane schedules the post-filter attempt. Poll errors
            // under the deny filter are expected (map reads refuse
            // too); what matters is whether the stimulus diagnostic
            // arrives.
            let stimulus = Instant::now() + Duration::from_secs(15);
            let mut ran = false;
            loop {
                if session.poll(Instant::now(), &cancel).is_ok() {
                    ran = true;
                }
                if stimulus_pending(&session) {
                    break;
                }
                // The filter is installed on a known arch: a new link
                // means the denial did not deny (broken pin). Check
                // before finish closes everything.
                if link_fds() > baseline {
                    return 0;
                }
                if Instant::now() >= stimulus {
                    // Polled cleanly but never attempted a post-filter
                    // link: the pin's stimulus never materialized, so
                    // there is nothing to assert (skip). Zero successful
                    // polls means the session never ran: setup failure.
                    return if ran { 2 } else { 3 };
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let result = match session.finish(Instant::now() + Duration::from_secs(10)) {
                Ok(result) => result,
                Err(_) => return 3,
            };
            if result.document.attach_diagnostics.iter().any(is_link_top) {
                1
            } else {
                5
            }
        })(session, cancel);
        // finish() detaches a live workload (and every early return
        // above leaves it spawned): the worker always stops its
        // vehicle before reporting.
        crate::target::kill_test_child(vehicle, Duration::from_secs(5));
        verdict
    }
}

#[cfg(test)]
mod r71_tests {
    use super::*;
    use crate::observation_memory::MemoryPool;

    fn hollow(pool: &MemoryPool) -> FocusedSession {
        let mut session = FocusedSession::hollow_for_coordinator_tests(
            7,
            1,
            crate::inventory::NamespaceIds::default(),
            pool,
        );
        session.last_clean_drain_ns = 100;
        session
    }

    fn batch(exec_witnesses: Vec<u32>, exec_deferred: Vec<u32>) -> ObservationBatch {
        ObservationBatch {
            exec_witnesses,
            exec_deferred,
            ..Default::default()
        }
    }

    #[test]
    fn r71_deferred_exec_fences_at_detection_and_freezes_clean() {
        // R7-1 bridge (headless hollow session): a deferred-exec
        // detection batch fences immediately (detecting) WITHOUT
        // sealing (no exec_pending — witnesses still ride retry
        // completion); witness-free batches while the hold
        // persists stay detecting (the drain must not advance the
        // clean instant past the exec); the retry witness seals
        // and releases; only then does a clean drain advance.
        let cancel = AtomicBool::new(false);
        let tick_end = Instant::now() + Duration::from_secs(10);
        let pool = MemoryPool::new(1 << 20);
        let mut session = hollow(&pool);
        // Detection: fence now, seal nothing, latch the hold.
        assert!(
            session.note_batch_exec_signals(&batch(vec![], vec![7]), true),
            "deferred detection must fence immediately"
        );
        assert!(session.exec_fence_pending, "detection must latch the hold");
        assert!(
            session.exec_pending.is_empty(),
            "detection must not seal (witnesses ride completion)"
        );
        session
            .apply_drain_batch(batch(vec![], vec![7]), true, tick_end, &cancel)
            .unwrap();
        assert_eq!(
            session.last_clean_drain_ns, 100,
            "detecting drain must not advance the clean instant"
        );
        // Witness-free while held: still detecting, still frozen.
        assert!(
            session.note_batch_exec_signals(&batch(vec![], vec![]), true),
            "held witness-free batch must stay detecting"
        );
        session
            .apply_drain_batch(batch(vec![], vec![]), true, tick_end, &cancel)
            .unwrap();
        assert_eq!(
            session.last_clean_drain_ns, 100,
            "held witness-free drain must not advance past the exec"
        );
        // Retry witness: seal + release; the drain stays detecting.
        assert!(
            session.note_batch_exec_signals(&batch(vec![7], vec![]), false),
            "witness batch must fence"
        );
        assert_eq!(
            session.exec_pending,
            vec![7],
            "witness must seal exactly once"
        );
        assert!(
            !session.exec_fence_pending,
            "completion must release the hold"
        );
        session
            .apply_drain_batch(batch(vec![7], vec![]), false, tick_end, &cancel)
            .unwrap();
        assert_eq!(
            session.last_clean_drain_ns, 100,
            "witness drain must not advance (preceding-clean edge)"
        );
        // Clean and unheld: advance resumes.
        assert!(
            !session.note_batch_exec_signals(&batch(vec![], vec![]), false),
            "clean unheld batch must not fence"
        );
        session
            .apply_drain_batch(batch(vec![], vec![]), false, tick_end, &cancel)
            .unwrap();
        assert!(
            session.last_clean_drain_ns > 100,
            "clean unheld drain must advance the clean instant"
        );
    }
}
#[cfg(test)]
mod quarantine_visibility_tests {
    use super::*;
    #[test]
    fn quarantine_gap_names_itself_outside_read_unknown() {
        // I-2: the kernel-panic quarantine refusal must surface under
        // its own counter name — never the generic read_unknown
        // catch-all (a refused attach is not a drain/read failure).
        let counter = observation_loss(ObservationGap::QuarantinedApi);
        assert_eq!(counter.name, "focused.attach_refused_quarantined");
        assert_eq!(counter.source, CounterSource::Attach);
        assert_eq!(counter.kind, CounterKind::Loss);
        // The genuine missing-symbol gap keeps its own (non-quarantine)
        // identity: the two producers must never conflate.
        let genuine = observation_loss(ObservationGap::SymbolUnavailable);
        assert_ne!(genuine.name, counter.name);
    }
}
