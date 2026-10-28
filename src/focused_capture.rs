// SPDX-License-Identifier: GPL-3.0-or-later
//! One-process synchronous focused capture. Advertisements only permit bounded
//! callback attachment; open attribution and the production tail stay unknown.
use crate::{
    capture::{self, ClockPort, LiveClock},
    evidence::*,
    focused_count::{CountCandidate, CountLimits, CountSample, FocusedCounter},
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
#[derive(Clone, Copy, Debug)]
pub struct FocusedConfig {
    pub duration: Duration,
    pub timeout: Duration,
    pub grace: Duration,
}
impl Default for FocusedConfig {
    fn default() -> Self {
        Self {
            duration: Duration::from_secs(30),
            timeout: Duration::from_secs(60),
            grace: Duration::from_secs(5),
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
                | ObservationGap::IdentityUnverified
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
        BpfUnavailable | InvalidObject | ClassifierFailed => {
            ("focused.tracing_unavailable", CounterSource::Setup)
        }
        AttachFailed => ("focused.observation_attach", CounterSource::Attach),
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
    let metadata_fits = candidate_projection_fits(&associations);
    if !metadata_fits {
        sample.gaps.push(loss(
            "focused.metadata_output_limit",
            CounterSource::Discovery,
            1,
        ));
    }
    let mut document = crate::evidence::finalize(FinalizeInput {
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
    if metadata_fits {
        document.project_candidate_metadata();
    }
    document
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

enum BatchProgress {
    Applied(bool),
    Deferred,
}
fn process_batch(
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
    if valid {
        *state_bytes = admitted.unwrap();
    }
    Ok(BatchProgress::Applied(
        valid && counter.active_site_count() > 0 && now_ns()? < deadline_ns,
    ))
}

/// Reusable bounded process observation. Fields close counter/provider links
/// before releasing original owned custody, including error/drop paths.
pub(crate) struct FocusedSession {
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
    gaps: BTreeSet<ObservationGap>,
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
        let mut bytes = (104usize << 20) + objects.observation.len() + objects.count.len();
        for spec in crate::loader::FOCUSED_COUNT_MAPS
            .into_iter()
            .chain(crate::provider_observation::session::specs())
        {
            let value = (spec.value_size as usize + 7) & !7;
            let payload = if spec.map_type == 27 {
                spec.max_entries as usize
            } else {
                let copies = if matches!(spec.map_type, 5 | 6) {
                    cpus
                } else {
                    1
                };
                (spec.key_size as usize + value * copies + 128) * spec.max_entries as usize
            };
            bytes = bytes
                .checked_add(payload + 65_536)
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
            if owned.1.is_some()
                || expected.pid != pid
                || expected.modules.len() > 256
                || expected
                    .modules
                    .iter()
                    .any(|m| m.info.sha256.len() != 64 || m.info.exports.len() > 46)
            {
                return Err(TargetUnavailable.into());
            }
            (expected.clone(), 0)
        } else {
            let snapshot = inventory::snapshot(&inventory::SnapshotOptions {
                pids: vec![pid],
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
        let mut gaps = BTreeSet::new();
        let mut session = if objects.observation.is_empty() {
            gaps.insert(ObservationGap::BpfUnavailable);
            None
        } else {
            match ProviderSession::open_budgeted(budget.clone(), &objects.observation) {
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
        let mut counter = if objects.count.is_empty() {
            gaps.insert(ObservationGap::BpfUnavailable);
            None
        } else {
            match observer_namespace() {
                Ok(namespace) => match FocusedCounter::open(
                    &objects.count,
                    pid,
                    namespace,
                    CountLimits {
                        window: CountAdmissionWindow {
                            start_ns,
                            deadline_ns,
                        },
                        max_state_bytes: 24 << 20,
                        ..Default::default()
                    },
                ) {
                    Ok(c) => Some(c),
                    Err(_) => {
                        gaps.insert(ObservationGap::BpfUnavailable);
                        None
                    }
                },
                Err(_) => {
                    gaps.insert(ObservationGap::NamespaceChanged);
                    None
                }
            }
        };
        if cancel.load(Ordering::Relaxed) || Instant::now() >= setup_deadline {
            bail!("focused setup interrupted or expired");
        }
        if let Some(gap) = session
            .as_mut()
            .and_then(|s| s.set_api_window(start_ns, deadline_ns).err())
        {
            gaps.insert(gap);
            // Never keep the unbounded standalone-session default on failure.
            session = None;
        }
        if let Some(session) = &mut session {
            if let Some(preexec) = &mut preexec {
                if let Err(gap) = session.prearm_operational(
                    std::mem::take(&mut preexec.apis),
                    setup_deadline,
                    cancel,
                ) {
                    gaps.insert(gap);
                }
            }
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
        if let Some(child) = &mut owned.1 {
            child.release_retaining_exit()?;
        }
        Ok(Self {
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
            gaps,
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
            _reservation: reservation,
        })
    }
    fn apply_batch(
        &mut self,
        batch: ObservationBatch,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> anyhow::Result<()> {
        self.gaps.extend(batch.gaps.iter().copied());
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
                self.apply_batch(batch, tick_end, cancel)?;
            }
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
            self.apply_batch(batch, tick_end, cancel)?;
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
        Ok(SessionProgress::Running)
    }
    /// Fence active counting before another member's final output can block.
    pub(crate) fn stop_admission(&mut self, cancel: &AtomicBool) {
        self.signal_cut |= cancel.load(Ordering::Relaxed);
        self.pending = None;
        if let Some(counter) = &mut self.counter {
            counter.retire();
        }
        if let Some(session) = &mut self.session {
            match now_ns().and_then(|cut| {
                session
                    .set_api_window(self.start_ns, cut.min(self.deadline_ns))
                    .map_err(|_| anyhow::anyhow!("API admission stop failed"))
            }) {
                Ok(()) => (),
                Err(_) => {
                    self.gaps.insert(ObservationGap::AttachFailed);
                }
            }
        }
    }
    pub(crate) fn finish(mut self, deadline: Instant) -> anyhow::Result<FocusedResult> {
        self.pending = None;
        let end_ns = now_ns()?.min(self.deadline_ns);
        // Close admission/links first. Neither close nor equal map reads prove a
        // terminal cut; keep a single bounded cumulative final read and its gaps.
        if let Some(c) = &mut self.counter {
            c.retire();
        }
        let mut api_activity = Vec::new();
        if let Some(s) = self.session.take() {
            let batch = s.close_until(deadline);
            self.gaps.extend(batch.gaps);
            api_activity = batch
                .api_activity
                .into_iter()
                .filter(|a| a.pid == self.pid && a.starttime == self.starttime)
                .map(|a| a.row)
                .collect();
        }
        if let Some(c) = self.counter.take() {
            self.sample = c.close(deadline);
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
        let mut document = project(
            self.pid,
            CaptureWindow {
                requested_start_ns: self.start_ns,
                requested_end_ns: self.deadline_ns,
                effective_start_ns: self.start_ns,
                effective_end_ns: end_ns.max(self.start_ns),
                signal_cut: self.signal_cut,
                count_admission: Some(CountAdmissionWindow {
                    start_ns: self.start_ns,
                    deadline_ns: self.deadline_ns,
                }),
            },
            std::mem::take(&mut self.sample),
            &self.gaps.iter().copied().collect::<Vec<_>>(),
        );
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
        document.context = Some(CaptureContext {
            kernel_release: String::new(),
            wall_start_unix_ns: self.wall_start,
            wall_end_unix_ns: unix_ns(),
        });
        Ok(FocusedResult {
            document,
            child_exit,
            workload_discarded: self.workload_discarded,
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
    session.finish(Instant::now() + config.grace)
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
            limits: inventory::Limits {
                max_objects_per_process: 0,
                ..Default::default()
            },
        })
        .processes
        .remove(0)
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
    fn session_reservation_precedes_open_and_shares_parser_headroom() {
        let objects = objects();
        let bytes = FocusedSession::reservation_bytes(&objects).unwrap();
        println!("persistent session reservation {bytes} bytes on this CPU configuration");
        let pool = crate::observation_memory::MemoryPool::new(256 << 20);
        let one = pool.reserve(bytes).unwrap();
        let two = pool.reserve(bytes).unwrap();
        let stock = pool
            .reserve(crate::inventory::elf::parser_scratch_bytes(6_386_528).unwrap())
            .unwrap();
        assert!(
            pool.reserve(crate::inventory::elf::parser_scratch_bytes(128 << 20).unwrap())
                .is_none()
        );
        drop(stock);
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
}
