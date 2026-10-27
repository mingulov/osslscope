// SPDX-License-Identifier: GPL-3.0-or-later
//! One-process synchronous focused capture. Advertisements only permit bounded
//! callback attachment; open attribution and the production tail stay unknown.
use crate::{
    capture::{self, ClockPort, LiveClock},
    evidence::*,
    focused_count::{CountLimits, CountSample, FocusedCounter},
    inventory::{
        self,
        scope::{ScopedScanner, Selection},
    },
    provider_observation::{
        AliasStatus, Cacheability, ObservationBatch, ObservationGap, ObservationLimits,
        ObservationPayload, ProviderSession, VerifiedSiteCandidate, cli::Signals,
    },
    target::{OwnedTarget, TargetDisposition},
};
use anyhow::{Context, bail};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    os::unix::fs::MetadataExt,
    sync::{Arc, atomic::Ordering},
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
pub struct FocusedObjects {
    pub observation: Arc<[u8]>,
    pub count: Arc<[u8]>,
    pub count_sha256: [u8; 32],
}
pub struct FocusedResult {
    pub document: CaptureDocument,
    pub child_exit: Option<i32>,
    pub workload_discarded: bool,
}

/// No event-order proof is exposed within a batch. Retirement therefore also
/// forbids admitting that batch's candidates; only a later return can rearm.
pub fn batch_requires_retirement(batch: &ObservationBatch, pid: u32) -> bool {
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
    crate::evidence::finalize(FinalizeInput {
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
    })
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
fn observer_namespace() -> anyhow::Result<inventory::NamespaceId> {
    let metadata = std::fs::File::open("/proc/self/ns/pid")?.metadata()?;
    Ok(inventory::NamespaceId {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

// This grouping owns only the current bounded batch, never a shadow link table.
type Group = (u64, u64, u64, u64, u64, u64, String);
fn process_batch(
    session: &ProviderSession,
    counter: &mut FocusedCounter,
    batch: ObservationBatch,
    pid: u32,
    deadline_ns: u64,
    gaps: &mut BTreeSet<ObservationGap>,
    state_bytes: &mut usize,
) -> anyhow::Result<bool> {
    gaps.extend(batch.gaps.iter().copied());
    if batch_requires_retirement(&batch, pid) {
        counter.retire();
        return Ok(false);
    }
    // Reserve 8 MiB of the combined 32 MiB host allowance for controller
    // grouping/clones/projection. Charge cumulatively before allocation.
    let charge = batch.learned_sites.iter().try_fold(0usize, |n, c| {
        c.advertiser_candidates()
            .len()
            .checked_mul(1024)?
            .checked_add(2048)?
            .checked_add(n)
    });
    let admitted = charge.and_then(|n| state_bytes.checked_add(n));
    if admitted.is_none_or(|n| n > 8 << 20) {
        gaps.insert(ObservationGap::StateLimit);
        counter.retire();
        return Ok(false);
    }
    *state_bytes = admitted.unwrap();
    let mut groups: BTreeMap<Group, Vec<VerifiedSiteCandidate>> = BTreeMap::new();
    for candidate in batch.learned_sites {
        if candidate.pid() != pid {
            continue;
        }
        if candidate.alias_quality().status != AliasStatus::Complete {
            gaps.insert(ObservationGap::AmbiguousSite);
            if candidate.alias_quality().status == AliasStatus::ReadFailed {
                gaps.insert(ObservationGap::DispatchPartial);
            }
        }
        let site = candidate.site();
        groups
            .entry((
                candidate.starttime(),
                candidate.generation(),
                site.generation(),
                site.native_device(),
                site.inode(),
                site.file_offset(),
                site.object_hash().clone().into(),
            ))
            .or_default()
            .push(candidate);
    }
    let mut valid = true;
    for candidates in groups.into_values() {
        for candidate in &candidates {
            if let Err(gap) = session.revalidate_candidate(candidate) {
                gaps.insert(gap);
                counter.retire();
                return Ok(false);
            }
        }
        let installed = now_ns()?;
        if installed >= deadline_ns {
            return Ok(false);
        }
        if counter.attach_group(candidates.clone(), installed).is_err() {
            valid = false;
        }
        for candidate in &candidates {
            if let Err(gap) = session.revalidate_candidate(candidate) {
                gaps.insert(gap);
                counter.retire();
                return Ok(false);
            }
        }
    }
    Ok(valid && counter.active_site_count() > 0 && now_ns()? < deadline_ns)
}

/// Capture one selected process incarnation. Foreign PIDs acquire no custody;
/// released children are detached on expiry, cancellation and error.
pub fn run(
    config: FocusedConfig,
    target: capture::Target,
    objects: FocusedObjects,
    setup_deadline: Instant,
) -> anyhow::Result<FocusedResult> {
    config.validate()?;
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
    let signals = Signals::install().context("focused signal setup failed")?;
    let cancel = signals.cancel();
    let mut owned = match target {
        capture::Target::Pid(pid) if pid > 0 && pid <= i32::MAX as u32 => (pid, None),
        capture::Target::Pid(_) => bail!("focused target unavailable"),
        capture::Target::Spawn { argv, workload } => {
            let child =
                OwnedTarget::spawn_stopped_with_control(&argv, workload, setup_deadline, cancel)?;
            (child.pid(), Some(child))
        }
    };
    let pid = owned.0;
    if cancel.load(Ordering::Relaxed) || Instant::now() >= setup_deadline {
        bail!("focused setup interrupted or expired");
    }
    let mut scanner = ScopedScanner::new(
        Selection {
            pids: vec![pid],
            ..Default::default()
        },
        inventory::Limits {
            max_pids: 1,
            max_objects_per_process: 256,
            max_objects: 256,
            max_read_bytes: 256 << 20,
            timeout: RESCAN.min(setup_deadline.saturating_duration_since(Instant::now())),
            ..Default::default()
        },
    )
    .map_err(|_| anyhow::anyhow!("focused target scope unavailable"))?;
    // Readable target acquisition is independent of tracing availability.
    let initial = scanner.snapshot();
    let starttime = initial
        .processes
        .iter()
        .find(|p| p.pid == pid)
        .map(|p| p.starttime)
        .context("focused target unavailable")?;
    let mut gaps = BTreeSet::new();
    let mut session = match ProviderSession::open(
        ObservationLimits {
            max_processes: 1,
            max_links: 512,
            ..Default::default()
        },
        &objects.observation,
    ) {
        Ok(s) => Some(s),
        Err(gap) => {
            gaps.insert(gap);
            None
        }
    };
    if cancel.load(Ordering::Relaxed) || Instant::now() >= setup_deadline {
        bail!("focused setup interrupted or expired");
    }
    let start_ns = now_ns()?;
    let wall_start = unix_ns();
    let deadline_ns = start_ns
        .checked_add(u64::try_from(config.duration.as_nanos())?)
        .context("focused admission overflow")?;
    let end = Instant::now()
        .checked_add(config.duration)
        .context("focused duration overflow")?;
    let mut counter = match observer_namespace() {
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
    };
    if cancel.load(Ordering::Relaxed) || Instant::now() >= setup_deadline {
        bail!("focused setup interrupted or expired");
    }
    if let Some(child) = &mut owned.1 {
        child.release()?;
    }
    // The admission bound is the count program's actual start, including its
    // unattached prefix; first-call/unknown-scope gaps describe that prefix.
    let effective_start_ns = start_ns;
    let mut next_snapshot = Instant::now();
    let mut ready = false;
    let mut inventory_gaps = 0u64;
    let mut state_bytes = 0usize;
    let mut sample = CountSample::default();
    loop {
        let poll_deadline = Instant::now() + POLL;
        if cancel.load(Ordering::Relaxed) || Instant::now() >= end {
            break;
        }
        if let Some(child) = &mut owned.1 {
            // Preserve waitability until count admission/links and observer
            // resources close. finish_observation below consumes the exit.
            if child.peek_exit()?.is_some() {
                break;
            }
        }
        if Instant::now() >= next_snapshot {
            let snapshot = scanner.snapshot();
            if !snapshot.gaps.is_empty() {
                inventory_gaps = inventory_gaps.saturating_add(1);
            }
            if !snapshot
                .processes
                .iter()
                .any(|p| p.pid == pid && p.starttime == starttime)
            {
                gaps.insert(ObservationGap::ProcessChanged);
                if let Some(c) = &mut counter {
                    c.retire();
                }
                break;
            }
            if let Some(s) = &mut session {
                let batch = s.reconcile(&snapshot);
                gaps.extend(batch.gaps.iter().copied());
                if let Some(c) = &mut counter {
                    let _ =
                        process_batch(s, c, batch, pid, deadline_ns, &mut gaps, &mut state_bytes)?;
                }
            }
            next_snapshot = Instant::now() + RESCAN;
        }
        if let Some(s) = &mut session {
            let batch = s.drain(Instant::now() + DRAIN);
            gaps.extend(batch.gaps.iter().copied());
            if let Some(c) = &mut counter {
                let attached =
                    process_batch(s, c, batch, pid, deadline_ns, &mut gaps, &mut state_bytes)?;
                if attached && !ready {
                    eprintln!(
                        "osslscope: focused callbacks attached (pid={pid}, sites={})",
                        c.active_site_count()
                    );
                    ready = true;
                }
            }
        }
        if let Some(c) = &mut counter {
            sample = c.sample(Instant::now() + DRAIN);
            if sample.namespace_failures > 0 {
                c.retire();
                gaps.insert(ObservationGap::NamespaceChanged);
            }
        }
        // Work consumes the cadence budget. A delayed iteration is not made
        // timely by sleeping a fresh 100 ms after it.
        let now = Instant::now();
        if now > poll_deadline {
            gaps.insert(ObservationGap::SnapshotLag);
        }
        std::thread::sleep(poll_deadline.min(end).saturating_duration_since(now));
    }
    let end_ns = now_ns()?.min(deadline_ns);
    // Close admission/links first. Neither close nor equal map reads prove a
    // terminal cut; keep a single bounded cumulative final read and its gaps.
    if let Some(c) = &mut counter {
        c.retire();
    }
    if let Some(s) = session {
        gaps.extend(s.close().gaps);
    }
    if let Some(c) = counter {
        sample = c.close(Instant::now() + config.grace);
    }
    if inventory_gaps > 0 {
        sample.gaps.push(loss(
            "focused.inventory_partial",
            CounterSource::Discovery,
            inventory_gaps,
        ));
    }
    let mut document = project(
        pid,
        CaptureWindow {
            requested_start_ns: start_ns,
            requested_end_ns: deadline_ns,
            effective_start_ns,
            effective_end_ns: end_ns.max(effective_start_ns),
            signal_cut: cancel.load(Ordering::Relaxed),
            count_admission: Some(CountAdmissionWindow {
                start_ns,
                deadline_ns,
            }),
        },
        sample,
        &gaps.into_iter().collect::<Vec<_>>(),
    );
    let disposition = match &mut owned.1 {
        Some(child) => child.finish_observation()?,
        None => TargetDisposition::Detached { pid },
    };
    let child_exit = match disposition {
        TargetDisposition::Exited { code } => Some(code),
        _ => None,
    };
    document.disposition = Some(match (owned.1.is_some(), disposition) {
        (_, TargetDisposition::Exited { code }) => DispositionRecord::exited(code),
        (true, TargetDisposition::Detached { pid }) => DispositionRecord::detached_running(pid),
        (false, TargetDisposition::Detached { pid }) => DispositionRecord::foreign_observed(pid),
    });
    document.context = Some(CaptureContext {
        kernel_release: String::new(),
        wall_start_unix_ns: wall_start,
        wall_end_unix_ns: unix_ns(),
    });
    Ok(FocusedResult {
        document,
        child_exit,
        workload_discarded,
    })
}
