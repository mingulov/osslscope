// SPDX-License-Identifier: GPL-3.0-or-later
//! Owned, immutable, count-only foreground capture.

use super::{
    AdmissionMode, AdmissionProjection, Capture, ClockPort, Counters, Execution, FatalKind,
    LiveClock, Outcome, ReleaseAttempt, ReleaseOutcome, ReleaseStart, Target, TargetPort,
    count_effective_end, doc_context, duration_ns, project_admission, render_candidates,
};
use crate::count_session::{CloseReason, CloseRequest, CountBackend, CountSession, DiscoveredSite};
use crate::evidence::{
    self, CaptureWindow, Completeness, CounterKind, CounterSource, CounterUnits, ExpectedScope,
    FinalizeInput, LegacyCallPartition, ObjectRecord, OpensslVersion, ScopeCoverage, TargetRecord,
};
use crate::package::commands::{PackageRoleProvenance, ProfiledCount};
use crate::package::records::Digest;
use crate::target;
use anyhow::{Context as _, bail};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub(crate) struct ProfiledConfig {
    pub libcrypto: PathBuf,
    pub count_object: Option<PathBuf>,
    pub duration: Duration,
    pub timeout: Duration,
    pub grace: Duration,
}

impl ProfiledConfig {
    pub(crate) fn for_command(
        libcrypto: Option<PathBuf>,
        cfg: &super::Config,
        target: &Target,
        settle_explicit: bool,
    ) -> Result<Self, String> {
        if !matches!(target, Target::Spawn { .. })
            || cfg.harvest_object.is_some()
            || cfg.members_object.is_some()
            || cfg.dev_bundle.is_some()
            || cfg.provider.is_some()
            || cfg.builtin
            || cfg.table.is_some()
            || cfg.force_offset.is_some()
            || cfg.provider_enrollment.is_some()
            || settle_explicit
            || !cfg.image_digest.is_empty()
        {
            return Err("v0.2 supports count-only run; PID, discovery/provider, bundle and settle modes are deferred".into());
        }
        let libcrypto = libcrypto.ok_or("v0.2 requires --libcrypto PATH")?;
        let config = Self {
            libcrypto,
            count_object: cfg.count_object.clone(),
            duration: cfg.duration,
            timeout: cfg.harvest_timeout,
            grace: cfg.grace,
        };
        config
            .validate()
            .map_err(|_| "invalid preview duration, timeout or grace")?;
        Ok(config)
    }

    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        if self.duration.is_zero()
            || self.duration > Duration::from_secs(3600)
            || self.timeout > Duration::from_secs(120)
            || self.grace > Duration::from_secs(30)
        {
            bail!("invalid preview duration, timeout or grace");
        }
        Ok(())
    }
}

pub(crate) fn run_profiled_before(
    cfg: &ProfiledConfig,
    target: Target,
    count: ProfiledCount,
    setup_deadline: Option<Instant>,
) -> anyhow::Result<Capture> {
    cfg.validate()?;
    let Target::Spawn { argv, workload } = target else {
        bail!("preview accepts only an owned foreground run");
    };
    let deadline = setup_deadline.unwrap_or(
        Instant::now()
            .checked_add(cfg.timeout)
            .context("preview setup deadline overflow")?,
    );
    super::arm_signals();
    let check = || {
        if super::interrupted() || Instant::now() >= deadline {
            bail!("preview setup cancelled or timed out");
        }
        Ok(())
    };
    check()?;
    let profile = crate::profile::admit(&cfg.libcrypto)?;
    crate::profile::admit_initial_pid_namespaces()?;
    check()?;
    // Acquisition order is essential: fork the stopped child before preparing
    // any count owner, program, map or link. No fork follows this prefix.
    let mut child = target::OwnedTarget::spawn_stopped_with_control(
        &argv,
        workload,
        deadline,
        &super::INTERRUPTED,
    )?;
    let prepared = (|| {
        check()?;
        crate::profile::admit_child_pid_namespace(child.pid())?;
        profile.verify_backing()?;
        check()?;
        super::prepare_count_backend_interruptible(
            Arc::clone(&count.object_bytes),
            count.object_sha256,
            child.pid(),
            Arc::new(crate::count_owner::CountForkBarrier::new()),
            deadline,
            Some(&super::INTERRUPTED),
        )
        .map_err(anyhow::Error::from)
    })();
    let backend = match prepared {
        Ok(backend) => backend,
        Err(error) => {
            child
                .resolve_setup_failure()
                .context("preview setup child cleanup failed")?;
            return Err(error);
        }
    };
    let mut session = CountSession::new(child.pid(), backend);
    let ctx = RunContext {
        cfg,
        profile_id: &profile.profile_id,
        kernel_release: &profile.kernel_release,
        object: &profile.object,
        sites: &profile.sites,
        locator: &profile.locator,
        count_provenance: PackageRoleProvenance {
            selection: count.selection,
            sha256: Digest(count.object_sha256),
            bytes: count.object_bytes.len() as u64,
            build_input_id: None,
        },
        setup_deadline: deadline,
        cancelled: &super::interrupted,
    };
    // profile retains the exact opened file for the entire observation. The
    // owner's pin independently checks and retains that same dev/inode.
    observe_profiled(&ctx, &mut child, &mut session, &LiveClock)
}

struct RunContext<'a> {
    cfg: &'a ProfiledConfig,
    profile_id: &'a str,
    kernel_release: &'a str,
    object: &'a ObjectRecord,
    sites: &'a [DiscoveredSite],
    locator: &'a Path,
    count_provenance: PackageRoleProvenance,
    setup_deadline: Instant,
    cancelled: &'a dyn Fn() -> bool,
}

/// The preview accepts unknown final-writer coverage, never a false completion
/// witness. Only this sole, expected capability gap is nonfatal; the immutable
/// terminal and every loss counter remain unchanged. Scan all channels because
/// runtime_failure retains only the first failure.
fn only_unreviewed_completion(terminal: &crate::count_session::CountTerminal) -> bool {
    use crate::count_owner::{
        CleanupState, CountOperation, FailureClass, KernelApplicability, OwnerFailure,
        ProfileFailure, QuiescenceReason, ReadStatus, ResourceId, ResourceState, SealBracket,
        StopResult, WriterCompletion,
    };
    let expected = OwnerFailure::engine(CountOperation::Close, FailureClass::Profile);
    let receipt = &terminal.receipt;
    terminal.runtime_failure == Some(expected)
        && receipt.kernel_profile == KernelApplicability::Unknown(ProfileFailure::UnboundBuild)
        && receipt.writers == WriterCompletion::Unknown(QuiescenceReason::Profile)
        && receipt.failures.operations[CountOperation::Close as usize] == Some(expected)
        && receipt
            .failures
            .operations
            .iter()
            .flatten()
            .all(|f| *f == expected)
        && receipt.failures.components.iter().all(Option::is_none)
        && matches!(receipt.seal, SealBracket { before_ns: Some(before), after_ns: Some(after), result: StopResult::Stopped } if before <= after)
        && receipt.host_writes_sealed
        && receipt.final_references.file
        && receipt.final_references.bpf_link
        && receipt.read_status == ReadStatus::Complete
        && receipt.checkpoint.is_some()
        && receipt
            .snapshot_binding
            .is_some_and(|binding| !binding.immutable)
        && receipt.manifest.len() == receipt.close_outcomes.len()
        && receipt
            .manifest
            .iter()
            .zip(&receipt.close_outcomes)
            .all(|(record, close)| {
                record.id == close.id
                    && record.close_state == ResourceState::CloseReturned
                    && record.close_errno.is_none()
                    && close.state == ResourceState::CloseReturned
                    && close.errno.is_none()
                    && close
                        .issued_at
                        .zip(close.returned_at)
                        .is_some_and(|(issued, returned)| {
                            issued <= returned && returned < receipt.deadline
                        })
            })
        && match &receipt.cleanup_state {
            CleanupState::Complete => true,
            CleanupState::Failed(_) => false,
            CleanupState::Pending(summary) => {
                summary.sealed
                    && summary.resources.iter().all(|r| {
                        r.errno.is_none()
                            && (matches!(
                                r.state,
                                ResourceState::Unused | ResourceState::CloseReturned
                            ) || (r.state == ResourceState::Held
                                && !matches!(r.resource, ResourceId::Link(_))))
                    })
            }
        }
        && !terminal
            .retained_drain
            .counters
            .iter()
            .any(|c| c.name == "count.reference_inventory_invalid" && c.value != 0)
}

fn observe_profiled<T: TargetPort, B: CountBackend, C: ClockPort>(
    ctx: &RunContext<'_>,
    target: &mut T,
    count: &mut CountSession<B>,
    clock: &C,
) -> anyhow::Result<Capture> {
    let check_setup = || {
        if (ctx.cancelled)() || clock.now() >= ctx.setup_deadline {
            bail!("preview setup cancelled or timed out");
        }
        Ok(())
    };
    let setup = (|| {
        check_setup()?;
        if !target.is_owned()
            || target.pid() == 0
            || count.pid() != target.pid()
            || count.backend().ready().writer_object_identity != ctx.count_provenance.sha256.0
        {
            bail!("preview owner, target or count identity mismatch");
        }
        let now = clock
            .checked_monotonic_ns()
            .context("preview monotonic clock unavailable")?;
        let report = count.attach_preplanned(ctx.sites, ctx.locator, now, ctx.setup_deadline)?;
        if report.attached as usize != ctx.sites.len()
            || !report.missed.is_empty()
            || report.unresolved != 0
        {
            bail!("preview catalogue could not be fully attached");
        }
        check_setup()?;
        let start = clock
            .checked_monotonic_ns()
            .context("preview monotonic clock unavailable")?;
        let end = start
            .checked_add(duration_ns(ctx.cfg.duration))
            .context("preview window overflow")?;
        count.open_window(start, end, ctx.setup_deadline)?;
        check_setup()?;
        let before = ReleaseStart {
            monotonic_ns: clock
                .checked_monotonic_ns()
                .context("preview release clock unavailable")?,
            wall: clock.wall_now(),
            instant: clock.now(),
        };
        if before.monotonic_ns >= end {
            bail!("preview count window expired before release");
        }
        let requested_end = before
            .monotonic_ns
            .checked_add(duration_ns(ctx.cfg.duration))
            .context("preview requested window overflow")?;
        target.release_retaining_exit()?;
        let release = ReleaseAttempt {
            before,
            after_ns: clock.checked_monotonic_ns(),
            outcome: ReleaseOutcome::Succeeded,
        };
        Ok((release, end, requested_end))
    })();
    let (release, programmed_end, requested_end) = match setup {
        Ok(ready) => ready,
        Err(error) => {
            count.terminal_shared(CloseRequest {
                started_at: clock.now(),
                grace: ctx.cfg.grace,
                reason: CloseReason::SetupAbort,
            });
            if let Some(owned) = target.take_setup_target() {
                match count.backend_mut().retain_setup_target(owned) {
                    Ok(termination) => {
                        termination.context("preview setup child termination failed")?
                    }
                    Err(mut owned) => owned
                        .resolve_setup_failure()
                        .context("preview setup child cleanup failed")?,
                }
            } else {
                target
                    .resolve_setup_failure()
                    .context("preview setup child cleanup failed")?;
            }
            return Err(error);
        }
    };
    let mut failure = None;
    let mut last_established = release.before.monotonic_ns;
    let reason = loop {
        if (ctx.cancelled)() {
            break CloseReason::Interrupted;
        }
        let Some(now) = clock
            .checked_monotonic_ns()
            .filter(|now| *now >= last_established)
        else {
            failure = Some("preview monotonic clock failed");
            break CloseReason::Failure;
        };
        last_established = now;
        if now >= programmed_end {
            break CloseReason::Expired;
        }
        match target.peek_exit() {
            Ok(Some(_)) => break CloseReason::OwnedExit,
            Ok(None) => {}
            Err(_) => {
                failure = Some("preview owned-child wait failed");
                break CloseReason::Failure;
            }
        }
        clock.sleep(Duration::from_nanos(programmed_end - now).min(Duration::from_millis(5)));
    };
    let wall_end = clock.wall_now();
    let drain_start = clock.now();
    // Select the existing canonical terminal before the first consuming wait.
    // Pending/failed cleanup remains visible in its typed loss counters; this
    // ordering is not a claim of last-writer finality or a hard close deadline.
    let terminal = count.terminal_shared(CloseRequest {
        started_at: drain_start,
        grace: ctx.cfg.grace,
        reason,
    });
    let drain_wall_us = clock
        .now()
        .saturating_duration_since(drain_start)
        .as_micros()
        .min(u64::MAX as u128) as u64;
    let endpoint = count_effective_end(
        reason,
        programmed_end,
        terminal.receipt.seal,
        last_established,
    );
    if terminal.runtime_failure.is_some() && !only_unreviewed_completion(&terminal) {
        failure.get_or_insert("preview count owner failed");
    }
    let disposition = match target.finish_observation() {
        Ok(d) => Some(d),
        Err(_) => {
            failure.get_or_insert("preview child disposition failed");
            None
        }
    };
    let drain = &terminal.retained_drain;
    let mut window = CaptureWindow {
        requested_start_ns: release.before.monotonic_ns,
        requested_end_ns: requested_end,
        effective_start_ns: release.before.monotonic_ns,
        effective_end_ns: endpoint.end_ns.max(release.before.monotonic_ns),
        signal_cut: reason == CloseReason::Interrupted,
        count_admission: None,
    };
    let programmed = count.programmed_admission().copied();
    let mode = if reason == CloseReason::Expired && failure.is_none() {
        AdmissionMode::Ordinary
    } else {
        AdmissionMode::Degraded
    };
    match project_admission(programmed.as_ref(), Some(&release), &window, drain, mode) {
        Ok(AdmissionProjection::RenderBound(bound)) => window.count_admission = Some(bound),
        Err(mut binding) => {
            // Preserve the existing canonical receipt and rejected-row summary
            // for failure handling, without publishing falsely timed assets.
            binding.terminal = Some(Arc::clone(&terminal));
            return Err(binding.into());
        }
        Ok(_) => {
            return Err(super::WindowBindingFailure {
                reason: super::WindowBindingReason::InvalidEndpoint,
                terminal: Some(Arc::clone(&terminal)),
                rejected: super::RejectedPrefix::from_drain(drain),
            }
            .into());
        }
    }
    let mut counters = drain.counters.clone();
    if endpoint.uncertain {
        counters.push(super::typed_counter(
            "capture.close_time_uncertain",
            CounterKind::Loss,
            CounterUnits::Events,
            CounterSource::Drain,
            1,
        ));
    }
    if reason == CloseReason::Expired {
        counters.push(super::typed_counter(
            "capture.over_budget",
            CounterKind::Loss,
            CounterUnits::Events,
            CounterSource::Lifecycle,
            1,
        ));
    }
    let child_exit = match disposition {
        Some(target::TargetDisposition::Exited { code }) => Some(code),
        _ => None,
    };
    let disposition_record = disposition.map(|d| match d {
        target::TargetDisposition::Exited { code } => evidence::DispositionRecord::exited(code),
        target::TargetDisposition::Detached { pid } => {
            evidence::DispositionRecord::detached_running(pid)
        }
    });
    let mut document = evidence::finalize(FinalizeInput {
        window,
        sites: drain.current.clone(),
        fenced: drain.fenced.clone(),
        objects: vec![ctx.object.clone()],
        coverage: vec![ScopeCoverage {
            scope: format!("profile:{}", ctx.profile_id),
            expected: ExpectedScope::Unknown,
            discovered: ctx.sites.len() as u64,
            attached: count.cookie_count() as u64,
        }],
        counters,
        fatal: failure.map(|why| evidence::FatalKind::Runtime(why.into())),
        target: TargetRecord::new(
            target.pid(),
            "owned-process".into(),
            String::new(),
            String::new(),
        ),
        openssl: OpensslVersion::unknown(),
        disposition: disposition_record,
        policy: None,
        legacy_partition: LegacyCallPartition {
            non_legacy_exclusive: drain.total_calls(),
            ..Default::default()
        },
        engine_observations: Vec::new(),
        traversal: None,
    });
    document.context = Some(doc_context(
        ctx.kernel_release,
        release.before.wall,
        wall_end,
    ));
    document.count_object = Some(ctx.count_provenance.clone());
    let executions = document
        .sites
        .iter()
        .map(|s| {
            let (id, aliases) = render_candidates(&s.candidates, s.site.offset);
            Execution {
                cookie: count
                    .cookie_for(s.site.device, s.site.inode, s.site.offset)
                    .expect("attributed CountSession row retains its cookie"),
                id,
                aliases,
                count: s.calls,
                first_ns: s.first_ns,
                last_ns: s.last_ns,
            }
        })
        .collect();
    let outcome = match &document.status {
        Completeness::Complete => Outcome::Complete,
        Completeness::Partial { .. } => Outcome::Partial,
        Completeness::Fatal { .. } => Outcome::Fatal(FatalKind::Runtime(
            failure.unwrap_or("preview count failure").into(),
        )),
    };
    Ok(Capture {
        programmed_admission: programmed,
        release_attempt: Some(release),
        failure_context: None,
        target_pid: target.pid(),
        target_comm: "owned-process".into(),
        window_planned: ctx.cfg.duration,
        window_actual: Duration::from_nanos(
            window
                .effective_end_ns
                .saturating_sub(window.effective_start_ns),
        ),
        outcome,
        reasons: vec!["unknown-denominator".into()],
        executions,
        stale: Vec::new(),
        counters: Counters {
            over_budget: u64::from(reason == CloseReason::Expired),
            ..Default::default()
        },
        child_exit,
        drain_wall_us,
        harvest_doc: serde_json::Value::Null,
        legacy: serde_json::Value::Null,
        window_start_wall: release.before.wall,
        window_end_wall: wall_end,
        kernel_release: ctx.kernel_release.into(),
        target_cmdline: String::new(),
        target_container_id: String::new(),
        provider_build_id: String::new(),
        provider_path: "stock-libcrypto".into(),
        image_digest: String::new(),
        document,
        disposition,
        traversal: None,
        selected_objects: None,
    })
}

#[cfg(test)]
pub(crate) fn preview_document_for_test(definite: bool) -> crate::evidence::CaptureDocument {
    tests::preview_document(definite)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::count_session::*;
    use crate::evidence::{CandidateCoverage, Completeness, GapReason};
    use crate::package::commands::{PackageRoleProvenance, RoleSelection};
    use crate::package::records::Digest;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;
    use std::sync::Arc;
    use std::time::SystemTime;

    type Log = Rc<RefCell<Vec<&'static str>>>;

    // Thin instrumentation around the existing owner model, not another owner.
    #[derive(Clone, Copy)]
    enum ModelCase {
        DefiniteSite,
        None,
        UnknownTail,
        InvalidTimestamp,
        CloseFailure,
        UnboundProfile,
        UnboundReadFailure,
        UnboundComponentFailure,
        UnboundInventoryFailure,
    }

    struct TracedBackend {
        inner: FakeCountBackend,
        log: Log,
        invalid_timestamp: bool,
    }
    impl CountBackend for TracedBackend {
        type Link = LinkToken;
        fn ready(&self) -> &Ready {
            self.inner.ready()
        }
        fn attach(&mut self, r: AttachRequest) -> CommandResult<AttachAck<LinkToken>> {
            self.log.borrow_mut().push("attach");
            self.inner.attach(r)
        }
        fn open_window(&mut self, r: OpenRequest) -> CommandResult<OpenReceipt> {
            self.log.borrow_mut().push("open");
            self.inner.open_window(r)
        }
        fn set_generation(&mut self, r: GenerationRequest) -> CommandResult<()> {
            self.inner.set_generation(r)
        }
        fn drain(&mut self, r: ReadRequest) -> CommandResult<Arc<RawSnapshot>> {
            self.inner.drain(r)
        }
        fn terminal_request(&mut self, d: Instant, f: ControllerFrontier) -> TerminalRequest {
            self.inner.terminal_request(d, f)
        }
        fn terminal(&mut self, r: TerminalRequest) -> RawTerminal {
            self.log.borrow_mut().push("close");
            if let Some(&(pid, _, start, _)) = self.inner.programmed().last() {
                self.inner.fire(pid as u32, 0, start + 1, 32);
                self.inner.fire(pid as u32 + 1, 0, start + 1, 100);
                if self.invalid_timestamp {
                    self.inner.inject_row(
                        0,
                        0,
                        osslscope_ebpf_common::CountValue {
                            count: 1,
                            first_ns: start - 1,
                            last_ns: start - 1,
                        },
                    );
                }
            }
            self.inner.terminal(r)
        }
        fn progress(&self) -> Option<RawCheckpoint> {
            self.inner.progress()
        }
        fn fork_permit(&self, d: Instant) -> Result<CountForkPermit<'_>, ForkBlocked> {
            self.inner.fork_permit(d)
        }
    }

    struct Child {
        log: Log,
        polls: Cell<u32>,
        fail_release: bool,
        fail_wait: bool,
        remains_alive: bool,
    }
    impl TargetPort for Child {
        fn pid(&self) -> u32 {
            42
        }
        fn is_owned(&self) -> bool {
            true
        }
        fn release(&mut self) -> anyhow::Result<()> {
            self.log.borrow_mut().push("release");
            if self.fail_release {
                anyhow::bail!("controlled release failure");
            }
            Ok(())
        }
        fn poll_exit(&mut self) -> anyhow::Result<Option<i32>> {
            panic!("consuming poll before terminal")
        }
        fn peek_exit(&self) -> anyhow::Result<Option<i32>> {
            self.log.borrow_mut().push("peek");
            let n = self.polls.get();
            self.polls.set(n + 1);
            if self.fail_wait {
                anyhow::bail!("controlled wait failure");
            }
            if n == 0 {
                self.log.borrow_mut().push("exec");
            }
            Ok((n > 0 && !self.remains_alive).then_some(0))
        }
        fn resolve_setup_failure(&mut self) -> anyhow::Result<()> {
            self.log.borrow_mut().push("cleanup");
            Ok(())
        }
        fn finish_observation(&mut self) -> anyhow::Result<target::TargetDisposition> {
            self.log.borrow_mut().push("reap");
            Ok(if self.remains_alive {
                target::TargetDisposition::Detached { pid: 42 }
            } else {
                target::TargetDisposition::Exited { code: 0 }
            })
        }
        fn verify(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    struct Clock {
        now: Cell<u64>,
        base: Instant,
    }
    impl ClockPort for Clock {
        fn checked_monotonic_ns(&self) -> Option<u64> {
            Some(self.now.get())
        }
        fn monotonic_ns(&self) -> u64 {
            self.now.get()
        }
        fn now(&self) -> Instant {
            self.base + Duration::from_nanos(self.now.get())
        }
        fn wall_now(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH + Duration::from_nanos(self.now.get())
        }
        fn sleep(&self, d: Duration) {
            self.now.set(self.now.get() + d.as_nanos() as u64);
        }
    }

    fn run_model(
        fail_release: bool,
        fail_wait: bool,
        remains_alive: bool,
        signal: bool,
        fault: ModelCase,
    ) -> (
        anyhow::Result<Capture>,
        Vec<&'static str>,
        CountSession<TracedBackend>,
    ) {
        let (_backing, locator, mut site) = crate::count_session::tests::preplanned_fixture();
        // Two possible meanings, one physical site. Unknown must stay unknown.
        let mut alias = site.candidates[0].clone();
        alias.algorithm_classes = vec!["AES-256-GCM".into()];
        if !matches!(fault, ModelCase::DefiniteSite) {
            site.candidates.push(alias);
            site.candidates_coverage = CandidateCoverage::Unknown;
        }
        let object = ObjectRecord {
            id: site.site.object.clone(),
            device: site.site.device,
            inode: site.site.inode,
            display_locator: "fixture-library".into(),
        };
        let sites = [site];
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut inner = FakeCountBackend::new();
        inner.set_modeled_seal(Some(5_000_100), Some(5_000_101));
        match fault {
            ModelCase::UnknownTail => inner.terminal_faults(FakeTerminalFaults {
                quiescence_unknown: true,
                ..Default::default()
            }),
            ModelCase::CloseFailure => inner.terminal_faults(FakeTerminalFaults {
                close_errno: Some(libc::EIO),
                ..Default::default()
            }),
            ModelCase::UnboundProfile
            | ModelCase::UnboundReadFailure
            | ModelCase::UnboundComponentFailure
            | ModelCase::UnboundInventoryFailure => inner.terminal_faults(FakeTerminalFaults {
                unbound_profile: true,
                read_error: matches!(fault, ModelCase::UnboundReadFailure),
                admitted_unavailable: matches!(fault, ModelCase::UnboundComponentFailure),
                forget_frontier: matches!(fault, ModelCase::UnboundInventoryFailure),
                ..Default::default()
            }),
            _ => {}
        }
        let mut count = CountSession::new(
            42,
            TracedBackend {
                inner,
                log: Rc::clone(&log),
                invalid_timestamp: matches!(fault, ModelCase::InvalidTimestamp),
            },
        );
        let mut child = Child {
            log: Rc::clone(&log),
            polls: Cell::new(0),
            fail_release,
            fail_wait,
            remains_alive,
        };
        let clock = Clock {
            now: Cell::new(100),
            base: Instant::now(),
        };
        let cfg = ProfiledConfig {
            libcrypto: PathBuf::from("unused-model"),
            count_object: None,
            duration: Duration::from_millis(20),
            timeout: Duration::from_secs(1),
            grace: Duration::from_secs(1),
        };
        let cancelled = || signal && child_poll_signal(&log);
        let ctx = RunContext {
            cfg: &cfg,
            profile_id: "fixture-preview",
            kernel_release: "model",
            object: &object,
            sites: &sites,
            locator: &locator,
            count_provenance: PackageRoleProvenance {
                selection: RoleSelection::OperatorExplicit,
                sha256: Digest([0x48; 32]),
                bytes: 128,
                build_input_id: None,
            },
            setup_deadline: clock.base + Duration::from_secs(1),
            cancelled: &cancelled,
        };
        let result = observe_profiled(&ctx, &mut child, &mut count, &clock);
        let events = log.borrow().clone();
        (result, events, count)
    }
    fn child_poll_signal(log: &Log) -> bool {
        log.borrow().contains(&"peek")
    }

    pub(crate) fn preview_document(definite: bool) -> crate::evidence::CaptureDocument {
        run_model(
            false,
            false,
            false,
            false,
            if definite {
                ModelCase::DefiniteSite
            } else {
                ModelCase::None
            },
        )
        .0
        .unwrap()
        .document
    }

    #[test]
    fn owned_exit_is_not_reaped_before_count_close() {
        let (result, events, _) = run_model(false, false, false, false, ModelCase::None);
        let capture = result.unwrap();
        let pos = |s| events.iter().position(|x| *x == s).unwrap();
        assert!(pos("open") < pos("release"));
        assert!(pos("peek") < pos("close") && pos("close") < pos("reap"));
        assert_eq!(capture.child_exit, Some(0));
        assert_eq!(capture.document.total_calls(), 32);
    }

    #[test]
    fn count_only_never_constructs_discovery() {
        let (result, _, _) = run_model(false, false, false, false, ModelCase::None);
        let capture = result.unwrap();
        assert!(capture.traversal.is_none() && capture.selected_objects.is_none());
        assert_eq!(capture.harvest_doc, serde_json::Value::Null);
        let provenance = capture.document.count_object.as_ref().unwrap();
        assert_eq!(provenance.sha256, Digest([0x48; 32]));
        assert_eq!(provenance.selection, RoleSelection::OperatorExplicit);
        assert_eq!(capture.target_comm, "owned-process");
    }

    #[test]
    fn exec_keeps_original_group_and_partial_scope() {
        let (result, events, count) = run_model(false, false, false, false, ModelCase::None);
        let capture = result.unwrap();
        assert!(events.contains(&"exec"));
        assert_eq!(count.backend().inner.programmed().len(), 1);
        assert_eq!(count.backend().inner.programmed()[0].0, 42);
        assert_eq!(count.generation(), 0);
        assert_eq!(capture.document.sites[0].candidates.len(), 2);
        assert_eq!(
            capture.document.sites[0].candidates_coverage,
            CandidateCoverage::Unknown
        );
        assert!(
            matches!(&capture.document.status, Completeness::Partial { reasons } if reasons.iter().any(|r| matches!(r, GapReason::UnknownDenominator { scope } if scope == "profile:fixture-preview")))
        );
    }

    #[test]
    fn release_failure_closes_count_before_setup_cleanup() {
        let (result, events, _) = run_model(true, false, false, false, ModelCase::None);
        assert!(result.is_err());
        let close = events.iter().position(|x| *x == "close").unwrap();
        let cleanup = events.iter().position(|x| *x == "cleanup").unwrap();
        assert!(close < cleanup);
        assert!(!events.contains(&"reap"));
    }

    #[test]
    fn wait_failure_keeps_positive_evidence() {
        let (result, _, _) = run_model(false, true, false, false, ModelCase::None);
        let capture = result.unwrap();
        assert_eq!(capture.document.total_calls(), 32);
        assert!(matches!(
            capture.document.status,
            Completeness::Fatal {
                kind: evidence::FatalKind::Runtime(_),
                ..
            }
        ));
    }

    #[test]
    fn unknown_tail_keeps_positive_counts_and_explicit_loss() {
        let (result, _, _) = run_model(false, false, false, false, ModelCase::UnknownTail);
        let capture = result.unwrap();
        assert_eq!(capture.document.total_calls(), 32);
        assert!(
            capture
                .document
                .counters
                .iter()
                .any(|c| c.name == "count.quiescence_unknown" && c.value > 0)
        );
        assert!(matches!(
            capture.document.status,
            Completeness::Partial { .. }
        ));
    }

    #[test]
    fn failed_close_keeps_positive_counts_and_runtime_failure() {
        let (result, _, _) = run_model(false, false, false, false, ModelCase::CloseFailure);
        let capture = result.unwrap();
        assert_eq!(capture.document.total_calls(), 32);
        assert!(matches!(
            capture.document.status,
            Completeness::Fatal {
                kind: evidence::FatalKind::Runtime(_),
                ..
            }
        ));
    }

    #[test]
    fn unbound_completion_profile_preserves_partial_evidence_and_original_receipt() {
        use crate::count_owner::{
            KernelApplicability, ProfileFailure, QuiescenceReason, WriterCompletion,
        };
        let (result, _, count) = run_model(false, false, false, false, ModelCase::UnboundProfile);
        let capture = result.unwrap();
        assert_eq!(capture.document.total_calls(), 32);
        assert!(matches!(
            capture.document.status,
            Completeness::Partial { .. }
        ));
        let terminal = count.shared_terminal(count.terminal_id().unwrap());
        assert_eq!(
            terminal.receipt.kernel_profile,
            KernelApplicability::Unknown(ProfileFailure::UnboundBuild)
        );
        assert_eq!(
            terminal.receipt.writers,
            WriterCompletion::Unknown(QuiescenceReason::Profile)
        );
        assert!(terminal.runtime_failure.is_some());
        for name in [
            "count.quiescence_unknown",
            "count.close_failed",
            "count.owner_failed",
        ] {
            assert!(
                capture
                    .document
                    .counters
                    .iter()
                    .any(|c| c.name == name && c.value == 1),
                "retain {name}"
            );
        }
    }

    #[test]
    fn unbound_profile_never_masks_read_component_or_inventory_failure() {
        for fault in [
            ModelCase::UnboundReadFailure,
            ModelCase::UnboundComponentFailure,
            ModelCase::UnboundInventoryFailure,
        ] {
            let (result, events, count) = run_model(false, false, false, false, fault);
            assert!(events.contains(&"release") && events.contains(&"close"));
            let terminal = count.shared_terminal(count.terminal_id().unwrap());
            assert!(terminal.runtime_failure.is_some());
            match result {
                Ok(capture) => assert!(matches!(
                    capture.document.status,
                    Completeness::Fatal { .. }
                )),
                Err(error) => assert!(
                    error
                        .downcast_ref::<super::super::WindowBindingFailure>()
                        .is_some()
                ),
            }
        }
    }

    #[test]
    fn invalid_window_binding_retains_canonical_count() {
        let (result, events, _) =
            run_model(false, false, false, false, ModelCase::InvalidTimestamp);
        let error = result
            .err()
            .expect("pre-request rows must refuse publication");
        let binding = error
            .downcast_ref::<super::super::WindowBindingFailure>()
            .expect("retain the typed binding failure");
        assert_eq!(
            binding
                .terminal
                .as_ref()
                .unwrap()
                .retained_drain
                .total_calls(),
            33
        );
        assert!(
            events.iter().position(|x| *x == "close").unwrap()
                < events.iter().position(|x| *x == "reap").unwrap()
        );
    }

    #[test]
    fn signal_and_expiry_close_then_leave_live_child_running() {
        for signal in [false, true] {
            let (result, events, _) = run_model(false, false, true, signal, ModelCase::None);
            let capture = result.unwrap();
            assert_eq!(
                capture.disposition,
                Some(target::TargetDisposition::Detached { pid: 42 })
            );
            assert_eq!(capture.document.window.signal_cut, signal);
            assert!(
                events.iter().position(|x| *x == "close").unwrap()
                    < events.iter().position(|x| *x == "reap").unwrap()
            );
        }
    }
}
