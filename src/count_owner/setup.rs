//! SPDX-License-Identifier: GPL-3.0-or-later
//! Independent, data-only observation of the existing Count owner.
use super::*;
use crate::capture::{BoundaryFailureClass, BoundaryStage};
use crate::capture_setup::{SetupControl, SetupFailure};

#[derive(Clone)]
pub(crate) struct CountPrepareControl(SetupControl);
impl CountPrepareControl {
    pub(crate) fn new(control: SetupControl) -> Self {
        Self(control)
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.0.deadline()
    }
    pub(crate) fn abandon(&self) {
        self.0.abandon();
    }
    pub(crate) fn check(&self) -> Result<(), OwnerFailure> {
        self.0.check(BoundaryStage::Setup).map_err(|failure| {
            let class = match failure {
                SetupFailure::Cancelled { .. } => FailureClass::Cancelled,
                SetupFailure::Boundary(f) if f.class == BoundaryFailureClass::Timeout => {
                    FailureClass::Deadline
                }
                _ => FailureClass::Capacity,
            };
            OwnerFailure::engine(CountOperation::Load, class)
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CountSetupPhase {
    NotInvoked,
    Preflight,
    OwnerPublished,
    OwnerStarted,
    Ready,
    Failed,
}
// One-way physical-disposal permission; it has no edge back to app state.
pub(crate) struct DisposalHold(AtomicBool);
impl DisposalHold {
    fn new() -> Self {
        Self(AtomicBool::new(false))
    }
    pub(super) fn permitted(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
    pub(crate) fn release_commit(&self, _: &crate::capture::ReleaseCommit) {
        self.permit();
    }
    fn permit(&self) {
        self.0.store(true, Ordering::Release);
    }
}
struct JournalState {
    disposal: Option<Arc<DisposalHold>>,
    phase: CountSetupPhase,
    shared: Option<Arc<Shared>>,
    abandoned: bool,
    seal_deadline: Option<Instant>,
    failure: Option<CountPrepareFailure>,
    launch: Option<Arc<OwnerLaunchState>>,
}
#[derive(Clone)]
pub(crate) struct CountSetupJournal(Arc<Mutex<JournalState>>);
#[derive(Clone)]
pub(crate) struct CountSetupWatch(CountSetupJournal);
#[derive(Debug, Clone, Copy)]
pub(crate) struct CountSetupProgress {
    pub(crate) phase: CountSetupPhase,
    pub(crate) owner_epoch: Option<OwnerEpoch>,
    pub(crate) cleanup_ticket: Option<CleanupTicket>,
    pub(crate) cleanup: Option<CleanupProgress>,
    pub(crate) open_pending: bool,
    pub(crate) late_ready: bool,
    pub(crate) known_failure: Option<OwnerFailure>,
    pub(crate) prepare_failure: Option<CountPrepareFailure>,
    pub(crate) owner_cleanup_acknowledged: bool,
    pub(crate) owner_task_disposed: bool,
}
impl CountSetupJournal {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Mutex::new(JournalState {
            disposal: None,
            phase: CountSetupPhase::NotInvoked,
            shared: None,
            abandoned: false,
            seal_deadline: None,
            failure: None,
            launch: None,
        })))
    }
    pub(crate) fn new_held() -> Self {
        let journal = Self::new();
        locked(&journal.0).disposal = Some(Arc::new(DisposalHold::new()));
        journal
    }
    pub(crate) fn disposal_hold(&self) -> Option<Arc<DisposalHold>> {
        locked(&self.0).disposal.clone()
    }
    pub(crate) fn watch(&self) -> CountSetupWatch {
        CountSetupWatch(self.clone())
    }
    pub(crate) fn begin(&self) {
        let mut state = locked(&self.0);
        if state.phase == CountSetupPhase::NotInvoked {
            state.phase = CountSetupPhase::Preflight;
        }
    }
    pub(crate) fn failed(&self, failure: CountPrepareFailure) {
        let mut state = locked(&self.0);
        state.failure.get_or_insert(failure);
        if state.shared.is_none() {
            state.phase = CountSetupPhase::Failed;
        }
    }
    pub(super) fn launch(&self, launch: Arc<OwnerLaunchState>) {
        let mut state = locked(&self.0);
        assert!(state.launch.is_none(), "single owner launch");
        state.launch = Some(launch);
    }
    /// Publication and token admission serialize with independent abandonment.
    /// The journal retains this Arc until its last observer has gone away.
    pub(crate) fn check(&self, control: &CountPrepareControl) -> Result<(), OwnerFailure> {
        control.check()?;
        let state = locked(&self.0);
        if state.abandoned || state.seal_deadline.is_some() {
            return Err(OwnerFailure::engine(
                CountOperation::Load,
                FailureClass::Cancelled,
            ));
        }
        Ok(())
    }
    pub(super) fn publish(
        &self,
        shared: &Arc<Shared>,
        token: CountSetupAdmission,
        control: &CountPrepareControl,
    ) -> Result<(), OwnerFailure> {
        {
            let mut state = locked(&self.0);
            control.check()?;
            if state.abandoned || state.seal_deadline.is_some() || state.shared.is_some() {
                return Err(OwnerFailure::engine(
                    CountOperation::Load,
                    FailureClass::Cancelled,
                ));
            }
            shared.barrier.admit_setup(token, shared.epoch)?;
            state.shared = Some(Arc::clone(shared));
            state.phase = CountSetupPhase::OwnerPublished;
        }
        // A racing abort sees the same actual Shared, never a placeholder.
        self.forward_abort();
        Ok(())
    }
    fn forward_abort(&self) {
        let (shared, abandoned, deadline) = {
            let state = locked(&self.0);
            (state.shared.clone(), state.abandoned, state.seal_deadline)
        };
        if let Some(shared) = shared {
            if let Some(deadline) = deadline {
                shared.seal(deadline);
            }
            if abandoned {
                shared.abandon();
            }
        }
    }
    pub(super) fn started(&self) {
        locked(&self.0).phase = CountSetupPhase::OwnerStarted;
    }
    pub(super) fn ready(&self) {
        locked(&self.0).phase = CountSetupPhase::Ready;
    }
}
impl CountSetupWatch {
    pub(crate) fn child_receipt(&self, receipt: &crate::capture::CustodyReceipt) {
        if matches!(
            receipt.resolution,
            crate::capture::CustodyResolution::Resolved
                | crate::capture::CustodyResolution::NotAcquired
        ) {
            if let Some(hold) = self.0.disposal_hold() {
                hold.permit();
            }
        }
    }

    pub(crate) fn abandon(&self) {
        // Claim the real Shared flag in the same publication critical section.
        // Timestamp sampling and wake syscalls stay outside this lock.
        let now = Instant::now();
        {
            let mut state = locked(&self.0.0);
            state.abandoned = true;
            if let Some(shared) = &state.shared {
                shared.claim_abandon(now);
            }
        }
        self.0.forward_abort();
    }
    pub(crate) fn seal(&self, deadline: Instant) -> Option<CleanupTicket> {
        let shared = {
            let mut state = locked(&self.0.0);
            state.seal_deadline.get_or_insert(deadline);
            state.shared.clone()
        };
        // No terminal identity exists until actual owner admission.
        shared.map(|shared| {
            let deadline = locked(&self.0.0).seal_deadline.expect("sticky request");
            shared.seal(deadline)
        })
    }
    pub(crate) fn progress(&self) -> Option<CountSetupProgress> {
        let (phase, shared, abandoned, failure, launch) = {
            let state = self.0.0.try_lock().ok()?;
            (
                state.phase,
                state.shared.clone(),
                state.abandoned,
                state.failure,
                state.launch.clone(),
            )
        };
        let mut progress = CountSetupProgress {
            phase,
            owner_epoch: shared.as_ref().map(|s| s.epoch),
            cleanup_ticket: None,
            cleanup: None,
            open_pending: false,
            late_ready: phase == CountSetupPhase::Ready && abandoned,
            known_failure: failure.map(|f| f.failure),
            prepare_failure: failure,
            owner_task_disposed: launch
                .as_ref()
                .is_some_and(|launch| launch.disposed.load(Ordering::Acquire)),
            owner_cleanup_acknowledged: launch.as_ref().is_some_and(|launch| {
                launch.spawn_failed.load(Ordering::Acquire)
                    && !launch.entered.load(Ordering::Acquire)
                    && launch.disposed.load(Ordering::Acquire)
            }),
        };
        if let Some(shared) = shared {
            let state = shared.state.try_lock().ok()?;
            progress.cleanup_ticket = state.terminal.map(|s| s.ticket);
            progress.cleanup = shared.cleanup_progress_locked(&state);
            progress.owner_cleanup_acknowledged |= progress
                .cleanup
                .is_some_and(|p| p.status == CleanupStatus::Complete);
            progress.open_pending = state.pending_open.is_some()
                && state
                    .resolved_open
                    .is_none_or(|open| open.outcome == OpenOutcome::Unknown);
            progress.late_ready |= state.phase == OwnerPhase::Ready && abandoned;
            // Prepare's real control receipt remains separate. Established owner
            // operation/component/cleanup errors take precedence over it.
            progress.known_failure = state
                .failures
                .independent_failure()
                .or_else(|| {
                    state
                        .terminal_result
                        .as_ref()
                        .and_then(|data| data.failures.independent_failure())
                })
                .or_else(|| {
                    state
                        .terminal_candidate
                        .as_ref()
                        .and_then(|(_, data)| data.failures.independent_failure())
                })
                .or_else(|| {
                    state
                        .terminal_fallback
                        .as_ref()
                        .and_then(|data| data.failures.independent_failure())
                })
                .or_else(|| {
                    state.read_failure.filter(|f| {
                        !matches!(f.class, FailureClass::Cancelled | FailureClass::Deadline)
                    })
                })
                .or_else(|| {
                    state.resources.resources.iter().find_map(|r| {
                        (r.state == ResourceState::ConsumedError).then_some(OwnerFailure {
                            operation: CountOperation::Cleanup,
                            resource: r.resource,
                            class: FailureClass::Io,
                            errno: r.errno,
                        })
                    })
                })
                .or(progress.known_failure)
                .or_else(|| state.failures.operations.iter().flatten().copied().next());
            drop(state);
            // Published read components are also already-established Shared
            // data. Never wait on the owner or nest its publication locks.
            let component = shared.latest_progress.try_lock().ok().and_then(|slot| {
                let snapshot = &slot.as_ref()?.snapshot;
                [snapshot.admitted, snapshot.dropfail]
                    .into_iter()
                    .chain(snapshot.latc)
                    .find_map(|value| {
                        let Component::Unavailable(f) = value else {
                            return None;
                        };
                        let class = f.class?;
                        (!matches!(class, FailureClass::Cancelled | FailureClass::Deadline))
                            .then_some(OwnerFailure {
                                operation: f.operation,
                                resource: ResourceId::Map(f.map),
                                class,
                                errno: f.errno,
                            })
                    })
            });
            if progress
                .known_failure
                .is_none_or(|f| matches!(f.class, FailureClass::Cancelled | FailureClass::Deadline))
            {
                progress.known_failure = component.or(progress.known_failure);
            }
        }
        Some(progress)
    }
}
pub(super) struct SetupPreparation {
    pub(super) admission: Option<CountSetupAdmission>,
    pub(super) control: CountPrepareControl,
    pub(super) journal: CountSetupJournal,
}
