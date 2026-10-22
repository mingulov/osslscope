//! SPDX-License-Identifier: GPL-3.0-or-later
//! A prepared exclusive owner for bounded count-resource acquisition/cleanup.
//! No descriptor or join obligation enters the controller's handle.
// The owner is integrated with the session by subsequent serial tasks. Keep
// these crate-private contracts available without publishing a new library API.
#![allow(dead_code)]
pub(crate) mod io;
pub(crate) mod protocol;
pub(crate) mod registry;
use io::{CountIoDriver, LiveCountIoDriver, ReadWorkspace};
pub use protocol::*;
use registry::Registry;
use std::sync::{
    Arc, Condvar, Mutex, MutexGuard, OnceLock,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::thread;
use std::time::Instant;

fn locked<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
    lock.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[derive(Default)]
struct BarrierState {
    permits: usize,
    active: Option<OwnerEpoch>,
    ever_started: bool,
    retired: Option<OwnerEpoch>,
    sealed: bool,
    unresolved: bool,
}
/// Allocate before the product's prefix forks and share with the later engine.
#[derive(Default)]
pub struct CountForkBarrier {
    state: Mutex<BarrierState>,
    changed: Condvar,
}
pub struct CountForkPermit<'a> {
    barrier: &'a CountForkBarrier,
}
impl Drop for CountForkPermit<'_> {
    fn drop(&mut self) {
        let mut state = locked(&self.barrier.state);
        state.permits -= 1;
        self.barrier.changed.notify_all();
    }
}
impl CountForkBarrier {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn prefix_permit(&self, deadline: Instant) -> Result<CountForkPermit<'_>, ForkBlocked> {
        self.permit(None, deadline)
    }
    fn terminal_permit(
        &self,
        epoch: OwnerEpoch,
        deadline: Instant,
    ) -> Result<CountForkPermit<'_>, ForkBlocked> {
        self.permit(Some(epoch), deadline)
    }
    fn permit(
        &self,
        epoch: Option<OwnerEpoch>,
        deadline: Instant,
    ) -> Result<CountForkPermit<'_>, ForkBlocked> {
        let mut state = locked(&self.state);
        loop {
            if epoch.is_none() && state.ever_started {
                return Err(ForkBlocked::PrefixAfterEpoch);
            }
            if state.unresolved {
                return Err(ForkBlocked::Unresolved);
            }
            let allowed = if let Some(epoch) = epoch {
                state.active.is_none() && state.retired == Some(epoch) && state.sealed
            } else {
                state.active.is_none() && !state.ever_started
            };
            if allowed {
                state.permits = state
                    .permits
                    .checked_add(1)
                    .ok_or(ForkBlocked::IdExhausted)?;
                return Ok(CountForkPermit { barrier: self });
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ForkBlocked::Deadline);
            }
            state = self
                .changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
    }
    fn admit(&self, epoch: OwnerEpoch, deadline: Instant) -> Result<(), OwnerFailure> {
        let mut state = locked(&self.state);
        loop {
            if state.active.is_some() || state.unresolved {
                return Err(OwnerFailure::engine(
                    CountOperation::Load,
                    FailureClass::Capacity,
                ));
            }
            if state.permits == 0 {
                if Instant::now() >= deadline {
                    return Err(OwnerFailure::engine(
                        CountOperation::Load,
                        FailureClass::Deadline,
                    ));
                }
                state.active = Some(epoch);
                state.sealed = false;
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(OwnerFailure::engine(
                    CountOperation::Load,
                    FailureClass::Deadline,
                ));
            }
            state = self
                .changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
    }
    fn started(&self, epoch: OwnerEpoch) {
        let mut state = locked(&self.state);
        if state.active == Some(epoch) {
            state.ever_started = true;
        }
    }
    fn spawn_failed(&self, epoch: OwnerEpoch) {
        let mut state = locked(&self.state);
        if state.active == Some(epoch) {
            state.active = None;
        }
        self.changed.notify_all();
    }
    fn cleaned(&self, epoch: OwnerEpoch, complete: bool) {
        let mut state = locked(&self.state);
        if state.active != Some(epoch) {
            return;
        }
        state.sealed = true;
        state.unresolved = !complete;
        if complete {
            state.active = None;
            state.retired = Some(epoch);
        }
        self.changed.notify_all();
    }
}

#[derive(Clone, Copy)]
struct Seal {
    ticket: CleanupTicket,
    deadline: Instant,
    submitted_at: Instant,
}
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
enum MailboxEvent {
    Constructed { request: usize, reply: usize },
    RequestPublished(usize),
    RequestTaken(usize),
    ReplyPublished(usize),
    ReplyTaken(usize),
}
/// One inline request cell and one inline reply cell. Taking a request does not
/// release its admission allowance: that happens only when its reply is taken.
/// These cells are part of the preallocated SharedState, never grown at Ready.
struct OrdinaryCells<Request, Reply> {
    request: Option<Request>,
    reply: Option<Reply>,
    in_flight: bool,
    #[cfg(test)]
    observer: Option<Arc<dyn Fn(MailboxEvent) + Send + Sync>>,
}
impl<Request, Reply> OrdinaryCells<Request, Reply> {
    fn new() -> Self {
        Self {
            request: None,
            reply: None,
            in_flight: false,
            #[cfg(test)]
            observer: None,
        }
    }
    fn publish_request(&mut self, request: Request) -> Result<(), Request> {
        if self.in_flight {
            return Err(request);
        }
        self.request = Some(request);
        self.in_flight = true;
        #[cfg(test)]
        if let Some(observer) = &self.observer {
            observer(MailboxEvent::RequestPublished(
                &self.request as *const _ as usize,
            ));
        }
        Ok(())
    }
    fn take_request(&mut self) -> Option<Request> {
        let request = self.request.take()?;
        #[cfg(test)]
        if let Some(observer) = &self.observer {
            observer(MailboxEvent::RequestTaken(
                &self.request as *const _ as usize,
            ));
        }
        Some(request)
    }
    fn publish_reply(&mut self, reply: Reply) -> Result<(), Reply> {
        if !self.in_flight || self.request.is_some() || self.reply.is_some() {
            return Err(reply);
        }
        self.reply = Some(reply);
        #[cfg(test)]
        if let Some(observer) = &self.observer {
            observer(MailboxEvent::ReplyPublished(
                &self.reply as *const _ as usize,
            ));
        }
        Ok(())
    }
    fn take_reply(&mut self) -> Option<Reply> {
        let reply = self.reply.take()?;
        self.in_flight = false;
        #[cfg(test)]
        if let Some(observer) = &self.observer {
            observer(MailboxEvent::ReplyTaken(&self.reply as *const _ as usize));
        }
        Some(reply)
    }
    #[cfg(test)]
    fn observe_constructed(&self) {
        if let Some(observer) = &self.observer {
            observer(MailboxEvent::Constructed {
                request: &self.request as *const _ as usize,
                reply: &self.reply as *const _ as usize,
            });
        }
    }
}
// Preparation and attach share these physically preallocated cells. The
// sticky seal remains independent of ordinary-command admission.
struct PreparationRequest {
    owner_epoch: OwnerEpoch,
    deadline: Instant,
    input: CountInput,
    prepared: crate::loader::Prepared,
}
enum OwnerRequest {
    Prepare(PreparationRequest),
    Attach {
        request: AttachRequest,
        ack: AttachAck<LinkToken>,
    },
    Open(OpenRequest),
    Generation(GenerationRequest),
    Read(ReadRequest),
}
// One bounded inline reply cell exists before count acquisition. Boxing Ready
// here would introduce a publication allocation; the 344-byte cell is intended.
#[allow(clippy::large_enum_variant)]
enum OwnerReply {
    Prepared(Result<Ready, OwnerFailure>),
    Attached(CommandResult<AttachAck<LinkToken>>),
    Opened(CommandResult<OpenReceipt>),
    Generated(CommandResult<()>),
    Read(CommandResult<Arc<RawSnapshot>>),
}
struct SharedState {
    ordinary: OrdinaryCells<OwnerRequest, OwnerReply>,
    terminal: Option<Seal>,
    terminal_ids: protocol::IdCounter,
    resources: ResourceSummary,
    phase: OwnerPhase,
    active_operation: Option<CountOperation>,
    last_command_seq: Option<CommandSeq>,
    // The submission guard above is not evidence of returned map I/O. This
    // frontier advances when an entered handler returns (including EIO) or a
    // metadata-only command succeeds; queued refusal/unreturned calls do not.
    last_completed_seq: Option<CommandSeq>,
    pending_open: Option<OpenRequest>,
    resolved_open: Option<OpenReceipt>,
    read_failure: Option<OwnerFailure>,
    failures: TerminalFailures,
    frontier: ControllerFrontier,
    inventory: Option<Result<Arc<SealedInventory>, InventoryFailure>>,
    terminal_expected: Option<TerminalRequest>,
    terminal_contradiction: bool,
    terminal_fallback: Option<Arc<RawTerminalData>>,
    terminal_candidate: Option<(Instant, RawTerminal)>,
    terminal_result: Option<RawTerminal>,
    terminal_read_started: Option<Instant>,
    initial_empty: Option<EmptyFamily>,
    cleanup_stranded: bool,
}
struct Shared {
    epoch: OwnerEpoch,
    barrier: Arc<CountForkBarrier>,
    setup_deadline: Instant,
    link_limit: usize,
    target_tgid: u32,
    abandoned: Arc<AtomicBool>,
    trigger_origin: Instant,
    // 0 = unclaimed, 1 = invalid/expired abandonment, MAX = explicit trigger;
    // other values encode the first abandonment offset plus two. A single CAS
    // arbitrates explicit admission versus flag-only Drop, without waiting for
    // an initializer or taking the owner publication mutex in Drop.
    first_trigger: AtomicU64,
    worker: OnceLock<thread::Thread>,
    state: Mutex<SharedState>,
    latest_progress: Mutex<Option<RawCheckpoint>>,
    controller_progress: Mutex<Option<RawCheckpoint>>,
    changed: Condvar,
    #[cfg(test)]
    clock: Option<Arc<dyn Fn() -> Instant + Send + Sync>>,
    #[cfg(test)]
    seal_claim_observer: Option<Arc<dyn Fn() + Send + Sync>>,
}
impl Shared {
    fn now(&self) -> Instant {
        #[cfg(test)]
        if let Some(clock) = &self.clock {
            return clock();
        }
        Instant::now()
    }
    /// Only pre-cutoff progress may change the unpublished fallback envelope.
    /// The first local seal records already-known state even for grace=0.
    fn refresh_fallback_locked(&self, state: &mut SharedState, first_seal: bool) {
        let Some(seal) = state.terminal else { return };
        if state.terminal_result.is_some() || (!first_seal && self.now() >= seal.deadline) {
            return;
        }
        if let Some(mut fallback) = state.terminal_fallback.take() {
            fill_terminal_shared(
                state,
                Arc::get_mut(&mut fallback).expect("private fallback"),
            );
            state.terminal_fallback = Some(fallback);
        }
    }
    fn seal(&self, deadline: Instant) -> CleanupTicket {
        let mut state = locked(&self.state);
        let ticket = self.seal_locked(&mut state, deadline);
        self.changed.notify_all();
        if let Some(worker) = self.worker.get() {
            worker.unpark();
        }
        ticket
    }
    fn seal_locked(&self, state: &mut SharedState, deadline: Instant) -> CleanupTicket {
        if let Some(seal) = state.terminal {
            return seal.ticket;
        }
        // This is the single preallocated terminal slot in a fresh epoch. Its
        // counter is advanced once, under this same lock; zero cannot escape.
        let sequence = state
            .terminal_ids
            .next()
            .and_then(TerminalSeq::checked)
            .expect("fresh terminal identity slot");
        let ticket = CleanupTicket {
            owner_epoch: self.epoch,
            terminal_id: TerminalId {
                owner_epoch: self.epoch,
                sequence,
            },
        };
        let submitted_at = self.now();
        let trigger = self
            .first_trigger
            .compare_exchange(0, u64::MAX, Ordering::AcqRel, Ordering::Acquire)
            .unwrap_or_else(|prior| prior);
        // Explicit/operation claims and installing their actual deadline share
        // this one SharedState guard. MAX is never visible to another seal
        // caller without that already-bound slot; Drop merely sets its flag.
        #[cfg(test)]
        if trigger == 0
            && let Some(observer) = &self.seal_claim_observer
        {
            observer();
        }
        let deadline = match trigger {
            0 | u64::MAX => deadline,
            1 => submitted_at.min(self.trigger_origin),
            offset => self
                .trigger_origin
                .checked_add(std::time::Duration::from_nanos(offset - 2))
                .unwrap_or_else(|| submitted_at.min(self.trigger_origin)),
        };
        state.terminal = Some(Seal {
            ticket,
            deadline,
            submitted_at,
        });
        self.refresh_fallback_locked(state, true);
        ticket
    }
    fn abandon(&self) {
        let code = abandonment_code(self.now().checked_duration_since(self.trigger_origin));
        let _ = self
            .first_trigger
            .compare_exchange(0, code, Ordering::AcqRel, Ordering::Acquire);
        self.abandoned.store(true, Ordering::Release);
        self.changed.notify_all();
        if let Some(worker) = self.worker.get() {
            worker.unpark();
        }
    }
    fn failed(&self, failure: OwnerFailure) {
        let mut state = locked(&self.state);
        state.failures.record_at(failure, self.now());
        self.seal_locked(&mut state, self.setup_deadline);
        let _ = state
            .ordinary
            .publish_reply(OwnerReply::Prepared(Err(failure)));
        self.changed.notify_all();
    }
    fn cleanup_progress(&self, registry: &Registry, phase: OwnerPhase) {
        let mut state = locked(&self.state);
        state.phase = phase;
        registry.publish_into(&mut state.resources);
        self.refresh_fallback_locked(&mut state, false);
        self.changed.notify_all();
    }
    fn registry_progress(&self, registry: &Registry) {
        let mut state = locked(&self.state);
        registry.publish_into(&mut state.resources);
        self.refresh_fallback_locked(&mut state, false);
        self.changed.notify_all();
    }
    fn terminal_close_progress(&self, outcome: LinkCloseOutcome, failure: Option<OwnerFailure>) {
        let mut state = locked(&self.state);
        if let Some(failure) = failure {
            state.failures.record_at(failure, self.now());
        }
        let eligible = state
            .terminal
            .is_some_and(|seal| self.now() < seal.deadline);
        if eligible && let Some(fallback) = state.terminal_fallback.as_mut() {
            let data = Arc::get_mut(fallback).expect("unpublished close progress");
            if let Some(previous) = data.close_outcomes.iter_mut().find(|c| c.id == outcome.id) {
                *previous = outcome;
            } else {
                assert!(data.close_outcomes.len() < data.close_outcomes.capacity());
                data.close_outcomes.push(outcome);
            }
            if let Some(failure) = failure {
                data.failures.record_at(failure, self.now());
            }
        }
        self.changed.notify_all();
    }
}
fn abandonment_code(offset: Option<std::time::Duration>) -> u64 {
    offset
        .and_then(|offset| u64::try_from(offset.as_nanos()).ok())
        .and_then(|offset| offset.checked_add(2))
        .filter(|code| *code < u64::MAX)
        .unwrap_or(1)
}
/// Ready contains data only; the worker retains every map/program/pin/link.
pub struct CountEngine {
    shared: Arc<Shared>,
    ready: Ready,
}
impl CountEngine {
    pub fn prepare(
        input: CountInput,
        limits: CountOwnerLimits,
        setup_deadline: Instant,
    ) -> Result<Self, CountPrepareFailure> {
        Self::prepare_with(
            input,
            limits,
            setup_deadline,
            PrepareHooks::live(),
            || LiveCountIoDriver,
            spawn_owner,
        )
    }
    pub fn ready(&self) -> &Ready {
        &self.ready
    }
    /// Posting abandonment allocates nothing, never joins, and never closes.
    pub fn abandon(&self) {
        self.shared.abandon();
    }
    pub fn fork_permit(&self, deadline: Instant) -> Result<CountForkPermit<'_>, ForkBlocked> {
        self.shared
            .barrier
            .terminal_permit(self.ready.owner_epoch, deadline)
    }
    #[cfg(test)]
    pub fn resource_summary(&self) -> ResourceSummary {
        locked(&self.shared.state).resources.clone()
    }

    /// Nonblocking immutable observation. If publication is busy, retain the
    /// previous controller image; no registry cloning or count I/O occurs here.
    pub fn progress(&self) -> Option<RawCheckpoint> {
        let mut latest = self
            .shared
            .latest_progress
            .try_lock()
            .ok()
            .and_then(|latest| latest.clone());
        let mut previous = None;
        let view = {
            let mut retained = self.shared.controller_progress.try_lock().ok()?;
            if latest.as_ref().is_some_and(|latest| {
                retained
                    .as_ref()
                    .is_none_or(|old| old.snapshot.sequence < latest.snapshot.sequence)
            }) {
                previous = std::mem::replace(&mut *retained, latest.take());
            }
            retained.clone()
        };
        // An owner that has finished cleanup may have dropped its pool handles.
        // Releasing an old controller view can then free its row allocation;
        // keep that destruction outside both publication/access mutexes.
        drop(previous);
        drop(latest);
        view
    }

    /// Nonblocking, bounded diagnostics; never a replacement capture result.
    pub fn cleanup_progress(&self) -> Option<CleanupProgress> {
        let state = self.shared.state.try_lock().ok()?;
        let seal = state.terminal?;
        let unresolved_resources = state
            .resources
            .resources
            .iter()
            .filter(|resource| {
                !matches!(
                    resource.state,
                    ResourceState::Unused
                        | ResourceState::CreateFailed
                        | ResourceState::CloseReturned
                )
            })
            .count();
        let status = if state.cleanup_stranded {
            CleanupStatus::Stranded
        } else if state.phase == OwnerPhase::Idle && state.resources.cleanup_complete {
            CleanupStatus::Complete
        } else if state
            .resources
            .resources
            .iter()
            .any(|r| r.state == ResourceState::ConsumedError)
            && !state.resources.resources.iter().any(|r| {
                matches!(
                    r.state,
                    ResourceState::Reserved
                        | ResourceState::Creating
                        | ResourceState::Held
                        | ResourceState::CloseIssued
                )
            })
        {
            CleanupStatus::Failed
        } else {
            CleanupStatus::Pending
        };
        Some(CleanupProgress {
            ticket: seal.ticket,
            actual_phase: state.phase,
            active_operation: state.active_operation,
            coordinator_finalized: state.terminal_result.is_some(),
            status,
            unresolved_resources,
            failures: state.failures,
        })
    }

    /// Bind the controller's interpretation before notifying the already
    /// owning worker. A prior fault/abandonment retains its exact ID and budget.
    pub(crate) fn terminal_request(
        &self,
        deadline: Instant,
        evidence_domain: EvidenceDomain,
        writer_object_identity: [u8; 32],
        frontier: ControllerFrontier,
    ) -> TerminalRequest {
        let mut state = locked(&self.shared.state);
        let ticket = self.shared.seal_locked(&mut state, deadline);
        let request = TerminalRequest {
            id: ticket.terminal_id,
            deadline: state.terminal.expect("sticky seal").deadline,
            evidence_domain,
            writer_object_identity,
            frontier,
        };
        if state.terminal_expected.is_none() {
            state.terminal_contradiction = evidence_domain != self.ready.evidence_domain
                || writer_object_identity != self.ready.writer_object_identity
                || request.frontier != state.frontier;
            state.terminal_expected = Some(request.clone());
        } else if state.terminal_expected.as_ref() != Some(&request) {
            // The selected result, if any, is already immutable. Before result
            // selection a contradictory first consumer cannot gain authority.
            state.terminal_contradiction = true;
        }
        self.shared.changed.notify_all();
        self.shared.worker.get().expect("prepared owner").unpark();
        request
    }

    pub fn terminal(&self, request: TerminalRequest) -> RawTerminal {
        let mut state = locked(&self.shared.state);
        let ticket = self.shared.seal_locked(&mut state, request.deadline);
        if state.terminal_expected.is_none() {
            state.terminal_contradiction = request.id != ticket.terminal_id
                || request.deadline != state.terminal.expect("sticky seal").deadline
                || request.evidence_domain != self.ready.evidence_domain
                || request.writer_object_identity != self.ready.writer_object_identity
                || request.frontier != state.frontier;
            state.terminal_expected = Some(request);
        }
        self.shared.changed.notify_all();
        self.shared.worker.get().expect("prepared owner").unpark();
        loop {
            if let Some(result) = &state.terminal_result {
                return result.clone();
            }
            let seal = state.terminal.expect("terminal admission");
            // Observation precedes candidate acceptance. Publication alone is
            // not coordinator observation, and equality is already too late.
            let observed_at = self.shared.now();
            let expired = observed_at >= seal.deadline;
            if expired || state.terminal_candidate.is_some() {
                return self.select_terminal(state, expired);
            }
            state = self
                .shared
                .changed
                .wait_timeout(state, seal.deadline.saturating_duration_since(observed_at))
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
    }

    /// Salvage never waits, retries I/O, creates a new deadline, or replaces a
    /// selected artifact. Without a prior trigger it seals at the current edge.
    pub fn salvage_view(&self, id: TerminalId) -> RawTerminal {
        let mut state = locked(&self.shared.state);
        if let Some(result) = &state.terminal_result {
            return result.clone();
        }
        let ticket = self.shared.seal_locked(&mut state, self.shared.now());
        if id != ticket.terminal_id {
            state.terminal_contradiction = true;
        }
        self.shared.changed.notify_all();
        self.shared.worker.get().expect("prepared owner").unpark();
        let expired = self.shared.now() >= state.terminal.expect("salvage seal").deadline;
        self.select_terminal(state, expired)
    }

    fn select_terminal(
        &self,
        mut state: MutexGuard<'_, SharedState>,
        expired: bool,
    ) -> RawTerminal {
        let seal = state.terminal.expect("sticky seal");
        let mut fallback = state
            .terminal_fallback
            .take()
            .expect("one fallback builder");
        let data = Arc::get_mut(&mut fallback).expect("unpublished fallback");
        if !expired
            && let Some((published_at, candidate)) = &state.terminal_candidate
            && *published_at < seal.deadline
        {
            copy_terminal_result(candidate, data);
            fill_terminal_shared(&state, data);
        }
        // Errors first recorded after cutoff are only custody diagnostics.
        data.failures = data.failures.before(seal.deadline);
        data.failures.merge(state.failures.before(seal.deadline));
        if state.terminal_contradiction {
            data.failures.record_at(
                OwnerFailure::engine(CountOperation::Close, FailureClass::Inventory),
                seal.submitted_at,
            );
        }
        let known_empty = state.initial_empty.filter(|family| {
            family.published_at < seal.deadline
                && family.writer.owner_epoch == self.shared.epoch
                && family.writer.object_sha256 == self.ready.writer_object_identity
                && state.last_command_seq.is_none()
                && state.last_completed_seq.is_none()
                && state.pending_open.is_none()
                && state.resolved_open.is_none()
                && state.active_operation.is_none()
                && !state.ordinary.in_flight
                && state.frontier == ControllerFrontier::default()
                && !state.terminal_contradiction
                && data.manifest.is_empty()
                && data.failures == TerminalFailures::default()
        });
        if expired && let Some(family) = known_empty {
            data.host_writes_sealed = true;
            data.writers = WriterCompletion::KnownEmpty(EmptyWitness {
                owner_epoch: self.shared.epoch,
                terminal_id: seal.ticket.terminal_id,
                writer_object_identity: family.writer.object_sha256,
                ready_published_at: family.published_at,
                sealed_at: seal.submitted_at,
                deadline: seal.deadline,
            });
        } else if expired || state.terminal_candidate.is_none() {
            let completed_prefix = data.close_outcomes.len();
            for record in data.manifest.iter().skip(completed_prefix) {
                data.close_outcomes.push(LinkCloseOutcome {
                    id: record.id,
                    issued_at: None,
                    returned_at: None,
                    state: record.close_state,
                    errno: record.close_errno,
                });
            }
            if data.seal.result == StopResult::NotAttempted {
                data.failures.record(OwnerFailure::engine(
                    CountOperation::Stop,
                    FailureClass::Deadline,
                ));
            }
            let finished = matches!(data.writers, WriterCompletion::Finished(w) if w.established_at < seal.deadline);
            if !finished {
                data.writers = WriterCompletion::Unknown(QuiescenceReason::Deadline);
            }
            data.failures.record(OwnerFailure::engine(
                if finished {
                    CountOperation::Read
                } else {
                    CountOperation::Close
                },
                FailureClass::Deadline,
            ));
            let latest = self
                .shared
                .latest_progress
                .try_lock()
                .ok()
                .and_then(|p| p.clone());
            let retained = self
                .shared
                .controller_progress
                .try_lock()
                .ok()
                .and_then(|p| p.clone());
            data.checkpoint = latest
                .filter(|p| p.published_at < seal.deadline)
                .or_else(|| retained.filter(|p| p.published_at < seal.deadline));
            if let Some(start) = state
                .terminal_read_started
                .filter(|start| *start < seal.deadline)
            {
                bind_terminal_prefix(data, start);
            }
            record_terminal_components(data);
        }
        let complete = matches!(&data.cleanup_state, CleanupState::Pending(summary) if summary.cleanup_complete)
            && state.phase == OwnerPhase::Idle
            && !state.cleanup_stranded;
        let old_cleanup =
            complete.then(|| std::mem::replace(&mut data.cleanup_state, CleanupState::Complete));
        let result = RawTerminal(fallback);
        state.terminal_result = Some(result.clone());
        let candidate = state.terminal_candidate.take();
        self.shared.changed.notify_all();
        drop(state);
        drop(old_cleanup);
        drop(candidate);
        result
    }

    pub fn open_window(&self, request: OpenRequest) -> CommandResult<OpenReceipt> {
        if request.tgid != u64::from(self.shared.target_tgid)
            || request.tgid == 0
            || request.start_ns >= request.deadline_ns
        {
            return Err(CommandFailure {
                seq: request.seq,
                failure: OwnerFailure::engine(CountOperation::Open, FailureClass::InvalidInput),
                completion: CommandCompletion::NotEntered,
                cleanup_ticket: None,
            });
        }
        self.map_command(OwnerRequest::Open(request), |reply| {
            if let OwnerReply::Opened(result) = reply {
                Some(result)
            } else {
                None
            }
        })
    }
    pub fn set_generation(&self, request: GenerationRequest) -> CommandResult<()> {
        self.map_command(OwnerRequest::Generation(request), |reply| {
            if let OwnerReply::Generated(result) = reply {
                Some(result)
            } else {
                None
            }
        })
    }
    pub fn drain(&self, request: ReadRequest) -> CommandResult<Arc<RawSnapshot>> {
        self.map_command(OwnerRequest::Read(request), |reply| {
            if let OwnerReply::Read(result) = reply {
                Some(result)
            } else {
                None
            }
        })
    }
    fn map_command<T>(
        &self,
        request: OwnerRequest,
        extract: fn(OwnerReply) -> Option<CommandResult<T>>,
    ) -> CommandResult<T> {
        let (seq, deadline, operation) = map_request_identity(&request).expect("map command");
        let refused = |class, completion, cleanup_ticket| CommandFailure {
            seq,
            failure: OwnerFailure::engine(operation, class),
            completion,
            cleanup_ticket,
        };
        if Instant::now() >= deadline {
            return Err(refused(
                FailureClass::Deadline,
                CommandCompletion::NotEntered,
                None,
            ));
        }
        let mut state = locked(&self.shared.state);
        if let Some(seal) = state.terminal {
            return Err(refused(
                FailureClass::Disconnected,
                CommandCompletion::NotEntered,
                Some(seal.ticket),
            ));
        }
        if self.shared.abandoned.load(Ordering::Acquire)
            || !matches!(state.phase, OwnerPhase::Ready | OwnerPhase::Observing)
        {
            return Err(refused(
                FailureClass::Disconnected,
                CommandCompletion::NotEntered,
                None,
            ));
        }
        if state.last_command_seq.is_some_and(|last| seq <= last) {
            return Err(refused(
                FailureClass::InvalidInput,
                CommandCompletion::NotEntered,
                None,
            ));
        }
        if state.ordinary.in_flight {
            return Err(refused(
                FailureClass::Capacity,
                CommandCompletion::NotEntered,
                None,
            ));
        }
        state.last_command_seq = Some(seq);
        state.initial_empty = None;
        state.frontier.pending = Some(PendingCommandId { seq, operation });
        if let OwnerRequest::Open(open) = &request {
            state.pending_open = Some(*open);
            state.resolved_open = Some(OpenReceipt::pending(self.ready.owner_epoch, open));
        }
        assert!(state.ordinary.publish_request(request).is_ok());
        self.shared.worker.get().expect("prepared owner").unpark();
        loop {
            if Instant::now() >= deadline {
                let ticket = self.shared.seal_locked(&mut state, deadline);
                drop(state);
                self.shared.abandon();
                return Err(refused(
                    FailureClass::Deadline,
                    CommandCompletion::Unknown,
                    Some(ticket),
                ));
            }
            if let Some(reply) = state.ordinary.take_reply() {
                let Some(result) = extract(reply) else {
                    let ticket = self.shared.seal_locked(&mut state, deadline);
                    self.shared.worker.get().unwrap().unpark();
                    return Err(refused(
                        FailureClass::Inventory,
                        CommandCompletion::Unknown,
                        Some(ticket),
                    ));
                };
                let ack = result?;
                if let Some(seal) = state.terminal {
                    return Err(refused(
                        FailureClass::Disconnected,
                        CommandCompletion::Completed,
                        Some(seal.ticket),
                    ));
                }
                if ack.seq != seq {
                    let ticket = self.shared.seal_locked(&mut state, deadline);
                    self.shared.worker.get().unwrap().unpark();
                    return Err(refused(
                        FailureClass::Inventory,
                        CommandCompletion::Unknown,
                        Some(ticket),
                    ));
                }
                state.frontier.last_acked = Some(seq);
                state.frontier.pending = None;
                self.shared.worker.get().unwrap().unpark();
                return Ok(ack);
            }
            if let Some(seal) = state.terminal {
                return Err(refused(
                    FailureClass::Disconnected,
                    CommandCompletion::Unknown,
                    Some(seal.ticket),
                ));
            }
            state = self
                .shared
                .changed
                .wait_timeout(state, deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
    }

    pub fn attach(&self, request: AttachRequest) -> CommandResult<AttachAck<LinkToken>> {
        let seq = request.seq;
        let deadline = request.deadline;
        let refused = |failure, completion, cleanup_ticket| CommandFailure {
            seq,
            failure,
            completion,
            cleanup_ticket,
        };
        request
            .validate()
            .map_err(|failure| refused(failure, CommandCompletion::NotEntered, None))?;
        if Instant::now() >= deadline {
            return Err(refused(
                OwnerFailure::engine(CountOperation::Attach, FailureClass::Deadline),
                CommandCompletion::NotEntered,
                None,
            ));
        }
        // Reply allocations are checked before publication, outside the lock
        // and before the owner can acquire anything for this command.
        let ack = AttachAck {
            links: registry::preallocated(self.shared.link_limit).map_err(|mut failure| {
                failure.operation = CountOperation::Attach;
                refused(failure, CommandCompletion::NotEntered, None)
            })?,
            refused: registry::preallocated(request.offsets.len()).map_err(|mut failure| {
                failure.operation = CountOperation::Attach;
                refused(failure, CommandCompletion::NotEntered, None)
            })?,
        };
        let mut state = locked(&self.shared.state);
        if let Some(seal) = state.terminal {
            return Err(refused(
                OwnerFailure::engine(CountOperation::Attach, FailureClass::Disconnected),
                CommandCompletion::NotEntered,
                Some(seal.ticket),
            ));
        }
        if self.shared.abandoned.load(Ordering::Acquire)
            || !matches!(state.phase, OwnerPhase::Ready | OwnerPhase::Observing)
        {
            return Err(refused(
                OwnerFailure::engine(CountOperation::Attach, FailureClass::Disconnected),
                CommandCompletion::NotEntered,
                None,
            ));
        }
        if state.last_command_seq.is_some_and(|last| seq <= last) {
            return Err(refused(
                OwnerFailure::engine(CountOperation::Attach, FailureClass::InvalidInput),
                CommandCompletion::NotEntered,
                None,
            ));
        }
        if state.ordinary.in_flight {
            return Err(refused(
                OwnerFailure::engine(CountOperation::Attach, FailureClass::Capacity),
                CommandCompletion::NotEntered,
                None,
            ));
        }
        state.last_command_seq = Some(seq);
        state.initial_empty = None;
        state.frontier.pending = Some(PendingCommandId {
            seq,
            operation: CountOperation::Attach,
        });
        // Admission was checked under this lock; publication cannot overwrite.
        assert!(
            state
                .ordinary
                .publish_request(OwnerRequest::Attach { request, ack })
                .is_ok()
        );
        self.shared.worker.get().expect("prepared owner").unpark();
        loop {
            if Instant::now() >= deadline {
                let ticket = self.shared.seal_locked(&mut state, deadline);
                drop(state);
                self.shared.abandon();
                return Err(refused(
                    OwnerFailure::engine(CountOperation::Attach, FailureClass::Deadline),
                    CommandCompletion::Unknown,
                    Some(ticket),
                ));
            }
            if let Some(OwnerReply::Attached(result)) = state.ordinary.take_reply() {
                match result {
                    Ok(ack) => {
                        if let Some(seal) = state.terminal {
                            return Err(refused(
                                OwnerFailure::engine(
                                    CountOperation::Attach,
                                    FailureClass::Disconnected,
                                ),
                                CommandCompletion::Completed,
                                Some(seal.ticket),
                            ));
                        }
                        if ack.seq != seq {
                            return Err(refused(
                                OwnerFailure::engine(
                                    CountOperation::Attach,
                                    FailureClass::Inventory,
                                ),
                                CommandCompletion::Unknown,
                                None,
                            ));
                        }
                        for link in &ack.value.links {
                            if !state.frontier.acknowledged_links.contains(&link.id()) {
                                // One record per reserved link slot; capacity was
                                // fixed before loading and is never grown here.
                                assert!(
                                    state.frontier.acknowledged_links.len()
                                        < self.shared.link_limit
                                );
                                state.frontier.acknowledged_links.push(link.id());
                            }
                        }
                        state.frontier.last_acked = Some(seq);
                        state.frontier.pending = None;
                        self.shared.worker.get().unwrap().unpark();
                        return Ok(ack);
                    }
                    Err(failure) => return Err(failure),
                }
            }
            if let Some(seal) = state.terminal {
                return Err(refused(
                    OwnerFailure::engine(CountOperation::Attach, FailureClass::Disconnected),
                    CommandCompletion::Unknown,
                    Some(seal.ticket),
                ));
            }
            state = self
                .shared
                .changed
                .wait_timeout(state, deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
    }

    fn prepare_with<D, F, S>(
        input: CountInput,
        limits: CountOwnerLimits,
        deadline: Instant,
        hooks: PrepareHooks,
        factory: F,
        spawner: S,
    ) -> Result<Self, CountPrepareFailure>
    where
        D: CountIoDriver + 'static,
        F: FnOnce() -> D + Send + 'static,
        S: FnOnce(Box<dyn FnOnce() + Send>) -> std::io::Result<()>,
    {
        use sha2::Digest as _;
        let preflight_failure =
            |class| CountPrepareFailure::from(OwnerFailure::engine(CountOperation::Load, class));
        if Instant::now() >= deadline {
            return Err(preflight_failure(FailureClass::Deadline));
        }
        if hooks.domain == EvidenceDomain::Live {
            let actual = (hooks.possible_cpu_count)().map_err(|error| {
                CountPrepareFailure::from(OwnerFailure::io(
                    CountOperation::Load,
                    ResourceId::Engine,
                    &error,
                ))
            })?;
            limits.validate_possible_cpus(actual)?;
        }
        if input.target_tgid == 0
            || <[u8; 32]>::from(sha2::Sha256::digest(&input.object_bytes)) != input.object_sha256
        {
            return Err(preflight_failure(FailureClass::ObjectDrift));
        }
        crate::loader::validate_count_object(&input.object_bytes)
            .map_err(CountPrepareFailure::from)?;
        let prepared = crate::loader::prepare(
            &input.object_bytes,
            &crate::loader::COUNT_MAPS,
            &crate::loader::COUNT_PROGS,
        )
        .map_err(|_| preflight_failure(FailureClass::ObjectDrift))?;
        crate::loader::validate_count_prepared(&prepared).map_err(CountPrepareFailure::from)?;
        if hooks.fail_allocation {
            return Err(preflight_failure(FailureClass::Allocation));
        }
        let mut registry = Registry::allocate(limits)?;
        let read_workspace = ReadWorkspace::allocate(limits, registry.take_read_storage())?;
        #[cfg(test)]
        let read_workspace = {
            let mut workspace = read_workspace;
            workspace.sequences = IdCounter::with_last(hooks.snapshot_sequence_last);
            workspace
        };
        let resources = registry.summary_storage()?;
        let acknowledged_links = registry::preallocated(limits.link_slots)?;
        #[cfg(test)]
        {
            registry.observer = hooks.registry_observer.clone();
        }
        static LAST_EPOCH: AtomicU64 = AtomicU64::new(0);
        let prior = LAST_EPOCH
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |last| {
                last.checked_add(1)
            })
            .map_err(|_| preflight_failure(FailureClass::IdExhausted))?;
        let epoch = OwnerEpoch::checked(
            prior
                .checked_add(1)
                .ok_or_else(|| preflight_failure(FailureClass::IdExhausted))?,
        )?;
        // Both ordinary cells, the registry, sticky terminal and progress state
        // exist before spawn. Preparation itself owns the first request/reply;
        // later count commands cannot be submitted or processed yet.
        let ordinary = OrdinaryCells::new();
        #[cfg(test)]
        let ordinary = OrdinaryCells {
            observer: hooks.mailbox_observer.clone(),
            ..ordinary
        };
        let terminal_builder =
            terminal_storage(epoch, &input, limits, &registry, deadline, hooks.domain)?;
        let fallback = terminal_storage(epoch, &input, limits, &registry, deadline, hooks.domain)?;
        let trigger_origin = Instant::now();
        #[cfg(test)]
        let trigger_origin = hooks.clock.as_ref().map_or(trigger_origin, |clock| clock());
        let shared = Arc::new(Shared {
            epoch,
            barrier: Arc::clone(&input.fork_barrier),
            setup_deadline: deadline,
            link_limit: limits.link_slots,
            target_tgid: input.target_tgid,
            abandoned: Arc::clone(&registry.abandoned),
            trigger_origin,
            first_trigger: AtomicU64::new(0),
            worker: OnceLock::new(),
            state: Mutex::new(SharedState {
                ordinary,
                terminal: None,
                terminal_ids: protocol::IdCounter::default(),
                resources,
                phase: OwnerPhase::Preparing,
                active_operation: None,
                last_command_seq: None,
                last_completed_seq: None,
                pending_open: None,
                resolved_open: None,
                read_failure: None,
                failures: TerminalFailures::default(),
                frontier: ControllerFrontier {
                    acknowledged_links,
                    ..ControllerFrontier::default()
                },
                inventory: None,
                terminal_expected: None,
                terminal_contradiction: false,
                terminal_fallback: Some(fallback),
                terminal_candidate: None,
                terminal_result: None,
                terminal_read_started: None,
                initial_empty: None,
                cleanup_stranded: false,
            }),
            latest_progress: Mutex::new(None),
            controller_progress: Mutex::new(None),
            changed: Condvar::new(),
            #[cfg(test)]
            clock: hooks.clock.clone(),
            #[cfg(test)]
            seal_claim_observer: hooks.seal_claim_observer.clone(),
        });
        {
            let mut state = locked(&shared.state);
            #[cfg(test)]
            state.ordinary.observe_constructed();
            if state
                .ordinary
                .publish_request(OwnerRequest::Prepare(PreparationRequest {
                    owner_epoch: epoch,
                    deadline,
                    input,
                    prepared,
                }))
                .is_err()
            {
                return Err(preflight_failure(FailureClass::Publication));
            }
        }
        registry.shared = Some(Arc::clone(&shared));
        shared.barrier.admit(epoch, deadline)?;
        let owner_shared = Arc::clone(&shared);
        let task = Box::new(move || {
            owner_main(
                owner_shared,
                registry,
                read_workspace,
                terminal_builder,
                hooks,
                factory,
            )
        });
        if let Err(error) = spawner(task) {
            shared.barrier.spawn_failed(epoch);
            return Err(CountPrepareFailure::from(OwnerFailure::io(
                CountOperation::Load,
                ResourceId::Engine,
                &error,
            )));
        }
        let mut state = locked(&shared.state);
        loop {
            // A late Ready does not extend setup. Its FDs remain in the owner
            // even if this side has ceased waiting for publication.
            if Instant::now() >= deadline {
                drop(state);
                let ticket = shared.seal(deadline);
                shared.abandon();
                return Err(CountPrepareFailure {
                    failure: OwnerFailure::engine(CountOperation::Load, FailureClass::Deadline),
                    cleanup_ticket: Some(ticket),
                });
            }
            if let Some(OwnerReply::Prepared(result)) = state.ordinary.take_reply() {
                drop(state);
                return match result {
                    Ok(ready) => Ok(Self { shared, ready }),
                    Err(failure) => {
                        let ticket = shared.seal(deadline);
                        shared.abandon();
                        Err(CountPrepareFailure {
                            failure,
                            cleanup_ticket: Some(ticket),
                        })
                    }
                };
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            state = shared
                .changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
    }
}
impl Drop for CountEngine {
    fn drop(&mut self) {
        self.shared.abandon();
    }
}

fn spawn_owner(task: Box<dyn FnOnce() + Send>) -> std::io::Result<()> {
    thread::Builder::new()
        .name("osslscope-count".into())
        .spawn(task)
        .map(drop)
}
// No production constructor accepts a driver or a model-evidence selector.
struct PrepareHooks {
    domain: EvidenceDomain,
    possible_cpu_count: fn() -> std::io::Result<usize>,
    fail_allocation: bool,
    fail_ready_publication: bool,
    fail_attach_publication: bool,
    #[cfg(test)]
    snapshot_sequence_last: u64,
    #[cfg(test)]
    kernel_profile: KernelApplicability,
    #[cfg(test)]
    final_references: ReferenceFinality,
    #[cfg(test)]
    writer_family: CountDimensions,
    #[cfg(test)]
    registry_observer: Option<Arc<dyn Fn(registry::RegistryEvent) + Send + Sync>>,
    #[cfg(test)]
    mailbox_observer: Option<Arc<dyn Fn(MailboxEvent) + Send + Sync>>,
    #[cfg(test)]
    clock: Option<Arc<dyn Fn() -> Instant + Send + Sync>>,
    #[cfg(test)]
    before_terminal_publication: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(test)]
    seal_claim_observer: Option<Arc<dyn Fn() + Send + Sync>>,
}
impl PrepareHooks {
    fn live() -> Self {
        Self {
            domain: EvidenceDomain::Live,
            possible_cpu_count: io::possible_cpu_count,
            fail_allocation: false,
            fail_ready_publication: false,
            fail_attach_publication: false,
            #[cfg(test)]
            snapshot_sequence_last: 0,
            #[cfg(test)]
            kernel_profile: resolve_kernel_applicability(&KernelBuildIdentity::default()),
            #[cfg(test)]
            final_references: ReferenceFinality::final_owned(),
            #[cfg(test)]
            writer_family: CountDimensions::validated(),
            #[cfg(test)]
            registry_observer: None,
            #[cfg(test)]
            mailbox_observer: None,
            #[cfg(test)]
            clock: None,
            #[cfg(test)]
            before_terminal_publication: None,
            #[cfg(test)]
            seal_claim_observer: None,
        }
    }
    #[cfg(test)]
    fn host() -> Self {
        Self {
            domain: EvidenceDomain::HostModel,
            ..Self::live()
        }
    }
}
fn owner_main<D, F>(
    shared: Arc<Shared>,
    mut registry: Registry,
    mut read_workspace: ReadWorkspace,
    mut terminal_builder: Arc<RawTerminalData>,
    hooks: PrepareHooks,
    factory: F,
) where
    D: CountIoDriver,
    F: FnOnce() -> D,
{
    use std::panic::{AssertUnwindSafe, catch_unwind};
    let _ = shared.worker.set(thread::current());
    shared.barrier.started(shared.epoch);
    // Construct injected drivers here, after successful owner creation; no test
    // factory can create a count FD on the controller through this entry point.
    let initialization = catch_unwind(AssertUnwindSafe(|| {
        let Some(OwnerRequest::Prepare(request)) = locked(&shared.state).ordinary.take_request()
        else {
            return Err(OwnerFailure::engine(
                CountOperation::Load,
                FailureClass::Inventory,
            ));
        };
        if request.owner_epoch != shared.epoch || request.deadline != shared.setup_deadline {
            return Err(OwnerFailure::engine(
                CountOperation::Load,
                FailureClass::Inventory,
            ));
        }
        Ok((request, factory()))
    }));
    let (request, mut driver) = match initialization {
        Ok(Ok(initialized)) => initialized,
        failed => {
            let failure = match failed {
                Ok(Err(failure)) => failure,
                Err(_) => OwnerFailure::engine(CountOperation::Load, FailureClass::Panic),
                Ok(Ok(_)) => unreachable!(),
            };
            shared.failed(failure);
            // No syscall seam was entered. Resolve the actual empty registry,
            // rather than manufacturing a cleanup acknowledgment from a count.
            registry.seal_unentered();
            shared.cleanup_progress(&registry, OwnerPhase::Idle);
            let complete = locked(&shared.state).resources.cleanup_complete;
            shared.barrier.cleaned(shared.epoch, complete);
            return;
        }
    };
    registry
        .journal
        .bind(shared.epoch, request.input.object_sha256);
    let setup = catch_unwind(AssertUnwindSafe(|| {
        if shared.abandoned.load(Ordering::Acquire) {
            return Err(OwnerFailure::engine(
                CountOperation::Load,
                FailureClass::Disconnected,
            ));
        }
        let loaded = crate::loader::load_count_tracked(
            &request.prepared,
            &mut registry,
            &mut driver,
            shared.setup_deadline,
        )
        .map_err(|failure| failure.failure)?;
        if driver.now() >= shared.setup_deadline {
            return Err(OwnerFailure::engine(
                CountOperation::Load,
                FailureClass::Deadline,
            ));
        }
        if shared.abandoned.load(Ordering::Acquire) {
            return Err(OwnerFailure::engine(
                CountOperation::Load,
                FailureClass::Disconnected,
            ));
        }
        if hooks.fail_ready_publication {
            return Err(OwnerFailure::engine(
                CountOperation::Load,
                FailureClass::Publication,
            ));
        }
        // Data-only load slots remain in the owner through every command.

        let mut state = locked(&shared.state);
        if shared.abandoned.load(Ordering::Acquire) {
            return Err(OwnerFailure::engine(
                CountOperation::Load,
                FailureClass::Disconnected,
            ));
        }
        registry.publish_into(&mut state.resources);
        state.phase = OwnerPhase::Ready;
        state.initial_empty = registry.initial_empty(shared.now());
        let ready = Ready {
            owner_epoch: shared.epoch,
            writer_object_identity: request.input.object_sha256,
            dimensions: CountDimensions::validated(),
            evidence_domain: hooks.domain,
        };
        if state
            .ordinary
            .publish_reply(OwnerReply::Prepared(Ok(ready)))
            .is_err()
        {
            return Err(OwnerFailure::engine(
                CountOperation::Load,
                FailureClass::Publication,
            ));
        }
        shared.changed.notify_all();
        Ok(loaded)
    }));
    let mut active_deadline = shared.setup_deadline;
    let loaded = match setup {
        Ok(Ok(loaded)) => {
            loop {
                let command = {
                    let mut state = locked(&shared.state);
                    registry.journal.acknowledged(state.frontier.last_acked);
                    let command = state.ordinary.take_request();
                    if command.is_none()
                        && (state.terminal.is_some() || shared.abandoned.load(Ordering::Acquire))
                    {
                        break;
                    }
                    command
                };
                let command = match command {
                    Some(command) => command,
                    None => {
                        thread::park();
                        continue;
                    }
                };
                if let Some((seq, deadline, operation)) = map_request_identity(&command) {
                    active_deadline = deadline;
                    registry.journal.begin(seq, operation);
                    execute_map_command(
                        &shared,
                        &mut registry,
                        &mut read_workspace,
                        &loaded,
                        &mut driver,
                        command,
                    );
                    continue;
                }
                let Some(OwnerRequest::Attach {
                    request: attach_request,
                    ack,
                }) = Some(command)
                else {
                    thread::park();
                    continue;
                };
                active_deadline = attach_request.deadline;
                registry
                    .journal
                    .begin(attach_request.seq, CountOperation::Attach);
                let result = catch_unwind(AssertUnwindSafe(|| {
                    let result = registry.attach(
                        &mut driver,
                        loaded.program,
                        request.input.target_tgid,
                        &attach_request,
                        ack,
                    );
                    (result, driver.now())
                }));
                let returned = result.is_ok();
                let (result, command_finished) = match result {
                    Ok(result) => result,
                    Err(_) => {
                        let operation = locked(&shared.state)
                            .active_operation
                            .unwrap_or(CountOperation::Attach);
                        (
                            Err(OwnerFailure::engine(operation, FailureClass::Panic)),
                            Instant::now(),
                        )
                    }
                };
                #[cfg(test)]
                registry.observe_attach_storage();
                let mut state = locked(&shared.state);
                let entered = state.active_operation.take().is_some();
                if returned && (entered || result.is_ok()) {
                    state.last_completed_seq = Some(attach_request.seq);
                    registry
                        .journal
                        .completed(attach_request.seq, CountOperation::Attach);
                }
                let result = result.and_then(|ack| {
                    if hooks.fail_attach_publication {
                        Err(OwnerFailure::engine(
                            CountOperation::Attach,
                            FailureClass::Publication,
                        ))
                    } else if command_finished >= attach_request.deadline {
                        Err(OwnerFailure::engine(
                            CountOperation::Attach,
                            FailureClass::Deadline,
                        ))
                    } else if state.terminal.is_some() || shared.abandoned.load(Ordering::Acquire) {
                        Err(OwnerFailure::engine(
                            CountOperation::Attach,
                            FailureClass::Disconnected,
                        ))
                    } else {
                        Ok(ack)
                    }
                });
                let response = match result {
                    Ok(ack) => {
                        state.phase = OwnerPhase::Observing;
                        Ok(CommandAck {
                            seq: attach_request.seq,
                            value: ack,
                        })
                    }
                    Err(failure) => {
                        state.failures.record_at(failure, shared.now());
                        let ticket = shared.seal_locked(&mut state, attach_request.deadline);
                        state.phase = OwnerPhase::Sealing;
                        Err(CommandFailure {
                            seq: attach_request.seq,
                            failure,
                            completion: if failure.class == FailureClass::Panic {
                                CommandCompletion::Unknown
                            } else if entered {
                                CommandCompletion::Completed
                            } else {
                                CommandCompletion::NotEntered
                            },
                            cleanup_ticket: Some(ticket),
                        })
                    }
                };
                // Both vectors were reserved before this command. Publishing
                // moves metadata only; successful FDs already have custody.
                let successful_reply = response.is_ok();
                if state
                    .ordinary
                    .publish_reply(OwnerReply::Attached(response))
                    .is_err()
                {
                    shared.seal_locked(&mut state, attach_request.deadline);
                    state.phase = OwnerPhase::Sealing;
                } else if successful_reply {
                    registry.journal.published(attach_request.seq);
                }
                shared.refresh_fallback_locked(&mut state, false);
                shared.changed.notify_all();
            }
            Some(loaded)
        }
        Ok(Err(failure)) => {
            shared.failed(failure);
            None
        }
        Err(_) => {
            shared.failed(OwnerFailure::engine(
                CountOperation::Load,
                FailureClass::Panic,
            ));
            None
        }
    };
    shared.seal(active_deadline);
    let frontier = {
        let mut state = locked(&shared.state);
        registry.journal.acknowledged(state.frontier.last_acked);
        registry.journal.resolved_open(state.resolved_open);
        std::mem::take(&mut state.frontier)
    };
    let inventory = registry.journal.seal(&frontier);
    {
        let mut state = locked(&shared.state);
        state.inventory = Some(inventory);
        shared.refresh_fallback_locked(&mut state, false);
        shared.changed.notify_all();
    }
    if let Some(loaded) = loaded.as_ref() {
        let terminal = catch_unwind(AssertUnwindSafe(|| {
            finish_terminal(
                &shared,
                &mut registry,
                &mut read_workspace,
                loaded,
                &mut driver,
                &hooks,
                &mut terminal_builder,
            );
        }));
        if terminal.is_err() {
            let mut state = locked(&shared.state);
            let operation = state
                .active_operation
                .take()
                .unwrap_or(CountOperation::Close);
            state.failures.record_at(
                OwnerFailure::engine(operation, FailureClass::Panic),
                shared.now(),
            );
            shared.refresh_fallback_locked(&mut state, false);
        }
    }
    shared.cleanup_progress(&registry, OwnerPhase::Cleaning);
    let cleanup = catch_unwind(AssertUnwindSafe(|| registry.cleanup(&mut driver)));
    if cleanup.is_err() {
        let mut state = locked(&shared.state);
        state.cleanup_stranded = true;
        state.failures.record_at(
            OwnerFailure::engine(CountOperation::Cleanup, FailureClass::Panic),
            shared.now(),
        );
        shared.refresh_fallback_locked(&mut state, false);
    }
    shared.cleanup_progress(&registry, OwnerPhase::Cleaning);
    let complete = cleanup.is_ok() && locked(&shared.state).resources.cleanup_complete;
    if complete {
        shared.cleanup_progress(&registry, OwnerPhase::Idle);
    } else {
        let mut state = locked(&shared.state);
        state.cleanup_stranded |= state.resources.resources.iter().any(|resource| {
            matches!(
                resource.state,
                ResourceState::Reserved
                    | ResourceState::Creating
                    | ResourceState::Held
                    | ResourceState::CloseIssued
            )
        });
        shared.refresh_fallback_locked(&mut state, false);
        shared.changed.notify_all();
    }
    shared.barrier.cleaned(shared.epoch, complete);
    if !complete {
        // An unknown creation/consumed-close outcome or cleanup unwind cannot
        // erase the registry or hand it to a replacement closer. Retain this
        // one worker and its bounded custody without retrying a consumed FD.
        loop {
            thread::park();
        }
    }
    // The canonical deadline belongs to the sticky terminal identity even when
    // eventual cleanup happens later. Cleanup never replaces or extends it.
    let _canonical_deadline = locked(&shared.state).terminal.map(|seal| seal.deadline);
}

fn map_request_identity(request: &OwnerRequest) -> Option<(CommandSeq, Instant, CountOperation)> {
    match request {
        OwnerRequest::Open(r) => Some((r.seq, r.deadline, CountOperation::Open)),
        OwnerRequest::Generation(r) => Some((r.seq, r.deadline, CountOperation::Generation)),
        OwnerRequest::Read(r) => Some((r.seq, r.deadline, CountOperation::Read)),
        _ => None,
    }
}
enum MapValue {
    Open(OpenReceipt),
    Generation,
    Read(Arc<RawSnapshot>),
}
fn execute_map_command(
    shared: &Shared,
    registry: &mut Registry,
    workspace: &mut ReadWorkspace,
    loaded: &crate::loader::CountLoadedSlots,
    driver: &mut impl CountIoDriver,
    request: OwnerRequest,
) {
    let (seq, deadline, operation) = map_request_identity(&request).expect("map command");
    let io = io::MapIo::new(shared, registry, loaded, deadline, operation);
    let execution = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match request {
        OwnerRequest::Open(request) => io.open(driver, &request).map(MapValue::Open),
        OwnerRequest::Generation(request) => io
            .generation(driver, request.generation)
            .map(|()| MapValue::Generation),
        OwnerRequest::Read(_) => workspace.read(driver, &io).map(MapValue::Read),
        _ => unreachable!("map command identity was checked"),
    }));
    let returned = execution.is_ok();
    let result =
        execution.unwrap_or_else(|_| Err(OwnerFailure::engine(operation, FailureClass::Panic)));
    let mut state = locked(&shared.state);
    let entered = state.active_operation.take().is_some();
    if returned && entered {
        state.last_completed_seq = Some(seq);
        registry.journal.completed(seq, operation);
    }
    let result = result.and_then(|value| {
        if state.terminal.is_some() || shared.abandoned.load(Ordering::Acquire) {
            Err(OwnerFailure::engine(operation, FailureClass::Disconnected))
        } else {
            Ok(value)
        }
    });
    let result = result.map_err(|failure| {
        state.failures.record_at(failure, shared.now());
        let ticket = shared.seal_locked(&mut state, deadline);
        state.phase = OwnerPhase::Sealing;
        CommandFailure {
            seq,
            failure,
            completion: if !returned {
                CommandCompletion::Unknown
            } else if entered {
                CommandCompletion::Completed
            } else {
                CommandCompletion::NotEntered
            },
            cleanup_ticket: Some(ticket),
        }
    });
    let successful_reply = result.is_ok();
    let reply = match result {
        Ok(MapValue::Open(value)) => OwnerReply::Opened(Ok(CommandAck { seq, value })),
        Ok(MapValue::Generation) => OwnerReply::Generated(Ok(CommandAck { seq, value: () })),
        Ok(MapValue::Read(value)) => OwnerReply::Read(Ok(CommandAck { seq, value })),
        Err(failure) => match operation {
            CountOperation::Open => OwnerReply::Opened(Err(failure)),
            CountOperation::Generation => OwnerReply::Generated(Err(failure)),
            CountOperation::Read => OwnerReply::Read(Err(failure)),
            _ => unreachable!("map operation"),
        },
    };
    if successful_reply {
        state.phase = OwnerPhase::Observing;
    }
    if state.ordinary.publish_reply(reply).is_err() {
        shared.seal_locked(&mut state, deadline);
        state.phase = OwnerPhase::Sealing;
    } else if successful_reply {
        registry.journal.published(seq);
    }
    shared.refresh_fallback_locked(&mut state, false);
    shared.changed.notify_all();
}

#[cfg(test)]
mod tests;

fn terminal_storage(
    epoch: OwnerEpoch,
    input: &CountInput,
    limits: CountOwnerLimits,
    registry: &Registry,
    deadline: Instant,
    domain: EvidenceDomain,
) -> Result<Arc<RawTerminalData>, OwnerFailure> {
    let id = TerminalId {
        owner_epoch: epoch,
        sequence: TerminalSeq::checked(1)?,
    };
    Ok(Arc::new(RawTerminalData {
        owner_epoch: epoch,
        terminal_id: id,
        deadline,
        last_command_seq: None,
        resolved_open: None,
        evidence_domain: domain,
        inventory: None,
        manifest: registry::preallocated(limits.link_slots)?,
        close_outcomes: registry::preallocated(limits.link_slots)?,
        kernel_profile: resolve_kernel_applicability(&KernelBuildIdentity::default()),
        writer_object_identity: input.object_sha256,
        writer_family: CountDimensions::validated(),
        host_writes_sealed: false,
        final_references: ReferenceFinality::final_owned(),
        seal: SealBracket::default(),
        writers: WriterCompletion::Unknown(QuiescenceReason::Owner),
        checkpoint: None,
        snapshot_binding: None,
        read_status: ReadStatus::NotStarted,
        cleanup_ticket: CleanupTicket {
            owner_epoch: epoch,
            terminal_id: id,
        },
        cleanup_state: CleanupState::Pending(registry.summary_storage()?),
        failures: TerminalFailures::default(),
    }))
}
fn fill_terminal_shared(state: &SharedState, data: &mut RawTerminalData) {
    let seal = state.terminal.expect("sticky terminal slot");
    data.terminal_id = seal.ticket.terminal_id;
    data.cleanup_ticket = seal.ticket;
    data.deadline = seal.deadline;
    data.last_command_seq = state.last_completed_seq;
    data.failures.merge(state.failures.before(seal.deadline));
    data.resolved_open = state.resolved_open;
    data.inventory = state
        .inventory
        .as_ref()
        .and_then(|i| i.as_ref().ok())
        .map(Arc::clone);
    if let Some(inventory) = &data.inventory {
        data.manifest.clear();
        data.manifest.extend(inventory.records.iter().cloned());
        refresh_manifest_close_states(&mut data.manifest, &state.resources.resources);
    }
    if let CleanupState::Pending(summary) | CleanupState::Failed(summary) = &mut data.cleanup_state
    {
        summary.resources.clear();
        summary
            .resources
            .extend_from_slice(&state.resources.resources);
        summary.sealed = state.resources.sealed;
        summary.cleanup_complete = state.resources.cleanup_complete;
    }
    mark_failed_cleanup(data);
    if state.terminal_contradiction || matches!(state.inventory, Some(Err(_))) {
        data.failures.record_at(
            OwnerFailure::engine(CountOperation::Close, FailureClass::Inventory),
            seal.submitted_at,
        );
    }
}
fn refresh_manifest_close_states(
    manifest: &mut [CreationRecord],
    resources: &[ResourceRecord],
) -> usize {
    // Successful link slots and the sealed manifest share creation order; a
    // held successful slot is never reused within its epoch. Traverse those
    // ordered slots once instead of restarting a full search per link. Keep a
    // later serial available if an earlier resource is missing, so missing
    // acknowledgments stay unavailable without erasing a later known outcome.
    let mut resources = resources.iter().peekable();
    let mut visits = 0;
    for record in manifest {
        while let Some(resource) = resources.peek() {
            visits += 1;
            match resource.resource {
                ResourceId::Link(id) if id == record.id => {
                    record.close_state = resource.state;
                    record.close_errno = resource.errno;
                    resources.next();
                    break;
                }
                ResourceId::Link(id)
                    if id.owner_epoch == record.id.owner_epoch && id.serial > record.id.serial =>
                {
                    break;
                }
                _ => {
                    resources.next();
                }
            }
        }
    }
    visits
}
fn finish_terminal(
    shared: &Shared,
    registry: &mut Registry,
    workspace: &mut ReadWorkspace,
    loaded: &crate::loader::CountLoadedSlots,
    driver: &mut impl CountIoDriver,
    hooks: &PrepareHooks,
    builder: &mut Arc<RawTerminalData>,
) {
    let (explicit, possibly_opened) = {
        let state = locked(&shared.state);
        (
            state.terminal_expected.is_some(),
            state.resolved_open.is_some(),
        )
    };
    // A never-opened Ready family has known-inert admission. Once an Open was
    // submitted, failures/abandonment use this same stop/close path and its
    // existing deadline; no new grace period or ordinary I/O is admitted.
    if !explicit && !possibly_opened {
        return;
    }
    let data = Arc::get_mut(builder).expect("unpublished owner terminal builder");
    {
        let mut state = locked(&shared.state);
        state.phase = OwnerPhase::Sealing;
        fill_terminal_shared(&state, data);
        // Ready's no-observation authority ends before any terminal map I/O,
        // even if there have never been links. A late full read cannot be
        // relabeled as the zero-I/O KnownEmpty exception.
        if shared.now() < data.deadline && shared.first_trigger.load(Ordering::Acquire) != 1 {
            state.initial_empty = None;
        }
    }
    #[cfg(test)]
    {
        data.kernel_profile = hooks.kernel_profile;
        data.final_references = hooks.final_references;
        data.writer_family = hooks.writer_family;
    }
    #[cfg(not(test))]
    let _ = hooks;
    let stopped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if shared.first_trigger.load(Ordering::Acquire) == 1 || shared.now() >= data.deadline {
            return SealBracket {
                before_ns: None,
                after_ns: None,
                result: StopResult::Failed(OwnerFailure::engine(
                    CountOperation::Stop,
                    FailureClass::Deadline,
                )),
            };
        }
        io::MapIo::terminal(
            shared,
            registry,
            loaded,
            data.deadline,
            CountOperation::Stop,
        )
        .stop(driver)
    }));
    data.seal = stopped.unwrap_or_else(|_| SealBracket {
        before_ns: None,
        after_ns: None,
        result: StopResult::Failed(OwnerFailure::engine(
            CountOperation::Stop,
            FailureClass::Panic,
        )),
    });
    if let StopResult::Failed(failure) = data.seal.result {
        data.failures.record_at(failure, shared.now());
    }
    {
        let mut state = locked(&shared.state);
        state.active_operation = None;
        state.phase = OwnerPhase::Closing;
        if let StopResult::Failed(failure) = data.seal.result {
            state.failures.record_at(failure, shared.now());
        }
        if shared.now() < data.deadline
            && let Some(fallback) = state.terminal_fallback.as_mut()
        {
            let fallback = Arc::get_mut(fallback).expect("unpublished stop progress");
            copy_terminal_proof(data, fallback);
        }
        shared.changed.notify_all();
    }
    registry.close_writers(driver, &mut data.close_outcomes);
    registry.copy_manifest(&mut data.manifest);
    for close in &data.close_outcomes {
        if close.state != ResourceState::CloseReturned || close.errno.is_some() {
            data.failures.record_at(
                OwnerFailure {
                    operation: CountOperation::Close,
                    resource: ResourceId::Link(close.id),
                    class: if close.returned_at.is_none() {
                        FailureClass::Panic
                    } else {
                        FailureClass::Io
                    },
                    errno: close.errno,
                },
                shared.now(),
            );
        }
    }
    data.host_writes_sealed = true;
    let now = shared.now();
    let reason = if !explicit {
        Some(QuiescenceReason::Owner)
    } else if locked(&shared.state).terminal_contradiction || data.inventory.is_none() {
        Some(QuiescenceReason::Inventory)
    } else if !matches!(data.seal, SealBracket { result: StopResult::Stopped, before_ns: Some(b), after_ns: Some(a) } if b <= a)
    {
        Some(QuiescenceReason::Stop)
    } else if data.close_outcomes.len() != data.manifest.len()
        || data
            .close_outcomes
            .iter()
            .any(|c| c.state != ResourceState::CloseReturned || c.errno.is_some())
    {
        Some(QuiescenceReason::Close)
    } else if !data.final_references.file || !data.final_references.bpf_link {
        Some(QuiescenceReason::References)
    } else if !data.kernel_profile.applicable(data.evidence_domain) {
        Some(QuiescenceReason::Profile)
    } else if data.writer_family != CountDimensions::validated() {
        Some(QuiescenceReason::ObjectDrift)
    } else if now >= data.deadline {
        Some(QuiescenceReason::Deadline)
    } else {
        None
    };
    if let Some(reason) = reason {
        let class = match reason {
            QuiescenceReason::Profile => Some(FailureClass::Profile),
            QuiescenceReason::ObjectDrift => Some(FailureClass::ObjectDrift),
            QuiescenceReason::References | QuiescenceReason::Inventory => {
                Some(FailureClass::Inventory)
            }
            QuiescenceReason::Deadline => Some(FailureClass::Deadline),
            _ => None,
        };
        if let Some(class) = class {
            data.failures.record_at(
                OwnerFailure::engine(CountOperation::Close, class),
                shared.now(),
            );
        }
    }
    data.writers = reason.map_or_else(
        || {
            WriterCompletion::Finished(WriterWitness {
                owner_epoch: shared.epoch,
                terminal_id: data.terminal_id,
                last_command_seq: data.last_command_seq,
                writer_object_identity: data.writer_object_identity,
                established_at: now,
            })
        },
        WriterCompletion::Unknown,
    );
    if shared.first_trigger.load(Ordering::Acquire) != 1
        && driver.now() < data.deadline
        && shared.now() < data.deadline
    {
        let start = shared.now();
        {
            let mut state = locked(&shared.state);
            state.phase = OwnerPhase::Snapshotting;
            state.terminal_read_started = Some(start);
            // Fixed proof metadata is available even if a subsequent map read
            // blocks. Copy into the second preallocated envelope, then freeze
            // only the coordinator's first selected result at its cutoff.
            if let Some(fallback) = state.terminal_fallback.as_mut() {
                let fallback = Arc::get_mut(fallback).expect("unpublished fallback proof");
                copy_terminal_proof(data, fallback);
            }
        }
        let read = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            workspace.read(
                driver,
                &io::MapIo::terminal(
                    shared,
                    registry,
                    loaded,
                    data.deadline,
                    CountOperation::Read,
                ),
            )
        }));
        let completed_at = shared.now();
        match read {
            Ok(Ok(snapshot)) if completed_at < data.deadline => {
                data.snapshot_binding = Some(SnapshotBinding {
                    sequence: snapshot.sequence,
                    started_at: start,
                    completed_at,
                    immutable: matches!(data.writers, WriterCompletion::Finished(_)),
                });
                data.read_status = if snapshot_complete(&snapshot) {
                    ReadStatus::Complete
                } else {
                    ReadStatus::Incomplete {
                        enumeration: snapshot.enumeration,
                    }
                };
                data.checkpoint = Some(RawCheckpoint {
                    snapshot,
                    phase: OwnerPhase::Snapshotting,
                    published_at: completed_at,
                });
            }
            failed => {
                let failure = match failed {
                    Ok(Err(failure)) => failure,
                    Err(_) => OwnerFailure::engine(CountOperation::Read, FailureClass::Panic),
                    _ => OwnerFailure::engine(CountOperation::Read, FailureClass::Deadline),
                };
                data.failures.record_at(failure, shared.now());
                data.checkpoint = shared
                    .latest_progress
                    .try_lock()
                    .ok()
                    .and_then(|p| p.clone())
                    .filter(|p| p.published_at < data.deadline);
                bind_terminal_prefix(data, start);
            }
        }
    }
    record_terminal_components(data);
    #[cfg(test)]
    if let Some(observer) = &hooks.before_terminal_publication {
        observer();
    }
    {
        let mut state = locked(&shared.state);
        state.active_operation = None;
        data.failures.merge(state.failures.before(data.deadline));
        if let CleanupState::Pending(summary) | CleanupState::Failed(summary) =
            &mut data.cleanup_state
        {
            registry.publish_into(summary);
        }
        mark_failed_cleanup(data);
        state.phase = OwnerPhase::Result;
        let published_at = shared.now();
        if state.terminal_result.is_none() && published_at < data.deadline {
            state.terminal_candidate = Some((published_at, RawTerminal(Arc::clone(builder))));
        }
        shared.changed.notify_all();
    }
}
fn record_terminal_components(data: &mut RawTerminalData) {
    if let Some(checkpoint) = &data.checkpoint {
        for component in [checkpoint.snapshot.admitted, checkpoint.snapshot.dropfail]
            .into_iter()
            .chain(checkpoint.snapshot.latc)
        {
            if let Component::Unavailable(failure) = component {
                data.failures.record_component(failure);
            }
        }
    }
}

fn copy_terminal_proof(source: &RawTerminalData, destination: &mut RawTerminalData) {
    destination.seal = source.seal;
    destination.writers = source.writers;
    destination.host_writes_sealed = source.host_writes_sealed;
    destination.final_references = source.final_references;
    destination.kernel_profile = source.kernel_profile;
    destination.writer_family = source.writer_family;
    destination.failures = source.failures;
    destination.close_outcomes.clear();
    destination
        .close_outcomes
        .extend_from_slice(&source.close_outcomes);
}

fn copy_terminal_result(source: &RawTerminalData, destination: &mut RawTerminalData) {
    // The second preallocated envelope becomes the canonical view. Only bounded
    // metadata is copied; the row image and inventory remain immutable Arcs.
    destination.owner_epoch = source.owner_epoch;
    destination.terminal_id = source.terminal_id;
    destination.deadline = source.deadline;
    destination.cleanup_ticket = source.cleanup_ticket;
    destination.last_command_seq = source.last_command_seq;
    destination.resolved_open = source.resolved_open;
    destination.evidence_domain = source.evidence_domain;
    destination.writer_object_identity = source.writer_object_identity;
    destination.inventory = source.inventory.clone();
    destination.manifest.clear();
    destination.manifest.extend_from_slice(&source.manifest);
    copy_terminal_proof(source, destination);
    destination.checkpoint = source.checkpoint.clone();
    destination.snapshot_binding = source.snapshot_binding;
    destination.read_status = source.read_status;
}

fn mark_failed_cleanup(data: &mut RawTerminalData) {
    let failed = matches!(&data.cleanup_state, CleanupState::Pending(summary)
        if summary.resources.iter().any(|r| r.state == ResourceState::ConsumedError));
    if !failed {
        return;
    }
    if let CleanupState::Pending(summary) =
        std::mem::replace(&mut data.cleanup_state, CleanupState::Complete)
    {
        data.cleanup_state = CleanupState::Failed(summary);
    }
}

fn bind_terminal_prefix(data: &mut RawTerminalData, started_at: Instant) {
    let Some(checkpoint) = data
        .checkpoint
        .as_ref()
        .filter(|p| p.phase == OwnerPhase::Snapshotting)
    else {
        return;
    };
    data.snapshot_binding = Some(SnapshotBinding {
        sequence: checkpoint.snapshot.sequence,
        started_at,
        completed_at: checkpoint.published_at,
        immutable: matches!(data.writers, WriterCompletion::Finished(_)),
    });
    data.read_status = ReadStatus::Incomplete {
        enumeration: checkpoint.snapshot.enumeration,
    };
}
