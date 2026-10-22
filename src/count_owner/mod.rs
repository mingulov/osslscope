//! SPDX-License-Identifier: GPL-3.0-or-later
//! A prepared exclusive owner for bounded count-resource acquisition/cleanup.
//! No descriptor or join obligation enters the controller's handle.
// The owner is integrated with the session by subsequent serial tasks. Keep
// these crate-private contracts available without publishing a new library API.
#![allow(dead_code)]
pub(crate) mod io;
pub(crate) mod protocol;
pub(crate) mod registry;
use io::{CountIoDriver, LiveCountIoDriver};
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
}
// One bounded inline reply cell exists before count acquisition. Boxing Ready
// here would introduce a publication allocation; the 344-byte cell is intended.
#[allow(clippy::large_enum_variant)]
enum OwnerReply {
    Prepared(Result<Ready, OwnerFailure>),
    Attached(CommandResult<AttachAck<LinkToken>>),
}
struct SharedState {
    ordinary: OrdinaryCells<OwnerRequest, OwnerReply>,
    terminal: Option<Seal>,
    terminal_ids: protocol::IdCounter,
    resources: ResourceSummary,
    phase: OwnerPhase,
    active_operation: Option<CountOperation>,
    last_command_seq: Option<CommandSeq>,
    frontier: ControllerFrontier,
    inventory: Option<Result<SealedInventory, InventoryFailure>>,
}
struct Shared {
    epoch: OwnerEpoch,
    barrier: Arc<CountForkBarrier>,
    setup_deadline: Instant,
    link_limit: usize,
    abandoned: Arc<AtomicBool>,
    worker: OnceLock<thread::Thread>,
    state: Mutex<SharedState>,
    changed: Condvar,
}
impl Shared {
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
        state.terminal = Some(Seal { ticket, deadline });
        ticket
    }
    fn abandon(&self) {
        self.abandoned.store(true, Ordering::Release);
        if let Some(worker) = self.worker.get() {
            worker.unpark();
        }
    }
    fn failed(&self, failure: OwnerFailure) {
        self.seal(self.setup_deadline);
        let mut state = locked(&self.state);
        let _ = state
            .ordinary
            .publish_reply(OwnerReply::Prepared(Err(failure)));
        self.changed.notify_all();
    }
    fn cleanup_progress(&self, registry: &Registry, phase: OwnerPhase) {
        let mut state = locked(&self.state);
        state.phase = phase;
        registry.publish_into(&mut state.resources);
        self.changed.notify_all();
    }
    fn registry_progress(&self, registry: &Registry) {
        let mut state = locked(&self.state);
        registry.publish_into(&mut state.resources);
        self.changed.notify_all();
    }
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
    pub fn resource_summary(&self) -> ResourceSummary {
        locked(&self.shared.state).resources.clone()
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
        let shared = Arc::new(Shared {
            epoch,
            barrier: Arc::clone(&input.fork_barrier),
            setup_deadline: deadline,
            link_limit: limits.link_slots,
            abandoned: Arc::clone(&registry.abandoned),
            worker: OnceLock::new(),
            state: Mutex::new(SharedState {
                ordinary,
                terminal: None,
                terminal_ids: protocol::IdCounter::default(),
                resources,
                phase: OwnerPhase::Preparing,
                active_operation: None,
                last_command_seq: None,
                frontier: ControllerFrontier {
                    acknowledged_links,
                    ..ControllerFrontier::default()
                },
                inventory: None,
            }),
            changed: Condvar::new(),
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
        let task = Box::new(move || owner_main(owner_shared, registry, hooks, factory));
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
    fail_allocation: bool,
    fail_ready_publication: bool,
    fail_attach_publication: bool,
    #[cfg(test)]
    registry_observer: Option<Arc<dyn Fn(registry::RegistryEvent) + Send + Sync>>,
    #[cfg(test)]
    mailbox_observer: Option<Arc<dyn Fn(MailboxEvent) + Send + Sync>>,
}
impl PrepareHooks {
    fn live() -> Self {
        Self {
            domain: EvidenceDomain::Live,
            fail_allocation: false,
            fail_ready_publication: false,
            fail_attach_publication: false,
            #[cfg(test)]
            registry_observer: None,
            #[cfg(test)]
            mailbox_observer: None,
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
fn owner_main<D, F>(shared: Arc<Shared>, mut registry: Registry, hooks: PrepareHooks, factory: F)
where
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
    match setup {
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
                let Some(OwnerRequest::Attach {
                    request: attach_request,
                    ack,
                }) = command
                else {
                    thread::park();
                    continue;
                };
                active_deadline = attach_request.deadline;
                registry.journal.begin(attach_request.seq);
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
                shared.changed.notify_all();
            }
        }
        Ok(Err(failure)) => shared.failed(failure),
        Err(_) => shared.failed(OwnerFailure::engine(
            CountOperation::Load,
            FailureClass::Panic,
        )),
    }
    shared.seal(active_deadline);
    let frontier = {
        let mut state = locked(&shared.state);
        registry.journal.acknowledged(state.frontier.last_acked);
        std::mem::take(&mut state.frontier)
    };
    let inventory = registry.journal.seal(&frontier);
    {
        let mut state = locked(&shared.state);
        state.inventory = Some(inventory);
        shared.changed.notify_all();
    }
    shared.cleanup_progress(&registry, OwnerPhase::Cleaning);
    let cleanup = catch_unwind(AssertUnwindSafe(|| registry.cleanup(&mut driver)));
    shared.cleanup_progress(&registry, OwnerPhase::Cleaning);
    let complete = cleanup.is_ok() && locked(&shared.state).resources.cleanup_complete;
    if complete {
        shared.cleanup_progress(&registry, OwnerPhase::Idle);
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

#[cfg(test)]
mod tests;
