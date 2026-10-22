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
struct SharedState {
    ready: Option<Result<Ready, OwnerFailure>>,
    terminal: Option<Seal>,
    terminal_ids: protocol::IdCounter,
    resources: ResourceSummary,
    phase: OwnerPhase,
}
struct Shared {
    epoch: OwnerEpoch,
    barrier: Arc<CountForkBarrier>,
    setup_deadline: Instant,
    abandoned: Arc<AtomicBool>,
    worker: OnceLock<thread::Thread>,
    state: Mutex<SharedState>,
    changed: Condvar,
}
impl Shared {
    fn seal(&self, deadline: Instant) -> CleanupTicket {
        let mut state = locked(&self.state);
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
        if state.ready.is_none() {
            state.ready = Some(Err(failure));
        }
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
        // All registry, ready/reply, sticky-terminal and progress cells exist
        // before the worker starts. No ordinary command is admitted in Preparing.
        let shared = Arc::new(Shared {
            epoch,
            barrier: Arc::clone(&input.fork_barrier),
            setup_deadline: deadline,
            abandoned: Arc::clone(&registry.abandoned),
            worker: OnceLock::new(),
            state: Mutex::new(SharedState {
                ready: None,
                terminal: None,
                terminal_ids: protocol::IdCounter::default(),
                resources,
                phase: OwnerPhase::Preparing,
            }),
            changed: Condvar::new(),
        });
        registry.shared = Some(Arc::clone(&shared));
        input.fork_barrier.admit(epoch, deadline)?;
        let owner_shared = Arc::clone(&shared);
        let task =
            Box::new(move || owner_main(owner_shared, input, prepared, registry, hooks, factory));
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
            if let Some(result) = state.ready.take() {
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
    #[cfg(test)]
    registry_observer: Option<Arc<dyn Fn(registry::RegistryEvent) + Send + Sync>>,
}
impl PrepareHooks {
    fn live() -> Self {
        Self {
            domain: EvidenceDomain::Live,
            fail_allocation: false,
            fail_ready_publication: false,
            #[cfg(test)]
            registry_observer: None,
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
    input: CountInput,
    prepared: crate::loader::Prepared,
    mut registry: Registry,
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
    let mut driver = match catch_unwind(AssertUnwindSafe(factory)) {
        Ok(driver) => driver,
        Err(_) => {
            shared.failed(OwnerFailure::engine(
                CountOperation::Load,
                FailureClass::Panic,
            ));
            // No syscall seam was entered. Resolve the actual empty registry,
            // rather than manufacturing a cleanup acknowledgment from a count.
            registry.seal_unentered();
            shared.cleanup_progress(&registry, OwnerPhase::Idle);
            let complete = locked(&shared.state).resources.cleanup_complete;
            shared.barrier.cleaned(shared.epoch, complete);
            return;
        }
    };
    let setup = catch_unwind(AssertUnwindSafe(|| {
        if shared.abandoned.load(Ordering::Acquire) {
            return Err(OwnerFailure::engine(
                CountOperation::Load,
                FailureClass::Disconnected,
            ));
        }
        let loaded = crate::loader::load_count_tracked(
            &prepared,
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
        // Keep data-only load slots in this owner's stack through cleanup.
        let _loaded = loaded;
        let mut state = locked(&shared.state);
        if shared.abandoned.load(Ordering::Acquire) {
            return Err(OwnerFailure::engine(
                CountOperation::Load,
                FailureClass::Disconnected,
            ));
        }
        registry.publish_into(&mut state.resources);
        state.phase = OwnerPhase::Ready;
        state.ready = Some(Ok(Ready {
            owner_epoch: shared.epoch,
            writer_object_identity: input.object_sha256,
            dimensions: CountDimensions::validated(),
            evidence_domain: hooks.domain,
        }));
        shared.changed.notify_all();
        Ok(())
    }));
    match setup {
        Ok(Ok(())) => {
            while !shared.abandoned.load(Ordering::Acquire) {
                thread::park();
            }
        }
        Ok(Err(failure)) => shared.failed(failure),
        Err(_) => shared.failed(OwnerFailure::engine(
            CountOperation::Load,
            FailureClass::Panic,
        )),
    }
    shared.seal(shared.setup_deadline);
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
