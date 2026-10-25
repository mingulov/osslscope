//! SPDX-License-Identifier: GPL-3.0-or-later
//! Native pre-release link custody. The application coordinator adds its real
//! prepared-window and Count observer to this state at the integration boundary.
use crate::capture::{BoundaryFailure, BoundaryFailureClass, BoundaryStage};
use crate::discovery::session::{LinkEntry, LinkKind, LinkSet};
use std::os::fd::OwnedFd;
use std::sync::{
    Arc, Mutex, MutexGuard,
    atomic::{AtomicBool, AtomicU8, Ordering},
};
use std::time::Instant;

pub(crate) const MAX_SETUP_LINKS: usize = 1024;
const MAX_TEMPORARY_FDS: usize = 4;
pub(crate) const COUNT_NON_COUNT_FD_RESERVE: u64 = (2 * MAX_SETUP_LINKS + MAX_TEMPORARY_FDS) as u64;

#[derive(Clone)]
pub(crate) enum SetupInterrupt {
    Static(&'static AtomicBool),
    #[cfg(test)]
    Owned(Arc<AtomicBool>),
}
impl SetupInterrupt {
    fn raised(&self) -> bool {
        match self {
            Self::Static(flag) => flag.load(Ordering::Acquire),
            #[cfg(test)]
            Self::Owned(flag) => flag.load(Ordering::Acquire),
        }
    }
}
#[derive(Clone)]
pub(crate) struct SetupControl {
    deadline: Instant,
    interrupted: SetupInterrupt,
    abandoned: Arc<AtomicBool>,
    stage: Arc<AtomicU8>,
    native: Arc<std::sync::OnceLock<std::sync::Weak<NativeCore>>>,
}
#[derive(Debug, Clone)]
pub(crate) enum SetupFailure {
    Cancelled { stage: BoundaryStage },
    Resource { stage: BoundaryStage },
    Boundary(BoundaryFailure),
}
impl std::fmt::Display for SetupFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled { stage } => write!(f, "setup cancelled at {stage:?}"),
            Self::Resource { stage } => write!(f, "setup resource capacity exhausted at {stage:?}"),
            Self::Boundary(failure) => f.write_str(&failure.detail),
        }
    }
}
impl std::error::Error for SetupFailure {}
impl SetupFailure {
    pub(crate) fn io(stage: BoundaryStage, error: &std::io::Error, detail: &str) -> Self {
        Self::Boundary(BoundaryFailure::new(
            stage,
            BoundaryFailureClass::Io,
            error.raw_os_error(),
            detail,
        ))
    }

    pub(crate) fn from_error(stage: BoundaryStage, error: anyhow::Error) -> Self {
        Self::from_error_ref(stage, &error)
    }
    pub(crate) fn from_error_ref(stage: BoundaryStage, error: &anyhow::Error) -> Self {
        if let Some(failure) = error.downcast_ref::<Self>() {
            return failure.clone();
        }
        let failure = BoundaryFailure::from_error(stage, error);
        if failure.class == BoundaryFailureClass::Cancelled {
            Self::Cancelled {
                stage: failure.stage,
            }
        } else {
            Self::Boundary(failure)
        }
    }
}
#[cfg(test)]
std::thread_local! {
    static MATERIALIZATION_HOLD: std::cell::RefCell<Option<Arc<app_tests::Gate>>> = const { std::cell::RefCell::new(None) };
}
#[derive(Clone)]
enum FailureState {
    Cancelled(BoundaryStage),
    Timeout(BoundaryStage),
    Resource(BoundaryStage),
    Boundary(Arc<BoundaryFailure>),
}
impl FailureState {
    fn prepared(failure: SetupFailure) -> Self {
        match failure {
            SetupFailure::Cancelled { stage } => Self::Cancelled(stage),
            SetupFailure::Resource { stage } => Self::Resource(stage),
            SetupFailure::Boundary(failure) => Self::Boundary(Arc::new(failure)),
        }
    }
    fn materialize(self) -> SetupFailure {
        #[cfg(test)]
        MATERIALIZATION_HOLD.with(|slot| {
            if let Some(gate) = slot.borrow_mut().take() {
                gate.hold();
            }
        });
        match self {
            Self::Cancelled(stage) => SetupFailure::Cancelled { stage },
            Self::Resource(stage) => SetupFailure::Resource { stage },
            Self::Timeout(stage) => SetupFailure::Boundary(BoundaryFailure::new(
                stage,
                BoundaryFailureClass::Timeout,
                None,
                "setup deadline expired",
            )),
            Self::Boundary(failure) => SetupFailure::Boundary((*failure).clone()),
        }
    }
}
impl SetupControl {
    pub(crate) fn new(deadline: Instant, interrupted: SetupInterrupt) -> Self {
        Self {
            deadline,
            interrupted,
            abandoned: Arc::new(AtomicBool::new(false)),
            stage: Arc::new(AtomicU8::new(0)),
            native: Arc::new(std::sync::OnceLock::new()),
        }
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn abandon(&self) {
        self.abandoned.store(true, Ordering::Release);
    }
    fn bind(&self, links: &SetupLinks) {
        let _ = self.native.set(Arc::downgrade(&links.0));
    }
    pub(crate) fn check_effect(&self, stage: BoundaryStage) -> Result<(), SetupFailure> {
        if let Some(state) = self.native.get().and_then(std::sync::Weak::upgrade) {
            return SetupLinks(state).check(self, stage);
        }
        self.check(stage)
    }
    pub(crate) fn stage(&self) -> BoundaryStage {
        match self.stage.load(Ordering::Acquire) {
            1 => BoundaryStage::Discovery,
            2 => BoundaryStage::Traversal,
            3 => BoundaryStage::Fence,
            4 => BoundaryStage::Release,
            5 => BoundaryStage::Open,
            _ => BoundaryStage::Setup,
        }
    }
    fn status(&self, stage: BoundaryStage) -> Option<FailureState> {
        self.stage.store(
            match stage {
                BoundaryStage::Discovery => 1,
                BoundaryStage::Traversal => 2,
                BoundaryStage::Fence => 3,
                BoundaryStage::Release => 4,
                BoundaryStage::Open => 5,
                _ => 0,
            },
            Ordering::Release,
        );
        if self.interrupted.raised() || self.abandoned.load(Ordering::Acquire) {
            return Some(FailureState::Cancelled(stage));
        }
        if Instant::now() >= self.deadline {
            return Some(FailureState::Timeout(stage));
        }
        None
    }
    pub(crate) fn check(&self, stage: BoundaryStage) -> Result<(), SetupFailure> {
        self.status(stage)
            .map_or(Ok(()), |failure| Err(failure.materialize()))
    }
}
fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

// One preallocated one-way handoff marker belongs to the same custody owner.
// It records actual ReleaseCommit, never Ready/acceptance arbitration.
struct NativeCore {
    state: Mutex<NativeState>,
    runtime_committed: AtomicBool,
}
impl std::ops::Deref for NativeCore {
    type Target = Mutex<NativeState>;
    fn deref(&self) -> &Self::Target {
        &self.state
    }
}
// This is the one native custody mutex; no separate Ready/acceptance protocol.
#[derive(Clone)]
pub(crate) struct SetupLinks(Arc<NativeCore>);
#[derive(Clone, Copy, PartialEq, Eq)]
enum Publication {
    Running,
    Ready,
    Accepted,
    Abandoned,
}
pub(crate) struct WorkerContext {
    pub(crate) comm: String,
    pub(crate) container_id: String,
    pub(crate) kernel_release: String,
}
struct NativeState {
    worker_context: Option<Arc<WorkerContext>>,
    #[cfg(test)]
    retained_fd_probe: [Option<i32>; 4],
    #[cfg(test)]
    retained_mapping_probe: [Option<(usize, usize)>; 2],
    #[cfg(test)]
    mapping_cleanup_hold: Option<Arc<NativeTestGate>>,
    #[cfg(test)]
    context_comm_hold: Option<Arc<NativeTestGate>>,
    phase: Publication,
    payload_type: Option<std::any::TypeId>,
    payload: Option<Box<dyn std::any::Any + Send>>,
    watch: Option<crate::count_owner::CountSetupWatch>,
    custody: Option<Arc<crate::capture::CustodyReceipt>>,
    terminal: Option<crate::capture::PreObservationCount>,
    worker_done: bool,
    native_disposed: bool,
    failure_instant: Option<Instant>,
    grace: std::time::Duration,
    control: Option<SetupControl>,
    retained_child: Option<crate::target::OwnedSetupCleanup>,
    abandoned: bool,
    failure: Option<FailureState>,
    in_flight: usize,
    temporary: usize,
    discovery: Vec<LinkEntry>,
    retired_discovery: Vec<LinkEntry>,
    members: Vec<MemberLink>,
    retired_members: Vec<MemberLink>,
    pins: Vec<OwnedFd>,
}
pub(crate) struct MemberLink {
    pub(crate) slot: Option<u32>,
    pub(crate) link: OwnedFd,
}
pub(crate) struct SetupDisplaced {
    pub(crate) guards: Vec<SetupLinks>,
    pub(crate) discovery: Vec<DiscoveryLinkStore>,
    pub(crate) members: Vec<MemberLinkStore>,
    pub(crate) controls: Vec<SetupControl>,
    pub(crate) custody: Vec<SetupLinkCustody>,
}
impl SetupDisplaced {
    fn new() -> Self {
        Self {
            guards: Vec::with_capacity(8),
            discovery: Vec::with_capacity(1),
            members: Vec::with_capacity(1),
            controls: Vec::with_capacity(1),
            custody: Vec::with_capacity(1),
        }
    }
}
#[derive(Default)]
pub(crate) struct SetupLinkCustody {
    discovery: Vec<LinkEntry>,
    retired_discovery: Vec<LinkEntry>,
    pins: Vec<OwnedFd>,
    members: Vec<MemberLink>,
    retired_members: Vec<MemberLink>,
}
#[derive(Clone)]
pub(crate) struct SetupWeak(std::sync::Weak<NativeCore>);
impl SetupWeak {
    pub(crate) fn disposal_error(&self, stage: BoundaryStage, error: &std::io::Error) {
        if let Some(state) = self.0.upgrade() {
            if state.runtime_committed.load(Ordering::Acquire) {
                return;
            }
            let links = SetupLinks(state);
            links.seal(SetupFailure::io(
                stage,
                error,
                "setup mapping disposal failed",
            ));
            links.before_dispose(stage);
        }
    }
}
impl SetupLinks {
    fn commit_runtime(&self, _: &crate::capture::ReleaseCommit) {
        self.0.runtime_committed.store(true, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn test_retained_fd(&self, fd: i32) {
        let mut state = locked(&self.0);
        if let Some(slot) = state
            .retained_fd_probe
            .iter_mut()
            .find(|slot| slot.is_none())
        {
            *slot = Some(fd);
        }
    }
    #[cfg(test)]
    pub(crate) fn test_retained_mapping(&self, address: usize, len: usize) {
        let mut state = locked(&self.0);
        if let Some(slot) = state
            .retained_mapping_probe
            .iter_mut()
            .find(|slot| slot.is_none())
        {
            *slot = Some((address, len));
        }
    }
    #[cfg(test)]
    pub(crate) fn test_fds(&self) -> [Option<i32>; 4] {
        locked(&self.0).retained_fd_probe
    }
    pub(crate) fn weak(&self) -> SetupWeak {
        SetupWeak(Arc::downgrade(&self.0))
    }
    #[cfg(test)]
    pub(crate) fn test_mapping_cleanup_hold(&self) -> Option<Arc<NativeTestGate>> {
        locked(&self.0).mapping_cleanup_hold.take()
    }
    #[cfg(test)]
    pub(crate) fn context_comm_test_hold(&self) {
        let gate = locked(&self.0).context_comm_hold.take();
        if let Some(gate) = gate {
            gate.hold();
        }
    }
    pub(crate) fn publish_context(&self, info: &crate::capture::TargetInfo) {
        // Existing capture fields only. Linux comm, container IDs and utsname
        // have finite limits; prepare bounded owned data before the arbiter.
        let context = Arc::new(WorkerContext {
            comm: info.comm.chars().take(64).collect(),
            container_id: info.container_id.chars().take(64).collect(),
            kernel_release: info.kernel_release.chars().take(64).collect(),
        });
        let displaced = { locked(&self.0).worker_context.replace(context) };
        drop(displaced);
    }
    pub(crate) fn worker_context(&self) -> Option<Arc<WorkerContext>> {
        locked(&self.0).worker_context.clone()
    }
    pub(crate) fn coordinated(&self) -> bool {
        locked(&self.0).payload_type.is_some()
    }
    pub(crate) fn await_resource_disposal(&self) {
        loop {
            if self.0.runtime_committed.load(Ordering::Acquire) {
                return;
            }
            let state = locked(&self.0);
            if state.payload_type.is_none()
                || (state.custody.as_ref().is_some_and(|receipt| {
                    matches!(
                        receipt.resolution,
                        crate::capture::CustodyResolution::Resolved
                            | crate::capture::CustodyResolution::NotAcquired
                    )
                }) && state.native_disposed)
            {
                return;
            }
            drop(state);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    pub(crate) fn before_dispose(&self, stage: BoundaryStage) {
        if self.0.runtime_committed.load(Ordering::Acquire) {
            return;
        }
        if !self.coordinated() {
            return;
        }
        if std::thread::panicking() {
            self.seal(SetupFailure::Boundary(BoundaryFailure::new(
                stage,
                BoundaryFailureClass::Panic,
                None,
                "setup resource scope unwound",
            )));
        }
        if locked(&self.0).abandoned {
            self.await_resource_disposal();
        }
    }
    pub(crate) fn retain_result<T>(
        &self,
        result: anyhow::Result<T>,
        stage: BoundaryStage,
    ) -> anyhow::Result<T> {
        if let Err(error) = &result {
            self.seal(SetupFailure::from_error_ref(stage, error));
            if self.coordinated() {
                self.await_resource_disposal();
            }
        }
        result
    }
    pub(crate) fn new() -> Self {
        Self(Arc::new(NativeCore {
            runtime_committed: AtomicBool::new(false),
            state: Mutex::new(NativeState {
                worker_context: None,
                #[cfg(test)]
                retained_fd_probe: [None; 4],
                #[cfg(test)]
                retained_mapping_probe: [None; 2],
                #[cfg(test)]
                mapping_cleanup_hold: None,
                #[cfg(test)]
                context_comm_hold: None,
                phase: Publication::Running,
                payload_type: None,
                payload: None,
                watch: None,
                custody: None,
                terminal: None,
                worker_done: false,
                native_disposed: false,
                failure_instant: None,
                grace: std::time::Duration::ZERO,
                retained_child: None,
                control: None,
                abandoned: false,
                failure: None,
                in_flight: 0,
                temporary: 0,
                discovery: Vec::with_capacity(MAX_SETUP_LINKS),
                retired_discovery: Vec::with_capacity(MAX_SETUP_LINKS),
                members: Vec::with_capacity(MAX_SETUP_LINKS),
                retired_members: Vec::with_capacity(MAX_SETUP_LINKS),
                pins: Vec::with_capacity(MAX_SETUP_LINKS),
            }),
        }))
    }
    pub(crate) fn seal(&self, failure: SetupFailure) {
        let mut failure = Some(FailureState::prepared(failure));
        let mut state = locked(&self.0);
        state.abandoned = true;
        state.phase = Publication::Abandoned;
        state.failure_instant.get_or_insert_with(Instant::now);
        if state.failure.is_none() {
            state.failure = failure.take();
        }
        drop(state);
        drop(failure);
    }
    fn sealed_failure(state: &NativeState, stage: BoundaryStage) -> FailureState {
        state
            .failure
            .clone()
            .unwrap_or(FailureState::Cancelled(stage))
    }
    fn checked_state(
        &self,
        control: &SetupControl,
        stage: Option<BoundaryStage>,
    ) -> Result<MutexGuard<'_, NativeState>, FailureState> {
        let mut state = locked(&self.0);
        let stage = stage.unwrap_or_else(|| control.stage());
        if let Some(failure) = &state.failure {
            return Err(failure.clone());
        }
        if let Some(failure) = control.status(stage) {
            state.abandoned = true;
            state.phase = Publication::Abandoned;
            state.failure_instant.get_or_insert_with(Instant::now);
            state.failure = Some(failure.clone());
            return Err(failure);
        }
        if state.abandoned {
            return Err(Self::sealed_failure(&state, stage));
        }
        Ok(state)
    }
    pub(crate) fn check(
        &self,
        control: &SetupControl,
        stage: BoundaryStage,
    ) -> Result<(), SetupFailure> {
        self.checked_state(control, Some(stage))
            .map(drop)
            .map_err(FailureState::materialize)
    }
    pub(crate) fn control_for_effect(&self) -> Option<SetupControl> {
        locked(&self.0).control.clone()
    }
    pub(crate) fn check_owned(&self, stage: BoundaryStage) -> Result<(), SetupFailure> {
        let control = locked(&self.0).control.clone();
        match control {
            Some(control) => self.check(&control, stage),
            None => Ok(()),
        }
    }
    pub(crate) fn reserve(
        &self,
        control: &SetupControl,
        stage: BoundaryStage,
        count: usize,
    ) -> Result<SetupLinkReservation, SetupFailure> {
        let mut state = self
            .checked_state(control, Some(stage))
            .map_err(FailureState::materialize)?;
        let used = state.discovery.len()
            + state.retired_discovery.len()
            + state.members.len()
            + state.retired_members.len()
            + state.in_flight;
        if count > MAX_SETUP_LINKS - used {
            let failure = SetupFailure::Resource { stage };
            state.abandoned = true;
            state.phase = Publication::Abandoned;
            state.failure_instant.get_or_insert_with(Instant::now);
            state.failure = Some(FailureState::Resource(stage));
            return Err(failure);
        }
        state.in_flight += count;
        Ok(SetupLinkReservation {
            links: self.clone(),
            remaining: count,
            stage,
        })
    }
    pub(crate) fn temporary(
        &self,
        control: &SetupControl,
        stage: BoundaryStage,
        count: usize,
    ) -> Result<TemporaryFds, SetupFailure> {
        let mut state = self
            .checked_state(control, Some(stage))
            .map_err(FailureState::materialize)?;
        if count > MAX_TEMPORARY_FDS - state.temporary {
            let failure = SetupFailure::Resource { stage };
            state.abandoned = true;
            state.phase = Publication::Abandoned;
            state.failure_instant.get_or_insert_with(Instant::now);
            state.failure = Some(FailureState::Resource(stage));
            return Err(failure);
        }
        state.temporary += count;
        Ok(TemporaryFds {
            links: self.clone(),
            count,
        })
    }
    fn publish_discovery(
        &self,
        entry: LinkEntry,
        stage: BoundaryStage,
    ) -> Result<(), SetupFailure> {
        let result = {
            let mut state = locked(&self.0);
            state.in_flight -= 1;
            if state.abandoned {
                Err((entry, Self::sealed_failure(&state, stage)))
            } else {
                state.discovery.push(entry);
                Ok(())
            }
        };
        result.map_err(|(late, failure)| {
            self.before_dispose(stage);
            drop(late);
            failure.materialize()
        })
    }
    pub(crate) fn discovery_counts(&self) -> (u64, u64) {
        let state = locked(&self.0);
        state
            .discovery
            .iter()
            .fold((0, 0), |(dispatch, trip), entry| {
                if entry.kind == LinkKind::Tripwire {
                    (dispatch, trip + 1)
                } else {
                    (dispatch + 1, trip)
                }
            })
    }
    pub(crate) fn retire_discovery(&self, mut matches: impl FnMut(LinkKind, &[u64]) -> bool) {
        // Evaluate the port's predicate outside the publication mutex. Only
        // this session's worker mutates these entries; abandonment may drain
        // them concurrently, in which case there is nothing left to retire.
        let mut metadata = Vec::with_capacity(MAX_SETUP_LINKS);
        {
            let state = locked(&self.0);
            for entry in &state.discovery {
                metadata.push((entry.kind, Vec::new(), entry.cookies.len()));
            }
        }
        for (_, cookies, len) in &mut metadata {
            cookies.reserve_exact(*len);
        }
        {
            let state = locked(&self.0);
            for ((_, cookies, _), entry) in metadata.iter_mut().zip(&state.discovery) {
                cookies.extend_from_slice(&entry.cookies);
            }
        }
        let selected: Vec<_> = metadata
            .iter()
            .map(|(kind, cookies, _)| matches(*kind, cookies))
            .collect();
        let mut state = locked(&self.0);
        for index in (0..selected.len().min(state.discovery.len())).rev() {
            if selected[index] {
                let entry = state.discovery.remove(index);
                state.retired_discovery.push(entry);
            }
        }
    }
    fn publish_member(
        &self,
        slot: Option<u32>,
        link: OwnedFd,
        stage: BoundaryStage,
    ) -> Result<(), SetupFailure> {
        let entry = MemberLink { slot, link };
        let result = {
            let mut state = locked(&self.0);
            state.in_flight -= 1;
            if state.abandoned {
                Err((entry, Self::sealed_failure(&state, stage)))
            } else {
                state.members.push(entry);
                Ok(())
            }
        };
        result.map_err(|(late, failure)| {
            self.before_dispose(stage);
            drop(late);
            failure.materialize()
        })
    }
    pub(crate) fn retire_members(&self) {
        let mut state = locked(&self.0);
        while let Some(link) = state.members.pop() {
            if link.slot.is_some() {
                state.retired_members.push(link);
            } else {
                state.members.push(link);
                break;
            }
        }
    }
    // Called by the later child-first owner only after its consuming reap receipt.
    // This method just seals and moves custody; it never closes a descriptor.
    pub(crate) fn abandon(&self) -> SetupLinkCustody {
        let mut state = locked(&self.0);
        state.abandoned = true;
        SetupLinkCustody {
            discovery: std::mem::take(&mut state.discovery),
            retired_discovery: std::mem::take(&mut state.retired_discovery),
            pins: std::mem::take(&mut state.pins),
            members: std::mem::take(&mut state.members),
            retired_members: std::mem::take(&mut state.retired_members),
        }
    }
}

/// A real returned resource, guarded only on the coordinated pre-release path.
/// Error sites publish their cause before this guard can await child custody.
pub(crate) struct SetupResource<T> {
    value: Option<T>,
    links: Option<SetupLinks>,
    stage: BoundaryStage,
}
impl<T> SetupResource<T> {
    pub(crate) fn local(value: T) -> Self {
        Self {
            value: Some(value),
            links: None,
            stage: BoundaryStage::Setup,
        }
    }
    pub(crate) fn guarded(value: T, links: &SetupLinks, stage: BoundaryStage) -> Self {
        Self {
            value: Some(value),
            links: Some(links.clone()),
            stage,
        }
    }
    pub(crate) fn into_inner(mut self) -> T {
        self.value.take().expect("owned resource")
    }
    pub(crate) fn setup_links(&self) -> Option<&SetupLinks> {
        self.links.as_ref()
    }
    pub(crate) fn take_setup(&mut self) -> Option<SetupLinks> {
        self.links.take()
    }
    pub(crate) fn before_dispose(&self) {
        if let Some(links) = &self.links {
            links.before_dispose(self.stage);
        }
    }
}
impl<T> std::ops::Deref for SetupResource<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.value.as_ref().expect("owned resource")
    }
}
impl<T> std::ops::DerefMut for SetupResource<T> {
    fn deref_mut(&mut self) -> &mut T {
        self.value.as_mut().expect("owned resource")
    }
}
impl<T> Drop for SetupResource<T> {
    fn drop(&mut self) {
        if self.value.is_some() {
            if let Some(links) = &self.links {
                links.before_dispose(self.stage);
            }
        }
    }
}
pub(crate) struct SetupLinkReservation {
    links: SetupLinks,
    remaining: usize,
    stage: BoundaryStage,
}
impl SetupLinkReservation {
    pub(crate) fn publish_discovery(&mut self, entry: LinkEntry) -> Result<(), SetupFailure> {
        assert!(self.remaining > 0);
        self.remaining -= 1;
        self.links.publish_discovery(entry, self.stage)
    }
    pub(crate) fn publish_member(
        &mut self,
        slot: Option<u32>,
        link: OwnedFd,
    ) -> Result<(), SetupFailure> {
        assert!(self.remaining > 0);
        self.remaining -= 1;
        self.links.publish_member(slot, link, self.stage)
    }
}
impl Drop for SetupLinkReservation {
    fn drop(&mut self) {
        locked(&self.links.0).in_flight -= self.remaining;
    }
}
pub(crate) struct TemporaryFds {
    links: SetupLinks,
    count: usize,
}
impl Drop for TemporaryFds {
    fn drop(&mut self) {
        locked(&self.links.0).temporary -= self.count;
    }
}

impl SetupLinkCustody {
    pub(crate) fn append(&mut self, other: &mut Self) {
        self.discovery.append(&mut other.discovery);
        self.retired_discovery.append(&mut other.retired_discovery);
        self.members.append(&mut other.members);
        self.retired_members.append(&mut other.retired_members);
        self.pins.append(&mut other.pins);
    }

    pub(crate) fn split_ready(&mut self, member_pool: &mut Vec<OwnedFd>) -> (LinkSet, MemberLinks) {
        let discovery = LinkSet {
            links: std::mem::take(&mut self.discovery),
        };
        let mut entry = None;
        for member in self.members.drain(..) {
            match member.slot {
                None if entry.is_none() => entry = Some(member.link),
                _ => member_pool.push(member.link),
            }
        }
        (
            discovery,
            MemberLinks {
                entry,
                members: std::mem::take(member_pool),
            },
        )
    }
    pub(crate) fn active(discovery: LinkSet, members: MemberLinks) -> Self {
        let mut member_fds =
            Vec::with_capacity(members.members.len() + usize::from(members.entry.is_some()));
        if let Some(link) = members.entry {
            member_fds.push(MemberLink { slot: None, link });
        }
        for (slot, link) in members.members.into_iter().enumerate() {
            member_fds.push(MemberLink {
                slot: Some(slot as u32),
                link,
            });
        }
        Self {
            discovery: discovery.links,
            members: member_fds,
            retired_discovery: Vec::new(),
            retired_members: Vec::new(),
            pins: Vec::new(),
        }
    }
}

impl Drop for SetupLinkCustody {
    fn drop(&mut self) {
        // All link closes precede every discovery pin close. The eventual
        // child-first owner chooses when to drop this real custody object.
        for entry in self
            .discovery
            .drain(..)
            .chain(self.retired_discovery.drain(..))
        {
            self.pins.push(entry.pin);
            drop(entry.link);
        }
        for member in self.members.drain(..).chain(self.retired_members.drain(..)) {
            drop(member.link);
        }
        self.pins.clear();
    }
}

/// Local observation custody or the shared pre-release ledger. The actual
/// Runner integration is the only future caller allowed to promote to local.
pub(crate) enum DiscoveryLinkStore {
    Local(LinkSet),
    Preparing {
        links: SetupLinks,
        control: SetupControl,
    },
}
impl Default for DiscoveryLinkStore {
    fn default() -> Self {
        Self::Local(LinkSet::default())
    }
}
impl DiscoveryLinkStore {
    pub(crate) fn setup_links(&self) -> Option<&SetupLinks> {
        match self {
            Self::Preparing { links, .. } => Some(links),
            _ => None,
        }
    }
    pub(crate) fn resource<T>(&self, value: T) -> SetupResource<T> {
        match self.setup_links() {
            Some(links) => SetupResource::guarded(value, links, BoundaryStage::Discovery),
            None => SetupResource::local(value),
        }
    }
    pub(crate) fn retain_result<T>(&self, result: anyhow::Result<T>) -> anyhow::Result<T> {
        match self.setup_links() {
            Some(links) => links.retain_result(result, BoundaryStage::Discovery),
            None => result,
        }
    }

    pub(crate) fn preparing(links: &SetupLinks, control: &SetupControl) -> Self {
        Self::Preparing {
            links: links.clone(),
            control: control.clone(),
        }
    }
    pub(crate) fn reserve(&self, count: usize) -> anyhow::Result<Option<SetupLinkReservation>> {
        match self {
            Self::Local(_) => Ok(None),
            Self::Preparing { links, control } => Ok(Some(links.reserve(
                control,
                BoundaryStage::Discovery,
                count,
            )?)),
        }
    }
    pub(crate) fn temporary(&self, count: usize) -> anyhow::Result<Option<TemporaryFds>> {
        match self {
            Self::Local(_) => Ok(None),
            Self::Preparing { links, control } => Ok(Some(links.temporary(
                control,
                BoundaryStage::Discovery,
                count,
            )?)),
        }
    }
    pub(crate) fn check(&self) -> anyhow::Result<()> {
        if let Self::Preparing { links, control } = self {
            links.check(control, BoundaryStage::Discovery)?;
        }
        Ok(())
    }
    pub(crate) fn push(
        &mut self,
        entry: LinkEntry,
        reservation: &mut Option<SetupLinkReservation>,
    ) -> anyhow::Result<()> {
        match self {
            Self::Local(links) => links.links.push(entry),
            Self::Preparing { .. } => reservation
                .as_mut()
                .expect("reserved before native effect")
                .publish_discovery(entry)?,
        }
        Ok(())
    }
    pub(crate) fn mark(&self) -> Option<usize> {
        if let Self::Local(links) = self {
            Some(links.links.len())
        } else {
            None
        }
    }
    pub(crate) fn abort(&self, failure: SetupFailure) {
        if let Self::Preparing { links, .. } = self {
            links.seal(failure);
        }
    }
    pub(crate) fn rollback(&mut self, mark: Option<usize>, failure: SetupFailure) {
        match (self, mark) {
            (Self::Local(links), Some(mark)) => links.links.truncate(mark),
            (Self::Preparing { links, .. }, _) => links.seal(failure),
            _ => {}
        }
    }
    pub(crate) fn clear(&mut self) {
        self.remove_matching(|_, _| true);
    }
    pub(crate) fn counts(&self) -> (u64, u64) {
        match self {
            Self::Local(links) => links.counts(),
            Self::Preparing { links, .. } => links.discovery_counts(),
        }
    }
    pub(crate) fn remove_matching(&mut self, predicate: impl FnMut(LinkKind, &[u64]) -> bool) {
        match self {
            Self::Local(links) => links.remove_matching(predicate),
            Self::Preparing { links, .. } => links.retire_discovery(predicate),
        }
    }
}

pub(crate) struct MemberLinks {
    pub(crate) entry: Option<OwnedFd>,
    pub(crate) members: Vec<OwnedFd>,
}
pub(crate) enum MemberLinkStore {
    Local(MemberLinks),
    Preparing {
        links: SetupLinks,
        control: SetupControl,
    },
}
impl MemberLinkStore {
    pub(crate) fn setup_links(&self) -> Option<&SetupLinks> {
        match self {
            Self::Preparing { links, .. } => Some(links),
            _ => None,
        }
    }
    pub(crate) fn resource<T>(&self, value: T) -> SetupResource<T> {
        match self.setup_links() {
            Some(links) => SetupResource::guarded(value, links, BoundaryStage::Traversal),
            None => SetupResource::local(value),
        }
    }
    pub(crate) fn retain_result<T>(&self, result: anyhow::Result<T>) -> anyhow::Result<T> {
        match self.setup_links() {
            Some(links) => links.retain_result(result, BoundaryStage::Traversal),
            None => result,
        }
    }

    pub(crate) fn local() -> Self {
        Self::Local(MemberLinks {
            entry: None,
            members: Vec::with_capacity(512),
        })
    }
    pub(crate) fn preparing(links: &SetupLinks, control: &SetupControl) -> Self {
        Self::Preparing {
            links: links.clone(),
            control: control.clone(),
        }
    }
    pub(crate) fn reserve(&self) -> anyhow::Result<Option<SetupLinkReservation>> {
        match self {
            Self::Local(_) => Ok(None),
            Self::Preparing { links, control } => {
                Ok(Some(links.reserve(control, BoundaryStage::Traversal, 1)?))
            }
        }
    }
    pub(crate) fn temporary(&self, count: usize) -> anyhow::Result<Option<TemporaryFds>> {
        match self {
            Self::Local(_) => Ok(None),
            Self::Preparing { links, control } => Ok(Some(links.temporary(
                control,
                BoundaryStage::Traversal,
                count,
            )?)),
        }
    }
    pub(crate) fn check(&self) -> anyhow::Result<()> {
        if let Self::Preparing { links, control } = self {
            links.check(control, BoundaryStage::Traversal)?;
        }
        Ok(())
    }
    pub(crate) fn push(
        &mut self,
        slot: Option<u32>,
        link: OwnedFd,
        reservation: &mut Option<SetupLinkReservation>,
    ) -> anyhow::Result<()> {
        match self {
            Self::Local(links) => match slot {
                None => {
                    assert!(links.entry.is_none());
                    links.entry = Some(link);
                }
                Some(_) => links.members.push(link),
            },
            Self::Preparing { .. } => reservation
                .as_mut()
                .expect("reserved before native effect")
                .publish_member(slot, link)?,
        }
        Ok(())
    }
    pub(crate) fn abort(&self, failure: SetupFailure) {
        if let Self::Preparing { links, .. } = self {
            links.seal(failure);
        }
    }
    pub(crate) fn clear_members(&mut self) {
        match self {
            Self::Local(links) => links.members.clear(),
            Self::Preparing { links, .. } => links.retire_members(),
        }
    }
    pub(crate) fn take_local(self) -> MemberLinks {
        match self {
            Self::Local(links) => links,
            Self::Preparing { .. } => {
                unreachable!("pre-release custody requires final publication")
            }
        }
    }
}

// The process slot covers both owners, including an abandoned blocked effect.
static SETUP_ADMITTED: AtomicBool = AtomicBool::new(false);
static SETUP_KEEPALIVE: Mutex<Option<SetupLinks>> = Mutex::new(None);
fn retire_admission() {
    let retained = locked(&SETUP_KEEPALIVE).take();
    drop(retained);
    SETUP_ADMITTED.store(false, Ordering::Release);
}
type Payload = Box<dyn std::any::Any + Send>;
enum CleanupRequest {
    Abort(Option<crate::target::OwnedTarget>),
    Accepted,
}

pub(crate) struct ReleaseReady<D, B: crate::count_session::CountBackend, L> {
    pub(crate) bundle: Box<crate::capture::SetupBundle<D, B, L>>,
}

/// Exactly one typed request and two pre-admitted, parked owners. Only the
/// existing native publication mutex arbitrates Ready against abandonment.
pub(crate) struct SetupAttempt<D, B: crate::count_session::CountBackend, L>
where
    D: Send + 'static,
    B: Send + 'static,
    B::Link: Send,
    L: Send + 'static,
{
    pub(crate) control: SetupControl,
    count_disposal: Arc<crate::count_owner::DisposalHold>,
    pub(crate) links: SetupLinks,
    pub(crate) barrier: Arc<crate::count_owner::SetupBarrierLease>,
    pub(crate) fork_barrier: Arc<crate::count_owner::CountForkBarrier>,
    request: Option<std::sync::mpsc::SyncSender<crate::capture::SetupRequest<D, B, L>>>,
    cleanup: Option<std::sync::mpsc::SyncSender<CleanupRequest>>,
    cleanup_thread: Option<std::thread::JoinHandle<()>>,
    #[cfg(test)]
    disposed: Arc<AtomicBool>,
    pub(crate) target: Option<crate::target::OwnedTarget>,
    pub(crate) ready: Option<ReleaseReady<D, B, L>>,
}

fn infrastructure(detail: &str) -> SetupFailure {
    SetupFailure::Boundary(BoundaryFailure::new(
        BoundaryStage::Setup,
        BoundaryFailureClass::Infrastructure,
        None,
        detail,
    ))
}

impl<D, B, L> SetupAttempt<D, B, L>
where
    D: crate::capture::DiscoveryPort + Send + 'static,
    B: crate::count_session::CountBackend + Send + 'static,
    B::Link: Send,
    L: crate::capture::LifecyclePort + Send + 'static,
{
    pub(crate) fn admit(control: SetupControl) -> Result<Self, SetupFailure> {
        Self::admit_inner(control, false)
    }

    fn admit_inner(control: SetupControl, fail_cleanup_start: bool) -> Result<Self, SetupFailure> {
        control.check(BoundaryStage::Setup)?;
        if SETUP_ADMITTED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(SetupFailure::Resource {
                stage: BoundaryStage::Setup,
            });
        }
        let barrier = Arc::new(crate::count_owner::CountForkBarrier::new());
        let fork_barrier = barrier.clone();
        let barrier = match barrier.reserve_setup() {
            Ok(lease) => Arc::new(lease),
            Err(_) => {
                SETUP_ADMITTED.store(false, Ordering::Release);
                return Err(infrastructure("setup barrier reservation failed"));
            }
        };
        let links = SetupLinks::new();
        control.bind(&links);
        *locked(&SETUP_KEEPALIVE) = Some(links.clone());
        let journal = crate::count_owner::CountSetupJournal::new_held();
        let count_disposal = journal
            .disposal_hold()
            .expect("app admission installs physical hold");
        {
            let mut state = locked(&links.0);
            state.payload_type =
                Some(std::any::TypeId::of::<crate::capture::SetupBundle<D, B, L>>());
            state.watch = Some(journal.watch());
            state.control = Some(control.clone());
        }
        let (request, requests) =
            std::sync::mpsc::sync_channel::<crate::capture::SetupRequest<D, B, L>>(1);
        let (cleanup, cleanups) = std::sync::mpsc::sync_channel(1);
        let work_links = links.clone();
        let work_control = control.clone();
        let work_barrier = barrier.clone();
        let worker = match std::thread::Builder::new()
            .name("osslscope-setup".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _phase = work_barrier.prefix_phase();
                    match requests.recv() {
                        Ok(request) => Some(crate::capture::prepare_setup_request(
                            request,
                            &work_control,
                            &work_links,
                            &work_barrier,
                            &journal,
                        )),
                        Err(_) => None,
                    }
                }));
                // All allocation and all typed preparation happen outside this lock.
                let (mut payload, failure) = match result {
                    Ok(Some((payload, failure))) => (Some(payload), failure),
                    Ok(None) => (None, Some(infrastructure("setup request disconnected"))),
                    Err(_) => (
                        None,
                        Some(SetupFailure::Boundary(BoundaryFailure::new(
                            work_control.stage(),
                            BoundaryFailureClass::Panic,
                            None,
                            "setup worker panicked",
                        ))),
                    ),
                };
                let mut displaced = SetupDisplaced::new();
                let mut member_pool = Vec::with_capacity(MAX_SETUP_LINKS);
                let mut failure = failure.map(FailureState::prepared);
                let mut invalid = Some(FailureState::prepared(infrastructure(
                    "setup Ready has incompatible real port state",
                )));
                // Checked type inspection happens before entering the publication lock.
                let mut prepared = payload.as_mut().and_then(|payload| {
                    if payload.is::<crate::capture::LiveSetupBundle>() {
                        payload
                            .downcast_mut::<crate::capture::LiveSetupBundle>()
                            .map(crate::capture::PublicationWindow::Live)
                    } else {
                        payload
                            .downcast_mut::<crate::capture::SetupBundle<D, B, L>>()
                            .map(crate::capture::PublicationWindow::Host)
                    }
                });
                {
                    let mut state = locked(&work_links.0);
                    if state.failure.is_none() {
                        state.failure = failure
                            .take()
                            .or_else(|| work_control.status(work_control.stage()));
                    }
                    if state.failure.is_none()
                        && !state.abandoned
                        && (!prepared
                            .as_ref()
                            .is_some_and(crate::capture::PublicationWindow::compatible)
                            || state
                                .members
                                .iter()
                                .filter(|member| member.slot.is_none())
                                .count()
                                > 1)
                    {
                        state.failure = invalid.take();
                    }
                    if state.failure.is_some() || state.abandoned {
                        state.abandoned = true;
                        state.phase = Publication::Abandoned;
                        state.failure_instant.get_or_insert_with(Instant::now);
                    } else {
                        let custody = SetupLinkCustody {
                            discovery: std::mem::take(&mut state.discovery),
                            retired_discovery: std::mem::take(&mut state.retired_discovery),
                            pins: std::mem::take(&mut state.pins),
                            members: std::mem::take(&mut state.members),
                            retired_members: std::mem::take(&mut state.retired_members),
                        };
                        // Only crate-owned data installation occurs here. No D/L
                        // trait method, checked downcast, allocation or disposal.
                        if let Some(prepared) = prepared.as_mut() {
                            prepared.install(custody, &mut member_pool, &mut displaced);
                        }
                        state.phase = Publication::Ready;
                    }
                    state.payload = payload;
                    state.worker_done = true;
                }
                drop(displaced);
            }) {
            Ok(worker) => worker,
            Err(error) => {
                barrier.abort();
                retire_admission();
                return Err(SetupFailure::io(
                    BoundaryStage::Setup,
                    &error,
                    "setup worker start failed",
                ));
            }
        };
        // Keep the JoinHandle in its reserved slot until the cleanup owner
        // consumes it. Failure to start the second thread cannot create a child.
        let worker = Arc::new(Mutex::new(Some(worker)));
        let owner_worker = worker.clone();
        let owner_links = links.clone();
        let owner_barrier = barrier.clone();
        let owner_control = control.clone();
        let disposed = Arc::new(AtomicBool::new(false));
        let owner_disposed = disposed.clone();
        let spawn = if fail_cleanup_start {
            Err(std::io::Error::from_raw_os_error(libc::EAGAIN))
        } else {
            std::thread::Builder::new()
                .name("osslscope-setup-cleanup".into())
                .spawn(move || {
                    let request = cleanups.recv();
                    match request {
                        Ok(CleanupRequest::Accepted) => {
                            if let Some(worker) = locked(&owner_worker).take() {
                                let _ = worker.join();
                            }
                        }
                        Ok(CleanupRequest::Abort(target)) => {
                            cleanup_owned::<D, B, L>(
                                target,
                                &owner_links,
                                &owner_control,
                                &owner_barrier,
                                &owner_worker,
                            );
                        }
                        Err(_) => {
                            // A controller unwind sends Abort through Drop. A missing
                            // message is unknown custody: retain the admission and state.
                            loop {
                                std::thread::park_timeout(std::time::Duration::from_millis(1));
                            }
                        }
                    }
                    owner_disposed.store(true, Ordering::Release);
                    retire_admission();
                })
        };
        let cleanup_thread = match spawn {
            Ok(thread) => thread,
            Err(error) => {
                barrier.abort();
                drop(request);
                if let Some(worker) = locked(&worker).take() {
                    let _ = worker.join();
                }
                let _ = barrier.complete_abort();
                retire_admission();
                return Err(SetupFailure::io(
                    BoundaryStage::Setup,
                    &error,
                    "setup cleanup owner start failed",
                ));
            }
        };
        Ok(Self {
            control,
            count_disposal,
            links,
            barrier,
            fork_barrier,
            request: Some(request),
            cleanup: Some(cleanup),
            cleanup_thread: Some(cleanup_thread),
            #[cfg(test)]
            disposed,
            target: None,
            ready: None,
        })
    }

    pub(crate) fn start(
        &mut self,
        request: crate::capture::SetupRequest<D, B, L>,
    ) -> Result<(), SetupFailure> {
        // This one reserved slot is empty and the worker is already parked.
        locked(&self.links.0).grace = request.grace();
        self.request
            .take()
            .ok_or_else(|| infrastructure("setup already started"))?
            .send(request)
            .map_err(|_| infrastructure("setup worker disconnected"))
    }

    pub(crate) fn wait(&mut self) -> Result<(), SetupFailure> {
        loop {
            let transfer = {
                let mut state = self
                    .links
                    .checked_state(&self.control, None)
                    .map_err(FailureState::materialize)?;
                if state.phase == Publication::Ready {
                    // Cancellation, original deadline, then Ready, under the
                    // sole publication mutex. Taking a Box never runs its Drop.
                    state.phase = Publication::Accepted;
                    Some(state.payload.take())
                } else {
                    None
                }
            };
            if let Some(payload) = transfer {
                let payload =
                    payload.ok_or_else(|| infrastructure("Ready missing prepared state"))?;
                match payload.downcast::<crate::capture::SetupBundle<D, B, L>>() {
                    Ok(bundle) => {
                        self.ready = Some(ReleaseReady { bundle });
                        return Ok(());
                    }
                    Err(payload) => {
                        let failure = infrastructure("prepared setup state type mismatch");
                        let mut prepared_failure = Some(FailureState::prepared(failure.clone()));
                        let mut state = locked(&self.links.0);
                        state.payload = Some(payload);
                        if state.failure.is_none() {
                            state.failure = prepared_failure.take();
                        }
                        state.phase = Publication::Abandoned;
                        state.abandoned = true;
                        drop(state);
                        drop(prepared_failure);
                        return Err(failure);
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    pub(crate) fn abandon(&mut self, failure: SetupFailure) {
        self.links.seal(failure);
        self.control.abandon();
        self.barrier.abort();
        // Recover accepted ownership into the same reserved publication slot.
        if let Some(ready) = self.ready.take() {
            let payload: Payload = ready.bundle;
            let mut state = locked(&self.links.0);
            state.payload = Some(payload);
        }
        let (watch, instant) = {
            let state = locked(&self.links.0);
            (
                state.watch.clone(),
                state.failure_instant.unwrap_or_else(Instant::now),
            )
        };
        if let Some(watch) = watch {
            watch.abandon();
            let grace = locked(&self.links.0).grace;
            watch.seal(instant.checked_add(grace).unwrap_or(instant));
        }
        drop(self.request.take());
        if let Some(cleanup) = self.cleanup.take() {
            // Reserved, empty slot; sender failure cannot be silently disposed.
            if let Err(error) = cleanup.send(CleanupRequest::Abort(self.target.take())) {
                if let CleanupRequest::Abort(target) = error.0 {
                    locked(&self.links.0).retained_child =
                        target.map(crate::target::OwnedTarget::into_setup_cleanup);
                }
            }
        }
    }

    pub(crate) fn await_receipt(&self, deadline: Instant) -> crate::capture::CustodyReceipt {
        loop {
            let receipt = { locked(&self.links.0).custody.clone() };
            if let Some(receipt) = receipt {
                return (*receipt).clone();
            }
            if Instant::now() >= deadline {
                return crate::capture::CustodyReceipt {
                    disposition: None,
                    child_exit: None,
                    resolution: crate::capture::CustodyResolution::Unresolved,
                    failure: None,
                };
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    pub(crate) fn count_diagnostic(&self) -> crate::capture::PreObservationCount {
        let (terminal, watch) = {
            let state = locked(&self.links.0);
            (state.terminal.clone(), state.watch.clone())
        };
        terminal
            .or_else(|| {
                watch
                    .as_ref()
                    .and_then(crate::capture::PreObservationCount::from_setup_watch)
            })
            .unwrap_or_else(|| {
                crate::capture::PreObservationCount::SetupPending(
                    crate::capture::CountSetupSnapshot::unknown(),
                )
            })
    }
    #[cfg(test)]
    pub(crate) fn join_cleanup_for_test(&mut self) -> bool {
        if self.cleanup.is_some() {
            self.abandon(infrastructure("test cleanup finally"));
        }
        let joined = self
            .cleanup_thread
            .take()
            .is_none_or(|thread| thread.join().is_ok());
        joined && self.disposed.load(Ordering::Acquire)
    }
    pub(crate) fn failure_instant(&self) -> Instant {
        locked(&self.links.0)
            .failure_instant
            .unwrap_or_else(Instant::now)
    }
    pub(crate) fn accepted(
        &mut self,
        commit: &crate::capture::ReleaseCommit,
    ) -> (crate::target::OwnedTarget, ReleaseReady<D, B, L>) {
        // The actual ReleaseCommit already records successful SIGCONT. Opening
        // this pre-held permission is an atomic data operation, with no new
        // post-signal mutex lookup, allocation, callback or disposal.
        self.count_disposal.release_commit(commit);
        // The actual successful ReleaseCommit ends pre-release disposal custody.
        // This is one preallocated atomic store, not Ready arbitration or I/O.
        self.links.commit_runtime(commit);
        let target = self.target.take().expect("release retains actual target");
        let ready = self
            .ready
            .take()
            .expect("release retains actual prepared state");
        if let Some(cleanup) = self.cleanup.take() {
            let _ = cleanup.send(CleanupRequest::Accepted);
        }
        (target, ready)
    }
}

impl<D, B: crate::count_session::CountBackend, L> Drop for SetupAttempt<D, B, L>
where
    D: Send + 'static,
    B: Send + 'static,
    B::Link: Send,
    L: Send + 'static,
{
    fn drop(&mut self) {
        drop(self.cleanup_thread.take());
        if self.cleanup.is_some() {
            let failure = infrastructure("setup controller unwound before release handoff");
            self.links.seal(failure);
            self.control.abandon();
            self.barrier.abort();
            if let Some(ready) = self.ready.take() {
                let payload: Payload = ready.bundle;
                let mut state = locked(&self.links.0);
                state.payload = Some(payload);
            }
            drop(self.request.take());
            if let Some(cleanup) = self.cleanup.take() {
                if let Err(error) = cleanup.send(CleanupRequest::Abort(self.target.take())) {
                    if let CleanupRequest::Abort(target) = error.0 {
                        locked(&self.links.0).retained_child =
                            target.map(crate::target::OwnedTarget::into_setup_cleanup);
                    }
                }
            }
        }
    }
}

fn cleanup_owned<D, B, L>(
    target: Option<crate::target::OwnedTarget>,
    links: &SetupLinks,
    control: &SetupControl,
    barrier: &crate::count_owner::SetupBarrierLease,
    worker: &Mutex<Option<std::thread::JoinHandle<()>>>,
) where
    D: crate::capture::DiscoveryPort + Send + 'static,
    B: crate::count_session::CountBackend + Send + 'static,
    B::Link: Send,
    L: crate::capture::LifecyclePort + Send + 'static,
{
    use crate::capture::{CustodyReceipt, CustodyResolution, PreObservationCount};
    let mut child = target.map(crate::target::OwnedTarget::into_setup_cleanup);
    let receipt = loop {
        match child.as_mut().map(|child| child.step()) {
            None => {
                break CustodyReceipt {
                    disposition: None,
                    child_exit: None,
                    resolution: CustodyResolution::NotAcquired,
                    failure: None,
                };
            }
            Some(Ok(crate::target::SetupCleanupProgress::Resolved(disposition))) => {
                break CustodyReceipt {
                    disposition: Some(disposition),
                    child_exit: match disposition {
                        crate::target::TargetDisposition::Exited { code } => Some(code),
                        _ => None,
                    },
                    resolution: CustodyResolution::Resolved,
                    failure: None,
                };
            }
            Some(Err(error)) => {
                // An unresolved identity never enters the old target Drop.
                let receipt = Arc::new(CustodyReceipt {
                    disposition: None,
                    child_exit: None,
                    resolution: CustodyResolution::Unresolved,
                    failure: Some(BoundaryFailure::from_error(BoundaryStage::Custody, &error)),
                });
                let displaced = locked(&links.0).custody.replace(receipt);
                drop(displaced);
            }
            Some(Ok(crate::target::SetupCleanupProgress::Pending)) => {}
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    };
    // Immutable consuming-reap/leave-running receipt precedes every resource Drop.
    let receipt = Arc::new(receipt);
    let displaced = locked(&links.0).custody.replace(receipt.clone());
    drop(displaced);
    let watch = { locked(&links.0).watch.clone() };
    if let Some(watch) = watch {
        watch.child_receipt(&receipt);
    }
    let (watch, started_at) = {
        let state = locked(&links.0);
        (
            state.watch.clone(),
            state.failure_instant.unwrap_or_else(Instant::now),
        )
    };
    if let Some(watch) = &watch {
        watch.abandon();
    }
    let native = links.abandon();
    drop(native);
    // This is an actual close-return acknowledgement. Worker-local resources
    // cannot dispose ahead of the shared link buckets on abandonment.
    locked(&links.0).native_disposed = true;
    // The exact worker may still be held in a syscall. Custody is already public.
    if let Some(worker) = locked(worker).take() {
        let _ = worker.join();
    }
    let payload = locked(&links.0).payload.take();
    if let Some(payload) = payload {
        match payload.downcast::<crate::capture::SetupBundle<D, B, L>>() {
            Ok(mut bundle) => {
                if let Some(window) = bundle.window.as_mut() {
                    let terminal = window.terminalize(started_at);
                    locked(&links.0).terminal = Some(PreObservationCount::Terminal(terminal));
                    window.dispose_native();
                }
                drop(bundle);
            }
            Err(payload) => {
                let mut failure = Some(FailureState::prepared(infrastructure(
                    "cleanup prepared state type mismatch",
                )));
                let mut state = locked(&links.0);
                state.payload = Some(payload);
                if state.failure.is_none() {
                    state.failure = failure.take();
                }
                drop(state);
                drop(failure);
                loop {
                    std::thread::park_timeout(std::time::Duration::from_millis(1));
                }
            }
        }
    }
    // A terminal timeout/fallback is not an owner disposal acknowledgement.
    if let Some(watch) = watch {
        loop {
            if let Some(progress) = watch.progress() {
                if progress.owner_epoch.is_none()
                    || (progress.owner_cleanup_acknowledged && progress.owner_task_disposed)
                {
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    let _ = control;
    let _ = barrier.complete_abort();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    fn control() -> SetupControl {
        SetupControl::new(
            Instant::now() + Duration::from_secs(20),
            SetupInterrupt::Owned(Arc::new(AtomicBool::new(false))),
        )
    }
    #[test]
    fn w079_native_capacity_refuses_before_effect() {
        let links = SetupLinks::new();
        let control = control();
        let held = links
            .reserve(&control, BoundaryStage::Traversal, 1024)
            .unwrap();
        assert!(
            matches!(
                links.reserve(&control, BoundaryStage::Traversal, 1),
                Err(SetupFailure::Resource { .. })
            ),
            "a full ledger must refuse before the next native effect"
        );
        drop(held);
    }
    fn pair() -> (OwnedFd, std::os::unix::net::UnixStream) {
        let (fd, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        (fd.into(), peer)
    }
    fn closed(peer: &std::os::unix::net::UnixStream) -> bool {
        use std::io::Read;
        let mut peer = peer;
        match peer.read(&mut [0]) {
            Ok(0) => true,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
            result => panic!("unexpected sentinel read {result:?}"),
        }
    }
    #[test]
    fn w079_native_retirement_retains_capacity_and_real_fd_custody() {
        let links = SetupLinks::new();
        let control = control();
        let (fd, peer) = pair();
        let alias = fd.try_clone().unwrap();
        let mut reservation = links
            .reserve(&control, BoundaryStage::Traversal, 1)
            .unwrap();
        reservation.publish_member(Some(3), fd).unwrap();
        drop(reservation);
        links.retire_members();
        let held = links
            .reserve(&control, BoundaryStage::Traversal, 1023)
            .unwrap();
        assert!(matches!(
            links.reserve(&control, BoundaryStage::Traversal, 1),
            Err(SetupFailure::Resource { .. })
        ));
        let custody = links.abandon();
        assert!(!closed(&peer));
        drop(custody);
        assert!(
            !closed(&peer),
            "retained alias is the negative close witness"
        );
        drop(alias);
        assert!(closed(&peer));
        drop(held);
    }
    #[test]
    fn w079_native_late_link_and_temporary_slots() {
        let links = SetupLinks::new();
        let control = control();
        let temporary = links
            .temporary(&control, BoundaryStage::Discovery, 4)
            .unwrap();
        assert!(matches!(
            links.temporary(&control, BoundaryStage::Discovery, 1),
            Err(SetupFailure::Resource { .. })
        ));
        drop(temporary);
        let links = SetupLinks::new();
        let mut reservation = links
            .reserve(&control, BoundaryStage::Traversal, 1)
            .unwrap();
        let custody = links.abandon();
        let (fd, peer) = pair();
        assert!(matches!(
            reservation.publish_member(None, fd),
            Err(SetupFailure::Cancelled { .. })
        ));
        assert!(closed(&peer));
        assert!(links.0.try_lock().is_ok());
        drop(custody);
        drop(reservation);
        assert!(matches!(
            links.reserve(&control, BoundaryStage::Traversal, 1),
            Err(SetupFailure::Cancelled { .. })
        ));
    }
    #[test]
    fn w079_native_control_prioritizes_cancel_and_preserves_errno() {
        let flag = Arc::new(AtomicBool::new(true));
        let control = SetupControl::new(Instant::now(), SetupInterrupt::Owned(flag.clone()));
        assert!(matches!(
            control.check(BoundaryStage::Discovery),
            Err(SetupFailure::Cancelled {
                stage: BoundaryStage::Discovery
            })
        ));
        flag.store(false, Ordering::Release);
        assert!(matches!(
            control.check(BoundaryStage::Traversal),
            Err(SetupFailure::Boundary(BoundaryFailure {
                class: BoundaryFailureClass::Timeout,
                ..
            }))
        ));
        let control = self::control();
        control.abandon();
        assert!(matches!(
            control.check(BoundaryStage::Setup),
            Err(SetupFailure::Cancelled { .. })
        ));
        let failure = SetupFailure::io(
            BoundaryStage::Discovery,
            &std::io::Error::from_raw_os_error(libc::EPERM),
            "attach query_entry@0x1 failed (kind=PermissionDenied)",
        );
        let recovered = SetupFailure::from_error(
            BoundaryStage::Setup,
            anyhow::Error::new(failure).context("outer stage"),
        );
        assert!(matches!(
            recovered,
            SetupFailure::Boundary(BoundaryFailure {
                errno: Some(libc::EPERM),
                stage: BoundaryStage::Discovery,
                ..
            })
        ));
    }
    #[test]
    fn w079_native_discovery_retirement_uses_unlocked_predicate_and_keeps_pins() {
        let links = SetupLinks::new();
        let control = control();
        let mut store = DiscoveryLinkStore::preparing(&links, &control);
        let (link, peer) = pair();
        let (pin, pin_peer) = pair();
        let mut permit = links
            .reserve(&control, BoundaryStage::Discovery, 1)
            .unwrap();
        permit
            .publish_discovery(LinkEntry {
                link,
                pin,
                kind: LinkKind::Stage2,
                cookies: vec![7],
            })
            .unwrap();
        drop(permit);
        store.remove_matching(|kind, cookies| {
            assert!(
                links.0.try_lock().is_ok(),
                "port callbacks cannot run under custody lock"
            );
            kind == LinkKind::Stage2 && cookies == [7]
        });
        assert_eq!(store.counts(), (0, 0));
        assert!(!closed(&peer));
        assert!(!closed(&pin_peer));
        let held = links
            .reserve(&control, BoundaryStage::Traversal, 1023)
            .unwrap();
        assert!(matches!(
            links.reserve(&control, BoundaryStage::Traversal, 1),
            Err(SetupFailure::Resource { .. })
        ));
        let custody = links.abandon();
        assert!(!closed(&peer));
        drop(custody);
        assert!(closed(&peer));
        assert!(closed(&pin_peer));
        drop(held);
    }
}

#[cfg(test)]
pub(crate) use app_tests::Gate as NativeTestGate;
#[cfg(test)]
mod app_tests {
    use super::*;
    use crate::capture::{self, ClockPort, DiscoveryPort, LifecyclePort, ProcPort};
    use crate::count_session::LiveBackend;
    use crate::discovery::session::{DiscoveryDelta, DiscoverySnapshot, PollBudget};
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::AtomicUsize;
    use std::time::{Duration, SystemTime};

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Hold {
        None,
        Maps,
        Exe,
        Discovery,
        Relevant,
        Traversal,
        Open,
        Fence,
        Attach,
        Unwind,
        ResourceError,
        ResourceUnwind,
        CountError,
        CountUnwind,
        PrepareLoadError,
        PrepareLoadUnwind,
        ContextPartial,
        ContextReady,
        Stage2PinError,
        Stage2PinCancel,
        Stage2PinUnwind,
        BirthError,
        BirthCancel,
        BirthUnwind,
        DiagnosticTimeout,
        DiagnosticError,
        PidPinError,
        FilePinError,
        RingMapInfoError,
        RingMmapError,
        RingMmapUnwind,
        RingUnmapError,
        RuntimeRing,
        HealthyRing,
        ReaderError,
        RecoverableReaderError,
        CountPreflight(crate::count_owner::W079AppPrepareHold),
    }
    pub(crate) struct Gate {
        entered: AtomicBool,
        released: Mutex<bool>,
        wake: std::sync::Condvar,
    }
    impl Gate {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                entered: AtomicBool::new(false),
                released: Mutex::new(false),
                wake: std::sync::Condvar::new(),
            })
        }
        pub(crate) fn hold(&self) {
            self.entered.store(true, Ordering::Release);
            let cutoff = Instant::now() + Duration::from_secs(10);
            let mut released = locked(&self.released);
            while !*released {
                let remaining = cutoff.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                released = self
                    .wake
                    .wait_timeout(released, remaining)
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .0;
            }
        }
        fn release(&self) {
            *locked(&self.released) = true;
            self.wake.notify_all();
        }
    }
    struct Discovery {
        events: Option<crate::loader::Events>,
        pid: u32,
        hold: Hold,
        gate: Arc<Gate>,
        polls: Arc<AtomicUsize>,
        dropped: Arc<AtomicBool>,
        delta: Option<DiscoveryDelta>,
        links: SetupLinks,
        control: SetupControl,
        peers: Arc<Mutex<Vec<UnixStream>>>,
        alias: Arc<Mutex<Option<UnixStream>>>,
        file: Option<std::path::PathBuf>,
    }
    impl Drop for Discovery {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }
    impl DiscoveryPort for Discovery {
        fn poll(&mut self, _: PollBudget) -> anyhow::Result<DiscoveryDelta> {
            self.polls.fetch_add(1, Ordering::AcqRel);
            if matches!(self.hold, Hold::Discovery | Hold::None)
                && self.polls.load(Ordering::Acquire) == 1
            {
                let mut first = self
                    .links
                    .reserve(&self.control, BoundaryStage::Discovery, 1)?;
                let (link, peer) = UnixStream::pair()?;
                let (pin, pin_peer) = UnixStream::pair()?;
                *locked(&self.alias) = Some(link.try_clone()?);
                locked(&self.peers).extend([peer, pin_peer]);
                first.publish_discovery(LinkEntry {
                    link: link.into(),
                    pin: pin.into(),
                    kind: LinkKind::Stage2,
                    cookies: vec![1],
                })?;
                let mut late = self
                    .links
                    .reserve(&self.control, BoundaryStage::Discovery, 1)?;
                if self.hold == Hold::Discovery {
                    self.gate.hold();
                }
                let (link, peer) = UnixStream::pair()?;
                let (pin, pin_peer) = UnixStream::pair()?;
                locked(&self.peers).extend([peer, pin_peer]);
                late.publish_discovery(LinkEntry {
                    link: link.into(),
                    pin: pin.into(),
                    kind: LinkKind::Stage2,
                    cookies: vec![2],
                })?;
            }
            if matches!(self.hold, Hold::DiagnosticTimeout | Hold::DiagnosticError) {
                if self.hold == Hold::DiagnosticError {
                    self.links.seal(SetupFailure::io(
                        BoundaryStage::Discovery,
                        &std::io::Error::from_raw_os_error(libc::EIO),
                        "diagnostic first cause",
                    ));
                } else {
                    while Instant::now() < self.control.deadline() {
                        std::thread::yield_now();
                    }
                }
                MATERIALIZATION_HOLD.with(|slot| *slot.borrow_mut() = Some(self.gate.clone()));
                self.links.check_owned(BoundaryStage::Discovery)?;
            }
            if matches!(
                self.hold,
                Hold::Stage2PinError | Hold::Stage2PinCancel | Hold::Stage2PinUnwind
            ) {
                let mode = match self.hold {
                    Hold::Stage2PinError => 1,
                    Hold::Stage2PinUnwind => 2,
                    _ => 0,
                };
                let _effect = crate::plan::pin_metadata_test(mode, self.gate.clone(), &self.links);
                if self.hold == Hold::Stage2PinError {
                    crate::discovery::session::w079_bootstrap_pin_boundary(
                        &self.links,
                        &self.control,
                    )?;
                } else {
                    crate::discovery::session::w079_stage2_pin_boundary(
                        &self.links,
                        &self.control,
                    )?;
                }
            }
            if matches!(
                self.hold,
                Hold::BirthError | Hold::BirthCancel | Hold::BirthUnwind
            ) {
                crate::scan::registry::w079_birth_boundary(
                    &self.links,
                    &self.control,
                    self.gate.clone(),
                    if self.hold == Hold::BirthUnwind { 2 } else { 0 },
                )?;
            }
            if self.hold == Hold::PidPinError {
                let _slot = self
                    .links
                    .temporary(&self.control, BoundaryStage::Discovery, 1)?;
                crate::pin::pin_controlled_fault(self.pid, &self.links)?;
            }
            if self.hold == Hold::FilePinError {
                let _slot = self
                    .links
                    .temporary(&self.control, BoundaryStage::Discovery, 1)?;
                crate::plan::resolve_pinned_controlled_fault("/dev/null", &self.links)?;
            }
            if matches!(
                self.hold,
                Hold::RingMapInfoError
                    | Hold::RingMmapError
                    | Hold::RingMmapUnwind
                    | Hold::RingUnmapError
                    | Hold::RuntimeRing
                    | Hold::HealthyRing
            ) && self.events.is_none()
            {
                use std::os::fd::{AsFd as _, AsRawFd as _, FromRawFd as _};
                if matches!(self.hold, Hold::RingUnmapError | Hold::RuntimeRing) {
                    locked(&self.links.0).mapping_cleanup_hold = Some(self.gate.clone());
                }
                let raw = unsafe { libc::memfd_create(c"w079-events".as_ptr(), libc::MFD_CLOEXEC) };
                if raw < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                let fd = SetupResource::guarded(
                    unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) },
                    &self.links,
                    BoundaryStage::Discovery,
                );
                self.links.test_retained_fd(fd.as_raw_fd());
                if unsafe { libc::ftruncate(fd.as_raw_fd(), 4096 * 4) } != 0 {
                    self.links.retain_result::<()>(
                        Err(std::io::Error::last_os_error().into()),
                        BoundaryStage::Discovery,
                    )?;
                }
                if self.hold == Hold::RingMapInfoError {
                    self.links.retain_result(
                        crate::loader::BorrowedMap::new(fd.as_fd())
                            .map(|_| ())
                            .map_err(Into::into),
                        BoundaryStage::Discovery,
                    )?;
                } else {
                    let events = crate::loader::prepare_host_events(
                        fd.as_fd(),
                        &self.links,
                        match self.hold {
                            Hold::RuntimeRing | Hold::HealthyRing => 0,
                            Hold::RingMmapUnwind => 2,
                            _ => 1,
                        },
                    )?;
                    self.events = Some(events);
                }
            }
            if matches!(self.hold, Hold::ResourceError | Hold::ResourceUnwind) {
                let (map, peer) = UnixStream::pair()?;
                let (prog, prog_peer) = UnixStream::pair()?;
                locked(&self.peers).extend([peer, prog_peer]);
                let _loaded = SetupResource::guarded(
                    crate::loader::Loaded {
                        maps: std::collections::HashMap::from([("map".into(), map.into())]),
                        progs: std::collections::HashMap::from([("prog".into(), prog.into())]),
                    },
                    &self.links,
                    BoundaryStage::Discovery,
                );
                if self.hold == Hold::ResourceUnwind {
                    panic!("retained native Loaded unwind control");
                }
                self.links.retain_result::<()>(
                    Err(std::io::Error::from_raw_os_error(libc::EIO).into()),
                    BoundaryStage::Discovery,
                )?;
            }
            if self.hold == Hold::ReaderError {
                crate::discovery::onboard::read_bounded_controlled(
                    self.file.as_ref().unwrap(),
                    1,
                    &self.links,
                    BoundaryStage::Discovery,
                    true,
                )
                .map_err(|error| anyhow::anyhow!(error))?;
            }
            assert_ne!(self.hold, Hold::Unwind, "owned baseline unwind control");
            Ok(self.delta.take().unwrap_or_default())
        }
        fn snapshot(&self) -> DiscoverySnapshot {
            DiscoverySnapshot::default()
        }
        fn finish(&mut self) -> anyhow::Result<DiscoverySnapshot> {
            Ok(self.snapshot())
        }
        fn traversal_active(&self) -> bool {
            self.hold == Hold::Traversal
        }
        fn poll_traversal(&mut self, _: bool) -> anyhow::Result<capture::TraversalDelta> {
            self.gate.hold();
            Ok(capture::TraversalDelta::default())
        }
    }
    struct Lifecycle(Arc<AtomicUsize>);
    impl LifecyclePort for Lifecycle {
        fn poll(&mut self) -> capture::LifecycleDelta {
            capture::LifecycleDelta::default()
        }
        fn fallback_partial(&self) -> bool {
            true
        }
        fn mark_released(&mut self) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }
    struct Proc {
        hold: Hold,
        gate: Arc<Gate>,
        live: capture::LiveProc,
        mapping: Option<crate::discovery::maps::Mapping>,
        setup: SetupLinks,
    }
    impl ProcPort for Proc {
        fn read_maps(&mut self, _: u32) -> anyhow::Result<Vec<crate::discovery::maps::Mapping>> {
            if self.hold == Hold::Maps {
                self.gate.hold();
            }
            Ok(self.mapping.iter().cloned().collect())
        }
        fn read_exe(&mut self, _: u32) -> Option<std::path::PathBuf> {
            if self.hold == Hold::Exe {
                self.gate.hold();
            }
            None
        }
        fn read_file(&mut self, path: &str) -> anyhow::Result<Vec<u8>> {
            self.live.read_file(path)
        }
        fn read_file_bound(
            &mut self,
            path: &str,
            max: usize,
        ) -> std::io::Result<(Arc<[u8]>, (u64, u64))> {
            if self.hold == Hold::Relevant {
                self.gate.hold();
            }
            if self.hold == Hold::RecoverableReaderError {
                return crate::plan::read_file_bounded_controlled(
                    path,
                    1,
                    &self.setup,
                    BoundaryStage::Discovery,
                    false,
                )
                .map(|file| (file.bytes, (file.dev, file.ino)));
            }
            self.live.read_file_bound(path, max)
        }
        fn stat_file(&mut self, path: &str) -> Option<capture::FileStat> {
            self.live.stat_file(path)
        }
        fn file_len(&mut self, path: &str) -> Option<u64> {
            self.live.file_len(path)
        }
        fn read_comm(&mut self, pid: u32) -> Option<String> {
            self.live.read_comm(pid)
        }
    }
    type Attempt = SetupAttempt<Discovery, LiveBackend, Lifecycle>;
    struct Owned {
        attempt: Attempt,
        fixture: Arc<crate::count_owner::W079AppCountFixture>,
        gate: Arc<Gate>,
        pid: u32,
        polls: Arc<AtomicUsize>,
        dropped: Arc<AtomicBool>,
        released: Arc<AtomicUsize>,
        cancelled: Arc<AtomicBool>,
        file: Option<std::path::PathBuf>,
        child_pidfd: Option<std::os::fd::OwnedFd>,
        peers: Arc<Mutex<Vec<UnixStream>>>,
        alias: Arc<Mutex<Option<UnixStream>>>,
        cfg: Option<capture::Config>,
        info: Option<capture::TargetInfo>,
    }
    impl Owned {
        fn new(hold: Hold, deadline: Duration, close_hold: bool) -> Self {
            let cancelled = Arc::new(AtomicBool::new(false));
            let control = SetupControl::new(
                Instant::now() + deadline,
                SetupInterrupt::Owned(cancelled.clone()),
            );
            let attempt = Attempt::admit(control).expect("one admitted attempt");
            let fixture = Arc::new(crate::count_owner::W079AppCountFixture::new(
                match hold {
                    Hold::Open => Some(1),
                    Hold::Fence => Some(5),
                    _ => None,
                },
                close_hold,
                hold == Hold::Attach,
                match hold {
                    Hold::CountPreflight(stage) => Some(stage),
                    _ => None,
                },
            ));
            if matches!(hold, Hold::CountError | Hold::CountUnwind) {
                fixture.fail_open(hold == Hold::CountUnwind);
            }
            if matches!(hold, Hold::PrepareLoadError | Hold::PrepareLoadUnwind) {
                fixture.fail_prepare_load(hold == Hold::PrepareLoadUnwind);
            }
            let gate = Gate::new();
            // Establish the unwind owner before the first actual child effect.
            let mut owned = Self {
                attempt,
                fixture,
                gate,
                pid: 0,
                polls: Arc::new(AtomicUsize::new(0)),
                dropped: Arc::new(AtomicBool::new(false)),
                released: Arc::new(AtomicUsize::new(0)),
                cancelled,
                file: None,
                child_pidfd: None,
                peers: Arc::new(Mutex::new(Vec::new())),
                alias: Arc::new(Mutex::new(None)),
                cfg: None,
                info: None,
            };
            let argv = vec!["/bin/sleep".to_owned(), "1".to_owned()];
            let target = {
                let _permit = owned
                    .attempt
                    .barrier
                    .prefix_permit(owned.attempt.control.deadline())
                    .unwrap();
                crate::target::OwnedTarget::spawn_stopped(&argv, crate::target::WorkloadDest::Null)
                    .unwrap()
            };
            owned.pid = target.pid();
            owned.attempt.target = Some(target);
            let raw =
                unsafe { libc::syscall(libc::SYS_pidfd_open, owned.pid as libc::pid_t, 0) as i32 };
            assert!(raw >= 0, "test retains exact child identity");
            owned.child_pidfd = Some(unsafe { std::os::fd::FromRawFd::from_raw_fd(raw) });
            let cfg = capture::Config {
                harvest_object: None,
                count_object: None,
                members_object: None,
                provider: None,
                builtin: false,
                table: None,
                force_offset: None,
                provider_enrollment: None,
                resolved_provider: None,
                duration: Duration::from_millis(25),
                settle: Duration::ZERO,
                harvest_timeout: deadline,
                grace: Duration::from_millis(100),
                image_digest: String::new(),
            };
            if hold == Hold::ContextPartial {
                locked(&owned.attempt.links.0).context_comm_hold = Some(owned.gate.clone());
            }
            let info = capture::TargetInfo {
                pid: owned.pid,
                owned: true,
                comm: if matches!(hold, Hold::ContextPartial | Hold::ContextReady) {
                    String::new()
                } else {
                    "held".into()
                },
                cmdline: String::new(),
                container_id: String::new(),
                kernel_release: String::new(),
                provider_build_id: String::new(),
                provider_path: String::new(),
                image_digest: String::new(),
                acquired_ns: capture::LiveClock.monotonic_ns(),
                acquired_instant: Instant::now(),
                acquired_wall: SystemTime::now(),
            };
            let (mapping, delta) = if matches!(
                hold,
                Hold::Relevant
                    | Hold::Fence
                    | Hold::CountError
                    | Hold::CountUnwind
                    | Hold::Attach
                    | Hold::ReaderError
                    | Hold::RecoverableReaderError
            ) {
                owned.site()
            } else {
                (None, None)
            };
            let seed = if matches!(hold, Hold::Fence | Hold::CountError | Hold::CountUnwind) {
                let mapping = mapping.clone().unwrap();
                let file = crate::plan::read_file_bounded(&mapping.path, 4096).unwrap();
                let site = crate::count_session::DiscoveredSite {
                    site: crate::evidence::SiteKey {
                        object: crate::evidence::ObjectId("old-object".into()),
                        device: file.dev,
                        inode: file.ino,
                        offset: 128,
                    },
                    candidates: vec![crate::evidence::CandidateIdentity::new(
                        crate::evidence::ObjectId("old-provider".into()),
                        "SHA-1".into(),
                        1,
                        11,
                        vec!["digest".into()],
                        false,
                    )],
                    candidates_coverage: crate::evidence::CandidateCoverage::Unknown,
                };
                Some((
                    crate::count_session::CountDelta {
                        discovered: vec![site],
                        losses: Vec::new(),
                    },
                    mapping,
                    file,
                ))
            } else {
                None
            };
            owned.cfg = Some(cfg.clone());
            owned.info = Some(info.clone());
            owned
                .attempt
                .start(capture::SetupRequest::Host {
                    cfg,
                    info,
                    discovery: Discovery {
                        events: None,
                        pid: owned.pid,
                        hold,
                        gate: owned.gate.clone(),
                        polls: owned.polls.clone(),
                        dropped: owned.dropped.clone(),
                        delta,
                        links: owned.attempt.links.clone(),
                        control: owned.attempt.control.clone(),
                        peers: owned.peers.clone(),
                        alias: owned.alias.clone(),
                        file: owned.file.clone(),
                    },
                    lifecycle: Lifecycle(owned.released.clone()),
                    count: owned.fixture.clone(),
                    proc: Box::new(Proc {
                        hold,
                        gate: owned.gate.clone(),
                        live: capture::LiveProc,
                        mapping,
                        setup: owned.attempt.links.clone(),
                    }),
                    seed,
                    establish_context: matches!(hold, Hold::ContextPartial | Hold::ContextReady),
                })
                .unwrap();
            owned
        }
        fn site(
            &mut self,
        ) -> (
            Option<crate::discovery::maps::Mapping>,
            Option<DiscoveryDelta>,
        ) {
            use std::os::unix::fs::MetadataExt;
            // A real ELF file with one executable PT_LOAD; planning, inode pins,
            // relevant-file reads and the actual Count Attach all remain real.
            let mut bytes = vec![0u8; 256];
            bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
            bytes[16..18].copy_from_slice(&3u16.to_le_bytes());
            bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
            bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
            bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
            bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
            bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
            bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
            bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
            bytes[68..72].copy_from_slice(&5u32.to_le_bytes());
            bytes[80..88].copy_from_slice(&0x1000u64.to_le_bytes());
            bytes[96..104].copy_from_slice(&256u64.to_le_bytes());
            bytes[104..112].copy_from_slice(&256u64.to_le_bytes());
            let file = std::env::temp_dir().join(format!(
                "w079-app-site-{}-{}",
                std::process::id(),
                self.pid
            ));
            self.file = Some(file.clone());
            std::fs::write(&file, &bytes).unwrap();
            let metadata = std::fs::metadata(&file).unwrap();
            let device = crate::plan::encode_device(
                libc::major(metadata.dev()),
                libc::minor(metadata.dev()),
            );
            let dev = crate::plan::render_device(device);
            let mapping = crate::discovery::maps::Mapping {
                start: 0x1000,
                end: 0x1100,
                x: true,
                offset: 0,
                dev: dev.clone(),
                ino: metadata.ino(),
                path: file.to_string_lossy().into_owned(),
            };
            let delta = DiscoveryDelta {
                candidates: vec![crate::discovery::session::DiscoveredCandidate {
                    advertising: mapping.path.clone(),
                    advertising_dev: dev.clone(),
                    advertising_ino: metadata.ino(),
                    backing: Some(crate::discovery::session::BackingRef {
                        dev,
                        ino: metadata.ino(),
                        offset: 128,
                    }),
                    op: 1,
                    funcid: 11,
                    class: "SHA-256".into(),
                    weak: false,
                    status: "ok".into(),
                    epoch: 0,
                    impl_addr: 0x1080,
                    arr: 0,
                }],
                ..DiscoveryDelta::default()
            };
            (Some(mapping), Some(delta))
        }
        fn settled(&mut self) -> bool {
            self.gate.release();
            self.fixture.release();
            if self.attempt.cleanup.is_some() {
                self.attempt.abandon(infrastructure("test custody cleanup"));
            }
            let cutoff = Instant::now() + Duration::from_secs(3);
            while !self.attempt.disposed.load(Ordering::Acquire) && Instant::now() < cutoff {
                std::thread::sleep(Duration::from_millis(1));
            }
            let timely = self.attempt.disposed.load(Ordering::Acquire);
            let joined = self.attempt.join_cleanup_for_test();
            timely && joined
        }
    }
    impl Drop for Owned {
        fn drop(&mut self) {
            let _ = self.settled();
            if let Some(pidfd) = self.child_pidfd.take() {
                let fd = std::os::fd::AsRawFd::as_raw_fd(&pidfd);
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        fd,
                        libc::SIGKILL,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    );
                }
                // No competing waiter exists for this exact fixture child.
                unsafe {
                    libc::waitpid(self.pid as i32, std::ptr::null_mut(), 0);
                }
            }
            if let Some(file) = self.file.take() {
                let _ = std::fs::remove_file(file);
            }
        }
    }
    fn peer_closed(peer: &UnixStream) -> bool {
        let mut event = libc::pollfd {
            fd: std::os::fd::AsRawFd::as_raw_fd(peer),
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        unsafe {
            libc::poll(&mut event, 1, 0);
        }
        event.revents & libc::POLLHUP != 0
    }
    fn exact_reaped(pid: u32) -> bool {
        let mut status = 0;
        (unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) }) == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
    }

    #[test]
    fn w079_pre_release_holds() {
        for hold in [
            Hold::Open,
            Hold::Maps,
            Hold::Exe,
            Hold::Discovery,
            Hold::Relevant,
            Hold::Attach,
            Hold::Fence,
            Hold::Traversal,
        ] {
            let mut owned = Owned::new(hold, Duration::from_millis(100), false);
            let started = Instant::now();
            let failure = match owned.attempt.wait() {
                Err(failure) => failure,
                Ok(()) => {
                    let entered = owned.fixture.attach_entered();
                    let settled = owned.settled();
                    panic!(
                        "held {hold:?} unexpectedly published Ready; attach_entered={entered} cleanup={settled}"
                    );
                }
            };
            let entered = if hold == Hold::Attach {
                owned.fixture.attach_entered()
            } else if matches!(hold, Hold::Open | Hold::Fence) {
                owned
                    .fixture
                    .wait_map_call(if hold == Hold::Open { 1 } else { 5 });
                true
            } else {
                owned.gate.entered.load(Ordering::Acquire)
            };
            owned.attempt.abandon(failure);
            let receipt = owned
                .attempt
                .await_receipt(Instant::now() + Duration::from_secs(1));
            let reaped = exact_reaped(owned.pid);
            let retained = if matches!(hold, Hold::Open | Hold::Attach | Hold::Fence) {
                // The bounded session call can return while its real owner is
                // still held. Its canonical state/FDs remain in that owner.
                !owned.fixture.descriptors_closed()
            } else {
                !owned.dropped.load(Ordering::Acquire)
            };
            let no_release = owned.released.load(Ordering::Acquire) == 0;
            let count = owned.attempt.count_diagnostic();
            let settled = owned.settled();
            assert!(
                settled && owned.fixture.descriptors_closed(),
                "actual owner/resources must settle at {hold:?}"
            );
            assert!(
                entered && started.elapsed() < Duration::from_secs(5),
                "held stage {hold:?} did not return independently"
            );
            assert_eq!(receipt.resolution, capture::CustodyResolution::Resolved);
            assert!(
                reaped && retained && no_release,
                "child-first retained preparation at {hold:?}"
            );
            if hold == Hold::Open {
                assert!(matches!(
                    count,
                    capture::PreObservationCount::SetupPending(_)
                        | capture::PreObservationCount::Terminal(_)
                ));
            }
        }
    }

    #[test]
    fn w079_wait_and_admission() {
        struct Foreign(std::process::Child);
        impl Drop for Foreign {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut foreign = Foreign(
            std::process::Command::new("/bin/sleep")
                .arg("10")
                .spawn()
                .unwrap(),
        );
        let mut owned = Owned::new(Hold::Discovery, Duration::from_secs(20), false);
        let cutoff = Instant::now() + Duration::from_secs(3);
        while !owned.gate.entered.load(Ordering::Acquire) && Instant::now() < cutoff {
            std::thread::yield_now();
        }
        owned.cancelled.store(true, Ordering::Release);
        let started = Instant::now();
        let failure = owned
            .attempt
            .wait()
            .expect_err("cancellation must interrupt held baseline");
        owned.attempt.abandon(failure.clone());
        let refused = Attempt::admit(SetupControl::new(
            Instant::now() + Duration::from_secs(1),
            SetupInterrupt::Owned(Arc::new(AtomicBool::new(false))),
        ))
        .is_err();
        let settled = owned.settled();
        let foreign_survived = foreign.0.try_wait().unwrap().is_none();
        assert!(
            foreign_survived,
            "owned cancellation cannot signal a foreign child"
        );
        assert!(settled && refused && started.elapsed() < Duration::from_secs(5));
        assert!(matches!(failure, SetupFailure::Cancelled { .. }));
        assert!(exact_reaped(owned.pid));
        let control = SetupControl::new(
            Instant::now() + Duration::from_secs(2),
            SetupInterrupt::Owned(Arc::new(AtomicBool::new(false))),
        );
        assert!(
            Attempt::admit_inner(control, true).is_err(),
            "second thread failure must refuse before child effects"
        );
    }

    #[test]
    fn w079_reap_receipt_before_close() {
        let mut owned = Owned::new(Hold::Discovery, Duration::from_secs(10), true);
        let cutoff = Instant::now() + Duration::from_secs(3);
        while !owned.gate.entered.load(Ordering::Acquire) && Instant::now() < cutoff {
            std::thread::yield_now();
        }
        owned
            .attempt
            .abandon(infrastructure("controlled abort before close"));
        let receipt = owned
            .attempt
            .await_receipt(Instant::now() + Duration::from_secs(1));
        let cutoff = Instant::now() + Duration::from_secs(2);
        while !owned.fixture.close_entered() && Instant::now() < cutoff {
            std::thread::yield_now();
        }
        let held = owned.fixture.close_entered() && !owned.fixture.descriptors_closed();
        let reaped = exact_reaped(owned.pid);
        let settled = owned.settled();
        assert!(settled && held && reaped);
        assert_eq!(receipt.child_exit, Some(137));
    }

    #[test]
    fn w079_fix1_count_waits_for_actual_consume() {
        for hold in [
            Hold::Discovery,
            Hold::Fence,
            Hold::ResourceError,
            Hold::ResourceUnwind,
            Hold::CountError,
            Hold::CountUnwind,
        ] {
            let mut owned = Owned::new(hold, Duration::from_secs(10), false);
            let reap = crate::target::hold_setup_reap(owned.attempt.target.as_mut().unwrap());
            let failure = if hold == Hold::Fence {
                owned.fixture.wait_map_call(5);
                infrastructure("explicit abandonment with real Count writer")
            } else if hold == Hold::Discovery {
                let until = Instant::now() + Duration::from_secs(2);
                while !owned.gate.entered.load(Ordering::Acquire) && Instant::now() < until {
                    std::thread::yield_now();
                }
                infrastructure("explicit held-consume abandonment")
            } else {
                owned.attempt.wait().expect_err("autonomous setup failure")
            };
            owned.attempt.abandon(failure);
            if hold == Hold::Fence {
                owned.fixture.release();
            }
            let until = Instant::now() + Duration::from_secs(2);
            while !reap.entered.load(Ordering::Acquire) && Instant::now() < until {
                std::thread::yield_now();
            }
            std::thread::sleep(Duration::from_millis(50));
            let entered = reap.entered.load(Ordering::Acquire);
            let close_before_receipt = owned.fixture.close_entered();
            let no_receipt = locked(&owned.attempt.links.0).custody.is_none();
            reap.release();
            let settled = owned.settled();
            assert!(settled && owned.fixture.descriptors_closed() && exact_reaped(owned.pid));
            assert!(
                entered && no_receipt && !close_before_receipt,
                "{hold:?}: Count close entered before real consuming reap"
            );
        }
    }

    #[test]
    fn w079_fix1_partial_pin_and_events_constructors() {
        for hold in [
            Hold::PidPinError,
            Hold::FilePinError,
            Hold::RingMapInfoError,
            Hold::RingMmapError,
            Hold::RingMmapUnwind,
        ] {
            let mut owned = Owned::new(hold, Duration::from_secs(10), false);
            let reap = crate::target::hold_setup_reap(owned.attempt.target.as_mut().unwrap());
            let failure = owned
                .attempt
                .wait()
                .expect_err("actual constructor/entry must fail");
            let expected_errno = match hold {
                Hold::PidPinError | Hold::FilePinError => Some(libc::EIO),
                Hold::RingMmapError => Some(libc::EINVAL),
                _ => None,
            };
            let observed_errno = match &failure {
                SetupFailure::Boundary(failure) => failure.errno,
                _ => None,
            };
            owned.attempt.abandon(failure);
            let until = Instant::now() + Duration::from_secs(2);
            while !reap.entered.load(Ordering::Acquire) && Instant::now() < until {
                std::thread::yield_now();
            }
            let (fds, mappings) = {
                let state = locked(&owned.attempt.links.0);
                (state.retained_fd_probe, state.retained_mapping_probe)
            };
            let retained = fds
                .iter()
                .flatten()
                .all(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) } >= 0);
            let mapped = mappings.iter().flatten().all(|(address, len)| {
                let mut vec = vec![0u8; len.div_ceil(4096)];
                unsafe { libc::mincore(*address as *mut libc::c_void, *len, vec.as_mut_ptr()) == 0 }
            });
            let entered = reap.entered.load(Ordering::Acquire);
            reap.release();
            let settled = owned.settled();
            let closed = fds
                .iter()
                .flatten()
                .all(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) } == -1);
            let unmapped = mappings.iter().flatten().all(|(address, len)| {
                let mut vec = vec![0u8; len.div_ceil(4096)];
                unsafe {
                    libc::mincore(*address as *mut libc::c_void, *len, vec.as_mut_ptr()) == -1
                }
            });
            assert!(settled && exact_reaped(owned.pid) && owned.fixture.descriptors_closed());
            assert!(
                entered
                    && fds.iter().any(Option::is_some)
                    && retained
                    && mapped
                    && closed
                    && unmapped,
                "partial owner at {hold:?}"
            );
            if let Some(errno) = expected_errno {
                assert_eq!(observed_errno, Some(errno), "{hold:?}");
            }
        }
    }

    #[test]
    fn w079_fix1_diagnostic_materialization_does_not_hold_arbiter() {
        for hold in [Hold::DiagnosticTimeout, Hold::DiagnosticError] {
            let mut owned = Owned::new(
                hold,
                if hold == Hold::DiagnosticTimeout {
                    Duration::from_millis(100)
                } else {
                    Duration::from_secs(20)
                },
                false,
            );
            let cutoff = Instant::now() + Duration::from_secs(2);
            while !owned.gate.entered.load(Ordering::Acquire) && Instant::now() < cutoff {
                std::thread::yield_now();
            }
            let entered = owned.gate.entered.load(Ordering::Acquire);
            if hold == Hold::DiagnosticError {
                owned.cancelled.store(true, Ordering::Release);
            }
            let start = Instant::now();
            let failure = owned.attempt.wait().expect_err("stored actual cause");
            let independent = start.elapsed() < Duration::from_secs(5);
            let class = match &failure {
                SetupFailure::Boundary(failure) => Some((failure.class, failure.errno)),
                _ => None,
            };
            owned.attempt.abandon(failure);
            let receipt = owned
                .attempt
                .await_receipt(Instant::now() + Duration::from_secs(1));
            let settled = owned.settled();
            assert!(settled && owned.fixture.descriptors_closed() && exact_reaped(owned.pid));
            assert!(entered && independent && receipt.child_exit == Some(137));
            assert_eq!(
                class,
                Some(if hold == Hold::DiagnosticTimeout {
                    (BoundaryFailureClass::Timeout, None)
                } else {
                    (BoundaryFailureClass::Io, Some(libc::EIO))
                })
            );
        }
    }

    #[test]
    fn w079_fix1_failed_unmap_keeps_real_owner_and_admission() {
        let mut owned = Owned::new(Hold::RingUnmapError, Duration::from_secs(10), false);
        let failure = owned.attempt.wait().expect_err("producer mmap failure");
        owned.attempt.abandon(failure);
        let receipt = owned
            .attempt
            .await_receipt(Instant::now() + Duration::from_secs(1));
        let cutoff = Instant::now() + Duration::from_secs(2);
        while !owned.gate.entered.load(Ordering::Acquire) && Instant::now() < cutoff {
            std::thread::yield_now();
        }
        let entered = owned.gate.entered.load(Ordering::Acquire);
        let mappings = locked(&owned.attempt.links.0).retained_mapping_probe;
        let retained = mappings.iter().flatten().all(|(address, len)| {
            let mut bytes = vec![0u8; len.div_ceil(4096)];
            unsafe { libc::mincore(*address as *mut libc::c_void, *len, bytes.as_mut_ptr()) == 0 }
        });
        let refused = Attempt::admit(SetupControl::new(
            Instant::now() + Duration::from_secs(1),
            SetupInterrupt::Owned(Arc::new(AtomicBool::new(false))),
        ))
        .is_err();
        let pending = !owned.attempt.disposed.load(Ordering::Acquire);
        let settled = owned.settled();
        let unmapped = mappings.iter().flatten().all(|(address, len)| {
            let mut bytes = vec![0u8; len.div_ceil(4096)];
            unsafe { libc::mincore(*address as *mut libc::c_void, *len, bytes.as_mut_ptr()) == -1 }
        });
        assert!(settled && owned.fixture.descriptors_closed() && exact_reaped(owned.pid));
        assert!(
            entered
                && retained
                && refused
                && pending
                && unmapped
                && receipt.child_exit == Some(137)
        );
    }

    #[test]
    fn w079_late_open_baseline() {
        let mut owned = Owned::new(Hold::Open, Duration::from_millis(100), false);
        let failure = owned
            .attempt
            .wait()
            .expect_err("held Open cannot finish setup");
        owned.attempt.abandon(failure);
        let receipt = owned
            .attempt
            .await_receipt(Instant::now() + Duration::from_secs(1));
        let settled = owned.settled();
        assert!(settled && owned.fixture.descriptors_closed());
        assert_eq!(receipt.child_exit, Some(137));
        assert_eq!(
            owned.polls.load(Ordering::Acquire),
            0,
            "late Open cannot begin baseline"
        );
        assert!(owned.attempt.ready.is_none());
    }

    #[test]
    fn w079_link_late_and_ready_races() {
        let mut owned = Owned::new(Hold::Discovery, Duration::from_secs(10), false);
        let cutoff = Instant::now() + Duration::from_secs(3);
        while !owned.gate.entered.load(Ordering::Acquire) && Instant::now() < cutoff {
            std::thread::yield_now();
        }
        let initially_retained = {
            let peers = locked(&owned.peers);
            peers.len() == 2 && peers.iter().all(|peer| !peer_closed(peer))
        };
        owned.cancelled.store(true, Ordering::Release);
        let failure = owned
            .attempt
            .wait()
            .expect_err("cancel wins while actual next native result is held");
        owned.attempt.abandon(failure);
        let receipt = owned
            .attempt
            .await_receipt(Instant::now() + Duration::from_secs(1));
        let cutoff = Instant::now() + Duration::from_secs(1);
        while !peer_closed(&locked(&owned.peers)[1]) && Instant::now() < cutoff {
            std::thread::yield_now();
        }
        let alias_negative = !peer_closed(&locked(&owned.peers)[0]);
        drop(locked(&owned.alias).take());
        let earlier_closed = locked(&owned.peers).iter().all(peer_closed);
        let reaped = exact_reaped(owned.pid);
        let settled = owned.settled();
        let late_closed = {
            let peers = locked(&owned.peers);
            peers.len() == 4 && peers.iter().all(peer_closed)
        };
        assert!(
            settled
                && initially_retained
                && alias_negative
                && earlier_closed
                && late_closed
                && reaped
        );
        assert_eq!(receipt.child_exit, Some(137));

        // Real Ready is accepted first; cancellation before the actual signal
        // returns that exact prepared state through the reserved cleanup slot.
        let mut owned = Owned::new(Hold::None, Duration::from_secs(10), false);
        owned.attempt.wait().unwrap();
        owned.cancelled.store(true, Ordering::Release);
        let ready = owned.attempt.ready.as_mut().unwrap();
        let result = capture::commit_owned_release(
            owned.attempt.target.as_mut().unwrap(),
            ready.bundle.window.as_mut().unwrap(),
            &owned.attempt.control,
            &capture::LiveClock,
        );
        let cancelled = matches!(result, Err(SetupFailure::Cancelled { .. }));
        let settled = owned.settled();
        drop(locked(&owned.alias).take());
        assert!(
            settled
                && cancelled
                && owned.released.load(Ordering::Acquire) == 0
                && exact_reaped(owned.pid)
        );
        assert!(locked(&owned.peers).iter().all(peer_closed));
    }

    struct RuntimeCaller {
        thread: Option<std::thread::JoinHandle<anyhow::Result<capture::Capture>>>,
        links: SetupLinks,
        commit: capture::ReleaseCommit,
        gate: Arc<Gate>,
    }
    impl RuntimeCaller {
        fn finish(&mut self) -> Option<std::thread::Result<anyhow::Result<capture::Capture>>> {
            // Finally may publish only the retained ACTUAL committed release,
            // never a fake child/ledger acknowledgement. This also safely
            // rescues the RED missing-publication path after observing failure.
            self.links.commit_runtime(&self.commit);
            self.gate.release();
            self.thread.take().map(|thread| thread.join())
        }
    }
    impl Drop for RuntimeCaller {
        fn drop(&mut self) {
            let _ = self.finish();
        }
    }
    fn mapping_present(address: usize, len: usize) -> bool {
        let mut pages = vec![0u8; len.div_ceil(4096)];
        unsafe { libc::mincore(address as *mut libc::c_void, len, pages.as_mut_ptr()) == 0 }
    }
    #[test]
    fn w079_fix2_runtime_mapping_retry_after_real_commit() {
        for hold in [Hold::HealthyRing, Hold::RuntimeRing] {
            let mut owned = Owned::new(hold, Duration::from_secs(10), false);
            owned.attempt.wait().expect("real baseline Ready");
            let ready = owned.attempt.ready.as_mut().unwrap();
            let commit = capture::commit_owned_release(
                owned.attempt.target.as_mut().unwrap(),
                ready.bundle.window.as_mut().unwrap(),
                &owned.attempt.control,
                &capture::LiveClock,
            )
            .unwrap();
            let (target, mut ready) = owned.attempt.accepted(&commit);
            let window = ready.bundle.window.take().unwrap();
            let (send, done) = std::sync::mpsc::channel();
            let mut caller = RuntimeCaller {
                thread: None,
                links: owned.attempt.links.clone(),
                commit,
                gate: owned.gate.clone(),
            };
            caller.thread = Some(std::thread::spawn(move || {
                let result = capture::resume_owned_window(
                    window,
                    target,
                    commit,
                    &capture::LiveClock,
                    &mut capture::LiveProc,
                    &|| false,
                );
                let _ = send.send(());
                result
            }));
            let entered = if hold == Hold::RuntimeRing {
                let until = Instant::now() + Duration::from_secs(1);
                while !owned.gate.entered.load(Ordering::Acquire) && Instant::now() < until {
                    std::thread::yield_now();
                }
                owned.gate.entered.load(Ordering::Acquire)
            } else {
                true
            };
            let (no_setup_cleanup, mappings) = {
                let state = locked(&owned.attempt.links.0);
                (
                    state.custody.is_none() && !state.native_disposed,
                    state.retained_mapping_probe,
                )
            };
            let held_mapping = mappings.iter().flatten().count() == 2
                && (hold != Hold::RuntimeRing
                    || mappings
                        .iter()
                        .flatten()
                        .all(|(address, len)| mapping_present(*address, *len)));
            owned.gate.release();
            let returned_before_recovery = done.recv_timeout(Duration::from_secs(1)).is_ok();
            let result = caller.finish();
            let settled = owned.settled();
            let until = Instant::now() + Duration::from_secs(3);
            let count_disposed = loop {
                let watch = { locked(&owned.attempt.links.0).watch.clone() };
                if watch
                    .as_ref()
                    .and_then(|watch| watch.progress())
                    .is_some_and(|p| p.owner_cleanup_acknowledged && p.owner_task_disposed)
                {
                    break true;
                }
                if Instant::now() >= until {
                    break false;
                }
                std::thread::yield_now();
            };
            let still_no_cleanup = {
                let state = locked(&owned.attempt.links.0);
                state.custody.is_none() && !state.native_disposed
            };
            let unmapped = mappings
                .iter()
                .flatten()
                .all(|(address, len)| !mapping_present(*address, *len));
            assert!(settled && count_disposed && owned.fixture.descriptors_closed());
            assert_eq!(owned.fixture.open_target_writes(), 1);
            assert_eq!(owned.released.load(Ordering::Acquire), 1);
            assert!(matches!(result, Some(Ok(Ok(_)))), "actual runtime result");
            assert!(
                entered
                    && held_mapping
                    && returned_before_recovery
                    && no_setup_cleanup
                    && still_no_cleanup
                    && unmapped,
                "{hold:?}: runtime unmap must return without setup cleanup or finally rescue"
            );
        }
    }
    #[test]
    fn w079_fix2_ready_abort_keeps_mapping_until_child_receipt() {
        let mut owned = Owned::new(Hold::RuntimeRing, Duration::from_secs(10), false);
        let reap = crate::target::hold_setup_reap(owned.attempt.target.as_mut().unwrap());
        owned.attempt.wait().expect("real baseline Ready");
        let uncommitted = !owned
            .attempt
            .links
            .0
            .runtime_committed
            .load(Ordering::Acquire);
        owned
            .attempt
            .abandon(infrastructure("Ready abort before actual release"));
        let until = Instant::now() + Duration::from_secs(2);
        while !reap.entered.load(Ordering::Acquire) && Instant::now() < until {
            std::thread::yield_now();
        }
        let mappings = locked(&owned.attempt.links.0).retained_mapping_probe;
        let pending = {
            let state = locked(&owned.attempt.links.0);
            state.custody.is_none() && !state.native_disposed
        };
        let no_drop = !owned.gate.entered.load(Ordering::Acquire);
        let held = mappings
            .iter()
            .flatten()
            .all(|(address, len)| mapping_present(*address, *len));
        let refused = Attempt::admit(SetupControl::new(
            Instant::now() + Duration::from_secs(1),
            SetupInterrupt::Owned(Arc::new(AtomicBool::new(false))),
        ))
        .is_err();
        reap.release();
        let settled = owned.settled();
        let unmapped = mappings
            .iter()
            .flatten()
            .all(|(address, len)| !mapping_present(*address, *len));
        assert!(settled && owned.fixture.descriptors_closed() && exact_reaped(owned.pid));
        assert!(uncommitted && pending && no_drop && held && refused && unmapped);
    }

    #[test]
    fn w079_success_once() {
        let mut owned = Owned::new(Hold::None, Duration::from_secs(10), false);
        owned
            .attempt
            .wait()
            .expect("full extracted baseline publishes actual Ready");
        let polls = owned.polls.load(Ordering::Acquire);
        let ready = owned.attempt.ready.as_mut().unwrap();
        let commit = capture::commit_owned_release(
            owned.attempt.target.as_mut().unwrap(),
            ready.bundle.window.as_mut().unwrap(),
            &owned.attempt.control,
            &capture::LiveClock,
        )
        .unwrap();
        let (target, mut ready) = owned.attempt.accepted(&commit);
        let window = ready.bundle.window.take().unwrap();
        let result = capture::resume_owned_window(
            window,
            target,
            commit,
            &capture::LiveClock,
            &mut capture::LiveProc,
            &|| false,
        );
        let settled = owned.settled();
        // After success the still-running actual child belongs to its application.
        // Test custody explicitly kills/reaps that exact retained test child.
        assert!(settled && owned.fixture.descriptors_closed());
        assert_eq!(polls, 1, "one preparation baseline");
        assert_eq!(
            owned.fixture.open_target_writes(),
            1,
            "actual Open exactly once"
        );
        assert_eq!(
            owned.released.load(Ordering::Acquire),
            1,
            "mark_released exactly once"
        );
        assert!(result.is_ok(), "actual continuation: {result:?}");
    }

    #[test]
    fn w079_count_preflight_caller_child_and_admission() {
        use crate::count_owner::W079AppPrepareHold as Stage;
        for stage in [
            Stage::FdInventory,
            Stage::OuterCpu,
            Stage::OwnerCpu,
            Stage::Hash,
            Stage::Parse,
            Stage::Allocation,
            Stage::OwnerStart,
            Stage::PrepareReply,
        ] {
            let mut owned = Owned::new(
                Hold::CountPreflight(stage),
                Duration::from_millis(100),
                false,
            );
            let started = Instant::now();
            let failure = owned
                .attempt
                .wait()
                .expect_err("held real Count preparation cannot publish app Ready");
            let entered = owned.fixture.prepare_entered();
            owned.attempt.abandon(failure);
            let receipt = owned
                .attempt
                .await_receipt(Instant::now() + Duration::from_secs(1));
            let rejected = Attempt::admit(SetupControl::new(
                Instant::now() + Duration::from_secs(1),
                SetupInterrupt::Owned(Arc::new(AtomicBool::new(false))),
            ))
            .is_err();
            let reaped = exact_reaped(owned.pid);
            let settled = owned.settled();
            assert!(
                settled
                    && entered
                    && rejected
                    && reaped
                    && started.elapsed() < Duration::from_secs(5),
                "actual stage {stage:?}"
            );
            assert_eq!(receipt.child_exit, Some(137));
            assert!(
                owned.fixture.descriptors_closed(),
                "actual acquired FD/owner disposition at {stage:?}"
            );
            assert_eq!(owned.polls.load(Ordering::Acquire), 0);
            assert_eq!(owned.released.load(Ordering::Acquire), 0);
        }
    }

    #[test]
    fn w079_owned_report_check_pending_child_receipt() {
        struct OutputFile(std::path::PathBuf);
        impl Drop for OutputFile {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        for (hold, report_exit, check_exit) in [
            (Hold::Open, 3, 11),
            (Hold::ResourceError, 4, 4),
            (Hold::ResourceUnwind, 1, 4),
        ] {
            for check in [false, true] {
                let mut owned = Owned::new(hold, Duration::from_secs(20), false);
                if hold == Hold::Open {
                    owned.fixture.wait_map_call(1);
                    owned.cancelled.store(true, Ordering::Release);
                }
                let failure = owned
                    .attempt
                    .wait()
                    .expect_err("actual held Open remains pre-observation");
                let error = capture::controlled_setup_failure(
                    &mut owned.attempt,
                    failure,
                    owned.info.as_ref().unwrap(),
                    owned.cfg.as_ref().unwrap(),
                );
                let path = OutputFile(
                    std::path::PathBuf::from(
                        std::env::var_os("OSSL_PACKAGE_TEST_PRIVATE_DIR").unwrap(),
                    )
                    .join(format!("w079-owned-report-{}-{check}.json", owned.pid)),
                );
                let rules = [crate::policy::PolicyRule::deny_weak()];
                let result = crate::report::consume_capture_result_with_diagnostics(
                    Err(error),
                    if check {
                        crate::report::CaptureCommand::Check { rules: &rules }
                    } else {
                        crate::report::CaptureCommand::Report
                    },
                    &crate::report::OutputRequest {
                        format: crate::report::OutputFormat::Json,
                        primary: crate::report::OutputDest::File(path.0.clone()),
                        cbom: None,
                    },
                    true,
                    &mut Vec::new(),
                );
                let settled = owned.settled();
                assert!(settled && owned.fixture.descriptors_closed() && exact_reaped(owned.pid));
                assert!(result.delivery.delivered_all());
                assert_eq!(result.child_exit, Some(137));
                assert_eq!(
                    result.exit_code,
                    if check { check_exit } else { report_exit },
                    "diagnostics={:?} typed={:?}",
                    result.diagnostics,
                    result
                        .failure_context
                        .as_ref()
                        .map(|context| (&context.failure, context.count.actual_failure()))
                );
                if hold == Hold::Open {
                    assert!(
                        !result
                            .diagnostics
                            .iter()
                            .any(|line| line.contains("re-run with --workload-out"))
                    );
                }
                assert_eq!(result.document.total_calls(), 0);
                assert!(
                    result.document.coverage.is_empty()
                        && result.document.window.count_admission.is_none()
                );
                let value: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path.0).unwrap()).unwrap();
                crate::schema::validate_v2(&value).unwrap();
                crate::schema::check_v2_semantics(&value).unwrap();
            }
        }
    }

    #[test]
    fn w079_fullplan_pending_owner_error_wins_cancel() {
        for hold in [Hold::PrepareLoadError, Hold::PrepareLoadUnwind] {
            for check in [false, true] {
                let mut owned = Owned::new(hold, Duration::from_secs(10), false);
                let until = Instant::now() + Duration::from_secs(2);
                while !owned.fixture.load_entered() && Instant::now() < until {
                    std::thread::yield_now();
                }
                let entered = owned.fixture.load_entered();
                owned.cancelled.store(true, Ordering::Release);
                let failure = owned
                    .attempt
                    .wait()
                    .expect_err("cancel actual held Prepare");
                owned.attempt.abandon(failure.clone());
                // Actual owner returns EIO/Panic only AFTER the real Cancelled Prepare reply.
                let settled = owned.settled();
                let count = owned.attempt.count_diagnostic();
                let error = capture::controlled_setup_failure(
                    &mut owned.attempt,
                    failure,
                    owned.info.as_ref().unwrap(),
                    owned.cfg.as_ref().unwrap(),
                );
                let original_cause = error
                    .downcast_ref::<capture::PreObservationFailure>()
                    .unwrap()
                    .cause;
                let path = std::path::PathBuf::from(
                    std::env::var_os("OSSL_PACKAGE_TEST_PRIVATE_DIR").unwrap(),
                )
                .join(format!("fullplan-pending-{}-{check}.json", owned.pid));
                let rules = [crate::policy::PolicyRule::deny_weak()];
                let result = crate::report::consume_capture_result_with_diagnostics(
                    Err(error),
                    if check {
                        crate::report::CaptureCommand::Check { rules: &rules }
                    } else {
                        crate::report::CaptureCommand::Report
                    },
                    &crate::report::OutputRequest {
                        format: crate::report::OutputFormat::Json,
                        primary: crate::report::OutputDest::File(path.clone()),
                        cbom: None,
                    },
                    true,
                    &mut Vec::new(),
                );
                let emitted = std::fs::read(&path);
                let _ = std::fs::remove_file(path);
                assert!(
                    entered
                        && settled
                        && exact_reaped(owned.pid)
                        && owned.fixture.descriptors_closed()
                );
                assert!(emitted.is_ok() && result.delivery.delivered_all());
                assert_eq!(
                    result.exit_code, 4,
                    "{hold:?} check={check} pending={count:?}"
                );
                assert_eq!(result.child_exit, Some(137));
                let context = result.failure_context.as_ref().unwrap();
                assert_eq!(original_cause, capture::PreObservationCause::Cancelled);
                assert_eq!(
                    context.failure.as_ref().unwrap().class,
                    BoundaryFailureClass::Cancelled
                );
                assert_eq!(
                    context.count.actual_failure().unwrap().class,
                    if hold == Hold::PrepareLoadError {
                        BoundaryFailureClass::Io
                    } else {
                        BoundaryFailureClass::Panic
                    }
                );
                let capture::PreObservationCount::SetupPending(snapshot) = count else {
                    panic!("actual pending Prepare");
                };
                let watch = locked(&owned.attempt.links.0).watch.clone().unwrap();
                let progress = watch.progress().unwrap();
                let raw = progress.prepare_failure.expect("real Prepare failure");
                assert_eq!(
                    snapshot.owner_epoch(),
                    progress.owner_epoch.map(|e| e.value())
                );
                assert_eq!(progress.cleanup_ticket, raw.cleanup_ticket);
                assert_eq!(
                    raw.failure.class,
                    crate::count_owner::FailureClass::Cancelled
                );
                let independent = snapshot.known_failure().expect("actual owner failure");
                assert_eq!(
                    independent.class,
                    if hold == Hold::PrepareLoadError {
                        BoundaryFailureClass::Io
                    } else {
                        BoundaryFailureClass::Panic
                    }
                );
                assert_eq!(
                    independent.errno,
                    if hold == Hold::PrepareLoadError {
                        Some(libc::EIO)
                    } else {
                        None
                    }
                );
            }
        }
    }

    #[test]
    fn w079_fullplan_worker_context_survives_failure() {
        for hold in [Hold::ContextReady, Hold::ContextPartial] {
            let mut owned = Owned::new(hold, Duration::from_secs(10), false);
            let expected_comm = std::fs::read_to_string(format!("/proc/{}/comm", owned.pid))
                .unwrap()
                .trim()
                .to_owned();
            assert!(!expected_comm.is_empty());
            assert!(
                owned.info.as_ref().unwrap().comm.is_empty()
                    && owned.info.as_ref().unwrap().kernel_release.is_empty()
            );
            let failure = if hold == Hold::ContextPartial {
                let until = Instant::now() + Duration::from_secs(2);
                while !owned.gate.entered.load(Ordering::Acquire) && Instant::now() < until {
                    std::thread::yield_now();
                }
                owned.cancelled.store(true, Ordering::Release);
                owned
                    .attempt
                    .wait()
                    .expect_err("partial context cancellation")
            } else {
                owned.attempt.wait().expect("actual prepared Ready");
                let window = owned
                    .attempt
                    .ready
                    .as_mut()
                    .unwrap()
                    .bundle
                    .window
                    .as_mut()
                    .unwrap();
                // Exercise the actual release-failure branch after Ready. The
                // existing duration-overflow validation guarantees no SIGCONT.
                window.cfg.duration = Duration::MAX;
                match capture::commit_owned_release(
                    owned.attempt.target.as_mut().unwrap(),
                    window,
                    &owned.attempt.control,
                    &capture::LiveClock,
                ) {
                    Err(failure) => failure,
                    Ok(_) => unreachable!("u64 monotonic + maximal duration cannot fit"),
                }
            };
            let error = capture::controlled_setup_failure(
                &mut owned.attempt,
                failure,
                owned.info.as_ref().unwrap(),
                owned.cfg.as_ref().unwrap(),
            );
            let settled = owned.settled();
            assert!(settled && exact_reaped(owned.pid));
            if hold == Hold::ContextReady {
                assert!(owned.fixture.descriptors_closed());
            } else {
                assert!(matches!(
                    owned.attempt.count_diagnostic(),
                    capture::PreObservationCount::NotPrepared
                ));
            }
            let context = error
                .downcast_ref::<capture::PreObservationFailure>()
                .unwrap();
            assert_eq!(
                context.target.comm, expected_comm,
                "worker comm already obtained at {hold:?}"
            );
            let kernel = &context.context.as_ref().unwrap().kernel_release;
            if hold == Hold::ContextReady {
                assert!(!kernel.is_empty());
            } else {
                assert!(kernel.is_empty(), "unobtained kernel remains unknown");
            }
        }
    }

    #[test]
    fn w079_fullplan_stage2_pin_child_custody() {
        for hold in [
            Hold::Stage2PinError,
            Hold::Stage2PinCancel,
            Hold::Stage2PinUnwind,
        ] {
            let mut owned = Owned::new(hold, Duration::from_secs(10), false);
            let reap = crate::target::hold_setup_reap(owned.attempt.target.as_mut().unwrap());
            let until = Instant::now() + Duration::from_secs(2);
            while !owned.gate.entered.load(Ordering::Acquire) && Instant::now() < until {
                std::thread::yield_now();
            }
            let entered = owned.gate.entered.load(Ordering::Acquire);
            let failure = if hold == Hold::Stage2PinCancel {
                owned.cancelled.store(true, Ordering::Release);
                owned
                    .attempt
                    .wait()
                    .expect_err("cancel while real File is held")
            } else {
                owned.gate.release();
                owned
                    .attempt
                    .wait()
                    .expect_err("real metadata failure/unwind")
            };
            owned.attempt.abandon(failure);
            owned.gate.release();
            let until = Instant::now() + Duration::from_secs(2);
            while !reap.entered.load(Ordering::Acquire) && Instant::now() < until {
                std::thread::yield_now();
            }
            std::thread::sleep(Duration::from_millis(30));
            let fds = owned.attempt.links.test_fds();
            let retained = fds
                .iter()
                .flatten()
                .all(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) } >= 0);
            let pending = locked(&owned.attempt.links.0).custody.is_none();
            let reap_entered = reap.entered.load(Ordering::Acquire);
            reap.release();
            let settled = owned.settled();
            assert!(settled && exact_reaped(owned.pid) && owned.fixture.descriptors_closed());
            assert!(
                entered && reap_entered && pending && fds.iter().any(Option::is_some) && retained,
                "real stage2 File must outlive consuming reap at {hold:?}"
            );
            assert!(
                fds.iter()
                    .flatten()
                    .all(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) } == -1)
            );
        }
    }

    #[test]
    fn w079_fullplan_birth_map_child_custody() {
        for hold in [Hold::BirthError, Hold::BirthCancel, Hold::BirthUnwind] {
            let mut owned = Owned::new(hold, Duration::from_secs(10), false);
            let reap = crate::target::hold_setup_reap(owned.attempt.target.as_mut().unwrap());
            let until = Instant::now() + Duration::from_secs(2);
            while !owned.gate.entered.load(Ordering::Acquire) && Instant::now() < until {
                std::thread::yield_now();
            }
            let entered = owned.gate.entered.load(Ordering::Acquire);
            let failure = if hold == Hold::BirthCancel {
                owned.cancelled.store(true, Ordering::Release);
                owned
                    .attempt
                    .wait()
                    .expect_err("cancel while real BIRTH map FD is held")
            } else {
                owned.gate.release();
                owned
                    .attempt
                    .wait()
                    .expect_err("real map-info failure/unwind")
            };
            owned.attempt.abandon(failure);
            owned.gate.release();
            let until = Instant::now() + Duration::from_secs(2);
            while !reap.entered.load(Ordering::Acquire) && Instant::now() < until {
                std::thread::yield_now();
            }
            std::thread::sleep(Duration::from_millis(30));
            let fds = owned.attempt.links.test_fds();
            let retained = fds
                .iter()
                .flatten()
                .all(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) } >= 0);
            let pending = locked(&owned.attempt.links.0).custody.is_none();
            let reap_entered = reap.entered.load(Ordering::Acquire);
            reap.release();
            let settled = owned.settled();
            assert!(settled && exact_reaped(owned.pid) && owned.fixture.descriptors_closed());
            assert!(
                entered && reap_entered && pending && fds.iter().any(Option::is_some) && retained,
                "real BIRTH map FD must outlive consuming reap at {hold:?}"
            );
            assert!(
                fds.iter()
                    .flatten()
                    .all(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) } == -1)
            );
        }
    }

    #[test]
    fn w079_recoverable_reader_keeps_ready() {
        let mut owned = Owned::new(Hold::RecoverableReaderError, Duration::from_secs(10), false);
        let result = owned.attempt.wait();
        let failed = locked(&owned.attempt.links.0).failure.is_some();
        let settled = owned.settled();
        assert!(
            settled && result.is_ok() && !failed,
            "handled cap refusal preserves ordinary baseline recovery: {result:?}"
        );
        assert!(exact_reaped(owned.pid) && owned.fixture.descriptors_closed());
        assert_eq!(owned.released.load(Ordering::Acquire), 0);
    }

    #[test]
    fn w079_native_first_cause_before_disposal() {
        for hold in [Hold::ResourceError, Hold::ResourceUnwind, Hold::ReaderError] {
            let mut owned = Owned::new(hold, Duration::from_secs(20), false);
            let started = Instant::now();
            let failure = owned
                .attempt
                .wait()
                .expect_err("original native cause must publish before its disposal wait");
            let original = match &failure {
                SetupFailure::Boundary(failure) => match hold {
                    Hold::ResourceError => {
                        failure.class == BoundaryFailureClass::Io
                            && failure.errno == Some(libc::EIO)
                    }
                    Hold::ResourceUnwind => failure.class == BoundaryFailureClass::Panic,
                    Hold::ReaderError => failure.class == BoundaryFailureClass::InvalidInput,
                    _ => false,
                },
                _ => false,
            };
            owned.attempt.abandon(failure);
            let receipt = owned
                .attempt
                .await_receipt(Instant::now() + Duration::from_secs(1));
            let settled = owned.settled();
            assert!(settled && original && started.elapsed() < Duration::from_secs(5));
            assert_eq!(receipt.child_exit, Some(137));
            assert!(exact_reaped(owned.pid) && owned.fixture.descriptors_closed());
            assert!(locked(&owned.peers).iter().all(peer_closed));
        }
    }

    #[test]
    fn w079_baseline_unwind_retains_state() {
        let mut owned = Owned::new(Hold::Unwind, Duration::from_secs(10), false);
        let failure = owned
            .attempt
            .wait()
            .expect_err("baseline unwind must be explicit");
        owned.attempt.abandon(failure.clone());
        let receipt = owned
            .attempt
            .await_receipt(Instant::now() + Duration::from_secs(1));
        let settled = owned.settled();
        assert!(settled && owned.fixture.descriptors_closed() && exact_reaped(owned.pid));
        assert_eq!(receipt.child_exit, Some(137));
        assert!(matches!(
            failure,
            SetupFailure::Boundary(BoundaryFailure {
                class: BoundaryFailureClass::Panic,
                ..
            })
        ));
    }
}
