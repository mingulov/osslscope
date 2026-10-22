//! SPDX-License-Identifier: GPL-3.0-or-later
//! Registry storage outlives unwindable I/O. Destruction never closes a count FD.
use super::io::CountIoDriver;
use super::protocol::*;
use std::mem::ManuallyDrop;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LoadSlot(usize);
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // Transient acquisition is wired by the read handler.
pub(crate) enum ResourceKind {
    Map(CountMap),
    Program,
    Pin,
    Link(LinkId),
    Transient,
}
impl ResourceKind {
    fn diagnostic(self) -> ResourceId {
        match self {
            Self::Map(m) => ResourceId::Map(m),
            Self::Program => ResourceId::Program,
            Self::Pin => ResourceId::Pin(0),
            Self::Link(id) => ResourceId::Link(id),
            Self::Transient => ResourceId::Transient(0),
        }
    }
}
/// Only owner code may use this interface. Returned slots carry no descriptors.
pub(crate) trait CountLoadSink {
    fn reserve(&mut self, kind: ResourceKind) -> Result<LoadSlot, OwnerFailure>;
    fn install(&mut self, slot: LoadSlot, fd: OwnedFd);
    fn borrow(&self, slot: LoadSlot) -> BorrowedFd<'_>;
    fn failed(&mut self, slot: LoadSlot, errno: Option<i32>);
}
struct Slot {
    record: ResourceRecord,
    fd: Option<ManuallyDrop<OwnedFd>>,
}
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub(super) enum RegistryEvent {
    Reserved(ResourceId),
    Creating(ResourceId),
    Installed(ResourceId),
    CloseIssued(ResourceId),
    CloseReturned(ResourceId),
    AttachStorage {
        attempts: usize,
        attempt_capacity: usize,
        attempt_address: usize,
        records: usize,
        memberships: usize,
        refusals: usize,
        refusal_capacity: usize,
        refusal_address: usize,
    },
}
#[cfg(test)]
impl RegistryEvent {
    pub(super) fn resource(self) -> ResourceId {
        match self {
            Self::Reserved(id)
            | Self::Creating(id)
            | Self::Installed(id)
            | Self::CloseIssued(id)
            | Self::CloseReturned(id) => id,
            Self::AttachStorage { .. } => ResourceId::Engine,
        }
    }
}

pub(crate) struct Registry {
    slots: Vec<Slot>,
    limits: CountOwnerLimits,
    sealed: bool,
    pub(super) abandoned: Arc<AtomicBool>,
    pub(super) shared: Option<Arc<super::Shared>>,
    // These bounded work buffers exist before the first acquisition. They are
    // retained by the same owner for the later attach/read command handlers.
    pub(super) journal: OwnerJournal,
    work: AttachWorkspace,
    pin_backings: Vec<Option<BackingIdentity>>,
    _raw_rows: Vec<(u64, osslscope_ebpf_common::CountValue)>,
    _cpu_scratch: Vec<u8>,
    #[cfg(test)]
    pub(super) observer: Option<Arc<dyn Fn(RegistryEvent) + Send + Sync>>,
}

pub(crate) fn preallocated<T>(count: usize) -> Result<Vec<T>, OwnerFailure> {
    let mut storage = Vec::new();
    storage
        .try_reserve_exact(count)
        .map_err(|_| OwnerFailure::engine(CountOperation::Load, FailureClass::Allocation))?;
    Ok(storage)
}
impl Registry {
    pub(super) fn allocate(limits: CountOwnerLimits) -> Result<Self, OwnerFailure> {
        let total = usize::try_from(limits.fd_reservation)
            .map_err(|_| OwnerFailure::engine(CountOperation::Load, FailureClass::Capacity))?;
        let mut slots = preallocated(total)?;
        for index in 0..total {
            let resource = if index < 7 {
                ResourceId::Map(CountMap::ALL[index])
            } else if index == 7 {
                ResourceId::Program
            } else if index >= 8 + limits.link_slots
                && index < 8 + limits.link_slots + limits.pin_slots
            {
                ResourceId::Pin(index - 8 - limits.link_slots)
            } else if index >= total - limits.transient_slots {
                ResourceId::Transient((index - (total - limits.transient_slots)) as u8)
            } else {
                ResourceId::Engine
            }; // Unused link slots acquire their LinkId at reserve.
            slots.push(Slot {
                record: ResourceRecord {
                    resource,
                    state: ResourceState::Unused,
                    errno: None,
                },
                fd: None,
            });
        }
        let mut scratch = preallocated(limits.cpu_scratch_bytes)?;
        scratch.resize(limits.cpu_scratch_bytes, 0);
        Ok(Self {
            slots,
            limits,
            sealed: false,
            abandoned: Arc::new(AtomicBool::new(false)),
            shared: None,
            journal: OwnerJournal::allocate(limits)?,
            work: AttachWorkspace::allocate(limits)?,
            pin_backings: {
                let mut pins = preallocated(limits.pin_slots)?;
                pins.resize(limits.pin_slots, None);
                pins
            },
            _raw_rows: preallocated(limits.raw_rows)?,
            _cpu_scratch: scratch,
            #[cfg(test)]
            observer: None,
        })
    }
    pub(super) fn summary_storage(&self) -> Result<ResourceSummary, OwnerFailure> {
        let mut resources = preallocated(self.slots.len())?;
        resources.extend(self.slots.iter().map(|slot| slot.record));
        Ok(ResourceSummary {
            resources,
            sealed: self.sealed,
            cleanup_complete: false,
        })
    }
    /// Move the already prepared read storage before the first count FD exists.
    /// The read owner adds the other two immutable images during preparation.
    pub(super) fn take_read_storage(
        &mut self,
    ) -> (Vec<(u64, osslscope_ebpf_common::CountValue)>, Vec<u8>) {
        (
            std::mem::take(&mut self._raw_rows),
            std::mem::take(&mut self._cpu_scratch),
        )
    }
    #[cfg(test)]
    pub(super) fn summary(&self) -> ResourceSummary {
        let mut summary = self.summary_storage().unwrap();
        self.publish_into(&mut summary);
        summary
    }
    pub(super) fn publish_into(&self, summary: &mut ResourceSummary) {
        for (out, slot) in summary.resources.iter_mut().zip(&self.slots) {
            *out = slot.record;
        }
        summary.sealed = self.sealed;
        summary.cleanup_complete = self.sealed
            && self.slots.iter().all(|slot| {
                matches!(
                    slot.record.state,
                    ResourceState::Unused
                        | ResourceState::CreateFailed
                        | ResourceState::CloseReturned
                )
            });
    }
    pub(super) fn seal_unentered(&mut self) {
        self.sealed = true;
        self.publish_progress();
    }
    pub(super) fn initial_empty(&self, published_at: Instant) -> Option<EmptyFamily> {
        let journal = &self.journal;
        let pristine = journal.records.is_empty()
            && journal.memberships.is_empty()
            && journal.last_started.is_none()
            && journal.last_completed.is_none()
            && journal.last_published.is_none()
            && journal.last_acked.is_none()
            && journal.resolved_open.is_none()
            && self.slots.iter().enumerate().all(|(index, slot)| {
                slot.record.state
                    == if index < 8 {
                        ResourceState::Held
                    } else {
                        ResourceState::Unused
                    }
            });
        pristine.then_some(EmptyFamily {
            writer: journal.writer?,
            published_at,
        })
    }
    fn publish_progress(&self) {
        if let Some(shared) = &self.shared {
            shared.registry_progress(self);
        }
    }
    /// Seal before any cleanup. Creating and consumed-error states remain
    /// unresolved; physical FD-count changes alone cannot retire this epoch.
    pub(super) fn cleanup(&mut self, driver: &mut impl CountIoDriver) {
        self.sealed = true;
        self.publish_progress();
        // Links precede pins; the program/maps follow both. Task 2 has only the
        // seven maps/program, but never introduces a future pin-before-link path.
        for range in [
            8..8 + self.limits.link_slots,
            8 + self.limits.link_slots..8 + self.limits.link_slots + self.limits.pin_slots,
            self.slots.len() - 8..self.slots.len(),
            7..8,
            0..7,
        ] {
            for index in range {
                if self.slots[index].record.state == ResourceState::Reserved {
                    self.slots[index].record.state = ResourceState::CreateFailed;
                    self.publish_progress();
                }
                if self.slots[index].fd.is_none() {
                    continue;
                }
                let _ = self.close_slot(LoadSlot(index), driver);
            }
        }
    }
}
impl CountLoadSink for Registry {
    fn reserve(&mut self, kind: ResourceKind) -> Result<LoadSlot, OwnerFailure> {
        let failure = |class| OwnerFailure {
            operation: CountOperation::Load,
            resource: kind.diagnostic(),
            class,
            errno: None,
        };
        if self.sealed || self.abandoned.load(Ordering::Acquire) {
            return Err(failure(FailureClass::Disconnected));
        }
        let indices = match kind {
            ResourceKind::Map(map) => map.index()..map.index() + 1,
            ResourceKind::Program => 7..8,
            ResourceKind::Link(_) => 8..8 + self.limits.link_slots,
            ResourceKind::Pin => {
                8 + self.limits.link_slots..8 + self.limits.link_slots + self.limits.pin_slots
            }
            ResourceKind::Transient => {
                self.slots.len() - self.limits.transient_slots..self.slots.len()
            }
        };
        let index = indices
            .into_iter()
            .find(|i| {
                matches!(
                    self.slots[*i].record.state,
                    ResourceState::Unused
                        | ResourceState::CreateFailed
                        | ResourceState::CloseReturned
                )
            })
            .ok_or_else(|| failure(FailureClass::Capacity))?;
        let slot = &mut self.slots[index];
        if let ResourceKind::Link(id) = kind {
            slot.record.resource = ResourceId::Link(id);
        }
        slot.record.state = ResourceState::Reserved;
        slot.record.errno = None;
        self.publish_progress();
        #[cfg(test)]
        if let Some(observer) = &self.observer {
            observer(RegistryEvent::Reserved(self.slots[index].record.resource));
        }
        self.slots[index].record.state = ResourceState::Creating;
        self.publish_progress();
        #[cfg(test)]
        if let Some(observer) = &self.observer {
            observer(RegistryEvent::Creating(self.slots[index].record.resource));
        }
        Ok(LoadSlot(index))
    }
    fn install(&mut self, slot: LoadSlot, fd: OwnedFd) {
        // Suppress destructor closure before even indexing. LoadSlot is minted
        // only by this private registry, into already allocated storage.
        let fd = ManuallyDrop::new(fd);
        let target = &mut self.slots[slot.0];
        target.fd = Some(fd);
        target.record.state = ResourceState::Held;
        self.publish_progress();
        #[cfg(test)]
        if let Some(observer) = &self.observer {
            observer(RegistryEvent::Installed(self.slots[slot.0].record.resource));
        }
    }
    fn borrow(&self, slot: LoadSlot) -> BorrowedFd<'_> {
        self.slots[slot.0]
            .fd
            .as_ref()
            .expect("installed owner slot")
            .as_fd()
    }
    fn failed(&mut self, slot: LoadSlot, errno: Option<i32>) {
        self.slots[slot.0].record.state = ResourceState::CreateFailed;
        self.slots[slot.0].record.errno = errno;
        self.publish_progress();
    }
}
// Deliberately no destructor close: only cleanup's checked consuming calls can
// resolve ownership. A stranded registry retains its bounded unresolved state.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AttachAttempt {
    pub id: LinkId,
    pub command: CommandSeq,
    pub first: usize,
    pub count: usize,
    pub errno: Option<i32>,
    pub succeeded: bool,
}
/// Successes last for the epoch; descriptor-free attempt diagnostics last only
/// until the active command is acknowledged. No failed retry adds history.
pub struct OwnerJournal {
    writer: Option<WriterIdentity>,
    records: Vec<CreationRecord>,
    memberships: Vec<AttachedMembership>,
    attempts: Vec<AttachAttempt>,
    serials: IdCounter,
    last_started: Option<PendingCommandId>,
    last_published: Option<CommandSeq>,
    last_acked: Option<CommandSeq>,
    last_completed: Option<PendingCommandId>,
    resolved_open: Option<OpenReceipt>,
    sealed_storage: Option<Arc<SealedInventory>>,
}
impl OwnerJournal {
    fn allocate(limits: CountOwnerLimits) -> Result<Self, OwnerFailure> {
        let epoch = OwnerEpoch::checked(1)?; // Bound to the real epoch before Ready.
        Ok(Self {
            writer: None,
            records: preallocated(limits.link_slots)?,
            memberships: preallocated(limits.membership_slots)?,
            attempts: preallocated(
                8192usize
                    .checked_mul(2)
                    .and_then(|n| n.checked_sub(1))
                    .ok_or_else(|| {
                        OwnerFailure::engine(CountOperation::Attach, FailureClass::Capacity)
                    })?,
            )?,
            serials: IdCounter::default(),
            last_started: None,
            last_published: None,
            last_acked: None,
            last_completed: None,
            resolved_open: None,
            sealed_storage: Some(Arc::new(SealedInventory {
                owner_epoch: epoch,
                writer: WriterIdentity {
                    owner_epoch: epoch,
                    object_sha256: [0; 32],
                    program: ResourceId::Program,
                    maps: CountMap::ALL.map(ResourceId::Map),
                },
                records: preallocated(limits.link_slots)?,
                memberships: preallocated(limits.membership_slots)?,
                acknowledged_links: preallocated(limits.link_slots)?,
                unpublished_links: preallocated(limits.link_slots)?,
                last_acked: None,
                pending: None,
                last_completed: None,
                resolved_open: None,
            })),
        })
    }
    pub(super) fn bind(&mut self, epoch: OwnerEpoch, object_sha256: [u8; 32]) {
        self.writer = Some(WriterIdentity {
            owner_epoch: epoch,
            object_sha256,
            program: ResourceId::Program,
            maps: CountMap::ALL.map(ResourceId::Map),
        });
        Arc::get_mut(self.sealed_storage.as_mut().expect("unsealed preparation"))
            .expect("unpublished inventory")
            .owner_epoch = epoch;
        Arc::get_mut(self.sealed_storage.as_mut().expect("unsealed preparation"))
            .expect("unpublished inventory")
            .writer = self.writer.unwrap();
    }
    pub(super) fn begin(&mut self, seq: CommandSeq, operation: CountOperation) {
        self.attempts.clear();
        self.last_started = Some(PendingCommandId { seq, operation });
    }
    pub(super) fn completed(&mut self, seq: CommandSeq, operation: CountOperation) {
        self.last_completed = Some(PendingCommandId { seq, operation });
    }
    pub(super) fn resolved_open(&mut self, open: Option<OpenReceipt>) {
        self.resolved_open = open;
    }
    pub(super) fn published(&mut self, seq: CommandSeq) {
        for record in &mut self.records {
            if record.command == seq {
                record.publication = PublicationState::Published;
            }
        }
        self.last_published = Some(seq);
    }
    pub(super) fn acknowledged(&mut self, seq: Option<CommandSeq>) {
        if seq.is_some() && seq == self.last_published {
            self.last_acked = seq;
        }
    }
    pub fn seal(
        &mut self,
        frontier: &ControllerFrontier,
    ) -> Result<Arc<SealedInventory>, InventoryFailure> {
        if self.last_acked != frontier.last_acked {
            return Err(InventoryFailure::Frontier);
        }
        let expected_pending = self
            .last_started
            .filter(|pending| Some(pending.seq) != self.last_acked);
        if expected_pending != frontier.pending {
            return Err(InventoryFailure::Frontier);
        }
        let mut out = self
            .sealed_storage
            .take()
            .ok_or(InventoryFailure::AlreadySealed)?;
        let data = Arc::get_mut(&mut out).expect("unpublished inventory");
        data.last_acked = frontier.last_acked;
        data.pending = frontier.pending;
        data.last_completed = self.last_completed;
        data.resolved_open = self.resolved_open;
        data.records.extend(self.records.iter().cloned());
        data.memberships.extend_from_slice(&self.memberships);
        for record in &self.records {
            if frontier.acknowledged_links.contains(&record.id) {
                data.acknowledged_links.push(record.id);
            } else {
                data.unpublished_links.push(record.id);
            }
        }
        out.validate(frontier)?;
        Ok(out)
    }
    fn existing(&self, backing: BackingIdentity, offset: u64) -> Option<(LinkId, u64)> {
        self.records
            .iter()
            .filter(|r| r.backing == backing && r.outcome == CreateOutcome::Succeeded)
            .find_map(|r| {
                self.memberships[r.memberships.clone()]
                    .iter()
                    .find(|m| m.offset == offset)
                    .map(|m| (r.id, m.cookie))
            })
    }
}
#[derive(Clone, Copy)]
struct PendingSite {
    offset: u64,
    cookie: u64,
}
struct AttachWorkspace {
    order: Vec<usize>,
    offsets: Vec<u64>,
    cookies: Vec<u64>,
    stack: Vec<std::ops::Range<usize>>,
    reused: Vec<LinkId>,
    refused_offsets: Vec<(u64, AttachRefusalReason)>,
}
impl AttachWorkspace {
    fn allocate(limits: CountOwnerLimits) -> Result<Self, OwnerFailure> {
        Ok(Self {
            order: preallocated(8192)?,
            offsets: preallocated(8192)?,
            cookies: preallocated(8192)?,
            stack: preallocated(8192)?,
            reused: preallocated(limits.link_slots)?,
            refused_offsets: preallocated(8192)?,
        })
    }
    fn clear(&mut self) {
        self.order.clear();
        self.offsets.clear();
        self.cookies.clear();
        self.stack.clear();
        self.reused.clear();
        self.refused_offsets.clear();
    }
}
impl Registry {
    #[cfg(test)]
    pub(super) fn observe_attach_storage(&self) {
        if let Some(observer) = &self.observer {
            observer(RegistryEvent::AttachStorage {
                attempts: self.journal.attempts.len(),
                attempt_capacity: self.journal.attempts.capacity(),
                attempt_address: self.journal.attempts.as_ptr() as usize,
                records: self.journal.records.len(),
                memberships: self.journal.memberships.len(),
                refusals: self.work.refused_offsets.len(),
                refusal_capacity: self.work.refused_offsets.capacity(),
                refusal_address: self.work.refused_offsets.as_ptr() as usize,
            });
        }
    }
    fn close_slot(
        &mut self,
        slot: LoadSlot,
        driver: &mut impl CountIoDriver,
    ) -> std::io::Result<()> {
        let index = slot.0;
        self.slots[index].record.state = ResourceState::CloseIssued;
        if let ResourceId::Link(id) = self.slots[index].record.resource {
            if let Some(record) = self.journal.records.iter_mut().find(|r| r.id == id) {
                record.close_state = ResourceState::CloseIssued;
            }
        }
        let fd = self.slots[index].fd.take().expect("issued held owner slot");
        self.publish_progress();
        #[cfg(test)]
        if let Some(observer) = &self.observer {
            observer(RegistryEvent::CloseIssued(
                self.slots[index].record.resource,
            ));
        }
        if let Some(shared) = &self.shared {
            let mut state = super::locked(&shared.state);
            state.active_operation = Some(if state.phase == OwnerPhase::Cleaning {
                CountOperation::Cleanup
            } else {
                CountOperation::Close
            });
        }
        let result = driver.close(ManuallyDrop::into_inner(fd));
        let record = &mut self.slots[index].record;
        record.errno = result.as_ref().err().and_then(std::io::Error::raw_os_error);
        record.state = if result.is_ok() {
            ResourceState::CloseReturned
        } else {
            ResourceState::ConsumedError
        };
        if let ResourceId::Link(id) = record.resource {
            if let Some(entry) = self.journal.records.iter_mut().find(|r| r.id == id) {
                entry.close_state = record.state;
                entry.close_errno = record.errno;
            }
        }
        if let Some(shared) = &self.shared {
            let mut state = super::locked(&shared.state);
            if let Err(error) = &result {
                let operation = if state.phase == OwnerPhase::Cleaning {
                    CountOperation::Cleanup
                } else {
                    CountOperation::Close
                };
                state.failures.record_at(
                    OwnerFailure::io(operation, record.resource, error),
                    shared.now(),
                );
            }
            state.active_operation = None;
        }
        self.publish_progress();
        #[cfg(test)]
        if let Some(observer) = &self.observer {
            observer(RegistryEvent::CloseReturned(
                self.slots[index].record.resource,
            ));
        }
        result
    }
    pub(super) fn close_writers(
        &mut self,
        driver: &mut impl CountIoDriver,
        outcomes: &mut Vec<LinkCloseOutcome>,
    ) {
        self.sealed = true;
        self.publish_progress();
        // Link slots are never reused within an epoch, so their physical order
        // is the never-wrapping successful creation serial order.
        for index in 8..8 + self.limits.link_slots {
            let ResourceId::Link(id) = self.slots[index].record.resource else {
                continue;
            };
            if self.slots[index].fd.is_none() {
                continue;
            }
            let issued_at = self
                .shared
                .as_ref()
                .map_or_else(Instant::now, |shared| shared.now());
            let outcome = LinkCloseOutcome {
                id,
                issued_at: Some(issued_at),
                returned_at: None,
                state: ResourceState::CloseIssued,
                errno: None,
            };
            assert!(outcomes.len() < outcomes.capacity());
            outcomes.push(outcome);
            if let Some(shared) = &self.shared {
                shared.terminal_close_progress(outcome, None);
            }
            // close_slot consumes the capability before the one syscall. A
            // panic cannot hand an OwnedFd to destructor/replacement cleanup.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.close_slot(LoadSlot(index), driver)
            }));
            let outcome = outcomes.last_mut().expect("reserved close outcome");
            if result.is_ok() {
                outcome.returned_at = Some(
                    self.shared
                        .as_ref()
                        .map_or_else(Instant::now, |shared| shared.now()),
                );
                outcome.state = self.slots[index].record.state;
                outcome.errno = self.slots[index].record.errno;
            }
            let failure = match result {
                Ok(Ok(())) => None,
                Ok(Err(ref error)) => Some(OwnerFailure::io(
                    CountOperation::Close,
                    ResourceId::Link(id),
                    error,
                )),
                Err(_) => Some(OwnerFailure {
                    operation: CountOperation::Close,
                    resource: ResourceId::Link(id),
                    class: FailureClass::Panic,
                    errno: None,
                }),
            };
            // Publish each returned failure before entering another close. A
            // selected immutable receipt is never modified by later progress.
            if let Some(shared) = &self.shared {
                shared.terminal_close_progress(*outcome, failure);
            }
        }
    }
    pub(super) fn copy_manifest(&self, destination: &mut Vec<CreationRecord>) {
        destination.clear();
        destination.extend(self.journal.records.iter().cloned());
    }
    fn stopped(&self, driver: &impl CountIoDriver, deadline: Instant) -> Result<(), OwnerFailure> {
        if driver.now() >= deadline {
            return Err(OwnerFailure::engine(
                CountOperation::Attach,
                FailureClass::Deadline,
            ));
        }
        if self.sealed
            || self.abandoned.load(Ordering::Acquire)
            || self
                .shared
                .as_ref()
                .is_some_and(|shared| super::locked(&shared.state).terminal.is_some())
        {
            return Err(OwnerFailure::engine(
                CountOperation::Attach,
                FailureClass::Disconnected,
            ));
        }
        Ok(())
    }
    fn operation(&self, operation: CountOperation) {
        if let Some(shared) = &self.shared {
            super::locked(&shared.state).active_operation = Some(operation);
        }
    }
    fn attach_reserve(
        &mut self,
        kind: ResourceKind,
        operation: CountOperation,
    ) -> Result<LoadSlot, OwnerFailure> {
        self.reserve(kind).map_err(|mut f| {
            f.operation = operation;
            f
        })
    }
    fn pin_index(&self, slot: LoadSlot) -> usize {
        slot.0 - 8 - self.limits.link_slots
    }
    fn refuse_all(
        &self,
        request: &AttachRequest,
        ack: &mut AttachAck<LinkToken>,
        reason: AttachRefusalReason,
    ) {
        for (position, offset) in request.offsets.iter().enumerate() {
            if self.work.offsets.contains(offset) {
                ack.refused.push(AttachRefusal { position, reason });
            }
        }
    }
    /// All buffers, including the exact success journal, were reserved before
    /// loading. The reply's bounded vectors are supplied before this command.
    pub(super) fn attach(
        &mut self,
        driver: &mut impl CountIoDriver,
        program: LoadSlot,
        tgid: u32,
        request: &AttachRequest,
        mut ack: AttachAck<LinkToken>,
    ) -> Result<AttachAck<LinkToken>, OwnerFailure> {
        self.work.clear();
        self.stopped(driver, request.deadline)?;
        self.work.order.extend(0..request.offsets.len());
        self.work
            .order
            .sort_unstable_by_key(|i| request.offsets[*i]);
        let mut previous: Option<PendingSite> = None;
        for i in self.work.order.iter().copied() {
            let site = PendingSite {
                offset: request.offsets[i],
                cookie: request.cookies[i],
            };
            if let Some(prior) = previous {
                if prior.offset == site.offset {
                    if prior.cookie != site.cookie {
                        return Err(OwnerFailure::engine(
                            CountOperation::Attach,
                            FailureClass::InvalidInput,
                        ));
                    }
                    continue;
                }
            }
            previous = Some(site);
            if let Some((id, cookie)) = self.journal.existing(request.expected_backing, site.offset)
            {
                if cookie != site.cookie {
                    return Err(OwnerFailure::engine(
                        CountOperation::Attach,
                        FailureClass::InvalidInput,
                    ));
                }
                if !self.work.reused.contains(&id) {
                    self.work.reused.push(id);
                }
            } else {
                self.work.offsets.push(site.offset);
                self.work.cookies.push(site.cookie);
            }
        }
        for id in &self.work.reused {
            ack.links.push(LinkToken::new(*id));
        }
        let n = self.work.offsets.len();
        if n == 0 {
            ack.links.sort_unstable_by_key(|link| link.id().serial);
            return Ok(ack);
        }
        let capacity = || OwnerFailure::engine(CountOperation::Attach, FailureClass::Capacity);
        if self
            .journal
            .memberships
            .len()
            .checked_add(n)
            .is_none_or(|n| n > self.limits.membership_slots)
            || self.journal.records.len() >= self.limits.link_slots
        {
            return Err(capacity());
        }
        let max_attempts = n
            .checked_mul(2)
            .and_then(|n| n.checked_sub(1))
            .ok_or_else(capacity)?;
        // A pin already retaining this exact verified backing is sufficient for
        // new sites too; a changed pathname cannot move that open description.
        let existing_pin = self
            .pin_backings
            .iter()
            .enumerate()
            .find(|(i, backing)| {
                **backing == Some(request.expected_backing)
                    && self.slots[8 + self.limits.link_slots + *i].record.state
                        == ResourceState::Held
            })
            .map(|(i, _)| LoadSlot(8 + self.limits.link_slots + i));
        let mut new_pin = false;
        let pin = if let Some(pin) = existing_pin {
            pin
        } else {
            self.operation(CountOperation::PinOpen);
            self.stopped(driver, request.deadline)?;
            let pin = self.attach_reserve(ResourceKind::Pin, CountOperation::PinOpen)?;
            // Validation occurred before publication; the bounded stack buffer
            // avoids CString allocation while a resource operation is active.
            let mut locator = [0u8; 4096];
            locator[..request.locator.len()].copy_from_slice(request.locator.as_bytes());
            let locator =
                std::ffi::CStr::from_bytes_with_nul(&locator[..request.locator.len() + 1])
                    .expect("validated locator");
            match driver.open_pin(locator) {
                Ok(fd) => self.install(pin, fd),
                Err(error) => {
                    self.failed(pin, error.raw_os_error());
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::EMFILE) | Some(libc::ENFILE)
                    ) {
                        return Err(OwnerFailure {
                            operation: CountOperation::PinOpen,
                            resource: self.slots[pin.0].record.resource,
                            class: FailureClass::Capacity,
                            errno: error.raw_os_error(),
                        });
                    }
                    self.refuse_all(request, &mut ack, AttachRefusalReason::Unreadable);
                    return Ok(ack);
                }
            }
            // The registry owns the successful open before either cutoff or
            // borrowed fstat, including an unwind in the identity seam.
            self.stopped(driver, request.deadline)?;
            self.operation(CountOperation::PinIdentity);
            let identity = driver.pin_identity(self.borrow(pin)).map_err(|error| {
                OwnerFailure::io(
                    CountOperation::PinIdentity,
                    self.slots[pin.0].record.resource,
                    &error,
                )
            })?;
            self.stopped(driver, request.deadline)?;
            if identity != request.expected_backing {
                self.close_slot(pin, driver).map_err(|error| {
                    OwnerFailure::io(
                        CountOperation::Close,
                        self.slots[pin.0].record.resource,
                        &error,
                    )
                })?;
                self.refuse_all(request, &mut ack, AttachRefusalReason::Replaced);
                return Ok(ack);
            }
            let pin_index = self.pin_index(pin);
            self.pin_backings[pin_index] = Some(identity);
            new_pin = true;
            pin
        };
        // FD-path formatting is bounded and owner-local; no raw FD enters any
        // token, reply, frontier or journal record.
        let mut path_storage = [0u8; 64];
        use std::io::Write as _;
        let mut path = std::io::Cursor::new(&mut path_storage[..]);
        write!(
            &mut path,
            "/proc/self/fd/{}\0",
            self.borrow(pin).as_raw_fd()
        )
        .expect("fixed descriptor path capacity");
        let path_len = path.position() as usize;
        let path = std::ffi::CStr::from_bytes_with_nul(&path_storage[..path_len])
            .expect("terminated fd path");
        self.work.stack.push(0..n);
        let successes_before = self.journal.records.len();
        while let Some(range) = self.work.stack.pop() {
            self.stopped(driver, request.deadline)?;
            self.operation(CountOperation::Attach);
            if self.journal.attempts.len() >= max_attempts {
                return Err(capacity());
            }
            let serial = self
                .journal
                .serials
                .next()
                .and_then(LinkSerial::checked)
                .map_err(|mut f| {
                    f.operation = CountOperation::Attach;
                    f
                })?;
            let id = LinkId {
                owner_epoch: self
                    .journal
                    .writer
                    .expect("loaded writer identity")
                    .owner_epoch,
                serial,
            };
            let slot = self.attach_reserve(ResourceKind::Link(id), CountOperation::Attach)?;
            let start = self.journal.memberships.len();
            for i in range.clone() {
                self.journal.memberships.push(AttachedMembership {
                    offset: self.work.offsets[i],
                    cookie: self.work.cookies[i],
                });
            }
            self.journal.records.push(CreationRecord {
                id,
                command: request.seq,
                writer: self.journal.writer.unwrap(),
                backing: request.expected_backing,
                pin_slot: self.pin_index(pin),
                memberships: start..self.journal.memberships.len(),
                outcome: CreateOutcome::Creating,
                publication: PublicationState::Unpublished,
                close_state: ResourceState::Creating,
                close_errno: None,
            });
            let record = self.journal.records.len() - 1;
            let attempt = AttachAttempt {
                id,
                command: request.seq,
                first: range.start,
                count: range.len(),
                errno: None,
                succeeded: false,
            };
            self.journal.attempts.push(attempt);
            match driver.attach(
                self.borrow(program),
                path,
                &self.work.offsets[range.clone()],
                &self.work.cookies[range.clone()],
                tgid,
            ) {
                Ok(fd) => {
                    // No fallible publication/instrumentation intervenes between
                    // acquisition and BOTH descriptor and exact journal custody.
                    let fd = ManuallyDrop::new(fd);
                    self.slots[slot.0].fd = Some(fd);
                    self.slots[slot.0].record.state = ResourceState::Held;
                    self.journal.records[record].outcome = CreateOutcome::Succeeded;
                    self.journal.records[record].close_state = ResourceState::Held;
                    self.journal.attempts.last_mut().unwrap().succeeded = true;
                    self.publish_progress();
                    #[cfg(test)]
                    if let Some(observer) = &self.observer {
                        observer(RegistryEvent::Installed(ResourceId::Link(id)));
                    }
                    ack.links.push(LinkToken::new(id));
                    self.stopped(driver, request.deadline)?;
                }
                Err(error) => {
                    self.failed(slot, error.raw_os_error());
                    self.journal.records.pop();
                    self.journal.memberships.truncate(start);
                    self.journal.attempts.last_mut().unwrap().errno = error.raw_os_error();
                    // A process/system FD limit is systemic capacity failure,
                    // never evidence that individual offsets were refused.
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::EMFILE) | Some(libc::ENFILE)
                    ) {
                        return Err(OwnerFailure {
                            operation: CountOperation::Attach,
                            resource: ResourceId::Link(id),
                            class: FailureClass::Capacity,
                            errno: error.raw_os_error(),
                        });
                    }
                    self.stopped(driver, request.deadline)?;
                    if range.len() > 1
                        && !matches!(error.raw_os_error(), Some(libc::EACCES) | Some(libc::EPERM))
                    {
                        let mid = range.start + range.len() / 2;
                        self.work.stack.push(mid..range.end);
                        self.work.stack.push(range.start..mid);
                    } else {
                        for i in range {
                            self.work
                                .refused_offsets
                                .push((self.work.offsets[i], AttachRefusalReason::KernelRefused));
                        }
                    }
                }
            }
        }
        if new_pin && self.journal.records.len() == successes_before {
            self.close_slot(pin, driver).map_err(|error| {
                OwnerFailure::io(
                    CountOperation::Close,
                    self.slots[pin.0].record.resource,
                    &error,
                )
            })?;
            let index = self.pin_index(pin);
            self.pin_backings[index] = None;
        }
        for (position, offset) in request.offsets.iter().enumerate() {
            if let Some((_, reason)) = self
                .work
                .refused_offsets
                .iter()
                .find(|(off, _)| off == offset)
            {
                ack.refused.push(AttachRefusal {
                    position,
                    reason: *reason,
                });
            }
        }
        ack.links.sort_unstable_by_key(|link| link.id().serial);
        Ok(ack)
    }
}
