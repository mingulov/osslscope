//! SPDX-License-Identifier: GPL-3.0-or-later
//! Registry storage outlives unwindable I/O. Destruction never closes a count FD.
use super::io::CountIoDriver;
use super::protocol::*;
use std::mem::ManuallyDrop;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LoadSlot(usize);
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // Pin/link/transient acquisition is wired by subsequent handlers.
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
    _memberships: Vec<(u64, u64)>,
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
            _memberships: preallocated(limits.membership_slots)?,
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
                self.slots[index].record.state = ResourceState::CloseIssued;
                self.publish_progress();
                #[cfg(test)]
                if let Some(observer) = &self.observer {
                    observer(RegistryEvent::CloseIssued(
                        self.slots[index].record.resource,
                    ));
                }
                let fd = self.slots[index].fd.take().expect("issued held owner slot");
                let result = driver.close(ManuallyDrop::into_inner(fd));
                let slot = &mut self.slots[index];
                slot.record.errno = result.as_ref().err().and_then(std::io::Error::raw_os_error);
                slot.record.state = if result.is_ok() {
                    ResourceState::CloseReturned
                } else {
                    ResourceState::ConsumedError
                };
                self.publish_progress();
                #[cfg(test)]
                if let Some(observer) = &self.observer {
                    observer(RegistryEvent::CloseReturned(
                        self.slots[index].record.resource,
                    ));
                }
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
                    ResourceState::Unused | ResourceState::CreateFailed
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
