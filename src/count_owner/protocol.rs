//! SPDX-License-Identifier: GPL-3.0-or-later
//! Data-only identities and finite owner bounds. No descriptor crosses here.
use super::CountForkBarrier;
use std::sync::Arc;

macro_rules! identity {
    ($($name:ident),+ $(,)?) => {$(
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u64);
        impl $name {
            pub fn value(self) -> u64 { self.0 }
            pub(super) fn checked(value: u64) -> Result<Self, OwnerFailure> {
                if value == 0 { Err(OwnerFailure::engine(CountOperation::Load, FailureClass::InvalidInput)) }
                else { Ok(Self(value)) }
            }
        }
    )+};
}
identity!(OwnerEpoch, LinkSerial, CommandSeq, TerminalSeq, SnapshotSeq);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TerminalId {
    pub owner_epoch: OwnerEpoch,
    pub sequence: TerminalSeq,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LinkId {
    pub owner_epoch: OwnerEpoch,
    pub serial: LinkSerial,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupTicket {
    pub owner_epoch: OwnerEpoch,
    pub terminal_id: TerminalId,
}

/// Identity only: dropping it cannot release any owner resource.
#[derive(Debug)]
pub struct LinkToken {
    id: LinkId,
}
impl LinkToken {
    pub fn id(&self) -> LinkId {
        self.id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackingIdentity {
    pub device: u64,
    pub inode: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceDomain {
    Live,
    HostModel,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CountOperation {
    Load,
    PinOpen,
    PinIdentity,
    Attach,
    Open,
    Generation,
    Read,
    Stop,
    Close,
    Cleanup,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    Capacity,
    Allocation,
    IdExhausted,
    InvalidInput,
    Deadline,
    DeadlineOverflow,
    Io,
    Panic,
    Disconnected,
    Publication,
    Inventory,
    Profile,
    ObjectDrift,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CountMap {
    Counts,
    Admitted,
    Latc,
    Gen,
    Target,
    Window,
    Dropfail,
}
impl CountMap {
    pub const ALL: [Self; 7] = [
        Self::Counts,
        Self::Admitted,
        Self::Latc,
        Self::Gen,
        Self::Target,
        Self::Window,
        Self::Dropfail,
    ];
    pub(crate) fn index(self) -> usize {
        self as usize
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceId {
    Engine,
    Map(CountMap),
    Program,
    Link(LinkId),
    Pin(usize),
    Transient(u8),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerFailure {
    pub operation: CountOperation,
    pub resource: ResourceId,
    pub class: FailureClass,
    pub errno: Option<i32>,
}
impl OwnerFailure {
    pub(crate) fn engine(operation: CountOperation, class: FailureClass) -> Self {
        Self {
            operation,
            resource: ResourceId::Engine,
            class,
            errno: None,
        }
    }
    pub(crate) fn io(
        operation: CountOperation,
        resource: ResourceId,
        error: &std::io::Error,
    ) -> Self {
        Self {
            operation,
            resource,
            class: FailureClass::Io,
            errno: error.raw_os_error(),
        }
    }
}
impl std::fmt::Display for OwnerFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "count owner {:?}/{:?}: {:?} (errno {:?})",
            self.operation, self.resource, self.class, self.errno
        )
    }
}
impl std::error::Error for OwnerFailure {}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CountPrepareFailure {
    pub failure: OwnerFailure,
    pub cleanup_ticket: Option<CleanupTicket>,
}
impl From<OwnerFailure> for CountPrepareFailure {
    fn from(failure: OwnerFailure) -> Self {
        Self {
            failure,
            cleanup_ticket: None,
        }
    }
}
impl std::fmt::Display for CountPrepareFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.failure.fmt(f)
    }
}
impl std::error::Error for CountPrepareFailure {}

pub struct CountInput {
    pub object_bytes: Arc<[u8]>,
    pub object_sha256: [u8; 32],
    pub target_tgid: u32,
    pub fork_barrier: Arc<CountForkBarrier>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CountMapDimensions {
    pub name: &'static str,
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub flags: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CountDimensions {
    pub maps: [CountMapDimensions; 7],
    pub root: &'static str,
}
impl CountDimensions {
    pub(crate) fn validated() -> Self {
        Self {
            maps: crate::loader::COUNT_MAPS.map(|m| CountMapDimensions {
                name: m.name,
                map_type: m.map_type,
                key_size: m.key_size,
                value_size: m.value_size,
                max_entries: m.max_entries,
                flags: m.flags,
            }),
            root: "count_entry",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ready {
    pub owner_epoch: OwnerEpoch,
    pub writer_object_identity: [u8; 32],
    pub dimensions: CountDimensions,
    pub evidence_domain: EvidenceDomain,
}

#[derive(Debug, Clone, Copy)]
pub struct CountOwnerLimits {
    pub(crate) link_slots: usize,
    pub(crate) pin_slots: usize,
    pub(crate) membership_slots: usize,
    pub(crate) raw_rows: usize,
    pub(crate) transient_slots: usize,
    pub(crate) fd_reservation: u64,
    pub(crate) possible_cpus: usize,
    pub(crate) cpu_scratch_bytes: usize,
}
impl CountOwnerLimits {
    pub fn from_allowance(allowance: u64, possible_cpus: usize) -> Result<Self, OwnerFailure> {
        let fail = || OwnerFailure::engine(CountOperation::Load, FailureClass::Capacity);
        if allowance < 18 || possible_cpus == 0 {
            return Err(fail());
        }
        let link_slots = allowance
            .checked_sub(16)
            .ok_or_else(fail)?
            .checked_div(2)
            .ok_or_else(fail)?
            .min(8192) as usize;
        let fd_reservation = (link_slots as u64)
            .checked_mul(2)
            .and_then(|n| n.checked_add(16))
            .ok_or_else(fail)?;
        let cpu_scratch_bytes = possible_cpus
            .checked_mul(24)
            .filter(|n| *n <= isize::MAX as usize)
            .ok_or_else(fail)?;
        Ok(Self {
            link_slots,
            pin_slots: link_slots,
            membership_slots: 8192,
            raw_rows: 8192,
            transient_slots: 8,
            fd_reservation,
            possible_cpus,
            cpu_scratch_bytes,
        })
    }
    pub fn link_slots(&self) -> usize {
        self.link_slots
    }
    pub fn reserved_fds(&self) -> u64 {
        self.fd_reservation
    }
    pub fn possible_cpus(&self) -> usize {
        self.possible_cpus
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceState {
    Unused,
    Reserved,
    Creating,
    Held,
    CreateFailed,
    CloseIssued,
    CloseReturned,
    ConsumedError,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceRecord {
    pub resource: ResourceId,
    pub state: ResourceState,
    pub errno: Option<i32>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceSummary {
    pub resources: Vec<ResourceRecord>,
    pub sealed: bool,
    pub cleanup_complete: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerPhase {
    Preparing,
    Ready,
    Observing,
    Sealing,
    Closing,
    Snapshotting,
    Result,
    Cleaning,
    Idle,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkBlocked {
    Deadline,
    ActiveEpoch,
    PrefixAfterEpoch,
    Unresolved,
    IdExhausted,
}

// Independent counters never wrap or reset an unresolved epoch. Future command
// handlers use the same allocator rather than minting identities from FD values.
#[derive(Default)]
pub(super) struct IdCounter {
    last: u64,
}
impl IdCounter {
    pub(super) fn next(&mut self) -> Result<u64, OwnerFailure> {
        let next = self
            .last
            .checked_add(1)
            .ok_or_else(|| OwnerFailure::engine(CountOperation::Load, FailureClass::IdExhausted))?;
        self.last = next;
        Ok(next)
    }
    #[cfg(test)]
    pub(super) fn with_last(last: u64) -> Self {
        Self { last }
    }
}
