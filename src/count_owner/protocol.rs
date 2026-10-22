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

#[derive(Debug)]
pub struct AttachRequest {
    pub seq: CommandSeq,
    pub deadline: std::time::Instant,
    pub expected_backing: BackingIdentity,
    pub locator: String,
    pub offsets: Vec<u64>,
    pub cookies: Vec<u64>,
}
impl AttachRequest {
    pub(super) fn validate(&self) -> Result<(), OwnerFailure> {
        if self.offsets.is_empty()
            || self.offsets.len() > 8192
            || self.offsets.len() != self.cookies.len()
            || self.locator.is_empty()
            || self.locator.len() > 4095
            || self.locator.as_bytes().contains(&0)
        {
            return Err(OwnerFailure::engine(
                CountOperation::Attach,
                FailureClass::InvalidInput,
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachRefusalReason {
    Unreadable,
    Replaced,
    KernelRefused,
    Capacity,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachRefusal {
    pub position: usize,
    pub reason: AttachRefusalReason,
}
#[derive(Debug)]
pub struct AttachAck<Link> {
    pub links: Vec<Link>,
    pub refused: Vec<AttachRefusal>,
}
#[derive(Debug)]
pub struct CommandAck<T> {
    pub seq: CommandSeq,
    pub value: T,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandCompletion {
    NotEntered,
    Completed,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandFailure {
    pub seq: CommandSeq,
    pub failure: OwnerFailure,
    pub completion: CommandCompletion,
    pub cleanup_ticket: Option<CleanupTicket>,
}
impl CommandFailure {
    /// Projection is outside bounded owner state and is consumed by the session.
    pub fn capacity_loss(&self) -> Option<crate::evidence::GapCounter> {
        (self.failure.class == FailureClass::Capacity).then(|| crate::evidence::GapCounter {
            name: "count.owner_capacity".into(),
            kind: crate::evidence::CounterKind::Loss,
            units: crate::evidence::CounterUnits::Events,
            source: crate::evidence::CounterSource::Attach,
            value: 1,
        })
    }
}
pub type CommandResult<T> = Result<CommandAck<T>, CommandFailure>;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingCommandId {
    pub seq: CommandSeq,
    pub operation: CountOperation,
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ControllerFrontier {
    pub last_acked: Option<CommandSeq>,
    pub acknowledged_links: Vec<LinkId>,
    pub pending: Option<PendingCommandId>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriterIdentity {
    pub owner_epoch: OwnerEpoch,
    pub object_sha256: [u8; 32],
    // Epoch + named registry slot uniquely identifies each actual tracked load;
    // no link/map census or descriptor alias is needed to inspect identity.
    pub program: ResourceId,
    pub maps: [ResourceId; 7],
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachedMembership {
    pub offset: u64,
    pub cookie: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateOutcome {
    Creating,
    Succeeded,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationState {
    Unpublished,
    Published,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreationRecord {
    pub id: LinkId,
    pub command: CommandSeq,
    pub writer: WriterIdentity,
    pub backing: BackingIdentity,
    pub pin_slot: usize,
    /// Exact range in SealedInventory::memberships (one epoch-wide bounded pool).
    pub memberships: std::ops::Range<usize>,
    pub outcome: CreateOutcome,
    pub publication: PublicationState,
    pub close_state: ResourceState,
    pub close_errno: Option<i32>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryFailure {
    Duplicate,
    Missing,
    Frontier,
    Unresolved,
    Membership,
    AlreadySealed,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedInventory {
    pub owner_epoch: OwnerEpoch,
    pub writer: WriterIdentity,
    pub records: Vec<CreationRecord>,
    pub memberships: Vec<AttachedMembership>,
    pub acknowledged_links: Vec<LinkId>,
    pub unpublished_links: Vec<LinkId>,
    pub last_acked: Option<CommandSeq>,
    pub pending: Option<PendingCommandId>,
}
impl SealedInventory {
    pub fn validate(&self, frontier: &ControllerFrontier) -> Result<(), InventoryFailure> {
        if self.last_acked != frontier.last_acked || self.pending != frontier.pending {
            return Err(InventoryFailure::Frontier);
        }
        if self.records.len() > 8192
            || self.memberships.len() > 8192
            || self.acknowledged_links.len() > 8192
            || self.unpublished_links.len() > 8192
            || frontier.acknowledged_links.len() > 8192
        {
            return Err(InventoryFailure::Frontier);
        }
        for (i, id) in frontier.acknowledged_links.iter().enumerate() {
            if frontier.acknowledged_links[..i].contains(id) {
                return Err(InventoryFailure::Duplicate);
            }
            if !self.acknowledged_links.contains(id) {
                return Err(InventoryFailure::Missing);
            }
        }
        if self.acknowledged_links.len() != frontier.acknowledged_links.len()
            || self.records.len() != self.acknowledged_links.len() + self.unpublished_links.len()
            || self.records.len() > 8192
            || self.memberships.len() > 8192
        {
            return Err(InventoryFailure::Missing);
        }
        let mut end = 0;
        for (i, record) in self.records.iter().enumerate() {
            if record.id.owner_epoch != self.owner_epoch
                || record.writer.owner_epoch != self.owner_epoch
                || record.writer != self.writer
                || record.outcome != CreateOutcome::Succeeded
            {
                return Err(InventoryFailure::Unresolved);
            }
            if self.records[..i].iter().any(|r| r.id == record.id) {
                return Err(InventoryFailure::Duplicate);
            }
            if i > 0 && self.records[i - 1].id.serial >= record.id.serial {
                return Err(InventoryFailure::Frontier);
            }
            if record.memberships.start != end
                || record.memberships.end <= end
                || record.memberships.end > self.memberships.len()
            {
                return Err(InventoryFailure::Membership);
            }
            end = record.memberships.end;
            let acknowledged = self
                .acknowledged_links
                .iter()
                .filter(|id| **id == record.id)
                .count();
            let unpublished = self
                .unpublished_links
                .iter()
                .filter(|id| **id == record.id)
                .count();
            if acknowledged + unpublished != 1 {
                return Err(InventoryFailure::Missing);
            }
            if acknowledged == 1 {
                if record.publication != PublicationState::Published
                    || self.last_acked.is_none_or(|seq| record.command > seq)
                {
                    return Err(InventoryFailure::Frontier);
                }
            } else if self.pending
                != Some(PendingCommandId {
                    seq: record.command,
                    operation: CountOperation::Attach,
                })
            {
                return Err(InventoryFailure::Frontier);
            }
        }
        if end != self.memberships.len() {
            return Err(InventoryFailure::Membership);
        }
        Ok(())
    }
}
impl LinkToken {
    pub(super) fn new(id: LinkId) -> Self {
        Self { id }
    }
}
