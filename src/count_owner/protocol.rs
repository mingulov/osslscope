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
            pub(crate) fn checked(value: u64) -> Result<Self, OwnerFailure> {
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
    Cancelled,
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
    pub(super) fn validate_possible_cpus(&self, actual: usize) -> Result<(), OwnerFailure> {
        if actual == 0
            || actual != self.possible_cpus
            || actual.checked_mul(24) != Some(self.cpu_scratch_bytes)
        {
            return Err(OwnerFailure::engine(
                CountOperation::Load,
                FailureClass::InvalidInput,
            ));
        }
        Ok(())
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
/// Eventual custody diagnostics are separate from the immutable capture view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupStatus {
    Pending,
    Complete,
    Failed,
    Stranded,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupProgress {
    pub ticket: CleanupTicket,
    pub actual_phase: OwnerPhase,
    pub active_operation: Option<CountOperation>,
    pub coordinator_finalized: bool,
    pub status: CleanupStatus,
    pub unresolved_resources: usize,
    pub failures: TerminalFailures,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkBlocked {
    SetupReserved,
    PrefixClosed,
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
/// Publication is independent of whether the handler entered any I/O. A
/// rejected command may carry an existing cleanup ticket without publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandPublication {
    NotPublished,
    Published,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandFailure {
    pub seq: CommandSeq,
    pub failure: OwnerFailure,
    pub completion: CommandCompletion,
    pub publication: CommandPublication,
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

#[derive(Debug, Clone, Copy)]
pub struct OpenRequest {
    pub seq: CommandSeq,
    pub deadline: std::time::Instant,
    pub tgid: u64,
    pub generation: u32,
    pub start_ns: u64,
    pub deadline_ns: u64,
}
#[derive(Debug, Clone, Copy)]
pub struct GenerationRequest {
    pub seq: CommandSeq,
    pub deadline: std::time::Instant,
    pub generation: u32,
}
#[derive(Debug, Clone, Copy)]
pub struct ReadRequest {
    pub seq: CommandSeq,
    pub deadline: std::time::Instant,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenWriteFrontier {
    NoWrites,
    WindowStart,
    WindowDeadline,
    Generation,
    Target,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenOutcome {
    Completed,
    Failed,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenReceipt {
    pub owner_epoch: OwnerEpoch,
    pub seq: CommandSeq,
    pub tgid: u64,
    pub generation: u32,
    pub start_ns: u64,
    pub deadline_ns: u64,
    pub completed_writes: OpenWriteFrontier,
    pub outcome: OpenOutcome,
}
/// Constructed only by checking the complete actual receipt against the pending
/// request. Its fields cannot be populated from a display interval or sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgrammedAdmission {
    owner_epoch: OwnerEpoch,
    open_seq: CommandSeq,
    tgid: u64,
    generation: u32,
    start_ns: u64,
    deadline_ns: u64,
}
impl OpenReceipt {
    pub(super) fn pending(owner_epoch: OwnerEpoch, request: &OpenRequest) -> Self {
        Self {
            owner_epoch,
            seq: request.seq,
            tgid: request.tgid,
            generation: request.generation,
            start_ns: request.start_ns,
            deadline_ns: request.deadline_ns,
            completed_writes: OpenWriteFrontier::NoWrites,
            outcome: OpenOutcome::Unknown,
        }
    }
    pub fn programmed_admission(
        self,
        owner_epoch: OwnerEpoch,
        request: &OpenRequest,
    ) -> Result<ProgrammedAdmission, OwnerFailure> {
        if self.owner_epoch != owner_epoch
            || self.seq != request.seq
            || self.tgid != request.tgid
            || self.generation != request.generation
            || self.start_ns != request.start_ns
            || self.deadline_ns != request.deadline_ns
            || self.start_ns >= self.deadline_ns
            || self.tgid == 0
            || self.completed_writes != OpenWriteFrontier::Target
            || self.outcome != OpenOutcome::Completed
        {
            return Err(OwnerFailure::engine(
                CountOperation::Open,
                FailureClass::Inventory,
            ));
        }
        Ok(ProgrammedAdmission {
            owner_epoch,
            open_seq: self.seq,
            tgid: self.tgid,
            generation: self.generation,
            start_ns: self.start_ns,
            deadline_ns: self.deadline_ns,
        })
    }
}
impl ProgrammedAdmission {
    pub fn owner_epoch(self) -> OwnerEpoch {
        self.owner_epoch
    }
    pub fn open_seq(self) -> CommandSeq {
        self.open_seq
    }
    pub fn tgid(self) -> u64 {
        self.tgid
    }
    pub fn generation(self) -> u32 {
        self.generation
    }
    pub fn start_ns(self) -> u64 {
        self.start_ns
    }
    pub fn deadline_ns(self) -> u64 {
        self.deadline_ns
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComponentFailure {
    pub map: CountMap,
    pub key: u32,
    pub operation: CountOperation,
    /// None means no value has returned yet, without inventing a syscall error.
    pub class: Option<FailureClass>,
    pub errno: Option<i32>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Component<T> {
    Available(T),
    Unavailable(ComponentFailure),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnumerationStatus {
    Complete { unread_keys: u64 },
    Unfinished,
}
#[derive(Debug, PartialEq, Eq)]
pub struct RawSnapshot {
    pub sequence: SnapshotSeq,
    pub rows: Vec<(u64, osslscope_ebpf_common::CountValue)>,
    pub admitted: Component<u64>,
    pub dropfail: Component<u64>,
    pub latc: [Component<u64>; 16],
    pub enumeration: EnumerationStatus,
}
#[derive(Debug, Clone)]
pub struct RawCheckpoint {
    pub snapshot: Arc<RawSnapshot>,
    pub phase: OwnerPhase,
    pub published_at: std::time::Instant,
}
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
    pub last_completed: Option<PendingCommandId>,
    pub resolved_open: Option<OpenReceipt>,
}
impl SealedInventory {
    pub fn validate(&self, frontier: &ControllerFrontier) -> Result<(), InventoryFailure> {
        if self.last_acked != frontier.last_acked || self.pending != frontier.pending {
            return Err(InventoryFailure::Frontier);
        }
        match self.last_completed {
            None if self.last_acked.is_some() => return Err(InventoryFailure::Frontier),
            Some(completed)
                if Some(completed.seq) != self.last_acked && Some(completed) != self.pending =>
            {
                return Err(InventoryFailure::Frontier);
            }
            _ => {}
        }
        if self
            .pending
            .is_some_and(|pending| self.last_acked.is_some_and(|acked| pending.seq <= acked))
        {
            return Err(InventoryFailure::Frontier);
        }
        if let Some(completed) = self.last_completed {
            if self
                .pending
                .is_some_and(|pending| pending.seq == completed.seq && pending != completed)
            {
                return Err(InventoryFailure::Frontier);
            }
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
            let members = &self.memberships[record.memberships.clone()];
            for (index, member) in members.iter().enumerate() {
                if index > 0 && members[index - 1].offset >= member.offset {
                    return Err(InventoryFailure::Membership);
                }
                if self.records[..i].iter().any(|prior| {
                    prior.backing == record.backing
                        && self.memberships[prior.memberships.clone()]
                            .iter()
                            .any(|m| m.offset == member.offset)
                }) {
                    return Err(InventoryFailure::Membership);
                }
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
    pub(crate) fn new(id: LinkId) -> Self {
        Self { id }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalRequest {
    pub id: TerminalId,
    pub deadline: std::time::Instant,
    pub evidence_domain: EvidenceDomain,
    pub writer_object_identity: [u8; 32],
    pub frontier: ControllerFrontier,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopResult {
    NotAttempted,
    Stopped,
    Failed(OwnerFailure),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealBracket {
    pub before_ns: Option<u64>,
    pub after_ns: Option<u64>,
    pub result: StopResult,
}
impl Default for SealBracket {
    fn default() -> Self {
        Self {
            before_ns: None,
            after_ns: None,
            result: StopResult::NotAttempted,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileFailure {
    UnboundBuild,
    UnknownVendor,
    SourceMismatch,
}
/// Source tags describe the theorem's source families, never uname prefixes or
/// permission to classify a running build as reviewed.
pub const SOURCE_THEOREM_PINS: [(&str, &str); 4] = [
    ("v6.9", "a38297e3fb012ddfa7ce0321a7e5a8daeb1872b6"),
    ("v6.12", "adc218676eef25575469234709c2d87185ca223a"),
    ("v6.18", "7d0a66e4bb9081d75c82ec4957c50034cb0ea449"),
    ("v7.0", "028ef9c96e96197026887c0f092424679298aae8"),
];
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KernelBuildIdentity {
    pub build_sha256: Option<[u8; 32]>,
    pub config_sha256: Option<[u8; 32]>,
    pub vendor_source_sha256: Option<[u8; 32]>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReviewedKernelProfile {
    source_family: usize,
    build: KernelBuildIdentity,
    domain: EvidenceDomain,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelApplicability {
    Unknown(ProfileFailure),
    Reviewed(ReviewedKernelProfile),
    ModelFixture,
}
pub fn resolve_kernel_applicability(_identity: &KernelBuildIdentity) -> KernelApplicability {
    // Enabling a live constructor requires separately reviewed exact build,
    // config, vendor/backport, raw-close lowering and callback-path bindings.
    KernelApplicability::Unknown(ProfileFailure::UnboundBuild)
}
impl KernelApplicability {
    pub(super) fn applicable(self, domain: EvidenceDomain) -> bool {
        match self {
            Self::Reviewed(p) => {
                p.domain == domain
                    && p.source_family < SOURCE_THEOREM_PINS.len()
                    && p.build.build_sha256.is_some()
                    && p.build.config_sha256.is_some()
                    && p.build.vendor_source_sha256.is_some()
            }
            Self::ModelFixture => domain == EvidenceDomain::HostModel,
            Self::Unknown(_) => false,
        }
    }
    #[cfg(test)]
    pub(super) fn reviewed_fixture(source_family: usize) -> Self {
        Self::Reviewed(ReviewedKernelProfile {
            source_family,
            build: KernelBuildIdentity {
                build_sha256: Some([1; 32]),
                config_sha256: Some([2; 32]),
                vendor_source_sha256: Some([3; 32]),
            },
            domain: EvidenceDomain::HostModel,
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReferenceFinality {
    pub file: bool,
    pub bpf_link: bool,
}
impl ReferenceFinality {
    pub(super) fn final_owned() -> Self {
        Self {
            file: true,
            bpf_link: true,
        }
    }
    fn is_final(self) -> bool {
        self.file && self.bpf_link
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuiescenceReason {
    Deadline,
    Inventory,
    Stop,
    Close,
    References,
    Profile,
    ObjectDrift,
    Owner,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriterWitness {
    pub owner_epoch: OwnerEpoch,
    pub terminal_id: TerminalId,
    pub last_command_seq: Option<CommandSeq>,
    pub writer_object_identity: [u8; 32],
    pub established_at: std::time::Instant,
}
/// The owner publishes this only at pristine Ready, before any ordinary
/// command can be admitted. Submission permanently withdraws that authority.
#[derive(Debug, Clone, Copy)]
pub(super) struct EmptyFamily {
    pub writer: WriterIdentity,
    pub published_at: std::time::Instant,
}
/// Vacuous no-writer/no-observation proof. This is neither a map read nor a
/// source-profile authorization, and it cannot supply Available(0) components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmptyWitness {
    pub owner_epoch: OwnerEpoch,
    pub terminal_id: TerminalId,
    pub writer_object_identity: [u8; 32],
    pub ready_published_at: std::time::Instant,
    pub sealed_at: std::time::Instant,
    pub deadline: std::time::Instant,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterCompletion {
    Finished(WriterWitness),
    KnownEmpty(EmptyWitness),
    Unknown(QuiescenceReason),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkCloseOutcome {
    pub id: LinkId,
    pub issued_at: Option<std::time::Instant>,
    pub returned_at: Option<std::time::Instant>,
    pub state: ResourceState,
    pub errno: Option<i32>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotBinding {
    pub sequence: SnapshotSeq,
    pub started_at: std::time::Instant,
    pub completed_at: std::time::Instant,
    pub immutable: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadStatus {
    NotStarted,
    Complete,
    Incomplete { enumeration: EnumerationStatus },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupState {
    Pending(ResourceSummary),
    Complete,
    Failed(ResourceSummary),
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TerminalFailures {
    pub operations: [Option<OwnerFailure>; 10],
    pub components: [Option<ComponentFailure>; 18],
    operation_times: [Option<std::time::Instant>; 10],
    component_times: [Option<std::time::Instant>; 18],
}
impl TerminalFailures {
    // Pure bounded-data selection, shared with pending setup diagnostics.
    pub(crate) fn independent_failure(&self) -> Option<OwnerFailure> {
        let independent =
            |f: &OwnerFailure| !matches!(f.class, FailureClass::Cancelled | FailureClass::Deadline);
        self.operations
            .iter()
            .flatten()
            .copied()
            .find(independent)
            .or_else(|| {
                self.components.iter().flatten().find_map(|f| {
                    let owner = OwnerFailure {
                        operation: f.operation,
                        resource: ResourceId::Map(f.map),
                        class: f.class?,
                        errno: f.errno,
                    };
                    independent(&owner).then_some(owner)
                })
            })
    }
    pub(super) fn record_component(&mut self, failure: ComponentFailure) {
        self.record_component_at(failure, std::time::Instant::now());
    }
    pub(super) fn record_component_at(
        &mut self,
        failure: ComponentFailure,
        at: std::time::Instant,
    ) {
        let index = match (failure.map, failure.key) {
            (CountMap::Admitted, 0) => 0,
            (CountMap::Dropfail, 0) => 1,
            (CountMap::Latc, key) if key < 16 => key as usize + 2,
            _ => return,
        };
        if self.components[index].is_none_or(|old| old.class.is_none()) {
            self.components[index] = Some(failure);
            self.component_times[index] = Some(at);
        }
    }
    pub(super) fn record(&mut self, failure: OwnerFailure) {
        self.record_at(failure, std::time::Instant::now());
    }
    pub(super) fn record_at(&mut self, failure: OwnerFailure, at: std::time::Instant) {
        let index = failure.operation as usize;
        let cell = &mut self.operations[index];
        // A prior uncertainty must not mask an actual returned runtime error.
        if cell.is_none_or(|old| {
            matches!(
                old.class,
                FailureClass::Deadline | FailureClass::Disconnected
            ) && !matches!(
                failure.class,
                FailureClass::Deadline | FailureClass::Disconnected
            )
        }) {
            *cell = Some(failure);
            self.operation_times[index] = Some(at);
        }
    }
    pub(super) fn before(self, cutoff: std::time::Instant) -> Self {
        let mut result = Self::default();
        for index in 0..10 {
            if self.operation_times[index].is_some_and(|at| at < cutoff) {
                result.operations[index] = self.operations[index];
                result.operation_times[index] = self.operation_times[index];
            }
        }
        for index in 0..18 {
            if self.component_times[index].is_some_and(|at| at < cutoff) {
                result.components[index] = self.components[index];
                result.component_times[index] = self.component_times[index];
            }
        }
        result
    }
    pub(super) fn merge(&mut self, other: Self) {
        for index in 0..10 {
            if let Some((failure, at)) = other.operations[index].zip(other.operation_times[index]) {
                self.record_at(failure, at);
            }
        }
        for index in 0..18 {
            if let Some((failure, at)) = other.components[index].zip(other.component_times[index]) {
                self.record_component_at(failure, at);
            }
        }
    }
}
/// Both metadata envelopes and their vector capacities exist before count FD
/// acquisition. Published views share immutable metadata, never clone vectors.
#[derive(Debug)]
pub struct RawTerminalData {
    pub owner_epoch: OwnerEpoch,
    pub terminal_id: TerminalId,
    pub deadline: std::time::Instant,
    pub last_command_seq: Option<CommandSeq>,
    pub resolved_open: Option<OpenReceipt>,
    pub evidence_domain: EvidenceDomain,
    pub inventory: Option<Arc<SealedInventory>>,
    pub manifest: Vec<CreationRecord>,
    pub close_outcomes: Vec<LinkCloseOutcome>,
    pub kernel_profile: KernelApplicability,
    pub writer_object_identity: [u8; 32],
    pub writer_family: CountDimensions,
    pub host_writes_sealed: bool,
    pub final_references: ReferenceFinality,
    pub seal: SealBracket,
    pub writers: WriterCompletion,
    pub checkpoint: Option<RawCheckpoint>,
    pub snapshot_binding: Option<SnapshotBinding>,
    pub read_status: ReadStatus,
    pub cleanup_ticket: CleanupTicket,
    pub cleanup_state: CleanupState,
    pub failures: TerminalFailures,
}
#[derive(Debug, Clone)]
pub struct RawTerminal(pub(super) Arc<RawTerminalData>);
impl RawTerminal {
    /// Data-only construction for the in-process fixture backend. Never grants
    /// a Live profile or lets an integration wrapper manufacture a receipt.
    pub(crate) fn model(data: Arc<RawTerminalData>) -> Self {
        assert_eq!(data.evidence_domain, EvidenceDomain::HostModel);
        assert!(matches!(
            data.kernel_profile,
            KernelApplicability::ModelFixture | KernelApplicability::Unknown(_)
        ));
        Self(data)
    }
}
impl std::ops::Deref for RawTerminal {
    type Target = RawTerminalData;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptFailure {
    Identity,
    Frontier,
    Inventory,
    Writer,
    Stop,
    Close,
    Snapshot,
    Cutoff,
    Cleanup,
}

pub fn validate_terminal(
    expected: &TerminalRequest,
    receipt: &RawTerminal,
) -> Result<(), ReceiptFailure> {
    use ReceiptFailure as F;
    if receipt.owner_epoch != expected.id.owner_epoch
        || receipt.terminal_id != expected.id
        || receipt.deadline != expected.deadline
        || receipt.evidence_domain != expected.evidence_domain
        || receipt.cleanup_ticket
            != (CleanupTicket {
                owner_epoch: expected.id.owner_epoch,
                terminal_id: expected.id,
            })
        || receipt.writer_object_identity != expected.writer_object_identity
    {
        return Err(F::Identity);
    }
    if receipt.last_command_seq != expected.frontier.last_acked
        && receipt.last_command_seq != expected.frontier.pending.map(|p| p.seq)
    {
        return Err(F::Frontier);
    }
    if let Some(pending) = expected.frontier.pending {
        if expected
            .frontier
            .last_acked
            .is_some_and(|seq| seq >= pending.seq)
        {
            return Err(F::Frontier);
        }
    }
    if let WriterCompletion::KnownEmpty(witness) = receipt.writers {
        if witness.owner_epoch != receipt.owner_epoch
            || witness.terminal_id != receipt.terminal_id
            || witness.writer_object_identity != receipt.writer_object_identity
            || witness.deadline != receipt.deadline
            || witness.ready_published_at >= receipt.deadline
            || witness.ready_published_at > witness.sealed_at
            || !receipt.host_writes_sealed
            || receipt.writer_family != CountDimensions::validated()
            || expected.frontier != ControllerFrontier::default()
            || receipt.last_command_seq.is_some()
            || receipt.resolved_open.is_some()
            || !receipt.manifest.is_empty()
            || !receipt.close_outcomes.is_empty()
            || receipt.seal != SealBracket::default()
            || receipt.checkpoint.is_some()
            || receipt.snapshot_binding.is_some()
            || receipt.read_status != ReadStatus::NotStarted
            || receipt.failures != TerminalFailures::default()
        {
            return Err(F::Writer);
        }
        if let Some(inventory) = &receipt.inventory {
            inventory
                .validate(&expected.frontier)
                .map_err(|_| F::Inventory)?;
            if inventory.owner_epoch != receipt.owner_epoch
                || inventory.writer
                    != (WriterIdentity {
                        owner_epoch: receipt.owner_epoch,
                        object_sha256: receipt.writer_object_identity,
                        program: ResourceId::Program,
                        maps: CountMap::ALL.map(ResourceId::Map),
                    })
                || !inventory.records.is_empty()
                || !inventory.memberships.is_empty()
                || inventory.last_completed.is_some()
                || inventory.resolved_open.is_some()
            {
                return Err(F::Inventory);
            }
        }
        return Ok(());
    }
    let inventory = receipt.inventory.as_ref().ok_or(F::Inventory)?;
    inventory
        .validate(&expected.frontier)
        .map_err(|_| F::Inventory)?;
    if receipt.last_command_seq != inventory.last_completed.map(|p| p.seq)
        || receipt.resolved_open != inventory.resolved_open
    {
        return Err(F::Frontier);
    }
    validate_resolved_open(
        receipt.owner_epoch,
        receipt.resolved_open,
        inventory.last_completed,
        inventory.pending,
    )?;
    if inventory.owner_epoch != receipt.owner_epoch
        || inventory.writer.object_sha256 != expected.writer_object_identity
        || inventory.writer.program != ResourceId::Program
        || inventory.writer.maps != CountMap::ALL.map(ResourceId::Map)
        || receipt.manifest.len() != inventory.records.len()
        || receipt.close_outcomes.len() != inventory.records.len()
    {
        return Err(F::Inventory);
    }
    for ((record, created), close) in receipt
        .manifest
        .iter()
        .zip(&inventory.records)
        .zip(&receipt.close_outcomes)
    {
        if record.id != created.id
            || record.command != created.command
            || record.writer != created.writer
            || record.backing != created.backing
            || record.pin_slot != created.pin_slot
            || record.memberships != created.memberships
            || record.outcome != created.outcome
            || record.publication != created.publication
            || close.id != record.id
        {
            return Err(F::Inventory);
        }
    }
    if let WriterCompletion::Finished(witness) = receipt.writers {
        if witness.owner_epoch != receipt.owner_epoch
            || witness.terminal_id != receipt.terminal_id
            || witness.last_command_seq != receipt.last_command_seq
            || witness.writer_object_identity != receipt.writer_object_identity
            || !receipt.host_writes_sealed
            || !receipt.final_references.is_final()
            || !receipt.kernel_profile.applicable(expected.evidence_domain)
            || receipt.writer_family != CountDimensions::validated()
        {
            return Err(F::Writer);
        }
        match receipt.seal {
            SealBracket {
                before_ns: Some(before),
                after_ns: Some(after),
                result: StopResult::Stopped,
            } if before <= after => {}
            _ => return Err(F::Stop),
        }
        let mut previous_ack = None;
        for (record, close) in receipt.manifest.iter().zip(&receipt.close_outcomes) {
            if previous_ack.is_some_and(|ack| close.issued_at.is_none_or(|issued| issued < ack)) {
                return Err(F::Close);
            }
            if record.close_state != ResourceState::CloseReturned
                || record.close_errno.is_some()
                || close.state != ResourceState::CloseReturned
                || close.errno.is_some()
                || close
                    .issued_at
                    .zip(close.returned_at)
                    .is_none_or(|(issued, returned)| {
                        issued > returned || returned > witness.established_at
                    })
            {
                return Err(F::Close);
            }
            previous_ack = close.returned_at;
        }
        if witness.established_at >= receipt.deadline {
            return Err(F::Cutoff);
        }
    }
    if let Some(binding) = receipt.snapshot_binding {
        let checkpoint = receipt.checkpoint.as_ref().ok_or(F::Snapshot)?;
        if binding.sequence != checkpoint.snapshot.sequence
            || checkpoint.phase != OwnerPhase::Snapshotting
            || checkpoint.published_at != binding.completed_at
            || binding.started_at > binding.completed_at
            || binding.completed_at >= receipt.deadline
            || checkpoint.published_at >= receipt.deadline
        {
            return Err(F::Snapshot);
        }
        if matches!(receipt.writers, WriterCompletion::Finished(_)) && !binding.immutable {
            return Err(F::Snapshot);
        }
        if binding.immutable
            && !matches!(receipt.writers, WriterCompletion::Finished(w) if w.established_at <= binding.started_at)
        {
            return Err(F::Snapshot);
        }
        match receipt.read_status {
            ReadStatus::NotStarted => return Err(F::Snapshot),
            ReadStatus::Complete if !snapshot_complete(&checkpoint.snapshot) => {
                return Err(F::Snapshot);
            }
            ReadStatus::Incomplete { enumeration }
                if enumeration != checkpoint.snapshot.enumeration =>
            {
                return Err(F::Snapshot);
            }
            _ => {}
        }
    } else if receipt.read_status != ReadStatus::NotStarted {
        return Err(F::Snapshot);
    }
    if receipt.cleanup_state == CleanupState::Complete
        && receipt
            .close_outcomes
            .iter()
            .any(|c| c.state != ResourceState::CloseReturned)
    {
        return Err(F::Cleanup);
    }
    Ok(())
}
pub(super) fn snapshot_complete(snapshot: &RawSnapshot) -> bool {
    snapshot.enumeration == (EnumerationStatus::Complete { unread_keys: 0 })
        && matches!(snapshot.admitted, Component::Available(_))
        && matches!(snapshot.dropfail, Component::Available(_))
        && snapshot
            .latc
            .iter()
            .all(|c| matches!(c, Component::Available(_)))
}

fn validate_resolved_open(
    epoch: OwnerEpoch,
    resolved: Option<OpenReceipt>,
    completed: Option<PendingCommandId>,
    pending: Option<PendingCommandId>,
) -> Result<(), ReceiptFailure> {
    let Some(open) = resolved else {
        return Ok(());
    };
    if open.owner_epoch != epoch
        || pending.is_some_and(|p| p.seq == open.seq && p.operation != CountOperation::Open)
        || completed.is_some_and(|p| p.seq == open.seq && p.operation != CountOperation::Open)
    {
        return Err(ReceiptFailure::Frontier);
    }
    let covered = completed.is_some_and(|p| p.seq >= open.seq);
    let pending_open = pending
        == Some(PendingCommandId {
            seq: open.seq,
            operation: CountOperation::Open,
        });
    let valid = match open.outcome {
        OpenOutcome::Completed => covered && open.completed_writes == OpenWriteFrontier::Target,
        // A queued request can fail its first admission without any syscall,
        // leaving the earlier actual completed operation unchanged.
        OpenOutcome::Failed => {
            covered || (pending_open && open.completed_writes == OpenWriteFrontier::NoWrites)
        }
        // Partial acknowledgments before an unreturned call remain explicit;
        // they are not an admission interval or evidence of command completion.
        OpenOutcome::Unknown => covered || pending_open,
    };
    if valid {
        Ok(())
    } else {
        Err(ReceiptFailure::Frontier)
    }
}
