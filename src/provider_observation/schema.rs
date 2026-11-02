// SPDX-License-Identifier: GPL-3.0-or-later
use crate::inventory;
use serde::{Deserialize, Serialize};
use std::cell::{Cell, RefCell};
use std::rc::Rc;

/// Metadata origin does not change a physical counter's attribution certainty.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataOrigin {
    StaticPublicTableCandidate,
    ObservedPublicAbi,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationGap {
    ProcessUnavailable,
    ProcessChanged,
    NamespaceChanged,
    BackingUnavailable,
    IdentityUnverified,
    ObjectChanged,
    MalformedMaps,
    MalformedElf,
    UnsupportedArchitecture,
    SymbolUnavailable,
    AmbiguousSite,
    ProcessLimit,
    ObjectLimit,
    LinkLimit,
    PendingLimit,
    DepthLimit,
    SiteLimit,
    FactLimit,
    StateLimit,
    ReadLimit,
    QueueLoss,
    DrainOverrun,
    SnapshotLag,
    FirstQueryUnknown,
    IntervalUnknown,
    BpfUnavailable,
    CompanionsUnavailable,
    InvalidObject,
    InvalidWire,
    AttachFailed,
    ClassifierFailed,
    TargetReadFailed,
    UnpairedReturn,
    RelocationRefused,
    DispatchPartial,
    SamplingPartial,
    MembershipUnknown,
    RegistrationRace,
    Invalidated,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationLimits {
    pub max_processes: usize,
    pub max_objects: usize,
    pub max_links: usize,
    pub max_pending_calls: usize,
    pub max_depth: usize,
    pub max_learned_sites: usize,
    pub max_facts: usize,
    pub ring_bytes: usize,
    pub max_state_bytes: usize,
    pub max_elf_read_bytes: u64,
}
impl Default for ObservationLimits {
    fn default() -> Self {
        Self {
            max_processes: 64,
            max_objects: 256,
            max_links: 1024,
            max_pending_calls: 4096,
            max_depth: 8,
            max_learned_sites: 4096,
            max_facts: 16384,
            ring_bytes: 1048576,
            // Funds the documented two-mode spawn observation: session
            // setup (~8M) + legacy startup (~4M) + typed-source retention
            // (~31M: source maps/iterator capacity plus full-file anchors,
            // retained even under a disabled native lease so the focused
            // counter can borrow the producer/source maps) + a full legacy
            // attach (~28M, full-file anchors per mapped object plus
            // per-site roles/links). Measured together at ~71M; the
            // legacy-era 64M ceiling starved every spawn-path attach with
            // a deterministic StateLimit and zero operational rows. The
            // model is conservative capacity (kernel map sizes, full-file
            // anchors), not host RSS; pathological single objects still
            // refuse. Native fit pins track this default, never a literal.
            max_state_bytes: 96 << 20,
            max_elf_read_bytes: 268435456,
        }
    }
}
#[derive(Default)]
struct Work {
    processes: usize,
    objects: usize,
    state: usize,
    /// State bytes currently held by live [`StateReservation`] guards.
    /// Invariant: `reserved <= state`. Retire-time release must preserve
    /// these bytes: dropping a guard subtracts from `state`, so lowering
    /// `state` below live reservations would underflow on drop.
    reserved: usize,
    reads: u64,
}
// A failed acquisition owns no retained state. Its provisional admissions can
// be released; descriptor reads remain cumulative even when acquisition fails.
pub(crate) struct ProcessAdmission {
    work: Rc<RefCell<Work>>,
    provisional: Option<(usize, usize)>,
}
impl ProcessAdmission {
    pub(crate) fn retain(&mut self) {
        self.provisional = None;
    }
}
impl Drop for ProcessAdmission {
    fn drop(&mut self) {
        let mut work = self.work.borrow_mut();
        work.processes -= 1;
        if let Some((objects, state)) = self.provisional {
            work.objects = objects;
            work.state = state;
        }
    }
}
pub(crate) struct StateReservation {
    work: Rc<RefCell<Work>>,
    bytes: usize,
}
impl StateReservation {
    pub(crate) fn retain(mut self) {
        let bytes = std::mem::replace(&mut self.bytes, 0);
        // Retained bytes stay in `state` permanently but leave the
        // reserved set: the guard will no longer subtract them on drop.
        let mut work = self.work.borrow_mut();
        debug_assert!(bytes <= work.reserved, "retain exceeds live reservations");
        work.reserved = work.reserved.saturating_sub(bytes);
    }
    /// Test-only shared-spent readback through the retained
    /// reservation, so lifetime controls can observe the charge
    /// after the originating budget owner is gone.
    #[cfg(test)]
    pub(crate) fn spent_test(&self) -> usize {
        self.work.borrow().state
    }
}
impl Drop for StateReservation {
    fn drop(&mut self) {
        let mut work = self.work.borrow_mut();
        debug_assert!(
            self.bytes <= work.reserved && self.bytes <= work.state,
            "reservation drop exceeds accounted spend"
        );
        work.reserved = work.reserved.saturating_sub(self.bytes);
        work.state = work.state.saturating_sub(self.bytes);
    }
}
/// Clones share cumulative admission, including lazy relocation work.
#[derive(Clone)]
pub struct ObservationBudget {
    pub limits: ObservationLimits,
    work: Rc<RefCell<Work>>,
    deadline: Rc<Cell<Option<std::time::Instant>>>,
    pub(crate) memory: Option<crate::observation_memory::MemoryPool>,
    /// Shaped backing-refusal strings recorded during acquisition (R06
    /// vocabulary, caller-rendered). Shared across budget clones like
    /// the work ledger; the session drains it once per reconcile so a
    /// refusal surfaces on the batch it belongs to. A set: repeats of
    /// the same refusal (one per mapping) collapse here, and past the
    /// cap further refusals drop (the gap counts stay exact).
    refusals: Rc<RefCell<std::collections::BTreeSet<String>>>,
}
impl Default for ObservationBudget {
    fn default() -> Self {
        Self::new(ObservationLimits::default())
    }
}
impl ObservationBudget {
    pub fn new(limits: ObservationLimits) -> Self {
        Self {
            limits,
            work: Rc::default(),
            deadline: Rc::default(),
            memory: None,
            refusals: Rc::default(),
        }
    }
    /// Stash one caller-rendered refusal string for the session drain.
    pub(crate) fn record_refusal(&self, refusal: String) {
        const CAP: usize = 64;
        let mut refusals = self.refusals.borrow_mut();
        if refusals.len() < CAP {
            refusals.insert(refusal);
        }
    }
    /// Take the refusals recorded since the last drain.
    pub(crate) fn take_refusals(&self) -> Vec<String> {
        std::mem::take(&mut *self.refusals.borrow_mut())
            .into_iter()
            .collect()
    }
    pub(crate) fn set_deadline(&self, deadline: std::time::Instant) {
        self.deadline.set(Some(deadline));
    }
    pub(crate) fn checkpoint(&self) -> Result<(), ObservationGap> {
        if self
            .deadline
            .get()
            .is_some_and(|d| std::time::Instant::now() >= d)
        {
            Err(ObservationGap::SnapshotLag)
        } else {
            Ok(())
        }
    }
    pub fn elf_read_bytes(&self) -> u64 {
        self.work.borrow().reads
    }
    pub(crate) fn read(&self, bytes: u64) -> Result<(), ObservationGap> {
        self.checkpoint()?;
        let mut work = self.work.borrow_mut();
        let next = work
            .reads
            .checked_add(bytes)
            .ok_or(ObservationGap::ReadLimit)?;
        if next > self.limits.max_elf_read_bytes {
            return Err(ObservationGap::ReadLimit);
        }
        work.reads = next;
        Ok(())
    }
    pub(crate) fn process(&self) -> Result<ProcessAdmission, ObservationGap> {
        self.checkpoint()?;
        let mut work = self.work.borrow_mut();
        if work.processes >= self.limits.max_processes {
            return Err(ObservationGap::ProcessLimit);
        }
        work.processes += 1;
        Ok(ProcessAdmission {
            work: self.work.clone(),
            provisional: Some((work.objects, work.state)),
        })
    }
    pub(crate) fn object(&self) -> Result<(), ObservationGap> {
        self.checkpoint()?;
        let mut work = self.work.borrow_mut();
        if work.objects >= self.limits.max_objects {
            return Err(ObservationGap::ObjectLimit);
        }
        work.objects += 1;
        Ok(())
    }
    pub(crate) fn reserve_state(&self, bytes: usize) -> Result<StateReservation, ObservationGap> {
        self.state(bytes)?;
        let mut work = self.work.borrow_mut();
        work.reserved = work.reserved.saturating_add(bytes);
        Ok(StateReservation {
            work: self.work.clone(),
            bytes,
        })
    }
    pub(crate) fn state(&self, bytes: usize) -> Result<(), ObservationGap> {
        self.checkpoint()?;
        let mut work = self.work.borrow_mut();
        let next = work
            .state
            .checked_add(bytes)
            .ok_or(ObservationGap::StateLimit)?;
        if next > self.limits.max_state_bytes {
            return Err(ObservationGap::StateLimit);
        }
        work.state = next;
        Ok(())
    }
    /// Test-only reserved-bytes readback, so retire/release controls can
    /// distinguish standing setup leases from attach-time leaks.
    #[cfg(test)]
    pub(crate) fn reserved_test(&self) -> usize {
        self.work.borrow().reserved
    }
    /// Test-only spent-state readback, so small-budget controls can size an
    /// exact-fit versus one-byte-short budget through the real path.
    #[cfg(test)]
    pub(crate) fn state_spent_test(&self) -> usize {
        self.spent_state()
    }
    /// Current cumulative state spend (setup plus live acquisitions).
    pub(crate) fn spent_state(&self) -> usize {
        self.work.borrow().state
    }
    /// Current cumulative ELF-read spend.
    pub(crate) fn spent_reads(&self) -> u64 {
        self.work.borrow().reads
    }
    /// Release read spend back to a setup-time floor. Only moves
    /// downward. Reads are cumulative across failed acquisitions by
    /// design, but a retired live target's reads are dead spend like
    /// its state: without a release here, no post-retire re-add could
    /// ever re-parse its objects. Same guard as state release.
    pub(crate) fn release_reads_to_floor(&self, floor: u64) {
        let mut work = self.work.borrow_mut();
        work.reads = work.reads.min(floor);
    }
    /// Release acquisition spend back to a setup-time floor. Only moves
    /// downward: floors above current spend are a no-op. Live
    /// reservations are preserved: dropping a guard subtracts from
    /// `state`, so the floor keeps `floor + reserved` bytes. Callers
    /// must ensure no live attachment owns direct spend above the
    /// floor (retire releases only when nothing remains live).
    ///
    /// Known accounting hole (external review; cost-theme followup):
    /// the fully-idle guard cannot see owners outside targets/startup
    /// rows. Parsed objects retained by the focused counter's learned
    /// sites (direct spend via reservation conversion) stay live across
    /// the release, so a re-add re-spends what the release erased — up
    /// to one parse set per retire/re-add cycle (single-digit MB against
    /// a ~25MB margin; cycles are rare now that steady-state retires are
    /// eliminated). The principled fix is incarnation-scoped parse
    /// sharing, which also removes the re-acquisition re-parse cost.
    pub(crate) fn release_state_to_floor(&self, floor: usize) {
        let mut work = self.work.borrow_mut();
        if floor >= work.state {
            return; // nothing above the floor: no-op
        }
        let keep = floor.saturating_add(work.reserved);
        debug_assert!(keep <= work.state, "release floor exceeds accounted spend");
        work.state = work.state.min(keep);
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationApi {
    Inventoried(inventory::Api),
    Operational(crate::api_activity::ApiId),
    OsslProviderUnqueryOperation,
    ProviderQueryCallback,
    ProviderTeardownCallback,
    ProviderUnqueryCallback,
}
impl ObservationApi {
    pub(crate) fn startup_supported(self) -> bool {
        use inventory::Api::*;
        matches!(
            self,
            Self::Operational(_)
                | Self::OsslProviderUnqueryOperation
                | Self::Inventoried(
                    OsslProviderInit
                        | OsslProviderLoad
                        | OsslProviderTryLoad
                        | OsslProviderUnload
                        | OsslProviderLoadEx
                        | OsslProviderTryLoadEx
                        | OsslProviderAddBuiltin
                        | OsslProviderGet0Dispatch
                        | OsslProviderQueryOperation
                )
        )
    }
    pub fn export_name(self) -> Option<&'static str> {
        use inventory::Api::*;
        Some(match self {
            Self::Operational(api) => api.export_name(),
            Self::ProviderQueryCallback
            | Self::ProviderTeardownCallback
            | Self::ProviderUnqueryCallback => return None,
            Self::OsslProviderUnqueryOperation => "OSSL_PROVIDER_unquery_operation",
            Self::Inventoried(api) => match api {
                OsslProviderInit => "OSSL_provider_init",
                OsslProviderLoad => "OSSL_PROVIDER_load",
                OsslProviderTryLoad => "OSSL_PROVIDER_try_load",
                OsslProviderUnload => "OSSL_PROVIDER_unload",
                OsslProviderLoadEx => "OSSL_PROVIDER_load_ex",
                OsslProviderTryLoadEx => "OSSL_PROVIDER_try_load_ex",
                OsslProviderAddBuiltin => "OSSL_PROVIDER_add_builtin",
                OsslProviderGet0Dispatch => "OSSL_PROVIDER_get0_dispatch",
                OsslProviderQueryOperation => "OSSL_PROVIDER_query_operation",
                EvpMdFetch => "EVP_MD_fetch",
                EvpCipherFetch => "EVP_CIPHER_fetch",
                EvpMacFetch => "EVP_MAC_fetch",
                EvpKdfFetch => "EVP_KDF_fetch",
                EvpSignatureFetch => "EVP_SIGNATURE_fetch",
                EvpKemFetch => "EVP_KEM_fetch",
                OpenSslInitCrypto | OpenSslVersionMajor => return None,
                _ => return api.operational_id().map(|id| id.export_name()),
            },
        })
    }
}
pub(crate) const APIS: [ObservationApi; 69] = [
    ObservationApi::Inventoried(inventory::Api::OsslProviderInit),
    ObservationApi::Inventoried(inventory::Api::OsslProviderLoad),
    ObservationApi::Inventoried(inventory::Api::OsslProviderTryLoad),
    ObservationApi::Inventoried(inventory::Api::OsslProviderUnload),
    ObservationApi::Inventoried(inventory::Api::OsslProviderLoadEx),
    ObservationApi::Inventoried(inventory::Api::OsslProviderTryLoadEx),
    ObservationApi::Inventoried(inventory::Api::OsslProviderAddBuiltin),
    ObservationApi::Inventoried(inventory::Api::OsslProviderGet0Dispatch),
    ObservationApi::Inventoried(inventory::Api::OsslProviderQueryOperation),
    ObservationApi::Inventoried(inventory::Api::EvpMdFetch),
    ObservationApi::Inventoried(inventory::Api::EvpCipherFetch),
    ObservationApi::Inventoried(inventory::Api::EvpMacFetch),
    ObservationApi::Inventoried(inventory::Api::EvpKdfFetch),
    ObservationApi::Inventoried(inventory::Api::EvpSignatureFetch),
    ObservationApi::Inventoried(inventory::Api::EvpKemFetch),
    ObservationApi::OsslProviderUnqueryOperation,
    ObservationApi::Operational(crate::api_activity::ApiId::constant(20)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(21)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(22)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(23)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(24)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(25)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(26)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(27)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(28)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(29)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(30)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(31)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(32)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(33)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(34)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(35)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(36)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(37)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(38)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(39)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(40)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(41)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(42)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(43)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(44)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(45)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(46)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(47)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(48)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(49)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(50)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(51)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(52)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(53)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(54)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(55)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(56)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(57)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(58)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(59)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(60)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(61)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(62)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(63)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(64)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(65)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(66)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(67)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(68)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(69)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(70)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(71)),
    ObservationApi::Operational(crate::api_activity::ApiId::constant(72)),
];
/// Content fingerprint validated on construction and deserialization.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ObjectHash(String);
impl TryFrom<String> for ObjectHash {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid_object_hash");
        }
        Ok(Self(value))
    }
}
impl From<ObjectHash> for String {
    fn from(value: ObjectHash) -> Self {
        value.0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LibraryContextId(pub u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderContextId(pub u64);
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContextIdentity {
    Unknown {},
    Known {
        library: LibraryContextId,
        provider: Option<ProviderContextId>,
    },
    Candidates {
        library: LibraryContextId,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationSource {
    PublicApi,
    ProviderInit,
    ProviderQuery,
    ProviderDispatch,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Digest,
    Cipher,
    Mac,
    Kdf,
    Rand,
    Keymgmt,
    Keyexch,
    Signature,
    AsymCipher,
    Kem,
    Encoder,
    Decoder,
    Store,
    Other,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlgorithmClass {
    Digest,
    Cipher,
    Mac,
    Kdf,
    Rand,
    Key,
    Signature,
    Kem,
    Encoding,
    Store,
    Other,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeConfidence {
    Observed,
    Candidates,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationFact {
    pub pid: u32,
    pub starttime: u64,
    pub object_sha256: ObjectHash,
    pub generation: u64,
    pub context: ContextIdentity,
    pub source: ObservationSource,
    pub api: ObservationApi,
    pub operation: Operation,
    pub class: AlgorithmClass,
    pub monotonic_ns: u64,
    pub confidence: ScopeConfidence,
    pub payload: ObservationPayload,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiOutcome {
    Success,
    Failure,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderNameClass {
    Default,
    Legacy,
    Fips,
    Other,
    Unreadable,
    Overlong,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cacheability {
    Cacheable,
    Volatile,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvalidationCause {
    Unload,
    Unquery,
    Teardown,
    IdentityChanged,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct AlgorithmId(u16);
impl TryFrom<u16> for AlgorithmId {
    type Error = &'static str;
    fn try_from(id: u16) -> Result<Self, Self::Error> {
        crate::kinds::alg_class_label(id)
            .map(|_| Self(id))
            .ok_or("invalid_algorithm_id")
    }
}
impl From<AlgorithmId> for u16 {
    fn from(id: AlgorithmId) -> Self {
        id.0
    }
}
impl AlgorithmId {
    pub fn label(self) -> &'static str {
        crate::kinds::alg_class_label(self.0).unwrap_or("other")
    }
}
/// Quality of the finite alias fold. The algorithm is the minimum registered
/// ID, not a unique semantic identity when status is mixed or incomplete.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AliasStatus {
    Complete,
    Unknown,
    Truncated,
    AliasLimit,
    ReadFailed,
    Mixed,
    #[default]
    Unavailable,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AliasQuality {
    pub status: AliasStatus,
    /// A weak alias (or conservative truncated-alias signal) was observed.
    pub weak: bool,
}
impl AliasQuality {
    pub(crate) fn from_fold(status: u8, weak: bool) -> Self {
        Self {
            status: match status {
                0 => AliasStatus::Complete,
                1 => AliasStatus::Unknown,
                2 => AliasStatus::Truncated,
                3 => AliasStatus::AliasLimit,
                4 => AliasStatus::ReadFailed,
                5 => AliasStatus::Mixed,
                _ => AliasStatus::Unavailable,
            },
            weak,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "(Operation, u32)", into = "(Operation, u32)")]
pub struct FunctionIdentity {
    operation: Operation,
    id: u32,
}
impl FunctionIdentity {
    pub fn new(operation: Operation, id: u32) -> Result<Self, &'static str> {
        if id <= i32::MAX as u32 {
            Ok(Self { operation, id })
        } else {
            Err("invalid_function_id")
        }
    }
    pub fn operation(self) -> Operation {
        self.operation
    }
    pub fn id(self) -> u32 {
        self.id
    }
}
impl TryFrom<(Operation, u32)> for FunctionIdentity {
    type Error = &'static str;
    fn try_from(v: (Operation, u32)) -> Result<Self, Self::Error> {
        Self::new(v.0, v.1)
    }
}
impl From<FunctionIdentity> for (Operation, u32) {
    fn from(v: FunctionIdentity) -> Self {
        (v.operation, v.id)
    }
}
impl Operation {
    pub fn registry_name(self) -> Option<&'static str> {
        Some(match self {
            Self::Digest => "OSSL_OP_DIGEST",
            Self::Cipher => "OSSL_OP_CIPHER",
            Self::Mac => "OSSL_OP_MAC",
            Self::Kdf => "OSSL_OP_KDF",
            Self::Rand => "OSSL_OP_RAND",
            Self::Keymgmt => "OSSL_OP_KEYMGMT",
            Self::Keyexch => "OSSL_OP_KEYEXCH",
            Self::Signature => "OSSL_OP_SIGNATURE",
            Self::AsymCipher => "OSSL_OP_ASYM_CIPHER",
            Self::Kem => "OSSL_OP_KEM",
            Self::Encoder => "OSSL_OP_ENCODER",
            Self::Decoder => "OSSL_OP_DECODER",
            Self::Store => "OSSL_OP_STORE",
            Self::Other => return None,
        })
    }
    pub fn from_id(id: u32) -> Option<Self> {
        Some(match id {
            0 => Self::Other,
            1 => Self::Digest,
            2 => Self::Cipher,
            3 => Self::Mac,
            4 => Self::Kdf,
            5 => Self::Rand,
            10 => Self::Keymgmt,
            11 => Self::Keyexch,
            12 => Self::Signature,
            13 => Self::AsymCipher,
            14 => Self::Kem,
            20 => Self::Encoder,
            21 => Self::Decoder,
            22 => Self::Store,
            _ => return None,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservationPayload {
    ApiAttempt {
        name: ProviderNameClass,
    },
    ApiResult {
        name: ProviderNameClass,
        outcome: ApiOutcome,
    },
    InitResult {
        outcome: ApiOutcome,
    },
    QueryResult {
        outcome: ApiOutcome,
        cacheability: Cacheability,
    },
    Algorithm {
        algorithm: AlgorithmId,
        #[serde(default)]
        alias_quality: AliasQuality,
        cacheability: Cacheability,
    },
    Implementation {
        algorithm: AlgorithmId,
        #[serde(default)]
        alias_quality: AliasQuality,
        function: FunctionIdentity,
        cacheability: Cacheability,
        advertiser_candidates: Vec<ObjectHash>,
        backing_sha256: Option<ObjectHash>,
    },
    Invalidation {
        cause: InvalidationCause,
    },
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    #[test]
    fn failed_provisional_acquisition_releases_ownership_but_not_reads() {
        let budget = ObservationBudget::new(ObservationLimits {
            max_processes: 1,
            max_objects: 1,
            max_state_bytes: 64,
            max_elf_read_bytes: 64,
            ..Default::default()
        });
        let admission = budget.process().unwrap();
        budget.object().unwrap();
        budget.state(64).unwrap();
        budget.read(32).unwrap();
        assert!(matches!(
            budget.process(),
            Err(ObservationGap::ProcessLimit)
        ));
        drop(admission);
        let mut admitted = budget.process().unwrap();
        budget.object().unwrap();
        budget.state(64).unwrap();
        assert_eq!(budget.elf_read_bytes(), 32);
        assert_eq!(budget.read(33), Err(ObservationGap::ReadLimit));
        admitted.retain();
        drop(admitted);
        assert!(budget.process().is_ok());
        assert_eq!(budget.state(1), Err(ObservationGap::StateLimit));
    }
    #[test]
    fn release_to_floor_preserves_live_reservations_and_never_underflows() {
        let budget = ObservationBudget::new(ObservationLimits {
            max_state_bytes: 1000,
            ..Default::default()
        });
        budget.state(100).unwrap(); // permanent setup-like spend
        let floor = budget.spent_state();
        let guard = budget.reserve_state(300).unwrap(); // live reservation
        budget.state(200).unwrap(); // permanent acquisition-like spend
        assert_eq!(budget.spent_state(), 600);
        // Release keeps floor + live reservations; the guard must still
        // drop cleanly afterwards (no underflow, no panic).
        budget.release_state_to_floor(floor);
        assert_eq!(budget.spent_state(), floor + 300);
        drop(guard);
        assert_eq!(budget.spent_state(), floor);
        // Retained reservations leave the reserved set (no double-drop
        // on release) but their spend is still acquisition spend, so a
        // later release drops it like any other dead spend.
        let kept = budget.reserve_state(50).unwrap();
        assert_eq!(budget.spent_state(), floor + 50);
        kept.retain(); // consumes; implicit drop subtracts 0
        assert_eq!(budget.spent_state(), floor + 50);
        budget.release_state_to_floor(floor);
        assert_eq!(budget.spent_state(), floor);
        // Floors above current spend are a no-op.
        budget.release_state_to_floor(floor + 5000);
        assert_eq!(budget.spent_state(), floor);
    }
}
