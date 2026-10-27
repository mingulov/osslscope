// SPDX-License-Identifier: GPL-3.0-or-later
use crate::inventory;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::rc::Rc;

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
            max_state_bytes: 67108864,
            max_elf_read_bytes: 268435456,
        }
    }
}
#[derive(Default)]
struct Work {
    processes: usize,
    objects: usize,
    state: usize,
    reads: u64,
}
/// Clones share cumulative admission, including lazy relocation work.
#[derive(Clone)]
pub struct ObservationBudget {
    pub limits: ObservationLimits,
    work: Rc<RefCell<Work>>,
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
        }
    }
    pub fn elf_read_bytes(&self) -> u64 {
        self.work.borrow().reads
    }
    pub(crate) fn read(&self, bytes: u64) -> Result<(), ObservationGap> {
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
    pub(crate) fn process(&self) -> Result<(), ObservationGap> {
        let mut work = self.work.borrow_mut();
        if work.processes >= self.limits.max_processes {
            return Err(ObservationGap::ProcessLimit);
        }
        work.processes += 1;
        Ok(())
    }
    pub(crate) fn object(&self) -> Result<(), ObservationGap> {
        let mut work = self.work.borrow_mut();
        if work.objects >= self.limits.max_objects {
            return Err(ObservationGap::ObjectLimit);
        }
        work.objects += 1;
        Ok(())
    }
    pub(crate) fn state(&self, bytes: usize) -> Result<(), ObservationGap> {
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
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationApi {
    Inventoried(inventory::Api),
    OsslProviderUnqueryOperation,
    ProviderQueryCallback,
    ProviderTeardownCallback,
    ProviderUnqueryCallback,
}
impl ObservationApi {
    pub fn export_name(self) -> Option<&'static str> {
        use inventory::Api::*;
        Some(match self {
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
            },
        })
    }
}
pub(crate) const APIS: [ObservationApi; 16] = [
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
];
/// Content fingerprint validated on construction and deserialization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
        if id == 0
            || crate::kinds::FUNCS
                .iter()
                .any(|f| f.id == id && f.op == operation.registry_name() && f.op.is_some())
        {
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
