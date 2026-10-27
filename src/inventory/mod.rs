// SPDX-License-Identifier: GPL-3.0-or-later
//! Passive, file-backed interface inventory. Compatibility is a candidate
//! property; it proves neither vendor authenticity nor provider activation.

pub mod cli;
pub mod elf;
pub mod scope;
pub mod watch;

use serde::{Deserialize, Serialize};

/// Recognized dynamic code exports. Unknown symbol names are discarded.
/// Declaration order also gives the stable, deduplicated export order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Api {
    OsslProviderInit,
    OsslProviderLoad,
    OsslProviderTryLoad,
    OsslProviderUnload,
    OsslProviderLoadEx,
    OsslProviderTryLoadEx,
    OsslProviderAddBuiltin,
    OsslProviderGet0Dispatch,
    OsslProviderQueryOperation,
    #[serde(rename = "openssl_init_crypto")]
    OpenSslInitCrypto,
    #[serde(rename = "openssl_version_major")]
    OpenSslVersionMajor,
    EvpMdFetch,
    EvpCipherFetch,
    EvpMacFetch,
    EvpKdfFetch,
    EvpSignatureFetch,
    EvpKemFetch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
    Aarch64,
    Other,
}

/// Interface/dependency evidence only, with no vendor or runtime claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    #[serde(rename = "openssl_compatible")]
    OpenSslCompatible,
    ProviderModule,
    #[serde(rename = "openssl_consumer")]
    OpenSslConsumer,
    Other,
}

/// Finite failure labels: underlying IO/parser messages never escape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapReason {
    Unavailable,
    NonRegular,
    TooLarge,
    NotElf,
    MalformedElf,
    Changed,
    UnsupportedArchitecture,
    ProcessUnavailable,
    IdentityUnverified,
    ReadLimit,
    ProcessLimit,
    ObjectLimit,
    MalformedMaps,
    Deadline,
    UnsupportedCgroup,
    CgroupUnavailable,
    CgroupLimit,
    MembershipUnknown,
    NamespaceUnavailable,
}

/// File identity plus finite interface evidence; never paths or raw symbols.
/// `device` is the native Linux `st_dev` value, paired with `st_ino`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleInfo {
    pub sha256: String,
    pub device: u64,
    pub inode: u64,
    pub size_bytes: u64,
    pub architecture: Architecture,
    pub kind: ObjectKind,
    pub exports: Vec<Api>,
    pub depends_on_libcrypto: bool,
    pub depends_on_libssl: bool,
}

mod procfs;

use std::time::Duration;

/// Snapshot-wide work bounds. The deadline is cooperative between IO calls;
/// it cannot interrupt a stalled filesystem syscall.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_module_bytes: u64,
    pub max_maps_bytes: usize,
    pub max_pids: usize,
    pub max_objects_per_process: usize,
    pub max_objects: usize,
    pub max_read_bytes: u64,
    pub timeout: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_module_bytes: 134_217_728,
            max_maps_bytes: 4_194_304,
            max_pids: 4096,
            max_objects_per_process: 1024,
            max_objects: 16_384,
            max_read_bytes: 1_073_741_824,
            timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct SnapshotOptions {
    pub pids: Vec<u32>,
    pub limits: Limits,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityStatus {
    Verified,
    LocatorCandidate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleRecord {
    pub info: ModuleInfo,
    pub identity_status: IdentityStatus,
}

/// Unknown historical state is distinct from an execution observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationState {
    Unknown,
    NotObserved,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessRecord {
    pub interval: CaptureInterval,
    pub namespaces: NamespaceIds,
    pub pid: u32,
    pub starttime: u64,
    pub modules: Vec<ModuleRecord>,
    pub provider_activation: ObservationState,
    pub provider_interfaces: ObservationState,
    pub execution: ObservationState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotMode {
    Snapshot,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    System,
    Pids,
    Cgroup,
    Modules,
    Intersection,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryState {
    Complete,
    Partial,
    Unavailable,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    pub inventory: InventoryState,
    pub provider_activation: ObservationState,
    pub provider_interfaces: ObservationState,
    pub execution: ObservationState,
}

/// Only safe process/file fingerprints accompany finite gap labels.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gap {
    pub pid: Option<u32>,
    pub device: Option<u64>,
    pub inode: Option<u64>,
    pub reason: GapReason,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkTotals {
    pub processes_attempted: usize,
    pub objects_attempted: usize,
    pub objects_inspected: usize,
    /// Conservatively charged read work, including ELF EOF probes. Cache
    /// hits do not charge file bytes a second time.
    pub read_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub interval: CaptureInterval,
    pub scope_record: ScopeRecord,
    pub schema_version: String,
    pub mode: SnapshotMode,
    pub scope: Scope,
    /// Bounded admitted PID selection, sorted and deduplicated.
    pub selected_pids: Vec<u32>,
    pub processes: Vec<ProcessRecord>,
    pub gaps: Vec<Gap>,
    pub totals: WorkTotals,
    pub limits: Limits,
    pub capabilities: Capabilities,
}
impl Snapshot {
    pub fn exit_code(&self) -> u8 {
        match self.capabilities.inventory {
            InventoryState::Complete => 0,
            InventoryState::Partial => 3,
            InventoryState::Unavailable => 4,
        }
    }
}

/// Read-only, file-backed discovery; no target memory, code, signals or BPF.
pub fn snapshot(options: &SnapshotOptions) -> Snapshot {
    procfs::snapshot(options)
}

/// Observer clocks describe capture only; wall time may move independently.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureInterval {
    pub started_unix_ms: Option<u64>,
    pub finished_unix_ms: Option<u64>,
    pub elapsed_ns: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceId {
    pub device: u64,
    pub inode: u64,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceIds {
    pub pid: Option<NamespaceId>,
    pub mount: Option<NamespaceId>,
}
/// Native cgroup identity and supplied content hashes, without locators.
/// Membership is sampled in the observer's visible PID/cgroup namespaces.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeRecord {
    pub cgroup: Option<NamespaceId>,
    pub modules: Vec<String>,
}
pub(super) struct CaptureClock {
    started: std::time::Instant,
    wall: Option<u64>,
}
impl CaptureClock {
    pub(super) fn start() -> Self {
        Self {
            started: std::time::Instant::now(),
            wall: wall_ms(),
        }
    }
    pub(super) fn finish(&self) -> CaptureInterval {
        CaptureInterval {
            started_unix_ms: self.wall,
            finished_unix_ms: wall_ms(),
            elapsed_ns: u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX),
        }
    }
}
fn wall_ms() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
}
