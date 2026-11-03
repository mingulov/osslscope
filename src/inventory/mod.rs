// SPDX-License-Identifier: GPL-3.0-or-later
//! Passive, file-backed interface inventory. Compatibility is a candidate
//! property; it proves neither vendor authenticity nor provider activation.

pub mod cli;
pub mod elf;
pub mod scope;
pub mod watch;

pub(crate) mod backing;

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
    EvpDigestInitEx,
    EvpDigestInitEx2,
    EvpDigestUpdate,
    EvpDigestFinalEx,
    EvpEncryptInitEx,
    EvpEncryptInitEx2,
    EvpEncryptUpdate,
    EvpEncryptFinalEx,
    EvpDecryptInitEx,
    EvpDecryptInitEx2,
    EvpDecryptUpdate,
    EvpDecryptFinalEx,
    EvpCipherInitEx,
    EvpCipherUpdate,
    EvpCipherFinalEx,
    EvpMacInit,
    EvpMacUpdate,
    EvpMacFinal,
    EvpKdfDerive,
    EvpPkeySign,
    EvpPkeyVerify,
    EvpPkeyEncrypt,
    EvpPkeyDecrypt,
    EvpPkeyDerive,
    EvpDigestSignFinal,
    EvpDigestVerifyFinal,
    EvpDigestSign,
    EvpDigestVerify,
    EvpRandGenerate,
    EvpPkeyEncapsulate,
    EvpPkeyDecapsulate,
    EvpPkeyKeygenInit,
    EvpPkeyKeygen,
    EvpPkeyParamgenInit,
    EvpPkeyParamgen,
    EvpPkeyDeriveInit,
    EvpPkeyCheck,
    EvpPkeyPublicCheck,
    EvpPkeyParamCheck,
    EvpPkeyCopyParameters,
    EvpDigestSignInit,
    EvpDigestSignUpdate,
    EvpDigestVerifyInit,
    EvpDigestVerifyUpdate,
    EvpQDigest,
    EvpQMac,
    EvpRandNonce,
    EvpRandCtxNew,
    EvpRandCtxFree,
    EvpMdCtxNew,
    EvpMdCtxFree,
    EvpCipherCtxNew,
    EvpCipherCtxFree,
}

impl Api {
    pub(crate) fn operational_id(self) -> Option<crate::api_activity::ApiId> {
        let id = match self {
            Self::EvpDigestInitEx => 20,
            Self::EvpDigestInitEx2 => 21,
            Self::EvpDigestUpdate => 22,
            Self::EvpDigestFinalEx => 23,
            Self::EvpEncryptInitEx => 24,
            Self::EvpEncryptInitEx2 => 25,
            Self::EvpEncryptUpdate => 26,
            Self::EvpEncryptFinalEx => 27,
            Self::EvpDecryptInitEx => 28,
            Self::EvpDecryptInitEx2 => 29,
            Self::EvpDecryptUpdate => 30,
            Self::EvpDecryptFinalEx => 31,
            Self::EvpCipherInitEx => 32,
            Self::EvpCipherUpdate => 33,
            Self::EvpCipherFinalEx => 34,
            Self::EvpMacInit => 35,
            Self::EvpMacUpdate => 36,
            Self::EvpMacFinal => 37,
            Self::EvpKdfDerive => 38,
            Self::EvpPkeySign => 39,
            Self::EvpPkeyVerify => 40,
            Self::EvpPkeyEncrypt => 41,
            Self::EvpPkeyDecrypt => 42,
            Self::EvpPkeyDerive => 43,
            Self::EvpDigestSignFinal => 44,
            Self::EvpDigestVerifyFinal => 45,
            Self::EvpDigestSign => 46,
            Self::EvpDigestVerify => 47,
            Self::EvpRandGenerate => 48,
            Self::EvpPkeyEncapsulate => 49,
            Self::EvpPkeyDecapsulate => 50,
            Self::EvpPkeyKeygenInit => 51,
            Self::EvpPkeyKeygen => 52,
            Self::EvpPkeyParamgenInit => 53,
            Self::EvpPkeyParamgen => 54,
            Self::EvpPkeyDeriveInit => 55,
            Self::EvpPkeyCheck => 56,
            Self::EvpPkeyPublicCheck => 57,
            Self::EvpPkeyParamCheck => 58,
            Self::EvpPkeyCopyParameters => 59,
            Self::EvpDigestSignInit => 60,
            Self::EvpDigestSignUpdate => 61,
            Self::EvpDigestVerifyInit => 62,
            Self::EvpDigestVerifyUpdate => 63,
            Self::EvpQDigest => 64,
            Self::EvpQMac => 65,
            Self::EvpRandNonce => 66,
            Self::EvpRandCtxNew => 67,
            Self::EvpRandCtxFree => 68,
            Self::EvpMdCtxNew => 69,
            Self::EvpMdCtxFree => 70,
            Self::EvpCipherCtxNew => 71,
            Self::EvpCipherCtxFree => 72,
            _ => return None,
        };
        Some(crate::api_activity::ApiId::constant(id))
    }
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
    /// Metadata was acquired, but its mapping association is a locator candidate.
    IdentityUnverified,
    /// Executable backing could not be acquired or its native identity mismatched.
    BackingUnavailable,
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

impl GapReason {
    /// Display word for the human preamble. Mirrors the serde
    /// snake_case label exactly (proven by
    /// `cli::tests::gap_reason_words_match_json`).
    pub fn word(&self) -> &'static str {
        match self {
            GapReason::Unavailable => "unavailable",
            GapReason::NonRegular => "non_regular",
            GapReason::TooLarge => "too_large",
            GapReason::NotElf => "not_elf",
            GapReason::MalformedElf => "malformed_elf",
            GapReason::Changed => "changed",
            GapReason::UnsupportedArchitecture => "unsupported_architecture",
            GapReason::ProcessUnavailable => "process_unavailable",
            GapReason::IdentityUnverified => "identity_unverified",
            GapReason::BackingUnavailable => "backing_unavailable",
            GapReason::ReadLimit => "read_limit",
            GapReason::ProcessLimit => "process_limit",
            GapReason::ObjectLimit => "object_limit",
            GapReason::MalformedMaps => "malformed_maps",
            GapReason::Deadline => "deadline",
            GapReason::UnsupportedCgroup => "unsupported_cgroup",
            GapReason::CgroupUnavailable => "cgroup_unavailable",
            GapReason::CgroupLimit => "cgroup_limit",
            GapReason::MembershipUnknown => "membership_unknown",
            GapReason::NamespaceUnavailable => "namespace_unavailable",
        }
    }
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
    /// Selected backing-operation `errno` for this gap, when the
    /// acquisition attempted an open or fstat that failed. Usually the
    /// refused range-bound open; may also name a metadata failure, and
    /// may accompany a limit reason when the refusal preceded the limit.
    /// Additive: absent in old documents and skipped when no backing
    /// operation failed, so the common shape is byte-identical.
    /// Appended last to preserve record order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errno: Option<i32>,
    /// Observer euid associated with the selected failed operation
    /// above, present iff `errno` is. uids are host-local diagnostics,
    /// like pids.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_euid: Option<u32>,
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

    /// Verified-vs-locator module counts across all processes (the
    /// human identity summary; JSON carries the per-module status).
    pub fn identity_counts(&self) -> (usize, usize) {
        let mut verified = 0;
        let mut locator = 0;
        for module in self.processes.iter().flat_map(|p| p.modules.iter()) {
            match module.identity_status {
                IdentityStatus::Verified => verified += 1,
                IdentityStatus::LocatorCandidate => locator += 1,
            }
        }
        (verified, locator)
    }

    /// Human preamble inputs (display-only; JSON is unchanged):
    /// identity counts plus gaps coalesced by (reason, device, pid).
    pub fn human_preamble(&self) -> SnapshotPreamble {
        SnapshotPreamble {
            identity: self.identity_counts(),
            gap_groups: coalesce_gaps(&self.gaps),
            conclusively_without_openssl: snapshot_conclusively_without_openssl(self),
        }
    }
}

/// Shared human identity totals line (one shape for snapshot
/// preambles, watch snapshots, provider records, and crypto
/// discovery rows): verified-vs-locator module counts plus the
/// verified share.
pub fn identity_totals_line(verified: usize, locator: usize) -> String {
    let total = verified + locator;
    if total == 0 {
        return "identity: no modules inventoried\n".to_string();
    }
    let pct = verified * 100 / total;
    format!(
        "identity: {verified} verified, {locator} locator-candidate of {total} modules ({pct}% verified)\n"
    )
}

/// Shared human blindness boundary: stated only when the caller has
/// conclusively established it (see
/// [`snapshot_conclusively_without_openssl`]). Static/vendored
/// crypto appear as the caveat (what would be invisible), never as
/// a diagnosis: absence stays inconclusive everywhere else.
pub fn blindness_line() -> &'static str {
    "blindness: no-mapped-openssl (complete enumeration found no OpenSSL object; statically linked or vendored crypto invisible)\n"
}

/// True when the snapshot conclusively shows no mapped OpenSSL: zero
/// OpenSSL-kind modules and no gap that could hide a mapping.
/// [`GapReason::IdentityUnverified`] leaves the mapping known, so it
/// does not veto; every other gap keeps absence inconclusive.
pub fn snapshot_conclusively_without_openssl(snapshot: &Snapshot) -> bool {
    let has_openssl = snapshot.processes.iter().flat_map(|p| &p.modules).any(|m| {
        matches!(
            m.info.kind,
            ObjectKind::OpenSslCompatible
                | ObjectKind::ProviderModule
                | ObjectKind::OpenSslConsumer
        )
    });
    if has_openssl {
        return false;
    }
    !snapshot
        .gaps
        .iter()
        .any(|g| g.reason != GapReason::IdentityUnverified)
}

/// Human-preamble inputs for a [`Snapshot`] (see
/// [`Snapshot::human_preamble`]). A group is (reason, device, pid,
/// exact count), sorted by (reason, device, pid) with absent ids
/// sorting first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotPreamble {
    pub identity: (usize, usize),
    pub gap_groups: Vec<(GapReason, Option<u64>, Option<u32>, usize)>,
    pub conclusively_without_openssl: bool,
}

/// Shared human gap-group block: groups (word, device, pid) triples
/// with exact counters, deterministic order (BTreeMap iteration),
/// empty string when there is nothing to show. The one grouping
/// implementation for snapshot preambles and all streaming paths;
/// each path adapts its gap type to words (inodes never key a group).
/// `indent` nests the block under streaming records (`""` top-level).
pub fn gap_groups_block<'a, I>(gaps: I, indent: &str) -> String
where
    I: IntoIterator<Item = (&'a str, Option<u64>, Option<u32>)>,
{
    let mut groups = std::collections::BTreeMap::new();
    for key in gaps {
        *groups.entry(key).or_insert(0usize) += 1;
    }
    if groups.is_empty() {
        return String::new();
    }
    let total: usize = groups.values().sum();
    let mut s = format!(
        "{indent}gaps ({total} total in {} group{}):\n",
        groups.len(),
        if groups.len() == 1 { "" } else { "s" },
    );
    for ((word, device, pid), count) in &groups {
        let dev = device.map_or("-".to_string(), |d| d.to_string());
        let p = pid.map_or("-".to_string(), |p| p.to_string());
        s.push_str(&format!("{indent}  {word} device={dev} pid={p}: {count}\n"));
    }
    s
}

/// Group gaps by (reason, device, pid) with exact counters
/// (P1-coalesce). Inodes vary per module and never key a group;
/// ordering is deterministic (BTreeMap iteration).
pub fn coalesce_gaps(gaps: &[Gap]) -> Vec<(GapReason, Option<u64>, Option<u32>, usize)> {
    let mut groups = std::collections::BTreeMap::new();
    for gap in gaps {
        *groups
            .entry((gap.reason, gap.device, gap.pid))
            .or_insert(0usize) += 1;
    }
    groups
        .into_iter()
        .map(|((reason, device, pid), count)| (reason, device, pid, count))
        .collect()
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
