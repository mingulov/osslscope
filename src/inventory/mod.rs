// SPDX-License-Identifier: GPL-3.0-or-later
//! Passive, file-backed interface inventory. Compatibility is a candidate
//! property; it proves neither vendor authenticity nor provider activation.

pub mod cli;
pub mod elf;
pub mod scope;
pub mod watch;

pub(crate) mod backing;
pub(crate) mod resolve;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
    /// Number of variants in this enum (update together). Bounds
    /// coordinator-supplied export metadata: `exports` is collected
    /// from a `BTreeSet<Api>`, so our own snapshots never exceed it.
    pub const COUNT: usize = 70;

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
/// - `OpenSslCompatible`: the file exports recognized OpenSSL API
///   symbols (defined dynamic code exports, provider-init excluded).
/// - `ProviderModule`: the file exports `OSSL_PROVIDER_init`.
/// - `OpenSslConsumer`: the file needs OpenSSL — a `DT_NEEDED`
///   `libcrypto`/`libssl` entry in a known SONAME form, or an
///   undefined reference to a recognized API symbol.
/// - `Other`: none of the above — an ELF object with no recognized
///   OpenSSL interface evidence. Others are counted per process
///   ([`ProcessRecord::other_objects`]), never listed — except under
///   an explicit `--module` selector, where a selected `Other` is
///   listed as a module row and lands in no count bucket (R11).
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

impl ObjectKind {
    /// Display word for human module rows. Mirrors the serde
    /// snake_case label exactly (proven by
    /// `cli::tests::object_kind_words_match_json`).
    pub fn word(&self) -> &'static str {
        match self {
            ObjectKind::OpenSslCompatible => "openssl_compatible",
            ObjectKind::ProviderModule => "provider_module",
            ObjectKind::OpenSslConsumer => "openssl_consumer",
            ObjectKind::Other => "other",
        }
    }
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

/// Availability of file-backed OpenSSL version evidence (v0.6.0 D4):
/// file facts only, never a runtime claim. `Present` carries exactly
/// one distinct recognized version id in `file_openssl_version`; every
/// other status leaves it `None`. Old documents default to `Absent`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileVersionStatus {
    Present,
    #[default]
    Absent,
    Ambiguous,
    NotFullyScanned,
}

/// File identity plus finite interface evidence; never paths or raw symbols.
/// `device` is the native Linux `st_dev` value, paired with `st_ino`.
/// `file_soname` is the object's OWN `DT_SONAME`, never inherited from a
/// dependency; `file_openssl_version` is the singular validated rodata
/// version id, or `None` with the reason in `file_version_status`.
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
    #[serde(default)]
    pub file_soname: Option<String>,
    #[serde(default)]
    pub file_openssl_version: Option<String>,
    #[serde(default)]
    pub file_version_status: FileVersionStatus,
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
    /// T5 `--resolve-paths` EFFECTIVE acquire intent: the caller
    /// passes `acquire_paths(raw, json, terminal)` — locators are
    /// established, sidecar capabilities retained, and machine path
    /// evidence (`verified_path`, `maps_spelling`) populated for
    /// JSON output and flagged runs alike (v0.6.0 D1 dropped the
    /// never-in-JSON gate; the TTY-only rule survives solely for
    /// the human `path=` fragment). Off (default): no resolution
    /// I/O, no retained locator bytes (cells 5/6).
    pub resolve_paths: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityStatus {
    Verified,
    LocatorCandidate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathEncoding {
    Utf8,
    Utf8PercentEscaped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocatorKind {
    HostDirect,
    ContainerLayer,
    ProcRootAnchored,
}

/// Proven object path (v0.6.0 D1/D3): `path` names the module's
/// retained identity (re-proven at capture time), `locator_kind`
/// records HOW it was proven (host direct, container layer, or
/// target-root anchored), and `capture_unix_ms` stamps WHEN.
/// Incarnation binding: the enclosing `ProcessRecord`'s `(pid,
/// starttime, namespaces)` triple is the identity the path is proven
/// against — consumers must NEVER join paths across processes by
/// `(device, inode)` alone (numbers recycle across namespaces and
/// mounts; the incarnation triple does not).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedPath {
    pub path: String,
    pub path_encoding: PathEncoding,
    pub locator_kind: LocatorKind,
    pub capture_unix_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MapsSource {
    ProcMaps,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MapsVerification {
    Unverified,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MapsSpelling {
    pub spelling: String,
    pub source: MapsSource,
    pub verification: MapsVerification,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathUnavailableReason {
    UnverifiedIdentity,
    NoLocator,
    ResolveFailed,
    Changed,
    Missing,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleRecord {
    pub info: ModuleInfo,
    pub identity_status: IdentityStatus,
    #[serde(default)]
    pub verified_path: Option<VerifiedPath>,
    #[serde(default)]
    pub verified_path_unavailable: Option<PathUnavailableReason>,
    #[serde(default)]
    pub maps_spelling: Option<MapsSpelling>,
}

/// Unknown historical state is distinct from an execution observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationState {
    Unknown,
    NotObserved,
}

impl ObservationState {
    /// Display word for `-v` full per-process state lines. Mirrors
    /// the serde snake_case label exactly (see
    /// `cli::tests::observation_state_words_match_json`).
    pub fn word(&self) -> &'static str {
        match self {
            ObservationState::Unknown => "unknown",
            ObservationState::NotObserved => "not_observed",
        }
    }
}

/// Finite availability of one sampled process-identity fact
/// (v0.6.0 D2): `comm` and `exe` are operator-visible `/proc`
/// readings, never authentication or proof. Old documents default
/// to `Unreadable` (absent), never to a fabricated value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityAvailability {
    Available,
    #[default]
    Unreadable,
    Changed,
    TooLong,
}

/// Per-process counts of `ObjectKind::Other` file-backed
/// executable objects (v0.6.0 P0-5): outside an explicit
/// `--module` selector scope, Others are counted, never listed,
/// so `0 modules` stays distinguishable from `nothing mapped`.
/// Under `scan --module` a selected `Other` is listed as a
/// module row instead and lands in no count bucket (R11: no
/// object is ever both listed and counted). `verified` counts
/// Others whose backing proof closed; `candidate` counts Others
/// bound only to an unverified locator (an `IdentityUnverified`
/// gap names the same mapping); `failed` counts executable
/// file-backed mappings that errored before any classification
/// (backing or parse failure — every one also carries a gap —
/// in every route, since failures are never listed anywhere).
/// Non-executable mappings, skipped non-regular files, and files
/// determined to be non-ELF are outside the counted population
/// and never increment any bucket. Counts are
/// classification-time outcomes: a later `Changed` gap
/// downgrades `verified` to `candidate` (like the published
/// rows) and always vetoes the
/// [`snapshot_conclusively_without_openssl`] predicate, but
/// never rewrites history beyond that.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OtherCounts {
    pub verified: u32,
    pub candidate: u32,
    pub failed: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessRecord {
    pub interval: CaptureInterval,
    pub namespaces: NamespaceIds,
    pub pid: u32,
    pub starttime: u64,
    #[serde(default)]
    pub comm: Option<String>,
    #[serde(default)]
    pub comm_status: IdentityAvailability,
    /// Sampled `/proc/PID/exe` spelling. Verbatim-lossy UTF-8 in
    /// JSON (lossy decode only — unlike `comm`, acquisition applies
    /// no display sanitization), so every human renderer MUST pass
    /// BOTH `comm` and `exe` through
    /// `crate::report::safe_display` at the human boundary (v0.6.0
    /// machine T4 parked minor); never render raw.
    #[serde(default)]
    pub exe: Option<String>,
    #[serde(default)]
    pub exe_status: IdentityAvailability,
    pub modules: Vec<ModuleRecord>,
    /// Counted-not-listed `Other` objects (always serialized;
    /// old documents default to zeros).
    #[serde(default)]
    pub other_objects: OtherCounts,
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
impl InventoryState {
    /// Display word for human per-sample status lines (watch
    /// heartbeats on every route). Mirrors the serde snake_case
    /// label exactly (see
    /// `tests::inventory_state_words_match_json`).
    pub fn word(&self) -> &'static str {
        match self {
            InventoryState::Complete => "complete",
            InventoryState::Partial => "partial",
            InventoryState::Unavailable => "unavailable",
        }
    }
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
    /// Selected refused-open `errno` for this gap, when the
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
    /// Render-time row capabilities (T5 `--resolve-paths` rule 3):
    /// retained backing custody + proven host locators, joined by
    /// exact object identity. Skipped by serde in BOTH directions
    /// (never emitted; defaults to empty on read) — the sidecar
    /// itself never moves machine bytes (cell 2); v0.6.0 D1 machine
    /// path evidence on the records may differ by acquisition.
    #[serde(skip)]
    pub(crate) resolve: resolve::ResolveSidecar,
    /// 6A cgroup stable-set sidecar: pid → directory identity
    /// (`NamespaceId`) for pids stable across the sample's two
    /// cgroup traversals (empty when unscoped). Skipped by serde
    /// like `resolve`. The membership coordinator diffs
    /// consecutive samples for inter-tick `cgroup_move` (§1.6).
    #[serde(skip)]
    pub(crate) cgroup_identity: BTreeMap<u32, NamespaceId>,
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

/// True when the snapshot conclusively shows no mapped OpenSSL, and
/// only then: zero OpenSSL-kind modules, zero gaps of any kind, and
/// no module-selector scoping. Any gap vetoes — including
/// [`GapReason::IdentityUnverified`], whose candidate file was never
/// proven to be the mapped backing object, so its `Other` kind
/// cannot exclude an OpenSSL mapping. Module selectors veto because
/// the published list is filtered before this predicate runs: a
/// scoped enumeration is not a complete one.
pub fn snapshot_conclusively_without_openssl(snapshot: &Snapshot) -> bool {
    if !snapshot.gaps.is_empty() || !snapshot.scope_record.modules.is_empty() {
        return false;
    }
    !snapshot.processes.iter().flat_map(|p| &p.modules).any(|m| {
        matches!(
            m.info.kind,
            ObjectKind::OpenSslCompatible
                | ObjectKind::ProviderModule
                | ObjectKind::OpenSslConsumer
        )
    })
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

/// Compact human namespace summary for `-v` full per-process
/// state lines (one shape for the inventory, provider, and
/// crypto-watch routes): `pid=<dev>:<ino>,mount=<dev>:<ino>`,
/// with `-` for each absent side. Observer-sampled numbers only.
pub fn human_namespaces(ids: &NamespaceIds) -> String {
    let side = |id: Option<&NamespaceId>| {
        id.map_or("-".to_string(), |n| format!("{}:{}", n.device, n.inode))
    };
    format!(
        "pid={},mount={}",
        side(ids.pid.as_ref()),
        side(ids.mount.as_ref())
    )
}

/// Human `exports=[...]` fragment for `-v` module rows (one shape
/// for the inventory, provider, and crypto-watch routes): serde
/// snake_case words in stored order, `[]` when empty.
pub fn human_exports(exports: &[Api]) -> String {
    let words: Vec<String> = exports
        .iter()
        .map(|api| {
            serde_json::to_value(api)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_else(|| "unknown".to_string())
        })
        .collect();
    format!("exports=[{}]", words.join(", "))
}

/// Run-level cumulative-uncertainty word for human end
/// records (one shape for the inventory, provider, and
/// crypto-watch routes): `clean` when every sample was
/// complete, otherwise the worst history seen. A later
/// complete sample never clears the word (H2).
pub fn cumulative_word(saw_partial: bool, saw_unavailable: bool) -> &'static str {
    if saw_unavailable {
        "unavailable-seen"
    } else if saw_partial {
        "partial-seen"
    } else {
        "clean"
    }
}

/// Human uncertainty notes for a run's first uncertain samples
/// (one shape for every route): one `note:` line per track
/// seen, chronological across tracks, empty when the history is
/// clean. The sample numbers are the route's own 1-based sample
/// (inventory/provider) or nominal tick (crypto-watch) ids.
pub fn cumulative_notes(first_partial: Option<u64>, first_unavailable: Option<u64>) -> String {
    let mut notes: Vec<(u64, &str)> = Vec::new();
    if let Some(seq) = first_partial {
        notes.push((seq, "partial"));
    }
    if let Some(seq) = first_unavailable {
        notes.push((seq, "unavailable"));
    }
    notes.sort();
    let mut out = String::new();
    for (seq, word) in notes {
        out.push_str(&format!(
            "note: sample {seq} was {word}; history remains uncertain\n"
        ));
    }
    out
}

/// Stable per-module watch digest: the fields a human row shows
/// (identity, evidence, versions), minus per-sample volatility.
/// `VerifiedPath::capture_unix_ms` is re-stamped every sample
/// and deliberately excluded — only the stable locator triple
/// (path, encoding, kind) counts, exactly like `same_module` in
/// the inventory watch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WatchedModuleDigest {
    info: ModuleInfo,
    identity: IdentityStatus,
    path: Option<(String, PathEncoding, LocatorKind)>,
    unavailable: Option<PathUnavailableReason>,
    maps: Option<MapsSpelling>,
}

/// Stable per-process watch digest for borrowed snapshots (the
/// provider and crypto-watch routes cannot retain full previous
/// snapshots): names, namespaces, states, and module digests.
/// The inventory watch compares retained typed snapshots
/// directly instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WatchedProcessDigest {
    pid: u32,
    starttime: u64,
    namespaces: NamespaceIds,
    comm: Option<String>,
    comm_status: IdentityAvailability,
    exe: Option<String>,
    exe_status: IdentityAvailability,
    activation: ObservationState,
    interfaces: ObservationState,
    execution: ObservationState,
    modules: Vec<WatchedModuleDigest>,
}

pub(crate) fn watched_process_digest(process: &ProcessRecord) -> WatchedProcessDigest {
    WatchedProcessDigest {
        pid: process.pid,
        starttime: process.starttime,
        namespaces: process.namespaces.clone(),
        comm: process.comm.clone(),
        comm_status: process.comm_status,
        exe: process.exe.clone(),
        exe_status: process.exe_status,
        activation: process.provider_activation,
        interfaces: process.provider_interfaces,
        execution: process.execution,
        modules: process
            .modules
            .iter()
            .map(|module| WatchedModuleDigest {
                info: module.info.clone(),
                identity: module.identity_status,
                path: module.verified_path.as_ref().map(|proven| {
                    (
                        proven.path.clone(),
                        proven.path_encoding,
                        proven.locator_kind,
                    )
                }),
                unavailable: module.verified_path_unavailable,
                maps: module.maps_spelling.clone(),
            })
            .collect(),
    }
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
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

/// v0.6.0 D1 machine publish clock: capture instant for
/// `VerifiedPath::capture_unix_ms` (wall time, like the capture
/// interval edges — observer clock, not target data).
pub(crate) fn wall_ms_pub() -> Option<u64> {
    wall_ms()
}

#[cfg(test)]
mod tests {
    use super::Api;
    use std::collections::BTreeSet;

    /// `Api::COUNT` pins the variant count (update together): every
    /// variant named once, collected exactly like `elf.rs` does.
    #[test]
    fn api_count_matches_variants() {
        let all = BTreeSet::from([
            Api::OsslProviderInit,
            Api::OsslProviderLoad,
            Api::OsslProviderTryLoad,
            Api::OsslProviderUnload,
            Api::OsslProviderLoadEx,
            Api::OsslProviderTryLoadEx,
            Api::OsslProviderAddBuiltin,
            Api::OsslProviderGet0Dispatch,
            Api::OsslProviderQueryOperation,
            Api::OpenSslInitCrypto,
            Api::OpenSslVersionMajor,
            Api::EvpMdFetch,
            Api::EvpCipherFetch,
            Api::EvpMacFetch,
            Api::EvpKdfFetch,
            Api::EvpSignatureFetch,
            Api::EvpKemFetch,
            Api::EvpDigestInitEx,
            Api::EvpDigestInitEx2,
            Api::EvpDigestUpdate,
            Api::EvpDigestFinalEx,
            Api::EvpEncryptInitEx,
            Api::EvpEncryptInitEx2,
            Api::EvpEncryptUpdate,
            Api::EvpEncryptFinalEx,
            Api::EvpDecryptInitEx,
            Api::EvpDecryptInitEx2,
            Api::EvpDecryptUpdate,
            Api::EvpDecryptFinalEx,
            Api::EvpCipherInitEx,
            Api::EvpCipherUpdate,
            Api::EvpCipherFinalEx,
            Api::EvpMacInit,
            Api::EvpMacUpdate,
            Api::EvpMacFinal,
            Api::EvpKdfDerive,
            Api::EvpPkeySign,
            Api::EvpPkeyVerify,
            Api::EvpPkeyEncrypt,
            Api::EvpPkeyDecrypt,
            Api::EvpPkeyDerive,
            Api::EvpDigestSignFinal,
            Api::EvpDigestVerifyFinal,
            Api::EvpDigestSign,
            Api::EvpDigestVerify,
            Api::EvpRandGenerate,
            Api::EvpPkeyEncapsulate,
            Api::EvpPkeyDecapsulate,
            Api::EvpPkeyKeygenInit,
            Api::EvpPkeyKeygen,
            Api::EvpPkeyParamgenInit,
            Api::EvpPkeyParamgen,
            Api::EvpPkeyDeriveInit,
            Api::EvpPkeyCheck,
            Api::EvpPkeyPublicCheck,
            Api::EvpPkeyParamCheck,
            Api::EvpPkeyCopyParameters,
            Api::EvpDigestSignInit,
            Api::EvpDigestSignUpdate,
            Api::EvpDigestVerifyInit,
            Api::EvpDigestVerifyUpdate,
            Api::EvpQDigest,
            Api::EvpQMac,
            Api::EvpRandNonce,
            Api::EvpRandCtxNew,
            Api::EvpRandCtxFree,
            Api::EvpMdCtxNew,
            Api::EvpMdCtxFree,
            Api::EvpCipherCtxNew,
            Api::EvpCipherCtxFree,
        ]);
        assert_eq!(all.len(), Api::COUNT);
    }

    #[test]
    fn v060_path_keys_round_trip_and_old_docs_default() {
        use super::{
            Architecture, FileVersionStatus, IdentityStatus, LocatorKind, MapsSource, MapsSpelling,
            MapsVerification, ModuleInfo, ModuleRecord, ObjectKind, PathEncoding,
            PathUnavailableReason, VerifiedPath,
        };
        let record = ModuleRecord {
            info: ModuleInfo {
                sha256: "a".repeat(64),
                device: 7,
                inode: 9,
                size_bytes: 100,
                architecture: Architecture::X86_64,
                kind: ObjectKind::OpenSslCompatible,
                exports: vec![],
                depends_on_libcrypto: false,
                depends_on_libssl: false,
                file_soname: None,
                file_openssl_version: None,
                file_version_status: FileVersionStatus::Absent,
            },
            identity_status: IdentityStatus::Verified,
            verified_path: Some(VerifiedPath {
                path: "/usr/lib/x86_64-linux-gnu/libcrypto.so.3".to_string(),
                path_encoding: PathEncoding::Utf8,
                locator_kind: LocatorKind::HostDirect,
                capture_unix_ms: Some(1_700_000_000_000),
            }),
            verified_path_unavailable: None,
            maps_spelling: Some(MapsSpelling {
                spelling: "/usr/lib/x86_64-linux-gnu/libcrypto.so.3".to_string(),
                source: MapsSource::ProcMaps,
                verification: MapsVerification::Unverified,
            }),
        };
        let value = serde_json::to_value(&record).unwrap();
        assert_eq!(value["verified_path"]["locator_kind"], "host_direct");
        assert_eq!(value["maps_spelling"]["verification"], "unverified");
        // v0.5 document (no new keys) still reads; new keys default to None.
        let old = serde_json::json!({
            "info": {
                "sha256": "a".repeat(64), "device": 7, "inode": 9, "size_bytes": 100,
                "architecture": "x86_64", "kind": "openssl_compatible", "exports": [],
                "depends_on_libcrypto": false, "depends_on_libssl": false
            },
            "identity_status": "verified"
        });
        let back: ModuleRecord = serde_json::from_value(old).unwrap();
        assert_eq!(back.verified_path, None);
        assert_eq!(back.maps_spelling, None);
        // New document always carries the keys, even when null.
        let bare = ModuleRecord {
            info: record.info.clone(),
            identity_status: IdentityStatus::LocatorCandidate,
            verified_path: None,
            verified_path_unavailable: Some(PathUnavailableReason::UnverifiedIdentity),
            maps_spelling: None,
        };
        let bare_value = serde_json::to_value(&bare).unwrap();
        assert!(bare_value.get("verified_path").is_some());
        assert!(bare_value.get("verified_path_unavailable").is_some());
        assert!(bare_value.get("maps_spelling").is_some());
        assert!(bare_value["verified_path"].is_null());
    }

    #[test]
    fn inventory_state_words_match_json() {
        for state in [
            super::InventoryState::Complete,
            super::InventoryState::Partial,
            super::InventoryState::Unavailable,
        ] {
            let json = serde_json::to_value(state).unwrap();
            assert_eq!(
                json,
                serde_json::Value::String(state.word().into()),
                "{state:?}"
            );
        }
    }

    #[test]
    fn cumulative_word_ranks_history() {
        assert_eq!(super::cumulative_word(false, false), "clean");
        assert_eq!(super::cumulative_word(true, false), "partial-seen");
        assert_eq!(super::cumulative_word(false, true), "unavailable-seen");
        assert_eq!(super::cumulative_word(true, true), "unavailable-seen");
    }

    #[test]
    fn cumulative_notes_name_first_uncertain_samples_chronologically() {
        assert_eq!(super::cumulative_notes(None, None), "");
        assert_eq!(
            super::cumulative_notes(Some(2), None),
            "note: sample 2 was partial; history remains uncertain\n"
        );
        assert_eq!(
            super::cumulative_notes(None, Some(1)),
            "note: sample 1 was unavailable; history remains uncertain\n"
        );
        // Chronological across tracks: the earlier sample first.
        assert_eq!(
            super::cumulative_notes(Some(4), Some(2)),
            "note: sample 2 was unavailable; history remains uncertain\n\
             note: sample 4 was partial; history remains uncertain\n"
        );
        assert_eq!(
            super::cumulative_notes(Some(2), Some(4)),
            "note: sample 2 was partial; history remains uncertain\n\
             note: sample 4 was unavailable; history remains uncertain\n"
        );
    }

    fn digest_process(pid: u32) -> super::ProcessRecord {
        super::ProcessRecord {
            interval: super::CaptureInterval {
                started_unix_ms: None,
                finished_unix_ms: None,
                elapsed_ns: 0,
            },
            namespaces: super::NamespaceIds::default(),
            pid,
            starttime: 7,
            comm: Some("child".to_string()),
            comm_status: super::IdentityAvailability::Available,
            exe: None,
            exe_status: super::IdentityAvailability::Unreadable,
            modules: vec![super::ModuleRecord {
                info: super::ModuleInfo {
                    sha256: "a".repeat(64),
                    device: 7,
                    inode: 9,
                    size_bytes: 100,
                    architecture: super::Architecture::X86_64,
                    kind: super::ObjectKind::Other,
                    exports: Vec::new(),
                    depends_on_libcrypto: false,
                    depends_on_libssl: false,
                    file_soname: None,
                    file_openssl_version: None,
                    file_version_status: super::FileVersionStatus::Absent,
                },
                identity_status: super::IdentityStatus::Verified,
                verified_path: None,
                verified_path_unavailable: None,
                maps_spelling: None,
            }],
            other_objects: super::OtherCounts::default(),
            provider_activation: super::ObservationState::Unknown,
            provider_interfaces: super::ObservationState::Unknown,
            execution: super::ObservationState::NotObserved,
        }
    }

    #[test]
    fn watched_process_digest_tracks_names_and_evidence_not_capture_time() {
        let base = digest_process(11);
        let same = digest_process(11);
        assert_eq!(
            super::watched_process_digest(&base),
            super::watched_process_digest(&same)
        );
        // Same pid+starttime, renamed comm: a meaningful change.
        let mut renamed = digest_process(11);
        renamed.comm = Some("renamed".to_string());
        assert_ne!(
            super::watched_process_digest(&base),
            super::watched_process_digest(&renamed)
        );
        // Same file, flipped identity: a meaningful change.
        let mut flipped = digest_process(11);
        flipped.modules[0].identity_status = super::IdentityStatus::LocatorCandidate;
        assert_ne!(
            super::watched_process_digest(&base),
            super::watched_process_digest(&flipped)
        );
        // Re-stamped capture time only: NOT a change (per-sample
        // volatility, like `same_module` in the inventory watch).
        let mut a = digest_process(11);
        let mut b = digest_process(11);
        for (slot, stamp) in [(&mut a, Some(100)), (&mut b, Some(200))] {
            slot.modules[0].verified_path = Some(super::VerifiedPath {
                path: "/lib/x.so".to_string(),
                path_encoding: super::PathEncoding::Utf8,
                locator_kind: super::LocatorKind::HostDirect,
                capture_unix_ms: stamp,
            });
        }
        assert_eq!(
            super::watched_process_digest(&a),
            super::watched_process_digest(&b)
        );
    }
}
