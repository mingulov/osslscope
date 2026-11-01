// SPDX-License-Identifier: GPL-3.0-or-later
//! Owned private source maps. Preparation alone cannot mint source eligibility.

use super::{
    ObjectHash, ObservationBudget, ObservationGap,
    objects::source_anchor::SourceAnchor,
    schema::StateReservation,
    source_acquire::{
        ACQUIRE_CORE_RESERVE, AcquisitionOrder, AdoptedLinks, AnchorReceipt, DomainIndex,
        EnrollmentReceipt, EntryReceipt, GuardLedger, GuardLife, HostIds, OriginalCustody,
        ReadyReceipt, RetainedSourceRoots,
    },
};
use crate::{loader, observation_memory::MemoryLease, writer_gate::WriterGate};
/// Attribution contract (typed admission/bind shapes, REL kinds, control
/// cell). Core-only: safe to include by path like `contract` below.
#[path = "../../crates/bpf-contract/src/attribution.rs"]
#[allow(dead_code)]
mod attr_contract;
#[allow(dead_code)]
#[path = "../../crates/bpf-contract/src/source.rs"]
pub(super) mod contract;
#[cfg(test)]
use contract::SourcePair;
use contract::{SourceConfig, SourceControl, SourceDomain, SourceObserver, SourceRequest};
use std::{
    collections::BTreeMap,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

// Existing namespace/map owner, two shared-map FDs and pairing/domain-map owners.
const HOST_OWNER_BYTES: usize = 4096 + 4 * crate::writer_gate::INJECTION_BYTES;
pub(super) const CONTROL_MAPS: [loader::MapSpec; 2] = [
    spec("ATTR_STATE", 2, 4, 64, 1),
    spec("SOURCE_CONFIG", 2, 4, 8, 1),
];
// Private REL is available to BPF injection only, never a host readback surface.
// The 12 producer maps join the 7 source maps through the shared
// `loader::PRODUCER_MAPS` table (`PRODUCER_MAPS[0]` is REL, already the
// first entry here, so only [1..12] extend the array).
pub(super) const MAPS: [loader::MapSpec; 18] = [
    spec("REL", 1, 48, 256, 8192),
    spec("SOURCE_GUARD", 1, 8, 16, 8192),
    spec("SOURCE_REQUEST", 1, 8, 112, 4096),
    spec("SOURCE_PAIR", 2, 4, 128, 1),
    spec("SOURCE_DOMAIN", 1, 4, 64, 64),
    spec("SOURCE_OBSERVER", 2, 4, 48, 1),
    spec("ITER_SLOT", 6, 4, 264, 2),
    loader::PRODUCER_MAPS[1],
    loader::PRODUCER_MAPS[2],
    loader::PRODUCER_MAPS[3],
    loader::PRODUCER_MAPS[4],
    loader::PRODUCER_MAPS[5],
    loader::PRODUCER_MAPS[6],
    loader::PRODUCER_MAPS[7],
    loader::PRODUCER_MAPS[8],
    loader::PRODUCER_MAPS[9],
    loader::PRODUCER_MAPS[10],
    loader::PRODUCER_MAPS[11],
];
const fn spec(
    name: &'static str,
    map_type: u32,
    key: u32,
    value: u32,
    entries: u32,
) -> loader::MapSpec {
    loader::MapSpec {
        name,
        map_type,
        key_size: key,
        value_size: value,
        max_entries: entries,
        flags: 0,
    }
}
fn iterator_reservation(class: u32, cpus: usize) -> Option<usize> {
    if cpus == 0 || ![16, 32, 64, 96, 128, 192, 256, 512, 1024, 2048, 4096].contains(&class) {
        return None;
    }
    let class = class as usize;
    let (low, high) = if class <= 256 {
        (32, 96)
    } else {
        ((8192 / class).max(1), (24576 / class).max(3))
    };
    let batch = ((high - low) / 4 * 3).max(1);
    let per_cpu = 2usize
        .checked_mul(high + batch + 1)?
        .checked_mul(class)?
        .checked_add(65_536)?;
    8192usize
        .checked_mul(class)?
        .checked_add(cpus.checked_mul(per_cpu)?)
}
fn map_reservation(cpus: usize) -> Option<usize> {
    MAPS.iter().try_fold(0usize, |sum, map| {
        sum.checked_add(map.reservation_bytes(cpus)?)
    })
}
fn source_reservation(class: u32, cpus: usize) -> Option<usize> {
    iterator_reservation(class, cpus)?
        .checked_add(map_reservation(cpus)?)?
        .checked_add(HOST_OWNER_BYTES)?
        .checked_add(ACQUIRE_CORE_RESERVE)
}
fn reserve_source(
    budget: &ObservationBudget,
    class: u32,
    cpus: usize,
) -> Result<SourceCapacity, ObservationGap> {
    let state =
        budget.reserve_state(source_reservation(class, cpus).ok_or(ObservationGap::StateLimit)?)?;
    // The outer watch already reserves this component's64MiB host/state
    // ceiling. Add actual new map capacities just as for its legacy maps;
    // neither this lease nor the component reservation measures kernel RSS.
    let watch_maps = budget
        .memory
        .as_ref()
        .map(|pool| {
            pool.reserve(map_reservation(cpus).ok_or(ObservationGap::StateLimit)?)
                .ok_or(ObservationGap::StateLimit)
        })
        .transpose()?;
    Ok(SourceCapacity {
        _state: state,
        _watch_maps: watch_maps,
    })
}
struct SourceCapacity {
    _state: StateReservation,
    _watch_maps: Option<MemoryLease>,
}
fn source_configuration(page: i64, pending_limit: usize) -> Result<SourceConfig, ObservationGap> {
    let page = u64::try_from(page).map_err(|_| ObservationGap::BpfUnavailable)?;
    if page < 2 || !page.is_power_of_two() {
        return Err(ObservationGap::BpfUnavailable);
    }
    if !(2..=4096).contains(&pending_limit) {
        return Err(ObservationGap::PendingLimit);
    }
    Ok(SourceConfig {
        page_shift: page.trailing_zeros(),
        pending_limit: pending_limit as u32,
    })
}
fn check(
    budget: &ObservationBudget,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<(), ObservationGap> {
    if cancel.load(Ordering::Relaxed) || Instant::now() >= deadline {
        return Err(ObservationGap::SnapshotLag);
    }
    budget.checkpoint()
}

/// Initial mandatory loader owns both maps. Initialize once while ADMIT is
/// closed; optional source preparation may later duplicate only these exact FDs.
pub(super) fn initialize_controls(
    loaded: &loader::Loaded,
    gate: &WriterGate,
    pending_limit: usize,
) -> Result<(), ObservationGap> {
    if !gate.preparing() {
        return Err(ObservationGap::Invalidated);
    }
    let config = source_configuration(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }, pending_limit)
        .unwrap_or(SourceConfig {
            page_shift: 0,
            pending_limit: 0,
        });
    let control = SourceControl::PREPARED;
    for (spec, value) in CONTROL_MAPS.into_iter().zip([
        // repr(C), size-asserted records with no implicit padding.
        unsafe { std::slice::from_raw_parts((&control as *const SourceControl).cast(), 64) },
        unsafe { std::slice::from_raw_parts((&config as *const SourceConfig).cast(), 8) },
    ]) {
        let fd = loaded
            .maps
            .get(spec.name)
            .ok_or(ObservationGap::InvalidObject)?;
        let map =
            loader::BorrowedMap::new(fd.as_fd()).map_err(|_| ObservationGap::BpfUnavailable)?;
        map.shape(
            &[spec.map_type],
            spec.key_size as usize,
            spec.value_size as usize,
        )
        .map_err(|_| ObservationGap::InvalidObject)?;
        if map.info.max_entries != 1 || map.info.flags != 0 {
            return Err(ObservationGap::InvalidObject);
        }
        for name in ["observation_entry", "observation_return"] {
            // Return consumes only ATTR_STATE; entry also consumes the frozen limit.
            if spec.name == "SOURCE_CONFIG" && name == "observation_return" {
                continue;
            }
            let program = loaded
                .progs
                .get(name)
                .ok_or(ObservationGap::InvalidObject)?;
            if !ossl_bpf_sys::prog_map_ids(program.as_raw_fd())
                .map_err(|_| ObservationGap::BpfUnavailable)?
                .contains(&map.info.id)
            {
                return Err(ObservationGap::InvalidObject);
            }
        }
        // Exact checked key/value dimensions above; both slices stay live for
        // the synchronous syscall, before any writer can enter this map.
        unsafe { ossl_bpf_sys::map_update_elem(fd.as_raw_fd(), &0u32.to_ne_bytes(), value, 0) }
            .map_err(|_| ObservationGap::BpfUnavailable)?;
    }
    ossl_bpf_sys::map_freeze(loaded.maps["SOURCE_CONFIG"].as_raw_fd())
        .map_err(|_| ObservationGap::BpfUnavailable)
}

/// Non-Send through its retained gate/account. Host initializes safe cells only
/// before writers; preparing these maps grants no registration or READY witness.
/// The owner retains the validated unloaded roots plus the pure acquisition
/// core (IDs, guard ledger, domain index, order). No root loads, no mode
/// change and no target attachment happen here; those need the phase-2 lease.
/// Native-lease gate for source acquisition. Production constructs `Disabled`
/// (byte-identical behavior: mode stays 0, roots unloaded, no triggers);
/// owned native qualification constructs `Enabled` with owned-target inputs.
/// The lease never leaves owned contexts: owned TMPDIR/targets, owned
/// workloads, host and floor kernels only.
pub(crate) enum SourceAcquisitionLease {
    Disabled,
    /// Only the owned native qualification tests can construct this variant:
    /// `NativeSourceParams` has private fields and its sole constructor is
    /// `#[cfg(test)]`, so a non-test build cannot name a value to wrap here.
    /// Production matches on the lease but can only ever observe `Disabled`.
    #[allow(dead_code)]
    Enabled(NativeSourceParams),
}

/// Owned inputs for one acquiring session. The target file doubles as the
/// anchor object: anchor and registration rows join on its single inode, so
/// no copy or second path may be substituted after admission.
///
/// Fields are private and the sole constructor is test-only, which makes
/// `SourceAcquisitionLease::Enabled` unconstructible outside `#[cfg(test)]`
/// by construction rather than by convention. Production code reads claimed
/// inputs through the accessors below (claim-vs-truth verification) but can
/// never mint the claims themselves.
/// One claimed attachment: the caller's (target, offset, pid) triple,
/// verified against one distinct retained startup attachment.
pub(crate) struct NativeSourceClaim {
    target: std::path::PathBuf,
    link_offset: u64,
    child_pid: u32,
}

impl NativeSourceClaim {
    pub(crate) fn target(&self) -> &std::path::Path {
        &self.target
    }
    pub(crate) fn link_offset(&self) -> u64 {
        self.link_offset
    }
    pub(crate) fn child_pid(&self) -> u32 {
        self.child_pid
    }
}

pub(crate) struct NativeSourceParams {
    claims: Vec<NativeSourceClaim>,
}

impl NativeSourceParams {
    /// Test-only claim constructor for the owned native qualification.
    /// Unavailable in non-test builds, which is what keeps `Enabled`
    /// out of production paths.
    #[cfg(test)]
    pub(crate) fn for_test(target: std::path::PathBuf, link_offset: u64, child_pid: u32) -> Self {
        Self {
            claims: vec![NativeSourceClaim {
                target,
                link_offset,
                child_pid,
            }],
        }
    }
    /// Test-only multi-attachment claim constructor: one triple per
    /// claimed attachment, matched in order against distinct retained
    /// startup attachments. Exact count: over/under-claimed orders
    /// refuse.
    #[cfg(test)]
    pub(crate) fn for_test_multi(claims: Vec<(std::path::PathBuf, u64, u32)>) -> Self {
        Self {
            claims: claims
                .into_iter()
                .map(|(target, link_offset, child_pid)| NativeSourceClaim {
                    target,
                    link_offset,
                    child_pid,
                })
                .collect(),
        }
    }
    pub(crate) fn claims(&self) -> &[NativeSourceClaim] {
        &self.claims
    }
}

/// Structural receipts for the pre-open enablement step.
#[allow(dead_code)]
pub(crate) struct RootsEnabled {
    pub programs: usize,
    pub links: usize,
    pub lifecycle: usize,
    pub mode_before: u64,
    pub mode_after: u64,
    pub typed_programs: usize,
}

/// One typed-site admission request. The caller verified freshness and
/// mints every ID; the owner binds them to planned domain coordinates.
/// `source_epoch` is the session anchor's epoch: the typed cookie's
/// registration and READY rows join that anchor, so they must carry its
/// epoch (the kernel checks the anchor guard under the request epoch).
pub(super) struct TypedAdmissionRequest {
    pub cookie: u64,
    pub site_id: u64,
    pub role_id: u32,
    pub public_api_id: u32,
    pub operation: u32,
    pub function: u32,
    pub tgid: u32,
    pub object_id: u64,
    pub object_sha256: [u8; 32],
    pub source_epoch: u64,
}

/// What the admission programmed, for the caller's records and receipts.
/// Admission alone grants no source authority: guards go LIVE and READY
/// publishes only through the per-cookie registration protocol that runs
/// after this returns.
pub(super) struct TypedAdmissionReceipts {
    pub cookie: u64,
    pub site_id: u64,
    pub source_epoch: u64,
    pub process_incarnation: u64,
    pub image_epoch: u64,
}

/// Shared acquisition context for every typed capability: the LIVE session
/// anchor every typed registration joins plus the enrolled observer key
/// and the armed domain coordinates. All typed registrations under one
/// anchor list as required capabilities in the single acquisition order;
/// the held child releases only after READY published for every one.
pub(crate) struct TypedAcquisitionScope {
    pub anchor: AnchorEstablished,
    pub host_key: u64,
    pub incarnation: u64,
    pub planned_image: u64,
}

/// Producer control coordinates, retained by the session for the final
/// cut-coordinate cross-check.
pub(super) struct ProducerControlProgrammed {
    pub session_id: u64,
    pub admission_epoch: u64,
    pub cut_id: u64,
}

/// Target-domain configuration minted for one acquisition. Fields are
/// consumed by the native qualification through the acquisition receipts.
#[allow(dead_code)]
pub(crate) struct DomainArmed {
    pub tgid: u32,
    pub incarnation: u64,
    pub original: u64,
    pub planned: u64,
}

/// Anchor identity established for one acquisition. Fields are consumed
/// by the native qualification through the acquisition receipts. Copied
/// into the typed acquisition scope so every typed capability joins this
/// same anchor without re-reading it.
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub(crate) struct AnchorEstablished {
    pub anchor_id: u64,
    pub epoch: u64,
    pub object_id: u64,
    pub sequence: u64,
    pub hash: [u8; 32],
}

/// Registration identity adopted for one acquisition.
#[derive(Clone, Copy)]
pub(crate) struct RegistrationAdopted {
    pub registration_id: u64,
}

/// Per-attachment establishment within a multi-attachment order, in
/// admission (claim) order: each attachment's cookie, offset, shared
/// file anchor, own registration and own READY sequence. Field reads
/// happen in the native qualification that consumes these receipts.
#[allow(dead_code)]
pub(crate) struct AttachmentEstablished {
    pub site_cookie: u64,
    pub link_offset: u64,
    pub anchor: AnchorEstablished,
    pub registration: RegistrationAdopted,
    pub ready_sequence: u64,
}

/// Structural receipts for one complete acquisition: every identity the
/// native run must cite. Field reads happen in the native qualification that
/// consumes these receipts.
#[allow(dead_code)]
pub(crate) struct SourceAcquisitionReceipts {
    pub host_key: u64,
    pub site_cookie: u64,
    pub link_offset: u64,
    pub domain: DomainArmed,
    pub anchor: AnchorEstablished,
    pub registration: RegistrationAdopted,
    pub ready_sequence: u64,
    pub adopted_links: usize,
    /// Every legacy attachment the order established, in admission
    /// order. The scalar fields above repeat the first attachment's
    /// (they are the whole order for single-attachment leases).
    pub attachments: Vec<AttachmentEstablished>,
    /// Retains the acquisition-peak charge (ER-S2-I2) for the
    /// returned `attachments` storage: session teardown cannot
    /// release it early, and dropping these receipts releases it
    /// exactly when the returned storage frees. `None` only for the
    /// Disabled inert path, which charges nothing and returns no
    /// attachments.
    pub acquisition_buffers: Option<StateReservation>,
}

impl SourceAcquisitionReceipts {
    /// Test-only readback of the shared state-spent through the
    /// retained acquisition charge (`None` for the uncharged
    /// Disabled inert receipts).
    #[cfg(test)]
    pub(crate) fn retained_state_spent_test(&self) -> Option<usize> {
        self.acquisition_buffers
            .as_ref()
            .map(StateReservation::spent_test)
    }
}

/// Structural receipts for the explicit source close.
#[allow(dead_code)]
pub(crate) struct SourceCloseReceipts {
    pub guards_retired: usize,
    pub guards_abandoned: usize,
    pub domains_retired: usize,
    pub order_refused: bool,
    pub cut_confirmed: bool,
    pub first_error: Option<ObservationGap>,
}

/// Conservative caller-budget charges for the multi-attachment order
/// buffers (ER-S2-I2). Both phases charge through the caller budget
/// before allocating, so a tight budget refuses with `StateLimit`
/// before any kernel effect. The admission charge is permanent: its
/// matching buffers are transient to acquisition (freed while the
/// session still runs), so permanence only over-charges. The
/// acquisition charge instead covers the RETURNED attachment vector,
/// which outlives session teardown: `acquire_source_after_open` holds
/// it as a `StateReservation` owned by the returned
/// `SourceAcquisitionReceipts`, so the charge survives teardown and
/// releases exactly when the receipts do. Each formula is 2x the
/// capacity-measured heap plus a 1 KiB base covering vector shells
/// and allocator rounding, in the `plan_arrays_charge` style. `None`
/// on overflow (fail closed).
///
/// Admission peak for `n` claimed attachments: the `matched` bitmap, the
/// admitted-sites vector, and one cloned 64-byte artifact hash per site.
pub(crate) fn multi_attachment_admission_charge(n: usize) -> Option<usize> {
    let per_site = 1usize
        .checked_add(std::mem::size_of::<AdmittedSourceSite>())?
        .checked_add(64)?;
    let heap = n.checked_mul(per_site)?;
    1024usize.checked_add(heap.checked_mul(2)?)
}

/// Acquisition peak for `n` admitted legacy attachments: the scope,
/// registration, sequence and returned-attachment vectors, the transient
/// backing-identity scratch, and one hash heap per scope (conservatively
/// re-charged even though the admission hash moves into the scope).
pub(crate) fn multi_attachment_acquisition_charge(n: usize) -> Option<usize> {
    let per_site = std::mem::size_of::<RequestScope>()
        .checked_add(64)?
        .checked_add(std::mem::size_of::<RegistrationAdopted>())?
        .checked_add(std::mem::size_of::<u64>())?
        .checked_add(std::mem::size_of::<AttachmentEstablished>())?
        .checked_add(std::mem::size_of::<(u64, u64)>())?;
    let heap = n.checked_mul(per_site)?;
    1024usize.checked_add(heap.checked_mul(2)?)
}

/// Decode a validated artifact hash to its raw bytes. Runs only after a
/// fault-safe capture proved the mapped bytes hash to this exact value, so
/// the result names the anchored mapping, never a re-read.
pub(super) fn decode_object_hash_hex(expected: &ObjectHash) -> Result<[u8; 32], ObservationGap> {
    fn hex_val(byte: u8) -> Result<u8, ObservationGap> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(ObservationGap::Invalidated),
        }
    }
    let hex = String::from(expected.clone());
    let digits = hex.as_bytes();
    if digits.len() != 64 {
        return Err(ObservationGap::Invalidated);
    }
    let mut out = [0u8; 32];
    for (i, pair) in digits.chunks_exact(2).enumerate() {
        out[i] = hex_val(pair[0])? << 4 | hex_val(pair[1])?;
    }
    Ok(out)
}

pub(super) struct SourceOwner {
    // Declared first so retained links/programs release before maps on drop.
    _roots: RetainedSourceRoots,
    _adopted: Vec<OwnedFd>,
    // Retained anchor object custody: the observer's own read-only private
    // full-file mapping (the VMA-join backing) plus its pinned backing
    // file, via the shared fault-safe capture path. Shared (`Rc`) with
    // the typed-staging anchor for the same file when it verifies, so
    // the mapping is captured and charged once; a fresh capture is
    // otherwise retained alone. The anchor's raw mapping pointer keeps
    // the owner off Send: the serialized source owner thread is the
    // only accessor.
    _anchor: Option<Rc<SourceAnchor>>,
    _anchor_id: Option<u64>,
    _registration_ids: Vec<u64>,
    _domain_tgids: Vec<u32>,
    _mode: Option<(u64, u64)>,
    _control: Option<ProducerControlProgrammed>,
    #[cfg(test)]
    _fail_next_retire: std::cell::Cell<bool>,
    /// Test-only one-shot typed-registration fault injection: the next
    /// typed-range ENTRY (resp. RETURN) request arms with a corrupted file
    /// offset, so the kernel refuses the mismatched registration with a
    /// genuine refused receipt. Legacy-range scopes never consult these.
    #[cfg(test)]
    _fail_typed_entry: std::cell::Cell<bool>,
    #[cfg(test)]
    _fail_typed_return: std::cell::Cell<bool>,
    /// Test-only readback of the most recently minted typed-range
    /// registration ID (set at mint time, whatever the outcome), so
    /// refusal controls can pin the exact ledger state of the failed
    /// capability. Zero when no typed registration was attempted.
    #[cfg(test)]
    _last_typed_registration: std::cell::Cell<u64>,
    _last_error: Option<String>,
    _maps: BTreeMap<&'static str, OwnedFd>,
    _namespace: File,
    _gate: WriterGate,
    _capacity: SourceCapacity,
    _ids: HostIds,
    _ledger: GuardLedger,
    _domains: DomainIndex,
    _order: AcquisitionOrder,
}
impl SourceOwner {
    pub(super) fn prepare(
        budget: &ObservationBudget,
        kernel: &loader::SourceKernel,
        gate: &WriterGate,
        loaded: &loader::Loaded,
        source_prepared: &mut loader::Prepared,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<Self, ObservationGap> {
        if !gate.preparing() {
            return Err(ObservationGap::Invalidated);
        }
        // Admit the exact source half before reserving or acquiring anything;
        // a malformed half refuses typed-source preparation fail-closed.
        RetainedSourceRoots::check(source_prepared, kernel.registration_btf_id())?;
        check(budget, deadline, cancel)?;
        source_configuration(
            unsafe { libc::sysconf(libc::_SC_PAGESIZE) },
            budget.limits.max_pending_calls,
        )?;
        let cpus = aya::util::nr_cpus().map_err(|_| ObservationGap::StateLimit)?;
        let capacity = reserve_source(budget, kernel.iterator_class(), cpus)?;
        crate::lifecycle_producer::note_acquisition()
            .map_err(|_| ObservationGap::BackingUnavailable)?;
        let namespace =
            File::open("/proc/self/ns/pid").map_err(|_| ObservationGap::NamespaceChanged)?;
        let ns = namespace
            .metadata()
            .map_err(|_| ObservationGap::NamespaceChanged)?;
        let pid = u64::from(std::process::id());
        let tid = u64::try_from(unsafe { libc::syscall(libc::SYS_gettid) })
            .map_err(|_| ObservationGap::NamespaceChanged)?;
        if tid == 0 || tid > u32::MAX as u64 || pid == 0 {
            return Err(ObservationGap::NamespaceChanged);
        }
        let observer_pid = u32::try_from(pid).map_err(|_| ObservationGap::NamespaceChanged)?;
        let observer = SourceObserver {
            namespace_device: ns.dev(),
            namespace_inode: ns.ino(),
            local_pid_tgid: (pid << 32) | tid,
            // Enrollment remains unarmed until actual source writers and an
            // owned observer-only trigger are ready. Never guess host PID/TID.
            nonce: 0,
            host_pid_tgid: 0,
            state: 0,
        };
        let mut maps = BTreeMap::new();
        for map in MAPS {
            check(budget, deadline, cancel)?;
            crate::lifecycle_producer::note_acquisition()
                .map_err(|_| ObservationGap::BpfUnavailable)?;
            let fd = ossl_bpf_sys::map_create(
                map.map_type,
                map.key_size,
                map.value_size,
                map.max_entries,
                None,
                map.name,
            )
            .map_err(|_| ObservationGap::BpfUnavailable)?;
            maps.insert(map.name, fd);
        }
        for spec in CONTROL_MAPS {
            check(budget, deadline, cancel)?;
            let original = loaded
                .maps
                .get(spec.name)
                .ok_or(ObservationGap::InvalidObject)?;
            let original_map = loader::BorrowedMap::new(original.as_fd())
                .map_err(|_| ObservationGap::BpfUnavailable)?;
            original_map
                .shape(
                    &[spec.map_type],
                    spec.key_size as usize,
                    spec.value_size as usize,
                )
                .map_err(|_| ObservationGap::InvalidObject)?;
            if original_map.info.max_entries != 1 || original_map.info.flags != 0 {
                return Err(ObservationGap::InvalidObject);
            }
            crate::lifecycle_producer::note_acquisition()
                .map_err(|_| ObservationGap::BpfUnavailable)?;
            let duplicate = original
                .try_clone()
                .map_err(|_| ObservationGap::BpfUnavailable)?;
            if loader::BorrowedMap::new(duplicate.as_fd())
                .map_err(|_| ObservationGap::BpfUnavailable)?
                .info
                .id
                != original_map.info.id
            {
                return Err(ObservationGap::InvalidObject);
            }
            maps.insert(spec.name, duplicate);
        }
        // These repr(C) records have compile-time checked sizes and no padding. No
        // private REL value, pointer or target operand is read back by the host.
        unsafe {
            let observer_bytes =
                std::slice::from_raw_parts((&observer as *const SourceObserver).cast(), 48);
            ossl_bpf_sys::map_update_elem(
                maps["SOURCE_OBSERVER"].as_raw_fd(),
                &0u32.to_ne_bytes(),
                observer_bytes,
                0,
            )
            .map_err(|_| ObservationGap::BpfUnavailable)?;
        }
        check(budget, deadline, cancel)?;
        // Move the checked half into the owner. Nothing mutated it since the
        // check above: this function holds the only `&mut` while ADMIT stays
        // closed, so retention cannot admit a different shape than checked.
        let prepared = std::mem::replace(
            source_prepared,
            loader::Prepared {
                progs: Vec::new(),
                maps: Vec::new(),
            },
        );
        Ok(Self {
            _roots: RetainedSourceRoots::retain(
                prepared,
                kernel.registration_btf_id(),
                observer_pid,
            ),
            _adopted: Vec::new(),
            _anchor: None,
            _anchor_id: None,
            _registration_ids: Vec::new(),
            _domain_tgids: Vec::new(),
            _mode: None,
            _control: None,
            #[cfg(test)]
            _fail_next_retire: std::cell::Cell::new(false),
            #[cfg(test)]
            _fail_typed_entry: std::cell::Cell::new(false),
            #[cfg(test)]
            _fail_typed_return: std::cell::Cell::new(false),
            #[cfg(test)]
            _last_typed_registration: std::cell::Cell::new(0),
            _last_error: None,
            _maps: maps,
            _namespace: namespace,
            _gate: gate.clone(),
            _capacity: capacity,
            _ids: HostIds::new(),
            _ledger: GuardLedger::new(),
            _domains: DomainIndex::new(),
            _order: AcquisitionOrder::new(),
        })
    }
}

/// Required ENTRY/RETURN link kinds for one 5A registration.
const REQUIRED_LINK_MASK: u32 = 3;

/// Admitted site truth for one acquisition, derived by the session
/// orchestrator from the single retained pre-exec startup attachment. The
/// target file is a dup of the site's retained descriptor (same open file
/// description, never a re-resolved path); the offset, cookie and artifact
/// hash are the site's own admitted values. The caller-supplied
/// [`NativeSourceParams`] are verified against this truth before any kernel
/// effect and never used as authority afterwards.
pub(super) struct AdmittedSourceSite {
    pub tgid: u32,
    pub site_cookie: u64,
    pub link_offset: u64,
    pub target: File,
    pub expected_artifact: ObjectHash,
    /// Backing identity the admission check proved (claim path
    /// device/inode equal the retained site's): the order groups
    /// attachments by file without re-statting.
    pub device: u64,
    pub inode: u64,
}

/// Request scope threaded through one acquisition's phases: the admitted
/// site cookie, offset, target custody and artifact identity, the observer
/// host key, and the minted domain join keys. Built by the session
/// orchestrator from admitted session truth only.
pub(super) struct RequestScope {
    pub site_cookie: u64,
    pub host_key: u64,
    pub incarnation: u64,
    pub planned_image: u64,
    pub link_offset: u64,
    pub target_pid: u32,
    pub target: File,
    pub expected_artifact: ObjectHash,
}

impl SourceOwner {
    fn map(&self, name: &str) -> Result<loader::BorrowedMap<'_>, ObservationGap> {
        let fd = self._maps.get(name).ok_or(ObservationGap::InvalidObject)?;
        loader::BorrowedMap::new(fd.as_fd()).map_err(|_| ObservationGap::BpfUnavailable)
    }
    fn guard_fd(&self) -> Result<std::os::fd::RawFd, ObservationGap> {
        self._maps
            .get("SOURCE_GUARD")
            .map(AsRawFd::as_raw_fd)
            .ok_or(ObservationGap::InvalidObject)
    }
    /// Current thread coordinates: (pid, tid, (pid<<32)|tid). Every trigger
    /// syscall in the acquisition runs on this serialized owner thread, so
    /// this key addresses exactly the armed request rows.
    fn current_host_key() -> Result<(u32, u32, u64), ObservationGap> {
        let pid = std::process::id();
        let tid = u64::try_from(unsafe { libc::syscall(libc::SYS_gettid) })
            .map_err(|_| ObservationGap::NamespaceChanged)?;
        if pid == 0 || tid == 0 || tid > u32::MAX as u64 {
            return Err(ObservationGap::NamespaceChanged);
        }
        Ok((pid, tid as u32, (u64::from(pid) << 32) | tid))
    }
    fn arm_request(&mut self, key: u64, request: &SourceRequest) -> Result<(), ObservationGap> {
        debug_assert_eq!(size_of::<SourceRequest>(), 112);
        // Never arm over a live request: a previous arm with a pending
        // verdict proves a skipped trigger, and replacing it would break the
        // entry/exit pairing evidence.
        if let Some(previous) = self.try_read_request(key)? {
            if previous.verdict == 0 && previous.nonce != 0 {
                self._last_error = Some(format!(
                    "request not idle: phase {} nonce {:#x} entry {} exit {} verdict {}",
                    previous.phase,
                    previous.nonce,
                    previous.entry_count,
                    previous.exit_count,
                    previous.verdict
                ));
                return Err(ObservationGap::Invalidated);
            }
        }
        let map = self.map("SOURCE_REQUEST")?;
        map.shape(&[1], 8, 112)
            .map_err(|_| ObservationGap::InvalidObject)?;
        // Exact 112-byte repr(C) record; the slice stays live for the
        // synchronous syscall.
        let bytes = unsafe {
            std::slice::from_raw_parts((request as *const SourceRequest).cast::<u8>(), 112)
        };
        map.update(&key.to_ne_bytes(), bytes)
            .map_err(|_| ObservationGap::BpfUnavailable)
    }
    fn try_read_request(&self, key: u64) -> Result<Option<SourceRequest>, ObservationGap> {
        let map = self.map("SOURCE_REQUEST")?;
        map.shape(&[1], 8, 112)
            .map_err(|_| ObservationGap::InvalidObject)?;
        let mut request: SourceRequest = SourceRequest::default();
        let bytes = unsafe {
            std::slice::from_raw_parts_mut((&mut request as *mut SourceRequest).cast::<u8>(), 112)
        };
        match map.lookup(&key.to_ne_bytes(), bytes) {
            Ok(()) => Ok(Some(request)),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
            Err(_) => Err(ObservationGap::BpfUnavailable),
        }
    }
    fn read_request(&self, key: u64) -> Result<SourceRequest, ObservationGap> {
        self.try_read_request(key)?
            .ok_or(ObservationGap::Invalidated)
    }
    /// Disarm a completed synchronous request: delete its SOURCE_REQUEST row
    /// after the terminal receipt validated. An absent row is the normal
    /// unarmed state — unrelated registrations stay quiet — while a retained
    /// completed row would refuse the next hook pair on this thread and
    /// terminally poison SOURCE_PAIR. Success path only: incomplete/error
    /// rows keep their terminal refusal and are never disarmed.
    fn disarm_request(&self, key: u64) -> Result<(), ObservationGap> {
        let map = self.map("SOURCE_REQUEST")?;
        map.shape(&[1], 8, 112)
            .map_err(|_| ObservationGap::InvalidObject)?;
        map.delete(&key.to_ne_bytes())
            .map_err(|_| ObservationGap::BpfUnavailable)
    }
    /// Enable source mode 1 exactly once, before the gate opens. The control
    /// row must still be the exact PREPARED bytes (no writer fires before
    /// ADMIT opens); any drift refuses instead of read-modify-write racing a
    /// live writer. Returns (before, after).
    fn enable_mode1(&self) -> Result<(u64, u64), ObservationGap> {
        let map = self.map("ATTR_STATE")?;
        map.shape(&[2], 4, 64)
            .map_err(|_| ObservationGap::InvalidObject)?;
        let mut control = SourceControl::PREPARED;
        let bytes = unsafe {
            std::slice::from_raw_parts_mut((&mut control as *mut SourceControl).cast::<u8>(), 64)
        };
        map.lookup(&0u32.to_ne_bytes(), bytes)
            .map_err(|_| ObservationGap::BpfUnavailable)?;
        let expected = SourceControl::PREPARED;
        let same = unsafe {
            std::slice::from_raw_parts((&expected as *const SourceControl).cast::<u8>(), 64)
                == std::slice::from_raw_parts((&control as *const SourceControl).cast::<u8>(), 64)
        };
        if !same {
            return Err(ObservationGap::Invalidated);
        }
        let before = control.source_mode;
        if before != 0 {
            return Err(ObservationGap::Invalidated);
        }
        control.source_mode = 1;
        let bytes = unsafe {
            std::slice::from_raw_parts((&control as *const SourceControl).cast::<u8>(), 64)
        };
        map.update(&0u32.to_ne_bytes(), bytes)
            .map_err(|_| ObservationGap::BpfUnavailable)?;
        Ok((before, 1))
    }
    /// One synchronous observer-only provisional trigger: the literal 16-byte
    /// NoOp program attached at offset 0 of the observer's own executable.
    /// Registration alone fires the enrolled hooks; the probe never executes.
    /// At most one provisional link is ever in flight.
    fn invoke_provisional_trigger(&mut self, pid: u32) -> Result<(), ObservationGap> {
        let program = self._roots.noop_program_fd()?;
        let exe = std::env::current_exe().map_err(|_| ObservationGap::BackingUnavailable)?;
        let path = std::ffi::CString::new(exe.as_os_str().as_encoded_bytes())
            .map_err(|_| ObservationGap::Invalidated)?;
        let link = ossl_bpf_sys::link_create_uprobe_multi(program, &path, &[0], &[0], pid)
            .map_err(|_| ObservationGap::BpfUnavailable)?;
        self._roots.store_provisional(link)
    }
    /// Pre-open enablement: load and attach the four retained roots under the
    /// closed gate, then enable mode 1. Runs only from the typed-startup path
    /// under an enabled lease; the loader refuses an opened gate and the
    /// mode write refuses a drifted control row, so misuse fails closed with
    /// mode 0 and nothing loaded.
    pub(super) fn enable_roots_pre_open(
        &mut self,
        legacy: &loader::Loaded,
    ) -> Result<RootsEnabled, ObservationGap> {
        let _ = self._last_error.take();
        if !self._gate.preparing() {
            return Err(ObservationGap::Invalidated);
        }
        // The retained half holds registration + typed roots; registration
        // loads attached, typed loads unattached against the same maps.
        // Cloning the small prepared metadata (no FDs) keeps the retained
        // half intact for diagnosis on refusal.
        let (registration, typed) = loader::split_typed_preparation(self._roots.prepared().clone())
            .map_err(|error| {
                self._last_error = Some(format!("{error:#}"));
                ObservationGap::InvalidObject
            })?;
        let loaded = loader::load_source_roots(
            &registration,
            &self._maps,
            legacy,
            self._roots.attach_btf_id(),
            &self._gate,
        )
        .map_err(|error| {
            self._last_error = Some(format!("{error:#}"));
            ObservationGap::BpfUnavailable
        })?;
        if loaded.programs.len() != 4 || loaded.links.len() != 2 || loaded.lifecycle.len() != 2 {
            self._last_error = Some(format!(
                "source load shape: {} programs, {} links, {} lifecycle",
                loaded.programs.len(),
                loaded.links.len(),
                loaded.lifecycle.len()
            ));
            return Err(ObservationGap::Invalidated);
        }
        let typed_programs = loader::load_typed_borrowed(&typed, &self._maps, legacy, &self._gate)
            .map_err(|error| {
                self._last_error = Some(format!("{error:#}"));
                ObservationGap::BpfUnavailable
            })?;
        let typed_count = typed_programs.len();
        self._roots.adopt_typed(typed_programs)?;
        // Control cell last among the loads, before the mode flip below:
        // the producer admits only with all coordinates in place.
        let control = self.program_producer_control().map_err(|gap| {
            self._last_error = Some("producer control refused".to_string());
            gap
        })?;
        self._control = Some(control);
        let receipts = RootsEnabled {
            programs: loaded.programs.len(),
            links: loaded.links.len(),
            lifecycle: loaded.lifecycle.len(),
            mode_before: 0,
            mode_after: 0,
            typed_programs: typed_count,
        };
        self._roots.adopt_loaded(loaded);
        let (before, after) = self.enable_mode1()?;
        if before != 0 || after != 1 {
            return Err(ObservationGap::Invalidated);
        }
        self._mode = Some((before, after));
        Ok(RootsEnabled {
            mode_before: before,
            mode_after: after,
            ..receipts
        })
    }
    /// Record the observed gate opening. The gate must actually be open
    /// (neither preparing nor closed); anything else refuses the order.
    pub(super) fn note_gate_open_observed(&mut self) -> Result<(), ObservationGap> {
        let _ = self._last_error.take();
        if self._gate.preparing() || !self._gate.admitting() {
            return Err(ObservationGap::Invalidated);
        }
        self._order.note_gate_open()
    }
    /// Refuse the acquisition after a phase failure. Best-effort: an already
    /// terminal order stays terminal.
    pub(super) fn refuse_acquisition(&mut self) {
        let _ = self._order.refuse();
    }
    /// The held child may run only after post-adoption READY published.
    pub(super) fn acquisition_ready(&self) -> bool {
        self._order.child_may_release()
    }
    pub(super) fn adopted_link_count(&self) -> usize {
        self._adopted.len()
    }
    /// Borrow one owned map FD for shared injection into the focused
    /// counter (same kernel map, dup'd FD) or for strict final reads.
    /// Only maps this owner created are lendable; anything else refuses.
    pub(super) fn owned_map(
        &self,
        name: &str,
    ) -> Result<std::os::fd::BorrowedFd<'_>, ObservationGap> {
        use std::os::fd::AsFd as _;
        self._maps
            .get(name)
            .map(|owned| owned.as_fd())
            .ok_or(ObservationGap::InvalidObject)
    }
    fn typed_map_fd(&self, name: &str) -> Result<std::os::fd::RawFd, ObservationGap> {
        use std::os::fd::AsRawFd as _;
        self._maps
            .get(name)
            .map(|owned| owned.as_raw_fd())
            .ok_or(ObservationGap::InvalidObject)
    }
    /// Program the producer control cell once, before the gate opens: the
    /// session/cut/admission coordinates (fresh host IDs), initial
    /// relation/loss epochs, first producer ID, and ADMITTED mode. Refuses
    /// if already programmed. Single-writer (enablement runs once) under
    /// the unopened gate, so no writer can race this configuration.
    pub(super) fn program_producer_control(
        &mut self,
    ) -> Result<ProducerControlProgrammed, ObservationGap> {
        if !self._gate.preparing() {
            return Err(ObservationGap::Invalidated);
        }
        let fd = self.typed_map_fd("ATTRIB_CONTROL")?;
        let mut current = [0u8; 64];
        unsafe { ossl_bpf_sys::map_lookup_elem(fd, &0u32.to_ne_bytes(), &mut current) }
            .map_err(|_| ObservationGap::BpfUnavailable)?;
        if current.iter().any(|b| *b != 0) {
            return Err(ObservationGap::Invalidated);
        }
        let session_id = self._ids.fresh()?;
        let admission_epoch = self._ids.fresh()?;
        let cut_id = self._ids.fresh()?;
        let mut value = [0u8; 64];
        value[0..8].copy_from_slice(&attr_contract::PRODUCER_ADMITTED.to_ne_bytes());
        value[8..16].copy_from_slice(&session_id.to_ne_bytes());
        value[16..24].copy_from_slice(&admission_epoch.to_ne_bytes());
        value[24..32].copy_from_slice(&cut_id.to_ne_bytes());
        value[32..40].copy_from_slice(&1u64.to_ne_bytes());
        value[40..48].copy_from_slice(&1u64.to_ne_bytes());
        value[48..56].copy_from_slice(&1u64.to_ne_bytes());
        unsafe {
            ossl_bpf_sys::map_update_elem(fd, &0u32.to_ne_bytes(), &value, ossl_bpf_sys::BPF_ANY)
        }
        .map_err(|_| ObservationGap::BpfUnavailable)?;
        Ok(ProducerControlProgrammed {
            session_id,
            admission_epoch,
            cut_id,
        })
    }
    /// Admit one verified typed site: program its admission and bind
    /// rows, both NOEXIST. The caller verified freshness (revalidated
    /// object, live TGID, armed domain) and mints the cookie, site ID and
    /// artifact ID; this function binds them to the TGID's planned domain
    /// coordinates and the session anchor's epoch. Admission alone grants
    /// no source authority: no guard is created here and no READY row is
    /// written — the cookie's guards go LIVE and its READY publishes only
    /// through the receipt-based registration protocol (ENTRY/RETURN
    /// receipts, FD adoption, kernel phase-4 publication) that the caller
    /// runs next. Without that capability the cookie's operand readers
    /// stay unavailable: every typed callback refuses at the READY gate.
    pub(super) fn admit_typed_site(
        &mut self,
        request: &TypedAdmissionRequest,
    ) -> Result<TypedAdmissionReceipts, ObservationGap> {
        if !self._gate.admitting() {
            return Err(ObservationGap::Invalidated);
        }
        if request.cookie == 0
            || request.site_id == 0
            || request.tgid == 0
            || request.object_id == 0
            || request.source_epoch == 0
        {
            return Err(ObservationGap::Invalidated);
        }
        if !contract::valid_site_cookie(request.cookie) {
            return Err(ObservationGap::Invalidated);
        }
        let (process, image) = self._domains.planned_coordinates(request.tgid)?;
        let epoch = request.source_epoch;
        let admission = attr_contract::TypedAdmission::new(
            request.role_id,
            request.public_api_id,
            request.operation,
            request.function,
            1,
            epoch,
        )
        .ok_or(ObservationGap::Invalidated)?;
        if !admission.valid() {
            return Err(ObservationGap::Invalidated);
        }
        let fd_admission = self.typed_map_fd("TYPED_ADMISSION")?;
        let fd_bind = self.typed_map_fd("SITE_BIND")?;
        let mut site_key = [0u8; 24];
        site_key[0..8].copy_from_slice(&request.cookie.to_ne_bytes());
        site_key[8..16].copy_from_slice(&process.to_ne_bytes());
        site_key[16..24].copy_from_slice(&image.to_ne_bytes());
        let mut admission_value = [0u8; 32];
        admission_value[0..4].copy_from_slice(&admission.role_id.to_ne_bytes());
        admission_value[4..8].copy_from_slice(&admission.public_api_id.to_ne_bytes());
        admission_value[8..12].copy_from_slice(&admission.operation.to_ne_bytes());
        admission_value[12..16].copy_from_slice(&admission.function.to_ne_bytes());
        admission_value[16..24].copy_from_slice(&admission.abi_epoch.to_ne_bytes());
        admission_value[24..32].copy_from_slice(&admission.source_epoch.to_ne_bytes());
        unsafe {
            ossl_bpf_sys::map_update_elem(
                fd_admission,
                &site_key,
                &admission_value,
                ossl_bpf_sys::BPF_NOEXIST,
            )
        }
        .map_err(|_| ObservationGap::BpfUnavailable)?;
        let mut bind_value = [0u8; 56];
        bind_value[0..8].copy_from_slice(&request.site_id.to_ne_bytes());
        bind_value[8..16].copy_from_slice(&epoch.to_ne_bytes());
        bind_value[16..24].copy_from_slice(&request.object_id.to_ne_bytes());
        bind_value[24..56].copy_from_slice(&request.object_sha256);
        unsafe {
            ossl_bpf_sys::map_update_elem(
                fd_bind,
                &site_key,
                &bind_value,
                ossl_bpf_sys::BPF_NOEXIST,
            )
        }
        .map_err(|_| ObservationGap::BpfUnavailable)?;
        Ok(TypedAdmissionReceipts {
            cookie: request.cookie,
            site_id: request.site_id,
            source_epoch: epoch,
            process_incarnation: process,
            image_epoch: image,
        })
    }
    /// Test-only close-failure injection: the next guard retirement in
    /// `close_source` fails with `BpfUnavailable`, exercising the
    /// retain-custody path with real maps and live writers.
    #[cfg(test)]
    pub(super) fn fail_next_guard_retire(&self) {
        self._fail_next_retire.set(true);
    }
    /// Test-only typed-registration fault injection: the next typed-range
    /// ENTRY (resp. RETURN) request arms with a corrupted file offset while
    /// the actual link is created at the true offset, so the kernel refuses
    /// the mismatched registration with a genuine refused receipt. One-shot;
    /// legacy-range scopes never consult these flags.
    #[cfg(test)]
    pub(super) fn fail_next_typed_entry(&self) {
        self._fail_typed_entry.set(true);
    }
    #[cfg(test)]
    pub(super) fn fail_next_typed_return(&self) {
        self._fail_typed_return.set(true);
    }
    /// Test-only readback of the most recently minted typed-range
    /// registration ID, whatever the outcome. Zero when no typed
    /// registration was attempted.
    #[cfg(test)]
    pub(super) fn last_typed_registration_test(&self) -> u64 {
        self._last_typed_registration.get()
    }
    /// Test-only anchor-custody readback.
    #[cfg(test)]
    pub(super) fn anchor_retained_test(&self) -> bool {
        self._anchor.is_some()
    }
    /// Test-only shared-anchor readback: the retained anchor `Rc`, so
    /// controls can prove (via `Rc::ptr_eq`) the owner shares the
    /// staging capture instead of re-capturing the file.
    #[cfg(test)]
    pub(super) fn anchor_rc_test(&self) -> Option<Rc<SourceAnchor>> {
        self._anchor.clone()
    }
    /// Test-only host guard-life readback.
    #[cfg(test)]
    pub(super) fn guard_life_test(&self, id: u64) -> Option<GuardLife> {
        self._ledger.guard_life(id)
    }
    /// Test-only kernel SOURCE_DOMAIN state readback.
    #[cfg(test)]
    pub(super) fn domain_state_test(&self, tgid: u32) -> Result<u64, ObservationGap> {
        let map = self.map("SOURCE_DOMAIN")?;
        map.shape(&[1], 4, 64)
            .map_err(|_| ObservationGap::InvalidObject)?;
        let mut row = SourceDomain {
            process_incarnation: 0,
            original_image: 0,
            planned_image: 0,
            current_image: 0,
            state: 0,
            loss_epoch: 0,
            reserved: [0, 0],
        };
        let bytes = unsafe {
            std::slice::from_raw_parts_mut((&mut row as *mut SourceDomain).cast::<u8>(), 64)
        };
        map.lookup(&tgid.to_ne_bytes(), bytes)
            .map_err(|_| ObservationGap::BpfUnavailable)?;
        Ok(row.state)
    }
    /// Test-only unrelated-registration control: performs a real native
    /// uprobe registration on the observer thread with no armed request and
    /// returns its link (the caller drops it). Against a disarmed row the
    /// hooks stay quiet; against a stale completed row they would refuse and
    /// terminally poison SOURCE_PAIR. The cookie is outside every armed
    /// site-cookie range, so this registration is unrelated by construction.
    #[cfg(test)]
    pub(super) fn fire_unrelated_registration(&self) -> Result<OwnedFd, ObservationGap> {
        let program = self._roots.noop_program_fd()?;
        let (pid, _, _) = Self::current_host_key()?;
        let exe = std::env::current_exe().map_err(|_| ObservationGap::BackingUnavailable)?;
        let path = std::ffi::CString::new(exe.as_os_str().as_encoded_bytes())
            .map_err(|_| ObservationGap::Invalidated)?;
        ossl_bpf_sys::link_create_uprobe_multi(program, &path, &[0], &[0x0BAD_F00D], pid)
            .map_err(|_| ObservationGap::BpfUnavailable)
    }
    /// Test-only disarm readback: true when no SOURCE_REQUEST row exists for
    /// the key (the normal unarmed state after a completed request disarms).
    #[cfg(test)]
    pub(super) fn request_absent_test(&self, key: u64) -> Result<bool, ObservationGap> {
        Ok(self.try_read_request(key)?.is_none())
    }
    /// Test-only SOURCE_PAIR state readback (0 idle, 1 active, 2 terminal).
    #[cfg(test)]
    pub(super) fn pair_state_test(&self) -> Result<u64, ObservationGap> {
        debug_assert_eq!(size_of::<SourcePair>(), 128);
        let map = self.map("SOURCE_PAIR")?;
        map.shape(&[2], 4, 128)
            .map_err(|_| ObservationGap::InvalidObject)?;
        let mut pair = SourcePair::default();
        let bytes = unsafe {
            std::slice::from_raw_parts_mut((&mut pair as *mut SourcePair).cast::<u8>(), 128)
        };
        map.lookup(&0u32.to_ne_bytes(), bytes)
            .map_err(|_| ObservationGap::BpfUnavailable)?;
        Ok(pair.state)
    }
    /// Test-only SOURCE_OBSERVER state readback (2 observed).
    #[cfg(test)]
    pub(super) fn observer_state_test(&self) -> Result<u64, ObservationGap> {
        debug_assert_eq!(size_of::<SourceObserver>(), 48);
        let map = self.map("SOURCE_OBSERVER")?;
        map.shape(&[2], 4, 48)
            .map_err(|_| ObservationGap::InvalidObject)?;
        let mut observer = SourceObserver::default();
        let bytes = unsafe {
            std::slice::from_raw_parts_mut((&mut observer as *mut SourceObserver).cast::<u8>(), 48)
        };
        map.lookup(&0u32.to_ne_bytes(), bytes)
            .map_err(|_| ObservationGap::BpfUnavailable)?;
        Ok(observer.state)
    }
    /// Programmed control coordinates for the final cut cross-check.
    pub(super) fn control_programmed(&self) -> Option<&ProducerControlProgrammed> {
        self._control.as_ref()
    }
    /// Borrow one loaded typed program FD for per-export attach.
    pub(super) fn typed_program_fd(
        &self,
        name: &str,
    ) -> Result<std::os::fd::BorrowedFd<'_>, ObservationGap> {
        self._roots.typed_program(name)
    }
    /// Post-hoc pre-open enablement receipts. Test-called only.
    #[allow(dead_code)]
    pub(super) fn roots_enabled_receipts(&self) -> Option<RootsEnabled> {
        let (before, after) = self._mode?;
        let (programs, links, lifecycle, typed_programs) = self._roots.loaded_counts();
        Some(RootsEnabled {
            programs,
            links,
            lifecycle,
            mode_before: before,
            mode_after: after,
            typed_programs,
        })
    }
    /// Last retained native diagnostic, taken by the qualification harness
    /// after a failure. Production never reads this.
    #[allow(dead_code)]
    pub(super) fn take_last_error(&mut self) -> Option<String> {
        self._last_error.take()
    }
    /// Record an order-level refusal that fired before any owner effect
    /// (admission or order assembly): the close receipts then carry the
    /// refusal diagnosis instead of silence. Overwrites any stale slot:
    /// the latest refusal is the last error.
    pub(super) fn note_refusal(&mut self, detail: String) {
        self._last_error = Some(detail);
    }
    /// Prefix the pending refusal diagnosis with order context (which
    /// multi-attachment claim failed, and where). No-op when no
    /// diagnosis is pending: never invents one.
    pub(super) fn context_last_error(&mut self, context: &str) {
        if let Some(prior) = self._last_error.take() {
            self._last_error = Some(format!("{context}: {prior}"));
        }
    }
    /// Arm the target domain for one held pre-exec child. The TGID must be
    /// stopped (procfs state T) at arm time; the test retains pidfd custody
    /// across the acquisition so the TGID cannot be recycled underneath.
    /// Images are opaque minted join keys at this stage (5B binds real image
    /// identity); incarnation/original/planned are distinct by construction.
    pub(super) fn arm_domain(&mut self, tgid: u32) -> Result<DomainArmed, ObservationGap> {
        let _ = self._last_error.take();
        if tgid == 0 {
            return Err(ObservationGap::Invalidated);
        }
        let stat = std::fs::read_to_string(format!("/proc/{tgid}/stat"))
            .map_err(|_| ObservationGap::NamespaceChanged)?;
        // comm may contain parens: state follows the LAST ')'.
        let after = stat.rsplit(')').next().ok_or(ObservationGap::Invalidated)?;
        let state = after
            .split_whitespace()
            .next()
            .ok_or(ObservationGap::Invalidated)?;
        if state != "T" {
            self._last_error = Some(format!("domain {tgid} not stopped: {state}"));
            return Err(ObservationGap::NamespaceChanged);
        }
        let custody = OriginalCustody::held(tgid)?;
        let incarnation = self._ids.fresh()?;
        let original = self._ids.fresh()?;
        let planned = self._ids.fresh()?;
        self._domains
            .arm(tgid, incarnation, original, planned, &custody)?;
        let row = SourceDomain {
            process_incarnation: incarnation,
            original_image: original,
            planned_image: planned,
            current_image: original,
            state: contract::DOMAIN_ARMED,
            loss_epoch: 0,
            reserved: [0, 0],
        };
        let map = self.map("SOURCE_DOMAIN")?;
        map.shape(&[1], 4, 64)
            .map_err(|_| ObservationGap::InvalidObject)?;
        let bytes =
            unsafe { std::slice::from_raw_parts((&row as *const SourceDomain).cast::<u8>(), 64) };
        map.update(&tgid.to_ne_bytes(), bytes)
            .map_err(|_| ObservationGap::BpfUnavailable)?;
        self._domain_tgids.push(tgid);
        Ok(DomainArmed {
            tgid,
            incarnation,
            original,
            planned,
        })
    }
    /// Enroll this thread as the sole observer: arm the observer row, fire
    /// one provisional trigger, consume the enrollment receipt. Returns the
    /// host request key for every later phase on this thread.
    pub(super) fn enroll_observer(&mut self) -> Result<u64, ObservationGap> {
        let _ = self._last_error.take();
        let (pid, tid, key) = Self::current_host_key()?;
        self._roots.check_observer(pid)?;
        let ns = self
            ._namespace
            .metadata()
            .map_err(|_| ObservationGap::NamespaceChanged)?;
        let nonce = self._ids.fresh()?;
        let observer = SourceObserver {
            namespace_device: ns.dev(),
            namespace_inode: ns.ino(),
            local_pid_tgid: (u64::from(pid) << 32) | u64::from(tid),
            nonce,
            host_pid_tgid: 0,
            state: 1,
        };
        {
            let map = self.map("SOURCE_OBSERVER")?;
            map.shape(&[2], 4, 48)
                .map_err(|_| ObservationGap::InvalidObject)?;
            let bytes = unsafe {
                std::slice::from_raw_parts((&observer as *const SourceObserver).cast::<u8>(), 48)
            };
            map.update(&0u32.to_ne_bytes(), bytes)
                .map_err(|_| ObservationGap::BpfUnavailable)?;
        }
        self._roots.load_noop_program()?;
        self.invoke_provisional_trigger(pid)?;
        let mut observed = SourceObserver {
            namespace_device: 0,
            namespace_inode: 0,
            local_pid_tgid: 0,
            nonce: 0,
            host_pid_tgid: 0,
            state: 0,
        };
        {
            let map = self.map("SOURCE_OBSERVER")?;
            let bytes = unsafe {
                std::slice::from_raw_parts_mut(
                    (&mut observed as *mut SourceObserver).cast::<u8>(),
                    48,
                )
            };
            map.lookup(&0u32.to_ne_bytes(), bytes)
                .map_err(|_| ObservationGap::BpfUnavailable)?;
        }
        drop(self._roots.take_provisional());
        if observed.state != 2 || observed.host_pid_tgid != key || observed.nonce != nonce {
            self._last_error = Some(format!(
                "enrollment receipt: state {} host {:#x} nonce {:#x}",
                observed.state, observed.host_pid_tgid, observed.nonce
            ));
            return Err(ObservationGap::Invalidated);
        }
        let receipt = EnrollmentReceipt::observed(nonce, key)?;
        self._order.note_enrolled(nonce, &receipt)?;
        Ok(key)
    }
    /// Anchor the admitted target file through the shared fault-safe
    /// capture path: bounded chunked self-reads, checkpoints, page/overhead
    /// plus read-budget accounting, and expected-artifact hash validation
    /// against the admitted parsed hash. A truncated or swapped backing
    /// returns an observation gap, never a fault. Then run the phase-1
    /// trigger and advance the anchor guard to LIVE. The file is the
    /// scope's retained admitted-site descriptor, never a re-resolved path.
    pub(super) fn anchor_source(
        &mut self,
        scope: &RequestScope,
        budget: &ObservationBudget,
        candidate: Option<Rc<SourceAnchor>>,
    ) -> Result<AnchorEstablished, ObservationGap> {
        let _ = self._last_error.take();
        // Shared staging anchor when it still proves this scope (same
        // backing, unchanged stamp, same hash): the mapping is captured
        // and charged once. Any mismatch falls back to a fresh capture,
        // which re-proves the current bytes — never a refusal.
        let captured = match candidate {
            Some(shared) if shared.verifies_against(&scope.target, &scope.expected_artifact) => {
                shared
            }
            _ => Rc::new(SourceAnchor::capture(
                &scope.target,
                &scope.expected_artifact,
                budget,
            )?),
        };
        // Capture proved the mapped bytes hash to the admitted value; the
        // receipt names those exact bytes without a second read.
        let hash = decode_object_hash_hex(&scope.expected_artifact)?;
        let mapping = captured.address();
        self._anchor = Some(captured);
        let epoch = self._ids.fresh()?;
        let object_id = self._ids.fresh()?;
        let nonce = self._ids.fresh()?;
        let anchor = self._ledger.mint_anchor(&mut self._ids, epoch, nonce)?;
        let request = SourceRequest {
            nonce,
            anchor_id: anchor,
            object_id,
            source_epoch: epoch,
            site_cookie: 0,
            file_offset: 0,
            observer_anchor_address: mapping,
            phase: contract::PHASE_ANCHOR,
            required_mask: 0,
            entry_count: 0,
            exit_count: 0,
            verdict: 0,
            reserved: 0,
            publication_sequence: 0,
            process_incarnation: scope.incarnation,
            image_epoch: scope.planned_image,
            registration_id: 0,
        };
        if !request.valid_input() {
            self._last_error = Some(format!(
                "anchor valid_input: nonce {nonce:#x} anchor {anchor:#x} obj {object_id:#x} epoch {epoch:#x} addr {:#x} inc {:#x} img {:#x}",
                request.observer_anchor_address, scope.incarnation, scope.planned_image
            ));
            return Err(ObservationGap::Invalidated);
        }
        self.arm_request(scope.host_key, &request)?;
        let (pid, _, _) = Self::current_host_key()?;
        self.invoke_provisional_trigger(pid)?;
        let row = self.read_request(scope.host_key)?;
        if !request.same_input(&row) {
            self._last_error = Some(format!(
                "anchor same-input: armed nonce {nonce:#x} anchor {anchor:#x} vs row nonce {:#x} anchor {:#x} phase {}",
                row.nonce, row.anchor_id, row.phase
            ));
            return Err(ObservationGap::Invalidated);
        }
        if let Err(error) =
            AnchorReceipt::observed(anchor, nonce, row.entry_count, row.exit_count, row.verdict)
        {
            self._last_error = Some(format!(
                "anchor receipt: entry {} exit {} verdict {}",
                row.entry_count, row.exit_count, row.verdict
            ));
            return Err(error);
        }
        let receipt =
            AnchorReceipt::observed(anchor, nonce, row.entry_count, row.exit_count, row.verdict)?;
        // Contract order: consume the terminal receipt, disarm the request,
        // then release the provisional link. Failures above keep both the
        // terminal row and provisional custody for final disposal.
        self.disarm_request(scope.host_key)?;
        drop(self._roots.take_provisional());
        let guard_fd = self.guard_fd()?;
        self._ledger
            .create_anchor_guarded(guard_fd, anchor, &receipt)?;
        self._ledger.live_anchor(anchor)?;
        self._ledger.converge_guard_live(guard_fd, anchor)?;
        self._order.note_anchored(&self._ledger, anchor)?;
        if row.publication_sequence == 0 {
            return Err(ObservationGap::Invalidated);
        }
        self._anchor_id = Some(anchor);
        Ok(AnchorEstablished {
            anchor_id: anchor,
            epoch,
            object_id,
            sequence: row.publication_sequence,
            hash,
        })
    }
    /// Adopt one registration with both required link kinds: arm the ENTRY
    /// request, create the actual entry link, consume the ENTRY receipt and
    /// create the adoption guard (PREPARING) strictly before the RETURN pair
    /// may arm; then arm RETURN, create the actual return link, and advance
    /// the guard to LIVE with the adopted-FD proof. File custody, offset,
    /// cookie and target PID all come from the admitted scope. The scope
    /// carries one capability: the legacy admitted site (legacy programs)
    /// or one typed cookie (typed programs); every adopted pair lists in
    /// the acquisition order under the shared anchor, and the owner retains
    /// every adopted link FD through the final consumers.
    pub(super) fn register_entry_return(
        &mut self,
        scope: &RequestScope,
        entry_prog: std::os::fd::RawFd,
        return_prog: std::os::fd::RawFd,
        anchor: &AnchorEstablished,
    ) -> Result<RegistrationAdopted, ObservationGap> {
        let _ = self._last_error.take();
        if !contract::valid_site_cookie(scope.site_cookie) || scope.link_offset > i64::MAX as u64 {
            return Err(ObservationGap::Invalidated);
        }
        #[cfg(test)]
        let typed_scope =
            (contract::TYPED_COOKIE_FIRST..contract::TYPED_COOKIE_END).contains(&scope.site_cookie);
        // Descriptor custody, never a re-resolved path: the fd names the same
        // open file description the admitted site retains.
        let path = std::ffi::CString::new(format!("/proc/self/fd/{}", scope.target.as_raw_fd()))
            .map_err(|_| ObservationGap::Invalidated)?;
        let base = SourceRequest {
            nonce: 0,
            anchor_id: anchor.anchor_id,
            object_id: anchor.object_id,
            source_epoch: anchor.epoch,
            site_cookie: scope.site_cookie,
            file_offset: scope.link_offset,
            observer_anchor_address: 0,
            phase: 0,
            required_mask: REQUIRED_LINK_MASK,
            entry_count: 0,
            exit_count: 0,
            verdict: 0,
            reserved: 0,
            publication_sequence: 0,
            process_incarnation: scope.incarnation,
            image_epoch: scope.planned_image,
            registration_id: 0,
        };
        let guard_fd = self.guard_fd()?;
        // ENTRY kind.
        let entry_nonce = self._ids.fresh()?;
        let registration = self._ledger.mint_registration(
            &mut self._ids,
            anchor.anchor_id,
            anchor.epoch,
            entry_nonce,
        )?;
        #[cfg(test)]
        if typed_scope {
            self._last_typed_registration.set(registration);
        }
        let entry = SourceRequest {
            nonce: entry_nonce,
            phase: contract::PHASE_ENTRY,
            registration_id: registration,
            ..base
        };
        // Test-only fault: arm a well-formed ENTRY request for the WRONG
        // offset while the link below uses the true offset. The kernel
        // refuses the mismatch with a genuine refused receipt; the
        // corrupted value stays inside the valid range so the refusal
        // lands at the offset check with 1/1 counts.
        #[cfg(test)]
        let mut entry = entry;
        #[cfg(test)]
        if typed_scope && self._fail_typed_entry.take() {
            entry.file_offset = if entry.file_offset == i64::MAX as u64 {
                entry.file_offset - 1
            } else {
                entry.file_offset + 1
            };
        }
        if !entry.valid_input() {
            return Err(ObservationGap::Invalidated);
        }
        self.arm_request(scope.host_key, &entry)?;
        let entry_link = ossl_bpf_sys::link_create_uprobe_multi(
            entry_prog,
            &path,
            &[scope.link_offset],
            &[scope.site_cookie],
            scope.target_pid,
        )
        .map_err(|_| ObservationGap::BpfUnavailable)?;
        self._adopted.push(entry_link);
        let row = self.read_request(scope.host_key)?;
        if !entry.same_input(&row) {
            self._last_error = Some(format!(
                "entry same-input: armed nonce {entry_nonce:#x} reg {registration:#x} vs row nonce {:#x} reg {:#x} phase {}",
                row.nonce, row.registration_id, row.phase
            ));
            return Err(ObservationGap::Invalidated);
        }
        if let Err(error) = EntryReceipt::observed(
            registration,
            entry_nonce,
            row.entry_count,
            row.exit_count,
            row.verdict,
            true,
        ) {
            self._last_error = Some(format!(
                "entry receipt: entry {} exit {} verdict {}",
                row.entry_count, row.exit_count, row.verdict
            ));
            return Err(error);
        }
        let receipt = EntryReceipt::observed(
            registration,
            entry_nonce,
            row.entry_count,
            row.exit_count,
            row.verdict,
            true,
        )?;
        self.disarm_request(scope.host_key)?;
        self._ledger
            .create_adoption_guarded(guard_fd, registration, &receipt)?;
        // RETURN kind: arms only with the adoption guard in PREPARING.
        self._ledger.return_may_arm(registration)?;
        let return_nonce = self._ids.fresh()?;
        let back = SourceRequest {
            nonce: return_nonce,
            phase: contract::PHASE_RETURN,
            registration_id: registration,
            ..base
        };
        // Test-only fault, same shape as ENTRY: the armed RETURN claims
        // the wrong offset while the link uses the true one. The staged
        // ENTRY row quarantines and the receipt refuses; the capability
        // never adopts and no READY can publish for it.
        #[cfg(test)]
        let mut back = back;
        #[cfg(test)]
        if typed_scope && self._fail_typed_return.take() {
            back.file_offset = if back.file_offset == i64::MAX as u64 {
                back.file_offset - 1
            } else {
                back.file_offset + 1
            };
        }
        if !back.valid_input() {
            return Err(ObservationGap::Invalidated);
        }
        self.arm_request(scope.host_key, &back)?;
        let return_link = ossl_bpf_sys::link_create_uretprobe_multi(
            return_prog,
            &path,
            &[scope.link_offset],
            &[scope.site_cookie],
            scope.target_pid,
        )
        .map_err(|_| ObservationGap::BpfUnavailable)?;
        self._adopted.push(return_link);
        let row = self.read_request(scope.host_key)?;
        if !back.same_input(&row) {
            self._last_error = Some(format!(
                "return same-input: armed nonce {return_nonce:#x} reg {registration:#x} vs row nonce {:#x} reg {:#x} phase {}",
                row.nonce, row.registration_id, row.phase
            ));
            return Err(ObservationGap::Invalidated);
        }
        // Terminal-shape validation only: the RETURN nonce is fresh by design,
        // so mint binding runs through return_may_arm (PREPARING proves ENTRY
        // completed for this mint) plus the armed-request same_input above.
        EntryReceipt::observed(
            registration,
            return_nonce,
            row.entry_count,
            row.exit_count,
            row.verdict,
            true,
        )?;
        self.disarm_request(scope.host_key)?;
        let adopted = AdoptedLinks::adopted(registration, anchor.anchor_id, anchor.epoch, 2)?;
        self._ledger.live_adoption(registration, &adopted)?;
        self._ledger.converge_guard_live(guard_fd, registration)?;
        self._order
            .note_links_adopted(&self._ledger, registration)?;
        self._registration_ids.push(registration);
        Ok(RegistrationAdopted {
            registration_id: registration,
        })
    }
    /// Publish post-adoption READY: arm the phase-4 request, fire one
    /// provisional trigger, and consume the READY receipt for the STORED
    /// registration. Returns the READY publication sequence. Terminal: the
    /// full listed capability set must be READY before the held child may
    /// release, so this refuses unless the order completes here. All
    /// other capabilities publish through `publish_capability_ready`
    /// before this runs: every capability lists before any READY
    /// completes the set.
    pub(super) fn publish_ready(
        &mut self,
        scope: &RequestScope,
        anchor: &AnchorEstablished,
        registration: &RegistrationAdopted,
    ) -> Result<u64, ObservationGap> {
        let sequence = self.publish_ready_inner(scope, anchor, registration)?;
        if !self._order.child_may_release() {
            return Err(ObservationGap::Invalidated);
        }
        Ok(sequence)
    }
    /// Publish post-adoption READY for one listed capability (typed
    /// cookie or non-terminal legacy attachment): the same contracted
    /// kernel phase-4 publication as `publish_ready`, without the
    /// terminal release check. The caller publishes every listed
    /// capability and checks `acquisition_ready` before releasing the
    /// held child; a partial set never releases.
    pub(super) fn publish_capability_ready(
        &mut self,
        scope: &RequestScope,
        anchor: &AnchorEstablished,
        registration: &RegistrationAdopted,
    ) -> Result<u64, ObservationGap> {
        self.publish_ready_inner(scope, anchor, registration)
    }
    /// One phase-4 publication for the STORED registration: arm the
    /// request, fire one provisional trigger, consume the READY receipt.
    /// Shared by the terminal legacy publisher and the per-capability
    /// publisher; only the release check differs.
    fn publish_ready_inner(
        &mut self,
        scope: &RequestScope,
        anchor: &AnchorEstablished,
        registration: &RegistrationAdopted,
    ) -> Result<u64, ObservationGap> {
        let _ = self._last_error.take();
        if !contract::valid_site_cookie(scope.site_cookie) || scope.link_offset > i64::MAX as u64 {
            return Err(ObservationGap::Invalidated);
        }
        let nonce = self._ids.fresh()?;
        let request = SourceRequest {
            nonce,
            anchor_id: anchor.anchor_id,
            object_id: anchor.object_id,
            source_epoch: anchor.epoch,
            site_cookie: scope.site_cookie,
            file_offset: scope.link_offset,
            observer_anchor_address: 0,
            phase: contract::PHASE_READY,
            required_mask: REQUIRED_LINK_MASK,
            entry_count: 0,
            exit_count: 0,
            verdict: 0,
            reserved: 0,
            publication_sequence: 0,
            process_incarnation: scope.incarnation,
            image_epoch: scope.planned_image,
            registration_id: registration.registration_id,
        };
        if !request.valid_input() {
            return Err(ObservationGap::Invalidated);
        }
        self.arm_request(scope.host_key, &request)?;
        let (pid, _, _) = Self::current_host_key()?;
        self.invoke_provisional_trigger(pid)?;
        let row = self.read_request(scope.host_key)?;
        if !request.same_input(&row) {
            self._last_error = Some(format!(
                "ready same-input: armed nonce {nonce:#x} vs row nonce {:#x} phase {}",
                row.nonce, row.phase
            ));
            return Err(ObservationGap::Invalidated);
        }
        if let Err(error) = ReadyReceipt::observed(
            nonce,
            registration.registration_id,
            row.entry_count,
            row.exit_count,
            row.verdict,
            row.publication_sequence,
        ) {
            self._last_error = Some(format!(
                "ready receipt: entry {} exit {} verdict {} seq {}",
                row.entry_count, row.exit_count, row.verdict, row.publication_sequence
            ));
            return Err(error);
        }
        let receipt = ReadyReceipt::observed(
            nonce,
            registration.registration_id,
            row.entry_count,
            row.exit_count,
            row.verdict,
            row.publication_sequence,
        )?;
        // Contract order: consume the terminal receipt, disarm the request,
        // then release the provisional link.
        self.disarm_request(scope.host_key)?;
        drop(self._roots.take_provisional());
        self._order.note_ready(&self._ledger, nonce, &receipt)?;
        Ok(row.publication_sequence)
    }
    /// Mirror an observed planned exec. Refuses unless the kernel row already
    /// shows the ACTIVE transition to the planned image: the host never
    /// mirrors a transition that did not happen. Returns the mirrored state.
    pub(super) fn note_exec_transition(
        &mut self,
        tgid: u32,
        planned_image: u64,
    ) -> Result<u64, ObservationGap> {
        let _ = self._last_error.take();
        if tgid == 0 || planned_image == 0 {
            return Err(ObservationGap::Invalidated);
        }
        let map = self.map("SOURCE_DOMAIN")?;
        map.shape(&[1], 4, 64)
            .map_err(|_| ObservationGap::InvalidObject)?;
        let row = SourceDomain {
            process_incarnation: 0,
            original_image: 0,
            planned_image: 0,
            current_image: 0,
            state: 0,
            loss_epoch: 0,
            reserved: [0, 0],
        };
        let mut observed = row;
        let bytes = unsafe {
            std::slice::from_raw_parts_mut((&mut observed as *mut SourceDomain).cast::<u8>(), 64)
        };
        map.lookup(&tgid.to_ne_bytes(), bytes)
            .map_err(|_| ObservationGap::BpfUnavailable)?;
        if observed.state != contract::DOMAIN_ACTIVE
            || observed.current_image != planned_image
            || observed.planned_image != planned_image
        {
            self._last_error = Some(format!(
                "exec mirror: kernel state {} current {:#x} planned {:#x}",
                observed.state, observed.current_image, observed.planned_image
            ));
            return Err(ObservationGap::Invalidated);
        }
        self._domains.note_planned_exec(tgid, planned_image)?;
        let state = self
            ._domains
            .state(tgid)
            .ok_or(ObservationGap::Invalidated)?;
        if state != contract::DOMAIN_ACTIVE {
            return Err(ObservationGap::Invalidated);
        }
        Ok(state)
    }
    /// Retire one armed kernel domain row now that writers are quiesced,
    /// then retire its host mirror. Runs only after the common cut: the host
    /// never read-modify-writes live kernel domain state.
    fn retire_domain_row(&mut self, tgid: u32) -> Result<(), ObservationGap> {
        let map = self.map("SOURCE_DOMAIN")?;
        map.shape(&[1], 4, 64)
            .map_err(|_| ObservationGap::InvalidObject)?;
        let mut row = SourceDomain {
            process_incarnation: 0,
            original_image: 0,
            planned_image: 0,
            current_image: 0,
            state: 0,
            loss_epoch: 0,
            reserved: [0, 0],
        };
        let bytes = unsafe {
            std::slice::from_raw_parts_mut((&mut row as *mut SourceDomain).cast::<u8>(), 64)
        };
        map.lookup(&tgid.to_ne_bytes(), bytes)
            .map_err(|_| ObservationGap::BpfUnavailable)?;
        if row.state == contract::DOMAIN_ARMED
            || row.state == contract::DOMAIN_ACTIVE
            || row.state == contract::DOMAIN_TRANSITION
        {
            row.state = contract::DOMAIN_RETIRED;
            let bytes = unsafe {
                std::slice::from_raw_parts((&row as *const SourceDomain).cast::<u8>(), 64)
            };
            map.update(&tgid.to_ne_bytes(), bytes)
                .map_err(|_| ObservationGap::BpfUnavailable)?;
        }
        self._domains.retire(tgid)
    }
    /// Explicit test-driven close, integrated with the retained gate's
    /// successful common cut: the cut receipt must exist before anything is
    /// touched, guards retire before any release, domain rows update only
    /// after writer quiescence, and a non-READY order refuses last. Fail-fast:
    /// the first error stops the close with all custody retained (roots,
    /// adopted links, anchor, unprocessed domain TGIDs, order state), so a
    /// failed close is retryable and never releases writers' backing.
    /// Production close lands with 5B activation.
    #[allow(dead_code)]
    pub(super) fn close_source(&mut self) -> SourceCloseReceipts {
        let mut receipts = SourceCloseReceipts {
            guards_retired: 0,
            guards_abandoned: 0,
            domains_retired: 0,
            order_refused: false,
            cut_confirmed: false,
            first_error: None,
        };
        // The retained shared gate must show the successful common-cut
        // receipt. Anything else (open, preparing, failed cut) refuses
        // WITHOUT touching guards, domains, order or custody: writers may
        // still be live, and a live acquisition must not be disturbed.
        if self._gate.receipt().is_none() {
            receipts.first_error = Some(ObservationGap::Invalidated);
            return receipts;
        }
        receipts.cut_confirmed = true;
        let guard_fd = match self.guard_fd() {
            Ok(fd) => Some(fd),
            Err(error) => {
                receipts.first_error = Some(error);
                None
            }
        };
        let mut ids = Vec::new();
        ids.extend(self._anchor_id);
        ids.extend(self._registration_ids.iter().copied());
        for id in ids {
            match self._ledger.guard_life(id) {
                Some(GuardLife::Preparing | GuardLife::Live) => {
                    #[cfg(test)]
                    if self._fail_next_retire.take() {
                        receipts.first_error = Some(ObservationGap::BpfUnavailable);
                        return receipts;
                    }
                    let from = if self._ledger.guard_life(id) == Some(GuardLife::Preparing) {
                        GuardLife::Preparing
                    } else {
                        GuardLife::Live
                    };
                    match guard_fd {
                        Some(fd) => {
                            match self._ledger.advance_guard_checked(
                                fd,
                                id,
                                from,
                                GuardLife::Retired,
                            ) {
                                Ok(()) => {
                                    receipts.guards_retired += 1;
                                    let _ = self._ledger.retire(id);
                                }
                                Err(error) => {
                                    receipts.first_error = Some(error);
                                    return receipts;
                                }
                            }
                        }
                        None => {
                            receipts.first_error = Some(ObservationGap::BpfUnavailable);
                            return receipts;
                        }
                    }
                }
                Some(GuardLife::Minted) => match self._ledger.abandon(id) {
                    Ok(()) => receipts.guards_abandoned += 1,
                    Err(error) => {
                        receipts.first_error = Some(error);
                        return receipts;
                    }
                },
                Some(GuardLife::Retired | GuardLife::Conflict) => {
                    let _ = self._ledger.retire(id);
                }
                None => {
                    receipts.first_error = Some(ObservationGap::Invalidated);
                    return receipts;
                }
            }
        }
        let mut pending = std::mem::take(&mut self._domain_tgids);
        // Drain from the front so a failure can restore the unprocessed
        // remainder (including the failed TGID) for a later retry.
        pending.reverse();
        while let Some(tgid) = pending.pop() {
            match self.retire_domain_row(tgid) {
                Ok(()) => receipts.domains_retired += 1,
                Err(error) => {
                    pending.push(tgid);
                    pending.reverse();
                    self._domain_tgids = pending;
                    receipts.first_error = Some(error);
                    return receipts;
                }
            }
        }
        receipts.order_refused = self._order.refuse().is_ok();
        // Success only: release in contract order (programs/links, then
        // adopted links, then the anchor mapping). Any failure above
        // returned with all custody retained.
        self._roots.release_loaded();
        self._adopted.clear();
        self._anchor = None;
        receipts
    }
}

#[cfg(test)]
mod tests {
    use super::super::ObservationLimits;
    use super::*;
    #[test]
    fn native_claims_round_trip_through_the_test_only_constructor() {
        // The sole `NativeSourceParams` constructors are `#[cfg(test)]`, so
        // non-test builds cannot mint the claims that `Enabled` wraps; the
        // clean non-test `cargo check` on this commit is the proof. The
        // accessors below are the production claim-vs-truth read path.
        let params =
            NativeSourceParams::for_test(std::path::PathBuf::from("/owned/fixture"), 0x11b4, 4242);
        assert_eq!(params.claims().len(), 1);
        assert_eq!(
            params.claims()[0].target(),
            std::path::Path::new("/owned/fixture")
        );
        assert_eq!(params.claims()[0].link_offset(), 0x11b4);
        assert_eq!(params.claims()[0].child_pid(), 4242);
        let multi = NativeSourceParams::for_test_multi(vec![
            (std::path::PathBuf::from("/owned/a"), 0x1000, 111),
            (std::path::PathBuf::from("/owned/b"), 0x2000, 111),
        ]);
        assert_eq!(multi.claims().len(), 2);
        assert_eq!(multi.claims()[1].target(), std::path::Path::new("/owned/b"));
        assert_eq!(multi.claims()[1].link_offset(), 0x2000);
        assert_eq!(multi.claims()[1].child_pid(), 111);
    }
    #[test]
    fn producer_map_tables_share_single_source_shapes() {
        // REL exists both as MAPS[0] and PRODUCER_MAPS[0]: same shape.
        for (a, b) in [(&MAPS[0], &loader::PRODUCER_MAPS[0])] {
            assert_eq!(a.name, b.name);
            assert_eq!(a.map_type, b.map_type);
            assert_eq!(a.key_size, b.key_size);
            assert_eq!(a.value_size, b.value_size);
            assert_eq!(a.max_entries, b.max_entries);
            assert_eq!(a.flags, b.flags);
        }
        // The focused table duplicates the 8 session-owned source/control
        // shapes (invisible to loader as `pub(super)`): guard the copy.
        for name in [
            "ATTR_STATE",
            "SOURCE_CONFIG",
            "SOURCE_GUARD",
            "SOURCE_REQUEST",
            "SOURCE_PAIR",
            "SOURCE_DOMAIN",
            "SOURCE_OBSERVER",
            "ITER_SLOT",
        ] {
            let focused = loader::FOCUSED_COUNT_MAPS
                .iter()
                .find(|m| m.name == name)
                .unwrap_or_else(|| panic!("focused table missing {name}"));
            let owned = MAPS
                .iter()
                .chain(CONTROL_MAPS.iter())
                .find(|m| m.name == name)
                .unwrap_or_else(|| panic!("owner table missing {name}"));
            assert_eq!(focused.map_type, owned.map_type, "{name}");
            assert_eq!(focused.key_size, owned.key_size, "{name}");
            assert_eq!(focused.value_size, owned.value_size, "{name}");
            assert_eq!(focused.max_entries, owned.max_entries, "{name}");
            assert_eq!(focused.flags, owned.flags, "{name}");
        }
        // Every producer map the counter borrows is session-owned.
        for name in loader::BORROWED_COUNT_MAPS {
            assert!(
                MAPS.iter()
                    .chain(CONTROL_MAPS.iter())
                    .any(|m| m.name == name),
                "borrowed {name} has no session owner"
            );
        }
    }
    #[test]
    fn source_capacity_includes_actual_maps_and_declared_iterator_reserve() {
        assert_eq!(iterator_reservation(512, 16), Some(6_438_912));
        // ITER_SLOT carries two per-CPU cells (scratch + commit-tail block):
        // the second cell adds exactly 4 + 264*16 + 128 = 4356 bytes.
        // The 11 producer maps beyond REL add 11,266,276 bytes at 16
        // CPUs (per-map: (key + value*cpus + 128) * entries + 65536).
        assert_eq!(map_reservation(16), Some(17_546_660));
        // The acquisition core adds its NoOp/program/link owner, ledger,
        // domain-index, order and allocator reserves to the component charge,
        // plus the two unattached typed roots (programs only, links come
        // per admitted export): 602_120 + 2 * 32768.
        assert_eq!(ACQUIRE_CORE_RESERVE, 667_656);
        assert_eq!(source_reservation(512, 16), Some(24_673_708));
        assert_eq!(iterator_reservation(512, 1), Some(4_334_592));
        for (class, cpus) in [(0, 16), (300, 16), (8192, 16), (512, 0), (512, usize::MAX)] {
            assert!(source_reservation(class, cpus).is_none());
        }
    }
    #[test]
    fn frozen_source_configuration_preserves_smaller_caller_pending_limit() {
        let config = source_configuration(4096, 128).unwrap();
        assert_eq!((config.page_shift, config.pending_limit), (12, 128));
        for (page, limit) in [
            (-1, 4096),
            (0, 4096),
            (3, 4096),
            (4096, 1),
            (4096, 4097),
            (4096, usize::MAX),
        ] {
            assert!(source_configuration(page, limit).is_err());
        }
    }
    #[test]
    fn source_capacity_refuses_before_acquisition_and_retains_its_full_lease() {
        let bytes = source_reservation(512, 16).unwrap();
        let small = ObservationBudget::new(ObservationLimits {
            max_state_bytes: bytes - 1,
            ..Default::default()
        });
        assert!(matches!(
            reserve_source(&small, 512, 16),
            Err(ObservationGap::StateLimit)
        ));
        let budget = ObservationBudget::new(ObservationLimits {
            max_state_bytes: bytes,
            ..Default::default()
        });
        let owned = reserve_source(&budget, 512, 16).unwrap();
        assert_eq!(budget.clone().state(1), Err(ObservationGap::StateLimit));
        drop(owned);
        budget.state(bytes).unwrap();
        let mut shared = ObservationBudget::new(ObservationLimits {
            max_state_bytes: bytes,
            ..Default::default()
        });
        shared.memory = Some(crate::observation_memory::MemoryPool::new(
            map_reservation(16).unwrap() - 1,
        ));
        assert!(matches!(
            reserve_source(&shared, 512, 16),
            Err(ObservationGap::StateLimit)
        ));
        // Outer-watch refusal must release the temporary component reservation.
        shared.state(bytes).unwrap();
    }
    /// Minimal owner for anchor-capture tests: valid (pure-metadata) roots
    /// admission, real budget/ledger/index/order state, and NO maps, so any
    /// capture success surfaces as the map-stage `InvalidObject` while every
    /// capture fault surfaces as its own gap first. Caps-free.
    fn anchor_test_owner(budget: &ObservationBudget) -> SourceOwner {
        let prepared = loader::Prepared {
            progs: [
                ("source_reg_in", "fentry/uprobe_register", false),
                ("source_reg_out", "fexit/uprobe_register", false),
                ("attr_exit", "raw_tracepoint/sched_process_exit", false),
                ("attr_exec", "raw_tracepoint/sched_process_exec", false),
                ("typed_entry", "uprobe", false),
                ("typed_return", "uretprobe", true),
            ]
            .into_iter()
            .map(|(name, section, is_return)| loader::PreparedProg {
                name: name.to_owned(),
                section: section.to_owned(),
                is_return,
                insns: Vec::new(),
                map_fixups: vec![loader::MapFixup {
                    insn_off: 0,
                    map: "ADMIT".to_owned(),
                }],
                subprogs: Vec::new(),
            })
            .collect(),
            maps: MAPS
                .iter()
                .map(|spec| loader::MapSpecLite {
                    name: spec.name.to_owned(),
                    map_type: spec.map_type,
                    key_size: spec.key_size,
                    value_size: spec.value_size,
                    max_entries: spec.max_entries,
                    flags: spec.flags,
                })
                .collect(),
        };
        RetainedSourceRoots::check(&prepared, 1).expect("fake prepared must check");
        let pool = crate::observation_memory::MemoryPool::new(256 << 20);
        let gate = crate::writer_gate::fake_for_shape_tests(&pool).unwrap();
        SourceOwner {
            _roots: RetainedSourceRoots::retain(prepared, 1, std::process::id()),
            _adopted: Vec::new(),
            _anchor: None,
            _anchor_id: None,
            _registration_ids: Vec::new(),
            _domain_tgids: Vec::new(),
            _mode: None,
            _control: None,
            _fail_next_retire: std::cell::Cell::new(false),
            _fail_typed_entry: std::cell::Cell::new(false),
            _fail_typed_return: std::cell::Cell::new(false),
            _last_typed_registration: std::cell::Cell::new(0),
            _last_error: None,
            _maps: BTreeMap::new(),
            _namespace: std::fs::File::open("/proc/self/ns/pid").unwrap(),
            _gate: gate,
            _capacity: reserve_source(budget, 512, 16).unwrap(),
            _ids: HostIds::new(),
            _ledger: GuardLedger::new(),
            _domains: DomainIndex::new(),
            _order: AcquisitionOrder::new(),
        }
    }
    fn anchor_test_scope(target: std::fs::File, expected: ObjectHash) -> RequestScope {
        RequestScope {
            site_cookie: 1,
            host_key: 0x1111_2222_3333_4444,
            incarnation: 0x8000_0000_0000_0001,
            planned_image: 0x8000_0000_0000_0002,
            link_offset: 0x11b4,
            target_pid: std::process::id(),
            target,
            expected_artifact: expected,
        }
    }
    fn anchor_test_hash(bytes: &[u8]) -> (ObjectHash, [u8; 32]) {
        use sha2::Digest as _;
        let digest = sha2::Sha256::digest(bytes);
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&digest);
        let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        (ObjectHash::try_from(hex).unwrap(), raw)
    }
    /// Fault-injection harness (hermetic, documented): files under the test
    /// temp dir mutated between admission-hash computation and the actual
    /// acquisition `anchor_source` call. Truncation and mid-read change must
    /// return observation gaps, never fault. The racy true-mid-read
    /// truncation (truncate between mmap and read) is covered at the capture
    /// level by `source_anchor`'s truncate-then-digest test; these controls
    /// drive the same path through the actual acquisition caller.
    fn anchor_fault_file(tag: &str, bytes: &[u8]) -> (std::path::PathBuf, std::fs::File) {
        let path = std::env::temp_dir().join(format!(
            "osslscope-anchor-fault-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, bytes).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        (path, file)
    }
    #[test]
    fn anchor_source_accepts_unchanged_backing_through_capture() {
        let budget = ObservationBudget::default();
        let mut owner = anchor_test_owner(&budget);
        let bytes = vec![0xA5u8; 8192];
        let (expected, _raw) = anchor_test_hash(&bytes);
        let (path, file) = anchor_fault_file("clean", &bytes);
        let scope = anchor_test_scope(file, expected);
        // Capture passes on the unchanged backing; with no maps the call
        // then fails exactly at the map stage, proving capture succeeded.
        let error = match owner.anchor_source(&scope, &budget, None) {
            Ok(_) => panic!("map stage must fail without maps"),
            Err(error) => error,
        };
        assert_eq!(error, ObservationGap::InvalidObject);
        assert!(owner.anchor_retained_test());
        std::fs::remove_file(&path).unwrap();
    }
    #[test]
    fn anchor_source_reuses_verified_candidate_without_recapture() {
        let budget = ObservationBudget::default();
        let mut owner = anchor_test_owner(&budget);
        let bytes = vec![0xA5u8; 8192];
        let (expected, _raw) = anchor_test_hash(&bytes);
        let (path, file) = anchor_fault_file("shared", &bytes);
        let candidate =
            Rc::new(SourceAnchor::capture(&file, &expected, &budget).expect("staging capture"));
        let scope = anchor_test_scope(file, expected);
        // Map stage still fails without maps, proving the call ran past
        // the capture step; the retained anchor must be the candidate
        // itself (no second capture, no second charge).
        let error = match owner.anchor_source(&scope, &budget, Some(candidate.clone())) {
            Ok(_) => panic!("map stage must fail without maps"),
            Err(error) => error,
        };
        assert_eq!(error, ObservationGap::InvalidObject);
        let retained = owner.anchor_rc_test().expect("anchor retained");
        assert!(
            Rc::ptr_eq(&retained, &candidate),
            "owner must share the verified staging capture"
        );
        std::fs::remove_file(&path).unwrap();
    }
    #[test]
    fn anchor_source_recaptures_when_candidate_mismatches() {
        let budget = ObservationBudget::default();
        let mut owner = anchor_test_owner(&budget);
        let bytes = vec![0xA5u8; 8192];
        let (expected, _raw) = anchor_test_hash(&bytes);
        let (_other_path, other_file) = anchor_fault_file("mismatch-backing", &bytes);
        // Same bytes, different backing: the candidate cannot verify.
        let candidate = Rc::new(
            SourceAnchor::capture(&other_file, &expected, &budget).expect("staging capture"),
        );
        let (path, file) = anchor_fault_file("mismatch-scope", &bytes);
        let scope = anchor_test_scope(file, expected);
        // A mismatch falls back to a fresh capture (re-proving current
        // bytes), never a refusal: the call still reaches the map stage.
        let error = match owner.anchor_source(&scope, &budget, Some(candidate.clone())) {
            Ok(_) => panic!("map stage must fail without maps"),
            Err(error) => error,
        };
        assert_eq!(error, ObservationGap::InvalidObject);
        let retained = owner.anchor_rc_test().expect("anchor retained");
        assert!(
            !Rc::ptr_eq(&retained, &candidate),
            "mismatched candidate must not be shared"
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(&_other_path).unwrap();
    }
    #[test]
    fn refusal_notes_carry_order_diagnosis_and_context_prefixes_pending() {
        let budget = ObservationBudget::default();
        let mut owner = anchor_test_owner(&budget);
        // Context with no pending diagnosis: no invention.
        owner.context_last_error("attachment 2/2 cookie 2 offset 0x0 register");
        assert_eq!(owner.take_last_error(), None);
        // A pre-effect refusal records its diagnosis for the close
        // receipts; a later context prefixes it with claim identity.
        owner.note_refusal("admission refused: 3 claims against 1 startup pid groups".into());
        owner.context_last_error("attachment 3/3 cookie 0 offset 0x0 admit");
        assert_eq!(
            owner.take_last_error().as_deref(),
            Some(
                "attachment 3/3 cookie 0 offset 0x0 admit: admission refused: 3 claims against 1 startup pid groups"
            ),
        );
        // The slot is single: a newer refusal overwrites stale content.
        owner.note_refusal("first".into());
        owner.note_refusal("second".into());
        assert_eq!(owner.take_last_error().as_deref(), Some("second"));
    }
    #[test]
    fn multi_attachment_charges_cover_capacity_measured_worst_case_heap() {
        // ER-S2-I2 worst-case heap proof for the new multi-attachment
        // buffers: at full registration admission (1024) and at the real
        // 38-attachment order, each phase charge must cover its
        // capacity-measured heap (vector buffers at capacity plus one
        // 64-byte artifact hash heap per site) with margin to spare.
        // Unprivileged and hermetic: pure arithmetic over `size_of`.
        for n in [2usize, 38, 1024] {
            let admission = multi_attachment_admission_charge(n).unwrap();
            let admission_heap = n
                + n * std::mem::size_of::<AdmittedSourceSite>()
                + n * 64
                + 2 * std::mem::size_of::<Vec<u8>>();
            assert!(
                admission >= admission_heap,
                "admission charge {admission} must cover heap {admission_heap} at n={n}"
            );
            let acquisition = multi_attachment_acquisition_charge(n).unwrap();
            let acquisition_heap = n * std::mem::size_of::<RequestScope>()
                + n * 64
                + n * std::mem::size_of::<RegistrationAdopted>()
                + n * std::mem::size_of::<u64>()
                + n * std::mem::size_of::<AttachmentEstablished>()
                + n * std::mem::size_of::<(u64, u64)>()
                + 5 * std::mem::size_of::<Vec<u8>>();
            assert!(
                acquisition >= acquisition_heap,
                "acquisition charge {acquisition} must cover heap {acquisition_heap} at n={n}"
            );
        }
        assert!(multi_attachment_admission_charge(usize::MAX).is_none());
        assert!(multi_attachment_acquisition_charge(usize::MAX).is_none());
    }
    #[test]
    fn anchor_source_truncation_returns_gap_never_faults() {
        let budget = ObservationBudget::default();
        let mut owner = anchor_test_owner(&budget);
        let bytes = vec![0xA5u8; 8192];
        let (expected, _raw) = anchor_test_hash(&bytes);
        let (path, file) = anchor_fault_file("truncate", &bytes);
        // Truncate between admission-hash computation and capture.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(0)
            .unwrap();
        let scope = anchor_test_scope(file, expected);
        let error = match owner.anchor_source(&scope, &budget, None) {
            Ok(_) => panic!("truncation must refuse"),
            Err(error) => error,
        };
        assert_eq!(error, ObservationGap::ReadLimit);
        assert!(!owner.anchor_retained_test());
        std::fs::remove_file(&path).unwrap();
    }
    #[test]
    fn anchor_source_shrink_returns_gap_never_faults() {
        let budget = ObservationBudget::default();
        let mut owner = anchor_test_owner(&budget);
        let bytes = vec![0xA5u8; 8192];
        let (expected, _raw) = anchor_test_hash(&bytes);
        let (path, file) = anchor_fault_file("shrink", &bytes);
        // Shrink to a nonzero smaller backing: the captured hash cannot
        // match the admitted one.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(4096)
            .unwrap();
        let scope = anchor_test_scope(file, expected);
        let error = match owner.anchor_source(&scope, &budget, None) {
            Ok(_) => panic!("backing change must refuse"),
            Err(error) => error,
        };
        assert_eq!(error, ObservationGap::ObjectChanged);
        assert!(!owner.anchor_retained_test());
        std::fs::remove_file(&path).unwrap();
    }
    #[test]
    fn anchor_source_mid_read_change_returns_gap_never_faults() {
        let budget = ObservationBudget::default();
        let mut owner = anchor_test_owner(&budget);
        let bytes = vec![0xA5u8; 8192];
        let (expected, _raw) = anchor_test_hash(&bytes);
        let (path, file) = anchor_fault_file("change", &bytes);
        // Swap the backing bytes (same length) between admission and capture.
        std::fs::write(&path, vec![0x5Au8; 8192]).unwrap();
        let scope = anchor_test_scope(file, expected);
        let error = match owner.anchor_source(&scope, &budget, None) {
            Ok(_) => panic!("backing change must refuse"),
            Err(error) => error,
        };
        assert_eq!(error, ObservationGap::ObjectChanged);
        assert!(!owner.anchor_retained_test());
        std::fs::remove_file(&path).unwrap();
    }
    #[test]
    fn decode_object_hash_hex_round_trips_valid_hashes() {
        let (_expected, raw) = anchor_test_hash(b"osslscope-anchor-bytes");
        let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let hash = ObjectHash::try_from(hex).unwrap();
        assert_eq!(decode_object_hash_hex(&hash).unwrap(), raw);
        let (empty, _) = anchor_test_hash(b"");
        assert_eq!(
            decode_object_hash_hex(&empty).unwrap()[..4],
            [0xe3, 0xb0, 0xc4, 0x42]
        );
    }
    /// P2 host-verifier proof: every producer program passes the running
    /// kernel's verifier through the repo loader, before any attach. Loads
    /// the legacy observation pair, prepares the source owner (maps only),
    /// loads the typed entry/return pair against borrowed maps, and loads
    /// the count root against the shared producer pool. Creates maps and
    /// unattached programs only: no links, no pins, no target processes,
    /// no gate opening. The registration half is split out and counted but
    /// deliberately never loaded (its loader attaches).
    ///
    /// ```sh
    /// OSSL_PROVIDER_OBSERVATION_TEST_BPF=<provider object> \
    /// OSSLSCOPE_FOCUSED_COUNT_OBJECT=<count object> \
    /// sudo -n cargo test --locked --offline --lib -- --ignored \
    ///     p2_typed_producer_passes_verifier_load --nocapture
    /// ```
    #[test]
    #[ignore = "loads BPF objects into the host kernel verifier (sudo, no attach)"]
    fn p2_typed_producer_passes_verifier_load() {
        use sha2::Digest as _;
        use std::collections::BTreeMap;
        use std::sync::atomic::AtomicBool;
        use std::time::{Duration, Instant};
        let provider =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        let count =
            std::fs::read(std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT").unwrap()).unwrap();
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        println!(
            "provider sha256={} len={} count sha256={} len={}",
            hex(&sha2::Sha256::digest(&provider)),
            provider.len(),
            hex(&sha2::Sha256::digest(&count)),
            count.len()
        );
        let pool = crate::observation_memory::MemoryPool::new(256 << 20);
        let mut budget = ObservationBudget::new(super::super::ObservationLimits::default());
        budget.memory = Some(pool.clone());
        let gate = WriterGate::create(&pool).unwrap();
        assert!(gate.preparing());
        // Legacy half: observation_entry + observation_return. The gated
        // loader attaches lifecycle links only for lifecycle roots, and the
        // legacy split holds none, so this load is programs-only.
        let legacy =
            crate::provider_observation::session::prepare_legacy_object(&provider).unwrap();
        assert_eq!(legacy.progs.len(), 2);
        let loaded = loader::load_gated(&legacy, &gate).unwrap();
        assert!(loaded.progs.contains_key("observation_entry"));
        assert!(loaded.progs.contains_key("observation_return"));
        assert_eq!(loaded.progs.len(), 2);
        // Source half: owner prepares maps only (no program loads).
        let full = crate::provider_observation::session::prepare_object(&provider).unwrap();
        let (_, mut source_prepared) =
            crate::provider_observation::session::split_source_preparation(full);
        let kernel = loader::SourceKernel::read(&budget).unwrap();
        kernel.patch(&mut source_prepared).unwrap();
        let owner = SourceOwner::prepare(
            &budget,
            &kernel,
            &gate,
            &loaded,
            &mut source_prepared,
            Instant::now() + Duration::from_secs(60),
            &AtomicBool::new(false),
        )
        .unwrap();
        // Core proof: the typed pair loads against borrowed maps. The
        // verifier runs inside `load_prog`; any rejection fails here.
        let (registration, typed) =
            loader::split_typed_preparation(owner._roots.prepared().clone()).unwrap();
        assert_eq!(
            registration.progs.len(),
            4,
            "registration half stays unloaded"
        );
        assert_eq!(typed.progs.len(), 2);
        let typed_programs =
            loader::load_typed_borrowed(&typed, &owner._maps, &loaded, &owner._gate).unwrap();
        assert!(typed_programs.contains_key("typed_entry"));
        assert!(typed_programs.contains_key("typed_return"));
        assert_eq!(typed_programs.len(), 2);
        // Count side through the shared P2 path: every borrowed name must
        // resolve to the same kernel maps the owner holds.
        let count_prepared =
            loader::prepare_focused_count(&count, &ObservationBudget::default()).unwrap();
        let mut borrowed = BTreeMap::new();
        for name in loader::BORROWED_COUNT_MAPS {
            borrowed.insert(name.to_string(), owner.owned_map(name).unwrap());
        }
        let count_loaded = loader::load_gated_borrowed(&count_prepared, &gate, &borrowed).unwrap();
        assert!(count_loaded.progs.contains_key("count_entry"));
        assert_eq!(count_loaded.progs.len(), 1);
        // Tripwire: the gate was never opened, so no attach path that
        // requires the open gate could have run. (No link/pin primitive is
        // called above by construction; this asserts the visible half.)
        assert!(gate.preparing());
        drop(count_loaded);
        drop(typed_programs);
        drop(owner);
        drop(loaded);
    }

    // ---- Task23A unattached nine-root diagnostic ----

    /// Canonical nine-root table order with sections.
    fn task23a_expected_roots() -> [(&'static str, &'static str); 9] {
        [
            ("observation_entry", "uprobe"),
            ("observation_return", "uretprobe"),
            ("source_reg_in", "fentry/uprobe_register"),
            ("source_reg_out", "fexit/uprobe_register"),
            ("attr_exit", "raw_tracepoint/sched_process_exit"),
            ("attr_exec", "raw_tracepoint/sched_process_exec"),
            ("typed_entry", "uprobe"),
            ("typed_return", "uretprobe"),
            ("count_entry", "uprobe"),
        ]
    }

    /// Setup-failure attribution sets: a preparation failure refuses
    /// exactly the roots whose inputs it poisoned, never the whole
    /// table. Slots are fresh `Unattempted` at every refusal site
    /// (setup precedes all loads; later refusals name only slots
    /// their phase could not have pushed), so refusal is total.
    const TASK23A_LEGACY_SLOTS: [&str; 2] = ["observation_entry", "observation_return"];
    const TASK23A_PROVIDER_SLOTS: [&str; 8] = [
        "observation_entry",
        "observation_return",
        "source_reg_in",
        "source_reg_out",
        "attr_exit",
        "attr_exec",
        "typed_entry",
        "typed_return",
    ];
    const TASK23A_SOURCE_SLOTS: [&str; 6] = [
        "source_reg_in",
        "source_reg_out",
        "attr_exit",
        "attr_exec",
        "typed_entry",
        "typed_return",
    ];
    const TASK23A_NON_LEGACY_SLOTS: [&str; 7] = [
        "source_reg_in",
        "source_reg_out",
        "attr_exit",
        "attr_exec",
        "typed_entry",
        "typed_return",
        "count_entry",
    ];
    const TASK23A_COUNT_SLOTS: [&str; 1] = ["count_entry"];

    /// Pre-build the nine `Unattempted` slots with per-root artifact
    /// pins (provider pins for the first eight, count pins last).
    fn task23a_unattempted_table(
        provider: loader::ArtifactPins,
        count: loader::ArtifactPins,
    ) -> Vec<loader::LoadDiagnostics> {
        task23a_expected_roots()
            .iter()
            .enumerate()
            .map(|(i, (name, section))| {
                loader::LoadDiagnostics::unattempted(
                    name,
                    section,
                    if i < 8 { provider } else { count },
                )
            })
            .collect()
    }

    /// Align pushed per-root records into their pre-built slots by
    /// root name. Unknown or duplicate pushed names are internal
    /// errors; unpushed slots stay explicitly `Unattempted`.
    fn task23a_align_records(
        table: &mut [loader::LoadDiagnostics],
        pushed: Vec<loader::LoadDiagnostics>,
    ) -> Result<(), String> {
        for record in pushed {
            let slot = table
                .iter_mut()
                .find(|slot| slot.root == record.root)
                .ok_or_else(|| format!("unexpected diagnostic root {}", record.root))?;
            if slot.stage != loader::LoadStage::Unattempted {
                return Err(format!("duplicate diagnostic root {}", record.root));
            }
            *slot = record;
        }
        Ok(())
    }

    /// Map a setup/preflight failure onto named `Unattempted` slots:
    /// they become `Preflight` with the shared error. Anything else
    /// (unknown slot, already attempted) is an internal error.
    fn task23a_refuse_slots(
        table: &mut [loader::LoadDiagnostics],
        names: &[&str],
        error: &str,
    ) -> Result<(), String> {
        for name in names {
            let slot = table
                .iter_mut()
                .find(|slot| slot.root == *name)
                .ok_or_else(|| format!("unknown diagnostic slot {name}"))?;
            if slot.stage != loader::LoadStage::Unattempted {
                return Err(format!("diagnostic slot {name} already attempted"));
            }
            slot.stage = loader::LoadStage::Preflight;
            slot.error = Some(error.to_owned());
        }
        Ok(())
    }

    /// Refuse every slot with one shared setup error. The caller
    /// guarantees a fresh `Unattempted` table (setup runs before any
    /// acquisition), so a refusal here is an internal bug, never an
    /// input failure.
    fn task23a_refuse_all(table: &mut [loader::LoadDiagnostics], error: &str) {
        for (name, _) in task23a_expected_roots() {
            task23a_refuse_slots(table, &[name], error).unwrap();
        }
    }

    /// Strict 64-lowercase-hex sha256 parse: exact length, hex digits
    /// only, no `0x` prefix, no whitespace. Pure; the diagnostic
    /// supplies the environment-provided string.
    fn task23a_parse_sha_hex(raw: &str) -> Result<[u8; 32], String> {
        fn hex_val(byte: u8) -> Result<u8, String> {
            match byte {
                b'0'..=b'9' => Ok(byte - b'0'),
                b'a'..=b'f' => Ok(byte - b'a' + 10),
                _ => Err(format!("non-hex sha256 digit {byte:#04x}")),
            }
        }
        let bytes = raw.as_bytes();
        if bytes.len() != 64 {
            return Err(format!("sha256 must be 64 hex digits, got {}", bytes.len()));
        }
        let mut out = [0u8; 32];
        for (i, pair) in bytes.chunks_exact(2).enumerate() {
            out[i] = hex_val(pair[0])? << 4 | hex_val(pair[1])?;
        }
        Ok(out)
    }

    /// Required expected-sha256 pin from the environment. Missing,
    /// non-Unicode, or malformed values refuse the diagnostic before
    /// any kernel object exists; nothing defaults, nothing stamps.
    fn task23a_required_sha(var: &str) -> Result<[u8; 32], String> {
        let raw =
            std::env::var(var).map_err(|_| format!("required pin {var} missing or non-Unicode"))?;
        task23a_parse_sha_hex(&raw).map_err(|e| format!("required pin {var} malformed: {e}"))
    }

    /// One named evaluation verdict over the finished table.
    struct Task23aEvaluation {
        root: String,
        check: &'static str,
        passed: bool,
        detail: String,
    }

    /// Validated phase-0 inputs: provider bytes, count bytes, and
    /// the required evidence directory.
    type Task23aInputs = (Vec<u8>, Vec<u8>, Option<std::path::PathBuf>);

    /// Pure host-side preparation of every load input: the four
    /// halves plus the patched source preparation and the kernel
    /// description that patched it. Built with no kernel objects;
    /// every failure refuses the diagnostic before acquisition.
    struct Task23aHalves {
        legacy: loader::Prepared,
        registration: loader::Prepared,
        typed: loader::Prepared,
        count_prepared: loader::Prepared,
        source_prepared: loader::Prepared,
        kernel: loader::SourceKernel,
    }

    /// Source-zero evaluation: every non-control root must show zero
    /// own BTF and zero metadata counts between live bracketing
    /// controls, with its legitimate attachment target IDs intact
    /// (exact FUNC target plus a nonzero target object for the
    /// registration roots, no target at all otherwise).
    fn task23a_evaluate_source_zeros(
        table: &[loader::LoadDiagnostics],
        control_before: &ossl_bpf_sys::ProgramInfoSummary,
        control_after: &ossl_bpf_sys::ProgramInfoSummary,
        registration_func: u32,
    ) -> Vec<Task23aEvaluation> {
        let mut evaluations = Vec::new();
        for record in table {
            if record.root == "observation_return" {
                continue;
            }
            let (expected_func, expect_obj) = match record.root.as_str() {
                "source_reg_in" | "source_reg_out" => (registration_func, true),
                _ => (0, false),
            };
            let Some(info) = &record.info else {
                evaluations.push(Task23aEvaluation {
                    root: record.root.clone(),
                    check: "source-zero",
                    passed: false,
                    detail: "no trustworthy program info".to_owned(),
                });
                continue;
            };
            match ossl_bpf_sys::calibration_admits_source_zero(
                control_before,
                info,
                control_after,
                expected_func,
                expect_obj,
            ) {
                Ok(()) => evaluations.push(Task23aEvaluation {
                    root: record.root.clone(),
                    check: "source-zero",
                    passed: true,
                    detail: "zero own metadata between live controls".to_owned(),
                }),
                Err(reason) => evaluations.push(Task23aEvaluation {
                    root: record.root.clone(),
                    check: "source-zero",
                    passed: false,
                    detail: reason.to_owned(),
                }),
            }
        }
        evaluations
    }

    /// Query-identity evaluation across all ten info queries: the two
    /// calibrator snapshots must agree with each other, and every
    /// loaded root's retained query identity must equal the
    /// calibrator's. Only `Loaded` roots verdict: refused roots never
    /// reached `InfoQuery` and unattempted slots never queried, so
    /// their missing identities are expected, never passing.
    fn task23a_evaluate_query_creds(
        table: &[loader::LoadDiagnostics],
        control_before: &ossl_bpf_sys::ThreadCredentials,
        control_after: &ossl_bpf_sys::ThreadCredentials,
    ) -> Vec<Task23aEvaluation> {
        let mut evaluations = Vec::new();
        evaluations.push(Task23aEvaluation {
            root: "observation_return".to_owned(),
            check: "query-creds",
            passed: control_before == control_after,
            detail: if control_before == control_after {
                "calibrator identity stable across diagnostic".to_owned()
            } else {
                "calibrator identity changed across diagnostic".to_owned()
            },
        });
        for record in table {
            if record.stage != loader::LoadStage::Loaded {
                continue;
            }
            match &record.query_creds {
                Some(creds) if creds == control_before => evaluations.push(Task23aEvaluation {
                    root: record.root.clone(),
                    check: "query-creds",
                    passed: true,
                    detail: "query identity matches calibrator".to_owned(),
                }),
                Some(_) => evaluations.push(Task23aEvaluation {
                    root: record.root.clone(),
                    check: "query-creds",
                    passed: false,
                    detail: "query identity differs from calibrator".to_owned(),
                }),
                None => evaluations.push(Task23aEvaluation {
                    root: record.root.clone(),
                    check: "query-creds",
                    passed: false,
                    detail: "loaded without trustworthy query credentials".to_owned(),
                }),
            }
        }
        evaluations
    }

    /// Log-completeness evaluation: a loaded root that ran the
    /// logged attempt must carry a `Complete` program log, so the
    /// evidence the record ships is trustworthy. A quiet success
    /// (`NoLogAttempted` with no quiet errno) never ran the logged
    /// attempt and passes without a log; `Indeterminate` (truncated
    /// or errno-marked) and a quiet failure with no logged attempt
    /// fail their root explicitly. Unattempted slots carry no verdict.
    fn task23a_evaluate_log_completeness(
        table: &[loader::LoadDiagnostics],
    ) -> Vec<Task23aEvaluation> {
        let mut evaluations = Vec::new();
        for record in table {
            if record.stage != loader::LoadStage::Loaded {
                continue;
            }
            let verdict = match (&record.log_completeness, record.quiet_errno) {
                (loader::LogCompleteness::Complete, _) => Ok("program log complete".to_owned()),
                (loader::LogCompleteness::NoLogAttempted, None) => {
                    Ok("quiet success without logged attempt".to_owned())
                }
                (loader::LogCompleteness::NoLogAttempted, Some(_)) => {
                    Err("quiet failed without a logged diagnostic".to_owned())
                }
                (other, _) => Err(format!("program log {other:?}: evidence inconclusive")),
            };
            match verdict {
                Ok(detail) => evaluations.push(Task23aEvaluation {
                    root: record.root.clone(),
                    check: "log-completeness",
                    passed: true,
                    detail,
                }),
                Err(detail) => evaluations.push(Task23aEvaluation {
                    root: record.root.clone(),
                    check: "log-completeness",
                    passed: false,
                    detail,
                }),
            }
        }
        evaluations
    }

    /// Cleanup classification by sweep membership, never by stage
    /// alone. `swept` is true only when the diagnostic held this
    /// root's descriptors in its own sweep set: a loader transaction
    /// that rolled back an earlier success (second-root `?` drops the
    /// whole local collection) leaves an error-free `Loaded` record
    /// whose FDs the sweep never saw, and that record is
    /// `ReleasedByLoader`, never `HandlesClosed`. Slots the loader
    /// never attempted keep no cleanup claim.
    fn task23a_classify_cleanup(
        stage: loader::LoadStage,
        has_error: bool,
        swept: bool,
    ) -> loader::CleanupStatus {
        use loader::{CleanupStatus, LoadStage};
        match (stage, has_error, swept) {
            (LoadStage::Loaded, false, true) => CleanupStatus::HandlesClosed,
            (LoadStage::Loaded, false, false) => CleanupStatus::ReleasedByLoader,
            (LoadStage::Unattempted | LoadStage::Preflight, _, _) => CleanupStatus::Pending,
            (_, true, _) => CleanupStatus::ReleasedByLoader,
            (_, false, _) => CleanupStatus::Pending,
        }
    }

    /// True when one log line carries a retained-kernel bound
    /// diagnostic whose size field equals the expected bound:
    /// `combined stack size of {calls} calls is {size}. Too large`
    /// or `stack size of subprog {idx} is {size}. Too large` (both
    /// retained verifier.c sources emit these identical templates,
    /// EACCES after). Exact bytes within the line; every template
    /// occurrence parses fully, and only the size field binds.
    fn task23a_line_binds_bound(line: &[u8], bound: &[u8]) -> bool {
        fn digits(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
            let len = bytes.iter().take_while(|b| b.is_ascii_digit()).count();
            if len == 0 {
                return None;
            }
            Some((&bytes[..len], &bytes[len..]))
        }
        const TEMPLATES: [(&[u8], &[u8]); 2] = [
            (b"combined stack size of ", b" calls is "),
            (b"stack size of subprog ", b" is "),
        ];
        const SUFFIX: &[u8] = b". Too large";
        for (prefix, infix) in TEMPLATES {
            let mut haystack = line;
            while let Some(at) = haystack.windows(prefix.len()).position(|w| w == prefix) {
                let rest = &haystack[at + prefix.len()..];
                if let Some((_, after_first)) = digits(rest) {
                    if let Some(sized) = after_first.strip_prefix(infix) {
                        if let Some((size, after_size)) = digits(sized) {
                            if after_size.starts_with(SUFFIX) && size == bound {
                                return true;
                            }
                        }
                    }
                }
                haystack = &haystack[at + 1..];
            }
        }
        false
    }

    /// Stack-negative classification over one root's record: accepts
    /// ONLY the named root dying AT load with a `Complete` nonempty
    /// verifier log containing one line that matches a retained-kernel
    /// bound diagnostic with its size field equal to the expected
    /// numeric bound. The logged diagnostic is assessed against its
    /// own attempt: the producing errno must be evidenced and must
    /// not be EPERM/EINVAL, while an earlier quiet errno never vetoes
    /// a genuine logged diagnostic. Everything else is explicitly not
    /// that negative: wrong root, non-numeric expectation, setup
    /// failure, post-load failure, missing logged attempt,
    /// permission/malformed logged errno, empty or partial log,
    /// unbound or wrong diagnostic, and unexpected success. Pure; the
    /// native stack-negative stage (separately granted) consumes it,
    /// this diagnostic proves it.
    fn task23a_classify_stack_negative(
        record: &loader::LoadDiagnostics,
        expected_root: &str,
        expected_bound: &str,
    ) -> Result<(), String> {
        use loader::LoadStage;
        if expected_bound.is_empty() || !expected_bound.bytes().all(|b| b.is_ascii_digit()) {
            return Err("no numeric bound named".to_owned());
        }
        if record.root != expected_root {
            return Err(format!(
                "wrong root: expected {expected_root}, got {}",
                record.root
            ));
        }
        match (&record.stage, record.error.is_some()) {
            (LoadStage::QuietLoad | LoadStage::LoggedLoad, true) => {}
            (LoadStage::Loaded, _) => {
                return Err("unexpected success is not a negative".to_owned());
            }
            (LoadStage::Attestation | LoadStage::InfoQuery, _) => {
                return Err("post-load failure is not a negative".to_owned());
            }
            (_, false) => return Err("no load failure evidenced".to_owned()),
            _ => return Err("setup failure is not a negative".to_owned()),
        }
        // The logged diagnostic is assessed against its own
        // attempt: the producing errno must be evidenced and must not
        // be a permission/malformed refusal. An earlier quiet errno
        // never vetoes a genuine logged diagnostic.
        match record.logged_errno {
            None => return Err("no logged diagnostic evidenced".to_owned()),
            Some(errno) if errno == libc::EPERM || errno == libc::EINVAL => {
                return Err(format!("logged errno {errno} is not a stack diagnostic"));
            }
            Some(_) => {}
        }
        if record.log_bytes.is_empty() {
            return Err("empty log is not a negative".to_owned());
        }
        if record.log_completeness != loader::LogCompleteness::Complete {
            return Err(format!(
                "partial log ({:?}) is not a negative",
                record.log_completeness
            ));
        }
        // The bound diagnostic binds the expected number to the
        // size field of a recognized retained-kernel template on one
        // line. Any other shape — memory errors, negations, split
        // templates, wrong sizes — never passes.
        let bound = expected_bound.as_bytes();
        let matched = record
            .log_bytes
            .split(|b| *b == b'\n')
            .any(|line| task23a_line_binds_bound(line, bound));
        if !matched {
            return Err("log names no bound diagnostic for the intended bound".to_owned());
        }
        Ok(())
    }

    /// Loader route per diagnostic root: the exact observed entry
    /// point each of the nine names must travel. The diagnostic body
    /// below follows this table (legacy pair, four registration
    /// singletons, typed pair, count singleton); the pure
    /// orchestration test pins the table against the expected names.
    fn task23a_loader_route(root: &str) -> Result<&'static str, String> {
        match root {
            "observation_entry" | "observation_return" => Ok("load_gated_observed"),
            "source_reg_in" | "source_reg_out" | "attr_exit" | "attr_exec" => {
                Ok("load_source_root_unattached_observed")
            }
            "typed_entry" | "typed_return" => Ok("load_typed_borrowed_observed"),
            "count_entry" => Ok("load_gated_borrowed_observed"),
            other => Err(format!("no loader route for {other}")),
        }
    }

    fn task23a_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Combine the stop reason with persistence failures for the
    /// `blocked:` line and the terminal panic: a persistence failure
    /// joins (never replaces, never hides behind) an existing stop
    /// reason, and nothing suppresses it when a stop already exists.
    fn task23a_combine_blocked(fatal: Option<&str>, persist: Option<&str>) -> Option<String> {
        match (fatal, persist) {
            (Some(f), Some(p)) => Some(format!("{f}; {p}")),
            (Some(f), None) => Some(f.to_owned()),
            (None, Some(p)) => Some(p.to_owned()),
            (None, None) => None,
        }
    }

    /// Fold a descriptor-leak finding into the stop reason: a leak
    /// joins an existing stop (proving cleanup ran and found
    /// survivors despite the earlier stop), and becomes the stop when
    /// nothing stopped the run. No leak leaves the reason untouched.
    fn task23a_fold_cleanup_leak(fatal: Option<&str>, leaked: &[String]) -> Option<String> {
        if leaked.is_empty() {
            return fatal.map(str::to_owned);
        }
        task23a_combine_blocked(
            fatal,
            Some(&format!("cleanup leaked descriptors: {}", leaked.join(","))),
        )
    }

    /// Deterministic evidence text: per-root receipts in canonical
    /// order, the patch audit, and the evaluation verdicts. Log bytes
    /// enter only as length/true-size/completeness/sha256; raw bytes
    /// ship as separate files, never inline. The calibrator identities
    /// head the report so the per-root `query_creds` lines read
    /// against them, and the global blocking reason is serialized so
    /// a stopped run never omits why it stopped.
    fn task23a_format_evidence(
        table: &[loader::LoadDiagnostics],
        evaluations: &[Task23aEvaluation],
        calibration: Option<(
            &ossl_bpf_sys::ThreadCredentials,
            &ossl_bpf_sys::ThreadCredentials,
        )>,
        blocked: Option<&str>,
        patch_audit: &[(String, Vec<loader::FixupAuditEntry>)],
    ) -> String {
        use sha2::Digest as _;
        let mut out = String::from("task23a unattached nine-root diagnostic evidence\n");
        let loaded = table
            .iter()
            .filter(|r| r.stage == loader::LoadStage::Loaded)
            .count();
        let refused = table.iter().filter(|r| r.error.is_some()).count();
        let unattempted = table
            .iter()
            .filter(|r| r.stage == loader::LoadStage::Unattempted)
            .count();
        out.push_str(&format!(
            "roots: {} loaded={loaded} refused={refused} unattempted={unattempted}\n",
            table.len()
        ));
        match calibration {
            Some((before, after)) => {
                out.push_str(&format!("calibration: before={before:?} after={after:?}\n"))
            }
            None => out.push_str("calibration: unavailable\n"),
        }
        match blocked {
            Some(reason) => out.push_str(&format!("blocked: {reason}\n")),
            None => out.push_str("blocked: none\n"),
        }
        for record in table {
            out.push_str(&format!(
                "--- root {} ({}) ---\n",
                record.root, record.section
            ));
            out.push_str(&format!(
                "stage: {:?}\nartifact: sha256={} len={}\n",
                record.stage,
                task23a_hex(&record.artifact.sha256),
                record.artifact.len
            ));
            out.push_str(&format!(
                "program: type={} attach={} target={} flags={}\n",
                record.prog_type, record.expected_attach, record.attach_target, record.prog_flags
            ));
            out.push_str(&format!(
                "callbacks: {} btf_synthesized: {}\n",
                record.callback_subprogs, record.btf_synthesized
            ));
            out.push_str("maps:");
            for (name, fd) in &record.maps {
                out.push_str(&format!(" {name}={fd}"));
            }
            out.push_str(&format!(
                "\nquiet_errno: {:?} logged_errno: {:?}\n",
                record.quiet_errno, record.logged_errno
            ));
            out.push_str(&format!(
                "log: bytes={} true_size={} completeness={:?} sha256={}\n",
                record.log_bytes.len(),
                record.log_true_size,
                record.log_completeness,
                task23a_hex(&sha2::Sha256::digest(&record.log_bytes)),
            ));
            out.push_str(&format!(
                "btf_log: bytes={} sha256={}\n",
                record.btf_log.len(),
                task23a_hex(&sha2::Sha256::digest(&record.btf_log)),
            ));
            out.push_str(&format!("loaded_id: {:?}\n", record.loaded_id));
            match &record.info {
                Some(info) => out.push_str(&format!(
                    "info: own_btf={} func={} line={} jline={} func_rec={} line_rec={} jline_rec={} attach_obj={} attach_id={} map_ids={:?}\n",
                    info.own_btf_id,
                    info.func_info_count,
                    info.line_info_count,
                    info.jited_line_info_count,
                    info.func_info_rec_size,
                    info.line_info_rec_size,
                    info.jited_line_info_rec_size,
                    info.attach_btf_obj_id,
                    info.attach_btf_id,
                    info.map_ids,
                )),
                None => out.push_str("info: unavailable\n"),
            }
            out.push_str(&format!(
                "info_unavailable: {:?}\nquery_creds: {:?}\n",
                record.info_unavailable, record.query_creds
            ));
            out.push_str(&format!(
                "fixup_audit: {} entries\n",
                record.fixup_audit.len()
            ));
            for entry in &record.fixup_audit {
                out.push_str(&format!(
                    "  site {} spans {:?} role {:?}\n",
                    entry.insn_off, entry.spans, entry.role
                ));
            }
            out.push_str(&format!(
                "cleanup: {:?}\nerror: {:?}\n",
                record.cleanup, record.error
            ));
        }
        out.push_str("--- patch audit ---\n");
        if patch_audit.is_empty() {
            out.push_str("patches: unaudited\n");
        } else {
            for (name, entries) in patch_audit {
                out.push_str(&format!("patch {name}: {} slots\n", entries.len()));
                for entry in entries {
                    out.push_str(&format!(
                        "  slot {} spans {:?} role {:?}\n",
                        entry.insn_off, entry.spans, entry.role
                    ));
                }
            }
        }
        out.push_str("--- evaluations ---\n");
        for evaluation in evaluations {
            out.push_str(&format!(
                "{} {}: {} ({})\n",
                evaluation.check,
                evaluation.root,
                if evaluation.passed { "PASS" } else { "FAIL" },
                evaluation.detail
            ));
        }
        out
    }

    fn task23a_test_pins() -> loader::ArtifactPins {
        loader::ArtifactPins {
            sha256: [9u8; 32],
            len: 77,
        }
    }

    fn task23a_test_summary(prog_id: u32) -> ossl_bpf_sys::ProgramInfoSummary {
        ossl_bpf_sys::ProgramInfoSummary {
            requested_len: 232,
            returned_len: 232,
            prog_type: 2,
            prog_id,
            name: [0u8; 16],
            tag: [0u8; 8],
            map_ids: vec![40],
            own_btf_id: 0,
            func_info_count: 0,
            line_info_count: 0,
            jited_line_info_count: 0,
            func_info_rec_size: 0,
            line_info_rec_size: 0,
            jited_line_info_rec_size: 0,
            attach_btf_obj_id: 0,
            attach_btf_id: 0,
        }
    }

    #[test]
    fn task23a_table_alignment_keeps_explicit_unattempted() {
        let pins = task23a_test_pins();
        let mut table = task23a_unattempted_table(pins, pins);
        assert_eq!(table.len(), 9);
        assert!(
            table
                .iter()
                .all(|r| r.stage == loader::LoadStage::Unattempted)
        );
        // Push two successes out of order; the rest stay unattempted.
        let mut first = loader::LoadDiagnostics::unattempted("typed_entry", "uprobe", pins);
        first.stage = loader::LoadStage::Loaded;
        let mut second = loader::LoadDiagnostics::unattempted("observation_entry", "uprobe", pins);
        second.stage = loader::LoadStage::Loaded;
        task23a_align_records(&mut table, vec![first, second]).unwrap();
        assert_eq!(table[0].stage, loader::LoadStage::Loaded);
        assert_eq!(table[6].stage, loader::LoadStage::Loaded);
        assert!(
            table[1..6]
                .iter()
                .all(|r| r.stage == loader::LoadStage::Unattempted)
        );
        // Unknown and duplicate pushed names are internal errors.
        let unknown = loader::LoadDiagnostics::unattempted("nope", "uprobe", pins);
        assert!(task23a_align_records(&mut table, vec![unknown]).is_err());
        let dupe = loader::LoadDiagnostics::unattempted("typed_entry", "uprobe", pins);
        assert!(task23a_align_records(&mut table, vec![dupe]).is_err());
        // Setup failures map onto named unattempted slots only.
        task23a_refuse_slots(&mut table, &["typed_return", "count_entry"], "boom").unwrap();
        assert_eq!(table[7].stage, loader::LoadStage::Preflight);
        assert_eq!(table[7].error.as_deref(), Some("boom"));
        assert!(task23a_refuse_slots(&mut table, &["typed_entry"], "late").is_err());
        assert!(task23a_refuse_slots(&mut table, &["nope"], "late").is_err());
    }

    #[test]
    fn task23a_source_zero_evaluation_uses_live_controls() {
        let pins = task23a_test_pins();
        let mut table = task23a_unattempted_table(pins, pins);
        // Every non-control root carries clean zero metadata.
        for record in table.iter_mut() {
            let mut info = task23a_test_summary(50);
            if record.root == "source_reg_in" || record.root == "source_reg_out" {
                info.attach_btf_obj_id = 3;
                info.attach_btf_id = 4242;
            }
            record.info = Some(info);
        }
        let mut control = task23a_test_summary(60);
        control.own_btf_id = 5;
        control.func_info_count = 2;
        let evaluations = task23a_evaluate_source_zeros(&table, &control, &control, 4242);
        assert_eq!(evaluations.len(), 8);
        assert!(evaluations.iter().all(|e| e.passed));
        assert!(evaluations.iter().all(|e| e.root != "observation_return"));
        // A dead control fails every root; a dirty source fails one.
        let mut dead = control.clone();
        dead.func_info_count = 0;
        let evaluations = task23a_evaluate_source_zeros(&table, &dead, &control, 4242);
        assert!(evaluations.iter().all(|e| !e.passed));
        table[2].info.as_mut().unwrap().own_btf_id = 1;
        let evaluations = task23a_evaluate_source_zeros(&table, &control, &control, 4242);
        assert!(
            !evaluations
                .iter()
                .find(|e| e.root == "source_reg_in")
                .unwrap()
                .passed
        );
        assert!(
            evaluations
                .iter()
                .find(|e| e.root == "typed_entry")
                .unwrap()
                .passed
        );
        // Missing info fails its root explicitly.
        table[8].info = None;
        let evaluations = task23a_evaluate_source_zeros(&table, &control, &control, 4242);
        let count = evaluations
            .iter()
            .find(|e| e.root == "count_entry")
            .unwrap();
        assert!(!count.passed);
        assert!(count.detail.contains("no trustworthy program info"));
    }

    #[test]
    fn task23a_evidence_format_is_deterministic() {
        let pins = task23a_test_pins();
        let mut table = task23a_unattempted_table(pins, pins);
        table[0].stage = loader::LoadStage::Loaded;
        table[0].info = Some(task23a_test_summary(50));
        table[0].log_bytes = vec![b'A', 0];
        table[0].log_completeness = loader::LogCompleteness::Complete;
        let evaluations = vec![Task23aEvaluation {
            root: "observation_entry".to_owned(),
            check: "source-zero",
            passed: true,
            detail: "zero own metadata between live controls".to_owned(),
        }];
        let first = task23a_format_evidence(&table, &evaluations, None, None, &[]);
        let second = task23a_format_evidence(&table, &evaluations, None, None, &[]);
        assert_eq!(first, second);
        assert!(first.contains("roots: 9 loaded=1 refused=0 unattempted=8"));
        assert!(first.contains("--- root observation_entry (uprobe) ---"));
        assert!(first.contains("source-zero observation_entry: PASS"));
        assert!(first.contains("calibration: unavailable"));
        assert!(first.contains("query_creds: None"));
        assert!(first.contains("blocked: none"));
        assert!(first.contains("patches: unaudited"));
        let blocked = task23a_format_evidence(&table, &evaluations, None, Some("boom"), &[]);
        assert!(blocked.contains("blocked: boom"));
        // Raw log bytes never appear inline, only their digest.
        assert!(!first.contains("vec![65, 0]"));
        assert!(first.contains("log: bytes=2"));
    }

    #[test]
    fn task23a_blocked_combination_keeps_both_reasons() {
        assert_eq!(task23a_combine_blocked(None, None), None);
        assert_eq!(
            task23a_combine_blocked(Some("stop"), None),
            Some("stop".to_owned())
        );
        assert_eq!(
            task23a_combine_blocked(None, Some("persist")),
            Some("persist".to_owned())
        );
        // A persistence failure joins an existing stop; neither hides.
        assert_eq!(
            task23a_combine_blocked(Some("stop"), Some("persist")),
            Some("stop; persist".to_owned())
        );
    }

    #[test]
    fn task23a_cleanup_leak_folds_into_any_stop() {
        let empty: Vec<String> = Vec::new();
        assert_eq!(task23a_fold_cleanup_leak(None, &empty), None);
        assert_eq!(
            task23a_fold_cleanup_leak(Some("stop"), &empty),
            Some("stop".to_owned())
        );
        // A leak with no earlier stop becomes the stop.
        assert_eq!(
            task23a_fold_cleanup_leak(None, &["a".to_owned(), "b".to_owned()]),
            Some("cleanup leaked descriptors: a,b".to_owned())
        );
        // A leak with an existing stop joins it; neither hides.
        assert_eq!(
            task23a_fold_cleanup_leak(Some("stop"), &["a".to_owned()]),
            Some("stop; cleanup leaked descriptors: a".to_owned())
        );
    }

    #[test]
    fn task23a_required_sha_parse_is_strict() {
        let good = "9f".repeat(32);
        let parsed = task23a_parse_sha_hex(&good).unwrap();
        assert_eq!(parsed, [0x9fu8; 32]);
        assert!(task23a_parse_sha_hex(&"9f".repeat(31)).is_err());
        assert!(task23a_parse_sha_hex(&("9f".repeat(32) + "00")).is_err());
        assert!(task23a_parse_sha_hex(&"9F".repeat(32)).is_err());
        let mut bad = "9f".repeat(32);
        bad.replace_range(0..2, "zz");
        assert!(task23a_parse_sha_hex(&bad).is_err());
        assert!(task23a_parse_sha_hex("").is_err());
        // Missing variable refuses; the diagnostic never defaults.
        assert!(task23a_required_sha("OSSL_TASK23A_DEFINITELY_UNSET_PIN").is_err());
    }

    #[test]
    fn task23a_query_creds_evaluation_compares_all_identities() {
        let pins = task23a_test_pins();
        let mut table = task23a_unattempted_table(pins, pins);
        let creds = ossl_bpf_sys::ThreadCredentials {
            caps: [[0u32; 3]; 2],
            euid: 0,
            tid: 7,
            userns_dev: 1,
            userns_ino: 2,
        };
        let other = ossl_bpf_sys::ThreadCredentials { tid: 8, ..creds };
        // Stable calibrator, one matching root, one mismatched, one
        // loaded-but-untrusted; the rest stay unattempted and verdict
        // nothing.
        table[0].stage = loader::LoadStage::Loaded;
        table[0].query_creds = Some(creds);
        table[1].stage = loader::LoadStage::Loaded;
        table[1].query_creds = Some(other);
        table[2].stage = loader::LoadStage::Loaded;
        table[2].query_creds = None;
        let evaluations = task23a_evaluate_query_creds(&table, &creds, &creds);
        assert_eq!(evaluations.len(), 4);
        // [0] is the stable-calibrator check; the observation_return
        // root then carries its own mismatched verdict.
        assert!(evaluations[0].passed);
        assert!(
            evaluations
                .iter()
                .find(|e| e.root == "observation_entry")
                .unwrap()
                .passed
        );
        let control_root: Vec<_> = evaluations
            .iter()
            .filter(|e| e.root == "observation_return")
            .collect();
        assert_eq!(control_root.len(), 2);
        assert!(control_root.iter().any(|e| e.passed));
        assert!(control_root.iter().any(|e| !e.passed));
        assert!(
            !evaluations
                .iter()
                .find(|e| e.root == "source_reg_in")
                .unwrap()
                .passed
        );
        // A changed calibrator fails the calibration check itself.
        let evaluations = task23a_evaluate_query_creds(&table, &creds, &other);
        assert!(!evaluations[0].passed);
        assert!(evaluations[0].detail.contains("changed"));
    }

    #[test]
    fn task23a_log_completeness_evaluation_requires_complete() {
        let pins = task23a_test_pins();
        let mut table = task23a_unattempted_table(pins, pins);
        table[0].stage = loader::LoadStage::Loaded;
        table[0].log_completeness = loader::LogCompleteness::Complete;
        table[1].stage = loader::LoadStage::Loaded;
        table[1].log_completeness = loader::LogCompleteness::Indeterminate;
        // A quiet success never ran the logged attempt: no log is
        // the valid receipt. A quiet failure with no logged attempt
        // is missing evidence, not a pass.
        table[2].stage = loader::LoadStage::Loaded;
        table[2].log_completeness = loader::LogCompleteness::NoLogAttempted;
        table[2].quiet_errno = None;
        table[3].stage = loader::LoadStage::Loaded;
        table[3].log_completeness = loader::LogCompleteness::NoLogAttempted;
        table[3].quiet_errno = Some(libc::EACCES);
        let evaluations = task23a_evaluate_log_completeness(&table);
        assert_eq!(evaluations.len(), 4);
        assert!(evaluations[0].passed);
        assert!(!evaluations[1].passed);
        assert!(evaluations[1].detail.contains("Indeterminate"));
        assert!(evaluations[2].passed);
        assert!(evaluations[2].detail.contains("quiet success"));
        assert!(!evaluations[3].passed);
        assert!(
            evaluations[3]
                .detail
                .contains("without a logged diagnostic")
        );
    }

    #[test]
    fn task23a_cleanup_classification_follows_sweep_membership() {
        use loader::{CleanupStatus, LoadStage};
        // Swept loaded roots close; unswept loaded roots (second-root
        // rollback inside a failed loader transaction) release by
        // loader, even with no error on their record.
        assert_eq!(
            task23a_classify_cleanup(LoadStage::Loaded, false, true),
            CleanupStatus::HandlesClosed
        );
        assert_eq!(
            task23a_classify_cleanup(LoadStage::Loaded, false, false),
            CleanupStatus::ReleasedByLoader
        );
        // Attempted failures release by loader; untouched slots keep
        // no claim; inconsistent non-loaded success claims nothing.
        assert_eq!(
            task23a_classify_cleanup(LoadStage::LoggedLoad, true, false),
            CleanupStatus::ReleasedByLoader
        );
        assert_eq!(
            task23a_classify_cleanup(LoadStage::MapSetup, true, true),
            CleanupStatus::ReleasedByLoader
        );
        assert_eq!(
            task23a_classify_cleanup(LoadStage::Preflight, true, false),
            CleanupStatus::Pending
        );
        assert_eq!(
            task23a_classify_cleanup(LoadStage::Unattempted, false, false),
            CleanupStatus::Pending
        );
        assert_eq!(
            task23a_classify_cleanup(LoadStage::Fixup, false, true),
            CleanupStatus::Pending
        );
    }

    /// A valid stack negative: the named root died at the logged
    /// load with verifier errno and a complete log carrying the
    /// retained kernels' combined bound diagnostic verbatim.
    fn task23a_negative_fixture() -> loader::LoadDiagnostics {
        let mut record =
            loader::LoadDiagnostics::unattempted("count_entry", "uprobe", task23a_test_pins());
        record.stage = loader::LoadStage::LoggedLoad;
        record.error = Some("verifier rejected".to_owned());
        record.quiet_errno = Some(libc::EACCES);
        record.logged_errno = Some(libc::EACCES);
        record.log_bytes = b"combined stack size of 3 calls is 816. Too large\0".to_vec();
        record.log_true_size = record.log_bytes.len() as u32;
        record.log_completeness = loader::LogCompleteness::Complete;
        record
    }

    #[test]
    fn task23a_stack_negative_accepts_only_the_named_bound() {
        let record = task23a_negative_fixture();
        assert!(task23a_classify_stack_negative(&record, "count_entry", "816").is_ok());
        // Wrong root, non-numeric expectation, and every non-negative.
        assert!(task23a_classify_stack_negative(&record, "typed_entry", "816").is_err());
        assert!(task23a_classify_stack_negative(&record, "count_entry", "").is_err());
        assert!(task23a_classify_stack_negative(&record, "count_entry", "chain816").is_err());
        let mut setup = record.clone();
        setup.stage = loader::LoadStage::MapSetup;
        assert!(task23a_classify_stack_negative(&setup, "count_entry", "816").is_err());
        let mut attest = record.clone();
        attest.stage = loader::LoadStage::Attestation;
        assert!(task23a_classify_stack_negative(&attest, "count_entry", "816").is_err());
        let mut success = record.clone();
        success.stage = loader::LoadStage::Loaded;
        success.error = None;
        assert!(task23a_classify_stack_negative(&success, "count_entry", "816").is_err());
        let mut no_attempt = record.clone();
        no_attempt.quiet_errno = None;
        no_attempt.logged_errno = None;
        assert!(task23a_classify_stack_negative(&no_attempt, "count_entry", "816").is_err());
        // The logged attempt governs its own diagnostic: a logged
        // permission/malformed errno refuses, while an earlier quiet
        // errno never vetoes a genuine logged rejection.
        let mut eperm = record.clone();
        eperm.logged_errno = Some(libc::EPERM);
        assert!(task23a_classify_stack_negative(&eperm, "count_entry", "816").is_err());
        let mut logged_einval = record.clone();
        logged_einval.logged_errno = Some(libc::EINVAL);
        assert!(task23a_classify_stack_negative(&logged_einval, "count_entry", "816").is_err());
        let mut quiet_einval = record.clone();
        quiet_einval.quiet_errno = Some(libc::EINVAL);
        assert!(task23a_classify_stack_negative(&quiet_einval, "count_entry", "816").is_ok());
        let mut quiet_eperm = record.clone();
        quiet_eperm.quiet_errno = Some(libc::EPERM);
        assert!(task23a_classify_stack_negative(&quiet_eperm, "count_entry", "816").is_ok());
        let mut empty = record.clone();
        empty.log_bytes.clear();
        assert!(task23a_classify_stack_negative(&empty, "count_entry", "816").is_err());
        let mut partial = record.clone();
        partial.log_completeness = loader::LogCompleteness::Indeterminate;
        assert!(task23a_classify_stack_negative(&partial, "count_entry", "816").is_err());
        // The individual-frame template binds the same way.
        let mut frame = record.clone();
        frame.log_bytes = b"stack size of subprog 1 is 520. Too large".to_vec();
        assert!(task23a_classify_stack_negative(&frame, "count_entry", "520").is_ok());
        // Wrong size, and the size must be the template's field, not
        // a bare number elsewhere on the line.
        assert!(task23a_classify_stack_negative(&record, "count_entry", "815").is_err());
        let mut elsewhere = record.clone();
        elsewhere.log_bytes =
            b"note 816: combined stack size of 3 calls is 815. Too large".to_vec();
        assert!(task23a_classify_stack_negative(&elsewhere, "count_entry", "816").is_err());
        // Same-line non-bound diagnostics refuse: stack-memory error
        // and negated bound language, both carrying the number.
        let mut mem_error = record.clone();
        mem_error.log_bytes = b"invalid read from stack off -8+0 size 8 in frame 816".to_vec();
        assert!(task23a_classify_stack_negative(&mem_error, "count_entry", "816").is_err());
        let mut negated = record.clone();
        negated.log_bytes =
            b"stack limit 512 not exceeded; 816 rejected for invalid access".to_vec();
        assert!(task23a_classify_stack_negative(&negated, "count_entry", "816").is_err());
        // A template split across lines never binds; a genuine
        // multi-line log binds on its rejection line.
        let mut split = record.clone();
        split.log_bytes = b"combined stack size of 3 calls is 816.\nToo large".to_vec();
        assert!(task23a_classify_stack_negative(&split, "count_entry", "816").is_err());
        let mut multiline = record.clone();
        multiline.log_bytes =
            b"verifier error:\ncombined stack size of 3 calls is 816. Too large\n".to_vec();
        assert!(task23a_classify_stack_negative(&multiline, "count_entry", "816").is_ok());
        // Leading bytes on the line do not break the template.
        let mut prefixed = record.clone();
        prefixed.log_bytes = b"\xffcombined stack size of 3 calls is 816. Too large".to_vec();
        assert!(task23a_classify_stack_negative(&prefixed, "count_entry", "816").is_ok());
        // Every template occurrence on the line parses: a mismatching
        // first diagnostic does not shadow a matching second.
        let mut two = record.clone();
        two.log_bytes =
            b"combined stack size of 3 calls is 815. Too large; combined stack size of 4 calls is 816. Too large"
                .to_vec();
        assert!(task23a_classify_stack_negative(&two, "count_entry", "816").is_ok());
        assert!(task23a_classify_stack_negative(&two, "count_entry", "815").is_ok());
        assert!(task23a_classify_stack_negative(&two, "count_entry", "814").is_err());
    }

    #[test]
    fn task23a_loader_routes_cover_all_nine_roots() {
        let mut routes = std::collections::BTreeMap::new();
        for (name, _) in task23a_expected_roots() {
            routes.insert(name, task23a_loader_route(name).unwrap());
        }
        assert_eq!(routes.len(), 9);
        assert_eq!(routes["observation_entry"], "load_gated_observed");
        assert_eq!(routes["observation_return"], "load_gated_observed");
        for root in ["source_reg_in", "source_reg_out", "attr_exit", "attr_exec"] {
            assert_eq!(routes[root], "load_source_root_unattached_observed");
        }
        assert_eq!(routes["typed_entry"], "load_typed_borrowed_observed");
        assert_eq!(routes["typed_return"], "load_typed_borrowed_observed");
        assert_eq!(routes["count_entry"], "load_gated_borrowed_observed");
        assert!(task23a_loader_route("nope").is_err());
    }

    /// One trustworthy calibrator query: credential snapshot, info
    /// query, credential snapshot. Unchanged privileged credentials
    /// plus a decodable reply yield the summary and the retained
    /// identity; anything else is an explicit refusal, never an
    /// assumption. The identity ships to evidence and the
    /// cross-query evaluation, not just this query's bracketing.
    fn task23a_calibration_query(
        program: &std::os::fd::OwnedFd,
    ) -> Result<
        (
            ossl_bpf_sys::ProgramInfoSummary,
            ossl_bpf_sys::ThreadCredentials,
        ),
        String,
    > {
        use std::os::fd::AsFd as _;
        let before = ossl_bpf_sys::calling_thread_credentials()
            .map_err(|e| format!("calibrator credentials unavailable: {e}"))?;
        let summary = ossl_bpf_sys::program_info_summary(program.as_fd())
            .map_err(|e| format!("calibrator info query refused: {e}"))?;
        let after = ossl_bpf_sys::calling_thread_credentials()
            .map_err(|e| format!("calibrator credentials unavailable: {e}"))?;
        if before != after {
            return Err("calibrator credentials changed around query".to_owned());
        }
        if !ossl_bpf_sys::has_bpf_query_capabilities(&before) {
            return Err("calibrator query privilege missing".to_owned());
        }
        Ok((summary, before))
    }

    #[test]
    #[ignore = "Task23A unattached nine-root diagnostic: privileged BPF plus both production objects, no attach"]
    fn task23a_unattached_nine_root_diagnostic() {
        use sha2::Digest as _;
        use std::collections::BTreeMap;
        use std::os::fd::{AsFd as _, AsRawFd as _};
        use std::sync::atomic::AtomicBool;
        use std::time::{Duration, Instant};
        // Phase 0: required host inputs. Artifact bytes, required
        // expected-sha256 pins, and the evidence directory validate
        // here, before the table exists and before any kernel object.
        // Any failure refuses every slot; the terminal protocol
        // (stdout evidence, cleanup sweep, panic with the reason)
        // still runs. Nothing defaults, nothing stamps.
        let setup: Result<Task23aInputs, String> = (|| {
            let provider_path = std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF")
                .ok_or_else(|| "missing OSSL_PROVIDER_OBSERVATION_TEST_BPF".to_owned())?;
            let count_path = std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT")
                .ok_or_else(|| "missing OSSLSCOPE_FOCUSED_COUNT_OBJECT".to_owned())?;
            let provider = std::fs::read(&provider_path)
                .map_err(|e| format!("provider object read refused: {e}"))?;
            let count = std::fs::read(&count_path)
                .map_err(|e| format!("count object read refused: {e}"))?;
            let expected_provider = task23a_required_sha("OSSL_TASK23A_EXPECTED_PROVIDER_SHA256")?;
            let expected_count = task23a_required_sha("OSSL_TASK23A_EXPECTED_COUNT_SHA256")?;
            let actual_provider: [u8; 32] = sha2::Sha256::digest(&provider).into();
            if actual_provider != expected_provider {
                return Err(format!(
                    "provider sha256 mismatch actual={} expected={}",
                    task23a_hex(&actual_provider),
                    task23a_hex(&expected_provider)
                ));
            }
            let actual_count: [u8; 32] = sha2::Sha256::digest(&count).into();
            if actual_count != expected_count {
                return Err(format!(
                    "count sha256 mismatch actual={} expected={}",
                    task23a_hex(&actual_count),
                    task23a_hex(&expected_count)
                ));
            }
            // The raw-artifact destination is required: acquisition
            // without a persistence target is refused outright.
            let evidence_dir = match std::env::var_os("OSSL_TASK23A_EVIDENCE_DIR") {
                None => return Err("required OSSL_TASK23A_EVIDENCE_DIR missing".to_owned()),
                Some(dir) => {
                    let dir = std::path::PathBuf::from(dir);
                    if !dir.is_dir() {
                        return Err(format!("evidence dir missing: {}", dir.display()));
                    }
                    Some(dir)
                }
            };
            Ok((provider, count, evidence_dir))
        })();
        let (provider, count, evidence_dir, mut table, mut fatal) = match setup {
            Ok((provider, count, evidence_dir)) => {
                let provider_pins = loader::ArtifactPins {
                    sha256: sha2::Sha256::digest(&provider).into(),
                    len: provider.len() as u64,
                };
                let count_pins = loader::ArtifactPins {
                    sha256: sha2::Sha256::digest(&count).into(),
                    len: count.len() as u64,
                };
                println!(
                    "provider sha256={} len={} count sha256={} len={}",
                    task23a_hex(&provider_pins.sha256),
                    provider.len(),
                    task23a_hex(&count_pins.sha256),
                    count.len()
                );
                (
                    Some(provider),
                    Some(count),
                    evidence_dir,
                    task23a_unattempted_table(provider_pins, count_pins),
                    None,
                )
            }
            Err(error) => {
                let zero = loader::ArtifactPins {
                    sha256: [0u8; 32],
                    len: 0,
                };
                let mut table = task23a_unattempted_table(zero, zero);
                task23a_refuse_all(&mut table, &error);
                (None, None, None, table, Some(error))
            }
        };
        let provider_pins = table[0].artifact;
        let count_pins = table[8].artifact;
        // Phase 1: pure preparation of every load input (host reads
        // only), then the nine-root preflight BEFORE any kernel
        // object exists. Fallible throughout: failures refuse all
        // slots and skip every acquisition below.
        let pool = crate::observation_memory::MemoryPool::new(256 << 20);
        let mut budget = ObservationBudget::new(super::super::ObservationLimits::default());
        budget.memory = Some(pool.clone());
        let mut halves: Option<Task23aHalves> = None;
        // Patch audit entries per source-prepared program, in prepared
        // order. Assigned inside phase 1 the moment the audit
        // completes, so a LATER preparation failure retains the
        // completed audit instead of discarding it; empty ⟺ no audit
        // completed (see the blocked reason).
        let mut patch_audit: Vec<(String, Vec<loader::FixupAuditEntry>)> = Vec::new();
        if fatal.is_none() {
            let provider = provider.as_ref().unwrap();
            let count = count.as_ref().unwrap();
            let built: Result<Task23aHalves, (String, Vec<&'static str>)> = (|| {
                let legacy = crate::provider_observation::session::prepare_legacy_object(provider)
                    .map_err(|e| {
                        (
                            format!("legacy preparation refused: {e:?}"),
                            TASK23A_LEGACY_SLOTS.to_vec(),
                        )
                    })?;
                let full = crate::provider_observation::session::prepare_object(provider).map_err(
                    |e| {
                        (
                            format!("provider preparation refused: {e:?}"),
                            TASK23A_PROVIDER_SLOTS.to_vec(),
                        )
                    },
                )?;
                let (_, mut source_prepared) =
                    crate::provider_observation::session::split_source_preparation(full);
                let kernel = loader::SourceKernel::read(&budget).map_err(|e| {
                    (
                        format!("kernel description refused: {e:?}"),
                        TASK23A_SOURCE_SLOTS.to_vec(),
                    )
                })?;
                // Snapshot every image, patch, then audit each
                // pre-patch-to-final pair against the admitted
                // configuration before any split or load consumes it.
                let patch_before = source_prepared.progs.clone();
                kernel.patch(&mut source_prepared).map_err(|e| {
                    (
                        format!("source patch refused: {e:?}"),
                        TASK23A_SOURCE_SLOTS.to_vec(),
                    )
                })?;
                let configuration = kernel.patch_configuration();
                let mut audit = Vec::with_capacity(source_prepared.progs.len());
                for (before_prog, after_prog) in
                    patch_before.iter().zip(source_prepared.progs.iter())
                {
                    let entries =
                        loader::audit_patch_images(before_prog, after_prog, &configuration)
                            .map_err(|e| {
                                (
                                    format!("patch audit {} refused: {e:#}", before_prog.name),
                                    TASK23A_SOURCE_SLOTS.to_vec(),
                                )
                            })?;
                    audit.push((before_prog.name.clone(), entries));
                }
                // Retain immediately: later steps may still fail.
                patch_audit = audit;
                let (registration, typed) =
                    loader::split_typed_preparation(source_prepared.clone()).map_err(|e| {
                        (
                            format!("typed split refused: {e:#}"),
                            TASK23A_SOURCE_SLOTS.to_vec(),
                        )
                    })?;
                // Count runs the identical production pipeline with
                // the patch audit inserted at the exposed boundary:
                // unpatched prep, snapshot, production patch, audit
                // against an independently read join layout, then the
                // shared post-patch allowlist.
                let mut count_prepared =
                    loader::prepare_focused_count_unpatched(count).map_err(|e| {
                        (
                            format!("count preparation refused: {e:#}"),
                            TASK23A_COUNT_SLOTS.to_vec(),
                        )
                    })?;
                let count_before = count_prepared.progs.clone();
                loader::patch_count_markers(&mut count_prepared, &ObservationBudget::default())
                    .map_err(|e| {
                        (
                            format!("count patch refused: {e:?}"),
                            TASK23A_COUNT_SLOTS.to_vec(),
                        )
                    })?;
                let join = loader::JoinKernel::read_join(&budget).map_err(|e| {
                    (
                        format!("join description refused: {e:?}"),
                        TASK23A_COUNT_SLOTS.to_vec(),
                    )
                })?;
                let join_configuration = join.patch_configuration();
                let mut count_audit = Vec::with_capacity(count_prepared.progs.len());
                for (before_prog, after_prog) in
                    count_before.iter().zip(count_prepared.progs.iter())
                {
                    let entries =
                        loader::audit_patch_images(before_prog, after_prog, &join_configuration)
                            .map_err(|e| {
                                (
                                    format!(
                                        "count patch audit {} refused: {e:#}",
                                        before_prog.name
                                    ),
                                    TASK23A_COUNT_SLOTS.to_vec(),
                                )
                            })?;
                    count_audit.push((before_prog.name.clone(), entries));
                }
                patch_audit.extend(count_audit);
                loader::check_focused_count_post_patch(&count_prepared).map_err(|e| {
                    (
                        format!("count post-patch check refused: {e:#}"),
                        TASK23A_COUNT_SLOTS.to_vec(),
                    )
                })?;
                Ok(Task23aHalves {
                    legacy,
                    registration,
                    typed,
                    count_prepared,
                    source_prepared,
                    kernel,
                })
            })();
            match built {
                Ok(halves_built) => {
                    halves = Some(halves_built);
                }
                Err((error, slots)) => {
                    // Phase-1 slots are fresh (see consts): refusal is total.
                    task23a_refuse_slots(&mut table, &slots, &error).unwrap();
                    fatal = Some(error);
                }
            }
        }
        if fatal.is_none() {
            let halves = halves.as_ref().unwrap();
            if let Err(error) = loader::preflight_nine_roots(
                &halves.legacy,
                &halves.registration,
                &halves.typed,
                &halves.count_prepared,
            ) {
                let fatal_error = format!("nine-root preflight refused: {error:#}");
                task23a_refuse_all(&mut table, &fatal_error);
                fatal = Some(fatal_error);
            }
        }
        // First kernel objects: the gate (which owns kernel maps),
        // then the exact legacy pair through the observed route.
        // Skipped outright when setup or preflight already refused:
        // no acquisition after refusal. Fail-fast from here: later
        // roots stay explicitly unattempted after the first refusal,
        // but cleanup, report flush, and terminal evaluation always run.
        let mut gate: Option<WriterGate> = None;
        if fatal.is_none() {
            match WriterGate::create(&pool) {
                Ok(created) => {
                    assert!(created.preparing());
                    gate = Some(created);
                }
                Err(error) => {
                    let fatal_error = format!("writer gate creation refused: {error}");
                    task23a_refuse_all(&mut table, &fatal_error);
                    fatal = Some(fatal_error);
                }
            }
        }
        let mut records: Vec<loader::LoadDiagnostics> = Vec::new();
        let loaded = if fatal.is_none() {
            let halves = halves.as_ref().unwrap();
            let gate = gate.as_ref().unwrap();
            match loader::load_gated_observed(&halves.legacy, gate, provider_pins, &mut records) {
                Ok(loaded) => Some(loaded),
                Err(error) => {
                    fatal = Some(format!("legacy observed load refused: {error:#}"));
                    None
                }
            }
        } else {
            None
        };
        let owner = if fatal.is_none() {
            let loaded = loaded.as_ref().unwrap();
            let gate = gate.as_ref().unwrap();
            let halves = halves.as_mut().unwrap();
            match SourceOwner::prepare(
                &budget,
                &halves.kernel,
                gate,
                loaded,
                &mut halves.source_prepared,
                Instant::now() + Duration::from_secs(60),
                &AtomicBool::new(false),
            ) {
                Ok(owner) => Some(owner),
                Err(error) => {
                    let reason = format!("source owner prepare refused: {error:?}");
                    // The owner feeds every non-legacy root; all seven
                    // slots are still fresh (their loads never ran).
                    task23a_refuse_slots(&mut table, &TASK23A_NON_LEGACY_SLOTS, &reason).unwrap();
                    fatal = Some(reason);
                    None
                }
            }
        } else {
            None
        };
        // Calibrator identity is retained with each summary: the
        // cross-query evaluation compares all ten query identities,
        // never just each query's own bracketing.
        let mut control_before = None;
        let mut control_after = None;
        let mut control_creds_before = None;
        let mut control_creds_after = None;
        if fatal.is_none() {
            let loaded = loaded.as_ref().unwrap();
            match loaded.progs.get("observation_return") {
                None => fatal = Some("legacy calibrator program missing".to_owned()),
                Some(program) => match task23a_calibration_query(program) {
                    Ok((summary, creds)) => {
                        control_before = Some(summary);
                        control_creds_before = Some(creds);
                    }
                    Err(error) => fatal = Some(error),
                },
            }
        }
        // Source roots load from the same split registration
        // preparation the preflight checked — never from the admitted
        // owner's copy — and the attested programs are retained for
        // the descriptor sweep. The diagnostic stops at FDs: nothing
        // attaches.
        let mut source_programs: Vec<(String, std::os::fd::OwnedFd)> = Vec::new();
        if fatal.is_none() {
            let owner = owner.as_ref().unwrap();
            let loaded = loaded.as_ref().unwrap();
            let halves = halves.as_ref().unwrap();
            let gate = gate.as_ref().unwrap();
            // The singleton loop consumes exactly the preflighted
            // registration half: every loop input must route to the
            // singleton entry point. A wrong-half input fails loudly
            // here instead of misloading downstream (earlier
            // successes stay retained and swept per fail-fast).
            for root in &halves.registration.progs {
                match task23a_loader_route(&root.name) {
                    Ok("load_source_root_unattached_observed") => {}
                    _ => {
                        fatal = Some(format!("singleton loop misrouted root {}", root.name));
                        break;
                    }
                }
                match loader::load_source_root_unattached_observed(
                    root,
                    &owner._maps,
                    loaded,
                    owner._roots.attach_btf_id(),
                    gate,
                    provider_pins,
                    &mut records,
                ) {
                    Ok(program) => source_programs.push((root.name.clone(), program)),
                    Err(error) => {
                        fatal = Some(format!("source root {} refused: {error:#}", root.name));
                        break;
                    }
                }
            }
        }
        let typed_programs = if fatal.is_none() {
            let owner = owner.as_ref().unwrap();
            let loaded = loaded.as_ref().unwrap();
            let halves = halves.as_ref().unwrap();
            let gate = gate.as_ref().unwrap();
            match loader::load_typed_borrowed_observed(
                &halves.typed,
                &owner._maps,
                loaded,
                gate,
                provider_pins,
                &mut records,
            ) {
                Ok(programs) => Some(programs),
                Err(error) => {
                    fatal = Some(format!("typed observed load refused: {error:#}"));
                    None
                }
            }
        } else {
            None
        };
        let count_loaded = if fatal.is_none() {
            let owner = owner.as_ref().unwrap();
            let halves = halves.as_ref().unwrap();
            let gate = gate.as_ref().unwrap();
            let mut borrowed = BTreeMap::new();
            for name in loader::BORROWED_COUNT_MAPS {
                match owner.owned_map(name) {
                    Ok(fd) => {
                        borrowed.insert(name.to_string(), fd);
                    }
                    Err(error) => {
                        let reason = format!("count borrowed map {name} refused: {error:?}");
                        // The count load never ran: its slot is fresh.
                        task23a_refuse_slots(&mut table, &TASK23A_COUNT_SLOTS, &reason).unwrap();
                        fatal = Some(reason);
                        break;
                    }
                }
            }
            if fatal.is_none() {
                match loader::load_gated_borrowed_observed(
                    &halves.count_prepared,
                    gate,
                    &borrowed,
                    count_pins,
                    &mut records,
                ) {
                    Ok(loaded) => Some(loaded),
                    Err(error) => {
                        fatal = Some(format!("count observed load refused: {error:#}"));
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };
        if fatal.is_none() {
            let loaded = loaded.as_ref().unwrap();
            match loaded.progs.get("observation_return") {
                None => fatal = Some("legacy calibrator program missing".to_owned()),
                Some(program) => match task23a_calibration_query(program) {
                    Ok((summary, creds)) => {
                        control_after = Some(summary);
                        control_creds_after = Some(creds);
                    }
                    Err(error) => fatal = Some(error),
                },
            }
        }
        task23a_align_records(&mut table, records).unwrap();
        // Evaluations: source zeros, per-root live map-identity
        // cross-checks (prepared references resolved to the same
        // gate and borrowed identities, compared to the info set),
        // cross-query credential identities, and log completeness.
        let mut evaluations = Vec::new();
        if fatal.is_none() {
            let before = control_before.as_ref().unwrap();
            let after = control_after.as_ref().unwrap();
            let creds_before = control_creds_before.as_ref().unwrap();
            let creds_after = control_creds_after.as_ref().unwrap();
            let owner = owner.as_ref().unwrap();
            let halves = halves.as_ref().unwrap();
            evaluations.extend(task23a_evaluate_source_zeros(
                &table,
                before,
                after,
                owner._roots.attach_btf_id(),
            ));
            evaluations.extend(task23a_evaluate_query_creds(
                &table,
                creds_before,
                creds_after,
            ));
            evaluations.extend(task23a_evaluate_log_completeness(&table));
            let loaded = loaded.as_ref().unwrap();
            let resolve = |root: &str, map: &str| -> Result<u32, String> {
                let fd = if root == "count_entry" {
                    count_loaded
                        .as_ref()
                        .unwrap()
                        .maps
                        .get(map)
                        .map(|owned| owned.as_fd())
                } else if root == "observation_entry" || root == "observation_return" {
                    loaded.maps.get(map).map(|owned| owned.as_fd())
                } else {
                    owner
                        ._maps
                        .get(map)
                        .map(|owned| owned.as_fd())
                        .or_else(|| loaded.maps.get(map).map(|owned| owned.as_fd()))
                }
                .ok_or_else(|| format!("map identity unresolved {map}"))?;
                loader::BorrowedMap::new(fd)
                    .map(|borrowed| borrowed.info.id)
                    .map_err(|e| format!("map identity query refused: {e}"))
            };
            let prepared_for = |root: &str| -> Option<&loader::PreparedProg> {
                if root == "count_entry" {
                    halves.count_prepared.progs.iter().find(|p| p.name == root)
                } else if root == "typed_entry" || root == "typed_return" {
                    halves.typed.progs.iter().find(|p| p.name == root)
                } else if root == "observation_entry" || root == "observation_return" {
                    halves.legacy.progs.iter().find(|p| p.name == root)
                } else {
                    halves.registration.progs.iter().find(|p| p.name == root)
                }
            };
            for record in table.iter() {
                let check = (|| -> Result<(), String> {
                    let info = record
                        .info
                        .as_ref()
                        .ok_or_else(|| "no trustworthy program info".to_owned())?;
                    let prepared = prepared_for(&record.root)
                        .ok_or_else(|| "prepared root missing".to_owned())?;
                    let mut expected = Vec::with_capacity(prepared.map_fixups.len());
                    for fixup in &prepared.map_fixups {
                        expected.push(resolve(&record.root, &fixup.map)?);
                    }
                    // One map referenced by several fixups reports one
                    // kernel ID: compare identity sets, never multisets.
                    expected.sort_unstable();
                    expected.dedup();
                    loader::check_map_id_set(&expected, &info.map_ids).map_err(|e| format!("{e:#}"))
                })();
                match check {
                    Ok(()) => evaluations.push(Task23aEvaluation {
                        root: record.root.clone(),
                        check: "map-ids",
                        passed: true,
                        detail: "info set matches live identities".to_owned(),
                    }),
                    Err(detail) => evaluations.push(Task23aEvaluation {
                        root: record.root.clone(),
                        check: "map-ids",
                        passed: false,
                        detail,
                    }),
                }
            }
        }
        // Cleanup verification: every owned descriptor number
        // closes, including the retained unattached source programs.
        // FDs are collected before the ordered drop, then proven gone.
        let mut owned_fds: Vec<(String, i32)> = Vec::new();
        if let Some(loaded) = loaded.as_ref() {
            for (name, fd) in loaded.maps.iter().chain(loaded.progs.iter()) {
                owned_fds.push((format!("legacy:{name}"), fd.as_raw_fd()));
            }
        }
        if let Some(owner) = owner.as_ref() {
            for (name, fd) in owner._maps.iter() {
                owned_fds.push((format!("owner:{name}"), fd.as_raw_fd()));
            }
        }
        for (name, fd) in source_programs.iter() {
            owned_fds.push((format!("source:{name}"), fd.as_raw_fd()));
        }
        if let Some(programs) = typed_programs.as_ref() {
            for (name, fd) in programs.iter() {
                owned_fds.push((format!("typed:{name}"), fd.as_raw_fd()));
            }
        }
        if let Some(count_loaded) = count_loaded.as_ref() {
            for (name, fd) in count_loaded.maps.iter().chain(count_loaded.progs.iter()) {
                owned_fds.push((format!("count:{name}"), fd.as_raw_fd()));
            }
        }
        // Sweep membership per root, captured before the ordered
        // drop: a root counts as swept only when the diagnostic held
        // its program FDs at sweep time. A loader transaction that
        // rolled back (second-root `?` drops the whole local
        // collection) leaves earlier successes unswept even though
        // their records read Loaded.
        let legacy_held = loaded.is_some();
        let typed_held = typed_programs.is_some();
        let count_held = count_loaded.is_some();
        let source_held: Vec<String> = source_programs
            .iter()
            .map(|(name, _)| name.clone())
            .collect();
        drop(count_loaded);
        drop(typed_programs);
        drop(source_programs);
        drop(owner);
        drop(loaded);
        let mut leaked = Vec::new();
        for (name, raw) in &owned_fds {
            if unsafe { libc::fcntl(*raw, libc::F_GETFD) } != -1 {
                leaked.push(name.clone());
            }
        }
        // Marks assign only on a clean global sweep, so
        // HandlesClosed additionally implies the shared owner maps
        // closed.
        let swept = |root: &str| -> bool {
            match root {
                "observation_entry" | "observation_return" => legacy_held,
                "typed_entry" | "typed_return" => typed_held,
                "count_entry" => count_held,
                _ => source_held.iter().any(|name| name == root),
            }
        };
        if leaked.is_empty() {
            for record in table.iter_mut() {
                record.cleanup = task23a_classify_cleanup(
                    record.stage,
                    record.error.is_some(),
                    swept(&record.root),
                );
            }
        }
        // Marks assign only on a clean sweep, but a leak finding
        // always folds into the stop reason — including alongside an
        // earlier stop.
        fatal = task23a_fold_cleanup_leak(fatal.as_deref(), &leaked);
        // Report flush: raw artifacts FIRST (their outcomes join
        // the stop reason), then render evidence with the combined
        // reason, then stdout (which always carries the final
        // evidence), then evidence.txt last. A persistence failure
        // can neither hide behind an earlier stop nor be hidden by
        // it. The directory was validated in phase 0, never re-read
        // here.
        let calibration = match (control_creds_before.as_ref(), control_creds_after.as_ref()) {
            (Some(before), Some(after)) => Some((before, after)),
            _ => None,
        };
        let mut persist_failed = Vec::new();
        if let Some(dir) = evidence_dir.as_ref() {
            for record in table.iter() {
                if !record.log_bytes.is_empty()
                    && std::fs::write(
                        dir.join(format!("log-{}.bin", record.root)),
                        &record.log_bytes,
                    )
                    .is_err()
                {
                    persist_failed.push(format!("log-{}.bin", record.root));
                }
                if !record.btf_log.is_empty()
                    && std::fs::write(
                        dir.join(format!("btf-{}.bin", record.root)),
                        &record.btf_log,
                    )
                    .is_err()
                {
                    persist_failed.push(format!("btf-{}.bin", record.root));
                }
            }
        }
        let persist_error = (!persist_failed.is_empty())
            .then(|| format!("evidence write failed: {}", persist_failed.join(",")));
        let blocked = task23a_combine_blocked(fatal.as_deref(), persist_error.as_deref());
        let evidence = task23a_format_evidence(
            &table,
            &evaluations,
            calibration,
            blocked.as_deref(),
            &patch_audit,
        );
        println!("{evidence}");
        // evidence.txt last: stdout already carries the evidence even
        // if this write fails, and the failure still joins the
        // terminal reason below.
        let mut terminal = blocked;
        if let Some(dir) = evidence_dir.as_ref() {
            if std::fs::write(dir.join("evidence.txt"), &evidence).is_err() {
                println!("task23a evidence.txt write failed");
                terminal =
                    task23a_combine_blocked(terminal.as_deref(), Some("evidence.txt write failed"));
            }
        }
        // Terminal evaluation after cleanup and report flush.
        assert!(
            gate.as_ref().is_none_or(|gate| gate.preparing()),
            "diagnostic must never open the gate"
        );
        if let Some(terminal) = terminal {
            panic!("task23a diagnostic failed: {terminal}");
        }
        assert!(
            table.iter().all(|r| r.stage == loader::LoadStage::Loaded),
            "all nine roots must load"
        );
        for evaluation in &evaluations {
            assert!(
                evaluation.passed,
                "{} {}: {}",
                evaluation.check, evaluation.root, evaluation.detail
            );
        }
        drop(gate);
    }
}
