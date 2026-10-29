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
pub(super) const MAPS: [loader::MapSpec; 7] = [
    spec("REL", 1, 48, 256, 8192),
    spec("SOURCE_GUARD", 1, 8, 16, 8192),
    spec("SOURCE_REQUEST", 1, 8, 112, 4096),
    spec("SOURCE_PAIR", 2, 4, 128, 1),
    spec("SOURCE_DOMAIN", 1, 4, 64, 64),
    spec("SOURCE_OBSERVER", 2, 4, 48, 1),
    spec("ITER_SLOT", 6, 4, 264, 1),
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
pub(crate) struct NativeSourceParams {
    target: std::path::PathBuf,
    link_offset: u64,
    child_pid: u32,
}

impl NativeSourceParams {
    /// Test-only claim constructor for the owned native qualification.
    /// Unavailable in non-test builds, which is what keeps `Enabled`
    /// out of production paths.
    #[cfg(test)]
    pub(crate) fn for_test(target: std::path::PathBuf, link_offset: u64, child_pid: u32) -> Self {
        Self {
            target,
            link_offset,
            child_pid,
        }
    }
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

/// Structural receipts for the pre-open enablement step.
#[allow(dead_code)]
pub(crate) struct RootsEnabled {
    pub programs: usize,
    pub links: usize,
    pub lifecycle: usize,
    pub mode_before: u64,
    pub mode_after: u64,
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
/// by the native qualification through the acquisition receipts.
#[allow(dead_code)]
pub(crate) struct AnchorEstablished {
    pub anchor_id: u64,
    pub epoch: u64,
    pub object_id: u64,
    pub sequence: u64,
    pub hash: [u8; 32],
}

/// Registration identity adopted for one acquisition.
pub(crate) struct RegistrationAdopted {
    pub registration_id: u64,
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

/// Decode a validated artifact hash to its raw bytes. Runs only after a
/// fault-safe capture proved the mapped bytes hash to this exact value, so
/// the result names the anchored mapping, never a re-read.
fn decode_object_hash_hex(expected: &ObjectHash) -> Result<[u8; 32], ObservationGap> {
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
    // file, via the shared fault-safe capture path. The anchor's raw
    // mapping pointer keeps the owner off Send: the serialized source
    // owner thread is the only accessor.
    _anchor: Option<SourceAnchor>,
    _anchor_id: Option<u64>,
    _registration_ids: Vec<u64>,
    _domain_tgids: Vec<u32>,
    _mode: Option<(u64, u64)>,
    #[cfg(test)]
    _fail_next_retire: std::cell::Cell<bool>,
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
            #[cfg(test)]
            _fail_next_retire: std::cell::Cell::new(false),
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
        let loaded = loader::load_source_roots(
            self._roots.prepared(),
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
        let receipts = RootsEnabled {
            programs: loaded.programs.len(),
            links: loaded.links.len(),
            lifecycle: loaded.lifecycle.len(),
            mode_before: 0,
            mode_after: 0,
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
    /// Test-only close-failure injection: the next guard retirement in
    /// `close_source` fails with `BpfUnavailable`, exercising the
    /// retain-custody path with real maps and live writers.
    #[cfg(test)]
    pub(super) fn fail_next_guard_retire(&self) {
        self._fail_next_retire.set(true);
    }
    /// Test-only anchor-custody readback.
    #[cfg(test)]
    pub(super) fn anchor_retained_test(&self) -> bool {
        self._anchor.is_some()
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
    /// Post-hoc pre-open enablement receipts. Test-called only.
    #[allow(dead_code)]
    pub(super) fn roots_enabled_receipts(&self) -> Option<RootsEnabled> {
        let (before, after) = self._mode?;
        let (programs, links, lifecycle) = self._roots.loaded_counts();
        Some(RootsEnabled {
            programs,
            links,
            lifecycle,
            mode_before: before,
            mode_after: after,
        })
    }
    /// Last retained native diagnostic, taken by the qualification harness
    /// after a failure. Production never reads this.
    #[allow(dead_code)]
    pub(super) fn take_last_error(&mut self) -> Option<String> {
        self._last_error.take()
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
    ) -> Result<AnchorEstablished, ObservationGap> {
        let _ = self._last_error.take();
        let captured = SourceAnchor::capture(&scope.target, &scope.expected_artifact, budget)?;
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
    /// cookie and target PID all come from the admitted scope: this creates
    /// the SOLE required link pair for the admitted site.
    pub(super) fn register_entry_return(
        &mut self,
        scope: &RequestScope,
        entry_prog: std::os::fd::RawFd,
        return_prog: std::os::fd::RawFd,
        anchor: &AnchorEstablished,
    ) -> Result<RegistrationAdopted, ObservationGap> {
        let _ = self._last_error.take();
        if !(1..=4096).contains(&scope.site_cookie) || scope.link_offset > i64::MAX as u64 {
            return Err(ObservationGap::Invalidated);
        }
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
        let entry = SourceRequest {
            nonce: entry_nonce,
            phase: contract::PHASE_ENTRY,
            registration_id: registration,
            ..base
        };
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
    /// registration. Returns the READY publication sequence.
    pub(super) fn publish_ready(
        &mut self,
        scope: &RequestScope,
        anchor: &AnchorEstablished,
        registration: &RegistrationAdopted,
    ) -> Result<u64, ObservationGap> {
        let _ = self._last_error.take();
        if !(1..=4096).contains(&scope.site_cookie) || scope.link_offset > i64::MAX as u64 {
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
        if !self._order.child_may_release() {
            return Err(ObservationGap::Invalidated);
        }
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
        // The sole `NativeSourceParams` constructor is `#[cfg(test)]`, so
        // non-test builds cannot mint the claims that `Enabled` wraps; the
        // clean non-test `cargo check` on this commit is the proof. The
        // accessors below are the production claim-vs-truth read path.
        let params =
            NativeSourceParams::for_test(std::path::PathBuf::from("/owned/fixture"), 0x11b4, 4242);
        assert_eq!(params.target(), std::path::Path::new("/owned/fixture"));
        assert_eq!(params.link_offset(), 0x11b4);
        assert_eq!(params.child_pid(), 4242);
    }
    #[test]
    fn source_capacity_includes_actual_maps_and_declared_iterator_reserve() {
        assert_eq!(iterator_reservation(512, 16), Some(6_438_912));
        assert_eq!(map_reservation(16), Some(6_276_028));
        // The acquisition core adds its NoOp/program/link owner, ledger,
        // domain-index, order and allocator reserves to the component charge.
        assert_eq!(ACQUIRE_CORE_RESERVE, 602_120);
        assert_eq!(source_reservation(512, 16), Some(13_337_540));
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
                ("source_reg_in", "fentry/uprobe_register"),
                ("source_reg_out", "fexit/uprobe_register"),
                ("attr_exit", "raw_tracepoint/sched_process_exit"),
                ("attr_exec", "raw_tracepoint/sched_process_exec"),
            ]
            .into_iter()
            .map(|(name, section)| loader::PreparedProg {
                name: name.to_owned(),
                section: section.to_owned(),
                is_return: false,
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
            _fail_next_retire: std::cell::Cell::new(false),
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
        let error = match owner.anchor_source(&scope, &budget) {
            Ok(_) => panic!("map stage must fail without maps"),
            Err(error) => error,
        };
        assert_eq!(error, ObservationGap::InvalidObject);
        assert!(owner.anchor_retained_test());
        std::fs::remove_file(&path).unwrap();
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
        let error = match owner.anchor_source(&scope, &budget) {
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
        let error = match owner.anchor_source(&scope, &budget) {
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
        let error = match owner.anchor_source(&scope, &budget) {
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
}
