// SPDX-License-Identifier: GPL-3.0-or-later
//! Owned private source maps. Preparation alone cannot mint source eligibility.

use super::{
    ObservationBudget, ObservationGap,
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
use contract::{SourceConfig, SourceControl, SourceDomain, SourceObserver, SourceRequest};
use sha2::{Digest as _, Sha256};
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
    /// Constructed only by the owned native qualification tests; production
    /// builds never enable acquisition.
    #[allow(dead_code)]
    Enabled(NativeSourceParams),
}

/// Owned inputs for one acquiring session. The target file doubles as the
/// anchor object: anchor and registration rows join on its single inode, so
/// no copy or second path may be substituted after admission.
pub(crate) struct NativeSourceParams {
    pub target: std::path::PathBuf,
    pub link_offset: u64,
    pub child_pid: u32,
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
    pub first_error: Option<ObservationGap>,
}

/// Retained anchor object custody: the observer's own read-only private
/// full-file mapping plus the SHA256 over those exact mapped bytes and the
/// retained budget charge for the mapping. The mapping (not a copy or a
/// plain FD read) is the VMA-join backing.
struct AnchorCustody {
    mapping: *mut libc::c_void,
    len: usize,
    hash: [u8; 32],
    _budget: StateReservation,
}
// Raw mapping pointer keeps this (and the owner) off Send: the serialized
// source owner thread is the only accessor.
impl Drop for AnchorCustody {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.mapping, self.len);
        }
    }
}

pub(super) struct SourceOwner {
    // Declared first so retained links/programs release before maps on drop.
    _roots: RetainedSourceRoots,
    _adopted: Vec<OwnedFd>,
    _anchor: Option<AnchorCustody>,
    _anchor_id: Option<u64>,
    _registration_ids: Vec<u64>,
    _domain_tgids: Vec<u32>,
    _mode: Option<(u64, u64)>,
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

/// Request scope threaded through one acquisition's phases: the admitted
/// site cookie, the observer host key, and the minted domain join keys.
/// Built by the session orchestrator from admitted session truth.
pub(super) struct RequestScope {
    pub site_cookie: u64,
    pub host_key: u64,
    pub incarnation: u64,
    pub planned_image: u64,
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
    /// Anchor the target file: retain the observer's own read-only private
    /// full-file mapping plus its SHA256, then run the phase-1 trigger and
    /// advance the anchor guard to LIVE.
    pub(super) fn anchor_source(
        &mut self,
        params: &NativeSourceParams,
        budget: &ObservationBudget,
        host_key: u64,
        incarnation: u64,
        planned_image: u64,
    ) -> Result<AnchorEstablished, ObservationGap> {
        let _ = self._last_error.take();
        let file =
            std::fs::File::open(&params.target).map_err(|_| ObservationGap::BackingUnavailable)?;
        let len = usize::try_from(
            file.metadata()
                .map_err(|_| ObservationGap::BackingUnavailable)?
                .len(),
        )
        .map_err(|_| ObservationGap::StateLimit)?;
        if !file
            .metadata()
            .map_err(|_| ObservationGap::BackingUnavailable)?
            .is_file()
            || len == 0
        {
            return Err(ObservationGap::Invalidated);
        }
        let charge = budget.reserve_state(len)?;
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            drop(charge);
            return Err(ObservationGap::BackingUnavailable);
        }
        let bytes = unsafe { std::slice::from_raw_parts(mapping.cast::<u8>(), len) };
        let digest = Sha256::digest(bytes);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&digest);
        self._anchor = Some(AnchorCustody {
            mapping,
            len,
            hash,
            _budget: charge,
        });
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
            observer_anchor_address: mapping as u64,
            phase: contract::PHASE_ANCHOR,
            required_mask: 0,
            entry_count: 0,
            exit_count: 0,
            verdict: 0,
            reserved: 0,
            publication_sequence: 0,
            process_incarnation: incarnation,
            image_epoch: planned_image,
            registration_id: 0,
        };
        if !request.valid_input() {
            self._last_error = Some(format!(
                "anchor valid_input: nonce {nonce:#x} anchor {anchor:#x} obj {object_id:#x} epoch {epoch:#x} addr {:#x} inc {incarnation:#x} img {planned_image:#x}",
                request.observer_anchor_address
            ));
            return Err(ObservationGap::Invalidated);
        }
        self.arm_request(host_key, &request)?;
        let (pid, _, _) = Self::current_host_key()?;
        self.invoke_provisional_trigger(pid)?;
        let row = self.read_request(host_key)?;
        drop(self._roots.take_provisional());
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
        let hash = self
            ._anchor
            .as_ref()
            .map(|custody| custody.hash)
            .ok_or(ObservationGap::Invalidated)?;
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
    /// the guard to LIVE with the adopted-FD proof.
    pub(super) fn register_entry_return(
        &mut self,
        params: &NativeSourceParams,
        scope: &RequestScope,
        entry_prog: std::os::fd::RawFd,
        return_prog: std::os::fd::RawFd,
        anchor: &AnchorEstablished,
    ) -> Result<RegistrationAdopted, ObservationGap> {
        let _ = self._last_error.take();
        if !(1..=4096).contains(&scope.site_cookie) || params.link_offset > i64::MAX as u64 {
            return Err(ObservationGap::Invalidated);
        }
        let path = std::ffi::CString::new(params.target.as_os_str().as_encoded_bytes())
            .map_err(|_| ObservationGap::Invalidated)?;
        let base = SourceRequest {
            nonce: 0,
            anchor_id: anchor.anchor_id,
            object_id: anchor.object_id,
            source_epoch: anchor.epoch,
            site_cookie: scope.site_cookie,
            file_offset: params.link_offset,
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
            &[params.link_offset],
            &[scope.site_cookie],
            params.child_pid,
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
            &[params.link_offset],
            &[scope.site_cookie],
            params.child_pid,
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
        link_offset: u64,
        anchor: &AnchorEstablished,
        registration: &RegistrationAdopted,
    ) -> Result<u64, ObservationGap> {
        let _ = self._last_error.take();
        if !(1..=4096).contains(&scope.site_cookie) || link_offset > i64::MAX as u64 {
            return Err(ObservationGap::Invalidated);
        }
        let nonce = self._ids.fresh()?;
        let request = SourceRequest {
            nonce,
            anchor_id: anchor.anchor_id,
            object_id: anchor.object_id,
            source_epoch: anchor.epoch,
            site_cookie: scope.site_cookie,
            file_offset: link_offset,
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
        drop(self._roots.take_provisional());
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
    /// Explicit test-driven close: retire every created guard row in the map
    /// before releasing anything, abandon minted-never-created IDs, retire
    /// armed kernel domain rows, refuse a non-READY order, then release all
    /// program/link/mapping owners. Best-effort per item with the first error
    /// retained in the receipts; production close lands with 5B activation.
    #[allow(dead_code)]
    pub(super) fn close_source(&mut self) -> SourceCloseReceipts {
        let mut receipts = SourceCloseReceipts {
            guards_retired: 0,
            guards_abandoned: 0,
            domains_retired: 0,
            order_refused: false,
            first_error: None,
        };
        let note = |receipts: &mut SourceCloseReceipts, error: ObservationGap| {
            if receipts.first_error.is_none() {
                receipts.first_error = Some(error);
            }
        };
        let guard_fd = match self.guard_fd() {
            Ok(fd) => Some(fd),
            Err(error) => {
                note(&mut receipts, error);
                None
            }
        };
        let mut ids = Vec::new();
        ids.extend(self._anchor_id);
        ids.extend(self._registration_ids.iter().copied());
        for id in ids {
            match self._ledger.guard_life(id) {
                Some(GuardLife::Preparing | GuardLife::Live) => {
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
                                Err(error) => note(&mut receipts, error),
                            }
                        }
                        None => note(&mut receipts, ObservationGap::BpfUnavailable),
                    }
                }
                Some(GuardLife::Minted) => match self._ledger.abandon(id) {
                    Ok(()) => receipts.guards_abandoned += 1,
                    Err(error) => note(&mut receipts, error),
                },
                Some(GuardLife::Retired | GuardLife::Conflict) => {
                    let _ = self._ledger.retire(id);
                }
                None => note(&mut receipts, ObservationGap::Invalidated),
            }
        }
        for tgid in std::mem::take(&mut self._domain_tgids) {
            match self.map("SOURCE_DOMAIN") {
                Ok(map) => {
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
                        std::slice::from_raw_parts_mut(
                            (&mut row as *mut SourceDomain).cast::<u8>(),
                            64,
                        )
                    };
                    match map.lookup(&tgid.to_ne_bytes(), bytes) {
                        Ok(()) => {
                            if row.state == contract::DOMAIN_ARMED
                                || row.state == contract::DOMAIN_ACTIVE
                                || row.state == contract::DOMAIN_TRANSITION
                            {
                                row.state = contract::DOMAIN_RETIRED;
                                let bytes = unsafe {
                                    std::slice::from_raw_parts(
                                        (&row as *const SourceDomain).cast::<u8>(),
                                        64,
                                    )
                                };
                                if map.update(&tgid.to_ne_bytes(), bytes).is_err() {
                                    note(&mut receipts, ObservationGap::BpfUnavailable);
                                }
                            }
                            match self._domains.retire(tgid) {
                                Ok(()) => receipts.domains_retired += 1,
                                Err(error) => note(&mut receipts, error),
                            }
                        }
                        Err(_) => note(&mut receipts, ObservationGap::BpfUnavailable),
                    }
                }
                Err(error) => note(&mut receipts, error),
            }
        }
        receipts.order_refused = self._order.refuse().is_ok();
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
}
