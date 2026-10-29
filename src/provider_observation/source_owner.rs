// SPDX-License-Identifier: GPL-3.0-or-later
//! Owned private source maps. Preparation alone cannot mint source eligibility.

use super::{ObservationBudget, ObservationGap, schema::StateReservation};
use crate::{loader, observation_memory::MemoryLease, writer_gate::WriterGate};
#[allow(dead_code)]
#[path = "../../crates/bpf-contract/src/source.rs"]
mod contract;
use contract::{SourceConfig, SourceControl, SourceObserver};
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
    spec("ITER_SLOT", 6, 4, 8, 1),
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
        .checked_add(HOST_OWNER_BYTES)
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
pub(super) struct SourceOwner {
    _maps: BTreeMap<&'static str, OwnedFd>,
    _namespace: File,
    _gate: WriterGate,
    _capacity: SourceCapacity,
}
impl SourceOwner {
    pub(super) fn prepare(
        budget: &ObservationBudget,
        kernel: &loader::SourceKernel,
        gate: &WriterGate,
        loaded: &loader::Loaded,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<Self, ObservationGap> {
        if !gate.preparing() {
            return Err(ObservationGap::Invalidated);
        }
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
        Ok(Self {
            _maps: maps,
            _namespace: namespace,
            _gate: gate.clone(),
            _capacity: capacity,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::ObservationLimits;
    use super::*;
    #[test]
    fn source_capacity_includes_actual_maps_and_declared_iterator_reserve() {
        assert_eq!(iterator_reservation(512, 16), Some(6_438_912));
        assert_eq!(map_reservation(16), Some(6_271_932));
        assert_eq!(source_reservation(512, 16), Some(12_731_324));
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
