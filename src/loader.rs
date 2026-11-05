//! SPDX-License-Identifier: GPL-3.0-or-later
//! Raw multi loader for the frozen eBPF shape (P2).
//!
//! aya 0.14 loads uprobe progs with `expected_attach_type=0`, which
//! the kernel rejects for multi links — so the multi path parses the
//! object itself (goblin), creates maps raw, applies relocations,
//! and loads progs raw with `expected_attach_type=UPROBE_MULTI`.
//!
//! `prepare()` is pure (unit-tested on synthetic ELFs — no blobs,
//! no toolchain); `load()` needs caps. The lane gates load the real
//! object. Fail-closed throughout: any shape drift (BTF sections,
//! unknown relocs, dim mismatch, non-GPL license) is an error, and
//! map-fd fixups assert `BPF_PSEUDO_MAP_FD` at the site.
type BorrowedRows<K, V> = (Vec<(K, Vec<V>)>, bool);
mod source_btf;
/// Transient BTF scratch the kernel-layout read reserves before opening
/// `/sys/kernel/btf/vmlinux` or allocating either buffer. Callers charge
/// this peak against their own component budget before preparing a
/// marker-carrying object; the reservation releases when the read ends.
pub(crate) const COUNT_JOIN_SCRATCH_BYTES: usize = source_btf::SCRATCH_RESERVATION;
/// Prepared kernel ABI only; this is not source registration or eligibility.
/// Retained by the production observation session until its writers are gone.
pub(crate) struct SourceKernel {
    _configuration: [u32; 13],
    _reservation: crate::provider_observation::schema::StateReservation,
}
/// VMA-join kernel layout only: kfunc IDs, field offsets, VMA extent and
/// iterator allocation class, without the registration-hook ABI. Marker
/// patching (including source-disabled counting) reads through this type,
/// which admits pre-6.12 kernels; it deliberately exposes no registration
/// hook identity, so it can never authorize source acquisition. Retained
/// only for the patch call, never across a session.
pub(crate) struct JoinKernel {
    _configuration: [u32; 13],
    _reservation: crate::provider_observation::schema::StateReservation,
}
impl SourceKernel {
    pub(crate) fn iterator_class(&self) -> u32 {
        self._configuration[12]
    }
    /// Admitted patch configuration (kfunc BTF IDs, field offsets,
    /// VMA size, registration ID, allocation) for the patch audit:
    /// the diagnostic re-validates patched images against these same
    /// values. Read-only copy; no behavior change.
    /// Diagnostic-evidence surface: exercised by host unit tests and
    /// the ignored load-only diagnostic, not by production paths.
    #[allow(dead_code)]
    pub(crate) fn patch_configuration(&self) -> [u32; 13] {
        self._configuration
    }
    /// Validated running-vmlinux `uprobe_register` FUNC ID selected by the
    /// finite prototype validator. Zero is impossible here: parsing refuses
    /// a missing ID before this configuration exists.
    pub(crate) fn registration_btf_id(&self) -> u32 {
        self._configuration[10]
    }
    pub(crate) fn patch(
        &self,
        prepared: &mut Prepared,
    ) -> Result<(), crate::provider_observation::ObservationGap> {
        patch_source_configuration(&self._configuration, &mut prepared.progs)
            .map_err(|_| crate::provider_observation::ObservationGap::InvalidObject)
    }
    pub(crate) fn read(
        budget: &crate::provider_observation::ObservationBudget,
    ) -> Result<Self, crate::provider_observation::ObservationGap> {
        use crate::provider_observation::ObservationGap as Gap;
        let (bytes, retained, _scratch) = read_kernel_btf_bytes(budget)?;
        let layout = source_btf::SourceLayout::parse(&bytes).map_err(|_| Gap::BpfUnavailable)?;
        budget.checkpoint()?;
        let mut configuration = [0; 13];
        configuration[..3].copy_from_slice(&layout.kfunc_ids());
        configuration[3..9].copy_from_slice(&layout.field_offsets());
        configuration[9] = layout.vma_size();
        configuration[10] = layout.registration_id();
        configuration[11..].copy_from_slice(&layout.allocation());
        Ok(Self {
            _configuration: configuration,
            _reservation: retained,
        })
    }
}
impl JoinKernel {
    pub(crate) fn patch(
        &self,
        prepared: &mut Prepared,
    ) -> Result<(), crate::provider_observation::ObservationGap> {
        patch_source_configuration(&self._configuration, &mut prepared.progs)
            .map_err(|_| crate::provider_observation::ObservationGap::InvalidObject)
    }
    /// Admitted join configuration for the count post-patch survival
    /// scan: the diagnostic re-validates the pre-patched count image
    /// against these same values. Read-only copy; no behavior change.
    /// Diagnostic-evidence surface: exercised by host unit tests and
    /// the ignored load-only diagnostic, not by production paths.
    #[allow(dead_code)]
    pub(crate) fn patch_configuration(&self) -> [u32; 13] {
        self._configuration
    }
    /// Join-only kernel-layout read for marker patching. Reserves the same
    /// BTF scratch against the CALLER's budget and admits pre-6.12 kernels;
    /// the registration slot stays zero and no registration-hook identity
    /// escapes, so this can never authorize source acquisition.
    pub(crate) fn read_join(
        budget: &crate::provider_observation::ObservationBudget,
    ) -> Result<Self, crate::provider_observation::ObservationGap> {
        use crate::provider_observation::ObservationGap as Gap;
        let (bytes, retained, _scratch) = read_kernel_btf_bytes(budget)?;
        let layout =
            source_btf::SourceLayout::parse_join(&bytes).map_err(|_| Gap::BpfUnavailable)?;
        budget.checkpoint()?;
        let mut configuration = [0; 13];
        configuration[..3].copy_from_slice(&layout.kfunc_ids());
        configuration[3..9].copy_from_slice(&layout.field_offsets());
        configuration[9] = layout.vma_size();
        configuration[11..].copy_from_slice(&layout.allocation());
        Ok(Self {
            _configuration: configuration,
            _reservation: retained,
        })
    }
}
/// Acquire the running kernel's raw BTF bytes: reserve scratch against the
/// caller's budget first, then open, bound and read. Shared by the full and
/// join-only layout readers so their acquisition semantics cannot drift.
fn read_kernel_btf_bytes(
    budget: &crate::provider_observation::ObservationBudget,
) -> Result<
    (
        Vec<u8>,
        crate::provider_observation::schema::StateReservation,
        crate::provider_observation::schema::StateReservation,
    ),
    crate::provider_observation::ObservationGap,
> {
    use crate::provider_observation::ObservationGap as Gap;
    use std::io::Read as _;
    // Reserve before opening the BTF descriptor or allocating either buffer.
    let scratch = budget.reserve_state(source_btf::SCRATCH_RESERVATION)?;
    let retained = budget.reserve_state(128)?;
    crate::lifecycle_producer::note_acquisition().map_err(|_| Gap::BpfUnavailable)?;
    let mut file =
        std::fs::File::open("/sys/kernel/btf/vmlinux").map_err(|_| Gap::BpfUnavailable)?;
    let mut bytes = vec![0; source_btf::MAX_BYTES];
    let mut length = 0;
    while length < bytes.len() {
        budget.checkpoint()?;
        let count = match file.read(&mut bytes[length..]) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            other => other.map_err(|_| Gap::BpfUnavailable)?,
        };
        if count == 0 {
            break;
        }
        length += count;
    }
    let mut excess = [0; 1];
    if file.read(&mut excess).map_err(|_| Gap::BpfUnavailable)? != 0 {
        return Err(Gap::ReadLimit);
    }
    bytes.truncate(length);
    Ok((bytes, retained, scratch))
}
/// Marker immediates owned by the VMA-join helper (kfunc call identities
/// plus field-offset identities). Shared by the patcher and the
/// presence scan so the two can never disagree on what a marker is.
const SOURCE_KFUNC_MARKERS: core::ops::RangeInclusive<u32> = 0x7f001..=0x7f003;
const SOURCE_FIELD_MARKERS: core::ops::RangeInclusive<u32> = 0x6f001..=0x6f006;

/// True when any prepared instruction carries a VMA-join marker
/// immediate. The patcher itself re-validates shape and ownership; this
/// scan only decides patch-or-skip for objects that predate the join.
fn prepared_has_source_markers(programs: &[PreparedProg]) -> bool {
    programs.iter().any(|program| {
        program.insns.chunks_exact(8).any(|instruction| {
            let immediate = u32::from_le_bytes(instruction[4..8].try_into().unwrap());
            SOURCE_KFUNC_MARKERS.contains(&immediate) || SOURCE_FIELD_MARKERS.contains(&immediate)
        })
    })
}

/// Patch VMA-join markers in a prepared count object when present. Each
/// object carries its own copy of the helper, so the counter patches its
/// own image (the session patches only its registration half). Absent
/// markers skip silently (pre-U1 objects stay loadable); present markers
/// patch-or-fail loudly: an unpatched VMA call must never reach the
/// verifier. Patching reads the join-only kernel layout (no registration
/// hook admission, so source-disabled counting stays independent of it)
/// with the BTF scratch reserved against the CALLER's budget, never a
/// fresh default.
pub(crate) fn patch_count_markers(
    prepared: &mut Prepared,
    budget: &crate::provider_observation::ObservationBudget,
) -> anyhow::Result<()> {
    if !prepared_has_source_markers(&prepared.progs) {
        return Ok(());
    }
    let kernel = JoinKernel::read_join(budget).map_err(|gap| anyhow::anyhow!("{gap:?}"))?;
    kernel
        .patch(prepared)
        .map_err(|gap| anyhow::anyhow!("{gap:?}"))
}

/// Roots blessed to own a VMA-join helper copy. Reachable-subset linking
/// copies the helper body into every root that reaches it, so multi-root
/// ownership is structural (registration fexit + typed pair + count
/// entry), never incidental: any other root carrying the helper or a
/// marker still refuses.
fn blessed_source_owner(program: &PreparedProg) -> bool {
    matches!(
        (
            program.name.as_str(),
            program.section.as_str(),
            program.is_return
        ),
        ("source_reg_out", "fexit/uprobe_register", false)
            | ("typed_entry", "uprobe", false)
            | ("typed_return", "uretprobe", true)
            | ("count_entry", "uprobe", false)
    )
}

/// Finite patch set owned by one global callback-free helper. Validate every
/// site before changing any bytes; an incidental constant or another root cannot
/// acquire a kernel-read identity. Values come only from SourceLayout admission.
/// Every blessed owner root carries its own complete copy of the 9 sites;
/// all copies validate first, then all patch (never partial).
fn patch_source_configuration(
    configuration: &[u32; 13],
    programs: &mut [PreparedProg],
) -> anyhow::Result<()> {
    anyhow::ensure!(
        configuration[..3]
            .iter()
            .all(|id| *id != 0 && *id <= i32::MAX as u32),
        "source kfunc ID range"
    );
    anyhow::ensure!(
        configuration[3..9]
            .iter()
            .all(|offset| *offset <= i32::MAX as u32),
        "source offset range"
    );
    anyhow::ensure!(
        configuration[3..8].iter().all(|offset| offset
            .checked_add(8)
            .is_some_and(|end| end <= configuration[9])),
        "source VMA extent"
    );
    // f_inode's separate containing-file extent was checked by SourceLayout's
    // semantic member parser; do not substitute the VMA size for that type.
    let mut helpers = 0usize;
    let mut patches: Vec<(usize, usize, usize)> = Vec::new();
    for (root_index, program) in programs.iter().enumerate() {
        let mut helper_range = None;
        for (index, subprogram) in program.subprogs.iter().enumerate() {
            if subprogram.name != "current_source_at" {
                continue;
            }
            anyhow::ensure!(
                blessed_source_owner(program) && !subprogram.is_callback,
                "source helper owner"
            );
            anyhow::ensure!(helper_range.is_none(), "duplicate source helper body");
            helpers += 1;
            let start = subprogram.insn_off as usize * 8;
            let end = program
                .subprogs
                .get(index + 1)
                .map_or(program.insns.len(), |next| next.insn_off as usize * 8);
            anyhow::ensure!(
                start < end && end <= program.insns.len(),
                "source helper extent"
            );
            helper_range = Some(start..end);
        }
        let mut sites = [None; 9];
        for (index, instruction) in program.insns.chunks_exact(8).enumerate() {
            let immediate = u32::from_le_bytes(instruction[4..8].try_into().unwrap());
            let site = match immediate {
                0x7f001..=0x7f003 => (immediate - 0x7f001) as usize,
                0x6f001..=0x6f006 => 3 + (immediate - 0x6f001) as usize,
                0x7f000..=0x7ffff | 0x6f000..=0x6ffff => {
                    anyhow::bail!("unknown source patch identity")
                }
                _ => continue,
            };
            let offset = index * 8;
            anyhow::ensure!(
                helper_range.as_ref().is_some_and(|r| r.contains(&offset)),
                "source patch outside helper"
            );
            anyhow::ensure!(sites[site].is_none(), "duplicate source patch identity");
            if site < 3 {
                anyhow::ensure!(
                    instruction[..4] == [0x85, 0, 0, 0],
                    "source kfunc patch shape"
                );
            } else {
                anyhow::ensure!(
                    instruction[0] == 0xb7 && instruction[1] <= 10 && instruction[2..4] == [0, 0],
                    "source field patch shape"
                );
            }
            sites[site] = Some(offset);
        }
        if helper_range.is_some() {
            anyhow::ensure!(
                sites.iter().all(Option::is_some),
                "missing source helper patch"
            );
            for (identity, site) in sites.into_iter().enumerate() {
                patches.push((root_index, site.unwrap(), identity));
            }
        } else {
            anyhow::ensure!(
                sites.iter().all(Option::is_none),
                "source marker without helper body"
            );
        }
    }
    anyhow::ensure!(
        helpers >= 1 && !patches.is_empty(),
        "missing source helper patch"
    );
    for (root, offset, identity) in patches {
        let instruction = &mut programs[root].insns[offset..offset + 8];
        if identity < 3 {
            instruction[1] = 0x20;
        }
        instruction[4..8].copy_from_slice(&configuration[identity].to_le_bytes());
    }
    Ok(())
}

use std::collections::{HashMap, HashSet};
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};

/// BPF relocation types (from `readelf -r` on the real object).
const R_BPF_64_64: u32 = 1;
const R_BPF_64_32: u32 = 10;
/// `ld_imm64` src reg the loader sets at a map-fd site (the
/// compiler emits src=0; anything else pre-patch is corruption).
const BPF_PSEUDO_MAP_FD: u8 = 1;
/// aya legacy map-def record size (7×u32; first 5 are dims).
const MAP_DEF_SIZE: usize = 28;
/// Kernel GPL-compatible license set (subset we accept).
const GPL_OK: [&str; 6] = [
    "GPL",
    "GPL v2",
    "GPL and additional rights",
    "Dual BSD/GPL",
    "Dual MIT/GPL",
    "Dual MPL/GPL",
];

/// Wanted map: dimensions frozen by spec, asserted vs the object.
#[derive(Debug, Clone, Copy)]
pub struct MapSpec {
    pub name: &'static str,
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub flags: u32,
}

impl MapSpec {
    /// Conservative accounted capacity, not measured kernel allocation/RSS.
    pub(crate) fn reservation_bytes(&self, possible_cpus: usize) -> Option<usize> {
        map_capacity_bytes(
            self.map_type,
            self.key_size,
            self.value_size,
            self.max_entries,
            possible_cpus,
        )
    }
}
fn map_capacity_bytes(
    map_type: u32,
    key: u32,
    value: u32,
    entries: u32,
    cpus: usize,
) -> Option<usize> {
    if cpus == 0 {
        return None;
    }
    let payload = if map_type == 27 {
        entries as usize
    } else {
        let value = (value as usize).checked_add(7)? & !7;
        let copies = if matches!(map_type, 5 | 6) { cpus } else { 1 };
        (key as usize)
            .checked_add(value.checked_mul(copies)?)?
            .checked_add(128)?
            .checked_mul(entries as usize)?
    };
    payload.checked_add(65_536)
}

/// Wanted program: looked up by symbol in its section.
#[derive(Debug, Clone, Copy)]
pub struct ProgSpec {
    pub name: &'static str,
    /// "uprobe" (entry) or "uretprobe" (return).
    pub section: &'static str,
}

impl ProgSpec {
    /// Entry-program spec (const so frozen tables stay `const`).
    pub const fn uprobe(name: &'static str) -> ProgSpec {
        ProgSpec {
            name,
            section: "uprobe",
        }
    }
    /// Return-program spec (const so frozen tables stay `const`).
    pub const fn uretprobe(name: &'static str) -> ProgSpec {
        ProgSpec {
            name,
            section: "uretprobe",
        }
    }
}

/// Exact observer-only tracing roots. Preparation does not authorize loading;
/// the generic uprobe loader deliberately rejects these program kinds.
pub(crate) const SOURCE_REGISTRATION_PROGS: [ProgSpec; 2] = [
    ProgSpec {
        name: "source_reg_in",
        section: "fentry/uprobe_register",
    },
    ProgSpec {
        name: "source_reg_out",
        section: "fexit/uprobe_register",
    },
];
fn selected_source_registration(name: &str, section: &str) -> bool {
    [
        ossl_bpf_sys::SourceTracingRoot::Enter,
        ossl_bpf_sys::SourceTracingRoot::Exit,
    ]
    .into_iter()
    .any(|root| root.program_name() == name && root.section() == section)
}

/// Exact synchronous lifecycle writer roots; their programs read no ctx fields.
pub const LIFECYCLE_PROGS: [ProgSpec; 2] = [
    ProgSpec {
        name: "attr_exit",
        section: "raw_tracepoint/sched_process_exit",
    },
    ProgSpec {
        name: "attr_exec",
        section: "raw_tracepoint/sched_process_exec",
    },
];
fn selected_lifecycle(name: &str, section: &str) -> Option<ossl_bpf_sys::LifecycleTracepoint> {
    [
        ossl_bpf_sys::LifecycleTracepoint::Exit,
        ossl_bpf_sys::LifecycleTracepoint::Exec,
    ]
    .into_iter()
    .find(|r| r.program_name() == name && r.section() == section)
}
fn lifecycle_root(p: &PreparedProg) -> anyhow::Result<Option<ossl_bpf_sys::LifecycleTracepoint>> {
    if matches!(p.section.as_str(), "uprobe" | "uretprobe") {
        anyhow::ensure!(
            p.is_return == (p.section == "uretprobe"),
            "program return kind mismatch"
        );
        return Ok(None);
    }
    let root = selected_lifecycle(&p.name, &p.section)
        .ok_or_else(|| anyhow::anyhow!("unreviewed raw program kind"))?;
    anyhow::ensure!(
        !p.is_return && !p.subprogs.iter().any(|s| s.is_callback),
        "raw lifecycle forbids return mode and callback BTF"
    );
    Ok(Some(root))
}

/// Adopted v4 shared declarations. Admission only; no load/attach authority.
pub const IDENTITY_MAPS: [MapSpec; 6] = [
    MapSpec {
        name: "ID_CONTROL",
        map_type: 2,
        key_size: 4,
        value_size: 128,
        max_entries: 1,
        flags: 1024,
    },
    MapSpec {
        name: "ID_GROUP",
        map_type: 1,
        key_size: 16,
        value_size: 64,
        max_entries: 2,
        flags: 0,
    },
    MapSpec {
        name: "ID_CLAIM",
        map_type: 1,
        key_size: 8,
        value_size: 32,
        max_entries: 8192,
        flags: 0,
    },
    MapSpec {
        name: "ID_TASK",
        map_type: 1,
        key_size: 8,
        value_size: 64,
        max_entries: 8192,
        flags: 0,
    },
    MapSpec {
        name: "ID_IMAGE",
        map_type: 1,
        key_size: 8,
        value_size: 64,
        max_entries: 8192,
        flags: 0,
    },
    MapSpec {
        name: "ID_AUDIT",
        map_type: 2,
        key_size: 4,
        value_size: 64,
        max_entries: 1,
        flags: 0,
    },
];
pub const IDENTITY_PROGS: [ProgSpec; 4] = [
    ProgSpec {
        name: "identity_newtask",
        section: "raw_tracepoint/task_newtask",
    },
    ProgSpec {
        name: "identity_exit",
        section: "raw_tracepoint/sched_process_exit",
    },
    ProgSpec {
        name: "identity_sys_enter",
        section: "raw_tracepoint/sys_enter",
    },
    ProgSpec {
        name: "identity_exec",
        section: "raw_tracepoint/sched_process_exec",
    },
];
pub(crate) fn v2_maps(role: crate::package::records::Role) -> Vec<MapSpec> {
    use crate::package::records::Role;
    let mut maps = match role {
        Role::Harvest => HARVEST_MAPS.to_vec(),
        Role::Count => COUNT_MAPS.to_vec(),
        Role::Members => MEMBER_MAPS.to_vec(),
        Role::Identity => Vec::new(),
    };
    maps.extend(IDENTITY_MAPS);
    maps
}
pub(crate) fn prepare_identity_role(
    role: crate::package::records::Role,
    obj: &[u8],
) -> anyhow::Result<Prepared> {
    use crate::package::records::Role;
    let programs: &[ProgSpec] = match role {
        Role::Harvest => &HARVEST_PROGS,
        Role::Count => &COUNT_PROGS,
        Role::Members => &MEMBER_PROGS,
        Role::Identity => &IDENTITY_PROGS,
    };
    let raw = role == Role::Identity;
    if role == Role::Count {
        validate_count_object(obj)?;
    }
    let elf = goblin::elf::Elf::parse(obj)?;
    for section in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("");
        if section.sh_flags & 4 != 0
            && name != ".text"
            && !programs.iter().any(|p| p.section == name)
        {
            anyhow::bail!("v2 unselected executable section");
        }
    }
    for symbol in &elf.syms {
        if !symbol.is_function() {
            continue;
        }
        let Some(section) = elf.section_headers.get(symbol.st_shndx) else {
            anyhow::bail!("v2 function section");
        };
        let section = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("");
        if section != ".text"
            && !programs
                .iter()
                .any(|p| p.section == section && elf.strtab.get_at(symbol.st_name) == Some(p.name))
        {
            anyhow::bail!("v2 unselected program root");
        }
    }
    let prepared = prepare_sections(obj, &v2_maps(role), programs, raw)?;
    if role == Role::Count {
        validate_count_prepared_v2(&prepared)?;
    }
    Ok(prepared)
}
fn validate_count_prepared_v2(p: &Prepared) -> anyhow::Result<()> {
    validate_count_prepared_policy(p, true).map_err(Into::into)
}
/// Frozen harvest shape (keyed-design §1): dims asserted vs the
/// object by `prepare`, fail-closed on drift. Proven by the P2
/// task-0 spike (spike-uret.sh GREEN 3/3). T02 adds the two
/// observer-populated classifier tables (`ALG_CLASS`, `TRIP_CLASS`):
/// same frozen discipline, same commit as the wire ABI change.
/// F-C/A8: the five counter/flag maps (`LOSS`, `TRUNC`, `CALLS`,
/// `TRIP`, `LGCALLS`) are per-CPU hash (type 5) — exact
/// single-writer slots replace racy shared read-modify-write.
/// P5a-C1 adds the chain jump table (`JUMPS`, prog-array); the
/// handoff rides `PENDING_QUERY` + `QUERY_NEXT` (no new state — a
/// dedicated `CURSOR` map was prototyped and rejected, see the BPF
/// notes: stash materialization vs the verifier meets the
/// no-tail-call-in-subprog kernel rule).
pub const HARVEST_MAPS: [MapSpec; 14] = [
    MapSpec {
        name: "EVENTS",
        map_type: 27,
        key_size: 0,
        value_size: 0,
        max_entries: 1 << 21,
        flags: 0,
    },
    MapSpec {
        name: "PENDING_INIT",
        map_type: 1,
        key_size: 8,
        value_size: 8,
        max_entries: 1024,
        flags: 0,
    },
    MapSpec {
        name: "PENDING_QUERY",
        map_type: 1,
        key_size: 8,
        value_size: 16,
        max_entries: 1024,
        flags: 0,
    },
    MapSpec {
        name: "TERMD",
        map_type: 1,
        key_size: 8,
        value_size: 8,
        max_entries: 1024,
        flags: 0,
    },
    MapSpec {
        name: "GEN",
        map_type: 1,
        key_size: 8,
        value_size: 8,
        max_entries: 1024,
        flags: 0,
    },
    MapSpec {
        name: "LOSS",
        map_type: 5,
        key_size: 4,
        value_size: 8,
        max_entries: 32,
        flags: 0,
    },
    MapSpec {
        name: "QUERY_NEXT",
        map_type: 1,
        key_size: 16,
        value_size: 8,
        max_entries: 4096,
        flags: 0,
    },
    MapSpec {
        name: "TRUNC",
        map_type: 5,
        key_size: 4,
        value_size: 8,
        max_entries: 64,
        flags: 0,
    },
    MapSpec {
        name: "CALLS",
        map_type: 5,
        key_size: 4,
        value_size: 8,
        max_entries: 64,
        flags: 0,
    },
    MapSpec {
        name: "TRIP",
        map_type: 5,
        key_size: 8,
        value_size: 8,
        max_entries: 128,
        flags: 0,
    },
    MapSpec {
        name: "LGCALLS",
        map_type: 5,
        key_size: 4,
        value_size: 8,
        max_entries: 64,
        flags: 0,
    },
    MapSpec {
        name: "ALG_CLASS",
        map_type: 1,
        key_size: 8,
        value_size: 42,
        max_entries: 1024,
        flags: 0,
    },
    MapSpec {
        name: "TRIP_CLASS",
        map_type: 1,
        key_size: 8,
        value_size: 22,
        max_entries: 64,
        flags: 0,
    },
    MapSpec {
        name: "JUMPS",
        map_type: 3,
        key_size: 4,
        value_size: 4,
        max_entries: 8,
        flags: 0,
    },
];

/// Frozen capture shape (keyed-design §2): dims asserted vs the
/// object by `prepare`, fail-closed on drift. Read off the built
/// `osslscope-count` object (maps-section records). T07 count ABI
/// v2 adds `WINDOW` (2 u64 cells: start/deadline); an object without
/// it fails `prepare` rather than running deadline-blind.
pub const COUNT_MAPS: [MapSpec; 7] = [
    MapSpec {
        name: "COUNTS",
        map_type: 5,
        key_size: 8,
        value_size: 24,
        max_entries: 8192,
        flags: 0,
    },
    MapSpec {
        name: "ADMITTED",
        map_type: 6,
        key_size: 4,
        value_size: 8,
        max_entries: 1,
        flags: 0,
    },
    MapSpec {
        name: "LATC",
        map_type: 6,
        key_size: 4,
        value_size: 8,
        max_entries: 16,
        flags: 0,
    },
    MapSpec {
        name: "GEN",
        map_type: 2,
        key_size: 4,
        value_size: 4,
        max_entries: 1,
        flags: 0,
    },
    MapSpec {
        name: "TARGET",
        map_type: 2,
        key_size: 4,
        value_size: 8,
        max_entries: 1,
        flags: 0,
    },
    MapSpec {
        name: "WINDOW",
        map_type: 2,
        key_size: 4,
        value_size: 8,
        max_entries: 2,
        flags: 0,
    },
    MapSpec {
        name: "DROPFAIL",
        map_type: 6,
        key_size: 4,
        value_size: 8,
        max_entries: 1,
        flags: 0,
    },
];

/// Frozen capture programs: entry-only counting (v1).
pub const COUNT_PROGS: [ProgSpec; 1] = [ProgSpec {
    name: "count_entry",
    section: "uprobe",
}];

/// Frozen harvest programs: the init/query entry+return pairs plus
/// the three entry-only tripwire counters. P5a adds the eight chain
/// hops (`c0..c7` — loaded, never directly attached: the only attach
/// call sites name entry/return pairs explicitly, and hop `i` is
/// reachable solely via `JUMPS[i]`).
pub const HARVEST_PROGS: [ProgSpec; 15] = [
    ProgSpec {
        name: "init_entry",
        section: "uprobe",
    },
    ProgSpec {
        name: "init_return",
        section: "uretprobe",
    },
    ProgSpec {
        name: "query_entry",
        section: "uprobe",
    },
    ProgSpec {
        name: "query_return",
        section: "uretprobe",
    },
    ProgSpec {
        name: "trip_count",
        section: "uprobe",
    },
    ProgSpec {
        name: "trip_str0",
        section: "uprobe",
    },
    ProgSpec {
        name: "trip_str1",
        section: "uprobe",
    },
    ProgSpec {
        name: "c0",
        section: "uretprobe",
    },
    ProgSpec {
        name: "c1",
        section: "uretprobe",
    },
    ProgSpec {
        name: "c2",
        section: "uretprobe",
    },
    ProgSpec {
        name: "c3",
        section: "uretprobe",
    },
    ProgSpec {
        name: "c4",
        section: "uretprobe",
    },
    ProgSpec {
        name: "c5",
        section: "uretprobe",
    },
    ProgSpec {
        name: "c6",
        section: "uretprobe",
    },
    ProgSpec {
        name: "c7",
        section: "uretprobe",
    },
];

/// Frozen member shape (P7 items 3–5): dims asserted vs
/// `osslscope-members` by `prepare`, fail-closed on drift. The
/// first 6 mirror harvest dims; TERMD/LGCALLS/QUERY_NEXT are
/// deliberately absent (single-site CALLS only, no cursor — every
/// scan is full; termination proof is the item-4 join's job). The
/// scan plane (SCAN/SEQ/BIRTH/RCOUNT/T_CACHE/CTRL/ATTEMPT)
/// arrives with item 3; members.o dropped its PENDING_QUERY
/// scaffold in stage D when members switched to SCAN (R18 §6.1;
/// the harvest path's cursor maps retire in item 9). Item 5 adds
/// the tier-1 BUCKET map; item 7 grows EVENTS to 16MiB. Round 3
/// adds the per-op TRUNC_SEQ flag-event generation (recurring
/// faults re-report on generation advance — the lossless drain
/// never clears, so there is no clear to race at all).
pub const MEMBER_MAPS: [MapSpec; 15] = [
    MapSpec {
        name: "EVENTS",
        map_type: 27,
        key_size: 0,
        value_size: 0,
        max_entries: 1 << 24,
        flags: 0,
    },
    MapSpec {
        name: "BUCKET",
        map_type: 1,
        key_size: 4,
        value_size: 8,
        max_entries: 4096,
        flags: 0,
    },
    MapSpec {
        name: "GEN",
        map_type: 1,
        key_size: 8,
        value_size: 8,
        max_entries: 1024,
        flags: 0,
    },
    MapSpec {
        name: "LOSS",
        map_type: 5,
        key_size: 4,
        value_size: 8,
        max_entries: 32,
        flags: 0,
    },
    MapSpec {
        name: "TRUNC",
        map_type: 5,
        key_size: 4,
        value_size: 8,
        max_entries: 64,
        flags: 0,
    },
    MapSpec {
        name: "CALLS",
        map_type: 5,
        key_size: 4,
        value_size: 8,
        max_entries: 64,
        flags: 0,
    },
    MapSpec {
        name: "ALG_CLASS",
        map_type: 1,
        key_size: 8,
        value_size: 42,
        max_entries: 1024,
        flags: 0,
    },
    MapSpec {
        name: "SCAN",
        map_type: 9,
        key_size: 4,
        value_size: 40,
        max_entries: 1024,
        flags: 0,
    },
    MapSpec {
        name: "SEQ",
        map_type: 1,
        key_size: 4,
        value_size: 8,
        max_entries: 4096,
        flags: 0,
    },
    MapSpec {
        name: "BIRTH",
        map_type: 1,
        key_size: 4,
        value_size: 2,
        max_entries: 4096,
        flags: 0,
    },
    MapSpec {
        name: "RCOUNT",
        map_type: 1,
        key_size: 4,
        value_size: 8,
        max_entries: 4096,
        flags: 0,
    },
    MapSpec {
        name: "T_CACHE",
        map_type: 1,
        key_size: 8,
        value_size: 16,
        max_entries: 1024,
        flags: 0,
    },
    MapSpec {
        name: "CTRL",
        map_type: 2,
        key_size: 4,
        value_size: 24,
        max_entries: 1,
        flags: 0,
    },
    MapSpec {
        name: "ATTEMPT",
        map_type: 6,
        key_size: 4,
        value_size: 8,
        max_entries: 1,
        flags: 0,
    },
    MapSpec {
        name: "TRUNC_SEQ",
        map_type: 5,
        key_size: 4,
        value_size: 8,
        max_entries: 64,
        flags: 0,
    },
];

/// Frozen member programs: `member_entry` (uprobe stash) + 512
/// baked-slot members (`member_000..member_511`, uretprobe). One
/// line per member via the const constructors (struct literals
/// would fmt-expand to 4 lines each), generated once and committed
/// explicitly — the frozen `HARVEST_PROGS` discipline (dynamic
/// names stay test-only per the B-chunk probe's comment).
/// `prepare` fails closed on any name/symbol drift.
#[allow(
    clippy::large_const_arrays,
    reason = "the 513 frozen specs are the point"
)]
pub const MEMBER_PROGS: [ProgSpec; 513] = [
    ProgSpec::uprobe("member_entry"),
    ProgSpec::uretprobe("member_000"),
    ProgSpec::uretprobe("member_001"),
    ProgSpec::uretprobe("member_002"),
    ProgSpec::uretprobe("member_003"),
    ProgSpec::uretprobe("member_004"),
    ProgSpec::uretprobe("member_005"),
    ProgSpec::uretprobe("member_006"),
    ProgSpec::uretprobe("member_007"),
    ProgSpec::uretprobe("member_008"),
    ProgSpec::uretprobe("member_009"),
    ProgSpec::uretprobe("member_010"),
    ProgSpec::uretprobe("member_011"),
    ProgSpec::uretprobe("member_012"),
    ProgSpec::uretprobe("member_013"),
    ProgSpec::uretprobe("member_014"),
    ProgSpec::uretprobe("member_015"),
    ProgSpec::uretprobe("member_016"),
    ProgSpec::uretprobe("member_017"),
    ProgSpec::uretprobe("member_018"),
    ProgSpec::uretprobe("member_019"),
    ProgSpec::uretprobe("member_020"),
    ProgSpec::uretprobe("member_021"),
    ProgSpec::uretprobe("member_022"),
    ProgSpec::uretprobe("member_023"),
    ProgSpec::uretprobe("member_024"),
    ProgSpec::uretprobe("member_025"),
    ProgSpec::uretprobe("member_026"),
    ProgSpec::uretprobe("member_027"),
    ProgSpec::uretprobe("member_028"),
    ProgSpec::uretprobe("member_029"),
    ProgSpec::uretprobe("member_030"),
    ProgSpec::uretprobe("member_031"),
    ProgSpec::uretprobe("member_032"),
    ProgSpec::uretprobe("member_033"),
    ProgSpec::uretprobe("member_034"),
    ProgSpec::uretprobe("member_035"),
    ProgSpec::uretprobe("member_036"),
    ProgSpec::uretprobe("member_037"),
    ProgSpec::uretprobe("member_038"),
    ProgSpec::uretprobe("member_039"),
    ProgSpec::uretprobe("member_040"),
    ProgSpec::uretprobe("member_041"),
    ProgSpec::uretprobe("member_042"),
    ProgSpec::uretprobe("member_043"),
    ProgSpec::uretprobe("member_044"),
    ProgSpec::uretprobe("member_045"),
    ProgSpec::uretprobe("member_046"),
    ProgSpec::uretprobe("member_047"),
    ProgSpec::uretprobe("member_048"),
    ProgSpec::uretprobe("member_049"),
    ProgSpec::uretprobe("member_050"),
    ProgSpec::uretprobe("member_051"),
    ProgSpec::uretprobe("member_052"),
    ProgSpec::uretprobe("member_053"),
    ProgSpec::uretprobe("member_054"),
    ProgSpec::uretprobe("member_055"),
    ProgSpec::uretprobe("member_056"),
    ProgSpec::uretprobe("member_057"),
    ProgSpec::uretprobe("member_058"),
    ProgSpec::uretprobe("member_059"),
    ProgSpec::uretprobe("member_060"),
    ProgSpec::uretprobe("member_061"),
    ProgSpec::uretprobe("member_062"),
    ProgSpec::uretprobe("member_063"),
    ProgSpec::uretprobe("member_064"),
    ProgSpec::uretprobe("member_065"),
    ProgSpec::uretprobe("member_066"),
    ProgSpec::uretprobe("member_067"),
    ProgSpec::uretprobe("member_068"),
    ProgSpec::uretprobe("member_069"),
    ProgSpec::uretprobe("member_070"),
    ProgSpec::uretprobe("member_071"),
    ProgSpec::uretprobe("member_072"),
    ProgSpec::uretprobe("member_073"),
    ProgSpec::uretprobe("member_074"),
    ProgSpec::uretprobe("member_075"),
    ProgSpec::uretprobe("member_076"),
    ProgSpec::uretprobe("member_077"),
    ProgSpec::uretprobe("member_078"),
    ProgSpec::uretprobe("member_079"),
    ProgSpec::uretprobe("member_080"),
    ProgSpec::uretprobe("member_081"),
    ProgSpec::uretprobe("member_082"),
    ProgSpec::uretprobe("member_083"),
    ProgSpec::uretprobe("member_084"),
    ProgSpec::uretprobe("member_085"),
    ProgSpec::uretprobe("member_086"),
    ProgSpec::uretprobe("member_087"),
    ProgSpec::uretprobe("member_088"),
    ProgSpec::uretprobe("member_089"),
    ProgSpec::uretprobe("member_090"),
    ProgSpec::uretprobe("member_091"),
    ProgSpec::uretprobe("member_092"),
    ProgSpec::uretprobe("member_093"),
    ProgSpec::uretprobe("member_094"),
    ProgSpec::uretprobe("member_095"),
    ProgSpec::uretprobe("member_096"),
    ProgSpec::uretprobe("member_097"),
    ProgSpec::uretprobe("member_098"),
    ProgSpec::uretprobe("member_099"),
    ProgSpec::uretprobe("member_100"),
    ProgSpec::uretprobe("member_101"),
    ProgSpec::uretprobe("member_102"),
    ProgSpec::uretprobe("member_103"),
    ProgSpec::uretprobe("member_104"),
    ProgSpec::uretprobe("member_105"),
    ProgSpec::uretprobe("member_106"),
    ProgSpec::uretprobe("member_107"),
    ProgSpec::uretprobe("member_108"),
    ProgSpec::uretprobe("member_109"),
    ProgSpec::uretprobe("member_110"),
    ProgSpec::uretprobe("member_111"),
    ProgSpec::uretprobe("member_112"),
    ProgSpec::uretprobe("member_113"),
    ProgSpec::uretprobe("member_114"),
    ProgSpec::uretprobe("member_115"),
    ProgSpec::uretprobe("member_116"),
    ProgSpec::uretprobe("member_117"),
    ProgSpec::uretprobe("member_118"),
    ProgSpec::uretprobe("member_119"),
    ProgSpec::uretprobe("member_120"),
    ProgSpec::uretprobe("member_121"),
    ProgSpec::uretprobe("member_122"),
    ProgSpec::uretprobe("member_123"),
    ProgSpec::uretprobe("member_124"),
    ProgSpec::uretprobe("member_125"),
    ProgSpec::uretprobe("member_126"),
    ProgSpec::uretprobe("member_127"),
    ProgSpec::uretprobe("member_128"),
    ProgSpec::uretprobe("member_129"),
    ProgSpec::uretprobe("member_130"),
    ProgSpec::uretprobe("member_131"),
    ProgSpec::uretprobe("member_132"),
    ProgSpec::uretprobe("member_133"),
    ProgSpec::uretprobe("member_134"),
    ProgSpec::uretprobe("member_135"),
    ProgSpec::uretprobe("member_136"),
    ProgSpec::uretprobe("member_137"),
    ProgSpec::uretprobe("member_138"),
    ProgSpec::uretprobe("member_139"),
    ProgSpec::uretprobe("member_140"),
    ProgSpec::uretprobe("member_141"),
    ProgSpec::uretprobe("member_142"),
    ProgSpec::uretprobe("member_143"),
    ProgSpec::uretprobe("member_144"),
    ProgSpec::uretprobe("member_145"),
    ProgSpec::uretprobe("member_146"),
    ProgSpec::uretprobe("member_147"),
    ProgSpec::uretprobe("member_148"),
    ProgSpec::uretprobe("member_149"),
    ProgSpec::uretprobe("member_150"),
    ProgSpec::uretprobe("member_151"),
    ProgSpec::uretprobe("member_152"),
    ProgSpec::uretprobe("member_153"),
    ProgSpec::uretprobe("member_154"),
    ProgSpec::uretprobe("member_155"),
    ProgSpec::uretprobe("member_156"),
    ProgSpec::uretprobe("member_157"),
    ProgSpec::uretprobe("member_158"),
    ProgSpec::uretprobe("member_159"),
    ProgSpec::uretprobe("member_160"),
    ProgSpec::uretprobe("member_161"),
    ProgSpec::uretprobe("member_162"),
    ProgSpec::uretprobe("member_163"),
    ProgSpec::uretprobe("member_164"),
    ProgSpec::uretprobe("member_165"),
    ProgSpec::uretprobe("member_166"),
    ProgSpec::uretprobe("member_167"),
    ProgSpec::uretprobe("member_168"),
    ProgSpec::uretprobe("member_169"),
    ProgSpec::uretprobe("member_170"),
    ProgSpec::uretprobe("member_171"),
    ProgSpec::uretprobe("member_172"),
    ProgSpec::uretprobe("member_173"),
    ProgSpec::uretprobe("member_174"),
    ProgSpec::uretprobe("member_175"),
    ProgSpec::uretprobe("member_176"),
    ProgSpec::uretprobe("member_177"),
    ProgSpec::uretprobe("member_178"),
    ProgSpec::uretprobe("member_179"),
    ProgSpec::uretprobe("member_180"),
    ProgSpec::uretprobe("member_181"),
    ProgSpec::uretprobe("member_182"),
    ProgSpec::uretprobe("member_183"),
    ProgSpec::uretprobe("member_184"),
    ProgSpec::uretprobe("member_185"),
    ProgSpec::uretprobe("member_186"),
    ProgSpec::uretprobe("member_187"),
    ProgSpec::uretprobe("member_188"),
    ProgSpec::uretprobe("member_189"),
    ProgSpec::uretprobe("member_190"),
    ProgSpec::uretprobe("member_191"),
    ProgSpec::uretprobe("member_192"),
    ProgSpec::uretprobe("member_193"),
    ProgSpec::uretprobe("member_194"),
    ProgSpec::uretprobe("member_195"),
    ProgSpec::uretprobe("member_196"),
    ProgSpec::uretprobe("member_197"),
    ProgSpec::uretprobe("member_198"),
    ProgSpec::uretprobe("member_199"),
    ProgSpec::uretprobe("member_200"),
    ProgSpec::uretprobe("member_201"),
    ProgSpec::uretprobe("member_202"),
    ProgSpec::uretprobe("member_203"),
    ProgSpec::uretprobe("member_204"),
    ProgSpec::uretprobe("member_205"),
    ProgSpec::uretprobe("member_206"),
    ProgSpec::uretprobe("member_207"),
    ProgSpec::uretprobe("member_208"),
    ProgSpec::uretprobe("member_209"),
    ProgSpec::uretprobe("member_210"),
    ProgSpec::uretprobe("member_211"),
    ProgSpec::uretprobe("member_212"),
    ProgSpec::uretprobe("member_213"),
    ProgSpec::uretprobe("member_214"),
    ProgSpec::uretprobe("member_215"),
    ProgSpec::uretprobe("member_216"),
    ProgSpec::uretprobe("member_217"),
    ProgSpec::uretprobe("member_218"),
    ProgSpec::uretprobe("member_219"),
    ProgSpec::uretprobe("member_220"),
    ProgSpec::uretprobe("member_221"),
    ProgSpec::uretprobe("member_222"),
    ProgSpec::uretprobe("member_223"),
    ProgSpec::uretprobe("member_224"),
    ProgSpec::uretprobe("member_225"),
    ProgSpec::uretprobe("member_226"),
    ProgSpec::uretprobe("member_227"),
    ProgSpec::uretprobe("member_228"),
    ProgSpec::uretprobe("member_229"),
    ProgSpec::uretprobe("member_230"),
    ProgSpec::uretprobe("member_231"),
    ProgSpec::uretprobe("member_232"),
    ProgSpec::uretprobe("member_233"),
    ProgSpec::uretprobe("member_234"),
    ProgSpec::uretprobe("member_235"),
    ProgSpec::uretprobe("member_236"),
    ProgSpec::uretprobe("member_237"),
    ProgSpec::uretprobe("member_238"),
    ProgSpec::uretprobe("member_239"),
    ProgSpec::uretprobe("member_240"),
    ProgSpec::uretprobe("member_241"),
    ProgSpec::uretprobe("member_242"),
    ProgSpec::uretprobe("member_243"),
    ProgSpec::uretprobe("member_244"),
    ProgSpec::uretprobe("member_245"),
    ProgSpec::uretprobe("member_246"),
    ProgSpec::uretprobe("member_247"),
    ProgSpec::uretprobe("member_248"),
    ProgSpec::uretprobe("member_249"),
    ProgSpec::uretprobe("member_250"),
    ProgSpec::uretprobe("member_251"),
    ProgSpec::uretprobe("member_252"),
    ProgSpec::uretprobe("member_253"),
    ProgSpec::uretprobe("member_254"),
    ProgSpec::uretprobe("member_255"),
    ProgSpec::uretprobe("member_256"),
    ProgSpec::uretprobe("member_257"),
    ProgSpec::uretprobe("member_258"),
    ProgSpec::uretprobe("member_259"),
    ProgSpec::uretprobe("member_260"),
    ProgSpec::uretprobe("member_261"),
    ProgSpec::uretprobe("member_262"),
    ProgSpec::uretprobe("member_263"),
    ProgSpec::uretprobe("member_264"),
    ProgSpec::uretprobe("member_265"),
    ProgSpec::uretprobe("member_266"),
    ProgSpec::uretprobe("member_267"),
    ProgSpec::uretprobe("member_268"),
    ProgSpec::uretprobe("member_269"),
    ProgSpec::uretprobe("member_270"),
    ProgSpec::uretprobe("member_271"),
    ProgSpec::uretprobe("member_272"),
    ProgSpec::uretprobe("member_273"),
    ProgSpec::uretprobe("member_274"),
    ProgSpec::uretprobe("member_275"),
    ProgSpec::uretprobe("member_276"),
    ProgSpec::uretprobe("member_277"),
    ProgSpec::uretprobe("member_278"),
    ProgSpec::uretprobe("member_279"),
    ProgSpec::uretprobe("member_280"),
    ProgSpec::uretprobe("member_281"),
    ProgSpec::uretprobe("member_282"),
    ProgSpec::uretprobe("member_283"),
    ProgSpec::uretprobe("member_284"),
    ProgSpec::uretprobe("member_285"),
    ProgSpec::uretprobe("member_286"),
    ProgSpec::uretprobe("member_287"),
    ProgSpec::uretprobe("member_288"),
    ProgSpec::uretprobe("member_289"),
    ProgSpec::uretprobe("member_290"),
    ProgSpec::uretprobe("member_291"),
    ProgSpec::uretprobe("member_292"),
    ProgSpec::uretprobe("member_293"),
    ProgSpec::uretprobe("member_294"),
    ProgSpec::uretprobe("member_295"),
    ProgSpec::uretprobe("member_296"),
    ProgSpec::uretprobe("member_297"),
    ProgSpec::uretprobe("member_298"),
    ProgSpec::uretprobe("member_299"),
    ProgSpec::uretprobe("member_300"),
    ProgSpec::uretprobe("member_301"),
    ProgSpec::uretprobe("member_302"),
    ProgSpec::uretprobe("member_303"),
    ProgSpec::uretprobe("member_304"),
    ProgSpec::uretprobe("member_305"),
    ProgSpec::uretprobe("member_306"),
    ProgSpec::uretprobe("member_307"),
    ProgSpec::uretprobe("member_308"),
    ProgSpec::uretprobe("member_309"),
    ProgSpec::uretprobe("member_310"),
    ProgSpec::uretprobe("member_311"),
    ProgSpec::uretprobe("member_312"),
    ProgSpec::uretprobe("member_313"),
    ProgSpec::uretprobe("member_314"),
    ProgSpec::uretprobe("member_315"),
    ProgSpec::uretprobe("member_316"),
    ProgSpec::uretprobe("member_317"),
    ProgSpec::uretprobe("member_318"),
    ProgSpec::uretprobe("member_319"),
    ProgSpec::uretprobe("member_320"),
    ProgSpec::uretprobe("member_321"),
    ProgSpec::uretprobe("member_322"),
    ProgSpec::uretprobe("member_323"),
    ProgSpec::uretprobe("member_324"),
    ProgSpec::uretprobe("member_325"),
    ProgSpec::uretprobe("member_326"),
    ProgSpec::uretprobe("member_327"),
    ProgSpec::uretprobe("member_328"),
    ProgSpec::uretprobe("member_329"),
    ProgSpec::uretprobe("member_330"),
    ProgSpec::uretprobe("member_331"),
    ProgSpec::uretprobe("member_332"),
    ProgSpec::uretprobe("member_333"),
    ProgSpec::uretprobe("member_334"),
    ProgSpec::uretprobe("member_335"),
    ProgSpec::uretprobe("member_336"),
    ProgSpec::uretprobe("member_337"),
    ProgSpec::uretprobe("member_338"),
    ProgSpec::uretprobe("member_339"),
    ProgSpec::uretprobe("member_340"),
    ProgSpec::uretprobe("member_341"),
    ProgSpec::uretprobe("member_342"),
    ProgSpec::uretprobe("member_343"),
    ProgSpec::uretprobe("member_344"),
    ProgSpec::uretprobe("member_345"),
    ProgSpec::uretprobe("member_346"),
    ProgSpec::uretprobe("member_347"),
    ProgSpec::uretprobe("member_348"),
    ProgSpec::uretprobe("member_349"),
    ProgSpec::uretprobe("member_350"),
    ProgSpec::uretprobe("member_351"),
    ProgSpec::uretprobe("member_352"),
    ProgSpec::uretprobe("member_353"),
    ProgSpec::uretprobe("member_354"),
    ProgSpec::uretprobe("member_355"),
    ProgSpec::uretprobe("member_356"),
    ProgSpec::uretprobe("member_357"),
    ProgSpec::uretprobe("member_358"),
    ProgSpec::uretprobe("member_359"),
    ProgSpec::uretprobe("member_360"),
    ProgSpec::uretprobe("member_361"),
    ProgSpec::uretprobe("member_362"),
    ProgSpec::uretprobe("member_363"),
    ProgSpec::uretprobe("member_364"),
    ProgSpec::uretprobe("member_365"),
    ProgSpec::uretprobe("member_366"),
    ProgSpec::uretprobe("member_367"),
    ProgSpec::uretprobe("member_368"),
    ProgSpec::uretprobe("member_369"),
    ProgSpec::uretprobe("member_370"),
    ProgSpec::uretprobe("member_371"),
    ProgSpec::uretprobe("member_372"),
    ProgSpec::uretprobe("member_373"),
    ProgSpec::uretprobe("member_374"),
    ProgSpec::uretprobe("member_375"),
    ProgSpec::uretprobe("member_376"),
    ProgSpec::uretprobe("member_377"),
    ProgSpec::uretprobe("member_378"),
    ProgSpec::uretprobe("member_379"),
    ProgSpec::uretprobe("member_380"),
    ProgSpec::uretprobe("member_381"),
    ProgSpec::uretprobe("member_382"),
    ProgSpec::uretprobe("member_383"),
    ProgSpec::uretprobe("member_384"),
    ProgSpec::uretprobe("member_385"),
    ProgSpec::uretprobe("member_386"),
    ProgSpec::uretprobe("member_387"),
    ProgSpec::uretprobe("member_388"),
    ProgSpec::uretprobe("member_389"),
    ProgSpec::uretprobe("member_390"),
    ProgSpec::uretprobe("member_391"),
    ProgSpec::uretprobe("member_392"),
    ProgSpec::uretprobe("member_393"),
    ProgSpec::uretprobe("member_394"),
    ProgSpec::uretprobe("member_395"),
    ProgSpec::uretprobe("member_396"),
    ProgSpec::uretprobe("member_397"),
    ProgSpec::uretprobe("member_398"),
    ProgSpec::uretprobe("member_399"),
    ProgSpec::uretprobe("member_400"),
    ProgSpec::uretprobe("member_401"),
    ProgSpec::uretprobe("member_402"),
    ProgSpec::uretprobe("member_403"),
    ProgSpec::uretprobe("member_404"),
    ProgSpec::uretprobe("member_405"),
    ProgSpec::uretprobe("member_406"),
    ProgSpec::uretprobe("member_407"),
    ProgSpec::uretprobe("member_408"),
    ProgSpec::uretprobe("member_409"),
    ProgSpec::uretprobe("member_410"),
    ProgSpec::uretprobe("member_411"),
    ProgSpec::uretprobe("member_412"),
    ProgSpec::uretprobe("member_413"),
    ProgSpec::uretprobe("member_414"),
    ProgSpec::uretprobe("member_415"),
    ProgSpec::uretprobe("member_416"),
    ProgSpec::uretprobe("member_417"),
    ProgSpec::uretprobe("member_418"),
    ProgSpec::uretprobe("member_419"),
    ProgSpec::uretprobe("member_420"),
    ProgSpec::uretprobe("member_421"),
    ProgSpec::uretprobe("member_422"),
    ProgSpec::uretprobe("member_423"),
    ProgSpec::uretprobe("member_424"),
    ProgSpec::uretprobe("member_425"),
    ProgSpec::uretprobe("member_426"),
    ProgSpec::uretprobe("member_427"),
    ProgSpec::uretprobe("member_428"),
    ProgSpec::uretprobe("member_429"),
    ProgSpec::uretprobe("member_430"),
    ProgSpec::uretprobe("member_431"),
    ProgSpec::uretprobe("member_432"),
    ProgSpec::uretprobe("member_433"),
    ProgSpec::uretprobe("member_434"),
    ProgSpec::uretprobe("member_435"),
    ProgSpec::uretprobe("member_436"),
    ProgSpec::uretprobe("member_437"),
    ProgSpec::uretprobe("member_438"),
    ProgSpec::uretprobe("member_439"),
    ProgSpec::uretprobe("member_440"),
    ProgSpec::uretprobe("member_441"),
    ProgSpec::uretprobe("member_442"),
    ProgSpec::uretprobe("member_443"),
    ProgSpec::uretprobe("member_444"),
    ProgSpec::uretprobe("member_445"),
    ProgSpec::uretprobe("member_446"),
    ProgSpec::uretprobe("member_447"),
    ProgSpec::uretprobe("member_448"),
    ProgSpec::uretprobe("member_449"),
    ProgSpec::uretprobe("member_450"),
    ProgSpec::uretprobe("member_451"),
    ProgSpec::uretprobe("member_452"),
    ProgSpec::uretprobe("member_453"),
    ProgSpec::uretprobe("member_454"),
    ProgSpec::uretprobe("member_455"),
    ProgSpec::uretprobe("member_456"),
    ProgSpec::uretprobe("member_457"),
    ProgSpec::uretprobe("member_458"),
    ProgSpec::uretprobe("member_459"),
    ProgSpec::uretprobe("member_460"),
    ProgSpec::uretprobe("member_461"),
    ProgSpec::uretprobe("member_462"),
    ProgSpec::uretprobe("member_463"),
    ProgSpec::uretprobe("member_464"),
    ProgSpec::uretprobe("member_465"),
    ProgSpec::uretprobe("member_466"),
    ProgSpec::uretprobe("member_467"),
    ProgSpec::uretprobe("member_468"),
    ProgSpec::uretprobe("member_469"),
    ProgSpec::uretprobe("member_470"),
    ProgSpec::uretprobe("member_471"),
    ProgSpec::uretprobe("member_472"),
    ProgSpec::uretprobe("member_473"),
    ProgSpec::uretprobe("member_474"),
    ProgSpec::uretprobe("member_475"),
    ProgSpec::uretprobe("member_476"),
    ProgSpec::uretprobe("member_477"),
    ProgSpec::uretprobe("member_478"),
    ProgSpec::uretprobe("member_479"),
    ProgSpec::uretprobe("member_480"),
    ProgSpec::uretprobe("member_481"),
    ProgSpec::uretprobe("member_482"),
    ProgSpec::uretprobe("member_483"),
    ProgSpec::uretprobe("member_484"),
    ProgSpec::uretprobe("member_485"),
    ProgSpec::uretprobe("member_486"),
    ProgSpec::uretprobe("member_487"),
    ProgSpec::uretprobe("member_488"),
    ProgSpec::uretprobe("member_489"),
    ProgSpec::uretprobe("member_490"),
    ProgSpec::uretprobe("member_491"),
    ProgSpec::uretprobe("member_492"),
    ProgSpec::uretprobe("member_493"),
    ProgSpec::uretprobe("member_494"),
    ProgSpec::uretprobe("member_495"),
    ProgSpec::uretprobe("member_496"),
    ProgSpec::uretprobe("member_497"),
    ProgSpec::uretprobe("member_498"),
    ProgSpec::uretprobe("member_499"),
    ProgSpec::uretprobe("member_500"),
    ProgSpec::uretprobe("member_501"),
    ProgSpec::uretprobe("member_502"),
    ProgSpec::uretprobe("member_503"),
    ProgSpec::uretprobe("member_504"),
    ProgSpec::uretprobe("member_505"),
    ProgSpec::uretprobe("member_506"),
    ProgSpec::uretprobe("member_507"),
    ProgSpec::uretprobe("member_508"),
    ProgSpec::uretprobe("member_509"),
    ProgSpec::uretprobe("member_510"),
    ProgSpec::uretprobe("member_511"),
];

/// A map-fd fixup site: byte offset of the insn + map name.
#[derive(Debug, Clone)]
pub struct MapFixup {
    pub insn_off: usize,
    pub map: String,
}

/// One prepared program: relocated bytes (`.text` appended, call
/// relocs applied) + map fixups for `load()`.
#[derive(Debug, Clone)]
pub struct PreparedProg {
    pub name: String,
    /// Preserved for exact load-type selection; raw identity declarations are admission-only.
    pub section: String,
    pub is_return: bool,
    pub insns: Vec<u8>,
    pub map_fixups: Vec<MapFixup>,
    /// Linked subprograms in insn order (main first): the BTF
    /// synthesis input. Callbacks (function-pointer targets) are
    /// flagged — only progs with a callback take the BTF path in
    /// `load()`; every other prog loads exactly as before.
    pub subprogs: Vec<SubprogInfo>,
}

/// Pure preparation output (no fds — safe unprivileged).
#[derive(Debug, Clone)]
pub struct Prepared {
    pub progs: Vec<PreparedProg>,
    pub maps: Vec<MapSpecLite>,
}

/// Map dims confirmed against the object (load input).
#[derive(Debug, Clone)]
pub struct MapSpecLite {
    pub name: String,
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub flags: u32,
}

impl MapSpecLite {
    pub(crate) fn reservation_bytes(&self, possible_cpus: usize) -> Option<usize> {
        map_capacity_bytes(
            self.map_type,
            self.key_size,
            self.value_size,
            self.max_entries,
            possible_cpus,
        )
    }
}

/// Loaded fds (needs caps).
pub struct Loaded {
    pub progs: HashMap<String, OwnedFd>,
    pub maps: HashMap<String, OwnedFd>,
}

/// Local gated pipeline owner. Legacy cross-thread loading remains Send;
/// synchronous global links retain the actual local shared gate separately.
pub(crate) struct GatedLoaded {
    lifecycle: Vec<crate::writer_gate::LifecycleWriter>,
    loaded: Loaded,
}
impl std::ops::Deref for GatedLoaded {
    type Target = Loaded;
    fn deref(&self) -> &Loaded {
        &self.loaded
    }
}

struct Sym {
    name: String,
    value: usize,
    size: usize,
    shndx: usize,
    is_func: bool,
    is_obj: bool,
    is_section: bool,
}

struct Reloc {
    off: usize,
    typ: u32,
    sym: usize,
}

fn u32le(b: &[u8]) -> u32 {
    u32::from_le_bytes(b[0..4].try_into().unwrap())
}

fn sec_bytes<'a>(
    elf: &goblin::elf::Elf<'a>,
    obj: &'a [u8],
    want: &str,
) -> anyhow::Result<&'a [u8]> {
    for s in &elf.section_headers {
        if &elf.shdr_strtab[s.sh_name] == want {
            let o = s.sh_offset as usize;
            let n = s.sh_size as usize;
            return obj
                .get(o..o + n)
                .ok_or_else(|| anyhow::anyhow!("section {want} out of bounds"));
        }
    }
    anyhow::bail!("section {want} missing")
}

fn sec_bytes_opt<'a>(elf: &goblin::elf::Elf<'a>, obj: &'a [u8], want: &str) -> Option<&'a [u8]> {
    sec_bytes(elf, obj, want).ok()
}

fn parse_syms(elf: &goblin::elf::Elf) -> Vec<Sym> {
    let mut out = Vec::new();
    for s in elf.syms.iter() {
        let ty = s.st_type();
        // Section symbols name via shstrtab, not strtab.
        let name = if ty == goblin::elf::sym::STT_SECTION {
            elf.section_headers
                .get(s.st_shndx)
                .map(|h| elf.shdr_strtab[h.sh_name].to_string())
                .unwrap_or_default()
        } else {
            elf.strtab.get_at(s.st_name).unwrap_or("").to_string()
        };
        out.push(Sym {
            name,
            value: s.st_value as usize,
            size: s.st_size as usize,
            shndx: s.st_shndx,
            is_func: ty == goblin::elf::sym::STT_FUNC,
            is_obj: ty == goblin::elf::sym::STT_OBJECT,
            is_section: ty == goblin::elf::sym::STT_SECTION,
        });
    }
    out
}

/// Parse a REL section (16B entries: r_offset, r_info).
fn parse_relocs(bytes: &[u8], sec: &str) -> anyhow::Result<Vec<Reloc>> {
    if bytes.len() % 16 != 0 {
        anyhow::bail!("rel section {sec}: bad size {}", bytes.len());
    }
    let mut out = Vec::new();
    for e in bytes.chunks_exact(16) {
        let off = u64::from_le_bytes(e[0..8].try_into().unwrap()) as usize;
        let info = u64::from_le_bytes(e[8..16].try_into().unwrap());
        out.push(Reloc {
            off,
            typ: (info & 0xffff_ffff) as u32,
            sym: (info >> 32) as usize,
        });
    }
    Ok(out)
}

fn sec_index(elf: &goblin::elf::Elf, want: &str) -> anyhow::Result<usize> {
    for (i, s) in elf.section_headers.iter().enumerate() {
        if &elf.shdr_strtab[s.sh_name] == want {
            return Ok(i);
        }
    }
    anyhow::bail!("section {want} missing")
}

/// BPF static-call opcode (sites carry src=1 + a reloc).
const BPF_CALL: u8 = 0x85;
/// `call` src reg marking a subprogram (pseudo) call, as opposed to
/// a helper call (`src == 0`, imm = helper id).
const BPF_PSEUDO_CALL: u8 = 1;
/// `ld_imm64` opcode: function-pointer sites (address-taken
/// callbacks for helpers like `bpf_loop`) are 16-byte insns carrying
/// an `R_BPF_64_64` reloc against a `.text` FUNC sym.
const BPF_LD_IMM64: u8 = 0x18;
/// `ld_imm64` src reg marking a relocated function address (the
/// kernel resolves the relative imm to a subprogram — the aya-obj
/// rule: same `target - pc - 1` encoding as a static call).
const BPF_PSEUDO_FUNC: u8 = 4;

/// Require a whole reloc site inside its owning function. The
/// ownership filters pin only the site start; without this a
/// two-slot site could cross into sibling bytes and resolve from
/// them. (Start-ownership is the caller's filter; this pins the
/// tail. The checked add also fails closed on offset overflow
/// before any site read.)
fn check_site_contained(
    off: usize,
    width: usize,
    owner_end: usize,
    owner_name: &str,
    prog: &str,
) -> anyhow::Result<()> {
    let end = off
        .checked_add(width)
        .ok_or_else(|| anyhow::anyhow!("prog {prog}: reloc @{off} site out of range"))?;
    if end > owner_end {
        anyhow::bail!("prog {prog}: reloc @{off} site crosses {owner_name} end");
    }
    Ok(())
}

/// Validate one `ld_imm64` map site: instruction-aligned offset
/// plus an unrelocated encoding (opcode, src 0, zero reserved
/// offset bytes). Shared by both map arms and the load-time fixup
/// path (func arms use the stricter `func_ptr_target`, which
/// additionally pins the imm — map sites take an fd imm at load,
/// so only the shape is pinned here).
fn check_ld_imm64_site(bytes: &[u8], off: usize, prog: &str) -> anyhow::Result<()> {
    if off % 8 != 0 {
        anyhow::bail!("prog {prog}: map site misaligned");
    }
    let end = off
        .checked_add(16)
        .ok_or_else(|| anyhow::anyhow!("prog {prog}: map site out of range"))?;
    let site = bytes
        .get(off..end)
        .ok_or_else(|| anyhow::anyhow!("prog {prog}: map site out of range"))?;
    if site[0] != BPF_LD_IMM64 || site[1] >> 4 != 0 {
        anyhow::bail!("prog {prog}: map site vs non-ld_imm64");
    }
    if site[2..4] != [0u8; 2] {
        anyhow::bail!("prog {prog}: map site reserved bytes set");
    }
    Ok(())
}

/// Resolve an `R_BPF_64_32` call reloc to a `.text` function name.
/// Named FUNC syms resolve by (value, name); STT_SECTION syms (the
/// toolchain's reduction for LOCAL callees — `call -1` + section
/// reloc, as in query_return→walk_dispatch) resolve as
/// section_base + (imm+1)*8, the aya-obj rule. Either way the
/// target MUST be a `.text` entry: mid-function landings are drift,
/// never a guess. The site must be instruction-aligned: a
/// misaligned offset reads a straddling window, never an insn.
fn call_target(
    syms: &[Sym],
    text_fns: &[(usize, usize, String)],
    text_idx: usize,
    site_sec: &[u8],
    r: &Reloc,
    prog: &str,
) -> anyhow::Result<String> {
    if r.off % 8 != 0 {
        anyhow::bail!("prog {prog}: call reloc site misaligned");
    }
    let rsym = syms
        .get(r.sym)
        .ok_or_else(|| anyhow::anyhow!("prog {prog}: bad reloc sym"))?;
    let site = site_sec
        .get(r.off..r.off + 8)
        .ok_or_else(|| anyhow::anyhow!("prog {prog}: call reloc out of range"))?;
    if site[0] != BPF_CALL {
        anyhow::bail!("prog {prog}: call reloc vs non-call insn");
    }
    if site[1] >> 4 != BPF_PSEUDO_CALL {
        // A reloc on a helper-form call would rewrite the helper id
        // into a relative target — a silent semantic change. Real
        // toolchains emit PSEUDO_CALL for static calls, always.
        anyhow::bail!("prog {prog}: call reloc vs helper call");
    }
    if !rsym.is_section {
        if !rsym.is_func || rsym.shndx != text_idx {
            anyhow::bail!("prog {prog}: call reloc vs non-entry {}", rsym.name);
        }
        return text_fns
            .iter()
            .find(|(v, _, n)| *v == rsym.value && *n == rsym.name)
            .map(|(_, _, n)| n.clone())
            .ok_or_else(|| anyhow::anyhow!("prog {prog}: call reloc vs non-entry {}", rsym.name));
    }
    if rsym.shndx != text_idx {
        anyhow::bail!("prog {prog}: call reloc vs non-.text section {}", rsym.name);
    }
    let imm = i32::from_le_bytes(site[4..8].try_into().unwrap()) as i64;
    let target_off = rsym.value as i64 + (imm + 1) * 8;
    let target_off = usize::try_from(target_off)
        .map_err(|_| anyhow::anyhow!("prog {prog}: call target out of range"))?;
    text_fns
        .iter()
        .find(|(v, _, _)| *v == target_off)
        .map(|(_, _, n)| n.clone())
        .ok_or_else(|| anyhow::anyhow!("prog {prog}: call lands mid-function at {target_off:#x}"))
}

/// Rewrite one static-call imm: call site at `rel_off` (in the final
/// layout) targets `target_off` (in the final layout).
fn apply_call(
    insns: &mut [u8],
    rel_off: usize,
    target_off: usize,
    prog: &str,
) -> anyhow::Result<()> {
    if rel_off % 8 != 0 {
        anyhow::bail!("{prog}: call site misaligned");
    }
    let insn = insns
        .get_mut(rel_off..rel_off + 8)
        .ok_or_else(|| anyhow::anyhow!("{prog}: call reloc out of range"))?;
    if target_off % 8 != 0 {
        anyhow::bail!("{prog}: call target unaligned");
    }
    let pc = rel_off / 8;
    let imm = target_off as i64 / 8 - (pc as i64 + 1);
    let imm32: i32 = imm
        .try_into()
        .map_err(|_| anyhow::anyhow!("{prog}: call target out of range"))?;
    insn[4..8].copy_from_slice(&imm32.to_le_bytes());
    Ok(())
}

/// Resolve an `R_BPF_64_64` function-pointer reloc to a `.text`
/// function name. The site must be an aligned, unrelocated
/// `ld_imm64` (src 0, zero reserved offset bytes, zero imm64 —
/// anything else is an already-relocated or corrupt object); the
/// symbol must be a named global FUNC in `.text` (what the
/// toolchain emits for address-taken callbacks). The target MUST
/// be a `.text` entry: mid-function landings are drift, never a
/// guess.
fn func_ptr_target(
    syms: &[Sym],
    text_fns: &[(usize, usize, String)],
    text_idx: usize,
    site_sec: &[u8],
    r: &Reloc,
    prog: &str,
) -> anyhow::Result<String> {
    if r.off % 8 != 0 {
        anyhow::bail!("prog {prog}: func reloc site misaligned");
    }
    let rsym = syms
        .get(r.sym)
        .ok_or_else(|| anyhow::anyhow!("prog {prog}: bad reloc sym"))?;
    let site = site_sec
        .get(r.off..r.off + 16)
        .ok_or_else(|| anyhow::anyhow!("prog {prog}: func reloc out of range"))?;
    if site[0] != BPF_LD_IMM64 || site[1] >> 4 != 0 {
        anyhow::bail!("prog {prog}: func reloc vs non-ld_imm64 site");
    }
    if site[2..4] != [0u8; 2] {
        anyhow::bail!("prog {prog}: func reloc site reserved bytes set");
    }
    if site[4..16] != [0u8; 12] {
        anyhow::bail!("prog {prog}: func reloc vs relocated site");
    }
    if !rsym.is_func || rsym.shndx != text_idx {
        anyhow::bail!("prog {prog}: func reloc vs non-entry {}", rsym.name);
    }
    text_fns
        .iter()
        .find(|(v, _, n)| *v == rsym.value && *n == rsym.name)
        .map(|(_, _, n)| n.clone())
        .ok_or_else(|| anyhow::anyhow!("prog {prog}: func reloc vs non-entry {}", rsym.name))
}

/// Rewrite one function-pointer site: the `imm` takes the same
/// relative encoding as a static call (`target - pc - 1`, in insns),
/// and the src nibble takes `BPF_PSEUDO_FUNC` (the dst reg is
/// preserved). The high half stays zero (asserted at resolve time).
/// The site is fully validated before any mutation: a failed
/// rewrite leaves the image untouched.
fn apply_func_ptr(
    insns: &mut [u8],
    rel_off: usize,
    target_off: usize,
    prog: &str,
) -> anyhow::Result<()> {
    if rel_off % 8 != 0 {
        anyhow::bail!("{prog}: func site misaligned");
    }
    let site = insns
        .get(rel_off..rel_off + 8)
        .ok_or_else(|| anyhow::anyhow!("{prog}: func reloc out of range"))?;
    if site[0] != BPF_LD_IMM64 || site[1] >> 4 != 0 {
        anyhow::bail!("{prog}: func site not an unrelocated ld_imm64");
    }
    if site[2..4] != [0u8; 2] {
        anyhow::bail!("{prog}: func site reserved bytes set");
    }
    apply_call(insns, rel_off, target_off, prog)?;
    let insn = insns
        .get_mut(rel_off..rel_off + 8)
        .ok_or_else(|| anyhow::anyhow!("{prog}: func reloc out of range"))?;
    insn[1] = (insn[1] & 0x0f) | (BPF_PSEUDO_FUNC << 4);
    Ok(())
}

/// Reject a linked image containing a subprogram call that was not
/// rewritten from a relocation (F-BPF-1 hardening).
///
/// The toolchain pre-resolves same-section local→local calls to
/// relative pseudo-calls WITHOUT relocs, and reachable-subset
/// linking (required: the verifier rejects unreachable trailing
/// insns) invalidates their offsets — observed as `window_byte`
/// mis-linked onto `memset`, surfacing in the guest as `invalid
/// size of register spill`. Helper calls (`src == 0`) need no
/// reloc and are ignored; every pseudo-call (`src ==
/// BPF_PSEUDO_CALL) must be in `rewritten` (byte offsets into
/// `insns` that `apply_call` patched from a reloc).
fn check_calls_rewritten(
    insns: &[u8],
    rewritten: &HashSet<usize>,
    prog: &str,
) -> anyhow::Result<()> {
    if insns.len() % 8 != 0 {
        anyhow::bail!("{prog}: linked insns not a whole count");
    }
    for (i, insn) in insns.chunks_exact(8).enumerate() {
        if insn[0] == BPF_CALL && insn[1] >> 4 == BPF_PSEUDO_CALL && !rewritten.contains(&(i * 8)) {
            anyhow::bail!(
                "{prog}: unrelocated static call at insn {i} \
                 (callee must be global or inlined)"
            );
        }
    }
    Ok(())
}

/// Reject a linked image containing a function pointer that was not
/// rewritten from a relocation (same hazard as
/// [`check_calls_rewritten`]): a pre-resolved `ld_imm64` with
/// `BPF_PSEUDO_FUNC` src but no reloc would silently point at a
/// stale offset after reachable-subset linking. The scan steps over
/// each `ld_imm64`'s second slot (its bytes are not opcodes);
/// map sites (src 0, rewritten later by `load()`) are ignored here.
fn check_func_ptrs_rewritten(
    insns: &[u8],
    rewritten: &HashSet<usize>,
    prog: &str,
) -> anyhow::Result<()> {
    if insns.len() % 8 != 0 {
        anyhow::bail!("{prog}: linked insns not a whole count");
    }
    let mut i = 0usize;
    while i * 8 < insns.len() {
        let insn = &insns[i * 8..i * 8 + 8];
        if insn[0] == BPF_LD_IMM64 {
            if insn[1] >> 4 == BPF_PSEUDO_FUNC && !rewritten.contains(&(i * 8)) {
                anyhow::bail!(
                    "{prog}: unrelocated function pointer at insn {i} \
                     (callee must be global)"
                );
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    Ok(())
}

/// One linked subprogram for BTF synthesis: the main entry (insn 0)
/// plus every included `.text` function in linked order. Callbacks
/// (function-pointer targets for helpers like `bpf_loop`) need the
/// callback proto; plain static callees take the void placeholder
/// (the verifier never signature-checks static calls).
#[derive(Debug, Clone)]
pub struct SubprogInfo {
    pub name: String,
    pub insn_off: u32,
    pub is_callback: bool,
}

/// Synthesized BTF bytes plus the func_info table (`(insn_off,
/// type_id)` pairs in subprogram order).
pub type SynthBtf = (Vec<u8>, Vec<(u32, u32)>);

/// Synthesize minimal BTF + func_info for one linked image (P5b-D).
/// The toolchain emits no `.BTF` (the frozen object ban stays), so
/// helper-callback shapes (`bpf_loop`) get loader-built metadata:
/// a fixed type prefix (u64/u32 ints, a data pointer, main/callback/
/// static protos) plus one FUNC per subprog, and a func_info table
/// mapping each subprogram's insn offset to its FUNC id. Pure bytes;
/// the kernel re-validates everything at `BPF_BTF_LOAD`/`prog_load`
/// (fail-closed, loud). Fails closed on any malformed table.
pub fn synth_btf(subprogs: &[SubprogInfo]) -> anyhow::Result<SynthBtf> {
    if subprogs.is_empty() {
        anyhow::bail!("synth_btf: no subprograms");
    }
    if subprogs.len() > 256 {
        anyhow::bail!("synth_btf: too many subprograms ({})", subprogs.len());
    }
    if subprogs[0].insn_off != 0 {
        anyhow::bail!("synth_btf: main at 0, got {}", subprogs[0].insn_off);
    }
    for w in subprogs.windows(2) {
        if w[1].insn_off <= w[0].insn_off {
            anyhow::bail!("synth_btf: offsets not increasing");
        }
    }
    for s in subprogs {
        if s.name.is_empty() {
            anyhow::bail!("synth_btf: empty name");
        }
        if s.name.bytes().any(|b| b == 0) {
            anyhow::bail!("synth_btf: NUL in name");
        }
    }
    // String section: leading empty + fixed literals + names.
    let mut strs: Vec<u8> = vec![0];
    let mut off_of: Vec<u32> = Vec::with_capacity(subprogs.len() + 6);
    for lit in ["__u64", "__u32", "ctx", "pad", "arg0", "index", "cctx"] {
        off_of.push(strs.len() as u32);
        strs.extend_from_slice(lit.as_bytes());
        strs.push(0);
    }
    for s in subprogs {
        off_of.push(strs.len() as u32);
        strs.extend_from_slice(s.name.as_bytes());
        strs.push(0);
    }
    // Type section. Kinds per uapi/linux/btf.h: INT=1, PTR=2,
    // STRUCT=4, FUNC=12, FUNC_PROTO=13. The ctx arg is PTR to a
    // DEFINED struct with named params (the kernel rejects looser
    // shapes here: measured `Invalid arg#1` for PTR-to-scalar and
    // PTR-to-FWD with anonymous params on 7.0).
    let mut types: Vec<u8> = Vec::new();
    let mut rec = |name: u32, kind: u32, vlen: u32, size_or_type: u32, payload: &[u32]| {
        types.extend_from_slice(&name.to_le_bytes());
        types.extend_from_slice(&((kind << 24) | vlen).to_le_bytes());
        types.extend_from_slice(&size_or_type.to_le_bytes());
        for w in payload {
            types.extend_from_slice(&w.to_le_bytes());
        }
    };
    rec(off_of[0], 1, 0, 8, &[64]); // 1: INT __u64
    rec(off_of[1], 1, 0, 4, &[32]); // 2: INT __u32
    rec(off_of[2], 4, 1, 8, &[off_of[3], 1, 0]); // 3: STRUCT ctx { u64 pad; }
    rec(0, 2, 0, 3, &[]); // 4: PTR to ctx
    rec(0, 13, 1, 2, &[off_of[4], 4]); // 5: main proto u32 <- (ctx *arg0)
    rec(0, 13, 2, 1, &[off_of[5], 1, off_of[6], 1]); // 6: cb proto u64 <- (u64, u64)
    rec(0, 13, 0, 0, &[]); // 7: static proto void <- ()
    let mut info: Vec<(u32, u32)> = Vec::with_capacity(subprogs.len());
    for (i, s) in subprogs.iter().enumerate() {
        let proto = if i == 0 {
            5
        } else if s.is_callback {
            6
        } else {
            7
        };
        let id = 8 + i as u32;
        rec(off_of[7 + i], 12, 0, proto, &[]);
        info.push((s.insn_off, id));
    }
    // Header: magic, version, flags, hdr_len, type_off, type_len,
    // str_off, str_len.
    let mut btf: Vec<u8> = Vec::with_capacity(24 + types.len() + strs.len());
    btf.extend_from_slice(&0xEB9Fu16.to_le_bytes());
    btf.push(1);
    btf.push(0);
    btf.extend_from_slice(&24u32.to_le_bytes());
    btf.extend_from_slice(&0u32.to_le_bytes());
    btf.extend_from_slice(&(types.len() as u32).to_le_bytes());
    btf.extend_from_slice(&(types.len() as u32).to_le_bytes());
    btf.extend_from_slice(&(strs.len() as u32).to_le_bytes());
    btf.extend_from_slice(&types);
    btf.extend_from_slice(&strs);
    Ok((btf, info))
}

/// Pure preparation: parse, assert shape, relocate (map fds stay
/// symbolic — applied by `load()`).
pub fn prepare(obj: &[u8], maps: &[MapSpec], progs: &[ProgSpec]) -> anyhow::Result<Prepared> {
    prepare_sections(obj, maps, progs, false)
}
fn prepare_sections(
    obj: &[u8],
    maps: &[MapSpec],
    progs: &[ProgSpec],
    raw_identity: bool,
) -> anyhow::Result<Prepared> {
    let elf = goblin::Object::parse(obj).map_err(|e| anyhow::anyhow!("elf parse: {e}"))?;
    let goblin::Object::Elf(elf) = elf else {
        anyhow::bail!("not an ELF object");
    };
    if elf.header.e_machine != goblin::elf::header::EM_BPF {
        anyhow::bail!("not a BPF object (machine {})", elf.header.e_machine);
    }
    if !elf.little_endian {
        anyhow::bail!("big-endian BPF object unsupported");
    }
    for s in &elf.section_headers {
        let n = &elf.shdr_strtab[s.sh_name];
        if n == ".BTF" || n == ".BTF.ext" {
            anyhow::bail!("frozen shape forbids {n} (BTF-disabled objects only)");
        }
        if (n.starts_with("fentry") || n.starts_with("fexit"))
            && !progs
                .iter()
                .any(|p| p.section == n && selected_source_registration(p.name, n))
        {
            anyhow::bail!("unselected source registration section");
        }
        if n.starts_with("raw_tracepoint")
            && !(raw_identity && IDENTITY_PROGS.iter().any(|p| p.section == n))
            && !progs
                .iter()
                .any(|p| p.section == n && selected_lifecycle(p.name, p.section).is_some())
        {
            anyhow::bail!("unselected raw tracepoint section");
        }
    }
    // License: .license governs when present (must be GPL-compatible),
    // else our objects default to GPL (same as aya).
    if let Some(lic) = sec_bytes_opt(&elf, obj, ".license") {
        let s = std::str::from_utf8(lic)
            .unwrap_or("")
            .trim_end_matches('\0');
        if !GPL_OK.contains(&s) {
            anyhow::bail!("license {s:?} not GPL-compatible");
        }
    }
    let syms = parse_syms(&elf);
    let maps_sec = sec_bytes(&elf, obj, "maps")?;
    let maps_idx = sec_index(&elf, "maps")?;

    // Maps: spec dims asserted against the in-object def records.
    let mut lites = Vec::new();
    for m in maps {
        let sym = syms
            .iter()
            .find(|s| s.is_obj && s.name == m.name && s.shndx == maps_idx)
            .ok_or_else(|| anyhow::anyhow!("map {} missing", m.name))?;
        if sym.size != MAP_DEF_SIZE {
            anyhow::bail!("map {}: def size {} != {MAP_DEF_SIZE}", m.name, sym.size);
        }
        let rec = maps_sec
            .get(sym.value..sym.value + MAP_DEF_SIZE)
            .ok_or_else(|| anyhow::anyhow!("map {} def out of range", m.name))?;
        let dims = [
            u32le(&rec[0..4]),
            u32le(&rec[4..8]),
            u32le(&rec[8..12]),
            u32le(&rec[12..16]),
            u32le(&rec[16..20]),
        ];
        let want = [m.map_type, m.key_size, m.value_size, m.max_entries, m.flags];
        if dims != want {
            anyhow::bail!("map {}: dims {dims:?} != spec {want:?}", m.name);
        }
        lites.push(MapSpecLite {
            name: m.name.to_string(),
            map_type: dims[0],
            key_size: dims[1],
            value_size: dims[2],
            max_entries: dims[3],
            flags: dims[4],
        });
    }
    // Unknown map symbols fail closed (an uncreated map would dangle).
    for s in &syms {
        if s.is_obj && s.shndx == maps_idx && !maps.iter().any(|m| m.name == s.name) {
            anyhow::bail!("map {} in object but not in spec", s.name);
        }
    }

    // Relocations per section (REL format).
    let mut relocs: HashMap<String, Vec<Reloc>> = HashMap::new();
    for s in &elf.section_headers {
        let n = &elf.shdr_strtab[s.sh_name];
        if let Some(tgt) = n.strip_prefix(".rel") {
            let o = s.sh_offset as usize;
            let e = o + s.sh_size as usize;
            let bytes = obj
                .get(o..e)
                .ok_or_else(|| anyhow::anyhow!("rel section {n} out of bounds"))?;
            relocs.insert(tgt.to_string(), parse_relocs(bytes, n)?);
        }
    }
    // Func ranges per section (reloc ownership check).
    let mut funcs: HashMap<String, Vec<(usize, usize, String)>> = HashMap::new();
    for (i, s) in elf.section_headers.iter().enumerate() {
        let n = &elf.shdr_strtab[s.sh_name];
        if n == "uprobe"
            || n == "uretprobe"
            || (raw_identity && IDENTITY_PROGS.iter().any(|p| p.section == n))
            || progs.iter().any(|p| {
                p.section == n
                    && (selected_lifecycle(p.name, n).is_some()
                        || selected_source_registration(p.name, n))
            })
        {
            let mut v = Vec::new();
            for f in syms.iter().filter(|f| f.is_func && f.shndx == i) {
                v.push((f.value, f.value + f.size, f.name.clone()));
            }
            funcs.insert(n.to_string(), v);
        }
    }
    // `.text` subprograms (link candidates; may be absent).
    let text = sec_bytes_opt(&elf, obj, ".text").unwrap_or(&[]);
    let text_idx = sec_index(&elf, ".text").ok();
    let mut text_fns: Vec<(usize, usize, String)> = Vec::new();
    if let Some(tidx) = text_idx {
        for f in syms.iter().filter(|f| f.is_func && f.shndx == tidx) {
            if f.size == 0 || f.size % 8 != 0 {
                anyhow::bail!(".text fn {}: bad size {}", f.name, f.size);
            }
            if f.value % 8 != 0 {
                anyhow::bail!(".text fn {}: misaligned value", f.name);
            }
            if text_fns.iter().any(|t| t.2 == f.name) {
                anyhow::bail!(".text fn {}: duplicate name", f.name);
            }
            text_fns.push((f.value, f.value + f.size, f.name.clone()));
        }
    }
    // Owner indexes (built once): section relocs grouped by owning
    // function, plus the ownerless offsets in file order. The per-prog
    // loops below used to re-scan every section's func ranges per reloc
    // — O(progs x relocs x fns), ~54s on the 513-prog members object.
    // Same ownership predicate, run once per reloc (ranges are
    // disjoint, so first-hit == only-hit); the per-prog walk merges
    // owned + ownerless in file order, so error precedence is
    // identical to the old full scan, including multi-fault inputs.
    let mut sec_groups: HashMap<String, HashMap<String, Vec<(usize, usize)>>> = HashMap::new();
    let mut sec_ownerless: HashMap<String, Vec<(usize, usize)>> = HashMap::new();
    for (sec, ranges) in &funcs {
        let mut groups: HashMap<String, Vec<(usize, usize)>> = HashMap::new();
        let mut ownerless: Vec<(usize, usize)> = Vec::new();
        for (i, r) in relocs
            .get(sec)
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .enumerate()
        {
            match ranges.iter().find(|(a, b, _)| *a <= r.off && r.off < *b) {
                Some((_, ob, oname)) => {
                    groups.entry(oname.clone()).or_default().push((i, *ob));
                }
                None => ownerless.push((i, r.off)),
            }
        }
        sec_groups.insert(sec.clone(), groups);
        sec_ownerless.insert(sec.clone(), ownerless);
    }
    let mut text_owner_map: HashMap<usize, (usize, usize, String)> = HashMap::new();
    for r in relocs.get(".text").map(Vec::as_slice).unwrap_or(&[]) {
        if let Some((a, b, n)) = text_fns.iter().find(|(a, b, _)| *a <= r.off && r.off < *b) {
            text_owner_map.insert(r.off, (*a, *b, n.clone()));
        }
    }
    // `.text` relocs grouped by owning fn (file order preserved per
    // fn — the closure walk below sees the same sequence as the old
    // filter-over-all scan).
    let mut text_by_fn: HashMap<String, Vec<usize>> = HashMap::new();
    if let Some(rs) = relocs.get(".text") {
        for (i, r) in rs.iter().enumerate() {
            if let Some((_, _, owner)) = text_owner_map.get(&r.off) {
                text_by_fn.entry(owner.clone()).or_default().push(i);
            }
        }
    }
    // `.text` fn ranges by name (names are unique — the duplicate
    // check above bails — so this matches the old linear finds).
    let mut text_fn_range: HashMap<String, (usize, usize)> = HashMap::new();
    for (a, b, n) in &text_fns {
        text_fn_range.insert(n.clone(), (*a, *b));
    }

    let mut out = Vec::new();
    for p in progs {
        let is_return = match p.section {
            "uprobe" => false,
            "uretprobe" => true,
            s if raw_identity && IDENTITY_PROGS.iter().any(|p| p.section == s) => false,
            s if selected_lifecycle(p.name, s).is_some() => false,
            s if selected_source_registration(p.name, s) => false,
            s => anyhow::bail!("prog {}: bad section {s}", p.name),
        };
        let sec = sec_bytes(&elf, obj, p.section)?;
        let sidx = sec_index(&elf, p.section)?;
        let sym = syms
            .iter()
            .find(|s| s.is_func && s.name == p.name && s.shndx == sidx)
            .ok_or_else(|| anyhow::anyhow!("prog {} missing", p.name))?;
        if sym.size == 0 || sym.size % 8 != 0 {
            anyhow::bail!("prog {}: bad size {}", p.name, sym.size);
        }
        if sym.value % 8 != 0 {
            anyhow::bail!("prog {}: misaligned value", p.name);
        }
        let main = sec
            .get(sym.value..sym.value + sym.size)
            .ok_or_else(|| anyhow::anyhow!("prog {} out of range", p.name))?;
        let mut fixups = Vec::new();
        // Main's owned relocs: map sites recorded, call and
        // function-pointer targets rooted.
        let mut roots: Vec<(usize, String)> = Vec::new(); // (local off, fn)
        let mut func_roots: Vec<(usize, String)> = Vec::new(); // (local off, fn)
        let sec_rs = relocs.get(p.section).map(Vec::as_slice).unwrap_or(&[]);
        let empty_group: &[(usize, usize)] = &[];
        // Owned relocs (file order) + ownerless relocs (file order);
        // the walk below merges both in file order (same encounter
        // order as the old full scan — sibling relocs skipped
        // without ever being visited).
        let own = sec_groups
            .get(p.section)
            .and_then(|g| g.get(p.name))
            .map(Vec::as_slice)
            .unwrap_or(empty_group);
        let less = sec_ownerless
            .get(p.section)
            .map(Vec::as_slice)
            .unwrap_or(empty_group);
        // One owned reloc's checks (the old loop body minus the
        // owner scan/sibling skip — grouping already selected;
        // `oname` there always equaled `p.name` here).
        let mut process = |r: &Reloc, ob: usize| -> anyhow::Result<()> {
            // Calls patch 8 bytes, `ld_imm64` sites (func and map)
            // 16: the whole site must sit inside its owner.
            let width = match r.typ {
                R_BPF_64_64 => 16,
                R_BPF_64_32 => 8,
                t => anyhow::bail!("prog {}: reloc type {t} unsupported", p.name),
            };
            check_site_contained(r.off, width, ob, p.name, p.name)?;
            let rsym = syms
                .get(r.sym)
                .ok_or_else(|| anyhow::anyhow!("prog {}: bad reloc sym", p.name))?;
            let local = r.off - sym.value;
            match r.typ {
                R_BPF_64_64 => {
                    if rsym.is_func {
                        let tidx = text_idx.ok_or_else(|| {
                            anyhow::anyhow!("prog {}: func reloc but no .text", p.name)
                        })?;
                        let target = func_ptr_target(&syms, &text_fns, tidx, sec, r, p.name)?;
                        func_roots.push((local, target));
                    } else {
                        if !(rsym.is_obj && maps.iter().any(|m| m.name == rsym.name)) {
                            anyhow::bail!("prog {}: map reloc vs {}", p.name, rsym.name);
                        }
                        check_ld_imm64_site(sec, r.off, p.name)?;
                        fixups.push(MapFixup {
                            insn_off: local,
                            map: rsym.name.clone(),
                        });
                    }
                }
                R_BPF_64_32 => {
                    let tidx = text_idx.ok_or_else(|| {
                        anyhow::anyhow!("prog {}: call reloc but no .text", p.name)
                    })?;
                    let target = call_target(&syms, &text_fns, tidx, sec, r, p.name)?;
                    roots.push((local, target));
                }
                t => anyhow::bail!("prog {}: reloc type {t} unsupported", p.name),
            }
            Ok(())
        };
        // `b` never advances: the first ownerless reloc reached
        // always bails (same as the old scan encountering it).
        let (mut a, b) = (0usize, 0usize);
        while a < own.len() || b < less.len() {
            let own_first = b >= less.len() || (a < own.len() && own[a].0 < less[b].0);
            if own_first {
                let (i, ob) = own[a];
                a += 1;
                process(&sec_rs[i], ob)?;
            } else {
                anyhow::bail!("prog {}: reloc @{} ownerless (drift)", p.name, less[b].1);
            }
        }
        // Reachable closure over `.text` call and function-pointer
        // relocs (transitive). Only reachable subprograms are linked:
        // the verifier rejects unreachable trailing insns, so blind
        // `.text` appends fail.
        let mut included: Vec<String> = Vec::new();
        let mut included_set: HashSet<String> = HashSet::new();
        let mut work: Vec<String> = roots
            .iter()
            .chain(func_roots.iter())
            .map(|(_, n)| n.clone())
            .collect();
        let text_rs = relocs.get(".text").map(Vec::as_slice).unwrap_or(&[]);
        while let Some(next) = work.pop() {
            if !included_set.insert(next.clone()) {
                continue;
            }
            included.push(next.clone());
            let (f0, f1) = text_fn_range
                .get(&next)
                .copied()
                .ok_or_else(|| anyhow::anyhow!("prog {}: call vs unknown {next}", p.name))?;
            let empty: &[usize] = &[];
            for &i in text_by_fn.get(&next).map(Vec::as_slice).unwrap_or(empty) {
                let r = &text_rs[i];
                // Range guard retained: grouping already restricts
                // to this fn's relocs (same predicate, same file
                // order) — belt and suspenders.
                if f0 <= r.off && r.off < f1 {
                    let width = match r.typ {
                        R_BPF_64_32 => 8,
                        R_BPF_64_64 => 16,
                        // Unknown types bail in the apply loop below.
                        _ => continue,
                    };
                    check_site_contained(r.off, width, f1, &next, p.name)?;
                    if r.typ == R_BPF_64_32 {
                        let tidx = text_idx.ok_or_else(|| {
                            anyhow::anyhow!("prog {}: call reloc but no .text", p.name)
                        })?;
                        work.push(call_target(&syms, &text_fns, tidx, text, r, p.name)?);
                    } else if r.typ == R_BPF_64_64 {
                        let rsym = syms.get(r.sym).ok_or_else(|| {
                            anyhow::anyhow!("prog {}: bad text reloc sym", p.name)
                        })?;
                        if rsym.is_func {
                            let tidx = text_idx.ok_or_else(|| {
                                anyhow::anyhow!("prog {}: func reloc but no .text", p.name)
                            })?;
                            work.push(func_ptr_target(&syms, &text_fns, tidx, text, r, p.name)?);
                        }
                        // Map relocs pull no code.
                    }
                }
            }
        }
        included.sort_by_key(|n| text_fn_range.get(n).map(|(v, _)| *v));
        // Layout: main + included subprograms in `.text` order.
        let mut insns = main.to_vec();
        let mut base: HashMap<String, usize> = HashMap::new();
        for name in &included {
            let (f0, f1) = text_fn_range.get(name).copied().unwrap();
            let bytes = text
                .get(f0..f1)
                .ok_or_else(|| anyhow::anyhow!("prog {}: .text fn {name} out of range", p.name))?;
            base.insert(name.clone(), insns.len());
            insns.extend_from_slice(bytes);
        }
        // Apply calls and function pointers (main + included)
        // and included map sites. Every rewritten call/func site is
        // recorded: the linked image must contain no other
        // pseudo-call or pseudo-func (see `check_calls_rewritten`
        // and `check_func_ptrs_rewritten`).
        let mut rewritten: HashSet<usize> = HashSet::new();
        for (local, target) in &roots {
            let t = base
                .get(target)
                .ok_or_else(|| anyhow::anyhow!("prog {}: call vs unlinked {target}", p.name))?;
            apply_call(&mut insns, *local, *t, p.name)?;
            rewritten.insert(*local);
        }
        let mut callbacks: HashSet<String> = HashSet::new();
        for (local, target) in &func_roots {
            let t = base
                .get(target)
                .ok_or_else(|| anyhow::anyhow!("prog {}: func vs unlinked {target}", p.name))?;
            apply_func_ptr(&mut insns, *local, *t, p.name)?;
            rewritten.insert(*local);
            callbacks.insert(target.clone());
        }
        for r in relocs.get(".text").map(Vec::as_slice).unwrap_or(&[]) {
            let Some((f0, f1, owner)) = text_owner_map.get(&r.off) else {
                anyhow::bail!("prog {}: text reloc @{} ownerless (drift)", p.name, r.off);
            };
            let Some(obase) = base.get(owner.as_str()) else {
                continue; // subprogram unreachable from this prog
            };
            let width = match r.typ {
                R_BPF_64_64 => 16,
                R_BPF_64_32 => 8,
                t => anyhow::bail!("prog {}: text reloc type {t} unsupported", p.name),
            };
            check_site_contained(r.off, width, *f1, owner, p.name)?;
            let rsym = syms
                .get(r.sym)
                .ok_or_else(|| anyhow::anyhow!("prog {}: bad text reloc sym", p.name))?;
            match r.typ {
                R_BPF_64_64 => {
                    if rsym.is_func {
                        let tidx = text_idx.ok_or_else(|| {
                            anyhow::anyhow!("prog {}: func reloc but no .text", p.name)
                        })?;
                        let target = func_ptr_target(&syms, &text_fns, tidx, text, r, p.name)?;
                        if !included_set.contains(&target) {
                            anyhow::bail!("prog {}: func vs excluded {}", p.name, target);
                        }
                        let t = base.get(&target).ok_or_else(|| {
                            anyhow::anyhow!("prog {}: func vs unlinked {}", p.name, target)
                        })?;
                        let site = obase + (r.off - *f0);
                        apply_func_ptr(&mut insns, site, *t, p.name)?;
                        rewritten.insert(site);
                        callbacks.insert(target.clone());
                        continue;
                    }
                    if !(rsym.is_obj && maps.iter().any(|m| m.name == rsym.name)) {
                        anyhow::bail!("prog {}: text map reloc vs {}", p.name, rsym.name);
                    }
                    check_ld_imm64_site(text, r.off, p.name)?;
                    fixups.push(MapFixup {
                        insn_off: obase + (r.off - *f0),
                        map: rsym.name.clone(),
                    });
                }
                R_BPF_64_32 => {
                    let tidx = text_idx.ok_or_else(|| {
                        anyhow::anyhow!("prog {}: call reloc but no .text", p.name)
                    })?;
                    let target = call_target(&syms, &text_fns, tidx, text, r, p.name)?;
                    // Call targets must be entries (closure invariant).
                    if !included_set.contains(&target) {
                        anyhow::bail!("prog {}: call vs excluded {}", p.name, target);
                    }
                    let t = base.get(&target).ok_or_else(|| {
                        anyhow::anyhow!("prog {}: call vs unlinked {}", p.name, target)
                    })?;
                    let site = obase + (r.off - *f0);
                    apply_call(&mut insns, site, *t, p.name)?;
                    rewritten.insert(site);
                }
                t => anyhow::bail!("prog {}: text reloc type {t} unsupported", p.name),
            }
        }
        check_calls_rewritten(&insns, &rewritten, p.name)?;
        check_func_ptrs_rewritten(&insns, &rewritten, p.name)?;
        let mut subprogs = Vec::with_capacity(included.len() + 1);
        subprogs.push(SubprogInfo {
            name: p.name.to_string(),
            insn_off: 0,
            is_callback: false,
        });
        for name in &included {
            // Invariant: the layout loop above entered every included
            // name (same vec, same order).
            let off = base.get(name).copied().unwrap() / 8;
            subprogs.push(SubprogInfo {
                name: name.clone(),
                insn_off: off as u32,
                is_callback: callbacks.contains(name),
            });
        }
        out.push(PreparedProg {
            name: p.name.to_string(),
            section: p.section.to_string(),
            is_return,
            insns,
            map_fixups: fixups,
            subprogs,
        });
    }
    Ok(Prepared {
        progs: out,
        maps: lites,
    })
}

/// Data-only slots from the exclusive count owner's tracked load.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // Consumed by the subsequent count-command handlers.
pub(crate) struct CountLoadedSlots {
    pub maps: [crate::count_owner::registry::LoadSlot; 7],
    pub program: crate::count_owner::registry::LoadSlot,
}

pub(crate) struct CountLoadFailure {
    pub failure: crate::count_owner::OwnerFailure,
    // Bounded memory only. Count loading never opens a verifier spill file.
    #[allow(dead_code)]
    pub verifier_log: Vec<u8>,
}
impl From<crate::count_owner::OwnerFailure> for CountLoadFailure {
    fn from(failure: crate::count_owner::OwnerFailure) -> Self {
        Self {
            failure,
            verifier_log: Vec::new(),
        }
    }
}

/// Reject invocation roots that the general multi-plane preparer deliberately
/// ignores when selecting its requested programs. Count has one reviewed root.
pub(crate) fn validate_count_object(obj: &[u8]) -> Result<(), crate::count_owner::OwnerFailure> {
    use crate::count_owner::{CountOperation, FailureClass, OwnerFailure};
    let drift = || OwnerFailure::engine(CountOperation::Load, FailureClass::ObjectDrift);
    let goblin::Object::Elf(elf) = goblin::Object::parse(obj).map_err(|_| drift())? else {
        return Err(drift());
    };
    let mut roots = 0usize;
    for (index, section) in elf.section_headers.iter().enumerate() {
        if section.sh_flags & goblin::elf::section_header::SHF_EXECINSTR as u64 == 0 {
            continue;
        }
        let name = elf.shdr_strtab.get_at(section.sh_name).ok_or_else(drift)?;
        if name != ".text" && name != "uprobe" {
            return Err(drift());
        }
        for symbol in &elf.syms {
            if symbol.st_shndx != index || !symbol.is_function() {
                continue;
            }
            if name == "uprobe" {
                if elf.strtab.get_at(symbol.st_name) != Some("count_entry") || symbol.st_size == 0 {
                    return Err(drift());
                }
                roots = roots.checked_add(1).ok_or_else(drift)?;
            }
        }
    }
    if roots != 1 {
        return Err(drift());
    }
    Ok(())
}

pub(crate) fn validate_count_prepared(
    prep: &Prepared,
) -> Result<(), crate::count_owner::OwnerFailure> {
    validate_count_prepared_policy(prep, false)
}
fn validate_count_prepared_policy(
    prep: &Prepared,
    v2: bool,
) -> Result<(), crate::count_owner::OwnerFailure> {
    use crate::count_owner::{CountOperation, FailureClass, OwnerFailure};
    let drift = || OwnerFailure::engine(CountOperation::Load, FailureClass::ObjectDrift);
    if prep.maps.len() != (if v2 { 13 } else { 7 }) || prep.progs.len() != 1 {
        return Err(drift());
    }
    for expected in COUNT_MAPS {
        let actual = prep
            .maps
            .iter()
            .find(|m| m.name == expected.name)
            .ok_or_else(drift)?;
        if [
            actual.map_type,
            actual.key_size,
            actual.value_size,
            actual.max_entries,
            actual.flags,
        ] != [
            expected.map_type,
            expected.key_size,
            expected.value_size,
            expected.max_entries,
            expected.flags,
        ] {
            return Err(drift());
        }
    }
    let p = &prep.progs[0];
    if p.name != "count_entry"
        || p.is_return
        || p.insns.is_empty()
        || p.insns.len() % 8 != 0
        || p.subprogs
            .first()
            .is_none_or(|s| s.name != "count_entry" || s.insn_off != 0)
        || p.subprogs.iter().any(|s| s.is_callback)
    {
        return Err(drift());
    }
    for insn in p.insns.chunks_exact(8) {
        // BPF_FUNC_tail_call and BPF_PSEUDO_FUNC both require new proof review.
        if (insn[0] == 0x85 && insn[1] >> 4 == 0 && u32le(&insn[4..8]) == 12)
            || (insn[0] == 0x18 && insn[1] >> 4 == 4)
        {
            return Err(drift());
        }
    }
    for fixup in &p.map_fixups {
        check_ld_imm64_site(&p.insns, fixup.insn_off, &p.name).map_err(|_| drift())?;
        if !(COUNT_MAPS.iter().any(|m| m.name == fixup.map)
            || v2 && IDENTITY_MAPS.iter().any(|m| m.name == fixup.map))
        {
            return Err(drift());
        }
    }
    Ok(())
}

/// Count-only loading: every create is reserved and installed in the owner's
/// preallocated registry before diagnostics or publication. The driver is an
/// owner-private seam; neither this result nor its failure owns any descriptor.
pub(crate) fn load_count_tracked(
    prep: &Prepared,
    sink: &mut impl crate::count_owner::registry::CountLoadSink,
    driver: &mut impl crate::count_owner::io::CountIoDriver,
    deadline: std::time::Instant,
) -> Result<CountLoadedSlots, CountLoadFailure> {
    use crate::count_owner::registry::{ResourceKind, preallocated};
    use crate::count_owner::{CountMap, CountOperation, FailureClass, OwnerFailure, ResourceId};
    crate::lifecycle_producer::note_acquisition()
        .map_err(|_| OwnerFailure::engine(CountOperation::Load, FailureClass::InvalidInput))?;
    validate_count_prepared(prep)?;
    let check_deadline = |driver: &_| {
        if crate::count_owner::io::CountIoDriver::now(driver) >= deadline {
            Err(OwnerFailure::engine(
                CountOperation::Load,
                FailureClass::Deadline,
            ))
        } else {
            Ok(())
        }
    };
    // Both allocations precede the first map create, including the diagnostic
    // retry buffer. No callback BTF or temporary diagnostic FD is needed.
    let p = &prep.progs[0];
    let mut insns = preallocated(p.insns.len())?;
    insns.extend_from_slice(&p.insns);
    let mut log = preallocated(4 << 20)?;
    log.resize(4 << 20, 0);
    let mut maps = [None; 7];
    for (index, expected) in COUNT_MAPS.iter().enumerate() {
        check_deadline(driver)?;
        let m = prep
            .maps
            .iter()
            .find(|m| m.name == expected.name)
            .expect("validated count map");
        let slot = sink.reserve(ResourceKind::Map(CountMap::ALL[index]))?;
        match driver.map_create(m) {
            Ok(fd) => sink.install(slot, fd),
            Err(error) => {
                sink.failed(slot, error.raw_os_error());
                return Err(OwnerFailure::io(
                    CountOperation::Load,
                    ResourceId::Map(CountMap::ALL[index]),
                    &error,
                )
                .into());
            }
        }
        maps[index] = Some(slot);
    }
    let maps = maps.map(|slot| slot.expect("all validated maps installed"));
    for f in &p.map_fixups {
        // Same validated ld_imm64 relocation and BPF_PSEUDO_MAP_FD rewrite as
        // load_prog; all fallible shape checks ran before the first acquisition.
        let index = COUNT_MAPS
            .iter()
            .position(|m| m.name == f.map)
            .expect("validated fixup map");
        let fd = sink.borrow(maps[index]);
        let insn = &mut insns[f.insn_off..f.insn_off + 8];
        insn[1] = (insn[1] & 0x0f) | (BPF_PSEUDO_MAP_FD << 4);
        insn[4..8].copy_from_slice(&(fd.as_raw_fd() as u32).to_le_bytes());
    }
    check_deadline(driver)?;
    let mut program = sink.reserve(ResourceKind::Program)?;
    match driver.load_program(&insns, &p.name, None) {
        Ok(fd) => sink.install(program, fd),
        Err(error) => {
            sink.failed(program, error.raw_os_error());
            check_deadline(driver)?;
            program = sink.reserve(ResourceKind::Program)?;
            match driver.load_program(&insns, &p.name, Some(&mut log)) {
                Ok(fd) => sink.install(program, fd),
                Err(error) => {
                    sink.failed(program, error.raw_os_error());
                    return Err(CountLoadFailure {
                        failure: OwnerFailure::io(
                            CountOperation::Load,
                            ResourceId::Program,
                            &error,
                        ),
                        verifier_log: log,
                    });
                }
            }
        }
    }
    check_deadline(driver)?;
    Ok(CountLoadedSlots { maps, program })
}

/// Load a prepared object: create maps, apply map-fd fixups (with
/// the `BPF_PSEUDO_MAP_FD` assertion), load progs raw. Needs caps.
/// Verifier output travels in the error on failure.
/// Load one prepared program (map-fd fixups + quiet load with
/// a logging retry on failure). Shared by all-or-nothing
/// [`load`] and keep-good [`load_keep_good`]; `spill` gates the
/// full-verifier-log temp file.
fn load_prog(
    p: &PreparedProg,
    maps: &HashMap<String, OwnedFd>,
    spill: bool,
    setup: Option<(
        &crate::capture_setup::SetupLinks,
        crate::capture::BoundaryStage,
    )>,
) -> anyhow::Result<OwnedFd> {
    load_prog_inner(p, maps, spill, setup, None, None)
}

/// Shared load implementation: fixup, BTF synthesis, quiet-first
/// logged retry. `record` threads one observed per-root record
/// through the real decisions (production passes `None` and sees
/// byte-identical behavior, messages, and ordering); `ops` scripts
/// the syscall boundary for host-only tests (production: `None`).
/// Attestation and the final info query stay with the caller.
fn load_prog_inner(
    p: &PreparedProg,
    maps: &HashMap<String, OwnedFd>,
    spill: bool,
    setup: Option<(
        &crate::capture_setup::SetupLinks,
        crate::capture::BoundaryStage,
    )>,
    record: Option<&mut LoadDiagnostics>,
    ops: Option<&dyn LoadBoundaryOps>,
) -> anyhow::Result<OwnedFd> {
    use anyhow::Context as _;
    let mut record = record;
    let observed = record.is_some();
    // The caller sets the entry stage (maps are ready); classification
    // failures below keep it, fixup advances from it.
    if let Some(record) = record.as_deref_mut() {
        record.callback_subprogs = p.subprogs.iter().filter(|s| s.is_callback).count();
    }
    let raw_root = lifecycle_root(p)?;
    let kind = match raw_root {
        Some(root) => AttemptKind::Lifecycle(root),
        None => AttemptKind::Kprobe,
    };
    if let Some(record) = record.as_deref_mut() {
        record.prog_type = if raw_root.is_some() { 17 } else { 2 };
        record.expected_attach = if raw_root.is_some() { 0 } else { 48 };
        record.attach_target = 0;
        record.prog_flags = 0;
        record.stage = LoadStage::Fixup;
    }
    let mut insns = p.insns.clone();
    for f in &p.map_fixups {
        // Full 16-byte range first (checked: `Prepared` fields
        // are public, so a huge hand-built offset must ERR, not
        // panic on overflow), then shape, then patch. The borrow
        // below cannot overflow: the validator proved
        // `off + 16 <= len`.
        check_ld_imm64_site(&insns, f.insn_off, &p.name)?;
        let insn = insns
            .get_mut(f.insn_off..f.insn_off + 8)
            .ok_or_else(|| anyhow::anyhow!("{}: fixup out of range", p.name))?;
        // The compiler emits map sites with src=0; the reloc means
        // "this imm64 is a map" — the loader sets src AND fd.
        // Anything else is an already-relocated (or corrupt) object.
        let fd = maps
            .get(&f.map)
            .ok_or_else(|| anyhow::anyhow!("{}: unknown map {}", p.name, f.map))?;
        insn[1] = (insn[1] & 0x0f) | (BPF_PSEUDO_MAP_FD << 4);
        insn[4..8].copy_from_slice(&(fd.as_raw_fd() as u32).to_le_bytes());
        if let Some(record) = record.as_deref_mut() {
            record.maps.push((f.map.clone(), fd.as_raw_fd()));
        }
    }
    let license = c"GPL";
    // Callback shapes only: synthesize BTF + func_info and load
    // it (the kernel needs the callback's FUNC_PROTO — without
    // it `bpf_loop` fails `missing btf func_info`). Every other
    // prog loads BTF-less exactly as before. The BTF fd outlives
    // both load attempts (drop closes it; loaded progs hold
    // their own refs).
    let mut btf_fd = match setup {
        Some((links, stage)) => crate::capture_setup::SetupResource::guarded(None, links, stage),
        None => crate::capture_setup::SetupResource::local(None),
    };
    let mut func_info_bytes: Vec<u8> = Vec::new();
    if let Some((links, stage)) = setup {
        links.check_owned(stage)?;
    }
    let mut btf_number: Option<i32> = None;
    if p.subprogs.iter().any(|s| s.is_callback) {
        if let Some(record) = record.as_deref_mut() {
            record.stage = LoadStage::BtfSetup;
            record.btf_synthesized = true;
        }
        let (btf, info) =
            synth_btf(&p.subprogs).with_context(|| format!("synth_btf {}", p.name))?;
        for (off, id) in &info {
            func_info_bytes.extend_from_slice(&off.to_le_bytes());
            func_info_bytes.extend_from_slice(&id.to_le_bytes());
        }
        const BTF_LOG_CAP: usize = 1 << 16;
        let (btf_result, mut btf_used) = match ops {
            Some(ops) => ops.btf_load(&btf, BTF_LOG_CAP),
            None => {
                let mut btf_log = vec![0u8; BTF_LOG_CAP];
                let result = ossl_bpf_sys::btf_load(&btf, &mut btf_log);
                (result, trim_nul(&btf_log).to_vec())
            }
        };
        btf_used.truncate(BTF_LOG_CAP);
        if let Some(record) = record.as_deref_mut() {
            record.btf_log = btf_used.clone();
        }
        let fd = btf_result.map_err(|e| {
            let detail = String::from_utf8_lossy(&btf_used)
                .chars()
                .take(1000)
                .collect::<String>();
            anyhow::anyhow!("btf_load {}: {e}\n{detail}", p.name)
        })?;
        btf_number = Some(fd.as_raw_fd());
        *btf_fd = Some(fd);
    }
    let prog_btf = |fd: &Option<std::os::fd::OwnedFd>| -> Option<ossl_bpf_sys::ProgBtf<'_>> {
        fd.as_ref().map(|f| ossl_bpf_sys::ProgBtf {
            btf_fd: std::os::fd::AsRawFd::as_raw_fd(f),
            func_info: &func_info_bytes,
        })
    };
    // Quiet load first: success needs no diagnostics, and a
    // large-but-valid verification can overflow a fixed log
    // buffer (`ENOSPC`) even when the program verifies. On
    // failure, retry with the log buffer to capture the
    // verifier's report (a 4 MiB buffer: failure explorations
    // run to ~0.9 MiB, and an overflowed buffer would eat the
    // very diagnostics the retry exists for).
    if let Some((links, stage)) = setup {
        links.check_owned(stage)?;
    }
    // Production keeps its 4 MiB logged ceiling; the observed
    // diagnostic alone uses the reviewed 16 MiB ceiling.
    let log_cap = if record.is_some() { 16 << 20 } else { 4 << 20 };
    if let Some(record) = record.as_deref_mut() {
        record.stage = LoadStage::QuietLoad;
    }
    let quiet = run_load_attempt(
        ops,
        kind,
        &p.name,
        &insns,
        btf_number,
        None,
        |_log| match raw_root {
            Some(root) => ossl_bpf_sys::prog_load_lifecycle_attempt(&insns, root, None),
            None => ossl_bpf_sys::prog_load_kprobe_attempt(
                &insns,
                license,
                None,
                None,
                &p.name,
                prog_btf(&btf_fd),
            ),
        },
    );
    if let Some(record) = record.as_deref_mut() {
        record.quiet_errno = quiet.result.as_ref().err().and_then(|e| e.raw_os_error());
    }
    let fd = match quiet.result {
        Ok(fd) => fd,
        Err(_) => {
            if let Some((links, stage)) = setup {
                links.check_owned(stage)?;
            }
            if let Some(record) = record.as_deref_mut() {
                record.stage = LoadStage::LoggedLoad;
            }
            let mut log = vec![0u8; log_cap];
            let logged = run_load_attempt(
                ops,
                kind,
                &p.name,
                &insns,
                btf_number,
                Some(&mut log),
                |log| match raw_root {
                    Some(root) => ossl_bpf_sys::prog_load_lifecycle_attempt(
                        &insns,
                        root,
                        log.map(Vec::as_mut_slice),
                    ),
                    None => ossl_bpf_sys::prog_load_kprobe_attempt(
                        &insns,
                        license,
                        None,
                        log.map(Vec::as_mut_slice),
                        &p.name,
                        prog_btf(&btf_fd),
                    ),
                },
            );
            if let Some(record) = record {
                let logged_errno = logged.result.as_ref().err().and_then(|e| e.raw_os_error());
                record.logged_errno = logged_errno;
                let (used, completeness) = classify_log(&log, logged.log_true_size, logged_errno);
                record.log_bytes = used;
                record.log_true_size = logged.log_true_size;
                record.log_completeness = completeness;
            }
            match logged.result {
                Ok(fd) => fd,
                Err(e) => {
                    let full = trim_nul(&log);
                    let detail = String::from_utf8_lossy(full)
                        .chars()
                        .take(2000)
                        .collect::<String>();
                    // Keep-good loads cap verifier-log spills (a pathological
                    // all-rejected object must not fill the temp dir).
                    if let Some((links, stage)) = setup {
                        links.seal(crate::capture_setup::SetupFailure::io(
                            stage,
                            &e,
                            "native program load failed",
                        ));
                    }
                    // Production spills to its temp file; observed
                    // loads keep the bytes in-record for the
                    // grant-supplied evidence destination instead.
                    let spill = (spill && setup.is_none() && !observed)
                        .then(|| spill_verifier_log(&p.name, full))
                        .flatten();
                    let error = anyhow::anyhow!(
                        "prog_load {}: {e}\n{detail}{}",
                        p.name,
                        spill
                            .map(|p| format!("\n(full verifier log: {})", p.display()))
                            .unwrap_or_default()
                    );
                    return match setup {
                        Some((links, stage)) => links.retain_result(Err(error), stage),
                        None => Err(error),
                    };
                }
            }
        }
    };
    Ok(fd)
}

pub fn load(prep: &Prepared) -> anyhow::Result<Loaded> {
    load_with_custody(prep, None, None)
}

/// Diagnostic-evidence surface: exercised by host unit tests and the
/// ignored load-only diagnostic, not by production paths.
#[allow(dead_code)]
/// Observed gated load for the diagnostic (the legacy pair):
/// preflights the exact pair before any effect, then loads through
/// the shared custody path, pushing one per-root record per
/// attempted root. Never attaches: the preflight proves the attach
/// loop would be empty, so it does not run here at all.
pub(crate) fn load_gated_observed(
    prep: &Prepared,
    gate: &crate::writer_gate::WriterGate,
    artifact: ArtifactPins,
    records: &mut Vec<LoadDiagnostics>,
) -> anyhow::Result<Loaded> {
    preflight_legacy_pair(prep)?;
    preflight_gated_producer(prep)?;
    load_with_custody_inner(
        prep,
        None,
        Some(gate),
        Some(DiagCtx { records, artifact }),
        None,
    )
}
/// The only admission path for the two shared writer object types.
/// Shared gated-producer preflight: exactly one shared writer map,
/// every program a reviewed gated shape carrying the gate fixup,
/// and no duplicate lifecycle roots. Both the production and the
/// observed legacy routes run this before any map/load effect.
fn preflight_gated_producer(prep: &Prepared) -> anyhow::Result<()> {
    anyhow::ensure!(
        prep.maps.iter().filter(|m| m.name == "ADMIT").count() == 1,
        "missing shared writer map"
    );
    anyhow::ensure!(
        prep.progs.iter().all(|p| ((matches!(
            p.name.as_str(),
            "count_entry" | "observation_entry" | "observation_return"
        ) && matches!(p.section.as_str(), "uprobe" | "uretprobe"))
            || selected_lifecycle(&p.name, &p.section).is_some())
            && p.map_fixups.iter().any(|f| f.map == "ADMIT")),
        "ungated producer root"
    );
    for root in [
        ossl_bpf_sys::LifecycleTracepoint::Exit,
        ossl_bpf_sys::LifecycleTracepoint::Exec,
    ] {
        anyhow::ensure!(
            prep.progs
                .iter()
                .filter(|p| p.name == root.program_name())
                .count()
                <= 1,
            "duplicate lifecycle root"
        );
    }
    Ok(())
}

pub(crate) fn load_gated(
    prep: &Prepared,
    gate: &crate::writer_gate::WriterGate,
) -> anyhow::Result<GatedLoaded> {
    preflight_gated_producer(prep)?;
    let loaded = load_with_custody_inner(prep, None, Some(gate), None, None)?;
    let mut owned = GatedLoaded {
        lifecycle: Vec::new(),
        loaded,
    };
    for p in &prep.progs {
        if let Some(root) = lifecycle_root(p)? {
            let writer = gate.attach_lifecycle(&owned.loaded.progs[&p.name], root)?;
            // Link reservation already covers this at-most-two-element owner vector.
            owned.lifecycle.push(writer);
        }
    }
    Ok(owned)
}
/// Loaded source roots: fentry/fexit programs with their tracing links plus
/// retained raw-lifecycle writers. Maps are borrowed (owner + legacy), never
/// created here.
pub(crate) struct SourceLoaded {
    pub programs: std::collections::HashMap<String, OwnedFd>,
    pub links: std::collections::HashMap<String, OwnedFd>,
    pub lifecycle: Vec<crate::writer_gate::LifecycleWriter>,
}

/// Exact map surface a source root may reference: the owned source maps,
/// the owned producer maps, the two owned control duplicates, the three
/// legacy join maps, and the shared admission gate. Any other fixup name
/// refuses the load.
const SOURCE_FIXUP_MAPS: [&str; 24] = [
    "REL",
    "SOURCE_GUARD",
    "SOURCE_REQUEST",
    "SOURCE_PAIR",
    "SOURCE_DOMAIN",
    "SOURCE_OBSERVER",
    "ITER_SLOT",
    "TYPED_ADMISSION",
    "SITE_BIND",
    "BIND_PENDING",
    "EXACT_NAME",
    "DIGEST_INDEX",
    "SELECTOR_DICT",
    "THREAD_IDENTITY",
    "PARTITION",
    "ATTRIB_CONTROL",
    "SEGMENT_INDEX",
    "PRODUCER_LOSS",
    "ATTR_STATE",
    "SOURCE_CONFIG",
    "CONFIG",
    "MEMBERS",
    "NAMESPACE",
    "ADMIT",
];

/// Immutable artifact pins stamped on every observed per-root record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ArtifactPins {
    pub sha256: [u8; 32],
    pub len: u64,
}

/// Last reached load stage, recorded at its actual owner. Refusals
/// keep the failing stage with `LoadDiagnostics.error` set; later
/// roots stay `Unattempted` under fail-fast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoadStage {
    Unattempted,
    Preflight,
    MapSetup,
    Fixup,
    BtfSetup,
    QuietLoad,
    LoggedLoad,
    Attestation,
    InfoQuery,
    Loaded,
}

/// Verifier-log completeness: `log_true_size` plus termination
/// checks prove it; anything else stays inconclusive, never a pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LogCompleteness {
    /// No logged attempt ran (quiet success or pre-load refusal).
    NoLogAttempted,
    /// True size fits the buffer with NUL termination.
    Complete,
    /// True size exceeds the buffer: truncated (ENOSPC-shaped).
    Truncated,
    /// Bytes retained but completeness unprovable.
    Indeterminate,
}

/// Post-drop handle verification, set by the diagnostic owner after
/// it proves owned descriptors closed. Unit ownership proofs use
/// pipe-peer EOF directly instead of this field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Diagnostic-evidence surface: exercised by host unit tests and the
/// ignored load-only diagnostic, not by production paths.
#[allow(dead_code)]
pub(crate) enum CleanupStatus {
    Pending,
    HandlesClosed,
    /// Failure transaction: the loader dropped the transient descriptors
    /// by RAII on its internal failure paths (proven by the pipe-EOF unit
    /// proofs, not by the FD sweep, which cannot name descriptors the
    /// diagnostic never held).
    ReleasedByLoader,
}

/// Concrete bounded per-root load record. Production passes `None`
/// and behaves exactly as before; the observed diagnostic threads
/// one record per attempted root through the real load path.
#[derive(Debug, Clone)]
/// Diagnostic-evidence surface: exercised by host unit tests and the
/// ignored load-only diagnostic, not by production paths.
#[allow(dead_code)]
pub(crate) struct LoadDiagnostics {
    pub root: String,
    pub section: String,
    pub artifact: ArtifactPins,
    /// Selected program type (2/26/17), expected attach type, supplied
    /// attach target (nonzero only for TRACING), and program flags
    /// (always 0; recorded, never assumed).
    pub prog_type: u32,
    pub expected_attach: u32,
    pub attach_target: u32,
    pub prog_flags: u32,
    /// Prepared callback-classified subprograms, and whether the
    /// loader took the BTF-synthesis path for this root.
    pub callback_subprogs: usize,
    pub btf_synthesized: bool,
    /// Fixup map names resolved to live FD numbers, in fixup order.
    pub maps: Vec<(String, i32)>,
    pub stage: LoadStage,
    pub quiet_errno: Option<i32>,
    pub logged_errno: Option<i32>,
    /// Full used logged buffer (bounded by the attempt's ceiling),
    /// its kernel-reported true size, and completeness.
    pub log_bytes: Vec<u8>,
    pub log_true_size: u32,
    pub log_completeness: LogCompleteness,
    /// Used BTF-load log on the BTF path (bounded 64 KiB).
    pub btf_log: Vec<u8>,
    /// Kernel program ID and safe summary from the final info query;
    /// `info_unavailable` carries the reason when the query (or its
    /// credential bracketing) refused. The load itself still stands.
    pub loaded_id: Option<u32>,
    pub info: Option<ossl_bpf_sys::ProgramInfoSummary>,
    pub info_unavailable: Option<String>,
    /// The credential identity bracketing the info query (set only
    /// when both snapshots agreed and carried query privilege).
    /// Cross-query sameness is evaluated by the diagnostic, never
    /// assumed from per-query bracketing alone.
    pub query_creds: Option<ossl_bpf_sys::ThreadCredentials>,
    pub fixup_audit: Vec<FixupAuditEntry>,
    pub cleanup: CleanupStatus,
    pub error: Option<String>,
}

impl LoadDiagnostics {
    pub(crate) fn unattempted(root: &str, section: &str, artifact: ArtifactPins) -> Self {
        Self {
            root: root.to_owned(),
            section: section.to_owned(),
            artifact,
            prog_type: 0,
            expected_attach: 0,
            attach_target: 0,
            prog_flags: 0,
            callback_subprogs: 0,
            btf_synthesized: false,
            maps: Vec::new(),
            stage: LoadStage::Unattempted,
            quiet_errno: None,
            logged_errno: None,
            log_bytes: Vec::new(),
            log_true_size: 0,
            log_completeness: LogCompleteness::NoLogAttempted,
            btf_log: Vec::new(),
            loaded_id: None,
            info: None,
            info_unavailable: None,
            query_creds: None,
            fixup_audit: Vec::new(),
            cleanup: CleanupStatus::Pending,
            error: None,
        }
    }
}

/// Expected role of one instruction-image change. Map-FD writes
/// carry full site-shape conformance. Marker/kfunc and approved
/// field roles declare their spans for window-containment,
/// equality, and full-coverage audit; their semantic role tables
/// (which markers/fields at which sites with which values, checked
/// against the kernel BTF and patch inputs that produced them)
/// arrive with the native stage that runs patch outputs through
/// this same interface. Until then these roles prove change
/// confinement, not marker/field semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
/// Diagnostic-evidence surface: exercised by host unit tests and the
/// ignored load-only diagnostic, not by production paths.
#[allow(dead_code)]
pub(crate) enum ImageChangeRole {
    MapFd {
        map: String,
        fd: i32,
    },
    MarkerKfunc {
        marker: String,
        spans: Vec<ImageSpan>,
    },
    ApprovedField {
        field: String,
        spans: Vec<ImageSpan>,
    },
}

/// One contiguous declared span: absolute image offset plus the
/// exact before/after bytes (small: at most 8 each).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImageSpan {
    pub start: usize,
    pub before: Vec<u8>,
    pub after: Vec<u8>,
}

/// One declared change site, anchored to an 8-aligned instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FixupSite {
    pub insn_off: usize,
    pub role: ImageChangeRole,
}

/// One verified image change recorded against its expected role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FixupAuditEntry {
    pub insn_off: usize,
    pub spans: Vec<(usize, usize)>,
    pub role: ImageChangeRole,
}

/// Audit a prepared-to-fixed instruction image: same length, every
/// declared span matches its before/after bytes, every changed byte
/// is covered by exactly one non-overlapping span, and map-FD spans
/// additionally conform to the ld_imm64 site shape with the declared
/// FD. Only map-FD roles audit here: marker/field patch roles refuse
/// outright (their transformations validate solely through
/// `audit_patch_images` against admitted kernel configuration, never
/// through caller-declared spans). No unchecked
/// opcode/register/frame-access/call-target/length change inherits
/// any conservative claim.
pub(crate) fn audit_fixup_image(
    before: &[u8],
    after: &[u8],
    sites: &[FixupSite],
) -> anyhow::Result<Vec<FixupAuditEntry>> {
    anyhow::ensure!(
        before.len() == after.len(),
        "image length changed {} -> {}",
        before.len(),
        after.len()
    );
    let mut covered = vec![false; before.len()];
    let mut entries = Vec::with_capacity(sites.len());
    for site in sites {
        anyhow::ensure!(site.insn_off % 8 == 0, "audit site misaligned");
        let end = site
            .insn_off
            .checked_add(16)
            .ok_or_else(|| anyhow::anyhow!("audit site out of range"))?;
        anyhow::ensure!(end <= before.len(), "audit site out of range");
        let spans: Vec<ImageSpan> = match &site.role {
            ImageChangeRole::MapFd { map: _, fd } => {
                let base = site.insn_off;
                let slot = &before[base..base + 16];
                anyhow::ensure!(
                    slot[0] == BPF_LD_IMM64 && slot[1] >> 4 == 0,
                    "audit map site vs non-ld_imm64"
                );
                let src_before = slot[1];
                let src_after = (src_before & 0x0f) | (BPF_PSEUDO_MAP_FD << 4);
                vec![
                    ImageSpan {
                        start: base + 1,
                        before: vec![src_before],
                        after: vec![src_after],
                    },
                    ImageSpan {
                        start: base + 4,
                        before: slot[4..8].to_vec(),
                        after: fd.to_le_bytes().to_vec(),
                    },
                ]
            }
            ImageChangeRole::MarkerKfunc { .. } | ImageChangeRole::ApprovedField { .. } => {
                anyhow::bail!(
                    "patch roles audit only through audit_patch_images against admitted configuration"
                )
            }
        };
        let mut entry_spans = Vec::with_capacity(spans.len());
        for span in &spans {
            let end = span
                .start
                .checked_add(span.before.len())
                .ok_or_else(|| anyhow::anyhow!("audit span overflow"))?;
            anyhow::ensure!(
                span.start >= site.insn_off && end <= site.insn_off + 16,
                "audit span outside declared instruction"
            );
            anyhow::ensure!(
                span.before.len() == span.after.len()
                    && !span.before.is_empty()
                    && span.before.len() <= 8,
                "audit span shape"
            );
            anyhow::ensure!(span.before != span.after, "audit vacuous change");
            let actual_before = before
                .get(span.start..end)
                .ok_or_else(|| anyhow::anyhow!("audit span out of range"))?;
            let actual_after = after
                .get(span.start..end)
                .ok_or_else(|| anyhow::anyhow!("audit span out of range"))?;
            anyhow::ensure!(
                actual_before == span.before.as_slice(),
                "audit before-bytes mismatch at {start}",
                start = span.start
            );
            anyhow::ensure!(
                actual_after == span.after.as_slice(),
                "audit after-bytes mismatch at {start}",
                start = span.start
            );
            for covered in covered
                .get_mut(span.start..end)
                .ok_or_else(|| anyhow::anyhow!("audit span out of range"))?
            {
                anyhow::ensure!(!*covered, "audit overlapping spans");
                *covered = true;
            }
            entry_spans.push((span.start, span.before.len()));
        }
        entries.push(FixupAuditEntry {
            insn_off: site.insn_off,
            spans: entry_spans,
            role: site.role.clone(),
        });
    }
    for (index, covered) in covered.iter().enumerate() {
        anyhow::ensure!(
            *covered || before[index] == after[index],
            "audit unchecked image change at {index}"
        );
    }
    Ok(entries)
}

/// Canonical VMA-join patch identities in marker order: the three
/// kfunc call slots (configuration 0..3) then the six field-offset
/// slots (configuration 3..9). The names match the kernel-layout
/// admission order (`SourceLayout`: new/next/destroy, then
/// vm_start/vm_end/vm_pgoff/vm_flags/vm_file/f_inode); the audit
/// derives them from slot identity, never from caller declaration.
const PATCH_KFUNC_NAMES: [&str; 3] = [
    "bpf_iter_task_vma_new",
    "bpf_iter_task_vma_next",
    "bpf_iter_task_vma_destroy",
];
const PATCH_FIELD_NAMES: [&str; 6] = [
    "vm_start", "vm_end", "vm_pgoff", "vm_flags", "vm_file", "f_inode",
];

/// Diagnostic-evidence surface: exercised by host unit tests and the
/// ignored load-only diagnostic, not by production paths.
#[allow(dead_code)]
/// Audit one prepared program's pre-patch-to-final images against the
/// admitted kernel configuration: the same owner/helper/site/shape
/// rules the patcher enforces, re-derived from the byte images, plus
/// replacement-value equality against `configuration` (kfunc BTF IDs
/// and field offsets from the kernel-layout read). Kfunc slots must
/// show the pre-patch call shape `[0x85, 0, 0, 0]` and the exact
/// post-patch rewrite `[0x85, 0x20, 0, 0]` with the admitted ID;
/// field slots must show the mov32 shape with an unchanged
/// destination and the admitted offset. Every changed byte must
/// belong to exactly one validated slot; non-helper roots must be
/// byte-identical and marker-free. Returns per-slot entries with
/// canonical identity names. An opcode or call-target change
/// labelled as a patch slot fails here unless the bytes prove the
/// declared slot, shape, and admitted value.
pub(crate) fn audit_patch_images(
    before: &PreparedProg,
    after: &PreparedProg,
    configuration: &[u32; 13],
) -> anyhow::Result<Vec<FixupAuditEntry>> {
    anyhow::ensure!(
        configuration[..3]
            .iter()
            .all(|id| *id != 0 && *id <= i32::MAX as u32),
        "source kfunc ID range"
    );
    anyhow::ensure!(
        configuration[3..9]
            .iter()
            .all(|offset| *offset <= i32::MAX as u32),
        "source offset range"
    );
    anyhow::ensure!(
        configuration[3..8].iter().all(|offset| offset
            .checked_add(8)
            .is_some_and(|end| end <= configuration[9])),
        "source VMA extent"
    );
    anyhow::ensure!(
        before.insns.len() == after.insns.len(),
        "patch image length changed {} -> {}",
        before.insns.len(),
        after.insns.len()
    );
    let mut helper_range = None;
    for (index, subprogram) in before.subprogs.iter().enumerate() {
        if subprogram.name != "current_source_at" {
            continue;
        }
        anyhow::ensure!(
            blessed_source_owner(before) && !subprogram.is_callback,
            "source helper owner"
        );
        anyhow::ensure!(helper_range.is_none(), "duplicate source helper body");
        let start = subprogram.insn_off as usize * 8;
        let end = before
            .subprogs
            .get(index + 1)
            .map_or(before.insns.len(), |next| next.insn_off as usize * 8);
        anyhow::ensure!(
            start < end && end <= before.insns.len(),
            "source helper extent"
        );
        helper_range = Some(start..end);
    }
    let mut sites: [Option<usize>; 9] = [None; 9];
    for (index, instruction) in before.insns.chunks_exact(8).enumerate() {
        let immediate = u32::from_le_bytes(instruction[4..8].try_into().unwrap());
        let identity = match immediate {
            0x7f001..=0x7f003 => (immediate - 0x7f001) as usize,
            0x6f001..=0x6f006 => 3 + (immediate - 0x6f001) as usize,
            0x7f000..=0x7ffff | 0x6f000..=0x6ffff => {
                anyhow::bail!("unknown source patch identity")
            }
            _ => continue,
        };
        let offset = index * 8;
        anyhow::ensure!(
            helper_range.as_ref().is_some_and(|r| r.contains(&offset)),
            "source patch outside helper"
        );
        anyhow::ensure!(sites[identity].is_none(), "duplicate source patch identity");
        if identity < 3 {
            anyhow::ensure!(
                instruction[..4] == [0x85, 0, 0, 0],
                "source kfunc patch shape"
            );
        } else {
            anyhow::ensure!(
                instruction[0] == 0xb7 && instruction[1] <= 10 && instruction[2..4] == [0, 0],
                "source field patch shape"
            );
        }
        sites[identity] = Some(offset);
    }
    if helper_range.is_none() {
        anyhow::ensure!(
            sites.iter().all(Option::is_none),
            "source marker without helper body"
        );
        anyhow::ensure!(
            before.insns == after.insns,
            "non-helper root changed by patch"
        );
        return Ok(Vec::new());
    }
    anyhow::ensure!(
        sites.iter().all(Option::is_some),
        "missing source helper patch"
    );
    let mut covered = vec![false; before.insns.len()];
    let mut entries = Vec::with_capacity(9);
    for (identity, site) in sites.into_iter().enumerate() {
        let offset = site.unwrap();
        let expected = configuration[identity].to_le_bytes();
        let actual = after
            .insns
            .get(offset..offset + 8)
            .ok_or_else(|| anyhow::anyhow!("patch slot out of range"))?;
        let before_slot = &before.insns[offset..offset + 8];
        let role = if identity < 3 {
            anyhow::ensure!(
                actual[..4] == [0x85, 0x20, 0, 0],
                "source kfunc call rewrite"
            );
            anyhow::ensure!(actual[4..8] == expected, "source kfunc replacement value");
            for covered in &mut covered[offset + 1..offset + 2] {
                *covered = true;
            }
            for covered in &mut covered[offset + 4..offset + 8] {
                *covered = true;
            }
            ImageChangeRole::MarkerKfunc {
                marker: PATCH_KFUNC_NAMES[identity].to_owned(),
                spans: vec![
                    ImageSpan {
                        start: offset + 1,
                        before: vec![before_slot[1]],
                        after: vec![actual[1]],
                    },
                    ImageSpan {
                        start: offset + 4,
                        before: before_slot[4..8].to_vec(),
                        after: expected.to_vec(),
                    },
                ],
            }
        } else {
            anyhow::ensure!(
                actual[0] == 0xb7 && actual[1] == before_slot[1] && actual[2..4] == [0, 0],
                "source field destination preserved"
            );
            anyhow::ensure!(actual[4..8] == expected, "source field replacement value");
            for covered in &mut covered[offset + 4..offset + 8] {
                *covered = true;
            }
            ImageChangeRole::ApprovedField {
                field: PATCH_FIELD_NAMES[identity - 3].to_owned(),
                spans: vec![ImageSpan {
                    start: offset + 4,
                    before: before_slot[4..8].to_vec(),
                    after: expected.to_vec(),
                }],
            }
        };
        let spans = match &role {
            ImageChangeRole::MarkerKfunc { spans, .. }
            | ImageChangeRole::ApprovedField { spans, .. } => spans
                .iter()
                .map(|span| (span.start, span.before.len()))
                .collect(),
            ImageChangeRole::MapFd { .. } => Vec::new(),
        };
        entries.push(FixupAuditEntry {
            insn_off: offset,
            spans,
            role,
        });
    }
    for (index, covered) in covered.iter().enumerate() {
        anyhow::ensure!(
            *covered || before.insns[index] == after.insns[index],
            "patch unchecked image change at {index}"
        );
    }
    Ok(entries)
}

/// Diagnostic-evidence surface: exercised by host unit tests and the
/// ignored load-only diagnostic, not by production paths.
#[allow(dead_code)]
/// Exact legacy-pair preflight before any map/load effect: exactly
/// the two reviewed names with their sections and return modes,
/// each once. `observation_return` must actually carry
/// callback-classified subprograms (its name alone is not
/// calibration evidence). Entry callbacks are recorded, not refused.
pub(crate) fn preflight_legacy_pair(prepared: &Prepared) -> anyhow::Result<()> {
    anyhow::ensure!(prepared.progs.len() == 2, "legacy pair shape");
    let mut entry = false;
    let mut ret = false;
    for prog in &prepared.progs {
        match (prog.name.as_str(), prog.section.as_str(), prog.is_return) {
            ("observation_entry", "uprobe", false) => {
                anyhow::ensure!(!entry, "duplicate legacy entry");
                entry = true;
            }
            ("observation_return", "uretprobe", true) => {
                anyhow::ensure!(!ret, "duplicate legacy return");
                anyhow::ensure!(
                    prog.subprogs.iter().any(|s| s.is_callback),
                    "legacy return lacks callback classification"
                );
                ret = true;
            }
            _ => anyhow::bail!("unexpected legacy root {}:{}", prog.name, prog.section),
        }
    }
    anyhow::ensure!(entry && ret, "legacy pair shape");
    Ok(())
}

/// Diagnostic-evidence surface: exercised by host unit tests and the
/// ignored load-only diagnostic, not by production paths.
#[allow(dead_code)]
/// Nine-root singleton preflight across the four prepared halves,
/// before any kernel object exists. Source and count halves keep
/// their zero-callback rules here; load-time seams re-check the
/// roots they load.
pub(crate) fn preflight_nine_roots(
    legacy: &Prepared,
    registration: &Prepared,
    typed: &Prepared,
    count: &Prepared,
) -> anyhow::Result<()> {
    preflight_legacy_pair(legacy)?;
    anyhow::ensure!(registration.progs.len() == 4, "registration shape");
    for (name, section) in [
        ("source_reg_in", "fentry/uprobe_register"),
        ("source_reg_out", "fexit/uprobe_register"),
        ("attr_exit", "raw_tracepoint/sched_process_exit"),
        ("attr_exec", "raw_tracepoint/sched_process_exec"),
    ] {
        let found = registration
            .progs
            .iter()
            .filter(|p| p.name == name && p.section == section && !p.is_return)
            .count();
        anyhow::ensure!(found == 1, "registration singleton {name}");
    }
    for prog in &registration.progs {
        anyhow::ensure!(
            !prog.subprogs.iter().any(|s| s.is_callback),
            "registration root {} forbids callback BTF",
            prog.name
        );
    }
    anyhow::ensure!(typed.progs.len() == 2, "typed pair shape");
    for (name, section, is_return) in [
        ("typed_entry", "uprobe", false),
        ("typed_return", "uretprobe", true),
    ] {
        let found = typed
            .progs
            .iter()
            .filter(|p| p.name == name && p.section == section && p.is_return == is_return)
            .count();
        anyhow::ensure!(found == 1, "typed singleton {name}");
    }
    for prog in &typed.progs {
        anyhow::ensure!(
            !prog.subprogs.iter().any(|s| s.is_callback),
            "typed root {} forbids callback BTF",
            prog.name
        );
    }
    anyhow::ensure!(
        count.progs.len() == 1
            && count.progs[0].name == "count_entry"
            && count.progs[0].section == "uprobe"
            && !count.progs[0].is_return
            && !count.progs[0].subprogs.iter().any(|s| s.is_callback),
        "count singleton shape"
    );
    Ok(())
}

/// Diagnostic-evidence surface: exercised by host unit tests and the
/// ignored load-only diagnostic, not by production paths.
#[allow(dead_code)]
/// Compare an observed kernel map-ID set against prepared references
/// resolved to live identities: same multiset, no zeros, no
/// duplicates. Pure; the native stage supplies both ID lists.
pub(crate) fn check_map_id_set(expected: &[u32], observed: &[u32]) -> anyhow::Result<()> {
    anyhow::ensure!(
        observed.iter().all(|id| *id != 0),
        "observed zero map identity"
    );
    let mut sorted = observed.to_vec();
    sorted.sort_unstable();
    anyhow::ensure!(
        sorted.windows(2).all(|pair| pair[0] != pair[1]),
        "observed duplicate map identity"
    );
    let mut want = expected.to_vec();
    want.sort_unstable();
    anyhow::ensure!(sorted == want, "map identity set mismatch");
    Ok(())
}

/// Split the used verifier-log bytes from a logged attempt and prove
/// completeness: the true size must fit the buffer with NUL
/// termination, else the log is truncated or indeterminate. A
/// failed attempt reporting ENOSPC can never be Complete (fitting
/// size metadata contradicts the errno). Indeterminate logs retain
/// the NUL-trimmed buffer rather than trusting a possibly
/// unusable true size, so no diagnostic bytes are silently
/// discarded; only the verdict stays inconclusive.
fn classify_log(
    buffer: &[u8],
    true_size: u32,
    failed_errno: Option<i32>,
) -> (Vec<u8>, LogCompleteness) {
    let true_size = true_size as usize;
    if true_size > buffer.len() {
        return (buffer.to_vec(), LogCompleteness::Truncated);
    }
    if failed_errno == Some(libc::ENOSPC) {
        return (trim_nul(buffer).to_vec(), LogCompleteness::Indeterminate);
    }
    if true_size >= 1 && buffer[true_size - 1] == 0 {
        (buffer[..true_size].to_vec(), LogCompleteness::Complete)
    } else {
        (trim_nul(buffer).to_vec(), LogCompleteness::Indeterminate)
    }
}

/// Observed-load context: the record table plus the artifact pins
/// stamped on every record pushed through it.
struct DiagCtx<'a> {
    records: &'a mut Vec<LoadDiagnostics>,
    artifact: ArtifactPins,
}

/// One source root's kind: tracing registration or raw lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceRootKind {
    Tracing(ossl_bpf_sys::SourceTracingRoot),
    Lifecycle(ossl_bpf_sys::LifecycleTracepoint),
}

/// Classify one prepared program as a source root, exactly as the
/// production loop does: the two reviewed tracing names, else the
/// finite lifecycle table. Anything else is unselected.
fn classify_source_root(root: &PreparedProg) -> anyhow::Result<SourceRootKind> {
    let tracing = match (root.name.as_str(), root.section.as_str()) {
        ("source_reg_in", "fentry/uprobe_register") => Some(ossl_bpf_sys::SourceTracingRoot::Enter),
        ("source_reg_out", "fexit/uprobe_register") => Some(ossl_bpf_sys::SourceTracingRoot::Exit),
        _ => None,
    };
    let raw = if tracing.is_none() {
        selected_lifecycle(&root.name, &root.section)
    } else {
        None
    };
    anyhow::ensure!(
        tracing.is_some() || raw.is_some(),
        "unselected source root {}:{}",
        root.name,
        root.section
    );
    Ok(match (tracing, raw) {
        (Some(kind), None) => SourceRootKind::Tracing(kind),
        (None, Some(kind)) => SourceRootKind::Lifecycle(kind),
        _ => unreachable!("selected exactly one root kind"),
    })
}

/// Load-attempt shape for the scripted boundary: kernel program
/// type plus, for tracing roots, the validated FUNC target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttemptKind {
    Kprobe,
    Lifecycle(ossl_bpf_sys::LifecycleTracepoint),
    SourceRegistration(ossl_bpf_sys::SourceTracingRoot, u32),
}

/// Scripted syscall-boundary effects for host-only tests. Every
/// method replaces exactly one boundary effect (load syscall,
/// BTF-load syscall, gate attestation, admission injection, info
/// query, credential snapshot, link creation); selection, fixup,
/// retry, classification, ordering, and ownership decisions stay in
/// the real code. Production always passes `None` and takes the
/// real path; lifecycle attachment has no scripted form (its writer
/// is unmintable without the gate), so scripted order probes use
/// tracing roots and scripted lifecycle attach is a refusal.
trait LoadBoundaryOps {
    /// One scripted load attempt. `name` identifies the root under
    /// load, `btf_fd` the live program-BTF FD when the input took
    /// the BTF path (scripts assert presence and stability across
    /// the quiet/logged pair), and `log` the actual attempt buffer
    /// (`None` for quiet attempts): scripts observe its ceiling and
    /// may fill it with distinctive bytes, which the real
    /// classification then retains.
    fn load_attempt(
        &self,
        kind: AttemptKind,
        name: &str,
        insns: &[u8],
        btf_fd: Option<i32>,
        log: Option<&mut [u8]>,
    ) -> ossl_bpf_sys::ProgLoadAttempt;
    fn btf_load(&self, btf: &[u8], log_cap: usize) -> (std::io::Result<OwnedFd>, Vec<u8>);
    fn attest(&self, program: &OwnedFd) -> std::io::Result<()>;
    fn inject_admit(
        &self,
        gate: &crate::writer_gate::WriterGate,
        spec: &MapSpecLite,
    ) -> std::io::Result<OwnedFd>;
    fn info_query(&self, program: &OwnedFd) -> std::io::Result<ossl_bpf_sys::ProgramInfoSummary>;
    fn thread_creds(&self) -> std::io::Result<ossl_bpf_sys::ThreadCredentials>;
    fn attach_link(
        &self,
        program: &OwnedFd,
        kind: ossl_bpf_sys::SourceTracingRoot,
    ) -> std::io::Result<OwnedFd>;
}

/// One load attempt through the scripted boundary or the real
/// loader. `log` is the actual attempt buffer (`None` for quiet
/// attempts, the sized logged buffer otherwise): scripts observe
/// its ceiling — asserting the production (4 MiB) versus diagnostic
/// (16 MiB) policy — and may fill it with distinctive bytes that
/// the real classification retains. `btf_fd` carries the live
/// program-BTF FD number when the input took the BTF path.
fn run_load_attempt(
    ops: Option<&dyn LoadBoundaryOps>,
    kind: AttemptKind,
    name: &str,
    insns: &[u8],
    btf_fd: Option<i32>,
    log: Option<&mut Vec<u8>>,
    real: impl FnOnce(Option<&mut Vec<u8>>) -> ossl_bpf_sys::ProgLoadAttempt,
) -> ossl_bpf_sys::ProgLoadAttempt {
    match ops {
        Some(ops) => ops.load_attempt(kind, name, insns, btf_fd, log.map(Vec::as_mut_slice)),
        None => real(log),
    }
}

/// Gate attestation through the scripted boundary or the real gate.
fn run_attest(
    ops: Option<&dyn LoadBoundaryOps>,
    gate: &crate::writer_gate::WriterGate,
    program: &OwnedFd,
) -> std::io::Result<()> {
    match ops {
        Some(ops) => ops.attest(program),
        None => gate.attest(program),
    }
}

/// Admission-map injection through the scripted boundary or the real gate.
fn run_inject_admit(
    ops: Option<&dyn LoadBoundaryOps>,
    gate: &crate::writer_gate::WriterGate,
    spec: &MapSpecLite,
) -> std::io::Result<OwnedFd> {
    match ops {
        Some(ops) => ops.inject_admit(gate, spec),
        None => gate.inject(spec),
    }
}

/// Final safe-info observation for one loaded program: credential
/// snapshot, info query, credential snapshot. Unchanged credentials
/// with query privilege plus a decodable reply yield the loaded ID
/// and summary; anything else records the precise unavailability
/// reason. Never fails: the load stands with or without metadata.
fn observe_loaded_program(
    program: &OwnedFd,
    diag: &mut LoadDiagnostics,
    ops: Option<&dyn LoadBoundaryOps>,
) {
    diag.stage = LoadStage::InfoQuery;
    let creds_before = match ops {
        Some(ops) => ops.thread_creds(),
        None => ossl_bpf_sys::calling_thread_credentials(),
    };
    let summary = match ops {
        Some(ops) => ops.info_query(program),
        None => ossl_bpf_sys::program_info_summary(program.as_fd()),
    };
    let creds_after = match ops {
        Some(ops) => ops.thread_creds(),
        None => ossl_bpf_sys::calling_thread_credentials(),
    };
    let mut unavailable = |reason: String| {
        diag.loaded_id = None;
        diag.info = None;
        diag.info_unavailable = Some(reason);
        diag.query_creds = None;
    };
    let (before, after) = match (creds_before, creds_after) {
        (Ok(before), Ok(after)) => (before, after),
        (Err(error), _) | (_, Err(error)) => {
            unavailable(format!("credentials unavailable: {error}"));
            return;
        }
    };
    if before != after {
        unavailable("credentials changed around info query".to_owned());
        return;
    }
    if !ossl_bpf_sys::has_bpf_query_capabilities(&before) {
        unavailable("query privilege missing".to_owned());
        return;
    }
    match summary {
        Ok(summary) => {
            diag.loaded_id = Some(summary.prog_id);
            diag.info = Some(summary);
            diag.info_unavailable = None;
            diag.query_creds = Some(before);
        }
        Err(error) => unavailable(format!("info query refused: {error}")),
    }
}

/// Diagnostic-evidence surface: exercised by host unit tests and the
/// ignored load-only diagnostic, not by production paths.
#[allow(dead_code)]
/// Load one checked source root without attaching: selection,
/// return-mode/callback/gate checks, map fixup, quiet-first logged
/// load, and gate attestation. Returns the attested unattached
/// program. Carries its own checks and never assumes a group
/// preflight ran; the diagnostic caller stops at the returned FD.
pub(crate) fn load_source_root_unattached(
    root: &PreparedProg,
    source_maps: &std::collections::BTreeMap<&'static str, OwnedFd>,
    legacy: &Loaded,
    attach_btf_id: u32,
    gate: &crate::writer_gate::WriterGate,
) -> anyhow::Result<OwnedFd> {
    load_source_root_inner(root, source_maps, legacy, attach_btf_id, gate, None, None)
}

/// Diagnostic-evidence surface: exercised by host unit tests and the
/// ignored load-only diagnostic, not by production paths.
#[allow(dead_code)]
/// Observed single-root load for the diagnostic: runs the shared
/// implementation and pushes exactly one per-root record (loaded or
/// refused) into `records`. Never attaches.
pub(crate) fn load_source_root_unattached_observed(
    root: &PreparedProg,
    source_maps: &std::collections::BTreeMap<&'static str, OwnedFd>,
    legacy: &Loaded,
    attach_btf_id: u32,
    gate: &crate::writer_gate::WriterGate,
    artifact: ArtifactPins,
    records: &mut Vec<LoadDiagnostics>,
) -> anyhow::Result<OwnedFd> {
    let mut record = LoadDiagnostics::unattempted(&root.name, &root.section, artifact);
    let outcome = load_source_root_inner(
        root,
        source_maps,
        legacy,
        attach_btf_id,
        gate,
        Some(&mut record),
        None,
    );
    if let Err(error) = outcome.as_ref() {
        record.error = Some(format!("{error:#}"));
    }
    records.push(record);
    outcome
}

/// Shared single-root implementation: the exact per-root checks,
/// fixup, quiet-first logged load, and attestation the production
/// loop ran inline. `record` threads one observed record through
/// the real decisions (production passes `None`); `ops` scripts
/// the syscall boundary for host-only tests (production: `None`).
/// No attach operation exists on this seam by construction.
fn load_source_root_inner(
    root: &PreparedProg,
    source_maps: &std::collections::BTreeMap<&'static str, OwnedFd>,
    legacy: &Loaded,
    attach_btf_id: u32,
    gate: &crate::writer_gate::WriterGate,
    record: Option<&mut LoadDiagnostics>,
    ops: Option<&dyn LoadBoundaryOps>,
) -> anyhow::Result<OwnedFd> {
    use anyhow::Context as _;
    let mut record = record;
    let observed = record.is_some();
    if let Some(record) = record.as_deref_mut() {
        record.stage = LoadStage::Preflight;
        record.callback_subprogs = root.subprogs.iter().filter(|s| s.is_callback).count();
    }
    anyhow::ensure!(attach_btf_id != 0, "source load requires nonzero FUNC ID");
    anyhow::ensure!(
        gate.preparing(),
        "source roots load only under the unopened gate"
    );
    // The complete map set, shared with the group loader: the seam
    // refuses a half-built map set before touching this root, even
    // when the root itself references only a subset.
    check_source_map_presence(source_maps, legacy)?;
    let kind = classify_source_root(root)?;
    anyhow::ensure!(!root.is_return, "source root forbids return mode");
    anyhow::ensure!(
        !root.subprogs.iter().any(|s| s.is_callback),
        "source root forbids callback BTF"
    );
    anyhow::ensure!(
        root.map_fixups.iter().any(|f| f.map == "ADMIT"),
        "source root lacks shared-gate fixup"
    );
    if let Some(record) = record.as_deref_mut() {
        let (prog_type, expected_attach) = match kind {
            SourceRootKind::Tracing(tr) => (26, tr.attach_type()),
            SourceRootKind::Lifecycle(_) => (17, 0),
        };
        record.prog_type = prog_type;
        record.expected_attach = expected_attach;
        record.attach_target = match kind {
            SourceRootKind::Tracing(_) => attach_btf_id,
            SourceRootKind::Lifecycle(_) => 0,
        };
        record.prog_flags = 0;
        record.stage = LoadStage::Fixup;
    }
    let mut insns = root.insns.clone();
    // Allocated only on push, which happens for observed loads alone.
    let mut sites = Vec::new();
    for fixup in &root.map_fixups {
        anyhow::ensure!(
            SOURCE_FIXUP_MAPS.contains(&fixup.map.as_str()),
            "source fixup to unreviewed map {}",
            fixup.map
        );
        check_ld_imm64_site(&insns, fixup.insn_off, &root.name)?;
        let fd = source_maps
            .get(fixup.map.as_str())
            .map(|owned| owned.as_fd())
            .or_else(|| legacy.maps.get(&fixup.map).map(|owned| owned.as_fd()))
            .ok_or_else(|| anyhow::anyhow!("source fixup unresolved {}", fixup.map))?;
        let slot = insns
            .get_mut(fixup.insn_off..fixup.insn_off + 8)
            .ok_or_else(|| anyhow::anyhow!("{}: fixup out of range", root.name))?;
        // Same validated ld_imm64 relocation and BPF_PSEUDO_MAP_FD rewrite
        // as load_prog: the compiler emits map sites with src=0.
        slot[1] = (slot[1] & 0x0f) | (BPF_PSEUDO_MAP_FD << 4);
        slot[4..8].copy_from_slice(&(fd.as_raw_fd() as u32).to_le_bytes());
        if record.is_some() {
            sites.push(FixupSite {
                insn_off: fixup.insn_off,
                role: ImageChangeRole::MapFd {
                    map: fixup.map.clone(),
                    fd: fd.as_raw_fd(),
                },
            });
        }
        if let Some(record) = record.as_deref_mut() {
            record.maps.push((fixup.map.clone(), fd.as_raw_fd()));
        }
    }
    if let Some(record) = record.as_deref_mut() {
        record.fixup_audit = audit_fixup_image(&root.insns, &insns, &sites)
            .with_context(|| format!("fixup audit {}", root.name))?;
    }
    // Production keeps its 4 MiB logged ceiling; the observed
    // diagnostic alone uses the reviewed 16 MiB ceiling.
    let log_cap = if record.is_some() { 16 << 20 } else { 4 << 20 };
    let attempt_kind = match kind {
        SourceRootKind::Tracing(tr) => AttemptKind::SourceRegistration(tr, attach_btf_id),
        SourceRootKind::Lifecycle(lc) => AttemptKind::Lifecycle(lc),
    };
    if let Some(record) = record.as_deref_mut() {
        record.stage = LoadStage::QuietLoad;
    }
    let quiet =
        run_load_attempt(
            ops,
            attempt_kind,
            &root.name,
            &insns,
            None,
            None,
            |_log| match kind {
                SourceRootKind::Tracing(tr) => {
                    ossl_bpf_sys::prog_load_source_attempt(&insns, tr, attach_btf_id, None)
                }
                SourceRootKind::Lifecycle(lc) => {
                    ossl_bpf_sys::prog_load_lifecycle_attempt(&insns, lc, None)
                }
            },
        );
    if let Some(record) = record.as_deref_mut() {
        record.quiet_errno = quiet.result.as_ref().err().and_then(|e| e.raw_os_error());
    }
    let program = match quiet.result {
        Ok(fd) => fd,
        Err(first) => {
            if let Some(record) = record.as_deref_mut() {
                record.stage = LoadStage::LoggedLoad;
            }
            let mut log = vec![0u8; log_cap];
            let logged = run_load_attempt(
                ops,
                attempt_kind,
                &root.name,
                &insns,
                None,
                Some(&mut log),
                |log| match kind {
                    SourceRootKind::Tracing(tr) => ossl_bpf_sys::prog_load_source_attempt(
                        &insns,
                        tr,
                        attach_btf_id,
                        log.map(Vec::as_mut_slice),
                    ),
                    SourceRootKind::Lifecycle(lc) => ossl_bpf_sys::prog_load_lifecycle_attempt(
                        &insns,
                        lc,
                        log.map(Vec::as_mut_slice),
                    ),
                },
            );
            if let Some(record) = record.as_deref_mut() {
                let logged_errno = logged.result.as_ref().err().and_then(|e| e.raw_os_error());
                record.logged_errno = logged_errno;
                let (used, completeness) = classify_log(&log, logged.log_true_size, logged_errno);
                record.log_bytes = used;
                record.log_true_size = logged.log_true_size;
                record.log_completeness = completeness;
            }
            match logged.result {
                Ok(fd) => fd,
                Err(error) => {
                    let full = trim_nul(&log);
                    let detail = String::from_utf8_lossy(full)
                        .chars()
                        .take(2000)
                        .collect::<String>();
                    // Production spills to its temp file; observed
                    // loads keep the bytes in-record for the
                    // grant-supplied evidence destination instead.
                    let spill = if observed {
                        None
                    } else {
                        spill_verifier_log(&root.name, full)
                            .map(|path| format!("\n(full verifier log: {})", path.display()))
                    };
                    anyhow::bail!(
                        "source prog_load {}: {error} (quiet: {first})\n{detail}{}",
                        root.name,
                        spill.unwrap_or_default()
                    );
                }
            }
        }
    };
    if let Some(record) = record.as_deref_mut() {
        record.stage = LoadStage::Attestation;
    }
    run_attest(ops, gate, &program)
        .with_context(|| format!("source program {} missing shared gate", root.name))?;
    if let Some(record) = record {
        observe_loaded_program(&program, record, ops);
        record.stage = LoadStage::Loaded;
    }
    Ok(program)
}

/// Load the checked source half under the closed gate: resolve every map
/// fixup against the owner's source/control maps plus the session's legacy
/// maps, load fentry/fexit roots through the finite tracing loader and raw
/// roots through the lifecycle loader, attach all four links, and attest
/// every program to the shared gate. Needs caps. The gate must be unopened:
/// raw attach requires it, and no writer may fire mid-load. Partial failure
/// drops every FD acquired here; maps are borrowed and stay with their owners.
pub(crate) fn load_source_roots(
    prepared: &Prepared,
    source_maps: &std::collections::BTreeMap<&'static str, OwnedFd>,
    legacy: &Loaded,
    attach_btf_id: u32,
    gate: &crate::writer_gate::WriterGate,
) -> anyhow::Result<SourceLoaded> {
    load_source_roots_inner(prepared, source_maps, legacy, attach_btf_id, gate, None)
}

/// Complete source-map presence validation, shared by the group
/// loader and the singleton seam: every reviewed fixup map must be
/// present on its owning side (the four legacy maps on the legacy
/// load, the rest owned by the source maps) before any root loads.
/// A singleton that checked only its own root's references could
/// load into a half-built map set; the seam carries the whole check
/// and never assumes a group preflight ran.
fn check_source_map_presence(
    source_maps: &std::collections::BTreeMap<&'static str, OwnedFd>,
    legacy: &Loaded,
) -> anyhow::Result<()> {
    for name in SOURCE_FIXUP_MAPS {
        if matches!(name, "CONFIG" | "MEMBERS" | "NAMESPACE" | "ADMIT") {
            anyhow::ensure!(
                legacy.maps.contains_key(name),
                "source load missing legacy map {name}"
            );
        } else {
            anyhow::ensure!(
                source_maps.contains_key(name),
                "source load missing owned map {name}"
            );
        }
    }
    Ok(())
}

/// Shared production loop: group preflight, then per-root
/// load/attest/attach strictly in prepared order through the
/// single-root seam. `ops` scripts the load/attest/link boundary for
/// host-only order probes (production: `None`); the lifecycle arm
/// always takes the real gate path.
fn load_source_roots_inner(
    prepared: &Prepared,
    source_maps: &std::collections::BTreeMap<&'static str, OwnedFd>,
    legacy: &Loaded,
    attach_btf_id: u32,
    gate: &crate::writer_gate::WriterGate,
    ops: Option<&dyn LoadBoundaryOps>,
) -> anyhow::Result<SourceLoaded> {
    use anyhow::Context as _;
    anyhow::ensure!(attach_btf_id != 0, "source load requires nonzero FUNC ID");
    anyhow::ensure!(
        gate.preparing(),
        "source roots load only under the unopened gate"
    );
    anyhow::ensure!(
        prepared.progs.len() == 4,
        "source half must hold exactly four roots"
    );
    check_source_map_presence(source_maps, legacy)?;
    let mut loaded = SourceLoaded {
        programs: std::collections::HashMap::with_capacity(4),
        links: std::collections::HashMap::with_capacity(2),
        lifecycle: Vec::with_capacity(2),
    };
    for root in &prepared.progs {
        let program =
            load_source_root_inner(root, source_maps, legacy, attach_btf_id, gate, None, ops)?;
        match classify_source_root(root)? {
            SourceRootKind::Tracing(kind) => {
                let link = match ops {
                    Some(ops) => ops
                        .attach_link(&program, kind)
                        .with_context(|| format!("source link_create {}", root.name))?,
                    None => {
                        ossl_bpf_sys::link_create_source_registration(program.as_raw_fd(), kind)
                            .with_context(|| format!("source link_create {}", root.name))?
                    }
                };
                loaded.links.insert(root.name.clone(), link);
            }
            SourceRootKind::Lifecycle(kind) => {
                let writer = gate
                    .attach_lifecycle(&program, kind)
                    .with_context(|| format!("source lifecycle attach {}", root.name))?;
                loaded.lifecycle.push(writer);
            }
        }
        loaded.programs.insert(root.name.clone(), program);
    }
    Ok(loaded)
}

/// Split the source half into registration roots (fentry/raw, loaded +
/// attached by `load_source_roots`) and typed roots (uprobe/uretprobe,
/// loaded unattached by `load_typed_borrowed`, attached later per typed
/// export). Single predicate; exactly the two reviewed typed names pass.
pub(crate) fn split_typed_preparation(prepared: Prepared) -> anyhow::Result<(Prepared, Prepared)> {
    let maps = prepared.maps;
    let (typed, registration): (Vec<PreparedProg>, Vec<PreparedProg>) = prepared
        .progs
        .into_iter()
        .partition(|p| matches!(p.name.as_str(), "typed_entry" | "typed_return"));
    for p in &typed {
        anyhow::ensure!(
            matches!(
                (p.name.as_str(), p.section.as_str(), p.is_return),
                ("typed_entry", "uprobe", false) | ("typed_return", "uretprobe", true)
            ),
            "typed root shape"
        );
    }
    let typed = Prepared {
        progs: typed,
        maps: maps.clone(),
    };
    let registration = Prepared {
        progs: registration,
        maps,
    };
    Ok((registration, typed))
}

/// Load the typed roots against borrowed maps without attaching: fixups
/// resolve against the owner's source/producer/control maps plus the
/// session's legacy maps (same surface as `load_source_roots`), programs
/// load through the shared kprobe loader with per-writer gate
/// attestation, and links are created later per typed export. Needs caps.
/// Maps are borrowed and stay with their owners; programs are returned.
/// Borrowed-FD table for the typed roots: every owned name in the half's
/// map list resolves first (a missing owned name refuses), then any
/// fixup-referenced name absent from that list completes from the same
/// owner-then-legacy order, mirroring `load_source_roots`. The shared gate
/// and the legacy join maps arrive only through that completion. Pure FD
/// duplication; no BPF calls, so unit tests drive it with `/dev/null` FDs.
fn collect_typed_fixup_maps(
    prepared: &Prepared,
    source_maps: &std::collections::BTreeMap<&'static str, OwnedFd>,
    legacy: &Loaded,
) -> anyhow::Result<HashMap<String, OwnedFd>> {
    use anyhow::Context as _;
    use std::os::fd::AsFd as _;
    let mut maps: HashMap<String, OwnedFd> = HashMap::with_capacity(prepared.maps.len());
    for m in &prepared.maps {
        let fd = source_maps
            .get(m.name.as_str())
            .map(|owned| owned.as_fd())
            .or_else(|| legacy.maps.get(&m.name).map(|owned| owned.as_fd()));
        match fd {
            Some(borrowed) => {
                let dup = borrowed
                    .try_clone_to_owned()
                    .with_context(|| format!("typed borrow dup {}", m.name))?;
                maps.insert(m.name.clone(), dup);
            }
            None => {
                anyhow::bail!("typed fixup map unresolved {}", m.name);
            }
        }
    }
    for p in &prepared.progs {
        for fixup in &p.map_fixups {
            if maps.contains_key(&fixup.map) {
                continue;
            }
            let borrowed = source_maps
                .get(fixup.map.as_str())
                .map(|owned| owned.as_fd())
                .or_else(|| legacy.maps.get(&fixup.map).map(|owned| owned.as_fd()))
                .ok_or_else(|| anyhow::anyhow!("typed fixup unresolved {}", fixup.map))?;
            let dup = borrowed
                .try_clone_to_owned()
                .with_context(|| format!("typed borrow dup {}", fixup.map))?;
            maps.insert(fixup.map.clone(), dup);
        }
    }
    Ok(maps)
}
/// Load the typed roots against borrowed maps without attaching:
/// fixups resolve against the owner's source/producer/control maps
/// plus the session's legacy maps (same surface as
/// `load_source_roots`), programs load through the shared kprobe
/// loader with per-writer gate attestation, and links are created
/// later per typed export. Needs caps. Maps are borrowed and stay
/// with their owners; programs are returned. Typed roots take no
/// callback BTF path (prepare refuses first; this seam re-checks).
pub(crate) fn load_typed_borrowed(
    prepared: &Prepared,
    source_maps: &std::collections::BTreeMap<&'static str, OwnedFd>,
    legacy: &Loaded,
    gate: &crate::writer_gate::WriterGate,
) -> anyhow::Result<std::collections::HashMap<String, OwnedFd>> {
    load_typed_borrowed_inner(prepared, source_maps, legacy, gate, None, None)
}

/// Diagnostic-evidence surface: exercised by host unit tests and the
/// ignored load-only diagnostic, not by production paths.
#[allow(dead_code)]
/// Observed typed load for the diagnostic: runs the shared
/// implementation and pushes one per-root record per attempted root
/// into `records`. Never attaches.
pub(crate) fn load_typed_borrowed_observed(
    prepared: &Prepared,
    source_maps: &std::collections::BTreeMap<&'static str, OwnedFd>,
    legacy: &Loaded,
    gate: &crate::writer_gate::WriterGate,
    artifact: ArtifactPins,
    records: &mut Vec<LoadDiagnostics>,
) -> anyhow::Result<std::collections::HashMap<String, OwnedFd>> {
    load_typed_borrowed_inner(
        prepared,
        source_maps,
        legacy,
        gate,
        Some(DiagCtx { records, artifact }),
        None,
    )
}

fn load_typed_borrowed_inner(
    prepared: &Prepared,
    source_maps: &std::collections::BTreeMap<&'static str, OwnedFd>,
    legacy: &Loaded,
    gate: &crate::writer_gate::WriterGate,
    diag: Option<DiagCtx<'_>>,
    ops: Option<&dyn LoadBoundaryOps>,
) -> anyhow::Result<std::collections::HashMap<String, OwnedFd>> {
    use anyhow::Context as _;
    let mut diag = diag;
    anyhow::ensure!(
        prepared.progs.len() == 2
            && prepared.progs.iter().any(|p| p.name == "typed_entry")
            && prepared.progs.iter().any(|p| p.name == "typed_return"),
        "typed half must hold exactly the entry/return pair"
    );
    // Borrowed FDs duplicated for fixup patching only; the kernel holds
    // program-to-map references after load, and every map stays owned by
    // its session-side owner. Nothing here outlives this call except the
    // returned unattached programs.
    let maps = match collect_typed_fixup_maps(prepared, source_maps, legacy) {
        Ok(maps) => maps,
        Err(error) => {
            if let Some(ctx) = diag.as_mut() {
                for p in &prepared.progs {
                    let mut record =
                        LoadDiagnostics::unattempted(&p.name, &p.section, ctx.artifact);
                    record.stage = LoadStage::MapSetup;
                    record.error = Some(format!("{error:#}"));
                    ctx.records.push(record);
                }
            }
            return Err(error);
        }
    };
    let mut programs = std::collections::HashMap::with_capacity(2);
    for p in &prepared.progs {
        let mut record = diag.as_ref().map(|ctx| {
            let mut record = LoadDiagnostics::unattempted(&p.name, &p.section, ctx.artifact);
            record.stage = LoadStage::MapSetup;
            record
        });
        let outcome = (|| -> anyhow::Result<OwnedFd> {
            anyhow::ensure!(
                !p.subprogs.iter().any(|s| s.is_callback),
                "typed root forbids callback BTF"
            );
            for fixup in &p.map_fixups {
                anyhow::ensure!(
                    SOURCE_FIXUP_MAPS.contains(&fixup.map.as_str()),
                    "typed fixup to unreviewed map {}",
                    fixup.map
                );
            }
            anyhow::ensure!(
                p.map_fixups.iter().any(|f| f.map == "ADMIT"),
                "typed root lacks shared-gate fixup"
            );
            let fd = load_prog_inner(p, &maps, true, None, record.as_mut(), ops)
                .with_context(|| format!("typed prog_load {}", p.name))?;
            if let Some(record) = record.as_mut() {
                record.stage = LoadStage::Attestation;
            }
            run_attest(ops, gate, &fd)
                .with_context(|| format!("typed program {} missing shared gate", p.name))?;
            if let Some(record) = record.as_mut() {
                observe_loaded_program(&fd, record, ops);
                record.stage = LoadStage::Loaded;
            }
            // Deliberately unattached: typed links are created per admitted
            // export with per-site cookies, never bulk at load.
            Ok(fd)
        })();
        if let Some(ctx) = diag.as_mut() {
            if let Some(mut record) = record {
                if let Err(error) = outcome.as_ref() {
                    record.error = Some(format!("{error:#}"));
                }
                ctx.records.push(record);
            }
        }
        programs.insert(p.name.clone(), outcome?);
    }
    Ok(programs)
}

/// Gated load with borrowed shared maps: `ADMIT` injects from the gate,
/// maps present in `borrowed` resolve to dup'd FDs of the same kernel
/// maps (one relationship pool across both programs), every other map is
/// created fresh. Programs attest per writer. Needs caps.
pub(crate) fn load_gated_borrowed(
    prep: &Prepared,
    gate: &crate::writer_gate::WriterGate,
    borrowed: &std::collections::BTreeMap<String, std::os::fd::BorrowedFd<'_>>,
) -> anyhow::Result<GatedLoaded> {
    load_gated_borrowed_inner(prep, gate, borrowed, None, None)
}

/// Diagnostic-evidence surface: exercised by host unit tests and the
/// ignored load-only diagnostic, not by production paths.
#[allow(dead_code)]
/// Observed borrowed load for the diagnostic (the count root):
/// pushes one per-root record per attempted root. Never attaches;
/// the lifecycle vector stays empty exactly as in production.
pub(crate) fn load_gated_borrowed_observed(
    prep: &Prepared,
    gate: &crate::writer_gate::WriterGate,
    borrowed: &std::collections::BTreeMap<String, std::os::fd::BorrowedFd<'_>>,
    artifact: ArtifactPins,
    records: &mut Vec<LoadDiagnostics>,
) -> anyhow::Result<GatedLoaded> {
    load_gated_borrowed_inner(
        prep,
        gate,
        borrowed,
        Some(DiagCtx { records, artifact }),
        None,
    )
}

fn load_gated_borrowed_inner(
    prep: &Prepared,
    gate: &crate::writer_gate::WriterGate,
    borrowed: &std::collections::BTreeMap<String, std::os::fd::BorrowedFd<'_>>,
    diag: Option<DiagCtx<'_>>,
    ops: Option<&dyn LoadBoundaryOps>,
) -> anyhow::Result<GatedLoaded> {
    use anyhow::Context as _;
    let mut diag = diag;
    anyhow::ensure!(
        prep.maps.iter().filter(|m| m.name == "ADMIT").count() == 1,
        "missing shared writer map"
    );
    for name in BORROWED_COUNT_MAPS {
        if prep.maps.iter().any(|m| m.name == name) {
            anyhow::ensure!(
                borrowed.contains_key(name),
                "shared count load missing borrowed map {name}"
            );
        }
    }
    let mut maps: HashMap<String, OwnedFd> = HashMap::with_capacity(prep.maps.len());
    let maps_outcome = (|| -> anyhow::Result<()> {
        for m in &prep.maps {
            let fd = if m.name == "ADMIT" {
                run_inject_admit(ops, gate, m)?
            } else if let Some(shared) = borrowed.get(m.name.as_str()) {
                shared
                    .try_clone_to_owned()
                    .with_context(|| format!("borrow dup {}", m.name))?
            } else {
                create_native_map(m).with_context(|| format!("map_create {}", m.name))?
            };
            maps.insert(m.name.clone(), fd);
        }
        Ok(())
    })();
    if let Err(error) = maps_outcome.as_ref() {
        if let Some(ctx) = diag.as_mut() {
            for p in &prep.progs {
                let mut record = LoadDiagnostics::unattempted(&p.name, &p.section, ctx.artifact);
                record.stage = LoadStage::MapSetup;
                record.error = Some(format!("{error:#}"));
                ctx.records.push(record);
            }
        }
    }
    maps_outcome?;
    let mut progs: HashMap<String, OwnedFd> = HashMap::with_capacity(prep.progs.len());
    for p in &prep.progs {
        let mut record = diag.as_ref().map(|ctx| {
            let mut record = LoadDiagnostics::unattempted(&p.name, &p.section, ctx.artifact);
            record.stage = LoadStage::MapSetup;
            record
        });
        let outcome = (|| -> anyhow::Result<OwnedFd> {
            let fd = load_prog_inner(p, &maps, true, None, record.as_mut(), ops)?;
            if let Some(record) = record.as_mut() {
                record.stage = LoadStage::Attestation;
            }
            run_attest(ops, gate, &fd)?;
            if let Some(record) = record.as_mut() {
                observe_loaded_program(&fd, record, ops);
                record.stage = LoadStage::Loaded;
            }
            Ok(fd)
        })();
        if let Some(ctx) = diag.as_mut() {
            if let Some(mut record) = record {
                if let Err(error) = outcome.as_ref() {
                    record.error = Some(format!("{error:#}"));
                }
                ctx.records.push(record);
            }
        }
        progs.insert(p.name.clone(), outcome?);
    }
    Ok(GatedLoaded {
        lifecycle: Vec::new(),
        loaded: Loaded { maps, progs },
    })
}
pub(crate) fn load_controlled(
    prep: &Prepared,
    links: &crate::capture_setup::SetupLinks,
    stage: crate::capture::BoundaryStage,
) -> anyhow::Result<Loaded> {
    load_with_custody(prep, Some((links, stage)), None)
}

fn load_with_custody(
    prep: &Prepared,
    setup: Option<(
        &crate::capture_setup::SetupLinks,
        crate::capture::BoundaryStage,
    )>,
    gate: Option<&crate::writer_gate::WriterGate>,
) -> anyhow::Result<Loaded> {
    load_with_custody_inner(prep, setup, gate, None, None)
}
#[cfg(test)]
thread_local! {static HOST_NATIVE_MAP:std::cell::RefCell<Option<OwnedFd>>=const {std::cell::RefCell::new(None)};}
fn create_native_map(m: &MapSpecLite) -> std::io::Result<OwnedFd> {
    #[cfg(test)]
    if let Some(fd) = HOST_NATIVE_MAP.with(|v| v.borrow_mut().take()) {
        return Ok(fd);
    }
    ossl_bpf_sys::map_create(
        m.map_type,
        m.key_size,
        m.value_size,
        m.max_entries,
        None,
        &m.name,
    )
}
#[cfg(test)]
pub(crate) fn host_acquisition_history(blocked: bool) {
    use std::os::fd::AsRawFd;
    let sentinel = std::fs::File::open("/dev/null").unwrap();
    let raw = sentinel.as_raw_fd();
    HOST_NATIVE_MAP.with(|v| *v.borrow_mut() = Some(sentinel.into()));
    let prep = Prepared {
        progs: Vec::new(),
        maps: vec![MapSpecLite {
            name: "host-sentinel".into(),
            map_type: 0,
            key_size: 0,
            value_size: 0,
            max_entries: 0,
            flags: 0,
        }],
    };
    let result = load(&prep);
    if blocked {
        assert!(result.is_err());
        assert!(
            HOST_NATIVE_MAP.with(|v| v.borrow().is_some()),
            "Starting must refuse before the actual create seam consumes an owned descriptor"
        );
        drop(HOST_NATIVE_MAP.with(|v| v.borrow_mut().take()));
        return;
    }
    let loaded = result.unwrap();
    assert_eq!(loaded.maps["host-sentinel"].as_raw_fd(), raw);
    drop(loaded);
    assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFD) }, -1);
}
fn load_with_custody_inner(
    prep: &Prepared,
    setup: Option<(
        &crate::capture_setup::SetupLinks,
        crate::capture::BoundaryStage,
    )>,
    gate: Option<&crate::writer_gate::WriterGate>,
    diag: Option<DiagCtx<'_>>,
    ops: Option<&dyn LoadBoundaryOps>,
) -> anyhow::Result<Loaded> {
    let mut diag = diag;
    anyhow::ensure!(
        gate.is_some() || !prep.maps.iter().any(|m| m.name == "ADMIT"),
        "shared writer map requires typed injection"
    );
    for p in &prep.progs {
        if lifecycle_root(p)?.is_some() {
            anyhow::ensure!(gate.is_some(), "lifecycle root requires shared gate");
            anyhow::ensure!(
                gate.is_some_and(|g| g.preparing()),
                "lifecycle root requires unopened gate"
            );
        }
    }
    crate::lifecycle_producer::note_acquisition()?;
    use anyhow::Context as _;
    let loaded = Loaded {
        maps: HashMap::with_capacity(prep.maps.len()),
        progs: HashMap::with_capacity(prep.progs.len()),
    };
    let mut loaded = match setup {
        Some((links, stage)) => crate::capture_setup::SetupResource::guarded(loaded, links, stage),
        None => crate::capture_setup::SetupResource::local(loaded),
    };
    // The transaction remains outside the fallible/unwinding operation scope.
    // Every returned FD enters it before another effect can begin.
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> anyhow::Result<()> {
            let maps_outcome = (|| -> anyhow::Result<()> {
                for m in &prep.maps {
                    if let Some((links, stage)) = setup {
                        links.check_owned(stage)?;
                    }
                    let fd = if m.name == "ADMIT" {
                        run_inject_admit(ops, gate.context("shared gate missing")?, m)?
                    } else {
                        create_native_map(m).with_context(|| format!("map_create {}", m.name))?
                    };
                    loaded.maps.insert(m.name.clone(), fd);
                }
                Ok(())
            })();
            // A map-setup failure belongs to every root of this half:
            // record the blocking stage explicitly instead of leaving
            // the half silently unpushed.
            if let Err(error) = maps_outcome.as_ref() {
                if let Some(ctx) = diag.as_mut() {
                    for p in &prep.progs {
                        let mut record =
                            LoadDiagnostics::unattempted(&p.name, &p.section, ctx.artifact);
                        record.stage = LoadStage::MapSetup;
                        record.error = Some(format!("{error:#}"));
                        ctx.records.push(record);
                    }
                }
            }
            maps_outcome?;
            for p in &prep.progs {
                if let Some((links, stage)) = setup {
                    links.check_owned(stage)?;
                }
                let mut record = diag.as_ref().map(|ctx| {
                    let mut record =
                        LoadDiagnostics::unattempted(&p.name, &p.section, ctx.artifact);
                    record.stage = LoadStage::MapSetup;
                    record
                });
                let outcome = (|| -> anyhow::Result<OwnedFd> {
                    let fd = load_prog_inner(p, &loaded.maps, true, setup, record.as_mut(), ops)?;
                    if let Some(gate) = gate {
                        if let Some(record) = record.as_mut() {
                            record.stage = LoadStage::Attestation;
                        }
                        run_attest(ops, gate, &fd)?;
                    }
                    if let Some(record) = record.as_mut() {
                        observe_loaded_program(&fd, record, ops);
                        record.stage = LoadStage::Loaded;
                    }
                    Ok(fd)
                })();
                if let Some(ctx) = diag.as_mut() {
                    if let Some(mut record) = record {
                        if let Err(error) = outcome.as_ref() {
                            record.error = Some(format!("{error:#}"));
                        }
                        ctx.records.push(record);
                    }
                }
                loaded.progs.insert(p.name.clone(), outcome?);
            }
            Ok(())
        }));
    match result {
        Ok(Ok(())) => Ok(loaded.into_inner()),
        Ok(Err(error)) => match setup {
            Some((links, stage)) => links.retain_result(Err(error), stage),
            None => Err(error),
        },
        Err(panic) => {
            if let Some((links, stage)) = setup {
                links.seal(crate::capture_setup::SetupFailure::Boundary(
                    crate::capture::BoundaryFailure::new(
                        stage,
                        crate::capture::BoundaryFailureClass::Panic,
                        None,
                        "native load transaction unwound",
                    ),
                ));
                links.before_dispose(stage);
            }
            std::panic::resume_unwind(panic)
        }
    }
}

/// One rejected program under keep-good loading (the slot is
/// reported, never silently dropped — the oracle marks it
/// unobserved PARTIAL).
#[derive(Debug, Clone)]
pub struct FailedProg {
    pub prog: String,
    pub error: String,
}

/// Keep-good load: maps are all-or-nothing (shared by every
/// member — a map failure fails the load), but each program loads
/// independently — one rejection is recorded and the rest proceed.
/// Verifier-log spills are capped at 8 (a pathological
/// all-rejected object must not fill the temp dir; every failure
/// still carries its 2000-char summary in `error`).
pub fn load_keep_good(prep: &Prepared) -> anyhow::Result<(Loaded, Vec<FailedProg>)> {
    anyhow::ensure!(
        !prep
            .maps
            .iter()
            .any(|m| m.name == "ADMIT" || m.map_type == 12),
        "shared writer gate requires typed all-root loading"
    );
    crate::lifecycle_producer::note_acquisition()?;
    use anyhow::Context as _;
    for p in &prep.progs {
        anyhow::ensure!(
            lifecycle_root(p)?.is_none(),
            "lifecycle root requires shared gate"
        );
    }
    let mut maps = HashMap::new();
    for m in &prep.maps {
        let fd = ossl_bpf_sys::map_create(
            m.map_type,
            m.key_size,
            m.value_size,
            m.max_entries,
            None,
            &m.name,
        )
        .with_context(|| format!("map_create {}", m.name))?;
        maps.insert(m.name.clone(), fd);
    }
    let mut progs = HashMap::new();
    let mut failed = Vec::new();
    for p in &prep.progs {
        match load_prog(p, &maps, failed.len() < 8, None) {
            Ok(fd) => {
                progs.insert(p.name.clone(), fd);
            }
            Err(e) => failed.push(FailedProg {
                prog: p.name.clone(),
                error: format!("{e:#}"),
            }),
        }
    }
    Ok((Loaded { progs, maps }, failed))
}

/// Member-chunk fd budget: 513 prog fds + 15 map fds + 513 link fds
/// (all held — drop = detach) + clones + stdio ≈ 1048 > the 1024
/// default (EMFILE observed at member_499). NEED is the fail-closed
/// floor; WANT is the unprivileged raise target under the hard cap.
pub const MEMBERS_FD_NEED: u64 = 4096;
pub const MEMBERS_FD_WANT: u64 = 8192;

/// Pure gate: is this soft RLIMIT_NOFILE enough for the chunk?
/// (Unit-tested; the effectful raise below is live-proven — every
/// member leg attaches through it, EMFILE would RED.)
pub const fn members_fd_budget_ok(soft: u64) -> bool {
    soft >= MEMBERS_FD_NEED
}

/// Raise/check own RLIMIT_NOFILE for the chunk budget (fail-closed:
/// errors when the hard cap itself is too small — no silent
/// half-attach). Unprivileged soft raise; idempotent.
pub fn ensure_members_fd_budget() -> anyhow::Result<()> {
    // SAFETY: getrlimit/setrlimit on valid pointers; rlim_t widths
    // are libc's. No threads are spawned here — the limit is
    // process-wide by design (the attach needs it process-wide).
    unsafe {
        let mut r = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut r as *mut _) != 0 {
            anyhow::bail!("getrlimit NOFILE failed");
        }
        if r.rlim_cur < MEMBERS_FD_WANT {
            r.rlim_cur = std::cmp::min(MEMBERS_FD_WANT, r.rlim_max);
            if libc::setrlimit(libc::RLIMIT_NOFILE, &r as *const _) != 0 {
                anyhow::bail!("setrlimit NOFILE failed");
            }
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut r as *mut _) != 0 {
                anyhow::bail!("getrlimit NOFILE re-read failed");
            }
        }
        if !members_fd_budget_ok(r.rlim_cur) {
            anyhow::bail!(
                "NOFILE {} below the {}-fd chunk budget (hard cap too small)",
                r.rlim_cur,
                MEMBERS_FD_NEED
            );
        }
    }
    Ok(())
}

/// Member-object EVENTS ring size in bytes (pinned here and in
/// `MEMBER_MAPS`; item 7 grew it to 16MiB — the 4MiB governor
/// policy value is now live, not the small-ring fixture half).
pub const MEMBER_RING_BYTES: u64 = 1 << 24;

/// Production session-control value (R18 §5): EXPECTED = attached
/// member count (1..=512 — item 6 programs fewer legitimately),
/// epoch 1, SKIP_ALL clear, governor = min(4MiB policy, ring/2)
/// per [`osslscope_ebpf_common::governor_for_ring`]. Rejects
/// out-of-range EXPECTED before any attach (the entry would skip
/// cause 7 on it — loud either way, but fail-fast is better).
pub fn default_ctrl(
    expected: u32,
    ring_bytes: u64,
) -> anyhow::Result<osslscope_ebpf_common::CtrlValue> {
    if !(1..=512).contains(&expected) {
        anyhow::bail!("EXPECTED {expected} outside 1..=512");
    }
    Ok(osslscope_ebpf_common::ctrl_value(
        expected,
        1,
        osslscope_ebpf_common::governor_for_ring(ring_bytes),
    ))
}

/// Program the scan-plane session control cell (`CTRL[0]`).
/// Live-proven (L1 reads it back — a failed write REDs there).
pub fn program_ctrl(
    maps: &HashMap<String, OwnedFd>,
    ctrl: &osslscope_ebpf_common::CtrlValue,
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use aya::maps::{Array, Map, MapData};
    let fd = maps
        .get("CTRL")
        .context("CTRL map missing")?
        .try_clone()
        .context("clone CTRL")?;
    let data = MapData::from_fd(fd).context("CTRL mapdata")?;
    let map = Map::from_map_data(data).context("CTRL map")?;
    let mut arr =
        Array::<_, osslscope_ebpf_common::CtrlValue>::try_from(map).context("CTRL array shape")?;
    arr.set(0, *ctrl, 0).context("write CTRL[0]")?;
    Ok(())
}

/// Read back the session control cell (legs + future daemon).
pub fn read_ctrl(
    maps: &HashMap<String, OwnedFd>,
) -> anyhow::Result<osslscope_ebpf_common::CtrlValue> {
    use anyhow::Context as _;
    use aya::maps::{Array, Map, MapData};
    let fd = maps
        .get("CTRL")
        .context("CTRL map missing")?
        .try_clone()
        .context("clone CTRL")?;
    let data = MapData::from_fd(fd).context("CTRL mapdata")?;
    let map = Map::from_map_data(data).context("CTRL map")?;
    let arr =
        Array::<_, osslscope_ebpf_common::CtrlValue>::try_from(map).context("CTRL array shape")?;
    arr.get(&0, 0).context("read CTRL[0]")
}

/// A fully attached member chunk: loaded progs/maps + live links.
/// Fields drop in declaration order (no manual `Drop` impl):
/// maps/progs (`Loaded` drop) first, then entry, then members —
/// the same order as construction.
pub struct MembersAttached {
    pub loaded: Loaded,
    pub entry: OwnedFd,
    pub members: Vec<OwnedFd>,
}

/// Normalize + validate a selective slot set (sorted, deduped;
/// rejects empty sets and slots ≥ 512 — a scan with no members
/// retires nothing, so attach nothing instead).
pub fn normalize_slots(slots: &[u32]) -> anyhow::Result<Vec<u32>> {
    let mut want: Vec<u32> = slots.to_vec();
    want.sort_unstable();
    want.dedup();
    if want.is_empty() {
        anyhow::bail!("selective attach with no members");
    }
    if want.iter().any(|&j| j >= 512) {
        anyhow::bail!("selective attach slot exceeds 511");
    }
    Ok(want)
}

/// Prog specs for a selective attach: the entry + exactly the
/// wanted members (selective prepare loads ONLY these programs —
/// never the full 513 — so unselected members cost no verify
/// time and cannot fail the attach).
pub fn member_specs_for_slots(slots: &[u32]) -> anyhow::Result<Vec<ProgSpec>> {
    let want = normalize_slots(slots)?;
    let mut specs = Vec::with_capacity(want.len() + 1);
    specs.push(MEMBER_PROGS[0]);
    for j in want {
        specs.push(MEMBER_PROGS[1 + j as usize]);
    }
    Ok(specs)
}

/// Selective member attach (item 6): entry + exactly `slots`
/// (cookie = slot), EXPECTED programmed from `ctrl` (which MUST
/// equal `slots.len()` — the retire equation counts attached
/// members; mismatch fails fast here, never silently in BPF).
/// Unattached slots are OUT OF SCOPE (the oracle reports them as
/// unobserved, never as holes — holes are missing evidence
/// WITHIN the attached set). The entry is always attached (the
/// CALLS census and the oracle's join root never drop). Order of
/// `slots` is normalized (sorted, deduped); empty sets are
/// rejected (a scan with no members retires nothing — attach
/// nothing instead).
/// One slot that did not attach under a selective attach
/// (load rejection or link failure — reported, never silent).
#[derive(Debug, Clone)]
pub struct FailedSlot {
    pub slot: u32,
    pub stage: &'static str,
    pub error: String,
}

/// Selective-attach outcome: what attached (with EXPECTED
/// programmed to the attached count) plus every failed slot.
pub struct SubsetAttached {
    pub attached: MembersAttached,
    /// Actually-attached slots, sorted (the oracle scope — failed
    /// slots are unobserved PARTIAL there, never holes).
    pub slots: Vec<u32>,
    pub failed: Vec<FailedSlot>,
}

// Only the native link and CTRL operations vary in host policy tests.
// Selection, failure handling, ownership, and the classifier gate below
// are the same routines used by the public constructors.
trait MemberAttachOps {
    fn entry(&mut self, prog: BorrowedFd<'_>) -> anyhow::Result<OwnedFd>;
    fn member(&mut self, prog: BorrowedFd<'_>, slot: u32) -> anyhow::Result<OwnedFd>;
    fn ctrl(
        &mut self,
        maps: &HashMap<String, OwnedFd>,
        value: &osslscope_ebpf_common::CtrlValue,
    ) -> anyhow::Result<()>;
}

struct NativeMemberAttachOps<'a> {
    setup: Option<crate::capture_setup::SetupLinks>,
    exe: &'a std::ffi::CStr,
    off: u64,
    pid: u32,
}

impl MemberAttachOps for NativeMemberAttachOps<'_> {
    fn entry(&mut self, prog: BorrowedFd<'_>) -> anyhow::Result<OwnedFd> {
        Ok(ossl_bpf_sys::link_create_uprobe_multi(
            prog.as_raw_fd(),
            self.exe,
            &[self.off],
            &[osslscope_ebpf_common::MEMBER_ENTRY_COOKIE],
            self.pid,
        )?)
    }

    fn member(&mut self, prog: BorrowedFd<'_>, slot: u32) -> anyhow::Result<OwnedFd> {
        Ok(ossl_bpf_sys::link_create_uretprobe_multi(
            prog.as_raw_fd(),
            self.exe,
            &[self.off],
            &[slot as u64],
            self.pid,
        )?)
    }

    fn ctrl(
        &mut self,
        maps: &HashMap<String, OwnedFd>,
        value: &osslscope_ebpf_common::CtrlValue,
    ) -> anyhow::Result<()> {
        if let Some(setup) = &self.setup {
            borrowed_ctrl(maps, Some(value), setup).map(|_| ())
        } else {
            program_ctrl(maps, value)
        }
    }
}

pub fn attach_members_subset(
    obj: &std::path::Path,
    exe: &std::ffi::CStr,
    off: u64,
    pid: u32,
    ctrl: &osslscope_ebpf_common::CtrlValue,
    slots: &[u32],
) -> anyhow::Result<SubsetAttached> {
    use anyhow::Context as _;
    let bytes = std::fs::read(obj).with_context(|| format!("read {}", obj.display()))?;
    attach_members_subset_from_bytes(&bytes, exe, off, pid, ctrl, slots)
}

/// Selective attach over verified bytes (no path re-read — the
/// caller hashes these same bytes for provenance, so identity and
/// loading cannot drift).
pub fn attach_members_subset_from_bytes(
    bytes: &[u8],
    exe: &std::ffi::CStr,
    off: u64,
    pid: u32,
    ctrl: &osslscope_ebpf_common::CtrlValue,
    slots: &[u32],
) -> anyhow::Result<SubsetAttached> {
    use anyhow::Context as _;
    if bytes.len() as u64 > crate::discovery::onboard::MAX_OBJECT_SCAN_BYTES {
        anyhow::bail!(
            "members snapshot {} bytes exceeds the onboarding cap",
            bytes.len()
        );
    }
    let want = normalize_slots(slots)?;
    if ctrl.expected as usize != want.len() {
        anyhow::bail!(
            "CTRL EXPECTED {} != {} wanted members",
            ctrl.expected,
            want.len()
        );
    }
    ensure_members_fd_budget()?;
    // Selective prepare: ONLY the entry + wanted members (never
    // the full 513 — unselected members cost no verify time and
    // cannot fail the attach).
    let specs = member_specs_for_slots(&want)?;
    let prep = prepare(bytes, &MEMBER_MAPS, &specs).context("prepare members.o subset")?;
    // Keep-good load: one rejection is recorded, the rest proceed.
    let (loaded, load_failed) = load_keep_good(&prep).context("load members.o subset")?;
    let mut ops = NativeMemberAttachOps {
        exe,
        off,
        pid,
        setup: None,
    };
    attach_subset_loaded(
        loaded,
        load_failed,
        want,
        ctrl,
        |handles| {
            crate::discovery::classifier_maps::initialize_classifier_maps(
                handles,
                crate::discovery::classifier_maps::ClassifierRole::Members,
            )
        },
        &mut ops,
    )
}

fn attach_subset_loaded<I: FnOnce(&HashMap<String, OwnedFd>) -> anyhow::Result<()>>(
    loaded: Loaded,
    load_failed: Vec<FailedProg>,
    want: Vec<u32>,
    ctrl: &osslscope_ebpf_common::CtrlValue,
    initialize: I,
    ops: &mut impl MemberAttachOps,
) -> anyhow::Result<SubsetAttached> {
    use anyhow::Context as _;
    if !loaded.progs.contains_key("member_entry") {
        anyhow::bail!("selective attach: member_entry rejected, no census possible");
    }
    let classifier_handles = crate::discovery::classifier_maps::clone_classifier_handles(
        &loaded.maps,
        crate::discovery::classifier_maps::ClassifierRole::Members,
    )?;
    crate::discovery::classifier_maps::after_classifier_init(
        move || initialize(&classifier_handles),
        || {
            let entry = ops
                .entry(loaded.progs["member_entry"].as_fd())
                .context("attach member_entry")?;
            // Keep-good attach: one link failure is recorded, the rest
            // proceed. EXPECTED programs to the ATTACHED count (the
            // retire equation counts attached members, not wanted ones).
            let mut members = Vec::new();
            let mut attached_slots = Vec::new();
            let mut failed: Vec<FailedSlot> = load_failed
                .into_iter()
                .filter_map(|f| {
                    f.prog
                        .strip_prefix("member_")
                        .and_then(|s| s.parse::<u32>().ok())
                        .map(|slot| FailedSlot {
                            slot,
                            stage: "load",
                            error: f.error,
                        })
                })
                .collect();
            for j in want {
                let name = format!("member_{j:03}");
                let Some(prog) = loaded.progs.get(&name) else {
                    continue; // load rejection already recorded above
                };
                match ops.member(prog.as_fd(), j) {
                    Ok(link) => {
                        members.push(link);
                        attached_slots.push(j);
                    }
                    Err(e) => failed.push(FailedSlot {
                        slot: j,
                        stage: "attach",
                        error: format!("{e:#}"),
                    }),
                }
            }
            if attached_slots.is_empty() {
                anyhow::bail!("selective attach: every wanted member failed");
            }
            let mut actual_ctrl = *ctrl;
            actual_ctrl.expected = attached_slots.len() as u32;
            ops.ctrl(&loaded.maps, &actual_ctrl)
                .context("program CTRL")?;
            failed.sort_by_key(|f| f.slot);
            Ok(SubsetAttached {
                attached: MembersAttached {
                    loaded,
                    entry,
                    members,
                },
                slots: attached_slots,
                failed,
            })
        },
    )
}

/// Production attach of the member chunk: fd budget → prepare →
/// load → program CTRL → initialize/freeze ALG_CLASS → attach entry
/// (cookie 512) + members (cookie = slot) at `off` in `exe` for `pid`.
/// Custom-name fixture legs use a separate synthetic immutable image.
pub fn attach_members(
    obj: &std::path::Path,
    exe: &std::ffi::CStr,
    off: u64,
    pid: u32,
    ctrl: &osslscope_ebpf_common::CtrlValue,
) -> anyhow::Result<MembersAttached> {
    use anyhow::Context as _;
    let bytes = std::fs::read(obj).with_context(|| format!("read {}", obj.display()))?;
    attach_members_from_bytes(&bytes, exe, off, pid, ctrl)
}

/// Full attach over verified bytes (no path re-read — the caller
/// hashes these same bytes for provenance, so identity and loading
/// cannot drift). All-or-nothing (a full-table scan with holes
/// from load failure refuses instead of half-observing).
pub fn attach_members_from_bytes(
    bytes: &[u8],
    exe: &std::ffi::CStr,
    off: u64,
    pid: u32,
    ctrl: &osslscope_ebpf_common::CtrlValue,
) -> anyhow::Result<MembersAttached> {
    let mut links = crate::capture_setup::MemberLinkStore::local();
    let loaded = prepare_members_from_bytes(bytes, exe, off, pid, ctrl, &mut links)?;
    let links = links.take_local();
    Ok(MembersAttached {
        loaded,
        entry: links.entry.expect("full entry attached"),
        members: links.members,
    })
}

#[derive(Clone, Copy)]
pub(crate) struct FullMemberInput<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) exe: &'a std::ffi::CStr,
    pub(crate) off: u64,
    pub(crate) pid: u32,
    pub(crate) ctrl: &'a osslscope_ebpf_common::CtrlValue,
}
pub(crate) fn prepare_full_members(
    input: FullMemberInput<'_>,
    links: &mut crate::capture_setup::MemberLinkStore,
) -> anyhow::Result<Loaded> {
    prepare_members_from_bytes(
        input.bytes,
        input.exe,
        input.off,
        input.pid,
        input.ctrl,
        links,
    )
}
fn prepare_members_from_bytes(
    bytes: &[u8],
    exe: &std::ffi::CStr,
    off: u64,
    pid: u32,
    ctrl: &osslscope_ebpf_common::CtrlValue,
    links: &mut crate::capture_setup::MemberLinkStore,
) -> anyhow::Result<Loaded> {
    use anyhow::Context as _;
    if bytes.len() as u64 > crate::discovery::onboard::MAX_OBJECT_SCAN_BYTES {
        anyhow::bail!(
            "members snapshot {} bytes exceeds the onboarding cap",
            bytes.len()
        );
    }
    links.check()?;
    if links.setup_links().is_some() {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if !members_fd_budget_ok(limit.rlim_cur) {
            anyhow::bail!("NOFILE below the full-member budget");
        }
    } else {
        ensure_members_fd_budget()?;
    }
    links.check()?;
    let prep = prepare(bytes, &MEMBER_MAPS, &MEMBER_PROGS).context("prepare members.o")?;
    links.check()?;
    let loaded = match links.setup_links() {
        Some(setup) => load_controlled(&prep, setup, crate::capture::BoundaryStage::Traversal),
        None => load(&prep),
    }
    .context("load members.o")?;
    let setup = links.setup_links().cloned();
    let mut ops = NativeMemberAttachOps {
        exe,
        off,
        pid,
        setup: setup.clone(),
    };
    attach_full_loaded(
        loaded,
        ctrl,
        |handles| match &setup {
            Some(setup) => {
                crate::discovery::classifier_maps::initialize_classifier_maps_controlled(
                    handles,
                    crate::discovery::classifier_maps::ClassifierRole::Members,
                    setup,
                )
            }
            None => crate::discovery::classifier_maps::initialize_classifier_maps(
                handles,
                crate::discovery::classifier_maps::ClassifierRole::Members,
            ),
        },
        &mut ops,
        links,
    )
}

#[cfg(test)]
fn attach_full_local<I: FnOnce(&HashMap<String, OwnedFd>) -> anyhow::Result<()>>(
    loaded: Loaded,
    ctrl: &osslscope_ebpf_common::CtrlValue,
    initialize: I,
    ops: &mut impl MemberAttachOps,
) -> anyhow::Result<MembersAttached> {
    let mut links = crate::capture_setup::MemberLinkStore::local();
    let loaded = attach_full_loaded(loaded, ctrl, initialize, ops, &mut links)?;
    let links = links.take_local();
    Ok(MembersAttached {
        loaded,
        entry: links.entry.expect("full entry attached"),
        members: links.members,
    })
}
struct MemberAttachGuard<'a> {
    links: &'a mut crate::capture_setup::MemberLinkStore,
    complete: bool,
    failure: Option<crate::capture_setup::SetupFailure>,
}
impl Drop for MemberAttachGuard<'_> {
    fn drop(&mut self) {
        if !self.complete {
            let failure = self.failure.take().unwrap_or_else(|| {
                crate::capture_setup::SetupFailure::Boundary(crate::capture::BoundaryFailure::new(
                    crate::capture::BoundaryStage::Traversal,
                    crate::capture::BoundaryFailureClass::Panic,
                    None,
                    "native member attach unwound",
                ))
            });
            self.links.abort(failure);
        }
    }
}
fn attach_full_loaded<I: FnOnce(&HashMap<String, OwnedFd>) -> anyhow::Result<()>>(
    loaded: Loaded,
    ctrl: &osslscope_ebpf_common::CtrlValue,
    initialize: I,
    ops: &mut impl MemberAttachOps,
    links: &mut crate::capture_setup::MemberLinkStore,
) -> anyhow::Result<Loaded> {
    let loaded = links.resource(loaded);
    let mut guard = MemberAttachGuard {
        links,
        complete: false,
        failure: None,
    };
    let result = (|| {
        let links = &mut *guard.links;
        use anyhow::Context as _;
        links.check()?;
        links.retain_result(ops.ctrl(&loaded.maps, ctrl).context("program CTRL"))?;
        let classifier_temporary = links.temporary(1)?;
        // Members has exactly one classifier handle: an unsuccessful clone
        // returns no partial set. Keep its existing exact initializer input.
        let classifier_handles = links.resource(links.retain_result(
            crate::discovery::classifier_maps::clone_classifier_handles(
                &loaded.maps,
                crate::discovery::classifier_maps::ClassifierRole::Members,
            ),
        )?);
        let classifier_setup = links.setup_links().cloned();
        links.check()?;
        crate::discovery::classifier_maps::after_classifier_init(
            || {
                let result = initialize(&classifier_handles);
                let result = match &classifier_setup {
                    Some(setup) => {
                        setup.retain_result(result, crate::capture::BoundaryStage::Traversal)
                    }
                    None => result,
                };
                drop(classifier_handles);
                drop(classifier_temporary);
                result
            },
            || {
                let mut reservation = links.reserve()?;
                let entry = links.retain_result(
                    ops.entry(loaded.progs["member_entry"].as_fd())
                        .context("attach member_entry"),
                )?;
                links.push(None, entry, &mut reservation)?;
                attach_member_slots_with_ops(&loaded, &(0..512).collect::<Vec<_>>(), links, ops)?;
                Ok(())
            },
        )?;
        Ok(())
    })();
    if let Err(error) = &result {
        guard.failure = Some(crate::capture_setup::SetupFailure::from_error_ref(
            crate::capture::BoundaryStage::Traversal,
            error,
        ));
    }
    guard.complete = result.is_ok();
    if let Err(error) = result {
        return guard.links.retain_result(Err(error));
    }
    Ok(loaded.into_inner())
}

pub(crate) fn attach_member_slots(
    loaded: &Loaded,
    exe: &std::ffi::CStr,
    off: u64,
    pid: u32,
    slots: &[u32],
    links: &mut crate::capture_setup::MemberLinkStore,
) -> anyhow::Result<()> {
    attach_member_slots_with_ops(
        loaded,
        slots,
        links,
        &mut NativeMemberAttachOps {
            exe,
            off,
            pid,
            setup: None,
        },
    )
}
fn attach_member_slots_with_ops(
    loaded: &Loaded,
    slots: &[u32],
    links: &mut crate::capture_setup::MemberLinkStore,
    ops: &mut impl MemberAttachOps,
) -> anyhow::Result<()> {
    let mut guard = MemberAttachGuard {
        links,
        complete: false,
        failure: None,
    };
    let result = (|| {
        let links = &mut *guard.links;
        use anyhow::Context as _;
        for &slot in slots {
            let name = format!("member_{slot:03}");
            let prog = loaded
                .progs
                .get(&name)
                .with_context(|| format!("prog {name} missing"))?;
            let mut reservation = links.reserve()?;
            let link = ops
                .member(prog.as_fd(), slot)
                .with_context(|| format!("attach {name}"))?;
            links.push(Some(slot), link, &mut reservation)?;
        }
        Ok(())
    })();
    if let Err(error) = &result {
        guard.failure = Some(crate::capture_setup::SetupFailure::from_error_ref(
            crate::capture::BoundaryStage::Traversal,
            error,
        ));
    }
    guard.complete = result.is_ok();
    result
}

/// Strip the kernel log buffer's NUL padding (the verifier writes a
/// C string into our 1 MiB buffer).
fn trim_nul(log: &[u8]) -> &[u8] {
    let mut end = log.len();
    while end > 0 && log[end - 1] == 0 {
        end -= 1;
    }
    &log[..end]
}

/// Best-effort spill of a FULL verifier log on `prog_load` failure
/// (F-DIAG-1): the in-error summary stays capped at 2000 chars, but
/// diagnosis needs the whole multi-hundred-KB text, so it lands in
/// a temp file whose path the error names. Returns the path written.
fn spill_verifier_log(prog: &str, log: &[u8]) -> Option<std::path::PathBuf> {
    let safe: String = prog
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let path = std::env::temp_dir().join(format!(
        "osslscope-verifier-{safe}-{}.log",
        std::process::id()
    ));
    std::fs::write(&path, log).ok()?;
    Some(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    fn model_fd() -> OwnedFd {
        let (fd, _peer) = UnixStream::pair().unwrap();
        fd.into()
    }

    fn model_loaded(slots: &[u32]) -> Loaded {
        let mut progs = HashMap::from([("member_entry".to_owned(), model_fd())]);
        for &slot in slots {
            progs.insert(format!("member_{slot:03}"), model_fd());
        }
        Loaded {
            progs,
            maps: HashMap::from([
                ("ALG_CLASS".to_owned(), model_fd()),
                ("CTRL".to_owned(), model_fd()),
            ]),
        }
    }

    fn model_identity(fd: &OwnedFd) -> std::path::PathBuf {
        std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap()
    }

    fn loaded_identities(loaded: &Loaded) -> Vec<std::path::PathBuf> {
        loaded
            .progs
            .values()
            .chain(loaded.maps.values())
            .map(model_identity)
            .collect()
    }

    fn assert_identities_closed(identities: &[std::path::PathBuf]) {
        let open: Vec<_> = std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|entry| std::fs::read_link(entry.ok()?.path()).ok())
            .collect();
        for identity in identities {
            assert!(
                !open.contains(identity),
                "owned descriptor leaked: {identity:?}"
            );
        }
    }

    #[derive(Default)]
    struct ModelMemberOps {
        entry_calls: usize,
        member_calls: Vec<u32>,
        ctrl_expected: Vec<u32>,
        fail_member: Option<u32>,
        fail_ctrl: bool,
        link_identities: Vec<std::path::PathBuf>,
    }

    impl ModelMemberOps {
        fn link(&mut self) -> OwnedFd {
            let fd = model_fd();
            self.link_identities
                .push(std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap());
            fd
        }

        fn assert_links_closed(&self) {
            assert_identities_closed(&self.link_identities);
        }
    }

    impl MemberAttachOps for ModelMemberOps {
        fn entry(&mut self, _prog: std::os::fd::BorrowedFd<'_>) -> anyhow::Result<OwnedFd> {
            self.entry_calls += 1;
            Ok(self.link())
        }

        fn member(
            &mut self,
            _prog: std::os::fd::BorrowedFd<'_>,
            slot: u32,
        ) -> anyhow::Result<OwnedFd> {
            self.member_calls.push(slot);
            if self.fail_member == Some(slot) {
                anyhow::bail!("injected member link failure");
            }
            Ok(self.link())
        }

        fn ctrl(
            &mut self,
            maps: &HashMap<String, OwnedFd>,
            value: &osslscope_ebpf_common::CtrlValue,
        ) -> anyhow::Result<()> {
            assert!(maps.contains_key("CTRL"));
            self.ctrl_expected.push(value.expected);
            if self.fail_ctrl {
                anyhow::bail!("injected CTRL failure");
            }
            Ok(())
        }
    }

    fn model_initialize(maps: &HashMap<String, OwnedFd>) -> anyhow::Result<()> {
        crate::discovery::classifier_maps::tests::host_initialize_members(maps, None)
    }

    struct HeldMemberOps {
        peers: std::sync::Arc<std::sync::Mutex<Vec<UnixStream>>>,
        ordinal: usize,
        hold: usize,
        panic_at: Option<usize>,
        entered: std::sync::mpsc::SyncSender<()>,
        resume: std::sync::mpsc::Receiver<()>,
    }
    impl HeldMemberOps {
        fn link(&mut self) -> OwnedFd {
            let (fd, peer) = UnixStream::pair().unwrap();
            peer.set_nonblocking(true).unwrap();
            self.peers.lock().unwrap().push(peer);
            assert_ne!(
                Some(self.ordinal),
                self.panic_at,
                "native member effect unwind"
            );
            if self.ordinal == self.hold {
                self.entered.send(()).unwrap();
                self.resume
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
            }
            self.ordinal += 1;
            fd.into()
        }
    }
    impl MemberAttachOps for HeldMemberOps {
        fn entry(&mut self, _: BorrowedFd<'_>) -> anyhow::Result<OwnedFd> {
            Ok(self.link())
        }
        fn member(&mut self, _: BorrowedFd<'_>, _: u32) -> anyhow::Result<OwnedFd> {
            Ok(self.link())
        }
        fn ctrl(
            &mut self,
            _: &HashMap<String, OwnedFd>,
            _: &osslscope_ebpf_common::CtrlValue,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }
    fn sentinel_closed(peer: &UnixStream) -> bool {
        use std::io::Read;
        let mut peer = peer;
        match peer.read(&mut [0]) {
            Ok(0) => true,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
            result => panic!("sentinel read {result:?}"),
        }
    }
    #[test]
    #[ignore = "requires rebuilt OSSL_PROVIDER_OBSERVATION_TEST_BPF; preparation only"]
    fn source_iterator_real_object_patches_only_exact_owned_sites() {
        let object =
            std::fs::read(std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF").unwrap()).unwrap();
        let prepare = || crate::provider_observation::session::prepare_object(&object).unwrap();
        let configuration = [101, 102, 103, 0, 8, 120, 32, 128, 40, 184, 104, 184, 192];
        let mut prepared = prepare();
        patch_source_configuration(&configuration, &mut prepared.progs).unwrap();
        let original = prepare();
        let mut changed = 0;
        let mut owners: Vec<String> = Vec::new();
        for (old, new) in original.progs.iter().zip(&prepared.progs) {
            assert_eq!(old.insns.len(), new.insns.len());
            let mut root_changed = 0;
            for (a, b) in old.insns.chunks_exact(8).zip(new.insns.chunks_exact(8)) {
                if a == b {
                    continue;
                }
                changed += 1;
                root_changed += 1;
                let marker = u32::from_le_bytes(a[4..8].try_into().unwrap());
                if (0x7f001..=0x7f003).contains(&marker) {
                    assert_eq!(&b[..4], &[0x85, 0x20, 0, 0]);
                    assert_eq!(
                        u32::from_le_bytes(b[4..8].try_into().unwrap()),
                        configuration[(marker - 0x7f001) as usize]
                    );
                } else {
                    assert!((0x6f001..=0x6f006).contains(&marker));
                    assert_eq!(&a[..4], &b[..4]);
                    assert_eq!(
                        u32::from_le_bytes(b[4..8].try_into().unwrap()),
                        configuration[3 + (marker - 0x6f001) as usize]
                    );
                }
            }
            if root_changed > 0 {
                assert_eq!(root_changed, 9);
                owners.push(new.name.clone());
            }
        }
        // U1: reachable-subset linking copies the helper into every root
        // that reaches it (registration fexit + typed pair); each copy
        // carries the complete 9-site set, nothing else changes.
        owners.sort();
        assert_eq!(
            owners,
            vec!["source_reg_out", "typed_entry", "typed_return"]
        );
        assert_eq!(changed, 27);
        assert!(patch_source_configuration(&configuration, &mut prepared.progs).is_err());
        // Corrupt an actual field opcode, duplicate a field identity, and move
        // the helper to the wrong root. None may produce a partial patched body.
        for mutation in 0..3 {
            let mut mutant = prepare();
            let root = mutant
                .progs
                .iter_mut()
                .find(|p| p.name == "source_reg_out")
                .unwrap();
            let at = root
                .insns
                .chunks_exact(8)
                .position(|i| i[4..8] == 0x6f001u32.to_le_bytes())
                .unwrap()
                * 8;
            match mutation {
                0 => root.insns[at] = 0x07,
                1 => root.insns[at + 4..at + 8].copy_from_slice(&0x6f002u32.to_le_bytes()),
                _ => root.name = "source_reg_in".into(),
            }
            let before: Vec<_> = mutant.progs.iter().map(|p| p.insns.clone()).collect();
            assert!(patch_source_configuration(&configuration, &mut mutant.progs).is_err());
            assert!(mutant.progs.iter().zip(before).all(|(p, b)| p.insns == b));
        }
    }
    #[test]
    fn w079_native_member_first_and_late_custody_at_actual_effects() {
        use crate::capture_setup::{MemberLinkStore, SetupControl, SetupInterrupt, SetupLinks};
        use std::sync::{Arc, Mutex, atomic::AtomicBool, mpsc::sync_channel};
        use std::time::{Duration, Instant};
        // Entry, member0, middle and511 are genuine NativeMemberAttachOps
        // boundaries; selection/classifier/ownership are the production body.
        for hold in [0, 1, 257, 512] {
            let links = SetupLinks::new();
            let control = SetupControl::new(
                Instant::now() + Duration::from_secs(15),
                SetupInterrupt::Owned(Arc::new(AtomicBool::new(false))),
            );
            let peers = Arc::new(Mutex::new(Vec::new()));
            let (entered_tx, entered_rx) = sync_channel(1);
            let (resume_tx, resume_rx) = sync_channel(1);
            let mut ops = HeldMemberOps {
                peers: peers.clone(),
                ordinal: 0,
                hold,
                panic_at: None,
                entered: entered_tx,
                resume: resume_rx,
            };
            let mut store = MemberLinkStore::preparing(&links, &control);
            let worker = std::thread::spawn(move || {
                let loaded = model_loaded(&(0..512).collect::<Vec<_>>());
                let ctrl = osslscope_ebpf_common::ctrl_value(512, 1, 1 << 22);
                attach_full_loaded(loaded, &ctrl, model_initialize, &mut ops, &mut store)
                    .map(|_| ())
            });
            let entered = entered_rx.recv_timeout(Duration::from_secs(5));
            let custody = links.abandon();
            let before = peers
                .lock()
                .unwrap()
                .iter()
                .all(|peer| !sentinel_closed(peer));
            drop(custody);
            let during: Vec<_> = peers.lock().unwrap().iter().map(sentinel_closed).collect();
            let _ = resume_tx.send(());
            let result = worker.join().unwrap();
            assert!(entered.is_ok());
            assert!(before);
            assert_eq!(during.len(), hold + 1);
            assert!(
                during[..hold].iter().all(|closed| *closed),
                "prior returned links must be independently disposable before the held effect resumes"
            );
            assert!(!during[hold], "in-flight native result stays worker-owned");
            assert!(result.is_err());
            assert!(peers.lock().unwrap().iter().all(sentinel_closed));
        }
    }
    #[test]
    fn w079_native_member_dynamic_and_unwind_retain_actual_custody() {
        use crate::capture_setup::{MemberLinkStore, SetupControl, SetupInterrupt, SetupLinks};
        use std::sync::{Arc, Mutex, atomic::AtomicBool, mpsc::sync_channel};
        use std::time::{Duration, Instant};
        for panic_at in [None, Some(1)] {
            let links = SetupLinks::new();
            let control = SetupControl::new(
                Instant::now() + Duration::from_secs(15),
                SetupInterrupt::Owned(Arc::new(AtomicBool::new(false))),
            );
            let peers = Arc::new(Mutex::new(Vec::new()));
            let (entered_tx, entered_rx) = sync_channel(1);
            let (resume_tx, resume_rx) = sync_channel(1);
            let mut ops = HeldMemberOps {
                peers: peers.clone(),
                ordinal: 0,
                hold: 1,
                panic_at,
                entered: entered_tx,
                resume: resume_rx,
            };
            let mut store = MemberLinkStore::preparing(&links, &control);
            let worker = std::thread::spawn(move || {
                attach_member_slots_with_ops(
                    &model_loaded(&[0, 256, 511]),
                    &[0, 256, 511],
                    &mut store,
                    &mut ops,
                )
            });
            if panic_at.is_none() {
                let entered = entered_rx.recv_timeout(Duration::from_secs(5));
                links.retire_members();
                let during: Vec<_> = peers.lock().unwrap().iter().map(sentinel_closed).collect();
                let custody = links.abandon();
                drop(custody);
                let after_drain: Vec<_> =
                    peers.lock().unwrap().iter().map(sentinel_closed).collect();
                let _ = resume_tx.send(());
                let result = worker.join().unwrap();
                assert!(entered.is_ok());
                assert_eq!(during, [false, false]);
                assert_eq!(after_drain, [true, false]);
                assert!(result.is_err());
            } else {
                assert!(worker.join().is_err());
                assert!(
                    links
                        .reserve(&control, crate::capture::BoundaryStage::Traversal, 1)
                        .is_err(),
                    "member unwind leaves abort-only native custody"
                );
                assert_eq!(
                    peers
                        .lock()
                        .unwrap()
                        .iter()
                        .map(sentinel_closed)
                        .collect::<Vec<_>>(),
                    [false, true]
                );
                drop(links.abandon());
            }
            assert!(peers.lock().unwrap().iter().all(sentinel_closed));
        }
    }

    #[test]
    fn w079_native_member_full_positive_and_capacity_before_effect() {
        use crate::capture_setup::{MemberLinkStore, SetupControl, SetupInterrupt, SetupLinks};
        use std::sync::{Arc, atomic::AtomicBool};
        use std::time::{Duration, Instant};
        let links = SetupLinks::new();
        let control = SetupControl::new(
            Instant::now() + Duration::from_secs(15),
            SetupInterrupt::Owned(Arc::new(AtomicBool::new(false))),
        );
        let mut store = MemberLinkStore::preparing(&links, &control);
        let mut ops = ModelMemberOps::default();
        let ctrl = osslscope_ebpf_common::ctrl_value(512, 1, 1 << 22);
        let loaded = attach_full_loaded(
            model_loaded(&(0..512).collect::<Vec<_>>()),
            &ctrl,
            model_initialize,
            &mut ops,
            &mut store,
        )
        .unwrap();
        assert_eq!(ops.entry_calls, 1);
        assert_eq!(ops.member_calls, (0..512).collect::<Vec<_>>());
        assert_eq!(ops.link_identities.len(), 513);
        drop(links.abandon());
        ops.assert_links_closed();
        drop(loaded);
        let links = SetupLinks::new();
        let held = links
            .reserve(&control, crate::capture::BoundaryStage::Traversal, 1024)
            .unwrap();
        let mut store = MemberLinkStore::preparing(&links, &control);
        let mut ops = ModelMemberOps::default();
        let result = attach_full_loaded(
            model_loaded(&[0]),
            &ctrl,
            model_initialize,
            &mut ops,
            &mut store,
        );
        assert!(result.is_err());
        assert_eq!(ops.entry_calls, 0);
        assert!(ops.member_calls.is_empty());
        drop(held);
    }

    #[test]
    fn member_postload_classifier_failure_creates_no_links() {
        let loaded = model_loaded(&[1, 3]);
        let identities = loaded_identities(&loaded);
        let mut ops = ModelMemberOps::default();
        let ctrl = osslscope_ebpf_common::ctrl_value(2, 1, 1 << 22);
        let result = attach_subset_loaded(
            loaded,
            Vec::new(),
            vec![1, 3],
            &ctrl,
            |maps| {
                crate::discovery::classifier_maps::tests::host_initialize_members(
                    maps,
                    Some("freeze"),
                )
            },
            &mut ops,
        );
        assert!(result.is_err());
        assert_eq!(ops.entry_calls, 0);
        assert!(ops.member_calls.is_empty());
        assert!(ops.ctrl_expected.is_empty());
        ops.assert_links_closed();
        assert_identities_closed(&identities);
    }

    #[test]
    fn member_postload_subset_keeps_good_and_writes_actual_expected() {
        let loaded = model_loaded(&[1, 3]);
        let mut ops = ModelMemberOps {
            fail_member: Some(3),
            ..Default::default()
        };
        let ctrl = osslscope_ebpf_common::ctrl_value(3, 1, 1 << 22);
        let want = normalize_slots(&[7, 3, 1, 7]).unwrap();
        let outcome = attach_subset_loaded(
            loaded,
            vec![FailedProg {
                prog: "member_007".into(),
                error: "verifier reject".into(),
            }],
            want,
            &ctrl,
            model_initialize,
            &mut ops,
        )
        .unwrap();
        assert_eq!(ops.entry_calls, 1);
        assert_eq!(ops.member_calls, [1, 3]);
        assert_eq!(ops.ctrl_expected, [1]);
        assert_eq!(outcome.slots, [1]);
        assert_eq!(
            outcome
                .failed
                .iter()
                .map(|f| (f.slot, f.stage))
                .collect::<Vec<_>>(),
            [(3, "attach"), (7, "load")]
        );
        assert_eq!(outcome.attached.members.len(), 1);
        drop(outcome);
        ops.assert_links_closed();
    }

    #[test]
    fn member_postload_full_refuses_after_partial_links() {
        let loaded = model_loaded(&[0, 1]);
        let identities = loaded_identities(&loaded);
        let unrelated = model_fd();
        let unrelated_identity = model_identity(&unrelated);
        let mut ops = ModelMemberOps {
            fail_member: Some(1),
            ..Default::default()
        };
        let ctrl = osslscope_ebpf_common::ctrl_value(512, 1, 1 << 22);
        let error = attach_full_local(loaded, &ctrl, model_initialize, &mut ops)
            .err()
            .expect("full attach must refuse member failure");
        assert!(format!("{error:#}").contains("attach member_001"));
        assert_eq!(ops.ctrl_expected, [512]);
        assert_eq!(ops.entry_calls, 1);
        assert_eq!(ops.member_calls, [0, 1]);
        assert_eq!(ops.link_identities.len(), 2);
        ops.assert_links_closed();
        assert_identities_closed(&identities);
        assert_eq!(model_identity(&unrelated), unrelated_identity);
    }

    #[test]
    fn member_postload_full_classifier_failure_creates_no_links() {
        let loaded = model_loaded(&[]);
        let identities = loaded_identities(&loaded);
        let mut ops = ModelMemberOps::default();
        let ctrl = osslscope_ebpf_common::ctrl_value(512, 1, 1 << 22);
        assert!(
            attach_full_local(
                loaded,
                &ctrl,
                |maps| crate::discovery::classifier_maps::tests::host_initialize_members(
                    maps,
                    Some("final_keys")
                ),
                &mut ops,
            )
            .is_err()
        );
        assert_eq!(ops.ctrl_expected, [512]);
        assert_eq!(ops.entry_calls, 0);
        assert!(ops.member_calls.is_empty());
        assert_identities_closed(&identities);
    }

    #[test]
    fn member_postload_subset_all_failed_refuses_without_ctrl() {
        let loaded = model_loaded(&[3]);
        let identities = loaded_identities(&loaded);
        let mut ops = ModelMemberOps {
            fail_member: Some(3),
            ..Default::default()
        };
        let ctrl = osslscope_ebpf_common::ctrl_value(2, 1, 1 << 22);
        let error = attach_subset_loaded(
            loaded,
            vec![FailedProg {
                prog: "member_001".into(),
                error: "verifier reject".into(),
            }],
            normalize_slots(&[3, 1]).unwrap(),
            &ctrl,
            model_initialize,
            &mut ops,
        )
        .err()
        .expect("all failed must refuse");
        assert!(format!("{error:#}").contains("every wanted member failed"));
        assert_eq!(ops.member_calls, [3]);
        assert!(ops.ctrl_expected.is_empty());
        ops.assert_links_closed();
        assert_identities_closed(&identities);
    }

    #[test]
    fn member_postload_subset_ctrl_failure_closes_partial_activation() {
        let loaded = model_loaded(&[1]);
        let identities = loaded_identities(&loaded);
        let unrelated = model_fd();
        let unrelated_identity = model_identity(&unrelated);
        let mut ops = ModelMemberOps {
            fail_ctrl: true,
            ..Default::default()
        };
        let ctrl = osslscope_ebpf_common::ctrl_value(2, 1, 1 << 22);
        let error = attach_subset_loaded(
            loaded,
            vec![FailedProg {
                prog: "member_003".into(),
                error: "verifier reject".into(),
            }],
            normalize_slots(&[3, 1]).unwrap(),
            &ctrl,
            model_initialize,
            &mut ops,
        )
        .err()
        .expect("CTRL failure must refuse");
        assert!(format!("{error:#}").contains("program CTRL"));
        assert_eq!(ops.ctrl_expected, [1]);
        assert_eq!(ops.link_identities.len(), 2);
        ops.assert_links_closed();
        assert_identities_closed(&identities);
        assert_eq!(model_identity(&unrelated), unrelated_identity);
    }

    fn u16(v: u16) -> [u8; 2] {
        v.to_le_bytes()
    }
    fn u32(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }
    fn u64(v: u64) -> [u8; 8] {
        v.to_le_bytes()
    }

    #[test]
    fn subset_from_bytes_refuses_over_cap_before_bpf() {
        // Finding 11 (loader layer): an over-cap caller buffer
        // refuses before prepare/load (no post-onboarding
        // enlargement bypass). Host-safe: the refusal precedes
        // all BPF work.
        let big = vec![0u8; (crate::discovery::onboard::MAX_OBJECT_SCAN_BYTES + 1) as usize];
        let exe = std::ffi::CString::new("/exe").unwrap();
        let ctrl = osslscope_ebpf_common::ctrl_value(2, 1, 1 << 22);
        let e = attach_members_subset_from_bytes(&big, &exe, 0, 0, &ctrl, &[0, 1])
            .err()
            .expect("over-cap refuses");
        assert!(
            e.to_string().contains("exceeds the onboarding cap"),
            "{e:#}"
        );
    }

    #[test]
    fn selective_specs_cover_entry_plus_wanted_only() {
        // Normalized (sorted, deduped): entry + exactly the
        // wanted members — unselected members are never
        // prepared, loaded, or attached.
        let specs = member_specs_for_slots(&[3, 1, 1]).unwrap();
        let names: Vec<&str> = specs.iter().map(|s| s.name).collect();
        assert_eq!(names, ["member_entry", "member_001", "member_003"]);
        assert_eq!(specs[0].section, "uprobe");
        assert!(specs[1..].iter().all(|s| s.section == "uretprobe"));
        // Full-range edge: slot 511 resolves, 512 rejects.
        let specs = member_specs_for_slots(&[511]).unwrap();
        assert_eq!(specs[1].name, "member_511");
        assert!(member_specs_for_slots(&[512]).is_err());
        assert!(member_specs_for_slots(&[]).is_err());
        // Every slot resolves to its baked name (no off-by-one
        // in the frozen table index).
        for j in [0u32, 9, 10, 56, 255, 511] {
            let specs = member_specs_for_slots(&[j]).unwrap();
            assert_eq!(specs[1].name, MEMBER_PROGS[1 + j as usize].name);
        }
    }

    #[test]
    fn trim_nul_strips_padding_only() {
        assert_eq!(trim_nul(b"abc\0\0"), b"abc");
        assert_eq!(trim_nul(b"abc"), b"abc");
        assert_eq!(trim_nul(b"\0\0"), b"");
        assert_eq!(trim_nul(b""), b"");
        assert_eq!(trim_nul(b"a\0b\0"), b"a\0b");
    }

    #[test]
    fn verifier_spill_round_trips_full_log() {
        let body = vec![b'v'; 300_000];
        let path = spill_verifier_log("query_return", &body).unwrap();
        let back = std::fs::read(&path).unwrap();
        assert_eq!(back, body);
        assert!(path.to_string_lossy().contains("query_return"));
        std::fs::remove_file(&path).ok();
        // Hostile prog names cannot escape the temp dir.
        let evil = spill_verifier_log("../../x", b"e").unwrap();
        assert!(
            evil.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("osslscope-verifier-")
        );
        std::fs::remove_file(&evil).ok();
    }

    fn call_insn(src_pseudo: bool, imm: i32) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0] = BPF_CALL;
        b[1] = if src_pseudo { BPF_PSEUDO_CALL << 4 } else { 0 };
        b[4..8].copy_from_slice(&imm.to_le_bytes());
        b
    }

    #[test]
    fn stale_static_calls_fail_closed() {
        let exit = [0x95u8, 0, 0, 0, 0, 0, 0, 0];
        let helper = call_insn(false, 14);
        let pseudo = call_insn(true, 205);
        let img = |insns: &[&[u8; 8]]| {
            let mut v = Vec::new();
            for i in insns {
                v.extend_from_slice(*i);
            }
            v
        };
        // Helper calls need no reloc.
        let ok = img(&[&helper, &exit]);
        check_calls_rewritten(&ok, &HashSet::new(), "p").unwrap();
        // Rewritten pseudo-calls pass.
        let ok = img(&[&pseudo, &exit]);
        check_calls_rewritten(&ok, &[0usize].into_iter().collect(), "p").unwrap();
        // Unrewritten pseudo-calls fail, naming the insn.
        let bad = img(&[&pseudo, &exit]);
        let e = check_calls_rewritten(&bad, &HashSet::new(), "p").unwrap_err();
        assert!(
            e.to_string().contains("unrelocated static call at insn 0"),
            "{e:#}"
        );
        // A rewritten set covering the wrong offset does not help.
        let bad = img(&[&exit, &pseudo]);
        let e = check_calls_rewritten(&bad, &[0usize].into_iter().collect(), "p").unwrap_err();
        assert!(
            e.to_string().contains("unrelocated static call at insn 1"),
            "{e:#}"
        );
        // Ragged images fail rather than scan short.
        let e = check_calls_rewritten(&[0u8; 7], &HashSet::new(), "p").unwrap_err();
        assert!(e.to_string().contains("not a whole count"), "{e:#}");
    }

    /// Minimal BPF relocatable: 1 uprobe prog (ld_map/call/exit),
    /// .text sub (ld_map/exit), 1 map def, relocs for all three.
    /// Layout (offsets): ehdr 0/64, uprobe 64/32, .text 96/24, maps
    /// 120/28, .reluprobe 148/32, .rel.text 180/16, symtab 196/96,
    /// strtab 292/26, shstrtab 320/62, shdrs 384/576.
    fn min_elf() -> Vec<u8> {
        let mut b = vec![0u8; 392 + 9 * 64];
        // ELF header.
        b[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        b[4] = 2; // 64-bit
        b[5] = 1; // LE
        b[6] = 1; // version
        b[16..18].copy_from_slice(&u16(1)); // ET_REL
        b[18..20].copy_from_slice(&u16(247)); // EM_BPF
        b[40..48].copy_from_slice(&u64(392)); // shoff
        b[58..60].copy_from_slice(&u16(64)); // shentsize
        b[60..62].copy_from_slice(&u16(9)); // shnum
        b[62..64].copy_from_slice(&u16(8)); // shstrndx
        // uprobe: ld_imm64 r1,map + call + exit.
        b[64..80].copy_from_slice(&[0x18, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        b[80..88].copy_from_slice(&[0x85, 0x10, 0, 0, 0, 0, 0, 0]);
        b[88..96].copy_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]);
        // .text: ld_imm64 r1,map + exit.
        b[96..112].copy_from_slice(&[0x18, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        b[112..120].copy_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]);
        // maps: ARRAY u32->u64 max 1.
        for (i, v) in [2u32, 4, 8, 1, 0, 0, 0].iter().enumerate() {
            b[120 + i * 4..124 + i * 4].copy_from_slice(&u32(*v));
        }
        // .reluprobe: map ref @0 (sym 3), call @16 (sym 2).
        b[148..156].copy_from_slice(&u64(0));
        b[156..164].copy_from_slice(&u64(3 << 32 | 1));
        b[164..172].copy_from_slice(&u64(16));
        b[172..180].copy_from_slice(&u64(2 << 32 | 10));
        // .rel.text: map ref @0 (sym 3).
        b[180..188].copy_from_slice(&u64(0));
        b[188..196].copy_from_slice(&u64(3 << 32 | 1));
        // symtab: null, uprobe_func, memsub, MYMAP.
        let mut sym = |o: usize, name: u32, info: u8, shndx: u16, val: u64, size: u64| {
            b[o..o + 4].copy_from_slice(&u32(name));
            b[o + 4] = info;
            b[o + 6..o + 8].copy_from_slice(&u16(shndx));
            b[o + 8..o + 16].copy_from_slice(&u64(val));
            b[o + 16..o + 24].copy_from_slice(&u64(size));
        };
        sym(196, 0, 0, 0, 0, 0);
        sym(220, 1, 0x12, 1, 0, 32);
        sym(244, 13, 0x12, 2, 0, 24);
        sym(268, 20, 0x11, 3, 0, 28);
        // strtab.
        let s = b"\0uprobe_func\0memsub\0MYMAP\0";
        b[292..292 + s.len()].copy_from_slice(s);
        // shstrtab.
        let t = b"\0uprobe\0.text\0maps\0.reluprobe\0.rel.text\0.symtab\0.strtab\0.shstrtab\0";
        b[320..320 + t.len()].copy_from_slice(t);
        // Section headers: null, uprobe, .text, maps, .reluprobe,
        // .rel.text, symtab, strtab, shstrtab.
        let mut sh = |i: usize,
                      name: u32,
                      ty: u32,
                      flags: u64,
                      off: u64,
                      size: u64,
                      link: u32,
                      info: u32,
                      entsize: u64| {
            let o = 392 + i * 64;
            b[o..o + 4].copy_from_slice(&u32(name));
            b[o + 4..o + 8].copy_from_slice(&u32(ty));
            b[o + 8..o + 16].copy_from_slice(&u64(flags));
            b[o + 24..o + 32].copy_from_slice(&u64(off));
            b[o + 32..o + 40].copy_from_slice(&u64(size));
            b[o + 40..o + 44].copy_from_slice(&u32(link));
            b[o + 44..o + 48].copy_from_slice(&u32(info));
            b[o + 48..o + 56].copy_from_slice(&u64(8));
            b[o + 56..o + 64].copy_from_slice(&u64(entsize));
        };
        sh(0, 0, 0, 0, 0, 0, 0, 0, 0);
        sh(1, 1, 1, 6, 64, 32, 0, 0, 0);
        sh(2, 8, 1, 6, 96, 24, 0, 0, 0);
        sh(3, 14, 1, 3, 120, 28, 0, 0, 0);
        sh(4, 19, 9, 0, 148, 32, 6, 1, 16);
        sh(5, 30, 9, 0, 180, 16, 6, 2, 16);
        sh(6, 40, 2, 0, 196, 96, 7, 1, 24);
        sh(7, 48, 3, 0, 292, 26, 0, 0, 0);
        sh(8, 56, 3, 0, 320, 65, 0, 0, 0);
        b
    }

    /// Key offsets into [`mixed_elf`] for tests that patch it (the
    /// builder lays out sequentially, so tests take offsets from
    /// here instead of duplicating the layout).
    struct MixedLayout {
        symtab_off: usize,
        reltext_off: usize,
        cb_name_off: u32,
    }

    /// Mixed callback graph: main calls `wrap` (static), `wrap`
    /// takes `cb`'s address (func-ptr, backward over `dead`), `cb`
    /// bumps the map and calls `helper` (static, forward over
    /// `dead`+`wrap`), and `dead` is unreferenced between `cb` and
    /// `wrap` so its exclusion shifts linked offsets. `.text`
    /// order: cb @0/24, dead @24/8, wrap @32/16, helper @48/8;
    /// main is 16B (`call` + `exit`). Syms: null, main, cb, dead,
    /// wrap, helper, MYMAP.
    fn mixed_elf() -> (Vec<u8>, MixedLayout) {
        let uprobe_off = 64usize;
        let text_off = uprobe_off + 16;
        let maps_off = text_off + 56;
        let reluprobe_off = maps_off + 28;
        let reltext_off = reluprobe_off + 16;
        let symtab_off = reltext_off + 48;
        let strtab_off = symtab_off + 7 * 24;
        let strtab: &[u8] = b"\0main\0cb\0dead\0wrap\0helper\0MYMAP\0";
        // Name offsets into strtab: main=1, cb=6, dead=9, wrap=14,
        // helper=19, MYMAP=26.
        let shstrtab_off = strtab_off + strtab.len();
        let shstr: &[u8] =
            b"\0uprobe\0.text\0maps\0.reluprobe\0.rel.text\0.symtab\0.strtab\0.shstrtab\0";
        let shoff = (shstrtab_off + shstr.len() + 7) & !7;
        let mut b = vec![0u8; shoff + 9 * 64];
        // ELF header.
        b[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        b[4] = 2;
        b[5] = 1;
        b[6] = 1;
        b[16..18].copy_from_slice(&u16(1));
        b[18..20].copy_from_slice(&u16(247));
        b[40..48].copy_from_slice(&u64(shoff as u64));
        b[58..60].copy_from_slice(&u16(64));
        b[60..62].copy_from_slice(&u16(9));
        b[62..64].copy_from_slice(&u16(8));
        // uprobe main: pseudo-call + exit.
        b[uprobe_off..uprobe_off + 8].copy_from_slice(&[0x85, 0x10, 0, 0, 0, 0, 0, 0]);
        b[uprobe_off + 8..uprobe_off + 16].copy_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]);
        // .text cb: ld_imm64 r1,map + call.
        b[text_off..text_off + 16]
            .copy_from_slice(&[0x18, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        b[text_off + 16..text_off + 24].copy_from_slice(&[0x85, 0x10, 0, 0, 0, 0, 0, 0]);
        // .text dead: exit (unreferenced).
        b[text_off + 24..text_off + 32].copy_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]);
        // .text wrap: ld_imm64 r2,cb.
        b[text_off + 32..text_off + 48]
            .copy_from_slice(&[0x18, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        // .text helper: exit.
        b[text_off + 48..text_off + 56].copy_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]);
        // maps: ARRAY u32->u64 max 1.
        for (i, v) in [2u32, 4, 8, 1, 0, 0, 0].iter().enumerate() {
            b[maps_off + i * 4..maps_off + i * 4 + 4].copy_from_slice(&u32(*v));
        }
        // .reluprobe: call @0 (sym 4 = wrap).
        b[reluprobe_off..reluprobe_off + 8].copy_from_slice(&u64(0));
        b[reluprobe_off + 8..reluprobe_off + 16].copy_from_slice(&u64(4 << 32 | 10));
        // .rel.text: map @0 (sym 6), call @16 (sym 5 = helper),
        // func @32 (sym 2 = cb).
        b[reltext_off..reltext_off + 8].copy_from_slice(&u64(0));
        b[reltext_off + 8..reltext_off + 16].copy_from_slice(&u64(6 << 32 | 1));
        b[reltext_off + 16..reltext_off + 24].copy_from_slice(&u64(16));
        b[reltext_off + 24..reltext_off + 32].copy_from_slice(&u64(5 << 32 | 10));
        b[reltext_off + 32..reltext_off + 40].copy_from_slice(&u64(32));
        b[reltext_off + 40..reltext_off + 48].copy_from_slice(&u64(2 << 32 | 1));
        // symtab.
        let mut sym = |o: usize, name: u32, info: u8, shndx: u16, val: u64, size: u64| {
            b[o..o + 4].copy_from_slice(&u32(name));
            b[o + 4] = info;
            b[o + 6..o + 8].copy_from_slice(&u16(shndx));
            b[o + 8..o + 16].copy_from_slice(&u64(val));
            b[o + 16..o + 24].copy_from_slice(&u64(size));
        };
        sym(symtab_off, 0, 0, 0, 0, 0);
        sym(symtab_off + 24, 1, 0x12, 1, 0, 16);
        sym(symtab_off + 48, 6, 0x12, 2, 0, 24);
        sym(symtab_off + 72, 9, 0x12, 2, 24, 8);
        sym(symtab_off + 96, 14, 0x12, 2, 32, 16);
        sym(symtab_off + 120, 19, 0x12, 2, 48, 8);
        sym(symtab_off + 144, 26, 0x11, 3, 0, 28);
        b[strtab_off..strtab_off + strtab.len()].copy_from_slice(strtab);
        b[shstrtab_off..shstrtab_off + shstr.len()].copy_from_slice(shstr);
        // Section headers: null, uprobe, .text, maps, .reluprobe,
        // .rel.text, symtab, strtab, shstrtab.
        let mut sh = |i: usize,
                      name: u32,
                      ty: u32,
                      flags: u64,
                      off: u64,
                      size: u64,
                      link: u32,
                      info: u32,
                      entsize: u64| {
            let o = shoff + i * 64;
            b[o..o + 4].copy_from_slice(&u32(name));
            b[o + 4..o + 8].copy_from_slice(&u32(ty));
            b[o + 8..o + 16].copy_from_slice(&u64(flags));
            b[o + 24..o + 32].copy_from_slice(&u64(off));
            b[o + 32..o + 40].copy_from_slice(&u64(size));
            b[o + 40..o + 44].copy_from_slice(&u32(link));
            b[o + 44..o + 48].copy_from_slice(&u32(info));
            b[o + 48..o + 56].copy_from_slice(&u64(8));
            b[o + 56..o + 64].copy_from_slice(&u64(entsize));
        };
        sh(0, 0, 0, 0, 0, 0, 0, 0, 0);
        sh(1, 1, 1, 6, uprobe_off as u64, 16, 0, 0, 0);
        sh(2, 8, 1, 6, text_off as u64, 56, 0, 0, 0);
        sh(3, 14, 1, 3, maps_off as u64, 28, 0, 0, 0);
        sh(4, 19, 9, 0, reluprobe_off as u64, 16, 6, 1, 16);
        sh(5, 30, 9, 0, reltext_off as u64, 48, 6, 2, 16);
        sh(6, 40, 2, 0, symtab_off as u64, 168, 7, 1, 24);
        sh(7, 48, 3, 0, strtab_off as u64, strtab.len() as u64, 0, 0, 0);
        sh(
            8,
            56,
            3,
            0,
            shstrtab_off as u64,
            shstr.len() as u64,
            0,
            0,
            0,
        );
        (
            b,
            MixedLayout {
                symtab_off,
                reltext_off,
                cb_name_off: 6,
            },
        )
    }

    #[test]
    fn prepare_links_mixed_callback_graph() {
        // main -call-> wrap -funcptr-> cb -call-> helper, with
        // `dead` unreferenced between cb and wrap: linked layout is
        // main(16) + cb(24) + wrap(16) + helper(8) = 64B, and the
        // func-ptr imm goes negative (backward over dead).
        let (obj, _) = mixed_elf();
        let prep = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "main",
                section: "uprobe",
            }],
        )
        .unwrap();
        let p = &prep.progs[0];
        assert_eq!(p.insns.len(), 64);
        let subs: Vec<(&str, u32, bool)> = p
            .subprogs
            .iter()
            .map(|s| (s.name.as_str(), s.insn_off, s.is_callback))
            .collect();
        assert_eq!(
            subs,
            vec![
                ("main", 0, false),
                ("cb", 2, true),
                ("wrap", 5, false),
                ("helper", 7, false),
            ]
        );
        // main call @0 -> wrap @5insns: PSEUDO_CALL nibble +
        // imm = 5-0-1.
        assert_eq!(p.insns[1], 0x10);
        assert_eq!(&p.insns[4..8], &4i32.to_le_bytes());
        // wrap func site @40 -> cb @2insns: dst r2 + PSEUDO_FUNC,
        // imm = 2-5-1 (backward).
        assert_eq!(p.insns[41], 0x02 | (BPF_PSEUDO_FUNC << 4));
        assert_eq!(&p.insns[44..48], &(-4i32).to_le_bytes());
        // cb call @32 -> helper @7insns: PSEUDO_CALL nibble +
        // imm = 7-4-1.
        assert_eq!(p.insns[33], 0x10);
        assert_eq!(&p.insns[36..40], &2i32.to_le_bytes());
        // One map fixup: cb's site at linked offset 16.
        assert_eq!(p.map_fixups.len(), 1);
        assert_eq!(p.map_fixups[0].insn_off, 16);
        assert_eq!(p.map_fixups[0].map, "MYMAP");
        // `dead` is excluded: the subprog offs already prove
        // compaction (helper sits 8B below its naive .text+main
        // position), and every unpatched image byte matches its
        // source — only the three asserted reloc sites differ.
        let text = &obj[80..136];
        assert_eq!(&p.insns[0..4], &obj[64..68]);
        assert_eq!(&p.insns[8..16], &obj[72..80]);
        assert_eq!(&p.insns[16..36], &text[0..20]);
        assert_eq!(p.insns[40], text[32]);
        assert_eq!(&p.insns[48..56], &text[40..48]);
        assert_eq!(&p.insns[56..64], &text[48..56]);
    }

    #[test]
    fn prepare_rejects_duplicate_targeting_second() {
        // Strengthened dup regression: valid main intact, two `cb`
        // bodies with distinct bytes at different offsets (0 and
        // 48), and the func-ptr reloc repointed at the SECOND.
        // Name-only linking would resolve (48, "cb") but link the
        // first body with agreeing func_info — silent substitution.
        let (mut obj, layout) = mixed_elf();
        // Rename helper (sym 5) to "cb".
        obj[layout.symtab_off + 5 * 24..layout.symtab_off + 5 * 24 + 4]
            .copy_from_slice(&u32(layout.cb_name_off));
        // Repoint the func-ptr reloc (3rd .rel.text entry) at sym 5.
        obj[layout.reltext_off + 2 * 16 + 8..layout.reltext_off + 2 * 16 + 16]
            .copy_from_slice(&u64(5 << 32 | 1));
        let e = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "main",
                section: "uprobe",
            }],
        )
        .err()
        .expect("must fail");
        assert!(e.to_string().contains("duplicate"), "{e:#}");
    }

    #[test]
    fn prepare_patches_calls_and_records_map_fixups() {
        let obj = min_elf();
        let prep = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .unwrap();
        assert_eq!(prep.progs.len(), 1);
        let p = &prep.progs[0];
        // main (32B) + .text (24B).
        assert_eq!(p.insns.len(), 56);
        // Two map fixups: main @0, text @32.
        assert_eq!(p.map_fixups.len(), 2);
        assert_eq!(p.map_fixups[0].insn_off, 0);
        assert_eq!(p.map_fixups[1].insn_off, 32);
        // Call @16: target=(32+0)/8=4, pc=2 → imm=1.
        assert_eq!(&p.insns[20..24], &1i32.to_le_bytes());
        // Map-def dims confirmed.
        assert_eq!(prep.maps[0].max_entries, 1);
    }

    #[test]
    fn prepare_rewrites_func_pointers_pseudo() {
        // The uprobe call site @16 becomes an ld_imm64 of the sub's
        // address (the `bpf_loop` callback shape): the linked site
        // takes the relative imm plus the PSEUDO_FUNC src nibble.
        let mut obj = min_elf();
        obj[64 + 16..64 + 32]
            .copy_from_slice(&[0x18, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        obj[172..180].copy_from_slice(&u64(2 << 32 | 1));
        let prep = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .unwrap();
        let p = &prep.progs[0];
        assert_eq!(p.insns.len(), 56);
        // Dst reg preserved, src nibble PSEUDO_FUNC, imm = 4-2-1 = 1.
        assert_eq!(p.insns[17], 0x02 | (BPF_PSEUDO_FUNC << 4));
        assert_eq!(&p.insns[20..24], &1i32.to_le_bytes());
        // High half untouched.
        assert_eq!(&p.insns[24..32], &[0u8; 8]);
    }

    #[test]
    fn prepare_rejects_duplicate_text_names() {
        // Two `.text` FUNCs sharing a name would resolve by value
        // but link by first-name-match (silent substitution), so
        // the loader rejects the shape outright. Repurpose sym1 as
        // a second `memsub` FUNC in `.text` (the dup check fires
        // before per-prog validation, so the missing uprobe sym
        // never masks it).
        let mut obj = min_elf();
        obj[220..224].copy_from_slice(&u32(13)); // name "memsub"
        obj[226..228].copy_from_slice(&u16(2)); // shndx .text
        let e = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .err()
        .expect("must fail");
        assert!(e.to_string().contains("duplicate"), "{e:#}");
    }

    #[test]
    fn prepare_rejects_bad_func_pointers() {
        let spec = || {
            (
                vec![MapSpec {
                    name: "MYMAP",
                    map_type: 2,
                    key_size: 4,
                    value_size: 8,
                    max_entries: 1,
                    flags: 0,
                }],
                vec![ProgSpec {
                    name: "uprobe_func",
                    section: "uprobe",
                }],
            )
        };
        // Func reloc against a non-.text FUNC (the prog itself).
        let mut obj = min_elf();
        obj[64 + 16..64 + 32]
            .copy_from_slice(&[0x18, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        obj[172..180].copy_from_slice(&u64(1 << 32 | 1));
        let (maps, progs) = spec();
        let e = prepare(&obj, &maps, &progs).err().expect("must fail");
        assert!(e.to_string().contains("non-entry"), "{e:#}");
        // Func reloc against a non-ld_imm64 site (the call shape).
        let mut obj = min_elf();
        obj[172..180].copy_from_slice(&u64(2 << 32 | 1));
        let (maps, progs) = spec();
        let e = prepare(&obj, &maps, &progs).err().expect("must fail");
        assert!(e.to_string().contains("non-ld_imm64"), "{e:#}");
        // Func reloc against an already-relocated site (nonzero imm).
        let mut obj = min_elf();
        obj[64 + 16..64 + 32]
            .copy_from_slice(&[0x18, 0x02, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        obj[172..180].copy_from_slice(&u64(2 << 32 | 1));
        let (maps, progs) = spec();
        let e = prepare(&obj, &maps, &progs).err().expect("must fail");
        assert!(e.to_string().contains("relocated site"), "{e:#}");
    }

    #[test]
    fn prepare_rejects_misaligned_func_site() {
        // A func-ptr reloc at misaligned @12 whose straddling bytes
        // decode as a valid unrelocated ld_imm64: start-only
        // ownership plus shape checks would link it.
        let mut obj = min_elf();
        obj[164..172].copy_from_slice(&u64(12));
        obj[172..180].copy_from_slice(&u64(2 << 32 | 1));
        obj[64 + 12] = 0x18;
        obj[64 + 13] = 0x02;
        obj[64 + 16..64 + 28].fill(0);
        let e = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .err()
        .expect("must fail");
        // The resolver fires first (roots resolve before apply).
        assert!(
            e.to_string().contains("func reloc site misaligned"),
            "{e:#}"
        );
    }

    #[test]
    fn prepare_rejects_func_site_crossing_fn_end() {
        // The site start is owned but its 16 bytes cross the
        // function's end (shrunk to 16): resolving from the whole
        // section would use sibling bytes.
        let mut obj = min_elf();
        obj[236..244].copy_from_slice(&u64(16));
        obj[164..172].copy_from_slice(&u64(8));
        obj[172..180].copy_from_slice(&u64(2 << 32 | 1));
        obj[64 + 8] = 0x18;
        obj[64 + 9] = 0x02;
        obj[64 + 16..64 + 24].fill(0);
        let e = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .err()
        .expect("must fail");
        assert!(e.to_string().contains("crosses"), "{e:#}");
    }

    #[test]
    fn prepare_rejects_helper_call_with_reloc() {
        // A call reloc on a helper-form call (src 0, not
        // PSEUDO_CALL): linking would rewrite the helper id into a
        // relative target — a silent semantic change. Pin the
        // helper-form byte explicitly (min_elf itself emits
        // PSEUDO_CALL).
        let mut obj = min_elf();
        obj[81] = 0x00;
        let e = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .err()
        .expect("must fail");
        assert!(e.to_string().contains("helper call"), "{e:#}");
    }

    #[test]
    fn prepare_rejects_misaligned_call_site() {
        // A call reloc at misaligned @18 whose straddling bytes
        // start with a CALL opcode: shape checks alone would link it.
        let mut obj = min_elf();
        obj[164..172].copy_from_slice(&u64(18));
        obj[64 + 18] = 0x85;
        let e = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .err()
        .expect("must fail");
        assert!(e.to_string().contains("misalign"), "{e:#}");
    }

    #[test]
    fn prepare_rejects_func_site_reserved_bytes() {
        // An otherwise valid func-ptr site with the first slot's
        // reserved offset bytes set.
        let mut obj = min_elf();
        obj[64 + 16..64 + 32]
            .copy_from_slice(&[0x18, 0x02, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        obj[172..180].copy_from_slice(&u64(2 << 32 | 1));
        let e = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .err()
        .expect("must fail");
        assert!(e.to_string().contains("reserved"), "{e:#}");
    }

    #[test]
    fn prepare_rejects_misaligned_text_value() {
        // A `.text` entry at a misaligned value would link a
        // mid-instruction slice.
        let mut obj = min_elf();
        obj[252..260].copy_from_slice(&u64(4));
        obj[260..268].copy_from_slice(&u64(8));
        obj[180..188].copy_from_slice(&u64(4));
        let e = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .err()
        .expect("must fail");
        assert!(e.to_string().contains("misalign"), "{e:#}");
    }

    #[test]
    fn prepare_rejects_misaligned_prog_value() {
        // A prog entry at a misaligned value would link a
        // mid-instruction main.
        let mut obj = min_elf();
        obj[228..236].copy_from_slice(&u64(4));
        obj[236..244].copy_from_slice(&u64(24));
        obj[148..156].copy_from_slice(&u64(8));
        let e = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .err()
        .expect("must fail");
        assert!(e.to_string().contains("misalign"), "{e:#}");
    }

    #[test]
    fn prepare_rejects_map_site_crossing_fn_end() {
        // Map sites are `ld_imm64` too (16 bytes): a map reloc at
        // @24 in a 32-byte function crosses the end.
        let mut obj = min_elf();
        obj[148..156].copy_from_slice(&u64(24));
        let e = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .err()
        .expect("must fail");
        assert!(e.to_string().contains("crosses"), "{e:#}");
    }

    #[test]
    fn prepare_accepts_call_site_at_exact_fit() {
        // An 8-byte call site ending exactly at the function end is
        // contained (pins the call width against the 16-byte
        // `ld_imm64` width).
        let mut obj = min_elf();
        obj[164..172].copy_from_slice(&u64(24));
        obj[64 + 24] = 0x85;
        obj[64 + 25] = 0x10;
        // The reloc moved: clear the stale call bytes (an unowned
        // pseudo-call is drift and must not linger).
        obj[64 + 16..64 + 24].fill(0);
        let prep = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .unwrap();
        assert_eq!(prep.progs[0].insns.len(), 56);
    }

    #[test]
    fn prepare_rejects_misaligned_map_site() {
        // Map reloc at misaligned @4 (contained: 4+16=20 <= 32):
        // map arms must enforce alignment like call/func sites.
        let mut obj = min_elf();
        obj[148..156].copy_from_slice(&u64(4));
        let e = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .err()
        .expect("must fail");
        // Exact phrase: proves the map arm fired (not another check).
        assert!(e.to_string().contains("map site misaligned"), "{e:#}");
    }

    #[test]
    fn prepare_rejects_map_site_reserved_bytes() {
        // Main map site with the first slot's reserved offset bytes
        // set: map arms must check them like func sites.
        let mut obj = min_elf();
        obj[64 + 2] = 1;
        let e = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .err()
        .expect("must fail");
        // Exact phrase: proves the map arm fired (not another check).
        assert!(
            e.to_string().contains("map site reserved bytes set"),
            "{e:#}"
        );
    }

    #[test]
    fn prepare_rejects_misaligned_text_map_site() {
        // `.text` map reloc at misaligned @4 (contained in memsub):
        // the apply-loop map arm must enforce alignment.
        let mut obj = min_elf();
        obj[180..188].copy_from_slice(&u64(4));
        let e = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .err()
        .expect("must fail");
        // Exact phrase: proves the apply-loop map arm fired.
        assert!(e.to_string().contains("map site misaligned"), "{e:#}");
    }

    #[test]
    fn prepare_rejects_text_map_site_reserved_bytes() {
        // `.text` map site with reserved offset bytes set: the
        // apply-loop map arm must check them.
        let mut obj = min_elf();
        obj[96 + 2] = 1;
        let e = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .err()
        .expect("must fail");
        // Exact phrase: proves the apply-loop map arm fired.
        assert!(
            e.to_string().contains("map site reserved bytes set"),
            "{e:#}"
        );
    }

    #[test]
    fn accounted_map_capacity_includes_possible_cpu_replication_and_overhead() {
        let relation = MapSpec {
            name: "REL",
            map_type: 1,
            key_size: 48,
            value_size: 256,
            max_entries: 8192,
            flags: 0,
        };
        assert_eq!(relation.reservation_bytes(16), Some(3_604_480));
        let partition = MapSpec {
            name: "PARTITION",
            map_type: 5,
            key_size: 104,
            value_size: 24,
            max_entries: 8192,
            flags: 0,
        };
        assert_eq!(partition.reservation_bytes(16), Some(5_111_808));
        assert_eq!(partition.reservation_bytes(0), None);
        assert_eq!(partition.reservation_bytes(usize::MAX), None);
        let ring = MapSpec {
            name: "EVENTS",
            map_type: 27,
            key_size: 0,
            value_size: 0,
            max_entries: 1 << 20,
            flags: 0,
        };
        assert_eq!(ring.reservation_bytes(16), Some(1_114_112));
        let unaligned = MapSpec {
            name: "PAD",
            map_type: 6,
            key_size: 4,
            value_size: 9,
            max_entries: 1,
            flags: 0,
        };
        assert_eq!(unaligned.reservation_bytes(2), Some(65_700));
    }

    #[test]
    fn lifecycle_loader_refuses_unreviewed_kind_and_ungated_acquisition() {
        let mut p = PreparedProg {
            name: "attr_exit".into(),
            section: "raw_tracepoint/sched_process_exit".into(),
            is_return: false,
            insns: vec![0x95, 0, 0, 0, 0, 0, 0, 0],
            map_fixups: Vec::new(),
            subprogs: Vec::new(),
        };
        assert_eq!(
            lifecycle_root(&p).unwrap(),
            Some(ossl_bpf_sys::LifecycleTracepoint::Exit)
        );
        p.name = "identity_exit".into();
        assert!(lifecycle_root(&p).is_err());
        p.name = "attr_exit".into();
        p.is_return = true;
        assert!(lifecycle_root(&p).is_err());
        p.is_return = false;
        p.subprogs.push(SubprogInfo {
            name: "callback".into(),
            insn_off: 1,
            is_callback: true,
        });
        assert!(lifecycle_root(&p).is_err());
        p.subprogs.clear();
        let error = load(&Prepared {
            progs: vec![p],
            maps: Vec::new(),
        })
        .err()
        .unwrap();
        assert!(
            error
                .to_string()
                .contains("lifecycle root requires shared gate")
        );
    }

    #[test]
    fn load_rejects_huge_fixup_off_caps_free() {
        // `Prepared` fields are public: a hand-built fixup at
        // `MAX-7` (aligned) must ERR, not panic on `off + 8`
        // overflow in debug. No maps: the validator bails before
        // any fd use, so no caps are needed.
        let prep = Prepared {
            maps: Vec::new(),
            progs: vec![PreparedProg {
                name: "p".to_string(),
                section: "uprobe".into(),
                is_return: false,
                insns: vec![0u8; 32],
                map_fixups: vec![MapFixup {
                    insn_off: usize::MAX - 7,
                    map: "NOPE".to_string(),
                }],
                subprogs: vec![SubprogInfo {
                    name: "p".to_string(),
                    insn_off: 0,
                    is_callback: false,
                }],
            }],
        };
        let e = load(&prep).err().expect("must fail");
        assert!(e.to_string().contains("out of range"), "{e:#}");
    }

    #[test]
    fn check_ld_imm64_site_rejects_huge_off() {
        // Aligned `MAX-15`: `off + 16` overflows — must ERR, not
        // panic in debug.
        let e = check_ld_imm64_site(&[0u8; 32], usize::MAX - 15, "p").unwrap_err();
        assert!(e.to_string().contains("out of range"), "{e:#}");
    }

    #[test]
    fn check_site_contained_rejects_offset_overflow() {
        // All current callers pre-constrain the offset via
        // ownership filters; this pins the fail-closed contract
        // for future callers (without the checked add this input
        // panics in debug / wraps in release).
        let e = check_site_contained(usize::MAX, 16, 32, "f", "p").unwrap_err();
        assert!(e.to_string().contains("site out of range"), "{e:#}");
    }

    #[test]
    fn apply_call_rejects_misaligned_site() {
        // Unreachable via `prepare` (reloc offset and prog value
        // are both aligned there); pinned directly.
        let mut insns = vec![0u8; 16];
        let e = apply_call(&mut insns, 4, 8, "t").err().expect("must fail");
        assert!(e.to_string().contains("call site misaligned"), "{e:#}");
    }

    #[test]
    fn apply_func_ptr_rejects_misaligned_site() {
        let mut insns = vec![0u8; 24];
        insns[4] = 0x18;
        insns[5] = 0x02;
        let before = insns.clone();
        let e = apply_func_ptr(&mut insns, 4, 16, "t")
            .err()
            .expect("must fail");
        assert!(e.to_string().contains("misalign"), "{e:#}");
        assert_eq!(insns, before, "no mutation on failure");
    }

    #[test]
    fn apply_func_ptr_rejects_reserved_bytes() {
        let mut insns = vec![0u8; 16];
        insns[0] = 0x18;
        insns[1] = 0x02;
        insns[2] = 1;
        let before = insns.clone();
        let e = apply_func_ptr(&mut insns, 0, 8, "t")
            .err()
            .expect("must fail");
        assert!(e.to_string().contains("reserved"), "{e:#}");
        assert_eq!(insns, before, "no mutation on failure");
    }

    #[test]
    fn stale_func_pointers_fail_closed() {
        let exit = [0x95u8, 0, 0, 0, 0, 0, 0, 0];
        let zeros = [0u8; 8];
        // A PSEUDO_FUNC site without a rewrite record fails, naming
        // the insn; map sites (src 0) are ignored here.
        let mut bad = Vec::new();
        bad.extend_from_slice(&[0x18, 0x02 | (BPF_PSEUDO_FUNC << 4), 0, 0, 1, 0, 0, 0]);
        bad.extend_from_slice(&zeros);
        bad.extend_from_slice(&exit);
        let e = check_func_ptrs_rewritten(&bad, &HashSet::new(), "p").unwrap_err();
        assert!(
            e.to_string()
                .contains("unrelocated function pointer at insn 0"),
            "{e:#}"
        );
        let mut ok = Vec::new();
        ok.extend_from_slice(&[0x18, 0x02 | (BPF_PSEUDO_FUNC << 4), 0, 0, 1, 0, 0, 0]);
        ok.extend_from_slice(&zeros);
        ok.extend_from_slice(&exit);
        check_func_ptrs_rewritten(&ok, &[0usize].into_iter().collect(), "p").unwrap();
        // The second slot's bytes are not opcodes: 0x85 there must
        // not scan as a call (and 0x18 there must not recurse).
        let mut second = Vec::new();
        second.extend_from_slice(&[0x18, 0x01, 0, 0, 0, 0, 0, 0]);
        second.extend_from_slice(&[0x85, 0x10, 0, 0, 0, 0, 0, 0]);
        second.extend_from_slice(&exit);
        check_func_ptrs_rewritten(&second, &HashSet::new(), "p").unwrap();
        // Ragged images fail rather than scan short.
        let e = check_func_ptrs_rewritten(&[0u8; 7], &HashSet::new(), "p").unwrap_err();
        assert!(e.to_string().contains("not a whole count"), "{e:#}");
    }

    #[test]
    fn prepare_rejects_dim_mismatch_and_missing_syms() {
        let obj = min_elf();
        let r = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 999,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        );
        assert!(r.is_err());
        let r = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "nope",
                section: "uprobe",
            }],
        );
        assert!(r.is_err());
    }

    /// Minimal BTF walker for synthesis tests: parses the header,
    /// walks the type section by (kind, vlen), splits the string
    /// section. Returns (types, strings) where each type is
    /// (kind, name, size_or_type, payload words).
    fn walk_btf(btf: &[u8]) -> (Vec<(u32, u32, u32, Vec<u32>)>, Vec<Vec<u8>>) {
        assert!(btf.len() >= 24, "btf shorter than header");
        let u16le = |o: usize| u16::from_le_bytes([btf[o], btf[o + 1]]) as u32;
        let u32le = |o: usize| u32::from_le_bytes([btf[o], btf[o + 1], btf[o + 2], btf[o + 3]]);
        assert_eq!(u16le(0), 0xEB9F, "bad magic");
        assert_eq!(btf[2], 1, "bad version");
        // Header layout: magic(0:2) version(2) flags(3) hdr_len(4:8)
        // type_off(8:12) type_len(12:16) str_off(16:20) str_len(20:24).
        let hdr_len = u32le(4) as usize;
        let type_off = hdr_len + u32le(8) as usize;
        let type_len = u32le(12) as usize;
        let str_off = hdr_len + u32le(16) as usize;
        let str_len = u32le(20) as usize;
        assert!(type_off + type_len <= btf.len(), "type section overrun");
        assert!(str_off + str_len <= btf.len(), "string section overrun");
        let mut types = Vec::new();
        let mut o = type_off;
        while o < type_off + type_len {
            let name = u32le(o);
            let info = u32le(o + 4);
            let kind = (info >> 24) & 0x1f;
            let vlen = (info & 0xffff) as usize;
            let size_or_type = u32le(o + 8);
            o += 12;
            let words = match kind {
                1 => {
                    // INT: one data word.
                    let w = vec![u32le(o)];
                    o += 4;
                    w
                }
                2 => {
                    // PTR: no payload.
                    assert_eq!(vlen, 0, "ptr with vlen");
                    Vec::new()
                }
                4 => {
                    // STRUCT members: vlen triples.
                    let mut w = Vec::new();
                    for _ in 0..vlen {
                        w.push(u32le(o));
                        w.push(u32le(o + 4));
                        w.push(u32le(o + 8));
                        o += 12;
                    }
                    w
                }
                12 | 13 => {
                    // FUNC (vlen 0) / FUNC_PROTO params: vlen pairs.
                    let mut w = Vec::new();
                    for _ in 0..vlen {
                        w.push(u32le(o));
                        w.push(u32le(o + 4));
                        o += 8;
                    }
                    w
                }
                _ => panic!("unexpected kind {kind} in synthesized btf"),
            };
            types.push((kind, name, size_or_type, words));
        }
        let strings: Vec<Vec<u8>> = btf[str_off..str_off + str_len]
            .split(|b| *b == 0)
            .map(|s| s.to_vec())
            .collect();
        (types, strings)
    }

    #[test]
    fn synth_btf_callback_shape_layout() {
        // main @0 + one callback @24: fixed type prefix (INT u64,
        // INT u32, STRUCT ctx, PTR, main proto, callback proto,
        // static proto) plus one FUNC per subprog; func_info maps
        // insn offsets to the matching FUNC ids.
        let (btf, info) = synth_btf(&[
            SubprogInfo {
                name: "main".into(),
                insn_off: 0,
                is_callback: false,
            },
            SubprogInfo {
                name: "cb".into(),
                insn_off: 24,
                is_callback: true,
            },
        ])
        .unwrap();
        assert_eq!(info, vec![(0u32, 8u32), (24u32, 9u32)]);
        let (types, strings) = walk_btf(&btf);
        assert_eq!(types.len(), 9, "7 prefix + 2 funcs");
        // Kinds: INT=1, PTR=2, STRUCT=4, FUNC_PROTO=13, FUNC=12.
        let kinds: Vec<u32> = types.iter().map(|t| t.0).collect();
        assert_eq!(kinds, vec![1, 1, 4, 2, 13, 13, 13, 12, 12]);
        // INT widths.
        assert_eq!((types[0].2, types[0].3[0]), (8, 64));
        assert_eq!((types[1].2, types[1].3[0]), (4, 32));
        // STRUCT ctx { u64 pad; } + PTR to it.
        assert_eq!(types[2].2, 8);
        assert_eq!(types[2].3.len(), 3);
        assert_eq!(types[3].2, 3);
        // Main proto: u32 <- (ctx *arg0). Callback proto with named
        // params. Params are (name_off, type) pairs per
        // uapi/linux/btf.h.
        assert_eq!(types[4].2, 2);
        assert_eq!(types[4].3.len(), 2);
        assert_eq!(types[4].3[1], 4);
        assert_eq!(types[5].2, 1);
        assert_eq!(types[5].3.len(), 4);
        assert_eq!((types[5].3[1], types[5].3[3]), (1, 1));
        // Static proto: void <- ().
        assert_eq!((types[6].2, types[6].3.len()), (0, 0));
        // FUNCs bind the right protos.
        assert_eq!((types[7].2, types[8].2), (5, 6));
        // Names resolve in the string section.
        let s = |off: u32| {
            // String offsets are relative to the string section; find
            // it via the header (hdr_len 24 + str_off field).
            let base = 24 + u32::from_le_bytes([btf[16], btf[17], btf[18], btf[19]]) as usize;
            let mut end = base + off as usize;
            while btf[end] != 0 {
                end += 1;
            }
            std::str::from_utf8(&btf[base + off as usize..end])
                .unwrap()
                .to_string()
        };
        assert_eq!(s(types[0].1), "__u64");
        assert_eq!(s(types[1].1), "__u32");
        assert_eq!(s(types[2].1), "ctx");
        assert_eq!(s(types[2].3[0]), "pad");
        assert_eq!(s(types[4].3[0]), "arg0");
        assert_eq!(s(types[5].3[0]), "index");
        assert_eq!(s(types[5].3[2]), "cctx");
        assert_eq!(s(types[7].1), "main");
        assert_eq!(s(types[8].1), "cb");
        // String section is NUL-separated with a leading empty entry.
        assert_eq!(strings[0], b"");
        let joined = strings.concat();
        for want in [
            b"__u64".as_slice(),
            b"__u32",
            b"ctx",
            b"pad",
            b"arg0",
            b"index",
            b"cctx",
            b"main",
            b"cb",
        ] {
            assert!(
                joined.windows(want.len()).any(|w| w == want),
                "missing {want:?}"
            );
        }
    }

    #[test]
    fn prepare_records_subprog_table() {
        // Plain static-call shape: main + one static callee, no
        // callbacks — the table still records (main @0, callee @4).
        let obj = min_elf();
        let prep = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .unwrap();
        let subs: Vec<(String, u32, bool)> = prep.progs[0]
            .subprogs
            .iter()
            .map(|s| (s.name.clone(), s.insn_off, s.is_callback))
            .collect();
        assert_eq!(
            subs,
            vec![
                ("uprobe_func".to_string(), 0, false),
                ("memsub".to_string(), 4, false),
            ]
        );
        // Function-pointer shape: the reloc target is a callback.
        let mut obj = min_elf();
        obj[64 + 16..64 + 32]
            .copy_from_slice(&[0x18, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        obj[172..180].copy_from_slice(&u64(2 << 32 | 1));
        let prep = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        )
        .unwrap();
        let subs: Vec<(String, u32, bool)> = prep.progs[0]
            .subprogs
            .iter()
            .map(|s| (s.name.clone(), s.insn_off, s.is_callback))
            .collect();
        assert_eq!(
            subs,
            vec![
                ("uprobe_func".to_string(), 0, false),
                ("memsub".to_string(), 4, true),
            ]
        );
    }

    #[test]
    fn synth_btf_rejects_bad_inputs() {
        let sub = |name: &str, off: u32, cb: bool| SubprogInfo {
            name: name.into(),
            insn_off: off,
            is_callback: cb,
        };
        // Empty: no main.
        let e = synth_btf(&[]).err().expect("must fail");
        assert!(e.to_string().contains("no subprograms"), "{e:#}");
        // First offset must be 0 (main).
        let e = synth_btf(&[sub("main", 8, false)])
            .err()
            .expect("must fail");
        assert!(e.to_string().contains("main at 0"), "{e:#}");
        // Offsets strictly increasing.
        let e = synth_btf(&[sub("main", 0, false), sub("cb", 0, true)])
            .err()
            .expect("must fail");
        assert!(e.to_string().contains("increasing"), "{e:#}");
        // Empty name.
        let e = synth_btf(&[sub("", 0, false)]).err().expect("must fail");
        assert!(e.to_string().contains("empty name"), "{e:#}");
        // NUL in name would corrupt the string section.
        let e = synth_btf(&[sub("a\0b", 0, false)])
            .err()
            .expect("must fail");
        assert!(e.to_string().contains("NUL"), "{e:#}");
        // Absurd subprog count.
        let many: Vec<SubprogInfo> = (0..300).map(|i| sub("s", i * 8, false)).collect();
        let e = synth_btf(&many).err().expect("must fail");
        assert!(e.to_string().contains("too many"), "{e:#}");
    }

    #[test]
    fn prepare_rejects_non_bpf_machine() {
        let mut obj = min_elf();
        obj[18..20].copy_from_slice(&u16(62)); // EM_X86_64
        let r = prepare(
            &obj,
            &[MapSpec {
                name: "MYMAP",
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }],
            &[ProgSpec {
                name: "uprobe_func",
                section: "uprobe",
            }],
        );
        assert!(r.is_err());
    }

    fn t_sym(name: &str, value: usize, shndx: usize, func: bool, sec: bool) -> Sym {
        Sym {
            name: name.to_string(),
            value,
            size: 8,
            shndx,
            is_func: func,
            is_obj: false,
            is_section: sec,
        }
    }

    fn call_site(imm: i32) -> Vec<u8> {
        let mut b = vec![0x95u8; 16]; // exit padding
        b[0] = 0x85;
        b[1] = 0x10; // PSEUDO_CALL, like a real toolchain
        b[4..8].copy_from_slice(&imm.to_le_bytes());
        b
    }

    #[test]
    fn call_target_section_rule() {
        // Mirrors the real shape: .text[0] = local callee, .text[0x330]
        // = named builtin; section sym value 0.
        let fns = vec![
            (0usize, 528usize, "walk".to_string()),
            (0x330usize, 0x370usize, "memset".to_string()),
        ];
        let syms = vec![
            t_sym(".text", 0, 2, false, true),
            t_sym("memset", 0x330, 2, true, false),
            t_sym("uprobe_func", 0, 4, true, false),
        ];
        // Named path: (value, name) entry.
        let site = call_site(-1);
        let r = Reloc {
            off: 0,
            typ: R_BPF_64_32,
            sym: 1,
        };
        assert_eq!(
            call_target(&syms, &fns, 2, &site, &r, "p").unwrap(),
            "memset"
        );
        // Section path, placeholder imm: base + 0 = entry@0.
        let r = Reloc {
            off: 0,
            typ: R_BPF_64_32,
            sym: 0,
        };
        assert_eq!(call_target(&syms, &fns, 2, &site, &r, "p").unwrap(), "walk");
        // Section path, folded offset: imm = X/8 - 1 lands on memset.
        let site = call_site(0x330 / 8 - 1);
        assert_eq!(
            call_target(&syms, &fns, 2, &site, &r, "p").unwrap(),
            "memset"
        );
        // Mid-function landing is drift, never a guess.
        let site = call_site(8 / 8 - 1);
        assert!(call_target(&syms, &fns, 2, &site, &r, "p").is_err());
        // Non-call site is drift.
        let mut site = call_site(-1);
        site[0] = 0x95;
        assert!(call_target(&syms, &fns, 2, &site, &r, "p").is_err());
        // Named non-.text func is drift.
        let r = Reloc {
            off: 0,
            typ: R_BPF_64_32,
            sym: 2,
        };
        let site = call_site(-1);
        assert!(call_target(&syms, &fns, 2, &site, &r, "p").is_err());
    }

    #[test]
    fn count_shape_carries_window_cells() {
        // T07 count ABI v2: the loader spec must name the WINDOW
        // interval map with exactly the dims the BPF object
        // declares (ARRAY, u32 key, u64 value, 2 cells); anything
        // else fails `prepare` against the real object instead of
        // running deadline-blind.
        let window = COUNT_MAPS
            .iter()
            .find(|m| m.name == "WINDOW")
            .expect("COUNT_MAPS names WINDOW");
        assert_eq!(window.map_type, 2);
        assert_eq!(window.key_size, 4);
        assert_eq!(window.value_size, 8);
        assert_eq!(window.max_entries, 2);
        assert_eq!(window.flags, 0);
        assert_eq!(
            window.max_entries,
            osslscope_ebpf_common::WINDOW_CELLS,
            "spec dims track the shared ABI"
        );
    }

    #[test]
    fn members_fd_budget_predicate() {
        // Pure gate for the chunk's fd budget (513 prog + 15 map +
        // 513 link fds + clones ≈ 1048 > the 1024 default): soft
        // limits below NEED fail closed before any attach.
        assert!(!members_fd_budget_ok(1024), "default 1024 insufficient");
        assert!(!members_fd_budget_ok(MEMBERS_FD_NEED - 1));
        assert!(members_fd_budget_ok(MEMBERS_FD_NEED));
        assert!(members_fd_budget_ok(MEMBERS_FD_WANT));
        assert!(MEMBERS_FD_WANT >= MEMBERS_FD_NEED);
    }

    #[test]
    fn member_map_count_covers_scan_plane() {
        // The spec count is the prepare-time contract: 6 retained
        // maps + the 7 scan-plane maps + item-5 BUCKET (stage D
        // dropped PENDING — R18 §6.1 — → 13, then +1 → 14) +
        // round-3 per-op TRUNC_SEQ (→ 15).
        assert_eq!(MEMBER_MAPS.len(), 15);
        assert!(
            MEMBER_MAPS.iter().all(|m| m.name != "PENDING_QUERY"),
            "PENDING dropped in D"
        );
        for name in [
            "SCAN", "SEQ", "BIRTH", "RCOUNT", "T_CACHE", "CTRL", "ATTEMPT",
        ] {
            assert!(
                MEMBER_MAPS.iter().any(|m| m.name == name),
                "spec names {name}"
            );
        }
    }

    #[test]
    fn default_ctrl_programs_occupancy_policy() {
        // Stage C (R18 §2/§5): EXPECTED/epoch/gov program the
        // occupancy policy; EXPECTED 0 and 513 fail fast (the entry
        // would skip cause 7 on them).
        let c = default_ctrl(512, MEMBER_RING_BYTES).unwrap();
        assert_eq!(
            (c.expected, c.skip_all, c.epoch, c.governor),
            (512, 0, 1, 4 << 20),
            "16MiB ring: 4MiB policy live"
        );
        let c2 = default_ctrl(512, 1 << 21).unwrap();
        assert_eq!(c2.governor, 1 << 20, "2MiB ring: small-ring fixture half");
        let sub = default_ctrl(7, MEMBER_RING_BYTES).unwrap();
        assert_eq!(sub.expected, 7, "item-6 selective EXPECTED allowed");
        assert!(default_ctrl(0, MEMBER_RING_BYTES).is_err());
        assert!(default_ctrl(513, MEMBER_RING_BYTES).is_err());
    }

    #[test]
    fn attach_subset_validates_before_load() {
        // Item 6: slot/EXPECTED validation precedes the fd budget
        // and load — these fail offline (no object needed): empty
        // slots, slot 512, and EXPECTED != slots.len() (the
        // retire equation counts attached members; mismatch fails
        // fast here, never silently in BPF).
        use std::ffi::CString;
        let exe = CString::new("/nonexistent").unwrap();
        let obj = std::path::Path::new("/nonexistent.o");
        let ctrl4 = default_ctrl(4, MEMBER_RING_BYTES).unwrap();
        let ctrl5 = default_ctrl(5, MEMBER_RING_BYTES).unwrap();
        assert!(attach_members_subset(obj, &exe, 0, 1, &ctrl4, &[]).is_err());
        assert!(attach_members_subset(obj, &exe, 0, 1, &ctrl4, &[0, 512]).is_err());
        assert!(attach_members_subset(obj, &exe, 0, 1, &ctrl5, &[0, 1, 2, 3]).is_err());
    }
    fn source_root_fixture(name: &str, section: &str) -> PreparedProg {
        PreparedProg {
            name: name.to_owned(),
            section: section.to_owned(),
            is_return: false,
            insns: Vec::new(),
            map_fixups: vec![MapFixup {
                insn_off: 0,
                map: "ADMIT".to_owned(),
            }],
            subprogs: Vec::new(),
        }
    }
    fn source_half_fixture() -> Prepared {
        Prepared {
            progs: vec![
                source_root_fixture("source_reg_in", "fentry/uprobe_register"),
                source_root_fixture("source_reg_out", "fexit/uprobe_register"),
                source_root_fixture("attr_exit", "raw_tracepoint/sched_process_exit"),
                source_root_fixture("attr_exec", "raw_tracepoint/sched_process_exec"),
            ],
            maps: Vec::new(),
        }
    }
    fn source_map_fixtures() -> (std::collections::BTreeMap<&'static str, OwnedFd>, Loaded) {
        fn leak(name: &'static str) -> String {
            name.to_owned()
        }
        let owned: std::collections::BTreeMap<&'static str, OwnedFd> = [
            "REL",
            "SOURCE_GUARD",
            "SOURCE_REQUEST",
            "SOURCE_PAIR",
            "SOURCE_DOMAIN",
            "SOURCE_OBSERVER",
            "ITER_SLOT",
            "ATTR_STATE",
            "SOURCE_CONFIG",
        ]
        .into_iter()
        .map(|name| (name, model_fd()))
        .collect();
        let legacy = Loaded {
            progs: std::collections::HashMap::new(),
            maps: ["ADMIT", "CONFIG", "MEMBERS", "NAMESPACE"]
                .into_iter()
                .map(|name| (leak(name), model_fd()))
                .collect(),
        };
        (owned, legacy)
    }
    #[test]
    fn source_root_load_refuses_before_any_native_effect() {
        use crate::observation_memory::MemoryPool;
        let pool = MemoryPool::new(1 << 20);
        let gate = crate::writer_gate::fake_for_shape_tests(&pool).unwrap();
        let prepared = source_half_fixture();
        let (owned, legacy) = source_map_fixtures();
        // Zero FUNC ID and non-preparing gate refuse before touching roots.
        assert!(load_source_roots(&prepared, &owned, &legacy, 0, &gate).is_err());
        let spent = crate::writer_gate::fake_for_shape_tests(&pool).unwrap();
        assert!(spent.open().is_err());
        assert!(!spent.preparing());
        assert!(load_source_roots(&prepared, &owned, &legacy, 7, &spent).is_err());
        // Root-count, selection, return-mode, callback-BTF and ADMIT axes.
        let mut short = source_half_fixture();
        short.progs.pop();
        assert!(load_source_roots(&short, &owned, &legacy, 7, &gate).is_err());
        let mut renamed = source_half_fixture();
        renamed.progs[0].name = "observation_entry".to_owned();
        assert!(load_source_roots(&renamed, &owned, &legacy, 7, &gate).is_err());
        let mut ret = source_half_fixture();
        ret.progs[1].is_return = true;
        assert!(load_source_roots(&ret, &owned, &legacy, 7, &gate).is_err());
        let mut callback = source_half_fixture();
        callback.progs[2].subprogs.push(SubprogInfo {
            name: "cb".to_owned(),
            insn_off: 0,
            is_callback: true,
        });
        assert!(load_source_roots(&callback, &owned, &legacy, 7, &gate).is_err());
        let mut no_admit = source_half_fixture();
        no_admit.progs[3].map_fixups.clear();
        assert!(load_source_roots(&no_admit, &owned, &legacy, 7, &gate).is_err());
        // Unreviewed fixup maps and missing owned/legacy maps refuse.
        let mut foreign = source_half_fixture();
        foreign.progs[0].map_fixups.push(MapFixup {
            insn_off: 8,
            map: "PENDING".to_owned(),
        });
        assert!(load_source_roots(&foreign, &owned, &legacy, 7, &gate).is_err());
        let (mut owned, legacy) = source_map_fixtures();
        owned.remove("SOURCE_GUARD");
        assert!(load_source_roots(&prepared, &owned, &legacy, 7, &gate).is_err());
        let (owned, mut legacy) = source_map_fixtures();
        legacy.maps.remove("CONFIG");
        assert!(load_source_roots(&prepared, &owned, &legacy, 7, &gate).is_err());
    }
    #[test]
    fn typed_fixup_table_completes_shared_gate_from_legacy() {
        use std::os::fd::AsRawFd as _;
        fn lite(name: &str) -> MapSpecLite {
            MapSpecLite {
                name: name.to_owned(),
                map_type: 1,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }
        }
        fn prog(name: &str, section: &str, is_return: bool, fixups: &[&str]) -> PreparedProg {
            PreparedProg {
                name: name.to_owned(),
                section: section.to_owned(),
                is_return,
                insns: Vec::new(),
                map_fixups: fixups
                    .iter()
                    .enumerate()
                    .map(|(i, map)| MapFixup {
                        insn_off: i * 8,
                        map: (*map).to_owned(),
                    })
                    .collect(),
                subprogs: Vec::new(),
            }
        }
        let (owned, legacy) = source_map_fixtures();
        let prepared = Prepared {
            progs: vec![
                prog("typed_entry", "uprobe", false, &["REL", "ADMIT"]),
                prog(
                    "typed_return",
                    "uretprobe",
                    true,
                    &["REL", "ADMIT", "CONFIG"],
                ),
            ],
            maps: vec![lite("REL")],
        };
        let table = collect_typed_fixup_maps(&prepared, &owned, &legacy).unwrap();
        // Owned REL plus fixup-completed ADMIT/CONFIG from the legacy half.
        assert_eq!(table.len(), 3);
        assert!(table.contains_key("REL"));
        assert!(table.contains_key("ADMIT"));
        assert!(table.contains_key("CONFIG"));
        // Duplicated FDs, not aliases of the owners' FDs.
        assert_ne!(table["REL"].as_raw_fd(), owned["REL"].as_raw_fd());
        assert_ne!(table["ADMIT"].as_raw_fd(), legacy.maps["ADMIT"].as_raw_fd());
        // A listed-but-absent owned name refuses the whole table.
        let mut missing = prepared.clone();
        missing.maps.push(lite("NOPE"));
        assert!(collect_typed_fixup_maps(&missing, &owned, &legacy).is_err());
        // A fixup-only name absent from both halves refuses too.
        let mut missing2 = prepared.clone();
        missing2.progs[0].map_fixups.push(MapFixup {
            insn_off: 16,
            map: "NOPE2".to_owned(),
        });
        assert!(collect_typed_fixup_maps(&missing2, &owned, &legacy).is_err());
    }

    // ---- Task23A unattached-seam fixtures and scripted boundary ----

    use std::collections::VecDeque;
    use std::sync::Mutex;

    static TASK23A_FD_LOCK: Mutex<()> = Mutex::new(());

    fn task23a_lock() -> std::sync::MutexGuard<'static, ()> {
        TASK23A_FD_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn task23a_artifact() -> ArtifactPins {
        ArtifactPins {
            sha256: [7u8; 32],
            len: 1234,
        }
    }

    /// Complete source-map fixtures: all 20 owned names plus the 4
    /// legacy join names, derived from the allowlist itself so the
    /// fixture cannot drift from it. Reaches past the missing-map
    /// refusals that stop the older 9-map fixtures.
    fn source_map_fixtures_complete() -> (std::collections::BTreeMap<&'static str, OwnedFd>, Loaded)
    {
        let mut owned = std::collections::BTreeMap::new();
        let mut legacy_maps = HashMap::new();
        for name in SOURCE_FIXUP_MAPS {
            if matches!(name, "CONFIG" | "MEMBERS" | "NAMESPACE" | "ADMIT") {
                legacy_maps.insert(name.to_owned(), model_fd());
            } else {
                owned.insert(name, model_fd());
            }
        }
        (
            owned,
            Loaded {
                progs: HashMap::new(),
                maps: legacy_maps,
            },
        )
    }

    /// Source root with valid ld_imm64 sites (one 16-byte slot per
    /// fixup map, src 0, reserved bytes clear).
    fn source_root_loaded_fixture(
        name: &str,
        section: &str,
        is_return: bool,
        fixup_maps: &[&str],
    ) -> PreparedProg {
        let mut insns = vec![0u8; fixup_maps.len() * 16];
        for (i, _) in fixup_maps.iter().enumerate() {
            insns[i * 16] = BPF_LD_IMM64;
        }
        PreparedProg {
            name: name.to_owned(),
            section: section.to_owned(),
            is_return,
            insns,
            map_fixups: fixup_maps
                .iter()
                .enumerate()
                .map(|(i, map)| MapFixup {
                    insn_off: i * 16,
                    map: (*map).to_owned(),
                })
                .collect(),
            subprogs: vec![SubprogInfo {
                name: name.to_owned(),
                insn_off: 0,
                is_callback: false,
            }],
        }
    }

    fn source_half_loaded_fixture() -> Prepared {
        Prepared {
            progs: vec![
                source_root_loaded_fixture(
                    "source_reg_in",
                    "fentry/uprobe_register",
                    false,
                    &["ADMIT"],
                ),
                source_root_loaded_fixture(
                    "source_reg_out",
                    "fexit/uprobe_register",
                    false,
                    &["ADMIT"],
                ),
                source_root_loaded_fixture(
                    "attr_exit",
                    "raw_tracepoint/sched_process_exit",
                    false,
                    &["ADMIT"],
                ),
                source_root_loaded_fixture(
                    "attr_exec",
                    "raw_tracepoint/sched_process_exec",
                    false,
                    &["ADMIT"],
                ),
            ],
            maps: Vec::new(),
        }
    }

    fn legacy_pair_fixture() -> Prepared {
        Prepared {
            progs: vec![
                source_root_loaded_fixture("observation_entry", "uprobe", false, &["ADMIT"]),
                PreparedProg {
                    subprogs: vec![SubprogInfo {
                        name: "query_return".to_owned(),
                        insn_off: 0,
                        is_callback: true,
                    }],
                    ..source_root_loaded_fixture(
                        "observation_return",
                        "uretprobe",
                        true,
                        &["ADMIT"],
                    )
                },
            ],
            maps: Vec::new(),
        }
    }

    fn typed_pair_fixture() -> Prepared {
        Prepared {
            progs: vec![
                source_root_loaded_fixture("typed_entry", "uprobe", false, &["ADMIT"]),
                source_root_loaded_fixture("typed_return", "uretprobe", true, &["ADMIT"]),
            ],
            maps: Vec::new(),
        }
    }

    fn mark_callback(root: &mut PreparedProg) {
        root.subprogs.push(SubprogInfo {
            name: "cb".to_owned(),
            insn_off: 0,
            is_callback: true,
        });
    }

    fn count_singleton_fixture() -> Prepared {
        Prepared {
            progs: vec![source_root_loaded_fixture(
                "count_entry",
                "uprobe",
                false,
                &["ADMIT"],
            )],
            maps: Vec::new(),
        }
    }

    /// Real pipe pair for ownership sentinels: dropping the write end
    /// is observable as EOF on the read end. No fabricated FDs.
    fn sentinel_pipe() -> (std::fs::File, OwnedFd) {
        let (read, write) = UnixStream::pair().unwrap();
        let read: OwnedFd = read.into();
        (read.into(), write.into())
    }

    fn assert_pipe_eof(read: &mut std::fs::File) {
        use std::io::Read as _;
        let mut byte = [0xAAu8; 1];
        assert_eq!(read.read(&mut byte).unwrap(), 0, "FD still open");
    }

    fn assert_fd_open(raw: i32) {
        assert_ne!(
            unsafe { libc::fcntl(raw, libc::F_GETFD) },
            -1,
            "owned FD {raw} closed early"
        );
    }

    /// Remove one verifier-log spill file, returning whether it existed.
    fn take_spill(prog: &str) -> bool {
        let safe: String = prog
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let path = std::env::temp_dir().join(format!(
            "osslscope-verifier-{safe}-{}.log",
            std::process::id()
        ));
        std::fs::remove_file(path).is_ok()
    }

    #[derive(Debug)]
    enum OpEvent {
        LoadAttempt {
            kind: AttemptKind,
            name: String,
            btf_fd: Option<i32>,
            log_len: Option<usize>,
            src1: u8,
            imm32: u32,
        },
        BtfLoad {
            len: usize,
            cap: usize,
        },
        Attest,
        InjectAdmit,
        InfoQuery,
        ThreadCreds,
        AttachLink {
            kind: ossl_bpf_sys::SourceTracingRoot,
        },
    }

    struct LoadScript {
        errno: Option<i32>,
        fd: Option<OwnedFd>,
        true_size: u32,
        log_fill: Vec<u8>,
    }

    impl LoadScript {
        fn ok(fd: OwnedFd) -> Self {
            Self {
                errno: None,
                fd: Some(fd),
                true_size: 0,
                log_fill: Vec::new(),
            }
        }

        fn err(errno: i32, true_size: u32) -> Self {
            Self {
                errno: Some(errno),
                fd: None,
                true_size,
                log_fill: Vec::new(),
            }
        }

        /// Distinctive bytes the script writes into the real attempt
        /// buffer, proving the retention path keeps actual contents.
        fn fill(mut self, bytes: &[u8]) -> Self {
            self.log_fill = bytes.to_vec();
            self
        }

        fn true_size(mut self, size: u32) -> Self {
            self.true_size = size;
            self
        }
    }

    /// Scripted boundary: every effect is a queued outcome, every call
    /// is recorded. An empty queue panics, so tests prove exact call
    /// counts. Decisions (retry, order, ownership) stay in real code.
    struct ScriptOps {
        events: std::cell::RefCell<Vec<OpEvent>>,
        loads: std::cell::RefCell<VecDeque<LoadScript>>,
        btfs: std::cell::RefCell<VecDeque<(std::io::Result<OwnedFd>, Vec<u8>)>>,
        attests: std::cell::RefCell<VecDeque<std::io::Result<()>>>,
        injects: std::cell::RefCell<VecDeque<std::io::Result<OwnedFd>>>,
        infos: std::cell::RefCell<VecDeque<std::io::Result<ossl_bpf_sys::ProgramInfoSummary>>>,
        creds_list: std::cell::RefCell<VecDeque<std::io::Result<ossl_bpf_sys::ThreadCredentials>>>,
        links: std::cell::RefCell<VecDeque<std::io::Result<OwnedFd>>>,
    }

    impl ScriptOps {
        fn new() -> Self {
            Self {
                events: std::cell::RefCell::new(Vec::new()),
                loads: std::cell::RefCell::new(VecDeque::new()),
                btfs: std::cell::RefCell::new(VecDeque::new()),
                attests: std::cell::RefCell::new(VecDeque::new()),
                injects: std::cell::RefCell::new(VecDeque::new()),
                infos: std::cell::RefCell::new(VecDeque::new()),
                creds_list: std::cell::RefCell::new(VecDeque::new()),
                links: std::cell::RefCell::new(VecDeque::new()),
            }
        }

        fn events(&self) -> Vec<OpEvent> {
            std::mem::take(&mut *self.events.borrow_mut())
        }

        /// Every queued outcome must be consumed: leftover scripts
        /// hide unexecuted branches, so tests assert exhaustion.
        fn assert_exhausted(&self) {
            assert!(self.loads.borrow().is_empty(), "unused load scripts");
            assert!(self.btfs.borrow().is_empty(), "unused btf scripts");
            assert!(self.attests.borrow().is_empty(), "unused attest scripts");
            assert!(self.injects.borrow().is_empty(), "unused inject scripts");
            assert!(self.infos.borrow().is_empty(), "unused info scripts");
            assert!(self.creds_list.borrow().is_empty(), "unused creds scripts");
            assert!(self.links.borrow().is_empty(), "unused link scripts");
        }
    }

    impl LoadBoundaryOps for ScriptOps {
        fn load_attempt(
            &self,
            kind: AttemptKind,
            name: &str,
            insns: &[u8],
            btf_fd: Option<i32>,
            log: Option<&mut [u8]>,
        ) -> ossl_bpf_sys::ProgLoadAttempt {
            // The real fixup ran before this boundary: every referenced
            // site carries the pseudo-map-FD mark. Record the first
            // site's rewritten bytes as evidence.
            let (src1, imm32) = if insns.len() >= 8 {
                (
                    insns[1],
                    u32::from_le_bytes(insns[4..8].try_into().unwrap()),
                )
            } else {
                (0xFF, 0xFFFF_FFFF)
            };
            // A supplied BTF FD must be live at the attempt: the guard
            // owns it across the whole quiet/logged pair.
            if let Some(fd) = btf_fd {
                assert_ne!(
                    unsafe { libc::fcntl(fd, libc::F_GETFD) },
                    -1,
                    "BTF FD closed before attempt"
                );
            }
            let log_len = log.as_ref().map(|buffer| buffer.len());
            self.events.borrow_mut().push(OpEvent::LoadAttempt {
                kind,
                name: name.to_owned(),
                btf_fd,
                log_len,
                src1,
                imm32,
            });
            let script = self.loads.borrow_mut().pop_front().expect("load script");
            if let Some(buffer) = log {
                let fill = &script.log_fill[..script.log_fill.len().min(buffer.len())];
                buffer[..fill.len()].copy_from_slice(fill);
            } else {
                assert!(
                    script.log_fill.is_empty(),
                    "quiet attempt takes no log bytes"
                );
            }
            ossl_bpf_sys::ProgLoadAttempt {
                result: match (script.errno, script.fd) {
                    (None, Some(fd)) => Ok(fd),
                    (Some(errno), None) => Err(std::io::Error::from_raw_os_error(errno)),
                    _ => panic!("load script shape"),
                },
                log_true_size: script.true_size,
            }
        }

        fn btf_load(&self, btf: &[u8], log_cap: usize) -> (std::io::Result<OwnedFd>, Vec<u8>) {
            self.events.borrow_mut().push(OpEvent::BtfLoad {
                len: btf.len(),
                cap: log_cap,
            });
            self.btfs.borrow_mut().pop_front().expect("btf script")
        }

        fn attest(&self, _program: &OwnedFd) -> std::io::Result<()> {
            self.events.borrow_mut().push(OpEvent::Attest);
            self.attests
                .borrow_mut()
                .pop_front()
                .expect("attest script")
        }

        fn inject_admit(
            &self,
            _gate: &crate::writer_gate::WriterGate,
            _spec: &MapSpecLite,
        ) -> std::io::Result<OwnedFd> {
            self.events.borrow_mut().push(OpEvent::InjectAdmit);
            self.injects
                .borrow_mut()
                .pop_front()
                .expect("inject script")
        }

        fn info_query(
            &self,
            _program: &OwnedFd,
        ) -> std::io::Result<ossl_bpf_sys::ProgramInfoSummary> {
            self.events.borrow_mut().push(OpEvent::InfoQuery);
            self.infos.borrow_mut().pop_front().expect("info script")
        }

        fn thread_creds(&self) -> std::io::Result<ossl_bpf_sys::ThreadCredentials> {
            self.events.borrow_mut().push(OpEvent::ThreadCreds);
            self.creds_list
                .borrow_mut()
                .pop_front()
                .expect("creds script")
        }

        fn attach_link(
            &self,
            _program: &OwnedFd,
            kind: ossl_bpf_sys::SourceTracingRoot,
        ) -> std::io::Result<OwnedFd> {
            self.events.borrow_mut().push(OpEvent::AttachLink { kind });
            self.links.borrow_mut().pop_front().expect("link script")
        }
    }

    fn script_summary(prog_id: u32) -> ossl_bpf_sys::ProgramInfoSummary {
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

    fn script_creds() -> ossl_bpf_sys::ThreadCredentials {
        // Effective CAP_SYS_ADMIN (bit 21, set 0): query privilege.
        ossl_bpf_sys::ThreadCredentials {
            caps: [[1 << 21, 0, 0], [0, 0, 0]],
            euid: 1000,
            tid: 4242,
            userns_dev: 1,
            userns_ino: 2,
        }
    }

    #[test]
    fn task23a_complete_fixtures_cover_the_fixup_surface() {
        let (owned, legacy) = source_map_fixtures_complete();
        assert_eq!(owned.len(), 20);
        assert_eq!(legacy.maps.len(), 4);
        for name in SOURCE_FIXUP_MAPS {
            let found = owned.contains_key(name) || legacy.maps.contains_key(name);
            assert!(found, "fixup surface name missing: {name}");
        }
        assert!(legacy.maps.contains_key("ADMIT"));
        assert!(owned.contains_key("REL"));
        assert!(owned.contains_key("SOURCE_CONFIG"));
    }

    #[test]
    fn task23a_audit_accepts_exact_map_fd_rewrites() {
        let mut before = vec![0u8; 32];
        before[0] = BPF_LD_IMM64;
        before[16] = BPF_LD_IMM64;
        let mut after = before.clone();
        after[1] = BPF_PSEUDO_MAP_FD << 4;
        after[4..8].copy_from_slice(&1234u32.to_le_bytes());
        after[17] = BPF_PSEUDO_MAP_FD << 4;
        after[20..24].copy_from_slice(&5678u32.to_le_bytes());
        let entries = audit_fixup_image(
            &before,
            &after,
            &[
                FixupSite {
                    insn_off: 0,
                    role: ImageChangeRole::MapFd {
                        map: "ADMIT".to_owned(),
                        fd: 1234,
                    },
                },
                FixupSite {
                    insn_off: 16,
                    role: ImageChangeRole::MapFd {
                        map: "REL".to_owned(),
                        fd: 5678,
                    },
                },
            ],
        )
        .unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].spans, vec![(1, 1), (4, 4)]);
        assert_eq!(entries[1].spans, vec![(17, 1), (20, 4)]);
    }

    #[test]
    fn task23a_audit_refuses_every_unchecked_change_class() {
        fn images() -> (Vec<u8>, Vec<u8>) {
            let mut before = vec![0u8; 32];
            before[0] = BPF_LD_IMM64;
            before[16] = BPF_LD_IMM64;
            let mut after = before.clone();
            after[1] = BPF_PSEUDO_MAP_FD << 4;
            after[4..8].copy_from_slice(&9u32.to_le_bytes());
            after[17] = BPF_PSEUDO_MAP_FD << 4;
            after[20..24].copy_from_slice(&10u32.to_le_bytes());
            (before, after)
        }
        fn site() -> Vec<FixupSite> {
            vec![
                FixupSite {
                    insn_off: 0,
                    role: ImageChangeRole::MapFd {
                        map: "ADMIT".to_owned(),
                        fd: 9,
                    },
                },
                FixupSite {
                    insn_off: 16,
                    role: ImageChangeRole::MapFd {
                        map: "REL".to_owned(),
                        fd: 10,
                    },
                },
            ]
        }
        let (before, after) = images();
        assert!(audit_fixup_image(&before, &after, &site()).is_ok());
        // Opcode change at a declared site.
        let mut bad = after.clone();
        bad[0] = 0x85;
        assert!(audit_fixup_image(&before, &bad, &site()).is_err());
        // Reserved-bytes change inside the slot.
        let mut bad = after.clone();
        bad[2] = 1;
        assert!(audit_fixup_image(&before, &bad, &site()).is_err());
        // Off-site byte change.
        let mut bad = after.clone();
        bad[31] ^= 1;
        assert!(audit_fixup_image(&before, &bad, &site()).is_err());
        // Length change.
        let mut bad = after.clone();
        bad.push(0);
        assert!(audit_fixup_image(&before, &bad, &site()).is_err());
        // Wrong declared FD.
        let mut wrong = site();
        wrong[0].role = ImageChangeRole::MapFd {
            map: "ADMIT".to_owned(),
            fd: 11,
        };
        assert!(audit_fixup_image(&before, &after, &wrong).is_err());
        // Overlapping declarations.
        let mut overlap = site();
        overlap.push(overlap[0].clone());
        assert!(audit_fixup_image(&before, &after, &overlap).is_err());
        // Misaligned site.
        let misaligned = vec![FixupSite {
            insn_off: 4,
            role: ImageChangeRole::MapFd {
                map: "ADMIT".to_owned(),
                fd: 9,
            },
        }];
        assert!(audit_fixup_image(&before, &after, &misaligned).is_err());
        // Non-ld_imm64 site.
        let mut non_ld = before.clone();
        non_ld[0] = 0x85;
        assert!(audit_fixup_image(&non_ld, &after, &site()).is_err());
    }

    #[test]
    fn task23a_fixup_audit_rejects_patch_roles() {
        // Caller-declared marker/field spans refuse through the fixup
        // interface no matter how well-formed: patch roles validate
        // only through audit_patch_images against admitted kernel
        // configuration, never through declared spans.
        let before = vec![0u8; 32];
        let mut after = before.clone();
        after[4..8].copy_from_slice(&4242u32.to_le_bytes());
        after[12..14].copy_from_slice(&[3u8, 4u8]);
        for role in [
            ImageChangeRole::MarkerKfunc {
                marker: "bpf_iter_task_vma_new".to_owned(),
                spans: vec![ImageSpan {
                    start: 4,
                    before: vec![0, 0, 0, 0],
                    after: 4242u32.to_le_bytes().to_vec(),
                }],
            },
            ImageChangeRole::ApprovedField {
                field: "vm_start".to_owned(),
                spans: vec![ImageSpan {
                    start: 12,
                    before: vec![0, 0],
                    after: vec![3, 4],
                }],
            },
        ] {
            let sites = vec![FixupSite { insn_off: 0, role }];
            let error = audit_fixup_image(&before, &after, &sites).unwrap_err();
            assert!(
                format!("{error:#}").contains("audit_patch_images"),
                "{error:#}"
            );
        }
    }

    /// Admitted patch configuration: nonzero kfunc IDs, in-extent
    /// field offsets, 64-byte VMA.
    fn task23a_patch_configuration() -> [u32; 13] {
        [15, 17, 19, 0, 8, 16, 24, 32, 8, 64, 7, 320, 8]
    }

    /// Blessed helper owner carrying all nine marker slots (kfunc
    /// call shapes first, then mov32 field shapes) inside one helper
    /// body spanning the whole image, plus trailing exits.
    fn task23a_patch_fixture() -> PreparedProg {
        let mut insns = vec![0u8; 16 * 8];
        for i in 0..3 {
            insns[i * 8] = 0x85;
            insns[i * 8 + 4..i * 8 + 8].copy_from_slice(&(0x7f001 + i as u32).to_le_bytes());
        }
        for i in 0..6 {
            let base = (3 + i) * 8;
            insns[base] = 0xb7;
            insns[base + 1] = 1 + i as u8;
            insns[base + 4..base + 8].copy_from_slice(&(0x6f001 + i as u32).to_le_bytes());
        }
        for i in 9..16 {
            insns[i * 8] = 0x95;
        }
        PreparedProg {
            name: "source_reg_out".to_owned(),
            section: "fexit/uprobe_register".to_owned(),
            is_return: false,
            insns,
            map_fixups: Vec::new(),
            subprogs: vec![SubprogInfo {
                name: "current_source_at".to_owned(),
                insn_off: 0,
                is_callback: false,
            }],
        }
    }

    #[test]
    fn task23a_patch_audit_accepts_real_patcher_output() {
        let configuration = task23a_patch_configuration();
        let before = task23a_patch_fixture();
        let mut progs = vec![before.clone()];
        patch_source_configuration(&configuration, &mut progs).unwrap();
        let after = progs.into_iter().next().unwrap();
        let entries = audit_patch_images(&before, &after, &configuration).unwrap();
        assert_eq!(entries.len(), 9);
        // Canonical identity names derive from slot order.
        let names: Vec<String> = entries
            .iter()
            .map(|entry| match &entry.role {
                ImageChangeRole::MarkerKfunc { marker, .. } => marker.clone(),
                ImageChangeRole::ApprovedField { field, .. } => field.clone(),
                ImageChangeRole::MapFd { .. } => "map".to_owned(),
            })
            .collect();
        assert_eq!(
            names,
            vec![
                "bpf_iter_task_vma_new",
                "bpf_iter_task_vma_next",
                "bpf_iter_task_vma_destroy",
                "vm_start",
                "vm_end",
                "vm_pgoff",
                "vm_flags",
                "vm_file",
                "f_inode",
            ]
        );
        // Kfunc entries carry the call rewrite plus the ID; field
        // entries carry the offset alone.
        assert_eq!(entries[0].spans.len(), 2);
        assert_eq!(entries[3].spans.len(), 1);
        // A non-helper root with identical images audits clean.
        let mut plain = before.clone();
        plain.subprogs.clear();
        plain.name = "source_reg_in".to_owned();
        plain.section = "fentry/uprobe_register".to_owned();
        for i in 0..9 {
            plain.insns[(i * 8 + 4)..(i * 8 + 8)].copy_from_slice(&[0, 0, 0, 0]);
        }
        let entries = audit_patch_images(&plain, &plain, &configuration).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn task23a_marker_scan_sees_only_marker_ranges() {
        // All nine slots: seen.
        assert!(prepared_has_source_markers(&[task23a_patch_fixture()]));
        // Plain immediates (including zero): not markers.
        let plain = source_root_loaded_fixture(
            "source_reg_in",
            "fentry/uprobe_register",
            false,
            &["ADMIT"],
        );
        assert!(!prepared_has_source_markers(&[plain]));
        // One surviving slot among clean roots: seen.
        let mut survivor = task23a_patch_fixture();
        for i in 1..9 {
            survivor.insns[(i * 8 + 4)..(i * 8 + 8)].copy_from_slice(&[0, 0, 0, 0]);
        }
        assert!(prepared_has_source_markers(&[survivor]));
    }

    #[test]
    fn task23a_patch_audit_accepts_colliding_admitted_values() {
        // Legitimate collision control: admitted replacements that
        // numerically overlap marker values are resolved slots, not
        // surviving markers — validated against the admitted
        // configuration, not by shape alone.
        let mut configuration = task23a_patch_configuration();
        configuration[0] = 0x7f001;
        configuration[3] = 0x6f001;
        configuration[9] = 0x70000;
        let before = task23a_patch_fixture();
        let mut progs = vec![before.clone()];
        patch_source_configuration(&configuration, &mut progs).unwrap();
        let after = progs.into_iter().next().unwrap();
        let entries = audit_patch_images(&before, &after, &configuration).unwrap();
        assert_eq!(entries.len(), 9);
    }

    #[test]
    fn task23a_patch_audit_refuses_partial_rewrite() {
        // N9's counterexample: the call nibble rewritten but the
        // marker immediate retained is an incomplete transformation,
        // even though the shape looks resolved.
        let configuration = task23a_patch_configuration();
        let before = task23a_patch_fixture();
        let mut progs = vec![before.clone()];
        patch_source_configuration(&configuration, &mut progs).unwrap();
        let mut partial = progs.into_iter().next().unwrap();
        partial.insns[4..8].copy_from_slice(&0x7f002u32.to_le_bytes());
        assert_eq!(partial.insns[..4], [0x85, 0x20, 0, 0]);
        let error = audit_patch_images(&before, &partial, &configuration).unwrap_err();
        assert!(
            format!("{error:#}").contains("replacement value"),
            "{error:#}"
        );
    }

    #[test]
    fn task23a_patch_audit_refuses_each_bad_transformation() {
        let configuration = task23a_patch_configuration();
        let before = task23a_patch_fixture();
        let mut progs = vec![before.clone()];
        patch_source_configuration(&configuration, &mut progs).unwrap();
        let after = progs.into_iter().next().unwrap();
        // Admitted-configuration ranges refuse first.
        let mut bad_config = configuration;
        bad_config[0] = 0;
        assert!(audit_patch_images(&before, &after, &bad_config).is_err());
        let mut bad_config = configuration;
        bad_config[9] = 8;
        assert!(audit_patch_images(&before, &after, &bad_config).is_err());
        // Unblessed owner, marker without helper, unknown identity.
        let mut unblessed = before.clone();
        unblessed.name = "source_reg_in".to_owned();
        unblessed.section = "fentry/uprobe_register".to_owned();
        assert!(audit_patch_images(&unblessed, &after, &configuration).is_err());
        let mut helpless = before.clone();
        helpless.subprogs.clear();
        assert!(audit_patch_images(&helpless, &after, &configuration).is_err());
        let mut unknown = before.clone();
        unknown.insns[4..8].copy_from_slice(&0x7f000u32.to_le_bytes());
        assert!(audit_patch_images(&unknown, &after, &configuration).is_err());
        // Duplicate identity and missing slot.
        let mut dupe = before.clone();
        dupe.insns[12..16].copy_from_slice(&0x7f001u32.to_le_bytes());
        assert!(audit_patch_images(&dupe, &after, &configuration).is_err());
        let mut missing = before.clone();
        missing.insns[4..8].copy_from_slice(&0u32.to_le_bytes());
        assert!(audit_patch_images(&missing, &after, &configuration).is_err());
        // Bad pre-patch shapes.
        let mut kfunc_shape = before.clone();
        kfunc_shape.insns[0] = 0x95;
        assert!(audit_patch_images(&kfunc_shape, &after, &configuration).is_err());
        let mut field_shape = before.clone();
        field_shape.insns[3 * 8 + 1] = 11;
        assert!(audit_patch_images(&field_shape, &after, &configuration).is_err());
        // Wrong replacement values and missing call rewrite.
        let mut bad_id = after.clone();
        bad_id.insns[4..8].copy_from_slice(&21u32.to_le_bytes());
        assert!(audit_patch_images(&before, &bad_id, &configuration).is_err());
        let mut bad_rewrite = after.clone();
        bad_rewrite.insns[1] = 0;
        assert!(audit_patch_images(&before, &bad_rewrite, &configuration).is_err());
        let mut bad_offset = after.clone();
        bad_offset.insns[3 * 8 + 4..3 * 8 + 8].copy_from_slice(&99u32.to_le_bytes());
        assert!(audit_patch_images(&before, &bad_offset, &configuration).is_err());
        // Relabelled-opcode attacks: a changed opcode or destination
        // fails even with the right immediate.
        let mut opcode_swap = after.clone();
        opcode_swap.insns[3 * 8] = 0x85;
        assert!(audit_patch_images(&before, &opcode_swap, &configuration).is_err());
        let mut dst_swap = after.clone();
        dst_swap.insns[3 * 8 + 1] = 9;
        assert!(audit_patch_images(&before, &dst_swap, &configuration).is_err());
        let mut call_opcode = after.clone();
        call_opcode.insns[0] = 0x95;
        assert!(audit_patch_images(&before, &call_opcode, &configuration).is_err());
        // Undeclared changes and non-helper drift refuse.
        let mut stray = after.clone();
        stray.insns[15 * 8] = 0x85;
        assert!(audit_patch_images(&before, &stray, &configuration).is_err());
        let mut plain = before.clone();
        plain.subprogs.clear();
        plain.name = "source_reg_in".to_owned();
        for i in 0..9 {
            plain.insns[(i * 8 + 4)..(i * 8 + 8)].copy_from_slice(&[0, 0, 0, 0]);
        }
        let mut drifted = plain.clone();
        drifted.insns[0] = 0x95;
        assert!(audit_patch_images(&plain, &drifted, &configuration).is_err());
        let mut short = after.clone();
        short.insns.pop();
        assert!(audit_patch_images(&before, &short, &configuration).is_err());
    }

    #[test]
    fn task23a_log_classification_proves_completeness() {
        let (used, verdict) = classify_log(b"AB\0", 3, None);
        assert_eq!(verdict, LogCompleteness::Complete);
        assert_eq!(used, b"AB\0");
        let (used, verdict) = classify_log(b"AB\0XXXX", 3, None);
        assert_eq!(verdict, LogCompleteness::Complete);
        assert_eq!(used, b"AB\0");
        let (used, verdict) = classify_log(b"AB", 9, None);
        assert_eq!(verdict, LogCompleteness::Truncated);
        assert_eq!(used, b"AB");
        let (used, verdict) = classify_log(b"AB\0", 2, None);
        assert_eq!(verdict, LogCompleteness::Indeterminate);
        assert_eq!(used, b"AB");
        let (used, verdict) = classify_log(b"", 0, None);
        assert_eq!(verdict, LogCompleteness::Indeterminate);
        assert!(used.is_empty());
        // A zero true size with real bytes retains the evidence.
        let (used, verdict) = classify_log(b"oops\0\0\0", 0, None);
        assert_eq!(verdict, LogCompleteness::Indeterminate);
        assert_eq!(used, b"oops");
        // ENOSPC with apparently fitting size metadata stays
        // inconclusive, never Complete.
        let (used, verdict) = classify_log(b"AB\0", 3, Some(libc::ENOSPC));
        assert_eq!(verdict, LogCompleteness::Indeterminate);
        assert_eq!(used, b"AB");
        // Other errnos do not disturb a proven-complete log.
        let (used, verdict) = classify_log(b"AB\0", 3, Some(libc::EACCES));
        assert_eq!(verdict, LogCompleteness::Complete);
        assert_eq!(used, b"AB\0");
    }

    #[test]
    fn task23a_map_id_set_check_is_exact() {
        assert!(check_map_id_set(&[40, 41], &[41, 40]).is_ok());
        assert!(check_map_id_set(&[], &[]).is_ok());
        assert!(check_map_id_set(&[40], &[40, 40]).is_err());
        assert!(check_map_id_set(&[40], &[0]).is_err());
        assert!(check_map_id_set(&[40], &[41]).is_err());
        assert!(check_map_id_set(&[40, 41], &[40]).is_err());
        assert!(check_map_id_set(&[40], &[40, 41]).is_err());
    }

    #[test]
    fn task23a_legacy_preflight_pins_the_calibration_pair() {
        assert!(preflight_legacy_pair(&legacy_pair_fixture()).is_ok());
        // Wrong second name refuses before any effect.
        let mut wrong = legacy_pair_fixture();
        wrong.progs[1].name = "observation_entry".to_owned();
        assert!(preflight_legacy_pair(&wrong).is_err());
        // The return root without callback classification is no control.
        let mut no_callback = legacy_pair_fixture();
        no_callback.progs[1].subprogs.clear();
        assert!(preflight_legacy_pair(&no_callback).is_err());
        // Shape violations refuse.
        let mut three = legacy_pair_fixture();
        three.progs.push(three.progs[0].clone());
        assert!(preflight_legacy_pair(&three).is_err());
        let mut swapped = legacy_pair_fixture();
        swapped.progs[0].section = "uretprobe".to_owned();
        assert!(preflight_legacy_pair(&swapped).is_err());
        let mut flipped = legacy_pair_fixture();
        flipped.progs[0].is_return = true;
        assert!(preflight_legacy_pair(&flipped).is_err());
    }

    #[test]
    fn task23a_nine_root_preflight_pins_every_singleton() {
        let legacy = legacy_pair_fixture();
        let registration = source_half_loaded_fixture();
        let typed = typed_pair_fixture();
        let count = count_singleton_fixture();
        assert!(preflight_nine_roots(&legacy, &registration, &typed, &count).is_ok());
        // Each half fails independently.
        let mut bad_legacy = legacy.clone();
        bad_legacy.progs[1].name = "typed_entry".to_owned();
        assert!(preflight_nine_roots(&bad_legacy, &registration, &typed, &count).is_err());
        let mut short = registration.clone();
        short.progs.pop();
        assert!(preflight_nine_roots(&legacy, &short, &typed, &count).is_err());
        let mut dup = registration.clone();
        dup.progs[3] = dup.progs[0].clone();
        assert!(preflight_nine_roots(&legacy, &dup, &typed, &count).is_err());
        let mut callback = registration.clone();
        callback.progs[0].subprogs.push(SubprogInfo {
            name: "cb".to_owned(),
            insn_off: 0,
            is_callback: true,
        });
        assert!(preflight_nine_roots(&legacy, &callback, &typed, &count).is_err());
        let mut typed_callback = typed.clone();
        typed_callback.progs[1].subprogs.push(SubprogInfo {
            name: "cb".to_owned(),
            insn_off: 0,
            is_callback: true,
        });
        assert!(preflight_nine_roots(&legacy, &registration, &typed_callback, &count).is_err());
        let mut swapped = typed.clone();
        swapped.progs[0].is_return = true;
        swapped.progs[1].is_return = false;
        assert!(preflight_nine_roots(&legacy, &registration, &swapped, &count).is_err());
        let mut count_callback = count.clone();
        count_callback.progs[0].subprogs.push(SubprogInfo {
            name: "cb".to_owned(),
            insn_off: 0,
            is_callback: true,
        });
        assert!(preflight_nine_roots(&legacy, &registration, &typed, &count_callback).is_err());
        let mut count_section = count.clone();
        count_section.progs[0].section = "uretprobe".to_owned();
        assert!(preflight_nine_roots(&legacy, &registration, &typed, &count_section).is_err());
    }

    #[test]
    fn task23a_typed_split_partitions_six_roots_by_route() {
        // The real partition the diagnostic consumes: registration
        // roots and typed roots separate by name, with typed shapes
        // enforced. A wrong-half loop input starts here.
        let half = Prepared {
            progs: vec![
                source_root_loaded_fixture(
                    "source_reg_in",
                    "fentry/uprobe_register",
                    false,
                    &["ADMIT"],
                ),
                source_root_loaded_fixture(
                    "source_reg_out",
                    "fexit/uprobe_register",
                    false,
                    &["ADMIT"],
                ),
                source_root_loaded_fixture(
                    "attr_exit",
                    "raw_tracepoint/sched_process_exit",
                    false,
                    &["ADMIT"],
                ),
                source_root_loaded_fixture(
                    "attr_exec",
                    "raw_tracepoint/sched_process_exec",
                    false,
                    &["ADMIT"],
                ),
                source_root_loaded_fixture("typed_entry", "uprobe", false, &["ADMIT"]),
                source_root_loaded_fixture("typed_return", "uretprobe", true, &["ADMIT"]),
            ],
            maps: Vec::new(),
        };
        let (registration, typed) = split_typed_preparation(half).unwrap();
        let mut reg_names: Vec<&str> = registration.progs.iter().map(|p| p.name.as_str()).collect();
        reg_names.sort_unstable();
        assert_eq!(
            reg_names,
            ["attr_exec", "attr_exit", "source_reg_in", "source_reg_out"]
        );
        let mut typed_names: Vec<&str> = typed.progs.iter().map(|p| p.name.as_str()).collect();
        typed_names.sort_unstable();
        assert_eq!(typed_names, ["typed_entry", "typed_return"]);
        // A mistyped root refuses instead of crossing halves.
        let bad = Prepared {
            progs: vec![
                source_root_loaded_fixture("typed_entry", "uprobe", false, &["ADMIT"]),
                source_root_loaded_fixture("typed_return", "uprobe", false, &["ADMIT"]),
            ],
            maps: Vec::new(),
        };
        assert!(split_typed_preparation(bad).is_err());
    }

    /// Drive the single-root seam with an empty script: any boundary
    /// call panics, proving refusals happen before native effects.
    fn drive_seam_refusal(
        root: &PreparedProg,
        attach_btf_id: u32,
    ) -> (String, LoadStage, Vec<OpEvent>) {
        use crate::observation_memory::MemoryPool;
        let pool = MemoryPool::new(1 << 20);
        let gate = crate::writer_gate::fake_for_shape_tests(&pool).unwrap();
        let (owned, legacy) = source_map_fixtures_complete();
        let ops = ScriptOps::new();
        let mut record =
            LoadDiagnostics::unattempted(&root.name, &root.section, task23a_artifact());
        let error = load_source_root_inner(
            root,
            &owned,
            &legacy,
            attach_btf_id,
            &gate,
            Some(&mut record),
            Some(&ops),
        )
        .unwrap_err();
        ops.assert_exhausted();
        (format!("{error:#}"), record.stage, ops.events())
    }

    #[test]
    fn task23a_seam_refuses_each_missing_prerequisite_first() {
        let _lock = task23a_lock();
        let valid = source_root_loaded_fixture(
            "source_reg_in",
            "fentry/uprobe_register",
            false,
            &["ADMIT", "REL"],
        );
        // A zero FUNC ID refuses first. (The non-preparing-gate
        // refusal stays covered by the pre-existing group-level
        // test: minting a spent gate needs gate.open(), which
        // issues real rejected BPF syscalls.)
        let (error, stage, events) = drive_seam_refusal(&valid, 0);
        assert!(error.contains("nonzero FUNC ID"), "{error}");
        assert_eq!(stage, LoadStage::Preflight);
        assert!(events.is_empty());
        // Unselected roots refuse at classification.
        let renamed = source_root_loaded_fixture(
            "observation_entry",
            "fentry/uprobe_register",
            false,
            &["ADMIT"],
        );
        let (error, stage, events) = drive_seam_refusal(&renamed, 7);
        assert!(error.contains("unselected source root"), "{error}");
        assert_eq!(stage, LoadStage::Preflight);
        assert!(events.is_empty());
        // Return mode, callbacks, and missing ADMIT refuse per root.
        let mut ret = valid.clone();
        ret.is_return = true;
        let (error, _, events) = drive_seam_refusal(&ret, 7);
        assert!(error.contains("forbids return mode"), "{error}");
        assert!(events.is_empty());
        let mut callback = valid.clone();
        mark_callback(&mut callback);
        let (error, _, events) = drive_seam_refusal(&callback, 7);
        assert!(error.contains("forbids callback BTF"), "{error}");
        assert!(events.is_empty());
        let mut no_admit =
            source_root_loaded_fixture("source_reg_in", "fentry/uprobe_register", false, &["REL"]);
        no_admit.map_fixups.clear();
        let (error, _, events) = drive_seam_refusal(&no_admit, 7);
        assert!(error.contains("lacks shared-gate fixup"), "{error}");
        assert!(events.is_empty());
        // Unreviewed and unresolvable fixups refuse at the fixup stage.
        let mut foreign = source_root_loaded_fixture(
            "source_reg_in",
            "fentry/uprobe_register",
            false,
            &["ADMIT", "REL"],
        );
        foreign.map_fixups[1].map = "PENDING".to_owned();
        let (error, stage, events) = drive_seam_refusal(&foreign, 7);
        assert!(error.contains("unreviewed map"), "{error}");
        assert_eq!(stage, LoadStage::Fixup);
        assert!(events.is_empty());
    }

    #[test]
    fn task23a_seam_refuses_callbacks_for_all_four_roots() {
        let _lock = task23a_lock();
        for (name, section) in [
            ("source_reg_in", "fentry/uprobe_register"),
            ("source_reg_out", "fexit/uprobe_register"),
            ("attr_exit", "raw_tracepoint/sched_process_exit"),
            ("attr_exec", "raw_tracepoint/sched_process_exec"),
        ] {
            let mut root = source_root_loaded_fixture(name, section, false, &["ADMIT"]);
            mark_callback(&mut root);
            let (error, stage, events) = drive_seam_refusal(&root, 7);
            assert!(error.contains("forbids callback BTF"), "{name}: {error}");
            assert_eq!(stage, LoadStage::Preflight);
            assert!(events.is_empty());
        }
    }

    #[test]
    fn task23a_seam_requires_complete_map_set_not_just_references() {
        let _lock = task23a_lock();
        use crate::observation_memory::MemoryPool;
        for (remove_owned, remove_legacy, expected) in [
            (
                Some("SOURCE_GUARD"),
                None,
                "source load missing owned map SOURCE_GUARD",
            ),
            (
                None,
                Some("NAMESPACE"),
                "source load missing legacy map NAMESPACE",
            ),
        ] {
            let pool = MemoryPool::new(1 << 20);
            let gate = crate::writer_gate::fake_for_shape_tests(&pool).unwrap();
            let (mut owned, mut legacy) = source_map_fixtures_complete();
            if let Some(name) = remove_owned {
                owned.remove(name);
            }
            if let Some(name) = remove_legacy {
                legacy.maps.remove(name);
            }
            // The root references only ADMIT: the missing map is never
            // named by this root, yet the shared presence check refuses
            // before classification with zero boundary effects.
            let root = source_root_loaded_fixture(
                "source_reg_in",
                "fentry/uprobe_register",
                false,
                &["ADMIT"],
            );
            let ops = ScriptOps::new();
            let mut record =
                LoadDiagnostics::unattempted(&root.name, &root.section, task23a_artifact());
            let error = load_source_root_inner(
                &root,
                &owned,
                &legacy,
                4242,
                &gate,
                Some(&mut record),
                Some(&ops),
            )
            .unwrap_err();
            ops.assert_exhausted();
            assert!(format!("{error:#}").contains(expected), "{error:#}");
            assert_eq!(record.stage, LoadStage::Preflight);
            assert!(ops.events().is_empty());
        }
    }

    #[test]
    fn task23a_seam_refuses_malformed_fixup_sites() {
        let _lock = task23a_lock();
        // Misaligned site.
        let mut root = source_root_loaded_fixture(
            "source_reg_in",
            "fentry/uprobe_register",
            false,
            &["ADMIT", "ADMIT"],
        );
        root.map_fixups[1].insn_off = 4;
        let (error, stage, events) = drive_seam_refusal(&root, 7);
        assert!(error.contains("misaligned"), "{error}");
        assert_eq!(stage, LoadStage::Fixup);
        assert!(events.is_empty());
        // Out-of-range site.
        let mut root = source_root_loaded_fixture(
            "source_reg_in",
            "fentry/uprobe_register",
            false,
            &["ADMIT"],
        );
        root.map_fixups[0].insn_off = usize::MAX - 7;
        let (error, stage, events) = drive_seam_refusal(&root, 7);
        assert!(error.contains("out of range"), "{error}");
        assert_eq!(stage, LoadStage::Fixup);
        assert!(events.is_empty());
        // Non-ld_imm64 site.
        let mut root = source_root_loaded_fixture(
            "source_reg_in",
            "fentry/uprobe_register",
            false,
            &["ADMIT"],
        );
        root.insns[0] = 0x85;
        let (error, stage, _) = drive_seam_refusal(&root, 7);
        assert!(error.contains("non-ld_imm64"), "{error}");
        assert_eq!(stage, LoadStage::Fixup);
        // Already-relocated site (src nibble set).
        let mut root = source_root_loaded_fixture(
            "source_reg_in",
            "fentry/uprobe_register",
            false,
            &["ADMIT"],
        );
        root.insns[1] = BPF_PSEUDO_MAP_FD << 4;
        let (error, stage, _) = drive_seam_refusal(&root, 7);
        assert!(error.contains("non-ld_imm64"), "{error}");
        assert_eq!(stage, LoadStage::Fixup);
    }

    #[test]
    fn task23a_typed_loader_refuses_callbacks_for_both_roots() {
        let _lock = task23a_lock();
        use crate::observation_memory::MemoryPool;
        // Callback on the first root: immediate refusal, zero effects.
        let pool = MemoryPool::new(1 << 20);
        let gate = crate::writer_gate::fake_for_shape_tests(&pool).unwrap();
        let (owned, legacy) = source_map_fixtures_complete();
        let mut pair = typed_pair_fixture();
        mark_callback(&mut pair.progs[0]);
        let ops = ScriptOps::new();
        let mut records = Vec::new();
        let error = load_typed_borrowed_inner(
            &pair,
            &owned,
            &legacy,
            &gate,
            Some(DiagCtx {
                records: &mut records,
                artifact: task23a_artifact(),
            }),
            Some(&ops),
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("forbids callback BTF"),
            "{error:#}"
        );
        assert!(ops.events().is_empty());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].root, "typed_entry");
        assert!(records[0].error.is_some());
        ops.assert_exhausted();
        // Callback on the second root: the first root loads, then the
        // refusal drops it (fail-fast) without touching the boundary
        // for the refused root.
        let pool = MemoryPool::new(1 << 20);
        let gate = crate::writer_gate::fake_for_shape_tests(&pool).unwrap();
        let (owned, legacy) = source_map_fixtures_complete();
        let mut pair = typed_pair_fixture();
        mark_callback(&mut pair.progs[1]);
        let ops = ScriptOps::new();
        let (mut entry_read, entry_write) = sentinel_pipe();
        ops.loads
            .borrow_mut()
            .push_back(LoadScript::ok(entry_write));
        ops.attests.borrow_mut().push_back(Ok(()));
        ops.creds_list.borrow_mut().push_back(Ok(script_creds()));
        ops.infos.borrow_mut().push_back(Ok(script_summary(71)));
        ops.creds_list.borrow_mut().push_back(Ok(script_creds()));
        let mut records = Vec::new();
        let error = load_typed_borrowed_inner(
            &pair,
            &owned,
            &legacy,
            &gate,
            Some(DiagCtx {
                records: &mut records,
                artifact: task23a_artifact(),
            }),
            Some(&ops),
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("forbids callback BTF"),
            "{error:#}"
        );
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].root, "typed_entry");
        assert_eq!(records[0].stage, LoadStage::Loaded);
        assert!(records[0].error.is_none());
        assert_eq!(records[1].root, "typed_return");
        assert!(records[1].error.is_some());
        assert_eq!(ops.events().len(), 5);
        ops.assert_exhausted();
        assert_pipe_eof(&mut entry_read);
    }

    #[test]
    fn task23a_seam_quiet_success_owns_exactly_one_fd() {
        let _lock = task23a_lock();
        use crate::observation_memory::MemoryPool;
        let pool = MemoryPool::new(1 << 20);
        let gate = crate::writer_gate::fake_for_shape_tests(&pool).unwrap();
        let (owned, legacy) = source_map_fixtures_complete();
        let root = source_root_loaded_fixture(
            "source_reg_in",
            "fentry/uprobe_register",
            false,
            &["ADMIT", "REL"],
        );
        let ops = ScriptOps::new();
        let (mut prog_read, prog_write) = sentinel_pipe();
        ops.loads.borrow_mut().push_back(LoadScript::ok(prog_write));
        ops.attests.borrow_mut().push_back(Ok(()));
        ops.creds_list.borrow_mut().push_back(Ok(script_creds()));
        ops.infos.borrow_mut().push_back(Ok(script_summary(77)));
        ops.creds_list.borrow_mut().push_back(Ok(script_creds()));
        let mut record =
            LoadDiagnostics::unattempted(&root.name, &root.section, task23a_artifact());
        let program = load_source_root_inner(
            &root,
            &owned,
            &legacy,
            4242,
            &gate,
            Some(&mut record),
            Some(&ops),
        )
        .unwrap();
        // Exactly one quiet load (no log), attestation, and the
        // credential-bracketed info query ran, in order.
        let events = ops.events();
        assert_eq!(events.len(), 5);
        assert!(matches!(
            events[0],
            OpEvent::LoadAttempt { log_len: None, .. }
        ));
        assert!(matches!(events[1], OpEvent::Attest));
        assert!(matches!(events[2], OpEvent::ThreadCreds));
        assert!(matches!(events[3], OpEvent::InfoQuery));
        assert!(matches!(events[4], OpEvent::ThreadCreds));
        // The real fixup rewrote the first site before the boundary.
        ops.assert_exhausted();
        if let OpEvent::LoadAttempt {
            src1,
            imm32,
            kind,
            name,
            btf_fd,
            ..
        } = &events[0]
        {
            assert_eq!(*src1, BPF_PSEUDO_MAP_FD << 4);
            assert_eq!(*imm32, legacy.maps["ADMIT"].as_raw_fd() as u32);
            assert_eq!(name, "source_reg_in");
            assert_eq!(*btf_fd, None);
            assert_eq!(
                *kind,
                AttemptKind::SourceRegistration(ossl_bpf_sys::SourceTracingRoot::Enter, 4242)
            );
        } else {
            panic!("first event shape");
        }
        assert_eq!(record.stage, LoadStage::Loaded);
        assert_eq!(record.prog_type, 26);
        assert_eq!(record.expected_attach, 24);
        assert_eq!(record.attach_target, 4242);
        assert_eq!(record.quiet_errno, None);
        assert_eq!(record.logged_errno, None);
        assert_eq!(record.log_completeness, LogCompleteness::NoLogAttempted);
        assert_eq!(record.loaded_id, Some(77));
        assert_eq!(record.fixup_audit.len(), 2);
        assert!(record.error.is_none());
        // The returned program owns its FD; dropping closes it.
        let raw = program.as_raw_fd();
        drop(program);
        assert_pipe_eof(&mut prog_read);
        assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFD) }, -1);
        // Original owners survive.
        for fd in owned.values() {
            assert_fd_open(fd.as_raw_fd());
        }
        for fd in legacy.maps.values() {
            assert_fd_open(fd.as_raw_fd());
        }
    }

    #[test]
    fn task23a_seam_logged_retry_preserves_first_errno() {
        let _lock = task23a_lock();
        use crate::observation_memory::MemoryPool;
        let pool = MemoryPool::new(1 << 20);
        let gate = crate::writer_gate::fake_for_shape_tests(&pool).unwrap();
        let (owned, legacy) = source_map_fixtures_complete();
        let root = source_root_loaded_fixture(
            "attr_exit",
            "raw_tracepoint/sched_process_exit",
            false,
            &["ADMIT"],
        );
        let ops = ScriptOps::new();
        let (mut prog_read, prog_write) = sentinel_pipe();
        ops.loads
            .borrow_mut()
            .push_back(LoadScript::err(libc::EPERM, 0));
        ops.loads.borrow_mut().push_back(LoadScript::ok(prog_write));
        ops.attests.borrow_mut().push_back(Ok(()));
        ops.creds_list.borrow_mut().push_back(Ok(script_creds()));
        ops.infos.borrow_mut().push_back(Ok(script_summary(78)));
        ops.creds_list.borrow_mut().push_back(Ok(script_creds()));
        let mut record =
            LoadDiagnostics::unattempted(&root.name, &root.section, task23a_artifact());
        let program = load_source_root_inner(
            &root,
            &owned,
            &legacy,
            4242,
            &gate,
            Some(&mut record),
            Some(&ops),
        )
        .unwrap();
        let events = ops.events();
        assert_eq!(events.len(), 6);
        assert!(matches!(
            events[0],
            OpEvent::LoadAttempt { log_len: None, .. }
        ));
        // The observed diagnostic uses the 16 MiB logged ceiling.
        assert!(matches!(
            events[1],
            OpEvent::LoadAttempt { log_len: Some(n), .. } if n == 16 << 20
        ));
        for event in &events[0..2] {
            if let OpEvent::LoadAttempt {
                kind, name, btf_fd, ..
            } = event
            {
                assert_eq!(
                    *kind,
                    AttemptKind::Lifecycle(ossl_bpf_sys::LifecycleTracepoint::Exit)
                );
                assert_eq!(name, "attr_exit");
                assert_eq!(*btf_fd, None);
            } else {
                panic!("attempt event shape");
            }
        }
        ops.assert_exhausted();
        assert_eq!(record.stage, LoadStage::Loaded);
        assert_eq!(record.prog_type, 17);
        assert_eq!(record.expected_attach, 0);
        assert_eq!(record.quiet_errno, Some(libc::EPERM));
        assert_eq!(record.logged_errno, None);
        drop(program);
        assert_pipe_eof(&mut prog_read);
    }

    #[test]
    fn task23a_production_path_keeps_the_4mib_ceiling() {
        let _lock = task23a_lock();
        use crate::observation_memory::MemoryPool;
        let pool = MemoryPool::new(1 << 20);
        let gate = crate::writer_gate::fake_for_shape_tests(&pool).unwrap();
        let (owned, legacy) = source_map_fixtures_complete();
        let root = source_root_loaded_fixture(
            "source_reg_out",
            "fexit/uprobe_register",
            false,
            &["ADMIT"],
        );
        let ops = ScriptOps::new();
        let (_prog_read, prog_write) = sentinel_pipe();
        ops.loads
            .borrow_mut()
            .push_back(LoadScript::err(libc::EACCES, 0));
        ops.loads.borrow_mut().push_back(LoadScript::ok(prog_write));
        ops.attests.borrow_mut().push_back(Ok(()));
        // No record: the production ceiling and no info query.
        let program =
            load_source_root_inner(&root, &owned, &legacy, 4242, &gate, None, Some(&ops)).unwrap();
        let events = ops.events();
        assert_eq!(events.len(), 3);
        assert!(matches!(
            events[1],
            OpEvent::LoadAttempt { log_len: Some(n), .. } if n == 4 << 20
        ));
        assert!(matches!(events[2], OpEvent::Attest));
        ops.assert_exhausted();
        drop(program);
    }

    #[test]
    fn task23a_seam_double_failure_retains_both_errnos() {
        let _lock = task23a_lock();
        for name in ["source_reg_in", "source_reg_out"] {
            take_spill(name);
        }
        use crate::observation_memory::MemoryPool;
        let pool = MemoryPool::new(1 << 20);
        let gate = crate::writer_gate::fake_for_shape_tests(&pool).unwrap();
        let (owned, legacy) = source_map_fixtures_complete();
        let root = source_root_loaded_fixture(
            "source_reg_in",
            "fentry/uprobe_register",
            false,
            &["ADMIT"],
        );
        let ops = ScriptOps::new();
        ops.loads
            .borrow_mut()
            .push_back(LoadScript::err(libc::EACCES, 0));
        // True size past the buffer: truncated, bytes retained.
        ops.loads
            .borrow_mut()
            .push_back(LoadScript::err(libc::E2BIG, u32::MAX).fill(b"verifier says no\0"));
        let mut record =
            LoadDiagnostics::unattempted(&root.name, &root.section, task23a_artifact());
        let error = load_source_root_inner(
            &root,
            &owned,
            &legacy,
            4242,
            &gate,
            Some(&mut record),
            Some(&ops),
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("source prog_load source_reg_in"),
            "{message}"
        );
        assert!(message.contains("quiet:"), "{message}");
        assert_eq!(record.stage, LoadStage::LoggedLoad);
        assert_eq!(record.quiet_errno, Some(libc::EACCES));
        assert_eq!(record.logged_errno, Some(libc::E2BIG));
        assert_eq!(record.log_true_size, u32::MAX);
        assert_eq!(record.log_completeness, LogCompleteness::Truncated);
        assert_eq!(record.log_bytes.len(), 16 << 20);
        assert_eq!(&record.log_bytes[..17], b"verifier says no\0");
        assert_eq!(ops.events().len(), 2);
        ops.assert_exhausted();
        // Observed loads never spill outside the grant evidence dir:
        // the bytes live in-record for the diagnostic to flush.
        assert!(!take_spill("source_reg_in"));
        for fd in owned.values().chain(legacy.maps.values()) {
            assert_fd_open(fd.as_raw_fd());
        }
    }

    #[test]
    fn task23a_production_loop_orders_load_attest_attach_per_root() {
        let _lock = task23a_lock();
        use crate::observation_memory::MemoryPool;
        // Tracing-only order probe: lifecycle attachment mints its
        // writer through the real gate (no scripted form), so the
        // order property is proven on four tracing roots; lifecycle
        // classification/load/attest are covered through the seam.
        let pool = MemoryPool::new(1 << 20);
        let gate = crate::writer_gate::fake_for_shape_tests(&pool).unwrap();
        let (owned, legacy) = source_map_fixtures_complete();
        let prepared = Prepared {
            progs: vec![
                source_root_loaded_fixture(
                    "source_reg_in",
                    "fentry/uprobe_register",
                    false,
                    &["ADMIT"],
                ),
                source_root_loaded_fixture(
                    "source_reg_out",
                    "fexit/uprobe_register",
                    false,
                    &["ADMIT"],
                ),
                source_root_loaded_fixture(
                    "source_reg_in",
                    "fentry/uprobe_register",
                    false,
                    &["ADMIT"],
                ),
                source_root_loaded_fixture(
                    "source_reg_out",
                    "fexit/uprobe_register",
                    false,
                    &["ADMIT"],
                ),
            ],
            maps: Vec::new(),
        };
        let ops = ScriptOps::new();
        let mut prog_reads = Vec::new();
        let mut link_reads = Vec::new();
        for _ in 0..4 {
            let (prog_read, prog_write) = sentinel_pipe();
            let (link_read, link_write) = sentinel_pipe();
            prog_reads.push(prog_read);
            link_reads.push(link_read);
            ops.loads.borrow_mut().push_back(LoadScript::ok(prog_write));
            ops.attests.borrow_mut().push_back(Ok(()));
            ops.links.borrow_mut().push_back(Ok(link_write));
        }
        let loaded =
            load_source_roots_inner(&prepared, &owned, &legacy, 4242, &gate, Some(&ops)).unwrap();
        // Strict per-root load/attest/attach order, four times.
        let events = ops.events();
        assert_eq!(events.len(), 12);
        for (i, chunk) in events.chunks_exact(3).enumerate() {
            let want_name = if i % 2 == 0 {
                "source_reg_in"
            } else {
                "source_reg_out"
            };
            assert!(
                matches!(chunk[0], OpEvent::LoadAttempt { log_len: None, .. }),
                "root {i} load"
            );
            if let OpEvent::LoadAttempt { name, .. } = &chunk[0] {
                assert_eq!(name, want_name, "root {i} identity");
            } else {
                panic!("root {i} load shape");
            }
            assert!(matches!(chunk[1], OpEvent::Attest), "root {i} attest");
            let want = if i % 2 == 0 {
                ossl_bpf_sys::SourceTracingRoot::Enter
            } else {
                ossl_bpf_sys::SourceTracingRoot::Exit
            };
            assert!(
                matches!(chunk[2], OpEvent::AttachLink { kind } if kind == want),
                "root {i} attach"
            );
        }
        // Duplicate names collapse in the maps; both roots present.
        assert!(loaded.programs.contains_key("source_reg_in"));
        assert!(loaded.programs.contains_key("source_reg_out"));
        assert!(loaded.links.contains_key("source_reg_in"));
        assert!(loaded.links.contains_key("source_reg_out"));
        ops.assert_exhausted();
        drop(loaded);
        for read in prog_reads.iter_mut().chain(link_reads.iter_mut()) {
            assert_pipe_eof(read);
        }
        for fd in owned.values().chain(legacy.maps.values()) {
            assert_fd_open(fd.as_raw_fd());
        }
    }

    #[test]
    fn task23a_production_loop_failure_drops_prior_acquisitions() {
        let _lock = task23a_lock();
        take_spill("source_reg_in");
        use crate::observation_memory::MemoryPool;
        let pool = MemoryPool::new(1 << 20);
        let gate = crate::writer_gate::fake_for_shape_tests(&pool).unwrap();
        let (owned, legacy) = source_map_fixtures_complete();
        let prepared = Prepared {
            progs: vec![
                source_root_loaded_fixture(
                    "source_reg_in",
                    "fentry/uprobe_register",
                    false,
                    &["ADMIT"],
                ),
                source_root_loaded_fixture(
                    "source_reg_out",
                    "fexit/uprobe_register",
                    false,
                    &["ADMIT"],
                ),
                source_root_loaded_fixture(
                    "source_reg_in",
                    "fentry/uprobe_register",
                    false,
                    &["ADMIT"],
                ),
                source_root_loaded_fixture(
                    "source_reg_out",
                    "fexit/uprobe_register",
                    false,
                    &["ADMIT"],
                ),
            ],
            maps: Vec::new(),
        };
        let ops = ScriptOps::new();
        let (mut prog0_read, prog0_write) = sentinel_pipe();
        let (mut link0_read, link0_write) = sentinel_pipe();
        let (mut prog1_read, prog1_write) = sentinel_pipe();
        let (mut link1_read, link1_write) = sentinel_pipe();
        for (prog, link) in [(prog0_write, link0_write), (prog1_write, link1_write)] {
            ops.loads.borrow_mut().push_back(LoadScript::ok(prog));
            ops.attests.borrow_mut().push_back(Ok(()));
            ops.links.borrow_mut().push_back(Ok(link));
        }
        // Third root fails both attempts; the fourth never starts.
        ops.loads
            .borrow_mut()
            .push_back(LoadScript::err(libc::EACCES, 0));
        ops.loads
            .borrow_mut()
            .push_back(LoadScript::err(libc::EINVAL, 0));
        let error =
            match load_source_roots_inner(&prepared, &owned, &legacy, 4242, &gate, Some(&ops)) {
                Ok(_) => panic!("third-root failure must refuse"),
                Err(error) => error,
            };
        assert!(
            format!("{error:#}").contains("source prog_load source_reg_in"),
            "{error:#}"
        );
        assert_eq!(ops.events().len(), 8);
        ops.assert_exhausted();
        assert_pipe_eof(&mut prog0_read);
        assert_pipe_eof(&mut link0_read);
        assert_pipe_eof(&mut prog1_read);
        assert_pipe_eof(&mut link1_read);
        assert!(take_spill("source_reg_in"));
        for fd in owned.values().chain(legacy.maps.values()) {
            assert_fd_open(fd.as_raw_fd());
        }
    }

    #[test]
    fn task23a_production_group_preflight_makes_no_calls() {
        let _lock = task23a_lock();
        use crate::observation_memory::MemoryPool;
        let pool = MemoryPool::new(1 << 20);
        let gate = crate::writer_gate::fake_for_shape_tests(&pool).unwrap();
        let (owned, legacy) = source_map_fixtures_complete();
        let full = source_half_loaded_fixture();
        // Short half refuses before any root starts.
        let mut short = full.clone();
        short.progs.pop();
        let ops = ScriptOps::new();
        assert!(load_source_roots_inner(&short, &owned, &legacy, 7, &gate, Some(&ops)).is_err());
        assert!(ops.events().is_empty());
        // Missing owned map refuses before any root starts.
        let (mut owned, legacy) = source_map_fixtures_complete();
        owned.remove("TYPED_ADMISSION");
        let ops = ScriptOps::new();
        assert!(load_source_roots_inner(&full, &owned, &legacy, 7, &gate, Some(&ops)).is_err());
        assert!(ops.events().is_empty());
    }

    #[test]
    fn task23a_custody_observed_path_loads_two_roots() {
        let _lock = task23a_lock();
        use crate::observation_memory::MemoryPool;
        let pool = MemoryPool::new(1 << 20);
        let gate = crate::writer_gate::fake_for_shape_tests(&pool).unwrap();
        let prep = Prepared {
            progs: vec![
                source_root_loaded_fixture("observation_entry", "uprobe", false, &["ADMIT"]),
                source_root_loaded_fixture("observation_return", "uretprobe", true, &["ADMIT"]),
            ],
            maps: vec![
                MapSpecLite {
                    name: "ADMIT".to_owned(),
                    map_type: 12,
                    key_size: 4,
                    value_size: 4,
                    max_entries: 1,
                    flags: 0,
                },
                MapSpecLite {
                    name: "REL".to_owned(),
                    map_type: 1,
                    key_size: 4,
                    value_size: 8,
                    max_entries: 1,
                    flags: 0,
                },
            ],
        };
        let ops = ScriptOps::new();
        let (mut admit_read, admit_write) = sentinel_pipe();
        let (mut rel_read, rel_write) = sentinel_pipe();
        ops.injects.borrow_mut().push_back(Ok(admit_write));
        HOST_NATIVE_MAP.with(|v| *v.borrow_mut() = Some(rel_write));
        let (mut prog0_read, prog0_write) = sentinel_pipe();
        let (mut prog1_read, prog1_write) = sentinel_pipe();
        for (prog, id) in [(prog0_write, 81u32), (prog1_write, 82u32)] {
            ops.loads.borrow_mut().push_back(LoadScript::ok(prog));
            ops.attests.borrow_mut().push_back(Ok(()));
            ops.creds_list.borrow_mut().push_back(Ok(script_creds()));
            ops.infos.borrow_mut().push_back(Ok(script_summary(id)));
            ops.creds_list.borrow_mut().push_back(Ok(script_creds()));
        }
        let mut records = Vec::new();
        let loaded = load_with_custody_inner(
            &prep,
            None,
            Some(&gate),
            Some(DiagCtx {
                records: &mut records,
                artifact: task23a_artifact(),
            }),
            Some(&ops),
        )
        .unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|r| r.stage == LoadStage::Loaded));
        assert!(records.iter().all(|r| r.error.is_none()));
        assert_eq!(records[0].loaded_id, Some(81));
        assert_eq!(records[1].loaded_id, Some(82));
        assert_eq!(records[0].prog_type, 2);
        assert!(loaded.progs.contains_key("observation_entry"));
        assert!(loaded.progs.contains_key("observation_return"));
        // Inject ran once; the REL map came from the host seam.
        assert!(
            ops.events()
                .iter()
                .any(|e| matches!(e, OpEvent::InjectAdmit))
        );
        ops.assert_exhausted();
        drop(loaded);
        assert_pipe_eof(&mut admit_read);
        assert_pipe_eof(&mut rel_read);
        assert_pipe_eof(&mut prog0_read);
        assert_pipe_eof(&mut prog1_read);
        HOST_NATIVE_MAP.with(|v| v.borrow_mut().take());
    }

    #[test]
    fn task23a_custody_second_failure_drops_first_root() {
        let _lock = task23a_lock();
        use crate::observation_memory::MemoryPool;
        let pool = MemoryPool::new(1 << 20);
        let gate = crate::writer_gate::fake_for_shape_tests(&pool).unwrap();
        let prep = Prepared {
            progs: vec![
                source_root_loaded_fixture("observation_entry", "uprobe", false, &["ADMIT"]),
                source_root_loaded_fixture("observation_return", "uretprobe", true, &["ADMIT"]),
            ],
            maps: vec![MapSpecLite {
                name: "ADMIT".to_owned(),
                map_type: 12,
                key_size: 4,
                value_size: 4,
                max_entries: 1,
                flags: 0,
            }],
        };
        let ops = ScriptOps::new();
        let (mut admit_read, admit_write) = sentinel_pipe();
        ops.injects.borrow_mut().push_back(Ok(admit_write));
        let (mut prog0_read, prog0_write) = sentinel_pipe();
        let (mut prog1_read, prog1_write) = sentinel_pipe();
        ops.loads
            .borrow_mut()
            .push_back(LoadScript::ok(prog0_write));
        ops.attests.borrow_mut().push_back(Ok(()));
        ops.creds_list.borrow_mut().push_back(Ok(script_creds()));
        ops.infos.borrow_mut().push_back(Ok(script_summary(81)));
        ops.creds_list.borrow_mut().push_back(Ok(script_creds()));
        ops.loads
            .borrow_mut()
            .push_back(LoadScript::ok(prog1_write));
        ops.attests
            .borrow_mut()
            .push_back(Err(std::io::Error::from_raw_os_error(libc::EPERM)));
        let mut records = Vec::new();
        let result = load_with_custody_inner(
            &prep,
            None,
            Some(&gate),
            Some(DiagCtx {
                records: &mut records,
                artifact: task23a_artifact(),
            }),
            Some(&ops),
        );
        assert!(result.is_err());
        ops.assert_exhausted();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].stage, LoadStage::Loaded);
        assert!(records[0].error.is_none());
        assert_eq!(records[1].stage, LoadStage::Attestation);
        assert!(records[1].error.is_some());
        assert_pipe_eof(&mut prog0_read);
        assert_pipe_eof(&mut prog1_read);
        assert_pipe_eof(&mut admit_read);
    }

    #[test]
    fn task23a_observe_program_records_precise_unavailability() {
        let fd = model_fd();
        // Happy path: bracketed creds plus a decodable reply.
        let ops = ScriptOps::new();
        ops.creds_list.borrow_mut().push_back(Ok(script_creds()));
        ops.infos.borrow_mut().push_back(Ok(script_summary(91)));
        ops.creds_list.borrow_mut().push_back(Ok(script_creds()));
        let mut record = LoadDiagnostics::unattempted("r", "uprobe", task23a_artifact());
        observe_loaded_program(&fd, &mut record, Some(&ops));
        assert_eq!(record.stage, LoadStage::InfoQuery);
        assert_eq!(record.loaded_id, Some(91));
        assert!(record.info.is_some());
        assert!(record.info_unavailable.is_none());
        assert_eq!(record.query_creds, Some(script_creds()));
        ops.assert_exhausted();
        // Changed credentials refuse.
        let ops = ScriptOps::new();
        ops.creds_list.borrow_mut().push_back(Ok(script_creds()));
        ops.infos.borrow_mut().push_back(Ok(script_summary(91)));
        let mut changed = script_creds();
        changed.tid = 9999;
        ops.creds_list.borrow_mut().push_back(Ok(changed));
        let mut record = LoadDiagnostics::unattempted("r", "uprobe", task23a_artifact());
        observe_loaded_program(&fd, &mut record, Some(&ops));
        assert!(record.loaded_id.is_none());
        assert!(record.info.is_none());
        assert!(
            record
                .info_unavailable
                .as_deref()
                .unwrap()
                .contains("changed")
        );
        ops.assert_exhausted();
        // Missing privilege refuses.
        let ops = ScriptOps::new();
        let mut poor = script_creds();
        poor.caps = [[0, 0, 0], [0, 0, 0]];
        ops.creds_list.borrow_mut().push_back(Ok(poor));
        ops.infos.borrow_mut().push_back(Ok(script_summary(91)));
        ops.creds_list.borrow_mut().push_back(Ok(poor));
        let mut record = LoadDiagnostics::unattempted("r", "uprobe", task23a_artifact());
        observe_loaded_program(&fd, &mut record, Some(&ops));
        assert!(
            record
                .info_unavailable
                .as_deref()
                .unwrap()
                .contains("privilege")
        );
        ops.assert_exhausted();
        // Refused query and missing credentials refuse distinctly.
        let ops = ScriptOps::new();
        ops.creds_list.borrow_mut().push_back(Ok(script_creds()));
        ops.infos
            .borrow_mut()
            .push_back(Err(std::io::Error::from_raw_os_error(libc::EPERM)));
        ops.creds_list.borrow_mut().push_back(Ok(script_creds()));
        let mut record = LoadDiagnostics::unattempted("r", "uprobe", task23a_artifact());
        observe_loaded_program(&fd, &mut record, Some(&ops));
        assert!(
            record
                .info_unavailable
                .as_deref()
                .unwrap()
                .contains("info query refused")
        );
        ops.assert_exhausted();
        let ops = ScriptOps::new();
        ops.creds_list
            .borrow_mut()
            .push_back(Err(std::io::Error::from_raw_os_error(libc::EIO)));
        ops.infos.borrow_mut().push_back(Ok(script_summary(91)));
        ops.creds_list.borrow_mut().push_back(Ok(script_creds()));
        let mut record = LoadDiagnostics::unattempted("r", "uprobe", task23a_artifact());
        observe_loaded_program(&fd, &mut record, Some(&ops));
        assert!(
            record
                .info_unavailable
                .as_deref()
                .unwrap()
                .contains("credentials unavailable")
        );
        ops.assert_exhausted();
    }

    #[test]
    fn task23a_load_prog_inner_refuses_fixup_before_boundary() {
        let _lock = task23a_lock();
        let mut maps = HashMap::new();
        maps.insert("ADMIT".to_owned(), model_fd());
        let root = source_root_loaded_fixture("typed_entry", "uprobe", false, &["ADMIT"]);
        let ops = ScriptOps::new();
        let mut record =
            LoadDiagnostics::unattempted(&root.name, &root.section, task23a_artifact());
        record.stage = LoadStage::MapSetup;
        // Unknown second map refuses at fixup with zero boundary calls.
        let mut bad = root.clone();
        bad.map_fixups.push(MapFixup {
            insn_off: 16,
            map: "NOPE".to_owned(),
        });
        bad.insns.resize(32, 0);
        bad.insns[16] = BPF_LD_IMM64;
        let error =
            load_prog_inner(&bad, &maps, true, None, Some(&mut record), Some(&ops)).unwrap_err();
        assert!(format!("{error:#}").contains("unknown map"), "{error:#}");
        assert_eq!(record.stage, LoadStage::Fixup);
        assert_eq!(record.prog_type, 2);
        assert_eq!(record.maps.len(), 1);
        assert!(ops.events().is_empty());
        // Lifecycle classification records its type before fixup too.
        let mut record =
            LoadDiagnostics::unattempted("attr_exit", "raw_tracepoint", task23a_artifact());
        record.stage = LoadStage::MapSetup;
        let lifecycle = source_root_loaded_fixture(
            "attr_exit",
            "raw_tracepoint/sched_process_exit",
            false,
            &["ADMIT"],
        );
        let mut bad = lifecycle.clone();
        bad.map_fixups[0].map = "NOPE".to_owned();
        let error =
            load_prog_inner(&bad, &maps, true, None, Some(&mut record), Some(&ops)).unwrap_err();
        assert!(format!("{error:#}").contains("unknown map"), "{error:#}");
        assert_eq!(record.prog_type, 17);
        assert_eq!(record.expected_attach, 0);
    }

    #[test]
    fn task23a_load_prog_inner_records_the_btf_path() {
        let _lock = task23a_lock();
        let mut maps = HashMap::new();
        maps.insert("ADMIT".to_owned(), model_fd());
        let mut root =
            source_root_loaded_fixture("observation_return", "uretprobe", true, &["ADMIT"]);
        root.subprogs = vec![
            SubprogInfo {
                name: "observation_return".to_owned(),
                insn_off: 0,
                is_callback: false,
            },
            SubprogInfo {
                name: "query_return".to_owned(),
                insn_off: 8,
                is_callback: true,
            },
        ];
        // BTF success: the synthesized image loads, the BTF FD is
        // owned by the guarded handle and drops with the call.
        let ops = ScriptOps::new();
        let (mut btf_read, btf_write) = sentinel_pipe();
        let (mut prog_read, prog_write) = sentinel_pipe();
        ops.btfs
            .borrow_mut()
            .push_back((Ok(btf_write), vec![b'B', b'T', b'F', 0]));
        ops.loads.borrow_mut().push_back(LoadScript::ok(prog_write));
        let mut record =
            LoadDiagnostics::unattempted(&root.name, &root.section, task23a_artifact());
        record.stage = LoadStage::MapSetup;
        let program =
            load_prog_inner(&root, &maps, true, None, Some(&mut record), Some(&ops)).unwrap();
        assert_eq!(record.stage, LoadStage::QuietLoad);
        assert_eq!(record.callback_subprogs, 1);
        assert!(record.btf_synthesized);
        assert_eq!(record.btf_log, vec![b'B', b'T', b'F', 0]);
        let events = ops.events();
        assert_eq!(events.len(), 2);
        assert!(matches!(
            events[0],
            OpEvent::BtfLoad { len, cap } if len > 0 && cap == 1 << 16
        ));
        ops.assert_exhausted();
        drop(program);
        assert_pipe_eof(&mut prog_read);
        assert_pipe_eof(&mut btf_read);
        // BTF failure: its own stage with the retained log, and the
        // load boundary is never reached.
        let ops = ScriptOps::new();
        ops.btfs.borrow_mut().push_back((
            Err(std::io::Error::from_raw_os_error(libc::EIO)),
            vec![b'b', b'a', b'd', 0],
        ));
        let mut record =
            LoadDiagnostics::unattempted(&root.name, &root.section, task23a_artifact());
        record.stage = LoadStage::MapSetup;
        let error =
            load_prog_inner(&root, &maps, true, None, Some(&mut record), Some(&ops)).unwrap_err();
        assert!(format!("{error:#}").contains("btf_load"), "{error:#}");
        assert_eq!(record.stage, LoadStage::BtfSetup);
        assert_eq!(record.btf_log, vec![b'b', b'a', b'd', 0]);
        assert_eq!(ops.events().len(), 1);
        ops.assert_exhausted();
    }

    #[test]
    fn task23a_observed_wrappers_refuse_before_any_effect() {
        let _lock = task23a_lock();
        use crate::observation_memory::MemoryPool;
        let pool = MemoryPool::new(1 << 20);
        let gate = crate::writer_gate::fake_for_shape_tests(&pool).unwrap();
        let (owned, legacy) = source_map_fixtures_complete();
        // Plain single-root wrapper: unselected root, no record channel.
        let renamed = source_root_loaded_fixture(
            "observation_entry",
            "fentry/uprobe_register",
            false,
            &["ADMIT"],
        );
        let error = load_source_root_unattached(&renamed, &owned, &legacy, 7, &gate).unwrap_err();
        assert!(
            format!("{error:#}").contains("unselected source root"),
            "{error:#}"
        );
        // Observed single-root wrapper: refusal pushes its receipt.
        let mut records = Vec::new();
        let error = load_source_root_unattached_observed(
            &renamed,
            &owned,
            &legacy,
            7,
            &gate,
            task23a_artifact(),
            &mut records,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("unselected source root"),
            "{error:#}"
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].stage, LoadStage::Preflight);
        assert!(records[0].error.is_some());
        // Observed typed wrapper: callback on the first root stops
        // before the boundary with zero loads attempted.
        let mut pair = typed_pair_fixture();
        mark_callback(&mut pair.progs[0]);
        let mut records = Vec::new();
        let error = load_typed_borrowed_observed(
            &pair,
            &owned,
            &legacy,
            &gate,
            task23a_artifact(),
            &mut records,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("forbids callback BTF"),
            "{error:#}"
        );
        assert_eq!(records.len(), 1);
        // Observed count wrapper: a half without the shared writer
        // map refuses before any map or load effect.
        let mut naked = count_singleton_fixture();
        naked.maps = Vec::new();
        let borrowed = std::collections::BTreeMap::new();
        let mut records = Vec::new();
        let error = match load_gated_borrowed_observed(
            &naked,
            &gate,
            &borrowed,
            task23a_artifact(),
            &mut records,
        ) {
            Ok(_) => panic!("naked count half must refuse"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("missing shared writer map"),
            "{error:#}"
        );
        assert!(records.is_empty());
        // Observed legacy wrapper: a wrong second name is rejected
        // by the preflight before map/load calls.
        let mut wrong = legacy_pair_fixture();
        wrong.progs[1].name = "typed_entry".to_owned();
        let mut records = Vec::new();
        let error = match load_gated_observed(&wrong, &gate, task23a_artifact(), &mut records) {
            Ok(_) => panic!("wrong-name legacy pair must refuse"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("unexpected legacy root"),
            "{error:#}"
        );
        assert!(records.is_empty());
    }

    #[test]
    fn task23a_btf_stays_live_across_quiet_logged_retry() {
        let _lock = task23a_lock();
        let mut maps = HashMap::new();
        maps.insert("ADMIT".to_owned(), model_fd());
        let mut root =
            source_root_loaded_fixture("observation_return", "uretprobe", true, &["ADMIT"]);
        root.subprogs = vec![
            SubprogInfo {
                name: "observation_return".to_owned(),
                insn_off: 0,
                is_callback: false,
            },
            SubprogInfo {
                name: "query_return".to_owned(),
                insn_off: 8,
                is_callback: true,
            },
        ];
        let ops = ScriptOps::new();
        let (mut btf_read, btf_write) = sentinel_pipe();
        let btf_raw = btf_write.as_raw_fd();
        let (mut prog_read, prog_write) = sentinel_pipe();
        ops.btfs
            .borrow_mut()
            .push_back((Ok(btf_write), vec![b'B', b'T', b'F', 0]));
        ops.loads
            .borrow_mut()
            .push_back(LoadScript::err(libc::EPERM, 0));
        ops.loads.borrow_mut().push_back(
            LoadScript::ok(prog_write)
                .fill(b"ok-after-retry\0")
                .true_size(15),
        );
        let mut record =
            LoadDiagnostics::unattempted(&root.name, &root.section, task23a_artifact());
        record.stage = LoadStage::MapSetup;
        let program =
            load_prog_inner(&root, &maps, true, None, Some(&mut record), Some(&ops)).unwrap();
        // The same live BTF FD rode both attempts; the scripted
        // harness already proved liveness at each attempt.
        let events = ops.events();
        assert_eq!(events.len(), 3);
        assert!(matches!(events[0], OpEvent::BtfLoad { .. }));
        for event in &events[1..] {
            if let OpEvent::LoadAttempt { name, btf_fd, .. } = event {
                assert_eq!(name, "observation_return");
                assert_eq!(*btf_fd, Some(btf_raw));
            } else {
                panic!("attempt event shape");
            }
        }
        assert!(matches!(
            events[1],
            OpEvent::LoadAttempt { log_len: None, .. }
        ));
        assert!(matches!(
            events[2],
            OpEvent::LoadAttempt {
                log_len: Some(n),
                ..
            } if n == 16 << 20
        ));
        // Distinctive logged bytes rode the real buffer into the record.
        assert_eq!(record.stage, LoadStage::LoggedLoad);
        assert_eq!(record.quiet_errno, Some(libc::EPERM));
        assert_eq!(record.log_completeness, LogCompleteness::Complete);
        assert_eq!(&record.log_bytes[..15], b"ok-after-retry\0");
        ops.assert_exhausted();
        drop(program);
        assert_pipe_eof(&mut prog_read);
        assert_pipe_eof(&mut btf_read);
    }

    #[test]
    fn task23a_map_setup_failures_belong_to_their_roots() {
        let _lock = task23a_lock();
        use crate::observation_memory::MemoryPool;
        fn lite(name: &str) -> MapSpecLite {
            MapSpecLite {
                name: name.to_owned(),
                map_type: 1,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
            }
        }
        // Custody: refused ADMIT inject attributes MapSetup to both roots.
        let pool = MemoryPool::new(1 << 20);
        let gate = crate::writer_gate::fake_for_shape_tests(&pool).unwrap();
        let prep = Prepared {
            progs: vec![
                source_root_loaded_fixture("observation_entry", "uprobe", false, &["ADMIT"]),
                source_root_loaded_fixture("observation_return", "uretprobe", true, &["ADMIT"]),
            ],
            maps: vec![lite("ADMIT")],
        };
        let ops = ScriptOps::new();
        ops.injects
            .borrow_mut()
            .push_back(Err(std::io::Error::from_raw_os_error(libc::EIO)));
        let mut records = Vec::new();
        let result = load_with_custody_inner(
            &prep,
            None,
            Some(&gate),
            Some(DiagCtx {
                records: &mut records,
                artifact: task23a_artifact(),
            }),
            Some(&ops),
        );
        assert!(result.is_err());
        assert_eq!(records.len(), 2);
        assert!(
            records
                .iter()
                .all(|r| r.stage == LoadStage::MapSetup && r.error.is_some())
        );
        assert_eq!(ops.events().len(), 1);
        ops.assert_exhausted();
        // Typed: unresolvable borrow table attributes MapSetup, zero calls.
        let pool = MemoryPool::new(1 << 20);
        let gate = crate::writer_gate::fake_for_shape_tests(&pool).unwrap();
        let (owned, legacy) = source_map_fixtures_complete();
        let mut pair = typed_pair_fixture();
        pair.maps = vec![lite("ADMIT"), lite("NOPE")];
        let ops = ScriptOps::new();
        let mut records = Vec::new();
        let result = load_typed_borrowed_inner(
            &pair,
            &owned,
            &legacy,
            &gate,
            Some(DiagCtx {
                records: &mut records,
                artifact: task23a_artifact(),
            }),
            Some(&ops),
        );
        assert!(result.is_err());
        assert_eq!(records.len(), 2);
        assert!(
            records
                .iter()
                .all(|r| r.stage == LoadStage::MapSetup && r.error.is_some())
        );
        assert!(ops.events().is_empty());
        ops.assert_exhausted();
        // Count: refused inject attributes MapSetup to its singleton.
        let pool = MemoryPool::new(1 << 20);
        let gate = crate::writer_gate::fake_for_shape_tests(&pool).unwrap();
        let mut naked = count_singleton_fixture();
        naked.maps = vec![lite("ADMIT")];
        let borrowed = std::collections::BTreeMap::new();
        let ops = ScriptOps::new();
        ops.injects
            .borrow_mut()
            .push_back(Err(std::io::Error::from_raw_os_error(libc::EIO)));
        let mut records = Vec::new();
        let result = load_gated_borrowed_inner(
            &naked,
            &gate,
            &borrowed,
            Some(DiagCtx {
                records: &mut records,
                artifact: task23a_artifact(),
            }),
            Some(&ops),
        );
        assert!(result.is_err());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].stage, LoadStage::MapSetup);
        assert!(records[0].error.is_some());
        ops.assert_exhausted();
    }

    #[test]
    fn task23a_observed_legacy_shares_the_gated_preflight() {
        let _lock = task23a_lock();
        use crate::observation_memory::MemoryPool;
        let pool = MemoryPool::new(1 << 20);
        let gate = crate::writer_gate::fake_for_shape_tests(&pool).unwrap();
        // A maps-less pair stops at the shared writer map check.
        let pair = legacy_pair_fixture();
        let mut records = Vec::new();
        let error = match load_gated_observed(&pair, &gate, task23a_artifact(), &mut records) {
            Ok(_) => panic!("maps-less pair must refuse"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("missing shared writer map"),
            "{error:#}"
        );
        assert!(records.is_empty());
        // A pair whose return root lacks the gate fixup is ungated.
        let mut ungated = legacy_pair_fixture();
        ungated.maps = vec![MapSpecLite {
            name: "ADMIT".to_owned(),
            map_type: 1,
            key_size: 4,
            value_size: 8,
            max_entries: 1,
            flags: 0,
        }];
        ungated.progs[1].map_fixups.clear();
        let mut records = Vec::new();
        let error = match load_gated_observed(&ungated, &gate, task23a_artifact(), &mut records) {
            Ok(_) => panic!("ungated pair must refuse"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("ungated producer root"),
            "{error:#}"
        );
        assert!(records.is_empty());
    }

    #[test]
    fn task23a_seam_attestation_failure_drops_current_fd() {
        let _lock = task23a_lock();
        use crate::observation_memory::MemoryPool;
        let pool = MemoryPool::new(1 << 20);
        let gate = crate::writer_gate::fake_for_shape_tests(&pool).unwrap();
        let (owned, legacy) = source_map_fixtures_complete();
        let root = source_root_loaded_fixture(
            "source_reg_out",
            "fexit/uprobe_register",
            false,
            &["ADMIT"],
        );
        let ops = ScriptOps::new();
        let (mut prog_read, prog_write) = sentinel_pipe();
        ops.loads.borrow_mut().push_back(LoadScript::ok(prog_write));
        ops.attests
            .borrow_mut()
            .push_back(Err(std::io::Error::from_raw_os_error(libc::EPERM)));
        let mut record =
            LoadDiagnostics::unattempted(&root.name, &root.section, task23a_artifact());
        let error = load_source_root_inner(
            &root,
            &owned,
            &legacy,
            4242,
            &gate,
            Some(&mut record),
            Some(&ops),
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("missing shared gate"),
            "{error:#}"
        );
        assert_eq!(record.stage, LoadStage::Attestation);
        // The current FD dropped; no info query ran after refusal.
        assert_pipe_eof(&mut prog_read);
        assert_eq!(ops.events().len(), 2);
        ops.assert_exhausted();
        for fd in owned.values().chain(legacy.maps.values()) {
            assert_fd_open(fd.as_raw_fd());
        }
    }
}

// Controlled ring consumption follows Aya 0.14.0 maps/ring_buf.rs.
// Copyright (c) 2021 Alessandro Decina
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

/// Borrowed map operations never manufacture an owning Aya descriptor.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BorrowedMapInfo {
    pub(crate) map_type: u32,
    pub(crate) id: u32,
    pub(crate) key_size: u32,
    pub(crate) value_size: u32,
    pub(crate) max_entries: u32,
    pub(crate) flags: u32,
}
pub(crate) struct BorrowedMap<'a> {
    fd: BorrowedFd<'a>,
    pub(crate) info: BorrowedMapInfo,
    setup: Option<(
        &'a crate::capture_setup::SetupLinks,
        crate::capture::BoundaryStage,
    )>,
}
impl<'a> BorrowedMap<'a> {
    pub(crate) fn new(fd: BorrowedFd<'a>) -> std::io::Result<Self> {
        #[repr(C)]
        struct Attr {
            fd: u32,
            len: u32,
            info: u64,
        }
        let mut bytes = [0u32; 64];
        let mut attr = Attr {
            fd: fd.as_raw_fd() as u32,
            len: std::mem::size_of_val(&bytes) as u32,
            info: bytes.as_mut_ptr() as u64,
        };
        // SAFETY: the complete zeroed map-info buffer and fixed UAPI attribute
        // remain live through this borrowed-FD syscall; it creates no owner.
        let result = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                ossl_bpf_sys::BPF_OBJ_GET_INFO_BY_FD,
                &mut attr,
                std::mem::size_of::<Attr>(),
            )
        };
        if result < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            fd,
            setup: None,
            info: BorrowedMapInfo {
                map_type: bytes[0],
                id: bytes[1],
                key_size: bytes[2],
                value_size: bytes[3],
                max_entries: bytes[4],
                flags: bytes[5],
            },
        })
    }
    pub(crate) fn checked(
        fd: BorrowedFd<'a>,
        setup: &'a crate::capture_setup::SetupLinks,
        stage: crate::capture::BoundaryStage,
    ) -> anyhow::Result<Self> {
        setup.check_owned(stage)?;
        let mut map = Self::new(fd)?;
        map.setup = Some((setup, stage));
        Ok(map)
    }
    fn check(&self) -> std::io::Result<()> {
        if let Some((setup, stage)) = self.setup {
            setup.check_owned(stage).map_err(std::io::Error::other)?;
        }
        Ok(())
    }
    pub(crate) fn shape(&self, types: &[u32], key: usize, value: usize) -> anyhow::Result<()> {
        anyhow::ensure!(
            types.contains(&self.info.map_type)
                && self.info.key_size as usize == key
                && self.info.value_size as usize == value,
            "borrowed map shape mismatch"
        );
        Ok(())
    }
    pub(crate) fn lookup(&self, key: &[u8], values: &mut [u8]) -> std::io::Result<()> {
        self.check()?;
        if key.len() != self.info.key_size as usize {
            return Err(std::io::Error::other("map key size mismatch"));
        }
        let expected = if matches!(self.info.map_type, 5 | 6) {
            let cpus = aya::util::nr_cpus().map_err(|(_, error)| error)?;
            (self.info.value_size as usize)
                .next_multiple_of(8)
                .checked_mul(cpus)
                .ok_or_else(|| std::io::Error::other("per-CPU value size overflow"))?
        } else {
            self.info.value_size as usize
        };
        if values.len() != expected {
            return Err(std::io::Error::other("map value size mismatch"));
        }
        // SAFETY: sizes were checked against immutable metadata of this exact FD.
        unsafe { ossl_bpf_sys::map_lookup_elem(self.fd.as_raw_fd(), key, values) }
    }
    pub(crate) fn update(&self, key: &[u8], value: &[u8]) -> std::io::Result<()> {
        self.check()?;
        if key.len() != self.info.key_size as usize
            || value.len() != self.info.value_size as usize
            || matches!(self.info.map_type, 5 | 6)
        {
            return Err(std::io::Error::other("map update shape mismatch"));
        }
        // SAFETY: non-per-CPU key/value lengths match this exact FD.
        unsafe { ossl_bpf_sys::map_update_elem(self.fd.as_raw_fd(), key, value, 0) }
    }
    /// 6B bound-epoch flip: whole-value update of a per-CPU map
    /// (one host write per key touching each CPU's slot once).
    /// Restricted by construction to host-owned maps (the flip
    /// writes `EPOCH` only, which BPF never writes — no RMW race
    /// with BPF count updates is constructable). `BPF_ANY`
    /// creates-or-updates (absent ⟺ insert with the new epoch).
    pub(crate) fn update_percpu(&self, key: &[u8], value: &[u8]) -> std::io::Result<()> {
        self.check()?;
        if key.len() != self.info.key_size as usize || !matches!(self.info.map_type, 5 | 6) {
            return Err(std::io::Error::other("map update shape mismatch"));
        }
        let cpus = aya::util::nr_cpus().map_err(|(_, error)| error)?;
        let expected = (self.info.value_size as usize)
            .next_multiple_of(8)
            .checked_mul(cpus)
            .ok_or_else(|| std::io::Error::other("per-CPU value size overflow"))?;
        if value.len() != expected {
            return Err(std::io::Error::other("map value size mismatch"));
        }
        // SAFETY: per-CPU key/value lengths match this exact FD.
        unsafe { ossl_bpf_sys::map_update_elem(self.fd.as_raw_fd(), key, value, 0) }
    }
    pub(crate) fn keys(&self, capacity: u32) -> std::io::Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        let mut previous: Option<Vec<u8>> = None;
        let mut seen = HashSet::new();
        loop {
            self.check()?;
            let mut next = vec![0; self.info.key_size as usize];
            // SAFETY: both key buffers match the exact immutable map key size.
            match unsafe {
                ossl_bpf_sys::map_get_next_key(self.fd.as_raw_fd(), previous.as_deref(), &mut next)
            } {
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(out),
                Err(error) => return Err(error),
                Ok(()) => {}
            }
            if out.len() >= capacity as usize || !seen.insert(next.clone()) {
                return Err(std::io::Error::other(
                    "map key iteration repeats or exceeds capacity",
                ));
            }
            previous = Some(next.clone());
            out.push(next);
        }
    }
    pub(crate) fn delete(&self, key: &[u8]) -> std::io::Result<()> {
        self.check()?;
        if key.len() != self.info.key_size as usize {
            return Err(std::io::Error::other("map key size mismatch"));
        }
        #[repr(C)]
        struct Attr {
            fd: u32,
            pad: u32,
            key: u64,
            value: u64,
            flags: u64,
        }
        let attr = Attr {
            fd: self.fd.as_raw_fd() as u32,
            pad: 0,
            key: key.as_ptr() as u64,
            value: 0,
            flags: 0,
        };
        // SAFETY: BPF_MAP_DELETE_ELEM reads only the checked live key.
        let result = unsafe { libc::syscall(libc::SYS_bpf, 3, &attr, std::mem::size_of::<Attr>()) };
        if result < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
pub(crate) fn pod_bytes<T: aya::Pod>(value: &T) -> &[u8] {
    // SAFETY: Pod has no uninitialized padding and is valid as bytes.
    unsafe { std::slice::from_raw_parts((value as *const T).cast(), std::mem::size_of::<T>()) }
}
fn pod_value<T: aya::Pod>(bytes: &[u8]) -> T {
    assert_eq!(bytes.len(), std::mem::size_of::<T>());
    // SAFETY: Pod admits every initialized bit pattern; unaligned copy owns T.
    unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) }
}
pub(crate) fn borrowed_rows<K: aya::Pod, V: aya::Pod>(
    maps: &HashMap<String, OwnedFd>,
    name: &str,
    percpu: bool,
    setup: &crate::capture_setup::SetupLinks,
    stage: crate::capture::BoundaryStage,
) -> anyhow::Result<Vec<(K, Vec<V>)>> {
    use anyhow::Context as _;
    let map = BorrowedMap::checked(maps.get(name).context("map missing")?.as_fd(), setup, stage)?;
    map.shape(
        if percpu { &[5][..] } else { &[1][..] },
        std::mem::size_of::<K>(),
        std::mem::size_of::<V>(),
    )?;
    let cpus = if percpu {
        aya::util::nr_cpus().map_err(|(_, error)| error)?
    } else {
        1
    };
    let stride = if percpu {
        std::mem::size_of::<V>().next_multiple_of(8)
    } else {
        std::mem::size_of::<V>()
    };
    let mut values = vec![0u8; stride.checked_mul(cpus).context("per-CPU size overflow")?];
    let mut out = Vec::new();
    for key in map.keys(map.info.max_entries)? {
        match map.lookup(&key, &mut values) {
            Ok(()) => out.push((
                pod_value(&key),
                values
                    .chunks_exact(stride)
                    .map(|value| pod_value(&value[..std::mem::size_of::<V>()]))
                    .collect(),
            )),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(out)
}
pub(crate) fn borrowed_rows_partial<K: aya::Pod, V: aya::Pod>(
    maps: &HashMap<String, OwnedFd>,
    name: &str,
    percpu: bool,
    setup: &crate::capture_setup::SetupLinks,
    stage: crate::capture::BoundaryStage,
) -> anyhow::Result<BorrowedRows<K, V>> {
    use anyhow::Context as _;
    let map = BorrowedMap::checked(maps.get(name).context("map missing")?.as_fd(), setup, stage)?;
    map.shape(
        if percpu { &[5][..] } else { &[1][..] },
        std::mem::size_of::<K>(),
        std::mem::size_of::<V>(),
    )?;
    let cpus = if percpu {
        aya::util::nr_cpus().map_err(|(_, e)| e)?
    } else {
        1
    };
    let stride = if percpu {
        std::mem::size_of::<V>().next_multiple_of(8)
    } else {
        std::mem::size_of::<V>()
    };
    stride.checked_mul(cpus).context("per-CPU size overflow")?;
    Ok(read_partial_rows(
        map.info.max_entries,
        stride,
        cpus,
        |previous, key| {
            map.check()?;
            // SAFETY: the key buffers match the checked map shape and remain live.
            unsafe { ossl_bpf_sys::map_get_next_key(map.fd.as_raw_fd(), previous, key) }
        },
        |key, value| map.lookup(key, value),
    ))
}

// Discovery tolerates read loss; traversal above deliberately stays all-or-error.
fn read_partial_rows<K: aya::Pod, V: aya::Pod>(
    capacity: u32,
    stride: usize,
    cpus: usize,
    mut next: impl FnMut(Option<&[u8]>, &mut [u8]) -> std::io::Result<()>,
    mut lookup: impl FnMut(&[u8], &mut [u8]) -> std::io::Result<()>,
) -> BorrowedRows<K, V> {
    let mut rows = Vec::new();
    let mut previous: Option<Vec<u8>> = None;
    let mut seen = HashSet::new();
    let mut failed = false;
    let mut values = vec![0; stride * cpus];
    loop {
        let mut key = vec![0; std::mem::size_of::<K>()];
        match next(previous.as_deref(), &mut key) {
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => break,
            Err(_) => {
                failed = true;
                break;
            }
            Ok(()) => {}
        }
        if seen.len() >= capacity as usize || !seen.insert(key.clone()) {
            failed = true;
            break;
        }
        previous = Some(key.clone());
        match lookup(&key, &mut values) {
            Ok(()) => rows.push((
                pod_value(&key),
                values
                    .chunks_exact(stride)
                    .map(|value| pod_value(&value[..std::mem::size_of::<V>()]))
                    .collect(),
            )),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
            Err(_) => {
                failed = true;
            }
        }
    }
    (rows, failed)
}

#[cfg(test)]
mod partial_row_tests {
    #[test]
    fn w079_fullplan_discovery_partial_rows() {
        for failure in [0, 1, 2] {
            let mut n = 0u32;
            let (rows, failed) = super::read_partial_rows::<u32, u64>(
                8,
                8,
                1,
                |_, key| {
                    n += 1;
                    if n == 3 {
                        return Err(std::io::Error::from_raw_os_error(if failure == 1 {
                            libc::EIO
                        } else {
                            libc::ENOENT
                        }));
                    }
                    key.copy_from_slice(&n.to_ne_bytes());
                    Ok(())
                },
                |key, value| {
                    if key == 2u32.to_ne_bytes() && failure == 2 {
                        return Err(std::io::Error::from_raw_os_error(libc::EIO));
                    }
                    value.copy_from_slice(&42u64.to_ne_bytes());
                    Ok(())
                },
            );
            assert_eq!(failed, failure != 0);
            assert_eq!(
                rows.first(),
                Some(&(1, vec![42])),
                "learned row survives read loss {failure}"
            );
            assert_eq!(rows.len(), if failure == 2 { 1 } else { 2 });
        }
    }
}

pub(crate) fn borrowed_ctrl(
    maps: &HashMap<String, OwnedFd>,
    value: Option<&osslscope_ebpf_common::CtrlValue>,
    setup: &crate::capture_setup::SetupLinks,
) -> anyhow::Result<osslscope_ebpf_common::CtrlValue> {
    use anyhow::Context as _;
    let map = BorrowedMap::checked(
        maps.get("CTRL").context("CTRL missing")?.as_fd(),
        setup,
        crate::capture::BoundaryStage::Traversal,
    )?;
    map.shape(
        &[2],
        4,
        std::mem::size_of::<osslscope_ebpf_common::CtrlValue>(),
    )?;
    let key = 0u32.to_ne_bytes();
    if let Some(value) = value {
        map.update(&key, pod_bytes(value))?;
        return Ok(*value);
    }
    let mut bytes = vec![0; map.info.value_size as usize];
    map.lookup(&key, &mut bytes)?;
    Ok(pod_value(&bytes))
}

struct EventMapping {
    address: usize,
    len: usize,
    owner: crate::capture_setup::SetupWeak,
    stage: crate::capture::BoundaryStage,
    #[cfg(test)]
    cleanup_hold: Option<std::sync::Arc<crate::capture_setup::NativeTestGate>>,
}
impl EventMapping {
    fn new(
        fd: BorrowedFd<'_>,
        len: usize,
        prot: i32,
        offset: usize,
        links: &crate::capture_setup::SetupLinks,
        stage: crate::capture::BoundaryStage,
    ) -> std::io::Result<Self> {
        // SAFETY: the OS creates an independent mapping; its sole owner unmaps it.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                prot,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                offset as libc::off_t,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            address: ptr as usize,
            len,
            owner: links.weak(),
            stage,
            #[cfg(test)]
            cleanup_hold: links.test_mapping_cleanup_hold(),
        })
    }
    fn position(&self) -> &std::sync::atomic::AtomicUsize {
        assert_ne!(self.address, 0, "EVENTS position has a non-null mapping");
        // SAFETY: mmap is page-aligned and its first word is the ring position;
        // kernel and userspace use the documented atomic ring protocol.
        unsafe { &*(self.address as *const std::sync::atomic::AtomicUsize) }
    }
}
impl Drop for EventMapping {
    fn drop(&mut self) {
        // A failed unmap is unresolved ownership, never a successful Drop ack.
        loop {
            #[cfg(test)]
            let hold = self.cleanup_hold.take();
            let address = self.address;
            #[cfg(test)]
            let address = if hold.is_some() { address + 1 } else { address };
            if unsafe { libc::munmap(address as *mut libc::c_void, self.len) } == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            self.owner.disposal_error(self.stage, &error);
            #[cfg(test)]
            if let Some(hold) = hold {
                hold.hold();
            }
            std::thread::park_timeout(std::time::Duration::from_millis(1));
        }
    }
}
#[derive(Default)]
struct EventConstruction {
    consumer: Option<EventMapping>,
    producer: Option<EventMapping>,
}
enum EventInit {
    Kernel,
    #[cfg(test)]
    Host(u8),
}
pub(crate) struct OwnedEvents {
    consumer: EventMapping,
    producer: EventMapping,
    position: usize,
    producer_cache: usize,
    needs_wakeup: bool,
    page: usize,
    mask: usize,
}
impl OwnedEvents {
    fn prepare(
        fd: BorrowedFd<'_>,
        bytes: u32,
        links: &crate::capture_setup::SetupLinks,
        stage: crate::capture::BoundaryStage,
    ) -> anyhow::Result<Self> {
        Self::prepare_with(fd, bytes, links, stage, EventInit::Kernel)
    }
    fn prepare_with(
        fd: BorrowedFd<'_>,
        bytes: u32,
        links: &crate::capture_setup::SetupLinks,
        stage: crate::capture::BoundaryStage,
        mode: EventInit,
    ) -> anyhow::Result<Self> {
        let mut transaction = crate::capture_setup::SetupResource::guarded(
            EventConstruction::default(),
            links,
            stage,
        );
        let result = (|| {
            links.check_owned(stage)?;
            let (info, fault) = match mode {
                EventInit::Kernel => (BorrowedMap::new(fd)?.info, 0),
                #[cfg(test)]
                EventInit::Host(fault) => (
                    BorrowedMapInfo {
                        map_type: 27,
                        id: 0,
                        key_size: 0,
                        value_size: 0,
                        max_entries: bytes,
                        flags: 0,
                    },
                    fault,
                ),
            };
            anyhow::ensure!(
                info.map_type == 27
                    && info.key_size == 0
                    && info.value_size == 0
                    && info.max_entries == bytes,
                "EVENTS shape mismatch"
            );
            Self::map_parts(fd, bytes, &mut transaction, fault, links, stage)
        })();
        let (page, position, producer_cache) = links.retain_result(result, stage)?;
        let parts = transaction.into_inner();
        Ok(Self {
            consumer: parts.consumer.expect("consumer mapped"),
            producer: parts.producer.expect("producer mapped"),
            position,
            producer_cache,
            needs_wakeup: false,
            page,
            mask: bytes as usize - 1,
        })
    }
    fn map_parts(
        fd: BorrowedFd<'_>,
        bytes: u32,
        transaction: &mut EventConstruction,
        fault: u8,
        links: &crate::capture_setup::SetupLinks,
        stage: crate::capture::BoundaryStage,
    ) -> anyhow::Result<(usize, usize, usize)> {
        let raw_page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        anyhow::ensure!(raw_page > 0, "page size unavailable");
        let page = raw_page as usize;
        anyhow::ensure!(
            bytes.is_power_of_two() && bytes as usize >= page && bytes as usize % page == 0,
            "EVENTS ring size invalid"
        );
        links.check_owned(stage)?;
        transaction.consumer = Some(EventMapping::new(
            fd,
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            0,
            links,
            stage,
        )?);
        #[cfg(test)]
        {
            let mapping = transaction.consumer.as_ref().unwrap();
            links.test_retained_mapping(mapping.address, mapping.len);
            if fault == 2 {
                panic!("EVENTS constructor unwound after consumer mmap");
            }
        }
        #[cfg(not(test))]
        let _ = links;
        let position = transaction
            .consumer
            .as_ref()
            .unwrap()
            .position()
            .load(std::sync::atomic::Ordering::Acquire);
        let len = (bytes as usize)
            .checked_mul(2)
            .and_then(|n| n.checked_add(page))
            .ok_or_else(|| anyhow::anyhow!("EVENTS mapping length overflow"))?;
        let offset = if fault == 1 { 1 } else { page };
        links.check_owned(stage)?;
        transaction.producer = Some(EventMapping::new(
            fd,
            len,
            libc::PROT_READ,
            offset,
            links,
            stage,
        )?);
        #[cfg(test)]
        {
            let mapping = transaction.producer.as_ref().unwrap();
            links.test_retained_mapping(mapping.address, mapping.len);
        }
        links.check_owned(stage)?;
        let producer_cache = transaction
            .producer
            .as_ref()
            .unwrap()
            .position()
            .load(std::sync::atomic::Ordering::Acquire);
        Ok((page, position, producer_cache))
    }
    fn consume(&mut self, len: usize) {
        self.position = self.position.wrapping_add((8 + len).next_multiple_of(8));
        self.consumer
            .position()
            .store(self.position, std::sync::atomic::Ordering::Release);
        self.needs_wakeup = true;
    }
    fn next(&mut self) -> Option<OwnedEvent<'_>> {
        use std::sync::atomic::{AtomicU32, Ordering, fence};
        loop {
            if self.position == self.producer_cache {
                if self.needs_wakeup {
                    fence(Ordering::SeqCst);
                    self.needs_wakeup = false;
                }
                self.producer_cache = self.producer.position().load(Ordering::Acquire);
            }
            if self.position == self.producer_cache {
                return None;
            }
            let offset = self.position & self.mask;
            let start = self.page + offset;
            assert!(start + 8 <= self.producer.len);
            // SAFETY: headers are 8-byte aligned and bounded in this mapping.
            let header = unsafe { &*((self.producer.address + start) as *const AtomicU32) }
                .load(Ordering::Acquire);
            if header & (1 << 31) != 0 {
                if !self.needs_wakeup {
                    return None;
                }
                fence(Ordering::SeqCst);
                self.needs_wakeup = false;
                continue;
            }
            let len = (header as usize) & self.mask;
            if header & (1 << 30) != 0 {
                self.consume(len);
                continue;
            }
            assert!(start + 8 + len <= self.producer.len);
            return Some(OwnedEvent {
                ring: self,
                start: start + 8,
                len,
            });
        }
    }
}
pub(crate) struct OwnedEvent<'a> {
    ring: &'a mut OwnedEvents,
    start: usize,
    len: usize,
}
impl std::ops::Deref for OwnedEvent<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        // SAFETY: next checked bounds; the exclusive consumer borrow prevents
        // consumption/reuse until this item's Drop publishes its new position.
        unsafe {
            std::slice::from_raw_parts(
                (self.ring.producer.address + self.start) as *const u8,
                self.len,
            )
        }
    }
}
impl Drop for OwnedEvent<'_> {
    fn drop(&mut self) {
        self.ring.consume(self.len);
    }
}
pub(crate) enum Events {
    Direct(aya::maps::RingBuf<aya::maps::MapData>),
    Controlled(OwnedEvents),
}
pub(crate) enum Event<'a> {
    Direct(aya::maps::ring_buf::RingBufItem<'a>),
    Controlled(OwnedEvent<'a>),
}
impl std::ops::Deref for Event<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Self::Direct(item) => item,
            Self::Controlled(item) => item,
        }
    }
}
impl Events {
    pub(crate) fn prepare(
        maps: &HashMap<String, OwnedFd>,
        setup: Option<&crate::capture_setup::SetupLinks>,
        stage: crate::capture::BoundaryStage,
        bytes: u32,
    ) -> anyhow::Result<Self> {
        use anyhow::Context as _;
        let fd = maps.get("EVENTS").context("EVENTS missing")?;
        if let Some(links) = setup {
            return OwnedEvents::prepare(fd.as_fd(), bytes, links, stage).map(Self::Controlled);
        }
        let map = aya::maps::MapData::from_fd(fd.try_clone()?)?;
        Ok(Self::Direct(aya::maps::RingBuf::try_from(
            aya::maps::Map::from_map_data(map)?,
        )?))
    }
    pub(crate) fn next(&mut self) -> Option<Event<'_>> {
        match self {
            Self::Direct(ring) => ring.next().map(Event::Direct),
            Self::Controlled(ring) => ring.next().map(Event::Controlled),
        }
    }
}

#[cfg(test)]
pub(crate) fn prepare_host_events(
    fd: BorrowedFd<'_>,
    links: &crate::capture_setup::SetupLinks,
    fault: u8,
) -> anyhow::Result<Events> {
    OwnedEvents::prepare_with(
        fd,
        4096,
        links,
        crate::capture::BoundaryStage::Discovery,
        EventInit::Host(fault),
    )
    .map(Events::Controlled)
}

#[cfg(test)]
mod fix1_event_tests {
    use super::*;
    use std::os::fd::FromRawFd as _;
    fn memory() -> OwnedFd {
        let fd = unsafe { libc::memfd_create(c"events-layout".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0);
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        assert_eq!(unsafe { libc::ftruncate(fd.as_raw_fd(), 4096 * 4) }, 0);
        fd
    }
    fn write(fd: BorrowedFd<'_>, offset: usize, bytes: &[u8]) {
        assert_eq!(
            unsafe {
                libc::pwrite(
                    fd.as_raw_fd(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    offset as libc::off_t,
                )
            },
            bytes.len() as isize
        );
    }
    fn position(fd: BorrowedFd<'_>) -> usize {
        let mut bytes = [0; std::mem::size_of::<usize>()];
        assert_eq!(
            unsafe { libc::pread(fd.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len(), 0) },
            bytes.len() as isize
        );
        usize::from_ne_bytes(bytes)
    }
    #[test]
    fn w079_fix1_real_events_busy_discard_wrap_and_release() {
        let fd = memory();
        let links = crate::capture_setup::SetupLinks::new();
        write(fd.as_fd(), 4096, &16usize.to_ne_bytes());
        write(fd.as_fd(), 8192, &((1u32 << 31) | 3).to_ne_bytes());
        let mut ring = prepare_host_events(fd.as_fd(), &links, 0).unwrap();
        assert!(ring.next().is_none());
        assert_eq!(position(fd.as_fd()), 0);
        write(fd.as_fd(), 8192 + 8, b"abc");
        write(fd.as_fd(), 8192, &3u32.to_ne_bytes());
        {
            let item = ring.next().unwrap();
            assert_eq!(&*item, b"abc");
            assert_eq!(position(fd.as_fd()), 0);
        }
        assert_eq!(position(fd.as_fd()), 16);
        write(fd.as_fd(), 8192 + 16, &((1u32 << 30) | 4).to_ne_bytes());
        write(fd.as_fd(), 4096, &32usize.to_ne_bytes());
        assert!(ring.next().is_none());
        assert_eq!(position(fd.as_fd()), 32);
        drop(ring);
        write(fd.as_fd(), 0, &4088usize.to_ne_bytes());
        write(fd.as_fd(), 4096, &4112usize.to_ne_bytes());
        write(fd.as_fd(), 8192 + 4088, &12u32.to_ne_bytes());
        write(fd.as_fd(), 8192 + 4096, b"abcdefghijkl");
        let mut ring = prepare_host_events(fd.as_fd(), &links, 0).unwrap();
        {
            let item = ring.next().unwrap();
            assert_eq!(&*item, b"abcdefghijkl");
        }
        assert_eq!(position(fd.as_fd()), 4112);
        assert!(ring.next().is_none());
    }
}

/// Focused Count adds only the public observer PID-namespace helper contract.
/// Typed-producer shared maps, single source of truth. The session side
/// owns and creates these (see `source_owner::MAPS`, which indexes this
/// table); the focused counter borrows the same FDs when a session is
/// present and creates private instances otherwise. Shapes must match
/// `crates/ebpf/src/shared_maps.rs` exactly; `prepare` asserts every
/// dimension against the object.
pub const PRODUCER_MAPS: [MapSpec; 12] = [
    MapSpec {
        name: "REL",
        map_type: 1,
        key_size: 48,
        value_size: 256,
        max_entries: 8192,
        flags: 0,
    },
    MapSpec {
        name: "TYPED_ADMISSION",
        map_type: 1,
        key_size: 24,
        value_size: 32,
        max_entries: 1024,
        flags: 0,
    },
    MapSpec {
        name: "SITE_BIND",
        map_type: 1,
        key_size: 24,
        value_size: 56,
        max_entries: 1024,
        flags: 0,
    },
    MapSpec {
        name: "BIND_PENDING",
        map_type: 1,
        key_size: 32,
        value_size: 304,
        max_entries: 4096,
        flags: 0,
    },
    MapSpec {
        name: "EXACT_NAME",
        map_type: 1,
        key_size: 144,
        value_size: 8,
        max_entries: 2048,
        flags: 0,
    },
    MapSpec {
        name: "DIGEST_INDEX",
        map_type: 1,
        key_size: 48,
        value_size: 8,
        max_entries: 2048,
        flags: 0,
    },
    MapSpec {
        name: "SELECTOR_DICT",
        map_type: 1,
        key_size: 16,
        value_size: 64,
        max_entries: 1024,
        flags: 0,
    },
    MapSpec {
        name: "THREAD_IDENTITY",
        map_type: 1,
        key_size: 16,
        value_size: 16,
        max_entries: 4096,
        flags: 0,
    },
    MapSpec {
        name: "PARTITION",
        map_type: 5,
        key_size: 104,
        value_size: 24,
        max_entries: 8192,
        flags: 0,
    },
    MapSpec {
        name: "ATTRIB_CONTROL",
        map_type: 2,
        key_size: 4,
        value_size: 64,
        max_entries: 1,
        flags: 0,
    },
    MapSpec {
        name: "SEGMENT_INDEX",
        map_type: 1,
        key_size: 32,
        value_size: 8,
        max_entries: 8192,
        flags: 0,
    },
    MapSpec {
        name: "PRODUCER_LOSS",
        map_type: 6,
        key_size: 4,
        value_size: 8,
        max_entries: 8,
        flags: 0,
    },
];

/// Maps the focused counter borrows from the session owner instead of
/// creating: the 12 producer maps plus the source/control maps its
/// same-handler check reads. Single source for the borrow set used by
/// `load_gated_borrowed`; the reservation estimator charges the full
/// table conservatively whether or not sharing engages.
pub const BORROWED_COUNT_MAPS: [&str; 20] = [
    "REL",
    "TYPED_ADMISSION",
    "SITE_BIND",
    "BIND_PENDING",
    "EXACT_NAME",
    "DIGEST_INDEX",
    "SELECTOR_DICT",
    "THREAD_IDENTITY",
    "PARTITION",
    "ATTRIB_CONTROL",
    "SEGMENT_INDEX",
    "PRODUCER_LOSS",
    "ATTR_STATE",
    "SOURCE_CONFIG",
    "SOURCE_GUARD",
    "SOURCE_REQUEST",
    "SOURCE_PAIR",
    "SOURCE_DOMAIN",
    "SOURCE_OBSERVER",
    "ITER_SLOT",
];

/// The legacy seven-map Count owner/validators remain independent.
pub const FOCUSED_COUNT_MAPS: [MapSpec; 33] = [
    crate::writer_gate::SPEC,
    COUNT_MAPS[0],
    COUNT_MAPS[1],
    COUNT_MAPS[2],
    COUNT_MAPS[3],
    COUNT_MAPS[4],
    COUNT_MAPS[5],
    COUNT_MAPS[6],
    // 6B sealed-bound maps (D-record §11.1 + L1): per-CPU bound
    // pairs under a seqlock, the host-owned per-key epoch, and the
    // global epoch default.
    MapSpec {
        name: "BOUNDS",
        map_type: 5,
        key_size: 8,
        value_size: 48,
        // 1024: the pool charges worst-case-full maps per
        // session, and the pinned 256 MiB two-session arithmetic
        // (`session_reservation_precedes_open...`) budgets these
        // three maps at ≤1,394,063 B/session on a 16-CPU box
        // (904×BOUNDS + 264×EPOCH ≤ 1,197,315 after the fixed
        // 65,536 B/map terms — 1024/1024 clears it by 1,283 B).
        // 8192 would refuse the second concurrent session the 6A
        // gates require (control-1 parent + survivor). 1024
        // covers qual-scale key counts (bounds annotate counted
        // hits only; overflow drops bounds with counts exact —
        // the D-record L2 degraded mode).
        max_entries: 1024,
        flags: 0,
    },
    MapSpec {
        name: "EPOCH",
        map_type: 5,
        key_size: 8,
        value_size: 8,
        // Same 1024 key space as BOUNDS (one epoch per bound
        // key); absent ⟺ EPOCH_CUR by BPF construction.
        max_entries: 1024,
        flags: 0,
    },
    MapSpec {
        name: "EPOCH_CUR",
        map_type: 2,
        key_size: 4,
        value_size: 8,
        max_entries: 1,
        flags: 0,
    },
    MapSpec {
        name: "NS_CONFIG",
        map_type: 2,
        key_size: 4,
        value_size: 16,
        max_entries: 1,
        flags: 0,
    },
    MapSpec {
        name: "NSFAIL",
        map_type: 6,
        key_size: 4,
        value_size: 8,
        max_entries: 1,
        flags: 0,
    },
    PRODUCER_MAPS[0],
    PRODUCER_MAPS[1],
    PRODUCER_MAPS[2],
    PRODUCER_MAPS[3],
    PRODUCER_MAPS[4],
    PRODUCER_MAPS[5],
    PRODUCER_MAPS[6],
    PRODUCER_MAPS[7],
    PRODUCER_MAPS[8],
    PRODUCER_MAPS[9],
    PRODUCER_MAPS[10],
    PRODUCER_MAPS[11],
    // Session-owned source/control shapes, duplicated from
    // `source_owner::MAPS`/`CONTROL_MAPS` (invisible here as
    // `pub(super)`); `source_owner` tests guard the duplication.
    MapSpec {
        name: "ATTR_STATE",
        map_type: 2,
        key_size: 4,
        value_size: 64,
        max_entries: 1,
        flags: 0,
    },
    MapSpec {
        name: "SOURCE_CONFIG",
        map_type: 2,
        key_size: 4,
        value_size: 8,
        max_entries: 1,
        flags: 0,
    },
    MapSpec {
        name: "SOURCE_GUARD",
        map_type: 1,
        key_size: 8,
        value_size: 16,
        max_entries: 8192,
        flags: 0,
    },
    MapSpec {
        name: "SOURCE_REQUEST",
        map_type: 1,
        key_size: 8,
        value_size: 112,
        max_entries: 4096,
        flags: 0,
    },
    MapSpec {
        name: "SOURCE_PAIR",
        map_type: 2,
        key_size: 4,
        value_size: 128,
        max_entries: 1,
        flags: 0,
    },
    MapSpec {
        name: "SOURCE_DOMAIN",
        map_type: 1,
        key_size: 4,
        value_size: 64,
        max_entries: 64,
        flags: 0,
    },
    MapSpec {
        name: "SOURCE_OBSERVER",
        map_type: 2,
        key_size: 4,
        value_size: 48,
        max_entries: 1,
        flags: 0,
    },
    MapSpec {
        name: "ITER_SLOT",
        map_type: 6,
        key_size: 4,
        value_size: 264,
        max_entries: 2,
        flags: 0,
    },
];
/// Pure, fail-closed shape/privacy admission for the learned-site counter.
/// Marker patching (when the object carries the VMA-join helper) reserves
/// its BTF scratch against the caller's budget.
pub fn prepare_focused_count(
    object: &[u8],
    budget: &crate::provider_observation::ObservationBudget,
) -> anyhow::Result<Prepared> {
    let mut prepared = prepare_focused_count_unpatched(object)?;
    patch_count_markers(&mut prepared, budget)?;
    check_focused_count_post_patch(&prepared)?;
    Ok(prepared)
}

/// Validate + prepare the count object WITHOUT patching: the
/// before-image stage for the diagnostic's count patch audit.
/// Production reaches the identical state through
/// `prepare_focused_count`, which patches immediately after; the
/// split moves statements verbatim and changes no behavior, only
/// exposes the patch boundary.
pub(crate) fn prepare_focused_count_unpatched(object: &[u8]) -> anyhow::Result<Prepared> {
    validate_count_object(object)?;
    let prepared = prepare(object, &FOCUSED_COUNT_MAPS, &COUNT_PROGS)?;
    anyhow::ensure!(
        prepared.maps.len() == FOCUSED_COUNT_MAPS.len() && prepared.progs.len() == 1,
        "focused shape"
    );
    let root = &prepared.progs[0];
    anyhow::ensure!(
        root.name == "count_entry"
            && !root.is_return
            && !root.insns.is_empty()
            && root.insns.len() % 8 == 0
            && root
                .subprogs
                .first()
                .is_some_and(|s| s.name == "count_entry" && s.insn_off == 0)
            && root.subprogs.iter().all(|s| !s.is_callback),
        "focused root"
    );
    Ok(prepared)
}

/// Post-patch allowlist + fixup validation over the patched count
/// image. Shared verbatim by production `prepare_focused_count` and
/// the diagnostic's audited count pipeline: identical checks,
/// identical order. Patch VMA-join markers before this runs:
/// pre-patch kfunc call sites carry reserved immediates, not helper
/// IDs. The allowlist then sees the patched image (kfunc calls use
/// src 2 and skip the helper check; the join's only plain helpers
/// are the kernel-memory read 113 and current-task-BTF 158).
pub(crate) fn check_focused_count_post_patch(prepared: &Prepared) -> anyhow::Result<()> {
    let root = &prepared.progs[0];
    let mut namespace_helper = false;
    for i in root.insns.chunks_exact(8) {
        anyhow::ensure!(!(i[0] == 0x18 && i[1] >> 4 == 4), "focused callback");
        if i[0] == 0x85 && i[1] >> 4 == 0 {
            let helper = u32le(&i[4..8]);
            anyhow::ensure!(
                [1, 2, 5, 113, 120, 158, 174].contains(&helper),
                "focused helper"
            );
            namespace_helper |= helper == 120;
        }
    }
    anyhow::ensure!(namespace_helper, "focused namespace helper absent");
    for fixup in &root.map_fixups {
        check_ld_imm64_site(&root.insns, fixup.insn_off, &root.name)?;
        anyhow::ensure!(
            FOCUSED_COUNT_MAPS.iter().any(|m| m.name == fixup.map),
            "focused map fixup"
        );
    }
    Ok(())
}
