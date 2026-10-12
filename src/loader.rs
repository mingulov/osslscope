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
use std::collections::{HashMap, HashSet};
use std::os::fd::{AsRawFd as _, OwnedFd};

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
pub struct MapSpec {
    pub name: &'static str,
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub flags: u32,
}

/// Wanted program: looked up by symbol in its section.
pub struct ProgSpec {
    pub name: &'static str,
    /// "uprobe" (entry) or "uretprobe" (return).
    pub section: &'static str,
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
pub const COUNT_MAPS: [MapSpec; 5] = [
    MapSpec {
        name: "COUNTS",
        map_type: 5,
        key_size: 8,
        value_size: 24,
        max_entries: 8192,
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

/// A map-fd fixup site: byte offset of the insn + map name.
pub struct MapFixup {
    pub insn_off: usize,
    pub map: String,
}

/// One prepared program: relocated bytes (`.text` appended, call
/// relocs applied) + map fixups for `load()`.
pub struct PreparedProg {
    pub name: String,
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
pub struct Prepared {
    pub progs: Vec<PreparedProg>,
    pub maps: Vec<MapSpecLite>,
}

/// Map dims confirmed against the object (load input).
pub struct MapSpecLite {
    pub name: String,
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub flags: u32,
}

/// Loaded fds (needs caps).
pub struct Loaded {
    pub progs: HashMap<String, OwnedFd>,
    pub maps: HashMap<String, OwnedFd>,
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
        if n == "uprobe" || n == "uretprobe" {
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
    let text_owner = |off: usize| {
        text_fns
            .iter()
            .find(|(a, b, _)| *a <= off && off < *b)
            .map(|(a, b, n)| (*a, *b, n.clone()))
    };

    let mut out = Vec::new();
    for p in progs {
        let is_return = match p.section {
            "uprobe" => false,
            "uretprobe" => true,
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
        for r in relocs.get(p.section).map(Vec::as_slice).unwrap_or(&[]) {
            let owner = funcs
                .get(p.section)
                .and_then(|v| v.iter().find(|(a, b, _)| *a <= r.off && r.off < *b));
            let Some((_, ob, oname)) = owner else {
                anyhow::bail!("prog {}: reloc @{} ownerless (drift)", p.name, r.off);
            };
            if *oname != p.name {
                continue; // belongs to an unloaded sibling prog
            }
            // Calls patch 8 bytes, `ld_imm64` sites (func and map)
            // 16: the whole site must sit inside its owner.
            let width = match r.typ {
                R_BPF_64_64 => 16,
                R_BPF_64_32 => 8,
                t => anyhow::bail!("prog {}: reloc type {t} unsupported", p.name),
            };
            check_site_contained(r.off, width, *ob, oname, p.name)?;
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
        }
        // Reachable closure over `.text` call and function-pointer
        // relocs (transitive). Only reachable subprograms are linked:
        // the verifier rejects unreachable trailing insns, so blind
        // `.text` appends fail.
        let mut included: Vec<String> = Vec::new();
        let mut work: Vec<String> = roots
            .iter()
            .chain(func_roots.iter())
            .map(|(_, n)| n.clone())
            .collect();
        while let Some(next) = work.pop() {
            if included.contains(&next) {
                continue;
            }
            included.push(next.clone());
            let (f0, f1, _) = text_fns
                .iter()
                .find(|(_, _, n)| *n == next)
                .ok_or_else(|| anyhow::anyhow!("prog {}: call vs unknown {next}", p.name))?;
            for r in relocs.get(".text").map(Vec::as_slice).unwrap_or(&[]) {
                if *f0 <= r.off && r.off < *f1 {
                    let width = match r.typ {
                        R_BPF_64_32 => 8,
                        R_BPF_64_64 => 16,
                        // Unknown types bail in the apply loop below.
                        _ => continue,
                    };
                    check_site_contained(r.off, width, *f1, &next, p.name)?;
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
        included.sort_by_key(|n| text_fns.iter().find(|(_, _, m)| m == n).map(|(v, _, _)| *v));
        // Layout: main + included subprograms in `.text` order.
        let mut insns = main.to_vec();
        let mut base: HashMap<String, usize> = HashMap::new();
        for name in &included {
            let (f0, f1, _) = text_fns.iter().find(|(_, _, n)| n == name).unwrap();
            let bytes = text
                .get(*f0..*f1)
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
            let Some((f0, f1, owner)) = text_owner(r.off) else {
                anyhow::bail!("prog {}: text reloc @{} ownerless (drift)", p.name, r.off);
            };
            let Some(obase) = base.get(&owner) else {
                continue; // subprogram unreachable from this prog
            };
            let width = match r.typ {
                R_BPF_64_64 => 16,
                R_BPF_64_32 => 8,
                t => anyhow::bail!("prog {}: text reloc type {t} unsupported", p.name),
            };
            check_site_contained(r.off, width, f1, &owner, p.name)?;
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
                        if !included.contains(&target) {
                            anyhow::bail!("prog {}: func vs excluded {}", p.name, target);
                        }
                        let t = base.get(&target).ok_or_else(|| {
                            anyhow::anyhow!("prog {}: func vs unlinked {}", p.name, target)
                        })?;
                        let site = obase + (r.off - f0);
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
                        insn_off: obase + (r.off - f0),
                        map: rsym.name.clone(),
                    });
                }
                R_BPF_64_32 => {
                    let tidx = text_idx.ok_or_else(|| {
                        anyhow::anyhow!("prog {}: call reloc but no .text", p.name)
                    })?;
                    let target = call_target(&syms, &text_fns, tidx, text, r, p.name)?;
                    // Call targets must be entries (closure invariant).
                    if !included.contains(&target) {
                        anyhow::bail!("prog {}: call vs excluded {}", p.name, target);
                    }
                    let t = base.get(&target).ok_or_else(|| {
                        anyhow::anyhow!("prog {}: call vs unlinked {}", p.name, target)
                    })?;
                    let site = obase + (r.off - f0);
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

/// Load a prepared object: create maps, apply map-fd fixups (with
/// the `BPF_PSEUDO_MAP_FD` assertion), load progs raw. Needs caps.
/// Verifier output travels in the error on failure.
pub fn load(prep: &Prepared) -> anyhow::Result<Loaded> {
    use anyhow::Context as _;
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
    for p in &prep.progs {
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
        }
        let license = c"GPL";
        // Callback shapes only: synthesize BTF + func_info and load
        // it (the kernel needs the callback's FUNC_PROTO — without
        // it `bpf_loop` fails `missing btf func_info`). Every other
        // prog loads BTF-less exactly as before. The BTF fd outlives
        // both load attempts (drop closes it; loaded progs hold
        // their own refs).
        let mut btf_fd: Option<std::os::fd::OwnedFd> = None;
        let mut func_info_bytes: Vec<u8> = Vec::new();
        if p.subprogs.iter().any(|s| s.is_callback) {
            let (btf, info) =
                synth_btf(&p.subprogs).with_context(|| format!("synth_btf {}", p.name))?;
            for (off, id) in &info {
                func_info_bytes.extend_from_slice(&off.to_le_bytes());
                func_info_bytes.extend_from_slice(&id.to_le_bytes());
            }
            let mut btf_log = vec![0u8; 1 << 16];
            let fd = ossl_bpf_sys::btf_load(&btf, &mut btf_log).map_err(|e| {
                let detail = String::from_utf8_lossy(trim_nul(&btf_log))
                    .chars()
                    .take(1000)
                    .collect::<String>();
                anyhow::anyhow!("btf_load {}: {e}\n{detail}", p.name)
            })?;
            btf_fd = Some(fd);
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
        let fd = match ossl_bpf_sys::prog_load_kprobe_quiet(
            &insns,
            license,
            None,
            &p.name,
            prog_btf(&btf_fd),
        ) {
            Ok(fd) => fd,
            Err(_) => {
                let mut log = vec![0u8; 4 << 20];
                match ossl_bpf_sys::prog_load_kprobe(
                    &insns,
                    license,
                    None,
                    &mut log,
                    &p.name,
                    prog_btf(&btf_fd),
                ) {
                    Ok(fd) => fd,
                    Err(e) => {
                        let full = trim_nul(&log);
                        let detail = String::from_utf8_lossy(full)
                            .chars()
                            .take(2000)
                            .collect::<String>();
                        let spill = spill_verifier_log(&p.name, full);
                        return Err(anyhow::anyhow!(
                            "prog_load {}: {e}\n{detail}{}",
                            p.name,
                            spill
                                .map(|p| format!("\n(full verifier log: {})", p.display()))
                                .unwrap_or_default()
                        ));
                    }
                }
            }
        };
        progs.insert(p.name.clone(), fd);
    }
    Ok(Loaded { progs, maps })
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
        b[80..88].copy_from_slice(&[0x85, 0, 0, 0, 0, 0, 0, 0]);
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
    fn load_rejects_huge_fixup_off_caps_free() {
        // `Prepared` fields are public: a hand-built fixup at
        // `MAX-7` (aligned) must ERR, not panic on `off + 8`
        // overflow in debug. No maps: the validator bails before
        // any fd use, so no caps are needed.
        let prep = Prepared {
            maps: Vec::new(),
            progs: vec![PreparedProg {
                name: "p".to_string(),
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
}
