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
use std::collections::HashMap;
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
/// task-0 spike (spike-uret.sh GREEN 3/3).
pub const HARVEST_MAPS: [MapSpec; 8] = [
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
        value_size: 8,
        max_entries: 1024,
        flags: 0,
    },
    MapSpec {
        name: "QUERY_NEXT",
        map_type: 1,
        key_size: 8,
        value_size: 8,
        max_entries: 4096,
        flags: 0,
    },
    MapSpec {
        name: "TRUNC",
        map_type: 1,
        key_size: 4,
        value_size: 8,
        max_entries: 64,
        flags: 0,
    },
    MapSpec {
        name: "CALLS",
        map_type: 1,
        key_size: 4,
        value_size: 8,
        max_entries: 64,
        flags: 0,
    },
    MapSpec {
        name: "TRIP",
        map_type: 1,
        key_size: 8,
        value_size: 8,
        max_entries: 128,
        flags: 0,
    },
    MapSpec {
        name: "LGCALLS",
        map_type: 1,
        key_size: 4,
        value_size: 8,
        max_entries: 64,
        flags: 0,
    },
];

/// Frozen capture shape (keyed-design §2): dims asserted vs the
/// object by `prepare`, fail-closed on drift. Read off the built
/// `osslscope-count` object (maps-section records).
pub const COUNT_MAPS: [MapSpec; 4] = [
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
/// the three entry-only tripwire counters.
pub const HARVEST_PROGS: [ProgSpec; 7] = [
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

/// Resolve an `R_BPF_64_32` call reloc to a `.text` function name.
/// Named FUNC syms resolve by (value, name); STT_SECTION syms (the
/// toolchain's reduction for LOCAL callees — `call -1` + section
/// reloc, as in query_return→walk_dispatch) resolve as
/// section_base + (imm+1)*8, the aya-obj rule. Either way the
/// target MUST be a `.text` entry: mid-function landings are drift,
/// never a guess.
fn call_target(
    syms: &[Sym],
    text_fns: &[(usize, usize, String)],
    text_idx: usize,
    site_sec: &[u8],
    r: &Reloc,
    prog: &str,
) -> anyhow::Result<String> {
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
    let addr = rsym.value as i64 + (imm + 1) * 8;
    let addr = usize::try_from(addr)
        .map_err(|_| anyhow::anyhow!("prog {prog}: call target out of range"))?;
    text_fns
        .iter()
        .find(|(v, _, _)| *v == addr)
        .map(|(_, _, n)| n.clone())
        .ok_or_else(|| anyhow::anyhow!("prog {prog}: call lands mid-function at {addr:#x}"))
}

/// Rewrite one static-call imm: call site at `rel_off` (in the final
/// layout) targets `target_off` (in the final layout).
fn apply_call(
    insns: &mut [u8],
    rel_off: usize,
    target_off: usize,
    prog: &str,
) -> anyhow::Result<()> {
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
            text_fns.push((f.value, f.value + f.size, f.name.clone()));
        }
    }
    let text_owner = |off: usize| {
        text_fns
            .iter()
            .find(|(a, b, _)| *a <= off && off < *b)
            .map(|(_, _, n)| n.clone())
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
        let main = sec
            .get(sym.value..sym.value + sym.size)
            .ok_or_else(|| anyhow::anyhow!("prog {} out of range", p.name))?;
        let mut fixups = Vec::new();
        // Main's owned relocs: map sites recorded, call targets rooted.
        let mut roots: Vec<(usize, String)> = Vec::new(); // (local off, fn)
        for r in relocs.get(p.section).map(Vec::as_slice).unwrap_or(&[]) {
            let owner = funcs
                .get(p.section)
                .and_then(|v| v.iter().find(|(a, b, _)| *a <= r.off && r.off < *b));
            let Some((_, _, oname)) = owner else {
                anyhow::bail!("prog {}: reloc @{} ownerless (drift)", p.name, r.off);
            };
            if *oname != p.name {
                continue; // belongs to an unloaded sibling prog
            }
            let rsym = syms
                .get(r.sym)
                .ok_or_else(|| anyhow::anyhow!("prog {}: bad reloc sym", p.name))?;
            let local = r.off - sym.value;
            match r.typ {
                R_BPF_64_64 => {
                    if !(rsym.is_obj && maps.iter().any(|m| m.name == rsym.name)) {
                        anyhow::bail!("prog {}: map reloc vs {}", p.name, rsym.name);
                    }
                    fixups.push(MapFixup {
                        insn_off: local,
                        map: rsym.name.clone(),
                    });
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
        // Reachable closure over `.text` call relocs (transitive).
        // Only reachable subprograms are linked: the verifier rejects
        // unreachable trailing insns, so blind `.text` appends fail.
        let mut included: Vec<String> = Vec::new();
        let mut work: Vec<String> = roots.iter().map(|(_, n)| n.clone()).collect();
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
                if *f0 <= r.off && r.off < *f1 && r.typ == R_BPF_64_32 {
                    let tidx = text_idx.ok_or_else(|| {
                        anyhow::anyhow!("prog {}: call reloc but no .text", p.name)
                    })?;
                    work.push(call_target(&syms, &text_fns, tidx, text, r, p.name)?);
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
        // Apply calls (main + included) and included map sites.
        for (local, target) in &roots {
            let t = base
                .get(target)
                .ok_or_else(|| anyhow::anyhow!("prog {}: call vs unlinked {target}", p.name))?;
            apply_call(&mut insns, *local, *t, p.name)?;
        }
        for r in relocs.get(".text").map(Vec::as_slice).unwrap_or(&[]) {
            let Some(owner) = text_owner(r.off) else {
                anyhow::bail!("prog {}: text reloc @{} ownerless (drift)", p.name, r.off);
            };
            let Some(obase) = base.get(&owner) else {
                continue; // subprogram unreachable from this prog
            };
            let rsym = syms
                .get(r.sym)
                .ok_or_else(|| anyhow::anyhow!("prog {}: bad text reloc sym", p.name))?;
            match r.typ {
                R_BPF_64_64 => {
                    if !(rsym.is_obj && maps.iter().any(|m| m.name == rsym.name)) {
                        anyhow::bail!("prog {}: text map reloc vs {}", p.name, rsym.name);
                    }
                    fixups.push(MapFixup {
                        insn_off: obase
                            + (r.off
                                - text_fns
                                    .iter()
                                    .find(|(_, _, n)| n == &owner)
                                    .map(|(v, _, _)| *v)
                                    .unwrap()),
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
                    let site = obase
                        + (r.off
                            - text_fns
                                .iter()
                                .find(|(_, _, n)| n == &owner)
                                .map(|(v, _, _)| *v)
                                .unwrap());
                    apply_call(&mut insns, site, *t, p.name)?;
                }
                t => anyhow::bail!("prog {}: text reloc type {t} unsupported", p.name),
            }
        }
        out.push(PreparedProg {
            name: p.name.to_string(),
            is_return,
            insns,
            map_fixups: fixups,
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
        let fd =
            ossl_bpf_sys::map_create(m.map_type, m.key_size, m.value_size, m.max_entries, None)
                .with_context(|| format!("map_create {}", m.name))?;
        maps.insert(m.name.clone(), fd);
    }
    let mut progs = HashMap::new();
    for p in &prep.progs {
        let mut insns = p.insns.clone();
        for f in &p.map_fixups {
            let insn = insns
                .get_mut(f.insn_off..f.insn_off + 8)
                .ok_or_else(|| anyhow::anyhow!("{}: fixup out of range", p.name))?;
            // The compiler emits map sites with src=0; the reloc means
            // "this imm64 is a map" — the loader sets src AND fd.
            // Anything else is an already-relocated (or corrupt) object.
            if insn[0] != 0x18 || insn[1] >> 4 != 0 {
                anyhow::bail!("{}: fixup site not an unrelocated ld_imm64", p.name);
            }
            let fd = maps
                .get(&f.map)
                .ok_or_else(|| anyhow::anyhow!("{}: unknown map {}", p.name, f.map))?;
            insn[1] = (insn[1] & 0x0f) | (BPF_PSEUDO_MAP_FD << 4);
            insn[4..8].copy_from_slice(&(fd.as_raw_fd() as u32).to_le_bytes());
        }
        let mut log = vec![0u8; 1 << 20];
        let license = c"GPL";
        let fd = ossl_bpf_sys::prog_load_kprobe(&insns, license, None, &mut log).map_err(|e| {
            let detail = String::from_utf8_lossy(&log)
                .trim_end_matches('\0')
                .chars()
                .take(2000)
                .collect::<String>();
            anyhow::anyhow!("prog_load {}: {e}\n{detail}", p.name)
        })?;
        progs.insert(p.name.clone(), fd);
    }
    Ok(Loaded { progs, maps })
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
}
