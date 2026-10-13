//! P7 item 2: member-object shape tests (offline, unprivileged).
//!
//! Pins the `osslscope-members` object contract via the pure
//! `loader::prepare` path (no caps needed): 513 progs (512 baked-slot
//! members + entry), exact 14-map dims, baked-slot distinctness, a
//! forbidden-helper scan, and size records. Behavioral proof (baking,
//! walk contents) is the live `members_probe` suite's job.
//!
//! Run (optional mode, the local default):
//! `OSSL_MEMBERS_OBJECT=<members.o> cargo +1.88.0 test
//! --test members_shape`. Unset object → labeled SKIP (CI has no
//! BPF artifacts in the host job); set-but-bad → FAIL.
//!
//! Run (required mode, the CI gate): prepend
//! `OSSL_MEMBERS_REQUIRED=1`. Unset/empty object → FAIL — no
//! silent skips; the suite must run against the job's freshly
//! built members object. Set-but-bad → FAIL in both modes.

use osslscope::loader::{MEMBER_MAPS, MEMBER_PROGS, MapSpec};
use std::collections::{HashMap, HashSet};

fn object_path() -> Option<String> {
    std::env::var("OSSL_MEMBERS_OBJECT")
        .ok()
        .filter(|s| !s.is_empty())
}

/// Required mode (the CI gate): `OSSL_MEMBERS_REQUIRED=1` fails
/// closed on a missing object. Any other value, including unset,
/// keeps the optional local default.
fn is_required() -> bool {
    matches!(std::env::var("OSSL_MEMBERS_REQUIRED").as_deref(), Ok("1"))
}

/// Missing-object branch shared by the nine object-backed tests:
/// loud FAIL in required mode, clearly labeled optional-mode SKIP
/// otherwise.
fn no_object() {
    if is_required() {
        panic!(
            "FAIL(members-required): OSSL_MEMBERS_OBJECT unset or empty; \
             required mode refuses silent skips"
        );
    }
    eprintln!(
        "SKIP(members-object,optional-mode): OSSL_MEMBERS_OBJECT unset \
         (set OSSL_MEMBERS_REQUIRED=1 to fail closed)"
    );
}

fn object_bytes() -> Option<Vec<u8>> {
    let path = object_path()?;
    Some(std::fs::read(&path).unwrap_or_else(|e| panic!("read OSSL_MEMBERS_OBJECT={path}: {e}")))
}

fn prepared() -> Option<osslscope::loader::Prepared> {
    let obj = object_bytes()?;
    Some(osslscope::loader::prepare(&obj, &MEMBER_MAPS, &MEMBER_PROGS).expect("prepare members.o"))
}

/// Raw main bytes per func symbol in one section: (name, bytes).
fn section_mains(obj: &[u8], section: &str) -> Vec<(String, Vec<u8>)> {
    let elf = goblin::elf::Elf::parse(obj).expect("parse members.o");
    let (idx, sh) = elf
        .section_headers
        .iter()
        .enumerate()
        .find(|(_, s)| &elf.shdr_strtab[s.sh_name] == section)
        .unwrap_or_else(|| panic!("section {section} missing"));
    let base = sh.sh_offset as usize;
    let sec = &obj[base..base + sh.sh_size as usize];
    elf.syms
        .iter()
        .filter(|s| s.st_type() == goblin::elf::sym::STT_FUNC && s.st_shndx == idx && s.st_size > 0)
        .map(|s| {
            let name = elf.strtab.get_at(s.st_name).unwrap_or("?").to_string();
            let a = s.st_value as usize;
            let bytes = sec[a..a + s.st_size as usize].to_vec();
            (name, bytes)
        })
        .collect()
}

/// Helper-call ids in raw (pre-link) main bytes: `call` (0x85)
/// sites with src == 0 (helper form — imm is the helper id).
/// Pseudo-calls (src == 1: static calls, imm = relative offset or
/// -1 + reloc) are excluded — the toolchain pre-resolves
/// same-section locals WITHOUT relocs, so imm alone cannot tell
/// them apart (observed: pseudo imm 504 in every member). A src==0
/// imm is ALWAYS collected (even -1 — helper-form -1 is itself a
/// finding, never silently dropped). `ld_imm64` (0x18) spans 16
/// bytes.
fn helper_calls(raw: &[u8]) -> Vec<i32> {
    assert_eq!(raw.len() % 8, 0, "main bytes must be whole insns");
    let mut out = Vec::new();
    let mut i = 0;
    while i + 8 <= raw.len() {
        let op = raw[i];
        if op == 0x18 {
            i += 16;
            continue;
        }
        if op == 0x85 && raw[i + 1] >> 4 == 0 {
            out.push(i32::from_le_bytes([
                raw[i + 4],
                raw[i + 5],
                raw[i + 6],
                raw[i + 7],
            ]));
        }
        i += 8;
    }
    out
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn has_section(obj: &[u8], section: &str) -> bool {
    let elf = goblin::elf::Elf::parse(obj).expect("parse members.o");
    elf.section_headers
        .iter()
        .any(|s| &elf.shdr_strtab[s.sh_name] == section)
}

/// (func name, helper id) pairs across the mains sections PLUS
/// the shared-subprogram section (`.text`): `walk_dispatch` /
/// `classify_alg` / `emit_*` live there, so a mains-only scan
/// would miss a forbidden helper reachable only via `.text` (an
/// in-memory 181 mutation in `.text` passed the old scan).
/// `.text` joins when present; a fully-inlining toolchain would
/// leave no `.text`, and then the mains scan is already complete.
fn collect_helpers(obj: &[u8]) -> Vec<(String, i32)> {
    let mut out = Vec::new();
    for section in ["uprobe", "uretprobe"] {
        for (name, bytes) in section_mains(obj, section) {
            for id in helper_calls(&bytes) {
                out.push((name.clone(), id));
            }
        }
    }
    if has_section(obj, ".text") {
        for (name, bytes) in section_mains(obj, ".text") {
            for id in helper_calls(&bytes) {
                out.push((format!(".text:{name}"), id));
            }
        }
    }
    out
}

/// File offset of the `CALLS` max_entries low byte in the
/// `maps` section (for the S4 negative: bump 64 -> 65 in a COPY).
/// The def record is the loader's 28-byte aya legacy shape with
/// max_entries at +12; the 0x40 assertion fails loudly on layout
/// drift instead of mutating the wrong byte.
fn calls_max_entries_offset(obj: &[u8]) -> usize {
    let elf = goblin::elf::Elf::parse(obj).expect("parse members.o");
    let (idx, sh) = elf
        .section_headers
        .iter()
        .enumerate()
        .find(|(_, s)| &elf.shdr_strtab[s.sh_name] == "maps")
        .unwrap_or_else(|| panic!("section maps missing"));
    let sym = elf
        .syms
        .iter()
        .find(|s| {
            s.st_type() == goblin::elf::sym::STT_OBJECT
                && s.st_shndx == idx
                && elf.strtab.get_at(s.st_name) == Some("CALLS")
        })
        .expect("CALLS map sym present");
    assert_eq!(sym.st_size as usize, 28, "CALLS def record is 7 x u32");
    let off = sh.sh_offset as usize + sym.st_value as usize + 12;
    assert_eq!(obj[off], 0x40, "CALLS max_entries low byte is 64");
    off
}

/// File offset of the last `0` in the `member_000` strtab name (for
/// the S2 negative: rename to `member_00x` in a COPY). Same length,
/// NUL preserved, section headers and symtab untouched.
fn member_000_name_offset(obj: &[u8]) -> usize {
    let elf = goblin::elf::Elf::parse(obj).expect("parse members.o");
    let strtab = elf
        .section_headers
        .iter()
        .find(|s| &elf.shdr_strtab[s.sh_name] == ".strtab")
        .expect(".strtab present");
    let sym = elf
        .syms
        .iter()
        .find(|s| {
            s.st_type() == goblin::elf::sym::STT_FUNC
                && elf.strtab.get_at(s.st_name) == Some("member_000")
        })
        .expect("member_000 sym present");
    let off = strtab.sh_offset as usize + sym.st_name + "member_000".len() - 1;
    assert_eq!(obj[off], b'0', "member_000 name ends in 0");
    assert_eq!(obj[off + 1], 0, "member_000 NUL terminator intact");
    off
}

/// File offset of the first helper-form call in `.text` (for the
/// S5 negative: flip it to a forbidden id in a COPY of the
/// object). `None` when `.text` is absent or call-free.
fn first_text_call_offset(obj: &[u8]) -> Option<usize> {
    let elf = goblin::elf::Elf::parse(obj).expect("parse members.o");
    let sh = elf
        .section_headers
        .iter()
        .find(|s| &elf.shdr_strtab[s.sh_name] == ".text")?;
    let base = sh.sh_offset as usize;
    let sec = &obj[base..base + sh.sh_size as usize];
    let mut i = 0;
    while i + 8 <= sec.len() {
        if sec[i] == 0x18 {
            i += 16;
            continue;
        }
        if sec[i] == 0x85 && sec[i + 1] >> 4 == 0 {
            return Some(base + i);
        }
        i += 8;
    }
    None
}

#[test]
fn scanner_unit() {
    // call 112 (helper form) then ld_imm64 (16B, must be skipped,
    // not misparsed) then pseudo `call -1` (src=1, excluded) then
    // pseudo `call 504` (src=1, pre-resolved local, excluded) then
    // call 12 (helper form, included).
    let mut b = Vec::new();
    b.extend_from_slice(&[0x85, 0x00, 0, 0, 112, 0, 0, 0]);
    b.extend_from_slice(&[0x18, 0x00, 0, 0, 0, 0, 0, 0]);
    b.extend_from_slice(&[0x85, 0x00, 0, 0, 12, 0, 0, 0]); // looks like call 12: skipped
    b.extend_from_slice(&[0x85, 0x10, 0, 0, 0xff, 0xff, 0xff, 0xff]);
    b.extend_from_slice(&[0x85, 0x10, 0, 0, 0xf8, 0x01, 0, 0]);
    b.extend_from_slice(&[0x85, 0x00, 0, 0, 12, 0, 0, 0]);
    b.extend_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(helper_calls(&b), vec![112, 12]);
}

/// S1: the object prepares to exactly 513 progs.
#[test]
fn s1_prepare_513() {
    let Some(prep) = prepared() else {
        no_object();
        return;
    };
    assert_eq!(prep.progs.len(), 513, "512 members + member_entry");
    assert_eq!(
        prep.maps.len(),
        13,
        "exactly the 13 member maps (D dropped PENDING)"
    );
}

/// S2: symbol names and entry/return sections.
#[test]
fn s2_names_sections() {
    let Some(prep) = prepared() else {
        no_object();
        return;
    };
    let by_name: HashMap<&str, &osslscope::loader::PreparedProg> =
        prep.progs.iter().map(|p| (p.name.as_str(), p)).collect();
    let entry = by_name.get("member_entry").expect("member_entry present");
    assert!(!entry.is_return, "member_entry is an entry (uprobe)");
    for j in 0..512u32 {
        let want = format!("member_{j:03}");
        let m = by_name
            .get(want.as_str())
            .unwrap_or_else(|| panic!("{want} present"));
        assert!(m.is_return, "{want} is a return (uretprobe)");
    }
}

/// S2-negative: a renamed required program symbol must fail
/// `prepare` with the prog-missing error — not an ELF-parse error.
/// Renames `member_000` -> `member_00x` in an in-memory COPY (one
/// strtab byte; same length, NUL preserved, still parses) and pins
/// the exact failure.
#[test]
fn s2_prog_sym_negative() {
    let Some(obj) = object_bytes() else {
        no_object();
        return;
    };
    let off = member_000_name_offset(&obj);
    let mut mutated = obj.clone();
    mutated[off] = b'x';
    assert_eq!(
        obj.iter()
            .zip(mutated.iter())
            .filter(|(a, b)| a != b)
            .count(),
        1,
        "exactly one byte differs (surgical prog-sym mutation)"
    );
    let elf = goblin::elf::Elf::parse(&mutated).expect("mutated object still parses");
    let names: Vec<&str> = elf
        .syms
        .iter()
        .filter_map(|s| elf.strtab.get_at(s.st_name))
        .collect();
    assert!(
        !names.contains(&"member_000"),
        "member_000 gone after rename"
    );
    assert!(
        names.contains(&"member_00x"),
        "member_00x present after rename"
    );
    let err = osslscope::loader::prepare(&mutated, &MEMBER_MAPS, &MEMBER_PROGS)
        .err()
        .expect("renamed member_000 must fail prepare");
    assert_eq!(
        err.to_string(),
        "prog member_000 missing",
        "specific prog-symbol failure"
    );
}

/// S3: all 512 member bodies pairwise distinct (baking necessary
/// condition — identical bodies would disprove baked slots; the
/// live suite proves baking behaviorally).
#[test]
fn s3_bodies_distinct() {
    let Some(obj) = object_bytes() else {
        no_object();
        return;
    };
    let mains = section_mains(&obj, "uretprobe");
    let members: Vec<&(String, Vec<u8>)> =
        mains.iter().filter(|(n, _)| n != "member_entry").collect();
    assert_eq!(members.len(), 512, "512 member mains in uretprobe");
    let hashes: HashSet<u64> = members.iter().map(|(_, b)| fnv1a64(b)).collect();
    assert_eq!(hashes.len(), 512, "all 512 member bodies distinct");
}

/// S4: the 13 map dims pinned (6 retained + 7 item-3 scan-plane;
/// PENDING dropped in stage D when members switched to SCAN —
/// R18 §6.1 — end state 13).
#[test]
fn s4_map_dims() {
    let Some(prep) = prepared() else {
        no_object();
        return;
    };
    let want: &[(&str, u32, u32, u32, u32, u32)] = &[
        ("EVENTS", 27, 0, 0, 1 << 21, 0),
        ("GEN", 1, 8, 8, 1024, 0),
        ("LOSS", 5, 4, 8, 32, 0),
        ("TRUNC", 5, 4, 8, 64, 0),
        ("CALLS", 5, 4, 8, 64, 0),
        ("ALG_CLASS", 1, 8, 42, 1024, 0),
        // Item-3 scan plane (D end state: members read SCAN).
        ("SCAN", 9, 4, 40, 1024, 0),
        ("SEQ", 1, 4, 8, 4096, 0),
        ("BIRTH", 1, 4, 2, 4096, 0),
        ("RCOUNT", 1, 4, 8, 4096, 0),
        ("T_CACHE", 1, 8, 16, 1024, 0),
        ("CTRL", 2, 4, 24, 1, 0),
        ("ATTEMPT", 6, 4, 8, 1, 0),
    ];
    assert_eq!(prep.maps.len(), want.len());
    for (got, w) in prep.maps.iter().zip(want.iter()) {
        assert_eq!(
            (
                got.name.as_str(),
                got.map_type,
                got.key_size,
                got.value_size,
                got.max_entries,
                got.flags
            ),
            (w.0, w.1, w.2, w.3, w.4, w.5),
            "map dims pinned"
        );
    }
}

/// S4-negative: a tampered required map definition must fail
/// `prepare` with the map-dims error — not an ELF-parse error.
/// Bumps the `CALLS` max_entries 64 -> 65 in an in-memory COPY (one
/// byte; section headers and symtab untouched, still parses) and
/// pins the exact failure.
#[test]
fn s4_map_dims_negative() {
    let Some(obj) = object_bytes() else {
        no_object();
        return;
    };
    let off = calls_max_entries_offset(&obj);
    let mut mutated = obj.clone();
    mutated[off] = 0x41;
    assert_eq!(
        obj.iter()
            .zip(mutated.iter())
            .filter(|(a, b)| a != b)
            .count(),
        1,
        "exactly one byte differs (surgical map-def mutation)"
    );
    goblin::elf::Elf::parse(&mutated).expect("mutated object still parses");
    let err = osslscope::loader::prepare(&mutated, &MEMBER_MAPS, &MEMBER_PROGS)
        .err()
        .expect("tampered CALLS dims must fail prepare");
    assert_eq!(
        err.to_string(),
        "map CALLS: dims [5, 4, 8, 65, 0] != spec [5, 4, 8, 64, 0]",
        "specific map-definition failure"
    );
}

/// S5: helper set pinned (raw bytes, exact, mains + `.text`
/// subprograms), SPLIT by plane (R18 §6.5 — stage D): map_lookup
/// (1), map_update (2), map_delete (3 — entry skip-path deletes
/// plus the member-epilogue retire, inlined into member mains and
/// `.text`-resident shared paths), get_current_pid_tgid (14),
/// probe_read_user (112), probe_read_user_str (114),
/// ringbuf_reserve (131), ringbuf_submit (132), ringbuf_query
/// (134 — ENTRY-ONLY, the governor occupancy read; members never
/// query), get_attach_cookie (174) — and nothing else. In
/// particular: no tail_call (12 — members never chain), no
/// bpf_loop (181). Ids verified against
/// /usr/include/linux/bpf.h FN table; the set was read off the
/// built object and reviewed, then pinned as a regression lock.
#[test]
fn s5_no_forbidden_helpers() {
    let Some(obj) = object_bytes() else {
        no_object();
        return;
    };
    const FORBIDDEN: [i32; 2] = [12, 181];
    const PINNED: [i32; 10] = [1, 2, 3, 14, 112, 114, 131, 132, 134, 174];
    let mut observed: HashSet<i32> = HashSet::new();
    for (name, id) in collect_helpers(&obj) {
        observed.insert(id);
        assert!(
            !FORBIDDEN.contains(&id),
            "{name}: forbidden helper {id} (12=tail 181=loop)"
        );
        // Split rule (D): 134 is entry-only (uprobe main); 3
        // reaches member mains (the gated-epilogue retire) as
        // well as the entry skip path.
        if id == 134 {
            assert_eq!(
                name, "member_entry",
                "ringbuf_query outside the entry main: {name}"
            );
        }
    }
    let mut obs: Vec<i32> = observed.into_iter().collect();
    obs.sort_unstable();
    eprintln!("members helpers observed: {obs:?}");
    assert_eq!(obs, PINNED, "member helper set pinned (review any drift)");
}

/// S5-negative: a forbidden helper smuggled into `.text` must
/// trip the scan. Flips the first `.text` helper-form call to 181
/// (bpf_loop) in an in-memory COPY and asserts the collector
/// reports it from a `.text` func. SKIPs labeled when `.text` is
/// absent (same tolerance as S5); FAILs when `.text` exists but
/// has no helper-form call (the negative needs a call site).
#[test]
fn s5_dottext_negative() {
    let Some(obj) = object_bytes() else {
        no_object();
        return;
    };
    if !has_section(&obj, ".text") {
        eprintln!("SKIP(s5-negative): no .text section");
        return;
    }
    let off =
        first_text_call_offset(&obj).expect(".text exists but has no helper-form call to mutate");
    let mut mutated = obj.clone();
    mutated[off + 4..off + 8].copy_from_slice(&181i32.to_le_bytes());
    let hits: Vec<(String, i32)> = collect_helpers(&mutated)
        .into_iter()
        .filter(|(_, id)| *id == 181)
        .collect();
    assert_eq!(hits.len(), 1, "exactly the smuggled 181 is reported");
    assert!(
        hits[0].0.starts_with(".text:"),
        "smuggled 181 attributed to .text, got {}",
        hits[0].0
    );
}

/// S6: per-member size sanity cap + records (the real xlated
/// envelope is the live L1 leg's job).
#[test]
fn s6_size_cap() {
    let Some(prep) = prepared() else {
        no_object();
        return;
    };
    let mut sizes: Vec<(String, usize)> = prep
        .progs
        .iter()
        .filter(|p| p.name != "member_entry")
        .map(|p| (p.name.clone(), p.insns.len()))
        .collect();
    sizes.sort_by_key(|(_, s)| *s);
    let (min, max) = (sizes[0].1, sizes[511].1);
    let mean = sizes.iter().map(|(_, s)| s).sum::<usize>() / 512;
    eprintln!("member prepared bytes: min={min} mean={mean} max={max} n=512");
    assert!(
        max <= 65536,
        "per-member prepared bytes <= 64KiB sanity cap"
    );
}

/// S7: retired maps positively absent (QUERY_NEXT cursor, TERMD
/// proofs, LGCALLS legacy partition). `prepare` already fails
/// closed on extra maps; this names the absences.
#[test]
fn s7_retired_maps_absent() {
    let Some(obj) = object_bytes() else {
        no_object();
        return;
    };
    for retired in ["QUERY_NEXT", "TERMD", "LGCALLS"] {
        let spec: MapSpec = osslscope::loader::HARVEST_MAPS
            .iter()
            .find(|m| m.name == retired)
            .map(|m| MapSpec {
                name: m.name,
                map_type: m.map_type,
                key_size: m.key_size,
                value_size: m.value_size,
                max_entries: m.max_entries,
                flags: m.flags,
            })
            .unwrap_or_else(|| panic!("{retired} dims known from HARVEST_MAPS"));
        let mut maps: Vec<MapSpec> = MEMBER_MAPS.to_vec();
        maps.push(spec);
        let err = osslscope::loader::prepare(&obj, &maps, &MEMBER_PROGS)
            .err()
            .unwrap_or_else(|| panic!("{retired} must be absent from members.o"));
        assert_eq!(
            err.to_string(),
            format!("map {retired} missing"),
            "retired map fails for its absence, not any error"
        );
    }
}

/// S8: the const-folded specials (stage D) — member_000 carries
/// the ns-first read + RET emit + empty-slot gate, member_511 the
/// guard eligibility + GUARD event; members 1..510 are fold-free
/// and near-uniform (same code modulo baked immediates). Two known
/// variances, both proven innocent via objdump diff (same helper
/// sequence, same stores): J=4 == KIND_ALG, so LLVM CSEs the
/// idx/kind stores in both ALG emits (16B smaller —
/// walk_dispatch/classify stay shared `.text`, so no other J gets
/// this luck); J=40 keeps its idx immediate in a register across
/// the ALG emit (one extra mov, 8B larger — pure regalloc quirk;
/// the T-gate itself compiles identically for all J as `t > J-1 ⟺
/// walk`, verified at 040/041). Any other outlier fails loud —
/// investigate, don't widen.
#[test]
fn s8_folded_specials() {
    let Some(obj) = object_bytes() else {
        no_object();
        return;
    };
    let mains = section_mains(&obj, "uretprobe");
    let size = |n: &str| {
        mains
            .iter()
            .find(|(m, _)| m == n)
            .unwrap_or_else(|| panic!("{n} present"))
            .1
            .len()
    };
    let s000 = size("member_000");
    let s511 = size("member_511");
    let mid: Vec<(String, usize)> = (1..511u32)
        .map(|j| (format!("member_{j:03}"), size(&format!("member_{j:03}"))))
        .collect();
    let (mid_min, mid_max) = (
        mid.iter().map(|(_, s)| s).min().unwrap(),
        mid.iter().map(|(_, s)| s).max().unwrap(),
    );
    eprintln!(
        "raw main bytes: member_000={s000} member_511={s511} mid_min={mid_min} mid_max={mid_max}"
    );
    assert!(
        s000 > *mid_max,
        "member_000 above middle (ns-first + RET emit + empty gate)"
    );
    assert!(
        s511 > *mid_max,
        "member_511 above middle (guard eligibility + GUARD event)"
    );
    let mins: Vec<&str> = mid
        .iter()
        .filter(|(_, s)| s == mid_min)
        .map(|(n, _)| n.as_str())
        .collect();
    let maxs: Vec<&str> = mid
        .iter()
        .filter(|(_, s)| s == mid_max)
        .map(|(n, _)| n.as_str())
        .collect();
    assert_eq!(
        mins,
        ["member_004"],
        "only known small outlier is J=4 (KIND_ALG CSE)"
    );
    assert_eq!(
        maxs,
        ["member_040"],
        "only known large outlier is J=40 (regalloc mov)"
    );
    assert!(
        mid_max - mid_min <= 24,
        "members 1..510 near-uniform (16 + 8 known)"
    );
}
