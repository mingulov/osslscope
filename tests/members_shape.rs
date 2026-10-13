//! P7 item 2: member-object shape tests (offline, unprivileged).
//!
//! Pins the `osslscope-members` object contract via the pure
//! `loader::prepare` path (no caps needed): 513 progs (512 baked-slot
//! members + entry), exact 14-map dims, baked-slot distinctness, a
//! forbidden-helper scan, and size records. Behavioral proof (baking,
//! walk contents) is the live `members_probe` suite's job.
//!
//! Run: `OSSL_MEMBERS_OBJECT=<members.o> cargo +1.88.0 test
//! --test members_shape`. Unset object → labeled SKIP (CI has no
//! BPF artifacts in the host job); set-but-bad → FAIL.

use osslscope::loader::{MEMBER_MAPS, MEMBER_PROGS, MapSpec};
use std::collections::{HashMap, HashSet};

fn object_path() -> Option<String> {
    std::env::var("OSSL_MEMBERS_OBJECT")
        .ok()
        .filter(|s| !s.is_empty())
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
        eprintln!("SKIP(members-object): OSSL_MEMBERS_OBJECT unset");
        return;
    };
    assert_eq!(prep.progs.len(), 513, "512 members + member_entry");
    assert_eq!(prep.maps.len(), 14, "exactly the 14 member maps");
}

/// S2: symbol names and entry/return sections.
#[test]
fn s2_names_sections() {
    let Some(prep) = prepared() else {
        eprintln!("SKIP(members-object): OSSL_MEMBERS_OBJECT unset");
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

/// S3: all 512 member bodies pairwise distinct (baking necessary
/// condition — identical bodies would disprove baked slots; the
/// live suite proves baking behaviorally).
#[test]
fn s3_bodies_distinct() {
    let Some(obj) = object_bytes() else {
        eprintln!("SKIP(members-object): OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let mains = section_mains(&obj, "uretprobe");
    let members: Vec<&(String, Vec<u8>)> =
        mains.iter().filter(|(n, _)| n != "member_entry").collect();
    assert_eq!(members.len(), 512, "512 member mains in uretprobe");
    let hashes: HashSet<u64> = members.iter().map(|(_, b)| fnv1a64(b)).collect();
    assert_eq!(hashes.len(), 512, "all 512 member bodies distinct");
}

/// S4: the 14 map dims pinned (7 item-2 + 7 item-3 scan-plane;
/// PENDING drops in subtask C — end state 13).
#[test]
fn s4_map_dims() {
    let Some(prep) = prepared() else {
        eprintln!("SKIP(members-object): OSSL_MEMBERS_OBJECT unset");
        return;
    };
    let want: &[(&str, u32, u32, u32, u32, u32)] = &[
        ("EVENTS", 27, 0, 0, 1 << 21, 0),
        ("PENDING_QUERY", 1, 8, 16, 1024, 0),
        ("GEN", 1, 8, 8, 1024, 0),
        ("LOSS", 5, 4, 8, 32, 0),
        ("TRUNC", 5, 4, 8, 64, 0),
        ("CALLS", 5, 4, 8, 64, 0),
        ("ALG_CLASS", 1, 8, 42, 1024, 0),
        // Item-3 scan plane (bridge: PENDING drops in subtask C
        // when members switch to SCAN; end state is 13).
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

/// S5: helper set pinned (raw bytes, exact, mains + `.text`
/// subprograms): map_lookup (1), map_update (2),
/// get_current_pid_tgid (14), probe_read_user (112),
/// probe_read_user_str (114), ringbuf_reserve (131),
/// ringbuf_submit (132), get_attach_cookie (174) — and nothing
/// else. In particular: no tail_call (12 — members never chain),
/// no ringbuf_query (134 — entry-only per §5.4), no bpf_loop
/// (181), no map_delete (3 — peek-only proven). Ids verified
/// against /usr/include/linux/bpf.h FN table; the set was read off
/// the built object and reviewed (every id justified by the walk
/// body), then pinned as a regression lock.
#[test]
fn s5_no_forbidden_helpers() {
    let Some(obj) = object_bytes() else {
        eprintln!("SKIP(members-object): OSSL_MEMBERS_OBJECT unset");
        return;
    };
    const FORBIDDEN: [i32; 3] = [12, 134, 181];
    const PINNED: [i32; 8] = [1, 2, 14, 112, 114, 131, 132, 174];
    let mut observed: HashSet<i32> = HashSet::new();
    for (name, id) in collect_helpers(&obj) {
        observed.insert(id);
        assert!(
            !FORBIDDEN.contains(&id),
            "{name}: forbidden helper {id} (12=tail 134=rbq 181=loop)"
        );
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
        eprintln!("SKIP(members-object): OSSL_MEMBERS_OBJECT unset");
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
        eprintln!("SKIP(members-object): OSSL_MEMBERS_OBJECT unset");
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
        eprintln!("SKIP(members-object): OSSL_MEMBERS_OBJECT unset");
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
        assert!(
            osslscope::loader::prepare(&obj, &maps, &MEMBER_PROGS).is_err(),
            "{retired} must be absent from members.o"
        );
    }
}

/// S8: the const-folded specials — member_000 carries the CALLS
/// bump + empty-slot gate, member_511 the overrun guard; members
/// 1..510 are fold-free and near-uniform (same code modulo baked
/// immediates). The one known variance: J=4 == KIND_ALG, so LLVM
/// CSEs the idx/kind stores in both ALG emits (16B smaller —
/// proven innocent via objdump diff; walk_dispatch/classify stay
/// shared `.text`, so no other J gets this luck). Variance beyond
/// 16B means a missed fold — investigate, don't widen.
#[test]
fn s8_folded_specials() {
    let Some(obj) = object_bytes() else {
        eprintln!("SKIP(members-object): OSSL_MEMBERS_OBJECT unset");
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
    let mid: Vec<usize> = (1..511u32)
        .map(|j| size(&format!("member_{j:03}")))
        .collect();
    let (mid_min, mid_max) = (mid.iter().min().unwrap(), mid.iter().max().unwrap());
    eprintln!(
        "raw main bytes: member_000={s000} member_511={s511} mid_min={mid_min} mid_max={mid_max}"
    );
    assert!(
        s000 > *mid_max,
        "member_000 largest (CALLS bump + empty gate)"
    );
    assert!(s511 > *mid_max, "member_511 above middle (overrun guard)");
    assert!(
        mid_max - mid_min <= 16,
        "members 1..510 near-uniform (only the J=4 CSE is known)"
    );
}
