//! P5b-D: loader BTF + func_info for helper-callback shapes.
//!
//! Live lane only (`OSSL_D_LIVE=1`, caps via setcap like the other
//! live tests): hand-assembles a minimal `bpf_loop` object (main +
//! address-taken callback bumping a counter map; no toolchain) and
//! (a) loads it, (b) attaches it to `getpid` in our own libc and
//! proves the callback fires N×M, (c) captures the success-path
//! verifier cost.

use osslscope::loader::{
    MapFixup, MapSpec, MapSpecLite, Prepared, PreparedProg, ProgSpec, SubprogInfo,
};
use std::os::fd::AsRawFd as _;

/// `BPF_FUNC_loop` (kernel ABI; the verifier log names the callee,
/// and the cost test pins `call bpf_loop#` so a renumbered table
/// fails loud instead of silently calling another helper).
const BPF_FUNC_LOOP: u32 = 181;
/// `BPF_FUNC_map_lookup_elem` (same pinning rationale as above).
const BPF_FUNC_MAP_LOOKUP_ELEM: u32 = 1;

fn gated() -> bool {
    std::env::var("OSSL_D_LIVE").unwrap_or_default() == "1"
}

fn dcount_spec() -> MapSpec {
    MapSpec {
        name: "DCOUNT",
        map_type: 2,
        key_size: 4,
        value_size: 8,
        max_entries: 1,
        flags: 0,
    }
}

/// Minimal `bpf_loop` relocatable: 1 uprobe prog
/// (`bpf_loop(4, cb, fp-8, 0)`, 8 insns), 1 `.text` callback (map
/// counter bump + continue, 13 insns), 1 ARRAY map def, 2 relocs.
/// Layout (offsets): ehdr 0/64, uprobe 64/64, .text 128/104, maps
/// 232/28, .reluprobe 260/16, .rel.text 276/16, symtab 292/96,
/// strtab 388/18, shstrtab 406/66, shdrs 472/576.
fn loop_elf() -> Vec<u8> {
    fn u16(v: u16) -> [u8; 2] {
        v.to_le_bytes()
    }
    fn u32(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }
    fn u64(v: u64) -> [u8; 8] {
        v.to_le_bytes()
    }
    let mut b = vec![0u8; 472 + 9 * 64];
    // ELF header.
    b[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    b[4] = 2; // 64-bit
    b[5] = 1; // LE
    b[6] = 1; // version
    b[16..18].copy_from_slice(&u16(1)); // ET_REL
    b[18..20].copy_from_slice(&u16(247)); // EM_BPF
    b[40..48].copy_from_slice(&u64(472)); // shoff
    b[58..60].copy_from_slice(&u16(64)); // shentsize
    b[60..62].copy_from_slice(&u16(9)); // shnum
    b[62..64].copy_from_slice(&u16(8)); // shstrndx
    // uprobe main: ld_imm64 r2,cb + bpf_loop(4, r2, fp-8, 0) + exit.
    b[64..80].copy_from_slice(&[0x18, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    b[80..88].copy_from_slice(&[0xb7, 0x01, 0, 0, 4, 0, 0, 0]); // r1 = 4
    b[88..96].copy_from_slice(&[0xbf, 0xa3, 0, 0, 0, 0, 0, 0]); // r3 = r10
    b[96..104].copy_from_slice(&[0x07, 0x03, 0, 0, 0xf8, 0xff, 0xff, 0xff]); // r3 -= 8
    b[104..112].copy_from_slice(&[0xb7, 0x04, 0, 0, 0, 0, 0, 0]); // r4 = 0
    let mut call_loop = [0x85u8, 0x00, 0, 0, 0, 0, 0, 0];
    call_loop[4..8].copy_from_slice(&BPF_FUNC_LOOP.to_le_bytes());
    b[112..120].copy_from_slice(&call_loop); // call bpf_loop
    b[120..128].copy_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]); // exit
    // .text callback: bump DCOUNT[0], return 0 (continue).
    let mut o = 128;
    let mut insn = |bytes: &[u8; 8]| {
        b[o..o + 8].copy_from_slice(bytes);
        o += 8;
    };
    insn(&[0x18, 0x01, 0, 0, 0, 0, 0, 0]); // ld r1,map (slot 0)
    insn(&[0, 0, 0, 0, 0, 0, 0, 0]); // (slot 1)
    insn(&[0xb7, 0x00, 0, 0, 0, 0, 0, 0]); // r0 = 0
    insn(&[0x62, 0x0a, 0xfc, 0xff, 0, 0, 0, 0]); // [r10-4] = 0 (key)
    insn(&[0xbf, 0xa2, 0, 0, 0, 0, 0, 0]); // r2 = r10
    insn(&[0x07, 0x02, 0, 0, 0xfc, 0xff, 0xff, 0xff]); // r2 -= 4
    let mut call_lookup = [0x85u8, 0x00, 0, 0, 0, 0, 0, 0];
    call_lookup[4..8].copy_from_slice(&BPF_FUNC_MAP_LOOKUP_ELEM.to_le_bytes());
    insn(&call_lookup); // call map_lookup_elem
    insn(&[0x15, 0x00, 4, 0, 0, 0, 0, 0]); // if r0 == 0 goto +4 (exit)
    insn(&[0x79, 0x01, 0, 0, 0, 0, 0, 0]); // r1 = [r0]
    insn(&[0x07, 0x01, 0, 0, 1, 0, 0, 0]); // r1 += 1
    insn(&[0x7b, 0x10, 0, 0, 0, 0, 0, 0]); // [r0] = r1
    insn(&[0xb7, 0x00, 0, 0, 0, 0, 0, 0]); // r0 = 0 (continue)
    insn(&[0x95, 0, 0, 0, 0, 0, 0, 0]); // exit
    assert_eq!(o, 232, "callback must be 13 insns");
    // maps: ARRAY u32->u64 max 1.
    for (i, v) in [2u32, 4, 8, 1, 0, 0, 0].iter().enumerate() {
        b[232 + i * 4..236 + i * 4].copy_from_slice(&u32(*v));
    }
    // .reluprobe: func ref @0 (sym 2 = cb, R_BPF_64_64).
    b[260..268].copy_from_slice(&u64(0));
    b[268..276].copy_from_slice(&u64(2 << 32 | 1));
    // .rel.text: map ref @0 (sym 3 = DCOUNT, R_BPF_64_64).
    b[276..284].copy_from_slice(&u64(0));
    b[284..292].copy_from_slice(&u64(3 << 32 | 1));
    // symtab: null, dprobe, cb, DCOUNT.
    let mut sym = |o: usize, name: u32, info: u8, shndx: u16, val: u64, size: u64| {
        b[o..o + 4].copy_from_slice(&u32(name));
        b[o + 4] = info;
        b[o + 6..o + 8].copy_from_slice(&u16(shndx));
        b[o + 8..o + 16].copy_from_slice(&u64(val));
        b[o + 16..o + 24].copy_from_slice(&u64(size));
    };
    sym(292, 0, 0, 0, 0, 0);
    sym(316, 1, 0x12, 1, 0, 64);
    sym(340, 8, 0x12, 2, 0, 104);
    sym(364, 11, 0x11, 3, 0, 28);
    // strtab.
    let s = b"\0dprobe\0cb\0DCOUNT\0";
    b[388..388 + s.len()].copy_from_slice(s);
    // shstrtab.
    let t = b"\0uprobe\0.text\0maps\0.reluprobe\0.rel.text\0.symtab\0.strtab\0.shstrtab\0";
    b[406..406 + t.len()].copy_from_slice(t);
    // Section headers: null, uprobe, .text, maps, .reluprobe,
    // .rel.text, symtab, strtab, shstrtab.
    #[allow(clippy::too_many_arguments)]
    let mut sh = |i: usize,
                  name: u32,
                  ty: u32,
                  flags: u64,
                  off: u64,
                  size: u64,
                  link: u32,
                  info: u32,
                  entsize: u64| {
        let o = 472 + i * 64;
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
    sh(1, 1, 1, 6, 64, 64, 0, 0, 0);
    sh(2, 8, 1, 6, 128, 104, 0, 0, 0);
    sh(3, 14, 1, 3, 232, 28, 0, 0, 0);
    sh(4, 19, 9, 0, 260, 16, 6, 1, 16);
    sh(5, 30, 9, 0, 276, 16, 6, 2, 16);
    sh(6, 40, 2, 0, 292, 96, 7, 1, 24);
    sh(7, 48, 3, 0, 388, 18, 0, 0, 0);
    sh(8, 56, 3, 0, 406, 66, 0, 0, 0);
    b
}

fn prepare_loop() -> osslscope::loader::Prepared {
    osslscope::loader::prepare(
        &loop_elf(),
        &[dcount_spec()],
        &[ProgSpec {
            name: "dprobe",
            section: "uprobe",
        }],
    )
    .expect("prepare callback shape")
}

/// Hand-built `Prepared` with one map fixup (`Prepared` fields are
/// public, so `load()` cannot assume `prepare()` validated the
/// site): the load path must reject misaligned, reserved-byte, and
/// truncated fixup sites before patching.
fn fixup_prep(insns: Vec<u8>, off: usize) -> Prepared {
    Prepared {
        maps: vec![MapSpecLite {
            name: "DCOUNT".to_string(),
            map_type: 2,
            key_size: 4,
            value_size: 8,
            max_entries: 1,
            flags: 0,
        }],
        progs: vec![PreparedProg {
            name: "dprobefix".to_string(),
            is_return: false,
            insns,
            map_fixups: vec![MapFixup {
                insn_off: off,
                map: "DCOUNT".to_string(),
            }],
            subprogs: vec![SubprogInfo {
                name: "dprobefix".to_string(),
                insn_off: 0,
                is_callback: false,
            }],
        }],
    }
}

fn ld_imm64_r1() -> [u8; 16] {
    let mut s = [0u8; 16];
    s[0] = 0x18;
    s[1] = 0x01;
    s
}

#[test]
#[ignore = "live lane only (see module docs)"]
fn load_rejects_bad_map_fixup_sites() {
    if !gated() {
        eprintln!("d live leg: set OSSL_D_LIVE=1; skipping");
        return;
    }
    // Reserved offset bytes set.
    let mut site = ld_imm64_r1();
    site[2] = 1;
    let mut insns = site.to_vec();
    insns.extend_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]);
    let e = osslscope::loader::load(&fixup_prep(insns, 0))
        .err()
        .expect("reserved fixup must fail");
    assert!(
        e.to_string().contains("map site reserved bytes set"),
        "{e:#}"
    );
    // Misaligned site.
    let mut insns = vec![0u8; 4];
    insns.extend_from_slice(&ld_imm64_r1());
    insns.extend_from_slice(&[0u8; 4]);
    let e = osslscope::loader::load(&fixup_prep(insns, 4))
        .err()
        .expect("misaligned fixup must fail");
    assert!(e.to_string().contains("map site misaligned"), "{e:#}");
    // Truncated site (first slot only).
    let insns = ld_imm64_r1()[..8].to_vec();
    let e = osslscope::loader::load(&fixup_prep(insns, 0))
        .err()
        .expect("truncated fixup must fail");
    assert!(e.to_string().contains("map site out of range"), "{e:#}");
}

/// The callback shape prepares (relocation + subprog table) and
/// LOADS on 7.0: the loader synthesizes BTF + func_info for the
/// callback, answering r5's `missing btf func_info` EINVAL.
#[test]
#[ignore = "live lane only (see module docs)"]
fn bpf_loop_shape_loads_with_synth_btf() {
    if !gated() {
        eprintln!("d live leg: set OSSL_D_LIVE=1; skipping");
        return;
    }
    let prep = prepare_loop();
    let subs: Vec<(String, u32, bool)> = prep.progs[0]
        .subprogs
        .iter()
        .map(|s| (s.name.clone(), s.insn_off, s.is_callback))
        .collect();
    assert_eq!(
        subs,
        vec![
            ("dprobe".to_string(), 0, false),
            ("cb".to_string(), 8, true),
        ],
        "subprog table must flag the callback"
    );
    let loaded = osslscope::loader::load(&prep).expect("load callback shape");
    assert!(loaded.progs.contains_key("dprobe"), "dprobe must be loaded");
}

/// Our own libc path from /proc/self/maps (first `libc.so.6`
/// mapping with a file path).
fn own_libc() -> String {
    let maps = std::fs::read_to_string("/proc/self/maps").expect("read maps");
    maps.lines()
        .filter_map(|l| l.split_whitespace().nth(5))
        .find(|p| p.contains("libc.so.6"))
        .expect("libc mapping")
        .to_string()
}

fn read_count(map_fd: std::os::fd::RawFd) -> u64 {
    let mut val = [0u8; 8];
    // SAFETY: DCOUNT is key 4 / value 8 (plain ARRAY); the key is
    // a `u32` encoding and `val` is `[u8; 8]`, fd live (asserted —
    // a short buffer would be kernel-written heap overflow).
    debug_assert_eq!(val.len(), 8);
    unsafe { ossl_bpf_sys::map_lookup_elem(map_fd, &0u32.to_le_bytes(), &mut val) }
        .expect("lookup DCOUNT[0]");
    u64::from_le_bytes(val)
}

/// Parsed verifier success summary (lane kernel 7.0 line shape:
/// `processed 20 insns (limit 1000000) max_states_per_insn 1
/// total_states 2 peak_states 3 mark_read 0`). The state metrics are
/// verifier STATES, not frames.
struct VerifierCost {
    processed: u64,
    max_states_per_insn: u64,
    total_states: u64,
    peak_states: u64,
}

/// Parse one verifier summary line. Every required field must be
/// present and numeric — a missing or malformed metric is a failed
/// pin (`None`), never a silent default.
fn parse_verifier_cost(line: &str) -> Option<VerifierCost> {
    let tok: Vec<&str> = line.split_whitespace().collect();
    // `processed <n> insns` head.
    if tok.len() < 3 || tok[0] != "processed" || tok[2] != "insns" {
        return None;
    }
    let processed: u64 = tok[1].parse().ok()?;
    // Required `key <n>` metrics (other pairs like `(limit N)` and
    // `mark_read 0` are ignored). Each required key must appear
    // exactly once — no first-wins on repeats.
    let metric = |key: &str| -> Option<u64> {
        let mut at = tok.iter().position(|t| *t == key)?;
        if tok.iter().skip(at + 1).any(|t| *t == key) {
            return None;
        }
        at += 1;
        tok.get(at)?.parse().ok()
    };
    Some(VerifierCost {
        processed,
        max_states_per_insn: metric("max_states_per_insn")?,
        total_states: metric("total_states")?,
        peak_states: metric("peak_states")?,
    })
}

#[test]
fn cost_parser_accepts_golden_line() {
    let c = parse_verifier_cost(
        "processed 20 insns (limit 1000000) max_states_per_insn 1 total_states 2 peak_states 3 mark_read 0",
    )
    .expect("golden line must parse");
    assert_eq!(c.processed, 20);
    assert_eq!(c.max_states_per_insn, 1);
    assert_eq!(c.total_states, 2);
    assert_eq!(c.peak_states, 3);
}

#[test]
fn cost_parser_rejects_missing_metric() {
    assert!(
        parse_verifier_cost(
            "processed 20 insns (limit 1000000) max_states_per_insn 1 total_states 2 mark_read 0"
        )
        .is_none(),
        "dropped peak_states must not parse"
    );
}

#[test]
fn cost_parser_rejects_malformed_number() {
    assert!(
        parse_verifier_cost(
            "processed XX insns max_states_per_insn 1 total_states 2 peak_states 3"
        )
        .is_none(),
        "non-numeric processed must not parse"
    );
    assert!(
        parse_verifier_cost(
            "processed 20 insns max_states_per_insn 1 total_states 2 peak_states 3x"
        )
        .is_none(),
        "trailing garbage must not parse"
    );
}

#[test]
fn cost_parser_rejects_repeated_key() {
    assert!(
        parse_verifier_cost(
            "processed 20 insns max_states_per_insn 1 total_states 2 total_states 99 peak_states 3"
        )
        .is_none(),
        "repeated metric key must not parse (no first-wins)"
    );
}

#[test]
fn cost_parser_rejects_wrong_shape() {
    assert!(
        parse_verifier_cost("verification successful").is_none(),
        "non-summary line must not parse"
    );
    assert!(
        parse_verifier_cost("").is_none(),
        "empty line must not parse"
    );
}

/// The callback FIRES: attached to our own `getpid`, three calls
/// must bump the counter by 3 triggers × 4 `bpf_loop` iterations.
/// The pre-trigger zero proves the read path and that nothing
/// fired spuriously.
#[test]
#[ignore = "live lane only (see module docs)"]
fn bpf_loop_callback_fires_nxm() {
    if !gated() {
        eprintln!("d live leg: set OSSL_D_LIVE=1; skipping");
        return;
    }
    let prep = prepare_loop();
    let loaded = osslscope::loader::load(&prep).expect("load callback shape");
    let prog_fd = loaded.progs["dprobe"].as_raw_fd();
    let map_fd = loaded.maps["DCOUNT"].as_raw_fd();
    let libc = own_libc();
    let elf_bytes = std::fs::read(&libc).expect("read libc");
    let off =
        osslscope::discovery::elf::dynsym_file_offset(&elf_bytes, "getpid").expect("getpid off");
    let path = std::ffi::CString::new(libc).unwrap();
    // Self-pid filter: exact counts (system-wide would catch
    // stray getpids). The filter covers the whole THREAD GROUP, so
    // exactness additionally requires single-threaded execution: the
    // leg itself is synchronous (getpid only in the trigger loop,
    // none between attach and the reads otherwise) and the live
    // runner uses --test-threads=1, so no sibling test thread can
    // issue getpid concurrently.
    let _link =
        ossl_bpf_sys::link_create_uprobe_multi(prog_fd, &path, &[off], &[0], std::process::id())
            .expect("attach dprobe to getpid");
    assert_eq!(read_count(map_fd), 0, "counter must start at zero");
    for _ in 0..3 {
        unsafe { libc::getpid() };
    }
    assert_eq!(
        read_count(map_fd),
        12,
        "3 triggers x 4 loop iterations must bump the counter"
    );
}

/// Callback identity in the kernel's linked image: the kernel
/// expands the `bpf_loop` call into a bounds-check + dispatch
/// sequence and relocates the callback (lane 7.0 profile: 168B sent
/// -> 360B stored), so exact bytes past the setup are NOT pinned.
/// Pinned instead: growth as an anti-pruning observation (a pruned
/// callback shrinks to main-only 64B), the func-ptr site intact,
/// its imm decoded RELATIVELY (an absolute reading lands on main's
/// own exit), the expansion's static call agreeing on the same
/// entry, the callback's map-load prologue at that entry, and the
/// xlated exit count matching the linked subprog table.
#[test]
#[ignore = "live lane only (see module docs)"]
fn bpf_loop_shape_kernel_image_matches_send() {
    if !gated() {
        eprintln!("d live leg: set OSSL_D_LIVE=1; skipping");
        return;
    }
    let prep = prepare_loop();
    let p = &prep.progs[0];
    let loaded = osslscope::loader::load(&prep).expect("load callback shape");
    let prog_fd = loaded.progs["dprobe"].as_raw_fd();
    let xlated = ossl_bpf_sys::prog_xlated_bytes(prog_fd).expect("xlated fetch");
    assert!(
        xlated.len() > p.insns.len(),
        "linked image must grow past the {}B send (pruning would shrink to 64B)",
        p.insns.len()
    );
    assert_eq!(
        &xlated[0..4],
        &p.insns[0..4],
        "func-ptr ld_imm64 opcode/nibble must survive"
    );
    assert_eq!(
        &xlated[16..48],
        &p.insns[16..48],
        "register setup must survive verbatim"
    );
    // Callback identity, three independent ways. The kernel keeps
    // the func-ptr imm relative (lane 7.0 rewrote 7 -> 25 for the
    // expanded layout; an absolute reading would land on main's
    // own exit, not the callback).
    let imm = u32::from_le_bytes([xlated[4], xlated[5], xlated[6], xlated[7]]) as usize;
    let entry = 0 + 1 + imm;
    assert!(
        entry * 8 + 8 <= xlated.len(),
        "func-ptr target ({entry}) must land inside the stored image"
    );
    // (1) The loop expansion's static pseudo-call must agree: scan
    // for CALL-with-PSEUDO_CALL-src (stepping over `ld_imm64`
    // second slots, whose bytes are not opcodes) and decode each
    // relative target. NOTE: xlated pseudo-calls decode from `off`
    // (observed: imm reads 0), unlike pre-verifier images, which
    // keep the toolchain imm-form the loader writes.
    let mut call_targets = Vec::new();
    let mut i = 0;
    while i * 8 + 8 <= xlated.len() {
        let op = xlated[i * 8];
        if op == 0x85 && xlated[i * 8 + 1] >> 4 == 1 {
            let rel = i16::from_le_bytes([xlated[i * 8 + 2], xlated[i * 8 + 3]]);
            call_targets.push(i as i64 + 1 + rel as i64);
        }
        i += if op == 0x18 { 2 } else { 1 };
    }
    assert!(
        call_targets.contains(&(entry as i64)),
        "a static call must target the func-ptr entry {entry}: {call_targets:?}"
    );
    // (2) Recognizable callback prologue at the entry: the counter
    // map load (`ld_imm64 r1`, map-fd src nibble — the loader
    // patched the fd pre-load and the kernel kept the shape).
    assert_eq!(xlated[entry * 8], 0x18, "callback must open with ld_imm64");
    assert_eq!(
        xlated[entry * 8 + 1],
        0x11,
        "callback map load must keep dst r1 + map-fd src"
    );
    // (3) Subprogram count from exit scan must match the linked
    // table, and the callback must follow main's terminal exit
    // (it sits past its linked position: the expansion moved it).
    let mut exits = Vec::new();
    let mut j = 0;
    while j * 8 + 8 <= xlated.len() {
        let op = xlated[j * 8];
        if op == 0x95 {
            exits.push(j);
        }
        j += if op == 0x18 { 2 } else { 1 };
    }
    assert_eq!(
        exits.len(),
        p.subprogs.len(),
        "xlated exits must match linked subprogs: {exits:?}"
    );
    assert!(
        exits[0] < entry,
        "callback entry {entry} must follow main's exit at {}",
        exits[0]
    );
    let sent_cb = p
        .subprogs
        .iter()
        .find(|s| s.is_callback)
        .expect("callback")
        .insn_off as usize;
    assert!(
        entry > sent_cb,
        "callback entry {entry} must sit past its linked offset {sent_cb}"
    );
}

/// Where a manual metadata load failed: setup (BTF upload, map
/// create, fixup patch — caps or helper bugs) versus the actual
/// program load (the kernel's metadata verdict). Rejection pins
/// require `ProgLoad`: a setup failure must never count as a
/// metadata rejection.
#[derive(Debug)]
enum MetaLoadError {
    Setup(anyhow::Error),
    ProgLoad(std::io::Error, String),
}

impl std::fmt::Display for MetaLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetaLoadError::Setup(e) => write!(f, "setup: {e:#}"),
            MetaLoadError::ProgLoad(e, tail) => write!(f, "prog load: {e}\nlog tail: {tail}"),
        }
    }
}

/// Manual load of the prepared callback shape with caller-chosen
/// func_info records: map create + fixup patch (same encoding the
/// loader applies) + BTF synth/upload + log-buffer load (the
/// loader's quiet-first path keeps no log). Returns the verifier
/// log text. Callers corrupt `info` to pin kernel metadata
/// rejections.
fn load_with_func_info(
    p: &osslscope::loader::PreparedProg,
    info: &[(u32, u32)],
    prog_name: &str,
) -> Result<String, MetaLoadError> {
    use anyhow::Context as _;
    let (btf, _) = osslscope::loader::synth_btf(&p.subprogs).map_err(MetaLoadError::Setup)?;
    let mut func_info_bytes: Vec<u8> = Vec::new();
    for (off, id) in info {
        func_info_bytes.extend_from_slice(&off.to_le_bytes());
        func_info_bytes.extend_from_slice(&id.to_le_bytes());
    }
    let mut btf_log = vec![0u8; 1 << 16];
    let btf_fd =
        ossl_bpf_sys::btf_load(&btf, &mut btf_log).map_err(|e| MetaLoadError::Setup(e.into()))?;
    assert_eq!(p.map_fixups.len(), 1, "one DCOUNT site expected");
    let f = &p.map_fixups[0];
    let map_fd = ossl_bpf_sys::map_create(2, 4, 8, 1, None, "DCOUNT")
        .map_err(|e| MetaLoadError::Setup(e.into()))?;
    let mut insns = p.insns.clone();
    let slot = insns
        .get_mut(f.insn_off..f.insn_off + 8)
        .context("fixup range")
        .map_err(MetaLoadError::Setup)?;
    slot[1] = (slot[1] & 0x0f) | (1 << 4);
    slot[4..8].copy_from_slice(&(map_fd.as_raw_fd() as u32).to_le_bytes());
    let mut log = vec![0u8; 1 << 20];
    let btf_attach = ossl_bpf_sys::ProgBtf {
        btf_fd: btf_fd.as_raw_fd(),
        func_info: &func_info_bytes,
    };
    let r =
        ossl_bpf_sys::prog_load_kprobe(&insns, c"GPL", None, &mut log, prog_name, Some(btf_attach));
    if let Err(e) = r {
        // Kernel evidence: trailing log lines carry the rejection
        // mode (cut at the first NUL — `trim_end` leaves NUL
        // padding, which would drown the tail in zeros).
        let text = String::from_utf8_lossy(&log);
        let text = text.split('\0').next().unwrap_or("");
        let tail: String = text.trim_end().chars().rev().take(600).collect();
        let tail: String = tail.chars().rev().collect();
        return Err(MetaLoadError::ProgLoad(e, tail));
    }
    Ok(String::from_utf8_lossy(&log).into_owned())
}

/// Require a program-load EINVAL (lane 7.0): setup failures and
/// other errnos fail the pin — a rejection must come from the
/// kernel's metadata validation, never from fallout. Kernel message
/// wording stays unpinned (kernel text is not our contract).
fn assert_prog_load_einval(e: &MetaLoadError, what: &str) {
    match e {
        MetaLoadError::ProgLoad(io, tail) => {
            assert_eq!(
                io.raw_os_error(),
                Some(libc::EINVAL),
                "{what}: errno must be EINVAL"
            );
            eprintln!("DMETA {what}: EINVAL as expected");
            if !tail.trim().is_empty() {
                eprintln!("DMETA {what} log tail: {tail}");
            }
        }
        MetaLoadError::Setup(s) => panic!("{what}: setup failure is not a rejection: {s:#}"),
    }
}

/// Malformed upload metadata must fail at program load: the kernel
/// re-validates every func_info record, so lying counts, offsets, or
/// type IDs never load silently (defense in depth behind the
/// loader's own synthesis validation). The control (unmodified
/// metadata loads) proves setup, so each corruption's EINVAL is a
/// real kernel verdict, never setup fallout. Kernel message wording
/// stays unpinned (kernel text is not our contract).
#[test]
#[ignore = "live lane only (see module docs)"]
fn malformed_func_info_is_rejected() {
    if !gated() {
        eprintln!("d live leg: set OSSL_D_LIVE=1; skipping");
        return;
    }
    let prep = prepare_loop();
    let p = &prep.progs[0];
    let (_, info) = osslscope::loader::synth_btf(&p.subprogs).expect("synth");
    assert_eq!(info.len(), 2, "main + callback records expected");
    // Control: unmodified metadata loads (setup works).
    load_with_func_info(p, &info, "dprobemeta").expect("control must load");
    // (a) Dropped callback record: count 1 for 2 subprogs.
    let e = load_with_func_info(p, &info[..1], "dprobemeta")
        .err()
        .expect("dropped record must fail");
    assert_prog_load_einval(&e, "dropped-record");
    // (b) Callback offset shifted mid-function.
    let mut bad = info.clone();
    bad[1].0 += 1;
    let e = load_with_func_info(p, &bad, "dprobemeta")
        .err()
        .expect("shifted offset must fail");
    assert_prog_load_einval(&e, "shifted-offset");
    // (c) Callback type id to a non-FUNC (INT u64, id 1).
    let mut bad = info.clone();
    bad[1].1 = 1;
    let e = load_with_func_info(p, &bad, "dprobemeta")
        .err()
        .expect("non-FUNC type id must fail");
    assert_prog_load_einval(&e, "non-func-id");
    // (d) Callback type id out of range.
    let mut bad = info.clone();
    bad[1].1 = 999;
    let e = load_with_func_info(p, &bad, "dprobemeta")
        .err()
        .expect("out-of-range type id must fail");
    assert_prog_load_einval(&e, "oor-id");
    // (e) Extra record past the subprog count (off 100 is past the
    // image end) with the callback's own VALID func id, so the
    // rejection exercises the count/offset — not a repeat of the
    // non-FUNC-id mode.
    let mut extra = info.clone();
    extra.push((100, info[1].1));
    let e = load_with_func_info(p, &extra, "dprobemeta")
        .err()
        .expect("extra record must fail");
    assert_prog_load_einval(&e, "extra-record");
}

/// Success-path verifier cost for the callback shape: reload with
/// a log buffer and report the `processed N insns` summary (the
/// callback-once budget the D decision is weighed against).
#[test]
#[ignore = "live lane only (see module docs)"]
fn bpf_loop_shape_verifier_cost() {
    if !gated() {
        eprintln!("d live leg: set OSSL_D_LIVE=1; skipping");
        return;
    }
    let prep = prepare_loop();
    let p = &prep.progs[0];
    assert!(
        p.subprogs.iter().any(|s| s.is_callback),
        "cost leg needs the callback shape"
    );
    let (_, info) = osslscope::loader::synth_btf(&p.subprogs).expect("synth");
    let text = load_with_func_info(p, &info, "dprobecost").expect("cost load");
    let summary = text
        .lines()
        .find(|l| l.contains("processed") && l.contains("insns"))
        .expect("verifier summary line")
        .to_string();
    eprintln!("DPROCOST {summary}");
    // The kernel's own decoder pins the helper-number ABI: the call
    // must resolve to bpf_loop, not whatever shares a remembered id.
    assert!(
        text.lines()
            .any(|l| l.contains("call bpf_loop#") && l.contains(&format!("{BPF_FUNC_LOOP}"))),
        "verifier must decode the call as bpf_loop#{BPF_FUNC_LOOP}"
    );
    // Numeric cost pin for the fixed 8+13 shape on the lane kernel
    // (7.0): exact expectations, not bounds. Drift means the shape
    // or the verifier changed — investigate before updating, and
    // note the metrics are verifier STATES, not frames.
    let cost = parse_verifier_cost(&summary).expect("parse verifier summary");
    assert_eq!(cost.processed, 20, "processed insns: {summary}");
    assert_eq!(cost.max_states_per_insn, 1, "max states: {summary}");
    assert_eq!(cost.total_states, 2, "total states: {summary}");
    assert_eq!(cost.peak_states, 3, "peak states: {summary}");
}
