//! P5c B-chunk mechanism probe (live lane only).
//!
//! Answers the B-vs-A mechanism questions with N tiny single-slot
//! programs on ONE `getpid` uprobe in our own libc: (a) does the
//! kernel accept a 512-deep chunk and fire every member exactly once
//! per hit, (b) what does attach cost at N=512, (c) what fire order
//! does the kernel deliver (recorded, never depended on), (d) does a
//! missing member stop the others, (e) what is the per-prog marginal
//! runtime floor. P7 item 1 extends the file: (f) the
//! `bpf_ringbuf_query` floor (§5.4 — the B entry's sole new kernel
//! requirement) is present, (g) idle detach-512 wall timing
//! (tier-3 onset term (a)) with full-slot freeze honesty.
//!
//! Run: setcaps on the test binary (like the D legs) +
//! `OSSL_B_LIVE=1 cargo +1.88.0 test --test b_chunk_probe -- --test-threads=1 --ignored`.
//! Single-threaded execution is load-bearing for the exact-count
//! legs (the uprobe filter covers the whole thread group; a sibling
//! thread's stray `getpid` would inflate counts).
//!
//! Packaging mirrors production B: ONE relocatable object, N `uprobe`
//! mains, ONE shared ARRAY map. Each main carries a baked slot index
//! (the production slot position); the shared map carries the slots
//! (keys 0..512), the order-stamp sequence (key 512), and headroom.

use osslscope::loader::{MapSpec, ProgSpec};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

const BCHUNK_ENTRIES: u32 = 1024;
const SEQ_KEY: i32 = 512;
const CTL_KEY: i32 = 513;
const FLAG_KEY: i32 = 514;

fn gated() -> bool {
    std::env::var("OSSL_B_LIVE").unwrap_or_default() == "1"
}

fn bchunk_spec() -> MapSpec {
    MapSpec {
        name: "BCHUNK",
        map_type: 2,
        key_size: 4,
        value_size: 8,
        max_entries: BCHUNK_ENTRIES,
        flags: 0,
    }
}

/// One 8-byte insn: opcode, dst/src nibbles, offset, immediate.
fn insn(op: u8, regs: u8, off: i16, imm: i32) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0] = op;
    b[1] = regs;
    b[2..4].copy_from_slice(&off.to_le_bytes());
    b[4..8].copy_from_slice(&imm.to_le_bytes());
    b
}

/// INC(i): `slot[i] += 1` — the chunk member shape. 12 insns:
/// map-fd load (reloc site @0), key store, lookup, null guard,
/// read/add/write, exit. The fd rides `r6` (callee-saved).
fn inc_shape(i: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(12 * 8);
    v.extend_from_slice(&insn(0x18, 0x06, 0, 0)); // ld_imm64 r6, map
    v.extend_from_slice(&[0u8; 8]); // (second slot)
    v.extend_from_slice(&insn(0x62, 0x0a, -4, i as i32)); // [fp-4] = i
    v.extend_from_slice(&insn(0xbf, 0xa2, 0, 0)); // r2 = r10
    v.extend_from_slice(&insn(0x07, 0x02, 0, -4)); // r2 -= 4
    v.extend_from_slice(&insn(0xbf, 0x61, 0, 0)); // r1 = r6
    v.extend_from_slice(&insn(0x85, 0x00, 0, 1)); // call map_lookup
    v.extend_from_slice(&insn(0x15, 0x00, 3, 0)); // if r0 == 0 goto exit
    v.extend_from_slice(&insn(0x79, 0x01, 0, 0)); // r1 = [r0]
    v.extend_from_slice(&insn(0x07, 0x01, 0, 1)); // r1 += 1
    v.extend_from_slice(&insn(0x7b, 0x10, 0, 0)); // [r0] = r1
    v.extend_from_slice(&insn(0x95, 0x00, 0, 0)); // exit
    assert_eq!(v.len(), 96, "INC must be 12 insns");
    v
}

/// STAMP(i): `slot[i] = seq++` — the order-observation shape. 20
/// insns: the sequence read/bump (single-threaded leg: no atomic
/// needed — no sibling thread can interleave a hit) then the slot
/// write. The `seq` value each member stamps reveals the kernel's
/// per-hit fire order.
fn stamp_shape(i: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(20 * 8);
    v.extend_from_slice(&insn(0x18, 0x06, 0, 0)); // ld_imm64 r6, map
    v.extend_from_slice(&[0u8; 8]); // (second slot)
    v.extend_from_slice(&insn(0x62, 0x0a, -4, SEQ_KEY)); // [fp-4] = seq
    v.extend_from_slice(&insn(0xbf, 0xa2, 0, 0)); // r2 = r10
    v.extend_from_slice(&insn(0x07, 0x02, 0, -4)); // r2 -= 4
    v.extend_from_slice(&insn(0xbf, 0x61, 0, 0)); // r1 = r6
    v.extend_from_slice(&insn(0x85, 0x00, 0, 1)); // call map_lookup
    v.extend_from_slice(&insn(0x15, 0x00, 11, 0)); // null seq -> exit
    v.extend_from_slice(&insn(0x79, 0x07, 0, 0)); // r7 = [r0] (seq)
    v.extend_from_slice(&insn(0xbf, 0x71, 0, 0)); // r1 = r7
    v.extend_from_slice(&insn(0x07, 0x01, 0, 1)); // r1 += 1
    v.extend_from_slice(&insn(0x7b, 0x10, 0, 0)); // [r0] = r1 (seq++)
    v.extend_from_slice(&insn(0x62, 0x0a, -4, i as i32)); // [fp-4] = i
    v.extend_from_slice(&insn(0xbf, 0xa2, 0, 0)); // r2 = r10
    v.extend_from_slice(&insn(0x07, 0x02, 0, -4)); // r2 -= 4
    v.extend_from_slice(&insn(0xbf, 0x61, 0, 0)); // r1 = r6
    v.extend_from_slice(&insn(0x85, 0x00, 0, 1)); // call map_lookup
    v.extend_from_slice(&insn(0x15, 0x00, 1, 0)); // null -> exit
    v.extend_from_slice(&insn(0x7b, 0x70, 0, 0)); // [r0] = r7
    v.extend_from_slice(&insn(0x95, 0x00, 0, 0)); // exit
    assert_eq!(v.len(), 160, "STAMP must be 20 insns");
    v
}

/// SKIP(i): gated INC — when the control flag (key 513) is set, stamp
/// the fired flag (key 514) and return WITHOUT recording slot i;
/// otherwise the plain INC path. 30 insns. The flag distinguishes
/// "fired but recorded nothing" (flag set, slot zero) from
/// "never fired" (both zero) — the hole leg's detach cannot show
/// that, and an out-of-range baked index would be equally silent.
fn skip_shape(i: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(30 * 8);
    v.extend_from_slice(&insn(0x18, 0x06, 0, 0)); // ld_imm64 r6, map
    v.extend_from_slice(&[0u8; 8]); // (second slot)
    v.extend_from_slice(&insn(0x62, 0x0a, -4, CTL_KEY)); // key = ctl
    v.extend_from_slice(&insn(0xbf, 0xa2, 0, 0)); // r2 = r10
    v.extend_from_slice(&insn(0x07, 0x02, 0, -4)); // r2 -= 4
    v.extend_from_slice(&insn(0xbf, 0x61, 0, 0)); // r1 = r6
    v.extend_from_slice(&insn(0x85, 0x00, 0, 1)); // call map_lookup
    v.extend_from_slice(&insn(0x15, 0x00, 12, 0)); // null ctl -> INC
    v.extend_from_slice(&insn(0x79, 0x07, 0, 0)); // r7 = [r0] (ctl)
    v.extend_from_slice(&insn(0x15, 0x07, 10, 0)); // ctl == 0 -> INC
    v.extend_from_slice(&insn(0x62, 0x0a, -4, FLAG_KEY)); // key = flag
    v.extend_from_slice(&insn(0xbf, 0xa2, 0, 0)); // r2 = r10
    v.extend_from_slice(&insn(0x07, 0x02, 0, -4)); // r2 -= 4
    v.extend_from_slice(&insn(0xbf, 0x61, 0, 0)); // r1 = r6
    v.extend_from_slice(&insn(0x85, 0x00, 0, 1)); // call map_lookup
    v.extend_from_slice(&insn(0x15, 0x00, 3, 0)); // null flag -> exit
    v.extend_from_slice(&insn(0x79, 0x01, 0, 0)); // r1 = [r0] (fires)
    v.extend_from_slice(&insn(0x07, 0x01, 0, 1)); // r1 += 1
    v.extend_from_slice(&insn(0x7b, 0x10, 0, 0)); // [r0] = r1
    v.extend_from_slice(&insn(0x95, 0x00, 0, 0)); // exit
    // INC path (member records normally when ctl is clear).
    v.extend_from_slice(&insn(0x62, 0x0a, -4, i as i32)); // [fp-4] = i
    v.extend_from_slice(&insn(0xbf, 0xa2, 0, 0)); // r2 = r10
    v.extend_from_slice(&insn(0x07, 0x02, 0, -4)); // r2 -= 4
    v.extend_from_slice(&insn(0xbf, 0x61, 0, 0)); // r1 = r6
    v.extend_from_slice(&insn(0x85, 0x00, 0, 1)); // call map_lookup
    v.extend_from_slice(&insn(0x15, 0x00, 3, 0)); // null -> exit
    v.extend_from_slice(&insn(0x79, 0x01, 0, 0)); // r1 = [r0]
    v.extend_from_slice(&insn(0x07, 0x01, 0, 1)); // r1 += 1
    v.extend_from_slice(&insn(0x7b, 0x10, 0, 0)); // [r0] = r1
    v.extend_from_slice(&insn(0x95, 0x00, 0, 0)); // exit
    assert_eq!(v.len(), 240, "SKIP must be 30 insns");
    v
}

/// Mixed shape: member 2 skips (gated), the rest plain INC.
fn mixed_skip2(i: u32) -> Vec<u8> {
    if i == 2 { skip_shape(i) } else { inc_shape(i) }
}

/// One chunk object: N `section` mains (each `shape(i)`)
/// concatenated in one section, one shared `BCHUNK` map def, one
/// `.rel<section>` (one map reloc per main @ its `ld_imm64`), symtab
/// (`null`, `b0..`, `BCHUNK`), string tables, 7 section headers.
/// Offsets are cursor-computed (main count varies per leg).
fn chunk_elf(n: usize, shape: fn(u32) -> Vec<u8>, section: &str) -> Vec<u8> {
    assert!(
        section == "uprobe" || section == "uretprobe",
        "loader admits only uprobe/uretprobe sections"
    );
    let mains: Vec<Vec<u8>> = (0..n as u32).map(shape).collect();
    let uprobe_len: usize = mains.iter().map(|m| m.len()).sum();
    let mut b = vec![0; 64];
    // ELF header.
    b[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    b[4] = 2;
    b[5] = 1;
    b[6] = 1;
    b[16..18].copy_from_slice(&1u16.to_le_bytes()); // ET_REL
    b[18..20].copy_from_slice(&247u16.to_le_bytes()); // EM_BPF
    b[58..60].copy_from_slice(&64u16.to_le_bytes()); // shentsize
    b[60..62].copy_from_slice(&7u16.to_le_bytes()); // shnum
    b[62..64].copy_from_slice(&6u16.to_le_bytes()); // shstrndx
    // uprobe section.
    let uprobe_off = b.len();
    let mut main_off = Vec::with_capacity(n);
    for m in &mains {
        main_off.push(b.len() - uprobe_off);
        b.extend_from_slice(m);
    }
    assert_eq!(b.len() - uprobe_off, uprobe_len);
    // maps: ARRAY u32->u64.
    let maps_off = b.len();
    for v in [2u32, 4, 8, BCHUNK_ENTRIES, 0, 0, 0] {
        b.extend_from_slice(&v.to_le_bytes());
    }
    // .reluprobe: one R_BPF_64_64 map reloc per main. The map symbol
    // index is 1 + n (null + n funcs, then the map).
    let rel_off = b.len();
    for o in &main_off {
        b.extend_from_slice(&(*o as u64).to_le_bytes());
        b.extend_from_slice(&(((1 + n) as u64) << 32 | 1).to_le_bytes());
    }
    // symtab: null, b0.., BCHUNK.
    let sym_off = b.len();
    let mut strtab: Vec<u8> = vec![0];
    let mut name_off = Vec::with_capacity(n);
    for i in 0..n {
        name_off.push(strtab.len() as u32);
        strtab.extend_from_slice(format!("b{i}").as_bytes());
        strtab.push(0);
    }
    let map_name = strtab.len() as u32;
    strtab.extend_from_slice(b"BCHUNK\0");
    let mut sym = |name: u32, info: u8, shndx: u16, val: u64, size: u64| {
        b.extend_from_slice(&name.to_le_bytes());
        b.push(info);
        b.push(0);
        b.extend_from_slice(&shndx.to_le_bytes());
        b.extend_from_slice(&val.to_le_bytes());
        b.extend_from_slice(&size.to_le_bytes());
    };
    sym(0, 0, 0, 0, 0);
    for (i, o) in main_off.iter().enumerate() {
        sym(name_off[i], 0x12, 1, *o as u64, mains[i].len() as u64);
    }
    sym(map_name, 0x11, 2, 0, 28);
    // strtab.
    let str_off = b.len();
    b.extend_from_slice(&strtab);
    // shstrtab (name offsets differ per section spelling).
    let shstr_off = b.len();
    let (t, o_sec, o_maps, o_rel, o_sym, o_str, o_shstr): (&[u8], u32, u32, u32, u32, u32, u32) =
        if section == "uprobe" {
            (
                b"\0uprobe\0maps\0.reluprobe\0.symtab\0.strtab\0.shstrtab\0",
                1,
                8,
                13,
                24,
                32,
                40,
            )
        } else {
            (
                b"\0uretprobe\0maps\0.reluretprobe\0.symtab\0.strtab\0.shstrtab\0",
                1,
                11,
                16,
                30,
                38,
                46,
            )
        };
    b.extend_from_slice(t);
    // Section headers: null, uprobe, maps, .reluprobe, symtab,
    // strtab, shstrtab.
    let sh_off = b.len();
    b[40..48].copy_from_slice(&(sh_off as u64).to_le_bytes());
    let mut sh = |name: u32, ty: u32, flags: u64, off: u64, size: u64, link: u32, info: u32| {
        let o = b.len();
        b.resize(o + 64, 0);
        b[o..o + 4].copy_from_slice(&name.to_le_bytes());
        b[o + 4..o + 8].copy_from_slice(&ty.to_le_bytes());
        b[o + 8..o + 16].copy_from_slice(&flags.to_le_bytes());
        b[o + 24..o + 32].copy_from_slice(&off.to_le_bytes());
        b[o + 32..o + 40].copy_from_slice(&size.to_le_bytes());
        b[o + 40..o + 44].copy_from_slice(&link.to_le_bytes());
        b[o + 44..o + 48].copy_from_slice(&info.to_le_bytes());
        b[o + 48..o + 56].copy_from_slice(&8u64.to_le_bytes());
        let entsize = if ty == 2 {
            24u64
        } else if ty == 9 {
            16u64
        } else {
            0
        };
        b[o + 56..o + 64].copy_from_slice(&entsize.to_le_bytes());
    };
    sh(0, 0, 0, 0, 0, 0, 0);
    sh(o_sec, 1, 6, uprobe_off as u64, uprobe_len as u64, 0, 0);
    sh(o_maps, 1, 3, maps_off as u64, 28, 0, 0);
    sh(o_rel, 9, 0, rel_off as u64, (n * 16) as u64, 4, 1);
    sh(o_sym, 2, 0, sym_off as u64, ((2 + n) * 24) as u64, 5, 1);
    sh(o_str, 3, 0, str_off as u64, strtab.len() as u64, 0, 0);
    sh(o_shstr, 3, 0, shstr_off as u64, t.len() as u64, 0, 0);
    b
}

/// Prepare one chunk load: N `section/bi` progs over the shared map.
fn prepare_chunk(
    n: usize,
    shape: fn(u32) -> Vec<u8>,
    section: &'static str,
) -> osslscope::loader::Prepared {
    let obj = chunk_elf(n, shape, section);
    let names: Vec<String> = (0..n).map(|i| format!("b{i}")).collect();
    // `ProgSpec.name` is `&'static str` (production shapes are
    // frozen statics); the probe's 512 dynamic names leak ~2.5KB per
    // prepare call — bounded, test-only, and documented here.
    let specs: Vec<ProgSpec> = names
        .iter()
        .map(|s| ProgSpec {
            name: Box::leak(s.clone().into_boxed_str()) as &str,
            section,
        })
        .collect();
    osslscope::loader::prepare(&obj, &[bchunk_spec()], &specs).expect("prepare chunk")
}

fn read_slot(map_fd: std::os::fd::RawFd, key: u32) -> u64 {
    let mut val = [0u8; 8];
    // SAFETY: BCHUNK is key 4 / value 8 (plain ARRAY); fd live for
    // the leg (asserted — a short buffer would be kernel-written
    // heap overflow).
    debug_assert_eq!(val.len(), 8);
    unsafe { ossl_bpf_sys::map_lookup_elem(map_fd, &key.to_le_bytes(), &mut val) }
        .expect("lookup BCHUNK slot");
    u64::from_le_bytes(val)
}

fn own_libc() -> String {
    let maps = std::fs::read_to_string("/proc/self/maps").expect("read maps");
    maps.lines()
        .filter_map(|l| l.split_whitespace().nth(5))
        .find(|p| p.contains("libc.so.6"))
        .expect("libc mapping")
        .to_string()
}

fn fire(n: usize) {
    for _ in 0..n {
        unsafe { libc::getpid() };
    }
}

/// Attach every prog of one loaded chunk to our own `getpid` in
/// `order`, returning the links (drop = detach). Cookies ride the
/// member index, production-style. `is_return` selects the
/// uretprobe_multi (production B hooks the return) vs uprobe_multi
/// attach flavor.
fn attach_chunk(
    loaded: &osslscope::loader::Loaded,
    libc: &std::ffi::CString,
    off: u64,
    order: &[usize],
    is_return: bool,
) -> Vec<std::os::fd::OwnedFd> {
    let pid = std::process::id();
    order
        .iter()
        .map(|i| {
            let fd = loaded.progs[&format!("b{i}")].as_raw_fd();
            let link = if is_return {
                ossl_bpf_sys::link_create_uretprobe_multi(fd, libc, &[off], &[*i as u64], pid)
            } else {
                ossl_bpf_sys::link_create_uprobe_multi(fd, libc, &[off], &[*i as u64], pid)
            };
            link.expect("attach chunk member")
        })
        .collect()
}

fn write_slot(map_fd: std::os::fd::RawFd, key: u32, val: u64) {
    // SAFETY: BCHUNK is key 4 / value 8 (plain ARRAY); fd live for
    // the leg; value is a full 8-byte LE encoding.
    unsafe {
        ossl_bpf_sys::map_update_elem(map_fd, &key.to_le_bytes(), &val.to_le_bytes(), 0)
            .expect("update BCHUNK slot");
    }
}

fn getpid_off(libc: &str) -> u64 {
    let elf_bytes = std::fs::read(libc).expect("read libc");
    osslscope::discovery::elf::dynsym_file_offset(&elf_bytes, "getpid").expect("getpid off")
}

/// THE count verdict: 512 members on one site, 3 hits — every slot
/// must read exactly 3 (each member fired exactly once per hit: no
/// drops, no dupes, no cross-talk between baked indices). The
/// pre-trigger spot-zeroes prove the read path and no spurious fire.
#[test]
#[ignore = "live lane only (see module docs)"]
fn chunk_512_all_fire_exact() {
    if !gated() {
        eprintln!("b live leg: set OSSL_B_LIVE=1; skipping");
        return;
    }
    let prep = prepare_chunk(512, inc_shape, "uprobe");
    let loaded = osslscope::loader::load(&prep).expect("load 512 chunk");
    let map_fd = loaded.maps["BCHUNK"].as_raw_fd();
    let libc = own_libc();
    let off = getpid_off(&libc);
    let path = std::ffi::CString::new(libc).unwrap();
    let order: Vec<usize> = (0..512).collect();
    let _links = attach_chunk(&loaded, &path, off, &order, false);
    for k in [0u32, 255, 511] {
        assert_eq!(read_slot(map_fd, k), 0, "slot {k} must start at zero");
    }
    fire(3);
    let mut bad = 0;
    for k in 0..512u32 {
        if read_slot(map_fd, k) != 3 {
            bad += 1;
        }
    }
    assert_eq!(bad, 0, "all 512 slots must read exactly 3 after 3 hits");
    eprintln!("b-probe: 512 members x 3 hits, all slots == 3");
}

/// Attach/load cost at the 512-contract. Budgets are generous
/// regression bounds (30s/60s — the observed numbers ride the
/// eprintln lines into the criteria doc, never the asserts).
#[test]
#[ignore = "live lane only (see module docs)"]
fn chunk_attach_time_budget() {
    if !gated() {
        eprintln!("b live leg: set OSSL_B_LIVE=1; skipping");
        return;
    }
    let t0 = Instant::now();
    let prep = prepare_chunk(512, inc_shape, "uprobe");
    let t_prep = t0.elapsed();
    let loaded = osslscope::loader::load(&prep).expect("load 512 chunk");
    let t_load = t0.elapsed() - t_prep;
    let libc = own_libc();
    let off = getpid_off(&libc);
    let path = std::ffi::CString::new(libc).unwrap();
    let pid = std::process::id();
    let mut dts = Vec::with_capacity(512);
    let mut links = Vec::with_capacity(512);
    for i in 0..512usize {
        let fd = loaded.progs[&format!("b{i}")].as_raw_fd();
        let a = Instant::now();
        let link = ossl_bpf_sys::link_create_uprobe_multi(fd, &path, &[off], &[i as u64], pid)
            .expect("attach chunk member");
        dts.push(a.elapsed());
        links.push(link);
    }
    let total: std::time::Duration = dts.iter().sum();
    dts.sort_unstable();
    let p99 = dts[512 * 99 / 100];
    eprintln!(
        "b-probe: prepare={}ms load={}ms attach_total={}ms attach_mean={}us attach_p99={}us attach_max={}us",
        t_prep.as_millis(),
        t_load.as_millis(),
        total.as_millis(),
        total.as_micros() / 512,
        p99.as_micros(),
        dts[511].as_micros(),
    );
    assert!(
        total.as_secs() < 30,
        "512 attaches must take < 30s, took {total:?}"
    );
    assert!(
        t_load.as_secs() < 60,
        "512-prog load must take < 60s, took {t_load:?}"
    );
    // The timed chunk must still function (attach benchmarked a live
    // chunk, not 512 dead links): one hit bumps every slot by one.
    let map_fd = loaded.maps["BCHUNK"].as_raw_fd();
    fire(1);
    for k in [0u32, 511] {
        assert_eq!(read_slot(map_fd, k), 1, "timed chunk must fire");
    }
}

/// Fire order, recorded not depended on: one hit over N=4 STAMP
/// members in attach order A and in reverse attach order B. Each run
/// must stamp a full permutation (each member fired exactly once);
/// the two orders are printed for the doc (whatever the kernel
/// delivers — attach order, reverse, or other — the harvest design
/// must not depend on it).
#[test]
#[ignore = "live lane only (see module docs)"]
fn chunk_fire_order_recorded() {
    if !gated() {
        eprintln!("b live leg: set OSSL_B_LIVE=1; skipping");
        return;
    }
    let run = |order: &[usize]| -> [u64; 4] {
        let prep = prepare_chunk(4, stamp_shape, "uprobe");
        let loaded = osslscope::loader::load(&prep).expect("load stamp chunk");
        let map_fd = loaded.maps["BCHUNK"].as_raw_fd();
        let libc = own_libc();
        let off = getpid_off(&libc);
        let path = std::ffi::CString::new(libc).unwrap();
        let _links = attach_chunk(&loaded, &path, off, order, false);
        fire(1);
        [
            read_slot(map_fd, 0),
            read_slot(map_fd, 1),
            read_slot(map_fd, 2),
            read_slot(map_fd, 3),
        ]
    };
    for (label, order) in [("fwd", [0usize, 1, 2, 3]), ("rev", [3, 2, 1, 0])] {
        let stamps = run(&order);
        let mut sorted = stamps;
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            [0, 1, 2, 3],
            "{label}: one hit must stamp each member exactly once"
        );
        eprintln!("b-probe: order {label} attach={order:?} stamps={stamps:?}");
    }
}

/// A missing member stops nothing — at any position: N=4, one hit
/// with all attached, drop the middle member (2), second hit, then
/// drop the first (0) and last (3) members, third hit. Member 1
/// (never detached) reads 3; member 2 stays at 1; members 0/3 stay
/// at 2. (Models chunk members that failed to load/attach: the scan
/// degrades to holes, never a stall. Absence only — the skip leg
/// covers fired-but-silent; the accounting oracle is P7.)
#[test]
#[ignore = "live lane only (see module docs)"]
fn chunk_hole_member_missing() {
    if !gated() {
        eprintln!("b live leg: set OSSL_B_LIVE=1; skipping");
        return;
    }
    let prep = prepare_chunk(4, inc_shape, "uprobe");
    let loaded = osslscope::loader::load(&prep).expect("load hole chunk");
    let map_fd = loaded.maps["BCHUNK"].as_raw_fd();
    let libc = own_libc();
    let off = getpid_off(&libc);
    let path = std::ffi::CString::new(libc).unwrap();
    let mut links = attach_chunk(&loaded, &path, off, &[0, 1, 2, 3], false);
    fire(1);
    links.remove(2); // detach middle member 2 (OwnedFd drop)
    fire(1);
    // links now [0, 1, 3]: drop first (0) and last (3).
    links.remove(2);
    links.remove(0);
    fire(1);
    assert_eq!(read_slot(map_fd, 0), 2, "first member must miss hit 3");
    assert_eq!(read_slot(map_fd, 1), 3, "survivor must see all hits");
    assert_eq!(read_slot(map_fd, 2), 1, "middle member must miss hits 2-3");
    assert_eq!(read_slot(map_fd, 3), 2, "last member must miss hit 3");
    eprintln!("b-probe: hole leg green (1 == 3; 0,3 == 2; 2 == 1)");
}

/// Fired-but-silent is not absence: member 2 runs the SKIP shape
/// with control preset, so it fires (flag counts it) without
/// recording its slot — while siblings record normally. After 2
/// hits: slots 0/1/3 == 2, slot 2 == 0, flag == 2.
#[test]
#[ignore = "live lane only (see module docs)"]
fn chunk_member_skip_fires_but_records_nothing() {
    if !gated() {
        eprintln!("b live leg: set OSSL_B_LIVE=1; skipping");
        return;
    }
    let prep = prepare_chunk(4, mixed_skip2, "uprobe");
    let loaded = osslscope::loader::load(&prep).expect("load skip chunk");
    let map_fd = loaded.maps["BCHUNK"].as_raw_fd();
    write_slot(map_fd, CTL_KEY as u32, 1);
    let libc = own_libc();
    let off = getpid_off(&libc);
    let path = std::ffi::CString::new(libc).unwrap();
    let _links = attach_chunk(&loaded, &path, off, &[0, 1, 2, 3], false);
    assert_eq!(read_slot(map_fd, FLAG_KEY as u32), 0, "flag starts zero");
    fire(2);
    assert_eq!(read_slot(map_fd, 0), 2);
    assert_eq!(read_slot(map_fd, 1), 2);
    assert_eq!(read_slot(map_fd, 2), 0, "skipped member records nothing");
    assert_eq!(read_slot(map_fd, 3), 2);
    assert_eq!(
        read_slot(map_fd, FLAG_KEY as u32),
        2,
        "skipped member still fired twice"
    );
    eprintln!("b-probe: skip leg green (0,1,3 == 2; 2 == 0; flag == 2)");
}

/// The production-B hook is the RETURN: 512 uretprobe members, 3
/// getpid calls (= 3 returns) — every slot must read exactly 3.
/// Same verdict as the entry leg, on the hook production uses.
#[test]
#[ignore = "live lane only (see module docs)"]
fn chunk_512_uretprobe_all_fire_exact() {
    if !gated() {
        eprintln!("b live leg: set OSSL_B_LIVE=1; skipping");
        return;
    }
    let prep = prepare_chunk(512, inc_shape, "uretprobe");
    let loaded = osslscope::loader::load(&prep).expect("load 512 return chunk");
    let map_fd = loaded.maps["BCHUNK"].as_raw_fd();
    let libc = own_libc();
    let off = getpid_off(&libc);
    let path = std::ffi::CString::new(libc).unwrap();
    let order: Vec<usize> = (0..512).collect();
    let _links = attach_chunk(&loaded, &path, off, &order, true);
    for k in [0u32, 255, 511] {
        assert_eq!(read_slot(map_fd, k), 0, "slot {k} must start at zero");
    }
    fire(3);
    let mut bad = 0;
    for k in 0..512u32 {
        if read_slot(map_fd, k) != 3 {
            bad += 1;
        }
    }
    assert_eq!(bad, 0, "all 512 return slots must read exactly 3");
    eprintln!("b-probe: 512 uretprobe members x 3 returns, all slots == 3");
}

/// Per-prog marginal runtime floor (tiny INC body — the mechanism
/// floor, not the production slot-walk cost): timed getpid loops at
/// N = 0/1/4 members, 5 reps, median. The per-prog number is
/// (t4 - t1) / 3 / calls (the trap fires once per hit regardless of
/// N, so N=0->1 carries the trap and N=1->4 isolates the members).
/// The 5µs assert is a generous regression bound; the medians ride
/// the eprintln line into the criteria doc.
#[test]
#[ignore = "live lane only (see module docs)"]
fn chunk_marginal_runtime_floor() {
    if !gated() {
        eprintln!("b live leg: set OSSL_B_LIVE=1; skipping");
        return;
    }
    const CALLS: usize = 100_000;
    const REPS: usize = 5;
    let libc = own_libc();
    let off = getpid_off(&libc);
    let path = std::ffi::CString::new(libc).unwrap();
    let time_n = |n: usize| -> u128 {
        let mut reps = Vec::with_capacity(REPS);
        for _ in 0..REPS {
            // Each rep holds its own load+links (fresh maps, no
            // cross-rep state); N=0 times the bare loop.
            let _held = if n > 0 {
                let prep = prepare_chunk(n, inc_shape, "uprobe");
                let loaded = osslscope::loader::load(&prep).expect("load floor chunk");
                let order: Vec<usize> = (0..n).collect();
                let links = attach_chunk(&loaded, &path, off, &order, false);
                Some((loaded, links))
            } else {
                None
            };
            let t = Instant::now();
            fire(CALLS);
            reps.push(t.elapsed().as_nanos());
        }
        reps.sort_unstable();
        reps[REPS / 2]
    };
    let t0 = time_n(0);
    let t1 = time_n(1);
    let t4 = time_n(4);
    let per_call = |t: u128| t as f64 / CALLS as f64;
    let per_prog_ns = (t4 as f64 - t1 as f64) / 3.0 / CALLS as f64;
    eprintln!(
        "b-probe: floor n0={:.1}ns n1={:.1}ns n4={:.1}ns trap+1={:.1}ns per_prog={:.1}ns",
        per_call(t0),
        per_call(t1),
        per_call(t4),
        per_call(t1.saturating_sub(t0)),
        per_prog_ns,
    );
    assert!(
        per_prog_ns >= 0.0,
        "negative marginal {per_prog_ns:.1}ns = broken measurement, failing loud"
    );
    assert!(
        per_prog_ns < 5000.0,
        "per-prog marginal floor must be < 5µs, got {per_prog_ns:.1}ns"
    );
}

#[test]
fn prepare_accepts_512_prog_chunk() {
    let prep = prepare_chunk(512, inc_shape, "uprobe");
    assert_eq!(prep.progs.len(), 512);
    for (i, p) in prep.progs.iter().enumerate() {
        assert_eq!(p.insns.len(), 96, "member {i} must be 12 insns");
        assert_eq!(p.map_fixups.len(), 1, "member {i} needs one map site");
        assert!(!p.is_return, "chunk members are entry probes");
    }
    assert_eq!(prep.maps.len(), 1);
    assert_eq!(prep.maps[0].max_entries, BCHUNK_ENTRIES);
}

#[test]
fn prepare_accepts_stamp_shape() {
    let prep = prepare_chunk(4, stamp_shape, "uprobe");
    assert_eq!(prep.progs.len(), 4);
    for p in &prep.progs {
        assert_eq!(p.insns.len(), 160, "STAMP must be 20 insns");
        assert_eq!(p.map_fixups.len(), 1);
    }
}

#[test]
fn prepare_accepts_skip_shape() {
    let prep = prepare_chunk(4, mixed_skip2, "uprobe");
    assert_eq!(prep.progs.len(), 4);
    assert_eq!(prep.progs[2].insns.len(), 240, "SKIP must be 30 insns");
    for (i, p) in prep.progs.iter().enumerate() {
        if i != 2 {
            assert_eq!(p.insns.len(), 96, "sibling {i} stays INC");
        }
        assert_eq!(p.map_fixups.len(), 1);
    }
}

/// Resolve every section name of a built chunk ELF (minimal
/// parser: ehdr → shdrs → shstrtab). Pins the string-table offsets
/// for BOTH spellings — the loader locates symtab/strtab by
/// type/link, so a misnamed table still prepares; only this test
/// proves the names resolve (it caught the uretprobe 37/44 slip).
fn section_names(obj: &[u8], section: &str) -> Vec<String> {
    let shoff = u64::from_le_bytes(obj[40..48].try_into().unwrap()) as usize;
    let shnum = u16::from_le_bytes(obj[60..62].try_into().unwrap()) as usize;
    let shstrndx = u16::from_le_bytes(obj[62..64].try_into().unwrap()) as usize;
    assert_eq!((shnum, shstrndx), (7, 6));
    let hdr = |i: usize| &obj[shoff + i * 64..shoff + (i + 1) * 64];
    let shstr_hdr = hdr(shstrndx);
    let str_off = u64::from_le_bytes(shstr_hdr[24..32].try_into().unwrap()) as usize;
    let str_len = u64::from_le_bytes(shstr_hdr[32..40].try_into().unwrap()) as usize;
    let shstr = &obj[str_off..str_off + str_len];
    let rel = format!(".rel{section}");
    let expect = [
        "",
        section,
        "maps",
        rel.as_str(),
        ".symtab",
        ".strtab",
        ".shstrtab",
    ];
    (0..shnum)
        .map(|i| {
            let h = hdr(i);
            let at = u32::from_le_bytes(h[0..4].try_into().unwrap()) as usize;
            let end = shstr[at..].iter().position(|b| *b == 0).unwrap() + at;
            let name = std::str::from_utf8(&shstr[at..end]).unwrap().to_string();
            assert_eq!(name, expect[i], "section {i} name resolves");
            name
        })
        .collect()
}

#[test]
fn chunk_section_names_resolve_both_spellings() {
    for section in ["uprobe", "uretprobe"] {
        let obj = chunk_elf(2, inc_shape, section);
        let names = section_names(&obj, section);
        assert_eq!(names.len(), 7);
    }
}

#[test]
fn prepare_accepts_uretprobe_section() {
    let prep = prepare_chunk(4, inc_shape, "uretprobe");
    assert_eq!(prep.progs.len(), 4);
    for p in &prep.progs {
        assert_eq!(p.insns.len(), 96);
        assert_eq!(p.map_fixups.len(), 1);
        assert!(p.is_return, "uretprobe members are return probes");
    }
}

/// P7 item 1a (§5.4 floor): `bpf_ringbuf_query` must load on a B
/// lane — the entry's occupancy check is the sole new kernel
/// requirement. Live-only: map creation needs CAP_BPF, kprobe
/// program load needs CAP_PERFMON as well (CAP_SYS_ADMIN covers
/// both stages instead).
#[test]
#[ignore = "live lane only (see module docs)"]
fn ringbuf_query_floor_present() {
    if !gated() {
        eprintln!("b live leg: set OSSL_B_LIVE=1; skipping");
        return;
    }
    osslscope::doctor::probe_ringbuf_query().expect("bpf_ringbuf_query must load on a B lane");
    eprintln!("b-probe: ringbuf_query floor present");
}

/// Detach cost at the 512-contract (P7 item 1: tier-3 onset term
/// (a)) — IDLE entry-probe measurement, not onset qualification:
/// entry probes, no in-flight load, and the 30s bound is a
/// post-hoc regression ceiling, not a hang timeout. Under-load
/// onset qualification (in-flight drain) stays explicitly
/// outstanding. Honesty is symmetric with the attach leg: the
/// chunk must fire BEFORE detach (all slots bump) and freeze
/// AFTER detach+settle (all slots stop) — a detach that timed
/// dead links would prove nothing.
#[test]
#[ignore = "live lane only (see module docs)"]
fn chunk_detach_time_freezes() {
    if !gated() {
        eprintln!("b live leg: set OSSL_B_LIVE=1; skipping");
        return;
    }
    let prep = prepare_chunk(512, inc_shape, "uprobe");
    let loaded = osslscope::loader::load(&prep).expect("load 512 chunk");
    let map_fd = loaded.maps["BCHUNK"].as_raw_fd();
    let libc = own_libc();
    let off = getpid_off(&libc);
    let path = std::ffi::CString::new(libc).unwrap();
    let order: Vec<usize> = (0..512).collect();
    let links = attach_chunk(&loaded, &path, off, &order, false);
    assert_eq!(links.len(), 512);
    fire(2);
    for k in 0..512u32 {
        assert_eq!(read_slot(map_fd, k), 2, "chunk must fire before detach");
    }
    let t = Instant::now();
    drop(links);
    let wall = t.elapsed();
    eprintln!(
        "b-probe: detach_512_wall={}ms (avg {}us/link)",
        wall.as_millis(),
        wall.as_micros() / 512,
    );
    assert!(
        wall < Duration::from_secs(30),
        "512 detaches must take < 30s, took {wall:?}"
    );
    // Final link close is synchronous (unregister waits RCU/SRCU
    // grace inside the timed drop — slow grace extends the wall, it
    // does not outlast it). The settle below is scheduling margin
    // only; then the chunk must be dead (slots frozen, not slow).
    std::thread::sleep(Duration::from_millis(500));
    fire(3);
    for k in 0..512u32 {
        assert_eq!(
            read_slot(map_fd, k),
            2,
            "slot {k} must freeze after detach+settle"
        );
    }
    eprintln!("b-probe: post-detach fire frozen at 2 (500ms settle)");
}
