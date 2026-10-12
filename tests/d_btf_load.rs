//! P5b-D: loader BTF + func_info for helper-callback shapes.
//!
//! Live lane only (`OSSL_D_LIVE=1`, caps via setcap like the other
//! live tests): hand-assembles a minimal `bpf_loop` object (main +
//! address-taken callback, no maps, no toolchain) and loads it.
//! Without BTF wiring the kernel rejects it (`missing btf
//! func_info`, the r5 probe4 verdict); with wiring it loads.

use osslscope::loader::{MapSpec, ProgSpec};

fn gated() -> bool {
    std::env::var("OSSL_D_LIVE").unwrap_or_default() == "1"
}

/// Minimal `bpf_loop` relocatable: 1 uprobe prog (ld_func/calls/
/// exit, 8 insns), 1 `.text` callback (mov/exit), empty maps, 1
/// func reloc. Layout (offsets): ehdr 0/64, uprobe 64/64, .text
/// 128/16, maps 144/0, .reluprobe 144/16, symtab 160/72, strtab
/// 232/11, shstrtab 243/56, shdrs 304/512.
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
    let mut b = vec![0u8; 304 + 8 * 64];
    // ELF header.
    b[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    b[4] = 2; // 64-bit
    b[5] = 1; // LE
    b[6] = 1; // version
    b[16..18].copy_from_slice(&u16(1)); // ET_REL
    b[18..20].copy_from_slice(&u16(247)); // EM_BPF
    b[40..48].copy_from_slice(&u64(304)); // shoff
    b[58..60].copy_from_slice(&u16(64)); // shentsize
    b[60..62].copy_from_slice(&u16(8)); // shnum
    b[62..64].copy_from_slice(&u16(7)); // shstrndx
    // uprobe main: ld_imm64 r2,cb + bpf_loop(4, r2, fp-8, 0) + exit.
    b[64..80].copy_from_slice(&[0x18, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    b[80..88].copy_from_slice(&[0xb7, 0x01, 0, 0, 4, 0, 0, 0]); // r1 = 4
    b[88..96].copy_from_slice(&[0xbf, 0xa3, 0, 0, 0, 0, 0, 0]); // r3 = r10
    b[96..104].copy_from_slice(&[0x07, 0x03, 0, 0, 0xf8, 0xff, 0xff, 0xff]); // r3 -= 8
    b[104..112].copy_from_slice(&[0xb7, 0x04, 0, 0, 0, 0, 0, 0]); // r4 = 0
    b[112..120].copy_from_slice(&[0x85, 0x00, 0, 0, 80, 0, 0, 0]); // call bpf_loop
    b[120..128].copy_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]); // exit
    // .text callback: r0 = 0 (continue) + exit.
    b[128..136].copy_from_slice(&[0xb7, 0x00, 0, 0, 0, 0, 0, 0]);
    b[136..144].copy_from_slice(&[0x95, 0, 0, 0, 0, 0, 0, 0]);
    // .reluprobe: func ref @0 (sym 2 = cb, R_BPF_64_64).
    b[144..152].copy_from_slice(&u64(0));
    b[152..160].copy_from_slice(&u64(2 << 32 | 1));
    // symtab: null, dprobe, cb.
    let mut sym = |o: usize, name: u32, info: u8, shndx: u16, val: u64, size: u64| {
        b[o..o + 4].copy_from_slice(&u32(name));
        b[o + 4] = info;
        b[o + 6..o + 8].copy_from_slice(&u16(shndx));
        b[o + 8..o + 16].copy_from_slice(&u64(val));
        b[o + 16..o + 24].copy_from_slice(&u64(size));
    };
    sym(160, 0, 0, 0, 0, 0);
    sym(184, 1, 0x12, 1, 0, 64);
    sym(208, 8, 0x12, 2, 0, 16);
    // strtab.
    let s = b"\0dprobe\0cb\0";
    b[232..232 + s.len()].copy_from_slice(s);
    // shstrtab.
    let t = b"\0uprobe\0.text\0maps\0.reluprobe\0.symtab\0.strtab\0.shstrtab\0";
    b[243..243 + t.len()].copy_from_slice(t);
    // Section headers: null, uprobe, .text, maps, .reluprobe,
    // symtab, strtab, shstrtab.
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
        let o = 304 + i * 64;
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
    sh(2, 8, 1, 6, 128, 16, 0, 0, 0);
    sh(3, 14, 1, 3, 144, 0, 0, 0, 0);
    sh(4, 19, 9, 0, 144, 16, 5, 1, 16);
    sh(5, 30, 2, 0, 160, 72, 6, 1, 24);
    sh(6, 38, 3, 0, 232, 11, 0, 0, 0);
    sh(7, 46, 3, 0, 243, 56, 0, 0, 0);
    b
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
    let obj = loop_elf();
    let prep = osslscope::loader::prepare(
        &obj,
        &[] as &[MapSpec],
        &[ProgSpec {
            name: "dprobe",
            section: "uprobe",
        }],
    )
    .expect("prepare callback shape");
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
