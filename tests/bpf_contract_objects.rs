// SPDX-License-Identifier: GPL-3.0-or-later
//! Explicit unprivileged object gate for three freshly built BPF artifacts.
use goblin::elf::{Elf, header, section_header, sym};
use osslscope::loader::{
    self, COUNT_MAPS, COUNT_PROGS, HARVEST_MAPS, HARVEST_PROGS, MEMBER_MAPS, MEMBER_PROGS,
};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};

#[test]
fn ring_pad_negative_control() {
    let mut raw = Vec::new();
    let mut insn = |op: u8, regs: u8, off: i16, imm: i32| {
        raw.push(op);
        raw.push(regs);
        raw.extend_from_slice(&off.to_le_bytes());
        raw.extend_from_slice(&imm.to_le_bytes());
    };
    insn(0xb7, 2, 0, 16); // reserve length
    insn(0x85, 0, 0, 131);
    insn(0x15, 0, 6, 0); // null skips the submit
    insn(0xb7, 1, 0, 5); // TripEvent kind
    insn(0x63, 0x10, 0, 0);
    insn(0x62, 0, 4, 0);
    insn(0x7a, 0, 8, 0);
    insn(0xbf, 0x01, 0, 0);
    insn(0x85, 0, 0, 132);
    insn(0x95, 0, 0, 0);
    assert_eq!(inspect_ring_regions("fixture", "trip", &raw, None).len(), 1);
    let mut bad = raw;
    bad[6 * 8 + 4..6 * 8 + 8].copy_from_slice(&0x0100_0000u32.to_le_bytes());
    assert!(
        std::panic::catch_unwind(|| inspect_ring_regions("fixture", "trip", &bad, None)).is_err()
    );
}

#[test]
fn late_ring_alias_branch_is_not_treated_as_reserve_guard() {
    let mut raw = Vec::new();
    let mut insn = |op: u8, regs: u8, off: i16, imm: i32| {
        raw.push(op);
        raw.push(regs);
        raw.extend_from_slice(&off.to_le_bytes());
        raw.extend_from_slice(&imm.to_le_bytes());
    };
    insn(0xb7, 2, 0, 16);
    insn(0x85, 0, 0, 131);
    insn(0xbf, 0x06, 0, 0); // r6 retains the reservation pointer
    for value in 1..=4 {
        insn(0xb7, 7, 0, value);
    }
    insn(0x15, 6, 6, 0); // late null branch exits before submit
    insn(0x62, 6, 0, 7);
    insn(0x62, 6, 4, 0);
    insn(0x7a, 6, 8, 0);
    insn(0xbf, 0x61, 0, 0);
    insn(0xb7, 2, 0, 0);
    insn(0x85, 0, 0, 132);
    insn(0x95, 0, 0, 0);
    assert!(
        std::panic::catch_unwind(|| inspect_ring_regions("fixture", "late", &raw, None)).is_err(),
        "late pointer branch must be explored beyond the reserve-guard window"
    );
}

#[test]
fn extra_target_read_negative_control() {
    let read = [0x85, 0, 0, 0, 112, 0, 0, 0];
    assert!(
        std::panic::catch_unwind(|| verify_read_helpers("harvest", "trip_str0", &read, None))
            .is_err()
    );
}

#[test]
fn stack_range_negative_control() {
    for bad in [
        [0x79, 0xa1, 0xfc, 0xff, 0, 0, 0, 0], // u64 load straddles frame end
        [0x7b, 0x1a, 0x00, 0x00, 0, 0, 0, 0], // u64 store at frame end
        [0x61, 0xa1, 0xff, 0xfd, 0, 0, 0, 0], // u32 load below -512
    ] {
        assert!(
            std::panic::catch_unwind(|| scan_instructions("fixture", "stack", &bad, false))
                .is_err()
        );
    }
}

#[test]
fn cfg_cycle_negative_control() {
    let acyclic_back_jump = [
        [0x05, 0, 1, 0, 0, 0, 0, 0],
        [0x95, 0, 0, 0, 0, 0, 0, 0],
        [0x05, 0, 0xfe, 0xff, 0, 0, 0, 0],
    ]
    .concat();
    let actual_cycle = [
        [0xb7, 0, 0, 0, 0, 0, 0, 0],
        [0x05, 0, 0xfe, 0xff, 0, 0, 0, 0],
    ]
    .concat();
    assert_eq!(
        cfg_cycle_count("fixture", "shared_tail", &acyclic_back_jump),
        0
    );
    assert_eq!(cfg_cycle_count("fixture", "actual_cycle", &actual_cycle), 1);
}

#[test]
fn executable_coverage_negative_control() {
    assert_function_coverage("fixture", ".text", 16, &[(0, 8), (8, 16)]);
    for bad in [&[(0, 8)][..], &[(0, 12), (8, 16)][..]] {
        assert!(
            std::panic::catch_unwind(|| assert_function_coverage("fixture", ".text", 16, bad))
                .is_err()
        );
    }
}

#[test]
fn zero_call_must_dominate_string_read() {
    let mut raw = Vec::new();
    let mut insn = |op: u8, regs: u8, off: i16, imm: i32| {
        raw.push(op);
        raw.push(regs);
        raw.extend_from_slice(&off.to_le_bytes());
        raw.extend_from_slice(&imm.to_le_bytes());
    };
    insn(0x15, 0, 1, 0); // conditional edge skips the zero call
    insn(0x85, 0x10, 0, 0); // zero call
    insn(0x85, 0, 0, 114); // string read
    insn(0x95, 0, 0, 0);
    assert!(
        std::panic::catch_unwind(|| assert_zero_dominates_read("fixture", "branch", &raw, 1, 2))
            .is_err()
    );
    raw[2..4].copy_from_slice(&0i16.to_le_bytes());
    assert_zero_dominates_read("fixture", "straight", &raw, 1, 2);
}

#[test]
#[ignore = "requires three fresh pinned BPF objects and explicit environment paths"]
fn independent_bpf_objects() {
    let paths = [
        (
            "count",
            "OSSL_BPF_CONTRACT_COUNT_OBJECT",
            &COUNT_MAPS[..],
            &COUNT_PROGS[..],
        ),
        (
            "harvest",
            "OSSL_BPF_CONTRACT_HARVEST_OBJECT",
            &HARVEST_MAPS[..],
            &HARVEST_PROGS[..],
        ),
        (
            "members",
            "OSSL_BPF_CONTRACT_MEMBERS_OBJECT",
            &MEMBER_MAPS[..],
            &MEMBER_PROGS[..],
        ),
    ];
    let mut observations = Vec::new();
    for (role, variable, maps, progs) in paths {
        let path = std::env::var(variable).unwrap_or_else(|_| panic!("{variable} required"));
        assert!(!path.is_empty(), "{variable} must not be empty");
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{role}: read {path}: {e}"));
        let prepared =
            loader::prepare(&bytes, maps, progs).unwrap_or_else(|e| panic!("{role}: {e}"));
        assert_eq!(prepared.maps.len(), maps.len());
        assert_eq!(prepared.progs.len(), progs.len());
        observations.push(inspect_object(role, &bytes, &prepared, maps, progs));
        if role == "harvest" {
            ring_pad_object_negative(&bytes, &prepared);
        }
        if role == "members" {
            negative_controls(&bytes, &prepared);
        }
    }
    if let Ok(path) = std::env::var("OSSL_BPF_CONTRACT_REPORT") {
        assert!(!path.is_empty(), "report path must not be empty");
        std::fs::write(&path, serde_json::to_vec_pretty(&observations).unwrap())
            .unwrap_or_else(|e| panic!("write {path}: {e}"));
    }
}

fn section_bytes<'a>(bytes: &'a [u8], sh: &section_header::SectionHeader) -> &'a [u8] {
    let start = sh.sh_offset as usize;
    let len = sh.sh_size as usize;
    bytes
        .get(start..start.checked_add(len).expect("section overflow"))
        .expect("section in file")
}

fn assert_function_coverage(role: &str, section: &str, bytes: usize, ranges: &[(usize, usize)]) {
    assert_eq!(
        bytes % 8,
        0,
        "{role}:{section}: partial executable instruction"
    );
    let mut ranges = ranges.to_vec();
    ranges.sort();
    let mut cursor = 0;
    for (start, end) in ranges {
        assert_eq!(
            start, cursor,
            "{role}:{section}: gap or overlap at {cursor}"
        );
        assert!(
            end > start && end <= bytes && end % 8 == 0,
            "{role}:{section}: invalid function range"
        );
        cursor = end;
    }
    assert_eq!(
        cursor, bytes,
        "{role}:{section}: uncovered executable bytes"
    );
}

#[derive(Clone, Hash, Eq, PartialEq)]
struct RingState {
    pc: usize,
    initialized: u64,
    known_mask: u64,
    known_bytes: [u8; 64],
    aliases: [Option<i16>; 11],
    values: [Option<u64>; 11],
    near_reserve: u8,
}

fn field_mask(at: usize, width: usize) -> u64 {
    let bits = if width == 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    };
    bits.checked_shl(at as u32).expect("ring field shift")
}

fn decoded_cfg(role: &str, owner: &str, raw: &[u8]) -> (Vec<bool>, Vec<Vec<usize>>) {
    assert_eq!(raw.len() % 8, 0, "{role}:{owner}: partial instruction");
    let insns: Vec<_> = raw.chunks_exact(8).collect();
    let n = insns.len();
    let mut valid = vec![true; n];
    for (pc, x) in insns.iter().enumerate() {
        if !valid[pc] {
            continue;
        }
        if x[0] == 0x18 {
            assert!(pc + 1 < n, "{role}:{owner}:{pc}: truncated ld_imm64");
            assert!(valid[pc], "{role}:{owner}:{pc}: nested ld_imm64");
            valid[pc + 1] = false;
        }
    }
    let mut edges = vec![Vec::<usize>::new(); n];
    for (pc, x) in insns.iter().enumerate() {
        if !valid[pc] {
            continue;
        }
        let op = x[0];
        if op == 0x95 {
            continue;
        }
        let next = pc + if op == 0x18 { 2 } else { 1 };
        let mut successors = Vec::new();
        if (op & 7 == 5 || op & 7 == 6) && op != 0x85 {
            assert_ne!(op, 0x06, "{role}:{owner}:{pc}: unreviewed long jump");
            let off = i16::from_le_bytes(x[2..4].try_into().unwrap());
            let target = pc as isize + 1 + off as isize;
            assert!(target >= 0, "{role}:{owner}:{pc}: negative branch target");
            successors.push(target as usize);
            if op != 0x05 {
                successors.push(next);
            }
        } else {
            successors.push(next);
        }
        for target in successors {
            assert!(
                target < n && valid[target],
                "{role}:{owner}:{pc}: invalid CFG target {target}"
            );
            edges[pc].push(target);
        }
    }
    (valid, edges)
}

fn cfg_cycle_count(role: &str, owner: &str, raw: &[u8]) -> usize {
    let (valid, edges) = decoded_cfg(role, owner, raw);
    let n = edges.len();
    let mut reverse = vec![Vec::<usize>::new(); n];
    for (pc, successors) in edges.iter().enumerate() {
        for &target in successors {
            reverse[target].push(pc);
        }
    }
    let mut seen = vec![false; n];
    let mut finish = Vec::with_capacity(n);
    for start in 0..n {
        if !valid[start] || seen[start] {
            continue;
        }
        seen[start] = true;
        let mut stack = vec![(start, 0)];
        while let Some((node, next_edge)) = stack.last_mut() {
            if *next_edge == edges[*node].len() {
                finish.push(*node);
                stack.pop();
            } else {
                let target = edges[*node][*next_edge];
                *next_edge += 1;
                if !seen[target] {
                    seen[target] = true;
                    stack.push((target, 0));
                }
            }
        }
    }
    seen.fill(false);
    let mut cyclic = 0;
    for start in finish.into_iter().rev() {
        if seen[start] {
            continue;
        }
        seen[start] = true;
        let mut size = 0;
        let mut stack = vec![start];
        while let Some(node) = stack.pop() {
            size += 1;
            for &parent in &reverse[node] {
                if !seen[parent] {
                    seen[parent] = true;
                    stack.push(parent);
                }
            }
        }
        if size > 1 || edges[start].contains(&start) {
            cyclic += 1;
        }
    }
    cyclic
}

fn assert_insn(role: &str, owner: &str, raw: &[u8], pc: usize, expected: (u8, u8, i16, i32)) {
    let insn = raw
        .get(pc * 8..pc * 8 + 8)
        .unwrap_or_else(|| panic!("{role}:{owner}:{pc}: missing rank instruction"));
    assert_eq!(
        (
            insn[0],
            insn[1],
            i16::from_le_bytes(insn[2..4].try_into().unwrap()),
            i32::from_le_bytes(insn[4..8].try_into().unwrap()),
        ),
        expected,
        "{role}:{owner}:{pc}: rank instruction"
    );
}

fn assert_builtin_loop_witness(role: &str, owner: &str, raw: &[u8]) {
    let check = |pc, op, regs, off, imm| assert_insn(role, owner, raw, pc, (op, regs, off, imm));
    match owner {
        "memcpy" => {
            check(0, 0x15, 0x03, 9, 0); // zero length exits
            check(1, 0xb7, 0x04, 0, 0); // i = 0
            check(8, 0x07, 0x04, 0, 1); // i += 1
            check(9, 0x2d, 0x43, -8, 0); // loop only while len > i
        }
        "memmove" => {
            check(2, 0x3d, 0x34, 11, 0); // forward/backward split
            check(11, 0x07, 0x03, 0, -1); // backward remaining -= 1
            check(12, 0x55, 0x03, -8, 0); // backward until zero
            check(14, 0x15, 0x03, 9, 0); // zero-length forward exit
            check(15, 0xb7, 0x04, 0, 0); // forward i = 0
            check(22, 0x07, 0x04, 0, 1); // forward i += 1
            check(23, 0x2d, 0x43, -8, 0); // forward while len > i
        }
        "memset" => {
            check(0, 0x15, 0x03, 6, 0);
            check(1, 0xb7, 0x04, 0, 0);
            check(5, 0x07, 0x04, 0, 1);
            check(6, 0x2d, 0x43, -5, 0);
        }
        "memcmp" => {
            check(1, 0x15, 0x03, 13, 0);
            check(2, 0xb7, 0x04, 0, 0);
            check(5, 0x07, 0x04, 0, 1);
            check(6, 0x3d, 0x34, 8, 0);
            check(13, 0x1d, 0x50, -10, 0);
        }
        _ => {}
    }
}

fn assert_application_loop_witness(role: &str, owner: &str, raw: &[u8]) {
    let check = |pc, op, regs, off, imm| assert_insn(role, owner, raw, pc, (op, regs, off, imm));
    if owner == "count_entry" {
        // Constant 14 is compared with the pre-incremented cursor; the
        // 15th visit exits. The earlier right-shift guard can exit sooner.
        check(154, 0xb7, 0x01, 0, 0);
        check(163, 0xb7, 0x03, 0, 4);
        check(164, 0xb7, 0x04, 0, 14);
        check(165, 0xbf, 0x15, 0, 0);
        check(166, 0x07, 0x01, 0, 1);
        check(167, 0x2d, 0x23, 2, 0);
        check(168, 0x77, 0x02, 0, 1);
        check(169, 0x2d, 0x54, -5, 0);
    } else if owner == "init_return" {
        // r9 starts at zero and advances by 16; the 256 guard precedes
        // every path back to the shared loop head, so at most 16 records.
        check(36, 0xb7, 0x09, 0, 0);
        check(63, 0x79, 0xa6, -8, 0);
        check(64, 0x55, 0x06, 98, 0);
        check(65, 0x07, 0x09, 0, 16);
        check(66, 0x15, 0x09, 71, 256);
        check(67, 0x79, 0xa8, -24, 0);
        check(103, 0x15, 0x06, -41, 1027);
        check(104, 0x15, 0x06, 102, 0);
        check(105, 0x05, 0x00, -41, 0);
    } else if owner == "trip_str0" || owner == "trip_str1" {
        // A 32-byte user string read is clamped by signed guards and
        // the 16-byte comparison branch. The hash decrements its rank
        // to zero; the retained length is passed to memcmp.
        check(70, 0xb7, 0x09, 0, 0);
        check(71, 0xb7, 0x06, 0, 32);
        check(79, 0x85, 0x00, 0, 114);
        check(81, 0xcd, 0x90, 2, 0);
        check(82, 0x6d, 0x60, 1, 0);
        check(84, 0x6d, 0x09, 9, 0);
        check(85, 0x55, 0x01, 8, 1);
        check(86, 0xbf, 0x01, 0, 0);
        check(87, 0xb7, 0x02, 0, 1);
        check(88, 0x55, 0x01, 1, 0);
        check(89, 0xb7, 0x02, 0, 0);
        check(90, 0x57, 0x02, 0, 1);
        check(91, 0x1f, 0x20, 0, 0);
        check(139, 0x25, 0x00, 90, 30);
        check(141, 0x25, 0x00, 88, 16);
        check(144, 0xb7, 0x03, 0, 2);
        check(145, 0x2d, 0x13, 11, 0);
        check(150, 0xbf, 0x04, 0, 0);
        check(154, 0x07, 0x01, 0, 1);
        check(155, 0x07, 0x04, 0, -1);
        check(156, 0x55, 0x04, -6, 0);
        check(157, 0xbf, 0x08, 0, 0);
        check(190, 0xbf, 0x83, 0, 0);
        check(197, 0x85, 0x10, 0, 334); // linked target is memcmp
    } else if owner.ends_with("12classify_alg") {
        // Input length <=127. The inner cursor moves one byte toward
        // r7; the outer segment rank reaches eight before another
        // lookup/store/backedge. Complete bytes are separately pinned.
        check(0, 0xbf, 0x26, 0, 0);
        check(4, 0x55, 0x03, 203, 0);
        check(5, 0x25, 0x06, 202, 127);
        check(14, 0x15, 0x06, 145, 0);
        check(15, 0xbf, 0x17, 0, 0);
        check(16, 0x0f, 0x67, 0, 0);
        check(19, 0xb7, 0x02, 0, 0);
        check(20, 0x7b, 0x2a, -56, 0);
        check(28, 0xb7, 0x08, 0, 0);
        check(30, 0xbf, 0x16, 0, 0);
        check(31, 0x0f, 0x86, 0, 0);
        check(32, 0x71, 0x62, 0, 0);
        check(33, 0x15, 0x02, 7, 58);
        check(34, 0xaf, 0x23, 0, 0);
        check(35, 0x2f, 0x93, 0, 0);
        check(36, 0x07, 0x08, 0, 1);
        check(37, 0xbf, 0x12, 0, 0);
        check(38, 0x0f, 0x82, 0, 0);
        check(39, 0x1d, 0x72, 116, 0);
        check(40, 0x05, 0x00, -11, 0);
        check(53, 0x85, 0x00, 0, 1);
        check(100, 0x79, 0xa3, -56, 0);
        check(101, 0x07, 0x03, 0, 1);
        check(102, 0xbf, 0x31, 0, 0);
        check(103, 0x67, 0x01, 0, 32);
        check(104, 0x77, 0x01, 0, 32);
        check(105, 0x15, 0x01, 102, 8);
        check(106, 0x7b, 0x3a, -56, 0);
        check(107, 0x07, 0x06, 0, 1);
        check(110, 0xb7, 0x08, 0, 0);
        check(111, 0xbf, 0x61, 0, 0);
        check(117, 0x1d, 0x76, 42, 0);
        check(118, 0x05, 0x00, -93, 0);
        check(168, 0x85, 0x00, 0, 1);
    } else if owner.ends_with("13walk_dispatch") && role == "harvest" {
        check(4, 0xb7, 0x08, 0, 0);
        check(29, 0x07, 0x08, 0, 16);
        check(30, 0x15, 0x08, 63, 2048);
        check(31, 0x79, 0xa9, -32, 0);
    } else if owner.ends_with("13walk_dispatch") && role == "members" {
        check(11, 0xb7, 0x06, 0, 0);
        check(41, 0x07, 0x06, 0, 16);
        check(42, 0x15, 0x06, 63, 2048);
        check(43, 0x79, 0xa8, -32, 0);
    }
}

fn assert_reviewed_cycles(role: &str, actual: &[(String, usize, String)]) {
    // Hash the complete bytes of every cyclic function. CFG discovery runs
    // over every emitted function first, including uncalled compiler builtins.
    // These candidate bodies have separate finite induction witnesses in the
    // private object receipt; any new/changed cyclic body needs fresh review.
    let builtins = [
        (
            "memcpy",
            1,
            "7e7a209d32a6ea55688989450ea42fd989897e20f4fbdc34b22e998c0fe298eb",
        ),
        (
            "memmove",
            2,
            "62f0517ee3d810676bd434b4f39f9fcd1d6affb9c3cf09e3fcef626ea2019e6b",
        ),
        (
            "memset",
            1,
            "4f9302ba65b90ccdd5c0eccf98a67b66ee6e35e73df15c7650bf2d7f2a35e5fe",
        ),
    ];
    let mut expected = builtins.to_vec();
    match role {
        "count" => expected.push((
            "count_entry",
            1,
            "ce1274c458c727ad47be797787d28ce41f91d98b612ec3bd8f40af8e61871d2d",
        )),
        "harvest" => expected.extend([
            (
                "_RNvCsevktOyTz8Qs_17osslscope_harvest12classify_alg",
                1,
                "dd69c5df43b3a064da2d37f57f2a36cc3a91d53f3e1dc1ab7db91b51ac6e4aab",
            ),
            (
                "_RNvCsevktOyTz8Qs_17osslscope_harvest13walk_dispatch",
                1,
                "a9b65f762e91574eaeb13fe765afe93fd006270b3b0d5c8923a6ab5faf672083",
            ),
            (
                "init_return",
                1,
                "e7cede286e054a696ab5d857aac262d6cccf61594022c0d67335b31350ee4a77",
            ),
            (
                "memcmp",
                1,
                "2318d5d46a8e29d37f5263d94e620f055df7e97d69eee0151d21f4e0f1611fe0",
            ),
            (
                "trip_str0",
                1,
                "c6e7f134fe506fc8d361b6c314550a2332412024a49be071f639b711c565604b",
            ),
            (
                "trip_str1",
                1,
                "bd5afdd902fa3f2efe0b09f8452ddc857d890185e88b5c70599c6d41ba7a4c14",
            ),
        ]),
        "members" => expected.extend([
            (
                "_RNvCs4PN6m3KOtaZ_17osslscope_members12classify_alg",
                1,
                "dd69c5df43b3a064da2d37f57f2a36cc3a91d53f3e1dc1ab7db91b51ac6e4aab",
            ),
            (
                "_RNvCs4PN6m3KOtaZ_17osslscope_members13walk_dispatch",
                1,
                "3498fee53f799b03cd71a75c665f76524a941e6a78f57a86f93a72c5df6428f0",
            ),
        ]),
        _ => panic!("unknown BPF role {role}"),
    }
    expected.sort();
    let expected: Vec<_> = expected
        .into_iter()
        .map(|(name, count, hash)| (name.to_string(), count, hash.to_string()))
        .collect();
    assert_eq!(actual, expected, "{role}: reviewed cyclic function bodies");
}

fn inspect_ring_regions(
    role: &str,
    owner: &str,
    raw: &[u8],
    linked: Option<&loader::PreparedProg>,
) -> Vec<(usize, u32, u32)> {
    let insns: Vec<&[u8]> = raw.chunks_exact(8).collect();
    let mut sites = Vec::new();
    for start in 0..insns.len() {
        let x = insns[start];
        if x[0] != 0x85 || x[1] >> 4 != 0 || i32::from_le_bytes(x[4..8].try_into().unwrap()) != 131
        {
            continue;
        }
        let size = insns[start.saturating_sub(7)..start]
            .iter()
            .rev()
            .find(|y| y[0] == 0xb7 && y[1] & 15 == 2)
            .map(|y| u32::from_le_bytes(y[4..8].try_into().unwrap()) as usize)
            .unwrap_or_else(|| panic!("{role}:{owner}:{start}: reserve size unknown"));
        assert!(
            [16, 24, 32, 40, 48, 56, 64].contains(&size),
            "{role}:{owner}:{start}: reserve size {size}"
        );
        let mut initial = RingState {
            pc: start + 1,
            initialized: 0,
            known_mask: 0,
            known_bytes: [0; 64],
            aliases: [None; 11],
            values: [None; 11],
            near_reserve: 0,
        };
        initial.aliases[0] = Some(0);
        // A helper preserves r6..r9. A local, straight-line constant assignment
        // immediately before reserve is therefore usable for pad-zero proof.
        for reg in 6..10 {
            for y in insns[start.saturating_sub(16)..start].iter().rev() {
                if y[0] & 7 == 5 || y[0] & 7 == 6 {
                    break;
                }
                if y[1] & 15 == reg && (y[0] == 0xb7 || y[0] == 0xb4) {
                    initial.values[reg as usize] =
                        Some(i32::from_le_bytes(y[4..8].try_into().unwrap()) as u64);
                    break;
                }
                if y[1] & 15 == reg && (y[0] & 7 == 1 || y[0] & 7 == 4 || y[0] & 7 == 7) {
                    break;
                }
            }
        }
        let mut queue = VecDeque::from([initial]);
        let mut seen = HashSet::new();
        let mut submitted = HashSet::new();
        while let Some(mut state) = queue.pop_front() {
            if !seen.insert(state.clone()) {
                continue;
            }
            assert!(
                seen.len() <= 10_000,
                "{role}:{owner}:{start}: ring path state limit"
            );
            let pc = state.pc;
            let y = insns.get(pc).unwrap_or_else(|| {
                panic!("{role}:{owner}:{start}: reserve path exits without submit")
            });
            let op = y[0];
            let dst = (y[1] & 15) as usize;
            let src = (y[1] >> 4) as usize;
            let off = i16::from_le_bytes([y[2], y[3]]);
            let imm = i32::from_le_bytes(y[4..8].try_into().unwrap());
            if op == 0x85 && src == 0 {
                if imm == 132 {
                    assert_eq!(
                        state.aliases[1],
                        Some(0),
                        "{role}:{owner}:{start}: submit pointer"
                    );
                    let full = field_mask(0, size);
                    assert_eq!(
                        state.initialized, full,
                        "{role}:{owner}:{start}: uninitialized ring bytes"
                    );
                    assert_eq!(
                        state.known_mask & 15,
                        15,
                        "{role}:{owner}:{start}: event kind unknown"
                    );
                    let kind = u32::from_le_bytes(state.known_bytes[..4].try_into().unwrap());
                    let pads: &[usize] = match kind {
                        1..=4 => &[12, 13, 14, 15],
                        5 => &[11, 12, 13, 14, 15],
                        10 => &[12, 13, 14, 15, 44, 45, 46, 47],
                        11 => &[12, 13, 14, 15, 52, 53, 54, 55],
                        7..=9 => &[],
                        _ => panic!("{role}:{owner}:{start}: unexpected event kind {kind}"),
                    };
                    for &pad in pads {
                        assert_ne!(
                            state.known_mask & (1u64 << pad),
                            0,
                            "{role}:{owner}:{start}: pad {pad} unknown"
                        );
                        assert_eq!(
                            state.known_bytes[pad], 0,
                            "{role}:{owner}:{start}: pad {pad} nonzero"
                        );
                    }
                    submitted.insert(kind);
                    continue;
                }
                panic!("{role}:{owner}:{start}: helper {imm} before submit");
            }
            assert_ne!(
                op, 0x95,
                "{role}:{owner}:{start}: reserve path exits without submit"
            );
            if (op & 7 == 2 || op & 7 == 3) && state.aliases[dst].is_some() {
                let width = match op & 0x18 {
                    0x10 => 1,
                    0x08 => 2,
                    0x00 => 4,
                    0x18 => 8,
                    _ => unreachable!(),
                };
                let at = i32::from(state.aliases[dst].unwrap()) + i32::from(off);
                assert!(
                    at >= 0 && at as usize + width <= size,
                    "{role}:{owner}:{start}: ring store range"
                );
                let at = at as usize;
                let mask = field_mask(at, width);
                state.initialized |= mask;
                let value = if op & 7 == 2 {
                    Some(imm as u64)
                } else {
                    state.values[src]
                };
                state.known_mask &= !mask;
                if let Some(value) = value {
                    state.known_mask |= mask;
                    for k in 0..width {
                        state.known_bytes[at + k] = (value >> (8 * k)) as u8;
                    }
                }
            }
            match op {
                0xbf => {
                    state.aliases[dst] = state.aliases[src];
                    state.values[dst] = state.values[src];
                }
                0xbc => {
                    state.aliases[dst] = None;
                    state.values[dst] = state.values[src].map(|v| v & 0xffff_ffff);
                }
                0xb7 | 0xb4 => {
                    state.aliases[dst] = None;
                    state.values[dst] = Some(imm as u64);
                }
                0x07 => {
                    if let Some(a) = state.aliases[dst] {
                        state.aliases[dst] = Some(
                            a.checked_add(i16::try_from(imm).expect("ring pointer add width"))
                                .expect("ring pointer offset"),
                        );
                    }
                    state.values[dst] = state.values[dst].map(|v| v.wrapping_add(imm as u64));
                }
                0x18 => {
                    state.aliases[dst] = None;
                    state.values[dst] = None;
                }
                _ if op & 7 == 1 || op & 7 == 4 || op & 7 == 7 => {
                    state.aliases[dst] = None;
                    state.values[dst] = None;
                }
                _ => {}
            }
            if op == 0x85 && src == 1 {
                // One observed query_return call zeroes 16 RowEvent bytes.
                assert_eq!(
                    owner, "query_return",
                    "{role}:{owner}:{start}: unexpected pseudo-call in ring path"
                );
                assert_eq!(
                    imm, -1,
                    "{role}:{owner}:{start}: unexpected pseudo-call target"
                );
                let linked = linked.expect("pseudo-call requires loader-linked program");
                let call = &linked.insns[pc * 8..pc * 8 + 8];
                assert_eq!(call[0], 0x85, "linked copy call opcode");
                let relative = i32::from_le_bytes(call[4..8].try_into().unwrap()) as isize;
                let target = (pc as isize + 1 + relative) as u32;
                assert!(
                    linked
                        .subprogs
                        .iter()
                        .any(|s| s.insn_off == target && s.name == "memset"),
                    "{role}:{owner}:{start}: zero target {target}, linked {:?}",
                    linked
                        .subprogs
                        .iter()
                        .map(|s| (s.name.as_str(), s.insn_off))
                        .collect::<Vec<_>>()
                );
                let at = state.aliases[1].expect("zero destination is ring alias") as usize;
                assert_eq!(state.values[2], Some(0), "zero fill byte");
                assert_eq!(state.values[3], Some(16), "zero fill length");
                assert!(at + 16 <= size, "zero fill range");
                let mask = field_mask(at, 16);
                state.initialized |= mask;
                state.known_mask |= mask;
                for k in 0..16 {
                    state.known_bytes[at + k] = 0;
                }
                for reg in 0..6 {
                    state.aliases[reg] = None;
                    state.values[reg] = None;
                }
            }
            state.near_reserve = state.near_reserve.saturating_add(1);
            let mut push = |target: usize, mut next: RingState| {
                assert!(
                    target < insns.len(),
                    "{role}:{owner}:{start}: branch exits function"
                );
                next.pc = target;
                queue.push_back(next);
            };
            if (op & 7 == 5 || op & 7 == 6) && op != 0x85 {
                let target = (pc as isize + 1 + off as isize) as usize;
                if (op == 0x15 || op == 0x55)
                    && state.aliases[dst].is_some()
                    && imm == 0
                    && state.near_reserve <= 3
                {
                    push(if op == 0x55 { target } else { pc + 1 }, state);
                } else if op == 0x05 {
                    push(target, state);
                } else {
                    push(pc + 1, state.clone());
                    push(target, state);
                }
            } else {
                push(pc + if op == 0x18 { 2 } else { 1 }, state);
            }
        }
        assert!(
            !submitted.is_empty(),
            "{role}:{owner}:{start}: no submitted path"
        );
        for kind in submitted {
            sites.push((start, size as u32, kind));
        }
    }
    sites
}

fn scan_instructions(
    role: &str,
    owner: &str,
    raw: &[u8],
    classifier: bool,
) -> (usize, usize, usize) {
    let mut helpers = 0;
    let mut calls = 0;
    let mut min_stack = 0i16;
    let mut i = 0;
    while i < raw.len() / 8 {
        let insn = &raw[i * 8..i * 8 + 8];
        let op = insn[0];
        let dst = insn[1] & 15;
        let src = insn[1] >> 4;
        let off = i16::from_le_bytes([insn[2], insn[3]]);
        let imm = i32::from_le_bytes(insn[4..8].try_into().unwrap());
        if op == 0x18 {
            assert!(i + 1 < raw.len() / 8, "{role}:{owner}: truncated ld_imm64");
            i += 2;
            continue;
        }
        if op == 0x85 {
            if src == 0 {
                helpers += 1;
                if role == "members" {
                    assert!(
                        ![12, 181].contains(&imm),
                        "{role}:{owner}: tail/loop helper {imm}"
                    );
                }
                if role == "members" && [5, 134].contains(&imm) {
                    assert_eq!(
                        owner, "member_entry",
                        "member time/occupied helper must be entry only"
                    );
                }
                if classifier {
                    assert_eq!(
                        imm, 1,
                        "{role}:{owner}: classifier helper must be map lookup only"
                    );
                }
            } else {
                calls += 1;
                assert_eq!(src, 1, "{role}:{owner}: unknown call mode {src}");
            }
        }
        let stack_access =
            (op & 7 == 1 && src == 10) || ((op & 7 == 2 || op & 7 == 3) && dst == 10);
        if stack_access {
            let width = match op & 0x18 {
                0x10 => 1,
                0x08 => 2,
                0x00 => 4,
                0x18 => 8,
                _ => unreachable!(),
            };
            assert!(
                off >= -512 && i32::from(off) + width <= 0,
                "{role}:{owner}: stack access [{off}, {}) outside frame",
                i32::from(off) + width
            );
            min_stack = min_stack.min(off);
        }
        if classifier && (op & 0x07 == 0x03 || op & 0x07 == 0x02) {
            assert_eq!(
                dst, 10,
                "{role}:{owner}: classifier direct store outside stack"
            );
        }
        // This instruction pass does not establish verifier loop acceptance.
        i += 1;
    }
    assert!(
        min_stack >= -512,
        "{role}:{owner}: stack offset {min_stack} below -512"
    );
    (helpers, calls, (-min_stack) as usize)
}

type FrameState = [Option<i16>; 11];

fn frame_states(role: &str, owner: &str, raw: &[u8]) -> Vec<Option<FrameState>> {
    let (_valid, edges) = decoded_cfg(role, owner, raw);
    let insns: Vec<_> = raw.chunks_exact(8).collect();
    let mut at = vec![None; insns.len()];
    let mut entry: FrameState = [None; 11];
    entry[10] = Some(0); // BPF frame pointer
    at[0] = Some(entry);
    let mut queue = VecDeque::from([0]);
    let mut steps = 0;
    while let Some(pc) = queue.pop_front() {
        steps += 1;
        assert!(
            steps <= insns.len() * 64,
            "{role}:{owner}: frame provenance did not converge"
        );
        let x = insns[pc];
        let op = x[0];
        let dst = (x[1] & 15) as usize;
        let src = (x[1] >> 4) as usize;
        assert!(
            dst <= 10 && src <= 10,
            "{role}:{owner}:{pc}: register index"
        );
        let imm = i32::from_le_bytes(x[4..8].try_into().unwrap());
        let mut out = at[pc].expect("queued frame state");
        match op {
            0xbf => out[dst] = out[src],
            0x07 => {
                out[dst] = out[dst].and_then(|base| {
                    i16::try_from(imm)
                        .ok()
                        .and_then(|delta| base.checked_add(delta))
                });
            }
            0x85 => {
                for reg in &mut out[..=5] {
                    *reg = None; // helper and local-call ABI clobbers
                }
            }
            0x18 => out[dst] = None,
            _ => match op & 7 {
                0 | 1 | 4 | 7 => out[dst] = None,
                3 if op & 0xe0 == 0xc0 => out[src] = None, // atomic fetch can define source
                _ => {}
            },
        }
        assert_eq!(
            out[10],
            Some(0),
            "{role}:{owner}:{pc}: frame pointer changed"
        );
        for &next in &edges[pc] {
            let merged = if let Some(old) = at[next] {
                let mut meet = [None; 11];
                for reg in 0..11 {
                    if old[reg] == out[reg] {
                        meet[reg] = old[reg];
                    }
                }
                meet
            } else {
                out
            };
            if at[next] != Some(merged) {
                at[next] = Some(merged);
                queue.push_back(next);
            }
        }
    }
    at
}

fn require_frame_destination(
    role: &str,
    owner: &str,
    states: &[Option<FrameState>],
    pc: usize,
    size: i32,
) -> i16 {
    let state = states[pc].unwrap_or_else(|| panic!("{role}:{owner}:{pc}: unreachable read/zero"));
    let off =
        state[1].unwrap_or_else(|| panic!("{role}:{owner}:{pc}: scratch stack provenance lost"));
    assert!(
        off >= -512 && i32::from(off) + size <= 0,
        "{role}:{owner}:{pc}: scratch [{off}, {}) outside frame",
        i32::from(off) + size
    );
    off
}

fn assert_zero_dominates_read(role: &str, owner: &str, raw: &[u8], zero: usize, read: usize) {
    let (_valid, edges) = decoded_cfg(role, owner, raw);
    assert!(
        zero < read && read < edges.len(),
        "{role}:{owner}: zero/read PC range"
    );
    let mut seen = vec![false; edges.len()];
    let mut queue = VecDeque::from([0]);
    seen[0] = true;
    while let Some(pc) = queue.pop_front() {
        assert_ne!(
            pc, read,
            "{role}:{owner}:{read}: string read bypasses zero call {zero}"
        );
        for &next in &edges[pc] {
            if next != zero && !seen[next] {
                seen[next] = true;
                queue.push_back(next);
            }
        }
    }
}

fn verify_read_helpers(
    role: &str,
    owner: &str,
    raw: &[u8],
    linked: Option<&loader::PreparedProg>,
) -> (usize, usize) {
    let mut user = 0;
    let mut user_str = 0;
    let insns: Vec<_> = raw.chunks_exact(8).collect();
    let states = if insns.iter().any(|x| {
        x[0] == 0x85
            && x[1] >> 4 == 0
            && [112, 114].contains(&i32::from_le_bytes(x[4..8].try_into().unwrap()))
    }) {
        Some(frame_states(role, owner, raw))
    } else {
        None
    };
    for (pc, insn) in insns.iter().enumerate() {
        if insn[0] != 0x85 || insn[1] >> 4 != 0 {
            continue;
        }
        match i32::from_le_bytes(insn[4..8].try_into().unwrap()) {
            112 => {
                user += 1;
                assert!(pc >= 4, "{role}:{owner}:{pc}: short target read setup");
                let setup = &insns[pc - 4..pc];
                let stack = setup.iter().position(|x| x[0] == 0xbf && x[1] == 0xa1);
                let stack = stack.expect("target read destination derives from r10");
                assert!(stack + 2 < setup.len(), "target read destination setup");
                assert_eq!(setup[stack + 1][0], 0x07, "target read stack offset");
                assert_eq!(setup[stack + 1][1], 1, "target read stack destination");
                let off = i32::from_le_bytes(setup[stack + 1][4..8].try_into().unwrap());
                assert!((-512..0).contains(&off), "target read stack offset {off}");
                assert_eq!(setup[stack + 2][0..2], [0xb7, 2], "target read fixed size");
                let size = i32::from_le_bytes(setup[stack + 2][4..8].try_into().unwrap());
                assert!([4, 8].contains(&size), "target read size {size}");
                assert!(off + size <= 0, "target read extends past stack frame");
                assert_eq!(
                    require_frame_destination(role, owner, states.as_ref().unwrap(), pc, size),
                    off as i16,
                    "target read actual stack provenance"
                );
            }
            114 => {
                user_str += 1;
                assert!(pc >= 9, "{role}:{owner}:{pc}: short string read setup");
                assert_zero_dominates_read(role, owner, raw, pc - 4, pc);
                let pre = &insns[pc - 7..pc];
                let alias = pre[0][1] >> 4;
                assert_eq!(pre[0][0], 0xbf, "string zero destination move");
                assert_eq!(pre[0][1] & 15, 1, "string zero destination r1");
                assert!((6..=9).contains(&alias), "string stack alias register");
                assert_eq!(pre[1][0..2], [0xb7, 2], "string zero fill byte");
                assert_eq!(&pre[1][4..8], &[0, 0, 0, 0], "string zero fill byte");
                assert_eq!(pre[2][0..2], [0xb7, 3], "string zero fill length");
                assert_eq!(pre[3][0..2], [0x85, 0x10], "string zero call");
                if let Some(linked) = linked {
                    let call = &linked.insns[(pc - 4) * 8..(pc - 3) * 8];
                    assert_eq!(call[0..2], [0x85, 0x10], "linked string zero call");
                    let relative = i32::from_le_bytes(call[4..8].try_into().unwrap()) as isize;
                    let target = (pc as isize - 3 + relative) as u32;
                    assert!(
                        linked
                            .subprogs
                            .iter()
                            .any(|s| s.insn_off == target && s.name == "memset"),
                        "{role}:{owner}:{pc}: string zero call does not target memset"
                    );
                } else if role != "fixture" {
                    panic!("{role}:{owner}:{pc}: linked read provenance required");
                }
                assert_eq!(pre[4][0], 0xbf, "string read destination move");
                assert_eq!(
                    pre[4][1], pre[0][1],
                    "string read and zero same stack alias"
                );
                assert_eq!(pre[5][0..2], [0xb7, 2], "string fixed read bound");
                assert_eq!(pre[5][4..8], pre[2][4..8], "string read fits zeroed buffer");
                let size = i32::from_le_bytes(pre[5][4..8].try_into().unwrap());
                assert!([32, 128].contains(&size), "string read size {size}");
                assert_eq!(pre[6][0], 0xbf, "string read source move");
                assert_eq!(pre[6][1] & 15, 3, "string read source r3");
                let states = states.as_ref().unwrap();
                let zero_dest = require_frame_destination(role, owner, states, pc - 4, size);
                let read_dest = require_frame_destination(role, owner, states, pc, size);
                assert_eq!(
                    zero_dest, read_dest,
                    "{role}:{owner}:{pc}: zero/read stack alias differs"
                );
            }
            _ => {}
        }
    }
    let expected = match role {
        "count" => (0, 0),
        "harvest" if owner.ends_with("13walk_dispatch") => (2, 0),
        "harvest"
            if (owner.len() == 2
                && owner.starts_with('c')
                && owner.as_bytes()[1].is_ascii_digit()) =>
        {
            (4, 1)
        }
        "harvest" => match owner {
            "init_return" => (3, 0),
            "query_return" => (4, 1),
            "trip_str0" | "trip_str1" => (0, 1),
            _ => (0, 0),
        },
        "members" if owner.ends_with("13walk_dispatch") => (2, 0),
        "members" => match owner {
            "member_000" => (3, 1),
            "member_511" => (5, 1),
            name if name.starts_with("member_") && name.len() == 10 => (4, 1),
            _ => (0, 0),
        },
        _ => panic!("unknown object role {role}"),
    };
    assert_eq!(
        (user, user_str),
        expected,
        "{role}:{owner}: target read helper sites drift"
    );
    (user, user_str)
}

fn verify_tail_calls(
    role: &str,
    owner: &str,
    raw: &[u8],
    linked: Option<&loader::PreparedProg>,
) -> usize {
    let insns: Vec<_> = raw.chunks_exact(8).collect();
    let mut count = 0;
    for (pc, insn) in insns.iter().enumerate() {
        if insn[0] != 0x85
            || insn[1] >> 4 != 0
            || i32::from_le_bytes(insn[4..8].try_into().unwrap()) != 12
        {
            continue;
        }
        count += 1;
        assert_eq!(role, "harvest", "tail calls only in harvest");
        let expected_index = if owner == "query_return" {
            0
        } else if owner.len() == 2 && owner.starts_with('c') && owner.as_bytes()[1].is_ascii_digit()
        {
            let index = owner.as_bytes()[1] - b'0';
            assert!(index < 7, "{role}:{owner}: unexpected tail-call owner");
            i32::from(index) + 1
        } else {
            panic!("{role}:{owner}: unexpected tail-call owner");
        };
        assert!(pc >= 3, "{role}:{owner}:{pc}: short tail-call setup");
        assert_eq!(insns[pc - 1][0..2], [0xb7, 3], "tail-call fixed slot");
        assert_eq!(
            i32::from_le_bytes(insns[pc - 1][4..8].try_into().unwrap()),
            expected_index,
            "{role}:{owner}:{pc}: tail-call slot"
        );
        assert_eq!(insns[pc - 3][0], 0x18, "tail-call map load");
        assert_eq!(insns[pc - 3][1] & 15, 2, "tail-call map in r2");
        let linked = linked.expect("tail-call main must be linked");
        assert!(
            linked
                .map_fixups
                .iter()
                .any(|f| f.map == "JUMPS" && f.insn_off == (pc - 3) * 8),
            "{role}:{owner}:{pc}: tail-call map is JUMPS"
        );
    }
    assert_eq!(
        count,
        match owner {
            "query_return" => 2,
            "c0" | "c1" | "c2" | "c3" | "c4" | "c5" | "c6" => 3,
            _ => 0,
        },
        "{role}:{owner}: tail-call site count"
    );
    count
}

fn verify_trip_map_readonly(prepared: &loader::Prepared) {
    let mut seen = HashSet::new();
    for p in &prepared.progs {
        for fixup in p.map_fixups.iter().filter(|f| f.map == "TRIP_CLASS") {
            assert!(
                ["trip_str0", "trip_str1"].contains(&p.name.as_str()),
                "TRIP_CLASS referenced by {}",
                p.name
            );
            assert!(
                seen.insert(p.name.clone()),
                "duplicate TRIP_CLASS reference in {}",
                p.name
            );
            let pc = fixup.insn_off / 8;
            let at = |n: usize| &p.insns[n * 8..n * 8 + 8];
            assert_eq!(at(pc)[0], 0x18, "TRIP_CLASS map load");
            assert_eq!(at(pc)[1] & 15, 1, "TRIP_CLASS loaded into r1");
            assert_eq!(at(pc + 2)[0], 0x85, "TRIP_CLASS lookup call");
            assert_eq!(
                i32::from_le_bytes(at(pc + 2)[4..8].try_into().unwrap()),
                1,
                "TRIP_CLASS lookup-only helper"
            );
            assert_eq!(at(pc + 3)[0], 0x15, "TRIP_CLASS null guard");
            // Actual 22-byte value is copied with 11 paired 16-bit loads from
            // the map-value pointer r0 to a stack alias r1, then r0 is no
            // longer used as a writable pointer. No store targets r0.
            for j in 0..11 {
                let load = at(pc + 6 + 2 * j);
                let store = at(pc + 7 + 2 * j);
                assert_eq!((load[0], load[1]), (0x69, 0x02), "TRIP_CLASS value read");
                assert_eq!(
                    (store[0], store[1]),
                    (0x6b, 0x21),
                    "TRIP_CLASS stack-only copy"
                );
                assert_eq!(
                    i16::from_le_bytes(load[2..4].try_into().unwrap()),
                    (2 * j) as i16
                );
                assert_eq!(
                    i16::from_le_bytes(store[2..4].try_into().unwrap()),
                    (2 * j) as i16
                );
            }
            for n in pc + 28..pc + 36 {
                let x = at(n);
                assert!(
                    !((x[0] & 7 == 2 || x[0] & 7 == 3) && x[1] & 15 == 0),
                    "TRIP_CLASS value pointer direct store after copy"
                );
                assert!(
                    !(x[0] == 0xbf && x[1] >> 4 == 0),
                    "TRIP_CLASS pointer alias after copy"
                );
            }
            assert_eq!(
                at(pc + 36)[0],
                0x85,
                "TRIP_CLASS pointer lifetime ends at call"
            );
        }
    }
    assert_eq!(
        seen,
        HashSet::from(["trip_str0".to_string(), "trip_str1".to_string()]),
        "both trip classifier users inspected"
    );
}

fn linked_call_depth(role: &str, p: &loader::PreparedProg) -> usize {
    let starts: HashSet<usize> = p.subprogs.iter().map(|s| s.insn_off as usize).collect();
    let mut edges: HashMap<usize, HashSet<usize>> = HashMap::new();
    let mut owner = 0;
    for (pc, insn) in p.insns.chunks_exact(8).enumerate() {
        if starts.contains(&pc) {
            owner = pc;
        }
        if insn[0] == 0x85 && insn[1] >> 4 == 1 {
            let relative = i32::from_le_bytes(insn[4..8].try_into().unwrap()) as isize;
            let target = (pc as isize + 1 + relative) as usize;
            assert!(
                starts.contains(&target),
                "{role}:{}: call target {target} is not a linked subprogram",
                p.name
            );
            edges.entry(owner).or_default().insert(target);
        }
    }
    fn depth(
        node: usize,
        edges: &HashMap<usize, HashSet<usize>>,
        active: &mut HashSet<usize>,
        memo: &mut HashMap<usize, usize>,
    ) -> usize {
        if let Some(value) = memo.get(&node) {
            return *value;
        }
        assert!(active.insert(node), "recursive BPF subprogram graph");
        let value = 1 + edges
            .get(&node)
            .map(|next| {
                next.iter()
                    .map(|n| depth(*n, edges, active, memo))
                    .max()
                    .unwrap_or(0)
            })
            .unwrap_or(0);
        active.remove(&node);
        memo.insert(node, value);
        value
    }
    let mut memo = HashMap::new();
    let mut active = HashSet::new();
    let max = starts
        .iter()
        .map(|n| depth(*n, &edges, &mut active, &mut memo))
        .max()
        .unwrap_or(0);
    assert!(
        max <= 8,
        "{role}:{}: BPF call depth {max} exceeds 8",
        p.name
    );
    max
}

fn bounded_library_calls(role: &str, p: &loader::PreparedProg) -> (HashMap<i32, usize>, usize) {
    let mut memset_sizes = HashMap::new();
    let mut memcmp_calls = 0;
    for (pc, x) in p.insns.chunks_exact(8).enumerate() {
        if x[0] != 0x85 || x[1] >> 4 != 1 {
            continue;
        }
        let relative = i32::from_le_bytes(x[4..8].try_into().unwrap()) as isize;
        let target = (pc as isize + 1 + relative) as u32;
        let callee = p
            .subprogs
            .iter()
            .find(|s| s.insn_off == target)
            .expect("linked local call target");
        if callee.name == "memset" {
            assert!(pc > 0, "{role}:{}:{pc}: missing memset length", p.name);
            let length = &p.insns[(pc - 1) * 8..pc * 8];
            assert_eq!(
                length[0..2],
                [0xb7, 3],
                "{role}:{}:{pc}: literal memset length",
                p.name
            );
            let size = i32::from_le_bytes(length[4..8].try_into().unwrap());
            assert!(
                [16, 24, 32, 128].contains(&size),
                "{role}:{}:{pc}: memset length {size}",
                p.name
            );
            *memset_sizes.entry(size).or_insert(0) += 1;
        } else if callee.name == "memcmp" {
            assert_eq!(role, "harvest", "memcmp only in harvest");
            assert!(
                ["trip_str0", "trip_str1"].contains(&p.name.as_str()),
                "memcmp only in trip strings"
            );
            memcmp_calls += 1;
        }
    }
    (memset_sizes, memcmp_calls)
}

fn inspect_object(
    role: &str,
    bytes: &[u8],
    prepared: &loader::Prepared,
    maps: &[loader::MapSpec],
    progs: &[loader::ProgSpec],
) -> serde_json::Value {
    let elf = Elf::parse(bytes).expect("valid ELF");
    assert_eq!(elf.header.e_machine, header::EM_BPF, "BPF ELF");
    assert!(elf.little_endian, "little endian BPF");
    let mut license = None;
    let mut funcs = HashMap::<String, Vec<u8>>::new();
    let mut sections = HashMap::new();
    let mut function_ranges = HashMap::<usize, Vec<(usize, usize)>>::new();
    for (index, sh) in elf.section_headers.iter().enumerate() {
        let name = elf.shdr_strtab.get_at(sh.sh_name).expect("section name");
        sections.insert(index, name);
        assert!(
            ![".BTF", ".BTF.ext"].contains(&name),
            "{role}: embedded {name}"
        );
        assert!(
            !name.starts_with(".data") && !name.starts_with(".bss") && !name.starts_with(".rodata"),
            "{role}: non-map global data {name}"
        );
        if sh.sh_flags & (section_header::SHF_ALLOC as u64) != 0 {
            assert!(
                ["maps", ".text", "uprobe", "uretprobe"].contains(&name),
                "{role}: extra allocated section {name}"
            );
        }
        if name == ".license" {
            license = Some(section_bytes(bytes, sh).to_vec());
        }
    }
    let mut map_names = HashSet::new();
    for s in &elf.syms {
        let name = elf.strtab.get_at(s.st_name).unwrap_or("");
        let section = sections.get(&s.st_shndx).copied().unwrap_or("");
        if s.st_type() == sym::STT_OBJECT && section == "maps" {
            map_names.insert(name.to_string());
        }
        if s.st_type() != sym::STT_FUNC || s.st_size == 0 {
            continue;
        }
        assert!(
            ["uprobe", "uretprobe", ".text"].contains(&section),
            "{role}: unexpected func section {section}"
        );
        let sh = &elf.section_headers[s.st_shndx];
        let sec = section_bytes(bytes, sh);
        let start = s.st_value as usize;
        let end = start
            .checked_add(s.st_size as usize)
            .expect("function range overflow");
        let raw = sec.get(start..end).expect("function in section");
        assert_eq!(start % 8, 0, "{role}:{name}: unaligned function start");
        function_ranges
            .entry(s.st_shndx)
            .or_default()
            .push((start, end));
        assert!(
            funcs.insert(name.to_string(), raw.to_vec()).is_none(),
            "{role}: duplicate function {name}"
        );
    }
    for (index, sh) in elf.section_headers.iter().enumerate() {
        if sh.sh_flags & (section_header::SHF_EXECINSTR as u64) == 0 {
            continue;
        }
        let section = sections[&index];
        assert!(
            [".text", "uprobe", "uretprobe"].contains(&section),
            "{role}: unknown executable section {section}"
        );
        assert_function_coverage(
            role,
            section,
            sh.sh_size as usize,
            function_ranges
                .get(&index)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
        );
    }
    let expected_maps: HashSet<String> = maps.iter().map(|m| m.name.to_string()).collect();
    assert_eq!(map_names, expected_maps, "{role}: exact map symbols");
    if role != "count" {
        assert_eq!(
            funcs
                .keys()
                .filter(|name| name.ends_with("12classify_alg"))
                .count(),
            1,
            "{role}: emitted algorithm classifier subprogram"
        );
        assert!(
            prepared
                .progs
                .iter()
                .any(|p| p.map_fixups.iter().any(|f| f.map == "ALG_CLASS")),
            "{role}: algorithm classifier map must be referenced"
        );
        for p in &prepared.progs {
            for fixup in p.map_fixups.iter().filter(|f| f.map == "ALG_CLASS") {
                let site = fixup.insn_off / 8;
                let owner = p
                    .subprogs
                    .iter()
                    .rev()
                    .find(|s| s.insn_off as usize <= site)
                    .expect("algorithm map fixup owner");
                assert!(
                    owner.name.ends_with("12classify_alg"),
                    "{role}: ALG_CLASS map use outside classifier: {}",
                    owner.name
                );
            }
        }
    }
    if role == "harvest" {
        verify_trip_map_readonly(prepared);
    }
    let memset = funcs
        .get("memset")
        .expect("compiler memset function present");
    assert_eq!(
        Sha256::digest(memset)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        "4f9302ba65b90ccdd5c0eccf98a67b66ee6e35e73df15c7650bf2d7f2a35e5fe",
        "{role}: reviewed 8-instruction memset body changed"
    );
    let mut read_totals = (0, 0);
    let mut tail_total = 0;
    let mut cycles = Vec::new();
    for (name, raw) in &funcs {
        let linked = prepared.progs.iter().find(|p| p.name == *name);
        let (user, user_str) = verify_read_helpers(role, name, raw, linked);
        read_totals.0 += user;
        read_totals.1 += user_str;
        tail_total += verify_tail_calls(role, name, raw, linked);
        let count = cfg_cycle_count(role, name, raw);
        if count != 0 {
            assert_builtin_loop_witness(role, name, raw);
            assert_application_loop_witness(role, name, raw);
            let hash = Sha256::digest(raw)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            cycles.push((name.clone(), count, hash));
        }
    }
    cycles.sort();
    assert_reviewed_cycles(role, &cycles);
    assert_eq!(
        cycles.iter().map(|(_, count, _)| count).sum::<usize>(),
        match role {
            "count" => 5,
            "harvest" => 10,
            "members" => 6,
            _ => unreachable!(),
        },
        "{role}: exact cyclic SCC count"
    );
    assert_eq!(tail_total, if role == "harvest" { 23 } else { 0 });
    assert_eq!(
        read_totals,
        match role {
            "count" => (0, 0),
            "harvest" => (41, 11),
            "members" => (2050, 512),
            _ => unreachable!(),
        },
        "complete emitted target-read census"
    );
    let ring_sites: usize = funcs
        .iter()
        .map(|(name, raw)| {
            let linked = prepared.progs.iter().find(|p| p.name == *name);
            inspect_ring_regions(role, name, raw, linked).len()
        })
        .sum();
    assert_eq!(
        ring_sites,
        match role {
            "count" => 0,
            "harvest" => 27,
            "members" => 2566,
            _ => unreachable!(),
        },
        "{role}: all ring reservation sites inspected"
    );
    let mut visited = HashSet::new();
    let mut helper_count = 0;
    let mut call_count = 0;
    let mut max_stack = 0;
    let mut max_call_depth = 0;
    let mut memset_sizes = HashMap::new();
    let mut memcmp_calls = 0;
    for p in &prepared.progs {
        assert!(
            progs.iter().any(|s| s.name == p.name),
            "{role}: unexpected main"
        );
        assert_eq!(
            p.subprogs.first().map(|s| s.name.as_str()),
            Some(p.name.as_str()),
            "{role}: main first"
        );
        for sub in &p.subprogs {
            let raw = funcs
                .get(&sub.name)
                .unwrap_or_else(|| panic!("{role}: linked subprog {} missing", sub.name));
            visited.insert(sub.name.clone());
            let classifier = sub.name.contains("classify_alg")
                || sub.name.contains("classify_trip")
                || sub.name.contains("fnv");
            let (helpers, calls, stack) = scan_instructions(role, &sub.name, raw, classifier);
            helper_count += helpers;
            call_count += calls;
            max_stack = max_stack.max(stack);
        }
        assert!(
            p.insns.len() <= 1_000_000 * 8,
            "{role}: linked instruction sanity bound"
        );
        max_call_depth = max_call_depth.max(linked_call_depth(role, p));
        let (sizes, compare) = bounded_library_calls(role, p);
        for (size, count) in sizes {
            *memset_sizes.entry(size).or_insert(0) += count;
        }
        memcmp_calls += compare;
    }
    assert_eq!(
        memset_sizes,
        match role {
            "count" => HashMap::from([(24, 1)]),
            "harvest" => HashMap::from([(128, 9), (16, 1), (32, 2)]),
            "members" => HashMap::from([(128, 512)]),
            _ => unreachable!(),
        },
        "{role}: complete bounded memset call census"
    );
    assert_eq!(memcmp_calls, if role == "harvest" { 2 } else { 0 });
    for spec in progs {
        assert!(
            visited.contains(spec.name),
            "{role}: unvisited main {}",
            spec.name
        );
    }
    // Every emitted function must be a main or reachable from a main.  This
    // catches unvisited classifier bodies hidden in a newly emitted .text.
    let emitted: HashSet<String> = funcs.keys().cloned().collect();
    let unvisited: HashSet<_> = emitted.difference(&visited).cloned().collect();
    let compiler_builtins: HashSet<_> = ["memcpy", "memmove", "memset"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert!(
        unvisited.is_subset(&compiler_builtins),
        "{role}: unvisited application subprograms {unvisited:?}"
    );
    for name in &unvisited {
        let raw = funcs.get(name).expect("unvisited func present");
        let (helpers, calls, stack) = scan_instructions(role, name, raw, false);
        assert_eq!(helpers, 0, "{role}:{name}: unused compiler builtin helper");
        helper_count += helpers;
        call_count += calls;
        max_stack = max_stack.max(stack);
    }
    if role == "members" {
        let mains: Vec<_> = (0..512)
            .map(|i| {
                funcs
                    .get(&format!("member_{i:03}"))
                    .unwrap_or_else(|| panic!("member_{i:03} absent"))
            })
            .collect();
        assert_eq!(
            mains.iter().collect::<HashSet<_>>().len(),
            512,
            "512 distinct baked bodies"
        );
        assert!(funcs.contains_key("member_entry"));
    }
    let license_hex = license
        .as_ref()
        .map(|x| x.iter().map(|b| format!("{b:02x}")).collect::<String>());
    eprintln!(
        "{role}: functions={} maps={} helpers={} calls={} stack_offset_max={} license={license_hex:?}",
        funcs.len(),
        map_names.len(),
        helper_count,
        call_count,
        max_stack
    );
    serde_json::json!({"role":role,"functions":funcs.len(),"maps":map_names.len(),"helpers":helper_count,
        "calls":call_count,"max_stack_offset":max_stack,"license_hex":license_hex,
        "license_section_present":license.is_some(),"embedded_btf":false,
        "max_static_call_depth":max_call_depth,"ring_reservation_sites_checked":ring_sites,
        "target_read_user_sites":read_totals.0,"target_read_user_str_sites":read_totals.1,
        "fixed_tail_call_sites":tail_total,"cyclic_functions":cycles,
        "memset_call_sizes":memset_sizes,"memcmp_calls":memcmp_calls})
}

fn negative_controls(bytes: &[u8], prepared: &loader::Prepared) {
    let elf = Elf::parse(bytes).expect("members ELF");
    let branch_owner = elf
        .syms
        .iter()
        .find(|s| {
            s.st_type() == sym::STT_FUNC && elf.strtab.get_at(s.st_name) == Some("member_001")
        })
        .expect("member_001 symbol");
    let branch_at = elf.section_headers[branch_owner.st_shndx].sh_offset as usize
        + branch_owner.st_value as usize
        + 418 * 8;
    let mut bad_scratch = bytes.to_vec();
    assert_eq!(bad_scratch[branch_at], 0x05, "member_001 branch opcode");
    assert_eq!(
        i16::from_le_bytes(
            bad_scratch[branch_at + 2..branch_at + 4]
                .try_into()
                .unwrap()
        ),
        257,
        "member_001 original branch displacement"
    );
    bad_scratch[branch_at + 2..branch_at + 4].copy_from_slice(&4i16.to_le_bytes());
    assert_eq!(
        Sha256::digest(&bad_scratch)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        "657965b9b89eea790f0bfaed167b2fc9ed9ac4c1f4773ea44b2c3fa115ebecca",
        "reviewed scratch-bypass mutant bytes"
    );
    let altered = loader::prepare(&bad_scratch, &MEMBER_MAPS, &MEMBER_PROGS)
        .expect("scratch-bypass mutant remains a prepared BPF object");
    let section = section_bytes(&bad_scratch, &elf.section_headers[branch_owner.st_shndx]);
    let raw = &section[branch_owner.st_value as usize
        ..branch_owner.st_value as usize + branch_owner.st_size as usize];
    let rejection = std::panic::catch_unwind(|| {
        verify_read_helpers(
            "members",
            "member_001",
            raw,
            altered.progs.iter().find(|p| p.name == "member_001"),
        )
    })
    .expect_err("actual-object scratch-alias CFG bypass must fail");
    let reason = rejection
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| rejection.downcast_ref::<&str>().copied())
        .unwrap_or("non-string panic");
    assert!(
        reason.contains("scratch stack provenance lost"),
        "wrong scratch rejection: {reason}"
    );
    let map_index = elf
        .section_headers
        .iter()
        .position(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some("maps"))
        .unwrap();
    let map_sym = elf
        .syms
        .iter()
        .find(|s| {
            s.st_type() == sym::STT_OBJECT
                && s.st_shndx == map_index
                && elf.strtab.get_at(s.st_name) == Some("CALLS")
        })
        .unwrap();
    let mut bad_map = bytes.to_vec();
    let flag = elf.section_headers[map_index].sh_offset as usize + map_sym.st_value as usize + 16;
    assert_eq!(&bad_map[flag..flag + 4], &[0, 0, 0, 0]);
    bad_map[flag] = 1;
    assert!(
        loader::prepare(&bad_map, &MEMBER_MAPS, &MEMBER_PROGS).is_err(),
        "changed map flag must fail"
    );

    let mut bad_elf = bytes.to_vec();
    bad_elf[0] = 0;
    assert!(
        loader::prepare(&bad_elf, &MEMBER_MAPS, &MEMBER_PROGS).is_err(),
        "malformed ELF must fail"
    );

    let strtab = elf
        .section_headers
        .iter()
        .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".strtab"))
        .unwrap();
    let member = elf
        .syms
        .iter()
        .find(|s| elf.strtab.get_at(s.st_name) == Some("member_000"))
        .unwrap();
    let mut bad_member = bytes.to_vec();
    let char_offset = strtab.sh_offset as usize + member.st_name + "member_00".len();
    assert_eq!(bad_member[char_offset], b'0');
    bad_member[char_offset] = b'x';
    assert!(
        loader::prepare(&bad_member, &MEMBER_MAPS, &MEMBER_PROGS).is_err(),
        "missing member must fail"
    );
    assert!(
        std::panic::catch_unwind(|| inspect_object(
            "members",
            &bad_member,
            prepared,
            &MEMBER_MAPS,
            &MEMBER_PROGS
        ))
        .is_err(),
        "independent graph must also reject renamed member"
    );

    let text_sym = elf
        .syms
        .iter()
        .find(|s| {
            s.st_type() == sym::STT_FUNC
                && s.st_shndx < elf.section_headers.len()
                && elf
                    .shdr_strtab
                    .get_at(elf.section_headers[s.st_shndx].sh_name)
                    == Some(".text")
                && elf
                    .strtab
                    .get_at(s.st_name)
                    .unwrap_or("")
                    .contains("classify_alg")
        })
        .expect("classifier subprogram");
    let text_sec = section_bytes(bytes, &elf.section_headers[text_sym.st_shndx]);
    let mut classifier_raw = text_sec
        [text_sym.st_value as usize..text_sym.st_value as usize + text_sym.st_size as usize]
        .to_vec();
    let stack_store = classifier_raw
        .chunks_exact(8)
        .enumerate()
        .find(|(_, x)| (x[0] & 7 == 2 || x[0] & 7 == 3) && x[1] & 15 == 10)
        .map(|(i, _)| i)
        .expect("classifier stack store");
    classifier_raw[stack_store * 8 + 1] &= 0xf0;
    assert!(
        std::panic::catch_unwind(|| scan_instructions(
            "members",
            "classify_alg",
            &classifier_raw,
            true
        ))
        .is_err(),
        "actual-object classifier direct nonstack store must fail"
    );
    let mut bad_subprog = bytes.to_vec();
    let sub_offset = strtab.sh_offset as usize + text_sym.st_name;
    bad_subprog[sub_offset] = if bad_subprog[sub_offset] == b'_' {
        b'x'
    } else {
        b'_'
    };
    assert!(
        std::panic::catch_unwind(|| inspect_object(
            "members",
            &bad_subprog,
            prepared,
            &MEMBER_MAPS,
            &MEMBER_PROGS
        ))
        .is_err(),
        "missing classifier subprogram must fail"
    );

    let shstrtab = &elf.section_headers[elf.header.e_shstrndx as usize];
    let maps_name_at = shstrtab.sh_offset as usize + elf.section_headers[map_index].sh_name;
    assert_eq!(&bytes[maps_name_at..maps_name_at + 4], b"maps");
    for replacement in [b".BTF", b".bss"] {
        let mut bad_section = bytes.to_vec();
        bad_section[maps_name_at..maps_name_at + 4].copy_from_slice(replacement);
        assert!(
            std::panic::catch_unwind(|| inspect_object(
                "members",
                &bad_section,
                prepared,
                &MEMBER_MAPS,
                &MEMBER_PROGS
            ))
            .is_err(),
            "embedded BTF/global section must fail independent scan"
        );
    }
}

fn ring_pad_object_negative(bytes: &[u8], prepared: &loader::Prepared) {
    let elf = Elf::parse(bytes).expect("harvest ELF");
    let c0 = elf
        .syms
        .iter()
        .find(|s| s.st_type() == sym::STT_FUNC && elf.strtab.get_at(s.st_name) == Some("c0"))
        .expect("c0 symbol");
    let c0_sec = section_bytes(bytes, &elf.section_headers[c0.st_shndx]);
    let mut bad_slot =
        c0_sec[c0.st_value as usize..c0.st_value as usize + c0.st_size as usize].to_vec();
    let tail = bad_slot
        .chunks_exact(8)
        .position(|x| x[0] == 0x85 && x[1] == 0 && x[4..8] == [12, 0, 0, 0])
        .expect("c0 tail call");
    bad_slot[(tail - 1) * 8 + 4] = 0;
    assert!(
        std::panic::catch_unwind(|| {
            verify_tail_calls(
                "harvest",
                "c0",
                &bad_slot,
                prepared.progs.iter().find(|p| p.name == "c0"),
            )
        })
        .is_err(),
        "actual-object changed tail-call slot must fail"
    );
    let sym = elf
        .syms
        .iter()
        .find(|s| {
            s.st_type() == sym::STT_FUNC
                && elf
                    .strtab
                    .get_at(s.st_name)
                    .unwrap_or("")
                    .ends_with("13walk_dispatch")
        })
        .expect("harvest walk_dispatch symbol");
    let sh = &elf.section_headers[sym.st_shndx];
    let sec = section_bytes(bytes, sh);
    let start = sym.st_value as usize;
    let mut raw = sec[start..start + sym.st_size as usize].to_vec();
    let name = elf.strtab.get_at(sym.st_name).expect("walk symbol name");
    let mut bad_rank = raw.clone();
    assert_eq!(bad_rank[29 * 8 + 4], 16);
    bad_rank[29 * 8 + 4] = 0;
    assert!(
        std::panic::catch_unwind(|| assert_application_loop_witness("harvest", name, &bad_rank))
            .is_err(),
        "actual-object broken loop rank must fail"
    );
    let site = raw
        .chunks_exact(8)
        .enumerate()
        .find(|(i, x)| {
            x[0] == 0xb7
                && x[1] & 15 == 1
                && x[4..8] == [0, 0, 0, 0]
                && raw
                    .get((i + 1) * 8..(i + 2) * 8)
                    .is_some_and(|next| next[0] == 0x63 && next[1] == 0x10 && next[2..4] == [12, 0])
        })
        .map(|(i, _)| i)
        .expect("walk_dispatch pad-zero store");
    assert!(!inspect_ring_regions("harvest", "walk_dispatch", &raw, None).is_empty());
    raw[site * 8 + 4] = 1;
    assert!(
        std::panic::catch_unwind(|| inspect_ring_regions("harvest", "walk_dispatch", &raw, None))
            .is_err(),
        "actual-object changed pad store must fail"
    );

    let trip = elf
        .syms
        .iter()
        .find(|s| s.st_type() == sym::STT_FUNC && elf.strtab.get_at(s.st_name) == Some("trip_str0"))
        .expect("trip_str0 symbol");
    let trip_sec = section_bytes(bytes, &elf.section_headers[trip.st_shndx]);
    let mut trip_raw =
        trip_sec[trip.st_value as usize..trip.st_value as usize + trip.st_size as usize].to_vec();
    let call = trip_raw
        .chunks_exact(8)
        .enumerate()
        .find(|(_, x)| x[0] == 0x85 && x[1] >> 4 == 0 && x[4..8] == [1, 0, 0, 0])
        .map(|(i, _)| i)
        .expect("trip map lookup helper");
    trip_raw[call * 8 + 4..call * 8 + 8].copy_from_slice(&112i32.to_le_bytes());
    assert!(
        std::panic::catch_unwind(|| {
            verify_read_helpers(
                "harvest",
                "trip_str0",
                &trip_raw,
                prepared.progs.iter().find(|p| p.name == "trip_str0"),
            )
        })
        .is_err(),
        "actual-object added target read must fail"
    );

    let mut bad_string_bound =
        trip_sec[trip.st_value as usize..trip.st_value as usize + trip.st_size as usize].to_vec();
    let string_call = bad_string_bound
        .chunks_exact(8)
        .position(|x| x[0] == 0x85 && x[1] == 0 && x[4..8] == [114, 0, 0, 0])
        .expect("trip string-read helper");
    bad_string_bound[(string_call - 2) * 8 + 4..(string_call - 2) * 8 + 8]
        .copy_from_slice(&256i32.to_le_bytes());
    assert!(
        std::panic::catch_unwind(|| {
            verify_read_helpers(
                "harvest",
                "trip_str0",
                &bad_string_bound,
                prepared.progs.iter().find(|p| p.name == "trip_str0"),
            )
        })
        .is_err(),
        "actual-object oversized string read must fail"
    );

    let mut bad_trip_store = bytes.to_vec();
    let first_copy = trip_sec
        [trip.st_value as usize..trip.st_value as usize + trip.st_size as usize]
        .chunks_exact(8)
        .enumerate()
        .find(|(_, x)| x[0] == 0x69 && x[1] == 0x02 && x[2..4] == [0, 0])
        .map(|(i, _)| i)
        .expect("TRIP_CLASS first value read");
    let byte = elf.section_headers[trip.st_shndx].sh_offset as usize
        + trip.st_value as usize
        + first_copy * 8;
    bad_trip_store[byte] = 0x6b; // store u16 instead of load u16
    bad_trip_store[byte + 1] = 0x20; // map-value pointer r0 as destination
    let altered = loader::prepare(&bad_trip_store, &HARVEST_MAPS, &HARVEST_PROGS)
        .expect("mutated instruction still prepares, so independent gate must reject");
    assert!(
        std::panic::catch_unwind(|| verify_trip_map_readonly(&altered)).is_err(),
        "actual-object classifier map-value direct store must fail"
    );
}
