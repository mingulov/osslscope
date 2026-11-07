// SPDX-License-Identifier: GPL-3.0-or-later
use osslscope::{evidence::*, focused_count::*};
use osslscope_ebpf_common::CountValue;

fn binding(session: u64, mapping: u64, algorithm: &str) -> SiteBinding {
    SiteBinding {
        site: SiteKey {
            object: ObjectId("a".repeat(64)),
            device: 0x12345678,
            inode: 71,
            offset: 32,
        },
        session_generation: session,
        mapping_generation: mapping,
        candidates: vec![CandidateIdentity::new(
            ObjectId("b".repeat(64)),
            "unknown".into(),
            1,
            1,
            vec![algorithm.into()],
            true,
        )],
        installed_ns: 10,
    }
}
fn value(n: u64) -> CountValue {
    CountValue {
        count: n,
        first_ns: 12,
        last_ns: 18,
    }
}
#[test]
fn native_device_roundtrips_through_maps_encoding() {
    let native = libc::makedev(0xabc, 0xdef01);
    let encoded = evidence_device(native);
    assert_eq!(encoded, 0xabc000def01);
    assert_eq!(
        libc::makedev((encoded >> 32) as u32, encoded as u32),
        native
    );
}
#[test]
fn major_zero_high_minor_raw_differs_but_guards_stay_encoded() {
    // 1D-fix1 (codex R1): raw==encoded holds only for major-0
    // minor<256 — device 0:256 packs minor bits above bit 8 in
    // the glibc dev_t (0x100000) while the evidence encoding is
    // (major<<32)|minor (0x100).
    let raw = libc::makedev(0, 256);
    let encoded = osslscope::plan::encode_device(0, 256);
    assert_eq!(encoded, 0x100);
    assert_eq!(raw, 0x100000);
    assert_ne!(encoded, raw);
    // Both sides of every fixed guard use the encoded word: the
    // fresh-stat side is encoded before comparing, so the audit's
    // domain rule holds even where raw!=encoded.
    assert_eq!(evidence_device(raw), encoded);
    // Positive control pinning the qualified claim: major-0
    // minor<256 still coincides numerically.
    let low_raw = libc::makedev(0, 51);
    assert_eq!(osslscope::plan::encode_device(0, 51), low_raw);
    assert_eq!(evidence_device(low_raw), low_raw);
}
#[test]
fn physical_site_deduplicates_attachment_and_conserves_calls() {
    let mut fold = CountFold::new(CountLimits::default()).unwrap();
    let mut links = 0;
    let grouped = || {
        let mut b = binding(1, 90, "sha256");
        b.candidates.extend(binding(1, 90, "sha384").candidates);
        b
    };
    let a = fold
        .attach(grouped(), |_, _| {
            links += 1;
            Ok(())
        })
        .unwrap();
    let b = fold
        .attach(grouped(), |_, _| {
            links += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(a, b);
    assert_eq!(links, 1);
    fold.observe(a.0, a.1, &[value(7)]).unwrap();
    let sample = fold.sample();
    assert_eq!(sample.sites.len(), 1);
    assert_eq!(sample.sites[0].calls, 7);
    assert_eq!(sample.sites[0].candidates.len(), 2);
    assert_eq!(
        sample.sites[0].candidates_coverage,
        CandidateCoverage::Unknown
    );
    assert!(sample.sites[0].candidates.iter().all(|c| c.weak_alias));
}
#[test]
fn late_metadata_never_relabels_calls_on_an_installed_cookie() {
    let mut fold = CountFold::new(CountLimits::default()).unwrap();
    let a = fold
        .attach(binding(1, 90, "sha256"), |_, _| Ok(()))
        .unwrap();
    fold.observe(a.0, a.1, &[value(3)]).unwrap();
    let b = fold
        .attach(binding(1, 90, "sha384"), |_, _| {
            panic!("one active physical link")
        })
        .unwrap();
    fold.observe(b.0, b.1, &[value(5)]).unwrap();
    let sample = fold.sample();
    assert_eq!(a, b);
    assert_eq!(sample.sites[0].calls, 5);
    assert_eq!(sample.sites[0].candidates.len(), 1);
    assert_eq!(
        sample.sites[0].candidates[0].algorithm_classes,
        vec!["sha256"]
    );
    assert!(
        sample
            .gaps
            .iter()
            .any(|g| g.name == "focused_metadata_changed" && g.value > 0)
    );
}
#[test]
fn no_advertiser_still_counts_the_physical_site_with_unknown_attribution() {
    let mut fold = CountFold::new(CountLimits::default()).unwrap();
    let mut bare = binding(1, 90, "sha256");
    bare.candidates.clear();
    let a = fold.attach(bare, |_, _| Ok(())).unwrap();
    fold.observe(a.0, a.1, &[value(6)]).unwrap();
    let sample = fold.sample();
    assert_eq!(sample.sites[0].calls, 6);
    assert!(sample.sites[0].candidates.is_empty());
    assert_eq!(
        sample.sites[0].candidates_coverage,
        CandidateCoverage::Unknown
    );
}
#[test]
fn malformed_per_cpu_timestamp_cannot_hide_behind_another_cpu() {
    let mut fold = CountFold::new(CountLimits::default()).unwrap();
    let a = fold
        .attach(binding(1, 90, "sha256"), |_, _| Ok(()))
        .unwrap();
    assert_eq!(
        fold.observe(
            a.0,
            a.1,
            &[
                value(2),
                CountValue {
                    count: 1,
                    first_ns: 17,
                    last_ns: 0
                }
            ]
        ),
        Err(CountFailure::Read)
    );
    assert_eq!(fold.sample().sites[0].calls, 0);
}
#[test]
fn session_change_fences_old_cookie_without_truncating_or_using_mapping_generation() {
    let mut fold = CountFold::new(CountLimits::default()).unwrap();
    let a = fold
        .attach(binding(1, 90, "sha256"), |_, _| Ok(()))
        .unwrap();
    fold.observe(a.0, a.1, &[value(2)]).unwrap();
    let b = fold
        .attach(binding(1 + (1u64 << 32), 90, "sha256"), |_, _| Ok(()))
        .unwrap();
    assert_ne!(a.0, b.0);
    assert_ne!(a.1, b.1);
    assert_ne!(b.1, 90);
    fold.observe(a.0, a.1, &[value(3)]).unwrap();
    fold.observe(b.0, b.1, &[value(5)]).unwrap();
    let sample = fold.sample();
    assert_eq!(sample.fenced[0].calls, 3);
    assert_eq!(sample.sites[0].calls, 5);
}
#[test]
fn foreign_cookie_and_generation_are_unattributed_and_snapshots_are_cumulative() {
    let mut fold = CountFold::new(CountLimits::default()).unwrap();
    let a = fold
        .attach(binding(1, 90, "sha256"), |_, _| Ok(()))
        .unwrap();
    for _ in 0..2 {
        fold.observe(a.0, a.1, &[value(4), value(3)]).unwrap();
        fold.observe(999, a.1, &[value(2)]).unwrap();
        fold.observe(a.0, a.1 + 1, &[value(1)]).unwrap();
    }
    let sample = fold.sample();
    assert_eq!(sample.sites[0].calls, 7);
    assert_eq!(sample.unattributed, 3);
    assert!(sample.gaps.iter().any(|g| g.name == "focused_unattributed"
        && g.value == 3
        && g.units == CounterUnits::Calls
        && g.source == CounterSource::KernelMap));
}
#[test]
fn timestamps_outside_the_admission_window_are_refused() {
    let limits = CountLimits {
        window: CountAdmissionWindow {
            start_ns: 11,
            deadline_ns: 18,
        },
        ..Default::default()
    };
    let mut fold = CountFold::new(limits).unwrap();
    let a = fold
        .attach(binding(1, 90, "sha256"), |_, _| Ok(()))
        .unwrap();
    assert_eq!(fold.observe(a.0, a.1, &[value(2)]), Err(CountFailure::Read));
    assert_eq!(fold.sample().sites[0].calls, 0);
}
#[test]
fn map_generation_replacement_gets_a_new_cookie_but_old_evidence_survives() {
    let mut fold = CountFold::new(CountLimits::default()).unwrap();
    let a = fold
        .attach(binding(1, 90, "sha256"), |_, _| Ok(()))
        .unwrap();
    fold.observe(a.0, a.1, &[value(8)]).unwrap();
    let b = fold
        .attach(binding(1, 91, "sha256"), |_, _| Ok(()))
        .unwrap();
    assert_ne!(a, b);
    assert_eq!(fold.sample().fenced[0].calls, 8);
}
#[test]
fn metadata_storage_is_charged_before_an_attachment_can_succeed() {
    let mut fold = CountFold::new(CountLimits {
        max_state_bytes: 2048,
        ..Default::default()
    })
    .unwrap();
    let mut large = binding(1, 90, "sha256");
    large.site.object.0 = "a".repeat(4096);
    assert_eq!(
        fold.attach(large, |_, _| panic!("must not attach")),
        Err(CountFailure::Resource)
    );
    assert!(fold.sample().sites.is_empty());
}
#[test]
fn refused_attachment_never_publishes_site_and_consumes_cookie_budget() {
    let mut limits = CountLimits::default();
    limits.max_cookies = 1;
    let mut fold = CountFold::new(limits).unwrap();
    assert_eq!(
        fold.attach(binding(1, 90, "sha256"), |_, _| Err(CountFailure::Attach)),
        Err(CountFailure::Attach)
    );
    assert!(fold.sample().sites.is_empty());
    assert_eq!(
        fold.attach(binding(1, 90, "sha256"), |_, _| Ok(())),
        Err(CountFailure::Resource)
    );
}
#[test]
fn namespace_failure_refuses_even_matching_target() {
    assert!(!osslscope_ebpf_common::focused_namespace_admits(
        -22, 41, 41
    ));
    assert!(!osslscope_ebpf_common::focused_namespace_admits(0, 40, 41));
    assert!(!osslscope_ebpf_common::focused_namespace_admits(0, 0, 0));
    assert!(osslscope_ebpf_common::focused_namespace_admits(0, 41, 41));
}
#[test]
fn malformed_limits_and_window_are_refused_before_loading() {
    let mut limits = CountLimits::default();
    limits.max_cpus = 257;
    assert!(matches!(
        CountFold::new(limits),
        Err(CountFailure::Resource)
    ));
    let ns = osslscope::inventory::NamespaceId {
        device: 1,
        inode: 2,
    };
    assert!(matches!(
        FocusedCounter::open(&[], 1, ns, CountLimits::default()),
        Err(CountFailure::Object)
    ));
}
#[test]
#[ignore = "requires an explicitly supplied freshly built focused BPF object"]
fn actual_focused_object_shape_privacy_and_namespace_guard() {
    let path = std::env::var("OSSLSCOPE_FOCUSED_COUNT_OBJECT")
        .expect("set OSSLSCOPE_FOCUSED_COUNT_OBJECT to the freshly built object");
    let bytes = std::fs::read(path).expect("read focused BPF object");
    let budget = osslscope::provider_observation::ObservationBudget::default();
    let prepared = osslscope::loader::prepare_focused_count(&bytes, &budget).unwrap();
    // The count object carries the 20 borrowed producer maps plus its own
    // 13 (gate + 7 count + 2 ns + 3 6B sealed-bound maps: BOUNDS,
    // EPOCH, EPOCH_CUR per the frozen 6B D-record §11.1), exactly
    // what FOCUSED_COUNT_MAPS specifies. This 33-map pin updates the
    // 30-map pin for the D-record-mandated sealed-bound mechanism.
    assert_eq!(prepared.maps.len(), 33);
    assert_eq!(prepared.progs.len(), 1);
    let helpers: Vec<u32> = prepared.progs[0]
        .insns
        .chunks_exact(8)
        .filter(|i| i[0] == 0x85 && i[1] >> 4 == 0)
        .map(|i| u32::from_le_bytes(i[4..8].try_into().unwrap()))
        .collect();
    assert!(helpers.contains(&120));
    assert!(!helpers.contains(&14));
    // U1: the same-handler operational join adds the kernel-memory read
    // (113) and current-task-BTF (158) helpers via the VMA join; kfunc
    // calls use src 2 and never appear in this helper set.
    assert!(
        helpers
            .iter()
            .all(|h| [1, 2, 5, 113, 120, 158, 174].contains(h))
    );
    let mut drift = bytes.clone();
    let off = drift
        .windows(9)
        .position(|s| s == b"NS_CONFIG")
        .expect("namespace map symbol");
    drift[off] = b'X';
    assert!(osslscope::loader::prepare_focused_count(&drift, &budget).is_err());
}

#[test]
#[ignore = "requires an explicitly supplied freshly built focused BPF object"]
fn actual_object_refuses_dimension_root_helper_and_namespace_drift() {
    let path =
        std::env::var("OSSLSCOPE_FOCUSED_COUNT_OBJECT").expect("fresh focused BPF object required");
    let bytes = std::fs::read(path).unwrap();
    let budget = osslscope::provider_observation::ObservationBudget::default();
    let elf = goblin::elf::Elf::parse(&bytes).unwrap();
    for symbol in &elf.syms {
        let name = elf.strtab.get_at(symbol.st_name).unwrap_or("");
        if [
            "COUNTS",
            "ADMITTED",
            "LATC",
            "GEN",
            "TARGET",
            "WINDOW",
            "DROPFAIL",
            "NS_CONFIG",
            "NSFAIL",
        ]
        .contains(&name)
        {
            let offset =
                elf.section_headers[symbol.st_shndx].sh_offset as usize + symbol.st_value as usize;
            for field in [0, 4, 8, 12, 16] {
                let mut bad = bytes.clone();
                bad[offset + field] ^= 1;
                assert!(
                    osslscope::loader::prepare_focused_count(&bad, &budget).is_err(),
                    "{name} field {field}"
                );
            }
        }
    }
    let section = elf
        .section_headers
        .iter()
        .find(|s| elf.shdr_strtab.get_at(s.sh_name) == Some("uprobe"))
        .unwrap();
    let base = section.sh_offset as usize;
    let code = &bytes[base..base + section.sh_size as usize];
    let helper = code
        .chunks_exact(8)
        .position(|i| {
            i[0] == 0x85 && i[1] >> 4 == 0 && u32::from_le_bytes(i[4..8].try_into().unwrap()) == 120
        })
        .unwrap();
    let mut bad = bytes.clone();
    bad[base + helper * 8 + 4..base + helper * 8 + 8].copy_from_slice(&14u32.to_le_bytes());
    assert!(
        osslscope::loader::prepare_focused_count(&bad, &budget).is_err(),
        "initial-namespace helper must be refused"
    );
    let root = bytes
        .windows(12)
        .position(|w| w == b"count_entry\0")
        .unwrap();
    let mut bad = bytes.clone();
    bad[root] = b'x';
    assert!(
        osslscope::loader::prepare_focused_count(&bad, &budget).is_err(),
        "unapproved root must be refused"
    );
    let limits = CountLimits {
        window: CountAdmissionWindow {
            start_ns: 1,
            deadline_ns: 2,
        },
        ..Default::default()
    };
    assert!(matches!(
        FocusedCounter::open(
            &bytes,
            1,
            osslscope::inventory::NamespaceId {
                device: 0,
                inode: 0
            },
            limits
        ),
        Err(CountFailure::Namespace)
    ));
}

#[test]
fn physical_cookie_capacity_is_independent_of_link_fd_capacity() {
    let mut fold = CountFold::new(CountLimits {
        max_links: 1,
        ..CountLimits::default()
    })
    .unwrap();
    for offset in 0..600 {
        let mut b = binding(1, 90, "unknown");
        b.site.offset = offset;
        fold.attach(b, |_, _| Ok(()))
            .expect("one batched link can own many physical cookies");
    }
    assert_eq!(fold.sample().sites.len(), 600);
}

#[test]
fn saturated_physical_count_retains_lower_bound_with_explicit_loss() {
    let mut fold = CountFold::new(CountLimits::default()).unwrap();
    let (cookie, generation) = fold
        .attach(binding(1, 90, "sha256"), |_, _| Ok(()))
        .unwrap();
    fold.observe(cookie, generation, &[value(u64::MAX)])
        .unwrap();
    let sample = fold.sample();
    assert_eq!(sample.sites[0].calls, u64::MAX);
    assert!(
        sample
            .gaps
            .iter()
            .any(|g| g.name == "focused_saturated" && g.forces_partial())
    );
    fold.observe(cookie, generation, &[value(u64::MAX)])
        .unwrap();
    assert_eq!(
        fold.sample()
            .gaps
            .iter()
            .find(|g| g.name == "focused_saturated")
            .unwrap()
            .value,
        1
    );
}

/// Emitted seqlock shape (R1 finding 1): the `tag_bounds` updater
/// must emit TWO distinct seq stores (odd, then even) with payload
/// writes between — LLVM once merged them into a single `+= 2`
/// store AFTER the payload (insns 204-205, 347-348), making the
/// host even/equal check vacuous. Both inlined copies (fast +
/// slow path) must show the split shape:
/// (a) no `ALU64 ADD K=2` anywhere in `count_entry` (the merge
/// signature — exactly 2 pre-fix, both merges);
/// (b) ≥2 disjoint `LDX[+0] → STX[+0] → STX[+off] → STX[+0]`
/// windows on one base register, each flanking store fed by its
/// own `ADD64 K=1` (no clobber between).
#[test]
#[ignore = "requires an explicitly supplied freshly built focused BPF object"]
fn actual_focused_object_seqlock_emits_two_seq_stores() {
    let path = std::env::var("OSSLSCOPE_FOCUSED_COUNT_OBJECT")
        .expect("set OSSLSCOPE_FOCUSED_COUNT_OBJECT to the freshly built object");
    let bytes = std::fs::read(path).expect("read focused BPF object");
    let budget = osslscope::provider_observation::ObservationBudget::default();
    let prepared = osslscope::loader::prepare_focused_count(&bytes, &budget).unwrap();
    assert_eq!(prepared.progs.len(), 1);
    let insns = &prepared.progs[0].insns;
    assert_eq!(insns.len() % 8, 0, "whole instructions");
    let n = insns.len() / 8;
    let op = |i: usize| insns[i * 8];
    let dst = |i: usize| insns[i * 8 + 1] & 0x0f;
    let src = |i: usize| insns[i * 8 + 1] >> 4;
    let off = |i: usize| i16::from_le_bytes([insns[i * 8 + 2], insns[i * 8 + 3]]);
    let imm = |i: usize| {
        i32::from_le_bytes([
            insns[i * 8 + 4],
            insns[i * 8 + 5],
            insns[i * 8 + 6],
            insns[i * 8 + 7],
        ])
    };
    // (a) The merge signature: any ADD64 K=2 is the folded pair.
    let mut add2 = 0;
    for i in 0..n {
        if op(i) == 0x07 && imm(i) == 2 {
            add2 += 1;
        }
    }
    assert_eq!(add2, 0, "merged seq += 2 stores (R1 finding 1)");
    // An STX's value reg fed by ADD64 K=1 within 12 insns, with no
    // clobber between (a call clobbers r0-r5; LD_IMM64 tails are
    // not writes; jumps never write their dst).
    let fed_by_add1 = |store: usize, rv: u8| -> bool {
        let lo = store.saturating_sub(12);
        let mut j = store;
        while j > lo {
            j -= 1;
            if op(j) == 0x00 {
                continue; // LD_IMM64 tail — not a write.
            }
            if op(j) == 0x85 {
                if rv <= 5 {
                    return false; // Call clobbered r0-r5.
                }
                continue;
            }
            match op(j) & 0x07 {
                0x00 | 0x01 | 0x04 | 0x07 if dst(j) == rv => {
                    return op(j) == 0x07 && imm(j) == 1;
                }
                _ => {}
            }
        }
        false
    };
    // (b) Seq windows: LDX[rb+0] … STX[rb+0] … STX[rb+off≠0] …
    // STX[rb+0] on one base within 96 insns, both flankers ADD-1
    // fed. Greedy disjoint scan (extras are harmless — the bound
    // is a minimum, one window per inlined copy).
    let mut windows = 0;
    let mut i = 0;
    while i < n {
        let mut end = None;
        if op(i) == 0x79 && off(i) == 0 {
            let rb = src(i);
            let lim = (i + 96).min(n);
            let mut first: Option<usize> = None;
            let mut payload = false;
            let mut j = i + 1;
            while j < lim {
                if op(j) == 0x7b && dst(j) == rb {
                    if off(j) == 0 {
                        if first.is_none() {
                            first = Some(j);
                        } else if payload {
                            end = Some(j);
                            break;
                        }
                    } else if first.is_some() {
                        payload = true;
                    }
                }
                j += 1;
            }
            if let (Some(f), Some(e)) = (first, end) {
                let v0 = src(f);
                let v1 = src(e);
                if fed_by_add1(f, v0) && fed_by_add1(e, v1) {
                    windows += 1;
                    i = e + 1;
                    continue;
                }
            }
        }
        i += 1;
    }
    assert!(
        windows >= 2,
        "two split seq-guard windows (fast + slow path), found {windows}"
    );
}
