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
    let prepared = osslscope::loader::prepare_focused_count(&bytes).unwrap();
    assert_eq!(prepared.maps.len(), 9);
    assert_eq!(prepared.progs.len(), 1);
    let helpers: Vec<u32> = prepared.progs[0]
        .insns
        .chunks_exact(8)
        .filter(|i| i[0] == 0x85 && i[1] >> 4 == 0)
        .map(|i| u32::from_le_bytes(i[4..8].try_into().unwrap()))
        .collect();
    assert!(helpers.contains(&120));
    assert!(!helpers.contains(&14));
    assert!(helpers.iter().all(|h| [1, 2, 5, 120, 174].contains(h)));
    let mut drift = bytes.clone();
    let off = drift
        .windows(9)
        .position(|s| s == b"NS_CONFIG")
        .expect("namespace map symbol");
    drift[off] = b'X';
    assert!(osslscope::loader::prepare_focused_count(&drift).is_err());
}

#[test]
#[ignore = "requires an explicitly supplied freshly built focused BPF object"]
fn actual_object_refuses_dimension_root_helper_and_namespace_drift() {
    let path =
        std::env::var("OSSLSCOPE_FOCUSED_COUNT_OBJECT").expect("fresh focused BPF object required");
    let bytes = std::fs::read(path).unwrap();
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
                    osslscope::loader::prepare_focused_count(&bad).is_err(),
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
        osslscope::loader::prepare_focused_count(&bad).is_err(),
        "initial-namespace helper must be refused"
    );
    let root = bytes
        .windows(12)
        .position(|w| w == b"count_entry\0")
        .unwrap();
    let mut bad = bytes.clone();
    bad[root] = b'x';
    assert!(
        osslscope::loader::prepare_focused_count(&bad).is_err(),
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
