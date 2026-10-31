// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
#[path = "../../tests/support/provider_forwarder.rs"]
mod fixture;
use fixture::{ForwarderFixture, GETCTX, OTHER, QUERY, UNQUERY};
const NEAR: &str = ".byte 0xe9\n.long query_impl-.-4";
const SHORT_BACK: &str = ".byte 0xeb\n.byte unquery_impl-.-1";
const GETCTX_NEAR: &str = ".byte 0xe9\n.long getctx_impl-.-4";

#[test]
fn startup_admits_typed_metadata_at_real_forwarded_sites() {
    let f = ForwarderFixture::new(NEAR, SHORT_BACK);
    let child = crate::target::OwnedTarget::spawn_stopped(
        &["/bin/true".into()],
        crate::target::WorkloadDest::Null,
    )
    .unwrap();
    let custody = StartupProcess::held(&child).unwrap();
    let StartupCandidates { apis: sites, .. } =
        startup_candidates(custody, f.file(), &ObservationBudget::default(), None).unwrap();
    let offsets: Vec<_> = sites
        .into_iter()
        .map(|s| s.into_parts().1.file_offset())
        .collect();
    assert_eq!(
        offsets.len(),
        2,
        "query/unquery public signatures must prearm before exec; fetch remains mapped-only"
    );
    assert!(offsets.contains(&f.offsets["query_impl"]));
    assert!(offsets.contains(&f.offsets["unquery_impl"]));
}

#[test]
fn startup_metadata_alias_conflict_with_any_public_role_refuses_reader() {
    let mut f = ForwarderFixture::new(NEAR, SHORT_BACK);
    let at = f.symbols[OTHER] + 8;
    f.image[at..at + 8].copy_from_slice(&f.addresses[QUERY].to_le_bytes());
    let child = crate::target::OwnedTarget::spawn_stopped(
        &["/bin/true".into()],
        crate::target::WorkloadDest::Null,
    )
    .unwrap();
    let StartupCandidates {
        apis: sites,
        partial,
        ..
    } = startup_candidates(
        StartupProcess::held(&child).unwrap(),
        f.file(),
        &ObservationBudget::default(),
        None,
    )
    .unwrap();
    let offsets: Vec<_> = sites
        .into_iter()
        .map(|s| s.into_parts().1.file_offset())
        .collect();
    assert_eq!(
        offsets,
        vec![f.offsets["unquery_impl"]],
        "fetch alias must arbitrate even though fetch is not prearmed"
    );
    assert!(partial, "refused public role ambiguity must be disclosed");
}

#[test]
fn queued_startup_authority_survives_owned_exit_but_cannot_rearm() {
    let f = ForwarderFixture::new(NEAR, SHORT_BACK);
    let mut child = crate::target::OwnedTarget::spawn_stopped(
        &["/bin/true".into()],
        crate::target::WorkloadDest::Null,
    )
    .unwrap();
    let StartupCandidates { apis: sites, .. } = startup_candidates(
        StartupProcess::held(&child).unwrap(),
        f.file(),
        &ObservationBudget::default(),
        None,
    )
    .unwrap();
    let (_, site) = sites.into_iter().next().unwrap().into_parts();
    site.revalidate_object().unwrap();
    child.release_retaining_exit().unwrap();
    let until = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while child.peek_exit().unwrap().is_none() {
        assert!(std::time::Instant::now() < until);
        std::thread::yield_now();
    }
    assert!(
        site.revalidate_object().is_err(),
        "queued history cannot arm a new reader"
    );
    assert!(
        site.revalidate_queued().unwrap(),
        "exact retained pidfd permits historical queued records"
    );
    child.finish_observation().unwrap();
    assert!(
        site.revalidate_queued().unwrap(),
        "consuming wait cannot recycle retained original authority"
    );
    use std::os::unix::fs::PermissionsExt;
    let path = format!("/proc/self/fd/{}", site.attachment_fd().as_raw_fd());
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(site.revalidate_queued(), Err(ObservationGap::ObjectChanged));
}

fn parsed(f: &ForwarderFixture) -> ElfObject {
    let file = f.file();
    let expected = inventory::elf::inspect_file(&mut file.try_clone().unwrap(), u64::MAX).unwrap();
    assert!(
        inspect_expected_exports(
            &mut file.try_clone().unwrap(),
            &expected,
            &mut ObservationBudget::default()
        )
        .unwrap()
        .contains(&ObservationApi::OsslProviderUnqueryOperation)
    );
    let object = Object {
        stamp: Stamp::of(&file.metadata().unwrap()),
        page: None,
        file,
        parse_deferred: Cell::new(false),
        anchor: OnceCell::new(),
        expected: Some(expected),
        parsed: OnceCell::new(),
        tables: OnceCell::new(),
    };
    object.parsed(&ObservationBudget::default()).unwrap();
    object.parsed.into_inner().unwrap().unwrap()
}
fn offset(parsed: &ElfObject, name: &str) -> Option<u64> {
    parsed
        .exports
        .iter()
        .find(|(api, _)| api.export_name() == Some(name))
        .map(|(_, at)| *at)
}
fn query_role_offset(parsed: &ElfObject, role: u32) -> Option<u64> {
    parsed
        .query_exports
        .iter()
        .find(|(found, _)| found.id() == role)
        .map(|(_, at)| *at)
}
fn typed_role_offset(parsed: &ElfObject, role: u32) -> Option<u64> {
    parsed
        .typed_exports
        .iter()
        .find(|(found, _)| found.id() == role)
        .map(|(_, at)| *at)
}

#[test]
fn exact_forwarders_resolve_query_and_backward_unquery_once() {
    for prefix in ["", ".byte 0xf3,0x0f,0x1e,0xfa\n"] {
        for (query, unquery) in [
            (format!("{prefix}{NEAR}"), format!("{prefix}{SHORT_BACK}")),
            (
                format!("{prefix}.byte 0xeb\n.byte query_impl-.-1"),
                format!("{prefix}.byte 0xe9\n.long unquery_impl-.-4"),
            ),
        ] {
            let f = ForwarderFixture::new(&query, &unquery);
            let parsed = parsed(&f);
            assert_eq!(
                offset(&parsed, QUERY),
                Some(f.offsets["query_impl"]),
                "query: {query}"
            );
            assert_eq!(
                offset(&parsed, UNQUERY),
                Some(f.offsets["unquery_impl"]),
                "unquery: {unquery}"
            );
            assert_eq!(offset(&parsed, OTHER), Some(f.offsets[OTHER]));
            let at = offset(&parsed, QUERY).unwrap() as usize;
            assert_eq!(&f.image[at..at + 6], &[0xb8, 9, 0, 0, 0, 0xc3]);
            let at = offset(&parsed, UNQUERY).unwrap() as usize;
            assert_eq!(&f.image[at..at + 6], &[0xb8, 7, 0, 0, 0, 0xc3]);
        }
    }
}

#[test]
fn unsupported_wrappers_keep_the_validated_public_entry() {
    for wrapper in [
        ".byte 0xc3",
        ".byte 0xe9",
        ".byte 0xeb",
        ".byte 0xf3,0x0f,0x1e,0xfa,0xe9",
        ".byte 0x90,0xe9\n.long query_impl-.-4",
        ".byte 0xe9\n.long query_impl-.-4\n.byte 0x90",
        ".byte 0xe8\n.long query_impl-.-4\n.byte 0xc3",
        ".byte 0xff,0x25,0,0,0,0",
        ".byte 0x74,0",
        ".byte 0x48,0x83,0xc7,1,0xeb,0",
    ] {
        let f = ForwarderFixture::new(wrapper, SHORT_BACK);
        assert_eq!(
            offset(&parsed(&f), QUERY),
            Some(f.offsets[QUERY]),
            "{wrapper}"
        );
    }
}

#[test]
fn unsafe_forward_targets_keep_the_validated_public_entry() {
    let f = ForwarderFixture::new(NEAR, SHORT_BACK);
    let cases = [
        f.addresses[QUERY],
        f.addresses[QUERY] + 1,
        f.addresses["other_function"] + 1,
        f.addresses[OTHER],
        f.addresses["resolver"],
        f.addresses["linkage_stub"],
        f.addresses["data_target"],
        0,
    ];
    for target in cases {
        let mut f = ForwarderFixture::new(NEAR, SHORT_BACK);
        f.query_target(target);
        assert_eq!(
            offset(&parsed(&f), QUERY),
            Some(f.offsets[QUERY]),
            "target {target:x}"
        );
    }
    for delta in [i32::MIN, i32::MAX] {
        let mut f = ForwarderFixture::new(NEAR, SHORT_BACK);
        let at = f.offsets[QUERY] as usize;
        f.image[at + 1..at + 5].copy_from_slice(&delta.to_le_bytes());
        assert_eq!(offset(&parsed(&f), QUERY), Some(f.offsets[QUERY]));
    }
}

#[test]
fn absent_or_oversized_wrapper_lengths_do_not_authorize_forwarding() {
    for size in [0, 4, 6, 1024, u64::MAX] {
        let mut f = ForwarderFixture::new(NEAR, SHORT_BACK);
        f.size(QUERY, size);
        // A symbol that no longer fits its executable segment retains existing refusal.
        let expected = if size >= 1024 {
            None
        } else {
            Some(f.offsets[QUERY])
        };
        assert_eq!(offset(&parsed(&f), QUERY), expected, "size {size}");
    }
}

#[test]
fn forwarding_is_one_hop_and_never_looks_up_a_private_symbol() {
    let mut f = ForwarderFixture::new(NEAR, SHORT_BACK);
    let target = f.offsets["query_impl"] as usize;
    f.image[target..target + 6].copy_from_slice(&[0xeb, 2, 0x90, 0x90, 0xc3, 0x90]);
    assert_eq!(offset(&parsed(&f), QUERY), Some(f.offsets["query_impl"]));
}

#[test]
fn checked_target_arithmetic_rejects_positive_address_overflow() {
    let mut f = ForwarderFixture::new(NEAR, SHORT_BACK);
    f.rebase(u64::MAX - 0xffff);
    let at = f.offsets[QUERY] as usize;
    f.image[at + 1..at + 5].copy_from_slice(&i32::MAX.to_le_bytes());
    assert_eq!(offset(&parsed(&f), QUERY), Some(f.offsets[QUERY]));
}

#[test]
fn exact_dynamic_function_entry_is_allowed_but_public_source_alias_is_not_forwarded() {
    let mut f = ForwarderFixture::new(NEAR, SHORT_BACK);
    f.query_target(f.addresses["other_function"]);
    assert_eq!(
        offset(&parsed(&f), QUERY),
        Some(f.offsets["other_function"])
    );
    let mut f = ForwarderFixture::new(NEAR, SHORT_BACK);
    let at = f.symbols[OTHER] + 8;
    f.image[at..at + 8].copy_from_slice(&f.addresses[QUERY].to_le_bytes());
    assert_eq!(offset(&parsed(&f), QUERY), Some(f.offsets[QUERY]));
    assert_eq!(offset(&parsed(&f), OTHER), Some(f.offsets[QUERY]));
}

#[test]
fn sectionless_forwarders_work_and_immediate_indirect_stubs_are_refused() {
    for stub in [
        vec![0xff, 0x25, 0, 0, 0, 0],
        vec![0xf2, 0xff, 0x25, 0, 0, 0],
        vec![0xf3, 0x0f, 0x1e, 0xfa, 0xff, 0x25],
        vec![0xf3, 0x0f, 0x1e, 0xfa, 0xf2, 0xff],
        vec![0xb8, 9, 0, 0, 0, 0xc3],
    ] {
        let mut f = ForwarderFixture::new(NEAR, SHORT_BACK);
        let target = f.offsets["query_impl"] as usize;
        f.image[target..target + 6].copy_from_slice(&stub);
        f.sectionless();
        let want = if stub[0] == 0xb8 {
            f.offsets["query_impl"]
        } else {
            f.offsets[QUERY]
        };
        assert_eq!(offset(&parsed(&f), QUERY), Some(want), "stub {stub:x?}");
    }
}

#[test]
fn named_plt_sections_are_refused_even_without_an_indirect_prefix() {
    let mut f = ForwarderFixture::new(NEAR, SHORT_BACK);
    f.query_target(f.addresses["linkage_stub"]);
    let target = f.offsets["linkage_stub"] as usize;
    f.image[target..target + 6].copy_from_slice(&[0xb8, 9, 0, 0, 0, 0xc3]);
    assert_eq!(offset(&parsed(&f), QUERY), Some(f.offsets[QUERY]));
}

#[test]
fn target_must_be_within_executable_file_bytes_not_segment_padding() {
    let mut f = ForwarderFixture::new(NEAR, SHORT_BACK);
    let elf = goblin::elf::Elf::parse(&f.image).unwrap();
    let segment = elf
        .program_headers
        .iter()
        .find(|p| p.p_type == 1 && p.p_flags & 1 != 0)
        .unwrap();
    let end = segment.p_vaddr + segment.p_filesz;
    f.query_target(end);
    assert_eq!(offset(&parsed(&f), QUERY), Some(f.offsets[QUERY]));
}

#[test]
fn conflicting_forwarded_query_roles_keep_both_public_entries() {
    let f = ForwarderFixture::new(NEAR, ".byte 0xe9\n.long query_impl-.-4");
    let parsed = parsed(&f);
    assert_eq!(offset(&parsed, QUERY), Some(f.offsets[QUERY]));
    assert_eq!(offset(&parsed, UNQUERY), Some(f.offsets[UNQUERY]));
}

#[test]
fn writable_executable_backing_cannot_authorize_forwarding() {
    let mut f = ForwarderFixture::new(NEAR, SHORT_BACK);
    let elf = goblin::elf::Elf::parse(&f.image).unwrap();
    let index = elf
        .program_headers
        .iter()
        .position(|p| p.p_type == 1 && p.p_flags & 1 != 0)
        .unwrap();
    let at = elf.header.e_phoff as usize + index * 56 + 4;
    f.image[at] |= 2;
    assert_eq!(offset(&parsed(&f), QUERY), Some(f.offsets[QUERY]));
}

#[test]
fn forwarded_virtual_addresses_are_translated_to_distinct_file_offsets() {
    let mut f = ForwarderFixture::new(NEAR, SHORT_BACK);
    f.rebase(0x400000);
    assert_ne!(f.addresses["query_impl"], f.offsets["query_impl"]);
    let parsed = parsed(&f);
    assert_eq!(offset(&parsed, QUERY), Some(f.offsets["query_impl"]));
    assert_eq!(offset(&parsed, UNQUERY), Some(f.offsets["unquery_impl"]));
    assert_eq!(offset(&parsed, OTHER), Some(f.offsets[OTHER]));
}

#[test]
fn overlapping_executable_destination_ranges_do_not_authorize_forwarding() {
    let mut f = ForwarderFixture::new(NEAR, SHORT_BACK);
    let elf = goblin::elf::Elf::parse(&f.image).unwrap();
    let index = elf
        .program_headers
        .iter()
        .position(|p| p.p_type == 0x6474e551)
        .unwrap();
    let at = elf.header.e_phoff as usize + index * 56;
    f.image[at..at + 56].fill(0);
    for (relative, value, size) in [
        (0, 1u64, 4),
        (4, 5, 4),
        (8, f.offsets["query_impl"], 8),
        (16, f.addresses["query_impl"], 8),
        (32, 6, 8),
        (40, 6, 8),
        (48, 1, 8),
    ] {
        f.image[at + relative..at + relative + size].copy_from_slice(&value.to_le_bytes()[..size]);
    }
    assert_eq!(offset(&parsed(&f), QUERY), Some(f.offsets[QUERY]));
}

// Literal sectionless ELF: shared unknown FUNC names reuse one valid unrelated
// executable address. Disjoint PT_LOAD virtual ranges reuse the same file byte.
fn adversarial_forwarder() -> (ForwarderFixture, u64) {
    const BASE: u64 = 0x400000;
    const SYMBOLS: usize = 8192;
    const EXTRA_SEGMENTS: usize = 1024;
    let names = b"\0OSSL_PROVIDER_query_operation\0unrelated\0";
    let dynamic = 64 + (EXTRA_SEGMENTS + 2) * 56;
    let hash = dynamic + 96;
    let strings = hash + 8 + (1 + SYMBOLS) * 4;
    let symbols = (strings + names.len() + 7) & !7;
    let code = symbols + SYMBOLS * 24;
    let mut image = vec![0; code + 16];
    image[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    let put = |image: &mut [u8], at: usize, value: u64, size: usize| {
        image[at..at + size].copy_from_slice(&value.to_le_bytes()[..size]);
    };
    for (at, value, size) in [
        (16, 3, 2),
        (18, 62, 2),
        (20, 1, 4),
        (32, 64, 8),
        (52, 64, 2),
        (54, 56, 2),
        (56, (EXTRA_SEGMENTS + 2) as u64, 2),
    ] {
        put(&mut image, at, value, size);
    }
    let len = image.len() as u64;
    for (at, value, size) in [
        (64, 1, 4),
        (68, 5, 4),
        (80, BASE, 8),
        (96, len, 8),
        (104, len, 8),
        (112, 1, 8),
        (120, 2, 4),
        (124, 4, 4),
        (128, dynamic as u64, 8),
        (136, BASE + dynamic as u64, 8),
        (152, 96, 8),
        (160, 96, 8),
    ] {
        put(&mut image, at, value, size);
    }
    for index in 0..EXTRA_SEGMENTS {
        let at = 64 + (index + 2) * 56;
        for (relative, value, size) in [
            (0, 1, 4),
            (4, 5, 4),
            (8, (code + 8) as u64, 8),
            (16, 0x1000000 + index as u64 * 4096, 8),
            (32, 1, 8),
            (40, 1, 8),
            (48, 1, 8),
        ] {
            put(&mut image, at + relative, value, size);
        }
    }
    for (index, (tag, value)) in [
        (4, BASE + hash as u64),
        (5, BASE + strings as u64),
        (6, BASE + symbols as u64),
        (10, names.len() as u64),
        (11, 24),
        (0, 0),
    ]
    .into_iter()
    .enumerate()
    {
        put(&mut image, dynamic + index * 16, tag, 8);
        put(&mut image, dynamic + index * 16 + 8, value, 8);
    }
    put(&mut image, hash, 1, 4);
    put(&mut image, hash + 4, SYMBOLS as u64, 4);
    put(&mut image, hash + 8, 1, 4);
    image[strings..strings + names.len()].copy_from_slice(names);
    for index in 1..SYMBOLS {
        let at = symbols + index * 24;
        let (name, address, size) = if index == 1 {
            (1, BASE + code as u64, 5)
        } else {
            (31, 0x1000000, 1)
        };
        put(&mut image, at, name, 4);
        image[at + 4] = 0x12;
        put(&mut image, at + 6, 1, 2);
        put(&mut image, at + 8, address, 8);
        put(&mut image, at + 16, size, 8);
    }
    image[code..code + 5].copy_from_slice(&[0xe9, 3, 0, 0, 0]);
    image[code + 8] = 0xc3;
    let mut fixture = ForwarderFixture::new(NEAR, SHORT_BACK);
    fixture.image = image;
    (fixture, (code + 8) as u64)
}

#[test]
fn unrelated_dynamic_symbols_do_not_multiply_executable_segment_work() {
    use super::forwarder::{SCAN_PROBE, ScanProbe};
    let (fixture, target) = adversarial_forwarder();
    SCAN_PROBE.with(|probe| probe.set(ScanProbe::default()));
    let parsed = parse_object(&mut fixture.file(), None, &ObservationBudget::default()).unwrap();
    let work = SCAN_PROBE.with(|probe| probe.replace(ScanProbe::default()));
    assert_eq!(offset(&parsed, QUERY), Some(target));
    eprintln!(
        "adversarial conflict rows={}, segment predicates={}",
        work.rows[1], work.rows[2]
    );
    assert!(
        work.rows[1] >= 8192,
        "all conflict candidates were considered"
    );
    // Only query-source and target validation need a segment walk. This literal
    // bound allows ample headroom without deriving expectations from the helper.
    assert!(
        work.rows[2] < 4096,
        "unrelated symbols multiplied segment scans: {}",
        work.rows[2]
    );
}

#[test]
fn forwarding_deadlines_stop_in_memory_work_without_caching_partial_parse() {
    use super::forwarder::{SCAN_PROBE, ScanKind, ScanProbe};
    let (fixture, target) = adversarial_forwarder();
    for expire_at in [
        (ScanKind::Source, 300),
        (ScanKind::Conflict, 300),
        (ScanKind::Segment, 300),
    ] {
        let file = fixture.file();
        let object = Object {
            stamp: Stamp::of(&file.metadata().unwrap()),
            page: None,
            file,
            parse_deferred: Cell::new(false),
            anchor: OnceCell::new(),
            expected: None,
            parsed: OnceCell::new(),
            tables: OnceCell::new(),
        };
        let budget = ObservationBudget::default();
        SCAN_PROBE.with(|probe| {
            probe.set(ScanProbe {
                expire_at: Some(expire_at),
                ..Default::default()
            })
        });
        assert_eq!(
            object.parsed(&budget).err(),
            Some(ObservationGap::SnapshotLag)
        );
        let work = SCAN_PROBE.with(|probe| probe.replace(ScanProbe::default()));
        assert!(work.expired);
        eprintln!(
            "deadline phase={}, additional work rows={}",
            expire_at.0 as usize, work.after_expiry
        );
        assert!(
            work.after_expiry < 512,
            "deadline observed only after {} additional in-memory rows",
            work.after_expiry
        );
        assert!(
            object.parsed.get().is_none(),
            "partial parse cached across SnapshotLag"
        );
        budget.set_deadline(std::time::Instant::now() + std::time::Duration::from_secs(60));
        assert_eq!(offset(object.parsed(&budget).unwrap(), QUERY), Some(target));
        SCAN_PROBE.with(|probe| probe.set(ScanProbe::default()));
    }
}

#[test]
fn typed_conflict_at_original_export_survives_query_forward_derivation() {
    let mut f = ForwarderFixture::new(NEAR, SHORT_BACK);
    let at = f.symbols[OTHER] + 8;
    f.image[at..at + 8].copy_from_slice(&f.addresses[QUERY].to_le_bytes());
    // Equal-width public-name replacement introduces a separately typed free
    // role at the original query wrapper, before its one-hop derivation.
    let old = b"EVP_MD_fetch";
    let replacement = b"EVP_MAC_free";
    for at in 0..f.image.len() - old.len() + 1 {
        if &f.image[at..at + old.len()] == old {
            f.image[at..at + old.len()].copy_from_slice(replacement);
        }
    }
    let object = parsed(&f);
    assert!(object.typed_partial);
    assert!(
        object
            .typed_exports
            .iter()
            .all(|(role, _)| role.id() != 136)
    );
}

#[test]
fn typed_query_role_stages_at_the_derived_legacy_destination() {
    for prefix in ["", ".byte 0xf3,0x0f,0x1e,0xfa\n"] {
        let f = ForwarderFixture::new(&format!("{prefix}{NEAR}"), &format!("{prefix}{SHORT_BACK}"));
        let parsed = parsed(&f);
        assert_eq!(
            query_role_offset(&parsed, 161),
            Some(f.offsets["query_impl"]),
            "prefix {prefix:?}"
        );
        assert_eq!(
            query_role_offset(&parsed, 161),
            offset(&parsed, QUERY),
            "161 derives exactly as the legacy query API: {prefix:?}"
        );
    }
}

#[test]
fn typed_query_role_keeps_raw_entry_when_shared_destination_refuses() {
    let f = ForwarderFixture::new(NEAR, ".byte 0xe9\n.long query_impl-.-4");
    let parsed = parsed(&f);
    assert_eq!(offset(&parsed, QUERY), Some(f.offsets[QUERY]));
    assert_eq!(offset(&parsed, UNQUERY), Some(f.offsets[UNQUERY]));
    assert_eq!(
        query_role_offset(&parsed, 161),
        Some(f.offsets[QUERY]),
        "the shared-destination refusal covers the typed query role"
    );
}

#[test]
fn typed_query_role_keeps_raw_entry_for_plain_wrappers() {
    let f = ForwarderFixture::new(".byte 0xc3", SHORT_BACK);
    let parsed = parsed(&f);
    assert_eq!(offset(&parsed, QUERY), Some(f.offsets[QUERY]));
    assert_eq!(
        query_role_offset(&parsed, 161),
        Some(f.offsets[QUERY]),
        "no stub means no derivation, exactly as legacy"
    );
}

#[test]
fn typed_query_role_withholds_when_raw_entry_conflicts() {
    let mut f = ForwarderFixture::new(NEAR, SHORT_BACK);
    let at = f.symbols[OTHER] + 8;
    f.image[at..at + 8].copy_from_slice(&f.addresses[QUERY].to_le_bytes());
    let old = b"EVP_MD_fetch";
    let replacement = b"EVP_MAC_free";
    for at in 0..f.image.len() - old.len() + 1 {
        if &f.image[at..at + old.len()] == old {
            f.image[at..at + old.len()].copy_from_slice(replacement);
        }
    }
    let object = parsed(&f);
    assert_eq!(
        offset(&object, QUERY),
        Some(f.offsets[QUERY]),
        "the conflicted raw entry skips legacy derivation"
    );
    assert_eq!(
        query_role_offset(&object, 161),
        None,
        "the same conflict gate withholds the typed query role"
    );
}

#[test]
fn typed_getctx_role_stages_at_its_own_derived_destination() {
    for prefix in ["", ".byte 0xf3,0x0f,0x1e,0xfa\n"] {
        let f =
            ForwarderFixture::new_with_getctx(NEAR, SHORT_BACK, &format!("{prefix}{GETCTX_NEAR}"));
        let parsed = parsed(&f);
        assert_eq!(
            offset(&parsed, GETCTX),
            None,
            "no legacy API derives the getter symbol: {prefix:?}"
        );
        assert_eq!(
            typed_role_offset(&parsed, 146),
            Some(f.offsets["getctx_impl"]),
            "146 derives through its own resolve, not inheritance: {prefix:?}"
        );
    }
}

#[test]
fn typed_getctx_role_keeps_raw_entry_when_shared_destination_refuses() {
    let f = ForwarderFixture::new_with_getctx(NEAR, SHORT_BACK, ".byte 0xe9\n.long query_impl-.-4");
    let parsed = parsed(&f);
    assert_eq!(
        offset(&parsed, QUERY),
        Some(f.offsets["query_impl"]),
        "legacy query still derives to its own trampoline"
    );
    assert_eq!(
        typed_role_offset(&parsed, 146),
        Some(f.offsets[GETCTX]),
        "a destination shared with a derived legacy entry keeps the raw getter entry"
    );
}

#[test]
fn typed_getctx_role_keeps_raw_entry_when_all_three_wrappers_share_one_destination() {
    // Three-way signature collision: query, unquery, AND the getter all
    // jump to query_impl. Legacy resolution produces [T, T] and the
    // shared-destination refusal clears both — but the cleared list must
    // not let the getter derive to the known-conflicting T (an all()
    // over the emptied list would accept vacuously). All three keep
    // their validated raw entries.
    let shared = ".byte 0xe9\n.long query_impl-.-4";
    let f = ForwarderFixture::new_with_getctx(shared, shared, shared);
    let parsed = parsed(&f);
    assert_eq!(
        offset(&parsed, QUERY),
        Some(f.offsets[QUERY]),
        "legacy shared-destination refusal keeps the raw query entry"
    );
    assert_eq!(
        offset(&parsed, UNQUERY),
        Some(f.offsets[UNQUERY]),
        "legacy shared-destination refusal keeps the raw unquery entry"
    );
    assert_eq!(
        query_role_offset(&parsed, 161),
        Some(f.offsets[QUERY]),
        "the shared-destination refusal covers the typed query role"
    );
    assert_eq!(
        typed_role_offset(&parsed, 146),
        Some(f.offsets[GETCTX]),
        "the getter must not derive to the refused shared destination"
    );
}

#[test]
fn typed_getctx_role_keeps_raw_entry_for_plain_wrappers() {
    let f = ForwarderFixture::new_with_getctx(NEAR, SHORT_BACK, ".byte 0xc3");
    let parsed = parsed(&f);
    assert_eq!(
        typed_role_offset(&parsed, 146),
        Some(f.offsets[GETCTX]),
        "no stub means no derivation, exactly as legacy"
    );
}

#[test]
fn typed_getctx_role_withholds_when_raw_entry_conflicts() {
    let mut f = ForwarderFixture::new_with_getctx(NEAR, SHORT_BACK, GETCTX_NEAR);
    let at = f.symbols[OTHER] + 8;
    f.image[at..at + 8].copy_from_slice(&f.addresses[GETCTX].to_le_bytes());
    let old = b"EVP_MD_fetch";
    let replacement = b"EVP_MAC_free";
    for at in 0..f.image.len() - old.len() + 1 {
        if &f.image[at..at + old.len()] == old {
            f.image[at..at + old.len()].copy_from_slice(replacement);
        }
    }
    let object = parsed(&f);
    assert_eq!(
        offset(&object, QUERY),
        Some(f.offsets["query_impl"]),
        "the getter conflict leaves legacy derivation alone"
    );
    assert_eq!(
        typed_role_offset(&object, 146),
        None,
        "the same conflict gate withholds the typed getter role"
    );
}

#[test]
fn typed_getctx_derivation_runs_its_own_full_source_scans() {
    use super::forwarder::{SCAN_PROBE, ScanKind, ScanProbe};
    let plain = ForwarderFixture::new(NEAR, SHORT_BACK);
    let getctx = ForwarderFixture::new_with_getctx(NEAR, SHORT_BACK, ".byte 0xc3");
    let elf = goblin::elf::Elf::parse(&getctx.image).unwrap();
    let entries = elf
        .section_headers
        .iter()
        .find(|s| s.sh_type == 11)
        .map(|s| s.sh_size as usize / 24)
        .unwrap();
    SCAN_PROBE.with(|probe| probe.set(ScanProbe::default()));
    parse_object(&mut plain.file(), None, &ObservationBudget::default()).unwrap();
    let without = SCAN_PROBE.with(|probe| probe.replace(ScanProbe::default()));
    parse_object(&mut getctx.file(), None, &ObservationBudget::default()).unwrap();
    let with = SCAN_PROBE.with(|probe| probe.replace(ScanProbe::default()));
    // Two legacy resolves scan the table without the getter; the 146
    // derivation adds a third full scan with fresh budget charges rather
    // than reusing a legacy destination. The plain wrapper refuses after
    // the scan, so the work itself is the pinned behavior.
    assert_eq!(
        with.rows[ScanKind::Source as usize],
        3 * entries,
        "146 runs its own full source scan ({entries} entries)"
    );
    assert!(
        with.rows[ScanKind::Source as usize] > without.rows[ScanKind::Source as usize],
        "the getter derivation adds scan work, never reuses legacy scans"
    );
}
