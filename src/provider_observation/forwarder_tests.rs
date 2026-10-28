// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
#[path = "../../tests/support/provider_forwarder.rs"]
mod fixture;
use fixture::{ForwarderFixture, OTHER, QUERY, UNQUERY};
const NEAR: &str = ".byte 0xe9\n.long query_impl-.-4";
const SHORT_BACK: &str = ".byte 0xeb\n.byte unquery_impl-.-1";

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
        file,
        parse_deferred: Cell::new(false),
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
