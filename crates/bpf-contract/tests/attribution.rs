// SPDX-License-Identifier: GPL-2.0-or-later
use core::mem::{align_of, offset_of, size_of};
use osslscope_bpf_contract::attribution::*;
#[test]
fn reviewed_wire_sizes_and_offsets() {
    assert_eq!(size_of::<TypedAdmission>(), 32);
    assert_eq!(size_of::<ExactNameKey>(), 144);
    assert_eq!(size_of::<RelKey>(), 48);
    assert_eq!(size_of::<RelValue>(), 256);
    assert_eq!(size_of::<BindPendingKey>(), 32);
    assert_eq!(size_of::<BindPendingValue>(), 304);
    assert_eq!(offset_of!(BindPendingValue, name), 80);
    assert_eq!(offset_of!(BindPendingValue, parent_occurrence_id), 208);
    assert_eq!(offset_of!(BindPendingValue, transaction_flags), 300);
    assert_eq!(size_of::<SelectorDictionaryKey>(), 16);
    assert_eq!(size_of::<SelectorDictionaryValue>(), 64);
    assert_eq!(size_of::<SelectorRef>(), 24);
    assert_eq!(size_of::<PartitionKey>(), 104);
    assert_eq!(size_of::<PartitionValue>(), 24);
    assert_eq!(offset_of!(PartitionKey, count_generation), 88);
    assert_eq!(offset_of!(PartitionKey, selector_encoding), 100);
    assert_eq!(align_of::<PartitionKey>(), 8);
}
#[test]
fn typed_roles_do_not_infer_abi_from_numeric_coincidence() {
    assert!(TypedAdmission::new(305, 0, 3, 5, 1, 2).is_some());
    assert!(TypedAdmission::new(305, 0, 4, 5, 1, 2).is_none());
    assert!(TypedAdmission::new(305, 12, 3, 5, 1, 2).is_none());
    assert!(TypedAdmission::new(130, 12, 3, 0, 1, 2).is_some());
    assert!(TypedAdmission::new(130, 12, 3, 1, 1, 2).is_none());
    assert!(TypedAdmission::new(12, 12, 3, 0, 1, 2).is_none());
    assert!(TypedAdmission::new(128, 10, 1, 0, 1, 2).is_none());
    assert!(TypedAdmission::new(130, 12, 3, 0, 0, 2).is_none());
}
#[test]
fn exact_name_rejects_helper_boundary_and_preserves_non_utf8() {
    let mut bytes = [0u8; 128];
    bytes[0] = 255;
    let one = ExactNameKey::from_read(0, 3, &bytes, 2).unwrap();
    assert_eq!(one.name_length, 1);
    assert_eq!(one.name[0], 255);
    assert!(ExactNameKey::from_read(0, 3, &bytes, 0).is_none());
    assert!(ExactNameKey::from_read(0, 3, &bytes, 1).is_none());
    assert!(ExactNameKey::from_read(0, 3, &bytes, 128).is_none());
    bytes = [1; 128];
    bytes[126] = 0;
    assert!(ExactNameKey::from_read(0, 3, &bytes, 127).is_some());
    bytes[30] = 0;
    assert!(ExactNameKey::from_read(0, 3, &bytes, 127).is_none());
}
#[test]
fn selector_hash_is_exact_callback_code_scoped_sha256() {
    let expected = [
        (
            1,
            "7ce27deaa1d5b29ed0930dd81a91dfb693a67183a64041129f9f7c0741182560",
        ),
        (
            63,
            "fe3b2f8563b6cde460abc680898597e10935a083b0d7704a5ba72d4c5ba8a998",
        ),
        (
            64,
            "d31e76b988bd0efe6a3541313ab9556550e79bf72b931ba9d29e0501cf724519",
        ),
        (
            119,
            "d150c1e85e98e5585c019fe779c6320fa0f0cef4f463a14433ee5fef28383bcc",
        ),
        (
            120,
            "26df3e9481c10d5bc5a5001a6cdd2f7d6d58cb3e3b3bd98c54bd86064de32e75",
        ),
        (
            126,
            "84c764603236968a37aed686bfcc7f5341d5d0458076bac8330a4e33df6f69e1",
        ),
    ];
    let mut object = [0; 32];
    for (i, b) in object.iter_mut().enumerate() {
        *b = i as u8;
    }
    for (n, digest) in expected {
        let mut bytes = [0; 128];
        bytes[..n].fill(b'Z');
        let name = ExactNameKey::from_read(8, 3, &bytes, (n + 1) as i64).unwrap();
        let actual = selector_digest(&object, &name)
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(actual, digest);
    }
}

#[test]
fn selector_hash_never_accepts_a_prefix_or_unbound_object() {
    let mut bytes = [0; 128];
    bytes[0] = b'A';
    let mut name = ExactNameKey::from_read(0, 3, &bytes, 2).unwrap();
    assert!(selector_digest(&[0; 32], &name).is_none());
    name.object_domain = 1;
    name.name_length = 127;
    assert!(selector_digest(&[0; 32], &name).is_none());
    name.name_length = 1;
    name.name[2] = b'B';
    assert!(selector_digest(&[0; 32], &name).is_none());
}

#[test]
fn producer_map_layouts_are_exact() {
    assert_eq!(size_of::<TypedSiteKey>(), 24);
    assert_eq!(align_of::<TypedSiteKey>(), 8);
    assert_eq!(offset_of!(TypedSiteKey, process_incarnation), 8);
    assert_eq!(offset_of!(TypedSiteKey, image_epoch), 16);
    assert_eq!(size_of::<SiteBindValue>(), 56);
    assert_eq!(align_of::<SiteBindValue>(), 8);
    assert_eq!(offset_of!(SiteBindValue, object_sha256), 24);
    assert_eq!(size_of::<SegmentIndexKey>(), 32);
    assert_eq!(align_of::<SegmentIndexKey>(), 8);
    assert_eq!(offset_of!(SegmentIndexKey, reserved), 28);
    assert_eq!(size_of::<ProducerControl>(), 64);
    assert_eq!(align_of::<ProducerControl>(), 8);
    assert_eq!(offset_of!(ProducerControl, producer_mode), 0);
    assert_eq!(offset_of!(ProducerControl, next_producer_id), 32);
    assert_eq!(offset_of!(ProducerControl, reserved), 56);
    assert_eq!(size_of::<ThreadIdentityKey>(), 16);
    assert_eq!(size_of::<ThreadIdentityValue>(), 16);
    assert_eq!(size_of::<DigestKey>(), 48);
    let bound = SiteBindValue {
        site_id: 1,
        source_epoch: 1,
        code_object_id: 1,
        object_sha256: [7; 32],
    };
    assert!(bound.valid());
    let mut unbound = bound;
    unbound.site_id = 0;
    assert!(!unbound.valid());
    let admitted = ProducerControl {
        producer_mode: PRODUCER_ADMITTED,
        session_id: 1,
        admission_epoch: 1,
        cut_id: 1,
        next_producer_id: 1,
        relation_epoch: 1,
        loss_epoch: 1,
        reserved: 0,
    };
    assert!(admitted.admitted());
    for mode in [PRODUCER_CLOSED, PRODUCER_POISONED, 3, u64::MAX] {
        let mut poisoned = admitted;
        poisoned.producer_mode = mode;
        assert!(!poisoned.admitted());
    }
    let mut zeroed = admitted;
    zeroed.cut_id = 0;
    assert!(!zeroed.admitted());
    zeroed = admitted;
    zeroed.reserved = 1;
    assert!(!zeroed.admitted());
}
#[test]
fn producer_rel_kinds_and_states_are_disjoint() {
    let kinds = [
        REL_PROVIDER,
        REL_QUERY,
        REL_BINDING,
        REL_CONTEXT_INDEX,
        REL_CODE_ROLE,
        REL_REQUEST_NAME,
        REL_OBJECT_SELECTOR,
        REL_METHOD,
        REL_OWNER,
        REL_OWNER_SELECTOR,
        REL_METHOD_AMBIGUITY,
        REL_CONTEXT_QUARANTINE,
        REL_X_INDEX,
        REL_U_INDEX,
    ];
    assert_eq!(kinds, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
    assert_eq!(
        (REL_WITNESS, REL_CERTIFIED, REL_RETIRED, REL_CONFLICT),
        (1, 2, 3, 4)
    );
    assert_ne!(QUARANTINE_OWNER_U, QUARANTINE_CONTEXT_X);
    assert_eq!(
        (
            CONFLICT_METHOD_NAME,
            CONFLICT_SHARED_X,
            CONFLICT_SHARED_U,
            CONFLICT_DUP_EQUALITY
        ),
        (1, 2, 3, 4)
    );
}
#[test]
fn first_slice_role_census_is_exactly_twenty_nine() {
    let mut admitted = Vec::new();
    for id in 0..512u32 {
        if TypedRoleId::from_u32(id).is_some() {
            admitted.push(id);
        }
    }
    assert_eq!(
        admitted,
        vec![
            5, 18, 130, 131, 136, 137, 142, 143, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155,
            258, 259, 274, 275, 290, 291, 304, 305, 306, 307, 308,
        ]
    );
    for id in [
        0, 1, 12, 48, 49, 127, 128, 129, 132, 156, 160, 176, 256, 257, 260, 309, 511,
    ] {
        assert!(
            TypedRoleId::from_u32(id).is_none(),
            "role {id} must stay refused"
        );
    }
}
#[test]
fn canonical_name_check_implies_from_read_accepts() {
    // Canonical buffers pass both checks with identical material: the BPF
    // keyless path uses raw bytes verbatim, `from_read` zero-pads.
    for n in [1u32, 2, 63, 126] {
        let mut bytes = [0; 128];
        bytes[..n as usize].fill(0xAB);
        assert!(exact_name_canonical(&bytes, n), "length {n}");
        let key = ExactNameKey::from_read(0, 3, &bytes, n as i64 + 1).unwrap();
        assert_eq!(key.name_length, n);
        assert_eq!(&key.name[..n as usize], &bytes[..n as usize]);
        assert!(key.name[n as usize..].iter().all(|b| *b == 0));
    }
    // Both checks reject empty, overlong and unterminated reads.
    for (bytes, length, result) in [
        ([0u8; 128], 0, 1),
        ([0xFFu8; 128], 127, 128),
        ([0xFFu8; 128], 128, 129),
    ] {
        assert!(!exact_name_canonical(&bytes, length));
        assert!(ExactNameKey::from_read(0, 3, &bytes, result).is_none());
    }
    // A garbage tail is canonical-rejected but `from_read`-accepted (the
    // pinned lenient contract zero-pads): the kernel path refuses what the
    // host contract normalizes.
    let mut dirty_tail = [0u8; 128];
    dirty_tail[0] = b'A';
    dirty_tail[5] = b'B';
    assert!(!exact_name_canonical(&dirty_tail, 1));
    let padded = ExactNameKey::from_read(0, 3, &dirty_tail, 2).unwrap();
    assert_eq!(padded.name_length, 1);
    assert_eq!(padded.name[0], b'A');
    assert!(padded.name[1..].iter().all(|b| *b == 0));
    // An interior NUL fails both checks.
    let mut interior_nul = [b'C'; 128];
    interior_nul[2] = 0;
    assert!(!exact_name_canonical(&interior_nul, 5));
    assert!(ExactNameKey::from_read(0, 3, &interior_nul, 6).is_none());
}
#[test]
fn scratch_digest_matches_stack_digest_on_dirty_scratch() {
    let mut object = [0; 32];
    for (i, b) in object.iter_mut().enumerate() {
        *b = (i * 7 + 3) as u8;
    }
    for n in [1usize, 63, 64, 119, 120, 126] {
        let mut bytes = [0; 128];
        bytes[..n].fill(b'Q');
        let name = ExactNameKey::from_read(9, 4, &bytes, (n + 1) as i64).unwrap();
        let stacked = selector_digest(&object, &name).unwrap();
        let mut scratch = [0xA5u8; 192];
        let scratched = selector_digest_into(&object, &name, &mut scratch).unwrap();
        assert_eq!(stacked, scratched, "name length {n}");
    }
    let mut bytes = [0; 128];
    bytes[0] = b'A';
    let name = ExactNameKey::from_read(0, 3, &bytes, 2).unwrap();
    let mut scratch = [0u8; 192];
    assert!(selector_digest_into(&[0; 32], &name, &mut scratch).is_none());
}
#[test]
fn parts_digest_matches_key_digest_and_rejects_bad_parts() {
    let mut object = [0; 32];
    for (i, b) in object.iter_mut().enumerate() {
        *b = (i * 3 + 1) as u8;
    }
    for n in [1usize, 64, 126] {
        let mut bytes = [0; 128];
        bytes[..n].fill(b'W');
        let name = ExactNameKey::from_read(5, 3, &bytes, (n + 1) as i64).unwrap();
        let mut scratch = [0x5Au8; 192];
        let keyed = selector_digest_into(&object, &name, &mut scratch).unwrap();
        let mut scratch = [0xA5u8; 192];
        let parts = selector_digest_parts(3, n as u32, &bytes, &object, &mut scratch).unwrap();
        assert_eq!(keyed, parts, "name length {n}");
    }
    let bytes = [b'X'; 128];
    let mut scratch = [0u8; 192];
    assert!(selector_digest_parts(5, 1, &bytes, &object, &mut scratch).is_none());
    assert!(selector_digest_parts(3, 0, &bytes, &object, &mut scratch).is_none());
    assert!(selector_digest_parts(3, 127, &bytes, &object, &mut scratch).is_none());
    let mut bad = [0u8; 128];
    bad[0] = b'Y';
    bad[1] = b'Z';
    assert!(selector_digest_parts(3, 1, &bad, &object, &mut scratch).is_none());
}
#[test]
fn typed_role_has_separate_identity_and_exact_public_exports() {
    let role = TypedRoleId::from_u32(130).unwrap();
    assert_eq!(role.id(), 130);
    assert_eq!(role.public_export(), Some("EVP_MAC_fetch"));
    assert_eq!(
        TypedRoleId::from_u32(146).unwrap().public_export(),
        Some("OSSL_PROVIDER_get0_provider_ctx")
    );
    assert_eq!(TypedRoleId::from_u32(258).unwrap().public_export(), None);
    assert!(TypedRoleId::from_u32(12).is_none());
    assert!(TypedRoleId::from_u32(156).is_none());
    assert!(TypedAdmission::new(5, 5, 0, 0, 1, 1).is_some());
    assert!(TypedAdmission::new(18, 0, 0, 0, 1, 1).is_some());
}
#[test]
fn copied_and_operational_roles_have_no_public_export_or_staging_path() {
    // P3-I2 permanent-negative premise: copied callback roles (258/259
    // constructors, 274/275/290/291 lifecycle) and operational roles
    // (304-308) have no public export names, so no host staging path can
    // name them — constructor/operational staging (phase-2 U1) must arrive
    // before any owner can commit or any partition can assign. H2/H3 pin
    // the resulting definite=0 from the fail-closed side; this pins the
    // structural reason those pins must never flip without U1.
    for role in [258, 259, 274, 275, 290, 291, 304, 305, 306, 307, 308] {
        assert_eq!(
            TypedRoleId::from_u32(role).unwrap().public_export(),
            None,
            "role {role} must have no public export"
        );
    }
}
#[test]
fn query_observation_role_admits_paired_query_only() {
    // U1: role 161 observes OSSL_PROVIDER_query_operation (legacy query
    // API 8) to publish CODE_ROLE rows. Paired (entry stages op, return
    // walks the table), never operational, operation/function 0 in the
    // triple (the observed op rides the pending frame, never admission).
    let role = TypedRoleId::from_u32(161).unwrap();
    assert_eq!(role.id(), 161);
    assert_eq!(role.public_export(), Some("OSSL_PROVIDER_query_operation"));
    assert_eq!(TypedAdmission::admission_parts(161), Some((8, 0, 0)));
    let admission = TypedAdmission::new(161, 8, 0, 0, 1, 1).unwrap();
    assert!(admission.valid());
    assert!(admission.paired());
    assert!(!admission.operational());
    assert!(TypedAdmission::new(161, 8, 3, 0, 1, 1).is_none());
    assert!(TypedAdmission::new(161, 0, 0, 0, 1, 1).is_none());
}
